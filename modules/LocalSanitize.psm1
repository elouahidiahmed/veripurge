<#
.SYNOPSIS
    Sanitization sécurisée de fichiers locaux (Windows) + manifeste d'empreintes.

.NOTES
    NIST SP 800-88 Rev.1.
    L'overwrite logique multi-passes est efficace sur disques MAGNETIQUES (HDD).
    Sur SSD / NVMe / clé USB, le wear-leveling rend l'overwrite NON garanti :
    privilégier ATA Secure Erase / NVMe Format, ou crypto-erase (BitLocker) au
    niveau du volume. Voir README -> "Limites par type de support".

    LONGS CHEMINS (> 260 caractères) : sous-dossiers profonds / noms à UUID dépassent
    MAX_PATH et font échouer les cmdlets provider ("fichier introuvable" sur des
    fichiers existants). Ce module préfixe donc tous les chemins en forme étendue
    \\?\ (ou \\?\UNC\ pour les partages) et utilise .NET I/O directement.
#>

Set-StrictMode -Version Latest

Import-Module (Join-Path $PSScriptRoot 'Journal.psm1') -Force

function ConvertTo-ExtendedPath {
    <# Convertit en chemin absolu préfixé \\?\ (supporte ~32767 caractères). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ([string]::IsNullOrEmpty($Path)) { return $Path }
    if ($Path.StartsWith('\\?\'))       { return $Path }   # déjà étendu

    $full = [System.IO.Path]::GetFullPath($Path)           # normalise (slashs, relatif, .)
    if ($full.StartsWith('\\')) { return '\\?\UNC\' + $full.Substring(2) }  # UNC \\srv\share
    return '\\?\' + $full
}

function ConvertFrom-ExtendedPath {
    <# Retire le préfixe \\?\ pour un affichage lisible dans le manifeste. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    if ($Path -like '\\?\UNC\*') { return '\\' + $Path.Substring(8) }
    if ($Path -like '\\?\*')     { return $Path.Substring(4) }
    return $Path
}

function Get-LongPathFile {
    <# Énumération récursive long-path-safe, tolérante aux dossiers inaccessibles. #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ExtRoot)

    $results = New-Object System.Collections.Generic.List[string]
    $stack   = New-Object System.Collections.Generic.Stack[string]
    $stack.Push($ExtRoot)

    while ($stack.Count -gt 0) {
        $dir = $stack.Pop()
        try { foreach ($f in [System.IO.Directory]::EnumerateFiles($dir))       { $results.Add($f) } }
        catch { Write-Warning ("Fichiers illisibles dans {0} : {1}" -f (ConvertFrom-ExtendedPath $dir), $_.Exception.Message) }
        try { foreach ($d in [System.IO.Directory]::EnumerateDirectories($dir)) { $stack.Push($d) } }
        catch { Write-Warning ("Sous-dossiers illisibles dans {0} : {1}" -f (ConvertFrom-ExtendedPath $dir), $_.Exception.Message) }
    }
    return $results
}

function Get-FileManifestEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $ext = ConvertTo-ExtendedPath $Path
    $fi  = New-Object System.IO.FileInfo($ext)

    # Hash via flux (évite tout passage de long chemin à Get-FileHash -LiteralPath).
    $fs = [System.IO.File]::Open($ext, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, [System.IO.FileShare]::ReadWrite)
    try {
        $sha = (Get-FileHash -InputStream $fs -Algorithm SHA256).Hash
        $fs.Position = 0
        $md5 = (Get-FileHash -InputStream $fs -Algorithm MD5).Hash
    }
    finally { $fs.Dispose() }

    [pscustomobject]@{
        Path        = ConvertFrom-ExtendedPath $fi.FullName
        SizeBytes   = $fi.Length
        SHA256      = $sha
        MD5         = $md5
        CreatedUtc  = $fi.CreationTimeUtc.ToString('o')
        ModifiedUtc = $fi.LastWriteTimeUtc.ToString('o')
    }
}

function Invoke-SecureOverwrite {
    <# Overwrite multi-passes (random x N-1 + zéro final), puis rename + delete. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [int]$Passes = 3
    )

    $ext = ConvertTo-ExtendedPath $Path
    $fi  = New-Object System.IO.FileInfo($ext)
    if ($fi.IsReadOnly) { $fi.IsReadOnly = $false }

    $len = [int64]$fi.Length
    if ($len -gt 0) {
        $fs = [System.IO.File]::Open($ext, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write)
        try {
            $rng     = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $bufSize = [int64]1MB
            $buf     = New-Object byte[] $bufSize

            for ($p = 1; $p -le $Passes; $p++) {
                $fs.Position = 0
                $remaining   = [int64]$len
                while ($remaining -gt 0) {
                    # Int64 obligatoire : les fichiers > 2 Go débordent un Int32.
                    $chunk = [int][Math]::Min($bufSize, $remaining)
                    if ($p -eq $Passes) { [Array]::Clear($buf, 0, $chunk) }  # passe finale = zéros
                    else                { $rng.GetBytes($buf) }
                    $fs.Write($buf, 0, $chunk)
                    $remaining -= $chunk
                }
                $fs.Flush($true)   # flush jusqu'au disque
            }
        }
        finally { $fs.Dispose() }
    }

    # Casser le nom de fichier (anti-forensique sur les métadonnées MFT) puis supprimer.
    $dir    = [System.IO.Path]::GetDirectoryName($ext)
    $newExt = [System.IO.Path]::Combine($dir, [System.IO.Path]::GetRandomFileName())
    [System.IO.File]::Move($ext, $newExt)
    [System.IO.File]::Delete($newExt)
}

function Invoke-LocalSanitization {
    <#
    .SYNOPSIS  Traite une liste de répertoires : hash -> (Preview|Destroy) -> vérification.
    .OUTPUTS   Tableau d'entrées de manifeste enrichies (statut de destruction).
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Paths,
        [int]$Passes = 3,
        [ValidateSet('Preview','Destroy')][string]$Mode = 'Preview',
        [switch]$WipeFreeSpace,
        [string]$JournalPath
    )

    $results = New-Object System.Collections.Generic.List[object]

    # --- Reprise : recharger le journal existant (entrées LOCAL uniquement) ---
    $priorByPath   = [ordered]@{}
    $doneSet       = New-Object 'System.Collections.Generic.HashSet[string]'
    $successStatus = if ($Mode -eq 'Destroy') { 'DESTROYED' } else { 'PREVIEW' }
    if ($JournalPath) {
        foreach ($rec in (Read-DispositionJournal -JournalPath $JournalPath)) {
            if ($rec.Source -ne 'LOCAL') { continue }
            $priorByPath[$rec.Path] = $rec               # dernier état gagne
        }
        foreach ($rec in $priorByPath.Values) {
            if ($rec.Status -eq $successStatus) { [void]$doneSet.Add($rec.Path) }
        }
        if ($doneSet.Count -gt 0) {
            Write-Host ("[LOCAL] Reprise : {0} fichier(s) déjà traité(s), ignoré(s)." -f $doneSet.Count) -ForegroundColor DarkCyan
        }
    }

    foreach ($root in $Paths) {
        $extRoot = ConvertTo-ExtendedPath $root
        if (-not [System.IO.Directory]::Exists($extRoot) -and -not [System.IO.File]::Exists($extRoot)) {
            Write-Warning "Chemin introuvable, ignoré : $root"
            continue
        }

        # Fichier unique ou répertoire ?
        if ([System.IO.File]::Exists($extRoot)) {
            $files = @($extRoot)
        } else {
            $files = @(Get-LongPathFile -ExtRoot $extRoot)
        }
        Write-Host ("[LOCAL] {0} : {1} fichier(s)" -f $root, $files.Count) -ForegroundColor Cyan

        $total = $files.Count; $idx = 0; $lastPct = -1
        $sw = [System.Diagnostics.Stopwatch]::StartNew(); $bytesDone = [int64]0
        foreach ($extFile in $files) {
            $idx++
            # Barre de progression (throttle : redessine seulement quand le % entier change).
            $pct = if ($total -gt 0) { [int](($idx / $total) * 100) } else { 100 }
            if ($pct -ne $lastPct) {
                $elapsed = $sw.Elapsed.TotalSeconds
                $mbps = if ($elapsed -gt 0) { [math]::Round(($bytesDone / 1MB) / $elapsed, 1) } else { 0 }
                $eta  = if ($elapsed -gt 0) { [int](($total - $idx) * ($elapsed / $idx)) } else { 0 }
                Write-Progress -Id 1 -Activity ("Sanitization locale [{0}]" -f $Mode) `
                    -Status ("{0}/{1} fichiers ({2}%) - {3} Mo/s" -f $idx, $total, $pct, $mbps) `
                    -CurrentOperation (ConvertFrom-ExtendedPath $extFile) `
                    -PercentComplete $pct -SecondsRemaining $eta
                $lastPct = $pct
            }

            # Reprise : déjà traité avec succès lors d'un run précédent -> on saute.
            if ($doneSet.Contains((ConvertFrom-ExtendedPath $extFile))) { continue }

            $entry    = $null
            $status   = 'PREVIEW'
            $verified = $null
            $err      = $null

            try {
                $entry = Get-FileManifestEntry -Path $extFile
            }
            catch {
                # On journalise quand même l'échec de lecture pour traçabilité.
                Write-Warning ("Lecture impossible {0} : {1}" -f (ConvertFrom-ExtendedPath $extFile), $_.Exception.Message)
                $rec = [pscustomobject]@{
                    Source='LOCAL'; Path=(ConvertFrom-ExtendedPath $extFile); SizeBytes=$null
                    SHA256=$null; MD5=$null; CreatedUtc=$null; ModifiedUtc=$null
                    Method="Overwrite x$Passes (random+zero), rename, delete"
                    Status='READ_ERROR'; VerifiedDeleted=$null; Error=$_.Exception.Message
                    ProcessedUtc=(Get-Date).ToUniversalTime().ToString('o')
                }
                if ($JournalPath) { Add-JournalEntry -JournalPath $JournalPath -Entry $rec }
                $results.Add($rec)
                continue
            }

            if ($entry.SizeBytes) { $bytesDone += [int64]$entry.SizeBytes }

            if ($Mode -eq 'Destroy') {
                try {
                    Invoke-SecureOverwrite -Path $extFile -Passes $Passes
                    $verified = -not [System.IO.File]::Exists($extFile)
                    $status   = if ($verified) { 'DESTROYED' } else { 'FAILED' }
                }
                catch {
                    $status = 'FAILED'
                    $err    = $_.Exception.Message
                    Write-Warning ("Echec destruction {0} : {1}" -f $entry.Path, $err)
                }
            }

            $rec = [pscustomobject]@{
                Source           = 'LOCAL'
                Path             = $entry.Path
                SizeBytes        = $entry.SizeBytes
                SHA256           = $entry.SHA256
                MD5              = $entry.MD5
                CreatedUtc       = $entry.CreatedUtc
                ModifiedUtc      = $entry.ModifiedUtc
                Method           = "Overwrite x$Passes (random+zero), rename, delete"
                Status           = $status
                VerifiedDeleted  = $verified
                Error            = $err
                ProcessedUtc     = (Get-Date).ToUniversalTime().ToString('o')
            }
            if ($JournalPath) { Add-JournalEntry -JournalPath $JournalPath -Entry $rec }
            $results.Add($rec)
        }
        Write-Progress -Id 1 -Activity 'Sanitization locale' -Completed

        # Wipe de l'espace libre du volume (efface les rémanences post-suppression).
        if ($Mode -eq 'Destroy' -and $WipeFreeSpace) {
            $drive = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($root))
            Write-Host "[LOCAL] cipher /w sur $drive (peut être long)..." -ForegroundColor Yellow
            & cipher.exe "/w:$drive" | Out-Null
        }
    }

    # Avec reprise : fusionner l'historique (prior) + ce run (dernier état par chemin).
    if ($JournalPath) {
        $final = [ordered]@{}
        foreach ($r in $priorByPath.Values) { $final[$r.Path] = $r }
        foreach ($r in $results)            { $final[$r.Path] = $r }
        return @($final.Values)
    }
    return $results
}

Export-ModuleMember -Function Get-FileManifestEntry, Invoke-SecureOverwrite, Invoke-LocalSanitization, ConvertTo-ExtendedPath, ConvertFrom-ExtendedPath
