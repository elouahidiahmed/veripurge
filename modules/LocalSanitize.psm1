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

    $len = $fi.Length
    if ($len -gt 0) {
        $fs = [System.IO.File]::Open($ext, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write)
        try {
            $rng     = [System.Security.Cryptography.RandomNumberGenerator]::Create()
            $bufSize = 1MB
            $buf     = New-Object byte[] $bufSize

            for ($p = 1; $p -le $Passes; $p++) {
                $fs.Position = 0
                $remaining   = $len
                while ($remaining -gt 0) {
                    $chunk = [Math]::Min($bufSize, $remaining)
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
        [switch]$WipeFreeSpace
    )

    $results = New-Object System.Collections.Generic.List[object]

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

        foreach ($extFile in $files) {
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
                $results.Add([pscustomobject]@{
                    Source='LOCAL'; Path=(ConvertFrom-ExtendedPath $extFile); SizeBytes=$null
                    SHA256=$null; MD5=$null; CreatedUtc=$null; ModifiedUtc=$null
                    Method="Overwrite x$Passes (random+zero), rename, delete"
                    Status='READ_ERROR'; VerifiedDeleted=$null; Error=$_.Exception.Message
                    ProcessedUtc=(Get-Date).ToUniversalTime().ToString('o')
                })
                continue
            }

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

            $results.Add([pscustomobject]@{
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
            })
        }

        # Wipe de l'espace libre du volume (efface les rémanences post-suppression).
        if ($Mode -eq 'Destroy' -and $WipeFreeSpace) {
            $drive = [System.IO.Path]::GetPathRoot([System.IO.Path]::GetFullPath($root))
            Write-Host "[LOCAL] cipher /w sur $drive (peut être long)..." -ForegroundColor Yellow
            & cipher.exe "/w:$drive" | Out-Null
        }
    }

    return $results
}

Export-ModuleMember -Function Get-FileManifestEntry, Invoke-SecureOverwrite, Invoke-LocalSanitization, ConvertTo-ExtendedPath, ConvertFrom-ExtendedPath
