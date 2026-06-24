<#
.SYNOPSIS
    Sanitization sécurisée de fichiers locaux (Windows) + manifeste d'empreintes.

.NOTES
    NIST SP 800-88 Rev.1.
    L'overwrite logique multi-passes est efficace sur disques MAGNETIQUES (HDD).
    Sur SSD / NVMe / clé USB, le wear-leveling rend l'overwrite NON garanti :
    privilégier ATA Secure Erase / NVMe Format, ou crypto-erase (BitLocker) au
    niveau du volume. Voir README -> "Limites par type de support".
#>

Set-StrictMode -Version Latest

function Get-FileManifestEntry {
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$Path)

    $fi  = Get-Item -LiteralPath $Path -Force
    $sha = (Get-FileHash -LiteralPath $Path -Algorithm SHA256).Hash
    $md5 = (Get-FileHash -LiteralPath $Path -Algorithm MD5).Hash

    [pscustomobject]@{
        Path        = $fi.FullName
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

    $fi = Get-Item -LiteralPath $Path -Force
    if ($fi.IsReadOnly) { $fi.IsReadOnly = $false }

    $len = $fi.Length
    if ($len -gt 0) {
        $fs = [System.IO.File]::Open($fi.FullName, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Write)
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
    $rand    = [System.IO.Path]::GetRandomFileName()
    $newPath = Join-Path $fi.DirectoryName $rand
    Rename-Item -LiteralPath $fi.FullName -NewName $rand -Force
    Remove-Item -LiteralPath $newPath -Force
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
        if (-not (Test-Path -LiteralPath $root)) {
            Write-Warning "Chemin introuvable, ignoré : $root"
            continue
        }

        $files = @(Get-ChildItem -LiteralPath $root -Recurse -File -Force -ErrorAction SilentlyContinue)
        Write-Host ("[LOCAL] {0} : {1} fichier(s)" -f $root, $files.Count) -ForegroundColor Cyan

        foreach ($f in $files) {
            $entry = Get-FileManifestEntry -Path $f.FullName
            $status = 'PREVIEW'
            $verified = $null
            $err = $null

            if ($Mode -eq 'Destroy') {
                try {
                    Invoke-SecureOverwrite -Path $f.FullName -Passes $Passes
                    $verified = -not (Test-Path -LiteralPath $f.FullName)
                    $status   = if ($verified) { 'DESTROYED' } else { 'FAILED' }
                }
                catch {
                    $status = 'FAILED'
                    $err    = $_.Exception.Message
                    Write-Warning ("Echec destruction {0} : {1}" -f $f.FullName, $err)
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
            $drive = (Get-Item -LiteralPath $root).PSDrive.Name + ':\'
            Write-Host "[LOCAL] cipher /w sur $drive (peut être long)..." -ForegroundColor Yellow
            & cipher.exe "/w:$drive" | Out-Null
        }
    }

    return $results
}

Export-ModuleMember -Function Get-FileManifestEntry, Invoke-SecureOverwrite, Invoke-LocalSanitization
