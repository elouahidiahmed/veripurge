<#
.SYNOPSIS
    Suppression sécurisée de fichiers SharePoint Online + manifeste d'empreintes.

.REQUIREMENTS
    Module PnP.PowerShell  (Install-Module PnP.PowerShell -Scope CurrentUser)

.IMPORTANT  -- Limite de la "destruction" dans le cloud
    Sur SharePoint Online, vous ne contrôlez pas le stockage physique. Le mieux
    réalisable côté tenant = supprimer + VIDER les corbeilles (1er et 2nd niveau).
    Microsoft conserve néanmoins des sauvegardes côté plateforme (~14 jours).
    Pour une preuve juridique, le certificat documente : empreinte AVANT suppression,
    purge des corbeilles, et cette rémanence résiduelle non maîtrisable.
    Si une éradication totale est exigée contractuellement -> demander à Microsoft
    une attestation de suppression (Data Subject / GDPR deletion request).
#>

Set-StrictMode -Version Latest

function Connect-DisposerSharePoint {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SiteUrl,
        [ValidateSet('interactive','appcert')][string]$Mode = 'interactive',
        [string]$ClientId, [string]$Tenant, [string]$Thumbprint
    )
    if (-not (Get-Module -ListAvailable -Name PnP.PowerShell)) {
        throw "Module PnP.PowerShell absent. Installez-le : Install-Module PnP.PowerShell -Scope CurrentUser"
    }
    Import-Module PnP.PowerShell -ErrorAction Stop

    switch ($Mode) {
        'appcert' {
            if (-not ($ClientId -and $Tenant -and $Thumbprint)) {
                throw "Mode appcert : clientId, tenant et thumbprint requis."
            }
            Connect-PnPOnline -Url $SiteUrl -ClientId $ClientId -Tenant $Tenant -Thumbprint $Thumbprint -ErrorAction Stop
        }
        default {
            Connect-PnPOnline -Url $SiteUrl -Interactive -ErrorAction Stop
        }
    }
    Write-Host "[SPO] Connecté à $SiteUrl" -ForegroundColor Cyan
}

function Get-SpoFileHash {
    <# Télécharge le contenu en mémoire et calcule SHA256/MD5 (preuve d'intégrité). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$ServerRelativeUrl)

    $stream = Get-PnPFile -Url $ServerRelativeUrl -AsMemoryStream -ErrorAction Stop
    $bytes  = $stream.ToArray()

    $sha = [System.Security.Cryptography.SHA256]::Create()
    $md5 = [System.Security.Cryptography.MD5]::Create()
    try {
        $shaHash = ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
        $md5Hash = ($md5.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') }) -join ''
    } finally { $sha.Dispose(); $md5.Dispose() }

    [pscustomobject]@{ SizeBytes = $bytes.Length; SHA256 = $shaHash.ToUpper(); MD5 = $md5Hash.ToUpper() }
}

function Invoke-SharePointSanitization {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string[]]$Folders,        # site-relative, ex: "Shared Documents/CASE-..."
        [ValidateSet('Preview','Destroy')][string]$Mode = 'Preview',
        [bool]$HashBeforeDelete = $true,
        [bool]$PurgeRecycleBin  = $true
    )

    $results = New-Object System.Collections.Generic.List[object]

    foreach ($folder in $Folders) {
        $items    = @(Get-PnPFolderItem -FolderSiteRelativeUrl $folder -ItemType File -Recursive -ErrorAction Stop)
        $spoTotal = $items.Count
        Write-Host ("[SPO] {0} : {1} fichier(s)" -f $folder, $spoTotal) -ForegroundColor Cyan

        $sidx = 0; $sLastPct = -1
        $ssw = [System.Diagnostics.Stopwatch]::StartNew(); $sbytes = [int64]0
        foreach ($it in $items) {
            $sidx++
            # Barre de progression (le hachage télécharge chaque fichier : utile sur gros volumes).
            $spct = if ($spoTotal -gt 0) { [int](($sidx / $spoTotal) * 100) } else { 100 }
            if ($spct -ne $sLastPct) {
                $sel   = $ssw.Elapsed.TotalSeconds
                $smbps = if ($sel -gt 0) { [math]::Round(($sbytes / 1MB) / $sel, 1) } else { 0 }
                $seta  = if ($sel -gt 0) { [int](($spoTotal - $sidx) * ($sel / $sidx)) } else { 0 }
                Write-Progress -Id 2 -Activity ("Sanitization SharePoint [{0}]" -f $Mode) `
                    -Status ("{0}/{1} fichiers ({2}%) - {3} Mo/s" -f $sidx, $spoTotal, $spct, $smbps) `
                    -CurrentOperation $it.ServerRelativeUrl -PercentComplete $spct -SecondsRemaining $seta
                $sLastPct = $spct
            }

            $srv  = $it.ServerRelativeUrl
            $sha  = $null; $md5 = $null; $size = $it.Length
            $status = 'PREVIEW'; $err = $null

            if ($HashBeforeDelete) {
                try {
                    $h = Get-SpoFileHash -ServerRelativeUrl $srv
                    $sha = $h.SHA256; $md5 = $h.MD5; $size = $h.SizeBytes
                } catch { Write-Warning "Hash impossible $srv : $($_.Exception.Message)" }
            }

            if ($Mode -eq 'Destroy') {
                try {
                    Remove-PnPFile -ServerRelativeUrl $srv -Force -ErrorAction Stop
                    $status = 'DELETED'
                } catch { $status = 'FAILED'; $err = $_.Exception.Message }
            }

            if ($size) { $sbytes += [int64]$size }

            $results.Add([pscustomobject]@{
                Source          = 'SHAREPOINT'
                Path            = $srv
                SizeBytes       = $size
                SHA256          = $sha
                MD5             = $md5
                CreatedUtc      = $(if ($it.TimeCreated)      { $it.TimeCreated.ToUniversalTime().ToString('o') } else { $null })
                ModifiedUtc     = $(if ($it.TimeLastModified) { $it.TimeLastModified.ToUniversalTime().ToString('o') } else { $null })
                Method          = "Remove-PnPFile + purge corbeilles (1er+2nd niveau)"
                Status          = $status
                VerifiedDeleted = $(if ($Mode -eq 'Destroy') { $status -eq 'DELETED' } else { $null })
                Error           = $err
                ProcessedUtc    = (Get-Date).ToUniversalTime().ToString('o')
            })
        }
        Write-Progress -Id 2 -Activity 'Sanitization SharePoint' -Completed
    }

    # Purge des deux niveaux de corbeille pour les éléments supprimés.
    if ($Mode -eq 'Destroy' -and $PurgeRecycleBin) {
        Write-Host "[SPO] Purge des corbeilles (1er + 2nd niveau)..." -ForegroundColor Yellow
        try {
            $deletedNames = $results | Where-Object Status -eq 'DELETED' |
                            ForEach-Object { Split-Path $_.Path -Leaf }
            $bin = Get-PnPRecycleBinItem -ErrorAction Stop |
                   Where-Object { $deletedNames -contains $_.LeafName }
            foreach ($b in $bin) {
                Clear-PnPRecycleBinItem -Identity $b.Id -Force -ErrorAction Stop
            }
            Write-Host ("[SPO] {0} élément(s) purgé(s) définitivement." -f @($bin).Count) -ForegroundColor Yellow
        } catch {
            Write-Warning "Purge corbeille partielle/échouée : $($_.Exception.Message)"
        }
    }

    return $results
}

Export-ModuleMember -Function Connect-DisposerSharePoint, Get-SpoFileHash, Invoke-SharePointSanitization
