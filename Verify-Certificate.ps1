<#
.SYNOPSIS
    Vérifie l'intégrité d'un certificat émis : hash du manifeste + signature CMS (.p7s).
.EXAMPLE
    .\Verify-Certificate.ps1 -ManifestPath .\certificates\COD-CASE-2026-0042-20260623-101500.manifest.json
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ManifestPath)

Set-StrictMode -Version Latest
try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch {}

if (-not (Test-Path $ManifestPath)) { throw "Manifeste introuvable : $ManifestPath" }

$hash = (Get-FileHash -LiteralPath $ManifestPath -Algorithm SHA256).Hash
Write-Host "SHA-256 du manifeste : $hash" -ForegroundColor Cyan

$sigPath = "$ManifestPath.p7s"
if (Test-Path $sigPath) {
    try {
        $content = [System.IO.File]::ReadAllBytes($ManifestPath)
        $sig     = [System.IO.File]::ReadAllBytes($sigPath)
        $ci      = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,$content)
        $cms     = New-Object System.Security.Cryptography.Pkcs.SignedCms($ci, $true)
        $cms.Decode($sig)
        $cms.CheckSignature($true)   # $true = ne pas exiger la validation complète de la chaîne hors-ligne
        Write-Host "SIGNATURE VALIDE." -ForegroundColor Green
        foreach ($s in $cms.SignerInfos) {
            Write-Host (" Signataire : {0}" -f $s.Certificate.Subject)
            Write-Host (" Empreinte  : {0}" -f $s.Certificate.Thumbprint)
            Write-Host (" Valide jq  : {0}" -f $s.Certificate.NotAfter.ToString('o'))
        }
    } catch {
        Write-Host "SIGNATURE INVALIDE OU ALTÉRÉE : $($_.Exception.Message)" -ForegroundColor Red
    }
} else {
    Write-Warning "Pas de signature .p7s à côté du manifeste."
}

# --- Signature GPG (.asc armor ou .sig binaire) ---
foreach ($ext in 'asc','sig') {
    $gpgSig = "$ManifestPath.$ext"
    if (Test-Path $gpgSig) {
        $gpg = Get-Command gpg -ErrorAction SilentlyContinue
        if (-not $gpg) { Write-Warning "Signature GPG présente ($ext) mais gpg introuvable pour la vérifier."; continue }
        & $gpg.Source --verify $gpgSig $ManifestPath
        if ($LASTEXITCODE -eq 0) { Write-Host "SIGNATURE GPG VALIDE ($ext)." -ForegroundColor Green }
        else { Write-Host "SIGNATURE GPG INVALIDE ($ext)." -ForegroundColor Red }
    }
}

if (Test-Path "$ManifestPath.tsr") {
    Write-Host "Jeton d'horodatage RFC 3161 présent : $ManifestPath.tsr" -ForegroundColor Green
}
