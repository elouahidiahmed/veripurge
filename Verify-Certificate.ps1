<#
.SYNOPSIS
    Vérifie l'intégrité d'un certificat émis : hash du manifeste + signatures CMS (.p7s)
    et GPG (.asc/.sig) + présence du jeton d'horodatage (.tsr).
.EXAMPLE
    .\Verify-Certificate.ps1 -ManifestPath .\certificates\COD-CASE-2026-0042-20260623-101500.manifest.json
#>
[CmdletBinding()]
param([Parameter(Mandatory)][string]$ManifestPath)

Set-StrictMode -Version Latest
try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch {}
Import-Module (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'modules\Certificate.psm1') -Force

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
$gpgExe = Resolve-GpgCommand
foreach ($ext in 'asc','sig') {
    $gpgSig = "$ManifestPath.$ext"
    if (Test-Path $gpgSig) {
        if (-not $gpgExe) {
            Write-Warning "Signature GPG présente ($ext) mais gpg introuvable. Ouvrez un nouveau terminal après l'install Gpg4win, ou ajoutez '$($env:ProgramFiles)\GnuPG\bin' au PATH."
            continue
        }
        Write-Host "Verification GPG ($ext)..." -ForegroundColor Cyan
        & $gpgExe --verify $gpgSig $ManifestPath 2>&1 | ForEach-Object { Write-Host "  $_" }
        if ($LASTEXITCODE -eq 0) { Write-Host "SIGNATURE GPG VALIDE ($ext)." -ForegroundColor Green }
        else { Write-Host "SIGNATURE GPG INVALIDE ($ext) (gpg exit $LASTEXITCODE). Clé publique du signataire importée ? (gpg --import cle.asc)" -ForegroundColor Red }
    }
}

if (Test-Path "$ManifestPath.tsr") {
    Write-Host "Jeton d'horodatage RFC 3161 présent : $ManifestPath.tsr" -ForegroundColor Green
}
