<#
.SYNOPSIS
    Aide à la création / au repérage d'une clé de signature pour DFIR Disposer.

.DESCRIPTION
    -Type X509 : génère un certificat de signature AUTO-SIGNÉ dans Cert:\CurrentUser\My
                 et affiche le thumbprint à coller dans config.json (signing.cms.certThumbprint).
                 (Pour un usage opposable, préférez un cert émis par la PKI de votre organisation.)
    -Type GPG  : ne génère rien (gpg --gen-key est interactif) mais LISTE vos clés secrètes
                 et indique le keyId à mettre dans config.json (signing.gpg.keyId).

.EXAMPLE
    .\New-SigningCertificate.ps1 -Type X509 -Subject "CN=DFIR Evidence Disposer"
.EXAMPLE
    .\New-SigningCertificate.ps1 -Type GPG
#>
[CmdletBinding()]
param(
    [ValidateSet('X509','GPG')][string]$Type = 'X509',
    [string]$Subject = 'CN=DFIR Evidence Disposer',
    [int]$Years = 5
)

Set-StrictMode -Version Latest

if ($Type -eq 'X509') {
    $cert = New-SelfSignedCertificate `
                -Subject $Subject `
                -Type Custom `
                -KeyUsage DigitalSignature `
                -KeyExportPolicy Exportable `
                -CertStoreLocation 'Cert:\CurrentUser\My' `
                -NotAfter (Get-Date).AddYears($Years)

    Write-Host "Certificat X.509 auto-signé créé." -ForegroundColor Green
    Write-Host (" Sujet      : {0}" -f $cert.Subject)
    Write-Host (" Thumbprint : {0}" -f $cert.Thumbprint) -ForegroundColor Cyan
    Write-Host (" Expire le  : {0}" -f $cert.NotAfter.ToString('o'))
    Write-Host ""
    Write-Host "-> config.json : signing.method='cms', signing.cms.certThumbprint = '$($cert.Thumbprint)'" -ForegroundColor Yellow
    Write-Host "   (Sauvegardez/exportez la clé privée hors du poste : Export-PfxCertificate)" -ForegroundColor Yellow
}
else {
    $gpg = Get-Command gpg -ErrorAction SilentlyContinue
    if (-not $gpg) { throw "gpg introuvable. Installez Gpg4win (https://gpg4win.org), puis rouvrez la session." }

    Write-Host "Clés secrètes GPG disponibles :" -ForegroundColor Green
    & $gpg.Source --list-secret-keys --keyid-format long
    Write-Host ""
    Write-Host "Pas de clé ? Créez-en une (interactif) :" -ForegroundColor Yellow
    Write-Host "   gpg --full-generate-key" -ForegroundColor Yellow
    Write-Host "-> config.json : signing.method='gpg', signing.gpg.keyId = '<votre email ou fingerprint>'" -ForegroundColor Yellow
}
