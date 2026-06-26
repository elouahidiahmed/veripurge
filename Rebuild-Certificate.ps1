<#
.SYNOPSIS
    Régénère un certificat (template moderne) à partir d'un manifeste existant,
    avec re-signature, SANS rien re-détruire.

.DESCRIPTION
    Utile pour réémettre le certificat d'une destruction faite par une ancienne
    version : on relit le manifeste (affaire, examinateur, témoin, inventaire +
    empreintes) et on régénère le HTML moderne + une nouvelle signature.

    Les fichiers d'origine ne sont pas modifiés : un NOUVEAU certificat est produit
    (nouveau certificateId/horodatage), couvrant exactement le même inventaire. Les
    horodatages de destruction par fichier (ProcessedUtc) sont conservés tels quels.

.PARAMETER ManifestPath
    Manifeste source (COD-<case>-<ts>.manifest.json).

.PARAMETER Sign
    Méthode de signature du nouveau manifeste : gpg (défaut), cms, both, ou none.

.PARAMETER GpgKeyId
    Clé GPG à utiliser : email, keyid (court/long) ou empreinte. Vide = 1re clé secrète.
    Pour lister vos clés et leurs ID : .\New-SigningCertificate.ps1 -Type GPG

.PARAMETER OutputDir
    Dossier de sortie. Défaut : le dossier du manifeste source.

.EXAMPLE
    # Réémettre en CHOISISSANT explicitement la clé GPG (email ou empreinte) :
    .\Rebuild-Certificate.ps1 -ManifestPath .\COD-...manifest.json -Sign gpg -GpgKeyId elouahidi.ahmed@gmail.com

.EXAMPLE
    # Réémettre signé GPG (1re clé secrète, auto-détectée) :
    .\Rebuild-Certificate.ps1 -ManifestPath 'D:\Purge Evidence\COD-BNC-001-20260625-132908.manifest.json'

.EXAMPLE
    # Signature X.509 par empreinte + horodatage (PowerShell 7) :
    .\Rebuild-Certificate.ps1 -ManifestPath .\COD-...manifest.json -Sign cms -CertThumbprint AB12... -TimestampUrl http://timestamp.digicert.com
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [ValidateSet('gpg','cms','both','none')][string]$Sign = 'gpg',
    [string]$GpgKeyId          = '',
    [string]$CertThumbprint    = '',
    [string]$PfxPath           = '',
    [string]$PfxPasswordEnvVar = '',
    [string]$TimestampUrl      = '',
    [string]$OutputDir
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'modules\Certificate.psm1') -Force

if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "Manifeste introuvable : $ManifestPath" }
$m = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json
if (-not $m.items) { throw "Le manifeste ne contient aucune entrée 'items'." }

if (-not $OutputDir) { $OutputDir = Split-Path -Parent (Resolve-Path -LiteralPath $ManifestPath) }

# Reconstruire les métadonnées depuis le manifeste
$meta = @{
    caseId                      = $m.case.caseId
    evidenceRef                 = $m.case.evidenceRef
    investigationClosedOn       = $m.case.investigationClosedOn
    dispositionAuthorizationRef = $m.case.dispositionAuthorizationRef
    legalHoldActive             = $m.case.legalHoldActive
    standard                    = $m.standard
    examiner                    = $m.examiner
    witness                     = $m.witness
}
$items = @($m.items)
$mode  = if ([string]::IsNullOrWhiteSpace([string]$m.mode)) { 'Destroy' } else { [string]$m.mode }

$signing = @{
    enabled = ($Sign -ne 'none')
    method  = $Sign
    cms = @{ certThumbprint = $CertThumbprint; pfxPath = $PfxPath; pfxPasswordEnvVar = $PfxPasswordEnvVar }
    gpg = @{ keyId = $GpgKeyId; armor = $true }
    timestampUrl = $TimestampUrl
}

Write-Host ("Réémission depuis : {0}" -f $ManifestPath) -ForegroundColor Cyan
Write-Host (" Affaire {0} — {1} élément(s) — mode {2} — signature {3}" -f $meta.caseId, $items.Count, $mode, $Sign)

$cert = New-DispositionCertificate -Meta $meta -Items $items -OutputDir $OutputDir -Mode $mode -Signing $signing

Write-Host ""
Write-Host "================ CERTIFICAT RÉÉMIS ================" -ForegroundColor Green
Write-Host " Nouveau certificat : $($cert.CertificateId)"
Write-Host " Manifeste          : $($cert.ManifestPath)"
Write-Host " SHA-256 manifeste  : $($cert.ManifestSHA256)"
Write-Host " HTML (moderne)     : $($cert.HtmlPath)"
foreach ($s in $cert.Signatures) { Write-Host (" Signé [{0}] : {1}" -f $s.Type, $s.Signer) }
if ($cert.Timestamp) { Write-Host " Horodatage         : $($cert.Timestamp)" }
Write-Host "==================================================" -ForegroundColor Green
Write-Host "Les fichiers d'origine (ancien certificat/manifeste) sont intacts." -ForegroundColor DarkGray
