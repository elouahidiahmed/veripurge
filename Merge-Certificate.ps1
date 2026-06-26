<#
.SYNOPSIS
    Fusionne 2 manifestes (ou plus) en UN certificat consolidé, sans rien re-détruire.

.DESCRIPTION
    Relit chaque manifeste, réunit les inventaires et dédoublonne par (Source + chemin) :
    en cas de doublon, le meilleur statut l'emporte (DESTROYED/DELETED > PREVIEW > FAILED),
    départage par ProcessedUtc le plus récent. Émet ensuite un nouveau certificat moderne
    (nouveau certificateId) signé avec votre clé. Les manifestes d'origine restent intacts.

.PARAMETER ManifestPath
    Au moins 2 manifestes source (COD-<case>-<ts>.manifest.json).

.PARAMETER Sign
    Signature du certificat fusionné : gpg (défaut), cms, both, ou none.

.PARAMETER GpgKeyId
    Clé GPG (email / keyid / empreinte). Vide = 1re clé secrète.

.PARAMETER OutputDir
    Dossier de sortie. Défaut : le dossier du 1er manifeste.

.EXAMPLE
    .\Merge-Certificate.ps1 -ManifestPath .\COD-BNC-001-A.manifest.json, .\COD-BNC-001-B.manifest.json -Sign gpg
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string[]]$ManifestPath,
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

if (@($ManifestPath).Count -lt 2) {
    throw "Fournissez au moins 2 manifestes (séparés par une virgule). Pour un seul, utilisez Rebuild-Certificate.ps1."
}

function Get-StatusRank([string]$s) {
    switch ($s) { 'DESTROYED' { 3 } 'DELETED' { 3 } 'PREVIEW' { 2 } default { 1 } }
}

$manifests = @()
$allItems  = New-Object System.Collections.Generic.List[object]
foreach ($mp in $ManifestPath) {
    if (-not (Test-Path -LiteralPath $mp)) { throw "Manifeste introuvable : $mp" }
    $m = Get-Content -Raw -LiteralPath $mp | ConvertFrom-Json
    if (-not $m.items) { throw "Le manifeste ne contient aucune entrée 'items' : $mp" }
    $manifests += $m
    foreach ($it in @($m.items)) { $allItems.Add($it) }
    Write-Host (" + {0} : {1} élément(s) [{2}]" -f (Split-Path $mp -Leaf), @($m.items).Count, $m.case.caseId) -ForegroundColor DarkCyan
}

# Cohérence d'affaire (avertissement seulement)
$caseIds = @($manifests | ForEach-Object { [string]$_.case.caseId } | Sort-Object -Unique)
if ($caseIds.Count -gt 1) {
    Write-Warning ("Affaires différentes fusionnées : {0}. L'en-tête utilisera celle du 1er manifeste." -f ($caseIds -join ', '))
}

# Dédoublonnage par (Source|Path), meilleur statut puis ProcessedUtc le plus récent
$byKey = [ordered]@{}
$dups  = 0
foreach ($it in $allItems) {
    $key = "{0}|{1}" -f $it.Source, $it.Path
    if (-not $byKey.Contains($key)) {
        $byKey[$key] = $it
    } else {
        $dups++
        $cur = $byKey[$key]
        $rNew = Get-StatusRank ([string]$it.Status)
        $rCur = Get-StatusRank ([string]$cur.Status)
        if ($rNew -gt $rCur) { $byKey[$key] = $it }
        elseif ($rNew -eq $rCur -and ([string]$it.ProcessedUtc -gt [string]$cur.ProcessedUtc)) { $byKey[$key] = $it }
    }
}
$merged = @($byKey.Values)

# Métadonnées depuis le 1er manifeste ; mode = Destroy si l'un des deux l'est
$base = $manifests[0]
$mode = if (@($manifests | Where-Object { [string]$_.mode -eq 'Destroy' }).Count -gt 0) { 'Destroy' } else { [string]$base.mode }
if ([string]::IsNullOrWhiteSpace($mode)) { $mode = 'Destroy' }

$meta = @{
    caseId                      = $base.case.caseId
    evidenceRef                 = $base.case.evidenceRef
    investigationClosedOn       = $base.case.investigationClosedOn
    dispositionAuthorizationRef = $base.case.dispositionAuthorizationRef
    legalHoldActive             = $base.case.legalHoldActive
    standard                    = $base.standard
    examiner                    = $base.examiner
    witness                     = $base.witness
}

$signing = @{
    enabled = ($Sign -ne 'none')
    method  = $Sign
    cms = @{ certThumbprint = $CertThumbprint; pfxPath = $PfxPath; pfxPasswordEnvVar = $PfxPasswordEnvVar }
    gpg = @{ keyId = $GpgKeyId; armor = $true }
    timestampUrl = $TimestampUrl
}

if (-not $OutputDir) { $OutputDir = Split-Path -Parent (Resolve-Path -LiteralPath $ManifestPath[0]) }

Write-Host ("`nFusion : {0} manifeste(s) -> {1} élément(s) uniques ({2} doublon(s) résolu(s))." -f @($manifests).Count, $merged.Count, $dups) -ForegroundColor Cyan

$cert = New-DispositionCertificate -Meta $meta -Items $merged -OutputDir $OutputDir -Mode $mode -Signing $signing

Write-Host ""
Write-Host "================ CERTIFICAT FUSIONNÉ ================" -ForegroundColor Green
Write-Host " Nouveau certificat : $($cert.CertificateId)"
Write-Host " Manifeste          : $($cert.ManifestPath)"
Write-Host " SHA-256 manifeste  : $($cert.ManifestSHA256)"
Write-Host " HTML (moderne)     : $($cert.HtmlPath)"
Write-Host (" Sources fusionnées : {0}" -f (($manifests | ForEach-Object { $_.certificateId }) -join ', '))
foreach ($s in $cert.Signatures) { Write-Host (" Signé [{0}] : {1}" -f $s.Type, $s.Signer) }
if ($cert.Timestamp) { Write-Host " Horodatage         : $($cert.Timestamp)" }
Write-Host "====================================================" -ForegroundColor Green
Write-Host "Les manifestes d'origine sont intacts." -ForegroundColor DarkGray
