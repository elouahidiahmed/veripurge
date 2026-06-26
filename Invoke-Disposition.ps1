<#
.SYNOPSIS
    DFIR Disposer — Sanitization de preuves (poste Windows + SharePoint Online)
    avec génération automatique du Certificate of Destruction (manifeste signé).

.DESCRIPTION
    SAFE-BY-DEFAULT : sans -Confirm, le script tourne en mode PREVIEW
    (calcul des empreintes + certificat de revue, AUCUNE destruction).
    La destruction réelle exige -Confirm ET la saisie du mot "DETRUIRE".

.PARAMETER ConfigPath
    Chemin du fichier de configuration JSON (voir config.example.json).

.PARAMETER Confirm
    Active le mode DESTROY (destruction irréversible).

.EXAMPLE
    # 1) Revue à blanc (recommandé d'abord) :
    .\Invoke-Disposition.ps1 -ConfigPath .\config.json

    # 2) Destruction réelle :
    .\Invoke-Disposition.ps1 -ConfigPath .\config.json -Confirm

.NOTES
    Lancez PowerShell EN ADMINISTRATEUR pour la partie locale.
    Standard de référence : NIST SP 800-88 Rev.1.
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ConfigPath,
    [switch]$Confirm
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$here = Split-Path -Parent $MyInvocation.MyCommand.Path
Import-Module (Join-Path $here 'modules\LocalSanitize.psm1')       -Force
Import-Module (Join-Path $here 'modules\SharePointSanitize.psm1')  -Force
Import-Module (Join-Path $here 'modules\Certificate.psm1')         -Force
Import-Module (Join-Path $here 'modules\Journal.psm1')             -Force

# --- Chargement config ---
if (-not (Test-Path $ConfigPath)) { throw "Config introuvable : $ConfigPath" }
$cfg = Get-Content -Raw -Path $ConfigPath | ConvertFrom-Json

# --- Garde-fous juridiques ---
if ($cfg.legalHoldActive -eq $true) {
    throw "ARRÊT : legalHoldActive = true. Destruction interdite tant qu'un legal hold est actif."
}
if ([string]::IsNullOrWhiteSpace($cfg.dispositionAuthorizationRef)) {
    throw "ARRÊT : aucune autorisation de destruction (dispositionAuthorizationRef) renseignée."
}

# --- Détermination du mode ---
$mode = 'Preview'
if ($Confirm) {
    Write-Host ""
    Write-Host "================ DESTRUCTION IRRÉVERSIBLE ================" -ForegroundColor Red
    Write-Host " Affaire : $($cfg.caseId)   Scellé : $($cfg.evidenceRef)" -ForegroundColor Red
    Write-Host " Cibles locales   : $([string]::Join(', ', $cfg.local.paths))" -ForegroundColor Red
    if ($cfg.sharepoint.enabled) {
        Write-Host " Cibles SharePoint: $($cfg.sharepoint.siteUrl) :: $([string]::Join(', ', $cfg.sharepoint.folders))" -ForegroundColor Red
    }
    Write-Host "=========================================================" -ForegroundColor Red
    $answer = Read-Host "Tapez exactement DETRUIRE pour confirmer (sinon Entrée pour annuler)"
    if ($answer -ne 'DETRUIRE') { Write-Host "Annulé. Aucune donnée touchée." -ForegroundColor Yellow; return }
    $mode = 'Destroy'
}
else {
    Write-Host "[MODE PREVIEW] Aucune destruction. Empreintes + certificat de revue uniquement." -ForegroundColor Yellow
}

# --- Sécurité : outputDir NE DOIT PAS être dans une cible locale (sinon on détruit nos preuves) ---
if ($cfg.local.enabled) {
    $oNorm = [System.IO.Path]::GetFullPath($cfg.outputDir).TrimEnd('\')
    foreach ($p in $cfg.local.paths) {
        $pNorm = [System.IO.Path]::GetFullPath($p).TrimEnd('\')
        if ($oNorm.Equals($pNorm, [System.StringComparison]::OrdinalIgnoreCase) -or
            $oNorm.StartsWith($pNorm + '\', [System.StringComparison]::OrdinalIgnoreCase)) {
            throw "ARRÊT : outputDir ($oNorm) est à l'intérieur d'une cible locale ($pNorm) — le certificat et le journal seraient détruits. Placez outputDir en dehors des chemins à assainir."
        }
    }
}

# --- Journal de reprise (checkpoint incrémental, propre au couple affaire+mode) ---
if (-not (Test-Path $cfg.outputDir)) { New-Item -ItemType Directory -Path $cfg.outputDir -Force | Out-Null }
$journalPath = Join-Path $cfg.outputDir ("{0}.{1}.journal.jsonl" -f $cfg.caseId, $mode.ToLower())
if (Test-Path $journalPath) {
    $prior = @(Read-DispositionJournal -JournalPath $journalPath)
    $pOk   = @($prior | Where-Object { $_.Status -in 'DESTROYED','DELETED','PREVIEW' }).Count
    $pFail = @($prior | Where-Object { $_.Status -in 'FAILED','READ_ERROR' }).Count
    Write-Host ("[REPRISE] Journal existant : {0} entree(s) - {1} ok, {2} a reessayer." -f $prior.Count, $pOk, $pFail) -ForegroundColor Cyan
}

$allItems = New-Object System.Collections.Generic.List[object]

# --- 1) Sanitization locale ---
if ($cfg.local.enabled) {
    $localItems = Invoke-LocalSanitization `
        -Paths $cfg.local.paths `
        -Passes $cfg.local.passes `
        -Mode $mode `
        -WipeFreeSpace:([bool]$cfg.local.wipeFreeSpace) `
        -JournalPath $journalPath
    $localItems | ForEach-Object { $allItems.Add($_) }
}

# --- 2) Sanitization SharePoint ---
if ($cfg.sharepoint.enabled) {
    $spoAuth  = $cfg.sharepoint.auth
    $spoUser  = if ($spoAuth.PSObject.Properties['username'])       { $spoAuth.username }       else { '' }
    $spoPwEnv = if ($spoAuth.PSObject.Properties['passwordEnvVar']) { $spoAuth.passwordEnvVar } else { '' }
    Connect-DisposerSharePoint `
        -SiteUrl $cfg.sharepoint.siteUrl `
        -Mode $spoAuth.mode `
        -ClientId $spoAuth.clientId `
        -Tenant $spoAuth.tenant `
        -Thumbprint $spoAuth.thumbprint `
        -Username $spoUser `
        -PasswordEnvVar $spoPwEnv

    $spoItems = Invoke-SharePointSanitization `
        -Folders $cfg.sharepoint.folders `
        -Mode $mode `
        -HashBeforeDelete ([bool]$cfg.sharepoint.hashBeforeDelete) `
        -PurgeRecycleBin ([bool]$cfg.sharepoint.purgeRecycleBin) `
        -JournalPath $journalPath
    $spoItems | ForEach-Object { $allItems.Add($_) }

    try { Disconnect-PnPOnline } catch {}
}

# --- 3) Certificat ---
$meta = @{
    caseId                      = $cfg.caseId
    evidenceRef                 = $cfg.evidenceRef
    investigationClosedOn       = $cfg.investigationClosedOn
    dispositionAuthorizationRef = $cfg.dispositionAuthorizationRef
    legalHoldActive             = $cfg.legalHoldActive
    standard                    = $cfg.standard
    examiner                    = $cfg.examiner
    witness                     = $cfg.witness
}

$signing = @{
    enabled = [bool]$cfg.signing.enabled
    method  = $cfg.signing.method          # "cms" | "gpg" | "both"
    cms = @{
        certThumbprint    = $cfg.signing.cms.certThumbprint
        pfxPath           = $cfg.signing.cms.pfxPath
        pfxPasswordEnvVar = $cfg.signing.cms.pfxPasswordEnvVar
    }
    gpg = @{
        keyId = $cfg.signing.gpg.keyId
        armor = $cfg.signing.gpg.armor
    }
    timestampUrl = $cfg.signing.timestampUrl
}

$cert = New-DispositionCertificate `
    -Meta $meta `
    -Items $allItems.ToArray() `
    -OutputDir $cfg.outputDir `
    -Mode $mode `
    -Signing $signing

Write-Host ""
Write-Host "================== TERMINÉ ($mode) ==================" -ForegroundColor Green
Write-Host " Certificat   : $($cert.CertificateId)"
Write-Host " Manifeste    : $($cert.ManifestPath)"
Write-Host " SHA-256 man. : $($cert.ManifestSHA256)"
Write-Host " HTML         : $($cert.HtmlPath)"
foreach ($s in $cert.Signatures) { Write-Host (" Signé [{0}] : {1}" -f $s.Type, $s.Signer) }
if ($cert.Timestamp) { Write-Host " Horodatage   : $($cert.Timestamp)" }
Write-Host "====================================================" -ForegroundColor Green
if ($mode -eq 'Preview') {
    Write-Host "Revoyez le manifeste, puis relancez avec -Confirm pour détruire." -ForegroundColor Yellow
}

# --- Reprise : archiver le journal si tout est terminé, sinon le conserver pour relance ---
$openFailures = @($allItems | Where-Object { $_.Status -in 'FAILED','READ_ERROR' }).Count
if (Test-Path $journalPath) {
    if ($openFailures -eq 0) {
        $archived = Join-Path $cfg.outputDir ("{0}.journal.jsonl" -f $cert.CertificateId)
        Move-Item -LiteralPath $journalPath -Destination $archived -Force
        Write-Host " Journal archivé : $archived" -ForegroundColor Green
    } else {
        Write-Host (" {0} élément(s) en échec. Relancez la MÊME commande pour reprendre/retenter (journal conservé : {1})." -f $openFailures, $journalPath) -ForegroundColor Yellow
    }
}
