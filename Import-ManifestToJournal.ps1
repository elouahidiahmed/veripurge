<#
.SYNOPSIS
    Amorce un journal de reprise à partir d'un manifeste déjà émis.

.DESCRIPTION
    Utile pour CONSOLIDER un run antérieur (ex. exécuté avant l'ajout du mécanisme
    de reprise, ou avant un correctif) avec une relance : on rejoue les entrées du
    manifeste dans un journal, puis on relance la MÊME commande de destruction.
    La reprise saute alors les fichiers déjà détruits, réessaie les FAILED, et
    produit UN SEUL certificat consolidé couvrant l'ensemble.

.PARAMETER ManifestPath
    Chemin du manifeste source (COD-<case>-<ts>.manifest.json).

.PARAMETER JournalPath
    Optionnel. Par défaut : <dossier du manifeste>\<caseId>.<mode>.journal.jsonl
    (exactement le chemin attendu par Invoke-Disposition.ps1).

.EXAMPLE
    .\Import-ManifestToJournal.ps1 -ManifestPath 'D:\Purge Evidence\COD-BNC-001-20260625-132908.manifest.json'
    # puis :
    .\Invoke-Disposition.ps1 -ConfigPath .\config.json -Confirm
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)][string]$ManifestPath,
    [string]$JournalPath
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

Import-Module (Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) 'modules\Journal.psm1') -Force

if (-not (Test-Path -LiteralPath $ManifestPath)) { throw "Manifeste introuvable : $ManifestPath" }
$m = Get-Content -Raw -LiteralPath $ManifestPath | ConvertFrom-Json

if (-not $m.items) { throw "Le manifeste ne contient aucune entrée 'items'." }

# Chemin de journal attendu par l'orchestrateur : <outputDir>\<caseId>.<mode>.journal.jsonl
if (-not $JournalPath) {
    $caseId = $m.case.caseId
    $mode   = ([string]$m.mode).ToLower()
    $dir    = Split-Path -Parent (Resolve-Path -LiteralPath $ManifestPath)
    $JournalPath = Join-Path $dir ("{0}.{1}.journal.jsonl" -f $caseId, $mode)
}

if (Test-Path -LiteralPath $JournalPath) {
    throw "Un journal existe déjà ($JournalPath). Supprimez-le ou choisissez -JournalPath pour éviter les doublons."
}

$items = @($m.items)
$ok    = @($items | Where-Object { $_.Status -in 'DESTROYED','DELETED','PREVIEW' }).Count
$retry = @($items | Where-Object { $_.Status -in 'FAILED','READ_ERROR' }).Count

foreach ($it in $items) { Add-JournalEntry -JournalPath $JournalPath -Entry $it }

Write-Host "Journal amorcé : $JournalPath" -ForegroundColor Green
Write-Host (" {0} entrée(s) importée(s) — {1} déjà OK (seront ignorées), {2} à réessayer." -f $items.Count, $ok, $retry) -ForegroundColor Cyan
Write-Host " Relancez maintenant la MÊME commande de destruction pour consolider :" -ForegroundColor Yellow
Write-Host "   .\Invoke-Disposition.ps1 -ConfigPath .\config.json -Confirm" -ForegroundColor Yellow
