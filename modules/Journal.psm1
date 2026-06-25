<#
.SYNOPSIS
    Journal de reprise (checkpoint) append-only au format JSONL.

.DESCRIPTION
    Chaque élément traité est écrit IMMÉDIATEMENT (une ligne JSON compacte, flush
    disque) avant de passer au suivant. Si le process est interrompu (Ctrl+C, kill,
    coupure), le journal contient déjà tout ce qui a été fait — y compris les
    empreintes des fichiers DÉJÀ détruits, qu'on ne peut plus recalculer.
    À la relance, le module recharge ce journal pour :
      - ignorer ce qui est déjà terminé avec succès,
      - réessayer les FAILED / READ_ERROR,
      - reconstruire le manifeste complet (runs cumulés).
#>

Set-StrictMode -Version Latest

function Read-DispositionJournal {
    <# Lit un journal JSONL et renvoie un tableau d'objets (tolérant aux lignes corrompues). #>
    [CmdletBinding()]
    param([Parameter(Mandatory)][string]$JournalPath)

    if (-not (Test-Path -LiteralPath $JournalPath)) { return @() }

    $out = New-Object System.Collections.Generic.List[object]
    foreach ($line in [System.IO.File]::ReadAllLines($JournalPath, [System.Text.Encoding]::UTF8)) {
        if ([string]::IsNullOrWhiteSpace($line)) { continue }
        try { $out.Add(($line | ConvertFrom-Json)) }
        catch { Write-Warning "Ligne de journal illisible ignorée (probable interruption en écriture)." }
    }
    return $out.ToArray()
}

function Add-JournalEntry {
    <# Ajoute une entrée (1 ligne JSON compacte) et flush. Crée le fichier au besoin. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$JournalPath,
        [Parameter(Mandatory)][object]$Entry
    )
    $line = ($Entry | ConvertTo-Json -Depth 6 -Compress) + "`n"
    # AppendAllText = UTF-8 sans BOM, ouvre/écrit/ferme => flush OS à chaque appel.
    [System.IO.File]::AppendAllText($JournalPath, $line, (New-Object System.Text.UTF8Encoding($false)))
}

Export-ModuleMember -Function Read-DispositionJournal, Add-JournalEntry
