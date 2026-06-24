<#
.SYNOPSIS
    Génération du Certificate of Destruction : manifeste JSON + certificat HTML,
    scellement par hash, signature numérique PKCS#7 (détachée) et horodatage RFC 3161 optionnel.
#>

Set-StrictMode -Version Latest

function Add-CmsSignature {
    <# Signature PKCS#7/CMS détachée (.p7s) d'un fichier, via cert du magasin ou PFX. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$Thumbprint,
        [string]$PfxPath,
        [System.Security.SecureString]$PfxPassword
    )

    # Les types CMS (ContentInfo/SignedCms/CmsSigner) vivent dans System.Security,
    # non chargé par défaut sous Windows PowerShell 5.1.
    try { Add-Type -AssemblyName System.Security -ErrorAction Stop } catch {}

    $cert = $null
    if ($PfxPath) {
        $cert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($PfxPath, $PfxPassword)
    }
    elseif ($Thumbprint) {
        $cert = Get-Item -Path ("Cert:\CurrentUser\My\{0}" -f ($Thumbprint -replace '\s','')) -ErrorAction SilentlyContinue
        if (-not $cert) {
            $cert = Get-Item -Path ("Cert:\LocalMachine\My\{0}" -f ($Thumbprint -replace '\s','')) -ErrorAction Stop
        }
    }
    else { throw "Signature : fournir -Thumbprint ou -PfxPath." }

    $content = [System.IO.File]::ReadAllBytes($FilePath)
    $ci      = New-Object System.Security.Cryptography.Pkcs.ContentInfo (,$content)
    $cms     = New-Object System.Security.Cryptography.Pkcs.SignedCms($ci, $true)  # $true = détaché
    $signer  = New-Object System.Security.Cryptography.Pkcs.CmsSigner($cert)
    $signer.IncludeOption = [System.Security.Cryptography.X509Certificates.X509IncludeOption]::WholeChain
    $cms.ComputeSignature($signer)

    $sigPath = "$FilePath.p7s"
    [System.IO.File]::WriteAllBytes($sigPath, $cms.Encode())
    Write-Host "[SIGN] Signature CMS écrite : $sigPath" -ForegroundColor Green
    return [pscustomobject]@{
        Type          = 'CMS-X509'
        SignaturePath = $sigPath
        Signer        = $cert.Subject
        Thumbprint    = $cert.Thumbprint
        NotAfter      = $cert.NotAfter.ToString('o')
    }
}

function Add-GpgSignature {
    <# Signature GPG/OpenPGP détachée (.asc en ASCII-armor, sinon .sig binaire). #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$KeyId,
        [switch]$Armor
    )

    $gpg = Get-Command gpg -ErrorAction SilentlyContinue
    if (-not $gpg) { throw "gpg introuvable dans le PATH (installez Gpg4win, puis rouvrez la session)." }

    $ext     = if ($Armor) { 'asc' } else { 'sig' }
    $sigPath = "$FilePath.$ext"
    if (Test-Path $sigPath) { Remove-Item -LiteralPath $sigPath -Force }

    $gpgArgs = @('--batch','--yes','--detach-sign')
    if ($Armor)  { $gpgArgs += '--armor' }
    if ($KeyId)  { $gpgArgs += @('--local-user', $KeyId) }
    $gpgArgs += @('--output', $sigPath, $FilePath)

    & $gpg.Source @gpgArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $sigPath)) {
        throw "gpg a échoué (exit $LASTEXITCODE). Vérifiez que la clé secrète '$KeyId' existe."
    }

    # Empreinte de la clé signataire (pour traçabilité dans le certificat)
    $fpr = $null
    try {
        $out = & $gpg.Source --list-keys --with-colons $KeyId 2>$null
        $fprLine = ($out | Select-String '^fpr:') | Select-Object -First 1
        if ($fprLine) { $fpr = ($fprLine.ToString() -split ':')[9] }
    } catch {}

    Write-Host "[SIGN] Signature GPG écrite : $sigPath" -ForegroundColor Green
    return [pscustomobject]@{
        Type          = 'GPG'
        SignaturePath = $sigPath
        Signer        = $KeyId
        Thumbprint    = $fpr
        NotAfter      = $null
    }
}

function Add-Rfc3161Timestamp {
    <# Horodatage qualifié RFC 3161 (preuve d'antériorité). Nécessite PowerShell 7+. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [Parameter(Mandatory)][string]$TimestampUrl
    )
    $hasRfc = ('System.Security.Cryptography.Pkcs.Rfc3161TimestampRequest' -as [type])
    if (-not $hasRfc) {
        Write-Warning "[TS] Rfc3161TimestampRequest indisponible (PowerShell 5.1). Horodatage ignoré — utilisez PowerShell 7+."
        return $null
    }
    try {
        $bytes  = [System.IO.File]::ReadAllBytes($FilePath)
        $sha    = [System.Security.Cryptography.SHA256]::Create()
        $digest = $sha.ComputeHash($bytes); $sha.Dispose()

        $req = [System.Security.Cryptography.Pkcs.Rfc3161TimestampRequest]::CreateFromHash(
                    $digest, [System.Security.Cryptography.HashAlgorithmName]::SHA256, $null, $null, $true)
        $body = $req.Encode()

        $resp = Invoke-WebRequest -Uri $TimestampUrl -Method Post -Body $body `
                    -ContentType 'application/timestamp-query' -UseBasicParsing -ErrorAction Stop
        $tsPath = "$FilePath.tsr"
        [System.IO.File]::WriteAllBytes($tsPath, $resp.Content)
        Write-Host "[TS] Jeton d'horodatage écrit : $tsPath" -ForegroundColor Green
        return $tsPath
    } catch {
        Write-Warning "[TS] Horodatage échoué : $($_.Exception.Message)"
        return $null
    }
}

function New-DispositionCertificate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][hashtable]$Meta,        # caseId, examiner, witness, standard, ...
        [Parameter(Mandatory)][object[]]$Items,        # entrées de manifeste
        [Parameter(Mandatory)][string]$OutputDir,
        [string]$Mode = 'Preview',
        [hashtable]$Signing
    )

    if (-not (Test-Path $OutputDir)) { New-Item -ItemType Directory -Path $OutputDir -Force | Out-Null }

    $certId   = "COD-{0}-{1}" -f $Meta.caseId, (Get-Date -Format 'yyyyMMdd-HHmmss')
    $nowUtc   = (Get-Date).ToUniversalTime().ToString('o')
    $total    = @($Items).Count
    $destroyed= @($Items | Where-Object { $_.Status -in 'DESTROYED','DELETED' }).Count
    $failed   = @($Items | Where-Object { $_.Status -eq 'FAILED' }).Count

    $record = [ordered]@{
        certificateId   = $certId
        certificateType = 'Certificate of Destruction / Sanitization Record'
        generatedUtc    = $nowUtc
        mode            = $Mode
        case = [ordered]@{
            caseId                       = $Meta.caseId
            evidenceRef                  = $Meta.evidenceRef
            investigationClosedOn        = $Meta.investigationClosedOn
            dispositionAuthorizationRef  = $Meta.dispositionAuthorizationRef
            legalHoldActive              = $Meta.legalHoldActive
        }
        standard = $Meta.standard
        examiner = $Meta.examiner
        witness  = $Meta.witness
        host     = [ordered]@{
            computer = $env:COMPUTERNAME
            operator = $env:USERNAME
            psVersion= $PSVersionTable.PSVersion.ToString()
        }
        summary = [ordered]@{
            totalItems = $total; destroyed = $destroyed; failed = $failed
        }
        items = $Items
    }

    # --- Manifeste JSON (source de vérité, scellée par son propre hash) ---
    $jsonPath = Join-Path $OutputDir "$certId.manifest.json"
    ($record | ConvertTo-Json -Depth 12) | Set-Content -Path $jsonPath -Encoding UTF8
    $manifestHash = (Get-FileHash -LiteralPath $jsonPath -Algorithm SHA256).Hash

    # --- Certificat HTML lisible ---
    $enc = {
        param($s)
        if ($null -eq $s) { return '' }
        ([string]$s).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
    }
    $rows = ($Items | ForEach-Object {
        "<tr><td>{0}</td><td class='m'>{1}</td><td class='r'>{2}</td><td class='m'>{3}</td><td>{4}</td><td class='{5}'>{6}</td></tr>" -f `
            (& $enc $_.Source), (& $enc $_.Path), $_.SizeBytes, (& $enc $_.SHA256), `
            (& $enc $_.Method), ($_.Status.ToLower()), $_.Status
    }) -join "`n"

    $modeBanner = if ($Mode -eq 'Preview') {
        "<div class='warn'>MODE PREVIEW — aucune donnée détruite. Document de revue uniquement.</div>"
    } else { '' }

    $examinerLine = "{0} - {1} ({2})" -f $Meta.examiner.name, $Meta.examiner.role, $Meta.examiner.org
    $witnessLine  = "{0} - {1} ({2})" -f $Meta.witness.name,  $Meta.witness.role,  $Meta.witness.org

    $tpl = @'
<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<title>@@CERTID@@</title>
<style>
 body{font-family:Segoe UI,Arial,sans-serif;margin:32px;color:#1a1a1a}
 h1{font-size:20px;border-bottom:3px solid #1a1a1a;padding-bottom:8px}
 h2{font-size:14px;margin-top:24px;color:#444}
 table{border-collapse:collapse;width:100%;font-size:11px;margin-top:8px}
 th,td{border:1px solid #ccc;padding:4px 6px;text-align:left;vertical-align:top}
 th{background:#f0f0f0}
 .m{font-family:Consolas,monospace;font-size:10px;word-break:break-all}
 .r{text-align:right}
 .destroyed,.deleted{color:#0a7d28;font-weight:bold}
 .failed{color:#c00;font-weight:bold}
 .preview{color:#a60}
 .meta td{border:none;padding:2px 8px}
 .meta td:first-child{font-weight:bold;width:240px}
 .warn{background:#fff3cd;border:1px solid #e0a800;padding:8px;margin:12px 0;font-weight:bold}
 .seal{margin-top:24px;background:#f7f7f7;border:1px dashed #888;padding:12px;font-family:Consolas,monospace;font-size:11px;word-break:break-all}
 .sig{margin-top:32px;display:flex;gap:48px}
 .sig div{flex:1;border-top:1px solid #000;padding-top:6px;font-size:12px}
</style></head><body>
<h1>CERTIFICATE OF DESTRUCTION - @@CERTID@@</h1>
@@MODEBANNER@@
<table class="meta">
 <tr><td>Affaire (Case ID)</td><td>@@CASEID@@</td></tr>
 <tr><td>Reference scelle</td><td>@@EVIDENCEREF@@</td></tr>
 <tr><td>Enquete cloturee le</td><td>@@CLOSEDON@@</td></tr>
 <tr><td>Autorisation de destruction</td><td>@@AUTHREF@@</td></tr>
 <tr><td>Legal hold actif</td><td>@@LEGALHOLD@@</td></tr>
 <tr><td>Norme appliquee</td><td>@@STANDARD@@</td></tr>
 <tr><td>Examinateur</td><td>@@EXAMINER@@</td></tr>
 <tr><td>Temoin</td><td>@@WITNESS@@</td></tr>
 <tr><td>Poste / operateur</td><td>@@HOST@@</td></tr>
 <tr><td>Genere le (UTC)</td><td>@@NOWUTC@@</td></tr>
 <tr><td>Bilan</td><td>@@TOTAL@@ element(s) - detruits : @@DESTROYED@@ - echecs : @@FAILED@@</td></tr>
</table>

<h2>Inventaire des preuves traitees (empreintes relevees AVANT destruction)</h2>
<table>
 <tr><th>Source</th><th>Chemin</th><th>Octets</th><th>SHA-256</th><th>Methode</th><th>Statut</th></tr>
 @@ROWS@@
</table>

<div class="seal">
 SCEAU D'INTEGRITE<br>
 Manifeste JSON : @@CERTID@@.manifest.json<br>
 SHA-256 du manifeste : @@MANIFESTHASH@@<br>
 La preuve de "ce qui" a ete detruit repose sur les empreintes ci-dessus ;
 la preuve "que" cela a ete detruit repose sur ce certificat signe/horodate.
</div>

<div class="sig">
 <div>Examinateur - signature &amp; date<br><br>@@EXAMINERNAME@@</div>
 <div>Temoin - signature &amp; date<br><br>@@WITNESSNAME@@</div>
</div>
</body></html>
'@

    $html = $tpl.
        Replace('@@CERTID@@',       [string]$certId).
        Replace('@@MODEBANNER@@',   [string]$modeBanner).
        Replace('@@CASEID@@',       [string]$Meta.caseId).
        Replace('@@EVIDENCEREF@@',  [string]$Meta.evidenceRef).
        Replace('@@CLOSEDON@@',     [string]$Meta.investigationClosedOn).
        Replace('@@AUTHREF@@',      [string]$Meta.dispositionAuthorizationRef).
        Replace('@@LEGALHOLD@@',    [string]$Meta.legalHoldActive).
        Replace('@@STANDARD@@',     [string]$Meta.standard).
        Replace('@@EXAMINER@@',     [string]$examinerLine).
        Replace('@@WITNESS@@',      [string]$witnessLine).
        Replace('@@HOST@@',         ("{0} / {1}" -f $env:COMPUTERNAME, $env:USERNAME)).
        Replace('@@NOWUTC@@',       [string]$nowUtc).
        Replace('@@TOTAL@@',        [string]$total).
        Replace('@@DESTROYED@@',    [string]$destroyed).
        Replace('@@FAILED@@',       [string]$failed).
        Replace('@@ROWS@@',         [string]$rows).
        Replace('@@MANIFESTHASH@@', [string]$manifestHash).
        Replace('@@EXAMINERNAME@@', [string]$Meta.examiner.name).
        Replace('@@WITNESSNAME@@',  [string]$Meta.witness.name)

    $htmlPath = Join-Path $OutputDir "$certId.certificate.html"
    $html | Set-Content -Path $htmlPath -Encoding UTF8

    # --- Scellement cryptographique : signature(s) + horodatage du MANIFESTE ---
    $signatures = @(); $tsPath = $null
    if ($Signing -and $Signing.enabled) {
        $method = ([string]$Signing.method).ToLower()
        if (-not $method) { $method = 'cms' }

        if ($method -in 'cms','both') {
            try {
                # Mot de passe PFX lu depuis une variable d'environnement (jamais en clair dans la config).
                $pwd = $null
                if ($Signing.cms.pfxPasswordEnvVar) {
                    $raw = [Environment]::GetEnvironmentVariable([string]$Signing.cms.pfxPasswordEnvVar)
                    if ($raw) { $pwd = ConvertTo-SecureString $raw -AsPlainText -Force }
                }
                $signatures += Add-CmsSignature -FilePath $jsonPath `
                                -Thumbprint $Signing.cms.certThumbprint `
                                -PfxPath    $Signing.cms.pfxPath `
                                -PfxPassword $pwd
            } catch { Write-Warning "Signature CMS non appliquée : $($_.Exception.Message)" }
        }

        if ($method -in 'gpg','both') {
            try {
                $signatures += Add-GpgSignature -FilePath $jsonPath `
                                -KeyId $Signing.gpg.keyId `
                                -Armor:([bool]$Signing.gpg.armor)
            } catch { Write-Warning "Signature GPG non appliquée : $($_.Exception.Message)" }
        }

        if ($Signing.timestampUrl) {
            $tsPath = Add-Rfc3161Timestamp -FilePath $jsonPath -TimestampUrl $Signing.timestampUrl
        }
    }

    [pscustomobject]@{
        CertificateId = $certId
        ManifestPath  = $jsonPath
        ManifestSHA256= $manifestHash
        HtmlPath      = $htmlPath
        Signatures    = $signatures
        Timestamp     = $tsPath
    }
}

Export-ModuleMember -Function Add-CmsSignature, Add-GpgSignature, Add-Rfc3161Timestamp, New-DispositionCertificate
