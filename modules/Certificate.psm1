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
    <# Signature GPG/OpenPGP détachée (.asc en ASCII-armor, sinon .sig binaire).
       -KeyId : email / keyid / empreinte de la clé SECRÈTE à utiliser. Vide = 1re clé.
       Erreur explicite (avec la liste des clés) si l'identifiant demandé est introuvable. #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$FilePath,
        [string]$KeyId,
        [switch]$Armor
    )

    $gpg = Get-Command gpg -ErrorAction SilentlyContinue
    if (-not $gpg) { throw "gpg introuvable dans le PATH (installez Gpg4win, puis rouvrez la session)." }

    # --- Résolution de la clé secrète (filtrée par -KeyId si fourni, sinon la 1re) ---
    $secArgs = @('--list-secret-keys','--with-colons')
    if ($KeyId) { $secArgs += $KeyId }
    $secOut = & $gpg.Source @secArgs 2>$null
    if (-not $secOut) {
        $avail = (& $gpg.Source --list-secret-keys --keyid-format long 2>$null) -join [Environment]::NewLine
        throw "Clé secrète GPG introuvable pour '$KeyId'. Clés disponibles :`n$avail"
    }
    $fpr = $null; $signerUid = $null
    foreach ($l in $secOut) {
        $p = $l -split ':'
        if (-not $fpr       -and $p[0] -eq 'fpr') { $fpr = $p[9] }       # empreinte primaire
        if (-not $signerUid -and $p[0] -eq 'uid') { $signerUid = $p[9] } # "Nom <email>"
    }
    if (-not $fpr) { throw "Aucune clé secrète GPG. Créez-en une : gpg --full-generate-key" }
    if (-not $signerUid) { $signerUid = $fpr }
    Write-Host ("[SIGN] Clé GPG : {0} ({1})" -f $signerUid, $fpr) -ForegroundColor DarkCyan

    $ext     = if ($Armor) { 'asc' } else { 'sig' }
    $sigPath = "$FilePath.$ext"
    if (Test-Path $sigPath) { Remove-Item -LiteralPath $sigPath -Force }

    # --local-user = empreinte : la clé utilisée == la clé reportée (déterministe).
    $gpgArgs = @('--batch','--yes','--detach-sign','--local-user', $fpr)
    if ($Armor) { $gpgArgs += '--armor' }
    $gpgArgs += @('--output', $sigPath, $FilePath)

    & $gpg.Source @gpgArgs
    if ($LASTEXITCODE -ne 0 -or -not (Test-Path $sigPath)) {
        throw "gpg a échoué (exit $LASTEXITCODE) pour la clé $fpr."
    }

    Write-Host "[SIGN] Signature GPG écrite : $sigPath" -ForegroundColor Green
    return [pscustomobject]@{
        Type          = 'GPG'
        SignaturePath = $sigPath
        Signer        = $signerUid
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

    # --- Échappement HTML ---
    $enc = {
        param($s)
        if ($null -eq $s) { return '' }
        ([string]$s).Replace('&','&amp;').Replace('<','&lt;').Replace('>','&gt;').Replace('"','&quot;')
    }

    # --- Scellement cryptographique du MANIFESTE (AVANT le HTML, pour l'y inclure) ---
    $signatures = @(); $tsPath = $null
    if ($Signing -and $Signing.enabled) {
        $method = ([string]$Signing.method).ToLower()
        if (-not $method) { $method = 'cms' }

        if ($method -in 'cms','both') {
            try {
                # Mot de passe PFX lu depuis une variable d'environnement (jamais en clair).
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

    # Bloc HTML des signatures cryptographiques (traçabilité dans le certificat)
    if (@($signatures).Count -gt 0) {
        $sigLines = ($signatures | ForEach-Object {
            "<div class='s'><span class='t'>{0}</span> {1} <code>{2}</code></div>" -f `
                (& $enc $_.Type), (& $enc $_.Signer), (& $enc $_.Thumbprint)
        }) -join "`n"
        if ($tsPath) {
            $sigLines += "`n<div class='s'><span class='t'>RFC3161</span> " + (& $enc ([System.IO.Path]::GetFileName($tsPath))) + "</div>"
        }
        $sigHtml = $sigLines
    } else {
        $sigHtml = "<div class='s' style='color:#94a3b8'>Aucune signature cryptographique (mode preview ou signature désactivée).</div>"
    }

    # --- Certificat HTML lisible ---
    $rows = ($Items | ForEach-Object {
        "<tr><td>{0}</td><td class='mono'>{1}</td><td class='num'>{2}</td><td class='mono'>{3}</td><td>{4}</td><td><span class='badge {5}'>{6}</span></td></tr>" -f `
            (& $enc $_.Source), (& $enc $_.Path), $_.SizeBytes, (& $enc $_.SHA256), `
            (& $enc $_.Method), ($_.Status.ToLower()), $_.Status
    }) -join "`n"

    if ($Mode -eq 'Preview') {
        $modeBanner = "<div class='banner'>MODE PREVIEW — aucune donnée détruite. Document de revue uniquement.</div>"
        $modeClass  = 'preview'; $modeLabel = 'PREVIEW'
    } else {
        $modeBanner = ''
        $modeClass  = 'destroy'; $modeLabel = 'DESTRUCTION'
    }

    $examinerLine = "{0} - {1} ({2})" -f $Meta.examiner.name, $Meta.examiner.role, $Meta.examiner.org
    $witnessLine  = "{0} - {1} ({2})" -f $Meta.witness.name,  $Meta.witness.role,  $Meta.witness.org

    $tpl = @'
<!DOCTYPE html>
<html lang="fr"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>@@CERTID@@</title>
<style>
 :root{
  --ink:#0f172a;--text:#334155;--muted:#64748b;--line:#e5e7eb;--bg:#f1f5f9;--card:#fff;
  --accent:#0d9488;--ok:#16a34a;--okbg:#dcfce7;--bad:#dc2626;--badbg:#fee2e2;
  --warn:#b45309;--warnbg:#fef3c7;--info:#0369a1;--infobg:#e0f2fe;
 }
 *{box-sizing:border-box}
 body{margin:0;background:var(--bg);color:var(--text);font-size:13px;line-height:1.5;
  font-family:-apple-system,Segoe UI,Roboto,Helvetica,Arial,sans-serif;
  -webkit-print-color-adjust:exact;print-color-adjust:exact}
 .page{max-width:880px;margin:24px auto;padding:0 16px}
 .card{background:var(--card);border:1px solid var(--line);border-radius:14px;padding:20px 22px;
  margin:16px 0;box-shadow:0 1px 2px rgba(15,23,42,.04)}
 h2{font-size:12px;letter-spacing:.08em;text-transform:uppercase;color:var(--muted);margin:0 0 14px;font-weight:600}
 code{font-family:ui-monospace,Consolas,"SF Mono",Menlo,monospace}
 .hdr{background:linear-gradient(135deg,#0f172a,#1e293b);color:#fff;border-radius:16px;padding:26px 28px;
  display:flex;justify-content:space-between;align-items:flex-start;gap:20px}
 .brand{font-size:11px;letter-spacing:.22em;text-transform:uppercase;color:#5eead4;font-weight:700}
 .hdr h1{margin:6px 0 4px;font-size:25px;font-weight:700;color:#fff;letter-spacing:-.01em}
 .hdr .sub{font-size:12px;color:#94a3b8}
 .hdr-right{text-align:right;flex-shrink:0}
 .certid{font-family:ui-monospace,Consolas,monospace;font-size:12px;color:#cbd5e1}
 .pill{display:inline-block;margin-top:10px;padding:5px 12px;border-radius:999px;font-size:11px;font-weight:700;letter-spacing:.06em}
 .pill.destroy{background:#7f1d1d;color:#fecaca}
 .pill.preview{background:#78350f;color:#fde68a}
 .banner{background:var(--warnbg);border:1px solid #fcd34d;color:var(--warn);border-radius:10px;
  padding:12px 16px;margin:16px 0;font-weight:600;font-size:12px}
 .stats{display:flex;gap:14px;margin:16px 0}
 .stat{flex:1;background:var(--card);border:1px solid var(--line);border-radius:14px;padding:16px 18px;text-align:center}
 .stat .n{font-size:30px;font-weight:800;color:var(--ink);line-height:1}
 .stat .l{font-size:11px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-top:6px}
 .stat.ok .n{color:var(--ok)}.stat.bad .n{color:var(--bad)}
 .grid{display:grid;grid-template-columns:1fr 1fr;gap:0 28px}
 .f{padding:8px 0;border-bottom:1px solid #f1f5f9}
 .f span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:2px}
 .f b{font-weight:600;color:var(--ink)}
 .seal{border-left:4px solid var(--accent)}
 .kv{margin:6px 0;font-size:12px}.kv b{color:var(--ink)}
 .seal code{display:inline-block;background:#f8fafc;border:1px solid var(--line);border-radius:6px;padding:2px 7px;font-size:11px;word-break:break-all}
 .sigs{margin-top:12px;padding-top:12px;border-top:1px dashed var(--line)}
 .sigs .s{margin:4px 0;font-size:12px}
 .sigs .t{display:inline-block;min-width:66px;font-weight:700;color:var(--accent)}
 .sign-row{display:flex;gap:32px}
 .sigbox{flex:1}
 .sigbox .line{height:46px;border-bottom:1.5px solid var(--ink)}
 .sigbox .who{margin-top:6px;font-size:12px}.sigbox .who b{color:var(--ink)}
 .sigbox .who span{display:block;font-size:10px;text-transform:uppercase;letter-spacing:.05em;color:var(--muted)}
 .inv{page-break-before:always}
 table{border-collapse:collapse;width:100%;font-size:11px;margin-top:6px}
 thead th{background:var(--ink);color:#fff;text-align:left;padding:8px 9px;font-weight:600;font-size:10px;text-transform:uppercase;letter-spacing:.04em}
 tbody td{padding:7px 9px;border-bottom:1px solid var(--line);vertical-align:top}
 tbody tr:nth-child(even){background:#f8fafc}
 td.mono{font-family:ui-monospace,Consolas,monospace;font-size:10px;word-break:break-all;color:#475569}
 td.num{text-align:right;font-variant-numeric:tabular-nums;white-space:nowrap}
 .badge{display:inline-block;padding:2px 9px;border-radius:999px;font-size:10px;font-weight:700;letter-spacing:.03em}
 .badge.destroyed,.badge.deleted{background:var(--okbg);color:var(--ok)}
 .badge.failed,.badge.read_error{background:var(--badbg);color:var(--bad)}
 .badge.preview{background:var(--infobg);color:var(--info)}
 footer{text-align:center;color:var(--muted);font-size:10px;margin:18px 0 28px}
 @media print{body{background:#fff}.page{margin:0;max-width:none}.card,.stat{box-shadow:none}tbody tr{page-break-inside:avoid}}
</style></head><body>
<div class="page">

 <header class="hdr">
  <div>
   <div class="brand">VeriPurge</div>
   <h1>Certificate of Destruction</h1>
   <div class="sub">Sanitization Record &middot; conforme NIST SP 800-88 Rev.1</div>
  </div>
  <div class="hdr-right">
   <div class="certid">@@CERTID@@</div>
   <span class="pill @@MODECLASS@@">@@MODELABEL@@</span>
  </div>
 </header>

 @@MODEBANNER@@

 <section class="stats">
  <div class="stat"><div class="n">@@TOTAL@@</div><div class="l">Elements</div></div>
  <div class="stat ok"><div class="n">@@DESTROYED@@</div><div class="l">Detruits</div></div>
  <div class="stat bad"><div class="n">@@FAILED@@</div><div class="l">Echecs</div></div>
 </section>

 <section class="card">
  <h2>Dossier</h2>
  <div class="grid">
   <div class="f"><span>Affaire (Case ID)</span><b>@@CASEID@@</b></div>
   <div class="f"><span>Reference scelle</span><b>@@EVIDENCEREF@@</b></div>
   <div class="f"><span>Enquete cloturee le</span><b>@@CLOSEDON@@</b></div>
   <div class="f"><span>Autorisation de destruction</span><b>@@AUTHREF@@</b></div>
   <div class="f"><span>Legal hold actif</span><b>@@LEGALHOLD@@</b></div>
   <div class="f"><span>Norme appliquee</span><b>@@STANDARD@@</b></div>
   <div class="f"><span>Examinateur</span><b>@@EXAMINER@@</b></div>
   <div class="f"><span>Temoin</span><b>@@WITNESS@@</b></div>
   <div class="f"><span>Poste / operateur</span><b>@@HOST@@</b></div>
   <div class="f"><span>Genere le (UTC)</span><b>@@NOWUTC@@</b></div>
  </div>
 </section>

 <section class="card seal">
  <h2>Sceau d'integrite</h2>
  <div class="kv"><b>Manifeste :</b> <code>@@CERTID@@.manifest.json</code></div>
  <div class="kv"><b>SHA-256 :</b> <code>@@MANIFESTHASH@@</code></div>
  <div class="sigs">@@SIGNATURES@@</div>
 </section>

 <section class="card">
  <h2>Signatures</h2>
  <div class="sign-row">
   <div class="sigbox"><div class="line"></div><div class="who"><b>@@EXAMINERNAME@@</b><span>Examinateur &mdash; signature &amp; date</span></div></div>
   <div class="sigbox"><div class="line"></div><div class="who"><b>@@WITNESSNAME@@</b><span>Temoin &mdash; signature &amp; date</span></div></div>
  </div>
 </section>

 <section class="inv">
  <div class="card">
   <h2>Inventaire des preuves &mdash; @@TOTAL@@ element(s), empreintes relevees AVANT destruction</h2>
   <table>
    <thead><tr><th>Source</th><th>Chemin</th><th>Octets</th><th>SHA-256</th><th>Methode</th><th>Statut</th></tr></thead>
    <tbody>
@@ROWS@@
    </tbody>
   </table>
  </div>
 </section>

 <footer>VeriPurge &middot; genere le @@NOWUTC@@ &middot; @@CERTID@@</footer>
</div>
</body></html>
'@

    $html = $tpl.
        Replace('@@CERTID@@',       [string]$certId).
        Replace('@@MODEBANNER@@',   [string]$modeBanner).
        Replace('@@MODECLASS@@',    [string]$modeClass).
        Replace('@@MODELABEL@@',    [string]$modeLabel).
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
        Replace('@@SIGNATURES@@',   [string]$sigHtml).
        Replace('@@EXAMINERNAME@@', [string]$Meta.examiner.name).
        Replace('@@WITNESSNAME@@',  [string]$Meta.witness.name)

    $htmlPath = Join-Path $OutputDir "$certId.certificate.html"
    $html | Set-Content -Path $htmlPath -Encoding UTF8

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
