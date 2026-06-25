# VeriPurge

📖 **English** · [Français](LISEZ-MOI.md)

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Standard](https://img.shields.io/badge/NIST-SP%20800--88%20Rev.1-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)

**Verified purge** of forensic evidence (**Windows** workstation + **SharePoint Online**
share), with automatic generation of a signed, timestamped **Certificate of Destruction**.

> DFIR principle: you **destroy the data** but **keep the proof of destruction**.
> The *what* is proven by the **cryptographic hashes** captured before destruction;
> the *that it happened* is proven by the **signed + timestamped certificate**.
> Reference: **NIST SP 800-88 Rev.1** (Guidelines for Media Sanitization).

> [!WARNING]
> **VeriPurge destroys data irreversibly.** Use it only on data you own or for which you
> hold **written authorization** to destroy, and **never** under a *legal hold*. Always run
> **Preview mode** first (without `-Confirm`) to review the inventory. The authors accept no
> liability for data loss. See [SECURITY.md](SECURITY.md).

## Layout

```
veripurge/
├─ Invoke-Disposition.ps1      # orchestrator (Preview by default, Destroy with -Confirm)
├─ Verify-Certificate.ps1      # re-verifies hash + signature of an issued certificate
├─ New-SigningCertificate.ps1  # generates a self-signed X.509 cert / lists GPG keys
├─ config.example.json         # copy to config.json and adapt
├─ modules/
│  ├─ LocalSanitize.psm1       # multi-pass overwrite + manifest (Windows host)
│  ├─ SharePointSanitize.psm1  # delete + empty recycle bins (SPO via PnP)
│  └─ Certificate.psm1         # JSON manifest + HTML certificate + CMS/GPG signature + RFC3161
└─ certificates/               # outputs (created at runtime, git-ignored)
```

## Requirements

- **PowerShell as administrator** (local part). PowerShell **7+** recommended (RFC 3161 timestamping).
- For SharePoint: `Install-Module PnP.PowerShell -Scope CurrentUser`
- For signing: see the **Signing** section below.

## Signing the certificate (X.509 and/or GPG)

The JSON manifest (source of truth) is sealed with a detached signature. The backend is
chosen via `signing.method` in `config.json`: `"cms"`, `"gpg"`, or `"both"`.

**a) X.509 / CMS (`.p7s`)** — no "machine" cert needed: a certificate with a private key in
`Cert:\CurrentUser\My` is enough. Generate a self-signed one (internal use):
```powershell
.\New-SigningCertificate.ps1 -Type X509          # prints the thumbprint to paste
```
Then in `config.json`: `method:"cms"`, `cms.certThumbprint:"<thumbprint>"`.
For a legally defensible cert, prefer one issued by your **organization's PKI**, or a `.pfx`
(set `cms.pfxPath`; the password is read from the env var named in `cms.pfxPasswordEnvVar`,
never in clear text in the config).

**b) GPG / OpenPGP (`.asc`)** — recommended in DFIR, key fully under your control.
Requires **Gpg4win**. Find/create your key:
```powershell
.\New-SigningCertificate.ps1 -Type GPG           # lists your secret keys
```
Then in `config.json`: `method:"gpg"`, `gpg.keyId:"<email or fingerprint>"`.

`method:"both"` produces `.p7s` **and** `.asc`. `Verify-Certificate.ps1` checks both
automatically (CMS + `gpg --verify`).

> Note: a **self-signed** cert/key proves integrity and internal consistency, but not your
> identity to a third party. For legal defensibility, combine it with **RFC 3161 timestamping**
> (`signing.timestampUrl`) and WORM storage.

## Usage

```powershell
# 0) Prepare the config
Copy-Item .\config.example.json .\config.json
notepad .\config.json   # caseId, paths, SPO site, authorization, signatories...

# 1) DRY RUN (always first) — computes hashes, destroys NOTHING
.\Invoke-Disposition.ps1 -ConfigPath .\config.json
#    -> Open the "PREVIEW MODE" HTML certificate and review the inventory.

# 2) REAL DESTRUCTION — prompts you to type "DETRUIRE" to confirm
.\Invoke-Disposition.ps1 -ConfigPath .\config.json -Confirm

# 3) Later: re-verify a certificate's integrity
.\Verify-Certificate.ps1 -ManifestPath .\certificates\COD-...manifest.json
```

A **progress bar** is shown during both local and SharePoint processing — percentage,
processed/total file count, current file, **throughput (MB/s)** and **estimated time
remaining (ETA)** — so large jobs report live progress.

## Built-in safeguards

- **Preview by default**: no destruction without `-Confirm` + typing the word `DETRUIRE`.
- **Aborts if `legalHoldActive = true`** in the config.
- **Aborts if no authorization** (`dispositionAuthorizationRef`) is provided.
- **SHA-256 + MD5** hashes captured **before** any deletion.
- Post-destruction verification (file confirmed absent).
- **Long-path safe**: paths over 260 chars (deep folders, UUID names) are handled via
  `\\?\` extended paths and .NET I/O — no "file not found" on existing files.

## What each run produces (in `outputDir`)

| File | Purpose |
|---|---|
| `COD-<case>-<ts>.manifest.json` | Source of truth: metadata + inventory + hashes |
| `COD-<case>-<ts>.manifest.json.p7s` | **Detached** PKCS#7/CMS digital signature of the manifest |
| `COD-<case>-<ts>.manifest.json.asc` | Detached GPG/OpenPGP signature (when `gpg`/`both`) |
| `COD-<case>-<ts>.manifest.json.tsr` | RFC 3161 timestamp token (PowerShell 7+) |
| `COD-<case>-<ts>.certificate.html` | Human-readable/printable certificate, to be counter-signed |

The HTML certificate embeds the **SHA-256 of the manifest**: any printed copy stays
cryptographically tied to the signed manifest.

## Verifying a signature

**Easiest — the bundled verifier.** It recomputes the manifest hash and validates every
signature found next to it (`.p7s` CMS/X.509 **and** `.asc` GPG), and flags an RFC 3161 token:

```powershell
.\Verify-Certificate.ps1 -ManifestPath .\certificates\COD-<case>-<ts>.manifest.json
```

**Independent verification** (for a third party who does not run VeriPurge):

- **GPG (`.asc`)** — import the signer's public key once, then verify:
  ```powershell
  gpg --import signer-public-key.asc          # only needed the first time
  gpg --verify COD-<case>-<ts>.manifest.json.asc COD-<case>-<ts>.manifest.json
  # "Good signature from ..." => the manifest is intact.
  ```

- **CMS / X.509 (`.p7s`)** — with OpenSSL (cross-platform, no PowerShell needed). The
  signature is detached and DER-encoded, over the raw bytes, so pass `-binary`:
  ```bash
  openssl cms -verify -binary -inform DER \
    -in      COD-<case>-<ts>.manifest.json.p7s \
    -content COD-<case>-<ts>.manifest.json \
    -CAfile  signer-or-ca.pem -out /dev/null
  # Self-signed / internal cert: add -noverify to check the signature only
  # (not the trust chain).
  ```

- **Hash only (no keys)** — recompute and compare with the "SHA-256 of the manifest" value
  sealed in the HTML certificate:
  ```powershell
  Get-FileHash .\COD-<case>-<ts>.manifest.json -Algorithm SHA256
  ```

- **RFC 3161 timestamp (`.tsr`)** — with OpenSSL:
  ```bash
  openssl ts -verify -in COD-<case>-<ts>.manifest.json.tsr \
    -data COD-<case>-<ts>.manifest.json -CAfile tsa-ca.pem
  ```

> Any mismatch — a different hash, or `BAD signature` — means the manifest was altered after
> issuance: treat the certificate as **invalid**.

## ⚠ Limits by media type (know and document them)

- **Magnetic HDD**: multi-pass overwrite is effective (NIST *Purge*).
- **SSD / NVMe / USB flash**: wear-leveling makes logical overwrite **not guaranteed**.
  Prefer **ATA Secure Erase** / **NVMe Format**, or **crypto-erase** (BitLocker: destroy the
  key) at the volume level. When shredding is required → NIST *Destroy*.
- **SharePoint Online**: you do not control the physical storage. The script deletes and
  **empties both recycle-bin stages**, but Microsoft retains **platform backups (~14 days)**.
  For total contractual eradication, also submit a **formal deletion request to Microsoft**.
  This residual remanence is deliberately documented in the certificate.

## After a run

1. Have the HTML certificate **counter-signed** (examiner + witness).
2. File manifest + signature + certificate in the case folder (preferably WORM/append-only).
3. Add the final **chain-of-custody** line: `Disposition — <method> — certificate ref`.

## Script encoding

The `.ps1`/`.psm1` files **must** stay **UTF-8 with BOM**: without a BOM, Windows PowerShell
5.1 reads them as ANSI and breaks accented characters (both parsing **and** runtime).
`.gitattributes` enforces `eol=crlf` on these files; the BOM is preserved as-is by git.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Vulnerability reports follow [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE) © 2026 Ahmed Elouahidi.

> Disclaimer: software provided "as is", without warranty. This is a **data-destruction** tool —
> the user is solely responsible for compliant use (authorization, retention, legal hold).
