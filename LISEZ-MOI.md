# VeriPurge

[English](README.md) · 📖 **Français**

![PowerShell](https://img.shields.io/badge/PowerShell-5.1%20%7C%207%2B-5391FE?logo=powershell&logoColor=white)
![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)
![Standard](https://img.shields.io/badge/NIST-SP%20800--88%20Rev.1-blue)
![Platform](https://img.shields.io/badge/platform-Windows-0078D6?logo=windows&logoColor=white)

**Verified purge** de preuves forensiques (poste **Windows** + partage **SharePoint Online**),
avec génération automatique d'un **Certificate of Destruction** signé et horodaté.

> Principe DFIR : on **détruit la donnée** mais on **conserve la preuve de destruction**.
> Le *quoi* est prouvé par les **empreintes cryptographiques** relevées avant destruction ;
> le *que cela a eu lieu* est prouvé par le **certificat signé + horodaté**.
> Référence : **NIST SP 800-88 Rev.1** (Guidelines for Media Sanitization).

> [!WARNING]
> **VeriPurge détruit des données de façon irréversible.** Utilisez-le uniquement sur des
> données dont vous êtes propriétaire ou pour lesquelles vous avez une **autorisation écrite**
> de destruction, et **jamais** sous *legal hold*. Lancez toujours d'abord le **mode Preview**
> (sans `-Confirm`) pour relire l'inventaire. Les auteurs déclinent toute responsabilité en cas
> de perte de données. Voir [SECURITY.md](SECURITY.md).

## Structure

```
veripurge/
├─ Invoke-Disposition.ps1      # orchestrateur (Preview par défaut, Destroy avec -Confirm)
├─ Verify-Certificate.ps1      # revérifie hash + signature d'un certificat émis
├─ New-SigningCertificate.ps1  # génère un cert X.509 auto-signé / liste les clés GPG
├─ config.example.json         # à copier en config.json et adapter
├─ modules/
│  ├─ LocalSanitize.psm1       # overwrite multi-passes + manifeste (poste Windows)
│  ├─ SharePointSanitize.psm1  # suppression + purge corbeilles (SPO via PnP)
│  └─ Certificate.psm1         # manifeste JSON + certificat HTML + signature CMS/GPG + RFC3161
└─ certificates/               # sorties (créé à l'exécution, git-ignoré)
```

## Prérequis

- **PowerShell en administrateur** (partie locale). PowerShell **7+** recommandé (horodatage RFC 3161).
- Pour SharePoint : `Install-Module PnP.PowerShell -Scope CurrentUser`
- Pour la signature : voir la section **Signature** ci-dessous.

## Signature du certificat (X.509 et/ou GPG)

Le manifeste JSON (source de vérité) est scellé par une signature détachée. Le backend
est choisi via `signing.method` dans `config.json` : `"cms"`, `"gpg"` ou `"both"`.

**a) X.509 / CMS (`.p7s`)** — pas besoin de cert « machine » : un certificat avec clé
privée dans `Cert:\CurrentUser\My` suffit. Générez-en un auto-signé (usage interne) :
```powershell
.\New-SigningCertificate.ps1 -Type X509          # affiche le thumbprint à coller
```
Puis dans `config.json` : `method:"cms"`, `cms.certThumbprint:"<thumbprint>"`.
Pour un cert opposable, préférez un certificat émis par la **PKI de l'organisation**, ou un
`.pfx` (renseignez `cms.pfxPath` ; mot de passe lu depuis la variable d'env nommée dans
`cms.pfxPasswordEnvVar`, jamais en clair dans la config).

**b) GPG / OpenPGP (`.asc`)** — recommandé en DFIR, clé entièrement sous votre contrôle.
Nécessite **Gpg4win**. Repérez/créez votre clé :
```powershell
.\New-SigningCertificate.ps1 -Type GPG           # liste vos clés secrètes
```
Puis dans `config.json` : `method:"gpg"`, `gpg.keyId:"<email ou fingerprint>"`.

`method:"both"` produit `.p7s` **et** `.asc`. `Verify-Certificate.ps1` vérifie
automatiquement les deux (CMS + `gpg --verify`).

> Note : un cert/clé **auto-signé** prouve l'intégrité et la cohérence interne, mais pas
> l'identité auprès d'un tiers. Pour l'opposabilité, combinez avec l'**horodatage RFC 3161**
> (`signing.timestampUrl`) et un stockage WORM.

## Utilisation

```powershell
# 0) Préparer la config
Copy-Item .\config.example.json .\config.json
notepad .\config.json   # caseId, chemins, site SPO, autorisation, signataires...

# 1) REVUE À BLANC (obligatoire d'abord) — calcule les empreintes, ne détruit RIEN
.\Invoke-Disposition.ps1 -ConfigPath .\config.json
#    -> Ouvrez le certificat HTML "MODE PREVIEW", vérifiez l'inventaire.

# 2) DESTRUCTION RÉELLE — demande de taper "DETRUIRE" pour confirmer
.\Invoke-Disposition.ps1 -ConfigPath .\config.json -Confirm

# 3) Plus tard : revérifier l'intégrité d'un certificat
.\Verify-Certificate.ps1 -ManifestPath .\certificates\COD-...manifest.json
```

## Garde-fous intégrés

- **Preview par défaut** : aucune destruction sans `-Confirm` + saisie du mot `DETRUIRE`.
- **Blocage si `legalHoldActive = true`** dans la config.
- **Blocage si aucune autorisation** (`dispositionAuthorizationRef`) n'est renseignée.
- Empreintes **SHA-256 + MD5** relevées **avant** toute suppression.
- Vérification post-destruction (`Test-Path` → fichier absent).

## Ce que produit chaque exécution (dans `outputDir`)

| Fichier | Rôle |
|---|---|
| `COD-<case>-<ts>.manifest.json` | Source de vérité : métadonnées + inventaire + empreintes |
| `COD-<case>-<ts>.manifest.json.p7s` | Signature numérique **détachée** PKCS#7/CMS du manifeste |
| `COD-<case>-<ts>.manifest.json.tsr` | Jeton d'horodatage RFC 3161 (si PowerShell 7+) |
| `COD-<case>-<ts>.certificate.html` | Certificat lisible/imprimable, à contresigner |

Le certificat HTML inclut le **SHA-256 du manifeste** : tout doc imprimé reste rattaché
cryptographiquement au manifeste signé.

## ⚠ Limites par type de support (à connaître / documenter)

- **HDD magnétique** : l'overwrite multi-passes est efficace (NIST *Purge*).
- **SSD / NVMe / clé USB** : le wear-leveling rend l'overwrite logique **non garanti**.
  Préférez **ATA Secure Erase** / **NVMe Format**, ou **crypto-erase** (BitLocker :
  détruire la clé) au niveau du volume. Pour broyage exigé → NIST *Destroy*.
- **SharePoint Online** : vous ne maîtrisez pas le stockage physique. Le script
  supprime + **purge les deux niveaux de corbeille**, mais Microsoft conserve des
  **sauvegardes plateforme (~14 j)**. Pour une éradication contractuelle totale,
  doublez d'une **demande de suppression formelle à Microsoft**. Cette rémanence
  résiduelle est volontairement documentée dans le certificat.

## Après exécution

1. Faire **contresigner** le certificat HTML (examinateur + témoin).
2. Classer manifeste + signature + certificat dans le dossier d'enquête (WORM/append-only de préférence).
3. Ajouter la ligne finale de **chain of custody** : `Disposition — <méthode> — réf certificat`.

## Encodage des scripts

Les `.ps1`/`.psm1` **doivent** rester en **UTF-8 avec BOM** : sans BOM, Windows PowerShell 5.1
les lit en ANSI et casse les accents (parsing **et** exécution). `.gitattributes` impose `eol=crlf`
sur ces fichiers ; le BOM est préservé tel quel par git.

## Contribuer

Voir [CONTRIBUTING.md](CONTRIBUTING.md). Les rapports de vulnérabilité suivent [SECURITY.md](SECURITY.md).

## Licence

[MIT](LICENSE) © 2026 Ahmed Elouahidi.

> Avertissement : logiciel fourni « en l'état », sans garantie. Outil de **destruction de données** —
> l'utilisateur est seul responsable de son usage conforme (autorisation, rétention, legal hold).
