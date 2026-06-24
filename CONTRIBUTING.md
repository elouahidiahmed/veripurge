# Contribuer à VeriPurge

Merci de votre intérêt ! Quelques règles pour garder le projet sain.

## Avant de coder

- Ouvrez une *issue* pour discuter d'un changement non trivial.
- Les contributions touchant à la **logique de destruction** ou à la **signature**
  doivent être accompagnées d'un test reproductible (voir ci-dessous).

## Style & contraintes techniques

- **PowerShell** compatible **5.1 et 7+**. `Set-StrictMode -Version Latest` est activé :
  enveloppez les collations potentiellement scalaires dans `@(...)` avant `.Count`.
- **Encodage** : tous les `.ps1`/`.psm1` en **UTF-8 avec BOM** (sinon PS 5.1 casse les
  accents). `.gitattributes` impose `eol=crlf` sur ces fichiers.
- Pas de secret en dur ; les chemins d'affaire et identifiants vivent dans `config.json`
  (git-ignoré), jamais dans le code ou `config.example.json`.

## Vérifier avant un commit

```powershell
# 1) Parsing de tous les scripts (zéro erreur attendu)
Get-ChildItem -Recurse -Include *.ps1,*.psm1 | ForEach-Object {
    $e = $null
    [System.Management.Automation.Language.Parser]::ParseFile($_.FullName, [ref]$null, [ref]([ref]$e).Value) | Out-Null
}

# 2) Smoke-test en mode Preview sur un dossier jetable (ne détruit rien)
#    Voir le scénario de test dans le README / l'historique du projet.
```

## Sécurité

Ne signalez **pas** les vulnérabilités via une issue publique — voir [SECURITY.md](SECURITY.md).

## Licence des contributions

En contribuant, vous acceptez que votre code soit publié sous licence [MIT](LICENSE).
