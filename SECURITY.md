# Politique de sécurité

## Usage responsable

VeriPurge **détruit des données de façon irréversible** et produit un certificat de
destruction. C'est un outil destiné à un usage **autorisé** uniquement :

- Détruisez uniquement des données dont vous êtes propriétaire ou pour lesquelles vous
  disposez d'une **autorisation écrite** de destruction (`dispositionAuthorizationRef`).
- **Jamais** sous *legal hold* ni en présence d'une obligation de rétention active.
- Vérifiez systématiquement l'inventaire en **mode Preview** avant toute destruction.
- L'outil est fourni « en l'état » (voir [LICENSE](LICENSE)) ; l'utilisateur est seul
  responsable de la conformité de son usage.

## Limites de garantie technique

- Sur **SSD / NVMe / clés USB**, l'écrasement logique n'est pas garanti (wear-leveling) :
  utilisez ATA Secure Erase / crypto-erase au niveau du volume.
- Sur **SharePoint Online**, la suppression + purge des corbeilles n'élimine pas les
  sauvegardes côté plateforme Microsoft (~14 jours).

Ces limites sont documentées dans le certificat généré ; ne présentez pas une destruction
comme totale au-delà de ce que le support permet réellement.

## Signaler une vulnérabilité

Si vous découvrez une faille (ex. une destruction qui échoue silencieusement, une signature
contournable, une fuite de données sensibles dans les sorties) :

1. **N'ouvrez pas d'issue publique.**
2. Contactez le mainteneur en privé via l'adresse du profil GitHub
   [@elouahidiahmed](https://github.com/elouahidiahmed), ou via une *Security advisory*
   privée GitHub (onglet **Security → Report a vulnerability**).
3. Laissez un délai raisonnable de correction avant toute divulgation publique.

Merci de contribuer à la fiabilité de l'outil.
