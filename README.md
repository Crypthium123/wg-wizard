# wg-wizard

Assistant en ligne de commande pour installer et administrer un serveur VPN WireGuard sur un VPS Debian ou Ubuntu, sans éditer de fichier de configuration à la main.

L'outil est écrit en Python 3 et n'utilise que la bibliothèque standard. Il pilote directement WireGuard (`wireguard-tools`), sans conteneur intermédiaire.

## Ce que l'outil prend en charge

| Étape | Traitement automatique |
|---|---|
| Détection réseau | Adresse IPv4 publique, interface de sortie (`eth0`, `ens3`...), port SSH en cours d'utilisation |
| Paquets | `wireguard`, `wireguard-tools`, `iptables`, `qrencode`, `ufw` |
| Routage | `net.ipv4.ip_forward=1` rendu permanent via `/etc/sysctl.d/`, règles NAT (`MASQUERADE`) dans `PostUp` / `PostDown` |
| Pare-feu | Règle SSH ajoutée avant l'activation d'UFW, ouverture du port UDP de WireGuard et règle `ufw route` pour le transit `wg0` vers l'interface WAN |
| Cryptographie | Paire de clés Curve25519 par appareil et clé pré-partagée (`wg genpsk`) |
| Adressage | Attribution de la prochaine adresse libre dans `10.8.0.0/24` |
| Profils clients | Fichier `.conf` et QR code affiché dans le terminal |
| Application des changements | `wg syncconf` : l'ajout ou la révocation d'un appareil ne coupe pas les connexions actives |

## Prérequis

- Un serveur sous Debian 12/13 ou Ubuntu 22.04/24.04 avec accès root (`sudo`).
- Une connexion SSH déjà fonctionnelle.
- Si l'hébergeur propose un pare-feu externe, le port UDP choisi doit y être autorisé.

## Installation

```bash
git clone https://github.com/<utilisateur>/wg-wizard.git
cd wg-wizard
sudo python3 wg_wizard.py
```

Le menu interactif propose l'installation, puis la création du premier appareil.

## Commandes

```text
sudo python3 wg_wizard.py                 menu interactif
sudo python3 wg_wizard.py install         installation guidée du serveur
sudo python3 wg_wizard.py add [nom]       ajouter un appareil (--split : accès au réseau VPN uniquement)
sudo python3 wg_wizard.py list            lister les appareils, dernière connexion et volumes reçus/envoyés
sudo python3 wg_wizard.py qr [nom]        réafficher le QR code d'un appareil
sudo python3 wg_wizard.py remove [nom]    révoquer un appareil
sudo python3 wg_wizard.py doctor          diagnostic de l'installation
sudo python3 wg_wizard.py backup          sauvegarde de /etc/wireguard/wg0.conf
python3 wg_wizard.py --dry-run <commande> simulation : affiche les actions sans rien modifier
```

Le mode `--dry-run` peut être essayé sur n'importe quelle machine, sans droits root.

## Utiliser un profil sur un appareil

- **Smartphone** : installer l'application WireGuard, puis « Ajouter un tunnel » > « Scanner un QR code ».
- **Ordinateur** : récupérer le fichier `.conf` avec `scp utilisateur@<ip-du-serveur>:/etc/wireguard/clients/<nom>.conf .`, l'importer dans le client WireGuard, puis supprimer la copie locale du fichier.

Chaque appareil doit disposer de son propre profil. Deux machines utilisant le même fichier simultanément provoquent des déconnexions en boucle.

## Fichiers créés sur le serveur

```text
/etc/wireguard/wg0.conf               configuration du serveur et des pairs (droits 600)
/etc/wireguard/wg-wizard.env          paramètres mémorisés (adresse publique, port, clé publique)
/etc/wireguard/clients/<nom>.conf     profils clients (droits 600, contiennent la clé privée)
/etc/wireguard/backups/               sauvegardes horodatées avant chaque modification
/etc/sysctl.d/99-wg-wizard.conf       activation permanente du routage IPv4
```

## Choix de conception

- **Tunnel complet par défaut** : `AllowedIPs = 0.0.0.0/0, ::/0` et DNS imposé (`1.1.1.1`). Le serveur ne route pas l'IPv6 : le trafic IPv6 d'un client entre dans le tunnel et y est abandonné. Ce comportement est voulu, car il empêche toute fuite de l'adresse IPv6 réelle du client ; les applications reviennent en IPv4. Un mode « accès au réseau VPN uniquement » (`--split`) est disponible pour administrer le serveur sans router le trafic web.
- **Adresse du serveur** : une IPv4 ou un nom de domaine (utile avec une IP dynamique).
- **Entrées contrôlées** : le nom d'interface réseau, injecté dans `PostUp`/`PostDown`, et le nom des appareils sont validés par expression régulière.
- **Droits des fichiers** : les fichiers sont créés directement en `600` (dossiers en `700`), sans fenêtre de lecture intermédiaire.
- **Pare-feu** : le trafic retour vers `wg0` n'est accepté que pour les connexions établies (`conntrack`).
- **Pas de verrouillage SSH** : le port SSH est détecté (variable `SSH_CONNECTION`, puis `sshd -T`) et autorisé dans UFW avant son activation.
- **Sauvegarde avant modification** : chaque ajout ou révocation copie `wg0.conf` dans `/etc/wireguard/backups/`.
- **Pas de serveur de téléchargement intégré** : un profil contient une clé privée. Il est transféré par `scp` ou par QR code, jamais par un lien HTTP en clair.

## Limites actuelles

- IPv4 uniquement côté serveur.
- Une seule interface (`wg0`) et un seul sous-réseau (`10.8.0.0/24`, soit 253 appareils au maximum).
- Distributions basées sur `apt` uniquement.
- Pas de commande de désinstallation : `systemctl disable --now wg-quick@wg0`, puis suppression manuelle de `/etc/wireguard/` et des règles UFW correspondantes.

## Sécurité

Le port UDP de WireGuard ne répond à aucun paquet dépourvu de signature cryptographique valide. Le seul service exposé susceptible d'être visé par des tentatives de connexion automatisées reste SSH. Il est recommandé de désactiver l'authentification par mot de passe (`PasswordAuthentication no`) et d'installer Fail2ban sur le serveur.

## Licence

MIT
