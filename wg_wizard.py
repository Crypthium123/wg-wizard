#!/usr/bin/env python3
"""
wg-wizard : assistant d'installation et de gestion d'un VPN WireGuard.

Cible : serveur Debian / Ubuntu (apt). Aucune dépendance Python externe.

Utilisation :
    sudo python3 wg_wizard.py                  menu interactif
    sudo python3 wg_wizard.py install          installation guidée
    sudo python3 wg_wizard.py add [nom]        ajouter un appareil
    sudo python3 wg_wizard.py list             lister les appareils
    sudo python3 wg_wizard.py qr [nom]         afficher le QR code d'un appareil
    sudo python3 wg_wizard.py remove [nom]     révoquer un appareil
    sudo python3 wg_wizard.py doctor           diagnostic
    sudo python3 wg_wizard.py backup           sauvegarde de la configuration
    python3 wg_wizard.py --dry-run install     simulation sans rien modifier
"""

import argparse
import ipaddress
import os
import re
import shutil
import subprocess
import sys
import urllib.request
from datetime import datetime
from pathlib import Path

# --------------------------------------------------------------------------
# Constantes
# --------------------------------------------------------------------------

WG_DIR = Path("/etc/wireguard")
IFACE = "wg0"
CONF = WG_DIR / f"{IFACE}.conf"
CLIENTS_DIR = WG_DIR / "clients"
BACKUP_DIR = WG_DIR / "backups"
META_FILE = WG_DIR / "wg-wizard.env"
SYSCTL_FILE = Path("/etc/sysctl.d/99-wg-wizard.conf")

SUBNET = ipaddress.ip_network("10.8.0.0/24")
SERVER_IP = "10.8.0.1"
DEFAULT_PORT = 51820
DEFAULT_DNS = "1.1.1.1"
NAME_RE = re.compile(r"^[A-Za-z0-9_-]{1,32}$")
IFACE_RE = re.compile(r"^[A-Za-z0-9_.:@-]{1,15}$")
HOST_RE = re.compile(r"^(?=.{1,253}$)([A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)+[A-Za-z]{2,}$")
PEER_RE = re.compile(
    r"# BEGIN client (?P<name>[A-Za-z0-9_-]+)\n(?P<body>.*?)# END client (?P=name)\n",
    re.S,
)

DRY_RUN = False


class WizardError(Exception):
    """Erreur attendue, affichée sans trace d'exécution."""


# --------------------------------------------------------------------------
# Affichage et saisie
# --------------------------------------------------------------------------

_COLOR = sys.stdout.isatty()


def _c(code: str, text: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _COLOR else text


def info(msg: str) -> None:
    print(f"  {msg}")


def step(msg: str) -> None:
    print(_c("1;36", f"\n==> {msg}"))


def ok(msg: str) -> None:
    print(_c("32", f"  [OK] {msg}"))


def warn(msg: str) -> None:
    print(_c("33", f"  [!]  {msg}"))


def ko(msg: str) -> None:
    print(_c("31", f"  [KO] {msg}"))


def ask(prompt: str, default: str | None = None) -> str:
    suffix = f" [{default}]" if default else ""
    try:
        value = input(f"  {prompt}{suffix} : ").strip()
    except EOFError:
        value = ""
    return value or (default or "")


def confirm(prompt: str, default: bool = True) -> bool:
    hint = "O/n" if default else "o/N"
    answer = ask(f"{prompt} ({hint})").lower()
    if not answer:
        return default
    return answer in ("o", "oui", "y", "yes")


# --------------------------------------------------------------------------
# Accès système (toutes les modifications passent par ces fonctions)
# --------------------------------------------------------------------------


def run(cmd, input_data=None, mutating=True, check=True, env=None) -> str:
    """Exécute une commande. En mode simulation, les commandes qui modifient
    le système sont seulement affichées."""
    shown = " ".join(cmd)
    if DRY_RUN and mutating:
        print(f"  [simulation] $ {shown}")
        return ""
    try:
        res = subprocess.run(
            cmd, input=input_data, text=True, capture_output=True,
            check=check, env=env,
        )
    except FileNotFoundError:
        raise WizardError(f"Commande introuvable : {cmd[0]}")
    except subprocess.CalledProcessError as exc:
        detail = (exc.stderr or "").strip()
        raise WizardError(f"La commande a échoué : {shown}\n  {detail}")
    return res.stdout.strip()


def write_file(path: Path, content: str, mode: int = 0o600) -> None:
    if DRY_RUN:
        print(f"  [simulation] écriture de {path} (droits {oct(mode)})")
        return
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "w") as handle:
        os.fchmod(handle.fileno(), mode)  # couvre aussi un fichier déjà existant
        handle.write(content)


def require_root() -> None:
    if not DRY_RUN and os.geteuid() != 0:
        raise WizardError("Cette action nécessite les droits root. Relancez avec : sudo python3 wg_wizard.py")


# --------------------------------------------------------------------------
# Détection de l'environnement
# --------------------------------------------------------------------------


def detect_public_ip() -> str | None:
    for url in ("https://api.ipify.org", "https://ipv4.icanhazip.com"):
        try:
            with urllib.request.urlopen(url, timeout=5) as resp:
                candidate = resp.read().decode().strip()
            ipaddress.IPv4Address(candidate)
            return candidate
        except Exception:
            continue
    return None


def detect_wan_interface() -> str | None:
    try:
        out = run(["ip", "-4", "route", "get", "1.1.1.1"], mutating=False)
    except WizardError:
        return None
    match = re.search(r"\bdev (\S+)", out)
    return match.group(1) if match else None


def detect_ssh_port() -> int:
    """Port SSH actuellement utilisé, pour ne jamais s'enfermer dehors."""
    conn = os.environ.get("SSH_CONNECTION", "").split()
    if len(conn) == 4 and conn[3].isdigit():
        return int(conn[3])
    try:
        out = run(["sshd", "-T"], mutating=False, check=False)
        match = re.search(r"^port (\d+)$", out, re.M)
        if match:
            return int(match.group(1))
    except WizardError:
        pass
    return 22


# --------------------------------------------------------------------------
# Métadonnées du serveur et lecture de la configuration
# --------------------------------------------------------------------------


def save_meta(meta: dict) -> None:
    write_file(META_FILE, "".join(f"{k}={v}\n" for k, v in meta.items()))


def load_meta() -> dict:
    if not META_FILE.exists():
        if DRY_RUN:
            return {
                "ENDPOINT": "203.0.113.10", "PORT": str(DEFAULT_PORT),
                "DNS": DEFAULT_DNS, "SERVER_PUBKEY": "<CLE_PUBLIQUE_SERVEUR>",
            }
        raise WizardError("Aucune installation détectée. Lancez d'abord : install")
    meta = {}
    for line in META_FILE.read_text().splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            meta[key.strip()] = value.strip()
    return meta


def read_conf() -> str:
    if CONF.exists():
        return CONF.read_text()
    if DRY_RUN:
        return ""
    raise WizardError(f"{CONF} introuvable. Lancez d'abord : install")


def parse_peers(conf: str) -> list[dict]:
    peers = []
    for m in PEER_RE.finditer(conf):
        body = m.group("body")
        pub = re.search(r"PublicKey = (\S+)", body)
        addr = re.search(r"AllowedIPs = ([\d.]+)/32", body)
        peers.append({
            "name": m.group("name"),
            "pubkey": pub.group(1) if pub else "",
            "ip": addr.group(1) if addr else "",
        })
    return peers


def next_free_ip(used: list[str]) -> str:
    reserved = {ipaddress.ip_address(SERVER_IP)} | {ipaddress.ip_address(i) for i in used}
    for host in SUBNET.hosts():
        if host not in reserved:
            return str(host)
    raise WizardError("Plus aucune adresse libre dans 10.8.0.0/24 (253 appareils maximum).")


def backup_conf() -> None:
    if not CONF.exists():
        return
    stamp = datetime.now().strftime("%Y%m%d-%H%M%S")
    target = BACKUP_DIR / f"{IFACE}.conf.{stamp}"
    if DRY_RUN:
        print(f"  [simulation] sauvegarde de {CONF} vers {target}")
        return
    BACKUP_DIR.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(CONF, target)
    target.chmod(0o600)
    ok(f"Sauvegarde créée : {target}")


# --------------------------------------------------------------------------
# Cryptographie
# --------------------------------------------------------------------------


def generate_keypair() -> tuple[str, str]:
    if DRY_RUN:
        return "<CLE_PRIVEE>", "<CLE_PUBLIQUE>"
    private = run(["wg", "genkey"], mutating=False)
    public = run(["wg", "pubkey"], input_data=private, mutating=False)
    return private, public


def generate_psk() -> str:
    return "<CLE_PARTAGEE>" if DRY_RUN else run(["wg", "genpsk"], mutating=False)


# --------------------------------------------------------------------------
# Installation
# --------------------------------------------------------------------------


def render_server_conf(private_key: str, port: int, wan: str) -> str:
    up = (
        f"iptables -I FORWARD 1 -i {IFACE} -j ACCEPT; "
        f"iptables -I FORWARD 1 -o {IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; "
        f"iptables -t nat -A POSTROUTING -s {SUBNET} -o {wan} -j MASQUERADE"
    )
    down = (
        f"iptables -D FORWARD -i {IFACE} -j ACCEPT; "
        f"iptables -D FORWARD -o {IFACE} -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; "
        f"iptables -t nat -D POSTROUTING -s {SUBNET} -o {wan} -j MASQUERADE"
    )
    return (
        "[Interface]\n"
        f"Address = {SERVER_IP}/{SUBNET.prefixlen}\n"
        f"ListenPort = {port}\n"
        f"PrivateKey = {private_key}\n"
        f"PostUp = {up}\n"
        f"PostDown = {down}\n\n"
    )


def cmd_install() -> None:
    require_root()
    if CONF.exists() and not DRY_RUN:
        raise WizardError(
            f"{CONF} existe déjà. Utilisez 'add' pour ajouter un appareil, "
            "ou sauvegardez puis supprimez ce fichier pour réinstaller."
        )
    if not DRY_RUN and not shutil.which("apt-get"):
        raise WizardError("Seules les distributions basées sur apt (Debian, Ubuntu) sont prises en charge.")

    step("Détection de la configuration réseau")
    detected_ip = detect_public_ip()
    endpoint = ask("Adresse IPv4 publique ou nom de domaine du serveur", detected_ip)
    try:
        ipaddress.IPv4Address(endpoint)
    except ValueError:
        if not HOST_RE.match(endpoint):
            raise WizardError("Adresse invalide : saisissez une IPv4 ou un nom de domaine (ex. vpn.exemple.fr).")

    wan = ask("Interface réseau principale", detect_wan_interface() or "eth0")
    if not IFACE_RE.match(wan):
        raise WizardError("Nom d'interface invalide.")
    port_raw = ask("Port UDP de WireGuard", str(DEFAULT_PORT))
    if not port_raw.isdigit() or not 1 <= int(port_raw) <= 65535:
        raise WizardError("Port invalide.")
    port = int(port_raw)
    ssh_port = detect_ssh_port()

    step("Récapitulatif")
    info(f"Adresse publique : {endpoint}")
    info(f"Interface WAN    : {wan}")
    info(f"Port WireGuard   : {port}/udp")
    info(f"Port SSH préservé: {ssh_port}/tcp")
    info(f"Réseau du VPN    : {SUBNET} (serveur : {SERVER_IP})")
    info(f"DNS des clients  : {DEFAULT_DNS}")
    if not confirm("Lancer l'installation ?"):
        info("Installation annulée.")
        return

    step("Installation des paquets")
    env = dict(os.environ, DEBIAN_FRONTEND="noninteractive")
    run(["apt-get", "update"], env=env)
    run(["apt-get", "install", "-y", "wireguard", "wireguard-tools", "iptables", "qrencode", "ufw"], env=env)
    ok("Paquets installés")

    step("Activation du routage IPv4")
    write_file(SYSCTL_FILE, "net.ipv4.ip_forward=1\n", mode=0o644)
    run(["sysctl", "-p", str(SYSCTL_FILE)])
    ok("Routage activé de façon permanente")

    step("Génération des clés et de la configuration serveur")
    private, public = generate_keypair()
    write_file(CONF, render_server_conf(private, port, wan))
    save_meta({"ENDPOINT": endpoint, "PORT": port, "DNS": DEFAULT_DNS, "WAN": wan, "SERVER_PUBKEY": public})
    ok(f"Configuration écrite dans {CONF}")

    step("Configuration du pare-feu (UFW)")
    run(["ufw", "allow", f"{ssh_port}/tcp"])   # toujours avant 'enable'
    run(["ufw", "allow", f"{port}/udp"])
    run(["ufw", "route", "allow", "in", "on", IFACE, "out", "on", wan])  # persiste après 'ufw reload'
    run(["ufw", "--force", "enable"])
    ok(f"UFW actif : {ssh_port}/tcp et {port}/udp autorisés")

    step("Démarrage du service")
    run(["systemctl", "enable", "--now", f"wg-quick@{IFACE}"])
    ok("Service WireGuard démarré et activé au démarrage")

    warn("Si votre hébergeur dispose d'un pare-feu externe, autorisez aussi le port "
         f"{port}/udp dans son panneau de gestion.")

    if confirm("Créer maintenant le premier appareil ?"):
        cmd_add()


# --------------------------------------------------------------------------
# Gestion des appareils
# --------------------------------------------------------------------------


def apply_config() -> None:
    """Applique la configuration sans couper les connexions existantes."""
    if DRY_RUN:
        print(f"  [simulation] $ wg syncconf {IFACE} <(wg-quick strip {IFACE})")
        return
    active = run(["systemctl", "is-active", f"wg-quick@{IFACE}"], mutating=False, check=False)
    if active == "active":
        run(["bash", "-c", f"wg syncconf {IFACE} <(wg-quick strip {IFACE})"])
    else:
        run(["systemctl", "restart", f"wg-quick@{IFACE}"])


def show_qr(conf_text: str) -> None:
    if DRY_RUN:
        print("  [simulation] le QR code serait affiché ici")
        return
    if not shutil.which("qrencode"):
        warn("qrencode n'est pas installé : QR code indisponible.")
        return
    print(run(["qrencode", "-t", "ansiutf8"], input_data=conf_text, mutating=False))


def choose_client(name: str | None, action: str) -> str:
    peers = parse_peers(read_conf())
    if not peers:
        raise WizardError("Aucun appareil enregistré.")
    if name:
        if name not in [p["name"] for p in peers]:
            raise WizardError(f"Appareil introuvable : {name}")
        return name
    print()
    for i, p in enumerate(peers, 1):
        info(f"{i}. {p['name']} ({p['ip']})")
    choice = ask(f"Numéro de l'appareil à {action}")
    if not choice.isdigit() or not 1 <= int(choice) <= len(peers):
        raise WizardError("Choix invalide.")
    return peers[int(choice) - 1]["name"]


def cmd_add(name: str | None = None, full_tunnel: bool | None = None) -> None:
    require_root()
    meta = load_meta()
    conf = read_conf()
    peers = parse_peers(conf)

    if not name:
        name = ask("Nom de l'appareil (lettres, chiffres, - et _)", "telephone")
    if not NAME_RE.match(name):
        raise WizardError("Nom invalide : utilisez 1 à 32 caractères parmi lettres, chiffres, - et _.")
    if name in [p["name"] for p in peers]:
        raise WizardError(f"Un appareil nommé '{name}' existe déjà.")

    if full_tunnel is None:
        full_tunnel = confirm("Faire passer tout le trafic Internet par le VPN ? (non : accès au réseau VPN uniquement)")

    backup_conf()
    ip = next_free_ip([p["ip"] for p in peers])
    private, public = generate_keypair()
    psk = generate_psk()

    client_conf = (
        "[Interface]\n"
        f"PrivateKey = {private}\n"
        f"Address = {ip}/32\n"
        + (f"DNS = {meta.get('DNS', DEFAULT_DNS)}\n" if full_tunnel else "")
        + "\n"
        "[Peer]\n"
        f"PublicKey = {meta['SERVER_PUBKEY']}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {meta['ENDPOINT']}:{meta['PORT']}\n"
        + ("AllowedIPs = 0.0.0.0/0, ::/0\n" if full_tunnel else f"AllowedIPs = {SUBNET}\n")
        + "PersistentKeepalive = 25\n"
    )
    peer_block = (
        f"# BEGIN client {name}\n"
        "[Peer]\n"
        f"PublicKey = {public}\n"
        f"PresharedKey = {psk}\n"
        f"AllowedIPs = {ip}/32\n"
        f"# END client {name}\n\n"
    )

    client_file = CLIENTS_DIR / f"{name}.conf"
    write_file(client_file, client_conf)
    write_file(CONF, conf + peer_block)
    apply_config()

    ok(f"Appareil '{name}' créé avec l'adresse {ip}")
    step("QR code (application WireGuard sur smartphone : Ajouter un tunnel > Scanner)")
    show_qr(client_conf)
    step("Récupération du fichier sur un ordinateur")
    info(f"Fichier : {client_file}")
    info(f"Depuis votre PC : scp utilisateur@{meta['ENDPOINT']}:{client_file} .")
    warn("Ce fichier contient une clé privée : ne le transmettez jamais par un canal non chiffré "
         "et supprimez les copies inutiles.")


def human_bytes(n: int) -> str:
    value = float(n)
    for unit in ("o", "Kio", "Mio", "Gio"):
        if value < 1024:
            return f"{value:.0f} {unit}" if unit == "o" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} Tio"


def cmd_list() -> None:
    require_root()
    peers = parse_peers(read_conf())
    if not peers:
        info("Aucun appareil enregistré.")
        return
    handshakes, transfer = {}, {}
    if not DRY_RUN:
        out = run(["wg", "show", IFACE, "latest-handshakes"], mutating=False, check=False)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 2:
                handshakes[parts[0]] = int(parts[1])
        out = run(["wg", "show", IFACE, "transfer"], mutating=False, check=False)
        for line in out.splitlines():
            parts = line.split()
            if len(parts) == 3:
                transfer[parts[0]] = (int(parts[1]), int(parts[2]))
    now = int(datetime.now().timestamp())
    print()
    info(f"{'NOM':<20}{'ADRESSE':<14}{'DERNIÈRE CONNEXION':<22}{'REÇU':<12}ENVOYÉ")
    for p in peers:
        ts = handshakes.get(p["pubkey"], 0)
        if ts == 0:
            last = "jamais"
        else:
            delta = now - ts
            last = f"il y a {delta}s" if delta < 120 else f"il y a {delta // 60} min" if delta < 7200 else f"il y a {delta // 3600} h"
        rx, tx = transfer.get(p["pubkey"], (0, 0))
        info(f"{p['name']:<20}{p['ip']:<14}{last:<22}{human_bytes(rx):<12}{human_bytes(tx)}")


def cmd_qr(name: str | None = None) -> None:
    require_root()
    name = choose_client(name, "afficher")
    client_file = CLIENTS_DIR / f"{name}.conf"
    if not client_file.exists():
        raise WizardError(f"Fichier introuvable : {client_file}")
    show_qr(client_file.read_text())


def cmd_remove(name: str | None = None) -> None:
    require_root()
    name = choose_client(name, "révoquer")
    if not confirm(f"Révoquer définitivement '{name}' ?", default=False):
        info("Annulé.")
        return
    backup_conf()
    conf = read_conf()
    new_conf = re.sub(
        rf"# BEGIN client {re.escape(name)}\n.*?# END client {re.escape(name)}\n\n?",
        "", conf, flags=re.S,
    )
    write_file(CONF, new_conf)
    client_file = CLIENTS_DIR / f"{name}.conf"
    if DRY_RUN:
        print(f"  [simulation] suppression de {client_file}")
    elif client_file.exists():
        client_file.unlink()
    apply_config()
    ok(f"Appareil '{name}' révoqué : sa clé n'ouvre plus le tunnel.")


def cmd_backup() -> None:
    require_root()
    backup_conf()


# --------------------------------------------------------------------------
# Diagnostic
# --------------------------------------------------------------------------


def cmd_doctor() -> None:
    require_root()
    step("Diagnostic de l'installation")
    problems = 0

    state = run(["systemctl", "is-active", f"wg-quick@{IFACE}"], mutating=False, check=False)
    if state == "active":
        ok(f"Service wg-quick@{IFACE} actif")
    else:
        ko(f"Service wg-quick@{IFACE} inactif. Essayez : systemctl restart wg-quick@{IFACE}")
        problems += 1

    fwd = run(["sysctl", "-n", "net.ipv4.ip_forward"], mutating=False, check=False)
    if fwd == "1":
        ok("Routage IPv4 activé")
    else:
        ko("Routage IPv4 désactivé. Essayez : sysctl -w net.ipv4.ip_forward=1")
        problems += 1

    try:
        meta = load_meta()
        port = meta["PORT"]
        ufw = run(["ufw", "status"], mutating=False, check=False)
        if "inactive" in ufw.lower():
            warn("UFW est inactif : aucun filtrage entrant.")
        elif re.search(rf"{port}/udp\s+ALLOW", ufw):
            ok(f"UFW autorise {port}/udp")
        else:
            ko(f"Le port {port}/udp n'est pas autorisé dans UFW. Essayez : ufw allow {port}/udp")
            problems += 1
    except WizardError as exc:
        ko(str(exc))
        problems += 1

    out = run(["wg", "show", IFACE, "latest-handshakes"], mutating=False, check=False)
    recent = [l for l in out.splitlines() if len(l.split()) == 2 and l.split()[1] != "0"]
    if recent:
        ok(f"{len(recent)} appareil(s) ont déjà établi une connexion")
    else:
        warn("Aucune connexion établie pour l'instant. Si un client ne se connecte pas, "
             "vérifiez le pare-feu du panneau de l'hébergeur (port UDP).")

    print()
    if problems:
        ko(f"{problems} problème(s) détecté(s).")
    else:
        ok("Aucun problème détecté.")


# --------------------------------------------------------------------------
# Menu et point d'entrée
# --------------------------------------------------------------------------

MENU = [
    ("Installer le VPN sur ce serveur", cmd_install),
    ("Ajouter un appareil", cmd_add),
    ("Lister les appareils", cmd_list),
    ("Afficher le QR code d'un appareil", cmd_qr),
    ("Révoquer un appareil", cmd_remove),
    ("Diagnostic", cmd_doctor),
    ("Sauvegarder la configuration", cmd_backup),
]


def interactive_menu() -> None:
    while True:
        print(_c("1", "\nwg-wizard : assistant WireGuard"))
        if DRY_RUN:
            warn("Mode simulation : aucune modification ne sera effectuée.")
        for i, (label, _) in enumerate(MENU, 1):
            info(f"{i}. {label}")
        info("0. Quitter")
        choice = ask("Votre choix")
        if choice in ("0", "q", ""):
            return
        if choice.isdigit() and 1 <= int(choice) <= len(MENU):
            try:
                MENU[int(choice) - 1][1]()
            except WizardError as exc:
                ko(str(exc))
        else:
            warn("Choix invalide.")


def main() -> int:
    global DRY_RUN
    parser = argparse.ArgumentParser(description="Assistant d'installation WireGuard pour débutants.")
    parser.add_argument("--dry-run", action="store_true", help="simuler sans rien modifier")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("install")
    for name in ("add", "qr", "remove"):
        p = sub.add_parser(name)
        p.add_argument("name", nargs="?")
        if name == "add":
            p.add_argument("--split", action="store_true",
                           help="accès au réseau VPN uniquement (pas de tunnel complet)")
    for name in ("list", "doctor", "backup"):
        sub.add_parser(name)
    args = parser.parse_args()
    DRY_RUN = args.dry_run

    actions = {
        "install": cmd_install, "list": cmd_list, "doctor": cmd_doctor, "backup": cmd_backup,
        "add": lambda: cmd_add(args.name, False if args.split else None), "qr": lambda: cmd_qr(args.name),
        "remove": lambda: cmd_remove(args.name),
    }
    try:
        if args.command:
            actions[args.command]()
        else:
            interactive_menu()
    except WizardError as exc:
        ko(str(exc))
        return 1
    except KeyboardInterrupt:
        print("\nInterrompu.")
        return 130
    return 0


if __name__ == "__main__":
    sys.exit(main())


'''
__/\\\\\_____/\\\________/\\\\\\\\\__/\\\\\\\\\\\\\__________/\\\\\\\\\_        
 _\/\\\\\\___\/\\\_____/\\\////////__\/\\\/////////\\\_____/\\\////////__       
  _\/\\\/\\\__\/\\\___/\\\/___________\/\\\_______\/\\\___/\\\/___________      
   _\/\\\//\\\_\/\\\__/\\\_____________\/\\\\\\\\\\\\\/___/\\\_____________     
    _\/\\\\//\\\\/\\\_\/\\\_____________\/\\\/////////____\/\\\_____________    
     _\/\\\_\//\\\/\\\_\//\\\____________\/\\\_____________\//\\\____________   
      _\/\\\__\//\\\\\\__\///\\\__________\/\\\______________\///\\\__________  
       _\/\\\___\//\\\\\____\////\\\\\\\\\_\/\\\________________\////\\\\\\\\\_ 
        _\///_____\/////________\/////////__\///____________________\/////////__

        6E6520636F706965207061732C2063726565
  Auteur: Crypthium
  COPYRIGHT © 2025 Crypthium — Tous droits réservés
 '''
