# -*- coding: utf-8 -*-
"""
SERVEUR COLLECTE v5.0 - Stage Cyber I2SI
Flask + PostgreSQL : collecte, inventaire, dashboard
"""

import json, os, datetime, re, hashlib, io, csv, gzip, copy, threading

# NVD API key: set NVD_API_KEY in .env file or environment variable
_nvd_key = os.environ.get("NVD_API_KEY", "")
if not _nvd_key:
    try:
        with open(".env", encoding="utf-8") as _f:
            for _line in _f:
                if _line.strip().startswith("NVD_API_KEY="):
                    _nvd_key = _line.strip().split("=", 1)[1].strip("'\"")
                    break
    except:
        pass
if not _nvd_key:
    _nvd_key = os.environ.get("NVD_API_KEY", "")
if _nvd_key:
    os.environ["NVD_API_KEY"] = _nvd_key

# Default to SQLite
if not os.environ.get("DB_TYPE"):
    os.environ["DB_TYPE"] = "sqlite"

from flask import Flask, request, jsonify, send_from_directory, Response
from database import (
    get_conn,
    commit,
    close,
    row_to_dict,
    rows_to_list,
    execute,
    fetchone,
    fetchall,
    init_enterprise_tables,
    is_sqlite,
)
from cve_service import enrich_software, batch_enrich, load_cisa_kev
from export_service import (
    export_csv,
    export_json,
    export_xlsx,
    export_pdf,
    HAS_OPENPYXL,
)
from export_service import (
    LOGICIELS_COLUMNS,
    MACHINES_COLUMNS,
    VULNS_COLUMNS,
    LICENCES_COLUMNS,
)
from enrichissement import enrichir_executable_portable
from version_editor_service import (
    update_latest_version,
    batch_update_latest_versions,
    lookup_editor_country,
)

app = Flask(__name__, static_folder=None)

CATEGORIES = {
    "jeu": [
        "gta",
        "minecraft",
        "fortnite",
        "steam",
        "epic",
        "uplay",
        "origin",
        "battlefield",
        "call of duty",
        "valorant",
        "league of legends",
        "counter-strike",
        "cyberpunk",
        "elden ring",
        "game",
        "rockstar",
        "grand theft auto",
        "ubisoft",
        "ea games",
        "blizzard",
        "battlenet",
        "nintendo",
        "sega",
        "sony",
        "xbox",
        "rpg",
        "fps",
        "mmo",
    ],
    "Navigateur": [
        "chrome",
        "firefox",
        "edge",
        "opera",
        "brave",
        "vivaldi",
        "safari",
        "chromium",
    ],
    "Securite": [
        "avast",
        "avg",
        "kaspersky",
        "norton",
        "bitdefender",
        "eset",
        "malwarebytes",
        "defender",
        "mcafee",
        "trend micro",
        "avira",
        "panda",
        "crowdstrike",
        "sentinel",
        "sophos",
        "carbon black",
    ],
    "Bureautique": [
        "word",
        "excel",
        "powerpoint",
        "outlook",
        "office",
        "libreoffice",
        "openoffice",
        "writer",
        "calc",
        "wps office",
        "onlyoffice",
    ],
    "Developpement": [
        "vscode",
        "visual studio",
        "git",
        "node",
        "python",
        "java",
        "eclipse",
        "intellij",
        "pycharm",
        "sublime",
        "jetbrains",
        "docker",
        "kubernetes",
        "postman",
        "insomnia",
    ],
    "Communication": [
        "teams",
        "slack",
        "zoom",
        "discord",
        "skype",
        "webex",
        "signal",
        "telegram",
        "whatsapp",
        "mattermost",
        "rocket",
    ],
    "Utilitaire": [
        "7zip",
        "winrar",
        "notepad",
        "acrobat",
        "foxit",
        "everything",
        "putty",
        "winscp",
        "filezilla",
        "winmerge",
        "powertoys",
        "greenshot",
        "sharex",
        "obsidian",
        "treemanager",
        "treesize",
        "ccleaner",
        "sumatra",
        "pdf",
    ],
    "Reseau": [
        "nmap",
        "wireshark",
        "advanced ip",
        "angry ip",
        "putty",
        "winscp",
        "filezilla",
        "ping",
        "tracert",
        "netstat",
    ],
    "SupportDistant": [
        "teamviewer",
        "anydesk",
        "vnc",
        "splashtop",
        "logmein",
        "screenconnect",
        "remote desktop",
    ],
    "Multimedia": [
        "spotify",
        "vlc",
        "mpc",
        "foobar",
        "itunes",
        "photoshop",
        "gimp",
        "krita",
        "blender",
        "audacity",
        "obs",
        "avidemux",
        "handbrake",
        "ffmpeg",
    ],
    "BaseDonnees": [
        "sql server",
        "mysql",
        "mariadb",
        "postgresql",
        "mongodb",
        "oracle",
        "redis",
        "elasticsearch",
        "cassandra",
        "sqlite",
    ],
    "Virtualisation": [
        "vmware",
        "virtualbox",
        "hyper-v",
        "docker",
        "vagrant",
        "wsl",
        "proxmox",
        "qemu",
    ],
    "Cloud": [
        "dropbox",
        "onedrive",
        "google drive",
        "icloud",
        "nextcloud",
        "synology",
        "pcloud",
        "mega",
    ],
    "MotsDePasse": [
        "keepass",
        "bitwarden",
        "lastpass",
        "dashlane",
        "1password",
        "nordpass",
        "keeper",
    ],
    "Chiffrement": ["veracrypt", "gpg4win", "gnupg", "bitlocker", "axcrypt"],
    "Sauvegarde": ["veeam", "acronis", "easeus", "macrium", "aomei", "backup"],
    "Creation": [
        "photoshop",
        "illustrator",
        "indesign",
        "premiere",
        "after effects",
        "davinci",
        "figma",
        "canva",
        "autocad",
        "solidworks",
        "blender",
    ],
    "Pilote": ["nvidia", "amd", "intel", "realtek", "driver", "catalyst", "geforce"],
    "Gestion": [
        "sap",
        "salesforce",
        "odoo",
        "erp",
        "crm",
        "dynamics",
        "oracle crm",
        "sas",
    ],
    "OutilsSysteme": [
        "cpu-z",
        "gpu-z",
        "hwinfo",
        "crystaldiskinfo",
        "speccy",
        "msi afterburner",
        "hwmonitor",
        "process explorer",
        "autoruns",
        "tcpview",
        "sysinternals",
        "psexec",
    ],
    "Proxy": ["proxifier", "charles", "burp", "fiddler"],
}

CSV_SERVEUR = "AppInvRawData_trie.csv"
SERVEUR_APPS = set()
SERVEUR_APPS_NOM_EDITEUR = set()
if os.path.exists(CSV_SERVEUR):
    try:
        with open(CSV_SERVEUR, encoding="utf-8") as f:
            reader = csv.DictReader(f)
            for row in reader:
                nom = (row.get("ApplicationName") or "").strip().lower()
                edt = (row.get("ApplicationPublisher") or "").strip().lower()
                if nom:
                    SERVEUR_APPS.add(nom)
                    SERVEUR_APPS_NOM_EDITEUR.add((nom, edt))
    except Exception as e:
        print(f"⚠ Erreur chargement {CSV_SERVEUR}: {e}")

# ── Éditeurs database (pays, site, métier par défaut) ──────
_EDITEURS_PATH = os.path.join(os.path.dirname(__file__) or ".", "editeurs.json")
EDITEURS = {}
try:
    with open(_EDITEURS_PATH, "r", encoding="utf-8") as f:
        EDITEURS = json.load(f)
except Exception as e:
    print(f"⚠ Erreur chargement editeurs.json: {e}")


def _get_editeur_info(editeur_nom):
    if not editeur_nom:
        return None
    key = editeur_nom.strip().lower()
    if key in EDITEURS:
        return EDITEURS[key]
    for k, v in EDITEURS.items():
        if k in key or key in k:
            return v
    return None


_RESTRICTIONS_PAR_PAYS = {
    "US": "ITAR/EAR (Export Administration Regulations)",
    "CN": "Loi chinoise cybersecurite + PIPL + Great Firewall",
    "RU": "Sanctions internationales + FSB/SORM",
    "IR": "Sanctions OFAC + CGU IRGC",
    "KP": "Sanctions totales ONU + OFAC + embargo",
    "SY": "Sanctions OFAC + UE + Loi Caesar",
    "CU": "Sanctions OFAC + embargo commercial",
    "BY": "Sanctions UE/US (crise Ukrainienne)",
    "VE": "Sanctions OFAC + UE",
    "MM": "Sanctions UE/US + embargo armement",
    "SD": "Sanctions OFAC + conflit civil",
    "YE": "Conflit arme + sanctions Houthis",
    "ER": "Service militaire obligatoire illimite + surveillance",
    "CF": "Sanctions ONU + embargos",
    "SS": "Conflit civil + sanctions ONU",
    "HK": "Loi securite nationale chinoise (Article 23)",
    "SA": "Surveillance etatique + lois anti-chiffrement",
    "PK": "PECA + surveillance internet etatique",
    "IQ": "Sanctions partielles + conflit",
    "AF": "Sanctions Taliban + effondrement institutionnel",
    "ZW": "Surveillance etatique + lois restrictions internet",
    "LB": "Sanctions Hezbollah + instabilite",
    "LY": "Sanctions ONU + conflit civil",
    "SO": "Conflit + absence cadre legal",
    "ET": "Surveillance etatique + loi antiterroriste",
    "KH": "Loi cybersecurite autoritaire",
    "KZ": "Loi souverainete internet + surveillance",
    "UZ": "Surveillance etatique + censure internet",
    "AZ": "Conflit + surveillance",
    "IL": "Lois cybersecurite strictes + surveillance de masse",
    "SG": "OSA + loi cybersecurite autoritaire",
    "VN": "Loi cybersecurite + censure internet + data localisation",
    "TR": "Loi internet restrictive + censure + surveillance",
    "UA": "Conflit arme + lois temps de guerre",
}

_RISQUE_SOUVERAINETE_PAR_PAYS = {
    # Critique — surveillance etatique maximale, sanctions, lois restrictives
    "CN": "Critique",
    "RU": "Critique",
    "IR": "Critique",
    "KP": "Critique",
    "SY": "Critique",
    "CU": "Critique",
    "VE": "Critique",
    "MM": "Critique",
    "SD": "Critique",
    "YE": "Critique",
    "ER": "Critique",
    "CF": "Critique",
    "SS": "Critique",
    # Eleve — restrictions fortes, surveillance, instabilite
    "BY": "Eleve",
    "HK": "Eleve",
    "SA": "Eleve",
    "PK": "Eleve",
    "IQ": "Eleve",
    "AF": "Eleve",
    "ZW": "Eleve",
    "LB": "Eleve",
    "LY": "Eleve",
    "SO": "Eleve",
    "ET": "Eleve",
    "KH": "Eleve",
    "LA": "Eleve",
    "TJ": "Eleve",
    "UZ": "Eleve",
    "KZ": "Eleve",
    "AZ": "Eleve",
    "AM": "Eleve",
    "KG": "Eleve",
    "TM": "Eleve",
    "MN": "Eleve",
    # Moyen — allies sous surveillance, cloud americain, legislations exterritoriales
    "US": "Moyen",
    "GB": "Moyen",
    "AU": "Moyen",
    "CA": "Moyen",
    "NZ": "Moyen",
    "SG": "Moyen",
    "IL": "Moyen",
    "KR": "Moyen",
    "TW": "Moyen",
    "JP": "Moyen",
    "IN": "Moyen",
    "BR": "Moyen",
    "MX": "Moyen",
    "AR": "Moyen",
    "CL": "Moyen",
    "CO": "Moyen",
    "PE": "Moyen",
    "ZA": "Moyen",
    "NG": "Moyen",
    "KE": "Moyen",
    "MA": "Moyen",
    "TN": "Moyen",
    "DZ": "Moyen",
    "EG": "Moyen",
    "TR": "Moyen",
    "AE": "Moyen",
    "QA": "Moyen",
    "KW": "Moyen",
    "OM": "Moyen",
    "BH": "Moyen",
    "MY": "Moyen",
    "ID": "Moyen",
    "PH": "Moyen",
    "TH": "Moyen",
    "VN": "Moyen",
    "UA": "Moyen",
    "RS": "Moyen",
    "MK": "Moyen",
    "AL": "Moyen",
    "BA": "Moyen",
    "XK": "Moyen",
    "GE": "Moyen",
    "MD": "Moyen",
    "ME": "Moyen",
    # Faible — UE/EEE, Suisse, garanties fortes RGPD
    "FR": "Faible",
    "DE": "Faible",
    "CH": "Faible",
    "NL": "Faible",
    "SE": "Faible",
    "NO": "Faible",
    "DK": "Faible",
    "FI": "Faible",
    "BE": "Faible",
    "AT": "Faible",
    "IE": "Faible",
    "IT": "Faible",
    "ES": "Faible",
    "PT": "Faible",
    "LU": "Faible",
    "GR": "Faible",
    "CY": "Faible",
    "MT": "Faible",
    "CZ": "Faible",
    "SK": "Faible",
    "PL": "Faible",
    "HU": "Faible",
    "RO": "Faible",
    "BG": "Faible",
    "HR": "Faible",
    "SI": "Faible",
    "EE": "Faible",
    "LV": "Faible",
    "LT": "Faible",
    "IS": "Faible",
    "LI": "Faible",
    "MC": "Faible",
    "AD": "Faible",
    "SM": "Faible",
}


def _compute_sovereignty(pays, ed_info=None):
    """Calcule les risques de souverainete a partir du pays editeur.
    Si ed_info contient les champs specifiques (siege_pays, developpement_pays, etc.),
    ils sont utilises en priorite."""
    if not pays:
        return {
            "pays_editeur": "",
            "pays_siege": "",
            "pays_hebergement": "",
            "pays_developpement": "",
            "restrictions": "",
            "risque": "Faible",
        }
    ed_info = ed_info or {}
    pays_siege = ed_info.get("siege_pays") or pays
    pays_developpement = ed_info.get("developpement_pays") or pays
    pays_hebergement = ed_info.get("hebergement_pays") or pays
    restrictions = ed_info.get("restrictions") or _RESTRICTIONS_PAR_PAYS.get(pays, "")
    risque = ed_info.get("risque_souverainete") or _RISQUE_SOUVERAINETE_PAR_PAYS.get(
        pays, "Faible"
    )
    return {
        "pays_editeur": pays,
        "pays_siege": pays_siege,
        "pays_hebergement": pays_hebergement,
        "pays_developpement": pays_developpement,
        "restrictions": restrictions,
        "risque": risque,
    }


def _whois_lookup(domain):
    """Recupere le pays d'enregistrement d'un domaine via WHOIS (socket direct + fallback)."""
    import socket, re

    def _query_whois(server, query):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect((server, 43))
            s.sendall((query + "\r\n").encode())
            data = b""
            while True:
                chunk = s.recv(4096)
                if not chunk:
                    break
                data += chunk
            s.close()
            return data.decode("utf-8", errors="ignore")
        except:
            return ""

    whois_servers = [("whois.iana.org", domain), ("whois.verisign-grs.com", domain)]
    for svr, q in whois_servers:
        output = _query_whois(svr, q)
        if "whois:" in output:
            for line in output.splitlines():
                m = re.match(r"whois:\s*(\S+)", line, re.IGNORECASE)
                if m:
                    output = _query_whois(m.group(1), domain)
                    break
        patterns = [
            r"Country:\s*(\w{2})",
            r"country:\s*(\w{2})",
            r"Registrant Country:\s*(\w{2})",
            r"registrant country:\s*(\w{2})",
        ]
        for p in patterns:
            m = re.search(p, output, re.IGNORECASE)
            if m:
                return m.group(1).upper()
    return None


def _ip_geolookup(domain):
    """Resout un domaine en IP puis interroge ip-api.com pour le pays."""
    import socket, requests

    try:
        ip = socket.gethostbyname(domain)
        r = requests.get(f"http://ip-api.com/json/{ip}?fields=countryCode", timeout=10)
        if r.status_code == 200:
            data = r.json()
            if data.get("status") == "success":
                return data["countryCode"].upper()
    except Exception:
        pass
    return None


def _auto_enrich_sovereignty():
    """Enrichit editeurs.json avec les donnees de souverainete via WHOIS + IP geo."""
    import json, os, re
    from urllib.parse import urlparse

    EDITEURS_PATH = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "editeurs.json"
    )
    try:
        with open(EDITEURS_PATH, "r", encoding="utf-8") as f:
            editeurs = json.load(f)
    except:
        return {"error": "Impossible de lire editeurs.json"}
    total = len(editeurs)
    enriched = 0
    for key, val in editeurs.items():
        if val.get("pays") and val.get("siege_pays"):
            continue  # deja enrichi
        site = val.get("site", "").strip()
        if not site:
            continue
        parsed = urlparse(site)
        domain = parsed.hostname or site
        if not domain:
            continue
        domain = re.sub(r"^www\.", "", domain).lower()
        # Deja connus
        if domain in (
            "microsoft.com",
            "google.com",
            "apple.com",
            "adobe.com",
            "oracle.com",
            "ibm.com",
            "intel.com",
            "amd.com",
            "nvidia.com",
        ):
            continue
        pays = _whois_lookup(domain)
        if not pays:
            pays = _ip_geolookup(domain)
        if pays:
            if not val.get("pays"):
                val["pays"] = pays
            if not val.get("siege_pays"):
                val["siege_pays"] = pays
            enriched += 1
    with open(EDITEURS_PATH, "w", encoding="utf-8") as f:
        json.dump(editeurs, f, ensure_ascii=False, indent=2)
    return {"total": total, "enriched": enriched}


def fetch_latest_version(software_name):
    """Essaie de recuperer la derniere version via winget."""
    import subprocess, shutil

    if not shutil.which("winget"):
        return ""
    try:
        res = subprocess.run(
            [
                "winget",
                "search",
                "--name",
                software_name,
                "--exact",
                "--accept-source-agreements",
            ],
            capture_output=True,
            text=True,
            timeout=8,
        )
        lines = res.stdout.split("\n")
        for i, line in enumerate(lines):
            if line.startswith("---"):
                if i + 1 < len(lines):
                    parts = lines[i + 1].strip().split()
                    if len(parts) >= 3:
                        # Normalement le format est: Nom ID Version Source
                        # On prend l'avant dernier mot
                        version = parts[-2]
                        if version and version[0].isdigit():
                            return version
    except Exception:
        pass
    return ""


def enrich_editor_info(sw_dict):
    """Enrichit un logiciel avec les infos connues de l'editeur."""
    pub = sw_dict.get("ApplicationPublisher")
    info = _get_editeur_info(pub)
    if info:
        sw_dict["PaysOrigine"] = info.get("pays", "Inconnu")
        sw_dict["SiteWeb"] = info.get("site", "")
    return sw_dict


def _classifier_metier(nom, editeur="", categorie=""):
    n = (nom or "").strip().lower()
    e = (editeur or "").strip().lower()

    # Utilise des regex avec limite de mot (boundary) pour eviter les faux positifs
    def _match(kw):
        return bool(re.search(r"(?<![a-z])" + re.escape(kw) + r"(?![a-z])", n)) or bool(
            re.search(r"(?<![a-z])" + re.escape(kw) + r"(?![a-z])", e)
        )

    metiers = [
        (
            "Developpement",
            [
                "visual studio",
                "vscode",
                "vscodium",
                "code",
                "python",
                "java",
                "nodejs",
                "docker desktop",
                "docker engine",
                "kubernetes",
                "jetbrains",
                "intellij",
                "pycharm",
                "webstorm",
                "goland",
                "postman",
                "jupyter",
                "anaconda",
                "mingw",
                "golang",
                ".net core",
                "rustc",
                "ruby",
                "php",
                "git",
                "npm",
                "yarn",
                "pnpm",
                "webpack",
                "babel",
                "typescript",
                "kotlin",
                "swift",
                "dart",
                "flutter",
                "cmake",
                "makefile",
                "gradle",
                "maven",
                "tomcat",
                "sdk",
                "api",
                "compilateur",
            ],
        ),
        (
            "BaseDonnees",
            [
                "mysql",
                "postgresql",
                "mongodb",
                "mariadb",
                "sqlite",
                "oracle",
                "redis",
                "mssql",
                "ssms",
                "dbeaver",
                "heidisql",
                "couchdb",
                "elasticsearch",
                "cassandra",
                "sql server",
                "datagrip",
                "nosql",
                "influxdb",
            ],
        ),
        (
            "Design",
            [
                "photoshop",
                "illustrator",
                "indesign",
                "gimp",
                "blender",
                "autocad",
                "fusion 360",
                "sketchup",
                "figma",
                "canva",
                "coreldraw",
                "3ds max",
                "affinity",
                "krita",
                "lightroom",
                "premiere pro",
                "after effects",
                "maya",
                "zbrush",
                "cinema 4d",
                "rhinoceros",
            ],
        ),
        (
            "Multimedia",
            [
                "vlc media player",
                "spotify",
                "itunes",
                "apple music",
                "obs studio",
                "audacity",
                "handbrake",
                "ffmpeg",
                "steam",
                "epic games",
                "gog galaxy",
            ],
        ),
        (
            "Bureautique",
            [
                "microsoft 365",
                "microsoft office",
                "libreoffice",
                "openoffice",
                "wps office",
                "onlyoffice",
                "adobe acrobat",
                "foxit reader",
                "word",
                "excel",
                "powerpoint",
                "outlook",
                "onenote",
                "publisher",
                "access",
            ],
        ),
        (
            "Securite",
            [
                "antivirus",
                "windows defender",
                "firewall",
                "vpn",
                "bitdefender",
                "kaspersky",
                "mcafee",
                "norton",
                "eset",
                "avast",
                "malwarebytes",
                "crowdstrike",
                "sentinelone",
                "carbon black",
                "sysmon",
                "wazuh",
                "ossec",
                "sophos",
                "fortinet",
            ],
        ),
        (
            "Communication",
            [
                "microsoft teams",
                "slack",
                "zoom",
                "skype",
                "telegram",
                "whatsapp",
                "signal",
                "thunderbird",
            ],
        ),
        (
            "Reseau",
            [
                "google chrome",
                "mozilla firefox",
                "microsoft edge",
                "opera",
                "brave browser",
                "vivaldi",
                "tor browser",
                "putty",
                "winscp",
                "filezilla",
                "wireshark",
                "nmap",
                "cisco",
                "curl",
                "wget",
                "openssh",
                "openvpn",
                "cloudflare",
            ],
        ),
        (
            "Finance",
            [
                "sap",
                "sage",
                "comptabilite",
                "facture",
                "paie",
                "caisse",
                "erp",
                "cogicom",
                "quickbooks",
                "xero",
                "power bi",
                "tableau",
            ],
        ),
        (
            "Utilitaire",
            [
                "7-zip",
                "winrar",
                "winzip",
                "peazip",
                "ccleaner",
                "total commander",
                "everything",
                "greenshot",
                "snagit",
                "sharex",
                "notepad++",
                "sublime text",
                "obsidian",
                "teamviewer",
                "anydesk",
                "powertoys",
                "process explorer",
                "autoruns",
                "procmon",
                "tcpview",
            ],
        ),
        (
            "Systeme",
            [
                "windows 10",
                "windows 11",
                "windows server",
                "directx",
                "visual c++ redistributable",
                "microsoft visual c++",
                ".net framework",
                "powershell",
                "hyper-v",
                "bios",
                "intel",
                "amd",
                "nvidia",
                "chipset",
                "surface",
                "system firmware",
                "uefi",
            ],
        ),
    ]
    for metier, keywords in metiers:
        for kw in keywords:
            if _match(kw):
                return metier
    # Fallback: editeur info si aucun mot-cle n'a matché
    info = _get_editeur_info(e)
    if info and info.get("metier_defaut"):
        return info["metier_defaut"]
    return "Autre"


def _systeme_ou_app(sw):
    """Retourne le type d'installation. Accepte dict ou sqlite3.Row."""
    if not isinstance(sw, dict):
        try:
            sw = dict(sw)  # sqlite3.Row -> dict
        except Exception:
            return "Application"
    src = (sw.get("install_source") or "").lower()
    systeme_src = (
        "registry",
        "windowsfeature",
        "appxprovisioned",
        "windowsupdate",
        "wsl",
    )
    if src in systeme_src:
        return "Systeme"
    if src in ("portable", "path"):
        return "Portable"
    if src in ("pip", "npm", "composer", "winget", "chocolatey"):
        return "Developpement"
    if src:
        return "Application"
    return "Inconnu"


def detecter_categorie(nom, editeur="", description=""):
    texte = f"{nom} {editeur} {description}".lower()
    for cat, mots in CATEGORIES.items():
        for m in mots:
            if re.search(r"(?<![a-z])" + re.escape(m) + r"(?![a-z])", texte):
                return cat
    return None


DETECTEUR_LICENCE = {
    "Open Source": [
        "git",
        "python",
        "node",
        "rust",
        "golang",
        "ruby",
        "php",
        "perl",
        "vim",
        "emacs",
        "nano",
        "bash",
        "zsh",
        "gcc",
        "llvm",
        "clang",
        "cmake",
        "mingw",
        "cygwin",
        "openssl",
        "openssh",
        "openvpn",
        "nginx",
        "apache",
        "mysql",
        "mariadb",
        "postgresql",
        "mongodb",
        "redis",
        "sqlite",
        "elasticsearch",
        "cassandra",
        "docker",
        "kubernetes",
        "terraform",
        "ansible",
        "vagrant",
        "virtualbox",
        "blender",
        "gimp",
        "inkscape",
        "krita",
        "audacity",
        "obsidian",
        "keepass",
        "bitwarden",
        "7-zip",
        "notepad++",
        "vscode",
        "firefox",
        "chromium",
        "thunderbird",
        "filezilla",
        "putty",
        "winscp",
        "nmap",
        "wireshark",
        "burp",
        "gpg4win",
        "veracrypt",
        "ffmpeg",
        "vlc",
        "mpc-hc",
        "mpc-be",
        "foobar2000",
        "handbrake",
        "youtube-dl",
        "julia",
        "godot",
        "qt",
        "gtk",
        "pytorch",
        "tensorflow",
        "eclipse",
        "netbeans",
        "libreoffice",
        "openoffice",
        "wordpress",
        "drupal",
        "joomla",
        "obs-studio",
        "xmpp",
        "pidgin",
        "irssi",
        "weechat",
        "mutt",
        "wireguard",
        "kitty",
        "verdaccio",
        "sonarqube",
        "jenkins",
        "grafana",
        "prometheus",
        "influxdb",
        "puppet",
        "salt",
        "chef",
        "packer",
        "celery",
        "rabbitmq",
        "zeromq",
        "haproxy",
        "traefik",
        "ubuntu",
        "debian",
        "fedora",
        "centos",
        "arch",
        "gentoo",
        "linux",
        "bsd",
        "freebsd",
        "openbsd",
        "netbsd",
        "sonatype",
        "nexus",
        "keycloak",
        "authelia",
        "authentik",
        "heimdall",
        "organizr",
        "homeassistant",
        "esphome",
        "mqtt",
        "gitea",
        "forgejo",
        "nextcloud",
        "seafile",
        "syncthing",
        "jellyfin",
        "plex",
        "emby",
        "kodi",
        "certbot",
        "acme.sh",
        "caddy",
        "istio",
        "linkerd",
        "minio",
        "ceph",
        "rclone",
        "restic",
        "borg",
        "ansible-lint",
        "yamllint",
        "shellcheck",
        "hadolint",
        "zabbix",
        "nagios",
        "icinga",
        "netdata",
        "pi-hole",
        "adguard",
        "unbound",
        "bind9",
        "roundcube",
        "rainloop",
        "squirrelmail",
        "mattermost",
        "rocketchat",
        "zulip",
        "signal-desktop",
        "element",
        "riot",
        "protonvpn",
        "protonmail",
        "proton",
        "virustotal",
        "hybrid-analysis",
        "tor browser",
        "torbrowser",
        "tails",
        "openwrt",
        "dd-wrt",
        "tomato",
        "postman",
        "insomnia",
        "bruno",
        "dbeaver",
        "heidisql",
        "adminer",
        "ngrok",
        "frp",
        "cloudflared",
        "kind",
        "minikube",
        "k3s",
        "microk8s",
        "rustdesk",
        "scrcpy",
        "7z",
        "7-zip",
        "p7zip",
        "ripgrep",
        "exa",
        "fzf",
        "yq",
        "starship",
        "neovim",
        "lunarvim",
        "astro",
        "yarn",
        "pnpm",
        "npm",
        "bun",
        "deno",
        "ghidra",
        "radare2",
        "binwalk",
        "volatility",
        "openrefine",
        "pentaho",
        "spark",
        "hadoop",
        "nushell",
        "fish shell",
        "powershell core",
        "pwsh",
    ],
    "Inclus Windows": [
        "windows",
        "microsoft edge",
        "internet explorer",
        "directx",
        "powershell",
        "onedrive",
        "paint",
        "notepad",
        "wordpad",
        "calculatrice",
        "cmd",
        "explorer",
        "task manager",
        "cortana",
        "microsoft store",
        "windows update",
        "windows media player",
        "xbox",
        "microsoft account",
        "windows security",
        ".net",
        "dotnet",
        "microsoft visual c",
        "microsoft .net",
        "visual c++",
        "microsoft c++",
        "windows defender",
        "msedge",
        "windows search",
        "windows backup",
        "windows remote",
        "windows hello",
        "windows fax",
        "windows speech",
        "mspaint",
        "snipping tool",
        "sticky notes",
        "steps recorder",
        "narrator",
        "magnifier",
        "osk",
        "mobility center",
    ],
    "Freeware": [
        "adobe acrobat reader",
        "foxit",
        "sumatra",
        "sumatrapdf",
        "everything",
        "speccy",
        "hwmonitor",
        "cpu-z",
        "gpu-z",
        "crystaldiskinfo",
        "tree size",
        "ccleaner",
        "greenshot",
        "sharex",
        "google chrome",
        "chrome",
        "chromium",
        "brave",
        "vivaldi",
        "opera",
        "skype",
        "discord",
        "telegram",
        "whatsapp",
        "slack",
        "zoom",
        "splashtop",
        "steam",
        "epic games",
        "gog",
        "battlenet",
        "google drive",
        "icloud",
        "mega",
        "pcloud",
        "dropbox",
        "notepad++",
        "vlc",
        "mpc-hc",
        "mpc-be",
        "shotcut",
        "openshot",
        "avidemux",
        "hwinfo",
        "crystaldiskmark",
        "memtest",
        "powertoys",
        "microsoft powertoys",
        "revo uninstaller",
        "geek uninstaller",
        "malwarebytes",
        "adwcleaner",
        "tor browser",
        "torbrowser",
        "obsidian",
        "keepass",
        "bitwarden",
        "f.lux",
        "auto dark mode",
        "windirstat",
        "wiztree",
        "quicklook",
        "seer",
        "ditto clipboard",
        "clipx",
        "lightscreen",
        "greenshot",
        "sharex",
        "classic shell",
        "open shell",
        "startallback",
        "recuva",
        "defraggler",
        "speccy",
        "crystaldiskinfo",
        "crystaldiskmark",
        "qbit",
        "transmission",
        "deluge",
        "audacity",
        "gimp",
        "inkscape",
        "krita",
        "handbrake",
        "obs-studio",
        "rufus",
        "balena etcher",
        "ventoy",
        "hdd low level format",
        "notion",
        "todoist",
        "teamviewer",
        "anydesk",
        "duckduckgo",
        "ubisoft connect",
        "riot games",
        "battle.net",
        "google earth",
        "google desk",
        "google photos backup",
        "microsoft teams",
        "skype for business",
        "winrar",
        "iobit",
        "advanced systemcare",
        "macrium reflect",
        "minitool partition",
        "plex media server",
        "jellyfin media server",
        "freedownload manager",
        "jdownloader",
        "etcher",
        "balena etche",
    ],
    "Adware": [
        "adobe flash",
        "adobe air",
        "shockwave",
        "yahoo toolbar",
        "ask toolbar",
        "browser guard",
        "search protector",
        "conduit",
        "babylon",
        "delta",
        "search.safe",
        "web companion",
        "spigot",
        "open candy",
        "pinterest save",
        "pricegong",
        "sweetim",
        "funmoods",
        "incredibar",
        "bundle",
        "installcore",
        "outbrain",
        "taboola",
    ],
    "Freemium": [
        "spotify",
        "dropbox",
        "evernote",
        "trello",
        "github",
        "gitlab",
        "jira",
        "confluence",
        "canva",
        "figma",
        "mailchimp",
        "hubspot",
        "notion",
        "todoist",
        "lastpass",
        "dashlane",
        "logitech g hub",
        "logitech options",
        "signal",
        "telegram",
        "discord",
        "mega",
        "pcloud",
        "wix",
        "squarespace",
        "loom",
        "miro",
        "mural",
        "sentry",
        "datadog",
        "newrelic",
        "clickup",
        "asana",
        "monday",
        "trello",
        "nvidia geforce experience",
        "amd adrenalin",
        "teamviewer",
        "anydesk",
        "splashtop",
        "expressvpn",
        "nordvpn",
        "surfshark",
        "zoom",
        "slack",
        "scribe",
        "notion",
        "coda",
        "reddit",
        "quora",
        "linkedin",
        "xing",
    ],
    "Essai": [
        "norton",
        "mcafee",
        "kaspersky",
        "bitdefender",
        "eset",
        "avg",
        "avira",
        "avast",
        "panda",
        "trend micro",
        "winrar trial",
        "winzip trial",
        "nag",
        "trial",
        "demo",
        "eval",
    ],
    "Donationware": [
        "keepass",
        "7-zip",
        "notepad++",
        "vlc",
        "mpc-hc",
        "mpc-be",
        "foobar2000",
        "hwinfo",
        "crystaldiskinfo",
        "everything",
        "speccy",
        "sumatrapdf",
        "greenshot",
        "sharex",
    ],
    "Abandonware": [
        "windows 7",
        "windows 8",
        "windows vista",
        "windows xp",
        "internet explorer",
        "microsoft silverlight",
        "adobe flash",
        "adobe air",
        "shockwave",
        "quicktime",
        "realplayer",
        "winamp",
        "java 6",
        "java 7",
        "java 8",
        "icq",
        "aol",
        "aim",
        "msn messenger",
        "windows live",
        "windows essentials",
        "microsoft security essentials",
        "microsoft frontline",
        "windows sidebar",
        "windows media center",
        "windows dvd maker",
        "windows movie maker",
        "windows photo gallery",
        "windows mail",
        "windows calendar",
        "google talk",
        "hangouts",
        "google reader",
    ],
    "Payant": [
        "microsoft 365",
        "office",
        "visual studio",
        "windows server",
        "sql server",
        "exchange",
        "sharepoint",
        "adobe ",
        "photoshop",
        "illustrator",
        "premiere",
        "after effects",
        "indesign",
        "acrobat pro",
        "lightroom",
        "adobe creative cloud",
        "autocad",
        "solidworks",
        "matlab",
        "origin",
        "mathematica",
        "intellij",
        "pycharm",
        "webstorm",
        "clion",
        "rubymine",
        "goland",
        "unity",
        "unreal",
        "vmware",
        "veeam",
        "acronis",
        "winrar",
        "winzip",
        "corel",
        "davinci resolve",
        "cinema 4d",
        "maya",
        "3ds max",
        "oracle",
        "sap",
        "salesforce",
        "splunk",
        "synology",
        "final cut",
        "logic pro",
        "ableton",
        "fl studio",
        "cubase",
        "sony vegas",
        "vegas pro",
        "idm",
        "internet download manager",
        "total commander",
        "directory opus",
        "xyplorer",
        "acronis",
        "paragon",
        "veeam",
        "veeam agent",
        "malwarebytes premium",
        "bitdefender total",
        "norton 360",
        "mcafee total",
        "ansys",
        "abaqus",
        "catia",
        "nx",
        "jira",
        "confluence",
        "bitbucket",
    ],
}

CATEGORIES_LICENCE = list(DETECTEUR_LICENCE.keys())


def detecter_categorie_licence(nom, editeur=""):
    t = f"{nom} {editeur}".lower()
    t_nospace = t.replace(" ", "")
    for cat, mots in DETECTEUR_LICENCE.items():
        for m in mots:
            if m.replace(" ", "") in t_nospace:
                return cat
    if editeur:
        ed_lower = editeur.lower()
        payant_ed = [
            "microsoft",
            "adobe",
            "oracle",
            "ibm",
            "sap",
            "vmware",
            "autodesk",
            "corel",
            "symantec",
            "mcafee",
            "trend micro",
            "intel",
            "nvidia",
            "amd",
            "cisco",
            "jetbrains",
            "splunk",
            "datadog",
            "newrelic",
            "elastic",
            "sap",
            "salesforce",
            "ansys",
            "siemens",
            "dassault",
            "ptc",
        ]
        if any(ed in ed_lower for ed in payant_ed):
            microsoft_free = [
                "microsoft edge",
                "microsoft teams",
                "microsoft onedrive",
                "windows defender",
                "microsoft store",
                "power toys",
                "msedge",
                "skype",
                "microsoft paint",
            ]
            if nom and any(
                m.replace(" ", "") in nom.lower().replace(" ", "")
                for m in microsoft_free
            ):
                return "Inclus Windows"
            return "Payant"
        if any(
            ed in ed_lower
            for ed in [
                "gnu",
                "apache software",
                "mozilla",
                "eclipse",
                "free software",
                "openssl",
                "python",
                "git",
                "the docker",
            ]
        ):
            return "Open Source"
        freeware_ed = [
            "google",
            "hewlett-packard",
            "dell",
            "lenovo",
            "acer",
            "asus",
            "samsung electronics",
            "canon",
            "epson",
            "brother",
            "realtek",
            "broadcom",
            "qualcomm",
            "logitech",
            "seagate",
            "western digital",
            "kingston",
            "corsair",
            "creative technology",
        ]
        if any(ed in ed_lower for ed in freeware_ed):
            return "Freeware"
        if (
            ed_lower.startswith("hp")
            or ed_lower.startswith("lenovo")
            or ed_lower.startswith("dell ")
            or ed_lower.startswith("acer ")
        ):
            return "Freeware"
    return "Inconnu"


SOUS_TYPES_LICENCE = {
    "Open Source": {
        "gpl": "GPL",
        "lgpl": "LGPL",
        "gnu": "GNU",
        "mit": "MIT",
        "expat": "MIT",
        "apache": "Apache",
        "apache 2": "Apache",
        "bsd": "BSD",
        "freebsd": "BSD",
        "mozilla": "MPL",
        "mpl": "MPL",
        "eclipse": "EPL",
    },
    "Freeware": {
        "adobe": "Freeware",
        "google": "Freeware",
        "mozilla": "Freeware",
        "opera": "Freeware",
        "brave": "Freeware",
        "vivaldi": "Freeware",
    },
    "Payant": {
        "microsoft 365": "Abonnement",
        "office 365": "Abonnement",
        "adobe creative cloud": "Abonnement",
        "photoshop": "Perpetuel",
        "illustrator": "Perpetuel",
        "autocad": "Perpetuel",
        "solidworks": "Perpetuel",
        "matlab": "Perpetuel",
        "vmware": "Abonnement",
        "veeam": "Abonnement",
        "slack": "Par utilisateur",
        "zoom": "Par utilisateur",
        "teamviewer": "Par poste",
    },
}


def analyser_licence(nom, editeur=""):
    categorie = detecter_categorie_licence(nom, editeur)
    t = f"{nom} {editeur}".lower()
    t_nospace = t.replace(" ", "")
    sous_type = ""
    if categorie in SOUS_TYPES_LICENCE:
        for mot, st in SOUS_TYPES_LICENCE[categorie].items():
            if mot.replace(" ", "") in t_nospace:
                sous_type = st
                break
    return categorie, sous_type


GOUV_DESCRIPTIONS = {
    "chrome|google chrome": "Navigateur web developpe par Google, base sur Chromium.",
    "firefox|mozilla firefox": "Navigateur web open-source de la Fondation Mozilla.",
    "msedge|microsoft edge": "Navigateur web de Microsoft base sur Chromium.",
    "opera": "Navigateur web integrant un VPN et un bloqueur de publicites.",
    "brave": "Navigateur web axe sur la confidentialite et bloquant les publicites.",
    "chromium": "Navigateur web open-source, base de Chrome et Edge.",
    "word|winword|microsoft word": "Traitement de texte de la suite Microsoft Office.",
    "excel": "Tableur de la suite Microsoft Office.",
    "powerpoint|ppt": "Logiciel de presentation de la suite Microsoft Office.",
    "outlook": "Client de messagerie et gestionnaire de taches Microsoft.",
    "teams|microsoft teams": "Plateforme de communication collaborative Microsoft.",
    "onedrive": "Service de stockage cloud Microsoft (synchronisation fichier).",
    "vscode|visual studio code": "Editeur de code source leger et extensible de Microsoft.",
    "visual studio": "Environnement de developpement integre (IDE) Microsoft.",
    "python|python3": "Langage de programmation interprete, multiparadigme.",
    "git": "Systeme de gestion de versions decentralise.",
    "node|node.js": "Environnement d'execution JavaScript cote serveur.",
    "docker|docker desktop": "Plateforme de conteneurisation d'applications.",
    "postgresql|postgres": "Systeme de gestion de base de donnees relationnelle open-source.",
    "mysql|mariadb": "Systeme de gestion de base de donnees relationnelle.",
    "vlc|videolan": "Lecteur multimedia open-source supportant de nombreux formats.",
    "spotify": "Plateforme de streaming musical.",
    "slack": "Plateforme de messagerie collaborative d'equipe.",
    "zoom": "Application de visioconference et reunions en ligne.",
    "discord": "Plateforme de communication vocale et textuelle pour communautes.",
    "telegram|telegram desktop": "Application de messagerie instantanee chiffree.",
    "whatsapp|whatsapp desktop": "Application de messagerie instantanee proprietaire.",
    "skype": "Application de communication par messagerie et visio.",
    "adobe acrobat reader|acrobat reader": "Lecteur de fichiers PDF d'Adobe.",
    "adobe acrobat pro|acrobat pro|acrobat": "Logiciel professionnel de creation et edition PDF.",
    "photoshop|adobe photoshop": "Logiciel de retouche et creation d'images numeriques.",
    "illustrator|adobe illustrator": "Logiciel de creation de graphiques vectoriels.",
    "premiere|adobe premiere": "Logiciel de montage video professionnel.",
    "7-zip|7z": "Compresseur/decompresseur d'archives gratuit et open-source.",
    "winrar|winrar": "Utilitaire de compression d'archives (shareware).",
    "notepad++": "Editeur de texte source et remplacement du Bloc-Notes.",
    "putty": "Client SSH et Telnet pour connexions distantes securisees.",
    "winscp": "Client SFTP et FTP pour transferts securises de fichiers.",
    "filezilla": "Client FTP/SFTP open-source.",
    "wireshark": "Analyseur de paquets reseau (sniffing).",
    "nmap": "Utilitaire d'exploration reseau et d'audit de securite.",
    "vmware|vmware workstation": "Logiciel de virtualisation de postes de travail.",
    "virtualbox": "Logiciel de virtualisation open-source Oracle.",
    "docker desktop": "Application de gestion de conteneurs Docker.",
    "kubernetes|kubectl|minikube": "Orchestrateur de conteneurs pour deploiement automatise.",
    "terraform": "Outil d'infrastructure as code (IaC) HashiCorp.",
    "ansible": "Outil d'automatisation IT et configuration.",
    "postman": "Plateforme de developpement et test d'API.",
    "insomnia": "Client REST et GraphQL pour le test d'API.",
    "intellij|intellij idea": "IDE Java intelligent de JetBrains.",
    "pycharm": "IDE Python de JetBrains.",
    "webstorm": "IDE JavaScript/TypeScript de JetBrains.",
    "goland|gogland": "IDE Go de JetBrains.",
    "eclipse": "IDE polyvalent open-source principalement pour Java.",
    "android studio": "IDE officiel pour le developpement Android.",
    "unity|unity hub": "Moteur de jeu et environnement de developpement.",
    "jira": "Outil de gestion de projets et suivi de tickets Atlassian.",
    "confluence": "Plateforme de collaboration et documentation Atlassian.",
    "bitbucket": "Service d'hebergement de depots Git Atlassian.",
    "github desktop|github": "Plateforme d'hebergement de code et collaboration.",
    "gitlab": "Plateforme DevOps complete avec gestion de code et CI/CD.",
    "jenkins": "Serveur d'integration continue et de livraison continue (CI/CD).",
    "sonarqube|sonar": "Plateforme d'inspection continue de qualite de code.",
    "sentry": "Plateforme de surveillance et rapport d'erreurs applicatives.",
    "datadog": "Plateforme de monitoring et d'analyse pour applications cloud.",
    "newrelic": "Plateforme d'observabilite et de performance applicative.",
    "splunk": "Plateforme d'analyse et de recherche de donnees machine.",
    "oracle": "Base de donnees relationnelle enterprise Oracle.",
    "sql server|mssql": "Systeme de gestion de base de donnees Microsoft.",
    "mysql workbench": "Outil graphique d'administration pour MySQL.",
    "mongodb|mongosh|mongos": "Base de donnees NoSQL orientee documents.",
    "redis": "Stockage de structures de donnees en memoire (cache/queue).",
    "nginx": "Serveur web haute performance et proxy inverse.",
    "apache|httpd": "Serveur web HTTP open-source.",
    "libreoffice|openoffice": "Suite bureautique open-source alternative a Microsoft Office.",
    "gimp": "Logiciel de retouche d'image open-source.",
    "blender": "Suite de creation 3D open-source (modelisation, animation).",
    "audacity": "Editeur audio numerique open-source.",
    "obs studio|obs-studio": "Logiciel d'enregistrement et streaming video.",
    "handbrake": "Convertisseur video open-source.",
    "steam": "Plateforme de distribution de jeux video et jeux en ligne.",
    "epic games|epic": "Plateforme de distribution de jeux video et moteur Unreal.",
    "nvidia geforce|nvidia": "Pilotes et logiciels pour cartes graphiques NVIDIA.",
    "amd adrenalin|amd software": "Pilotes et logiciels pour cartes graphiques AMD.",
    "logitech g hub|logitech options": "Logiciel de configuration des peripheriques Logitech.",
    "malwarebytes": "Logiciel anti-malware et anti-exploit.",
    "bitdefender": "Suite de securite antivirus et anti-ransomware.",
    "norton|norton 360": "Suite de securite internet et antivirus.",
    "kaspersky": "Suite de securite informatique et antivirus.",
    "avg|avast|avira": "Antivirus gratuit avec protection en temps reel.",
    "teamviewer": "Logiciel de prise en controle a distance et assistance.",
    "anydesk": "Logiciel de bureau a distance leger.",
    "expressvpn|nordvpn": "Service VPN grand public pour la confidentialite en ligne.",
    "powertoys|microsoft powertoys": "Ensemble d'utilitaires systeme pour power users Windows.",
    "ccleaner": "Utilitaire de nettoyage et d'optimisation systeme.",
    "rufus": "Utilitaire de creation de supports d'installation USB bootables.",
    "etcher|balena etcher": "Outil de gravure d'images disque sur carte SD/USB.",
    "malwarebytes": "Logiciel anti-malware et anti-exploit.",
    "recuva": "Utilitaire de recuperation de fichiers supprimes.",
    "windirstat|wiztree": "Analyseur d'utilisation d'espace disque.",
    "everything": "Moteur de recherche instantanee de fichiers pour Windows.",
    "greenshot|sharex": "Capture d'ecran et annotation rapide.",
    "sumatra|sumatrapdf": "Lecteur PDF/EPUB/CBR leger et portable.",
    "foxit|foxit reader": "Lecteur PDF leger avec fonctionnalites d'annotation.",
    "autocad": "Logiciel de conception assistee par ordinateur (CAO/DAO).",
    "solidworks": "Logiciel de conception mecanique 3D (CFAO).",
    "matlab": "Environnement de calcul numerique et langage de programmation.",
    "mathematica|wolfram": "Logiciel de calcul formel et mathematiques techniques.",
    "catia": "Logiciel de conception et fabrication assistees par ordinateur.",
    "ansys": "Logiciel de simulation numerique par elements finis.",
    "abaqus": "Logiciel de simulation par elements finis (Dassault).",
    "unreal|unreal engine": "Moteur de jeu et outil de creation 3D temps reel Epic.",
    "davinci resolve": "Logiciel d'etalonnage et de montage video professionnel.",
    "cinema 4d": "Logiciel de modelisation, d'animation et de rendu 3D.",
    "maya": "Logiciel de modelisation, d'animation et de rendu 3D Autodesk.",
    "3ds max": "Logiciel de modelisation, d'animation et de rendu 3D Autodesk.",
    "final cut": "Logiciel de montage video professionnel Apple.",
    "ableton|ableton live": "Station de travail audio numerique pour production musicale.",
    "fl studio": "Station de travail audio numerique pour creation musicale.",
    "cubase": "Station de travail audio numerique professionnelle Steinberg.",
    "winzip": "Utilitaire de compression et decompression d'archives.",
    "acronis|acronis true image": "Logiciel de sauvegarde et recuperation de donnees.",
    "veeam|veeam agent": "Logiciel de sauvegarde et replication de machines virtuelles.",
    "paragon": "Utilitaire de gestion de partitions et de sauvegarde.",
    "vmware|vmware vsphere": "Plateforme de virtualisation de serveurs.",
    "sap": "Systeme ERP (Enterprise Resource Planning) SAP.",
    "salesforce": "Plateforme CRM (Customer Relationship Management) cloud.",
}

GOUV_FONCTIONS = {
    "browser|chrome|firefox|edge|msedge|opera|brave|vivaldi|chromium|safari|internet explorer|tor browser": "Navigation Internet",
    "notepad++|textpad|sublime|atom|ultraedit|gedit": "Developpement (Editeur de texte)",
    "acrobat|pdf|reader|foxit|sumatra|sumatrapdf": "Bureautique (PDF/Lecture)",
    "word|winword|excel|powerpoint|ppt|outlook|access|publisher|onenote|office|libreoffice|openoffice|wps office|onlyoffice": "Bureautique",
    "outlook|thunderbird|mail|postbox|em client|blue mail": "Messagerie",
    "teams|slack|zoom|discord|skype|telegram|whatsapp|signal|mattermost|rocketchat|zulip|element|riot": "Communication & Collaboration",
    "vscode|visual studio|intellij|pycharm|webstorm|goland|eclipse|netbeans|android studio|ide": "Developpement (IDE)",
    "git|github|gitlab|bitbucket|svn|mercurial|source tree|fork": "Gestion de versions",
    "python|node|golang|rust|ruby|php|perl|deno|bun|yarn|npm|pnpm": "Developpement (Langage/Runtime)",
    "docker|kubernetes|kubectl|minikube|k3s|terraform|ansible|vagrant|packer|pulumi": "DevOps & Conteneurisation",
    "jenkins|gitlab ci|github actions|circleci|travis|sonarqube|sonar": "Integration Continue / Qualite",
    "postman|insomnia|swagger|bruno|jmeter|soapui": "Test d'API",
    "postgresql|postgres|mysql|mariadb|mongodb|redis|sqlite|mssql|sql server|oracle|mongo|elasticsearch": "Base de donnees",
    "nginx|apache|httpd|haproxy|traefik|istio|linkerd|caddy": "Serveur Web / Proxy",
    "docker|portainer|rancher|kubernetes|k3s|openshift": "Conteneurisation & Orchestration",
    "jira|confluence|trello|asana|monday|clickup|notion|todoist|miro|mural": "Gestion de projet / Productivite",
    "photoshop|illustrator|indesign|gimp|inkscape|krita|blender|canva|figma": "Creation graphique & Design",
    "premiere|after effects|davinci resolve|final cut|vegas|shotcut|openshot|avidemux|handbrake": "Montage video & Audio",
    "vlc|mpc-hc|mpc-be|foobar2000|spotify|itunes|winamp|audacity": "Multimedia & Streaming",
    "autocad|solidworks|catia|nx|ansys|abaqus|matlab|simulink|mathematica|revit|sketchup": "CAO / Simulation / Calcul",
    "vmware|virtualbox|hyper-v|qemu|kvm|vagrant": "Virtualisation",
    "norton|mcafee|kaspersky|bitdefender|eset|avg|avira|avast|panda|trend micro|malwarebytes|adwcleaner": "Securite (Antivirus)",
    "windows defender|microsoft security|windows security": "Securite systeme",
    "wireshark|nmap|burp|nessus|openvas|ghidra|radare2": "Securite (Audit/Test)",
    "vpn|wireguard|openvpn|expressvpn|nordvpn|surfshark|protonvpn": "VPN & Reseau prive",
    "filezilla|winscp|putty|cyberduck|winscp": "Transfert de fichiers / SSH",
    "winrar|7-zip|7z|winzip|peazip|bandizip": "Compression d'archives",
    "acronis|veeam|paragon|macrium|reflect": "Sauvegarde & Restauration",
    "ccleaner|everything|speccy|hwinfo|cpu-z|gpu-z|crystaldiskinfo": "Utilitaire systeme",
    "powertoys|microsoft powertoys|open shell|classic shell|startallback": "Personnalisation systeme",
    "steam|epic games|gog|battlenet|ubisoft|riot|unity|unreal|godot": "Jeux video & Moteurs",
    "sap|salesforce|oracle ebs|dynamics|navision|sage": "ERP / CRM",
    "nvidia|amd adrenalin|intel graphics|realtek|logitech|hp|dell": "Pilotes & Utilitaires materiel",
}

GOUV_CRITICITE = {
    "securite|antivirus|defender|firewall|vpn|norton|mcafee|kaspersky|bitdefender|eset|malwarebytes|endpoint|edr|xdr|siem|soc": "Critique",
    "sauvegarde|backup|acronis|veeam|paragon|macrium|restauration|snapshot": "Critique",
    "active directory|ldap|sso|mfa|keycloak|authentik|ldap|iam|oauth": "Critique",
    "erp|sap|salesforce|oracle ebs|dynamics|navision|sage|peoplesoft": "Critique",
    "paie|payroll|hr|sirh|sage|nucleus|octime|silae": "Critique",
    "systeme|windows|kernel|driver|microsoft visual c|dotnet|framework|runtime": "Haute",
    "base de donnees|oracle|sql server|mysql|postgresql|mongodb|mariadb|redis|elasticsearch": "Haute",
    "serveur|nginx|apache|iis|haproxy|traefik|tomcat|jboss|wildfly": "Haute",
    "bureautique|office|word|excel|powerpoint|outlook|onedrive|sharepoint|bureau": "Haute",
    "collaboration|teams|slack|zoom|outlook|skype|webex|meet|discord|telegram": "Haute",
    "pdf|acrobat|reader|foxit|sumatra": "Faible",
    "navigateur|browser|chrome|firefox|edge|msedge|opera|brave|vivaldi|safari|internet explorer": "Moyen",
    "developpement|ide|vscode|visual studio|intellij|pycharm|eclipse|netbeans|android studio|jenkins|git|svn": "Moyen",
    "devops|docker|kubernetes|kubectl|terraform|ansible|vagrant|puppet|chef|ci/cd|ci|cd": "Moyen",
    "compression|7-zip|winrar|winzip|archive": "Faible",
    "multimedia|vlc|spotify|lecteur|media player|audio|video|musique|streaming|lecture|movie|film": "Faible",
    "jeu|steam|epic|jeux|game|gaming|jouer|ludique|unreal|unity": "Faible",
    "utilitaire|ccleaner|everything|speccy|hwinfo|cpu-z|gpu-z|crystaldisk|crystalmark|tweak|optimisation": "Faible",
    "personnalisation|theme|fond d ecran|screensaver|wallpaper|widget|dock": "Faible",
    "editeur|editor|bloc-note|notepad|texte|text": "Faible",
}

GOUV_PROVENANCE = {
    "appx|microsoft store": "Microsoft Store",
    "winget": "Gestionnaire Winget",
    "chocolatey|choco": "Chocolatey",
    "pip": "PyPI (pip)",
    "npm": "NPM Registry",
    "portable|exe": "Telecharge (exe)",
    "windowsupdate|windows update": "Windows Update",
    "wsl": "WSL (Windows Subsystem Linux)",
    "windowsfeature": "Fonctionnalite Windows",
    "office": "Microsoft Office",
    "registry|registry_hkcu": "Installateur MSI",
    "startmenu": "Raccourci menu Demarrer",
}

GOUV_EOL = {
    # Known EOL dates for common software products
    "windows 10": "2025-10-14",
    "windows 11": "2031-10-14",
    "windows 8": "2023-01-10",
    "windows 7": "2020-01-14",
    "windows server 2012": "2023-10-10",
    "windows server 2016": "2027-01-12",
    "windows server 2019": "2029-01-09",
    "windows server 2022": "2031-10-14",
    "office 2016": "2025-10-14",
    "office 2019": "2025-10-14",
    "office 2021": "2031-10-13",
    "office 365": "N/A (Abonnement continu)",
    ".net 5": "2022-05-08",
    ".net 6": "2024-11-12",
    ".net 7": "2024-05-14",
    ".net 8": "2026-11-10",
    "python 3.7": "2023-06-27",
    "python 3.8": "2024-10-14",
    "python 3.9": "2025-10-05",
    "python 3.10": "2026-10-04",
    "python 3.11": "2027-10-24",
    "python 3.12": "2028-10-02",
    "node 16": "2023-09-11",
    "node 18": "2025-04-30",
    "node 20": "2026-04-30",
    "node 22": "2027-04-30",
}

GOUV_EDITEURS_CONTRATS = {
    "microsoft": "Contrat Microsoft Enterprise / CSP",
    "adobe": "Contrat Adobe ETLA / VIP",
    "oracle": "Contrat Oracle ULA / BOT",
    "ibm": "Contrat IBM Passport Advantage",
    "vmware": "Contrat VMware EULA / SPP",
    "autodesk": "Contrat Autodesk Enterprise",
    "sap": "Contrat SAP Enterprise",
    "salesforce": "Contrat Salesforce Enterprise",
    "jetbrains": "Licence JetBrains All Products",
    "atlassian": "Contrat Atlassian Enterprise",
    "slack": "Abonnement Slack Enterprise",
    "zoom": "Abonnement Zoom Enterprise",
    "splunk": "Contrat Splunk Enterprise",
    "datadog": "Abonnement Datadog",
    "newrelic": "Abonnement New Relic",
}


def auto_remplir_gouvernance(
    nom, editeur="", install_source="", description="", version=""
):
    """Auto-detects and fills governance fields for a software."""
    t = f"{nom} {editeur} {description}".lower()

    result = {}

    # Description
    for kw, desc in GOUV_DESCRIPTIONS.items():
        if any(k.replace(" ", "") in t.replace(" ", "") for k in kw.split("|")):
            result["description"] = desc
            break

    # Fonction metier
    for kw, func in GOUV_FONCTIONS.items():
        if any(k.replace(" ", "") in t.replace(" ", "") for k in kw.split("|")):
            result["fonction_metier"] = func
            break

    # Criticite (d'abord par mot-cle, puis fallback sur fonction_metier)
    for kw, crit in GOUV_CRITICITE.items():
        if any(k.replace(" ", "") in t.replace(" ", "") for k in kw.split("|")):
            result["criticite_metier"] = crit
            break
    if "criticite_metier" not in result and "fonction_metier" in result:
        fm = result["fonction_metier"]
        if any(
            k in fm
            for k in ["Critique", "Haute", "Navigation", "Connectivite", "Systeme"]
        ):
            result["criticite_metier"] = "Haute"
        elif any(k in fm for k in ["Moyen", "Dev", "Base", "Securite"]):
            result["criticite_metier"] = "Moyen"
        else:
            result["criticite_metier"] = "Faible"

    # Provenance autorisee
    src_lower = (install_source or "").lower()
    for kw, prov in GOUV_PROVENANCE.items():
        if any(k.replace(" ", "") in src_lower.replace(" ", "") for k in kw.split("|")):
            result["provenance_autorisee"] = prov
            break

    # Contrat by editeur
    if editeur:
        ed_lower = editeur.lower()
        for ed_key, contrat in GOUV_EDITEURS_CONTRATS.items():
            if ed_key in ed_lower:
                result["contrat_associe"] = contrat
                break

    # EOL (try to match from name)
    if version:
        for kw, eol in GOUV_EOL.items():
            if kw in t or kw in version.lower():
                result["fin_support"] = eol
                break
    for kw, eol in GOUV_EOL.items():
        if kw in t:
            result["fin_support"] = eol
            break

    return result


BOOTSTRAP_BAT = r"""@echo off
powershell -NoProfile -ExecutionPolicy Bypass -Command "$env:SRV='%SRV%'; iex (irm ($env:SRV+'/collect.ps1'))"
"""


def get_db():
    return get_conn()


_PERSO_CACHE = {}


def _est_machine_perso(scan_id):
    """Retourne True si la machine n'est pas sur un domaine entreprise."""
    if not scan_id:
        return False
    if scan_id in _PERSO_CACHE:
        return _PERSO_CACHE[scan_id]
    try:
        conn = get_db()
        row = fetchone(conn, "SELECT domaine FROM machines WHERE scan_id=?", (scan_id,))
        close(conn)
        if not row:
            return False
        domaine = (row["domaine"] or "").strip().upper()
        result = domaine in ("", "WORKGROUP")
        _PERSO_CACHE[scan_id] = result
        return result
    except Exception:
        return False


_LATEST_VERSIONS = None


def _load_latest_versions():
    global _LATEST_VERSIONS
    if _LATEST_VERSIONS is not None:
        return _LATEST_VERSIONS
    try:
        path = os.path.join(
            os.path.dirname(__file__) or ".", "data", "latest_versions.json"
        )
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                _LATEST_VERSIONS = json.load(f)
            return _LATEST_VERSIONS
    except Exception as e:
        print(f"  [RISK] Impossible de charger latest_versions.json: {e}")
    _LATEST_VERSIONS = {}
    return _LATEST_VERSIONS


def _parse_version(v):
    """Convertit une version string en tuple comparable."""
    if not v or not isinstance(v, str):
        return (0,)
    v = v.strip().lower()
    # Supprime les prefixes comme 'v', 'version ', etc.
    v = re.sub(r"^version\s+|^v(\d)", r"\1", v, flags=re.I)
    # Sépare sur . , - _ espace
    parts = re.split(r"[.\s\-_]+", v)
    result = []
    for p in parts:
        # Extrait le nombre principal (ignore les suffixes alpha/beta)
        m = re.match(r"(\d+)", p)
        if m:
            result.append(int(m.group(1)))
        elif result:
            break
    return tuple(result) if result else (0,)


def _find_latest_ref(nom):
    """Cherche une entree dans latest_versions.json par nom ou alias."""
    refs = _load_latest_versions()
    if not refs:
        return None
    n = nom.strip()
    # 1) Exact match
    if n in refs:
        val = refs[n]
        return val if isinstance(val, dict) else None
    # 2) Alias match (les entrees avec 'alias' pointent vers la vraie entree)
    for key, val in refs.items():
        if not isinstance(val, dict):
            continue  # ignorer les valeurs non-dict (ex: chaine de caracteres)
        if val.get("alias") and n.lower() == val["alias"].lower():
            return val
        if val.get("alias") and n.lower() in val["alias"].lower():
            return val
    # 3) Match partiel (nom contient le key ou vice-versa)
    # On exige un minimum de 5 caracteres pour eviter les faux positifs
    n_lower = n.lower()
    for key, val in refs.items():
        if not isinstance(val, dict):
            continue
        kl = key.lower()
        if len(kl) >= 5 and len(n_lower) >= 5:
            if kl in n_lower or n_lower in kl:
                if val.get("version"):
                    return val
    return None


def _calculer_fraicheur_version(nom, version_installed):
    """Calcule un score de fraicheur de version (0 = a jour, 10 = tres obsolete)."""
    ref = _find_latest_ref(nom)
    if not ref or not ref.get("version"):
        return None  # Inconnu, pas de penalite
    latest_ver = ref["version"]
    installed = _parse_version(version_installed)
    latest = _parse_version(latest_ver)
    if not installed or installed == (0,):
        return None
    if not latest or latest == (0,):
        return None
    # Si la version installee est >= la derniere, c'est a jour
    if installed >= latest:
        return 0
    # Calculer le retard: difference en nombre de versions majeures
    diff_major = (
        latest[0] - installed[0] if len(latest) > 0 and len(installed) > 0 else 0
    )
    diff_minor = (
        (latest[1] - installed[1]) if len(latest) > 1 and len(installed) > 1 else 0
    )
    # Normaliser selon le cycle de publication
    cycle = ref.get("cycle_mois", 6) or 6
    retard = max(0, diff_major * (12 / cycle) + diff_minor * (1 / max(cycle, 1)))
    # Score base sur le retard normalise
    if retard <= 0.5:
        return 0  # A jour
    elif retard <= 1:
        return 1  # 1 cycle de retard
    elif retard <= 2:
        return 2
    elif retard <= 3:
        return 3
    elif retard <= 6:
        return 4
    elif retard <= 12:
        return 5
    elif retard <= 24:
        return 6
    elif retard <= 36:
        return 7
    else:
        return 8  # Tres obsolete


def recalculer_risque_par_cve(
    conn, nom, risque_actuel=None, risque_score_actuel=None, auto_enrich=False
):
    """Recalcule le risque d'un logiciel en fonction des CVE reelles ET de la fraicheur de version.
    Nouveau scoring:
      1. CISA KEV ou CVSS >= 9 => Critique (10)
      2. Pas de CVE mais version obsolete => Eleve/Moyen selon obsolescence
      3. CVE + version obsolete => max(CVE, version)
      4. A jour, sans CVE => Faible (1)
    """
    c = conn.cursor()
    # --- Facteur CVE ---
    cves = c.execute(
        """
        SELECT cvss_score, cvss_severity, source, exploit_public
        FROM cve_cache WHERE logiciel_nom=? ORDER BY cvss_score DESC
    """,
        (nom,),
    ).fetchall()
    if not cves and auto_enrich:
        try:
            from cve_service import enrich_software

            enrich_software(conn, nom)
            cves = c.execute(
                """
                SELECT cvss_score, cvss_severity, source, exploit_public
                FROM cve_cache WHERE logiciel_nom=? ORDER BY cvss_score DESC
            """,
                (nom,),
            ).fetchall()
        except Exception as e:
            print(f"  [CVE] Auto-enrich echec pour {nom}: {e}")
    max_cvss = 0
    cisa_kev = False
    for cv in cves:
        s = cv["cvss_score"] or 0
        if s > max_cvss:
            max_cvss = s
        if cv["source"] == "CISA_KEV" and cv["exploit_public"]:
            cisa_kev = True
    # CVE -> risque
    if cisa_kev or max_cvss >= 9.0:
        cve_niveau, cve_score = "Critique", 10
    elif max_cvss >= 7.0:
        cve_niveau, cve_score = "Eleve", 8
    elif max_cvss >= 4.0:
        cve_niveau, cve_score = "Moyen", 5
    elif max_cvss > 0:
        cve_niveau, cve_score = "Faible", 1
    else:
        cve_niveau, cve_score = None, 0
    # --- Facteur Version (fraicheur) ---
    # Cherche la version installee (premiere version trouvee dans la base)
    installed_version = None
    try:
        row = c.execute(
            "SELECT version FROM logiciels WHERE nom=? AND version IS NOT NULL AND version!='' LIMIT 1",
            (nom,),
        ).fetchone()
        if row:
            installed_version = row["version"]
    except Exception:
        pass
    fraicheur = _calculer_fraicheur_version(nom, installed_version)
    # Fraicheur -> risque
    if fraicheur is not None:
        if fraicheur >= 7:
            ver_niveau, ver_score = "Eleve", 7
        elif fraicheur >= 5:
            ver_niveau, ver_score = "Eleve", 6
        elif fraicheur >= 3:
            ver_niveau, ver_score = "Moyen", 4
        elif fraicheur >= 1:
            ver_niveau, ver_score = "Faible", 2
        else:
            ver_niveau, ver_score = "Faible", 1
    else:
        ver_niveau, ver_score = None, 0
    # --- Combinaison: on prend le MAX des deux scores ---
    final_score = max(cve_score, ver_score)
    if final_score >= 10:
        return "Critique", 10
    elif final_score >= 8:
        return "Eleve", 8
    elif final_score >= 5:
        return "Moyen", 5
    elif final_score >= 2:
        return "Faible", 2
    elif final_score == 1:
        return "Faible", 1
    else:
        return "Faible", 0


def classer_origine(sw, scan_id=None):
    if not isinstance(sw, dict):
        sw = dict(sw)
    nom = (sw.get("nom") or "").strip().lower()
    edt = (sw.get("editeur") or "").strip().lower()
    chemin = (sw.get("chemin") or "").lower()
    src_raw = (sw.get("install_source") or sw.get("install_sources") or "").lower()
    srcs = [s.strip() for s in src_raw.split(",") if s.strip()]
    est_entreprise = not _est_machine_perso(scan_id)

    windows_noms = [
        "microsoft visual c++",
        ".net framework",
        "microsoft .net",
        "microsoft edge",
        "microsoft edge update",
        "microsoft edge webview",
        "edge webview2",
        "microsoft update health",
        "windows update",
        "windows driver",
        "windows sdk",
        "windows software development kit",
        "windows app sdk",
        "microsoft windows",
        "windows malicious software",
        "microsoft defender",
        "windows defender",
        "security essentials",
        "microsoft silverlight",
        "directx",
        "microsoft directx",
        "microsoft onedrive",
        "onedrive",
        "microsoft search",
    ]
    windows_noms_exact = [
        "calculator",
        "notepad",
        "paint",
        "snipping tool",
        "windows media player",
        "microsoft store",
        "xbox",
        "xbox app",
        "cortana",
        "windows camera",
        "windows maps",
        "windows voice",
        "microsoft tips",
        "microsoft sticky notes",
        "windows clock",
        "windows calculator",
        "windows settings",
        "windows terminal",
        "microsoft paint",
        "microsoft solitaire",
        "microsoft people",
        "microsoft photos",
        "microsoft screen sketch",
        "microsoft 3d viewer",
        "windows security",
        "windows powershell",
        "windows subsystem",
    ]

    # 1) Dans le CSV serveur ? => Intune (uniquement si machine entreprise)
    if est_entreprise:
        if nom in SERVEUR_APPS:
            return "Intune"
        if (nom, edt) in SERVEUR_APPS_NOM_EDITEUR:
            return "Intune"
        for sv in SERVEUR_APPS:
            shorter, longer = (sv, nom) if len(sv) <= len(nom) else (nom, sv)
            if len(shorter) >= 4 and len(shorter) / max(len(longer), 1) >= 0.70:
                pattern = r"(?:^|[^a-z0-9])" + re.escape(shorter) + r"(?:$|[^a-z0-9])"
                if re.search(pattern, longer):
                    _sources_fiables = (
                        "registry",
                        "appx",
                        "appxprovisioned",
                        "windowsfeature",
                        "winget",
                    )
                    if any(s in srcs for s in _sources_fiables):
                        return "Intune"

    # 2) Windows / Microsoft
    for s in srcs:
        if s in ("windowsfeature", "appxprovisioned"):
            return "Windows"
    if "microsoft" in edt or "windows" in edt or "microsoft corporation" in edt:
        if chemin.startswith(("c:\\windows\\", "c:\\program files\\windowsapps\\")):
            return "Windows"
    if "appx" in srcs and "microsoft" in edt:
        return "Windows"
    for wn in windows_noms:
        if wn in nom:
            return "Windows"
    if re.match(r"^microsoft (visual c\+\+|\.net|update|search|windows|edge)", nom):
        return "Windows"
    if chemin.startswith(("c:\\windows\\", "c:\\program files\\windowsapps\\")):
        return "Windows"

    # 3) Ni Intune ni Windows => Utilisateur
    return "Utilisateur"


def _get_niveau_acces(install_source):
    """Retourne le contexte d'installation (niveau d'acces systeme).
    Windows Base > Installé par Administrateur > Installé par Utilisateur courant
    """
    src = (install_source or "").lower().strip()
    if src in ("windowsfeature", "appxprovisioned", "windowsupdate"):
        return "Windows Base"
    if src in ("registry", "chocolatey"):
        return "Installé par Administrateur"
    if src in (
        "registry_hkcu",
        "startmenu",
        "appx",
        "portable",
        "path",
        "pip",
        "npm",
        "composer",
        "winget",
    ):
        return "Installé par Utilisateur courant"
    return "Installé par Utilisateur courant"


def init_db():
    conn = get_db()
    try:
        conn.rollback()
    except Exception:
        pass
    c = conn.cursor()
    if is_sqlite(conn):
        c.executescript("""
            CREATE TABLE IF NOT EXISTS machines (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom_pc TEXT NOT NULL, ip TEXT, mac TEXT, utilisateur TEXT, domaine TEXT,
                os_nom TEXT, os_version TEXT, os_build TEXT, os_arch TEXT,
                fabricant TEXT, modele TEXT, ram_gb REAL,
                cpu_nom TEXT, cpu_coeurs INTEGER,
                disque_taille_gb REAL, disque_libre_gb REAL, disque_pct_libre REAL,
                uptime_jours REAL, department TEXT, location TEXT,
                site_id INTEGER, actif INTEGER DEFAULT 1,
                date_scan TEXT, heure_scan TEXT, scan_id TEXT UNIQUE,
                rapport_json TEXT, score_securite INTEGER DEFAULT 0,
                score_conformite INTEGER DEFAULT 0,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                dernier_demarrage TEXT DEFAULT '', nb_utilisateurs INTEGER DEFAULT 0,
                nb_connexions INTEGER DEFAULT 0, version_bios TEXT DEFAULT '',
                type_machine TEXT DEFAULT '', os TEXT, json_raw TEXT, arch TEXT,
                meta_json TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS logiciels (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT NOT NULL, nom TEXT NOT NULL,
                version TEXT, editeur TEXT, architecture TEXT,
                categorie TEXT, taille_kb TEXT,
                risque_niveau TEXT, risque_score INTEGER, eol TEXT,
                signature TEXT, editeur_url TEXT,
                risque_auto TEXT, risque_desc TEXT,
                portable INTEGER DEFAULT 0,
                meta_json TEXT DEFAULT '{}',
                approuve INTEGER DEFAULT 0,
                criticite_metier TEXT DEFAULT '', hash_sha256 TEXT DEFAULT '',
                cert_editeur TEXT DEFAULT '', derniere_execution TEXT DEFAULT '',
                dependances TEXT DEFAULT '', version_date TEXT DEFAULT '',
                install_source TEXT DEFAULT '', install_lang TEXT DEFAULT '',
                description TEXT DEFAULT '', build TEXT DEFAULT '',
                url_help TEXT DEFAULT '', type_logiciel TEXT DEFAULT '', chemin TEXT,
                derniere_version TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS historique_scan (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom_pc TEXT NOT NULL, scan_id TEXT NOT NULL,
                date_scan TEXT, heure_scan TEXT,
                rapport_json TEXT, archive_le DATETIME DEFAULT CURRENT_TIMESTAMP,
                ip TEXT, alertes TEXT, nb_logiciels INTEGER, duree_s REAL
            );
            CREATE TABLE IF NOT EXISTS historique_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_id TEXT, nom_pc TEXT, type_action TEXT,
                logiciel_nom TEXT, ancienne_version TEXT, nouvelle_version TEXT,
                description TEXT, date_action TEXT, heure_action TEXT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            CREATE TABLE IF NOT EXISTS cve_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                logiciel_nom TEXT NOT NULL, cve_id TEXT NOT NULL,
                score REAL, description TEXT, exploit_exists INTEGER DEFAULT 0,
                date_mise_a_jour DATETIME DEFAULT CURRENT_TIMESTAMP,
                hash_sha256 TEXT DEFAULT ''
            );
            CREATE TABLE IF NOT EXISTS catalogue (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nom TEXT UNIQUE NOT NULL, editeur TEXT, categorie TEXT,
                site_officiel TEXT, risque_intrinseque TEXT DEFAULT 'Faible',
                approuve INTEGER DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS licences (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                logiciel_nom TEXT NOT NULL, type_licence TEXT,
                nombre_licences INTEGER DEFAULT 1,
                date_expiration TEXT, cout_annuel REAL,
                fournisseur TEXT, contact TEXT, notes TEXT,
                categorie_licence TEXT DEFAULT 'Proprietaire',
                nb_utilisees INTEGER DEFAULT 0,
                date_achat TEXT, numero_licence TEXT,
                editeur TEXT
            );
            CREATE TABLE IF NOT EXISTS migrations (done INTEGER);
            CREATE TABLE IF NOT EXISTS conformite (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                regle TEXT UNIQUE NOT NULL, statut TEXT DEFAULT 'Non verifie',
                niveau TEXT DEFAULT 'Moyen', description TEXT,
                points INTEGER DEFAULT 0, max_points INTEGER DEFAULT 1
            );
            CREATE INDEX IF NOT EXISTS idx_scan_nom ON machines(nom_pc);
            CREATE INDEX IF NOT EXISTS idx_logiciel_nom ON logiciels(nom);
            CREATE INDEX IF NOT EXISTS idx_cve_nom ON cve_cache(logiciel_nom);
            CREATE INDEX IF NOT EXISTS idx_lic_nom ON licences(logiciel_nom);
            CREATE INDEX IF NOT EXISTS idx_actions_scan ON historique_actions(scan_id);
        """)
        for col_sql in [
            "ALTER TABLE licences ADD COLUMN categorie_licence TEXT DEFAULT 'Proprietaire'",
            "ALTER TABLE licences ADD COLUMN nb_utilisees INTEGER DEFAULT 0",
            "ALTER TABLE licences ADD COLUMN date_achat TEXT",
            "ALTER TABLE licences ADD COLUMN numero_licence TEXT",
            "ALTER TABLE licences ADD COLUMN editeur TEXT",
            "ALTER TABLE logiciels ADD COLUMN version_date TEXT DEFAULT ''",
            "ALTER TABLE logiciels ADD COLUMN metier TEXT DEFAULT ''",
            "ALTER TABLE logiciels ADD COLUMN notes TEXT DEFAULT ''",
            "ALTER TABLE logiciels ADD COLUMN contexte_installation TEXT DEFAULT ''",
            "ALTER TABLE logiciels ADD COLUMN pays_editeur TEXT DEFAULT ''",
            "ALTER TABLE logiciels ADD COLUMN derniere_version TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN description TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN fonction_metier TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN referent_metier TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN referent_technique TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN service_concerne TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN contrat_associe TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN fin_support TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN criticite_metier TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN provenance_autorisee TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN historique_failles TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN fuites_donnees TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN pays_siege TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN pays_hebergement TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN pays_developpement TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN restrictions_geopolitiques TEXT DEFAULT ''",
            "ALTER TABLE catalogue ADD COLUMN risque_souverainete TEXT DEFAULT ''",
            "ALTER TABLE machines ADD COLUMN meta_json TEXT DEFAULT '{}'",
            "ALTER TABLE cve_cache ADD COLUMN hash_sha256 TEXT DEFAULT ''",
        ]:
            try:
                conn.execute(col_sql)
            except Exception as ex_mig:
                err = str(ex_mig).lower()
                if "duplicate column" not in err and "already exists" not in err:
                    print(f"  [MIGRATION] {ex_mig}")
    conn.commit()
    try:
        init_enterprise_tables(conn)
    except Exception as ex:
        print(
            f"\n  [ERREUR] Impossible de creer les tables sites/departments/briques: {ex}"
        )
        print(
            f"  [ERREUR] Les endpoints /api/briques, /api/sites, /api/departments ne fonctionneront pas\n"
        )
        try:
            conn.rollback()
        except:
            pass
    conn.close()


def log_action(
    action,
    categorie="systeme",
    scan_id="",
    nom_pc="",
    details=None,
    ip_source="",
    utilisateur="",
    severite="info",
):
    """Enregistre une action dans le journal d'audit."""
    try:
        conn = get_db()
        execute(
            conn,
            "INSERT INTO audit_log (scan_id, nom_pc, action, categorie, details, ip_source, utilisateur, severite) VALUES (?,?,?,?,?,?,?,?)",
            (
                scan_id,
                nom_pc,
                action,
                categorie,
                json.dumps(details or {}),
                ip_source,
                utilisateur,
                severite,
            ),
        )
        commit(conn)
        close(conn)
    except Exception as e:
        print(f"  [AUDIT ERROR] {e}")


def get_client_ip():
    if request.headers.get("X-Forwarded-For"):
        return request.headers["X-Forwarded-For"].split(",")[0].strip()
    return request.remote_addr or ""


@app.route("/collect.ps1")
def serve_collector():
    return Response(COLLECT_PS1, mimetype="text/plain; charset=utf-8")


@app.route("/collect.bat")
def serve_bat():
    return Response(BOOTSTRAP_BAT, mimetype="text/plain")


@app.route("/api/collecte", methods=["POST"])
def api_collecte():
    try:
        raw = request.get_data()
        # Decompress Gzip si present
        ce = request.headers.get("Content-Encoding", "")
        if "gzip" in ce:
            try:
                buf = io.BytesIO(raw)
                with gzip.GzipFile(fileobj=buf) as f:
                    raw = f.read()
            except Exception:
                pass
        data = None
        for enc in ("utf-8", "utf-8-sig", "latin-1", "cp1252"):
            try:
                data = json.loads(raw.decode(enc))
                break
            except (UnicodeDecodeError, json.JSONDecodeError):
                continue
        if data is None:
            return jsonify({"error": "Impossible de decoder le JSON"}), 400
        scan_id = insert_scan(data)
        ident = data.get("identite") or data.get("machine", {})
        log_action(
            "scan_recu",
            "collecte",
            scan_id,
            ident.get("nom", ""),
            {"nb_logiciels": len(data.get("logiciels") or data.get("software", []))},
            get_client_ip(),
            "",
            "info",
        )
        return jsonify({"status": "ok", "scan_id": scan_id})
    except Exception as e:
        import traceback

        traceback.print_exc()
        return jsonify({"error": repr(e)}), 500


@app.route("/api/import-json", methods=["POST"])
def api_import_json():
    """Import one or more JSON collecte files (multipart/form-data).
    Accepts a single file field 'file' or multiple files.
    Returns scan_ids and summary."""
    try:
        files = request.files.getlist("file")
        if not files:
            return jsonify({"error": "Aucun fichier fourni"}), 400
        results = []
        errors = []
        for f in files:
            if not f.filename:
                continue
            raw = f.read()
            if not raw:
                errors.append({"file": f.filename, "error": "Fichier vide"})
                continue
            data = None
            for enc in ("utf-8-sig", "utf-8", "latin-1", "cp1252"):
                try:
                    data = json.loads(raw.decode(enc))
                    break
                except (UnicodeDecodeError, json.JSONDecodeError):
                    continue
            if data is None:
                errors.append({"file": f.filename, "error": "JSON invalide"})
                continue
            try:
                scan_id = insert_scan(data)
                ident = data.get("identite") or data.get("machine", {})
                log_action(
                    "scan_importe",
                    "import_json",
                    scan_id,
                    ident.get("nom", ""),
                    {"nb_logiciels": len(data.get("logiciels") or [])},
                    get_client_ip(),
                    "",
                    "info",
                )
                results.append({
                    "file": f.filename,
                    "scan_id": scan_id,
                    "machine": ident.get("nom", ""),
                    "logiciels": len(data.get("logiciels") or []),
                })
            except Exception as e:
                errors.append({"file": f.filename, "error": repr(e)})
        return jsonify({
            "status": "ok",
            "imported": len(results),
            "errors": len(errors),
            "results": results,
            "error_details": errors,
        })
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": repr(e)}), 500


def _strip_nulls(obj):
    """Recursively remove NUL (0x00) characters from all strings in obj."""
    if isinstance(obj, dict):
        return {k: _strip_nulls(v) for k, v in obj.items()}
    if isinstance(obj, list):
        # Also drop None entries (PowerShell $null becomes JSON null)
        return [_strip_nulls(v) for v in obj if v is not None]
    if isinstance(obj, str):
        return obj.replace("\x00", "")
    return obj


def _safe_int(val, default=0):
    """Convertit val en int de manière defensive."""
    try:
        return int(val or default)
    except (TypeError, ValueError):
        return default


def _safe_float(val, default=0.0):
    """Convertit val en float de manière defensive."""
    try:
        return float(val or default)
    except (TypeError, ValueError):
        return default


def _safe_dict(val):
    """Retourne val si c'est un dict, sinon {}."""
    return val if isinstance(val, dict) else {}


def _safe_list(val):
    """Retourne val si c'est une liste, sinon []."""
    return val if isinstance(val, list) else []


def insert_scan(data):
    data = _strip_nulls(data)
    identite = _safe_dict(data.get("identite") or data.get("machine"))
    systeme = _safe_dict(data.get("systeme") or data.get("os"))
    materiel = _safe_dict(data.get("materiel") or data.get("hardware"))
    # Filtre les nulls dans la liste de logiciels (PowerShell $null → JSON null)
    logiciels = [
        sw
        for sw in _safe_list(data.get("logiciels") or data.get("software"))
        if sw and isinstance(sw, dict)
    ]
    utilisateurs = _safe_dict(data.get("utilisateurs"))
    alertes_data = _safe_dict(data.get("alertes"))

    # Normaliser la date_scan (PowerShell peut envoyer 'dd/MM/yyyy')
    raw_date = str(data.get("date_scan", ""))
    try:
        import datetime as _dt

        if "/" in raw_date and len(raw_date) == 10:
            parts = raw_date.split("/")
            if len(parts[2]) == 4:  # dd/MM/yyyy
                raw_date = f"{parts[2]}-{parts[1].zfill(2)}-{parts[0].zfill(2)}"
    except Exception:
        pass

    scan_id = hashlib.md5(
        (identite.get("nom", "") + raw_date + data.get("heure_scan", "")).encode()
    ).hexdigest()[:12]
    ip = identite.get("ip", "") or ""
    mac = identite.get("mac", "") or ""
    conn = get_db()
    if is_sqlite(conn):
        conn.execute("PRAGMA busy_timeout = 300000")
        # Disable FK checks for the duration of this scan insert.
        # We change scan_id on the machines row while logiciels still reference
        # the old scan_id — that triggers FOREIGN KEY violation without this.
        conn.execute("PRAGMA foreign_keys = OFF")
    c = conn.cursor()
    try:
        cpu_info = _safe_dict(materiel.get("cpu"))
        ram_info = _safe_dict(materiel.get("ram"))
        disks = _safe_list(materiel.get("disques"))
        disque_taille = sum(
            _safe_float(d.get("taille_gb")) for d in disks if isinstance(d, dict)
        )
        disque_libre = sum(
            _safe_float(d.get("libre_gb")) for d in disks if isinstance(d, dict)
        )
        disque_pct = (
            round((disque_libre / disque_taille * 100), 1) if disque_taille > 0 else 0
        )
        uptime = systeme.get("dernier_demarrage_j", "")

        # ── Score sécurité défensif ──
        sec_data = _safe_dict(data.get("securite"))
        score_sec = 0
        av = sec_data.get("antivirus") or sec_data.get("defender") or {}
        if isinstance(av, dict) and av.get("actif"):
            score_sec += 30
        fw = sec_data.get("firewall") or {}
        if isinstance(fw, dict) and fw.get("actif"):
            score_sec += 30
        bl = sec_data.get("bitlocker") or {}
        if isinstance(bl, dict) and _safe_int(bl.get("volumes_chiffres", 0)) > 0:
            score_sec += 20
        if sec_data.get("secure_boot"):
            score_sec += 20

        eol_count = sum(1 for sw in logiciels if sw.get("eol") in ("OUI", 1, "1"))
        vuln_count = sum(
            1 for sw in logiciels if _safe_int(sw.get("risque_score", 0)) >= 5
        )
        crit_count = sum(
            1 for sw in logiciels if _safe_int(sw.get("risque_score", 0)) >= 8
        )

        # Calcul du score de conformité ANSSI réel
        malus_conf = 0
        if not (isinstance(av, dict) and av.get("actif")):
            malus_conf += 30
        if not (isinstance(fw, dict) and fw.get("actif")):
            malus_conf += 20
        if not (
            isinstance(bl, dict)
            and (_safe_int(bl.get("volumes_chiffres", 0)) > 0 or bl.get("present"))
        ):
            malus_conf += 20

        malus_conf += eol_count * 5
        malus_conf += vuln_count * 3
        malus_conf += crit_count * 8

        score_conf = max(0, min(100, 100 - malus_conf))

        # Auto-compute type_machine: Entreprise si domaine, sinon Personnel
        domaine_val = (identite.get("domaine") or "").strip().upper()
        raw_type = identite.get("type_machine") or ""
        if domaine_val and domaine_val not in ("", "WORKGROUP"):
            type_machine_val = "Entreprise"
        elif raw_type in ("VM", "Physique"):
            type_machine_val = raw_type
        else:
            type_machine_val = "Personnel"

        nom_pc = identite.get("nom", "")
        c.execute(
            "SELECT id, scan_id FROM machines WHERE nom_pc = ? LIMIT 1", (nom_pc,)
        )
        existing = c.fetchone()
        if existing:
            old_scan_id = existing["scan_id"]
            old_sw = c.execute(
                "SELECT nom, version, editeur, chemin, categorie, risque_niveau, risque_score, eol, install_source, signature, hash_sha256, cert_editeur, description, architecture FROM logiciels WHERE scan_id=?",
                (old_scan_id,),
            ).fetchall()
            old_by_key = {
                (
                    (o["nom"] or "").strip().lower(),
                    (o["version"] or "").strip().lower(),
                    (o["editeur"] or "").strip().lower(),
                ): dict(o)
                for o in old_sw
            }
            machine_id = existing["id"]
            c.execute(
                "DELETE FROM machines WHERE nom_pc = ? AND id != ?",
                (nom_pc, machine_id),
            )
            c.execute(
                """UPDATE machines SET scan_id=?, ip=?, mac=?, fabricant=?, modele=?, type_machine=?,
                        os_nom=?, os_version=?, os_build=?, os_arch=?, cpu_nom=?, cpu_coeurs=?, ram_gb=?,
                        disque_taille_gb=?, disque_libre_gb=?, disque_pct_libre=?,
                        uptime_jours=?, domaine=?, utilisateur=?, version_bios=?,
                        date_scan=?, heure_scan=?,
                        score_securite=?, score_conformite=?, actif=?,
                        rapport_json=?, json_raw=?
                        WHERE id=?""",
                (
                    scan_id,
                    ip,
                    mac,
                    identite.get("fabricant", ""),
                    identite.get("modele", ""),
                    type_machine_val,
                    systeme.get("nom", ""),
                    systeme.get("version", ""),
                    systeme.get("build", ""),
                    systeme.get("arch", ""),
                    cpu_info.get("modele", ""),
                    _safe_int(cpu_info.get("coeurs")),
                    _safe_float(ram_info.get("total_gb")),
                    disque_taille,
                    disque_libre,
                    disque_pct,
                    uptime,
                    identite.get("domaine", ""),
                    utilisateurs.get("connecte", ""),
                    identite.get("bios_version", ""),
                    raw_date,
                    data.get("heure_scan", ""),
                    score_sec,
                    score_conf,
                    1,
                    json.dumps(data, ensure_ascii=False),
                    json.dumps(data, ensure_ascii=False),
                    machine_id,
                ),
            )
            # Diff optimisation (collecte en memoire, batch insert)
            new_keys = set()
            added = removed = updated = kept = 0
            insert_rows = []
            update_rows = []
            for sw in logiciels:
                enrichir_logiciel(sw, sw.get("nom", ""))
                key = (
                    (sw.get("nom") or "").strip().lower(),
                    (sw.get("version") or "").strip().lower(),
                    (sw.get("editeur") or "").strip().lower(),
                )
                new_keys.add(key)
                old = old_by_key.get(key)
                if not old:
                    sw_metier = sw.get("metier") or _classifier_metier(
                        sw.get("nom", ""),
                        sw.get("editeur", ""),
                        sw.get("categorie", ""),
                    )
                    sw_type = sw.get("type_logiciel", "")
                    insert_rows.append(
                        (
                            scan_id,
                            sw.get("nom", ""),
                            sw.get("version", ""),
                            sw.get("editeur", ""),
                            sw.get("chemin", ""),
                            sw.get("categorie", ""),
                            sw.get("risque_auto", "Faible"),
                            _safe_int(sw.get("risque_score", 0)),
                            sw.get("eol", "Non"),
                            sw.get("install_source", ""),
                            sw.get("signature", ""),
                            sw.get("hash_sha256", ""),
                            sw.get("cert_editeur", ""),
                            sw.get("description", ""),
                            sw.get("architecture", ""),
                            sw_type,
                            sw_metier,
                            sw.get("contexte_installation", ""),
                            sw.get("pays_editeur", ""),
                        )
                    )
                    added += 1
                else:
                    keys_check = [
                        "version",
                        "editeur",
                        "risque_score",
                        "categorie",
                        "eol",
                    ]
                    changed = any(
                        str(old.get(k, "")) != str(sw.get(k, "")) for k in keys_check
                    )
                    if changed:
                        sw_metier = sw.get("metier") or _classifier_metier(
                            sw.get("nom", ""),
                            sw.get("editeur", ""),
                            sw.get("categorie", ""),
                        )
                        sw_type = sw.get("type_logiciel", "")
                        update_rows.append(
                            (
                                scan_id,
                                sw.get("version", ""),
                                sw.get("editeur", ""),
                                sw.get("chemin", ""),
                                sw.get("categorie", ""),
                                sw.get("risque_auto", "Faible"),
                                _safe_int(sw.get("risque_score", 0)),
                                sw.get("eol", "Non"),
                                sw.get("install_source", ""),
                                sw.get("signature", ""),
                                sw.get("hash_sha256", ""),
                                sw.get("cert_editeur", ""),
                                sw.get("description", ""),
                                sw.get("architecture", ""),
                                sw_type,
                                sw_metier,
                                sw.get("contexte_installation", ""),
                                sw.get("pays_editeur", ""),
                                old_scan_id,
                                old["nom"],
                                old["version"],
                                old["editeur"],
                            )
                        )
                        updated += 1
                    else:
                        kept += 1
            if insert_rows:
                c.executemany(
                    """INSERT INTO logiciels (scan_id, nom, version, editeur, chemin,
                              categorie, risque_niveau, risque_score, eol, install_source, signature,
                              hash_sha256, cert_editeur, description, architecture, type_logiciel, metier,
                              contexte_installation, pays_editeur)
                              VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                    insert_rows,
                )
            for up in update_rows:
                c.execute(
                    """UPDATE logiciels SET scan_id=?, version=?, editeur=?, chemin=?,
                            categorie=?, risque_niveau=?, risque_score=?, eol=?, install_source=?,
                            signature=?, hash_sha256=?, cert_editeur=?, description=?, architecture=?,
                            type_logiciel=?, metier=?, contexte_installation=?, pays_editeur=?
                            WHERE scan_id=? AND nom=? AND version=? AND editeur=?""",
                    up,
                )
            for old_key, old_val in old_by_key.items():
                if old_key not in new_keys:
                    c.execute(
                        "DELETE FROM logiciels WHERE scan_id=? AND nom=? AND version=? AND editeur=?",
                        (
                            old_scan_id,
                            old_val["nom"],
                            old_val["version"],
                            old_val["editeur"],
                        ),
                    )
                    removed += 1
            if old_scan_id != scan_id:
                c.execute(
                    "UPDATE logiciels SET scan_id=? WHERE scan_id=?",
                    (scan_id, old_scan_id),
                )
            print(
                f"  Diff: +{added} ajoutes, ~{updated} mis a jour, -{removed} supprimes, {kept} inchanges"
            )
        else:
            c.execute(
                """INSERT INTO machines (scan_id, nom_pc, ip, mac, fabricant, modele, type_machine,
                        os_nom, os_version, os_build, os_arch, cpu_nom, cpu_coeurs, ram_gb,
                        disque_taille_gb, disque_libre_gb, disque_pct_libre,
                        uptime_jours, domaine, utilisateur, version_bios,
                        date_scan, heure_scan,
                        score_securite, score_conformite, actif,
                        rapport_json, json_raw)
                        VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    scan_id,
                    nom_pc,
                    ip,
                    mac,
                    identite.get("fabricant", ""),
                    identite.get("modele", ""),
                    type_machine_val,
                    systeme.get("nom", ""),
                    systeme.get("version", ""),
                    systeme.get("build", ""),
                    systeme.get("arch", ""),
                    cpu_info.get("modele", ""),
                    _safe_int(cpu_info.get("coeurs")),
                    _safe_float(ram_info.get("total_gb")),
                    disque_taille,
                    disque_libre,
                    disque_pct,
                    uptime,
                    identite.get("domaine", ""),
                    utilisateurs.get("connecte", ""),
                    identite.get("bios_version", ""),
                    raw_date,
                    data.get("heure_scan", ""),
                    score_sec,
                    score_conf,
                    1,
                    json.dumps(data, ensure_ascii=False),
                    json.dumps(data, ensure_ascii=False),
                ),
            )
            rows = []
            for sw in logiciels:
                enrichir_logiciel(sw, sw.get("nom", ""))
                sw_metier = sw.get("metier") or _classifier_metier(
                    sw.get("nom", ""), sw.get("editeur", ""), sw.get("categorie", "")
                )
                sw_type = sw.get("type_logiciel", "")
                rows.append(
                    (
                        scan_id,
                        sw.get("nom", ""),
                        sw.get("version", ""),
                        sw.get("editeur", ""),
                        sw.get("chemin", ""),
                        sw.get("categorie", ""),
                        sw.get("risque_auto", "Faible"),
                        _safe_int(sw.get("risque_score", 0)),
                        sw.get("eol", "Non"),
                        sw.get("install_source", ""),
                        sw.get("signature", ""),
                        sw.get("hash_sha256", ""),
                        sw.get("cert_editeur", ""),
                        sw.get("description", ""),
                        sw.get("architecture", ""),
                        sw_type,
                        sw_metier,
                        sw.get("contexte_installation", ""),
                        sw.get("pays_editeur", ""),
                    )
                )
            c.executemany(
                """INSERT INTO logiciels (scan_id, nom, version, editeur, chemin,
                           categorie, risque_niveau, risque_score, eol, install_source, signature,
                           hash_sha256, cert_editeur, description, architecture, type_logiciel, metier,
                           contexte_installation, pays_editeur)
                           VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                rows,
            )
        c.execute(
            """INSERT INTO historique_scan (scan_id, nom_pc, ip, date_scan, heure_scan,
                    duree_s, nb_logiciels, alertes, rapport_json)
                    VALUES (?,?,?,?,?,?,?,?,?)""",
            (
                scan_id,
                identite.get("nom", ""),
                ip,
                raw_date,
                data.get("heure_scan", ""),
                _safe_float(data.get("duree_s", 0)),
                len(logiciels),
                json.dumps(_safe_list(alertes_data.get("liste"))),
                json.dumps(data, ensure_ascii=False),
            ),
        )
        c.execute(
            """INSERT INTO historique_actions (scan_id, nom_pc, type_action, logiciel_nom,
                    date_action, heure_action)
                    VALUES (?,?,?,?,?,?)""",
            (
                scan_id,
                identite.get("nom", ""),
                "scan_complete",
                "-",
                raw_date,
                data.get("heure_scan", ""),
            ),
        )
    except Exception:
        conn.rollback()
        if is_sqlite(conn):
            conn.execute("PRAGMA foreign_keys = ON")
        conn.close()
        raise
    conn.commit()
    if is_sqlite(conn):
        conn.execute("PRAGMA foreign_keys = ON")
    conn.close()
    return scan_id


@app.route("/api/stats")
def api_stats():
    conn = get_db()
    c = conn.cursor()
    total = c.execute("SELECT COUNT(*) as cnt FROM machines").fetchone()["cnt"]
    actifs = c.execute("SELECT COUNT(*) as cnt FROM machines WHERE actif=1").fetchone()[
        "cnt"
    ]
    inactifs = total - actifs
    critiques = c.execute(
        "SELECT COUNT(*) as cnt FROM logiciels WHERE risque_score >= 8"
    ).fetchone()["cnt"]
    vulns = c.execute(
        "SELECT COUNT(*) as cnt FROM logiciels WHERE risque_score >= 5"
    ).fetchone()["cnt"]
    logiciels_total = c.execute("SELECT COUNT(*) as cnt FROM logiciels").fetchone()[
        "cnt"
    ]
    logiciels_uniques = c.execute(
        "SELECT COUNT(DISTINCT nom) as cnt FROM logiciels"
    ).fetchone()["cnt"]
    os_rows = c.execute(
        "SELECT os_nom, COUNT(*) as cnt FROM machines GROUP BY os_nom"
    ).fetchall()
    os_repartition = {row["os_nom"] or "Inconnu": row["cnt"] for row in os_rows}
    evo_rows = c.execute("""SELECT date_scan, COUNT(*) as cnt FROM machines
                            GROUP BY date_scan ORDER BY date_scan LIMIT 30""").fetchall()
    evolution = [{"date_scan": r["date_scan"], "cnt": r["cnt"]} for r in evo_rows]
    conf_score = c.execute(
        "SELECT COALESCE(AVG(score_conformite), 0) as s FROM machines"
    ).fetchone()["s"]
    sec_score = c.execute(
        "SELECT COALESCE(AVG(score_securite), 0) as s FROM machines"
    ).fetchone()["s"]
    eol_count = c.execute(
        "SELECT COUNT(*) as cnt FROM logiciels WHERE (eol IN ('OUI','1') OR eol = '1')"
    ).fetchone()["cnt"]
    obsoletes = c.execute(
        "SELECT COUNT(*) as cnt FROM logiciels WHERE risque_score >= 3 AND risque_score < 5"
    ).fetchone()["cnt"]
    total_cve = c.execute("SELECT COUNT(*) as cnt FROM cve_cache").fetchone()["cnt"]
    cve_critiques = c.execute(
        "SELECT COUNT(*) as cnt FROM cve_cache WHERE cvss_score >= 9"
    ).fetchone()["cnt"]
    # Répartition des risques logiciels
    risque_rows = c.execute("""
        SELECT risque_niveau, COUNT(DISTINCT nom) as cnt FROM logiciels
        WHERE risque_niveau IS NOT NULL AND risque_niveau != ''
        GROUP BY risque_niveau
    """).fetchall()
    risques = {r["risque_niveau"]: r["cnt"] for r in risque_rows}
    machines = c.execute(
        "SELECT nom_pc, scan_id, date_scan FROM machines ORDER BY timestamp DESC"
    ).fetchall()
    conn.close()
    return jsonify(
        {
            "total_pc": total,
            "postes_actifs": actifs,
            "postes_inactifs": inactifs,
            "critiques": critiques,
            "vulnerables": vulns,
            "total_logiciels": logiciels_total,
            "logiciels_uniques": logiciels_uniques,
            "obsoletes": obsoletes,
            "eol": eol_count,
            "eol_count": eol_count,
            "total_cve": total_cve,
            "cve_critiques": cve_critiques,
            "risques": risques,
            "os_repartition": os_repartition,
            "evolution_parc": evolution,
            "score_conformite_global": round(conf_score, 1),
            "score_securite_global": round(sec_score, 1),
            "derniers_scans": [
                {"nom_pc": m["nom_pc"], "scan_id": m["scan_id"], "date": m["date_scan"]}
                for m in machines[:10]
            ],
        }
    )


@app.route("/api/machines")
def api_machines():
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("""SELECT scan_id, nom_pc, ip, os_nom, utilisateur, domaine,
                        cpu_nom, cpu_coeurs, ram_gb, disque_taille_gb, date_scan, actif,
                        score_securite, score_conformite
                        FROM machines ORDER BY timestamp DESC""").fetchall()
    result = []
    for r in rows:
        sw = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=?", (r["scan_id"],)
        ).fetchone()["cnt"]
        crit = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND risque_score>=8",
            (r["scan_id"],),
        ).fetchone()["cnt"]
        eol = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND (eol IN ('OUI','1') OR eol = '1')",
            (r["scan_id"],),
        ).fetchone()["cnt"]
        result.append(
            {
                "scan_id": r["scan_id"],
                "nom_pc": r["nom_pc"],
                "ip": r["ip"],
                "os_nom": r["os_nom"],
                "utilisateur": r["utilisateur"],
                "domaine": r["domaine"],
                "cpu_nom": r["cpu_nom"],
                "cpu_coeurs": r["cpu_coeurs"],
                "ram_gb": r["ram_gb"],
                "disque_taille_gb": r["disque_taille_gb"],
                "date_scan": r["date_scan"],
                "actif": r["actif"],
                "nb_logiciels": sw,
                "nb_critiques": crit,
                "nb_eol": eol,
                "score_securite": r["score_securite"],
                "score_conformite": r["score_conformite"],
            }
        )
    conn.close()
    return jsonify(result)


@app.route("/api/machine/save", methods=["POST"])
def api_machine_save():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    scan_id = (data.get("scan_id") or "").strip()
    conn = get_db()
    c = conn.cursor()
    if scan_id:
        existing = c.execute(
            "SELECT id FROM machines WHERE scan_id=?", (scan_id,)
        ).fetchone()
        if not existing:
            return jsonify({"error": "Machine introuvable"}), 404
        c.execute(
            """UPDATE machines SET nom_pc=?, ip=?, mac=?, utilisateur=?, domaine=?,
                     os_nom=?, os_version=?, os_build=?, os_arch=?, fabricant=?,
                     modele=?, ram_gb=?, cpu_nom=?, cpu_coeurs=?, disque_taille_gb=?,
                     disque_libre_gb=?, disque_pct_libre=?, uptime_jours=?,
                     department=?, location=?, actif=?, type_machine=?, notes=?,
                     date_scan=?, heure_scan=?, score_securite=?, score_conformite=?
                     WHERE scan_id=?""",
            (
                data.get("nom_pc"),
                data.get("ip"),
                data.get("mac"),
                data.get("utilisateur"),
                data.get("domaine"),
                data.get("os_nom"),
                data.get("os_version"),
                data.get("os_build"),
                data.get("os_arch"),
                data.get("fabricant"),
                data.get("modele"),
                data.get("ram_gb"),
                data.get("cpu_nom"),
                data.get("cpu_coeurs"),
                data.get("disque_taille_gb"),
                data.get("disque_libre_gb"),
                data.get("disque_pct_libre"),
                data.get("uptime_jours"),
                data.get("department"),
                data.get("location"),
                data.get("actif", 1),
                data.get("type_machine"),
                data.get("notes"),
                data.get("date_scan"),
                data.get("heure_scan"),
                data.get("score_securite", 0),
                data.get("score_conformite", 0),
                scan_id,
            ),
        )
    else:
        import hashlib

        raw = str(data.get("nom_pc", "")) + str(datetime.datetime.now().timestamp())
        new_scan_id = hashlib.md5(raw.encode()).hexdigest()[:12]
        c.execute(
            """INSERT INTO machines (scan_id, nom_pc, ip, mac, utilisateur, domaine,
                     os_nom, os_version, os_build, os_arch, fabricant, modele, ram_gb,
                     cpu_nom, cpu_coeurs, disque_taille_gb, disque_libre_gb,
                     disque_pct_libre, uptime_jours, department, location, actif,
                     type_machine, notes, date_scan, heure_scan,
                     score_securite, score_conformite)
                     VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                new_scan_id,
                data.get("nom_pc"),
                data.get("ip"),
                data.get("mac"),
                data.get("utilisateur"),
                data.get("domaine"),
                data.get("os_nom"),
                data.get("os_version"),
                data.get("os_build"),
                data.get("os_arch"),
                data.get("fabricant"),
                data.get("modele"),
                data.get("ram_gb"),
                data.get("cpu_nom"),
                data.get("cpu_coeurs"),
                data.get("disque_taille_gb"),
                data.get("disque_libre_gb"),
                data.get("disque_pct_libre"),
                data.get("uptime_jours"),
                data.get("department"),
                data.get("location"),
                data.get("actif", 1),
                data.get("type_machine"),
                data.get("notes"),
                data.get("date_scan"),
                data.get("heure_scan"),
                data.get("score_securite", 0),
                data.get("score_conformite", 0),
            ),
        )
        scan_id = new_scan_id
    conn.commit()
    conn.close()
    return jsonify({"status": "ok", "scan_id": scan_id})


@app.route("/api/machine/<scan_id>")
def api_machine(scan_id):
    conn = get_db()
    c = conn.cursor()
    row = c.execute("SELECT * FROM machines WHERE scan_id=?", (scan_id,)).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Machine non trouvee"}), 404
    machine = dict(row)
    logiciels = c.execute(
        "SELECT * FROM logiciels WHERE scan_id=?", (scan_id,)
    ).fetchall()
    machine["logiciels"] = [dict(l) for l in logiciels]
    intune_apps = []
    is_entreprise = False
    domaine = (machine.get("domaine") or "").upper()
    try:
        rapport = json.loads(machine.get("rapport_json", "{}"))
        intune_data = rapport.get("intune", {})
        if intune_data.get("present"):
            is_entreprise = True
            if intune_data.get("intune_apps"):
                intune_apps = [a.lower() for a in intune_data["intune_apps"]]
    except (json.JSONDecodeError, TypeError):
        pass

    if domaine not in ("", "WORKGROUP"):
        is_entreprise = True

    machine["is_entreprise"] = is_entreprise
    machine["type_usage"] = "Entreprise" if is_entreprise else "Personnel"

    for sw in machine["logiciels"]:
        sw["origine"] = classer_origine(sw, scan_id)
        sw_nom = (sw.get("nom") or "").lower()
        if sw["origine"] == "Utilisateur" and is_entreprise and intune_apps:
            for ia in intune_apps:
                if ia.lower() in sw_nom or sw_nom.startswith(ia.lower()):
                    sw["origine"] = "Intune"
                    break
        # Enrich each software with pays and provenance_autorisee
        edt_sw = sw.get("editeur") or ""
        ed_info_sw = _get_editeur_info(edt_sw)
        sw["pays"] = (ed_info_sw or {}).get("pays", "")
        sov_sw = _compute_sovereignty(sw["pays"], ed_info_sw)
        sw["pays_siege"] = sov_sw["pays_siege"]
        sw["pays_hebergement"] = sov_sw["pays_hebergement"]
        sw["pays_developpement"] = sov_sw["pays_developpement"]
        sw["restrictions"] = sov_sw["restrictions"]
        sw["risque_souverainete"] = sov_sw["risque"]
        src_lower_sw = (sw.get("install_source") or "").lower()
        sw["provenance_autorisee"] = ""
        for kw, prov in GOUV_PROVENANCE.items():
            if any(
                k.replace(" ", "") in src_lower_sw.replace(" ", "")
                for k in kw.split("|")
            ):
                sw["provenance_autorisee"] = prov
                break
        # Recalculer le risque base sur les CVE reelles
        nouveau_niv, nouveau_sc = recalculer_risque_par_cve(
            conn, sw["nom"], sw.get("risque_niveau"), sw.get("risque_score")
        )
        if nouveau_niv != sw.get("risque_niveau") or nouveau_sc != sw.get(
            "risque_score"
        ):
            sw["risque_niveau"] = nouveau_niv
            sw["risque_score"] = nouveau_sc
        # Classification metier et enrichissement
        if not sw.get("metier") or sw["metier"] in ("", "Autre"):
            sw["metier"] = _classifier_metier(sw.get("nom", ""), sw.get("editeur", ""))
        sw["est_metier"] = sw["metier"] not in ("Autre", "Non classe", "")
        if not sw.get("description"):
            gov = auto_remplir_gouvernance(
                sw.get("nom", ""), sw.get("editeur", ""), sw.get("install_source", "")
            )
            sw["description"] = gov.get("description", "")
    try:
        rapport = json.loads(machine.get("rapport_json", "{}"))
        extra = [
            "reseau",
            "securite",
            "processus",
            "services",
            "persistance",
            "mises_a_jour",
            "utilisateurs",
            "portables",
            "systeme",
            "materiel",
            "alertes",
            "ports_ecoute",
        ]
        for key in extra:
            machine[key] = rapport.get(key, {})
        # Appliquer les surcharges meta_json sur les sections modifiables
        try:
            meta = json.loads(machine.get("meta_json", "{}"))
            SEC_NESTED = {
                "antivirus_nom": ("antivirus", "nom"),
                "antivirus_actif": ("antivirus", "actif"),
                "antivirus_temps_reel": ("antivirus", "temps_reel"),
                "firewall_actif": ("firewall", "actif"),
                "bitlocker_present": ("bitlocker", "present"),
                "secure_boot": ("secure_boot",),
                "rdp": ("rdp",),
                "smb": ("smb",),
            }
            for section in [
                "info",
                "securite",
                "reseau",
                "systeme",
                "processus",
                "persistance",
                "historique",
            ]:
                overrides = meta.get(section + "_overrides", {})
                if overrides:
                    if section == "info":
                        machine.update(overrides)
                    elif isinstance(machine.get(section), dict):
                        if section == "securite":
                            for k, v in overrides.items():
                                path = SEC_NESTED.get(k)
                                if path:
                                    if len(path) == 1:
                                        machine[section][path[0]] = v
                                    else:
                                        parent, child = path
                                        if parent not in machine[
                                            section
                                        ] or not isinstance(
                                            machine[section][parent], dict
                                        ):
                                            machine[section][parent] = {}
                                        machine[section][parent][child] = v
                        else:
                            machine[section].update(overrides)
                    else:
                        machine[section] = overrides
        except (json.JSONDecodeError, TypeError):
            pass
        # Correction reseau : deriver MAC/type/passerelle depuis les interfaces si absents
        net = machine.get("reseau", {})
        if isinstance(net, dict):
            interfaces = net.get("interfaces", []) or []
            phys = [
                i
                for i in interfaces
                if isinstance(i, dict)
                and i.get("nom")
                and not re.search(
                    r"(?i)VMware|Virtual|Hyper-V|TAP|OpenVPN|Pseudo|Tunnel|WAN Miniport|Wi-Fi Direct|Bluetooth|Docker|WSL|Loopback",
                    i.get("nom", ""),
                )
            ]
            if phys:
                p = phys[0]
                if not net.get("mac"):
                    net["mac"] = p.get("mac", "")
                if not net.get("type_reseau"):
                    net["type_reseau"] = (
                        "Wi-Fi"
                        if re.search(r"(?i)Wi-Fi|Wireless|802\.11", p.get("nom", ""))
                        else "Ethernet"
                    )
                if (
                    not net.get("ip")
                    or net.get("ip", "").startswith("169.254")
                    or any(
                        i.get("ip") == net.get("ip")
                        and re.search(r"(?i)Wi-Fi Direct|Virtual", i.get("nom", ""))
                        for i in interfaces
                        if isinstance(i, dict)
                    )
                ):
                    net["ip"] = p.get("ip", net.get("ip", ""))
            if not net.get("passerelle") and net.get("dns"):
                dns = [
                    d
                    for d in (
                        net["dns"] if isinstance(net["dns"], list) else [net["dns"]]
                    )
                    if d
                ]
                if dns:
                    net["passerelle"] = dns[0]
    except (json.JSONDecodeError, TypeError):
        pass
    hist_rows = c.execute(
        """SELECT * FROM historique_scan
                             WHERE nom_pc=? ORDER BY id DESC LIMIT 20""",
        (machine["nom_pc"],),
    ).fetchall()
    machine["historique_scans"] = [dict(h) for h in hist_rows]
    prev = None
    if len(hist_rows) > 1:
        prev = hist_rows[1]
    if prev:
        try:
            prev_rapport = json.loads(prev["rapport_json"])
            prev_sw = {
                (s.get("nom", ""), s.get("version", ""))
                for s in prev_rapport.get("logiciels", [])
            }
        except (json.JSONDecodeError, TypeError):
            prev_sw = set()
    else:
        prev_sw = set()
    cur_sw = {(l["nom"], l["version"]) for l in machine["logiciels"]}
    added = [{"nom": n, "version": v} for n, v in cur_sw - prev_sw]
    removed = [{"nom": n, "version": v} for n, v in prev_sw - cur_sw]
    machine["diff"] = {"added": added, "removed": removed}
    conn.close()
    return jsonify(machine)


@app.route("/api/machine/<scan_id>/notes", methods=["GET", "POST"])
def api_machine_notes(scan_id):
    conn = get_db()
    c = conn.cursor()
    if request.method == "POST":
        data = request.get_json() or {}
        notes = data.get("notes", "")
        c.execute("UPDATE machines SET notes=? WHERE scan_id=?", (notes, scan_id))
        commit(conn)
        close(conn)
        return jsonify({"ok": True})
    row = c.execute("SELECT notes FROM machines WHERE scan_id=?", (scan_id,)).fetchone()
    close(conn)
    return jsonify({"notes": (row["notes"] or "") if row else ""})


@app.route("/api/machine/<scan_id>/meta", methods=["POST"])
def api_machine_meta(scan_id):
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    section = data.get("section", "")
    values = data.get("values", {})
    if not section or not values:
        return jsonify({"error": "section et values requis"}), 400
    conn = get_db()
    c = conn.cursor()
    row = c.execute(
        "SELECT meta_json FROM machines WHERE scan_id=?", (scan_id,)
    ).fetchone()
    if not row:
        close(conn)
        return jsonify({"error": "Machine introuvable"}), 404
    try:
        meta = json.loads(row["meta_json"]) if row["meta_json"] else {}
    except (json.JSONDecodeError, TypeError):
        meta = {}
    values = {k: v for k, v in values.items() if v not in ("", None)}
    meta[section + "_overrides"] = values
    c.execute(
        "UPDATE machines SET meta_json=? WHERE scan_id=?", (json.dumps(meta), scan_id)
    )
    commit(conn)
    close(conn)
    return jsonify({"status": "ok"})


@app.route("/api/machine/<scan_id>/sw/<int:sw_id>/notes", methods=["POST"])
def api_machine_sw_notes(scan_id, sw_id):
    data = request.get_json() or {}
    notes = data.get("notes", "")
    conn = get_db()
    c = conn.cursor()
    c.execute(
        "UPDATE logiciels SET notes=? WHERE id=? AND scan_id=?", (notes, sw_id, scan_id)
    )
    commit(conn)
    close(conn)
    return jsonify({"ok": True})


@app.route("/api/machine/<scan_id>/delete", methods=["DELETE"])
def api_machine_delete(scan_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM logiciels WHERE scan_id=?", (scan_id,))
    c.execute("DELETE FROM machines WHERE scan_id=?", (scan_id,))
    commit(conn)
    close(conn)
    return jsonify({"status": "ok"})


@app.route("/api/logiciels")
def api_logiciels():
    conn = get_db()
    c = conn.cursor()

    # --- Filter params ---
    q = request.args.get("q", "")
    cat = request.args.get("cat", "")
    risk = request.args.get("risk", "")
    eolF = request.args.get("eol", "")
    appF = request.args.get("approuve", "")
    editeurF = request.args.get("editeur", "")
    sourceF = request.args.get("source", "")
    typeF = request.args.get("type", "")
    metierF = request.args.get("metier", "")
    provenanceF = request.args.get("provenance", "")
    postesF = request.args.get("postes", "")

    page = int(request.args.get("page", 1))
    per_page = int(request.args.get("per_page", 100))
    sort_by = request.args.get("sort_by", "nb_installations")
    sort_dir = request.args.get("sort_dir", "desc")

    # --- Build WHERE ---
    where_clauses = []
    params = []

    if q:
        where_clauses.append("(LOWER(l.nom) LIKE ? OR LOWER(l.editeur) LIKE ?)")
        params.append(f"%{q.lower()}%")
        params.append(f"%{q.lower()}%")

    if sourceF:
        where_clauses.append("l.install_source = ?")
        params.append(sourceF)

    if editeurF == "microsoft":
        where_clauses.append("l.editeur LIKE '%Microsoft%'")
    elif editeurF == "tiers":
        where_clauses.append(
            "(l.editeur NOT LIKE '%Microsoft%' AND l.editeur NOT LIKE '%Windows%' AND (l.editeur IS NOT NULL AND l.editeur != ''))"
        )

    if typeF == "systeme":
        where_clauses.append(
            "l.install_source IN ('Registry','WindowsFeature','AppxProvisioned')"
        )
    elif typeF == "utilisateur":
        where_clauses.append(
            "l.install_source IN ('Appx','Registry_HKCU','StartMenu','PATH')"
        )
    elif typeF == "portable":
        where_clauses.append("l.install_source = 'Portable'")
    elif typeF == "dev":
        where_clauses.append(
            "l.install_source IN ('pip','npm','Composer','WSL','Chocolatey','Winget')"
        )

    if cat:
        where_clauses.append("l.categorie = ?")
        params.append(cat)
    if risk:
        where_clauses.append("l.risque_niveau = ?")
        params.append(risk)
    if eolF == "OUI":
        where_clauses.append("(l.eol = 'OUI' OR l.eol = 1)")
    if metierF:
        where_clauses.append("l.metier = ?")
        params.append(metierF)

    where_sql = "WHERE " + " AND ".join(where_clauses) if where_clauses else ""

    # --- HAVING for postes ---
    having_clauses = []
    having_params = []
    if postesF:
        if postesF == "1":
            having_clauses.append("nb_postes = ?")
            having_params.append(1)
        elif postesF == "2-5":
            having_clauses.append("nb_postes BETWEEN ? AND ?")
            having_params.extend([2, 5])
        elif postesF == "6-20":
            having_clauses.append("nb_postes BETWEEN ? AND ?")
            having_params.extend([6, 20])
        elif postesF == "21-100":
            having_clauses.append("nb_postes BETWEEN ? AND ?")
            having_params.extend([21, 100])
        elif postesF == "101+":
            having_clauses.append("nb_postes >= ?")
            having_params.append(101)
    having_sql = "HAVING " + " AND ".join(having_clauses) if having_clauses else ""

    # --- Allowed sort columns (whitelist) ---
    SORT_COLS = {
        "nom",
        "editeur",
        "categorie",
        "risque_niveau",
        "nb_installations",
        "nb_postes",
        "eol",
        "metier",
        "risque_score",
        "type_logiciel",
    }
    if sort_by not in SORT_COLS:
        sort_by = "nb_installations"
    if sort_dir not in ("asc", "desc"):
        sort_dir = "desc"

    # --- Base FROM/GROUP (shared between count and data queries) ---
    base_from = """FROM logiciels l
                   LEFT JOIN machines m ON l.scan_id = m.scan_id
                   {where_sql}
                   GROUP BY LOWER(l.nom)""".format(where_sql=where_sql)

    # --- Count query ---
    count_sql = """SELECT COUNT(*) as total FROM (SELECT 1 AS dummy {base_from} {having_sql}) sub"""
    # For HAVING, params include both WHERE params and HAVING params
    all_params = params + having_params
    total_row = c.execute(
        count_sql.format(base_from=base_from, having_sql=having_sql), all_params
    ).fetchone()
    total = total_row["total"] if total_row else 0

    # --- Data query with pagination ---
    offset = (page - 1) * per_page
    data_sql = """SELECT MIN(l.nom) as nom, MIN(l.editeur) as editeur,
                         MIN(l.categorie) as categorie, MIN(l.risque_niveau) as risque_niveau,
                         COUNT(*) as nb_installations,
                         MAX(l.risque_score) as risque_score,
                         MAX(l.eol) as eol,
                         COUNT(DISTINCT m.nom_pc) as nb_postes,
                         MIN(l.metier) as metier, MIN(l.type_logiciel) as type_logiciel
                  {base_from}
                  {having_sql}
                  ORDER BY {sort_col} {sort_dir}
                  LIMIT ? OFFSET ?"""
    data_sql = data_sql.format(
        base_from=base_from, having_sql=having_sql, sort_col=sort_by, sort_dir=sort_dir
    )
    limit_params = params + having_params + [per_page, offset]
    rows = c.execute(data_sql, limit_params).fetchall()

    # --- Enrich each row (same N+1 as before, but only for current page) ---
    result = []
    for r in rows:
        d = dict(r)
        edt = d.get("editeur") or ""
        d["est_microsoft"] = (
            1 if ("microsoft" in edt.lower() or "windows" in edt.lower()) else 0
        )
        d["origine"] = classer_origine(r)
        if d["origine"] == "Intune":
            domaines = c.execute(
                """SELECT DISTINCT m.domaine FROM logiciels l
                                    JOIN machines m ON l.scan_id = m.scan_id
                                    WHERE l.nom=?""",
                (d["nom"],),
            ).fetchall()
            if domaines:
                aucun_entreprise = all(
                    not dmx["domaine"]
                    or dmx["domaine"].strip().upper() in ("", "WORKGROUP")
                    for dmx in domaines
                )
                if aucun_entreprise:
                    d["origine"] = "Utilisateur"
        srcs = c.execute(
            "SELECT DISTINCT install_source FROM logiciels WHERE nom=?", (d["nom"],)
        ).fetchall()
        d["install_sources"] = ",".join(
            s["install_source"] for s in srcs if s["install_source"]
        )
        vulns = c.execute(
            "SELECT COUNT(*) as cnt FROM cve_cache WHERE logiciel_nom=?", (d["nom"],)
        ).fetchone()["cnt"]
        d["nb_cve"] = vulns
        app = c.execute(
            "SELECT approuve, provenance_autorisee FROM catalogue WHERE nom=?",
            (d["nom"],),
        ).fetchone()
        d["approuve"] = app["approuve"] if app else 0
        first_src = (
            (d.get("install_sources") or "").split(",")[0]
            if d.get("install_sources")
            else ""
        )
        d["niveau"] = _get_niveau_acces(first_src)
        if app and app["provenance_autorisee"]:
            d["provenance_autorisee"] = app["provenance_autorisee"]
        else:
            src_lower = first_src.lower()
            d["provenance_autorisee"] = ""
            for kw, prov in GOUV_PROVENANCE.items():
                if any(
                    k.replace(" ", "") in src_lower.replace(" ", "")
                    for k in kw.split("|")
                ):
                    d["provenance_autorisee"] = prov
                    break
        ed_info = _get_editeur_info(edt)
        d["pays"] = (ed_info or {}).get("pays", "")
        sov = _compute_sovereignty(d["pays"], ed_info)
        d["pays_siege"] = sov["pays_siege"]
        d["pays_hebergement"] = sov["pays_hebergement"]
        d["pays_developpement"] = sov["pays_developpement"]
        d["restrictions"] = sov["restrictions"]
        d["risque_souverainete"] = sov["risque"]
        nouveau_niveau, nouveau_score = recalculer_risque_par_cve(
            conn, d["nom"], d.get("risque_niveau"), d.get("risque_score")
        )
        if nouveau_niveau != d.get("risque_niveau") or nouveau_score != d.get(
            "risque_score"
        ):
            d["risque_niveau"] = nouveau_niveau
            d["risque_score"] = nouveau_score
            c.execute(
                "UPDATE logiciels SET risque_niveau=?, risque_score=? WHERE nom=?",
                (nouveau_niveau, nouveau_score, d["nom"]),
            )
            commit(conn)
        result.append(d)

    # --- Extract distinct filter values for dropdowns (from full unfiltered data) ---
    filters_data = {}
    try:
        cats = c.execute(
            "SELECT DISTINCT categorie FROM logiciels WHERE categorie IS NOT NULL AND categorie != '' ORDER BY categorie"
        ).fetchall()
        filters_data["categories"] = [r["categorie"] for r in cats]
    except Exception:
        filters_data["categories"] = []
    try:
        pays_list = c.execute(
            "SELECT DISTINCT editeur FROM logiciels WHERE editeur IS NOT NULL AND editeur != ''"
        ).fetchall()
        all_pays = set()
        for r in pays_list:
            ei = _get_editeur_info(r["editeur"])
            if ei and ei.get("pays"):
                all_pays.add(ei["pays"])
        filters_data["pays"] = sorted(all_pays)
    except Exception:
        filters_data["pays"] = []
    try:
        mets = c.execute(
            "SELECT DISTINCT metier FROM logiciels WHERE metier IS NOT NULL AND metier != '' ORDER BY metier"
        ).fetchall()
        filters_data["metiers"] = [r["metier"] for r in mets]
    except Exception:
        filters_data["metiers"] = []
    try:
        srcs = c.execute(
            "SELECT DISTINCT install_source FROM logiciels WHERE install_source IS NOT NULL AND install_source != '' ORDER BY install_source"
        ).fetchall()
        filters_data["sources"] = [r["install_source"] for r in srcs]
    except Exception:
        filters_data["sources"] = []
    try:
        ori = c.execute(
            "SELECT DISTINCT install_source FROM logiciels WHERE install_source IS NOT NULL AND install_source != ''"
        ).fetchall()
        ori_set = set()
        for r in ori:
            s = r["install_source"]
            if s in ("windowsfeature", "appxprovisioned"):
                ori_set.add("Windows")
            elif s and s.lower() in (
                "registry",
                "registry_hkcu",
                "appx",
                "startmenu",
                "path",
                "portable",
                "winget",
                "chocolatey",
                "pip",
                "npm",
                "wsl",
                "composer",
            ):
                ori_set.add("Utilisateur")
        filters_data["origines"] = sorted(ori_set)
    except Exception:
        filters_data["origines"] = []

    # --- Background CVE enrichment for uncached logiciels ---
    try:
        uncached = c.execute("""
            SELECT COUNT(DISTINCT l.nom) as cnt FROM logiciels l
            WHERE l.nom NOT IN (SELECT DISTINCT logiciel_nom FROM cve_cache)
        """).fetchone()["cnt"]
        if uncached > 0:
            import threading

            def _enrich_bg():
                try:
                    bg_conn = get_db()
                    batch_enrich(bg_conn, limit=30)
                    commit(bg_conn)
                    close(bg_conn)
                except Exception as ex:
                    print(f"[CVE] Erreur enrich bg: {ex}")

            threading.Thread(target=_enrich_bg, daemon=True).start()
    except Exception:
        pass

    conn.close()
    return jsonify(
        {
            "data": result,
            "total": total,
            "page": page,
            "per_page": per_page,
            "total_pages": (total + per_page - 1) // per_page if total else 0,
            "filters": filters_data,
        }
    )


def enrichir_logiciel(inst, nom, cat=None):
    """Complete les champs manquants d'une installation logiciel avec des valeurs deduites."""
    src = (inst.get("install_source") or "").lower()
    arch = inst.get("architecture") or ""
    typ = inst.get("type_logiciel") or ""
    # Architecture
    if not arch:
        if "32-bit" in src or "wow" in src.lower() or src == "32-bit":
            arch = "32-bit"
        elif "appx" in src:
            arch = "UWP (Neutre / Windows)"
        elif src in ("registry", "") or not arch:
            arch = "Non specifie"
        inst["architecture"] = arch
    # Type logiciel
    if not typ:
        type_map = {
            "registry": "Installe (MSI)",
            "registry_hkcu": "Installe (MSI - Utilisateur)",
            "appx": "App Store (UWP)",
            "appxprovisioned": "App Store (Preinstalle)",
            "winget": "Gestionnaire (Winget)",
            "chocolatey": "Gestionnaire (Choco)",
            "pip": "Gestionnaire (pip)",
            "npm": "Gestionnaire (npm)",
            "startmenu": "Raccourci (.lnk)",
            "wsl": "WSL Distribution",
            "windowsfeature": "Fonction Windows",
            "windowsupdate": "Mise a jour Windows (KB)",
            "composer": "Gestionnaire (Composer)",
        }
        typ = type_map.get(src)
        if typ is None and src in ("portable", "path"):
            ext_map = {
                ".exe": "Executable (.exe)",
                ".com": "Executable (.com)",
                ".msi": "Installeur (MSI)",
                ".msp": "Correctif (MSP)",
                ".msu": "Mise a jour (MSU)",
                ".cab": "Archive (CAB)",
                ".appx": "Package Store (APPX)",
                ".appxbundle": "Package Store (APPXBUNDLE)",
                ".jar": "Application Java (.jar)",
                ".ps1": "Script PowerShell (.ps1)",
                ".bat": "Script Batch (.bat)",
                ".vbs": "Script VBScript (.vbs)",
                ".cmd": "Script Batch (.cmd)",
            }
            nom = inst.get("nom", "")
            ext = os.path.splitext(nom)[1].lower()
            typ = ext_map.get(
                ext, "Portable (.exe)" if src == "portable" else "Executable (PATH)"
            )
        if not typ:
            typ = "Installe" if src else "Inconnu"
        inst["type_logiciel"] = typ
    # Signature numerique depuis l'editeur
    sig = inst.get("signature") or ""
    if not sig or sig == "Inconnu":
        edt = (inst.get("editeur") or "").lower()
        if any(
            m in edt
            for m in [
                "microsoft",
                "windows",
                "google",
                "mozilla",
                "adobe",
                "oracle",
                "apple",
                "intel",
                "amd",
                "nvidia",
                "vmware",
                "docker",
                "spotify",
                "slack",
                "github",
                "gitlab",
                "jetbrains",
                "autodesk",
            ]
        ):
            inst["signature"] = "Valide (editeur connu)"
    # Taille via chemin si dispo
    taille = inst.get("taille_kb")
    if not taille and inst.get("chemin"):
        _c = inst["chemin"]
        if _c.startswith("\\\\") or _c.startswith("//") or len(_c) > 260:
            pass
        elif (
            not _c.startswith("Non")
            and not _c.startswith("Gere")
            and not _c.startswith("Composant")
            and not _c.startswith("Application")
        ):
            try:
                if os.path.isfile(_c):
                    inst["taille_kb"] = str(round(os.path.getsize(_c) / 1024, 1))
            except:
                pass

    # Remplissage par defaut des champs vides
    if not inst.get("chemin"):
        if "appx" in src:
            inst["chemin"] = "Application UWP (Geree par Windows)"
        elif "winget" in src:
            inst["chemin"] = "Gere par Winget"
        elif "chocolatey" in src:
            inst["chemin"] = "Gere par Chocolatey"
        elif "windowsfeature" in src:
            inst["chemin"] = "Composant interne Windows"
        else:
            inst["chemin"] = "Non detecte"

    if not inst.get("hash_sha256"):
        if "appx" in src or "windowsfeature" in src:
            inst["hash_sha256"] = "N/A (Integre au systeme)"
        else:
            inst["hash_sha256"] = "Non collecte"

    if not inst.get("taille_kb"):
        inst["taille_kb"] = "Inconnue"

    if not inst.get("cert_editeur"):
        if "appx" in src:
            inst["cert_editeur"] = "Gere par Microsoft Store"
        else:
            inst["cert_editeur"] = "Non specifie"

    if not inst.get("date_installation"):
        inst["date_installation"] = "Inconnue"
    if not inst.get("date_version"):
        inst["date_version"] = "Inconnue"
    if not inst.get("build"):
        inst["build"] = "Non specifie"
    if not inst.get("derniere_execution"):
        inst["derniere_execution"] = "Inconnue"

    # Contexte d'installation (niveau d'acces)
    if not inst.get("contexte_installation"):
        inst["contexte_installation"] = _get_niveau_acces(
            inst.get("install_source", "")
        )

    # Pays de l'editeur (cache memoire pour eviter les requetes HTTP bloquantes)
    if not inst.get("pays_editeur"):
        edt = inst.get("editeur", "")
        ed_info = _get_editeur_info(edt)
        if ed_info:
            inst["pays_editeur"] = ed_info.get("pays", "")
        else:
            inst["pays_editeur"] = _lookup_editor_country_local(edt)

    return inst


_editor_country_cache = {}


def _lookup_editor_country_local(editor_name):
    """Recherche locale uniquement (fichier + hints), sans requete HTTP."""
    if not editor_name:
        return ""
    key = editor_name.strip().lower()
    if key in _editor_country_cache:
        return _editor_country_cache[key]

    # Cherche dans le fichier editors.json
    try:
        from version_editor_service import load_editors, _COUNTRY_HINTS

        editors = load_editors()
        if key in editors:
            val = editors[key].get("pays", "")
            _editor_country_cache[key] = val
            return val
        for k, v in editors.items():
            if k in key or key in k:
                val = v.get("pays", "")
                _editor_country_cache[key] = val
                return val
        # Cherche dans les hints
        for hint_key, country in _COUNTRY_HINTS.items():
            if hint_key in key or key in hint_key:
                _editor_country_cache[key] = country
                return country
    except Exception:
        pass
    _editor_country_cache[key] = ""
    return ""


@app.route("/api/logiciel/<nom>", methods=["GET", "POST"])
def api_logiciel(nom):
    if request.method == "POST":
        data = request.get_json(force=True, silent=True) or {}
        conn = get_db()
        c = conn.cursor()
        existing = c.execute("SELECT id FROM catalogue WHERE nom=?", (nom,)).fetchone()
        if existing:
            c.execute(
                """UPDATE catalogue SET
                description=?, fonction_metier=?, referent_metier=?, referent_technique=?,
                service_concerne=?, contrat_associe=?, fin_support=?, criticite_metier=?,
                approuve=?, provenance_autorisee=?, historique_failles=?, fuites_donnees=?
                WHERE nom=?""",
                (
                    data.get("description", ""),
                    data.get("fonction_metier", ""),
                    data.get("referent_metier", ""),
                    data.get("referent_technique", ""),
                    data.get("service_concerne", ""),
                    data.get("contrat_associe", ""),
                    data.get("fin_support", ""),
                    data.get("criticite_metier", ""),
                    int(data.get("approuve", 0)),
                    data.get("provenance_autorisee", ""),
                    data.get("historique_failles", ""),
                    data.get("fuites_donnees", ""),
                    nom,
                ),
            )
        else:
            ref = c.execute(
                "SELECT editeur, install_source, description FROM logiciels WHERE nom=? LIMIT 1",
                (nom,),
            ).fetchone()
            edt = ref["editeur"] if ref else ""
            install_src = ref["install_source"] if ref else ""
            desc = ref["description"] if ref else ""
            gov_auto = auto_remplir_gouvernance(nom, edt, install_src, desc, "")
            c.execute(
                """INSERT INTO catalogue
                (nom, editeur, categorie, description, fonction_metier, referent_metier,
                 referent_technique, service_concerne, contrat_associe, fin_support,
                 criticite_metier, approuve, provenance_autorisee, historique_failles, fuites_donnees)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    nom,
                    edt,
                    "",
                    data.get("description", gov_auto.get("description", "")),
                    data.get("fonction_metier", gov_auto.get("fonction_metier", "")),
                    data.get("referent_metier", ""),
                    data.get("referent_technique", ""),
                    data.get("service_concerne", ""),
                    data.get("contrat_associe", gov_auto.get("contrat_associe", "")),
                    data.get("fin_support", gov_auto.get("fin_support", "")),
                    data.get("criticite_metier", gov_auto.get("criticite_metier", "")),
                    int(data.get("approuve", 0)),
                    data.get(
                        "provenance_autorisee", gov_auto.get("provenance_autorisee", "")
                    ),
                    data.get("historique_failles", ""),
                    data.get("fuites_donnees", ""),
                ),
            )
        log_action(
            f"Gouvernance mise a jour: {nom}", categorie="gouvernance", details=data
        )
        commit(conn)
        conn.close()
        return jsonify({"success": True, "message": "Gouvernance sauvegardee"})
    conn = get_db()
    c = conn.cursor()
    editions = c.execute(
        "SELECT DISTINCT version, editeur FROM logiciels WHERE nom=?", (nom,)
    ).fetchall()
    installs = c.execute(
        """SELECT l.*, m.nom_pc
                            FROM logiciels l LEFT JOIN machines m ON l.scan_id=m.scan_id
                            WHERE l.nom=?""",
        (nom,),
    ).fetchall()
    inst_list = [dict(i) for i in installs]
    for inst in inst_list:
        inst["origine"] = classer_origine(inst, inst.get("scan_id"))
        enrichir_logiciel(inst, nom)
    cves = c.execute("SELECT * FROM cve_cache WHERE logiciel_nom=?", (nom,)).fetchall()
    if not cves:
        try:
            from cve_service import enrich_software

            enrich_software(conn, nom)
            cves = c.execute(
                "SELECT * FROM cve_cache WHERE logiciel_nom=?", (nom,)
            ).fetchall()
        except Exception as e:
            print(f"  [CVE] Auto-enrich echec pour {nom}: {e}")
    # Recalculer et persister le risque base sur CVE
    if inst_list:
        ref_sw = inst_list[0]
        nouveau_niv, nouveau_sc = recalculer_risque_par_cve(
            conn, nom, ref_sw.get("risque_niveau"), ref_sw.get("risque_score")
        )
        if nouveau_niv != ref_sw.get("risque_niveau") or nouveau_sc != ref_sw.get(
            "risque_score"
        ):
            c.execute(
                "UPDATE logiciels SET risque_niveau=?, risque_score=? WHERE nom=?",
                (nouveau_niv, nouveau_sc, nom),
            )
            commit(conn)
            for inst in inst_list:
                inst["risque_niveau"] = nouveau_niv
                inst["risque_score"] = nouveau_sc
    cat = c.execute("SELECT * FROM catalogue WHERE nom=?", (nom,)).fetchone()
    lic = c.execute("SELECT * FROM licences WHERE logiciel_nom=?", (nom,)).fetchone()
    hist = c.execute(
        """SELECT * FROM historique_actions
                        WHERE logiciel_nom=? ORDER BY timestamp DESC LIMIT 20""",
        (nom,),
    ).fetchall()
    nb_postes = c.execute(
        """SELECT COUNT(DISTINCT nom_pc) as cnt
                             FROM logiciels l LEFT JOIN machines m ON l.scan_id=m.scan_id
                             WHERE l.nom=?""",
        (nom,),
    ).fetchone()["cnt"]
    nb_versions = c.execute(
        "SELECT COUNT(DISTINCT version) as cnt FROM logiciels WHERE nom=?", (nom,)
    ).fetchone()["cnt"]
    enrichi = None
    first = inst_list[0] if inst_list else {}
    src = (first.get("install_source", "") or "").lower()
    if "portable" in src:
        from enrichissement import enrichir_executable_portable

        collecte_data = {
            "editeur": first.get("editeur", "") or "",
            "description": first.get("description", "") or "",
            "produit": first.get("nom_produit", "") or "",
        }
        enrichi = enrichir_executable_portable(nom, collecte_data)
    cat_enrichi = None
    if not cat:
        if enrichi and enrichi.get("categorie"):
            cat_enrichi = {"categorie": enrichi["categorie"]}
        else:
            edt = first.get("editeur", "") or ""
            desc = first.get("description", "") or ""
            detected = detecter_categorie(nom, edt, desc)
            if detected:
                cat_enrichi = {"categorie": detected}
    lic_auto = None
    if not lic:
        edt = first.get("editeur", "") or ""
        cat_lic = detecter_categorie_licence(nom, edt)
        sous_lic = None
        if cat_lic and cat_lic != "Inconnu":
            _, sous_lic = analyser_licence(nom, edt)
        if cat_lic:
            lic_auto = {"type_licence": cat_lic, "sous_type_licence": sous_lic}
    edt = first.get("editeur", "") or ""
    desc = first.get("description", "") or ""
    version = first.get("version", "") or ""
    gov_auto = auto_remplir_gouvernance(
        nom, edt, first.get("install_source", ""), desc, version
    )
    conn.close()
    if enrichi:
        for i in inst_list:
            if enrichi.get("editeur"):
                i["editeur"] = enrichi["editeur"]
            if enrichi.get("categorie"):
                i["categorie"] = enrichi["categorie"]
            if enrichi.get("nom_produit"):
                i["nom_produit"] = enrichi["nom_produit"]
    # editeur_info: try edt field, fallback to first word of sw name, then each word
    editeur_info = _get_editeur_info(edt)
    if not editeur_info:
        first_word = nom.split()[0] if nom else ""
        if first_word:
            editeur_info = _get_editeur_info(first_word)
    if not editeur_info:
        for w in nom.split():
            editeur_info = _get_editeur_info(w)
            if editeur_info:
                break
    sov = _compute_sovereignty((editeur_info or {}).get("pays", ""), editeur_info)
    return jsonify(
        {
            "nom": nom,
            "metier": first.get("metier"),
            "versions": [dict(e) for e in editions],
            "installations": inst_list,
            "cves": [dict(c) for c in cves],
            "catalogue": dict(cat) if cat else cat_enrichi,
            "licence": dict(lic) if lic else lic_auto,
            "licence_auto": lic_auto,
            "gouvernance_auto": gov_auto,
            "historique": [dict(h) for h in hist],
            "stats": {"nb_postes": nb_postes, "nb_versions": nb_versions},
            "enrichi": enrichi,
            "editeur_info": editeur_info,
            "souverainete": sov,
        }
    )


@app.route("/api/logiciel/<nom>/delete-catalogue", methods=["DELETE"])
def api_logiciel_delete_catalogue(nom):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM catalogue WHERE nom=?", (nom,))
    commit(conn)
    close(conn)
    return jsonify({"status": "ok"})


@app.route("/api/logiciel/row/<int:row_id>", methods=["PUT", "DELETE"])
def api_logiciel_row(row_id):
    if request.method == "DELETE":
        conn = get_db()
        c = conn.cursor()
        c.execute("DELETE FROM logiciels WHERE id=?", (row_id,))
        commit(conn)
        close(conn)
        return jsonify({"status": "ok"})
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    allowed = {
        "editeur",
        "version",
        "architecture",
        "categorie",
        "taille_kb",
        "risque_niveau",
        "risque_score",
        "eol",
        "signature",
        "portable",
        "hash_sha256",
        "cert_editeur",
        "derniere_execution",
        "version_date",
        "install_source",
        "install_lang",
        "description",
        "build",
        "type_logiciel",
        "chemin",
        "derniere_version",
        "notes",
        "approuve",
        "criticite_metier",
        "meta_json",
        "date_compilation",
    }
    updates = {k: v for k, v in data.items() if k in allowed}
    if not updates:
        return jsonify({"error": "Aucun champ valide"}), 400
    sets = ", ".join(f"{k}=?" for k in updates)
    vals = list(updates.values()) + [row_id]
    conn = get_db()
    c = conn.cursor()
    c.execute(f"UPDATE logiciels SET {sets} WHERE id=?", vals)
    commit(conn)
    close(conn)
    return jsonify({"status": "ok"})


@app.route("/api/enrich-souverainete", methods=["POST"])
def api_enrich_souverainete():
    """Declenche l'enrichissement automatique des donnees de souverainete."""
    try:
        result = _auto_enrich_sovereignty()
        return jsonify(
            {
                "status": "ok",
                "total": result.get("total"),
                "enriched": result.get("enriched"),
            }
        )
    except Exception as e:
        return jsonify({"status": "error", "error": str(e)}), 500


@app.route("/api/search")
def api_search():
    q = request.args.get("q", "").strip().lower()
    if len(q) < 2:
        return jsonify({"machines": [], "logiciels": [], "cves": []})

    conn = get_db()
    c = conn.cursor()

    # Search machines
    machines = c.execute(
        """
        SELECT scan_id, nom_pc, ip, utilisateur, os_nom 
        FROM machines 
        WHERE LOWER(nom_pc) LIKE ? OR LOWER(ip) LIKE ? OR LOWER(utilisateur) LIKE ?
        LIMIT 5
    """,
        (f"%{q}%", f"%{q}%", f"%{q}%"),
    ).fetchall()

    # Search logiciels
    logiciels = c.execute(
        """
        SELECT nom, editeur, risque_niveau, COUNT(*) as nb_installations 
        FROM logiciels 
        WHERE LOWER(nom) LIKE ? OR LOWER(editeur) LIKE ?
        GROUP BY nom, editeur, risque_niveau
        ORDER BY nb_installations DESC
        LIMIT 10
    """,
        (f"%{q}%", f"%{q}%"),
    ).fetchall()

    # Search CVEs
    cves = c.execute(
        """
        SELECT cve_id, cvss_score, logiciel_nom 
        FROM cve_cache 
        WHERE LOWER(cve_id) LIKE ? OR LOWER(logiciel_nom) LIKE ?
        LIMIT 10
    """,
        (f"%{q}%", f"%{q}%"),
    ).fetchall()

    conn.close()

    return jsonify(
        {
            "machines": [dict(m) for m in machines],
            "logiciels": [dict(l) for l in logiciels],
            "cves": [dict(cv) for cv in cves],
        }
    )


_REGLES_ANSSI = [
    {
        "regle": "antivirus_actif",
        "domaine": "Securisation poste",
        "niveau": "Critique",
        "poids": 10,
        "description": "Antivirus actif et base de signatures a jour",
        "remediation": "Activer Windows Defender ou un antivirus tiers, verifier les mises a jour des signatures",
        "cle_api": "securite.antivirus.actif / securite.defender.actif",
        "reference_anssi": "Guide hygiene ANSSI (R1)",
    },
    {
        "regle": "firewall_actif",
        "domaine": "Securisation poste",
        "niveau": "Critique",
        "poids": 9,
        "description": "Pare-feu active sur tous les profils",
        "remediation": "Activer le pare-feu Windows dans le Panneau de configuration / Securite",
        "cle_api": "securite.firewall.actif",
        "reference_anssi": "Guide hygiene ANSSI (R2)",
    },
    {
        "regle": "bitlocker_active",
        "domaine": "Securisation poste",
        "niveau": "Eleve",
        "poids": 8,
        "description": "Chiffrement BitLocker actif sur au moins un volume",
        "remediation": "Activer BitLocker via Gestion des peripheriques > Chiffrement",
        "cle_api": "securite.bitlocker.present / volumes_chiffres",
        "reference_anssi": "RGS - Chiffrement des donnees au repos",
    },
    {
        "regle": "secure_boot_active",
        "domaine": "Securisation poste",
        "niveau": "Moyen",
        "poids": 5,
        "description": "Secure Boot active dans l'UEFI",
        "remediation": "Activer Secure Boot dans les parametres UEFI/BIOS du poste",
        "cle_api": "securite.secure_boot / systeme.secure_boot",
        "reference_anssi": "ANSSI - Securisation du demarrage",
    },
    {
        "regle": "rdp_desactive",
        "domaine": "Securisation poste",
        "niveau": "Moyen",
        "poids": 4,
        "description": "Bureau a distance (RDP) desactive sauf necessite",
        "remediation": "Desactiver RDP dans Systeme > Parametres > Bureau a distance",
        "cle_api": "securite.rdp",
        "reference_anssi": "Guide hygiene ANSSI (R10)",
    },
    {
        "regle": "os_a_jour",
        "domaine": "Mise a jour",
        "niveau": "Critique",
        "poids": 10,
        "description": "Derniere mise a jour OS datant de moins de 90 jours",
        "remediation": "Installer les dernieres mises a jour Windows via Windows Update",
        "cle_api": "mises_a_jour.derniere",
        "reference_anssi": "Guide hygiene ANSSI (R3)",
    },
    {
        "regle": "update_recents",
        "domaine": "Mise a jour",
        "niveau": "Eleve",
        "poids": 7,
        "description": "Mise a jour OS recente (< 30 jours)",
        "remediation": "Installer les correctifs mensuels (Patch Tuesday) dans les 30 jours",
        "cle_api": "mises_a_jour.derniere",
        "reference_anssi": "ANSSI - Patch management",
    },
    {
        "regle": "pas_eol",
        "domaine": "Mise a jour",
        "niveau": "Critique",
        "poids": 9,
        "description": "Aucun logiciel en fin de vie (EOL) installe",
        "remediation": "Identifier les logiciels EOL et les mettre a jour ou les remplacer",
        "cle_api": "logiciels[].eol",
        "reference_anssi": "ANSSI - Fin de vie des logiciels",
    },
    {
        "regle": "utilisateurs_locaux_minimum",
        "domaine": "Controle acces",
        "niveau": "Moyen",
        "poids": 5,
        "description": "3 utilisateurs locaux ou moins (hors administrateur)",
        "remediation": "Supprimer les comptes utilisateurs inactifs ou non necessaires",
        "cle_api": "utilisateurs.locaux",
        "reference_anssi": "Guide hygiene ANSSI (R5)",
    },
    {
        "regle": "admin_count_limit",
        "domaine": "Controle acces",
        "niveau": "Eleve",
        "poids": 6,
        "description": "3 administrateurs locaux ou moins",
        "remediation": "Limiter le nombre d'administrateurs locaux au strict minimum",
        "cle_api": "utilisateurs.admins",
        "reference_anssi": "Guide hygiene ANSSI (R5) - Moindre privilege",
    },
    {
        "regle": "pas_compte_invite",
        "domaine": "Controle acces",
        "niveau": "Moyen",
        "poids": 4,
        "description": "Compte invite desactive",
        "remediation": "Desactiver le compte Invite via l'outil Utilisateurs locaux",
        "cle_api": "utilisateurs.locaux",
        "reference_anssi": "ANSSI - Gestion des comptes locaux",
    },
    {
        "regle": "intune_managed",
        "domaine": "Gestion centralisee",
        "niveau": "Moyen",
        "poids": 5,
        "description": "Appareil gere via Intune, GPO ou MDM",
        "remediation": "Inscrire le poste dans Intune / GPO Active Directory",
        "cle_api": "intune.present",
        "reference_anssi": "ANSSI - Gestion centralisee",
    },
    {
        "regle": "asr_regles_actives",
        "domaine": "Detection",
        "niveau": "Eleve",
        "poids": 6,
        "description": "Regles ASR (Attack Surface Reduction) actives dans Defender",
        "remediation": "Activer les regles ASR via GPO (Windows Defender > Exploit Guard)",
        "cle_api": "securite.asr.actif",
        "reference_anssi": "ANSSI - Reduction de la surface d'attaque",
    },
    {
        "regle": "logiciels_non_autorises",
        "domaine": "Securite applicative",
        "niveau": "Critique",
        "poids": 9,
        "description": "Absence de logiciels non autorises (risque Critique)",
        "remediation": "Desinstaller les logiciels non autorises et mettre en place une whitelist",
        "cle_api": "logiciels[].risque_niveau",
        "reference_anssi": "ANSSI - Politique de securite applicative",
    },
    {
        "regle": "smb_desactive",
        "domaine": "Securite applicative",
        "niveau": "Moyen",
        "poids": 3,
        "description": "Partage SMB desactive (si non utilise)",
        "remediation": "Desactiver le service SMB via Services ou pare-feu",
        "cle_api": "securite.smb",
        "reference_anssi": "Guide hygiene ANSSI (R10) - Desactiver SMBv1",
    },
]


@app.route("/api/conformite")
def api_conformite():
    from datetime import datetime, timedelta

    conn = get_db()
    c = conn.cursor()

    machines = c.execute(
        "SELECT nom_pc, scan_id, rapport_json FROM machines ORDER BY nom_pc"
    ).fetchall()
    total_machines = len(machines)
    if total_machines == 0:
        conn.close()
        return jsonify({"regles": [], "score": 0, "total_machines": 0})

    scores_domaines = {}
    total_poids_reel = 0
    total_pondere = 0.0

    regles = copy.deepcopy(_REGLES_ANSSI)

    for rule_def in regles:
        regle = rule_def["regle"]
        domaine = rule_def["domaine"]
        poids = rule_def["poids"]
        machines_ok = []
        machines_ko = []
        verifiable = 0

        for m in machines:
            nom_pc = m["nom_pc"]
            try:
                rapport = json.loads(m["rapport_json"])
            except (json.JSONDecodeError, TypeError):
                rapport = {}
            sec = rapport.get("securite", {}) or {}
            sys_info = rapport.get("systeme", {}) or {}
            logiciels = rapport.get("logiciels", []) or []
            updates = rapport.get("mises_a_jour", {}) or {}
            users = rapport.get("utilisateurs", {}) or {}
            intune_data = rapport.get("intune", {}) or {}
            raison = ""
            ok = False

            if regle == "antivirus_actif":
                av = sec.get("antivirus", {}) or {}
                if av.get("actif") is not None:
                    verifiable += 1
                    ok = bool(av["actif"])
                    if not ok:
                        raison = "Antivirus desactive"
                elif sec.get("defender", {}).get("actif") is not None:
                    verifiable += 1
                    ok = bool(sec["defender"]["actif"])
                    if not ok:
                        raison = "Defender desactive"
            elif regle == "firewall_actif":
                fw = sec.get("firewall", {}) or {}
                if fw.get("actif") is not None:
                    verifiable += 1
                    ok = bool(fw["actif"])
                    if not ok:
                        raison = "Pare-feu desactive"
            elif regle == "bitlocker_active":
                bl = sec.get("bitlocker", {}) or {}
                if bl.get("present") is not None:
                    verifiable += 1
                    ok = bool(bl["present"])
                    if not ok:
                        raison = "BitLocker inactif"
                elif bl.get("volumes_chiffres", 0) > 0:
                    verifiable += 1
                    ok = True
            elif regle == "secure_boot_active":
                sb = (
                    sec.get("secure_boot")
                    if sec.get("secure_boot") is not None
                    else sys_info.get("secure_boot")
                )
                if sb is not None:
                    verifiable += 1
                    ok = bool(sb)
                    if not ok:
                        raison = "Secure Boot desactive"
            elif regle == "rdp_desactive":
                rdp = sec.get("rdp")
                if rdp is not None:
                    verifiable += 1
                    ok = not rdp
                    if not ok:
                        raison = "RDP actif"
            elif regle == "os_a_jour":
                derniere = updates.get("derniere", "")
                if derniere:
                    verifiable += 1
                    try:
                        lu = datetime.strptime(str(derniere), "%d/%m/%Y")
                        ok = (datetime.now() - lu).days <= 90
                        if not ok:
                            raison = "Derniere MAJ > 90 jours"
                    except (ValueError, TypeError):
                        raison = "Date invalide"
            elif regle == "update_recents":
                derniere = updates.get("derniere", "")
                if derniere:
                    verifiable += 1
                    try:
                        lu = datetime.strptime(str(derniere), "%d/%m/%Y")
                        ok = (datetime.now() - lu).days <= 30
                        if not ok:
                            raison = "Pas de MAJ depuis > 30 jours"
                    except (ValueError, TypeError):
                        raison = "Date invalide"
            elif regle == "pas_eol":
                sw_list = logiciels or []
                eol_sw = [
                    s
                    for s in sw_list
                    if isinstance(s, dict)
                    and str(s.get("eol", "")).upper() in ("OUI", "1", "YES")
                ]
                verifiable += 1
                ok = not eol_sw
                if not ok:
                    noms_eol = [s.get("nom", "?") for s in eol_sw[:3]]
                    raison = "EOL: " + ", ".join(noms_eol)
            elif regle == "utilisateurs_locaux_minimum":
                locaux = users.get("locaux")
                if locaux is not None:
                    verifiable += 1
                    nb = len(locaux)
                    ok = nb <= 3
                    if not ok:
                        raison = f"{nb} utilisateurs locaux"
            elif regle == "admin_count_limit":
                admins = users.get("admins")
                if admins is not None:
                    verifiable += 1
                    nb = len(admins)
                    ok = nb <= 3
                    if not ok:
                        raison = f"{nb} administrateurs locaux"
            elif regle == "pas_compte_invite":
                locaux = users.get("locaux")
                if locaux is not None:
                    verifiable += 1
                    locaux_lower = [u.lower() for u in locaux]
                    ok = (
                        "invite" not in locaux_lower
                        and "invité" not in locaux_lower
                        and "guest" not in locaux_lower
                    )
                    if not ok:
                        raison = "Compte invite present"
            elif regle == "intune_managed":
                if intune_data.get("present") is not None:
                    verifiable += 1
                    ok = bool(intune_data["present"])
                    if not ok:
                        raison = "Non gere (Intune/GPO absent)"
            elif regle == "asr_regles_actives":
                asr = sec.get("asr", {}) or {}
                if asr.get("actif") is not None:
                    verifiable += 1
                    ok = bool(asr["actif"])
                    if not ok:
                        raison = "ASR desactive"
            elif regle == "logiciels_non_autorises":
                sw_list = logiciels or []
                crit = [
                    s
                    for s in sw_list
                    if isinstance(s, dict)
                    and str(s.get("risque_niveau", "")) == "Critique"
                ]
                verifiable += 1
                ok = not crit
                if not ok:
                    noms_crit = [s.get("nom", "?") for s in crit[:3]]
                    raison = "Non autorises: " + ", ".join(noms_crit)
            elif regle == "smb_desactive":
                smb = sec.get("smb")
                if smb is not None:
                    verifiable += 1
                    ok = not smb
                    if not ok:
                        raison = "SMB actif"

            if ok:
                machines_ok.append(nom_pc)
            elif verifiable > 0:
                machines_ko.append({"machine": nom_pc, "raison": raison})

        couverture = round(verifiable / max(total_machines, 1) * 100)
        if verifiable == 0:
            statut = "Non verifie"
            pct = 0
        elif len(machines_ok) == 0:
            statut = "KO"
            pct = 0
        elif len(machines_ko) == 0:
            statut = "OK"
            pct = 100
        else:
            statut = "Partiel"
            pct = round(len(machines_ok) / verifiable * 100)

        rule_def["statut"] = statut
        rule_def["ok"] = len(machines_ok)
        rule_def["total"] = verifiable
        rule_def["couverture"] = couverture
        rule_def["pct"] = pct
        rule_def["machines_ko"] = machines_ko

        # Score pondere: ne compte que si >= 30% des machines sont verifiables
        if verifiable >= max(1, round(total_machines * 0.3)):
            ratio_ok = len(machines_ok) / verifiable
            total_poids_reel += poids
            total_pondere += poids * ratio_ok
            if domaine not in scores_domaines:
                scores_domaines[domaine] = {"poids": 0, "acquis": 0.0, "regles": []}
            scores_domaines[domaine]["poids"] += poids
            scores_domaines[domaine]["acquis"] += poids * ratio_ok
            scores_domaines[domaine]["regles"].append(regle)

    score_global = round(total_pondere / max(total_poids_reel, 1) * 100)
    score_color = (
        "success"
        if score_global >= 80
        else "warning"
        if score_global >= 50
        else "danger"
    )

    domaines_data = {}
    for d, v in scores_domaines.items():
        ds = round(v["acquis"] / max(v["poids"], 1) * 100)
        dc = "success" if ds >= 80 else "warning" if ds >= 50 else "danger"
        domaines_data[d] = {
            "score": ds,
            "poids": v["poids"],
            "couleur": dc,
            "nb_regles": len(v["regles"]),
        }

    extra_rules = c.execute("SELECT * FROM compliance_rules").fetchall()
    extra_list = [dict(r) for r in extra_rules]

    conn.close()
    return jsonify(
        {
            "regles": regles,
            "extra_regles": extra_list,
            "score": score_global,
            "score_color": score_color,
            "domaines": domaines_data,
            "nb_regles": len(regles),
            "total_machines": total_machines,
            "machines_ko_count": sum(len(r.get("machines_ko", [])) for r in regles),
        }
    )


@app.route("/api/historique")
@app.route("/api/historique_actions")
def api_historique():
    conn = get_db()
    c = conn.cursor()
    try:
        limit = int(request.args.get("limit", 100))
    except (ValueError, TypeError):
        limit = 100
    rows = c.execute(
        """SELECT * FROM historique_actions
                        ORDER BY timestamp DESC LIMIT ?""",
        (limit,),
    ).fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/evolution/<scan_id>")
def api_evolution(scan_id):
    conn = get_db()
    c = conn.cursor()
    current = c.execute(
        "SELECT nom_pc, date_scan FROM machines WHERE scan_id=?", (scan_id,)
    ).fetchone()
    if not current:
        conn.close()
        return jsonify({"error": "Scan introuvable"}), 404
    previous = c.execute(
        """SELECT scan_id FROM machines WHERE nom_pc=? AND date_scan < ?
                            ORDER BY date_scan DESC LIMIT 1""",
        (current["nom_pc"], current["date_scan"]),
    ).fetchone()
    if not previous:
        conn.close()
        return jsonify({"added": [], "removed": [], "changed": []})
    cur_sw = set()
    old_sw = {}
    for row in c.execute(
        "SELECT nom, version FROM logiciels WHERE scan_id=?", (scan_id,)
    ).fetchall():
        cur_sw.add(row["nom"])
    for row in c.execute(
        "SELECT nom, version FROM logiciels WHERE scan_id=?", (previous["scan_id"],)
    ).fetchall():
        old_sw[row["nom"]] = row["version"]
    added = [s for s in cur_sw if s not in old_sw]
    removed = [s for s in old_sw if s not in cur_sw]
    changed = []
    for s in cur_sw:
        if (
            s in old_sw
            and old_sw[s]
            != c.execute(
                "SELECT version FROM logiciels WHERE scan_id=? AND nom=?", (scan_id, s)
            ).fetchone()["version"]
        ):
            changed.append(s)
    conn.close()
    return jsonify({"added": added, "removed": removed, "changed": changed})


@app.route("/api/cve_enrich/<nom>")
@app.route("/api/cve/enrich/<nom>", methods=["GET", "POST"])
def api_cve_enrich(nom):
    conn = get_db()
    c = conn.cursor()
    existing = c.execute(
        "SELECT * FROM cve_cache WHERE logiciel_nom=? ORDER BY cvss_score DESC", (nom,)
    ).fetchall()
    if existing:
        conn.close()
        return jsonify({"cves": [dict(e) for e in existing], "source": "cache"})
    try:
        cves = enrich_software(conn, nom)

        # Recuperation de la derniere version et editeur en arriere plan
        latest_v = fetch_latest_version(nom)
        if latest_v:
            c.execute(
                "UPDATE logiciels SET derniere_version=? WHERE nom=?", (latest_v, nom)
            )
            conn.commit()

        conn.close()
        return jsonify(
            {
                "cves": cves,
                "source": "live",
                "cve_count": len(cves),
                "derniere_version": latest_v,
            }
        )
    except Exception as e:
        conn.close()
        return jsonify({"cves": [], "error": str(e), "source": "error"})


@app.route("/api/cve/multi-enrich/<nom>", methods=["POST"])
def api_cve_multi_enrich(nom):
    conn = get_db()
    try:
        cves = enrich_software(conn, nom)
        latest_v = fetch_latest_version(nom)
        if latest_v:
            conn.cursor().execute(
                "UPDATE logiciels SET derniere_version=? WHERE nom=?", (latest_v, nom)
            )
        conn.commit()
        conn.close()
        return jsonify(
            {"cves": cves, "cve_count": len(cves), "derniere_version": latest_v}
        )
    except Exception as e:
        conn.close()
        return jsonify({"cves": [], "error": str(e)})


@app.route("/api/cve/batch-enrich", methods=["POST"])
def api_cve_batch_enrich():
    conn = get_db()
    try:
        results = batch_enrich(conn)
        conn.commit()
        conn.close()
        return jsonify({"enriched": results, "total": len(results)})
    except Exception as e:
        conn.close()
        return jsonify({"error": str(e)}), 500


@app.route("/api/cve/sources")
def api_cve_sources():
    cisa_count = len(load_cisa_kev())
    conn = get_db()
    c = conn.cursor()
    cache_count = c.execute(
        "SELECT COUNT(DISTINCT logiciel_nom) as cnt FROM cve_cache"
    ).fetchone()["cnt"]
    total_cves = c.execute("SELECT COUNT(*) as cnt FROM cve_cache").fetchone()["cnt"]
    by_source = c.execute(
        "SELECT source, COUNT(*) as cnt FROM cve_cache GROUP BY source"
    ).fetchall()
    source_stats = {r["source"]: r["cnt"] for r in by_source}
    conn.close()
    return jsonify(
        {
            "sources": {
                "NVD": {"available": True, "cached": source_stats.get("NVD", 0)},
                "CISA_KEV": {
                    "available": True,
                    "cached": source_stats.get("CISA_KEV", 0),
                    "total_known": cisa_count,
                },
                "MSRC": {"available": True, "cached": source_stats.get("MSRC", 0)},
            },
            "total_logiciels_cached": cache_count,
            "total_cves": total_cves,
        }
    )


@app.route("/api/logiciels-licences")
def api_logiciels_licences():
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("""
        SELECT MIN(l.nom) as nom, MIN(l.editeur) as editeur,
               MAX(l.version) as version_recente,
               COUNT(DISTINCT l.scan_id) as nb_machines,
               COUNT(DISTINCT l.version) as nb_versions,
               MAX(l.version_date) as dernier_scan,
               MAX(l.categorie) as categorie_fonctionnelle,
               MAX(l.description) as description,
               MAX(l.risque_niveau) as risque_niveau,
               MAX(l.risque_score) as risque_score,
               MAX(l.install_source) as install_source,
               MAX(l.chemin) as chemin
        FROM logiciels l
        GROUP BY LOWER(l.nom), LOWER(COALESCE(l.editeur,''))
        ORDER BY nb_machines DESC, MIN(l.nom) ASC
    """).fetchall()
    licences_data = c.execute("SELECT * FROM licences").fetchall()
    lic_map = {}
    for lic in licences_data:
        key = (lic["logiciel_nom"].lower(), (lic["editeur"] or "").lower())
        lic_map[key] = dict(lic)
    conn.close()
    result = []
    for r in rows:
        key = (r["nom"].lower(), (r["editeur"] or "").lower())
        manuelle = lic_map.get(key, {})
        if manuelle.get("categorie_licence"):
            cat = manuelle["categorie_licence"]
            sous_type = manuelle.get("type_licence") or ""
        else:
            cat, sous_type = analyser_licence(r["nom"], r["editeur"] or "")
        install_type = "Installe"
        src = r["install_source"] or ""
        if src in ("Appx", "AppxProvisioned"):
            install_type = "App Store (UWP)"
        elif src in ("Registry", "Registry_HKCU"):
            install_type = "Installe (Registre)"
        elif src in ("Winget", "Chocolatey"):
            install_type = "Installe (Package Manager)"
        elif src == "WindowsFeature":
            install_type = "Composant Windows"
        elif src == "WindowsUpdate":
            install_type = "Mise a jour Windows (KB)"
        elif src == "PATH":
            nom = r["nom"] or ""
            ext = os.path.splitext(nom)[1].lower()
            ext_map = {
                ".exe": "Executable (.exe)",
                ".com": "Executable (.com)",
                ".msi": "Installeur (MSI)",
                ".ps1": "Script PowerShell (.ps1)",
                ".bat": "Script Batch (.bat)",
                ".vbs": "Script VBScript (.vbs)",
                ".jar": "Application Java (.jar)",
            }
            install_type = ext_map.get(ext, "Executable (PATH)")
        elif src == "Portable" or (r["chemin"] and "portable" in r["chemin"].lower()):
            nom = r["nom"] or ""
            ext = os.path.splitext(nom)[1].lower()
            ext_map = {
                ".exe": "Portable (.exe)",
                ".com": "Executable (.com)",
                ".msi": "Installeur (MSI)",
                ".msp": "Correctif (MSP)",
                ".msu": "Mise a jour (MSU)",
                ".cab": "Archive (CAB)",
                ".appx": "Package Store (APPX)",
                ".appxbundle": "Package Store (APPXBUNDLE)",
                ".jar": "Application Java (.jar)",
                ".ps1": "Script PowerShell (.ps1)",
                ".bat": "Script Batch (.bat)",
                ".vbs": "Script VBScript (.vbs)",
                ".cmd": "Script Batch (.cmd)",
            }
            install_type = ext_map.get(ext, "Portable (.exe)")
        result.append(
            {
                "nom": r["nom"],
                "editeur": r["editeur"] or "",
                "version_recente": r["version_recente"] or "",
                "nb_machines": r["nb_machines"],
                "nb_versions": r["nb_versions"],
                "dernier_scan": r["dernier_scan"] or "",
                "categorie_fonctionnelle": r["categorie_fonctionnelle"] or "",
                "description": r["description"] or "",
                "risque_niveau": r["risque_niveau"] or "",
                "risque_score": r["risque_score"],
                "install_source": r["install_source"] or "",
                "install_type": install_type,
                "chemin": r["chemin"] or "",
                "categorie_licence": cat,
                "sous_type_licence": sous_type or manuelle.get("type_licence") or "",
                "cout_annuel": manuelle.get("cout_annuel"),
                "nombre_licences": manuelle.get("nombre_licences"),
                "date_expiration": manuelle.get("date_expiration"),
                "fournisseur": manuelle.get("fournisseur"),
                "contact": manuelle.get("contact"),
                "notes": manuelle.get("notes"),
                "numero_licence": manuelle.get("numero_licence"),
                "nb_utilisees": manuelle.get("nb_utilisees"),
                "date_achat": manuelle.get("date_achat"),
                "licence_id": manuelle.get("id"),
                "licence_manuelle": bool(manuelle),
            }
        )
    return jsonify(result)


@app.route("/api/licences")
def api_licences():
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("SELECT * FROM licences").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/licences", methods=["POST"])
def api_licences_post():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    nom = data.get("logiciel_nom", "")
    editeur = data.get("editeur", "")
    cat = data.get("categorie_licence") or detecter_categorie_licence(nom, editeur)
    conn = get_db()
    c = conn.cursor()
    if data.get("id"):
        c.execute(
            """UPDATE licences SET logiciel_nom=?, type_licence=?, nombre_licences=?,
                    date_expiration=?, cout_annuel=?, fournisseur=?, contact=?, notes=?,
                    categorie_licence=?, nb_utilisees=?, date_achat=?, numero_licence=?, editeur=?
                    WHERE id=?""",
            (
                nom,
                data.get("type_licence"),
                data.get("nombre_licences", 1),
                data.get("date_expiration"),
                data.get("cout_annuel"),
                data.get("fournisseur"),
                data.get("contact"),
                data.get("notes"),
                cat,
                data.get("nb_utilisees", 0),
                data.get("date_achat"),
                data.get("numero_licence"),
                editeur,
                data.get("id"),
            ),
        )
        lid = data.get("id")
    else:
        c.execute(
            """INSERT INTO licences (logiciel_nom, type_licence, nombre_licences,
                    date_expiration, cout_annuel, fournisseur, contact, notes,
                    categorie_licence, nb_utilisees, date_achat, numero_licence, editeur)
                    VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                nom,
                data.get("type_licence"),
                data.get("nombre_licences", 1),
                data.get("date_expiration"),
                data.get("cout_annuel"),
                data.get("fournisseur"),
                data.get("contact"),
                data.get("notes"),
                cat,
                data.get("nb_utilisees", 0),
                data.get("date_achat"),
                data.get("numero_licence"),
                editeur,
            ),
        )
        lid = c.lastrowid
    conn.commit()
    conn.close()
    action = "licence_modifiee" if data.get("id") else "licence_ajoutee"
    log_action(
        action,
        "licences",
        "",
        "",
        {"logiciel": nom, "editeur": editeur, "categorie": cat},
        get_client_ip(),
        "",
        "info",
    )
    return jsonify({"id": lid, "status": "ok"})


@app.route("/api/licences/<int:lid>", methods=["DELETE"])
def api_licences_delete(lid):
    conn = get_db()
    conn.execute("DELETE FROM licences WHERE id=?", (lid,))
    conn.commit()
    conn.close()
    log_action(
        "licence_supprimee",
        "licences",
        "",
        "",
        {"id": lid},
        get_client_ip(),
        "",
        "warning",
    )
    return jsonify({"status": "ok"})


# ───────────────────────────────
# Briques logiciel (APIs, librairies, SaaS, etc.)
# ───────────────────────────────
@app.route("/api/briques")
def api_briques_list():
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("SELECT * FROM briques_logiciel ORDER BY nom").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/briques", methods=["POST"])
def api_briques_create():
    data = request.get_json(force=True)
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute(
            """INSERT INTO briques_logiciel
            (nom, editeur, type_brique, description, editeur_url, documentation_url,
             repository_url, pays_origine, annee_creation, version_actuelle, version_utilisee,
             licence, cout, statut, responsable, service_concerne, tags, notes, vulnerabilites,
             requires_wp, requires_php, requires_plugins)
            VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                data.get("nom", ""),
                data.get("editeur", ""),
                data.get("type_brique", ""),
                data.get("description", ""),
                data.get("editeur_url", ""),
                data.get("documentation_url", ""),
                data.get("repository_url", ""),
                data.get("pays_origine", ""),
                data.get("annee_creation", ""),
                data.get("version_actuelle", ""),
                data.get("version_utilisee", ""),
                data.get("licence", ""),
                data.get("cout", ""),
                data.get("statut", ""),
                data.get("responsable", ""),
                data.get("service_concerne", ""),
                data.get("tags", ""),
                data.get("notes", ""),
                data.get("vulnerabilites", ""),
                data.get("requires_wp", ""),
                data.get("requires_php", ""),
                data.get("requires_plugins", ""),
            ),
        )
        conn.commit()
        bid = c.lastrowid
        log_action(
            "brique_ajoutee",
            "briques",
            data.get("nom", ""),
            "",
            {"id": bid, "type": data.get("type_brique")},
            get_client_ip(),
            "",
            "info",
        )
        return jsonify({"status": "ok", "id": bid})
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 400
    finally:
        conn.close()


@app.route("/api/briques/<int:bid>", methods=["PUT"])
def api_briques_update(bid):
    data = request.get_json(force=True)
    fields = [
        "nom",
        "editeur",
        "type_brique",
        "description",
        "editeur_url",
        "documentation_url",
        "repository_url",
        "pays_origine",
        "annee_creation",
        "version_actuelle",
        "version_utilisee",
        "licence",
        "cout",
        "statut",
        "responsable",
        "service_concerne",
        "tags",
        "notes",
        "vulnerabilites",
        "requires_wp",
        "requires_php",
        "requires_plugins",
    ]
    sets = []
    vals = []
    for f in fields:
        if f in data:
            sets.append(f"{f}=?")
            vals.append(data[f])
    if not sets:
        return jsonify({"status": "error", "message": "No fields to update"}), 400
    sets.append("updated_at=datetime('now','localtime')")
    vals.append(bid)
    conn = get_db()
    try:
        conn.execute(f"UPDATE briques_logiciel SET {','.join(sets)} WHERE id=?", vals)
        conn.commit()
        log_action(
            "brique_modifiee",
            "briques",
            str(bid),
            "",
            {"id": bid},
            get_client_ip(),
            "",
            "info",
        )
        return jsonify({"status": "ok"})
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 400
    finally:
        conn.close()


@app.route("/api/briques/<int:bid>", methods=["DELETE"])
def api_briques_delete(bid):
    conn = get_db()
    try:
        conn.execute("DELETE FROM briques_logiciel WHERE id=?", (bid,))
        conn.commit()
        log_action(
            "brique_supprimee",
            "briques",
            str(bid),
            "",
            {"id": bid},
            get_client_ip(),
            "",
            "warning",
        )
        return jsonify({"status": "ok"})
    except Exception as e:
        conn.rollback()
        return jsonify({"status": "error", "message": str(e)}), 400
    finally:
        conn.close()


@app.route("/api/briques/import", methods=["POST"])
def api_briques_import():
    data = request.get_json(force=True)
    briques = data.get("briques", [])
    if not briques:
        return jsonify({"status": "error", "message": "Aucune brique a importer"}), 400
    conn = get_db()
    c = conn.cursor()
    imported = 0
    errors = 0
    columns = (
        "nom",
        "editeur",
        "type_brique",
        "description",
        "editeur_url",
        "documentation_url",
        "repository_url",
        "pays_origine",
        "annee_creation",
        "version_actuelle",
        "version_utilisee",
        "licence",
        "cout",
        "statut",
        "responsable",
        "service_concerne",
        "tags",
        "notes",
        "vulnerabilites",
        "requires_wp",
        "requires_php",
        "requires_plugins",
    )
    placeholders = ",".join("?" for _ in columns)
    for b in briques:
        try:
            nom = (b.get("nom") or "").strip()
            if not nom:
                errors += 1
                continue
            vals = [b.get(c, "") if c != "nom" else nom for c in columns]
            c.execute(
                f"INSERT OR IGNORE INTO briques_logiciel ({','.join(columns)}) VALUES ({placeholders})",
                vals,
            )
            if c.rowcount:
                imported += 1
        except Exception:
            errors += 1
    conn.commit()
    log_action(
        "import_briques",
        "briques",
        str(imported),
        "",
        {"imported": imported, "errors": errors},
        get_client_ip(),
        "",
        "info",
    )
    conn.close()
    return jsonify({"status": "ok", "imported": imported, "errors": errors})


@app.route("/api/vulnerabilites")
def api_vulnerabilites():
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("""SELECT l.nom, l.editeur, l.version, l.risque_score, l.risque_niveau,
                        l.scan_id, m.nom_pc, m.date_scan
                        FROM logiciels l JOIN machines m ON l.scan_id = m.scan_id
                        WHERE l.risque_score >= 5
                        ORDER BY l.risque_score DESC""").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])


@app.route("/api/stats/adv")
@app.route("/api/stats_advanced")
def api_stats_adv():
    conn = get_db()
    c = conn.cursor()
    # Top logiciels les plus installes
    top_utilises = c.execute("""
        SELECT nom, COUNT(*) as nb FROM logiciels
        GROUP BY LOWER(nom) ORDER BY nb DESC LIMIT 20
    """).fetchall()
    # Top logiciels les plus vulnerables
    top_vulnerables = c.execute("""
        SELECT nom, MAX(risque_score) as score FROM logiciels
        WHERE risque_score >= 5
        GROUP BY LOWER(nom) ORDER BY score DESC LIMIT 20
    """).fetchall()
    # Top logiciels obsoletes (EOL)
    top_obsoletes = c.execute("""
        SELECT nom, COUNT(*) as nb FROM logiciels
        WHERE eol IN ('OUI','1') OR eol = '1'
        GROUP BY LOWER(nom) ORDER BY nb DESC LIMIT 20
    """).fetchall()
    # Logiciels avec plusieurs versions
    multi_versions = c.execute("""
        SELECT nom, COUNT(DISTINCT version) as nb_versions FROM logiciels
        GROUP BY LOWER(nom) HAVING COUNT(DISTINCT version) > 1
        ORDER BY nb_versions DESC LIMIT 20
    """).fetchall()
    # Evolution des scans dans le temps
    evolution = c.execute("""
        SELECT date_scan, COUNT(*) as nb FROM machines
        GROUP BY date_scan ORDER BY date_scan LIMIT 30
    """).fetchall()
    conn.close()
    return jsonify(
        {
            "top_utilises": [dict(r) for r in top_utilises],
            "top_vulnerables": [dict(r) for r in top_vulnerables],
            "top_obsoletes": [dict(r) for r in top_obsoletes],
            "multi_versions": [dict(r) for r in multi_versions],
            "evolution": [dict(r) for r in evolution],
        }
    )


@app.route("/api/audit/security")
def api_audit_security():
    """Audit securite complet : CVE + version + CISA KEV + retard de mise a jour."""
    from version_editor_service import load_latest_versions

    conn = get_db()
    c = conn.cursor()
    # Tous les logiciels uniques avec leur risque + version
    rows = c.execute("""
        SELECT LOWER(nom) as lkey, nom, editeur, risque_niveau, risque_score,
               derniere_version, eol, approuve
        FROM logiciels
        GROUP BY LOWER(nom)
        ORDER BY risque_score DESC
    """).fetchall()
    # Compter les postes par logiciel
    postes = {}
    for r in c.execute(
        "SELECT LOWER(nom) as lkey, COUNT(DISTINCT scan_id) as nb FROM logiciels GROUP BY LOWER(nom)"
    ).fetchall():
        postes[r["lkey"]] = r["nb"]
    # Version installee (premiere trouvee) par logiciel
    versions_inst = {}
    for r in c.execute(
        "SELECT LOWER(nom) as lkey, version FROM logiciels WHERE version IS NOT NULL AND version!='' GROUP BY LOWER(nom)"
    ).fetchall():
        versions_inst[r["lkey"]] = r["version"]
    # CVE et CISA KEV par logiciel
    cve_stats = {}
    for r in c.execute("""
        SELECT LOWER(logiciel_nom) as lkey,
               COUNT(*) as cnt,
               MAX(cvss_score) as max_cvss,
               MAX(CASE WHEN source='CISA_KEV' THEN 1 ELSE 0 END) as has_cisa
        FROM cve_cache GROUP BY LOWER(logiciel_nom)
    """).fetchall():
        cve_stats[r["lkey"]] = {
            "cnt": r["cnt"],
            "max_cvss": r["max_cvss"],
            "has_cisa": r["has_cisa"],
        }
    conn.close()
    # Dates de verification depuis le cache versions
    refs = load_latest_versions()
    audit = []
    for r in rows:
        key = r["lkey"]
        cs = cve_stats.get(key, {"cnt": 0, "max_cvss": 0, "has_cisa": 0})
        installe = versions_inst.get(key, "")
        latest = r["derniere_version"] or ""
        # Date derniere verification
        ref = refs.get(key) or refs.get(r["nom"] and r["nom"].lower(), {})
        date_verif = ""
        if isinstance(ref, dict):
            date_verif = ref.get("derniere_verification", "")
        # Calcul retard mises a jour
        update_delay = ""
        obsolete = False
        if installe and latest:
            try:
                inst_parts = installe.replace(",", ".").split(".")
                lat_parts = latest.replace(",", ".").split(".")
                inst_maj = int(inst_parts[0])
                lat_maj = int(lat_parts[0])
                # Retard: combien de versions majeures de difference
                diff = lat_maj - inst_maj
                if diff >= 2:
                    update_delay = f"{diff} versions majeures"
                    obsolete = True
                elif diff == 1:
                    update_delay = "1 version majeure"
                    obsolete = True
                elif diff == 0:
                    # Meme majeure, verifier les mineures
                    if len(inst_parts) > 1 and len(lat_parts) > 1:
                        try:
                            inst_min = int(inst_parts[1])
                            lat_min = int(lat_parts[1])
                            if lat_min - inst_min >= 5:
                                update_delay = (
                                    f"{lat_min - inst_min} mineures de retard"
                                )
                            elif lat_min > inst_min:
                                update_delay = "mineure de retard"
                        except:
                            pass
                elif diff < 0:
                    # Installe plus recent que latest (version de dev/preview)
                    update_delay = "version future/preview"
            except:
                pass
        # Latest version EOL ?
        eol_val = r["eol"] if "eol" in r else ""
        latest_eol = eol_val in ("OUI", "1")
        # Recommandation
        rec = "A jour"
        if eol_val in ("OUI", "1"):
            rec = "Remplacer urgemment (EOL)"
        elif cs["has_cisa"]:
            rec = "PATCHER urgemment (CISA KEV)"
        elif cs["max_cvss"] and cs["max_cvss"] >= 9:
            rec = "Mettre a jour (CVE critique)"
        elif obsolete:
            rec = "Version obsolete"
        elif cs["max_cvss"] and cs["max_cvss"] >= 7:
            rec = "Mettre a jour (CVE eleve)"
        # Score audit global 0-100
        score_audit = 100
        if eol_val in ("OUI", "1"):
            score_audit -= 40
        if cs["has_cisa"]:
            score_audit -= 30
        cvss = cs["max_cvss"] or 0
        if cvss >= 9:
            score_audit -= 20
        elif cvss >= 7:
            score_audit -= 10
        elif cvss >= 4:
            score_audit -= 5
        if obsolete:
            score_audit -= 15
        if r["approuve"] != 1:
            score_audit -= 5
        score_audit = max(0, min(100, score_audit))
        # Categorie action
        if eol_val in ("OUI", "1"):
            cat_action = "critique"
        elif cs["has_cisa"]:
            cat_action = "urgent"
        elif cvss >= 9:
            cat_action = "urgent"
        elif obsolete and cvss >= 7:
            cat_action = "urgent"
        elif obsolete:
            cat_action = "recommande"
        elif cvss >= 7:
            cat_action = "recommande"
        elif cvss >= 4:
            cat_action = "surveiller"
        else:
            cat_action = "ok"
        audit.append(
            {
                "nom": r["nom"],
                "editeur": r["editeur"] or "",
                "version_installee": installe,
                "derniere_version": latest,
                "date_verification": date_verif,
                "update_delay": update_delay,
                "nb_postes": postes.get(key, 0),
                "risque_niveau": r["risque_niveau"] or "Faible",
                "risque_score": r["risque_score"] or 0,
                "eol": eol_val,
                "latest_version_eol": latest_eol,
                "cve_count": cs["cnt"],
                "max_cvss": cs["max_cvss"],
                "cisa_kev": bool(cs["has_cisa"]),
                "obsolete": obsolete,
                "recommandation": rec,
                "score_audit": score_audit,
                "cat_action": cat_action,
            }
        )
    return jsonify(
        {
            "total": len(audit),
            "critiques": sum(1 for a in audit if a["risque_score"] >= 8),
            "cisa_kev_count": sum(1 for a in audit if a["cisa_kev"]),
            "obsoletes": sum(1 for a in audit if a["obsolete"]),
            "eol_count": sum(1 for a in audit if a["eol"] in ("OUI", "1")),
            "logiciels": audit,
        }
    )


# ─── Enterprise API Routes ─────────────────────────────────────────


@app.route("/api/sites")
def api_sites():
    conn = get_db()
    rows = fetchall(conn, "SELECT * FROM sites ORDER BY nom")
    close(conn)
    return jsonify(rows_to_list(rows))


@app.route("/api/sites", methods=["POST"])
def api_sites_post():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    conn = get_db()
    cur = execute(
        conn,
        "INSERT INTO sites (nom, adresse, ville, code_postal, pays, responsable, notes) VALUES (?,?,?,?,?,?,?)",
        (
            data.get("nom"),
            data.get("adresse"),
            data.get("ville"),
            data.get("code_postal"),
            data.get("pays"),
            data.get("responsable"),
            data.get("notes"),
        ),
    )
    commit(conn)
    lid = cur.lastrowid if hasattr(cur, "lastrowid") else None
    close(conn)
    log_action(
        "site_ajoute",
        "administration",
        "",
        "",
        {"nom": data.get("nom"), "id": lid},
        get_client_ip(),
        "",
        "info",
    )
    return jsonify({"id": lid, "status": "ok"})


@app.route("/api/sites/<int:sid>", methods=["DELETE"])
def api_sites_delete(sid):
    conn = get_db()
    execute(conn, "DELETE FROM sites WHERE id=?", (sid,))
    commit(conn)
    close(conn)
    log_action(
        "site_supprime",
        "administration",
        "",
        "",
        {"id": sid},
        get_client_ip(),
        "",
        "warning",
    )
    return jsonify({"status": "ok"})


@app.route("/api/departments")
def api_departments():
    conn = get_db()
    rows = fetchall(
        conn,
        "SELECT d.*, s.nom as site_nom FROM departments d LEFT JOIN sites s ON d.site_id = s.id ORDER BY d.nom",
    )
    close(conn)
    return jsonify(rows_to_list(rows))


@app.route("/api/departments", methods=["POST"])
def api_departments_post():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    conn = get_db()
    cur = execute(
        conn,
        "INSERT INTO departments (nom, site_id, responsable, notes) VALUES (?,?,?,?)",
        (
            data.get("nom"),
            data.get("site_id"),
            data.get("responsable"),
            data.get("notes"),
        ),
    )
    commit(conn)
    lid = cur.lastrowid if hasattr(cur, "lastrowid") else None
    close(conn)
    log_action(
        "departement_ajoute",
        "administration",
        "",
        "",
        {"nom": data.get("nom"), "site_id": data.get("site_id"), "id": lid},
        get_client_ip(),
        "",
        "info",
    )
    return jsonify({"id": lid, "status": "ok"})


@app.route("/api/audit_log")
def api_audit_log():
    conn = get_db()
    limit = min(int(request.args.get("limit", 200)), 1000)
    offset = int(request.args.get("offset", 0))
    categorie = request.args.get("categorie", "")
    action = request.args.get("action", "")
    sql = "SELECT * FROM audit_log WHERE 1=1"
    params = []
    if categorie:
        sql += " AND categorie=?"
        params.append(categorie)
    if action:
        sql += " AND action=?"
        params.append(action)
    sql += " ORDER BY id DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])
    rows = fetchall(conn, sql, params)
    total_row = fetchone(conn, "SELECT COUNT(*) as cnt FROM audit_log")
    total = total_row["cnt"] if total_row else 0
    close(conn)
    return jsonify({"data": rows_to_list(rows), "total": total})


@app.route("/api/audit_log", methods=["POST"])
def api_audit_log_post():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    conn = get_db()
    execute(
        conn,
        "INSERT INTO audit_log (scan_id, nom_pc, action, categorie, details, ip_source, utilisateur, severite) VALUES (?,?,?,?,?,?,?,?)",
        (
            data.get("scan_id", ""),
            data.get("nom_pc", ""),
            data.get("action"),
            data.get("categorie", "systeme"),
            json.dumps(data.get("details", {})),
            data.get("ip_source", ""),
            data.get("utilisateur", ""),
            data.get("severite", "info"),
        ),
    )
    commit(conn)
    close(conn)
    return jsonify({"status": "ok"})


@app.route("/api/compliance_rules")
def api_compliance_rules():
    conn = get_db()
    rows = fetchall(conn, "SELECT * FROM compliance_rules ORDER BY regle")
    close(conn)
    return jsonify(rows_to_list(rows))


@app.route("/api/compliance_rules", methods=["POST"])
def api_compliance_rules_post():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "Corps JSON invalide"}), 400
    conn = get_db()
    try:
        execute(
            conn,
            "INSERT INTO compliance_rules (regle, famille, description, niveau, statut, points, max_points) VALUES (?,?,?,?,?,?,?) ON CONFLICT (regle) DO UPDATE SET famille=EXCLUDED.famille, description=EXCLUDED.description, niveau=EXCLUDED.niveau, statut=EXCLUDED.statut, points=EXCLUDED.points, max_points=EXCLUDED.max_points",
            (
                data.get("regle"),
                data.get("famille", "ANSSI"),
                data.get("description"),
                data.get("niveau", "Moyen"),
                data.get("statut", "Non verifie"),
                data.get("points", 0),
                data.get("max_points", 1),
            ),
        )
    except Exception:
        execute(
            conn,
            "INSERT OR REPLACE INTO compliance_rules (regle, famille, description, niveau, statut, points, max_points) VALUES (?,?,?,?,?,?,?)",
            (
                data.get("regle"),
                data.get("famille", "ANSSI"),
                data.get("description"),
                data.get("niveau", "Moyen"),
                data.get("statut", "Non verifie"),
                data.get("points", 0),
                data.get("max_points", 1),
            ),
        )
    commit(conn)
    close(conn)
    log_action(
        "regle_conformite_mise_a_jour",
        "conformite",
        "",
        "",
        {"regle": data.get("regle"), "statut": data.get("statut")},
        get_client_ip(),
        "",
        "info",
    )
    return jsonify({"status": "ok"})


@app.route("/api/compliance_rule/<int:rule_id>", methods=["DELETE"])
def api_compliance_rule_delete(rule_id):
    conn = get_db()
    execute(conn, "DELETE FROM compliance_rules WHERE id=?", (rule_id,))
    commit(conn)
    close(conn)
    log_action(
        "regle_conformite_supprimee",
        "conformite",
        "",
        "",
        {"rule_id": rule_id},
        get_client_ip(),
        "",
        "warning",
    )
    return jsonify({"status": "ok"})


@app.route("/api/conformite/rule/<int:rule_id>", methods=["DELETE"])
def api_conformite_rule_delete(rule_id):
    conn = get_db()
    c = conn.cursor()
    c.execute("DELETE FROM compliance_rules WHERE id=?", (rule_id,))
    c.execute("DELETE FROM conformite WHERE id=?", (rule_id,))
    commit(conn)
    close(conn)
    log_action(
        "regle_conformite_supprimee",
        "conformite",
        "",
        "",
        {"rule_id": rule_id},
        get_client_ip(),
        "",
        "warning",
    )
    return jsonify({"status": "ok"})


@app.route("/api/usage_stats")
def api_usage_stats():
    conn = get_db()
    logiciel = request.args.get("logiciel", "")
    sql = "SELECT * FROM usage_stats"
    params = []
    if logiciel:
        sql += " WHERE logiciel_nom=?"
        params.append(logiciel)
    sql += " ORDER BY id DESC LIMIT 500"
    rows = fetchall(conn, sql, params)
    close(conn)
    return jsonify(rows_to_list(rows))


@app.route("/api/editeurs")
def api_editeurs():
    q = request.args.get("q", "").strip().lower()
    conn = get_db()
    rows = fetchall(
        conn,
        "SELECT DISTINCT editeur FROM logiciels WHERE editeur IS NOT NULL AND editeur != '' ORDER BY editeur",
    )
    close(conn)
    result = []
    seen = set()
    for r in rows:
        name = r["editeur"].strip()
        if not name or name.lower() in seen:
            continue
        seen.add(name.lower())
        if q and q not in name.lower():
            continue
        info = _get_editeur_info(name) or {}
        result.append(
            {"nom": name, "pays": info.get("pays", ""), "site": info.get("site", "")}
        )
    return jsonify(result)


@app.route("/api/droits")
def api_droits():
    conn = get_db()
    c = conn.cursor()
    machines = c.execute("""
        SELECT nom_pc, scan_id, utilisateur, domaine, nb_utilisateurs, nb_connexions,
               ip, os_nom, actif, rapport_json
        FROM machines ORDER BY nom_pc
    """).fetchall()
    rows = []
    for m in machines:
        sid = m["scan_id"]
        sw_count = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=?", (sid,)
        ).fetchone()["cnt"]
        reg_count = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND install_source='Registry'",
            (sid,),
        ).fetchone()["cnt"]
        service_count = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND install_source='WindowsFeature'",
            (sid,),
        ).fetchone()["cnt"]
        startup_count = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND install_source IN ('StartMenu','Registry_HKCU')",
            (sid,),
        ).fetchone()["cnt"]
        appx_count = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND install_source='Appx'",
            (sid,),
        ).fetchone()["cnt"]
        portable_count = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND install_source='Portable'",
            (sid,),
        ).fetchone()["cnt"]
        droit_count = c.execute(
            "SELECT COUNT(*) as cnt FROM logiciels WHERE scan_id=? AND install_source IN ('Registry','WindowsFeature','StartMenu','Registry_HKCU')",
            (sid,),
        ).fetchone()["cnt"]
        # Top 5 software with highest privilege risk
        top_sw = c.execute(
            """
            SELECT nom, editeur, version, install_source, type_logiciel, risque_niveau
            FROM logiciels WHERE scan_id=? AND install_source IN ('Registry','WindowsFeature')
            ORDER BY risque_score DESC NULLS LAST LIMIT 5
        """,
            (sid,),
        ).fetchall()
        # Software grouped by metier for this machine
        metier_rows = c.execute(
            """
            SELECT COALESCE(NULLIF(metier,''), 'Non classe') as metier,
                   nom, editeur, version, install_source, type_logiciel, risque_niveau, chemin
            FROM logiciels WHERE scan_id=?
            ORDER BY metier, nom
        """,
            (sid,),
        ).fetchall()
        metiers = {}
        for s in metier_rows:
            met = s["metier"]
            if met not in metiers:
                metiers[met] = []
            src = s["install_source"] or ""
            niveau = _get_niveau_acces(src)
            metiers[met].append(
                {
                    "nom": s["nom"],
                    "editeur": s["editeur"] or "",
                    "version": s["version"] or "",
                    "source": s["install_source"] or "",
                    "type": s["type_logiciel"] or _systeme_ou_app(s),
                    "niveau": niveau,
                    "risque": s["risque_niveau"] or "",
                    "chemin": s["chemin"] or "",
                }
            )
        metier_summary = {m: len(v) for m, v in metiers.items()}
        # Abusive rights detection
        alertes_droits = []
        if droit_count > 20:
            alertes_droits.append("Trop de logiciels avec droits eleves (>20)")
        if reg_count > 10:
            alertes_droits.append("Trop de logiciels systeme installes (>10)")
        if startup_count > 8:
            alertes_droits.append("Trop de demarrage automatique (>8)")
        if portable_count > 15:
            alertes_droits.append("Trop de portables/executables (>15)")
        if appx_count > 30:
            alertes_droits.append("Trop d'applications Store (>30)")
        for sw_list in metiers.values():
            for s in sw_list:
                if s["niveau"] == "Windows Base" and s.get("risque") in (
                    "Critique",
                    "Eleve",
                ):
                    alertes_droits.append(
                        f"Droit abusif: {s['nom']} ({s['editeur']}) - niveau {s['niveau']} avec risque {s['risque']}"
                    )
        locaux = []
        admins = []
        try:
            if m["rapport_json"]:
                rapport = json.loads(m["rapport_json"])
                utilisateurs_data = rapport.get("utilisateurs", {})
                locaux = utilisateurs_data.get("locaux", [])
                admins = utilisateurs_data.get("admins", [])
        except (json.JSONDecodeError, TypeError):
            pass

        rows.append(
            {
                "nom_pc": m["nom_pc"],
                "ip": m["ip"] or "",
                "os": m["os_nom"] or "",
                "utilisateur": m["utilisateur"] or "",
                "domaine": m["domaine"] or "",
                "nb_utilisateurs": m["nb_utilisateurs"] or 0,
                "nb_connexions": m["nb_connexions"] or 0,
                "nb_logiciels": sw_count,
                "nb_systeme": reg_count,
                "nb_services": service_count,
                "nb_startup": startup_count,
                "nb_appx": appx_count,
                "nb_portables": portable_count,
                "nb_droits": droit_count,
                "actif": m["actif"],
                "top_privilegies": [dict(s) for s in top_sw],
                "metiers": metiers,
                "metier_summary": metier_summary,
                "alertes_droits": alertes_droits,
                "droits_abusifs": len(alertes_droits) > 0,
                "utilisateurs_locaux": locaux,
                "administrateurs_locaux": admins,
            }
        )
    close(conn)
    return jsonify(rows)


@app.route("/api/droits/logiciels")
def api_droits_logiciels():
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("""
        SELECT l.nom, l.editeur, l.version, l.install_source, l.type_logiciel, l.metier,
               l.risque_niveau, l.risque_score, l.chemin, m.nom_pc, m.scan_id
        FROM logiciels l
        LEFT JOIN machines m ON l.scan_id = m.scan_id
        ORDER BY l.nom
    """).fetchall()
    logiciels = {}
    for r in rows:
        src = r["install_source"] or ""
        niveau = _get_niveau_acces(src)
        key = (r["nom"], r["version"] or "")
        if key not in logiciels:
            logiciels[key] = {
                "nom": r["nom"],
                "editeur": r["editeur"] or "",
                "version": r["version"] or "",
                "niveau": niveau,
                "type": r["type_logiciel"] or "",
                "metier": r["metier"] or "",
                "risque_niveau": r["risque_niveau"] or "",
                "risque_score": r["risque_score"] or 0,
                "nb_machines": 0,
                "machines": [],
            }
        logiciels[key]["nb_machines"] += 1
        logiciels[key]["machines"].append(r["nom_pc"] or "?")
    close(conn)
    return jsonify(
        sorted(logiciels.values(), key=lambda x: (-x["risque_score"], x["nom"]))
    )


@app.route("/api/droits/logiciel/<nom>")
def api_droits_logiciel(nom):
    conn = get_db()
    c = conn.cursor()
    rows = c.execute(
        """
        SELECT l.id, l.nom, l.editeur, l.version, l.install_source, l.type_logiciel,
               l.metier, l.risque_niveau, l.risque_score, l.chemin, l.description,
               l.notes, l.signature, l.cert_editeur, l.hash_sha256, l.architecture,
               l.derniere_execution, l.portable, m.nom_pc, m.scan_id, m.utilisateur, m.domaine
        FROM logiciels l
        LEFT JOIN machines m ON l.scan_id = m.scan_id
        WHERE l.nom=?
        ORDER BY m.nom_pc
    """,
        (nom,),
    ).fetchall()
    machines_list = {}
    for r in rows:
        src = r["install_source"] or ""
        niveau = _get_niveau_acces(src)
        scan_id = r["scan_id"]
        if scan_id not in machines_list:
            machines_list[scan_id] = {
                "nom_pc": r["nom_pc"],
                "utilisateur": r["utilisateur"] or "",
                "domaine": r["domaine"] or "",
                "installations": [],
            }
        machines_list[scan_id]["installations"].append(
            {
                "id": r["id"],
                "version": r["version"] or "",
                "install_source": r["install_source"] or "",
                "niveau": niveau,
                "type_logiciel": r["type_logiciel"] or "",
                "chemin": r["chemin"] or "",
                "description": r["description"] or "",
                "notes": r["notes"] or "",
                "signature": r["signature"] or "",
                "cert_editeur": r["cert_editeur"] or "",
                "architecture": r["architecture"] or "",
                "derniere_execution": r["derniere_execution"] or "",
                "portable": r["portable"] or 0,
            }
        )
    close(conn)
    return jsonify(
        {
            "nom": nom,
            "machines": list(machines_list.values()),
            "nb_machines": len(machines_list),
        }
    )


# ─── Export endpoints ──────────────────────────────────────────────


@app.route("/api/export/logiciels.<fmt>")
def export_logiciels(fmt):
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("""SELECT l.nom, l.editeur, l.version, l.categorie, l.risque_niveau,
                        l.risque_score, l.eol, l.install_source,
                        (SELECT COUNT(DISTINCT m.nom_pc) FROM machines m WHERE m.scan_id=l.scan_id) as nb_postes
                        FROM logiciels l GROUP BY l.nom ORDER BY l.nom""").fetchall()
    data = [dict(r) for r in rows]
    conn.close()
    content, mime, fname = export_data_from_rows(
        data, LOGICIELS_COLUMNS, fmt, "Inventaire_Logiciels"
    )
    if content is not None and mime is not None:
        return Response(
            content,
            mimetype=mime,
            headers={"Content-Disposition": f"attachment; filename={fname}"},
        )
    return jsonify({"error": "Format non supporte"}), 400


@app.route("/api/export/machines.<fmt>")
def export_machines(fmt):
    conn = get_db()
    c = conn.cursor()
    rows = c.execute(
        "SELECT nom_pc, ip, utilisateur, os_nom, domaine, ram_gb, score_securite, score_conformite FROM machines ORDER BY nom_pc"
    ).fetchall()
    conn.close()
    data = [dict(r) for r in rows]
    content, mime, fname = export_data_from_rows(
        data, MACHINES_COLUMNS, fmt, "Machines"
    )
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@app.route("/api/export/vulnerabilites.<fmt>")
def export_vulnerabilites(fmt):
    conn = get_db()
    c = conn.cursor()
    rows = c.execute("""SELECT l.nom as logiciel_nom, l.editeur, l.version, l.risque_niveau, l.risque_score,
                        m.nom_pc FROM logiciels l JOIN machines m ON l.scan_id=m.scan_id
                        WHERE l.risque_score >= 5 ORDER BY l.risque_score DESC""").fetchall()
    conn.close()
    cols = [
        {"key": "logiciel_nom", "label": "Logiciel"},
        {"key": "editeur", "label": "Editeur"},
        {"key": "version", "label": "Version"},
        {"key": "risque_niveau", "label": "Risque"},
        {"key": "risque_score", "label": "Score"},
        {"key": "nom_pc", "label": "Machine"},
    ]
    data = [dict(r) for r in rows]
    content, mime, fname = export_data_from_rows(data, cols, fmt, "Vulnerabilites")
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@app.route("/api/export/licences.<fmt>")
def export_licences(fmt):
    conn = get_db()
    c = conn.cursor()
    rows = c.execute(
        "SELECT logiciel_nom as nom, editeur, categorie_licence, type_licence, cout_annuel, nombre_licences as nb_licences FROM licences ORDER BY logiciel_nom"
    ).fetchall()
    conn.close()
    cols = [
        {"key": "nom", "label": "Logiciel"},
        {"key": "editeur", "label": "Editeur"},
        {"key": "categorie_licence", "label": "Type licence"},
        {"key": "type_licence", "label": "Sous-type"},
        {"key": "cout_annuel", "label": "Cout annuel"},
        {"key": "nb_licences", "label": "Nb licences"},
    ]
    data = [dict(r) for r in rows]
    content, mime, fname = export_data_from_rows(data, cols, fmt, "Licences")
    return Response(
        content,
        mimetype=mime,
        headers={"Content-Disposition": f"attachment; filename={fname}"},
    )


@app.route("/api/export/rapport.<fmt>")
def export_rapport(fmt):
    conn = get_db()
    c = conn.cursor()
    stats = c.execute("SELECT COUNT(*) as cnt FROM machines").fetchone()["cnt"]
    actifs = c.execute("SELECT COUNT(*) as cnt FROM machines WHERE actif=1").fetchone()[
        "cnt"
    ]
    logiciels_total = c.execute(
        "SELECT COUNT(DISTINCT nom) as cnt FROM logiciels"
    ).fetchone()["cnt"]
    vulns = c.execute(
        "SELECT COUNT(*) as cnt FROM logiciels WHERE risque_score>=5"
    ).fetchone()["cnt"]
    critiques = c.execute(
        "SELECT COUNT(*) as cnt FROM logiciels WHERE risque_score>=8"
    ).fetchone()["cnt"]
    eol_count = c.execute(
        "SELECT COUNT(*) as cnt FROM logiciels WHERE eol IN ('OUI','1') OR eol = '1'"
    ).fetchone()["cnt"]
    sec_score = c.execute(
        "SELECT COALESCE(AVG(score_securite),0) as s FROM machines"
    ).fetchone()["s"]
    conf_score = c.execute(
        "SELECT COALESCE(AVG(score_conformite),0) as s FROM machines"
    ).fetchone()["s"]

    if fmt == "pdf":
        sections = [
            {
                "title": "Resume du parc",
                "type": "kpi",
                "data": [
                    {"label": "Total machines", "value": stats},
                    {"label": "Machines actives", "value": actifs},
                    {"label": "Logiciels distincts", "value": logiciels_total},
                    {"label": "Vulnerabilites (score >= 5)", "value": vulns},
                    {"label": "Critiques (score >= 8)", "value": critiques},
                    {"label": "Logiciels EOL", "value": eol_count},
                    {
                        "label": "Score securite moyen",
                        "value": f"{round(sec_score)}/100",
                    },
                    {
                        "label": "Score conformite moyen",
                        "value": f"{round(conf_score)}/100",
                    },
                ],
            },
            {
                "title": "Top 10 logiciels les plus vulnerables",
                "type": "table",
                "columns": [
                    {"key": "nom", "label": "Logiciel"},
                    {"key": "editeur", "label": "Editeur"},
                    {"key": "risque_score", "label": "Score"},
                    {"key": "nb_postes", "label": "Postes"},
                ],
                "data": [
                    dict(r)
                    for r in c.execute("""SELECT l.nom, l.editeur, MAX(l.risque_score) as risque_score,
                        COUNT(DISTINCT m.nom_pc) as nb_postes FROM logiciels l
                        JOIN machines m ON l.scan_id=m.scan_id
                        WHERE l.risque_score>=5 GROUP BY l.nom ORDER BY risque_score DESC LIMIT 10""").fetchall()
                ],
            },
            {
                "title": "Machines",
                "type": "table",
                "columns": MACHINES_COLUMNS,
                "data": [
                    dict(r)
                    for r in c.execute(
                        "SELECT nom_pc, ip, utilisateur, os_nom, domaine, ram_gb, score_securite, score_conformite FROM machines ORDER BY nom_pc LIMIT 50"
                    ).fetchall()
                ],
            },
        ]
        conn.close()
        pdf_bytes = export_pdf("Rapport Global - Inventaire Parc", sections)
        return Response(
            pdf_bytes,
            mimetype="application/pdf",
            headers={"Content-Disposition": "attachment; filename=Rapport_Parc.pdf"},
        )
    elif fmt == "json":
        data = {
            "resume": {
                "total_machines": stats,
                "actives": actifs,
                "logiciels_distincts": logiciels_total,
                "vulnerabilites": vulns,
                "critiques": critiques,
                "eol": eol_count,
                "score_securite_moyen": round(sec_score, 1),
                "score_conformite_moyen": round(conf_score, 1),
            },
            "generated_at": datetime.datetime.now().isoformat(),
        }
        conn.close()
        return Response(
            export_json(data),
            mimetype="application/json",
            headers={"Content-Disposition": "attachment; filename=Rapport_Parc.json"},
        )
    else:
        conn.close()
        return jsonify(
            {"error": "Format non supporte pour le rapport (utilisez .pdf ou .json)"}
        ), 400


def export_data_from_rows(data, columns, fmt, title):
    if fmt == "csv":
        return export_csv(data, columns), "text/csv; charset=utf-8", f"{title}.csv"
    elif fmt == "json":
        return export_json(data), "application/json; charset=utf-8", f"{title}.json"
    elif fmt == "xlsx":
        if not HAS_OPENPYXL:
            return (
                json.dumps({"error": "openpyxl non installe"}),
                "application/json",
                f"{title}.json",
            )
        return (
            export_xlsx(data, columns, title),
            "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
            f"{title}.xlsx",
        )
    elif fmt == "pdf":
        sections = [{"title": title, "type": "table", "columns": columns, "data": data}]
        return export_pdf(title, sections), "application/pdf", f"{title}.pdf"
    return None, None, None


@app.route("/")
def serve_dashboard():
    return send_from_directory("dashboard", "index.html")


@app.route("/<path:path>", methods=["GET", "POST"])
def serve_static(path):
    if request.method == "POST":
        return jsonify({"error": "Not found"}), 404
    return send_from_directory("dashboard", path)


@app.route("/collect")
def serve_collect():
    return send_from_directory("dashboard", "collect.html")


@app.route("/briques.html")
def serve_briques():
    return send_from_directory("dashboard", "briques.html")


# Read and embed the PS1 collector
import os as _os

_ps1_path = _os.path.join(_os.path.dirname(__file__) or ".", "agent", "agent_pc.ps1")
if _os.path.exists(_ps1_path):
    with open(_ps1_path, "r", encoding="utf-8-sig") as _f:
        COLLECT_PS1 = _f.read()
else:
    COLLECT_PS1 = ""

# ── API: Latest Version Management ──────────────────────


@app.route("/api/versions/check/<path:nom>")
def api_check_version(nom):
    """Check latest version for a specific software."""
    conn = get_db()
    try:
        latest = update_latest_version(nom, conn)
        if latest:
            c = conn.cursor()
            c.execute(
                "UPDATE logiciels SET derniere_version=? WHERE nom=?", (latest, nom)
            )
            commit(conn)
            close(conn)
            return jsonify({"nom": nom, "derniere_version": latest, "status": "ok"})
        close(conn)
        return jsonify({"nom": nom, "derniere_version": "", "status": "not_found"})
    except Exception as e:
        close(conn)
        return jsonify({"error": str(e)}), 500


@app.route("/api/versions/batch", methods=["POST"])
def api_batch_versions():
    """Batch update latest versions for all software in DB."""
    conn = get_db()
    try:
        results = batch_update_latest_versions(conn)
        commit(conn)
        close(conn)
        return jsonify({"updated": len(results), "results": results})
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
        close(conn)
        return jsonify({"error": str(e)}), 500


@app.route("/api/versions/status")
def api_versions_status():
    """Show current latest versions cache status."""
    from version_editor_service import load_latest_versions

    refs = load_latest_versions()
    conn = get_db()
    c = conn.cursor()
    total_sw = c.execute("SELECT COUNT(DISTINCT nom) as cnt FROM logiciels").fetchone()[
        "cnt"
    ]
    with_version = c.execute(
        "SELECT COUNT(DISTINCT nom) as cnt FROM logiciels WHERE derniere_version != '' AND derniere_version IS NOT NULL"
    ).fetchone()["cnt"]
    close(conn)
    cached = len(
        [k for k, v in refs.items() if isinstance(v, dict) and v.get("version")]
    )
    return jsonify(
        {
            "cached_in_file": cached,
            "total_software": total_sw,
            "with_derniere_version": with_version,
            "without_version": total_sw - with_version,
            "last_updated": max(
                (
                    v.get("derniere_verification", "")
                    for v in refs.values()
                    if isinstance(v, dict)
                ),
                default="jamais",
            ),
        }
    )


# ── API: Editor Lookup ─────────────────────────────────


@app.route("/api/editor/lookup/<path:nom>")
def api_editor_lookup(nom):
    """Look up country for an editor."""
    country = lookup_editor_country(nom)
    if country:
        return jsonify({"editor": nom, "pays": country, "status": "found"})
    return jsonify({"editor": nom, "pays": "", "status": "not_found"})


@app.route("/api/editor/batch", methods=["POST"])
def api_editor_batch():
    """Batch lookup editors for unknown software from DB."""
    conn = get_db()
    c = conn.cursor()
    try:
        rows = c.execute("""SELECT DISTINCT l.editeur FROM logiciels l
                            WHERE l.editeur IS NOT NULL AND l.editeur != ''
                            AND (l.pays_editeur IS NULL OR l.pays_editeur = '')""").fetchall()
        results = {}
        for r in rows:
            edt = r["editeur"]
            if not edt:
                continue
            country = lookup_editor_country(edt)
            if country:
                results[edt] = country
                c.execute(
                    "UPDATE logiciels SET pays_editeur=? WHERE editeur=?",
                    (country, edt),
                )
        commit(conn)
        close(conn)
        return jsonify({"found": len(results), "results": results})
    except Exception as e:
        try:
            conn.rollback()
        except:
            pass
        close(conn)
        return jsonify({"error": str(e)}), 500


def _auto_enrich_background():
    """Lance un enrichissement CVE automatique en tache de fond, puis maj versions et editeurs."""
    try:
        conn = get_db()
        c = conn.cursor()
        uncached = c.execute("""SELECT COUNT(DISTINCT l.nom) as cnt FROM logiciels l
                                WHERE l.nom NOT IN (SELECT DISTINCT logiciel_nom FROM cve_cache)""").fetchone()[
            "cnt"
        ]
        if uncached:
            print(
                f"  [CVE] {uncached} logiciel(s) sans CVE - enrichissement automatique..."
            )
            results = batch_enrich(conn, limit=50)
            commit(conn)
            print(f"  [CVE] Enrichi: {len(results)} logiciel(s) avec CVE")
            for r in results:
                nom = r.get("software", "")
                if nom:
                    nouveau_niv, nouveau_sc = recalculer_risque_par_cve(
                        conn, nom, None, None
                    )
                    if nouveau_niv:
                        c.execute(
                            "UPDATE logiciels SET risque_niveau=?, risque_score=? WHERE nom=?",
                            (nouveau_niv, nouveau_sc, nom),
                        )
            commit(conn)

        # Mise a jour automatique des dernieres versions (sans limite)
        try:
            no_version = c.execute(
                "SELECT COUNT(DISTINCT nom) as cnt FROM logiciels WHERE derniere_version IS NULL OR derniere_version = ''"
            ).fetchone()["cnt"]
            if no_version > 0:
                print(
                    f"  [VERSION] {no_version} logiciel(s) sans derniere version connue - mise a jour..."
                )
                ver_results = batch_update_latest_versions(conn)
                if ver_results:
                    commit(conn)
                    print(f"  [VERSION] {len(ver_results)} version(s) trouvees")
        except Exception as ve:
            print(f"  [VERSION] Erreur: {ve}")

        # Mise a jour automatique des pays editeurs (sans limite)
        try:
            no_pays = c.execute(
                "SELECT COUNT(DISTINCT editeur) as cnt FROM logiciels WHERE editeur IS NOT NULL AND editeur != '' AND (pays_editeur IS NULL OR pays_editeur = '')"
            ).fetchone()["cnt"]
            if no_pays > 0:
                print(f"  [EDITOR] {no_pays} editeur(s) sans pays - mise a jour...")
                rows = c.execute("""SELECT DISTINCT editeur FROM logiciels
                                    WHERE editeur IS NOT NULL AND editeur != ''
                                    AND (pays_editeur IS NULL OR pays_editeur = '')""").fetchall()
                for r in rows:
                    edt = r["editeur"]
                    country = lookup_editor_country(edt)
                    if country:
                        c.execute(
                            "UPDATE logiciels SET pays_editeur=? WHERE editeur=?",
                            (country, edt),
                        )
                commit(conn)
        except Exception as ee:
            print(f"  [EDITOR] Erreur: {ee}")

        close(conn)
    except Exception as e:
        print(f"  [CVE] Erreur enrichissement auto: {e}")


if __name__ == "__main__":
    init_db()
    import threading

    t = threading.Thread(target=_auto_enrich_background, daemon=True)
    t.start()
    port = int(os.environ.get("PORT", 8091))
    api_key = os.environ.get("NVD_API_KEY", "")
    print(f"[INVENTAIRE v5.0] Serveur demarre sur http://0.0.0.0:{port}")
    if api_key:
        print(f"  [CVE] Cle NVD API fournie - taux ~50 req/30s")
    else:
        print(f"  [CVE] Pas de cle NVD API - taux limite ~5 req/30s (lent)")
        print(f"  [CVE] Pour accelerer: set NVD_API_KEY=<votre_cle>")
    app.run(host="0.0.0.0", port=port, debug=False)
