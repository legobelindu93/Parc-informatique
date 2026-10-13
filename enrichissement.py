import json, os, requests

DB_PATH = os.path.join(os.path.dirname(__file__), 'data', 'software_db.json')

def charger_base_locale():
    if not os.path.exists(DB_PATH):
        return {}
    try:
        with open(DB_PATH, 'r', encoding='utf-8') as f:
            return json.load(f)
    except:
        return {}

def enrichir_depuis_base(nom_fichier):
    base = charger_base_locale()
    if not base:
        return None
    return base.get(nom_fichier.lower())

CATEGORIES = {
    "jeu": ["gta", "minecraft", "fortnite", "steam", "epic", "uplay", "origin",
            "battlefield", "call of duty", "valorant", "league of legends",
            "counter-strike", "cyberpunk", "elden ring", "game", "rockstar",
            "grand theft auto", "ubisoft", "ea games", "blizzard", "battlenet",
            "nintendo", "sega", "sony", "xbox", "rpg", "fps", "mmo"],
    "navigateur": ["chrome", "firefox", "edge", "opera", "brave", "vivaldi", "safari", "chromium"],
    "antivirus": ["avast", "avg", "kaspersky", "norton", "bitdefender", "eset",
                  "malwarebytes", "defender", "mcafee", "trend micro", "avira", "panda"],
    "bureautique": ["word", "excel", "powerpoint", "outlook", "office", "libreoffice",
                    "openoffice", "writer", "calc", "wps office", "onlyoffice"],
    "developpement": ["vscode", "visual studio", "git", "node", "python", "java",
                      "eclipse", "intellij", "pycharm", "sublime", "jetbrains",
                      "docker", "kubernetes", "postman", "insomnia"],
    "communication": ["teams", "slack", "zoom", "discord", "skype", "webex",
                      "signal", "telegram", "whatsapp", "mattermost", "rocket"],
    "utilitaire": ["7zip", "winrar", "notepad", "vlc", "acrobat", "pdf",
                   "everything", "putty", "winscp", "filezilla", "winmerge",
                   "powertoys", "greenshot", "sharex", "obsidian"],
    "securite_offensive": ["nmap", "wireshark", "metasploit", "burp", "sqlmap",
                            "aircrack", "hashcat", "mimikatz", "netcat", "nikto",
                            "hydra", "john the ripper"],
    "vpn_non_corp": ["nordvpn", "protonvpn", "expressvpn", "mullvad", "cyberghost",
                      "surfshark", "private internet access", "vyprvpn"],
    "multimedia": ["spotify", "vlc", "mpc", "foobar", "itunes", "photoshop",
                   "gimp", "krita", "blender", "audacity", "obs", "avidemux",
                   "handbrake", "ffmpeg"],
    "driver": ["nvidia", "amd", "intel", "driver", "catalyst", "geforce"],
    "outil_systeme": ["cpu-z", "gpu-z", "hwinfo", "crystaldiskinfo", "speccy",
                      "msi afterburner", "hwmonitor", "process explorer",
                      "autoruns", "tcpview"]
}

def detecter_categorie_par_mots_cles(nom_fichier, editeur="", description=""):
    texte = f"{nom_fichier} {editeur} {description}".lower()
    for cat, mots in CATEGORIES.items():
        if any(m in texte for m in mots):
            return cat
    return None

def enrichir_nvd_par_cpe(nom_produit, editeur):
    if not nom_produit:
        return []
    cpe_query = f"{nom_produit} {editeur}".strip()
    if not cpe_query:
        return []
    url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={requests.utils.quote(cpe_query)}&resultsPerPage=5"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            items = r.json().get("vulnerabilities", [])
            return [{"cve_id": i["cve"]["id"],
                     "cvss": i["cve"].get("metrics", {}).get("cvssMetricV31", [{}])[0].get("cvssData", {}).get("baseScore", 0),
                     "description": i["cve"]["descriptions"][0]["value"][:200]
                    } for i in items]
    except:
        return []
    return []

def enrichir_executable_portable(nom_fichier, collecte={}):
    result = {}
    base = enrichir_depuis_base(nom_fichier)
    if base:
        result['base_locale'] = base
        result['nom_produit'] = base.get('nom_produit') or collecte.get('produit')
        result['editeur'] = base.get('editeur') or collecte.get('editeur')
        result['categorie'] = base.get('categorie')
        result['type_licence'] = base.get('type_licence')
        result['site_officiel'] = base.get('site_officiel')
        result['pays'] = base.get('pays')
        result['plateforme'] = base.get('plateforme')
        result['anssi_statut'] = base.get('anssi_statut')
        result['eol'] = base.get('eol')
        result['cpe'] = base.get('cpe')
    else:
        if not result.get('categorie'):
            cat = detecter_categorie_par_mots_cles(
                nom_fichier,
                collecte.get('editeur', ''),
                collecte.get('description', '')
            )
            if cat:
                result['categorie'] = cat
        if not result.get('editeur') and collecte.get('editeur'):
            result['editeur'] = collecte.get('editeur')
        if not result.get('nom_produit') and collecte.get('produit'):
            result['nom_produit'] = collecte.get('produit')
    return result if result else None
