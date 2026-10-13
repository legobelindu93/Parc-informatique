"""
CVE Service — Multi-source enrichment (NVD + CISA KEV + MSRC)
"""
import json, time, re, os, datetime, random
from urllib.request import Request, urlopen
from urllib.parse import quote
from urllib.error import HTTPError, URLError
from database import execute, commit, fetchall

CISA_KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'
CISA_KEV_CACHE = 'cisa_kev_cache.json'
MSRC_API = 'https://api.msrc.microsoft.com/sug/v2.0/fr-FR/vulnerability'
NVD_API = 'https://services.nvd.nist.gov/rest/json/cves/2.0'

# Rate limiting: NVD allows 5 req / 30s without API key, 50 / 30s with key
NVD_API_KEY = os.environ.get('NVD_API_KEY', '')
if NVD_API_KEY:
    NVD_MIN_INTERVAL = 0.6  # ~1.67 req/s
    NVD_RETRY_MAX = 5
else:
    NVD_MIN_INTERVAL = 6.0  # 1 req / 6s
    NVD_RETRY_MAX = 3

_nvd_last_call = 0.0

_GUID_RE = re.compile(
    r'^\{?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}\}?$'
)
_HEX_ID_RE = re.compile(r'^[0-9a-fA-F]{32,}$')
_EXTENSION_RE = re.compile(r'^\.[a-zA-Z0-9]{1,10}$')
_CHROME_EXT_RE = re.compile(r'^[a-z]{32}$')
_NUMBERS_ONLY_RE = re.compile(r'^\d+$')
_SHORT_NAME_RE = re.compile(r'^.{1,2}$')
_PACKAGE_ID_RE = re.compile(r'^[a-f0-9]{8,}\.[A-Za-z]', re.I)
_EXE_ONLY_RE = re.compile(r'^[a-zA-Z0-9_-]+\.exe$', re.I)
_TEMP_FILE_RE = re.compile(r'^[a-f0-9]{8,}$', re.I)
_INSTALLER_EXT_RE = re.compile(r'\.(msi|msp|cab)$', re.I)
_FILENAME_EXT_RE = re.compile(r'\.(exe|dll|lnk|sys|com|bat|ps1|vbs|cmd|appx|appxbundle|jar)$', re.I)
_KB_UPDATE_RE = re.compile(r'^(kb\d+|security update|update for|hotfix|rollup|patch)', re.I)
_GARBAGE_WORDS = {'', 'exe', 'dll', 'sys', 'dllhost', 'svchost', 'runtimebroker',
                  'conhost', 'csrss', 'lsass', 'services', 'smss', 'spoolsv',
                  'taskhostw', 'wininit', 'winlogon', 'system', 'registry',
                  'unknown', 'n/a', 'application', 'app', 'service', 'setup',
                  'installer', 'update', 'hotfix', 'patch', 'rollup', 'driver',
                  'plugin', 'add-in', 'addin', 'extension', 'theme', 'language pack'}


def _is_valid_software_name(name):
    if not name or not isinstance(name, str):
        return False
    name = name.strip()
    if not name:
        return False
    if _SHORT_NAME_RE.match(name):
        return False
    if _EXTENSION_RE.match(name):
        return False
    if _GUID_RE.match(name):
        return False
    if _HEX_ID_RE.match(name):
        return False
    if _NUMBERS_ONLY_RE.match(name):
        return False
    if _CHROME_EXT_RE.match(name) and len(name) == 32:
        return False
    if _PACKAGE_ID_RE.match(name):
        return False
    if _TEMP_FILE_RE.match(name) and len(name) >= 8:
        return False
    if name.lower() in _GARBAGE_WORDS:
        return False
    # Fichiers d'installation (.msi, .msp, .cab...) — jamais des produits CPE
    if _INSTALLER_EXT_RE.search(name):
        return False
    # Fichiers executables / bibliotheques — noms de fichiers, pas des produits
    if _FILENAME_EXT_RE.search(name):
        return False
    # KB / correctifs / mises à jour
    if _KB_UPDATE_RE.match(name):
        return False
    # Noms trop longs (probablement des chemins / hashes)
    if len(name) > 120:
        return False
    # Au moins une lettre
    if not re.search(r'[a-zA-Z]', name):
        return False
    return True


def _is_microsoft_name(name):
    name = name.lower()
    microsoft_keywords = [
        'microsoft', 'windows', 'office', 'visual studio', 'sql server',
        'powershell', 'edge', 'iexplore', 'internet explorer', 'outlook',
        'excel', 'word', 'powerpoint', 'onedrive', 'teams', 'skype',
        'directx', 'msxml', 'vc_redist', 'dotnet', '.net', 'vsto',
        'azure', 'hyper-v', 'bitlocker', 'defender', 'security essentials',
        'silverlight', 'paint', 'notepad', 'calculator', 'snipping tool',
        'media player', 'photos', 'maps', 'cortana', 'onenote', 'publisher',
        'access', 'visio', 'project', 'sharepoint', 'exchange', 'system center',
        'intune', 'configmgr', 'sccm', 'bginfo', 'sysinternals', 'procdump',
        'process explorer', 'tcpview', 'autoruns', 'windbg', 'msedge',
        'edgeupdate', 'edgewebview', 'windows update', 'update for',
        'security update', 'cumulative update', 'kb', 'hotfix',
        'adobe acrobat', 'adobe reader',
    ]
    return any(kw in name for kw in microsoft_keywords)


def _rate_limited_nvd(software_name):
    global _nvd_last_call
    elapsed = time.time() - _nvd_last_call
    if elapsed < NVD_MIN_INTERVAL:
        time.sleep(NVD_MIN_INTERVAL - elapsed)

    q = quote(software_name)
    url = f'{NVD_API}?keywordSearch={q}&resultsPerPage=20'
    if NVD_API_KEY:
        url += f'&apiKey={NVD_API_KEY}'

    for attempt in range(NVD_RETRY_MAX):
        try:
            _nvd_last_call = time.time()
            req = Request(url, headers={'User-Agent': 'CyberParc/5.1 (CVE enrichment)'})
            with urlopen(req, timeout=30) as r:
                data = json.loads(r.read())
            return data
        except HTTPError as e:
            if e.code == 429:
                wait = min(30, 2 ** attempt * 5) + random.uniform(1, 3)
                print(f'[CVE] NVD 429 rate limit pour "{software_name}" - attente {wait:.0f}s (essai {attempt + 1}/{NVD_RETRY_MAX})')
                time.sleep(wait)
                continue
            elif e.code == 403:
                print(f'[CVE] NVD 403 interdit pour "{software_name}"')
                return None
            else:
                # 404 et autres silencieux — la plupart des noms ne sont pas des produits CPE
                return None
        except Exception as ex:
            if attempt < NVD_RETRY_MAX - 1:
                time.sleep(2 ** attempt * 3)
                continue
            print(f'[CVE] NVD fetch error pour "{software_name}": {ex}')
            return None

    print(f'[CVE] NVD abandonne "{software_name}" apres {NVD_RETRY_MAX} tentatives (rate limit)')
    return None


def _rate_limited_msrc(software_name):
    q = quote(software_name)
    url = f'{MSRC_API}?$filter=contains(title,\'{q.replace(chr(39), chr(39)+chr(39))}\')&$top=10'
    try:
        req = Request(url, headers={'User-Agent': 'CyberParc/5.1 (CVE enrichment)'})
        with urlopen(req, timeout=15) as r:
            return json.loads(r.read())
    except HTTPError as e:
        if e.code == 429:
            time.sleep(10)
            return None
        if e.code == 400:
            return None
        print(f'[CVE] MSRC HTTP {e.code} pour "{software_name}"')
        return None
    except Exception as ex:
        if '400' not in str(ex):
            print(f'[CVE] MSRC fetch error pour "{software_name}": {ex}')
        return None


# ─── helpers ───────────────────────────────────────────────────────

def _json_get(url, timeout=20):
    req = Request(url, headers={'User-Agent': 'CyberParc/5.1 (CVE enrichment)'})
    with urlopen(req, timeout=timeout) as r:
        return json.loads(r.read())


def _safe_float(v, default=0):
    try:
        return float(v)
    except:
        return default


def _clean_cve_id(raw):
    m = re.search(r'(CVE-\d{4}-\d{4,})', raw, re.I)
    return m.group(1).upper() if m else ''


# ─── CISA KEV ──────────────────────────────────────────────────────

def load_cisa_kev(force_refresh=False):
    if not force_refresh and os.path.exists(CISA_KEV_CACHE):
        age = time.time() - os.path.getmtime(CISA_KEV_CACHE)
        if age < 86400 * 7:
            with open(CISA_KEV_CACHE, 'r', encoding='utf-8') as f:
                return json.load(f)
    try:
        data = _json_get(CISA_KEV_URL)
        vulns = data.get('vulnerabilities', [])
        with open(CISA_KEV_CACHE, 'w', encoding='utf-8') as f:
            json.dump(vulns, f)
        return vulns
    except Exception as e:
        print(f'[CVE] CISA KEV fetch error: {e}')
        if os.path.exists(CISA_KEV_CACHE):
            with open(CISA_KEV_CACHE, 'r', encoding='utf-8') as f:
                return json.load(f)
        return []


def match_cisa_kev(software_name, cisa_kev_list):
    sn = re.sub(r'\.exe$', '', software_name, flags=re.I).strip().lower()
    matches = []
    for vuln in cisa_kev_list:
        name = (vuln.get('vulnerabilityName') or '').lower()
        desc = (vuln.get('shortDescription') or '').lower()
        cve = _clean_cve_id(vuln.get('cveID', ''))
        if not cve:
            continue
        if sn in name or sn in desc:
            matches.append({
                'cve_id': cve,
                'source': 'CISA_KEV',
                'score': 10.0,
                'severity': 'Critical',
                'description': vuln.get('shortDescription', ''),
                'exploit_public': 1,
                'date_publiee': vuln.get('dateAdded', ''),
                'remediation': vuln.get('requiredAction', ''),
            })
    return matches


# ─── NVD ───────────────────────────────────────────────────────────

def _is_relevant_cve(software_name, editor, desc_text):
    """Filtre de pertinence : le nom du logiciel ou l'editeur doit
    apparaître dans la description textuelle du CVE (reduction du bruit)."""
    if not desc_text:
        return True  # conserver si pas de description
    desc_lower = desc_text.lower()
    name_lower = software_name.lower()
    if name_lower in desc_lower:
        return True
    if editor and editor.lower() in desc_lower:
        return True
    words = [w for w in name_lower.split() if len(w) >= 4]
    if words and any(w in desc_lower for w in words):
        return True
    return False

def fetch_nvd(software_name, editor=''):
    if not _is_valid_software_name(software_name):
        return []
    # NVD keywordSearch: nom + editeur pour une meilleure precision
    lookup_name = software_name.strip()
    if editor and editor not in lookup_name:
        lookup_name = f'{lookup_name} {editor}'

    data = _rate_limited_nvd(lookup_name)
    if not data:
        return []

    results = []
    for vuln in data.get('vulnerabilities', []):
        cve = vuln.get('cve', {})
        cve_id = cve.get('id', '')
        desc = ''
        for d in cve.get('descriptions', []):
            if d.get('lang') == 'en':
                desc = d['value']
                break
        if not _is_relevant_cve(software_name, editor, desc):
            continue
        metrics = cve.get('metrics', {})
        score = 0
        severity = 'Unknown'
        for key in ('cvssMetricV31', 'cvssMetricV30', 'cvssMetricV2'):
            if key in metrics:
                score = _safe_float(metrics[key][0]['cvssData']['baseScore'])
                severity = metrics[key][0]['cvssData'].get('baseSeverity', 'Unknown')
                break
        cwe = ''
        for weakness in cve.get('weaknesses', []):
            for w in weakness.get('description', []):
                if w.get('lang') == 'en':
                    cwe = w.get('value', '')
                    break
            if cwe:
                break
        results.append({
            'cve_id': cve_id,
            'source': 'NVD',
            'score': score,
            'severity': severity,
            'description': desc,
            'cwe': cwe,
            'exploit_public': 0,
            'date_publiee': cve.get('published', ''),
            'date_actualisee': cve.get('lastModified', ''),
        })
    return results


# ─── MSRC ──────────────────────────────────────────────────────────

def fetch_msrc(software_name):
    if not _is_valid_software_name(software_name):
        return []
    if not _is_microsoft_name(software_name):
        return []
    lookup_name = re.sub(r'\.exe$', '', software_name, flags=re.I).strip()
    data = _rate_limited_msrc(lookup_name)
    if not data:
        return []

    results = []
    for vuln in data.get('value', []):
        cve_id = _clean_cve_id(vuln.get('cveNumber', ''))
        if not cve_id:
            continue
        results.append({
            'cve_id': cve_id,
            'source': 'MSRC',
            'score': _safe_float(vuln.get('severityScore', 0)),
            'severity': vuln.get('severity', 'Unknown'),
            'description': (vuln.get('description', '') or '')[:500],
            'cwe': '',
            'exploit_public': 1 if vuln.get('exploitStatus') == 'Exploited' else 0,
            'date_publiee': vuln.get('publishedDate', ''),
            'remediation': vuln.get('mitigationSummary', ''),
        })
    return results


# ─── Orchestrator ──────────────────────────────────────────────────

def enrich_software(conn, software_name, editor='', file_hash=''):
    if not _is_valid_software_name(software_name):
        return []

    cisa_kev_list = load_cisa_kev()
    cves = []

    cves.extend(match_cisa_kev(software_name, cisa_kev_list))

    time.sleep(0.1)
    msrc_cves = fetch_msrc(software_name)
    cves.extend(msrc_cves)

    time.sleep(0.1)
    nvd_cves = fetch_nvd(software_name, editor)
    cves.extend(nvd_cves)

    seen = set()
    unique = []
    for cve in cves:
        if cve['cve_id'] and cve['cve_id'] not in seen:
            seen.add(cve['cve_id'])
            unique.append(cve)

    for cve in unique:
        try:
            execute(conn, '''
                INSERT OR IGNORE INTO cve_cache
                    (logiciel_nom, logiciel_editeur, cve_id, cvss_score, cvss_severity, cwe,
                     description, exploit_public, exploit_exists, remediation,
                     date_publiee, date_actualisee, source, hash_sha256)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
            ''', (
                software_name, editor,
                cve['cve_id'], cve['score'], cve.get('severity', ''),
                cve.get('cwe', ''), cve.get('description', ''),
                cve.get('exploit_public', 0), cve.get('exploit_public', 0),
                cve.get('remediation', ''),
                cve.get('date_publiee', ''), cve.get('date_actualisee', ''),
                cve.get('source', 'NVD'), file_hash
            ))
        except Exception:
            pass

    # Si aucune CVE trouvée, insérer un marqueur "no_cve" pour éviter de re-scanner
    if not unique:
        try:
            execute(conn, '''
                INSERT OR IGNORE INTO cve_cache
                    (logiciel_nom, logiciel_editeur, cve_id, source, description, hash_sha256)
                VALUES (?,?,?,?,?,?)
            ''', (software_name, editor, 'NO_CVE', 'SKIP', 'Aucune CVE trouvee', file_hash))
        except Exception:
            pass

    commit(conn)
    return unique


RELIABLE_SOURCES = ('Registry', 'Registry_HKCU', 'Appx', 'AppxProvisioned',
                    'Winget', 'Chocolatey', 'WindowsUpdate', 'WindowsFeature')


def batch_enrich(conn, limit=50):
    software = fetchall(conn, '''
        SELECT l.nom, l.editeur, l.version, l.install_source,
               (SELECT hash_sha256 FROM logiciels WHERE nom=l.nom AND hash_sha256!='' LIMIT 1) as hash_sha256,
               COUNT(*) as cnt
        FROM logiciels l
        WHERE l.nom NOT IN (SELECT DISTINCT logiciel_nom FROM cve_cache)
        GROUP BY l.nom, l.editeur, l.version, l.install_source
        ORDER BY cnt DESC
        LIMIT ?
    ''', (limit,))
    results = []
    total = len(software)
    valides = 0
    for i, row in enumerate(software):
        name = row['nom'] if isinstance(row, dict) else row[0]
        editor = (row.get('editeur') or '') if isinstance(row, dict) else (row[1] if len(row) > 1 else '')
        version = (row.get('version') or '') if isinstance(row, dict) else (row[2] if len(row) > 2 else '')
        source = (row.get('install_source') or '') if isinstance(row, dict) else (row[3] if len(row) > 3 else '')
        file_hash = (row.get('hash_sha256') or '') if isinstance(row, dict) else (row[4] if len(row) > 4 else '')
        if not name or not _is_valid_software_name(name):
            try:
                execute(conn, '''
                    INSERT OR IGNORE INTO cve_cache
                        (logiciel_nom, logiciel_editeur, cve_id, source, description, hash_sha256)
                    VALUES (?,?,?,?,?,?)
                ''', (name, '', 'NO_CVE', 'SKIP', 'Nom invalide', ''))
            except Exception:
                pass
            continue
        # Sources non-fiables (Portable, PATH, StartMenu…) -> jamais des produits CPE
        if source not in RELIABLE_SOURCES:
            try:
                execute(conn, '''
                    INSERT OR IGNORE INTO cve_cache
                        (logiciel_nom, logiciel_editeur, cve_id, source, description, hash_sha256)
                    VALUES (?,?,?,?,?,?)
                ''', (name, editor, 'NO_CVE', 'SKIP', 'Source non fiable', file_hash))
            except Exception:
                pass
            continue
        valides += 1
        cves = enrich_software(conn, name, editor, file_hash)
        if cves:
            results.append({'software': name, 'cves_found': len(cves)})
        time.sleep(1.5)
        if (i + 1) % 10 == 0:
            commit(conn)
            trouve = sum(r["cves_found"] for r in results)
            if trouve:
                print(f'[CVE] Enrichissement: {i + 1}/{total} (valides: {valides}, CVE trouvees: {trouve})')
    commit(conn)
    if results:
        print(f'[CVE] Batch termine: {len(results)} logiciels avec CVE sur {total} candidats (ignores: {total - valides})')
    else:
        print(f'[CVE] Batch termine: aucun logiciel avec CVE trouve sur {total} candidats')
    return results
