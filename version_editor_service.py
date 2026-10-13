import json, os, re, subprocess
from datetime import datetime

__dir__ = os.path.dirname(__file__)
LATEST_VERSIONS_PATH = os.path.join(__dir__, 'data', 'latest_versions.json')
EDITORS_PATH = os.path.join(__dir__, 'editeurs.json')

def _load_json(path):
    try:
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                return json.load(f)
    except Exception:
        pass
    return {}

def _save_json(path, data):
    try:
        with open(path, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        print(f"  [SAVE ERROR] {path}: {e}")

def load_latest_versions():
    return _load_json(LATEST_VERSIONS_PATH)

def save_latest_versions(data):
    _save_json(LATEST_VERSIONS_PATH, data)

def load_editors():
    return _load_json(EDITORS_PATH)

def save_editors(data):
    _save_json(EDITORS_PATH, data)

# ── Latest version lookup ──────────────────────────────

# Known software with hardcoded version check URLs/methods
_VERSION_SOURCES = {
    'vscode': {'type': 'github_releases', 'repo': 'microsoft/vscode'},
    'visual studio code': {'type': 'github_releases', 'repo': 'microsoft/vscode'},
    'chrome': {'type': 'chrome'},
    'google chrome': {'type': 'chrome'},
    'firefox': {'type': 'mozilla_product', 'product': 'firefox'},
    'mozilla firefox': {'type': 'mozilla_product', 'product': 'firefox'},
    '7-zip': {'type': 'sourceforge', 'project': 'sevenzip'},
    'notepad++': {'type': 'github_releases', 'repo': 'notepad-plus-plus/notepad-plus-plus'},
    'python': {'type': 'python'},
    'python 3': {'type': 'python'},
    'git': {'type': 'git'},
    'git for windows': {'type': 'git'},
    'node.js': {'type': 'nodejs'},
    'vlc': {'type': 'videolan'},
    'vlc media player': {'type': 'videolan'},
    'nginx': {'type': 'nginx'},
    'nginx stable': {'type': 'nginx'},
    'docker': {'type': 'docker'},
    'docker desktop': {'type': 'docker'},
    'kubernetes': {'type': 'kubernetes'},
    'postgresql': {'type': 'postgresql'},
    'mysql': {'type': 'oracle_mysql'},
    'mariadb': {'type': 'mariadb'},
    'mongodb': {'type': 'mongodb'},
    'redis': {'type': 'redis'},
    'elasticsearch': {'type': 'elastic'},
    'dotnet': {'type': 'dotnet'},
    'dotnet sdk': {'type': 'dotnet'},
    '.net sdk': {'type': 'dotnet'},
    '.net runtime': {'type': 'dotnet'},
    'powershell': {'type': 'powershell'},
    'powershell core': {'type': 'powershell'},
    'pwsh': {'type': 'powershell'},
    'yarn': {'type': 'npm_package', 'package': 'yarn'},
    'pnpm': {'type': 'npm_package', 'package': 'pnpm'},
    'npm': {'type': 'npm_package', 'package': 'npm'},
    'pip': {'type': 'pypi', 'package': 'pip'},
    'openssl': {'type': 'openssl'},
    'curl': {'type': 'curl'},
    'wget': {'type': 'gnu', 'package': 'wget'},
    'putty': {'type': 'putty'},
    'winscp': {'type': 'github_releases', 'repo': 'winscp/winscp'},
    'filezilla': {'type': 'filezilla'},
    'thunderbird': {'type': 'mozilla_product', 'product': 'thunderbird'},
    'libreoffice': {'type': 'libreoffice'},
    'openoffice': {'type': 'apache', 'project': 'openoffice'},
    'gimp': {'type': 'gimp'},
    'inkscape': {'type': 'inkscape'},
    'blender': {'type': 'blender'},
    'audacity': {'type': 'audacity'},
    'obs studio': {'type': 'github_releases', 'repo': 'obsproject/obs-studio'},
    'handbrake': {'type': 'handbrake'},
    'teamviewer': {'type': 'teamviewer'},
    'anydesk': {'type': 'anydesk'},
    'zoom': {'type': 'zoom'},
    'spotify': {'type': 'spotify'},
    'slack': {'type': 'slack'},
    'discord': {'type': 'discord'},
    'telegram': {'type': 'telegram'},
    'signal': {'type': 'signal'},
    'keepass': {'type': 'keepass'},
    'bitwarden': {'type': 'github_releases', 'repo': 'bitwarden/desktop'},
    'powertoys': {'type': 'github_releases', 'repo': 'microsoft/PowerToys'},
    'microsoft powertoys': {'type': 'github_releases', 'repo': 'microsoft/PowerToys'},
    'everything': {'type': 'voidtools'},
    'greenshot': {'type': 'github_releases', 'repo': 'greenshot/greenshot'},
    'sharex': {'type': 'github_releases', 'repo': 'ShareX/ShareX'},
    'sumatra pdf': {'type': 'sumatra'},
    'sumatrapdf': {'type': 'sumatra'},
    'foxit reader': {'type': 'foxit'},
    'steam': {'type': 'steam'},
    'epic games': {'type': 'epic'},
    'java': {'type': 'java'},
    'jre': {'type': 'java'},
    'jdk': {'type': 'java'},
    'openjdk': {'type': 'java'},
    'golang': {'type': 'golang'},
    'rust': {'type': 'rust'},
    'rustc': {'type': 'rust'},
    'ruby': {'type': 'ruby'},
    'php': {'type': 'php'},
    'composer': {'type': 'composer'},
    'gradle': {'type': 'gradle'},
    'maven': {'type': 'apache', 'project': 'maven'},
    'tomcat': {'type': 'apache', 'project': 'tomcat'},
    'jenkins': {'type': 'jenkins'},
    'sonarqube': {'type': 'sonarqube'},
    'grafana': {'type': 'grafana'},
    'prometheus': {'type': 'prometheus'},
    'vagrant': {'type': 'vagrant'},
    'terraform': {'type': 'hashicorp', 'product': 'terraform'},
    'packer': {'type': 'hashicorp', 'product': 'packer'},
    'vault': {'type': 'hashicorp', 'product': 'vault'},
    'consul': {'type': 'hashicorp', 'product': 'consul'},
    'nomad': {'type': 'hashicorp', 'product': 'nomad'},
    'ansible': {'type': 'pypi', 'package': 'ansible'},
    'vagrant': {'type': 'vagrant'},
    'virtualbox': {'type': 'virtualbox'},
    'vmware workstation': {'type': 'vmware'},
    'vmware workstation pro': {'type': 'vmware'},
    'wireshark': {'type': 'wireshark'},
    'nmap': {'type': 'nmap'},
    'burp suite': {'type': 'portswigger'},
}

def _fetch_github_latest(repo):
    """Fetch latest release tag from GitHub."""
    try:
        import requests
        r = requests.get(f'https://api.github.com/repos/{repo}/releases/latest', timeout=10)
        if r.status_code == 200:
            tag = r.json().get('tag_name', '')
            return re.sub(r'^v', '', tag.strip())
    except Exception:
        pass
    return ''

def _fetch_from_winget(software_name):
    """Use winget to search for latest version."""
    try:
        if os.name != 'nt':
            return ''
        res = subprocess.run(
            ['winget', 'search', '--name', software_name, '--exact', '--accept-source-agreements'],
            capture_output=True, text=True, timeout=15
        )
        lines = res.stdout.split('\n')
        for i, line in enumerate(lines):
            if line.startswith('---') and i + 1 < len(lines):
                parts = lines[i+1].strip().split()
                if len(parts) >= 3:
                    version = parts[-2]
                    if version and version[0].isdigit():
                        return version
    except Exception:
        pass
    return ''

def _fetch_from_chocolatey(software_name):
    """Use chocolatey to search."""
    try:
        if os.name != 'nt':
            return ''
        res = subprocess.run(
            ['choco', 'find', software_name, '--exact', '--limit-output'],
            capture_output=True, text=True, timeout=15
        )
        for line in res.stdout.split('\n'):
            parts = line.strip().split('|')
            if len(parts) >= 2:
                version = parts[1].strip()
                if version and version[0].isdigit():
                    return version
    except Exception:
        pass
    return ''

def _fetch_generic_html_version(url, pattern=r'v?(\d+\.\d+\.\d+)', timeout=10):
    """Scrape HTML page for version number matching pattern."""
    try:
        import requests
        from requests.adapters import HTTPAdapter
        from urllib3.util.retry import Retry
        session = requests.Session()
        retries = Retry(total=2, backoff_factor=0.5)
        session.mount('https://', HTTPAdapter(max_retries=retries))
        r = session.get(url, timeout=timeout, headers={'User-Agent': 'Mozilla/5.0'})
        if r.status_code == 200:
            m = re.search(pattern, r.text)
            if m:
                return m.group(1)
    except Exception:
        pass
    return ''

def _try_sources(software_name, sources_config):
    """Try multiple methods to find the latest version."""
    ver = _fetch_from_winget(software_name)
    if ver:
        return ver
    ver = _fetch_from_chocolatey(software_name)
    if ver:
        return ver

    source_type = sources_config.get('type', '')

    if source_type == 'github_releases':
        repo = sources_config.get('repo', '')
        return _fetch_github_latest(repo)

    elif source_type == 'chrome':
        return _fetch_generic_html_version(
            'https://chromereleases.googleblog.com/search/label/Stable%20updates',
            r'Google Chrome\xc2\xa0(\d+\.\d+\.\d+\.\d+)'
        ) or _fetch_generic_html_version(
            'https://omahaproxy.appspot.com/all',
            r'(\d+\.\d+\.\d+\.\d+)'
        )

    elif source_type == 'mozilla_product':
        product = sources_config.get('product', 'firefox')
        return _fetch_generic_html_version(
            f'https://product-details.mozilla.org/1.0/{product}_versions.json',
            r'"LATEST_[^"]+":\s*"(\d+\.\d+(?:\.\d+)?)"'
        )

    elif source_type == 'python':
        return _fetch_generic_html_version(
            'https://www.python.org/downloads/',
            r'Python\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'nodejs':
        return _fetch_generic_html_version(
            'https://nodejs.org/dist/index.json',
            r'"version":\s*"v(\d+\.\d+\.\d+)"'
        )

    elif source_type == 'git':
        return _fetch_generic_html_version(
            'https://github.com/git-for-windows/git/releases/latest',
            r'Git-(\d+\.\d+\.\d+)'
        )

    elif source_type == 'videolan':
        return _fetch_generic_html_version(
            'https://www.videolan.org/vlc/download-windows.html',
            r'VLC\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'nginx':
        return _fetch_generic_html_version(
            'https://nginx.org/en/download.html',
            r'nginx-(\d+\.\d+\.\d+)'
        )

    elif source_type == 'docker':
        return _fetch_github_latest('docker/docker-ce')

    elif source_type == 'kubernetes':
        return _fetch_generic_html_version(
            'https://dl.k8s.io/release/stable.txt',
            r'v?(\d+\.\d+\.\d+)'
        )

    elif source_type == 'postgresql':
        return _fetch_generic_html_version(
            'https://www.postgresql.org/',
            r'(\d+\.\d+)\s+Released'
        )

    elif source_type == 'dotnet':
        return _fetch_generic_html_version(
            'https://dotnet.microsoft.com/en-us/download/dotnet',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'powershell':
        return _fetch_github_latest('PowerShell/PowerShell')

    elif source_type == 'npm_package':
        pkg = sources_config.get('package', '')
        return _fetch_generic_html_version(
            f'https://registry.npmjs.org/{pkg}/latest',
            r'"version":\s*"(\d+\.\d+\.\d+)"'
        )

    elif source_type == 'pypi':
        pkg = sources_config.get('package', '')
        return _fetch_generic_html_version(
            f'https://pypi.org/pypi/{pkg}/json',
            r'"version":\s*"(\d+\.\d+\.\d+)"'
        )

    elif source_type == 'golang':
        return _fetch_generic_html_version(
            'https://go.dev/dl/',
            r'go(\d+\.\d+\.\d+)\.'
        )

    elif source_type == 'rust':
        return _fetch_generic_html_version(
            'https://static.rust-lang.org/dist/channel-rust-stable.toml',
            r'version\s*=\s*"(\d+\.\d+\.\d+)"'
        )

    elif source_type == 'ruby':
        return _fetch_generic_html_version(
            'https://www.ruby-lang.org/en/downloads/',
            r'Ruby\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'php':
        return _fetch_generic_html_version(
            'https://www.php.net/downloads.php',
            r'PHP\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'libreoffice':
        return _fetch_generic_html_version(
            'https://www.libreoffice.org/download/download/',
            r'LibreOffice\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'gimp':
        return _fetch_generic_html_version(
            'https://www.gimp.org/downloads/',
            r'GIMP\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'blender':
        return _fetch_generic_html_version(
            'https://www.blender.org/download/',
            r'Blender\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'inkscape':
        return _fetch_generic_html_version(
            'https://inkscape.org/release/',
            r'Inkscape\s+(\d+\.\d+\.?\d*)'
        )

    elif source_type == 'java':
        return _fetch_generic_html_version(
            'https://www.oracle.com/java/technologies/downloads/',
            r'Java\s+(\d+)'
        )

    elif source_type == 'hashicorp':
        product = sources_config.get('product', 'terraform')
        return _fetch_generic_html_version(
            f'https://releases.hashicorp.com/{product}/',
            rf'{product}/(\d+\.\d+\.\d+)'
        )

    elif source_type == 'steam':
        return _fetch_generic_html_version(
            'https://store.steampowered.com/',
            r'Steam\s+(?:Client\s+)?v?(\d+\.\d+\.\d+\.\d+)'
        )

    elif source_type == 'zoom':
        return _fetch_generic_html_version(
            'https://zoom.us/download',
            r'(\d+\.\d+\.\d+\.\d+)'
        )

    elif source_type == 'slack':
        return _fetch_github_latest('slackhq/slack-desktop')

    elif source_type == 'discord':
        return _fetch_generic_html_version(
            'https://discord.com/download',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'telegram':
        return _fetch_generic_html_version(
            'https://desktop.telegram.org/',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'signal':
        return _fetch_generic_html_version(
            'https://signal.org/download/',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'keepass':
        return _fetch_generic_html_version(
            'https://keepass.info/download.html',
            r'KeePass\s+(\d+\.\d+)'
        )

    elif source_type == 'wireshark':
        return _fetch_generic_html_version(
            'https://www.wireshark.org/download.html',
            r'Wireshark\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'nmap':
        return _fetch_generic_html_version(
            'https://nmap.org/download.html',
            r'Nmap\s+(\d+\.\d+)'
        )

    elif source_type == 'voidtools':
        return _fetch_generic_html_version(
            'https://www.voidtools.com/',
            r'(\d+\.\d+)'
        )

    elif source_type == 'composer':
        return _fetch_generic_html_version(
            'https://getcomposer.org/download/',
            r'Composer\s+version\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'gradle':
        return _fetch_generic_html_version(
            'https://gradle.org/releases/',
            r'Gradle\s+(\d+\.\d+)'
        )

    elif source_type == 'jenkins':
        return _fetch_generic_html_version(
            'https://www.jenkins.io/download/',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'grafana':
        return _fetch_github_latest('grafana/grafana')

    elif source_type == 'prometheus':
        return _fetch_github_latest('prometheus/prometheus')

    elif source_type == 'virtualbox':
        return _fetch_generic_html_version(
            'https://www.virtualbox.org/wiki/Downloads',
            r'VirtualBox\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'sumatra':
        return _fetch_generic_html_version(
            'https://www.sumatrapdfreader.org/download-free-pdf-viewer',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'foxit':
        return _fetch_generic_html_version(
            'https://www.foxit.com/pdf-reader/',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'mariadb':
        return _fetch_generic_html_version(
            'https://mariadb.org/download/',
            r'MariaDB\s+(\d+\.\d+\.\d+)'
        )

    elif source_type == 'mongodb':
        return _fetch_generic_html_version(
            'https://www.mongodb.com/try/download/community',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'redis':
        return _fetch_generic_html_version(
            'https://redis.io/download/',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type == 'elastic':
        return _fetch_generic_html_version(
            'https://www.elastic.co/downloads/elasticsearch',
            r'(\d+\.\d+\.\d+)'
        )

    elif source_type in ('putty', 'filezilla', 'sonarqube', 'openssl', 'curl', 'gnu',
                         'handbrake', 'teamviewer', 'anydesk', 'audacity', 'apache',
                         'spotify', 'portswigger', 'oracle_mysql', 'vagrant',
                         'vmware', 'steam', 'epic'):
        # Use winget/choco fallback only for these
        pass

    # Final fallback: try generic winget search with broader match
    if not ver:
        ver = _fetch_from_winget(software_name)
    return ver or ''

def update_latest_version(software_name, conn=None):
    """Fetch latest version for a single software and save to JSON + DB."""
    refs = load_latest_versions()
    if not isinstance(refs, dict) or 'test' in refs and len(refs) == 1:
        refs = {}

    key = software_name.strip().lower()
    source = _VERSION_SOURCES.get(key, {})
    latest = _try_sources(key, source) if source else ''

    if not latest:
        # Try partial match in known sources
        for known_key, known_source in _VERSION_SOURCES.items():
            if known_key in key or key in known_key:
                latest = _try_sources(known_key, known_source)
                if latest:
                    source = known_source
                    break

    if latest:
        existing = refs.get(key, {})
        if isinstance(existing, dict):
            existing['version'] = latest
            existing['source'] = source.get('type', 'winget') if source else 'winget'
            existing['derniere_verification'] = datetime.now().strftime('%Y-%m-%d')
            refs[key] = existing
        else:
            refs[key] = {'version': latest, 'source': source.get('type', 'winget') if source else 'winget',
                         'derniere_verification': datetime.now().strftime('%Y-%m-%d')}

        save_latest_versions(refs)

        # Also update DB if conn provided
        if conn:
            try:
                c = conn.cursor()
                c.execute('UPDATE logiciels SET derniere_version=? WHERE nom=?',
                          (latest, software_name))
                conn.commit()
            except Exception:
                conn.rollback()

    return latest

def batch_update_latest_versions(conn):
    """Batch update latest versions for all software in DB (sans limite)."""
    names = set()
    try:
        c = conn.cursor()
        rows = c.execute('SELECT DISTINCT nom FROM logiciels ORDER BY nom').fetchall()
        names = {r['nom'] for r in rows}
    except Exception:
        pass

    results = {}
    for name in sorted(names):
        ver = update_latest_version(name, conn)
        if ver:
            results[name] = ver
    return results

# ── Editor country lookup ──────────────────────────────

_COUNTRY_HINTS = {
    'microsoft': 'US', 'google': 'US', 'apple': 'US', 'adobe': 'US', 'oracle': 'US',
    'ibm': 'US', 'intel': 'US', 'amd': 'US', 'nvidia': 'US', 'vmware': 'US',
    'docker': 'US', 'cisco': 'US', 'broadcom': 'US', 'dell': 'US', 'hp': 'US',
    'lenovo': 'CN', 'asus': 'TW', 'acer': 'TW', 'samsung': 'KR', 'lg': 'KR',
    'sony': 'JP', 'panasonic': 'JP', 'toshiba': 'JP', 'fujitsu': 'JP',
    'sap': 'DE', 'siemens': 'DE', 'volkswagen': 'DE', 'bmw': 'DE', 'mercedes': 'DE',
    'airbus': 'FR', 'total': 'FR', 'orange': 'FR', 'bnp': 'FR', 'lvmh': 'FR',
    'capgemini': 'FR', 'dassault': 'FR', 'thales': 'FR', 'schneider': 'FR',
    'ubisoft': 'FR', 'videolan': 'FR', 'notepad++': 'FR', 'idoceo': 'FR',
    'logitech': 'CH', 'nestle': 'CH', 'novartis': 'CH', 'roche': 'CH',
    'canonical': 'GB', 'arm': 'GB', 'deepmind': 'GB', 'bt': 'GB', 'sky': 'GB',
    'jetbrains': 'CZ', 'avast': 'CZ', 'winscp': 'CZ', 'seznam': 'CZ',
    'spotify': 'SE', 'mysql': 'SE', 'ericsson': 'SE', 'volvo': 'SE', 'skype': 'SE',
    'mozilla': 'US', 'red hat': 'US', 'salesforce': 'US', 'tesla': 'US',
    'kaspersky': 'RU', 'yandex': 'RU', 'telegram': 'AE', 'teamviewer': 'DE',
    'anydesk': 'DE', 'gdata': 'DE', 'libreoffice': 'DE', 'filezilla': 'DE',
    'winrar': 'RO', 'bitdefender': 'RO', 'eclipse': 'CA', 'shopify': 'CA',
    'atlassian': 'AU', 'canva': 'AU', 'sublime': 'AU', 'wps office': 'CN',
    'tencent': 'CN', 'alibaba': 'CN', 'baidu': 'CN', 'bytedance': 'CN',
    'shenzhen': 'CN', 'trend micro': 'JP', 'line': 'JP', 'rakuten': 'JP',
    'postgresql': 'US', 'python': 'NL', 'blender': 'NL', 'elastic': 'NL',
    'booking': 'NL', 'ing': 'NL', 'github': 'US', 'gitlab': 'NL',
    'hashicorp': 'US', 'mongodb': 'US', 'nginx': 'US', 'cloudflare': 'US',
    'curl': 'SE', 'putty': 'GB', 'gnu': 'US', 'apache': 'US',
    'signal': 'US', 'whatsapp': 'US', 'instagram': 'US', 'facebook': 'US',
    'zoom': 'US', 'slack': 'US', 'discord': 'US', 'dropbox': 'US',
    'box': 'US', 'netflix': 'US', 'palo alto': 'US', 'fortinet': 'US',
    'mcafee': 'US', 'symantec': 'US', 'norton': 'US', 'crowdstrike': 'US',
    'zscaler': 'US', 'okta': 'US', 'splunk': 'US', 'datadog': 'US',
    'newrelic': 'US', 'verizon': 'US', 'att': 'US', 'ge': 'US',
    'proton': 'CH', 'epic games': 'US', 'unity': 'US', 'unreal': 'US',
    'steam': 'US', 'valve': 'US', 'blizzard': 'US', 'activision': 'US',
    'ea': 'US', 'electronic arts': 'US', 'take-two': 'US', 'rockstar': 'US',
    'autodesk': 'US', 'ansys': 'US', 'ptc': 'US', 'comsol': 'US',
    'matlab': 'US', 'mathworks': 'US', 'wolfram': 'US',
    'git for windows': 'DE',
}

def _search_editor_web(editor_name):
    """Try to find editor's country via Wikipedia or web search."""
    import urllib.parse
    try:
        import requests
        session = requests.Session()
        session.headers.update({'User-Agent': 'I2SI-Inventory/1.0'})

        # Try Wikipedia API first
        wiki_url = 'https://en.wikipedia.org/w/api.php'
        params = {
            'action': 'query',
            'list': 'search',
            'srsearch': editor_name + ' company',
            'format': 'json',
            'srlimit': 3
        }
        r = session.get(wiki_url, params=params, timeout=10)
        if r.status_code == 200:
            data = r.json()
            pages = data.get('query', {}).get('search', [])
            for page in pages[:2]:
                title = page.get('title', '')
                # Get page content to find country info
                params2 = {
                    'action': 'query',
                    'prop': 'extracts',
                    'exintro': '1',
                    'explaintext': '1',
                    'titles': title,
                    'format': 'json'
                }
                r2 = session.get(wiki_url, params=params2, timeout=10)
                if r2.status_code == 200:
                    pages2 = r2.json().get('query', {}).get('pages', {})
                    for pid, page_data in pages2.items():
                        if pid == '-1':
                            continue
                        extract = page_data.get('extract', '')
                        # Look for country patterns
                        patterns = [
                            r'(?:based|headquartered|founded|incorporated)\s+in\s+([A-Z][a-z]+(?:\s+[A-Z][a-z]+)?)',
                            r'(?:American|British|French|German|Japanese|Chinese|Korean|Dutch|Swiss|Swedish|Canadian|Australian|Indian|Russian|Italian|Spanish|Brazilian|Israeli)',
                        ]
                        for pat in patterns:
                            m = re.search(pat, extract)
                            if m:
                                country_word = m.group(0) if '(' not in pat else m.group(0)
                                # Map nationality to country code
                                country_map = {
                                    'american': 'US', 'british': 'GB', 'french': 'FR',
                                    'german': 'DE', 'japanese': 'JP', 'chinese': 'CN',
                                    'korean': 'KR', 'dutch': 'NL', 'swiss': 'CH',
                                    'swedish': 'SE', 'canadian': 'CA', 'australian': 'AU',
                                    'indian': 'IN', 'russian': 'RU', 'italian': 'IT',
                                    'spanish': 'ES', 'brazilian': 'BR', 'israeli': 'IL',
                                    'czech': 'CZ', 'romanian': 'RO', 'polish': 'PL',
                                    'danish': 'DK', 'finnish': 'FI', 'norwegian': 'NO',
                                    'turkish': 'TR', 'mexican': 'MX', 'argentine': 'AR',
                                }
                                for nat, code in country_map.items():
                                    if nat in extract.lower():
                                        return code

        # Fallback: try a simple search API
        search_url = f'https://api.duckduckgo.com/?q={urllib.parse.quote(editor_name + " company location")}&format=json&no_html=1'
        r3 = session.get(search_url, timeout=10)
        if r3.status_code == 200:
            ddg_data = r3.json()
            abstract = ddg_data.get('Abstract', '') or ddg_data.get('AbstractText', '')
            for nat, code in [
                ('United States', 'US'), ('USA', 'US'), ('US', 'US'),
                ('France', 'FR'), ('French', 'FR'),
                ('Germany', 'DE'), ('German', 'DE'),
                ('Japan', 'JP'), ('Japanese', 'JP'),
                ('China', 'CN'), ('Chinese', 'CN'),
                ('United Kingdom', 'GB'), ('UK', 'GB'), ('Britain', 'GB'),
                ('South Korea', 'KR'), ('Korea', 'KR'),
                ('Netherlands', 'NL'), ('Dutch', 'NL'),
                ('Switzerland', 'CH'), ('Swedish', 'SE'), ('Sweden', 'SE'),
                ('Canada', 'CA'), ('Australia', 'AU'),
                ('Russia', 'RU'), ('India', 'IN'),
                ('Italy', 'IT'), ('Spain', 'ES'),
                ('Brazil', 'BR'), ('Israel', 'IL'),
                ('Czech Republic', 'CZ'), ('Romania', 'RO'),
                ('Poland', 'PL'), ('Denmark', 'DK'),
                ('Finland', 'FI'), ('Norway', 'NO'),
                ('Turkey', 'TR'), ('Taiwan', 'TW'),
                ('Singapore', 'SG'), ('Hong Kong', 'HK'),
            ]:
                if nat in abstract or nat in extract:
                    return code

    except Exception:
        pass
    return ''

def lookup_editor_country(editor_name):
    """Look up the country for an editor, using local DB first, then web."""
    if not editor_name:
        return ''

    editors = load_editors()
    key = editor_name.strip().lower()

    # Check if already in DB
    if key in editors:
        return editors[key].get('pays', '')

    # Check partial match
    for k, v in editors.items():
        if k in key or key in k:
            return v.get('pays', '')

    # Check hints
    for hint_key, country in _COUNTRY_HINTS.items():
        if hint_key in key or key in hint_key:
            # Save to DB
            editors[key] = {'pays': country, 'site': '', 'metier_defaut': ''}
            # Try to find site
            try:
                import requests
                r = requests.get(f'https://www.google.com/search?q={editor_name.replace(" ", "+")}+official+website',
                                 timeout=5, headers={'User-Agent': 'Mozilla/5.0'})
                m = re.search(r'(https?://[^/]+)', r.text[:2000])
                if m:
                    editors[key]['site'] = m.group(1)
            except Exception:
                pass
            save_editors(editors)
            return country

    # Try web search
    country = _search_editor_web(editor_name)
    if country:
        editors[key] = {'pays': country, 'site': '', 'metier_defaut': ''}
        save_editors(editors)

    return country
