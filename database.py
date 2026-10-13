"""
Enterprise Database Abstraction Layer
Supports SQLite (dev) and PostgreSQL (production)
"""
import os
import json
import re
import sqlite3

DB_TYPE = os.environ.get('DB_TYPE', 'sqlite')
DB_FILE = os.environ.get('DB_FILE', 'parc.db')

PG_CONFIG = {
    'host': os.environ.get('PG_HOST', 'localhost'),
    'port': int(os.environ.get('PG_PORT', 5432)),
    'dbname': os.environ.get('PG_NAME', 'inventaire'),
    'user': os.environ.get('PG_USER', 'inventaire'),
    'password': os.environ.get('PG_PASS', ''),
}

class DatabaseError(Exception):
    pass

def _q(sql):
    return re.sub(r'\?', '%s', sql)

class PGCursor:
    def __init__(self, cur, conn=None):
        self._cur = cur
        self._conn = conn
        self.lastrowid = None
        self._row = None

    def execute(self, sql, params=None):
        xsql = _q(sql)
        if params is None:
            self._cur.execute(xsql)
        else:
            self._cur.execute(xsql, params)
        # Use savepoint to isolate LASTVAL() failure so it doesn't abort the outer transaction
        if not self._cur.description and self._conn:
            raw_conn = getattr(self._conn, '_conn', None)
            if raw_conn:
                sv = None
                try:
                    sv = raw_conn.cursor()
                    sv.execute("SAVEPOINT sp_lv")
                    sv.execute("SELECT LASTVAL()")
                    row = sv.fetchone()
                    self.lastrowid = row[0] if row else None
                    sv.execute("RELEASE SAVEPOINT sp_lv")
                except Exception:
                    if sv:
                        try: sv.execute("ROLLBACK TO SAVEPOINT sp_lv")
                        except: pass
                    self.lastrowid = None
                finally:
                    if sv:
                        try: sv.close()
                        except: pass
            else:
                self.lastrowid = None
        else:
            self.lastrowid = None
        return self

    def fetchone(self):
        return self._cur.fetchone()

    def fetchall(self):
        return self._cur.fetchall()

    def __getattr__(self, name):
        return getattr(self._cur, name)

class PGConnection:
    def __init__(self, conn):
        self._conn = conn
        self.row_factory = None

    def cursor(self):
        return PGCursor(self._conn.cursor(), conn=self._conn)

    def execute(self, sql, params=None):
        cur = self.cursor()
        return cur.execute(sql, params)

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        self._conn.close()

    def executescript(self, script):
        cur = self._conn.cursor()
        for stmt in script.split(';'):
            s = stmt.strip()
            if s:
                try:
                    cur.execute(s)
                except Exception:
                    pass
        cur.close()

    def __getattr__(self, name):
        return getattr(self._conn, name)

def get_conn():
    if DB_TYPE == 'postgresql':
        return _get_pg_conn()
    return _get_sqlite_conn()

def _get_sqlite_conn():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=300000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn

def _get_pg_conn():
    try:
        import psycopg2
        import psycopg2.extras
        conn = psycopg2.connect(**PG_CONFIG)
        conn.cursor_factory = psycopg2.extras.RealDictCursor
        return PGConnection(conn)
    except ImportError:
        raise DatabaseError("psycopg2 not installed. Run: pip install psycopg2-binary")
    except Exception as e:
        raise DatabaseError(f"PostgreSQL connection failed: {e}")

def is_sqlite(conn):
    return isinstance(conn, sqlite3.Connection)

def execute(conn, sql, params=None):
    if is_sqlite(conn):
        if params is None:
            return conn.execute(sql)
        return conn.execute(sql, params)
    else:
        cur = conn.cursor()
        return cur.execute(sql, params)

def fetchone(conn, sql, params=None):
    cur = execute(conn, sql, params)
    return cur.fetchone()

def fetchall(conn, sql, params=None):
    cur = execute(conn, sql, params)
    return cur.fetchall()

def commit(conn):
    conn.commit()

def rollback(conn):
    conn.rollback()

def close(conn):
    conn.close()

def row_to_dict(row):
    if row is None:
        return None
    return dict(row)

def rows_to_list(rows):
    return [dict(r) for r in rows]

def init_enterprise_tables(conn):
    sqlite = is_sqlite(conn)
    c = conn.cursor()

    if sqlite:
        _init_sqlite_tables(c)
    else:
        _init_pg_tables(c)

    conn.commit()

def _init_sqlite_tables(c):
    c.executescript('''
        CREATE TABLE IF NOT EXISTS sites (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL UNIQUE,
            adresse TEXT DEFAULT '',
            ville TEXT DEFAULT '',
            code_postal TEXT DEFAULT '',
            pays TEXT DEFAULT '',
            responsable TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            actif INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS departments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            site_id INTEGER REFERENCES sites(id),
            responsable TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            actif INTEGER DEFAULT 1,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS sbom (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT NOT NULL,
            logiciel_nom TEXT NOT NULL,
            logiciel_version TEXT DEFAULT '',
            editeur TEXT DEFAULT '',
            dependances TEXT DEFAULT '[]',
            vulnerabilites TEXT DEFAULT '[]',
            licenses TEXT DEFAULT '[]',
            purl TEXT DEFAULT '',
            cpe TEXT DEFAULT '',
            date_analyse TEXT DEFAULT '',
            meta_json TEXT DEFAULT '{}',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS usage_stats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            logiciel_nom TEXT NOT NULL,
            editeur TEXT DEFAULT '',
            scan_id TEXT NOT NULL,
            dernier_lancement TEXT DEFAULT '',
            frequence_usage TEXT DEFAULT 'Inconnu',
            nb_lancements INTEGER DEFAULT 0,
            usage_moyen_minutes REAL DEFAULT 0,
            machine_nom TEXT DEFAULT '',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS audit_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT DEFAULT '',
            nom_pc TEXT DEFAULT '',
            action TEXT NOT NULL,
            categorie TEXT DEFAULT 'systeme',
            details TEXT DEFAULT '{}',
            ip_source TEXT DEFAULT '',
            utilisateur TEXT DEFAULT '',
            severite TEXT DEFAULT 'info',
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        );

        CREATE TABLE IF NOT EXISTS compliance_rules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            regle TEXT UNIQUE NOT NULL,
            famille TEXT DEFAULT 'ANSSI',
            description TEXT DEFAULT '',
            niveau TEXT DEFAULT 'Moyen',
            statut TEXT DEFAULT 'Non verifie',
            points INTEGER DEFAULT 0,
            max_points INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS briques_logiciel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            nom TEXT NOT NULL,
            editeur TEXT DEFAULT '',
            type_brique TEXT DEFAULT '',
            description TEXT DEFAULT '',
            editeur_url TEXT DEFAULT '',
            documentation_url TEXT DEFAULT '',
            repository_url TEXT DEFAULT '',
            pays_origine TEXT DEFAULT '',
            annee_creation TEXT DEFAULT '',
            version_actuelle TEXT DEFAULT '',
            version_utilisee TEXT DEFAULT '',
            licence TEXT DEFAULT '',
            cout TEXT DEFAULT '',
            statut TEXT DEFAULT '',
            responsable TEXT DEFAULT '',
            service_concerne TEXT DEFAULT '',
            tags TEXT DEFAULT '',
            notes TEXT DEFAULT '',
            vulnerabilites TEXT DEFAULT '',
            requires_wp TEXT DEFAULT '',
            requires_php TEXT DEFAULT '',
            requires_plugins TEXT DEFAULT '',
            created_at TEXT DEFAULT (datetime('now','localtime')),
            updated_at TEXT DEFAULT (datetime('now','localtime'))
        );

        CREATE INDEX IF NOT EXISTS idx_sbom_scan ON sbom(scan_id);
        CREATE INDEX IF NOT EXISTS idx_sbom_nom ON sbom(logiciel_nom);
        CREATE INDEX IF NOT EXISTS idx_usage_nom ON usage_stats(logiciel_nom);
        CREATE INDEX IF NOT EXISTS idx_usage_scan ON usage_stats(scan_id);
        CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_log(scan_id);
        CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action);
        CREATE INDEX IF NOT EXISTS idx_audit_categorie ON audit_log(categorie);
        CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_log(timestamp);
    ''')

    sqlite_migrations = [
        "ALTER TABLE machines ADD COLUMN tags TEXT DEFAULT ''",
        "ALTER TABLE machines ADD COLUMN agent_version TEXT DEFAULT ''",
        "ALTER TABLE machines ADD COLUMN dernier_contact DATETIME",
        "ALTER TABLE machines ADD COLUMN notes TEXT DEFAULT ''",
        "ALTER TABLE logiciels ADD COLUMN sbom_id INTEGER DEFAULT 0",
        "ALTER TABLE logiciels ADD COLUMN license_key TEXT DEFAULT ''",
        "ALTER TABLE logiciels ADD COLUMN signature_date TEXT DEFAULT ''",
        "ALTER TABLE logiciels ADD COLUMN cert_authority TEXT DEFAULT ''",
        "ALTER TABLE logiciels ADD COLUMN install_source_detailed TEXT DEFAULT ''",
        "ALTER TABLE logiciels ADD COLUMN date_compilation TEXT DEFAULT ''",
        "ALTER TABLE catalogue ADD COLUMN sbom_generable INTEGER DEFAULT 0",
        "ALTER TABLE catalogue ADD COLUMN cpe_match TEXT DEFAULT ''",
        "ALTER TABLE catalogue ADD COLUMN purl TEXT DEFAULT ''",
        "ALTER TABLE cve_cache ADD COLUMN logiciel_editeur TEXT DEFAULT ''",
        "ALTER TABLE cve_cache ADD COLUMN cvss_score REAL DEFAULT 0",
        "ALTER TABLE cve_cache ADD COLUMN cvss_severity TEXT DEFAULT ''",
        "ALTER TABLE cve_cache ADD COLUMN cwe TEXT DEFAULT ''",
        "ALTER TABLE cve_cache ADD COLUMN exploit_public INTEGER DEFAULT 0",
        "ALTER TABLE cve_cache ADD COLUMN remediation TEXT DEFAULT ''",
        "ALTER TABLE cve_cache ADD COLUMN date_publiee TEXT DEFAULT ''",
        "ALTER TABLE cve_cache ADD COLUMN date_actualisee TEXT DEFAULT ''",
        "ALTER TABLE cve_cache ADD COLUMN source TEXT DEFAULT 'NVD'",
        "ALTER TABLE briques_logiciel ADD COLUMN editeur_url TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN repository_url TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN pays_origine TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN annee_creation TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN version_utilisee TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN cout TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN vulnerabilites TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN requires_wp TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN requires_php TEXT DEFAULT ''",
        "ALTER TABLE briques_logiciel ADD COLUMN requires_plugins TEXT DEFAULT ''",
    ]
    for col_sql in sqlite_migrations:
        try:
            c.execute(col_sql)
        except Exception as ex:
            err = str(ex).lower()
            if "duplicate column" not in err and "already exists" not in err:
                print(f"  [MIGRATION] {ex}")

def _init_pg_tables(c):
    pg_enterprise_tables = [
        '''CREATE TABLE IF NOT EXISTS sites (
            id SERIAL PRIMARY KEY, nom VARCHAR(255) NOT NULL UNIQUE, adresse TEXT DEFAULT '',
            ville VARCHAR(255) DEFAULT '', code_postal VARCHAR(20) DEFAULT '',
            pays VARCHAR(100) DEFAULT '', responsable VARCHAR(255) DEFAULT '',
            notes TEXT DEFAULT '', actif BOOLEAN DEFAULT true,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS departments (
            id SERIAL PRIMARY KEY, nom VARCHAR(255) NOT NULL,
            site_id INTEGER REFERENCES sites(id) ON DELETE CASCADE,
            responsable VARCHAR(255) DEFAULT '', notes TEXT DEFAULT '',
            actif BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY, nom VARCHAR(255) NOT NULL UNIQUE, email VARCHAR(255) UNIQUE,
            role VARCHAR(50) DEFAULT 'viewer', site_id INTEGER REFERENCES sites(id),
            department_id INTEGER REFERENCES departments(id), password_hash TEXT DEFAULT '',
            actif BOOLEAN DEFAULT true, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS sbom (
            id SERIAL PRIMARY KEY, scan_id VARCHAR(64) NOT NULL, logiciel_nom VARCHAR(512) NOT NULL,
            logiciel_version VARCHAR(255) DEFAULT '', editeur VARCHAR(512) DEFAULT '',
            dependances JSONB DEFAULT '[]', vulnerabilites JSONB DEFAULT '[]',
            licenses JSONB DEFAULT '[]', purl VARCHAR(512) DEFAULT '', cpe VARCHAR(512) DEFAULT '',
            date_analyse VARCHAR(20) DEFAULT '', meta_json JSONB DEFAULT '{}',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS usage_stats (
            id SERIAL PRIMARY KEY, logiciel_nom VARCHAR(512) NOT NULL, editeur VARCHAR(512) DEFAULT '',
            scan_id VARCHAR(64) NOT NULL, dernier_lancement VARCHAR(30) DEFAULT '',
            frequence_usage VARCHAR(50) DEFAULT 'Inconnu', nb_lancements INTEGER DEFAULT 0,
            usage_moyen_minutes REAL DEFAULT 0, machine_nom VARCHAR(255) DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS audit_log (
            id SERIAL PRIMARY KEY, scan_id VARCHAR(64) DEFAULT '', nom_pc VARCHAR(255) DEFAULT '',
            action VARCHAR(255) NOT NULL, categorie VARCHAR(50) DEFAULT 'systeme',
            details JSONB DEFAULT '{}', ip_source VARCHAR(45) DEFAULT '',
            utilisateur VARCHAR(255) DEFAULT '', severite VARCHAR(20) DEFAULT 'info',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS compliance_rules (
            id SERIAL PRIMARY KEY, regle VARCHAR(512) UNIQUE NOT NULL,
            famille VARCHAR(50) DEFAULT 'ANSSI', description TEXT DEFAULT '',
            niveau VARCHAR(20) DEFAULT 'Moyen', statut VARCHAR(50) DEFAULT 'Non verifie',
            points INTEGER DEFAULT 0, max_points INTEGER DEFAULT 1,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
        '''CREATE TABLE IF NOT EXISTS briques_logiciel (
            id SERIAL PRIMARY KEY, nom VARCHAR(512) NOT NULL, editeur VARCHAR(255) DEFAULT '',
            type_brique VARCHAR(100) DEFAULT '', description TEXT DEFAULT '',
            editeur_url TEXT DEFAULT '', documentation_url TEXT DEFAULT '', repository_url TEXT DEFAULT '',
            pays_origine VARCHAR(100) DEFAULT '', annee_creation VARCHAR(20) DEFAULT '',
            version_actuelle VARCHAR(100) DEFAULT '', version_utilisee VARCHAR(100) DEFAULT '',
            licence VARCHAR(255) DEFAULT '', cout VARCHAR(50) DEFAULT '',
            statut VARCHAR(50) DEFAULT '', responsable VARCHAR(255) DEFAULT '',
            service_concerne VARCHAR(255) DEFAULT '', tags TEXT DEFAULT '', notes TEXT DEFAULT '',
            vulnerabilites TEXT DEFAULT '', requires_wp VARCHAR(20) DEFAULT '',
            requires_php VARCHAR(20) DEFAULT '', requires_plugins TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )''',
    ]
    for sql in pg_enterprise_tables:
        try:
            c.execute(sql)
        except Exception:
            pass

    for idx in [
        'CREATE INDEX IF NOT EXISTS idx_sbom_scan ON sbom(scan_id)',
        'CREATE INDEX IF NOT EXISTS idx_sbom_nom ON sbom(logiciel_nom)',
        'CREATE INDEX IF NOT EXISTS idx_usage_nom ON usage_stats(logiciel_nom)',
        'CREATE INDEX IF NOT EXISTS idx_usage_scan ON usage_stats(scan_id)',
        'CREATE INDEX IF NOT EXISTS idx_audit_scan ON audit_log(scan_id)',
        'CREATE INDEX IF NOT EXISTS idx_audit_action ON audit_log(action)',
        'CREATE INDEX IF NOT EXISTS idx_audit_cat ON audit_log(categorie)',
        'CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(created_at)',
        'CREATE INDEX IF NOT EXISTS idx_users_role ON users(role)',
        'CREATE INDEX IF NOT EXISTS idx_users_site ON users(site_id)',
    ]:
        try:
            c.execute(idx)
        except Exception:
            pass
