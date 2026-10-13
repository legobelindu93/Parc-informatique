-- ═══════════════════════════════════════════════════════════════════
-- INVENTAIRE v5.1 — Enterprise PostgreSQL Schema
-- ═══════════════════════════════════════════════════════════════════

-- Extensions
CREATE EXTENSION IF NOT EXISTS pgcrypto;
CREATE EXTENSION IF NOT EXISTS pg_trgm;

-- ═══════════ 1. SITES & ORGANISATION ═══════════

CREATE TABLE IF NOT EXISTS sites (
    id              SERIAL PRIMARY KEY,
    nom             VARCHAR(255) NOT NULL UNIQUE,
    adresse         TEXT DEFAULT '',
    ville           VARCHAR(255) DEFAULT '',
    code_postal     VARCHAR(20) DEFAULT '',
    pays            VARCHAR(100) DEFAULT '',
    responsable     VARCHAR(255) DEFAULT '',
    notes           TEXT DEFAULT '',
    actif           BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS departments (
    id              SERIAL PRIMARY KEY,
    nom             VARCHAR(255) NOT NULL,
    site_id         INTEGER REFERENCES sites(id) ON DELETE CASCADE,
    responsable     VARCHAR(255) DEFAULT '',
    notes           TEXT DEFAULT '',
    actif           BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS users (
    id              SERIAL PRIMARY KEY,
    nom             VARCHAR(255) NOT NULL UNIQUE,
    email           VARCHAR(255) UNIQUE,
    role            VARCHAR(50) DEFAULT 'viewer'
                    CHECK (role IN ('admin', 'manager', 'analyst', 'viewer')),
    site_id         INTEGER REFERENCES sites(id),
    department_id   INTEGER REFERENCES departments(id),
    password_hash   TEXT DEFAULT '',
    actif           BOOLEAN DEFAULT true,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login      TIMESTAMP
);

CREATE INDEX idx_users_role ON users(role);
CREATE INDEX idx_users_site ON users(site_id);

-- ═══════════ 2. MACHINES ═══════════

CREATE TABLE IF NOT EXISTS machines (
    id                  SERIAL PRIMARY KEY,
    nom_pc              VARCHAR(255) NOT NULL,
    ip                  VARCHAR(45),
    mac                 VARCHAR(17),
    utilisateur         VARCHAR(255),
    domaine             VARCHAR(255),
    os_nom              VARCHAR(255),
    os_version          VARCHAR(50),
    os_build            VARCHAR(50),
    os_arch             VARCHAR(20),
    fabricant           VARCHAR(255),
    modele              VARCHAR(255),
    ram_gb              REAL,
    cpu_nom             VARCHAR(255),
    cpu_coeurs          INTEGER,
    disque_taille_gb    REAL,
    disque_libre_gb     REAL,
    disque_pct_libre    REAL,
    uptime_jours        REAL,
    department          VARCHAR(255),
    location            VARCHAR(255),
    site_id             INTEGER REFERENCES sites(id),
    actif               INTEGER DEFAULT 1,
    date_scan           VARCHAR(20),
    heure_scan          VARCHAR(20),
    scan_id             VARCHAR(64) UNIQUE,
    rapport_json        TEXT,
    score_securite      INTEGER DEFAULT 0,
    score_conformite    INTEGER DEFAULT 0,
    timestamp           TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    dernier_demarrage   VARCHAR(30) DEFAULT '',
    nb_utilisateurs     INTEGER DEFAULT 0,
    nb_connexions       INTEGER DEFAULT 0,
    version_bios        VARCHAR(255) DEFAULT '',
    type_machine        VARCHAR(50) DEFAULT '',
    os                  VARCHAR(255),
    json_raw            TEXT,
    arch                VARCHAR(20),
    -- Enterprise columns
    tags                TEXT[] DEFAULT '{}',
    agent_version       VARCHAR(50) DEFAULT '',
    dernier_contact     TIMESTAMP,
    notes               TEXT DEFAULT '',
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_machines_nom   ON machines(nom_pc);
CREATE INDEX idx_machines_site  ON machines(site_id);
CREATE INDEX idx_machines_actif ON machines(actif);
CREATE INDEX idx_machines_scan  ON machines(scan_id);
CREATE INDEX idx_machines_os    ON machines(os_nom);

-- ═══════════ 3. LOGICIELS ═══════════

CREATE TABLE IF NOT EXISTS logiciels (
    id                      SERIAL PRIMARY KEY,
    scan_id                 VARCHAR(64) NOT NULL REFERENCES machines(scan_id) ON DELETE CASCADE,
    nom                     VARCHAR(512) NOT NULL,
    version                 VARCHAR(255),
    editeur                 VARCHAR(512),
    architecture            VARCHAR(20),
    categorie               VARCHAR(100),
    taille_kb               VARCHAR(50),
    risque_niveau           VARCHAR(20),
    risque_score            INTEGER,
    eol                     VARCHAR(10),
    signature               VARCHAR(50),
    editeur_url             TEXT,
    risque_auto             VARCHAR(50),
    risque_desc             TEXT,
    portable                INTEGER DEFAULT 0,
    meta_json               JSONB DEFAULT '{}',
    approuve                INTEGER DEFAULT 0,
    criticite_metier        VARCHAR(50) DEFAULT '',
    hash_sha256             VARCHAR(64) DEFAULT '',
    cert_editeur            TEXT DEFAULT '',
    derniere_execution      VARCHAR(30) DEFAULT '',
    dependances             TEXT DEFAULT '',
    version_date            VARCHAR(30) DEFAULT '',
    install_source          VARCHAR(50) DEFAULT '',
    install_lang            VARCHAR(20) DEFAULT '',
    description             TEXT DEFAULT '',
    build                   VARCHAR(50) DEFAULT '',
    url_help                TEXT DEFAULT '',
    type_logiciel           VARCHAR(50) DEFAULT '',
    chemin                  TEXT,
    -- Enterprise columns
    sbom_id                 INTEGER DEFAULT 0,
    license_key             TEXT DEFAULT '',
    signature_date          VARCHAR(30) DEFAULT '',
    cert_authority          TEXT DEFAULT '',
    install_source_detailed TEXT DEFAULT '',
    date_compilation        VARCHAR(30) DEFAULT '',
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_logiciels_nom    ON logiciels(nom);
CREATE INDEX idx_logiciels_scan   ON logiciels(scan_id);
CREATE INDEX idx_logiciels_editeur ON logiciels(editeur);
CREATE INDEX idx_logiciels_cat    ON logiciels(categorie);
CREATE INDEX idx_logiciels_risque ON logiciels(risque_score);
CREATE INDEX idx_logiciels_eol    ON logiciels(eol);
CREATE INDEX idx_logiciels_trgm   ON logiciels USING gin (nom gin_trgm_ops);

-- ═══════════ 4. CATALOGUE ═══════════

CREATE TABLE IF NOT EXISTS catalogue (
    id                      SERIAL PRIMARY KEY,
    nom                     VARCHAR(512) UNIQUE NOT NULL,
    editeur                 VARCHAR(512),
    categorie               VARCHAR(100),
    site_officiel           TEXT,
    risque_intrinseque      VARCHAR(20) DEFAULT 'Faible',
    approuve                INTEGER DEFAULT 0,
    description             TEXT DEFAULT '',
    fonction_metier         TEXT DEFAULT '',
    service_concerne        TEXT DEFAULT '',
    referent_metier         TEXT DEFAULT '',
    referent_technique      TEXT DEFAULT '',
    criticite_metier        VARCHAR(50) DEFAULT '',
    tolere                  INTEGER DEFAULT 0,
    obligatoire             INTEGER DEFAULT 0,
    justification_metier    TEXT DEFAULT '',
    licence_type            VARCHAR(50) DEFAULT '',
    licence_numero          TEXT DEFAULT '',
    licence_date_achat      VARCHAR(20) DEFAULT '',
    licence_date_expiration VARCHAR(20) DEFAULT '',
    licence_cout_annuel     REAL,
    licence_conforme        INTEGER DEFAULT 0,
    derniere_version        VARCHAR(50) DEFAULT '',
    date_derniere_version   VARCHAR(20) DEFAULT '',
    fin_support             VARCHAR(20) DEFAULT '',
    eos                     INTEGER DEFAULT 0,
    url_editeur             TEXT DEFAULT '',
    help_url                TEXT DEFAULT '',
    meta_json               JSONB DEFAULT '{}',
    -- Enterprise columns
    sbom_generable          INTEGER DEFAULT 0,
    cpe_match               VARCHAR(512) DEFAULT '',
    purl                    VARCHAR(512) DEFAULT '',
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_catalogue_nom ON catalogue(nom);
CREATE INDEX idx_catalogue_cat ON catalogue(categorie);

-- ═══════════ 5. CVE & VULNÉRABILITÉS ═══════════

CREATE TABLE IF NOT EXISTS cve_cache (
    id                  SERIAL PRIMARY KEY,
    logiciel_nom        VARCHAR(512) NOT NULL,
    logiciel_editeur    VARCHAR(512) DEFAULT '',
    cve_id              VARCHAR(20) NOT NULL,
    cvss_score          REAL,
    cvss_severity       VARCHAR(20),
    cwe                 VARCHAR(50) DEFAULT '',
    description         TEXT DEFAULT '',
    exploit_public      INTEGER DEFAULT 0,
    exploit_exists      INTEGER DEFAULT 0,
    remediation         TEXT DEFAULT '',
    date_publiee        VARCHAR(20) DEFAULT '',
    date_actualisee     VARCHAR(20) DEFAULT '',
    source              VARCHAR(50) DEFAULT 'NVD'
                        CHECK (source IN ('NVD', 'CISA_KEV', 'MSRC', 'Vulners', 'Manual')),
    meta_json           JSONB DEFAULT '{}',
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_cve_nom     ON cve_cache(logiciel_nom);
CREATE INDEX idx_cve_id      ON cve_cache(cve_id);
CREATE INDEX idx_cve_score   ON cve_cache(cvss_score);
CREATE INDEX idx_cve_source  ON cve_cache(source);
CREATE INDEX idx_cve_exploit ON cve_cache(exploit_public);

-- ═══════════ 6. SBOM ═══════════

CREATE TABLE IF NOT EXISTS sbom (
    id                  SERIAL PRIMARY KEY,
    scan_id             VARCHAR(64) NOT NULL REFERENCES machines(scan_id) ON DELETE CASCADE,
    logiciel_nom        VARCHAR(512) NOT NULL,
    logiciel_version    VARCHAR(255) DEFAULT '',
    editeur             VARCHAR(512) DEFAULT '',
    dependances         JSONB DEFAULT '[]',
    vulnerabilites      JSONB DEFAULT '[]',
    licenses            JSONB DEFAULT '[]',
    purl                VARCHAR(512) DEFAULT '',
    cpe                 VARCHAR(512) DEFAULT '',
    date_analyse        VARCHAR(20) DEFAULT '',
    meta_json           JSONB DEFAULT '{}',
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_sbom_scan ON sbom(scan_id);
CREATE INDEX idx_sbom_nom  ON sbom(logiciel_nom);

-- ═══════════ 7. LICENCES ═══════════

CREATE TABLE IF NOT EXISTS licences (
    id                      SERIAL PRIMARY KEY,
    logiciel_nom            VARCHAR(512) NOT NULL,
    editeur                 VARCHAR(512) DEFAULT '',
    type_licence            VARCHAR(100),
    categorie_licence       VARCHAR(50) DEFAULT 'Proprietaire',
    numero_licence          TEXT DEFAULT '',
    date_achat              VARCHAR(20) DEFAULT '',
    date_expiration         VARCHAR(20) DEFAULT '',
    cout_annuel             REAL,
    nb_licences             INTEGER DEFAULT 0,
    nb_utilisees            INTEGER DEFAULT 0,
    contrat_maintenance     INTEGER DEFAULT 0,
    renouvellement_auto     INTEGER DEFAULT 0,
    fournisseur             TEXT DEFAULT '',
    contact_fournisseur     TEXT DEFAULT '',
    notes                   TEXT DEFAULT '',
    surconsommation         INTEGER DEFAULT 0,
    sous_utilisation        INTEGER DEFAULT 0,
    scan_id                 VARCHAR(64) REFERENCES machines(scan_id),
    meta_json               JSONB DEFAULT '{}',
    created_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at              TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_lic_nom ON licences(logiciel_nom);

-- ═══════════ 8. CONFORMITÉ ═══════════

CREATE TABLE IF NOT EXISTS compliance_rules (
    id              SERIAL PRIMARY KEY,
    regle           VARCHAR(512) UNIQUE NOT NULL,
    famille         VARCHAR(50) DEFAULT 'ANSSI',
    description     TEXT DEFAULT '',
    niveau          VARCHAR(20) DEFAULT 'Moyen',
    statut          VARCHAR(50) DEFAULT 'Non verifie',
    points          INTEGER DEFAULT 0,
    max_points      INTEGER DEFAULT 1,
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════════
-- 9. HISTORIQUE
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS historique_scan (
    id              SERIAL PRIMARY KEY,
    nom_pc          VARCHAR(255) NOT NULL,
    scan_id         VARCHAR(64) NOT NULL,
    date_scan       VARCHAR(20),
    heure_scan      VARCHAR(20),
    rapport_json    TEXT,
    archive_le      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip              VARCHAR(45),
    alertes         TEXT,
    nb_logiciels    INTEGER,
    duree_s         REAL
);

CREATE INDEX idx_hist_nom   ON historique_scan(nom_pc);
CREATE INDEX idx_hist_scan  ON historique_scan(scan_id);

CREATE TABLE IF NOT EXISTS historique_actions (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(64),
    nom_pc          VARCHAR(255),
    type_action     VARCHAR(50),
    logiciel_nom    VARCHAR(512),
    ancienne_version VARCHAR(255),
    nouvelle_version VARCHAR(255),
    description     TEXT,
    date_action     VARCHAR(20),
    heure_action    VARCHAR(20),
    timestamp       TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_actions_scan  ON historique_actions(scan_id);
CREATE INDEX idx_actions_type  ON historique_actions(type_action);

-- ═══════════ 10. AUDIT LOG ═══════════

CREATE TABLE IF NOT EXISTS audit_log (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(64),
    nom_pc          VARCHAR(255),
    action          VARCHAR(255) NOT NULL,
    categorie       VARCHAR(50) DEFAULT 'systeme',
    details         JSONB DEFAULT '{}',
    ip_source       VARCHAR(45) DEFAULT '',
    utilisateur     VARCHAR(255) DEFAULT '',
    severite        VARCHAR(20) DEFAULT 'info'
                    CHECK (severite IN ('info', 'warning', 'error', 'critical')),
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_audit_scan  ON audit_log(scan_id);
CREATE INDEX idx_audit_act   ON audit_log(action);
CREATE INDEX idx_audit_cat   ON audit_log(categorie);
CREATE INDEX idx_audit_ts    ON audit_log(created_at);
CREATE INDEX idx_audit_sev   ON audit_log(severite);

-- ═══════════ 11. USAGE STATS ═══════════

CREATE TABLE IF NOT EXISTS usage_stats (
    id                  SERIAL PRIMARY KEY,
    logiciel_nom        VARCHAR(512) NOT NULL,
    editeur             VARCHAR(512) DEFAULT '',
    scan_id             VARCHAR(64) NOT NULL,
    dernier_lancement   VARCHAR(30) DEFAULT '',
    frequence_usage     VARCHAR(50) DEFAULT 'Inconnu',
    nb_lancements       INTEGER DEFAULT 0,
    usage_moyen_minutes REAL DEFAULT 0,
    machine_nom         VARCHAR(255) DEFAULT '',
    created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX idx_usage_nom   ON usage_stats(logiciel_nom);
CREATE INDEX idx_usage_scan  ON usage_stats(scan_id);

-- ═══════════ 12. PROCESSUS & SERVICES (archivés par scan) ═══════════

CREATE TABLE IF NOT EXISTS processus (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(64) REFERENCES machines(scan_id) ON DELETE CASCADE,
    nom             VARCHAR(255),
    pid             INTEGER,
    mem_mb          REAL,
    cpu_s           REAL,
    chemin          TEXT,
    description     TEXT DEFAULT '',
    suspect         INTEGER DEFAULT 0,
    raison_suspecte TEXT DEFAULT ''
);

CREATE INDEX idx_proc_scan  ON processus(scan_id);
CREATE INDEX idx_proc_nom   ON processus(nom);

CREATE TABLE IF NOT EXISTS services (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(64) REFERENCES machines(scan_id) ON DELETE CASCADE,
    nom             VARCHAR(255),
    nom_court       VARCHAR(255),
    statut          VARCHAR(50),
    type_demarrage  VARCHAR(50),
    chemin          TEXT DEFAULT '',
    pid             INTEGER DEFAULT 0
);

CREATE INDEX idx_svc_scan ON services(scan_id);

CREATE TABLE IF NOT EXISTS mises_a_jour (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(64) REFERENCES machines(scan_id) ON DELETE CASCADE,
    title           TEXT,
    date_installee  VARCHAR(30),
    resultat        INTEGER DEFAULT 0
);

CREATE INDEX idx_maj_scan ON mises_a_jour(scan_id);

-- ═══════════ 13. PERSISTANCE (archivée par scan) ═══════════

CREATE TABLE IF NOT EXISTS persistance (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(64) REFERENCES machines(scan_id) ON DELETE CASCADE,
    type            VARCHAR(50),
    nom             VARCHAR(512),
    valeur          TEXT,
    provenance      VARCHAR(50),
    utilisateur     VARCHAR(255)
);

CREATE INDEX idx_persist_scan ON persistance(scan_id);

-- ═══════════════════════════════════════════════════════════════════
-- 14. PORTS ÉCOUTE
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS ports_ecoute (
    id              SERIAL PRIMARY KEY,
    scan_id         VARCHAR(64) REFERENCES machines(scan_id) ON DELETE CASCADE,
    port            INTEGER,
    risque          VARCHAR(20),
    description     TEXT,
    processus       VARCHAR(255),
    pid             INTEGER DEFAULT 0
);

CREATE INDEX idx_ports_scan ON ports_ecoute(scan_id);

-- ═══════════════════════════════════════════════════════════════════
-- 15. RÈGLES DE SÉCURITÉ / DURCISSEMENT
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS hardening_rules (
    id              SERIAL PRIMARY KEY,
    regle           VARCHAR(512) UNIQUE NOT NULL,
    famille         VARCHAR(100) DEFAULT 'Windows',
    description     TEXT DEFAULT '',
    niveau          VARCHAR(20) DEFAULT 'Moyen',
    remediation     TEXT DEFAULT '',
    reference       VARCHAR(255) DEFAULT '',
    created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- ═══════════════════════════════════════════════════════════════════
-- 16. MIGRATIONS TRACKING
-- ═══════════════════════════════════════════════════════════════════

CREATE TABLE IF NOT EXISTS migrations (
    id              SERIAL PRIMARY KEY,
    name            VARCHAR(255) UNIQUE NOT NULL,
    applied_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
