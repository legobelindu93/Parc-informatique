# Changelog — Parc Informatique (I2SI)

All notable changes to this project across all files are documented below.

---

## `serveur_collecte.py`

### New Functions Added
| Function | Line | Description |
|---|---|---|
| `enrichir_logiciel(inst, nom)` | ~1590 | Enriches a software entry with type, signature, size, and fills missing fields |
| `classer_origine(inst, scan_id)` | ~1560 | Classifies software origin as "Windows", "Intune", or "Utilisateur" |
| `_get_editeur_info(editeur)` | ~1650 | Looks up editor information (country, website) from editor name |
| `enrich_software(conn, nom)` | (internal) | Multi-source CVE enrichment (NVD + CISA KEV + MSRC) |
| `batch_enrich(conn)` | (internal) | Batch enrichment for multiple software entries |
| `load_cisa_kev()` | (internal) | Loads CISA Known Exploited Vulnerabilities catalog |
| `auto_remplir_gouvernance(nom, editeur, source, desc, version)` | (internal) | Auto-fills governance fields |
| `detecter_categorie_licence(nom, editeur)` | (internal) | Detects licence category automatically |
| `analyser_licence(nom, editeur)` | (internal) | Analyses licence type and sub-type |
| `export_data_from_rows(data, columns, fmt, title)` | (internal) | Helper for exporting data in multiple formats |
| `_export_data(conn, fmt, query, columns, title, transform)` | (internal) | Generic export handler |
| `_systeme_ou_app(s)` | (internal) | Classifies install type as system or app |

### New API Routes Added
| Route | Method | Description |
|---|---|---|
| `/api/sites` | GET | List all sites |
| `/api/sites` | POST | Create a new site |
| `/api/sites/<int:sid>` | DELETE | Delete a site |
| `/api/departments` | GET | List all departments |
| `/api/departments` | POST | Create a new department |
| `/api/sbom` | GET | List SBOM entries |
| `/api/sbom/<int:sid>` | GET | SBOM detail |
| `/api/audit_log` | GET | List audit log entries |
| `/api/audit_log` | POST | Create audit log entry |
| `/api/compliance_rules` | GET | List compliance rules |
| `/api/compliance_rules` | POST | Create/update compliance rule |
| `/api/usage_stats` | GET | Usage statistics |
| `/api/editeurs` | GET | List editors with info |
| `/api/droits` | GET | Rights review per machine |
| `/api/droits/logiciels` | GET | Rights review per software |
| `/api/logiciels-licences` | GET | Combined software-licence list |
| `/api/cve/multi-enrich/<nom>` | POST | Multi-source CVE enrichment (NVD+CISA+MSRC) |
| `/api/cve/batch-enrich` | POST | Batch CVE enrichment |
| `/api/cve/sources` | GET | CVE sources information |
| `/api/export/logiciels.<fmt>` | GET | Export software list (csv, xlsx, json, pdf) |
| `/api/export/machines.<fmt>` | GET | Export machines list |
| `/api/export/vulnerabilites.<fmt>` | GET | Export vulnerabilities |
| `/api/export/licences.<fmt>` | GET | Export licences |
| `/api/export/rapport.<fmt>` | GET | Full park report (pdf, json) |
| `/api/historique` | GET | Alias for `/api/historique_actions` |

### New Route Behavior
- **`/api/conformite`**: Now performs real-time compliance checking against each machine's reported security data (antivirus, firewall, bitlocker, secure boot, updates, EOL, unauthorized software), returns score, and queries `compliance_rules` table.
- **`/api/cve_enrich/<nom>`**: Changed from NVD-only to use multi-source enrichment (NVD + CISA KEV + MSRC).
- **`/api/licences` (POST)**: Now supports both INSERT and UPDATE (via `id` field). Added fields: `categorie_licence`, `nb_utilisees`, `date_achat`, `numero_licence`, `editeur`. Logs actions to audit log.
- **`/api/licences/<int:lid>` (DELETE)**: Now logs deletion to audit log.
- **`/api/historique_actions`**: Added try/except on limit parameter parsing for robustness.

### Modifications to Existing Code
- **`api_logiciel(nom)`**: Added auto-licence detection (licence_auto) and auto-governance (gouvernance_auto) to response. Added editor_info lookup. Now calls `enrichir_logiciel()` on installations.
- **`api_stats_adv()`**: Updated to return more comprehensive stats.
- **Dashboard serving**: `serve_dashboard()` now properly returns `index.html`.
- Import section: Added many new imports (`datetime`, `hashlib`, `io`, `csv`, `json`, `re`, `os`, `uuid`, `OpenSSL`-related, `tempfile`, `TextIOWrapper`, Gzip support).

### Bug Fixes
- Fixed `api_cve_enrich` to properly return from cache when existing CVE data found.

---

## `dashboard/app.js`

### New Functions Added
| Function | Description |
|---|---|
| `badgeOrigine(origine)` | Renders origin badge (Windows/Intune/Utilisateur) |
| `badgeLic(cat)` | Renders licence category badge |
| `badgeSource(src)` | Renders install source badge |
| `jesc(str)` | JavaScript-safe string escaping |
| `loadSecurite()` | Loads Security Centre tab (KPIs, top vulnerable machines, recommendations, firewall, encryption) |
| `loadSBOM()` | Loads SBOM data and dependencies |
| `renderSBOM(data)` | Renders SBOM table and dependency graph |
| `filterSBOM()` | Filters SBOM by search query |
| `safeParse(val, fallback)` | Safe JSON parse with fallback |
| `renderMachineSwRows(rows)` | Renders machine software table rows |
| `filterMachineSw()` | Filters machine software by name/origine/risk/EOL |
| `fldHtml(label, html)` | Renders a field with raw HTML value |
| `toggleExport(prefix)` | Toggles export dropdown menu |
| `exportData(type, format)` | Triggers file download for export |
| `loadDroits()` | Loads droits (rights) tab |
| `toggleDroitDetail(nomPc)` | Toggles expand/collapse for machine droit details |
| `filterDroits()` | Filters droits by search/domaine/actif/metier/niveau |
| `badgeNiveauDL(n)` | Renders niveau badge in droits logiciels view |
| `loadDroitsLogiciels()` | Loads droits logiciels (software by privilege level) |
| `filterDroitsLogiciels()` | Filters droits logiciels view |
| `showLicenceDetail(nom, editeur)` | Opens a licence detail drawer |
| `afficheChamp(label, value)` | Renders a label/value pair |
| `window.showLicenceFormFromApp(...)` | Opens licence form from application context |
| `deleteLicenceApp(nom, editeur)` | Deletes licence by software name |
| `filterLicencesApp()` | Filters licences by search/category/editor |

### Modifications to Existing Code
- **`showLogiciel(nom)`**: Now displays editor country flag, auto-detected licence categories, governance auto-fill. CVE enrichment button text updated to mention NVD+CISA+MSRC. Added CVE source badges (NVD/CISA KEV/MSRC). Added CWE, publication date, and remediation info to CVE cards. Size display now handles "Inconnue" gracefully.
- **`showMachine(scanId)`**: Added `encodeURIComponent` for scanId. Software table now has origin column, inline filters (search, origine, risk, EOL), and uses `renderMachineSwRows()`.
- **`loadConformite()`**: Now merges compliance rules from both `/api/conformite` and `/api/compliance_routes`. Shows family badge and points/max_points.
- **`saveGouvernance(nom)`**: Updated to persist auto-fill changes.
- **`saveLicence(id)`**: Now sends `categorie_licence` field. Uses `.nav-item[data-tab="licences"]` selector instead of obsolete `.tab-btn`.
- **`esc(str)`**: Improved to handle more edge cases.
- **`loadHistorique()`**: Changed arrow rendering from `→` to `-&gt;` for HTML safety.
- **`loadLicences()`**: Added per-editeur-filter and licence category filter support.
- **`filterCatalogue()`**: Now includes origin, type, editeur type, source, and metier filters.

### Global Event Handlers
- Added document click handler to close export dropdowns on outside click.
- Added global search keyboard shortcut handler (Ctrl+K).

---

## `dashboard/index.html`

### New HTML Sections Added
| Section | ID | Description |
|---|---|---|
| Security Centre | `pane-securite` | Full security tab with KPIs, vulnerable machines, recommendations, firewall/chiffrement bars |
| SBOM | `pane-sbom` | Software Bill of Materials tab with dependency graph |
| Revue des Droits | `pane-droits` | Rights review by machine with expandable details |
| Droits Logiciels | `pane-droits-logiciels` | Rights review by software |
| Notification Toast | `toast-container` | Toast notification container |

### Modified HTML Sections
- **All panes** (catalogue, machines, vulnerabilites, licences, conformite, historique, statistiques): Now have `pane-hero` headers with titles, subtitles, and action buttons. Added `aria-label` and `role` attributes for accessibility.
- **Toolbars**: All now use `search-input-wrap` with inline search SVG icons. Added many new filter dropdowns (origin, type, editeur type, source, metier, domaine, niveau etc.).
- **Export dropdowns**: All relevant panes now have export buttons with CSV/Excel/JSON/PDF options.
- **Drawers**: All three drawers (machine, sw, licence) redesigned with SVG icons, better header layout. Added `role="dialog"`, `aria-modal`, `aria-label` attributes. Inner tabs use `role="tablist"` and `role="tab"` with `aria-selected`/`aria-controls`.
- **Conformite pane**: Restructured to use `conformite-layout` with sticky score panel on left and rules list on right. Added compliance badges (ANSSI/NIS2).
- **Statistiques pane**: Now uses `stats-quad-grid` layout. Added `role="region"` and `aria-label` to all panes.
- **Licences pane**: Added inline "Ajouter une licence" button in header. Added licence category and editor filters.
- **Inline scripts**: Added JavaScript for theme toggle, sidebar toggle, navigation with breadcrumbs, refresh current tab, keyboard shortcuts (Ctrl+K, Escape), and progress bar utility.

### New CSS Classes (in inline `<style>`)
- `.badge-autodetected`, `.badge-oss`, `.badge-gratuit`, `.badge-payant`, `.badge-freemium`, `.badge-essai`, `.badge-donation`, `.badge-adware`, `.badge-abandon`
- `.badge-windows`, `.badge-intune`, `.badge-user`, `.badge-microsoft`, `.badge-tiers`
- `.badge-reg`, `.badge-appx`, `.badge-winget`, `.badge-choco`, `.badge-portable`, `.badge-path`, `.badge-start`, `.badge-winfeat`, `.badge-pip`, `.badge-npm`, `.badge-composer`, `.badge-wsl`
- `.badge-danger`, `.badge-warning`, `.badge-success`, `.badge-info`, `.badge-dev`, `.badge-inconnu`
- `.stat-card.accent`, `.stat-card.info`, `.stat-card.purple`

---

## `dashboard/style.css`

### New CSS Sections Added
- **FORM CONTROLS**: Unified input/textarea/select styling with focus states, placeholder styling, search cancel button.
- **Search Input Wrap**: `.search-input-wrap` with absolute positioned SVG icon, padded input.
- **PANELS / CARDS**: `.panel-title-badge` with danger/warning variants. Stats grid gap/transition updates.
- **BAR CHARTS**: `.bar-row`, `.bar-lbl`, `.bar-track`, `.bar-fill`, `.bar-val` with transitions.
- **DATA TABLES**: Sticky table headers, row hover states, progress bar in cells.
- **BADGES (extended)**: Many new badge variations (as listed above in index.html section).
- **OVERLAY & DRAWER (refactored)**: Drawer icons with gradients, `drawer-header-info` layout, drawer transitions with `var(--transition-slow)`.
- **INNER TABS**: Hidden scrollbar, `pane-in` animation.
- **FIELD GRID**: Updated spacing, monospace font via variable, `--text-disabled` for empty values.
- **STATES**: `.skeleton` loader with shimmer animation.
- **CVE CARDS**: Hover effects, CWE/publication date styling, remediation box styling.
- **COMPLIANCE / CONFORMITE LAYOUT**: `.conformite-layout` grid, sticky score panel, score ring display, compliance badges.
- **SECURITY CENTER**: `.securite-grid` and `.securite-grid-2` layouts.
- **STATS QUAD GRID**: `.stats-quad-grid` for 4-panel statistics.
- **EVOLUTION CHART**: `.evolution-chart` flex layout.
- **HISTORY / TIMELINE**: Refined history items with grid layout.
- **ALERTS / CALLOUTS**: Three alert variants (info, warning, danger).
- **EXPORT DROPDOWN**: `.export-dropdown`, `.export-menu` with hover states.
- **LICENCE FORM**: `.licence-form-grid`, `.form-group`, `.form-label`.
- **TOAST NOTIFICATIONS**: Fixed position bottom-right, slide-in animation.
- **AUTO-DETECTED BADGE**: `.badge-autodetected` superscript style.
- **RESPONSIVE**: Breakpoints at 1100px, 900px, 600px for stack layouts, sidebar mobile behavior.
- **HIGH CONTRAST MODE**: `@media (forced-colors: active)` rules.
- **PRINT**: `@media print` rules hiding UI chrome.
- **UTILITY CLASSES**: `.truncate`, `.sr-only`, `.flex`, `.flex-col`, `.items-center`, `.gap-*`, `.mt-*`, `.mb-*`.

### Variables Changed
- `--input-bg`, `--input-border`, `--input-focus-border`, `--input-placeholder`
- `--color-accent-glow`, `--color-accent`, `--color-accent-dim`, `--color-accent-text`
- `--color-danger-dim`, `--color-danger-text`, similar for success, warning, purple, cyan, orange
- `--card-bg`, `--card-border`, `--table-border`, `--table-header-bg`, `--table-row-hover`
- `--drawer-bg`, `--drawer-border`
- `--bg-elevated`, `--bg-surface`, `--bg-subtle`, `--border-hairline`, `--border-strong`
- `--nav-item-hover`
- `--space-1` through `--space-5` spacing scale
- `--radius-xs`, `--radius-sm`, `--radius-md`, `--radius-lg`, `--radius-full`
- `--shadow-md`, `--shadow-lg`, `--shadow-xl`
- `--transition`, `--transition-fast`, `--transition-slow`
- `--font-sans`, `--font-mono`

---

## `dashboard/collect.html`

### Modifications
- **Removed** Google Fonts preconnect and `Inter` font import; now uses `Segoe UI` system font stack.
- **CSS variables**: Slightly adjusted color values (e.g., `--bg: #0f1117` instead of `#0e1015`, `--surface-2: #22263a` instead of `#1e212a`, `--radius` reduced from 8px to 6px).
- **Removed emojis** from headings (e.g., "📦 Méthode 1" → "Méthode 1", "📋 Copier" → "Copier").
- **Button styles**: Smaller padding (8px 20px vs 10px 24px), smaller font size (12.5px vs 13px).
- **Copy feedback**: "✅ Copié !" → "Copié !"
- **Return link**: "← Retour au dashboard" → `&larr; Retour au dashboard` (HTML entity).

---

## `agent/agent_pc.ps1`

### New Functions Added
| Function | Description |
|---|---|
| `Compute-Fingerprint` | Computes SHA-256 fingerprint of installed software for cache invalidation |

### New Features
- **Smart Caching**: Software inventory is cached to `%LOCALAPPDATA%\InventaireParc\`. A fingerprint of installed software is computed; if unchanged, the cache is reused, dramatically speeding up re-scans.
- **Intune Detection**: New `$intune` object detects Microsoft Intune presence via registry, enrollment entries, and Company Portal app.
- **New Collection Sources**:
  - **Windows Features/Roles**: Collected via `dism /online /get-features`.
  - **PATH executables**: Scans all directories in `%PATH%` for executables.
  - **WSL Distributions**: Lists installed WSL distros via `wsl -l -q`.
  - **Composer (PHP)**: Lists global Composer packages.
  - **Start Menu shortcuts**: Scans `.lnk` files in Start Menu for installed executables.
  - **AppxProvisioned packages**: Collected via `Get-AppxProvisionedPackage`.
  - **KB/Windows Updates**: Collected separately from filtered registry.
- **Fingerprint-based Caching**: Entire collection (steps 5-7) is cached to disk; re-scans are near-instant if no software changes are detected.

### Modifications to Existing Code
- **Version**: Bumped from `5.0` to `5.1`.
- **MAC address collection**: Primary via `Get-NetAdapter`, fallback `Get-CimInstance`, then `Get-WmiObject`. Removed `Get-WmiObject` as primary.
- **Processor/RAM/Disks/GPU/Battery**: All switched from `Get-WmiObject` to `Get-CimInstance` with WMI fallback.
- **Admin detection**: Changed from `[Security.Principal.WindowsPrincipal]` to checking `$adm -match $env:USERNAME`.
- **Systeminfo fallback**: Added comprehensive `Parse-SystemInfo` call to fill missing fields (domain, manufacturer, model, OS name, RAM, BIOS version, install date).
- **Gateway detection**: Added multiple fallback layers: `Get-NetRoute` → CIM → WMI → `ipconfig` (French + English patterns).
- **Network interface**: Now filters out virtual adapters (VMware, Hyper-V, Docker, WSL, etc.) for primary MAC/IP.
- **Hosts file**: Removed `Select-Object -First 30` limit.
- **Services/Processes/Ports/ScheduledTasks**: Removed `Select-Object -First` limits to capture all items.
- **Software cataloging**: Rewritten `Add-RegistryItems` helper with better system component filtering. `Appx` limit of 100 removed. Winget parsing improved. Choco output parsing improved. PIP limit of 50 removed.
- **Portable scanning**: Now scans deep paths (Program Files, ProgramData, AppData, etc.) to depth 5, and shallow paths (Desktop, Downloads, Documents, TEMP) to depth 2. Extended file types to include `.com`, `.msi`, `.msp`, `.msu`, `.cab`, `.appx`, `.appxbundle`, `.jar`, `.ps1`, `.bat`, `.vbs`.
- **EOL/Blacklist matching**: Changed from `[regex]::Escape` exact match to `\b` word-boundary matching for more accurate categorization.
- **Categorization**: Added many new categories: `Reseau`, `SupportDistant`, `Multimedia`, `Sauvegarde`, `Pilote`, `Gestion`, `OutilsSysteme`, `Jeu`.
- **Enrichment step**: Now also cached when cache is valid.
- **Report submission**: Now multi-try with compression fallback. Saves a local JSON backup file to `OutputDir`. Errors are reported individually for each attempt.
- **Collection progress**: Changed step label from `[5/13] Logiciels (8 sources)` to `[5/13] Logiciels...`. Changed `[6/13] Portables...` to `[6/13] Portables (scan profond)...`.

### Bug Fixes
- Fixed admin detection to use actual group membership rather than WindowsPrincipal (which could give false negatives on non-elevated but admin-rights processes).
- Fixed MAC/IP detection to filter out virtual network adapters.
- Fixed domain detection to try French "Domaine" and English "Domain" from systeminfo output.
- Fixed hotfix enumeration to remove 50-item limit.

---

## `data/software_db.json`

### Changes
- **Massive expansion**: The software database grew from approximately ~100 entries to several hundred entries.
- **New entries added** (non-exhaustive):
  - **Development tools**: Sublime Text, Atom Editor, Java Development Kit, Git Bash, CMake, MSBuild, Gradle, AWS CLI, Azure CLI, Google Cloud SDK, Vault, Consul, Trivy
  - **Database tools**: MySQL CLI, MySQL Server, SQL Server, PostgreSQL CLI, PostgreSQL Server, DBeaver, HeidiSQL, pgAdmin, MongoDB Server, MongoDB Shell, SQLite3 CLI, Redis Server, Oracle Database, Oracle SQL Developer, Tableau, Power BI Desktop, SSMS Setup MSI
  - **CAD/Creative**: AutoCAD, Autodesk Inventor, Revit, 3ds Max, Maya, SOLIDWORKS, SketchUp, MATLAB, Fusion 360, Unity Editor
  - **Adobe Suite**: Illustrator, InDesign, Premiere Pro, After Effects, Audition, Lightroom Classic, Acrobat Reader
  - **Security**: KeePass, ProcDump, Handle, SigCheck, Strings (Sysinternals suite), Nessus, OpenVPN, VeraCrypt MSI, KeePass MSI
  - **Virtualization**: VMware Workstation, VMware Workstation Player, VirtualBox, Docker Compose, Docker Desktop, Vagrant
  - **Multimedia**: GIMP, Inkscape, mpv, foobar2000, WinZip, PeaZip
  - **Utilities**: SumatraPDF, Foxit PDF Reader, CPU-Z, GPU-Z, Greenshot, ShareX, Microsoft PowerToys, Paint, Calculator, PowerShell Core, System Configuration, Control Panel, MMC, DxDiag, System Information, Resource Monitor, Disk Cleanup, Disk Defragmenter, Snipping Tool, Remote Desktop, Telnet, OpenSSH, DNS Lookup, Traceroute, Ping, Netstat, IPConfig, WMIC, Character Map, WordPad, Magnifier, On-Screen Keyboard, Narrator, Performance Monitor
  - **Drivers**: NVIDIA Control Panel, NVIDIA SMI, AMD Radeon Software
  - **Remote/Support**: TeamViewer, AnyDesk, MobaXterm, mRemoteNG, VNC Viewer, TeamViewer Host MSI
  - **Backup**: Veeam Backup, Veeam Agent, Veeam Console, Acronis Cyber Protect
  - **Gaming**: GOG Galaxy, Ubisoft Connect
  - **Enterprise/SAP**: SAP GUI, SAP Logon, QuickBooks Desktop, Sage 50, Sage 1000
  - **MSI installers**: 7-Zip MSI, Google Chrome Enterprise MSI, Microsoft Edge Enterprise MSI, Firefox Setup MSI, Office 2021 Pro Plus MSI, .NET Framework 4.8 MSI, .NET 8.0 Runtime MSI, VC Redist 2015-2022 MSI, OpenVPN MSI, Zoom MSI, WinSCP MSI, PuTTY MSI, SSMS Setup MSI, VeraCrypt MSI, KeePass MSI
- **Each entry** includes: `nom_produit`, `editeur`, `pays`, `site_officiel`, `type_licence`, `categorie`, `plateforme`, `cpe`, `anssi_statut`, `eol`.

---

## `parc.db` (binary, not diffable)

The SQLite database grew significantly (from 2.8 MB to ~51 MB), reflecting new tables and data:
- New tables: `sites`, `departments`, `sbom`, `audit_log`, `compliance_rules`, `usage_stats`, `cve_cache` (expanded)
- New columns in `licences`: `categorie_licence`, `nb_utilisees`, `date_achat`, `numero_licence`, `editeur`
- New columns in `machines`: additional security/compliance score fields
- Schema updates to support all new API endpoints

---

## Summary Statistics

| Metric | Value |
|---|---|
| Files changed | 8 (+1 binary) |
| Insertions | ~8,773 lines |
| Deletions | ~1,082 lines |
| New API routes | 25+ |
| New HTML sections | 4 |
| New JS functions | 25+ |
| New CSS sections | 25+ |
| New software DB entries | ~150+ |
| Agent version | 5.0 → 5.1 |
