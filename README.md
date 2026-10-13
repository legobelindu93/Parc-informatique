# INVENTAIRE v5.1 — Gestion de Parc & Cyber-Inventaire

Plateforme complète d'inventaire informatique, détection de vulnérabilités (CVE), conformité ANSSI/NIS2, gestion des licences et SBOM — développée dans le cadre d'un stage Cyber I2SI.

```
program/
├── agent/
│   └── agent_pc.ps1              # Agent PowerShell de collecte (envoi JSON → serveur)
├── dashboard/
│   ├── index.html                 # Dashboard SPA (14 onglets)
│   ├── collect.html               # Page de déploiement de l'agent
│   ├── briques.html               # Inventaire des briques logicielles
│   ├── library.html               # Bibliothèque (placeholder)
│   ├── app.js                     # Logique front-end (API, rendu, graphiques)
│   └── style.css                  # Design system (thème clair/sombre)
├── data/
│   ├── software_db.json           # Base locale de ~4000 logiciels
│   └── latest_versions.json       # Cache des dernières versions (~2600 entrées)
├── serveur_collecte.py            # Serveur Flask principal (API REST, 60+ routes)
├── database.py                    # Abstraction base SQLite
├── cve_service.py                 # Enrichissement CVE (NVD + CISA KEV + MSRC)
├── enrichissement.py              # Enrichissement logiciel depuis base locale
├── export_service.py              # Export CSV / XLSX / JSON / PDF
├── version_editor_service.py      # Dernières versions + éditeurs (pays, risques)
├── schema.sql                     # Schéma de la base
├── editeurs.json                  # ~350 éditeurs avec pays, risque souveraineté
├── parc.db                        # Base SQLite
├── cisa_kev_cache.json            # Cache CISA Known Exploited Vulnerabilities
└── .env                           # Clé API NVD
```

## Fonctionnalités

- **Inventaire automatisé** — Collecte matériel, OS, logiciels (13 sources), processus, services, ports, tâches planifiées, persistance, mises à jour
- **Détection de vulnérabilités** — Agrège NVD + CISA KEV + MSRC par logiciel avec scoring automatique
- **Conformité ANSSI / NIS2** — Scoring en temps réel par machine selon des règles de hardening
- **Gestion des licences** — Auto-détection, suivi de consommation, catalogue approuvé
- **SBOM** — Génération de Software Bill of Materials avec graphe de dépendances
- **Analyse de souveraineté** — Éditeurs classés par pays et risque (Faible/Moyen/Élevé/Critique)
- **Export multifformat** — CSV, Excel, JSON, PDF
- **Agent intelligent** — Cache SHA-256 pour collectes incrémentales quasi-instantanées

## Démarrage rapide

```bash
python serveur_collecte.py
# Dashboard : http://localhost:5000/
```

Depuis un poste du parc, ouvrir `http://<serveur>:5000/collect` et suivre les instructions.

## Architecture

```
Postes Windows                Serveur Flask                   Dashboard
┌─────────────┐   POST JSON   ┌──────────────────────┐   ┌──────────────────┐
│ agent_pc.ps1 │ ──────────→  │ serveur_collecte.py  │ ← │ index.html       │
│ (PowerShell) │              │ cve_service.py        │   │ app.js           │
│ · matériel   │              │ enrichissement.py     │   │ style.css        │
│ · logiciels  │              │ version_editor..py    │   └──────────────────┘
│ · sécurité   │              │ export_service.py     │
└─────────────┘                                            │ database.py           │
                              │ SQLite                │
                              └──────────────────────┘
```

## Configuration

| Variable | Défaut | Rôle |
|---|---|---|
| `DB_FILE` | `parc.db` | Fichier SQLite |
| `PORT` | `5000` | Port serveur Flask |
| `NVD_API_KEY` | — | Clé API NVD (50 req/30s) |

## Stack technique

- **Backend** : Python 3, Flask
- **Frontend** : JavaScript vanilla, HTML5, CSS3 (design system avec variables CSS)
- **Base de données** : SQLite
- **Agent** : PowerShell 5.1+
- **APIs externes** : NVD, CISA KEV, MSRC, GitHub, PyPI, NPM
- **Bibliothèques** : fpdf, openpyxl, requests
