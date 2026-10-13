# INVENTAIRE v5.1 -- Guide d'utilisation

Plateforme d'inventaire informatique, detection de vulnerabilites (CVE), conformite ANSSI/NIS2, gestion des licences et SBOM.

---

## Sommaire

1. [Acceder au dashboard](#1-acceder-au-dashboard)
2. [Deployer l'agent de collecte](#2-deployer-lagent-de-collecte)
3. [Importer un fichier JSON](#3-importer-un-fichier-json)
4. [Presentation des onglets](#4-presentation-des-onglets)
5. [Enrichissement CVE et vulnerabilites](#5-enrichissement-cve-et-vulnerabilites)
6. [Configuration de la cle API NVD](#6-configuration-de-la-cle-api-nvd)
7. [Export de donnees](#7-export-de-donnees)
8. [Configuration avancee](#8-configuration-avancee)
9. [Maintenance et depannage](#9-maintenance-et-depannage)

---

## 1. Acceder au dashboard

Ouvrez un navigateur web et accede a l'adresse du serveur :

| Environnement | URL |
|---|---|
| Acces local | `http://IP_DU_SERVEUR:5000/` |
| Via reverse proxy | `http://ADRESSE_PROXY:PORT/` |

> Le dashboard est une application web unique (SPA) accessible depuis n'importe quel navigateur moderne (Chrome, Firefox, Edge). Aucune installation n'est necessaire du cote client.

---

## 2. Deployer l'agent de collecte

L'agent est un script PowerShell qui analyse une machine Windows et envoie le rapport au serveur.

### 2.1 Depuis une machine Windows

**Etape 1** -- Ouvrir PowerShell en administrateur :
- Clic droit sur le menu Demarrer --> PowerShell (admin)
- Ou : `Win + X` --> PowerShell (admin)

**Etape 2** -- Executer la commande de collecte :
```powershell
$env:SRV='http://ADRESSE_DU_SERVEUR:PORT'; iex (irm ($env:SRV+'/collect.ps1'))
```

> Remplacez `ADRESSE_DU_SERVEUR:PORT` par l'adresse reelle du serveur (ex: `192.168.1.10:5000` ou `192.168.21.1:8080`).

**Etape 3** -- Attendre la fin de la collecte (generalement 1 a 4 minutes selon la machine). Un message de confirmation s'affiche.

**Etape 4** -- Verifier dans le dashboard que la machine apparait dans l'onglet "Machines".

### 2.2 Deploiement en masse (GPO / Intune)

Pour deployer sur plusieurs machines simultanement :

1. Telechargez le fichier `collect.bat` depuis la page de collecte
2. Distribuez-le via GPO (script de logon) ou Intune
3. Configurez la variable `SRV` dans le fichier pour pointer vers le serveur

### 2.3 Que collecte l'agent ?

| Categorie | Donnees collectees |
|---|---|
| **Materiel** | CPU, RAM, disques, batterie, GPU |
| **Systeme** | OS, version, build, architecture, hotfixes |
| **Logiciels** | 13 sources (registre, winget, choco, pip, npm, AppX, portables...) |
| **Reseau** | IP, MAC, DNS, passerelle, VPN, interfaces |
| **Securite** | Antivirus, pare-feu, BitLocker, Secure Boot, ASR, WDAC |
| **Processus** | Liste des processus actifs, memoire, CPU |
| **Services** | Services Windows, type de demarrage |
| **Ports** | Ports en ecoute, processus associes |
| **Persistance** | Taches planifiees, cle de registre, services |
| **Intune** | Detection Microsoft Intune / Company Portal |
| **Utilisateurs** | Utilisateur connecte, comptes admin locaux |

> L'agent est **read-only** : il ne modifie rien sur la machine analysee.

---

## 3. Importer un fichier JSON

Si l'agent ne peut pas joindre le serveur directement (reseau different, pare-feu...), vous pouvez generer le fichier JSON sur la machine cible puis l'importer manuellement.

### 3.1 Generer le fichier JSON

Sur la machine cible, ejecutez l'agent en mode local :
```powershell
$env:SRV=''; iex (irm ('http://ADRESSE_DU_SERVEUR:PORT/collect.ps1'))
```

Le fichier JSON est sauvegarde dans `%LOCALAPPDATA%\InventaireParc\` (ex: `inventaire_NOMPC_20260722_165226.json`).

### 3.2 Importer via le dashboard

1. Ouvrez le dashboard dans le navigateur
2. Cliquez sur le bouton **Import** (dans la barre superieure) ou **Import JSON** (dans l'onglet Vue Globale)
3. Glissez-dposez le fichier JSON dans la zone prevue, ou cliquez pour le selectionner
4. Les resultats s'affichent : nombre de machines importees, nombre de logiciels detectes, erreurs eventuelles

> Vous pouvez importer plusieurs fichiers en meme temps.

---

## 4. Presentation des onglets

### Vue Globale
Tableau de bord avec les indicateurs cles (KPI) : nombre de machines, logiciels, vulnerabilites, score de conformite, score de securite.

### Machines
Liste de toutes les machines scannees. Cliquez sur une machine pour voir les details : materiel, OS, logiciels installes, score securite, score conformite.

### Catalogue
Inventaire centralise de tous les logiciels detectes sur le parc, avec classification par categorie, risque, editeur, origine.

### Vulnerabilites
Recherche de CVE par logiciel. Enrichissement multi-sources :
- **NVD** (National Vulnerability Database)
- **CISA KEV** (Known Exploited Vulnerabilities)
- **MSRC** (Microsoft Security Response Center)

### Audit Securite
Centre de securite avec evaluation globale du parc : machines vulnerables, recommandations, etat du pare-feu, chiffrement.

### ANSSI (Conformite)
Score de conformite ANSSI/NIS2 pour chaque machine, base sur des regles de hardening (antivirus, pare-feu, BitLocker, Secure Boot, EOL...).

### Droits
Revue des droits et priviliges par machine : utilisateurs admin, comptes locaux, detection d'anomalies.

### Droits Logiciels
Classement des logiciels par niveau de privilige requis (admin, utilisateur, etc.).

### Licences
Gestion des licences logicielles : type, numero, date d'achat/expiration, cout, nombre de licences utilisees vs disponibles.

### Statistiques
Graphiques et statistiques : repartition OS, top logiciels, evolution du parc, risques.

### Historique
Historique des scans et des actions (installations, desinstalls, mises a jour).

### Briques Logicielles
Inventaire des composants logiciels (APIs, librairies, SaaS) avec analyse de souveraineté (pays d'origine, risque).

### SBOM
Software Bill of Materials : graphe de dependances pour chaque logiciel.

---

## 5. Enrichissement CVE et vulnerabilites

### Lancer un enrichissement

1. Allez dans l'onglet **Catalogue** ou **Vulnerabilites**
2. Selectionnez un logiciel
3. Cliquez sur le bouton **Enrichir CVE**
4. Le serveur interroge NVD, CISA KEV et MSRC
5. Les CVE, scores CVSS, descriptions et remediations s'affichent

### Batch enrichment

Vous pouvez enrichir plusieurs logiciels enonce depuis l'onglet **Vulnerabilites** via le bouton **Enrichissement masse**.

### Sources de donnees

| Source | Contenu | Delai |
|---|---|---|
| NVD | CVE completes avec scores CVSS | Rate-limite (50 req/30s avec cle API) |
| CISA KEV | Vulnerabilites exploitees actuellement | Cache local, mise a jour periodique |
| MSRC | Vulnerabilites Microsoft | API publique |

---

## 6. Configuration de la cle API NVD

### Pourquoi une cle API ?

Sans cle API, NVD limite a **5 requetes toutes les 30 secondes** (tres lent pour un parc important). Avec une cle API, le taux monte a **50 requetes toutes les 30 secondes**.

### Creer une cle API NVD

1. Allez sur **https://nvd.nist.gov/developers/request-an-api-key**
2. Cliquez sur **"Request an API Key"**
3. Remplissez le formulaire :
   - **Email** : votre adresse email professionnelle
   - **Nom de l'organisation** : nom de l'entreprise
   - **Description** : "Inventaire informatique - enrichissement CVE automatique"
4. Validez votre email (vous recevez un lien de confirmation)
5. Cliquez sur le lien de confirmation --> votre cle API s'affiche

> La cle API est une chaine de caracteres du type `xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx`.

### Configurer la cle API

**Option A -- Fichier .env** (recommande) :

Ouvrez le fichier `.env` a la racine du projet et modifiez la ligne :
```
NVD_API_KEY=votre-cle-api-ici
```

**Option B -- Variable d'environnement** :

```bash
# Linux / macOS
export NVD_API_KEY="votre-cle-api-ici"

# Windows (PowerShell)
$env:NVD_API_KEY="votre-cle-api-ici"
```

**Option C -- Docker** :

Ajoutez dans le fichier `.env` du cote Docker :
```
NVD_API_KEY=votre-cle-api-ici
```

Puis redemenagez le conteneur :
```bash
docker compose up -d
```

### Verifier que la cle fonctionne

Au demarrage du serveur, vous devez voir :
```
[INVENTAIRE v5.0] Serveur demarre sur http://0.0.0.0:PORT
```

Sans cle, vous verrez un avertissement :
```
[CVE] Pas de cle NVD API - taux limite ~5 req/30s (lent)
[CVE] Pour accelerer: set NVD_API_KEY=<votre_cle>
```

---

## 7. Export de donnees

Tous les onglets disposent d'un bouton **Export** permettant de telecharger les donnees dans differents formats :

| Format | Utilisation |
|---|---|
| **CSV** | Import dans Excel, Google Sheets, outils BI |
| **Excel (XLSX)** | Rapports format, tableaux cotes, partage |
| **JSON** | Integration avec d'autres outils, API |
| **PDF** | Impression, archivage, presentation |

### Exporter

1. Appliquez les filtres desires dans l'onglet
2. Cliquez sur le bouton **Export**
3. Choisissez le format
4. Le fichier se telecharge automatiquement

---

## 8. Configuration avancee

### Variables d'environnement

| Variable | Defaut | Description |
|---|---|---|
| `DB_TYPE` | `sqlite` | Type de base : `sqlite` ou `postgresql` |
| `DB_FILE` | `parc.db` | Chemin du fichier SQLite |
| `PORT` | `5000` | Port du serveur Flask |
| `NVD_API_KEY` | (vide) | Cle API NVD pour l'enrichissement CVE |
| `PG_HOST` | `localhost` | Host PostgreSQL |
| `PG_PORT` | `5432` | Port PostgreSQL |
| `PG_NAME` | `inventaire` | Nom de la base PostgreSQL |
| `PG_USER` | `postgres` | Utilisateur PostgreSQL |
| `PG_PASS` | (vide) | Mot de passe PostgreSQL |

### Passer de SQLite a PostgreSQL

1. Installez PostgreSQL
2. Creez la base : `CREATE DATABASE inventaire;`
3. Modifiez le fichier `.env` :
   ```
   DB_TYPE=postgresql
   PG_HOST=localhost
   PG_PORT=5432
   PG_NAME=inventaire
   PG_USER=postgres
   PG_PASS=votre_mot_de_passe
   ```
4. Installez le driver : `pip install psycopg2-binary`
5. Redemenagez le serveur

### Reverse Proxy (HTTPS)

Pour exposer le serveur sur Internet ou un autre reseau, placez un reverse proxy (Nginx, Caddy, ou le reverse proxy Synology) devant Flask. Voir `DEPLOY_SYNOLOGY.md` pour la configuration details sur Synology NAS.

---

## 9. Maintenance et depannage

### Sauvegarde des donnees

Le fichier principal a sauvegarder est `parc.db` (base SQLite) ou l'ensemble de la base PostgreSQL.

```bash
# SQLite
cp parc.db parc_backup_$(date +%Y%m%d).db

# PostgreSQL
pg_dump -U postgres inventaire > backup_$(date +%Y%m%d).sql
```

### Problemes courants

| Probleme | Cause | Solution |
|---|---|---|
| **L'agent ne se connecte pas** | Pare-feu ou IP incorrecte | Verifiez que le port du serveur est ouvert. Testez avec `Test-NetConnection IP_SERVEUR -Port 5000` |
| **Import "JSON invalide"** | Fichier corrompu ou non JSON | Re-generez le fichier sur la machine cible |
| **Score conformite bas** | Regles de hardening non respectees | Verifiez l'antivirus, pare-feu, BitLocker, Secure Boot sur les machines concernees |
| **Enrichissement CVE lent** | Pas de cle API NVD | Configurez une cle API (voir section 6) |
| **Serveur ne demarre pas** | Port deja utilise | Changez le port dans `.env` ou fermez l'autre programme |
| **404 sur les API** | Reverse proxy mal configure | Verifiez que le proxy forward toutes les routes `/api/*` |
| **Base de donnees absente** | Premier demarrage | La base est creee automatiquement au premier lancement |

### Logs

```bash
# Docker
docker compose logs -f flask
docker compose logs -f nginx

# Direct
# Les logs s'affichent dans le terminal ou sont dans server_err.log / server_out.log
```

### Mise a jour

1. Remplacez les fichiers du projet
2. Rebuild l'image Docker (si applicable) :
   ```bash
   docker compose build --no-cache
   docker compose up -d
   ```
3. Ou redemenagez le serveur directement :
   ```bash
   python serveur_collecte.py
   ```

---

## Informations techniques

| Composant | Technologie |
|---|---|
| Backend | Python 3, Flask |
| Frontend | JavaScript vanilla, HTML5, CSS3 |
| Base de donnees | SQLite (dev) / PostgreSQL (prod) |
| Agent | PowerShell 5.1+ |
| Conteneurisation | Docker + Nginx |
| APIs externes | NVD, CISA KEV, MSRC, GitHub, PyPI, NPM |
