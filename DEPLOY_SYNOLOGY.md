# Déploiement sur Synology NAS (Container Manager)

## Prérequis

- Synology NAS avec **Container Manager** (installé depuis le Centre de Paquets)
- Accès à **File Station** ou **SSH** pour copier les fichiers
- Port **9080** libre sur le NAS (ou adapter selon ton choix)

---

## 1. Configuration de Container Manager (Docker) sur le NAS

### 1.1 Installation

1. **Centre de Paquets** → recherche **Container Manager** → **Installer**
2. Ouvre Container Manager une fois installé

### 1.2 Paramètres du registre (important pour le build)

Container Manager doit télécharger `python:3.11-slim` (plusieurs centaines de Mo).

**Réglages recommandés :**

- **Container Manager → Registre → Paramètres**
  - Cocher **"Activer le registre Docker Hub"**
  - Si le téléchargement est lent : ajoute un miroir (registry mirror) :
    1. Connecte-toi en SSH sur le NAS
    2. Modifie `/etc/docker/daemon.json` :
    ```json
    {
      "registry-mirrors": [
        "https://mirror.gcr.io",
        "https://docker.mirrors.ustc.edu.cn"
      ]
    }
    ```
    3. Redémarre Docker :
    ```bash
    sudo synosystemctl restart pkgctl-ContainerManager
    ```

- **Timeouts** : Sur Synology, les builds peuvent être lents. Dans **Container Manager → Registre → Paramètres**, augmente les timeouts si nécessaire.

### 1.3 Ressources allouées

Par défaut, Container Manager utilise les ressources du NAS sans limite. Pour éviter qu'un scan ou un build ne sature le CPU :

- **Container Manager → Conteneur** → sélectionner le conteneur → **Modifier** → onglet **Limites**
  - CPU : 50% max (sur un NAS 4 cœurs)
  - RAM : 1 Go pour flask, 256 Mo pour nginx

Ou directement dans `docker-compose.yml` :

```yaml
services:
  flask:
    build: .
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 1G
        reservations:
          memory: 512M
  nginx:
    image: nginx:alpine
    deploy:
      resources:
        limits:
          cpus: '0.5'
          memory: 256M
```

### 1.4 Réseau Docker

Par défaut, `docker-compose` crée un réseau `inventaire_default`. Les conteneurs se voient via leurs noms de service (`flask`, `nginx`).

Pour utiliser un réseau personnalisé (utile si tu veux connecter d'autres conteneurs) :

```yaml
networks:
  inventaire-net:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  flask:
    networks: [inventaire-net]
  nginx:
    networks: [inventaire-net]
```

### 1.5 Logs des conteneurs

Les logs Docker s'accumulent et peuvent remplir le disque système. Limite leur taille :

```yaml
services:
  flask:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
  nginx:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### 1.6 Redémarrage automatique

Synology applique `restart: unless-stopped` correctement. Après un reboot du NAS, les conteneurs redémarrent seuls. Vérification :

```bash
sudo docker ps --format "table {{.Names}}\t{{.Status}}\t{{.RestartCount}}"
```

---

## 2. Structure des dossiers

Crée l'arborescence dans un partage Synology (ex: `docker/inventaire/`) :

```
/volume1/docker/inventaire/
├── docker-compose.yml
├── nginx.conf
├── .env
├── data/                  # uploads, exports...
├── db/                    # base SQLite
```

### Via File Station
1. Ouvre **File Station**
2. Va dans `docker/` (ou crée-le)
3. Crée les dossiers : `inventaire/`, `inventaire/data/`, `inventaire/db/`

---

## 3. Fichiers à copier

Copie ces fichiers du projet vers `/volume1/docker/inventaire/` :

| Fichier | Rôle |
|---------|------|
| `docker-compose.yml` | Configuration des conteneurs |
| `nginx.conf` | Reverse-proxy Nginx |
| `.env` | Variables d'environnement |

---

## 4. Configuration Docker Compose

```yaml
services:
  flask:
    build: .
    container_name: inventaire-flask
    restart: unless-stopped
    env_file:
      - .env
    environment:
      - PORT=5000
      - DB_FILE=db/parc.db
    volumes:
      - /volume1/docker/inventaire/data:/app/data
      - /volume1/docker/inventaire/db:/app/db
    expose:
      - "5000"
    healthcheck:
      test: ["CMD-SHELL", "python -c \"import urllib.request; urllib.request.urlopen('http://localhost:5000/api/stats')\""]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 15s
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  nginx:
    image: nginx:alpine
    container_name: inventaire-nginx
    restart: unless-stopped
    ports:
      - "9080:80"
    volumes:
      - ./nginx.conf:/etc/nginx/conf.d/default.conf:ro
    depends_on:
      flask:
        condition: service_healthy
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
```

### Explication des paramètres

| Paramètre | Rôle |
|-----------|------|
| `build: .` | Construit l'image localement (télécharge `python:3.11-slim` puis installe les dépendances). |
| `container_name:` | Nom fixe pour identifier le conteneur dans Container Manager. |
| `restart: unless-stopped` | Redémarrage automatique après reboot ou crash. Ne redémarre pas si arrêté manuellement. |
| `env_file:` | Charge les variables depuis `.env`. |
| `environment:` | Surcharge des variables (PORT, DB_FILE). |
| `volumes: (bind mount)` | Monte un dossier du NAS dans le conteneur. `hôte:conteneur`. |
| `expose:` | Port interne accessible sur le réseau Docker (pas à l'extérieur). |
| `ports:` | Mappe un port du NAS vers le conteneur. `NAS:conteneur`. |
| `depends_on:` | Attend que flask soit sain avant de démarrer nginx. |
| `healthcheck:` | Vérifie que l'API répond toutes les 30s. |
| `logging:` | Limite la taille des logs à 10 Mo, 3 fichiers max. |

### Variables d'environnement (`.env`)

```
PORT=5000
DB_FILE=db/parc.db
DB_TYPE=sqlite
```

---

## 5. Configuration Nginx

```nginx
server {
    listen 80;
    server_name _;

    client_max_body_size 100M;
    proxy_read_timeout 300s;
    proxy_send_timeout 300s;

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;

    location / {
        proxy_pass http://flask:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;
    }
}
```

### Rôle de chaque directive

| Directive | Rôle |
|-----------|------|
| `listen 80` | Port interne du conteneur Nginx (mappé au port 9080 du NAS). |
| `client_max_body_size 100M` | Upload de fichiers jusqu'à 100 Mo. |
| `proxy_read_timeout 300s` | Timeout long pour l'import de données (5 min). |
| `proxy_pass http://flask:5000` | Redirige vers le service Flask (résolu via le réseau Docker). |
| `proxy_set_header` | Transmet l'IP réelle et le protocole à Flask. |
| `proxy_buffering off` | Streaming sans buffer (logs en temps réel). |
| `add_header X-Frame-Options` | Bloque le clickjacking. |
| `add_header X-Content-Type-Options` | Empêche le MIME-sniffing. |

---

## 6. Déploiement

### Option A : Container Manager (interface graphique)

1. **Container Manager → Projet → Créer**
2. Nom : `inventaire`
3. Dossier : sélectionne `/volume1/docker/inventaire/`
4. Laisse **"Importer depuis docker-compose.yml"** coché
5. Valide

**Ce qui se passe :**
1. Téléchargement de `nginx:alpine`
2. Build de l'image Flask (python + dépendances) → **plusieurs minutes**
3. Création du réseau Docker
4. Démarrage de `inventaire-flask` puis `inventaire-nginx`
5. Application du `restart: unless-stopped`

**Si le build échoue** (timeout) :
- **Container Manager → Projet** → sélectionne `inventaire` → **Action → Build**
- Ou via SSH : `docker-compose build --no-cache flask`

### Option B : SSH

```bash
# Copier les fichiers
scp -r ./projet/* admin@IP_DU_NAS:/volume1/docker/inventaire/

# SSH
ssh admin@IP_DU_NAS

# Lancer (depuis le dossier)
cd /volume1/docker/inventaire
docker-compose up -d

# Voir les logs
docker-compose logs -f

# Arrêter
docker-compose down

# Rebuild
docker-compose build flask
docker-compose up -d
```

---

## 7. Commandes Docker utiles sur Synology

```bash
# Lister les conteneurs
sudo docker ps -a

# Voir les logs en direct
sudo docker logs -f inventaire-flask

# Exécuter une commande dans un conteneur
sudo docker exec -it inventaire-flask sh

# Copier un fichier depuis le conteneur
sudo docker cp inventaire-flask:/app/parc.db ./backup.db

# Voir la consommation
sudo docker stats

# Nettoyer les images inutilisées
sudo docker image prune -a

# Voir le réseau
sudo docker network ls
sudo docker network inspect inventaire_default
```

---

## 8. Maintenance

### Mise à jour de l'application

```bash
cd /volume1/docker/inventaire/
# 1. Remplacer les fichiers du projet (serveur_collecte.py, etc.)
# 2. Rebuild l'image
docker-compose build --no-cache flask
# 3. Redémarrer
docker-compose up -d
```

Depuis Container Manager : **Projet → inventaire → Action → Build** puis **Redémarrer**.

### Sauvegarde des données

Les données sont dans `/volume1/docker/inventaire/` (partage Synology) :

| Dossier | Contenu |
|---------|---------|
| `data/` | exports, uploads, fichiers générés |
| `db/parc.db` | base de données SQLite complète |

→ Inclus ces dossiers dans **Hyper Backup** comme n'importe quel dossier partagé.

### Logs

```bash
# Logs en temps réel
docker-compose logs -f flask
docker-compose logs -f nginx

# Dernières 50 lignes
docker-compose logs --tail=50 flask

# Sauvegarder les logs dans un fichier
docker-compose logs flask > /volume1/docker/inventaire/logs/flask.log
```

---

## 9. Problèmes courants

| Problème | Cause | Solution |
|----------|-------|----------|
| **Port 9080 déjà utilisé** | Conflit avec une app Synergy | Change le port dans docker-compose.yml (`9090:80`). Vérifie dans **Panneau de configuration → Portail d'applications**. |
| **Build échoue (timeout)** | NAS lent, image volumineuse | Dans **Container Manager → Registre → Paramètres**, augmente le timeout. Ou utilise `docker-compose build --no-cache` en SSH. |
| **Conteneur redémarre en boucle** | Healthcheck qui échoue | Vérifie que Flask écoute bien sur le port 5000. Teste : `docker exec inventaire-flask curl http://localhost:5000/api/stats` |
| **Base de données absente** | Volume bind mount vide | wsgi.py crée parc.db au premier lancement. Vérifie les permissions du dossier `db/` (lecture/écriture pour l'utilisateur du conteneur). |
| **Permission denied sur data/** | Le conteneur tourne en root mais le dossier appartient à admin | `sudo chown 1000:1000 /volume1/docker/inventaire/data` ou change les droits avec File Station. |
| **Nom de résolution DNS** | Le réseau Docker ne résout pas les noms | Vérifie que les deux conteneurs sont sur le même réseau : `docker network inspect inventaire_default` |
| **Lenteur au démarrage** | Le healthcheck attend 15s avant de commencer | Normal. `start_period: 15s` laisse le temps à Flask de démarrer avant les vérifications. |

---

## 10. HTTPS (SSL)

### Via le Reverse Proxy Synology (recommandé)

1. **Panneau de configuration → Portail d'applications → Reverse Proxy**
2. Clique **Créer**
3. Source : `https://inventaire.mondomaine.com:443`
4. Destination : `http://localhost:9080`
5. **Sécurité → Certificat** → ajoute Let's Encrypt pour le domaine

### Via Nginx Proxy Manager (Docker)

1. Installe `jc21/nginx-proxy-manager` via Container Manager
2. Configure le proxy : domaine → `http://IP_NAS:9080`
3. Let's Encrypt géré automatiquement
