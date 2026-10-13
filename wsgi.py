import os
import threading

from serveur_collecte import app

# Initialisation de la base (appelé au démarrage des workers)
from serveur_collecte import init_db as _init_db

_init_db()

# Lancement de l'enrichissement auto en arrière-plan
from serveur_collecte import _auto_enrich_background as _enrich

t = threading.Thread(target=_enrich, daemon=True)
t.start()

port = os.environ.get('PORT', '5000')
api_key = os.environ.get('NVD_API_KEY', '')
print(f'[INVENTAIRE v5.0] Serveur demarre sur http://0.0.0.0:{port}')
if api_key:
    print(f'  [CVE] Cle NVD API fournie - taux ~50 req/30s')
else:
    print(f'  [CVE] Pas de cle NVD API - taux limite ~5 req/30s (lent)')
