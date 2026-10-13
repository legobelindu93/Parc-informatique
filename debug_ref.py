import json, os, sys

target = r'C:\Users\bruno_i1sa\OneDrive\Bureau\u2800\programation\I2SI\program'
sys.path.insert(0, target)
os.chdir(target)

import serveur_collecte
print(f'serveur_collecte.__file__: {serveur_collecte.__file__!r}')
print(f'dirname: {os.path.dirname(serveur_collecte.__file__)!r}')
path = os.path.join(os.path.dirname(serveur_collecte.__file__) or '.', 'data', 'latest_versions.json')
print(f'Resolved path: {path!r}')
print(f'Exists: {os.path.exists(path)}')
if os.path.exists(path):
    print(open(path, encoding='utf-8').read(200))
