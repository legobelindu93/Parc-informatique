import os
import psycopg2

conn = psycopg2.connect(
    host=os.environ.get('PG_HOST', 'localhost'),
    dbname=os.environ.get('PG_NAME', 'inventaire'),
    user=os.environ.get('PG_USER', 'postgres'),
    password=os.environ.get('PG_PASS', 'toor')
)
cur = conn.cursor()

tables = ['machines', 'logiciels', 'historique_scan', 'historique_actions', 'cve_cache',
          'catalogue', 'licences', 'conformite', 'sites', 'departments', 'users',
          'sbom', 'usage_stats', 'audit_log', 'compliance_rules']

for t in tables:
    cur.execute("SELECT pg_get_serial_sequence(%s, 'id')", (t,))
    seq = cur.fetchone()[0]
    if seq:
        cur.execute(f'SELECT MAX(id) FROM {t}')
        maxid = cur.fetchone()[0] or 0
        cur.execute("SELECT setval(%s, %s, false)", (seq, maxid + 1))
        print(f'{t}: {seq} -> {maxid + 1}')

conn.commit()
conn.close()
print('Done')
