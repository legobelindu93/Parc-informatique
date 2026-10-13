import sqlite3
conn = sqlite3.connect('dashboard/parc.db')
cur = conn.cursor()
cur.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
print('Tables:', cur.fetchall())
conn.close()
