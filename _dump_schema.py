import sqlite3
conn = sqlite3.connect(r'C:\Users\bruno_i1sa\OneDrive\Bureau\⠀\programation\I2SI\program\dashboard\parc.db')
c = conn.cursor()
c.execute("SELECT name FROM sqlite_master WHERE type='table' ORDER BY name")
tables = c.fetchall()
for t in tables:
    tn = t[0]
    print(f'--- {tn} ---')
    c.execute(f'PRAGMA table_info("{tn}")')
    for col in c.fetchall():
        print(f'  {col}')
conn.close()
