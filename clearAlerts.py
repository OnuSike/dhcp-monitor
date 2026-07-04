import sqlite3

conn = sqlite3.connect('leases.db')
conn.execute('DELETE FROM alerts')
conn.commit()
conn.close()