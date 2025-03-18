import sqlite3
conn = sqlite3.connect('database/users.db')
cur = conn.cursor()
cur.execute("SELECT * FROM users")
print(cur.fetchall())
conn.close()
