import sqlite3

DB_FILE = 'users.db'

conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

cursor.execute('''
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        hashed_password BLOB NOT NULL,
        salt_for_secret BLOB NOT NULL,
        hashed_secret2 BLOB NOT NULL
    )
''')

conn.commit()
conn.close()
print("✅ Database and users table created.")
