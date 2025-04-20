import sqlite3
import bcrypt
import hashlib
import os

DB_FILE = 'users.db'
SECRET_PEPPER = "my secret pepper"

def generate_random_salt():
    return os.urandom(16)

def hash_secret_with_salt(secret, salt):
    return hashlib.sha256(secret.encode('utf-8') + salt).hexdigest()

def add_user(username, password):
    salt_for_secret = generate_random_salt()
    hashed_secret = hash_secret_with_salt(SECRET_PEPPER, salt_for_secret)
    hashed_secret2 = bcrypt.hashpw(hashed_secret.encode('utf-8'), bcrypt.gensalt())

    combined_password = password + hashed_secret2.decode('utf-8')
    final_hashed_password = bcrypt.hashpw(combined_password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('''
            INSERT INTO users (username, hashed_password, salt_for_secret, hashed_secret2)
            VALUES (?, ?, ?, ?)
        ''', (username, final_hashed_password, salt_for_secret, hashed_secret2))
        conn.commit()
        print(f"✅ User '{username}' added successfully.")
    except sqlite3.IntegrityError:
        print(f"❌ Username '{username}' already exists.")
    finally:
        conn.close()

if __name__ == "__main__":
    print("📝 Add New User")
    username = input("Enter username: ")
    password = input("Enter password: ")
    add_user(username, password)
