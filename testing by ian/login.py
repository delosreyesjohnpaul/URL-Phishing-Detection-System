import sqlite3
import bcrypt
import hashlib

DB_FILE = 'users.db'
SECRET_PEPPER = "my secret pepper"

def login_user(username, password):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()

    # Fetch the necessary user data
    cursor.execute('''
        SELECT hashed_password, salt_for_secret, hashed_secret2 FROM users WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()
    conn.close()

    if result is None:
        print("❌ Username not found.")
        return

    stored_hashed_password, salt_for_secret, stored_hashed_secret2 = result

    # Combine entered password with stored hashed_secret2
    combined_input = password + stored_hashed_secret2.decode('utf-8')

    # Compare using bcrypt
    if bcrypt.checkpw(combined_input.encode('utf-8'), stored_hashed_password):
        print("✅ Correct password!")
    else:
        print("❌ Incorrect password.")

if __name__ == "__main__":
    print("🔐 Login")
    username = input("Enter username: ")
    password = input("Enter password: ")
    login_user(username, password)
