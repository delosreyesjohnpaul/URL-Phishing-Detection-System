import sqlite3
import bcrypt
import hashlib
import os

# Function to create a random salt for SHA-256 (for stronger encryption)
def generate_random_salt():
    return os.urandom(16)  # 16 bytes salt

# Hash the secret using SHA-256 with a salt
def hash_secret_with_salt(raw_secret):
    salt_for_secret = generate_random_salt()
    secret_with_salt = raw_secret.encode('utf-8') + salt_for_secret
    hashed_secret = hashlib.sha256(secret_with_salt).hexdigest()
    return hashed_secret, salt_for_secret

# Function to create a connection to SQLite database
def create_db():
    conn = sqlite3.connect('users.db')  # Connects to users.db (or creates it if it doesn't exist)
    cursor = conn.cursor()

    # Create table if it doesn't exist already
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            hashed_password TEXT NOT NULL,
            salt_for_secret BLOB NOT NULL
        )
    ''')

    conn.commit()  # Save the changes
    conn.close()

# Function to add a new user with a hashed password and secret salt
def add_user(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Hash the password using SHA-256 + salt, then bcrypt
    hashed_secret, salt_for_secret = hash_secret_with_salt("my secret pepper")
    hashed_secret2 = bcrypt.hashpw(hashed_secret.encode('utf-8'), bcrypt.gensalt())

    # Combine password and the hashed secret (which is also hashed with bcrypt)
    original_password = password + hashed_secret2.decode('utf-8')

    # Final bcrypt hash for the password + secret
    hashed_password = bcrypt.hashpw(original_password.encode('utf-8'), bcrypt.gensalt())

    # Insert user into the database with the hashed password and secret salt
    try:
        cursor.execute('''
            INSERT INTO users (username, hashed_password, salt_for_secret)
            VALUES (?, ?, ?)
        ''', (username, hashed_password, salt_for_secret))

        conn.commit()
        print("User added successfully!")
    except sqlite3.IntegrityError:
        print(f"Username '{username}' is already taken.")
    
    conn.close()

# Function to check if the entered password matches the stored password
def check_password(username, password):
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()

    # Retrieve the hashed password and secret salt for the given username
    cursor.execute('''
        SELECT hashed_password, salt_for_secret FROM users WHERE username = ?
    ''', (username,))
    result = cursor.fetchone()

    if result is None:
        print("Username not found!")
        return False

    stored_hashed_password, stored_salt_for_secret = result

    # Hash the secret using the stored salt
    hashed_secret, _ = hash_secret_with_salt("my secret pepper")

    # Hash the user input with the stored secret hash
    user_input_full = password + bcrypt.hashpw(hashed_secret.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Check if the entered password matches the stored hashed password
    if bcrypt.checkpw(user_input_full.encode('utf-8'), stored_hashed_password):
        print("✅ Correct password!")
        return True
    else:
        print("❌ Incorrect password.")
        return False

    conn.close()

# Main flow
if __name__ == "__main__":
    # Create database and table if not exists
    create_db()

    # Add a new user (run only once to add the user)
    # Uncomment the next line to add a user, and comment it after adding
    # add_user("user1", "securePassword123")

    # Simulate login (you can replace this with user input)
    username = input("Enter your username: ")
    password = input("Enter your password: ")

    # Check the user's password
    check_password(username, password)
