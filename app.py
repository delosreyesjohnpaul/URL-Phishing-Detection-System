from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import bcrypt
import hashlib
import os
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

app = Flask(__name__)
app.secret_key = 'your_flask_secret_key'

DB_FILE = 'users.db'
SECRET_PEPPER = 'my secret pepper'

# Load ML model
with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)

# ---------------- AUTH LOGIC ---------------- #

def generate_random_salt():
    return os.urandom(16)

def hash_secret_with_salt(secret, salt):
    return hashlib.sha256(secret.encode('utf-8') + salt).hexdigest()

def get_user_by_email(email):
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute('SELECT * FROM users WHERE username = ?', (email,))
    user = cursor.fetchone()
    conn.close()
    return user

def create_user(email, password):
    salt_for_secret = generate_random_salt()
    hashed_secret = hash_secret_with_salt(SECRET_PEPPER, salt_for_secret)
    hashed_secret2 = bcrypt.hashpw(hashed_secret.encode('utf-8'), bcrypt.gensalt())

    combined_password = password + hashed_secret2.decode('utf-8')
    final_hashed_password = bcrypt.hashpw(combined_password.encode('utf-8'), bcrypt.gensalt())

    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    try:
        cursor.execute('INSERT INTO users (username, hashed_password, salt_for_secret, hashed_secret2) VALUES (?, ?, ?, ?)',
                       (email, final_hashed_password, salt_for_secret, hashed_secret2))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False
    finally:
        conn.close()

def validate_login(email, password):
    user = get_user_by_email(email)
    if not user:
        return False

    stored_hashed_password, salt, hashed_secret2 = user[1], user[2], user[3]
    combined_input = password + hashed_secret2.decode('utf-8')
    return bcrypt.checkpw(combined_input.encode('utf-8'), stored_hashed_password)

# ---------------- ROUTES ---------------- #

@app.route('/', methods=['GET', 'POST'])
def home():
    if 'user' not in session:
        return redirect(url_for('auth'))

    if request.method == 'POST':
        url = request.form.get('url')
        if url:
            obj = FeatureExtraction(url)
            x = np.array(obj.getFeaturesList()).reshape(1, 30)
            y_pred = gbc.predict(x)[0]
            y_pro_phishing = gbc.predict_proba(x)[0, 0]
            y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

            return render_template('index.html', user=session['user'], xx=round(y_pro_non_phishing, 2), url=url)

    return render_template('index.html', user=session['user'], xx=-1)

@app.route('/auth', methods=['GET', 'POST'])
def auth():
    if request.method == 'POST':
        mode = request.form['form_mode']
        email = request.form['email']
        password = request.form['password']

        if mode == 'signup':
            confirm = request.form.get('confirmPassword')
            if password != confirm:
                flash("Passwords do not match.", "danger")
            elif create_user(email, password):
                flash("Account created! Please log in.", "success")
            else:
                flash("Email already exists.", "danger")
        else:
            if validate_login(email, password):
                session['user'] = email
                flash(f"Welcome back, {email}!", "success")
                return redirect(url_for('home'))
            else:
                flash("Invalid email or password.", "danger")

    return render_template('login.html')

@app.route('/logout')
def logout():
    session.pop('user', None)
    flash("Logged out successfully.", "info")
    return redirect(url_for('auth'))

if __name__ == '__main__':
    app.run(debug=True)
