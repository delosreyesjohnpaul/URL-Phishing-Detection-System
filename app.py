from flask import Flask, render_template, request, redirect, url_for, session, flash
import numpy as np
import pickle
import warnings
from feature import FeatureExtraction

warnings.filterwarnings('ignore')

app = Flask(__name__)
app.secret_key = 'maxchar14'

users = {'ian@testuser.com': 'testpass'}

with open("pickle/model.pkl", "rb") as file:
    gbc = pickle.load(file)


@app.route("/auth", methods=["POST"])
def auth():
    email = request.form['email']
    password = request.form['password']
    mode = request.form['form_mode']

    if mode == "signup":
        confirm = request.form['confirmPassword']
        if password != confirm:
            flash("Passwords do not match!", "danger")
            return redirect(url_for("login"))
        if email in users:
            flash("Email already exists!", "warning")
            return redirect(url_for("login"))
        users[email] = password
        flash("Signup successful! You can log in now.", "success")
        return redirect(url_for("login"))

    elif mode == "login":
        if email in users and users[email] == password:
            session['user'] = email
            return redirect(url_for("index"))
        else:
            flash("Invalid email or password", "danger")
            return redirect(url_for("login"))


@app.route("/login")
def login():
    return render_template("login.html")


@app.route("/logout")
def logout():
    session.pop("user", None)
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


@app.route("/", methods=["GET", "POST"])
def index():
    if "user" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        url = request.form["url"]
        obj = FeatureExtraction(url)
        x = np.array(obj.getFeaturesList()).reshape(1, 30)
        y_pred = gbc.predict(x)[0]
        y_pro_phishing = gbc.predict_proba(x)[0, 0]
        y_pro_non_phishing = gbc.predict_proba(x)[0, 1]

        return render_template("index.html", xx=round(y_pro_non_phishing, 2), url=url)

    return render_template("index.html", xx=-1)


if __name__ == "__main__":
    app.run(debug=True)