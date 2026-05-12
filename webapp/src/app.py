import hashlib
import os
import pickle
# FIX for Flaw 2: Use JSON instead of pickle
# import json
from datetime import datetime
from functools import wraps
# FIX for Flaw 4: Used for salted password hashing
# import bcrypt

from flask import (Flask, redirect, render_template, render_template_string,
                   request, session, url_for)

app = Flask(__name__)
app.secret_key = os.environ.get("DEVNOTES_SECRET_KEY") or os.urandom(32)

NOTES_PATH = "/var/lib/devnotes/notes.pkl"
LOG_PATH = "/var/lib/devnotes/access.log"

# === Flaw 4: A02 Cryptographic Failures ===
# Unsalted and hardcoded SHA-256 Admin Hash that is easy to brute-force with repo access ("admin123").
ADMIN_PASSWORD_HASH = "240be518fabd2724ddb6f04eeb1da5967448d7e831c08c8fa822809f74c720a9"
# === FIX for Flaw 4 ===
# Use bcrypt for salted password hashing and load the hash from env.
# ADMIN_PASSWORD_HASH = os.environ["ADMIN_PASSWORD_HASH"].encode()

def require_login(view_func):
    @wraps(view_func)
    def wrapped(*args, **kwargs):
        if not session.get("user"):
            return redirect(url_for("login"))
        return view_func(*args, **kwargs)
    return wrapped


@app.route("/")
def index():
    if session.get("user"):
        return redirect(url_for("dashboard"))
    return redirect(url_for("login"))


@app.route("/login", methods=["GET", "POST"])
def login():
    message = ""
    if request.method == "POST":
        username = request.form.get("username", "")
        password = request.form.get("password", "")

        # === Flaw 5: A09 Security Logging and Monitoring Failures ===
        # Plaintext password is written into the logs!
        log_line = (
            f"{datetime.now().isoformat()} login_attempt "
            f"user={username} password={password} "
            f"ip={request.remote_addr}\n"
        )
        # === FIX for Flaw 5 ===
        # Exclude the password field from all logs.
        # log_line = (
        #     f"{datetime.now().isoformat()} login_attempt "
        #     f"user={username} "
        #     f"ip={request.remote_addr}\n"
        # )
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        with open(LOG_PATH, "a") as f:
            f.write(log_line)

        # === Flaw 4 (continued) ===
        input_hash = hashlib.sha256(password.encode()).hexdigest()
        if username == "admin" and input_hash == ADMIN_PASSWORD_HASH:
            session["user"] = username
            return redirect(url_for("dashboard"))
        # === FIX for Flaw 4 ===
        # if username == "admin" and bcrypt.checkpw(password.encode(), ADMIN_PASSWORD_HASH):
        #     session["user"] = username
        #     return redirect(url_for("dashboard"))

        message = "Invalid credentials."

    return render_template("login.html", message=message)


@app.route("/logout")
def logout():
    session.pop("user", None)
    return redirect(url_for("login"))


@app.route("/dashboard", methods=["GET", "POST"])
@require_login
def dashboard():
    notes = load_notes()

    if request.method == "POST":
        title = request.form.get("title", "")
        body = request.form.get("body", "")
        notes.append({
            "title": title,
            "body": body,
            "author": session["user"],
            "created": datetime.now().isoformat(),
        })
        save_notes(notes)
        return redirect(url_for("dashboard"))

    return render_template("dashboard.html", notes=notes, user=session["user"])


def load_notes():
    if not os.path.exists(NOTES_PATH):
        return []
    # === Flaw 2: A08 Software and Data Integrity Failures ===
    # pickle.load runs arbitrary code via __reduce__ when loading a crafted file!
    with open(NOTES_PATH, "rb") as f:
        return pickle.load(f)
    # === FIX for Flaw 2 ===
    # JSON only deserializes primitive types and can never execute code.
    # with open(NOTES_PATH, "r") as f:
    #     return json.load(f)


def save_notes(notes):
    os.makedirs(os.path.dirname(NOTES_PATH), exist_ok=True)
    # === Flaw 2: A08 Software and Data Integrity Failures (same format) ===
    with open(NOTES_PATH, "wb") as f:
        pickle.dump(notes, f)
    # === FIX for Flaw 2 ===
    # with open(NOTES_PATH, "w") as f:
    #     json.dump(notes, f)

# === Flaw 3: A01 Broken Access Control ===
# Admin routes have no auth check and are even shown in /robots.txt!
@app.route("/admin/log_viewer", methods=["GET"])
# === FIX for Flaw 3 ===
# Require an authenticated admin session before granting access.
# @require_login
def admin_log_viewer():
    if not os.path.exists(LOG_PATH):
        return render_template("log_viewer.html", logs=[], message="No logs.")

    with open(LOG_PATH, "r") as f:
        raw_logs = f.readlines()

    # === Flaw 1: A03 Injection ===
    # Any {{ ... }} payload in the username/password fields becomes code execution!
    rendered_logs = [render_template_string(line) for line in raw_logs]
    # === FIX for Flaw 1 ===
    # The template's {{ line }} placeholder renders them as data and never as code.
    # rendered_logs = raw_logs

    return render_template("log_viewer.html", logs=rendered_logs, message="")

# === Flaw 3 (continued) ===
@app.route("/admin/notes", methods=["GET"])
# === FIX for Flaw 3 ===
# @require_login
def admin_notes():
    notes = load_notes()
    return render_template("dashboard.html", notes=notes, user="admin (UNAUTHENTICATED)")


@app.route("/robots.txt")
def robots():
    # Flaw 3 (continued)
    # robots.txt shows unprotected admin URLs.
    body = (
        "User-agent: *\n"
        "Disallow: /admin/log_viewer\n"
        "Disallow: /admin/notes\n"
    )
    return body, 200, {"Content-Type": "text/plain"}


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)