import os
from flask import Flask, request, jsonify, render_template
from flask_CORS import CORS
import json, os, hashlib, secrets

app = Flask(__name__, static_folder="static", template_folder="templates")
CORS(app)

USER_FILE = "users.json"

def load_users():
    if os.path.exists(USER_FILE):
        with open(USER_FILE, "r") as f:
            return json.load(f)
    return []

def save_users(users):    
    with open(USER_FILE, "w") as f:
        json.dump(users, f, indent=4)

def hash_password(pwd: str) -> str:
    salt = secrets.token_bytes(16)
    pwdhash = hashlib.pbkdf2_hmac('sha256', pwd.encode(), salt, 200_000)
    return salt.hex() + pwdhash.hex()

def verify_password(stored: str, provided: str) -> bool:
    salt = bytes.fromhex(stored[:32])
    stored_hash = bytes.fromhex(stored[32:])
    pwdhash = hashlib.pbkdf2_hmac('sha256', provided.encode(), salt, 200_000)
    return pwdhash == stored_hash

# Routes for pages
@app.route('/')
def home():
    return render_template('register.html')

@app.route("/login.html")
def page_login():
    return render_template("login.html")

@app.route("/services.html")
def services():
    return render_template("services.html")

@app.route("/dashboard.html")
def page_dashboard():
    return render_template("dashboard.html")

# API routes
@app.route("/register", methods=['POST'])
def register():
    data = request.get_json()
    name = data.get("name", "").strip()
    email = data.get("email", "").strip()
    password = data.get("password", "").strip()

    if not all([name, email, password]):
        return jsonify({"message": "All fields required"}), 400

    users = load_users()
    if any(user['email'] == email for user in users):
        return jsonify({"message": "Email already exists"}), 400

    users.append({
        "name": name,
        "email": email,
        "password": hash_password(password)
    })

    save_users(users)
    return jsonify({"message": "Registered successfully"})

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    email = data.get('email')
    password = data.get('password')

    users = load_users()
    for user in users:
        if user['email'] == email and verify_password(user['password'], password):
            return jsonify({"message": f"Welcome back, {user['name']}!"})

    return jsonify({"message": "Invalid email or password"}), 401

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )