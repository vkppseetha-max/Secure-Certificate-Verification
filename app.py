import os
import sqlite3
import hashlib
import uuid
import time

import qrcode
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get(
    "SECRET_KEY", "secure-certificate-demo-key"
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, "certificates.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
QR_FOLDER = os.path.join(BASE_DIR, "static", "qrcodes")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)

app.config["MAX_CONTENT_LENGTH"] = 10 * 1024 * 1024


def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def create_tables():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE NOT NULL,
            name TEXT NOT NULL,
            course TEXT NOT NULL,
            institution TEXT NOT NULL,
            file_hash TEXT,
            issue_date TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


create_tables()


# Blockchain demonstration
class Block:
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = time.time()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        value = (
            str(self.index) + str(self.timestamp)
            + str(self.data) + str(self.previous_hash)
        )
        return hashlib.sha256(value.encode()).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = [Block(0, "Genesis Block", "0")]

    def add_block(self, data):
        previous = self.chain[-1]
        block = Block(len(self.chain), data, previous.hash)
        self.chain.append(block)

    def is_valid(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                return False

            if current.previous_hash != previous.hash:
                return False

        return True


blockchain = Blockchain()


def login_required(function):
    from functools import wraps

    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login to issue a certificate.", "error")
            return redirect(url_for("login"))
        return function(*args, **kwargs)

    return wrapper


def file_sha256(filepath):
    sha = hashlib.sha256()

    with open(filepath, "rb") as file:
        for chunk in iter(lambda: file.read(4096), b""):
            sha.update(chunk)

    return sha.hexdigest()


# Home page — both endpoint names supported
@app.route("/")
@app.route("/home")
def home():
    return render_template("index.html")


# Keep compatibility with existing templates using index
app.add_url_rule(
    "/index",
    endpoint="index",
    view_func=home,
    methods=["GET"]
)


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill in all fields.", "error")
            return redirect(url_for("register"))

        if len(password) < 8:
            flash("Password must be at least 8 characters.", "error")
            return redirect(url_for("register"))

        conn = get_db()

        try:
            conn.execute(
                """INSERT INTO users (name, email, password_hash)
                   VALUES (?, ?, ?)""",
                (name, email, generate_password_hash(password))
            )
            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            flash("Email already registered. Please login.", "error")
            return redirect(url_for("login"))

        conn.close()
        flash("Registration successful! Please login.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(
            user["password_hash"], password
        ):
            session.clear()
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]

            flash("Login successful!", "success")
            return redirect(url_for("issue"))

        flash("Invalid email or password.", "error")

    return render_template("login.html")


# Logout
@app.route("/logout")
def logout():
    session.clear()
    flash("Logged out successfully.", "success")
    return redirect(url_for("home"))


# Issue certificate
@app.route("/issue", methods=["GET", "POST"])
@login_required
def issue():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        course = request.form.get("course", "").strip()
        institution = request.form.get("institution", "").strip()
        uploaded_file = request.files.get("certificate_file")

        if not name or not course or not institution:
            flash("Please fill in all certificate details.", "error")
            return redirect(url_for("issue"))

        file_hash = None

        if uploaded_file and uploaded_file.filename:
            if not uploaded_file.filename.lower().endswith(".pdf"):
                flash("Only PDF files are allowed.", "error")
                return redirect(url_for("issue"))

            filename = secure_filename(uploaded_file.filename)
            saved_name = uuid.uuid4().hex + "_" + filename
            filepath = os.path.join(UPLOAD_FOLDER, saved_name)

            uploaded_file.save(filepath)
            file_hash = file_sha256(filepath)

        certificate_id = str(uuid.uuid4())
        issue_date = time.strftime("%Y-%m-%d")

        conn = get_db()
        conn.execute("""
            INSERT INTO certificates
            (certificate_id, name, course, institution,
             file_hash, issue_date)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (
            certificate_id, name, course, institution,
            file_hash, issue_date
        ))
        conn.commit()
        conn.close()

        blockchain.add_block({
            "certificate_id": certificate_id,
            "name": name,
            "course": course,
            "institution": institution,
            "file_hash": file_hash
        })

        qr_url = request.url_root.rstrip("/") + url_for(
            "result", certificate_id=certificate_id
        )

        qr = qrcode.make(qr_url)
        qr.save(os.path.join(QR_FOLDER, certificate_id + ".png"))

        return redirect(
            url_for("result", certificate_id=certificate_id)
        )

    return render_template("issue.html")


# Certificate result
@app.route("/result/<certificate_id>")
def result(certificate_id):
    conn = get_db()
    certificate = conn.execute(
        "SELECT * FROM certificates WHERE certificate_id = ?",
        (certificate_id,)
    ).fetchone()
    conn.close()

    if not certificate:
        flash("Certificate not found.", "error")
        return redirect(url_for("verify"))

    return render_template("result.html", certificate=certificate)


# Verify by certificate ID — public
@app.route("/verify", methods=["GET", "POST"])
def verify():
    if request.method == "POST":
        certificate_id = request.form.get(
            "certificate_id", ""
        ).strip()

        conn = get_db()
        certificate = conn.execute(
            "SELECT * FROM certificates WHERE certificate_id = ?",
            (certificate_id,)
        ).fetchone()
        conn.close()

        if certificate:
            return redirect(
                url_for("result", certificate_id=certificate_id)
            )

        flash("Invalid certificate ID.", "error")

    return render_template("verify.html")


# Verify PDF using SHA-256 — public
@app.route("/verify-pdf", methods=["GET", "POST"])
def verify_pdf():
    if request.method == "POST":
        uploaded_file = request.files.get("certificate_file")

        if not uploaded_file or not uploaded_file.filename:
            flash("Please select a PDF file.", "error")
            return redirect(url_for("verify_pdf"))

        if not uploaded_file.filename.lower().endswith(".pdf"):
            flash("Please upload a PDF file.", "error")
            return redirect(url_for("verify_pdf"))

        filepath = os.path.join(
            UPLOAD_FOLDER, uuid.uuid4().hex + ".pdf"
        )
        uploaded_file.save(filepath)

        try:
            uploaded_hash = file_sha256(filepath)
        finally:
            if os.path.exists(filepath):
                os.remove(filepath)

        conn = get_db()
        certificate = conn.execute(
            "SELECT * FROM certificates WHERE file_hash = ?",
            (uploaded_hash,)
        ).fetchone()
        conn.close()

        return render_template(
            "verify_pdf.html",
            certificate=certificate,
            uploaded_hash=uploaded_hash
        )

    return render_template("verify_pdf.html")


# Blockchain records
@app.route("/blockchain")
def view_blockchain():
    return render_template(
        "blockchain.html",
        chain=blockchain.chain,
        is_valid=blockchain.is_valid()
    )


if __name__ == "__main__":
    app.run(debug=True)
