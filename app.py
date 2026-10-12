import os
import io
import sqlite3
import hashlib
import base64
from datetime import datetime
from functools import wraps

import qrcode
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secure-certificate-key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "certificates.db")


# ---------------- DATABASE ----------------

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT
        )
    """)

    # Keep existing user database compatible.
    user_columns = [
        row["name"]
        for row in conn.execute("PRAGMA table_info(users)").fetchall()
    ]

    if "password_hash" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")

    if "password" not in user_columns:
        conn.execute("ALTER TABLE users ADD COLUMN password TEXT")

    conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE NOT NULL,
            student_name TEXT NOT NULL,
            course TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            file_hash TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# ---------------- BLOCKCHAIN ----------------

class Blockchain:
    def __init__(self):
        self.chain = []

    def add_block(self, data):
        previous_hash = self.chain[-1]["hash"] if self.chain else "0"
        block_hash = hashlib.sha256(
            (str(data) + previous_hash).encode("utf-8")
        ).hexdigest()

        self.chain.append({
            "index": len(self.chain) + 1,
            "data": data,
            "previous_hash": previous_hash,
            "hash": block_hash
        })


blockchain = Blockchain()


# ---------------- LOGIN REQUIRED ----------------

def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# ---------------- HOME ----------------

@app.route("/")
def index():
    return render_template("index.html")


# ---------------- REGISTER ----------------

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill in all fields.")
            return redirect(url_for("register"))

        hashed_password = generate_password_hash(password)
        conn = get_db()

        try:
            columns = [
                row["name"]
                for row in conn.execute("PRAGMA table_info(users)").fetchall()
            ]

            if "password_hash" in columns:
                conn.execute(
                    "INSERT INTO users (name, email, password_hash) VALUES (?, ?, ?)",
                    (name, email, hashed_password)
                )
            else:
                conn.execute(
                    "INSERT INTO users (name, email, password) VALUES (?, ?, ?)",
                    (name, email, hashed_password)
                )

            conn.commit()

        except sqlite3.IntegrityError:
            conn.close()
            flash("Email already registered. Please login.")
            return redirect(url_for("login"))

        except sqlite3.Error as error:
            conn.close()
            app.logger.exception("Registration database error: %s", error)
            flash("Registration failed. Please try again.")
            return redirect(url_for("register"))

        conn.close()
        flash("Registration successful. Please login.")
        return redirect(url_for("login"))

    return render_template("register.html")


# ---------------- LOGIN ----------------

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

        if user:
            stored_hash = (
                user["password_hash"]
                if "password_hash" in user.keys()
                and user["password_hash"]
                else user["password"]
                if "password" in user.keys()
                else None
            )

            if stored_hash and check_password_hash(stored_hash, password):
                session["user_id"] = user["id"]
                session["user_name"] = user["name"]
                return redirect(url_for("index"))

        flash("Invalid email or password.")
        return redirect(url_for("login"))

    return render_template("login.html")


# ---------------- LOGOUT ----------------

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ---------------- ISSUE CERTIFICATE ----------------

@app.route("/issue", methods=["GET", "POST"])
@login_required
def issue():
    if request.method == "POST":
        student_name = (
            request.form.get("name")
            or request.form.get("student_name")
            or ""
        ).strip()

        course = request.form.get("course", "").strip()
        institution = request.form.get("institution", "").strip()

        if not student_name or not course:
            flash("Please enter Student Name and Course.")
            return redirect(url_for("issue"))

        issue_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        random_value = os.urandom(16).hex()

        certificate_id = hashlib.sha256(
            (student_name + course + issue_date + random_value).encode("utf-8")
        ).hexdigest()[:16].upper()

        certificate_data = (
            certificate_id + student_name + course + issue_date
        )
        file_hash = hashlib.sha256(
            certificate_data.encode("utf-8")
        ).hexdigest()

        conn = get_db()

        try:
            conn.execute("""
                INSERT INTO certificates
                (certificate_id, student_name, course, issue_date, file_hash)
                VALUES (?, ?, ?, ?, ?)
            """, (
                certificate_id, student_name, course, issue_date, file_hash
            ))
            conn.commit()

        except sqlite3.Error:
            conn.rollback()
            conn.close()
            app.logger.exception("Certificate database error")
            flash("Certificate could not be saved. Please try again.")
            return redirect(url_for("issue"))

        conn.close()

        blockchain.add_block({
            "certificate_id": certificate_id,
            "file_hash": file_hash
        })

        verify_url = url_for(
            "verify",
            certificate_id=certificate_id,
            _external=True
        )

        qr = qrcode.make(verify_url)
        image_buffer = io.BytesIO()
        qr.save(image_buffer, format="PNG")

        qr_code = base64.b64encode(
            image_buffer.getvalue()
        ).decode("utf-8")

        return render_template(
            "result.html",
            certificate_id=certificate_id,
            student_name=student_name,
            course=course,
            institution=institution,
            issue_date=issue_date,
            file_hash=file_hash,
            qr_code=qr_code,
            verify_url=verify_url
        )

    return render_template("issue.html")


# ---------------- VERIFY CERTIFICATE ----------------

@app.route("/verify", methods=["GET", "POST"])
def verify():
    certificate = None
    message = None

    if request.method == "POST":
        certificate_id = request.form.get("certificate_id", "").strip()
    else:
        certificate_id = request.args.get("certificate_id", "").strip()

    if certificate_id:
        conn = get_db()

        certificate = conn.execute("""
            SELECT * FROM certificates
            WHERE UPPER(certificate_id) = UPPER(?)
        """, (certificate_id,)).fetchone()

        conn.close()

        if certificate:
            message = "Certificate verified successfully!"
        else:
            message = "Certificate not found. Please check the Certificate ID."

    return render_template(
        "verify.html",
        certificate=certificate,
        message=message,
        certificate_id=certificate_id if "certificate_id" in locals() else ""
    )


# ---------------- VERIFY UPLOADED PDF ----------------

@app.route("/verify-pdf", methods=["POST"])
def verify_pdf():
    uploaded_file = request.files.get("file")

    if not uploaded_file or not uploaded_file.filename:
        flash("Please select a PDF file.")
        return redirect(url_for("verify"))

    uploaded_hash = hashlib.sha256(uploaded_file.read()).hexdigest()

    conn = get_db()
    certificates = conn.execute(
        "SELECT * FROM certificates"
    ).fetchall()
    conn.close()

    matched_certificate = next(
        (cert for cert in certificates if cert["file_hash"] == uploaded_hash),
        None
    )

    if matched_certificate:
        return render_template(
            "verify.html",
            certificate=matched_certificate,
            message="Uploaded file hash matched."
        )

    return render_template(
        "verify.html",
        certificate=None,
        message=(
            "Uploaded PDF does not match a stored certificate hash. "
            "The original PDF hash must be stored during certificate issuance."
        )
    )


# ---------------- BLOCKCHAIN VIEW ----------------

@app.route("/blockchain")
@login_required
def view_blockchain():
    return render_template(
        "blockchain.html",
        chain=blockchain.chain
    )


# ---------------- START APP ----------------

init_db()

if __name__ == "__main__":
    app.run(
        host="0.0.0.0",
        port=int(os.environ.get("PORT", 5000)),
        debug=False
    )
