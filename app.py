from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash
)
import sqlite3
import hashlib
import os
import qrcode
import io
import base64
from datetime import datetime
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secure-certificate-key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "certificates.db")


# DATABASE
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE NOT NULL,
            student_name TEXT NOT NULL,
            course TEXT NOT NULL,
            issue_date TEXT NOT NULL,
            file_hash TEXT
        )
    """)

    conn.commit()
    conn.close()


# BLOCKCHAIN
class Block:
    def __init__(self, index, data, previous_hash):
        self.index = index
        self.timestamp = datetime.now().isoformat()
        self.data = data
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        content = (
            str(self.index)
            + self.timestamp
            + str(self.data)
            + self.previous_hash
        )
        return hashlib.sha256(
            content.encode("utf-8")
        ).hexdigest()


class Blockchain:
    def __init__(self):
        self.chain = [
            Block(0, "Genesis Block", "0")
        ]

    def add_block(self, data):
        previous = self.chain[-1]

        block = Block(
            len(self.chain),
            data,
            previous.hash
        )

        self.chain.append(block)

    def is_valid(self):
        if not self.chain:
            return False

        for i, block in enumerate(self.chain):
            if block.hash != block.calculate_hash():
                return False

            if i == 0:
                if block.previous_hash != "0":
                    return False
            else:
                previous = self.chain[i - 1]

                if block.previous_hash != previous.hash:
                    return False

                if block.index != previous.index + 1:
                    return False

        return True


blockchain = Blockchain()


# LOGIN REQUIRED
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            flash("Please login first.")
            return redirect(url_for("login"))

        return func(*args, **kwargs)

    return wrapper


# HOME
@app.route("/")
def index():
    return render_template("index.html")


# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form.get("email", "").strip()
        password = request.form.get("password", "")

        if not username or not password:
            flash("Enter username and password.")
            return redirect(url_for("register"))

        conn = get_db()

        try:
            conn.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, generate_password_hash(password))
            )
            conn.commit()
            flash("Registration successful. Please login.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Username already exists.")

        finally:
            conn.close()

    return render_template("register.html")


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ?",
            (username,)
        ).fetchone()
        conn.close()

        if user and check_password_hash(user["password"], password):
            session["user_id"] = user["id"]
            session["username"] = user["username"]

            return redirect(url_for("index"))

        flash("Invalid username or password.")

    return render_template("login.html")


# LOGOUT
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))


# ISSUE CERTIFICATE
@app.route("/issue", methods=["GET", "POST"])
@login_required
def issue():
    if request.method == "POST":
        student_name = request.form.get(
            "student_name", ""
        ).strip()

        course = request.form.get(
            "course", ""
        ).strip()

        if not student_name or not course:
            flash("Enter student name and course.")
            return redirect(url_for("issue"))

        issue_date = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        certificate_id = hashlib.sha256(
            (
                student_name
                + course
                + issue_date
                + os.urandom(16).hex()
            ).encode("utf-8")
        ).hexdigest()[:16].upper()

        certificate_data = (
            certificate_id
            + student_name
            + course
            + issue_date
        )

        file_hash = hashlib.sha256(
            certificate_data.encode("utf-8")
        ).hexdigest()

        conn = get_db()

        conn.execute("""
            INSERT INTO certificates
            (certificate_id, student_name, course, issue_date, file_hash)
            VALUES (?, ?, ?, ?, ?)
        """, (
            certificate_id,
            student_name,
            course,
            issue_date,
            file_hash
        ))

        conn.commit()
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
            issue_date=issue_date,
            file_hash=file_hash,
            qr_code=qr_code,
            verify_url=verify_url
        )

    return render_template("issue.html")


# VERIFY CERTIFICATE
@app.route("/verify", methods=["GET", "POST"])
def verify():
    certificate = None
    verified = False

    certificate_id = request.args.get(
        "certificate_id", ""
    ).strip()

    if request.method == "POST":
        certificate_id = request.form.get(
            "certificate_id", ""
        ).strip()

    if certificate_id:
        conn = get_db()

        certificate = conn.execute("""
            SELECT * FROM certificates
            WHERE certificate_id = ?
        """, (certificate_id,)).fetchone()

        conn.close()

        if certificate and certificate["file_hash"]:
            original_data = (
                certificate["certificate_id"]
                + certificate["student_name"]
                + certificate["course"]
                + certificate["issue_date"]
            )

            calculated_hash = hashlib.sha256(
                original_data.encode("utf-8")
            ).hexdigest()

            verified = (
                calculated_hash == certificate["file_hash"]
            )

    return render_template(
        "verify.html",
        certificate=certificate,
        verified=verified,
        certificate_id=certificate_id
    )


# VERIFY PDF
@app.route("/verify-pdf", methods=["GET", "POST"])
def verify_pdf():
    verified = False
    uploaded_hash = None
    message = None

    if request.method == "POST":
        file = request.files.get("certificate")

        if not file or not file.filename:
            message = "Please select a PDF file."

        elif not file.filename.lower().endswith(".pdf"):
            message = "Only PDF files are allowed."

        else:
            file_bytes = file.read()

            uploaded_hash = hashlib.sha256(
                file_bytes
            ).hexdigest()

            conn = get_db()

            certificate = conn.execute("""
                SELECT * FROM certificates
                WHERE file_hash = ?
            """, (uploaded_hash,)).fetchone()

            conn.close()

            if certificate:
                verified = True
                message = "Certificate verified successfully."
            else:
                message = "Certificate not found or hash does not match."

    return render_template(
        "verify_pdf.html",
        verified=verified,
        uploaded_hash=uploaded_hash,
        message=message
    )


# BLOCKCHAIN RECORDS
@app.route("/blockchain")
def view_blockchain():
    is_valid = blockchain.is_valid()

    return render_template(
        "blockchain.html",
        chain=blockchain.chain,
        is_valid=is_valid
    )


# START APPLICATION
init_db()

if __name__ == "__main__":
    app.run(debug=True)
