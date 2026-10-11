from flask import Flask, render_template, request, redirect, url_for, session, flash
import sqlite3
import hashlib
import os
import qrcode
from datetime import datetime
from functools import wraps

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "secure-certificate-key")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(BASE_DIR, "certificates.db")
UPLOAD_FOLDER = os.path.join(BASE_DIR, "uploads")
QR_FOLDER = os.path.join(BASE_DIR, "static", "qrcodes")

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)


# DATABASE
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS USERS (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL
        )
    """)

    conn.execute("""
        CREATE TABLE IF NOT EXISTS CERTIFICATES (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE,
            name TEXT,
            course TEXT,
            institution TEXT,
            certificate_hash TEXT,
            file_hash TEXT,
            issue_date TEXT
        )
    """)

    conn.commit()
    conn.close()


# HASH
def calculate_hash(data):
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


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
        return hashlib.sha256(content.encode("utf-8")).hexdigest() "Genesis Block", "0")]

    def add_block(self, data):
        previous = self.chain[-1]
        block = Block(len(self.chain), data, previous.hash)
        self.chain.append(block)

    def is_valid(self):
        for i, block in enumerate(self.chain):
            if block.hash != block.calculate_hash():
                return False

            if i > 0 and block.previous_hash != self.chain[i - 1].hash:
                return False

        return self.chain[0].previous_hash == "0"


blockchain = Blockchain()


# LOGIN REQUIRED
def login_required(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        if "user_id" not in session:
            return redirect(url_for("login"))
        return function(*args, **kwargs)
    return wrapper


# HOME
@app.route("/")
def index():
    return render_template("index.html")


# REGISTER
@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        if not name or not email or not password:
            flash("Please fill all fields.")
            return redirect(url_for("register"))

        conn = get_db()

        try:
            conn.execute(
                "INSERT INTO USERS (name, email, password_hash) VALUES (?, ?, ?)",
                (name, email, calculate_hash(password))
            )
            conn.commit()
            flash("Registration successful. Please login.")
            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            flash("Email already registered.")
            return redirect(url_for("register"))

        finally:
            conn.close()

    return render_template("register.html")


# LOGIN
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM USERS WHERE email = ?", (email,)
        ).fetchone()
        conn.close()

        if user and user["password_hash"] == calculate_hash(password):
            session["user_id"] = user["id"]
            session["user_name"] = user["name"]
            return redirect(url_for("index"))

        flash("Invalid email or password.")

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
        name = request.form.get("name", "").strip()
        course = request.form.get("course", "").strip()
        institution = request.form.get("institution", "").strip()

        if not name or not course or not institution:
            flash("Please fill all certificate fields.")
            return redirect(url_for("issue"))

        certificate_id = "CERT-" + hashlib.sha256(
            (name + course + institution + datetime.now().isoformat()).encode()
        ).hexdigest()[:12].upper()

        issue_date = datetime.now().strftime("%Y-%m-%d")

        certificate_hash = calculate_hash(
            certificate_id + name + course + institution + issue_date
        )

        conn = get_db()
        conn.execute("""
            INSERT INTO CERTIFICATES
            (certificate_id, name, course, institution,
             certificate_hash, file_hash, issue_date)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            certificate_id, name, course, institution,
            certificate_hash, "", issue_date
        ))
        conn.commit()

        certificate = conn.execute(
            "SELECT * FROM CERTIFICATES WHERE certificate_id = ?",
            (certificate_id,)
        ).fetchone()
        conn.close()

        blockchain.add_block({
            "certificate_id": certificate_id,
            "certificate_hash": certificate_hash
        })

        qr = qrcode.make(
            request.host_url.rstrip("/")
            + "/verify?certificate_id="
            + certificate_id
        )
        qr.save(os.path.join(QR_FOLDER, certificate_id + ".png"))

        flash("Certificate issued successfully.")

        return render_template(
            "result.html",
            certificate=certificate
        )

    return render_template("issue.html")


# VERIFY CERTIFICATE
@app.route("/verify", methods=["GET", "POST"])
def verify():
    certificate = None
    verified = False

    certificate_id = request.args.get("certificate_id", "").strip()

    if request.method == "POST":
        certificate_id = request.form.get("certificate_id", "").strip()

    if certificate_id:
        conn = get_db()
        certificate = conn.execute(
            "SELECT * FROM CERTIFICATES WHERE certificate_id = ?",
            (certificate_id,)
        ).fetchone()
        conn.close()

        if certificate:
            expected_hash = calculate_hash(
                certificate["certificate_id"]
                + certificate["name"]
                + certificate["course"]
                + certificate["institution"]
                + certificate["issue_date"]
            )
            verified = expected_hash == certificate["certificate_hash"]

    return render_template(
        "verify.html",
        certificate=certificate,
        verified=verified
    )


# VERIFY UPLOADED PDF
@app.route("/verify_pdf", methods=["GET", "POST"])
def verify_pdf():
    verified = False
    message = ""

    if request.method == "POST":
        file = request.files.get("file")
        certificate_id = request.form.get("certificate_id", "").strip()

        if not file or not file.filename:
            message = "Please select a PDF file."
        elif not file.filename.lower().endswith(".pdf"):
            message = "Only PDF files are supported."
        else:
            file_hash = hashlib.sha256(file.read()).hexdigest()

            conn = get_db()
            certificate = conn.execute(
                "SELECT * FROM CERTIFICATES WHERE certificate_id = ?",
                (certificate_id,)
            ).fetchone()
            conn.close()

            if certificate and certificate["file_hash"]:
                verified = file_hash == certificate["file_hash"]
                message = (
                    "PDF verified successfully."
                    if verified
                    else "PDF does not match the stored certificate."
                )
            else:
                message = "Certificate not found or no original PDF hash is stored."

    return render_template(
        "verify_pdf.html",
        verified=verified,
        message=message
    )


# BLOCKCHAIN
@app.route("/blockchain")
def view_blockchain():
    return render_template(
        "blockchain.html",
        chain=blockchain.chain,
        is_valid=blockchain.is_valid()
    )


# CERTIFICATE LIST
@app.route("/certificates")
@login_required
def certificates():
    conn = get_db()
    records = conn.execute(
        "SELECT * FROM CERTIFICATES ORDER BY id DESC"
    ).fetchall()
    conn.close()

    return render_template(
        "index.html",
        certificates=records
    )


# ROBOTS
@app.route("/robots.txt")
def robots():
    return "User-agent: *\nAllow: /\n", 200, {
        "Content-Type": "text/plain"
    }


# SITEMAP
@app.route("/sitemap.xml")
def sitemap():
    base_url = request.host_url.rstrip("/")
    xml = f"""<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
<url><loc>{base_url}/</loc></url>
<url><loc>{base_url}/verify</loc></url>
<url><loc>{base_url}/blockchain</loc></url>
</urlset>"""

    return xml, 200, {"Content-Type": "application/xml"}


init_db()

if __name__ == "__main__":
    app.run(debug=True)
