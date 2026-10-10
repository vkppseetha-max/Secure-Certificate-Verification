from flask import Flask, render_template, request, redirect, url_for
import sqlite3
import hashlib
import uuid
import time
import qrcode
import os

app = Flask(__name__)

DATABASE = "certificates.db"
UPLOAD_FOLDER = "uploads"
QR_FOLDER = "static/qrcodes"

os.makedirs(UPLOAD_FOLDER, exist_ok=True)
os.makedirs(QR_FOLDER, exist_ok=True)


# Generate SHA-256 hash for a file
def file_hash(filepath):
    sha = hashlib.sha256()
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            sha.update(chunk)
    return sha.hexdigest()


# Blockchain block
class Block:
    def __init__(self, index, cert_id, cert_hash, previous_hash):
        self.index = index
        self.cert_id = cert_id
        self.cert_hash = cert_hash
        self.timestamp = time.time()
        self.previous_hash = previous_hash
        self.hash = self.calculate_hash()

    def calculate_hash(self):
        data = (
            str(self.index) + self.cert_id +
            self.cert_hash + str(self.timestamp) +
            self.previous_hash
        )
        return hashlib.sha256(data.encode()).hexdigest()


# Blockchain
class Blockchain:
    def __init__(self):
        self.chain = [
            Block(0, "Genesis", "0", "0")
        ]

    def add_block(self, cert_id, cert_hash):
        previous = self.chain[-1]
        block = Block(
            len(self.chain),
            cert_id,
            cert_hash,
            previous.hash
        )
        self.chain.append(block)

    def verify_chain(self):
        for i in range(1, len(self.chain)):
            current = self.chain[i]
            previous = self.chain[i - 1]

            if current.hash != current.calculate_hash():
                return False

            if current.previous_hash != previous.hash:
                return False

        return True


blockchain = Blockchain()


# Database connection
def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


# Create database table
def create_tables():
    conn = get_db()

    conn.execute("""
        CREATE TABLE IF NOT EXISTS certificates (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            certificate_id TEXT UNIQUE,
            name TEXT,
            course TEXT,
            institution TEXT,
            certificate_hash TEXT
        )
    """)

    conn.commit()
    conn.close()


# Get certificate details
def get_certificate(cert_id):
    conn = get_db()

    cert = conn.execute(
        "SELECT * FROM certificates WHERE certificate_id = ?",
        (cert_id,)
    ).fetchone()

    conn.close()
    return cert


# Save certificate and add blockchain block
def add_certificate(name, course, institution, pdf_path):
    cert_id = str(uuid.uuid4())
    cert_hash = file_hash(pdf_path)

    conn = get_db()

    conn.execute("""
        INSERT INTO certificates
        (certificate_id, name, course, institution, certificate_hash)
        VALUES (?, ?, ?, ?, ?)
    """, (cert_id, name, course, institution, cert_hash))

    conn.commit()
    conn.close()

    blockchain.add_block(cert_id, cert_hash)

    qr_url = url_for("verify", _external=True) + "?id=" + cert_id
    qr = qrcode.make(qr_url)
    qr.save(os.path.join(QR_FOLDER, cert_id + ".png"))

    return cert_id


# Home page
@app.route("/")
def home():
    return render_template("index.html")


# Issue certificate
@app.route("/issue", methods=["GET", "POST"])
def issue():
    if request.method == "POST":
        name = request.form.get("name", "").strip()
        course = request.form.get("course", "").strip()
        institution = request.form.get("institution", "").strip()
        pdf = request.files.get("pdf")

        if not name or not course or not institution:
            return "All fields are required", 400

        if not pdf or not pdf.filename.lower().endswith(".pdf"):
            return "Please upload a PDF certificate", 400

        filename = str(uuid.uuid4()) + ".pdf"
        path = os.path.join(UPLOAD_FOLDER, filename)
        pdf.save(path)

        cert_id = add_certificate(
            name, course, institution, path
        )

        return redirect(url_for("result", certificate_id=cert_id))

    return render_template("issue.html")


# Certificate result page
@app.route("/result/<certificate_id>")
def result(certificate_id):
    certificate = get_certificate(certificate_id)

    return render_template(
        "result.html",
        certificate=certificate
    )


# Verify certificate ID
@app.route("/verify", methods=["GET", "POST"])
def verify():
    certificate = None
    message = None

    cert_id = request.args.get("id", "").strip()

    if request.method == "POST":
        cert_id = request.form.get("certificate_id", "").strip()

    if cert_id:
        certificate = get_certificate(cert_id)

        if not certificate:
            message = "Certificate Not Found"
        else:
            block_exists = any(
                b.cert_id == cert_id and
                b.cert_hash == certificate["certificate_hash"]
                for b in blockchain.chain
            )

            if block_exists and blockchain.verify_chain():
                message = "Certificate Record Found"
            else:
                message = "Certificate Invalid or Tampered"

    return render_template(
        "verify.html",
        certificate=certificate,
        message=message
    )


# Verify uploaded PDF
@app.route("/verify-pdf", methods=["GET", "POST"])
def verify_pdf():
    message = None

    if request.method == "POST":
        pdf = request.files.get("pdf")

        if not pdf or not pdf.filename.lower().endswith(".pdf"):
            message = "Please upload a PDF file"
        else:
            temp_path = os.path.join(
                UPLOAD_FOLDER,
                str(uuid.uuid4()) + ".pdf"
            )

            pdf.save(temp_path)
            uploaded_hash = file_hash(temp_path)
            os.remove(temp_path)

            conn = get_db()
            certs = conn.execute(
                "SELECT * FROM certificates"
            ).fetchall()
            conn.close()

            found = None

            for cert in certs:
                if cert["certificate_hash"] == uploaded_hash:
                    found = cert
                    break

            if found:
                block_exists = any(
                    b.cert_id == found["certificate_id"] and
                    b.cert_hash == uploaded_hash
                    for b in blockchain.chain
                )

                if block_exists and blockchain.verify_chain():
                    message = (
                        "VALID: Certificate PDF matches "
                        "the stored record"
                    )
                else:
                    message = (
                        "INVALID: Blockchain record "
                        "verification failed"
                    )
            else:
                message = (
                    "INVALID: Certificate not found or "
                    "PDF has been changed"
                )

    return render_template(
        "verify_pdf.html",
        message=message
    )


# Styled blockchain page
@app.route("/blockchain")
def view_blockchain():
    return render_template(
        "blockchain.html",
        blockchain_valid=blockchain.verify_chain(),
        blocks=blockchain.chain
    )


# Run application
if __name__ == "__main__":
    create_tables()
    app.run(debug=True)