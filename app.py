from flask import Flask, render_template, request, redirect, url_for, session, send_file, flash
from werkzeug.security import generate_password_hash, check_password_hash
from flask_sqlalchemy import SQLAlchemy
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.backends import default_backend
import base64, json, os, io, secrets

# ------------------ Flask setup ------------------
app = Flask(__name__)
app.config["SECRET_KEY"] = os.environ.get("FLASK_SECRET_KEY", "dev-" + secrets.token_hex(16))
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///users.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
db = SQLAlchemy(app)

# ------------------ DB Model ------------------
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password_hash = db.Column(db.String(256), nullable=False)
    public_key = db.Column(db.Text, nullable=False)
    protected_key = db.Column(db.Text, nullable=False)  # JSON string

# ------------------ Helpers ------------------
def derive_kek_from_password(password: str, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend(),
    )
    return kdf.derive(password.encode())

def protect_private_key(priv_key: ec.EllipticCurvePrivateKey, password: str) -> dict:
    salt = secrets.token_bytes(16)
    kek = derive_kek_from_password(password, salt)
    aesgcm = AESGCM(kek)
    nonce = secrets.token_bytes(12)
    pem = priv_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    ct = aesgcm.encrypt(nonce, pem, None)
    return {
        "salt": base64.b64encode(salt).decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ct).decode(),
    }

def recover_private_key(protected: dict, password: str) -> ec.EllipticCurvePrivateKey:
    salt = base64.b64decode(protected["salt"])
    nonce = base64.b64decode(protected["nonce"])
    ct = base64.b64decode(protected["ciphertext"])
    kek = derive_kek_from_password(password, salt)
    aesgcm = AESGCM(kek)
    pem = aesgcm.decrypt(nonce, ct, None)
    return serialization.load_pem_private_key(pem, password=None, backend=default_backend())

def ecies_encrypt(plaintext: bytes, recipient_pub_pem: bytes) -> dict:
    recipient_pub = serialization.load_pem_public_key(recipient_pub_pem, backend=default_backend())
    eph_priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
    shared = eph_priv.exchange(ec.ECDH(), recipient_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ECC-ECIES", backend=default_backend()).derive(shared)
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    eph_pub_pem = eph_priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return {
        "ephemeral_public_key": eph_pub_pem.decode(),
        "nonce": base64.b64encode(nonce).decode(),
        "ciphertext": base64.b64encode(ciphertext).decode(),
    }

def ecies_decrypt(package: dict, recipient_priv: ec.EllipticCurvePrivateKey) -> bytes:
    eph_pub_pem = package["ephemeral_public_key"].encode()
    nonce = base64.b64decode(package["nonce"])
    ciphertext = base64.b64decode(package["ciphertext"])
    eph_pub = serialization.load_pem_public_key(eph_pub_pem, backend=default_backend())
    shared = recipient_priv.exchange(ec.ECDH(), eph_pub)
    key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"ECC-ECIES", backend=default_backend()).derive(shared)
    aesgcm = AESGCM(key)
    return aesgcm.decrypt(nonce, ciphertext, None)

# ------------------ Routes ------------------
@app.route("/")
def index():
    if "username" in session:
        return redirect(url_for("dashboard"))
    return render_template("index.html")

@app.route("/register", methods=["GET", "POST"])
def register():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        if User.query.filter_by(username=username).first():
            flash("Username already exists.", "error")
            return redirect(url_for("register"))

        pw_hash = generate_password_hash(password)
        priv = ec.generate_private_key(ec.SECP256R1(), backend=default_backend())
        pub = priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode()
        protected = protect_private_key(priv, password)

        user = User(
            username=username,
            password_hash=pw_hash,
            public_key=pub,
            protected_key=json.dumps(protected),
        )
        db.session.add(user)
        db.session.commit()
        flash("Registered successfully. Login now.", "success")
        return redirect(url_for("login"))
    return render_template("register.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        user = User.query.filter_by(username=username).first()
        if not user or not check_password_hash(user.password_hash, password):
            flash("Invalid credentials.", "error")
            return redirect(url_for("login"))
        session["username"] = username
        flash("Login successful.", "success")
        return redirect(url_for("dashboard"))
    return render_template("login.html")

@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("index"))

@app.route("/dashboard")
def dashboard():
    if "username" not in session:
        return redirect(url_for("login"))
    return render_template("dashboard.html", username=session["username"])

@app.route("/process", methods=["POST"])
def process():
    if "username" not in session:
        return redirect(url_for("login"))

    action = request.form["action"]
    target = request.form["target"]
    password = request.form["key_password"]

    user = User.query.filter_by(username=session["username"]).first()
    priv = recover_private_key(json.loads(user.protected_key), password)
    pub_pem = user.public_key.encode()

    # Text encryption/decryption
    if action == "encrypt" and target == "text":
        text = request.form["plain_text"].encode()
        package = ecies_encrypt(text, pub_pem)
        result = base64.b64encode(json.dumps(package).encode()).decode()
        return render_template("result.html", mode="Encrypted Text", output_text=result)

    if action == "decrypt" and target == "text":
        enc = request.form["cipher_text"]
        package = json.loads(base64.b64decode(enc).decode())
        plain = ecies_decrypt(package, priv).decode(errors="ignore")
        return render_template("result.html", mode="Decrypted Text", output_text=plain)

    # File encryption
    if action == "encrypt" and target == "file":
        file = request.files["plain_file"]
        data = file.read()
        package = ecies_encrypt(data, pub_pem)
        blob = base64.b64encode(json.dumps(package).encode())
        return send_file(io.BytesIO(blob), as_attachment=True, download_name=file.filename + ".enc")

    # File decryption
    if action == "decrypt" and target == "file":
        file = request.files["cipher_file"]
        blob = base64.b64decode(file.read())
        package = json.loads(blob.decode())
        data = ecies_decrypt(package, priv)
        return send_file(io.BytesIO(data), as_attachment=True, download_name="decrypted_" + file.filename.replace(".enc", ""))

    flash("Unsupported option.", "error")
    return redirect(url_for("dashboard"))

# ------------------ Main ------------------
if __name__ == "__main__":
    with app.app_context():
        db.create_all()
    app.run(debug=True)
