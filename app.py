import sqlite3
import os
import hmac
import hashlib
import base64
import struct
import time
import json
import secrets
import io
import base64 as b64
try:
    import qrcode
    HAS_QRCODE = True
except ImportError:
    HAS_QRCODE = False
from flask import (Flask, render_template, request, redirect, url_for,
                   session, jsonify, flash)
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime, timedelta
from functools import wraps

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=30)

DB_PATH = os.path.join(os.path.dirname(__file__), 'mfa_app.db')

# ─── DATABASE ────────────────────────────────────────────────────────────────

def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.executescript('''
            CREATE TABLE IF NOT EXISTS users (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                username    TEXT    UNIQUE NOT NULL,
                email       TEXT    UNIQUE NOT NULL,
                password    TEXT    NOT NULL,
                mfa_secret  TEXT,
                mfa_enabled INTEGER DEFAULT 0,
                backup_codes TEXT,
                created_at  TEXT    DEFAULT (datetime('now')),
                last_login  TEXT
            );

            CREATE TABLE IF NOT EXISTS login_attempts (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER,
                ip_address  TEXT,
                success     INTEGER,
                timestamp   TEXT DEFAULT (datetime('now')),
                FOREIGN KEY (user_id) REFERENCES users(id)
            );

            CREATE TABLE IF NOT EXISTS sessions (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id     INTEGER,
                token       TEXT UNIQUE,
                created_at  TEXT DEFAULT (datetime('now')),
                expires_at  TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            );
        ''')

# ─── TOTP (RFC 6238) ─────────────────────────────────────────────────────────

def generate_totp_secret():
    """Generate a random base32 secret for TOTP."""
    random_bytes = secrets.token_bytes(20)
    return base64.b32encode(random_bytes).decode('utf-8')

def get_totp_token(secret: str, timestamp: int = None) -> str:
    """Compute TOTP token (RFC 6238 / HOTP RFC 4226)."""
    if timestamp is None:
        timestamp = int(time.time())
    interval = timestamp // 30
    key = base64.b32decode(secret.upper())
    msg = struct.pack('>Q', interval)
    h = hmac.new(key, msg, hashlib.sha1).digest()
    offset = h[-1] & 0x0F
    code = struct.unpack('>I', h[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code % 1_000_000).zfill(6)

def verify_totp(secret: str, token: str, window: int = 1) -> bool:
    """Verify TOTP token allowing ±window*30s drift."""
    now = int(time.time())
    for delta in range(-window, window + 1):
        expected = get_totp_token(secret, now + delta * 30)
        if hmac.compare_digest(expected, token.strip()):
            return True
    return False

def generate_backup_codes(n: int = 8) -> list:
    return [secrets.token_hex(4).upper() for _ in range(n)]

def get_qr_data_uri(username: str, secret: str) -> str:
    """Generate QR code as base64 data URI."""
    otpauth = f"otpauth://totp/MFA-App:{username}?secret={secret}&issuer=MFA-App&algorithm=SHA1&digits=6&period=30"
    if HAS_QRCODE:
        qr = qrcode.QRCode(box_size=6, border=2)
        qr.add_data(otpauth)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        return "data:image/png;base64," + b64.b64encode(buf.getvalue()).decode()
    else:
        # Fallback: return the otpauth URI so the user can copy it manually
        return f"__otpauth__{otpauth}"

# ─── AUTH HELPERS ─────────────────────────────────────────────────────────────

def log_attempt(user_id, ip, success):
    with get_db() as conn:
        conn.execute(
            "INSERT INTO login_attempts (user_id, ip_address, success) VALUES (?,?,?)",
            (user_id, ip, 1 if success else 0)
        )

def is_rate_limited(ip: str) -> bool:
    with get_db() as conn:
        row = conn.execute(
            "SELECT COUNT(*) as cnt FROM login_attempts "
            "WHERE ip_address=? AND success=0 AND timestamp > datetime('now','-10 minutes')",
            (ip,)
        ).fetchone()
    return row['cnt'] >= 5

def login_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if 'user_id' not in session or not session.get('fully_authenticated'):
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated

# ─── ROUTES ──────────────────────────────────────────────────────────────────

@app.route('/')
def index():
    if session.get('fully_authenticated'):
        return redirect(url_for('dashboard'))
    return redirect(url_for('login'))

# ── Register ──────────────────────────────────────────────────────────────────

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '')
        confirm  = request.form.get('confirm_password', '')

        errors = []
        if len(username) < 3:
            errors.append('Nome de usuário deve ter pelo menos 3 caracteres.')
        if '@' not in email:
            errors.append('E-mail inválido.')
        if len(password) < 8:
            errors.append('Senha deve ter pelo menos 8 caracteres.')
        if password != confirm:
            errors.append('As senhas não coincidem.')

        if not errors:
            with get_db() as conn:
                existing = conn.execute(
                    "SELECT id FROM users WHERE username=? OR email=?",
                    (username, email)
                ).fetchone()
                if existing:
                    errors.append('Usuário ou e-mail já cadastrado.')
                else:
                    conn.execute(
                        "INSERT INTO users (username, email, password) VALUES (?,?,?)",
                        (username, email, generate_password_hash(password))
                    )
                    flash('Conta criada com sucesso! Faça login.', 'success')
                    return redirect(url_for('login'))

        for e in errors:
            flash(e, 'error')

    return render_template('register.html')

# ── Login (step 1: password) ──────────────────────────────────────────────────

@app.route('/login', methods=['GET', 'POST'])
def login():
    if session.get('fully_authenticated'):
        return redirect(url_for('dashboard'))

    if request.method == 'POST':
        ip       = request.remote_addr
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')

        if is_rate_limited(ip):
            flash('Muitas tentativas. Aguarde 10 minutos.', 'error')
            return render_template('login.html')

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE username=? OR email=?",
                (username, username)
            ).fetchone()

        if user and check_password_hash(user['password'], password):
            log_attempt(user['id'], ip, True)
            session['pending_user_id'] = user['id']
            session['pending_username'] = user['username']

            if user['mfa_enabled']:
                return redirect(url_for('mfa_verify'))
            else:
                # MFA not set up — log in directly
                session['user_id'] = user['id']
                session['username'] = user['username']
                session['fully_authenticated'] = True
                session.permanent = True
                with get_db() as conn:
                    conn.execute(
                        "UPDATE users SET last_login=datetime('now') WHERE id=?",
                        (user['id'],)
                    )
                return redirect(url_for('dashboard'))
        else:
            if user:
                log_attempt(user['id'], ip, False)
            flash('Credenciais inválidas.', 'error')

    return render_template('login.html')

# ── Login (step 2: TOTP) ──────────────────────────────────────────────────────

@app.route('/mfa/verify', methods=['GET', 'POST'])
def mfa_verify():
    if 'pending_user_id' not in session:
        return redirect(url_for('login'))

    if request.method == 'POST':
        token = request.form.get('token', '').replace(' ', '')
        use_backup = request.form.get('use_backup') == '1'

        with get_db() as conn:
            user = conn.execute(
                "SELECT * FROM users WHERE id=?", (session['pending_user_id'],)
            ).fetchone()

        valid = False
        if use_backup and user['backup_codes']:
            codes = json.loads(user['backup_codes'])
            if token.upper() in codes:
                codes.remove(token.upper())
                with get_db() as conn:
                    conn.execute(
                        "UPDATE users SET backup_codes=? WHERE id=?",
                        (json.dumps(codes), user['id'])
                    )
                valid = True
        elif user['mfa_secret']:
            valid = verify_totp(user['mfa_secret'], token)

        if valid:
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['fully_authenticated'] = True
            session.permanent = True
            session.pop('pending_user_id', None)
            session.pop('pending_username', None)
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET last_login=datetime('now') WHERE id=?",
                    (user['id'],)
                )
            return redirect(url_for('dashboard'))
        else:
            flash('Código inválido ou expirado.', 'error')

    return render_template('mfa_verify.html', username=session.get('pending_username'))

# ── MFA Setup ─────────────────────────────────────────────────────────────────

@app.route('/mfa/setup', methods=['GET', 'POST'])
@login_required
def mfa_setup():
    user_id = session['user_id']

    if request.method == 'POST':
        action = request.form.get('action')

        if action == 'generate':
            secret = generate_totp_secret()
            session['pending_mfa_secret'] = secret
            qr_uri = get_qr_data_uri(session['username'], secret)
            return jsonify({'secret': secret, 'qr': qr_uri})

        elif action == 'confirm':
            token  = request.form.get('token', '').replace(' ', '')
            secret = session.get('pending_mfa_secret')
            if not secret:
                return jsonify({'ok': False, 'msg': 'Sessão expirada. Gere um novo QR Code.'})
            if verify_totp(secret, token):
                backup_codes = generate_backup_codes()
                with get_db() as conn:
                    conn.execute(
                        "UPDATE users SET mfa_secret=?, mfa_enabled=1, backup_codes=? WHERE id=?",
                        (secret, json.dumps(backup_codes), user_id)
                    )
                session.pop('pending_mfa_secret', None)
                return jsonify({'ok': True, 'backup_codes': backup_codes})
            else:
                return jsonify({'ok': False, 'msg': 'Código inválido. Tente novamente.'})

        elif action == 'disable':
            with get_db() as conn:
                conn.execute(
                    "UPDATE users SET mfa_enabled=0, mfa_secret=NULL, backup_codes=NULL WHERE id=?",
                    (user_id,)
                )
            flash('MFA desativado.', 'info')
            return redirect(url_for('dashboard'))

    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (user_id,)).fetchone()
    return render_template('mfa_setup.html', user=user)

# ── Dashboard ─────────────────────────────────────────────────────────────────

@app.route('/dashboard')
@login_required
def dashboard():
    with get_db() as conn:
        user = conn.execute("SELECT * FROM users WHERE id=?", (session['user_id'],)).fetchone()
        attempts = conn.execute(
            "SELECT * FROM login_attempts WHERE user_id=? ORDER BY timestamp DESC LIMIT 5",
            (session['user_id'],)
        ).fetchall()
    return render_template('dashboard.html', user=user, attempts=attempts)

# ── Logout ────────────────────────────────────────────────────────────────────

@app.route('/logout')
def logout():
    session.clear()
    flash('Sessão encerrada com segurança.', 'info')
    return redirect(url_for('login'))

# ── TOTP live check (for setup page timer) ───────────────────────────────────

@app.route('/api/totp-remaining')
def totp_remaining():
    remaining = 30 - (int(time.time()) % 30)
    return jsonify({'remaining': remaining})

if __name__ == '__main__':
    init_db()
    print("✔  Banco de dados inicializado.")
    print("✔  Servidor rodando em http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
