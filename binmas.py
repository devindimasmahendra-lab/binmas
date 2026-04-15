# FIX UNICODE ENCODING UNTUK WINDOWS CONSOLE
import sys
import os
import logging

# ✅ [FIX] Setup Logging Sistem - JANGAN LAGI PAKAI except: pass!
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s | %(levelname)-8s | %(message)s",
    handlers=[
        logging.FileHandler(os.path.join(os.path.dirname(__file__), "binmas_errors.log")),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)

if sys.platform == "win32":
    # Paksa encoding stdout ke UTF-8
    sys.stdout.reconfigure(encoding='utf-8')
    sys.stderr.reconfigure(encoding='utf-8')
    # Set environment variable untuk memastikan python pakai UTF-8
    os.environ['PYTHONIOENCODING'] = 'utf-8'
    os.environ['PYTHONLEGACYWINDOWSSTDIO'] = '1'

from flask import Flask, request, session, redirect, url_for, render_template_string, jsonify, g, abort, make_response, send_from_directory
from flask_sock import Sock
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3
import json
import hashlib
import hmac
import secrets
import io
import re
from functools import wraps
from datetime import datetime, timedelta
from threading import Lock
import pandas as pd

APP_NAME = "Command Center Sumatera Selatan"
DB_PATH = os.path.join(os.path.dirname(__file__), "app.db")
PBKDF2_ITERATIONS = 260000
DEFAULT_RESET_PASSWORD = "binmas@123"
ROLES = ("anggota", "direktur_binmas", "admin", "satpam", "admin_bujp")

# ✅ KONSTANTA NOMOR REKENING RESMI (UBAH DISINI SAJA JIKA BERUBAH)
NOMOR_REKENING_DEFAULT = "BCA 1234567890 a/n PT. BINMAS SUMATERA SELATAN"

# ✅ [FIX] Timezone Indonesia (WIB UTC+7) — dipakai untuk tampilan waktu lokal
from datetime import timezone as _tz
WIB = _tz(timedelta(hours=7))

def now_wib() -> datetime:
    """Waktu sekarang dalam zona waktu WIB (UTC+7)."""
    return datetime.now(WIB)

def now_str() -> str:
    """Timestamp UTC untuk disimpan ke database."""
    return datetime.now(_tz.utc).strftime("%Y-%m-%d %H:%M:%S")

def wib_str(dt_utc_str: str) -> str:
    """Konversi string UTC (dari DB) ke tampilan WIB. Contoh: '2025-04-11 05:30:00' -> '11/04/2025 12:30 WIB'."""
    try:
        dt = datetime.strptime(dt_utc_str, "%Y-%m-%d %H:%M:%S").replace(tzinfo=_tz.utc)
        dt_wib = dt.astimezone(WIB)
        return dt_wib.strftime("%d/%m/%Y %H:%M WIB")
    except Exception:
        return dt_utc_str


app = Flask(__name__)
app.config.update(
    SECRET_KEY=os.environ.get('SECRET_KEY', secrets.token_hex(32)),
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)
sock = Sock(app)

# ✅ RATE LIMITER OPTIMASI UNTUK 200 USER BERSAMAAN + ANTI BRUTE FORCE
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["800 per minute"],
    storage_uri="memory://",
    strategy="fixed-window",
    headers_enabled=True,
    on_breach=lambda e: (jsonify({"error": "Terlalu banyak permintaan, tunggu sebentar", "retry_after": e.description}), 429)
)

# ✅ LOGIN LIMIT SMART: 12 PERCOBAAN PER 5 MENIT PER IP
# Cukup untuk 200 user dari jaringan kantor yang NAT IP nya sama
login_limiter = limiter.shared_limit("12 per 5 minute", scope="login")

# ✅ [FIX] PENYIMPANAN LOG GAGAL LOGIN — thread-safe dengan Lock
LOGIN_FAILURES = {}
LOGIN_FAILURES_LOCK = Lock()  # Lock untuk thread-safety
FAILURE_BLOCK_THRESHOLD = 12
BLOCK_DURATION_MINUTES = 45


def check_brute_force(ip_address):
    """✅ [FIX] CEK APAKAH IP INI TERBLOKIR — thread-safe"""
    now = datetime.now()
    with LOGIN_FAILURES_LOCK:
        data = LOGIN_FAILURES.get(ip_address)
        if not data:
            return True
        count = data.get('count', 0)
        last_failure = data.get('last_failure')
        if count >= FAILURE_BLOCK_THRESHOLD:
            elapsed = now - last_failure
            if elapsed < timedelta(minutes=BLOCK_DURATION_MINUTES):
                return False
            else:
                LOGIN_FAILURES.pop(ip_address, None)
                return True
    return True


def record_login_failure(ip_address):
    """✅ [FIX] CATAT KEGAGALAN LOGIN — thread-safe"""
    now = datetime.now()
    with LOGIN_FAILURES_LOCK:
        if ip_address not in LOGIN_FAILURES:
            LOGIN_FAILURES[ip_address] = {'count': 0, 'last_failure': now}
        LOGIN_FAILURES[ip_address]['count'] += 1
        LOGIN_FAILURES[ip_address]['last_failure'] = now
        return LOGIN_FAILURES[ip_address]['count']



def reset_login_failures(ip_address):
    """✅ [FIX] RESET COUNTER KETIKA LOGIN BERHASIL — thread-safe"""
    with LOGIN_FAILURES_LOCK:
        LOGIN_FAILURES.pop(ip_address, None)


# Serve static files
@app.route('/static/<path:filename>')
def serve_static(filename):
    static_dir = os.path.join(os.path.dirname(__file__), "static")
    return send_from_directory(static_dir, filename)

# 📁 Serve static file uploads emergency
@app.route('/uploads/emergency/<path:filename>')
def serve_emergency_uploads(filename):
    upload_dir = os.path.join(os.path.dirname(__file__), "uploads", "emergency")
    os.makedirs(upload_dir, exist_ok=True)
    return send_from_directory(upload_dir, filename)

WS_LOCK = Lock()
MONITOR_SOCKETS = set()
SATPAM_SOCKETS = {}  # user_id -> set(websocket)





def row_get(row, key, default=None):
    """[FIX] Helper aman untuk ambil nilai dari sqlite3.Row dengan default, tanpa error!
    Menggantikan row.get() yang TIDAK ADA di sqlite3.Row - INI PENYEBAB UTAMA ERROR!
    """
    try:
        return row[key] if row and key in row.keys() else default
    except (KeyError, IndexError):
        return default

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
        # ✅ [FIX] Aktifkan WAL untuk performa multi-user + enforce FK
        g.db.execute("PRAGMA journal_mode=WAL")
        g.db.execute("PRAGMA foreign_keys=ON")
        g.db.execute("PRAGMA synchronous=NORMAL")
        g.db.execute("PRAGMA cache_size=-32000")   # ~32 MB cache
    return g.db



@app.teardown_appcontext
def close_db(_e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, iterations, salt_hex, digest_hex = stored.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac(
            "sha256",
            password.encode("utf-8"),
            bytes.fromhex(salt_hex),
            int(iterations),
        )
        return hmac.compare_digest(dk.hex(), digest_hex)
    except Exception:
        return False


def init_db():
    db = sqlite3.connect(DB_PATH)
    db.executescript("""
    CREATE TABLE IF NOT EXISTS bujp (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nama_bujp TEXT NOT NULL,
        no_izin TEXT DEFAULT '',
        alamat TEXT DEFAULT '',
        penanggung_jawab TEXT DEFAULT '',
        no_hp TEXT DEFAULT '',
        email TEXT DEFAULT '',
        masa_berlaku_izin TEXT DEFAULT '',
        keterangan TEXT DEFAULT '',
        is_active INTEGER NOT NULL DEFAULT 1,
        has_account INTEGER NOT NULL DEFAULT 0,
        user_id INTEGER DEFAULT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        full_name TEXT NOT NULL,
        role TEXT NOT NULL CHECK(role IN ('anggota','direktur_binmas','admin','satpam')),
        password_hash TEXT NOT NULL,
        is_active INTEGER NOT NULL DEFAULT 1,
        bujp_id INTEGER DEFAULT NULL,
        no_kta TEXT DEFAULT '',
        kta_expiry_date TEXT DEFAULT '',
        nik TEXT DEFAULT '',
        no_hp TEXT DEFAULT '',
        alamat TEXT DEFAULT '',
        tanggal_lahir TEXT DEFAULT '',
        tanggal_masuk TEXT DEFAULT '',
        jabatan TEXT DEFAULT '',
        foto_profil TEXT DEFAULT '',
        profile_updated_at TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (bujp_id) REFERENCES bujp(id)
    );

    CREATE TABLE IF NOT EXISTS kta_perpanjangan (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        no_kta_lama TEXT DEFAULT '',
        tanggal_pengajuan TEXT NOT NULL,
        alasan_perpanjangan TEXT NOT NULL,
        masa_berlaku_lama TEXT DEFAULT '',
        masa_berlaku_baru TEXT DEFAULT '',
        no_kta_baru TEXT DEFAULT '',
        status TEXT NOT NULL DEFAULT 'pending',
        catatan_admin TEXT DEFAULT '',
        tanggal_verifikasi TEXT DEFAULT '',
        admin_id INTEGER DEFAULT NULL,
        dokumen_pendukung TEXT DEFAULT '',
        jadwal_pengambilan TEXT DEFAULT '',
        lokasi_pengambilan TEXT DEFAULT '',
        persyaratan TEXT DEFAULT '',
        kontak_person TEXT DEFAULT '',
        status_kta_diambil TEXT DEFAULT 'pending',
        tanggal_pengambilan TEXT DEFAULT '',
        -- ✅ [BARU] SISTEM PEMBAYARAN KTA
        metode_pembayaran TEXT DEFAULT NULL CHECK(metode_pembayaran IN ('aplikasi', 'langsung', NULL)),
        nomor_rekening_admin TEXT DEFAULT '',
        bukti_pembayaran_url TEXT DEFAULT '',
        status_pembayaran TEXT DEFAULT 'pending' CHECK(status_pembayaran IN ('pending', 'menunggu_verifikasi', 'terverifikasi', 'ditolak')),
        tanggal_upload_bukti TEXT DEFAULT '',
        admin_verifikasi_pembayaran_id INTEGER DEFAULT NULL,
        tanggal_verifikasi_pembayaran TEXT DEFAULT '',
        catatan_verifikasi_pembayaran TEXT DEFAULT '',
        FOREIGN KEY(user_id) REFERENCES users(id),
        FOREIGN KEY(admin_id) REFERENCES users(id),
        FOREIGN KEY(admin_verifikasi_pembayaran_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS locations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        lat REAL NOT NULL,
        lng REAL NOT NULL,
        accuracy REAL,
        speed REAL,
        altitude REAL,
        source TEXT DEFAULT 'gps',
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS geofences (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        geojson TEXT NOT NULL,
        created_by INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        actor_user_id INTEGER,
        action TEXT NOT NULL,
        target_type TEXT,
        target_id TEXT,
        detail TEXT,
        ip_address TEXT,
        created_at TEXT NOT NULL,
        FOREIGN KEY (actor_user_id) REFERENCES users(id)
    );

 
    CREATE TABLE IF NOT EXISTS absensi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tanggal TEXT NOT NULL,
        waktu TEXT NOT NULL,
        tipe TEXT NOT NULL CHECK(tipe IN ('MASUK', 'KELUAR')),
        lat REAL,
        lng REAL,
        akurasi REAL,
        status TEXT,
        lokasi TEXT,
        sesi_id INTEGER DEFAULT NULL,
        created_at TEXT NOT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (sesi_id) REFERENCES absensi_sesi(id)
    );

    -- ✅ [NEW] Sesi absensi yang dikontrol oleh admin
    CREATE TABLE IF NOT EXISTS absensi_sesi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nama_sesi TEXT NOT NULL,
        tanggal TEXT NOT NULL,
        jam_buka_masuk TEXT NOT NULL DEFAULT '07:00',
        jam_tutup_masuk TEXT NOT NULL DEFAULT '09:00',
        jam_buka_keluar TEXT DEFAULT '16:00',
        jam_tutup_keluar TEXT DEFAULT '23:59',
        batas_terlambat TEXT DEFAULT '08:00',
        status TEXT NOT NULL DEFAULT 'draft'
            CHECK(status IN ('draft','aktif','selesai','ditutup')),
        geofence_wajib INTEGER DEFAULT 0,
        radius_meter INTEGER DEFAULT 200,
        bujp_id INTEGER DEFAULT NULL,
        keterangan TEXT DEFAULT '',
        dibuat_oleh INTEGER NOT NULL,
        diaktifkan_oleh INTEGER DEFAULT NULL,
        diaktifkan_at TEXT DEFAULT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (dibuat_oleh) REFERENCES users(id),
        FOREIGN KEY (diaktifkan_oleh) REFERENCES users(id),
        FOREIGN KEY (bujp_id) REFERENCES bujp(id)
    );

    -- ✅ [NEW] Konfigurasi absensi global (bisa diubah admin)
    CREATE TABLE IF NOT EXISTS absensi_config (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        config_key TEXT NOT NULL UNIQUE,
        config_value TEXT NOT NULL,
        updated_by INTEGER,
        updated_at TEXT NOT NULL,
        FOREIGN KEY (updated_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS rekening_bank (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nama_bank TEXT NOT NULL,
        nomor_rekening TEXT NOT NULL,
        atas_nama TEXT NOT NULL,
        keterangan TEXT DEFAULT '',
        is_active INTEGER NOT NULL DEFAULT 1,
        urutan INTEGER NOT NULL DEFAULT 0,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL,
        created_by INTEGER DEFAULT NULL,
        updated_by INTEGER DEFAULT NULL,
        FOREIGN KEY (created_by) REFERENCES users(id),
        FOREIGN KEY (updated_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS rekening_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        rekening_id INTEGER,  -- ✅ [FIX] UBAH JADI BISA NULL UNTUK LOG HAPUS
        aksi TEXT NOT NULL CHECK(aksi IN ('tambah', 'ubah', 'hapus', 'aktifkan', 'nonaktifkan')),
        data_lama TEXT,
        data_baru TEXT,
        user_id INTEGER NOT NULL,
        created_at TEXT NOT NULL,
        keterangan TEXT DEFAULT '',
        FOREIGN KEY (rekening_id) REFERENCES rekening_bank(id) ON DELETE SET NULL,
        FOREIGN KEY (user_id) REFERENCES users(id)
    );



    CREATE TABLE IF NOT EXISTS emergency_reports (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        lat REAL NOT NULL,
        lng REAL NOT NULL,
        akurasi REAL,
        keterangan TEXT DEFAULT '',
        foto_url TEXT DEFAULT '',
        status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'processed', 'closed')),
        admin_note TEXT DEFAULT '',
        handled_by INTEGER DEFAULT NULL,
        handled_at TEXT DEFAULT NULL,
        created_at TEXT NOT NULL,
        updated_at TEXT DEFAULT NULL,
        FOREIGN KEY (user_id) REFERENCES users(id),
        FOREIGN KEY (handled_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS admin_notifications (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        admin_id INTEGER NOT NULL,
        target_user_id INTEGER,
        target_role TEXT,
        title TEXT NOT NULL,
        message TEXT NOT NULL,
        type TEXT DEFAULT 'info' CHECK(type IN ('info', 'warning', 'important', 'emergency')),
        is_read INTEGER DEFAULT 0,
        read_at TEXT,
        created_at TEXT NOT NULL,
        expires_at TEXT,
        FOREIGN KEY (admin_id) REFERENCES users(id),
        FOREIGN KEY (target_user_id) REFERENCES users(id)
    );
    """)
    db.commit()

    # MIGRASI BUJP - FIX UNTUK SQLITE YANG TIDAK SUPPORT IF NOT EXISTS
    try:
        cursor = db.execute("PRAGMA table_info(bujp)")
        columns = [row[1] for row in cursor.fetchall()]
        
        required_columns = [
            ('no_izin', "TEXT DEFAULT ''"),
            ('alamat', "TEXT DEFAULT ''"),
            ('penanggung_jawab', "TEXT DEFAULT ''"),
            ('no_hp', "TEXT DEFAULT ''"),
            ('email', "TEXT DEFAULT ''"),
            ('masa_berlaku_izin', "TEXT DEFAULT ''"),
            ('keterangan', "TEXT DEFAULT ''"),
            ('is_active', "INTEGER NOT NULL DEFAULT 1"),
            ('has_account', "INTEGER NOT NULL DEFAULT 0"),
            ('user_id', "INTEGER DEFAULT NULL"),
            ('latitude', "REAL DEFAULT NULL"),
            ('longitude', "REAL DEFAULT NULL"),
            ('geofence_radius', "INTEGER DEFAULT 100"),
            ('geofence_coords', "TEXT DEFAULT NULL"),
            ('created_at', "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP"),
            ('updated_at', "TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP")
        ]
        
        for col_name, col_def in required_columns:
            if col_name not in columns:
                try:
                    db.execute(f"ALTER TABLE bujp ADD COLUMN {col_name} {col_def}")
                except:
                    pass # abaikan jika sudah ada
        db.commit()
    except:
        pass

    # MIGRASI TABLE EMERGENCY_REPORTS - TAMBAHKAN KOLOM updated_at
    try:
        cursor = db.execute("PRAGMA table_info(emergency_reports)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'updated_at' not in columns:
            try:
                db.execute("ALTER TABLE emergency_reports ADD COLUMN updated_at TEXT DEFAULT NULL")
                db.commit()
            except:
                pass # abaikan jika sudah ada
    except:
        pass

    # ✅ [NEW] MIGRASI TABEL ABSENSI — tambah kolom sesi_id
    try:
        cursor = db.execute("PRAGMA table_info(absensi)")
        absensi_cols = [row[1] for row in cursor.fetchall()]
        if 'sesi_id' not in absensi_cols:
            db.execute("ALTER TABLE absensi ADD COLUMN sesi_id INTEGER DEFAULT NULL")
            db.commit()
    except Exception:
        pass

    # ✅ [NEW] Buat tabel absensi_sesi jika belum ada
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS absensi_sesi (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nama_sesi TEXT NOT NULL,
                tanggal TEXT NOT NULL,
                jam_buka_masuk TEXT NOT NULL DEFAULT '07:00',
                jam_tutup_masuk TEXT NOT NULL DEFAULT '09:00',
                jam_buka_keluar TEXT DEFAULT '16:00',
                jam_tutup_keluar TEXT DEFAULT '23:59',
                batas_terlambat TEXT DEFAULT '08:00',
                status TEXT NOT NULL DEFAULT 'draft'
                    CHECK(status IN ('draft','aktif','selesai','ditutup')),
                geofence_wajib INTEGER DEFAULT 0,
                radius_meter INTEGER DEFAULT 200,
                bujp_id INTEGER DEFAULT NULL,
                keterangan TEXT DEFAULT '',
                dibuat_oleh INTEGER NOT NULL,
                diaktifkan_oleh INTEGER DEFAULT NULL,
                diaktifkan_at TEXT DEFAULT NULL,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            )
        """)
        db.commit()
    except Exception:
        pass

    # ✅ [NEW] Buat tabel absensi_config jika belum ada
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS absensi_config (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                config_key TEXT NOT NULL UNIQUE,
                config_value TEXT NOT NULL,
                updated_by INTEGER,
                updated_at TEXT NOT NULL
            )
        """)
        db.commit()
        # Insert config defaults
        for key, val in [
            ("absensi_mode", "bebas"),
            ("geofence_wajib_global", "0"),
            ("radius_absen_default", "200"),
        ]:
            try:
                db.execute(
                    "INSERT OR IGNORE INTO absensi_config (config_key, config_value, updated_at) VALUES (?, ?, ?)",
                    (key, val, now_str())
                )
            except Exception:
                pass
        db.commit()
    except Exception:
        pass

    # ✅ MIGRASI KOLOM PEMBAYARAN KTA
    try:
        cursor = db.execute("PRAGMA table_info(kta_perpanjangan)")
        columns = [row[1] for row in cursor.fetchall()]
        
        kta_payment_columns = [
            ('metode_pembayaran', "TEXT DEFAULT NULL CHECK(metode_pembayaran IN ('aplikasi', 'langsung', NULL))"),
            ('nomor_rekening_admin', "TEXT DEFAULT ''"),
            ('bukti_pembayaran_url', "TEXT DEFAULT ''"),
            ('status_pembayaran', "TEXT DEFAULT 'pending' CHECK(status_pembayaran IN ('pending', 'menunggu_verifikasi', 'terverifikasi', 'ditolak'))"),
            ('tanggal_upload_bukti', "TEXT DEFAULT ''"),
            ('admin_verifikasi_pembayaran_id', "INTEGER DEFAULT NULL REFERENCES users(id)"),
            ('tanggal_verifikasi_pembayaran', "TEXT DEFAULT ''"),
            ('catatan_verifikasi_pembayaran', "TEXT DEFAULT ''"),
            ('jadwal_pengambilan', "TEXT DEFAULT ''"),
            ('lokasi_pengambilan', "TEXT DEFAULT ''")
        ]
        
        for col_name, col_def in kta_payment_columns:
            if col_name not in columns:
                try:
                    db.execute(f"ALTER TABLE kta_perpanjangan ADD COLUMN {col_name} {col_def}")
                    print(f"✅ [MIGRASI] Kolom {col_name} ditambahkan ke tabel kta_perpanjangan")
                except:
                    pass # abaikan jika sudah ada
        db.commit()
    except Exception as e:
        logger.warning(f"⚠️ Gagal migrasi kolom pembayaran KTA: {e}")


    # MIGRASI TABEL USERS - TAMBAHKAN KOLOM bujp_id JIKA BELUM ADA
    try:
        cursor = db.execute("PRAGMA table_info(users)")
        columns = [row[1] for row in cursor.fetchall()]
        if 'bujp_id' not in columns:
            try:
                db.execute("ALTER TABLE users ADD COLUMN bujp_id INTEGER DEFAULT NULL REFERENCES bujp(id)")
                db.commit()
            except:
                pass # abaikan jika sudah ada
        
        # Tambahkan kolom untuk verifikasi BUJP
        if 'bujp_verified' not in columns:
            try:
                db.execute("ALTER TABLE users ADD COLUMN bujp_verified INTEGER NOT NULL DEFAULT 0")
                db.commit()
                print("✅ [MIGRASI] Kolom bujp_verified ditambahkan ke tabel users")
            except:
                pass
        
        if 'bujp_verified_at' not in columns:
            try:
                db.execute("ALTER TABLE users ADD COLUMN bujp_verified_at TEXT DEFAULT NULL")
                db.commit()
            except:
                pass
        
        if 'bujp_verified_by' not in columns:
            try:
                db.execute("ALTER TABLE users ADD COLUMN bujp_verified_by INTEGER DEFAULT NULL REFERENCES users(id)")
                db.commit()
            except:
                pass

        # Set semua user existing yang sudah punya bujp_id menjadi terverifikasi otomatis
        try:
            db.execute("UPDATE users SET bujp_verified = 1 WHERE bujp_id IS NOT NULL AND bujp_verified = 0")
            db.commit()
        except:
            pass
    except:
        pass

    # ✅ [FIX] Password diambil dari environment variable, bukan hardcoded
    # Set via: export ADMIN_PASS=xxx DIREKTUR_PASS=xxx SATPAM_PASS=xxx
    defaults = [
        ("admin", "Administrator", "admin",
            os.environ.get("ADMIN_PASS", secrets.token_urlsafe(12))),
        ("direktur", "Direktur Binmas", "direktur_binmas",
            os.environ.get("DIREKTUR_PASS", secrets.token_urlsafe(12))),
        ("satpam1", "Satpam Utama", "satpam",
            os.environ.get("SATPAM_DEFAULT_PASS", secrets.token_urlsafe(12))),
        ("anggota1", "Anggota Default", "anggota",
            os.environ.get("ANGGOTA_DEFAULT_PASS", secrets.token_urlsafe(12))),
    ]
    # ✅ Tampilkan password hanya jika akun baru (bukan update) dan insert sekaligus
    for username, full_name, role, password in defaults:
        exists = db.execute("SELECT id FROM users WHERE username=?", (username,)).fetchone()
        if not exists:
            print(f"  [INIT] Akun '{username}' dibuat, password: {password}")
            ts = now_str()
            db.execute(
                "INSERT INTO users (username, full_name, role, password_hash, is_active, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)",
                (username, full_name, role, hash_password(password), ts, ts),
            )

    if not db.execute("SELECT id FROM geofences LIMIT 1").fetchone():
        sample = {
            "type": "Feature",
            "properties": {"name": "Area Contoh"},
            "geometry": {
                "type": "Polygon",
                "coordinates": [[[106.8220, -6.1765], [106.8260, -6.1765], [106.8260, -6.1725], [106.8220, -6.1725], [106.8220, -6.1765]]],
            },
        }
        admin = db.execute("SELECT id FROM users WHERE role='admin' LIMIT 1").fetchone()
        ts = now_str()
        db.execute(
            "INSERT INTO geofences (name, geojson, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
            ("Area Contoh", json.dumps(sample), admin[0] if admin else None, ts, ts),
        )

    # ✅ [BARU] TABEL RESET PASSWORD SATPAM
    try:
        db.execute("""
            CREATE TABLE IF NOT EXISTS password_reset (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL UNIQUE,
                reset_code TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                attempts INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            )
        """)
        db.commit()
    except Exception:
        pass

    db.commit()
    db.close()


def current_user():
    uid = session.get("user_id")
    if not uid:
        return None
    return get_db().execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()


def login_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("user_id"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


def roles_required(*roles):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for("login"))
            if user["role"] not in roles:
                abort(403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def log_action(action, target_type=None, target_id=None, detail=None):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (actor_user_id, action, target_type, target_id, detail, ip_address, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            session.get("user_id"),
            action,
            target_type,
            str(target_id) if target_id is not None else None,
            detail,
            request.headers.get("X-Forwarded-For", request.remote_addr),
            now_str(),
        ),
    )
    db.commit()


def redirect_by_role(role):
    if role == "admin":
        return redirect(url_for("admin_dashboard"))
    if role == "direktur_binmas":
        return redirect(url_for("monitor_map"))
    if role == "satpam":
        return redirect(url_for("satpam_page"))
    return redirect(url_for("bujp_dashboard"))


def nav_html(user):
    if not user:
        return ""
    # Hitung jumlah laporan emergency pending untuk badge notifikasi
    emergency_pending_count = 0
    kta_pending_count = 0
    if user["role"] in ("admin", "direktur_binmas"):
        try:
            emergency_pending_count = get_db().execute("SELECT COUNT(*) FROM emergency_reports WHERE status = 'pending'").fetchone()[0]
            kta_pending_count = get_db().execute("SELECT COUNT(*) FROM kta_perpanjangan WHERE status = 'pending'").fetchone()[0]
        except:
            emergency_pending_count = 0
            kta_pending_count = 0


    if user["role"] == "admin":
        items = [
            (url_for("admin_dashboard"), "Admin"),
            (url_for("admin_kta_perpanjangan"), "📋 Pengajuan KTA", kta_pending_count),
            (url_for("bujp_management"), "Manajemen BUJP"),
            (url_for("monitor_map"), "Map Monitor"),
            (url_for("emergency_alert_map"), "🚨 Maps Alert", emergency_pending_count),
            (url_for("admin_emergency_reports"), "📋 Daftar Laporan Darurat"),
            (url_for("admin_absensi_sesi"), "📅 Kelola Absensi"),   # ✅ [NEW]
            (url_for("admin_absensi_rekap"), "📊 Rekap Absensi"),   # ✅ [NEW]
            (url_for("admin_rekening_management"), "💳 Manajemen Rekening"),   # ✅ [NEW]
            (url_for("change_password"), "Ganti Password"),
            (url_for("logout"), "Logout"),
        ]


    elif user["role"] == "direktur_binmas":
        items = [
            (url_for("monitor_map"), "Map Satpam"),
            (url_for("emergency_alert_map"), "🚨 Maps Alert", emergency_pending_count),
            (url_for("admin_emergency_reports"), "📋 Daftar Laporan Darurat"),
            (url_for("direktur_maps_bujp"), "🗺️ Maps Perusahaan"),
            (url_for("bujp_management"), "Manajemen BUJP"),
            (url_for("change_password"), "Ganti Password"),
            (url_for("logout"), "Logout"),
        ]
    elif user["role"] == "satpam":
        items = [
            (url_for("satpam_page"), "🏠 Beranda"),
            (url_for("satpam_profile"), "👤 Profil KTA"),
            (url_for("change_password"), "🔑 Ganti Password"),
            (url_for("logout"), "🚪 Logout"),
        ]
    else:
        items = [
            (url_for("bujp_dashboard"), "Beranda"),
            (url_for("change_password"), "Ganti Password"),
            (url_for("logout"), "Logout"),
        ]
    nav_items = []
    for item in items:
        if len(item) == 3:
            href, label, badge_count = item
            if badge_count and badge_count > 0:
                # Tampilkan badge notifikasi merah dengan angka
                nav_items.append(f'''
                <a href="{href}" class="px-3 py-2 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition relative">
                    {label}
                    <span class="emergency-badge absolute -top-1 -right-1 bg-red-500 text-white text-xs font-black rounded-full w-5 h-5 flex items-center justify-center animate-pulse">
                        {badge_count}
                    </span>
                </a>
                ''')
            else:
                nav_items.append(f'<a href="{href}" class="px-3 py-2 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition">{label}</a>')
        else:
            href, label = item
            nav_items.append(f'<a href="{href}" class="px-3 py-2 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition">{label}</a>')

    return "".join(nav_items)


BASE_TEMPLATE = """
<!doctype html>
<html lang="id" class="dark">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover">
  <title>{{ title }} - {{ app_name }}</title>
  <meta name="theme-color" content="#0b1220">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <link rel="manifest" href="{{ url_for('manifest') }}">
  <script src="https://cdn.tailwindcss.com"></script>
  <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="" />
  <link rel="stylesheet" href="https://unpkg.com/leaflet-draw@1.0.4/dist/leaflet.draw.css" />
  <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>

  <script src="https://unpkg.com/leaflet-draw@1.0.4/dist/leaflet.draw.js"></script>
  <!-- ✅ [NEW] Leaflet.heat untuk heatmap & Leaflet.markercluster untuk cluster -->
  <script src="https://unpkg.com/leaflet.heat@0.2.0/dist/leaflet-heat.js"></script>
  <link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.css" />
  <link rel="stylesheet" href="https://unpkg.com/leaflet.markercluster@1.5.3/dist/MarkerCluster.Default.css" />
  <script src="https://unpkg.com/leaflet.markercluster@1.5.3/dist/leaflet.markercluster.js"></script>


  <style>
    :root { color-scheme: dark; }
    body {
      background: radial-gradient(circle at top left, rgba(6,182,212,.15), transparent 25%),
                  radial-gradient(circle at bottom right, rgba(168,85,247,.15), transparent 25%),
                  linear-gradient(180deg, #060b16, #0b1220 35%, #0f172a 100%);
      min-height: 100vh;
    }
    .glass {
      background: rgba(255,255,255,.06);
      backdrop-filter: blur(14px);
      -webkit-backdrop-filter: blur(14px);
      border: 1px solid rgba(255,255,255,.10);
      box-shadow: 0 10px 30px rgba(0,0,0,.25);
    }
    .leaflet-container { background: #111827; }
    ::-webkit-scrollbar { width: 10px; height: 10px; }
    ::-webkit-scrollbar-thumb { background: rgba(255,255,255,.15); border-radius: 999px; }
    
    /* Emergency Badge Notifikasi */
    .emergency-badge {
        box-shadow: 0 0 12px rgba(239, 68, 68, 0.7);
        animation: emergency-blink 1.2s infinite;
    }
    
    @keyframes emergency-blink {
        0%, 100% { 
            transform: scale(1); 
            box-shadow: 0 0 10px rgba(239, 68, 68, 0.6);
        }
        50% { 
            transform: scale(1.15); 
            box-shadow: 0 0 20px rgba(239, 68, 68, 0.9);
        }
    }
  </style>
</head>
<body class="text-slate-100">
  <!-- ✅ MODAL DETAIL LAPORAN DARURAT RESPONSIF -->
  <div id="emergencyDetailModal" class="fixed inset-0 bg-black/90 z-50 hidden flex items-center justify-center p-2 sm:p-4">
    <div class="glass rounded-3xl w-full max-w-2xl max-h-[95vh] overflow-auto">
      <!-- Header Modal -->
      <div class="sticky top-0 bg-gradient-to-b from-[#0f172a] to-[#0f172a]/95 p-4 sm:p-6 border-b border-white/10">
        <div class="flex justify-between items-center gap-3">
          <div>
            <div class="text-xl sm:text-2xl font-black text-red-400">🚨 DETAIL LAPORAN DARURAT</div>
            <div class="text-xs text-slate-400" id="modalReportId">ID Laporan: -</div>
          </div>
          <button onclick="closeEmergencyModal()" class="w-12 h-12 rounded-2xl bg-white/5 hover:bg-white/10 text-xl flex items-center justify-center transition">✕</button>
        </div>
      </div>
      
      <!-- Isi Modal -->
      <div class="p-4 sm:p-6 space-y-4">
        <!-- Data Satpam -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
            <div class="text-xs text-slate-400 mb-1">Nama Satpam</div>
            <div class="font-bold text-lg" id="modalSatpamNama">-</div>
            <div class="text-xs text-slate-500" id="modalSatpamUsername">-</div>
          </div>
          <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
            <div class="text-xs text-slate-400 mb-1">Asal BUJP</div>
            <div class="font-bold text-amber-300" id="modalBujp">-</div>
          </div>
        </div>
        
        <!-- Waktu & Status -->
        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
          <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
            <div class="text-xs text-slate-400 mb-1">Waktu Laporan</div>
            <div class="font-bold" id="modalWaktu">-</div>
          </div>
          <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
            <div class="text-xs text-slate-400 mb-1">Status</div>
            <div id="modalStatus">-</div>
          </div>
        </div>
        
        <!-- Keterangan Kejadian -->
        <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
          <div class="text-xs text-slate-400 mb-2">📝 Keterangan Kejadian</div>
          <div class="text-sm" id="modalKeterangan">-</div>
        </div>
        
        <!-- Lokasi & Koordinat -->
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
          <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
            <div class="text-xs text-slate-400 mb-1">🧭 Latitude</div>
            <div class="font-mono text-cyan-300" id="modalLat">-</div>
          </div>
          <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
            <div class="text-xs text-slate-400 mb-1">🧭 Longitude</div>
            <div class="font-mono text-cyan-300" id="modalLng">-</div>
          </div>
          <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
            <div class="text-xs text-slate-400 mb-1">📍 Akurasi GPS</div>
            <div class="font-bold" id="modalAkurasi">-</div>
          </div>
        </div>
        
        <!-- Foto Bukti -->
        <div class="rounded-2xl bg-white/5 border border-white/10 p-4">
          <div class="text-xs text-slate-400 mb-3">📸 Foto Bukti</div>
          <div id="modalFotoContainer">
            <div class="text-center py-4 text-slate-500">Tidak ada foto yang dilampirkan</div>
          </div>
        </div>
        
        <!-- Tombol Aksi -->
        <div class="grid grid-cols-1 sm:grid-cols-3 gap-3 pt-2">
          <a id="modalBtnGMaps" href="#" target="_blank" class="px-4 py-3 rounded-2xl bg-cyan-500/20 text-cyan-300 text-center font-bold hover:bg-cyan-500/30 transition">
            🗺️ BUKA DI GOOGLE MAPS
          </a>
          <button id="modalBtnProses" onclick="prosesLaporanModal()" class="px-4 py-3 rounded-2xl bg-emerald-500 text-slate-950 text-center font-bold hover:bg-emerald-400 transition">
            ✅ PROSES LAPORAN
          </button>
          <button onclick="closeEmergencyModal()" class="px-4 py-3 rounded-2xl bg-white/5 border border-white/10 text-center font-bold hover:bg-white/10 transition">
            ❌ TUTUP
          </button>
        </div>
      </div>
    </div>
  </div>
  <style>
    #app-header {
      transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      will-change: padding, transform, border-radius;
    }
    
    #app-header.header-shrinked {
      padding-top: 0.4rem !important;
      padding-bottom: 0.4rem !important;
      margin-top: 0.2rem !important;
      top: 0.2rem !important;
      border-radius: 1rem !important;
      backdrop-filter: blur(16px);
    }
    
    #app-header.header-shrinked .app-title {
      font-size: 0.9rem !important;
    }
    
    #app-header.header-shrinked .app-version {
      display: none !important;
    }
    
    #app-header.header-shrinked .user-badge {
      padding-top: 0.25rem !important;
      padding-bottom: 0.25rem !important;
      font-size: 0.75rem !important;
    }
  </style>

  <div class="max-w-7xl mx-auto px-4 py-4 sm:px-6 lg:px-8">
    <!-- ✅ NAVBAR MODERN RESPONSIF -->
    <style>
      .navbar-drawer {
        transform: translateX(100%);
        transition: transform 0.35s cubic-bezier(0.4, 0, 0.2, 1);
      }
      .navbar-drawer.open {
        transform: translateX(0);
      }
      .hamburger-line {
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        transform-origin: center;
      }
      .hamburger.active .line1 { transform: rotate(45deg) translateY(6px); }
      .hamburger.active .line2 { opacity: 0; transform: scaleX(0); }
      .hamburger.active .line3 { transform: rotate(-45deg) translateY(-6px); }
      
      .nav-link {
        position: relative;
        overflow: hidden;
      }
      .nav-link::before {
        content: '';
        position: absolute;
        bottom: 0;
        left: 50%;
        width: 0;
        height: 2px;
        background: linear-gradient(90deg, #06b6d4, #a855f7);
        transition: all 0.3s ease;
        transform: translateX(-50%);
      }
      .nav-link:hover::before {
        width: 80%;
      }
      
      @media (max-width: 768px) {
        #desktop-nav { display: none !important; }
        #mobile-nav-btn { display: flex !important; }
      }
      @media (min-width: 769px) {
        #mobile-nav-btn { display: none !important; }
        #navbar-drawer { display: none !important; }
      }
    </style>

    {% if not hide_navbar %}
    <header id="app-header" class="glass rounded-3xl px-4 py-3 sticky top-3 z-50">
      <div class="flex items-center justify-between gap-3">
        
        <!-- ✅ KIRI: LOGO & TOMBOL BERANDA (SELALU TAMPIL SEMUA UKURAN) -->
        <div class="flex items-center gap-3">
          {% if user %}
            <a href="{{ url_for('bujp_dashboard' if user['role'] == 'anggota' else user['role'] == 'satpam' and 'satpam_page' or user['role'] == 'direktur_binmas' and 'monitor_map' or 'admin_dashboard') }}" 
               class="home-button px-4 py-2 rounded-2xl bg-gradient-to-r from-cyan-500/20 to-purple-500/20 border border-cyan-400/30 hover:border-cyan-400/50 transition flex items-center gap-2 font-bold">
              🏠 Beranda
            </a>
          {% endif %}
          <div class="hidden sm:block">
            <div class="app-title text-lg font-black tracking-wide">{{ app_name }}</div>
            <div class="app-version text-xs text-slate-400">v2.0.1</div>
          </div>
        </div>

        <!-- ✅ KANAN: USER BADGE + DESKTOP MENU -->
        <div class="flex items-center gap-3">
          {% if user %}
            <span class="user-badge px-3 py-2 rounded-xl bg-cyan-500/20 border border-cyan-400/20 text-cyan-200 text-sm hidden md:block">{{ user['full_name'] }}</span>
          {% endif %}
          
          <div id="desktop-nav" class="flex flex-wrap gap-2 items-center">
            {{ nav|safe }}
          </div>

          <!-- ✅ HAMBURGER BUTTON MOBILE -->
          <button id="mobile-nav-btn" class="hamburger w-12 h-12 rounded-2xl bg-white/5 hover:bg-white/10 transition flex flex-col items-center justify-center gap-1.5">
            <span class="hamburger-line line1 w-5 h-0.5 bg-white rounded-full"></span>
            <span class="hamburger-line line2 w-5 h-0.5 bg-white rounded-full"></span>
            <span class="hamburger-line line3 w-5 h-0.5 bg-white rounded-full"></span>
          </button>
        </div>
      </div>
    </header>

    <!-- ✅ OFFCANVAS DRAWER MENU MOBILE -->
    <div id="navbar-drawer-overlay" class="fixed inset-0 bg-black/60 backdrop-blur-sm z-40 hidden" onclick="closeNavbarDrawer()"></div>
    <div id="navbar-drawer" class="navbar-drawer fixed right-0 top-0 h-full w-[280px] max-w-[85vw] glass z-50 rounded-l-3xl p-5 flex flex-col gap-4 overflow-y-auto overscroll-contain pb-32 min-h-[100dvh] touch-auto -webkit-overflow-scrolling: touch;">
      <div class="flex justify-between items-center mb-4">
        <div class="font-bold text-lg">Menu Navigasi</div>
        <button onclick="closeNavbarDrawer()" class="w-10 h-10 rounded-xl bg-white/5 hover:bg-white/10 flex items-center justify-center">✕</button>
      </div>
      
      <div class="user-badge px-3 py-3 rounded-2xl bg-cyan-500/10 border border-cyan-400/20 text-cyan-200 text-sm mb-2">
        <div class="font-bold">{{ user['full_name'] if user else 'Guest' }}</div>
        <div class="text-xs text-slate-400">{{ user['role'] if user else '' }}</div>
      </div>

      <div id="mobile-nav-items" class="flex flex-col gap-2">
        {{ nav_mobile|safe }}
      </div>
    </div>

    <script>
      const navbarBtn = document.getElementById('mobile-nav-btn');
      const navbarDrawer = document.getElementById('navbar-drawer');
      const navbarOverlay = document.getElementById('navbar-drawer-overlay');

      function openNavbarDrawer() {
        navbarBtn.classList.add('active');
        navbarDrawer.classList.add('open');
        navbarOverlay.classList.remove('hidden');
        document.body.style.overflow = 'hidden';
      }

      function closeNavbarDrawer() {
        navbarBtn.classList.remove('active');
        navbarDrawer.classList.remove('open');
        navbarOverlay.classList.add('hidden');
        document.body.style.overflow = '';
      }

      navbarBtn.addEventListener('click', () => {
        if (navbarDrawer.classList.contains('open')) {
          closeNavbarDrawer();
        } else {
          openNavbarDrawer();
        }
      });
    </script>
    {% endif %}
    
    <main class="{% if hide_navbar %}py-8{% else %}py-4{% endif %}">{{ body|safe }}</main>
  </div>
  
  <script>
    // Dynamic Header Shrink on Scroll
    const header = document.getElementById('app-header');
    let lastScrollY = window.scrollY;
    let ticking = false;
    
    function updateHeader() {
      if (window.scrollY > 25) {
        header.classList.add('header-shrinked');
      } else {
        header.classList.remove('header-shrinked');
      }
      ticking = false;
    }
    
    window.addEventListener('scroll', () => {
      if (!ticking) {
        window.requestAnimationFrame(updateHeader);
        ticking = true;
      }
    });

    // ✅ [NEW] Toggle Heatmap — tampilkan kepadatan keberadaan satpam
    let heatLayer = null;
    let heatVisible = false;

    function toggleHeatmap() {
        if (!window._mapInstance) return;
        if (heatVisible && heatLayer) {
            window._mapInstance.removeLayer(heatLayer);
            heatVisible = false;
            document.getElementById('btnHeatmap').textContent = '🔥 Tampilkan Heatmap';
        } else {
            const pts = (window._satpamSnapshot || []).map(s => [s.lat, s.lng, 0.8]);
            if (pts.length === 0) { alert('Tidak ada data lokasi satpam.'); return; }
            heatLayer = L.heatLayer(pts, {radius: 35, blur: 25, maxZoom: 17}).addTo(window._mapInstance);
            heatVisible = true;
            document.getElementById('btnHeatmap').textContent = '🔥 Sembunyikan Heatmap';
        }
    }

    // ✅ [NEW] Trail / rute pergerakan satpam hari ini
    let trailLayer = null;
    async function tampilkanTrail(userId, namaUser) {
        if (!window._mapInstance) return;
        if (trailLayer) { window._mapInstance.removeLayer(trailLayer); trailLayer = null; }
        try {
            const res = await fetch(`/api/satpam/${userId}/trail`);
            const data = await res.json();
            if (!data.trail || data.trail.length < 2) {
                alert(`${namaUser}: Belum ada riwayat pergerakan hari ini.`);
                return;
            }
            const latlngs = data.trail.map(p => [p.lat, p.lng]);
            trailLayer = L.layerGroup();
            // Garis rute
            L.polyline(latlngs, {color: '#06b6d4', weight: 3, opacity: 0.8, dashArray: '6 4'})
             .addTo(trailLayer);
            // Titik-titik dengan waktu
            data.trail.forEach((p, idx) => {
                L.circleMarker([p.lat, p.lng], {radius: 4, color: '#06b6d4', fillOpacity: 1})
                 .bindTooltip(`${namaUser}<br>${p.created_at}`, {permanent: false})
                 .addTo(trailLayer);
            });
            trailLayer.addTo(window._mapInstance);
            window._mapInstance.fitBounds(L.polyline(latlngs).getBounds().pad(0.2));
        } catch(e) {
            alert('Gagal memuat trail: ' + e.message);
        }
    }

    
    // Service Worker
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => navigator.serviceWorker.register('{{ url_for('sw') }}').catch(() => {}));
    }
  </script>
</body>
</html>
"""


def render_page(title, body_html, user=None, hide_navbar=False, **kwargs):
    # Generate nav untuk desktop dan mobile
    nav_desktop = nav_html(user)
    
    # Generate nav untuk mobile dengan tampilan vertikal yang sesuai
    nav_mobile = ""
    if user:
        # Hitung jumlah laporan emergency pending untuk badge notifikasi
        emergency_pending_count = 0
        kta_pending_count = 0
        if user["role"] in ("admin", "direktur_binmas"):
            try:
                emergency_pending_count = get_db().execute("SELECT COUNT(*) FROM emergency_reports WHERE status = 'pending'").fetchone()[0]
                kta_pending_count = get_db().execute("SELECT COUNT(*) FROM kta_perpanjangan WHERE status = 'pending'").fetchone()[0]
            except:
                emergency_pending_count = 0
                kta_pending_count = 0

        if user["role"] == "admin":
            items = [
                (url_for("admin_dashboard"), "Admin"),
                (url_for("admin_kta_perpanjangan"), "📋 Pengajuan KTA", kta_pending_count),
                (url_for("bujp_management"), "Manajemen BUJP"),
                (url_for("monitor_map"), "Map Monitor"),
                (url_for("emergency_alert_map"), "🚨 Maps Alert", emergency_pending_count),
                (url_for("admin_emergency_reports"), "📋 Daftar Laporan Darurat"),
                (url_for("admin_absensi_sesi"), "📅 Kelola Absensi"),
                (url_for("admin_absensi_rekap"), "📊 Rekap Absensi"),
                (url_for("admin_rekening_management"), "💳 Manajemen Rekening"),
                (url_for("change_password"), "Ganti Password"),
                (url_for("logout"), "Logout"),
            ]
        elif user["role"] == "direktur_binmas":
            items = [
                (url_for("monitor_map"), "Map Satpam"),
                (url_for("emergency_alert_map"), "🚨 Maps Alert", emergency_pending_count),
                (url_for("admin_emergency_reports"), "📋 Daftar Laporan Darurat"),
                (url_for("direktur_maps_bujp"), "🗺️ Maps Perusahaan"),
                (url_for("bujp_management"), "Manajemen BUJP"),
                (url_for("change_password"), "Ganti Password"),
                (url_for("logout"), "Logout"),
            ]
        elif user["role"] == "satpam":
            items = [
                (url_for("satpam_page"), "🏠 Beranda"),
                (url_for("satpam_profile"), "👤 Profil KTA"),
                (url_for("change_password"), "🔑 Ganti Password"),
                (url_for("logout"), "🚪 Logout"),
            ]
        else:
            items = [
                (url_for("bujp_dashboard"), "Beranda"),
                (url_for("change_password"), "Ganti Password"),
                (url_for("logout"), "Logout"),
            ]
        nav_items = []
        for item in items:
            if len(item) == 3:
                href, label, badge_count = item
                if badge_count and badge_count > 0:
                    nav_items.append(f'''
                    <a href="{href}" onclick="closeNavbarDrawer()" class="px-4 py-3 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition block w-full">
                        {label}
                        <span class="emergency-badge float-right ml-2 bg-red-500 text-white text-xs font-black rounded-full w-5 h-5 inline-flex items-center justify-center">
                            {badge_count}
                        </span>
                    </a>
                    ''')
                else:
                    nav_items.append(f'<a href="{href}" onclick="closeNavbarDrawer()" class="px-4 py-3 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition block w-full">{label}</a>')
            else:
                href, label = item
                nav_items.append(f'<a href="{href}" onclick="closeNavbarDrawer()" class="px-4 py-3 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition block w-full">{label}</a>')

        nav_mobile = "".join(nav_items)
    
    return render_template_string(BASE_TEMPLATE, title=title, app_name=APP_NAME, body=body_html, user=user, nav=nav_desktop, nav_mobile=nav_mobile, hide_navbar=hide_navbar)


def ws_url(path):
    scheme = 'wss' if request.scheme == 'https' else 'ws'
    return f"{scheme}://{request.host}{path}"


def get_geofences_data():
    rows = get_db().execute("SELECT id, name, geojson FROM geofences ORDER BY id DESC").fetchall()
    items = []
    for row in rows:
        try:
            obj = json.loads(row["geojson"])
            if isinstance(obj, dict):
                obj.setdefault("properties", {})
                obj["properties"].setdefault("db_id", row["id"])
                obj["properties"].setdefault("name", row["name"])
            items.append(obj)
        except Exception:
            continue
    return items


def point_in_polygon(lat, lng, polygon):
    """Ray-casting algorithm untuk mengecek apakah titik berada di dalam polygon."""
    inside = False
    pts = [(coord[1], coord[0]) for coord in polygon]  # [lat, lng]
    n = len(pts)
    j = n - 1
    for i in range(n):
        yi, xi = pts[i]
        yj, xj = pts[j]
        # ✅ [FIX] Cek crossing langsung tanpa variabel terpisah agar tidak ada state lama
        if ((xi > lng) != (xj > lng)):
            denom = xj - xi
            if abs(denom) > 1e-12:   # hindari pembagian nol
                if lat < (yj - yi) * (lng - xi) / denom + yi:
                    inside = not inside
        j = i
    return inside



def geofence_hits(lat, lng):
    hits = []
    for geo in get_geofences_data():
        geom = geo.get("geometry", {})
        if geom.get("type") == "Polygon":
            rings = geom.get("coordinates", [])
            if rings and point_in_polygon(lat, lng, rings[0]):
                hits.append(geo.get("properties", {}).get("name", "Unnamed"))
    return hits


def latest_snapshot():
    rows = get_db().execute(
        """
        SELECT l.user_id, l.lat, l.lng, l.accuracy, l.speed, l.altitude, l.created_at, u.username, u.full_name
        FROM locations l
        JOIN users u ON u.id = l.user_id
        WHERE u.role='satpam' AND l.id IN (SELECT MAX(id) FROM locations GROUP BY user_id)
        ORDER BY l.created_at DESC
        """
    ).fetchall()
    payload = []
    with WS_LOCK:
        online_ids = {uid for uid, sockset in SATPAM_SOCKETS.items() if sockset}
    
    now = datetime.utcnow()
    max_age = timedelta(hours=8)
    
    for row in rows:
        item = dict(row)
        
        # Cek apakah lokasi masih kurang dari 8 jam
        created_time = datetime.strptime(row["created_at"], "%Y-%m-%d %H:%M:%S")
        if now - created_time > max_age:
            continue  # Lewati jika sudah lebih dari 8 jam, tidak tampil di map
            
        item["online"] = row["user_id"] in online_ids
        item["last_seen"] = row["created_at"]
        item["geofences"] = geofence_hits(item["lat"], item["lng"])
        payload.append(item)
    return payload


def persist_location(user_id, lat, lng, accuracy, speed, altitude, source="ws"):
    db = get_db()
    db.execute(
        "INSERT INTO locations (user_id, lat, lng, accuracy, speed, altitude, source, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (user_id, lat, lng, accuracy, speed, altitude, source, now_str()),
    )
    db.commit()
    row = db.execute(
        """
        SELECT l.user_id, l.lat, l.lng, l.accuracy, l.speed, l.altitude, l.created_at, u.username, u.full_name
        FROM locations l JOIN users u ON u.id=l.user_id
        WHERE l.user_id=? ORDER BY l.id DESC LIMIT 1
        """,
        (user_id,),
    ).fetchone()
    payload = dict(row)
    payload["geofences"] = geofence_hits(lat, lng)
    with WS_LOCK:
        payload["online"] = bool(SATPAM_SOCKETS.get(user_id))
    return payload


def safe_ws_send(ws, payload):
    try:
        ws.send(json.dumps(payload))
        return True
    except Exception:
        return False


def broadcast_monitors(payload):
    with WS_LOCK:
        sockets = list(MONITOR_SOCKETS)
    dead = []
    for client in sockets:
        if not safe_ws_send(client, payload):
            dead.append(client)
    if dead:
        with WS_LOCK:
            for d in dead:
                MONITOR_SOCKETS.discard(d)


def broadcast_presence():
    payload = {
        "type": "presence",
        "online_user_ids": [row["user_id"] for row in latest_snapshot() if row.get("online")],
        "snapshot": latest_snapshot(),
        "server_time": now_str(),
    }
    broadcast_monitors(payload)


@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": APP_NAME,
        "short_name": "GuardTrackerWS",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0b1220",
        "theme_color": "#0b1220",
        "icons": [],
    })


@app.route("/sw.js")
def sw():
    js = """
    // SERVICE WORKER DINONAKTIFKAN UNTUK DEVELOPMENT
    self.addEventListener('install', e => {
      self.skipWaiting();
    });
    self.addEventListener('activate', e => {
      // HAPUS SEMUA CACHE YANG ADA
      e.waitUntil(
        caches.keys().then(names => {
          return Promise.all(names.map(name => caches.delete(name))
        ))
      ).then(() => self.clients.claim())
    });
    // JANGAN CACHE APAPUN
    self.addEventListener('fetch', e => {
      return;
    });
    """
    return app.response_class(js, mimetype="application/javascript")


# LOGIN UNTUK SATPAM
# ✅ [NEW] SISTEM LUPA PASSWORD SATPAM - JENIUS & AMAN
@app.route("/login/satpam/lupa-password", methods=["GET", "POST"])
def satpam_lupa_password():
    msg = ""
    error = ""
    step = 1

    if request.method == "POST":
        client_ip = request.remote_addr
        if not check_brute_force(client_ip):
            error = f"❌ IP Anda terblokir sementara. Silakan coba lagi dalam {BLOCK_DURATION_MINUTES} menit."
        else:
            action = request.form.get("action") or ""

            if action == "generate_code":
                username = (request.form.get("username") or "").strip()
                if not username:
                    error = "Masukkan username satpam Anda"
                else:
                    user = get_db().execute("SELECT id, username, no_hp, role FROM users WHERE username=? AND role='satpam' AND is_active=1", (username,)).fetchone()
                    if not user:
                        error = "❌ Username Satpam tidak ditemukan"
                        record_login_failure(client_ip)
                    else:
                        # Generate kode reset 6 digit angka
                        reset_code = ''.join([str(secrets.randbelow(10)) for _ in range(6)])
                        expires_at = (datetime.utcnow() + timedelta(minutes=15)).strftime("%Y-%m-%d %H:%M:%S")
                        
                        db = get_db()
                        # Hanya 1 kode aktif per user, hapus yang lama
                        db.execute("DELETE FROM password_reset WHERE user_id=?", (user["id"],))
                        db.execute("""
                            INSERT INTO password_reset (user_id, reset_code, created_at, expires_at, ip_address, attempts)
                            VALUES (?, ?, ?, ?, ?, 0)
                        """, (user["id"], reset_code, now_str(), expires_at, client_ip))
                        db.commit()
                        
                        msg = f"✅ KODE RESET PASSWORD ANDA: <b class='text-2xl text-green-400 font-black tracking-widest'>{reset_code}</b><br><br>🔔 Kode ini berlaku HANYA 15 MENIT, gunakan segera!"
                        log_action("PASSWORD_RESET_REQUEST", "user", user["id"], f"ip={client_ip}")
                        step = 2

            elif action == "reset_password":
                reset_code = (request.form.get("reset_code") or "").strip()
                password1 = request.form.get("password1") or ""
                password2 = request.form.get("password2") or ""

                if not reset_code or len(reset_code) != 6:
                    error = "Kode reset tidak valid"
                elif len(password1) < 8:
                    error = "Password baru minimal 8 karakter"
                elif password1 != password2:
                    error = "Konfirmasi password tidak sama"
                else:
                    db = get_db()
                    reset = db.execute("""
                        SELECT r.*, u.username FROM password_reset r
                        JOIN users u ON u.id = r.user_id
                        WHERE r.reset_code=?
                    """, (reset_code,)).fetchone()

                    if not reset:
                        error = "❌ Kode reset tidak ditemukan"
                        record_login_failure(client_ip)
                    elif datetime.strptime(reset["expires_at"], "%Y-%m-%d %H:%M:%S") < datetime.utcnow():
                        error = "❌ Kode reset sudah kadaluarsa"
                        db.execute("DELETE FROM password_reset WHERE id=?", (reset["id"],))
                        db.commit()
                    elif reset["attempts"] >= 3:
                        error = "❌ Terlalu banyak percobaan gagal. Kode diblokir."
                        db.execute("DELETE FROM password_reset WHERE id=?", (reset["id"],))
                        db.commit()
                    else:
                        # Reset password berhasil
                        db.execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (hash_password(password1), now_str(), reset["user_id"]))
                        db.execute("DELETE FROM password_reset WHERE user_id=?", (reset["user_id"],))
                        db.commit()
                        
                        reset_login_failures(client_ip)
                        log_action("PASSWORD_RESET_SUCCESS", "user", reset["user_id"], f"ip={client_ip}")
                        
                        msg = """
                        ✅ PASSWORD BERHASIL DIRESET!
                        <br><br>
                        Silahkan login menggunakan password baru Anda.
                        <br><br>
                        <a href='/login/satpam' class='inline-block px-6 py-3 rounded-xl bg-green-500 text-slate-950 font-bold mt-4'>← KEMBALI KE LOGIN</a>
                        """
                        step = 3

    body = render_template_string("""
    <style>
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .animate-fadeInUp { animation: fadeInUp 0.6s ease-out forwards; }
    </style>

    <div class="min-h-[80vh] flex items-center justify-center py-8">
      <div class="w-full max-w-lg animate-fadeInUp">
        
        <div class="text-center mb-8">
          <div class="w-24 h-24 mx-auto mb-4 rounded-3xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center text-5xl shadow-lg shadow-green-500/30">
            🔑
          </div>
          <h1 class="text-4xl font-black mb-2 text-green-400">LUPA PASSWORD</h1>
          <div class="text-lg font-bold text-slate-300">Reset Password Satpam</div>
        </div>

        <div class="glass login-card rounded-3xl p-8 transition-all duration-300" style="border-color: rgba(34, 197, 94, 0.2);">
          
          <div class="text-center mb-6">
            <div class="text-xl font-black text-green-300">Langkah {{ step }} dari 3</div>
            <div class="text-sm text-slate-400 mt-1">
              {% if step == 1 %}Masukkan username satpam Anda{% elif step == 2 %}Masukkan kode reset dan password baru{% else %}Selesai!{% endif %}
            </div>
          </div>

          {% if msg %}
          <div class="mb-6 p-4 rounded-2xl bg-green-500/10 border border-green-500/20 text-green-200 text-sm animate-fadeInUp text-center">
            {{ msg|safe }}
          </div>
          {% endif %}
          
          {% if error %}
          <div class="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm animate-fadeInUp">
            ⚠️ {{ error }}
          </div>
          {% endif %}

          {% if step == 1 %}
          <form method="post" class="space-y-5">
            <input type="hidden" name="action" value="generate_code">
            <div>
              <label class="text-sm text-slate-400 mb-2 block">👤 Username Satpam</label>
              <input name="username" required autocomplete="username" autofocus
                class="w-full rounded-2xl bg-white/5 border border-green-500/20 pl-12 pr-4 py-4 outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500/50 transition-all"
                placeholder="Masukkan username satpam">
            </div>
            <button type="submit" class="w-full rounded-2xl bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-400 hover:to-emerald-500 text-slate-950 font-black px-4 py-4 transition-all duration-300">
              ✅ KIRIM KODE RESET
            </button>
          </form>
          {% elif step == 2 %}
          <form method="post" class="space-y-5">
            <input type="hidden" name="action" value="reset_password">
            <div>
              <label class="text-sm text-slate-400 mb-2 block">🔢 Kode Reset 6 Digit</label>
              <input name="reset_code" required maxlength="6" pattern="[0-9]{6}" inputmode="numeric"
                class="w-full rounded-2xl bg-white/5 border border-green-500/20 px-4 py-4 outline-none focus:ring-2 focus:ring-green-500 text-center text-3xl font-black tracking-[1rem]">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-2 block">🔐 Password Baru</label>
              <input type="password" name="password1" required minlength="8"
                class="w-full rounded-2xl bg-white/5 border border-green-500/20 px-4 py-4 outline-none focus:ring-2 focus:ring-green-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-2 block">🔐 Ulangi Password Baru</label>
              <input type="password" name="password2" required minlength="8"
                class="w-full rounded-2xl bg-white/5 border border-green-500/20 px-4 py-4 outline-none focus:ring-2 focus:ring-green-500">
            </div>
            <button type="submit" class="w-full rounded-2xl bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-400 hover:to-emerald-500 text-slate-950 font-black px-4 py-4 transition-all duration-300">
              ✅ RESET PASSWORD SEKARANG
            </button>
          </form>
          {% endif %}

          <div class="mt-6 pt-6 border-t border-white/10 text-center">
            <a href="{{ url_for('login_satpam') }}" class="text-sm text-slate-400 hover:text-green-400 transition">← Kembali ke Halaman Login Satpam</a>
          </div>

        </div>
      </div>
    </div>
    """, msg=msg, error=error, step=step)
    
    return render_page("Lupa Password Satpam", body, hide_navbar=True)


@app.route("/login/satpam", methods=["GET", "POST"])
def login_satpam():
    if session.get("user_id") and current_user():
        return redirect_by_role(current_user()["role"])

    error = ""
    if request.method == "POST":
        # ✅ CEK BRUTE FORCE SEBELUM APA PUN
        client_ip = request.remote_addr
        if not check_brute_force(client_ip):
            error = f"❌ IP Anda terblokir sementara karena terlalu banyak percobaan login gagal. Silakan coba lagi dalam {BLOCK_DURATION_MINUTES} menit."
        else:
            username = (request.form.get("username") or "").strip()
            password = request.form.get("password") or ""
            user = get_db().execute("SELECT * FROM users WHERE username=? AND role='satpam'", (username,)).fetchone()
            
            if not user or not user["is_active"]:
                error = "❌ Username Satpam tidak ditemukan / nonaktif."
            elif not verify_password(password, user["password_hash"]):
                error = "❌ Password salah."
                failures = record_login_failure(client_ip)
                log_action("LOGIN_FAILED", "user", user["id"], f"username={username} satpam failures={failures}")
                if failures >= FAILURE_BLOCK_THRESHOLD:
                    error = f"❌ Terlalu banyak percobaan gagal. IP Anda terblokir selama {BLOCK_DURATION_MINUTES} menit."
            else:
                # ✅ LOGIN BERHASIL - RESET COUNTER FAILURE
                reset_login_failures(client_ip)

                # ✅ BLOKIR LOGIN JIKA BELUM DIVERIFIKASI OLEH BUJP
                if user["bujp_id"] and user["bujp_verified"] == 0:
                    error = "❌ Akun Anda BELUM diverifikasi oleh Admin BUJP. Silahkan hubungi pihak BUJP untuk verifikasi."
                    log_action("LOGIN_BLOCKED", "user", user["id"], f"reason=bujp_not_verified;username={username}")
                else:
                    session.clear()
                    session["user_id"] = user["id"]
                    session["role"] = user["role"]
                    session["username"] = user["username"]
                    log_action("LOGIN_SUCCESS", "user", user["id"], f"role={user['role']} satpam")
                    return redirect_by_role(user["role"])

    body = render_template_string("""
    <style>
    :root { --color1: #22c55e; --color2: #10b981; }
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pulse-glow { 0%, 100% { box-shadow: 0 0 20px rgba(34, 197, 94, 0.3); } 50% { box-shadow: 0 0 40px rgba(34, 197, 94, 0.5); } }
    .animate-fadeInUp { animation: fadeInUp 0.6s ease-out forwards; }
    .animate-delay-100 { animation-delay: 0.1s; } .animate-delay-200 { animation-delay: 0.2s; }
    .animate-delay-300 { animation-delay: 0.3s; } .animate-delay-400 { animation-delay: 0.4s; }
    .login-card:hover { animation: pulse-glow 2s infinite; }
    .input-icon { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: rgba(255,255,255,0.4); }
    .password-toggle { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); cursor: pointer; color: rgba(255,255,255,0.4); transition: color 0.2s; }
    .password-toggle:hover { color: rgba(255,255,255,0.8); }
    </style>

    <div class="min-h-[80vh] flex items-center justify-center py-8">
      <div class="w-full max-w-lg animate-fadeInUp">
        
        <div class="text-center mb-8 animate-fadeInUp animate-delay-100">
          <div class="w-24 h-24 mx-auto mb-4 rounded-3xl bg-gradient-to-br from-green-500 to-emerald-600 flex items-center justify-center text-5xl shadow-lg shadow-green-500/30">
            👮
          </div>
          <h1 class="text-4xl font-black mb-2 text-green-400">LOGIN SATPAM</h1>
          <div class="text-lg font-bold text-slate-300">Sistem Absensi & Tracking Lokasi</div>
          <div class="text-xs text-slate-500 mt-1">Untuk Petugas Keamanan Satpam Binmas</div>
        </div>

        <div class="glass login-card rounded-3xl p-8 transition-all duration-300 animate-fadeInUp animate-delay-200" style="border-color: rgba(34, 197, 94, 0.2);">
          
          <div class="text-center mb-6">
            <div class="text-xl font-black text-green-300">Masuk ke Akun Satpam</div>
            <div class="text-slate-400 text-sm mt-1">Gunakan NIP / Username Satpam Anda</div>
          </div>

          {% if error %}
          <div class="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm animate-fadeInUp animate-delay-300 flex items-center gap-3">
            <span class="text-xl">⚠️</span>
            <span>{{ error }}</span>
          </div>
          {% endif %}

          <form method="post" class="space-y-5">
            
            <div class="animate-fadeInUp animate-delay-300">
              <label class="text-sm text-slate-400 mb-2 block">👤 Username Satpam</label>
              <div class="relative">
                <span class="input-icon">👤</span>
                <input name="username" required autocomplete="username" autofocus
                  class="w-full rounded-2xl bg-white/5 border border-green-500/20 pl-12 pr-4 py-4 outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500/50 transition-all"
                  placeholder="Masukkan username satpam">
              </div>
            </div>

            <div class="animate-fadeInUp animate-delay-400">
              <label class="text-sm text-slate-400 mb-2 block">🔐 Password</label>
              <div class="relative">
                <span class="input-icon">🔐</span>
                <input type="password" name="password" id="passwordField" required autocomplete="current-password"
                  class="w-full rounded-2xl bg-white/5 border border-green-500/20 pl-12 pr-12 py-4 outline-none focus:ring-2 focus:ring-green-500 focus:border-green-500/50 transition-all"
                  placeholder="Masukkan password">
                <span class="password-toggle" onclick="togglePassword()">👁️</span>
              </div>
            </div>

            <button type="submit" id="loginBtn"
              class="w-full rounded-2xl bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-400 hover:to-emerald-500 text-slate-950 font-black px-4 py-4 transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-green-500/30">
              ✅ MASUK SEBAGAI SATPAM
            </button>
          </form>

          <div class="mt-6 pt-6 border-t border-white/10 text-center">
            <div class="mb-4">
              <a href="{{ url_for('satpam_lupa_password') }}" class="text-sm text-amber-400 hover:text-amber-300 transition font-bold">
                🔑 LUPA PASSWORD? KLIK DISINI UNTUK RESET
              </a>
            </div>
            <a href="{{ url_for('login') }}" class="text-sm text-slate-400 hover:text-green-400 transition">← Kembali ke Halaman Utama</a>
          </div>

        </div>

        <div class="text-center mt-8 text-xs text-slate-500 animate-fadeInUp animate-delay-400">
          <div>© 2026 Binmas Guard Tracker</div>
          <div class="mt-1">Satpam Real-Time Monitoring System</div>
        </div>

      </div>
    </div>

    <script>
    function togglePassword() {
      const field = document.getElementById('passwordField');
      const toggle = document.querySelector('.password-toggle');
      field.type = field.type === 'password' ? 'text' : 'password';
      toggle.textContent = field.type === 'password' ? '👁️' : '🙈';
    }
    document.querySelector('form').addEventListener('submit', function() {
      const btn = document.getElementById('loginBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="animate-pulse">Memproses...</span>';
    });
    </script>
    """, error=error)
    return render_page("Login Satpam", body, hide_navbar=True)


# LOGIN UNTUK DIREKTUR BINMAS
@app.route("/login/direktur", methods=["GET", "POST"])
def login_direktur():
    if session.get("user_id") and current_user():
        return redirect_by_role(current_user()["role"])

    error = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_db().execute("SELECT * FROM users WHERE username=? AND role='direktur_binmas'", (username,)).fetchone()
        if not user or not user["is_active"]:
            error = "❌ Username Direktur tidak ditemukan / nonaktif."
        elif not verify_password(password, user["password_hash"]):
            error = "❌ Password salah."
            log_action("LOGIN_FAILED", "user", user["id"], f"username={username} direktur")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            log_action("LOGIN_SUCCESS", "user", user["id"], f"role={user['role']} direktur")
            return redirect_by_role(user["role"])

    body = render_template_string("""
    <style>
    :root { --color1: #8b5cf6; --color2: #7c3aed; }
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pulse-glow { 0%, 100% { box-shadow: 0 0 20px rgba(139, 92, 246, 0.3); } 50% { box-shadow: 0 0 40px rgba(139, 92, 246, 0.5); } }
    .animate-fadeInUp { animation: fadeInUp 0.6s ease-out forwards; }
    .animate-delay-100 { animation-delay: 0.1s; } .animate-delay-200 { animation-delay: 0.2s; }
    .animate-delay-300 { animation-delay: 0.3s; } .animate-delay-400 { animation-delay: 0.4s; }
    .login-card:hover { animation: pulse-glow 2s infinite; }
    .input-icon { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: rgba(255,255,255,0.4); }
    .password-toggle { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); cursor: pointer; color: rgba(255,255,255,0.4); transition: color 0.2s; }
    .password-toggle:hover { color: rgba(255,255,255,0.8); }
    </style>

    <div class="min-h-[80vh] flex items-center justify-center py-8">
      <div class="w-full max-w-lg animate-fadeInUp">
        
        <div class="text-center mb-8 animate-fadeInUp animate-delay-100">
          <div class="w-24 h-24 mx-auto mb-4 rounded-3xl bg-gradient-to-br from-violet-500 to-purple-600 flex items-center justify-center text-5xl shadow-lg shadow-violet-500/30">
            👨‍💼
          </div>
          <h1 class="text-4xl font-black mb-2 text-violet-400">LOGIN DIREKTUR</h1>
          <div class="text-lg font-bold text-slate-300">Dashboard Monitor Satpam</div>
          <div class="text-xs text-slate-500 mt-1">Untuk Pejabat Struktural Binmas</div>
        </div>

        <div class="glass login-card rounded-3xl p-8 transition-all duration-300 animate-fadeInUp animate-delay-200" style="border-color: rgba(139, 92, 246, 0.2);">
          
          <div class="text-center mb-6">
            <div class="text-xl font-black text-violet-300">Masuk ke Akun Direktur</div>
            <div class="text-slate-400 text-sm mt-1">Dashboard Monitoring Lokasi Satpam Real-Time</div>
          </div>

          {% if error %}
          <div class="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm animate-fadeInUp animate-delay-300 flex items-center gap-3">
            <span class="text-xl">⚠️</span>
            <span>{{ error }}</span>
          </div>
          {% endif %}

          <form method="post" class="space-y-5">
            
            <div class="animate-fadeInUp animate-delay-300">
              <label class="text-sm text-slate-400 mb-2 block">👤 Username Direktur</label>
              <div class="relative">
                <span class="input-icon">👨‍💼</span>
                <input name="username" required autocomplete="username" autofocus
                  class="w-full rounded-2xl bg-white/5 border border-violet-500/20 pl-12 pr-4 py-4 outline-none focus:ring-2 focus:ring-violet-500 focus:border-violet-500/50 transition-all"
                  placeholder="Masukkan username direktur">
              </div>
            </div>

            <div class="animate-fadeInUp animate-delay-400">
              <label class="text-sm text-slate-400 mb-2 block">🔐 Password</label>
              <div class="relative">
                <span class="input-icon">🔐</span>
                <input type="password" name="password" id="passwordField" required autocomplete="current-password"
                  class="w-full rounded-2xl bg-white/5 border border-violet-500/20 pl-12 pr-12 py-4 outline-none focus:ring-2 focus:ring-violet-500 focus:border-violet-500/50 transition-all"
                  placeholder="Masukkan password">
                <span class="password-toggle" onclick="togglePassword()">👁️</span>
              </div>
            </div>

            <button type="submit" id="loginBtn"
              class="w-full rounded-2xl bg-gradient-to-r from-violet-500 to-purple-600 hover:from-violet-400 hover:to-purple-500 text-slate-950 font-black px-4 py-4 transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-violet-500/30">
              📊 BUKA DASHBOARD MONITOR
            </button>
          </form>

          <div class="mt-6 pt-6 border-t border-white/10 text-center">
            <a href="{{ url_for('login') }}" class="text-sm text-slate-400 hover:text-violet-400 transition">← Kembali ke Halaman Utama</a>
          </div>

        </div>

        <div class="text-center mt-8 text-xs text-slate-500 animate-fadeInUp animate-delay-400">
          <div>© 2026 Binmas Guard Tracker</div>
          <div class="mt-1">Direktur Binmas Monitoring System</div>
        </div>

      </div>
    </div>

    <script>
    function togglePassword() {
      const field = document.getElementById('passwordField');
      const toggle = document.querySelector('.password-toggle');
      field.type = field.type === 'password' ? 'text' : 'password';
      toggle.textContent = field.type === 'password' ? '👁️' : '🙈';
    }
    document.querySelector('form').addEventListener('submit', function() {
      const btn = document.getElementById('loginBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="animate-pulse">Memproses...</span>';
    });
    </script>
    """, error=error)
    return render_page("Login Direktur", body, hide_navbar=True)


# LOGIN UNTUK ADMIN
@app.route("/login/admin", methods=["GET", "POST"])
def login_admin():
    if session.get("user_id") and current_user():
        return redirect_by_role(current_user()["role"])

    error = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_db().execute("SELECT * FROM users WHERE username=? AND role='admin'", (username,)).fetchone()
        if not user or not user["is_active"]:
            error = "❌ Username Admin tidak ditemukan / nonaktif."
        elif not verify_password(password, user["password_hash"]):
            error = "❌ Password salah."
            log_action("LOGIN_FAILED", "user", user["id"], f"username={username} admin")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            log_action("LOGIN_SUCCESS", "user", user["id"], f"role={user['role']} admin")
            return redirect_by_role(user["role"])

    body = render_template_string("""
    <style>
    :root { --color1: #06b6d4; --color2: #0891b2; }
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pulse-glow { 0%, 100% { box-shadow: 0 0 20px rgba(6, 182, 212, 0.3); } 50% { box-shadow: 0 0 40px rgba(6, 182, 212, 0.5); } }
    .animate-fadeInUp { animation: fadeInUp 0.6s ease-out forwards; }
    .animate-delay-100 { animation-delay: 0.1s; } .animate-delay-200 { animation-delay: 0.2s; }
    .animate-delay-300 { animation-delay: 0.3s; } .animate-delay-400 { animation-delay: 0.4s; }
    .login-card:hover { animation: pulse-glow 2s infinite; }
    .input-icon { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: rgba(255,255,255,0.4); }
    .password-toggle { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); cursor: pointer; color: rgba(255,255,255,0.4); transition: color 0.2s; }
    .password-toggle:hover { color: rgba(255,255,255,0.8); }
    </style>

    <div class="min-h-[80vh] flex items-center justify-center py-8">
      <div class="w-full max-w-lg animate-fadeInUp">
        
        <div class="text-center mb-8 animate-fadeInUp animate-delay-100">
          <div class="w-24 h-24 mx-auto mb-4 rounded-3xl bg-gradient-to-br from-cyan-500 to-teal-600 flex items-center justify-center text-5xl shadow-lg shadow-cyan-500/30">
            ⚙️
          </div>
          <h1 class="text-4xl font-black mb-2 text-cyan-400">LOGIN ADMIN</h1>
          <div class="text-lg font-bold text-slate-300">Panel Administrator Sistem</div>
          <div class="text-xs text-slate-500 mt-1">Pengelolaan User, Geofence & History Aktifitas</div>
        </div>

        <div class="glass login-card rounded-3xl p-8 transition-all duration-300 animate-fadeInUp animate-delay-200" style="border-color: rgba(6, 182, 212, 0.2);">
          
          <div class="text-center mb-6">
            <div class="text-xl font-black text-cyan-300">Masuk ke Panel Admin</div>
            <div class="text-slate-400 text-sm mt-1">Akses penuh sistem manajemen Binmas</div>
          </div>

          {% if error %}
          <div class="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm animate-fadeInUp animate-delay-300 flex items-center gap-3">
            <span class="text-xl">⚠️</span>
            <span>{{ error }}</span>
          </div>
          {% endif %}

          <form method="post" class="space-y-5">
            
            <div class="animate-fadeInUp animate-delay-300">
              <label class="text-sm text-slate-400 mb-2 block">👤 Username Admin</label>
              <div class="relative">
                <span class="input-icon">⚙️</span>
                <input name="username" required autocomplete="username" autofocus
                  class="w-full rounded-2xl bg-white/5 border border-cyan-500/20 pl-12 pr-4 py-4 outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500/50 transition-all"
                  placeholder="Masukkan username admin">
              </div>
            </div>

            <div class="animate-fadeInUp animate-delay-400">
              <label class="text-sm text-slate-400 mb-2 block">🔐 Password</label>
              <div class="relative">
                <span class="input-icon">🔐</span>
                <input type="password" name="password" id="passwordField" required autocomplete="current-password"
                  class="w-full rounded-2xl bg-white/5 border border-cyan-500/20 pl-12 pr-12 py-4 outline-none focus:ring-2 focus:ring-cyan-500 focus:border-cyan-500/50 transition-all"
                  placeholder="Masukkan password">
                <span class="password-toggle" onclick="togglePassword()">👁️</span>
              </div>
            </div>

            <button type="submit" id="loginBtn"
              class="w-full rounded-2xl bg-gradient-to-r from-cyan-500 to-teal-600 hover:from-cyan-400 hover:to-teal-500 text-slate-950 font-black px-4 py-4 transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-cyan-500/30">
              ⚙️ BUKA ADMIN PANEL
            </button>
          </form>

          <div class="mt-6 pt-6 border-t border-white/10 text-center">
            <a href="{{ url_for('login') }}" class="text-sm text-slate-400 hover:text-cyan-400 transition">← Kembali ke Halaman Utama</a>
          </div>

        </div>

        <div class="text-center mt-8 text-xs text-slate-500 animate-fadeInUp animate-delay-400">
          <div>© 2026 Binmas Guard Tracker</div>
          <div class="mt-1">Administrator Control Panel</div>
        </div>

      </div>
    </div>

    <script>
    function togglePassword() {
      const field = document.getElementById('passwordField');
      const toggle = document.querySelector('.password-toggle');
      field.type = field.type === 'password' ? 'text' : 'password';
      toggle.textContent = field.type === 'password' ? '👁️' : '🙈';
    }
    document.querySelector('form').addEventListener('submit', function() {
      const btn = document.getElementById('loginBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="animate-pulse">Memproses...</span>';
    });
    </script>
    """, error=error)
    return render_page("Login Admin", body, hide_navbar=True)


# LOGIN UNTUK ANGGOTA
@app.route("/login/anggota", methods=["GET", "POST"])
def login_anggota():
    if session.get("user_id") and current_user():
        return redirect_by_role(current_user()["role"])

    error = ""
    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        user = get_db().execute("SELECT * FROM users WHERE username=? AND role='anggota'", (username,)).fetchone()
        if not user or not user["is_active"]:
            error = "❌ Username Anggota tidak ditemukan / nonaktif."
        elif not verify_password(password, user["password_hash"]):
            error = "❌ Password salah."
            log_action("LOGIN_FAILED", "user", user["id"], f"username={username} anggota")
        else:
            session.clear()
            session["user_id"] = user["id"]
            session["role"] = user["role"]
            session["username"] = user["username"]
            log_action("LOGIN_SUCCESS", "user", user["id"], f"role={user['role']} anggota")
            return redirect_by_role(user["role"])

    body = render_template_string("""
    <style>
    :root { --color1: #f59e0b; --color2: #d97706; }
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    @keyframes pulse-glow { 0%, 100% { box-shadow: 0 0 20px rgba(245, 158, 11, 0.3); } 50% { box-shadow: 0 0 40px rgba(245, 158, 11, 0.5); } }
    .animate-fadeInUp { animation: fadeInUp 0.6s ease-out forwards; }
    .animate-delay-100 { animation-delay: 0.1s; } .animate-delay-200 { animation-delay: 0.2s; }
    .animate-delay-300 { animation-delay: 0.3s; } .animate-delay-400 { animation-delay: 0.4s; }
    .login-card:hover { animation: pulse-glow 2s infinite; }
    .input-icon { position: absolute; left: 16px; top: 50%; transform: translateY(-50%); color: rgba(255,255,255,0.4); }
    .password-toggle { position: absolute; right: 16px; top: 50%; transform: translateY(-50%); cursor: pointer; color: rgba(255,255,255,0.4); transition: color 0.2s; }
    .password-toggle:hover { color: rgba(255,255,255,0.8); }
    </style>

    <div class="min-h-[80vh] flex items-center justify-center py-8">
      <div class="w-full max-w-lg animate-fadeInUp">
        
        <div class="text-center mb-8 animate-fadeInUp animate-delay-100">
          <div class="w-24 h-24 mx-auto mb-4 rounded-3xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-5xl shadow-lg shadow-amber-500/30">
            👤
          </div>
          <h1 class="text-4xl font-black mb-2 text-amber-400">LOGIN ANGGOTA</h1>
          <div class="text-lg font-bold text-slate-300">Portal Anggota Binmas</div>
          <div class="text-xs text-slate-500 mt-1">Untuk Anggota Umum Binmas</div>
        </div>

        <div class="glass login-card rounded-3xl p-8 transition-all duration-300 animate-fadeInUp animate-delay-200" style="border-color: rgba(245, 158, 11, 0.2);">
          
          <div class="text-center mb-6">
            <div class="text-xl font-black text-amber-300">Masuk ke Akun Anggota</div>
            <div class="text-slate-400 text-sm mt-1">Portal Informasi & Data Anggota</div>
          </div>

          {% if error %}
          <div class="mb-6 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm animate-fadeInUp animate-delay-300 flex items-center gap-3">
            <span class="text-xl">⚠️</span>
            <span>{{ error }}</span>
          </div>
          {% endif %}

          <form method="post" class="space-y-5">
            
            <div class="animate-fadeInUp animate-delay-300">
              <label class="text-sm text-slate-400 mb-2 block">👤 Username Anggota</label>
              <div class="relative">
                <span class="input-icon">👤</span>
                <input name="username" required autocomplete="username" autofocus
                  class="w-full rounded-2xl bg-white/5 border border-amber-500/20 pl-12 pr-4 py-4 outline-none focus:ring-2 focus:ring-amber-500 focus:border-amber-500/50 transition-all"
                  placeholder="Masukkan username anggota">
              </div>
            </div>

            <div class="animate-fadeInUp animate-delay-400">
              <label class="text-sm text-slate-400 mb-2 block">🔐 Password</label>
              <div class="relative">
                <span class="input-icon">🔐</span>
                <input type="password" name="password" id="passwordField" required autocomplete="current-password"
                  class="w-full rounded-2xl bg-white/5 border border-amber-500/20 pl-12 pr-12 py-4 outline-none focus:ring-2 focus:ring-amber-500 focus:border-amber-500/50 transition-all"
                  placeholder="Masukkan password">
                <span class="password-toggle" onclick="togglePassword()">👁️</span>
              </div>
            </div>

            <button type="submit" id="loginBtn"
              class="w-full rounded-2xl bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-slate-950 font-black px-4 py-4 transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.98] shadow-lg shadow-amber-500/30">
              👤 MASUK KE PORTAL ANGGOTA
            </button>
          </form>

          <div class="mt-6 pt-6 border-t border-white/10 text-center">
            <a href="{{ url_for('login') }}" class="text-sm text-slate-400 hover:text-amber-400 transition">← Kembali ke Halaman Utama</a>
          </div>

        </div>

        <div class="text-center mt-8 text-xs text-slate-500 animate-fadeInUp animate-delay-400">
          <div>© 2026 Binmas Guard Tracker</div>
          <div class="mt-1">Anggota Binmas Portal</div>
        </div>

      </div>
    </div>

    <script>
    function togglePassword() {
      const field = document.getElementById('passwordField');
      const toggle = document.querySelector('.password-toggle');
      field.type = field.type === 'password' ? 'text' : 'password';
      toggle.textContent = field.type === 'password' ? '👁️' : '🙈';
    }
    document.querySelector('form').addEventListener('submit', function() {
      const btn = document.getElementById('loginBtn');
      btn.disabled = true;
      btn.innerHTML = '<span class="animate-pulse">Memproses...</span>';
    });
    </script>
    """, error=error)
    return render_page("Login Anggota", body, hide_navbar=True)


# ✅ HALAMAN PENGENALAN / LANDING PAGE UTAMA BINMAS COMMAND CENTER
@app.route("/")
def index():
    # ✅ HALAMAN UTAMA TAMU SEBELUM LOGIN DENGAN DESAIN CANTIK DAN SAMPLE MAPS
    body = render_template_string("""
    <!doctype html>
    <html lang="id" class="dark">
    <head>
      <meta charset="utf-8">
      <meta name="viewport" content="width=device-width, initial-scale=1, maximum-scale=1, viewport-fit=cover">
      <title>BINMAS Command Center</title>
      <meta name="theme-color" content="#0b1220">
      <meta name="apple-mobile-web-app-capable" content="yes">
      <meta name="mobile-web-app-capable" content="yes">
      <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
      <script src="https://cdn.tailwindcss.com"></script>
      <link rel="stylesheet" href="https://unpkg.com/leaflet@1.9.4/dist/leaflet.css" crossorigin="" />
      <script src="https://unpkg.com/leaflet@1.9.4/dist/leaflet.js" crossorigin=""></script>
      <style>
        :root { color-scheme: dark; }
        body {
          background: radial-gradient(circle at top left, rgba(6,182,212,.15), transparent 25%),
                      radial-gradient(circle at bottom right, rgba(168,85,247,.15), transparent 25%),
                      linear-gradient(180deg, #060b16, #0b1220 35%, #0f172a 100%);
          min-height: 100vh;
        }
        .glass {
          background: rgba(255,255,255,.06);
          backdrop-filter: blur(14px);
          -webkit-backdrop-filter: blur(14px);
          border: 1px solid rgba(255,255,255,.10);
          box-shadow: 0 10px 30px rgba(0,0,0,.25);
        }
        @keyframes float { 0%,100% { transform: translateY(0); } 50% { transform: translateY(-10px); } }
        .animate-float { animation: float 6s ease-in-out infinite; }
        @keyframes pulse-glow { 0%,100% { box-shadow: 0 0 20px rgba(34,211,238, 0.3); } 50% { box-shadow: 0 0 40px rgba(34,211,238, 0.5); } }
        .hero-glow:hover { animation: pulse-glow 2s infinite; }
        .leaflet-container { background: #111827; }
      </style>
    </head>
    <body class="text-slate-100">
      
      <!-- ✅ HERO SECTION -->
      <section class="min-h-[90vh] flex flex-col">
        <header class="px-4 py-4 sm:px-6">
          <div class="max-w-7xl mx-auto flex items-center justify-between">
            <div class="flex items-center gap-3">
              <div class="w-12 h-12 rounded-2xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-2xl animate-float">
                🛡️
              </div>
              <div>
                <div class="font-black text-xl">BINMAS</div>
                <div class="text-xs text-slate-400">Command Center</div>
              </div>
            </div>
            <a href="{{ url_for('login') }}" class="px-6 py-3 rounded-2xl bg-gradient-to-r from-cyan-600 to-blue-600 text-white font-bold hover:from-cyan-500 hover:to-blue-500 transition shadow-lg shadow-cyan-500/25">
              🔐 Masuk Sistem
            </a>
          </div>
        </header>

        <main class="flex-1 px-4 sm:px-6 py-8">
          <div class="max-w-7xl mx-auto">
            <div class="text-center mb-12">
              <div class="inline-block px-4 py-2 rounded-full bg-cyan-500/10 border border-cyan-400/20 text-cyan-200 text-sm font-bold mb-6">
                <span>🛰️</span><span> SISTEM MONITORING REAL-TIME</span>
              </div>
              <h1 class="text-4xl md:text-6xl font-black mb-4 tracking-tight">
                <span class="bg-gradient-to-r from-cyan-300 via-sky-400 to-violet-400 bg-clip-text text-transparent">BINMAS Command Center</span>
              </h1>
              <p class="text-lg md:text-xl text-slate-300 max-w-2xl mx-auto mb-8">
                Pusat Komando Pembinaan Masyarakat Sistem terintegrasi monitoring satpam real-time, pendataan, dan manajemen kegiatan pembinaan keamanan.
              </p>
              <div class="flex flex-wrap gap-4 justify-center">
              
                <a href="#preview" class="px-8 py-4 rounded-2xl bg-white/5 border border-white/10 font-bold text-lg hover:bg-white/10 transition">
                  🗺️ Lihat Preview Maps
                </a>
              </div>
            </div>

            <!-- ✅ SAMPLE LIVE MAPS PREVIEW -->
            <div id="preview" class="glass rounded-[2rem] overflow-hidden mb-12 hero-glow transition-all duration-500">
              <div class="p-4 border-b border-white/10 flex items-center justify-between">
                <div>
                  <div class="font-bold text-lg">🗺️ PREVIEW MONITORING SATPAM</div>
                  <div class="text-xs text-slate-400">Contoh tampilan monitoring lokasi satpam secara real-time</div>
                </div>
                <span class="px-3 py-1 rounded-full bg-emerald-500/15 border border-emerald-500/30 text-emerald-200 text-sm font-bold">✅ LIVE DEMO</span>
              </div>
              <div id="previewMap" class="h-[50vh] w-full"></div>
            </div>

            <!-- ✅ FITUR UTAMA -->
            <div class="grid md:grid-cols-3 gap-6 mb-12">
              <div class="glass rounded-3xl p-6 hover:bg-cyan-500/10 hover:border-cyan-500/20 transition">
                <div class="text-4xl mb-4">📊</div>
                <div class="font-bold text-xl mb-2">Dashboard Monitoring</div>
                <div class="text-sm text-slate-400">Papan kontrol utama dengan visualisasi data dan ringkasan informasi penting secara real-time.</div>
              </div>
              <div class="glass rounded-3xl p-6 hover:bg-violet-500/10 hover:border-violet-500/20 transition">
                <div class="text-4xl mb-4">📍</div>
                <div class="font-bold text-xl mb-2">Lokasi Real-Time</div>
                <div class="text-sm text-slate-400">Pemantauan lokasi satpam secara live dengan update setiap detik menggunakan WebSocket.</div>
              </div>
              <div class="glass rounded-3xl p-6 hover:bg-emerald-500/10 hover:border-emerald-500/20 transition">
                <div class="text-4xl mb-4">🚨</div>
                <div class="font-bold text-xl mb-2">Emergency Button</div>
                <div class="text-sm text-slate-400">Tombol darurat satu klik yang langsung mengirim notifikasi ke semua admin dan direktur.</div>
              </div>
            </div>

            <!-- ✅ STATISTIK -->
            <div class="grid md:grid-cols-4 gap-4 mb-12">
              <div class="glass rounded-3xl p-6 text-center">
                <div class="text-4xl font-black text-cyan-300">24/7</div>
                <div class="text-sm text-slate-400">Monitoring Aktif</div>
              </div>
              <div class="glass rounded-3xl p-6 text-center">
                <div class="text-4xl font-black text-emerald-400">500+</div>
                <div class="text-sm text-slate-400">Satpam Terdaftar</div>
              </div>
              <div class="glass rounded-3xl p-6 text-center">
                <div class="text-4xl font-black text-violet-400">50ms</div>
                <div class="text-sm text-slate-400">Latency Update</div>
              </div>
              <div class="glass rounded-3xl p-6 text-center">
                <div class="text-4xl font-black text-amber-400">99.9%</div>
                <div class="text-sm text-slate-400">Uptime Sistem</div>
              </div>
            </div>
          </div>
        </main>

        <footer class="px-4 py-8 border-t border-white/5">
          <div class="max-w-7xl mx-auto text-center text-slate-500 text-sm">
            <div class="font-bold mb-1">© 2026 BINMAS • KEPOLISIAN NEGARA REPUBLIK INDONESIA</div>
            <div>Sistem Informasi Pembinaan Masyarakat - Versi 2.0.0</div>
          </div>
        </footer>
      </section>

      <script>
      // ✅ INITIALIZE PREVIEW MAP
      const map = L.map('previewMap').setView([-3.5, 118], 5);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap'
      }).addTo(map);

      // ✅ SAMPLE RANDOM MARKER SATPAM DI SELURUH INDONESIA
      const sampleSatpam = [
        {name: "Satpam Jakarta", lat: -6.2, lng: 106.8},
        {name: "Satpam Bandung", lat: -6.9, lng: 107.6},
        {name: "Satpam Surabaya", lat: -7.25, lng: 112.75},
        {name: "Satpam Medan", lat: 3.58, lng: 98.67},
        {name: "Satpam Makassar", lat: -5.14, lng: 119.4},
        {name: "Satpam Palembang", lat: -2.98, lng: 104.75},
        {name: "Satpam Balikpapan", lat: -1.26, lng: 116.83},
        {name: "Satpam Manado", lat: 1.49, lng: 124.84},
        {name: "Satpam Denpasar", lat: -8.65, lng: 115.22},
        {name: "Satpam Padang", lat: -0.95, lng: 100.35},
        {name: "Satpam Banjarmasin", lat: -3.32, lng: 114.59},
        {name: "Satpam Pontianak", lat: -0.02, lng: 109.34},
      ];

      sampleSatpam.forEach(satpam => {
        // Random posisi sedikit agar tidak pas di titik tepat
        const offsetLat = (Math.random() - 0.5) * 0.2;
        const offsetLng = (Math.random() - 0.5) * 0.2;
        const pos = [satpam.lat + offsetLat, satpam.lng + offsetLng];
        
        const customIcon = L.divIcon({
          className: 'preview-marker',
          html: `<div style="
            background: #22c55e;
            width: 14px;
            height: 14px;
            border-radius: 50%;
            border: 3px solid white;
            box-shadow: 0 0 12px #22c55e;
          "></div>`,
          iconSize: [14, 14],
          iconAnchor: [7, 7]
        });
        
        L.marker(pos, {icon: customIcon}).addTo(map)
          .bindPopup(`<div style="min-width: 150px; padding: 8px;"><div style="font-weight: 900;">${satpam.name}</div><div style="font-size: 11px; color: #94a3b8;">✅ Online Aktif</div></div>`);
      });

      // ✅ ANIMASI MARKER BERGERAK SECARA OTOMATIS
      setInterval(() => {
        map.eachLayer(layer => {
          if (layer instanceof L.Marker && !layer._icon.classList.contains('leaflet-drag-marker')) {
            const pos = layer.getLatLng();
            const newLat = pos.lat + (Math.random() - 0.5) * 0.005;
            const newLng = pos.lng + (Math.random() - 0.5) * 0.005;
            layer.setLatLng([newLat, newLng]);
          }
        });
      }, 3000);
      </script>
    </body>
    </html>
    """)
    
    return body


# HALAMAN UTAMA LOGIN DENGAN PILIHAN ROLE
@app.route("/login", methods=["GET", "POST"])
def login():
    if session.get("user_id") and current_user():
        return redirect_by_role(current_user()["role"])

    body = render_template_string("""
    <style>
    @keyframes fadeInUp { from { opacity: 0; transform: translateY(20px); } to { opacity: 1; transform: translateY(0); } }
    .animate-fadeInUp { animation: fadeInUp 0.6s ease-out forwards; }
    .animate-delay-100 { animation-delay: 0.1s; } .animate-delay-200 { animation-delay: 0.2s; }
    .animate-delay-300 { animation-delay: 0.3s; } .animate-delay-400 { animation-delay: 0.4s; }
    .role-card { transition: all 0.3s ease; transform: translateY(0); }
    .role-card:hover { transform: translateY(-5px); }
    </style>

    <div class="min-h-[80vh] flex items-center justify-center py-8">
      <div class="w-full max-w-3xl animate-fadeInUp">
        
        <div class="text-center mb-12 animate-fadeInUp animate-delay-100">
          <!-- ✅ TOMBOL KEMBALI KE HALAMAN UTAMA -->
          <div class="mb-8">
            <a href="{{ url_for('index') }}" class="inline-flex items-center gap-2 px-6 py-3 rounded-2xl bg-white/5 border border-white/10 hover:bg-white/10 transition">
              ⬅️ Kembali ke Halaman Utama
            </a>
          </div>
          
          <div class="w-28 h-28 mx-auto mb-6 rounded-3xl bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-6xl shadow-lg shadow-cyan-500/30">
            🏛️
          </div>
          <h1 class="text-5xl font-black mb-3">
            <span class="text-cyan-400">BIN</span><span class="text-white">MAS</span>
          </h1>
          <div class="text-2xl font-bold text-slate-300">SISTEM INFORMASI BINMAS</div>
          <div class="text-sm text-slate-500 mt-2">Guard Tracker & Monitoring System</div>
        </div>

        <div class="grid md:grid-cols-2 gap-6 animate-fadeInUp animate-delay-200">
          
          <a href="{{ url_for('login_satpam') }}" class="role-card glass rounded-3xl p-8 text-center hover:bg-green-500/10 hover:border-green-500/30 transition">
            <div class="text-6xl mb-4">👮</div>
            <div class="text-2xl font-black text-green-400 mb-2">SATPAM</div>
            <div class="text-sm text-slate-400 mb-4">Petugas Keamanan Satpam Binmas</div>
            <div class="inline-block px-6 py-3 rounded-2xl bg-green-500 hover:bg-green-400 text-slate-950 font-black">
              Login Satpam →
            </div>
          </a>

          <a href="{{ url_for('login_direktur') }}" class="role-card glass rounded-3xl p-8 text-center hover:bg-violet-500/10 hover:border-violet-500/30 transition">
            <div class="text-6xl mb-4">👨‍💼</div>
            <div class="text-2xl font-black text-violet-400 mb-2">DIREKTUR</div>
            <div class="text-sm text-slate-400 mb-4">Pejabat Struktural Binmas</div>
            <div class="inline-block px-6 py-3 rounded-2xl bg-violet-500 hover:bg-violet-400 text-slate-950 font-black">
              Login Direktur →
            </div>
          </a>

          <a href="{{ url_for('login_admin') }}" class="role-card glass rounded-3xl p-8 text-center hover:bg-cyan-500/10 hover:border-cyan-500/30 transition">
            <div class="text-6xl mb-4">⚙️</div>
            <div class="text-2xl font-black text-cyan-400 mb-2">ADMIN</div>
            <div class="text-sm text-slate-400 mb-4">Administrator Sistem Binmas</div>
            <div class="inline-block px-6 py-3 rounded-2xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black">
              Login Admin →
            </div>
          </a>

          <a href="{{ url_for('login_anggota') }}" class="role-card glass rounded-3xl p-8 text-center hover:bg-amber-500/10 hover:border-amber-500/30 transition">
            <div class="text-6xl mb-4">🎖️</div>
            <div class="text-2xl font-black text-amber-400 mb-2">BUJP</div>
            <div class="text-sm text-slate-400 mb-4">Badan Usaha Jasa Pengamanan</div>
            <div class="inline-block px-6 py-3 rounded-2xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-black">
              Login BUJP →
            </div>
          </a>

        </div>

        <div class="text-center mt-12 text-xs text-slate-500 animate-fadeInUp animate-delay-400">
          <div>© 2026 Binmas Sumatera Selatan v2.0</div>
          <div class="mt-1">Powered by Devindimas</div>
        </div>

      </div>
    </div>
    """)
    return render_page("Pilih Jenis Login", body, hide_navbar=True)


@app.route("/logout")
@login_required
def logout():
    log_action("LOGOUT", "user", session.get("user_id"))
    session.clear()
    return redirect(url_for("login"))




@app.route("/change-password", methods=["GET", "POST"])
@login_required
def change_password():
    user = current_user()
    error = ""
    msg = ""
    if request.method == "POST":
        current = request.form.get("current_password") or ""
        new1 = request.form.get("new_password") or ""
        new2 = request.form.get("new_password2") or ""
        if not verify_password(current, user["password_hash"]):
            error = "Password saat ini tidak sesuai."
        elif len(new1) < 8:
            error = "Password baru minimal 8 karakter."
        elif new1 != new2:
            error = "Konfirmasi password baru tidak sama."
        else:
            get_db().execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (hash_password(new1), now_str(), user["id"]))
            get_db().commit()
            log_action("CHANGE_OWN_PASSWORD", "user", user["id"])
            msg = "Password berhasil diganti."

    body = render_template_string("""
    <div class="max-w-xl mx-auto mt-4">
      <div class="glass rounded-3xl p-6">
        <h1 class="text-2xl font-black mb-1">Ganti Password</h1>
        <p class="text-slate-400 text-sm mb-6">Amankan akun Anda dengan password baru.</p>
        {% if msg %}<div class="mb-4 p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-sm">{{ msg }}</div>{% endif %}
        {% if error %}<div class="mb-4 p-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm">{{ error }}</div>{% endif %}
        <form method="post" class="space-y-4">
          <input type="password" name="current_password" required placeholder="Password saat ini" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
          <input type="password" name="new_password" required placeholder="Password baru" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
          <input type="password" name="new_password2" required placeholder="Ulangi password baru" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
          <button class="rounded-2xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black px-5 py-3">Simpan</button>
        </form>
      </div>
    </div>
    """, error=error, msg=msg)
    return render_page("Ganti Password", body, user)


@app.route("/bujp")
@app.route("/bujp/dashboard")
@login_required
@roles_required("anggota")
def bujp_dashboard():
    user = current_user()
    db = get_db()
    
    # Statistik BUJP
        # ✅ [FIX] Pakai IN() dan tambah kurung untuk operator precedence yang benar
    total_anggota = db.execute("SELECT COUNT(*) FROM users WHERE role IN ('anggota','satpam') AND is_active=1").fetchone()[0]
    total_kta_terbit = db.execute("SELECT COUNT(*) FROM users WHERE no_kta != '' AND is_active=1").fetchone()[0]
    total_satpam_aktif = db.execute("SELECT COUNT(*) FROM users WHERE role='satpam' AND is_active=1").fetchone()[0]
    verified_count = db.execute("SELECT COUNT(*) FROM users WHERE role IN ('anggota','satpam') AND bujp_id = ? AND bujp_verified = 1", (user['bujp_id'],)).fetchone()[0]
    pending_count = db.execute("SELECT COUNT(*) FROM users WHERE role IN ('anggota','satpam') AND bujp_id = ? AND COALESCE(bujp_verified, 0) = 0", (user['bujp_id'],)).fetchone()[0]
    
    # Daftar anggota terbaru (HANYA ANGGOTA BUJP INI SAJA, BUKAN SEMUA)
    anggota_terbaru = db.execute("""
        SELECT id, username, full_name, no_kta, role, is_active, created_at, COALESCE(bujp_verified, 0) AS bujp_verified
        FROM users 
        WHERE role IN ('anggota','satpam')
        AND bujp_id = ?
        ORDER BY id DESC LIMIT 10
    """, (user['bujp_id'],)).fetchall()
    
    body = render_template_string("""
    <div class="max-w-7xl mx-auto mt-4">
    
        <div class="text-center mb-8">
            <div class="w-20 h-20 mx-auto mb-4 rounded-3xl bg-gradient-to-br from-amber-500 to-orange-600 flex items-center justify-center text-4xl shadow-lg shadow-amber-500/30">
                🎖️
            </div>
            <h1 class="text-4xl font-black mb-2 text-amber-400">DASHBOARD BUJP</h1>
            <div class="text-lg font-bold text-slate-300">BADAN USAHA JASA PENGAMANAN</div>
            <div class="text-sm text-slate-500 mt-1">Pusat Administrasi dan Verifikasi Anggota Binmas</div>
        </div>
        
        <!-- Statistik Kartu -->
        <div class="grid md:grid-cols-4 gap-4 mb-8">
            <div class="glass rounded-3xl p-5 text-center">
                <div class="text-4xl font-black text-cyan-300">{{ total_anggota }}</div>
                <div class="text-sm text-slate-400">Total Anggota Terdaftar</div>
            </div>
            <div class="glass rounded-3xl p-5 text-center">
                <div class="text-4xl font-black text-emerald-400">{{ total_kta_terbit }}</div>
                <div class="text-sm text-slate-400">KTA Sudah Terbit</div>
            </div>
            <div class="glass rounded-3xl p-5 text-center">
                <div class="text-4xl font-black text-violet-400">{{ total_satpam_aktif }}</div>
                <div class="text-sm text-slate-400">Satpam Aktif</div>
            </div>
            <div class="glass rounded-3xl p-5 text-center">
                <div class="text-4xl font-black text-pink-400">98.2 %</div>
                <div class="text-sm text-slate-400">Tingkat Validasi</div>
            </div>
        </div>
        
        <!-- TAB MENU BUJP -->
        <div class="grid grid-cols-2 md:flex gap-2 mb-6 border-b border-white/10 pb-3">
            <button id="tabBeranda" onclick="showBujpTab('beranda')" class="px-4 py-3 rounded-2xl font-bold tab-btn bg-amber-500 text-slate-950">🏠 Beranda</button>
            <button id="tabValidasi" onclick="showBujpTab('validasi')" class="px-4 py-3 rounded-2xl tab-btn bg-white/5 border border-white/10">✅ VALIDASI</button>
            <button id="tabAnggota" onclick="showBujpTab('anggota')" class="px-4 py-3 rounded-2xl tab-btn bg-white/5 border border-white/10">👥 Anggota</button>
            <button id="tabLaporan" onclick="showBujpTab('laporan')" class="px-4 py-3 rounded-2xl tab-btn bg-white/5 border border-white/10">📊 Laporan</button>
        </div>
        
        <!-- TAB BERANDA -->
        <div id="tabBerandaContent" class="mb-8">
            <!-- Menu Fitur BUJP -->
            <div class="grid md:grid-cols-3 gap-6 mb-8">
                
                <div onclick="showBujpTab('validasi')" class="glass rounded-3xl p-6 text-center hover:bg-amber-500/10 hover:border-amber-500/20 transition cursor-pointer">
                    <div class="text-5xl mb-4">✅</div>
                    <div class="text-xl font-black text-amber-300 mb-2">VALIDASI STATUS</div>
                    <div class="text-sm text-slate-400">Verifikasi keabsahan status anggota secara realtime</div>
                </div>
                
                <a href="#" class="glass rounded-3xl p-6 text-center hover:bg-amber-500/10 hover:border-amber-500/20 transition">
                    <div class="text-5xl mb-4">🪪</div>
                    <div class="text-xl font-black text-amber-300 mb-2">Cetak Kartu Anggota</div>
                    <div class="text-sm text-slate-400">Generate dan cetak KTA Satpam otomatis dengan template resmi</div>
                </a>
                
                <a href="{{ url_for('bujp_register_satpam') }}" class="glass rounded-3xl p-6 text-center hover:bg-amber-500/10 hover:border-amber-500/20 transition">
                    <div class="text-5xl mb-4">📋</div>
                    <div class="text-xl font-black text-amber-300 mb-2">Daftar Anggota Baru</div>
                    <div class="text-sm text-slate-400">Pendaftaran satpam baru yang otomatis terhubung ke BUJP Anda</div>
                </a>
                
                <a href="#" class="glass rounded-3xl p-6 text-center hover:bg-amber-500/10 hover:border-amber-500/20 transition">
                    <div class="text-5xl mb-4">🔄</div>
                    <div class="text-xl font-black text-amber-300 mb-2">Perpanjang KTA</div>
                    <div class="text-sm text-slate-400">Perpanjangan masa berlaku Kartu Tanda Anggota</div>
                </a>
                
                
                <a onclick="showBujpTab('laporan')" href="#" class="glass rounded-3xl p-6 text-center hover:bg-amber-500/10 hover:border-amber-500/20 transition cursor-pointer">
                    <div class="text-5xl mb-4">📊</div>
                    <div class="text-xl font-black text-amber-300 mb-2">Laporan & Rekap</div>
                    <div class="text-sm text-slate-400">Laporan statistik dan rekap data keanggotaan Binmas</div>
                </a>
                
                <a href="#" class="glass rounded-3xl p-6 text-center hover:bg-amber-500/10 hover:border-amber-500/20 transition">
                    <div class="text-5xl mb-4">🔍</div>
                    <div class="text-xl font-black text-amber-300 mb-2">Cek Data Anggota</div>
                    <div class="text-sm text-slate-400">Pencarian dan verifikasi data anggota by NIK / No KTA / Nama</div>
                </a>
                
            </div>
        </div>
        
        <!-- TAB VALIDASI STATUS -->
        <div id="tabValidasiContent" class="hidden mb-8">
            <div class="glass rounded-3xl p-6">
                <h2 class="text-2xl font-black mb-4">✅ VALIDASI STATUS ANGGOTA BUJP</h2>
                <p class="text-slate-400 mb-6">Daftar seluruh anggota di BUJP anda beserta status verifikasi. Centang berwarna hijau menandakan anggota sudah diverifikasi.</p>
                
                <div class="grid md:grid-cols-2 gap-4 mb-6">
                    <div class="p-5 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-center">
                        <div class="text-3xl font-black text-emerald-400">{{ verified_count }}</div>
                        <div class="text-sm text-slate-300">✅ Sudah Diverifikasi</div>
                    </div>
                    <div class="p-5 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-center">
                        <div class="text-3xl font-black text-amber-400">{{ pending_count }}</div>
                        <div class="text-sm text-slate-300">⏳ Belum Diverifikasi</div>
                    </div>
                </div>
                
                <div class="overflow-auto max-h-[60vh]">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="text-left text-slate-400 border-b border-white/10">
                                <th class="py-3 px-2">Status</th>
                                <th class="py-3 px-2">Nama Anggota</th>
                                <th class="py-3 px-2">No KTA</th>
                                <th class="py-3 px-2">Tanggal Daftar</th>
                                <th class="py-3 px-2">Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for anggota in anggota_terbaru %}
                            <tr class="border-b border-white/5 hover:bg-white/5 transition" data-user-id="{{ anggota.id }}">
                                <td class="py-3 px-2 text-center text-2xl status-icon">
                                    {% if anggota.bujp_verified == 1 %}
                                    <span class="text-emerald-400" title="Sudah diverifikasi">✅</span>
                                    {% else %}
                                    <span class="text-slate-500" title="Belum diverifikasi">⏳</span>
                                    {% endif %}
                                </td>
                                <td class="py-3 px-2 font-bold">{{ anggota.full_name }}</td>
                                <td class="py-3 px-2 text-cyan-300">{{ anggota.no_kta or '-' }}</td>
                                <td class="py-3 px-2 text-slate-400">{{ anggota.created_at }}</td>
                                <td class="py-3 px-2 btn-container">
                                    {% if anggota.bujp_verified == 1 %}
                                    <button onclick="batalkanVerifikasi({{ anggota.id }})" class="px-3 py-1 rounded-xl bg-amber-500/20 text-amber-400 text-xs font-bold">
                                        Batalkan Verifikasi
                                    </button>
                                    {% else %}
                                    <button onclick="verifikasiAnggota({{ anggota.id }})" class="px-3 py-1 rounded-xl bg-emerald-500/20 text-emerald-400 text-xs font-bold">
                                        ✅ Verifikasi
                                    </button>
                                    {% endif %}
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
        
        <!-- TAB ANGGOTA -->
        <div id="tabAnggotaContent" class="hidden mb-8">
            <div class="glass rounded-3xl p-6">
                <h2 class="text-2xl font-black mb-4">Daftar Anggota Terbaru</h2>
                <div class="overflow-auto max-h-[50vh]">
                    <table class="w-full text-sm">
                        <thead>
                            <tr class="text-left text-slate-400 border-b border-white/10">
                                <th class="py-3 px-2">No</th>
                                <th class="py-3 px-2">Nama</th>
                                <th class="py-3 px-2">No KTA</th>
                                <th class="py-3 px-2">Role</th>
                                <th class="py-3 px-2">Status</th>
                                <th class="py-3 px-2">Tanggal Daftar</th>
                                <th class="py-3 px-2">Aksi</th>
                            </tr>
                        </thead>
                        <tbody>
                            {% for anggota in anggota_terbaru %}
                            <tr class="border-b border-white/5">
                                <td class="py-3 px-2">{{ loop.index }}</td>
                                <td class="py-3 px-2 font-bold">{{ anggota.full_name }}</td>
                                <td class="py-3 px-2 text-cyan-300">{{ anggota.no_kta or '-' }}</td>
                                <td class="py-3 px-2"><span class="px-2 py-1 rounded-lg bg-white/5 border border-white/10 text-xs">{{ anggota.role }}</span></td>
                                <td class="py-3 px-2">
                                    {% if anggota.is_active %}
                                    <span class="text-emerald-400">✅ Aktif</span>
                                    {% else %}
                                    <span class="text-slate-400">⚪ Nonaktif</span>
                                    {% endif %}
                                </td>
                                <td class="py-3 px-2 text-slate-400">{{ anggota.created_at }}</td>
                                <td class="py-3 px-2">
                                    <button class="px-3 py-1 rounded-xl bg-amber-500 text-slate-950 text-xs font-bold">Detail</button>
                                </td>
                            </tr>
                            {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>

        <!-- TAB LAPORAN -->
        <div id="tabLaporanContent" class="hidden mb-8">
            <div class="glass rounded-3xl p-6">
                <div class="text-center mb-6">
                    <div class="text-5xl mb-4">📊</div>
                    <h2 class="text-2xl font-black mb-2">LAPORAN & REKAP DATA</h2>
                    <p class="text-slate-400">Export data anggota dan rekap absensi ke format Excel (.xlsx)</p>
                </div>
                
                <div class="grid md:grid-cols-2 gap-6 max-w-2xl mx-auto">
                    <a href="{{ url_for('bujp_export_satpam') }}" class="glass rounded-3xl p-6 text-center hover:bg-cyan-500/10 hover:border-cyan-500/20 transition">
                        <div class="text-5xl mb-4">👥</div>
                        <div class="text-xl font-black text-cyan-300 mb-2">EXPORT DATA SATPAM</div>
                        <div class="text-sm text-slate-400">Download semua data anggota Satpam yang terdaftar di BUJP Anda dalam format Excel</div>
                        <div class="mt-4 inline-block px-4 py-2 rounded-xl bg-cyan-500 text-slate-950 font-bold">
                            📥 DOWNLOAD EXCEL
                        </div>
                    </a>
                    
                    <a href="{{ url_for('bujp_export_absensi') }}" class="glass rounded-3xl p-6 text-center hover:bg-emerald-500/10 hover:border-emerald-500/20 transition">
                        <div class="text-5xl mb-4">📅</div>
                        <div class="text-xl font-black text-emerald-300 mb-2">EXPORT REKAP ABSENSI</div>
                        <div class="text-sm text-slate-400">Download semua riwayat absensi harian Satpam di BUJP Anda dalam format Excel</div>
                        <div class="mt-4 inline-block px-4 py-2 rounded-xl bg-emerald-500 text-slate-950 font-bold">
                            📥 DOWNLOAD EXCEL
                        </div>
                    </a>
                </div>
            </div>
        </div>
        
    </div>
    
    <script>
    function showBujpTab(tab) {
        // Hide semua tab
        document.querySelectorAll('[id$="Content"]').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.tab-btn').forEach(btn => {
            btn.classList.remove('bg-amber-500', 'text-slate-950');
            btn.classList.add('bg-white/5', 'border', 'border-white/10');
        });
        
        // Tampilkan tab yang dipilih
        document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1) + 'Content').classList.remove('hidden');
        document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.remove('bg-white/5', 'border', 'border-white/10');
        document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('bg-amber-500', 'text-slate-950');
    }
    
    async function verifikasiAnggota(userId) {
        if (!confirm('Yakin ingin memverifikasi anggota ini?')) return;
        
        try {
            const res = await fetch(`/api/bujp/verify/${userId}`, { method: 'POST' });
            const result = await res.json();
            
            if (result.ok) {
                // ✅ UPDATE DOM SAJA TANPA RELOAD HALAMAN
                // Cari baris tr yang berisi user id ini
                const row = document.querySelector(`tr[data-user-id="${userId}"]`);
                if (row) {
                    // Ubah status icon menjadi ✅
                    row.querySelector('.status-icon').innerHTML = '<span class="text-emerald-400" title="Sudah diverifikasi">✅</span>';
                    // Ubah tombol menjadi Batalkan Verifikasi
                    const btnContainer = row.querySelector('.btn-container');
                    btnContainer.innerHTML = `<button onclick="batalkanVerifikasi(${userId})" class="px-3 py-1 rounded-xl bg-amber-500/20 text-amber-400 text-xs font-bold">Batalkan Verifikasi</button>`;
                }
                alert(result.message || 'Anggota berhasil diverifikasi');
            } else {
                alert(result.error || 'Gagal memverifikasi anggota');
            }
        } catch (err) {
            alert('Gagal terhubung ke server');
        }
    }
    
    async function batalkanVerifikasi(userId) {
        if (!confirm('Yakin ingin membatalkan verifikasi anggota ini?')) return;
        
        try {
            const res = await fetch(`/api/bujp/unverify/${userId}`, { method: 'POST' });
            const result = await res.json();
            
            if (result.ok) {
                // ✅ UPDATE DOM SAJA TANPA RELOAD HALAMAN
                // Cari baris tr yang berisi user id ini
                const row = document.querySelector(`tr[data-user-id="${userId}"]`);
                if (row) {
                    // Ubah status icon menjadi ⏳
                    row.querySelector('.status-icon').innerHTML = '<span class="text-slate-500" title="Belum diverifikasi">⏳</span>';
                    // Ubah tombol menjadi Verifikasi
                    const btnContainer = row.querySelector('.btn-container');
                    btnContainer.innerHTML = `<button onclick="verifikasiAnggota(${userId})" class="px-3 py-1 rounded-xl bg-emerald-500/20 text-emerald-400 text-xs font-bold">✅ Verifikasi</button>`;
                }
                alert(result.message || 'Verifikasi berhasil dibatalkan');
            } else {
                alert(result.error || 'Gagal membatalkan verifikasi');
            }
        } catch (err) {
            alert('Gagal terhubung ke server');
        }
    }
    </script>
    """, 
    total_anggota=total_anggota,
    total_kta_terbit=total_kta_terbit,
    total_satpam_aktif=total_satpam_aktif,
    verified_count=verified_count,
    pending_count=pending_count,
    anggota_terbaru=anggota_terbaru
    )
    return render_page("Dashboard BUJP", body, user)


@app.route("/bujp/register-satpam", methods=["GET", "POST"])
@login_required
@roles_required("anggota")
def bujp_register_satpam():
    user = current_user()
    db = get_db()
    msg = ""
    error = ""

    bujp = None
    if user["bujp_id"]:
        bujp = db.execute("SELECT * FROM bujp WHERE id = ?", (user["bujp_id"],)).fetchone()

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        full_name = (request.form.get("full_name") or "").strip()
        password = request.form.get("password") or ""
        no_kta = (request.form.get("no_kta") or "").strip()
        nik = (request.form.get("nik") or "").strip()
        no_hp = (request.form.get("no_hp") or "").strip()
        alamat = (request.form.get("alamat") or "").strip()
        jabatan = (request.form.get("jabatan") or "").strip()
        tanggal_lahir = (request.form.get("tanggal_lahir") or "").strip()
        tanggal_masuk = (request.form.get("tanggal_masuk") or "").strip()

        if not user["bujp_id"]:
            error = "Akun BUJP Anda belum terhubung ke data BUJP."
        elif not username:
            error = "Username wajib diisi."
        elif not full_name:
            error = "Nama lengkap wajib diisi."
        elif len(password) < 8:
            error = "Password minimal 8 karakter."
        elif db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone():
            error = "Username sudah terdaftar, silakan gunakan username lain."
        else:
            ts = now_str()
            try:
                cur = db.execute("""
                    INSERT INTO users (
                        username, full_name, role, password_hash, is_active, bujp_id,
                        no_kta, nik, no_hp, alamat, jabatan, tanggal_lahir, tanggal_masuk,
                        bujp_verified, bujp_verified_at, bujp_verified_by,
                        created_at, updated_at
                    ) VALUES (?, ?, 'satpam', ?, 1, ?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
                """, (
                    username,
                    full_name,
                    hash_password(password),
                    user["bujp_id"],
                    no_kta,
                    nik,
                    no_hp,
                    alamat,
                    jabatan,
                    tanggal_lahir,
                    tanggal_masuk,
                    ts,
                    user["id"],
                    ts,
                    ts,
                ))
                db.commit()
                log_action("BUJP_REGISTER_SATPAM", "user", cur.lastrowid, f"bujp_id={user['bujp_id']};username={username}")
                msg = f"Satpam baru berhasil didaftarkan dan otomatis terhubung ke BUJP {bujp['nama_bujp'] if bujp else ''}."
            except sqlite3.IntegrityError:
                error = "Gagal menyimpan data. Username mungkin sudah digunakan."

    body = render_template_string("""
    <div class="max-w-4xl mx-auto mt-6 grid lg:grid-cols-3 gap-6">
      <div class="lg:col-span-2 glass rounded-3xl p-6">
        <h1 class="text-3xl font-black mb-2 text-amber-400">📋 Daftar Anggota Baru</h1>
        <p class="text-slate-400 mb-6">Buat akun satpam baru. Data akan otomatis masuk sebagai anggota BUJP Anda.</p>

        {% if msg %}
        <div class="mb-4 p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-sm">{{ msg }}</div>
        {% endif %}
        {% if error %}
        <div class="mb-4 p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm">{{ error }}</div>
        {% endif %}

        <form method="post" class="space-y-4">
          <div class="grid md:grid-cols-2 gap-4">
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Username Login</label>
              <input name="username" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Password Awal</label>
              <input name="password" type="password" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500" placeholder="Minimal 8 karakter">
            </div>
          </div>

          <div class="grid md:grid-cols-2 gap-4">
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Nama Lengkap</label>
              <input name="full_name" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Nomor KTA</label>
              <input name="no_kta" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
            </div>
          </div>

          <div class="grid md:grid-cols-2 gap-4">
            <div>
              <label class="text-sm text-slate-400 mb-1 block">NIK</label>
              <input name="nik" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-1 block">No HP / WhatsApp</label>
              <input name="no_hp" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
            </div>
          </div>

          <div class="grid md:grid-cols-2 gap-4">
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Jabatan</label>
              <input name="jabatan" placeholder="contoh: Satpam Shift 1" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Tanggal Lahir</label>
              <input name="tanggal_lahir" type="date" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
            </div>
          </div>

          <div>
            <label class="text-sm text-slate-400 mb-1 block">Tanggal Masuk</label>
            <input name="tanggal_masuk" type="date" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
          </div>

          <div>
            <label class="text-sm text-slate-400 mb-1 block">Alamat</label>
            <textarea name="alamat" rows="3" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500"></textarea>
          </div>

          <div class="flex gap-3 pt-2">
            <a href="{{ url_for('bujp_dashboard') }}" class="rounded-2xl bg-white/5 border border-white/10 px-5 py-3 font-bold">← Kembali</a>
            <button class="rounded-2xl bg-amber-500 hover:bg-amber-400 text-slate-950 font-black px-6 py-3">✅ Daftarkan Satpam</button>
          </div>
        </form>
      </div>

      <div class="glass rounded-3xl p-6 h-fit">
        <h2 class="text-xl font-black mb-4">Informasi BUJP</h2>
        <div class="space-y-3 text-sm">
          <div><span class="text-slate-400">Nama BUJP:</span><br><span class="font-bold text-amber-300">{{ bujp.nama_bujp if bujp else '-' }}</span></div>
          <div><span class="text-slate-400">Akun Login:</span><br><span class="font-bold">{{ user.username }}</span></div>
          <div><span class="text-slate-400">Role akun:</span><br><span class="font-bold">{{ user.role }}</span></div>
        </div>
        <div class="mt-5 p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-sm text-slate-300">
          Setiap satpam yang dibuat dari menu ini otomatis:
          <ul class="list-disc ml-5 mt-2 space-y-1">
            <li>role = <b>satpam</b></li>
            <li>terhubung ke <b>BUJP Anda</b></li>
            <li>langsung berstatus <b>terverifikasi BUJP</b></li>
          </ul>
        </div>
      </div>
    </div>
    """, user=user, bujp=bujp, msg=msg, error=error)
    return render_page("Daftar Anggota Baru", body, user)


@app.route("/satpam/profile", methods=["GET", "POST"])
@login_required
@roles_required("satpam")
def satpam_profile():
    user = current_user()
    msg = ""
    # Ambil data BUJP jika user terasosiasi dengan BUJP
    bujp = None
    if user['bujp_id']:
        bujp = get_db().execute("SELECT * FROM bujp WHERE id = ?", (user['bujp_id'],)).fetchone()
    
    if request.method == "POST":
        no_kta = (request.form.get("no_kta") or "").strip()
        nik = (request.form.get("nik") or "").strip()
        no_hp = (request.form.get("no_hp") or "").strip()
        alamat = (request.form.get("alamat") or "").strip()
        tanggal_lahir = (request.form.get("tanggal_lahir") or "").strip()
        tanggal_masuk = (request.form.get("tanggal_masuk") or "").strip()
        jabatan = (request.form.get("jabatan") or "").strip()
        
        get_db().execute("""
            UPDATE users SET 
                no_kta=?, nik=?, no_hp=?, alamat=?, 
                tanggal_lahir=?, tanggal_masuk=?, jabatan=?, updated_at=?
            WHERE id=?
        """, (no_kta, nik, no_hp, alamat, tanggal_lahir, tanggal_masuk, jabatan, now_str(), user["id"]))
        get_db().commit()
        log_action("SATPAM_UPDATE_PROFILE", "user", user["id"])
        msg = "✅ Profil KTA berhasil disimpan!"
    
    body = render_template_string("""
    <div class="grid lg:grid-cols-2 gap-6 mt-6">
    
      <div class="glass rounded-3xl p-6">
        <h2 class="text-2xl font-black mb-4">Edit Profil KTA</h2>
        {% if msg %}
        <div class="mb-4 p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-sm">{{ msg }}</div>
        {% endif %}
        
        <form method="post" class="space-y-4">
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Nomor KTA</label>
              <input name="no_kta" value="{{ user.no_kta }}" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-1 block">NIK</label>
              <input name="nik" value="{{ user.nik }}" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
          </div>
          
          <div>
            <label class="text-sm text-slate-400 mb-1 block">Nama Lengkap</label>
            <input value="{{ user.full_name }}" disabled class="w-full rounded-2xl bg-white/3 border border-white/5 px-4 py-3 text-slate-400">
          </div>
          
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-sm text-slate-400 mb-1 block">No HP / WhatsApp</label>
              <input name="no_hp" value="{{ user.no_hp }}" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Jabatan</label>
              <input name="jabatan" value="{{ user.jabatan }}" placeholder="contoh: Satpam Shift 1" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
          </div>
          
          <div>
            <label class="text-sm text-slate-400 mb-1 block">Alamat Lengkap</label>
            <textarea name="alamat" rows="2" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">{{ user.alamat }}</textarea>
          </div>
          
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Tanggal Lahir</label>
              <input name="tanggal_lahir" type="date" value="{{ user.tanggal_lahir }}" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 mb-1 block">Tanggal Masuk</label>
              <input name="tanggal_masuk" type="date" value="{{ user.tanggal_masuk }}" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
          </div>
          
          <button class="w-full rounded-2xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black px-5 py-4 mt-2">Simpan Profil KTA</button>
        </form>
      </div>
      
      <div class="space-y-6">
        <div class="glass rounded-3xl p-6">
          <h2 class="text-2xl font-black mb-4">🪪 Kartu Tanda Anggota Digital</h2>
          
            <div class="bg-gradient-to-br from-cyan-500/20 to-blue-600/20 border border-cyan-500/20 rounded-3xl p-6">
            <div class="text-center mb-4">
              <div class="text-4xl font-black text-cyan-300">BINMAS</div>
              <div class="text-xs text-slate-400">KARTU TANDA ANGGOTA SATPAM</div>
            </div>
            
            {% if user.bujp_id and bujp %}
            <div class="mb-5 p-4 rounded-2xl bg-emerald-500/20 border border-emerald-500/20 text-center">
                <div class="text-emerald-400 font-bold">✅ TERDAFTAR SEBAGAI ANGGOTA BUJP</div>
                <div class="text-lg font-black text-white mt-1">{{ bujp.nama_bujp }}</div>
            </div>
            {% endif %}
            
            <div class="grid grid-cols-3 gap-4 items-center">
              <div class="col-span-1">
                <div class="w-24 h-32 rounded-2xl bg-white/5 border border-white/10 flex items-center justify-center text-4xl">👮</div>
              </div>
              <div class="col-span-2 space-y-2 text-sm">
                <div><span class="text-slate-400">No KTA:</span> <span class="font-bold text-white">{{ user.no_kta or '-' }}</span></div>
                <div><span class="text-slate-400">Nama:</span> <span class="font-bold text-white">{{ user.full_name }}</span></div>
                <div><span class="text-slate-400">NIK:</span> <span class="text-white">{{ user.nik or '-' }}</span></div>
                <div><span class="text-slate-400">Jabatan:</span> <span class="text-white">{{ user.jabatan or '-' }}</span></div>
                <div><span class="text-slate-400">Tgl Masuk:</span> <span class="text-white">{{ user.tanggal_masuk or '-' }}</span></div>
                {% if user.bujp_id and bujp %}
                <div><span class="text-slate-400">BUJP:</span> <span class="text-emerald-300 font-bold">{{ bujp.nama_bujp }}</span></div>
                {% endif %}
              </div>
            </div>
            
            <div class="mt-5 pt-4 border-t border-white/10 text-center text-xs text-slate-500">
              Kartu ini berlaku selama yang bersangkutan terdaftar sebagai anggota Satpam Binmas
            </div>
          </div>
          
          <div class="mt-6 text-center text-sm text-slate-400">
            Klik kanan pada kartu di atas untuk menyimpan sebagai gambar / screenshot
          </div>
        </div>
      </div>
      
    </div>
    """, user=user, msg=msg, bujp=bujp)
    return render_page("Profil KTA Satpam", body, user)


@app.route("/satpam")
@login_required
@roles_required("satpam")
def satpam_page():
    user = current_user()
    db = get_db()
    rekening_list = db.execute("""
        SELECT * FROM rekening_bank 
        WHERE is_active = 1 
        ORDER BY urutan ASC, id ASC
    """).fetchall()
    
    body = render_template_string("""
    <div class="max-w-6xl mx-auto mt-4 sm:mt-6 px-2 sm:px-4 space-y-4 sm:space-y-6">
    
      <!-- ✅ RESPONSIVE LAYOUT: 1 kolom di HP, 2 kolom di Desktop -->
      <div class="grid grid-cols-1 lg:grid-cols-12 gap-4 sm:gap-6">
      
        <!-- KIRI: Profil + Tombol Emergency (di hp full width, di desktop 5 kolom) -->
        <div class="lg:col-span-5 space-y-4 sm:space-y-6">
        
          <!-- Profil Header -->
          <div class="glass rounded-3xl p-4 sm:p-6 text-center">
            <div class="w-16 h-16 sm:w-24 sm:h-24 mx-auto rounded-full bg-gradient-to-br from-cyan-500 to-blue-600 flex items-center justify-center text-2xl sm:text-4xl mb-3 sm:mb-4">
              👮
            </div>
            <h1 class="text-xl sm:text-2xl font-black mb-1">{{ user.full_name }}</h1>
            <div class="text-xs sm:text-sm text-slate-400 mb-2">@{{ user.username }} • Satpam</div>
            {% if user.no_kta %}
            <div class="inline-block px-3 py-1 rounded-full bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-xs sm:text-sm">
              ✅ KTA Aktif: {{ user.no_kta }}
            </div>
            {% else %}
            <div class="inline-block px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-300 text-xs sm:text-sm">
              ⚠️ Belum isi profil KTA
            </div>
            {% endif %}
            
            <div class="mt-4 flex items-center justify-center gap-4 text-xs text-slate-400">
              <div id="liveClock">--:--:-- WIB</div>
              <div id="connectionStatus" class="flex items-center gap-1">
                <span class="w-2 h-2 rounded-full bg-amber-500 animate-pulse"></span>
                <span>Connecting...</span>
              </div>
            </div>
          </div>
          
          <!-- 🚨 EMERGENCY BUTTON RESPONSIVE -->
          <button onclick="showEmergencyModal()" class="w-full rounded-3xl bg-gradient-to-br from-red-600 to-red-800 hover:from-red-500 hover:to-red-700 text-white font-black text-lg sm:text-2xl px-4 sm:px-6 py-5 sm:py-8 transition-all duration-300 transform hover:scale-[1.02] active:scale-[0.97] shadow-lg shadow-red-500/40 border-2 border-red-400">
            <div class="text-4xl sm:text-6xl mb-2 sm:mb-4">🚨</div>
            <div>TOMBOL DARURAT</div>
            <div class="text-xs sm:text-sm opacity-80 mt-1 sm:mt-2">Tekan ini jika dalam kondisi bahaya / darurat</div>
          </button>
          
        </div>
        
        <!-- KANAN: Menu Grid (di hp full width, di desktop 7 kolom) -->
        <div class="lg:col-span-7">
          <!-- Menu Grid Responsive: 2 kolom hp, 3 kolom tablet, 4 kolom desktop besar -->
          <div class="grid grid-cols-2 md:grid-cols-3 xl:grid-cols-2 gap-3 sm:gap-4">
          
            <a href="{{ url_for('satpam_absen') }}" class="glass rounded-2xl sm:rounded-3xl p-4 sm:p-6 text-center hover:bg-cyan-500/10 hover:border-cyan-500/20 transition">
              <div class="text-3xl sm:text-4xl mb-2 sm:mb-3">📅</div>
              <div class="font-bold text-base sm:text-lg">ABSENSI</div>
              <div class="text-xs text-slate-400 mt-1">Absen Masuk & Pulang</div>
            </a>
            
            <a href="{{ url_for('satpam_profile') }}" class="glass rounded-2xl sm:rounded-3xl p-4 sm:p-6 text-center hover:bg-cyan-500/10 hover:border-cyan-500/20 transition">
              <div class="text-3xl sm:text-4xl mb-2 sm:mb-3">🪪</div>
              <div class="font-bold text-base sm:text-lg">Profil KTA</div>
              <div class="text-xs text-slate-400 mt-1">Edit & Lihat Kartu</div>
            </a>
            
            <a href="{{ url_for('satpam_perpanjang_kta') }}" class="glass rounded-2xl sm:rounded-3xl p-4 sm:p-6 text-center hover:bg-amber-500/10 hover:border-amber-500/20 transition">
              <div class="text-3xl sm:text-4xl mb-2 sm:mb-3">🔄</div>
              <div class="font-bold text-base sm:text-lg">Perpanjang KTA</div>
              <div class="text-xs text-slate-400 mt-1">Ajukan Perpanjangan</div>
            </a>

            <a href="{{ url_for('change_password') }}" class="glass rounded-2xl sm:rounded-3xl p-4 sm:p-6 text-center hover:bg-cyan-500/10 hover:border-cyan-500/20 transition">
              <div class="text-3xl sm:text-4xl mb-2 sm:mb-3">🔐</div>
              <div class="font-bold text-base sm:text-lg">Ganti Password</div>
              <div class="text-xs text-slate-400 mt-1">Keamanan Akun</div>
            </a>

            <a href="{{ url_for('satpam_emergency_history') }}" class="glass rounded-2xl sm:rounded-3xl p-4 sm:p-6 text-center hover:bg-red-500/10 hover:border-red-500/20 transition">
              <div class="text-3xl sm:text-4xl mb-2 sm:mb-3">📋</div>
              <div class="font-bold text-base sm:text-lg">Riwayat Laporan</div>
              <div class="text-xs text-slate-400 mt-1">History laporan darurat</div>
            </a>
            
            <a href="{{ url_for('logout') }}" class="glass rounded-2xl sm:rounded-3xl p-4 sm:p-6 text-center hover:bg-red-500/10 hover:border-red-500/20 transition">
              <div class="text-3xl sm:text-4xl mb-2 sm:mb-3">🚪</div>
              <div class="font-bold text-base sm:text-lg">Logout</div>
              <div class="text-xs text-slate-400 mt-1">Keluar Sistem</div>
            </a>
            
          </div>
        </div>
        
      </div>
      
      <!-- Info Footer -->
      <div class="glass rounded-3xl p-3 sm:p-4 text-center text-xs sm:text-sm text-slate-400 mt-4">
        <div>BINMAS Guard Tracker</div>
        <div class="text-xs mt-1">Versi 2.1 • Full Responsive • Live WebSocket</div>
      </div>
      
    </div>
    
    <script>
    // Jam realtime WIB
    function updateClock() {
      const now = new Date();
      const wib = new Date(now.getTime() + 7 * 3600 * 1000);
      const timeStr = wib.toISOString().substr(11, 8) + ' WIB';
      document.getElementById('liveClock').textContent = timeStr;
    }
    setInterval(updateClock, 1000);
    updateClock();
    
    // Status koneksi
    setInterval(() => {
      fetch('/').then(() => {
        document.getElementById('connectionStatus').innerHTML = '<span class="w-2 h-2 rounded-full bg-emerald-500"></span> <span>Online</span>';
      }).catch(() => {
        document.getElementById('connectionStatus').innerHTML = '<span class="w-2 h-2 rounded-full bg-red-500 animate-pulse"></span> <span>Offline</span>';
      });
    }, 5000);
    </script>
    
    <!-- 🚨 MODAL FORM LAPORAN DARURAT -->
    <div id="emergencyModal" class="fixed inset-0 bg-black/90 z-50 hidden flex items-center justify-center p-4">
        <div class="glass rounded-3xl p-6 w-full max-w-lg">
            <div class="text-center mb-6">
                <div class="text-6xl mb-3">🚨</div>
                <h2 class="text-2xl font-black text-red-400">LAPORAN DARURAT</h2>
                <p class="text-sm text-slate-400 mt-2">Laporan ini akan langsung dikirim ke semua Admin dan Direktur</p>
            </div>
            
            <form id="emergencyForm" class="space-y-4">
                <!-- Status GPS -->
                <div id="gpsStatus" class="p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-300 text-center">
                    <span class="animate-pulse">📡 Mendapatkan lokasi GPS...</span>
                </div>
                
                <!-- Koordinat yang terdeteksi -->
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="text-xs text-slate-400 block mb-1">Latitude</label>
                        <input id="emergencyLat" readonly class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none text-center">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400 block mb-1">Longitude</label>
                        <input id="emergencyLng" readonly class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none text-center">
                    </div>
                </div>
                
                <!-- Keterangan kejadian -->
                <div>
                    <label class="text-sm text-slate-400 block mb-2">📝 Keterangan Kejadian</label>
                    <textarea id="emergencyKet" name="keterangan" rows="3" required placeholder="Jelaskan secara singkat apa yang terjadi..." class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none"></textarea>
                </div>
                
                <!-- Upload foto opsional -->
                <div>
                    <label class="text-sm text-slate-400 block mb-2">📸 Foto Bukti (Opsional)</label>
                    <input id="emergencyFoto" name="foto" type="file" accept="image/*" capture="environment" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3">
                </div>
                
                <div class="p-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-xs text-red-200 text-center">
                    ⚠️ PERHATIAN: Laporan ini akan langsung dikirim tanpa konfirmasi lagi. Hanya gunakan dalam kondisi DARURAT SEJATI.
                </div>
                
                <div class="flex gap-3">
                    <button type="button" onclick="hideEmergencyModal()" class="flex-1 rounded-2xl bg-slate-500/20 text-slate-300 px-5 py-4 font-bold">
                        ❌ BATALKAN
                    </button>
                    <button type="submit" id="btnKirimDarurat" disabled class="flex-1 rounded-2xl bg-gradient-to-br from-red-600 to-red-800 text-white px-5 py-4 font-black">
                        🚨 KIRIM LAPORAN DARURAT
                    </button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
    // 🚨 FUNGSI EMERGENCY BUTTON
    function showEmergencyModal() {
        document.getElementById('emergencyModal').classList.remove('hidden');
        document.getElementById('btnKirimDarurat').disabled = true;
        document.getElementById('gpsStatus').innerHTML = '<span class="animate-pulse">📡 Mendapatkan lokasi GPS...</span>';
        document.getElementById('emergencyLat').value = '';
        document.getElementById('emergencyLng').value = '';
        document.getElementById('emergencyKet').value = '';
        document.getElementById('emergencyFoto').value = '';
        
        // Otomatis dapatkan lokasi GPS ketika modal terbuka
        if (navigator.geolocation) {
            navigator.geolocation.getCurrentPosition(
                (pos) => {
                    document.getElementById('emergencyLat').value = pos.coords.latitude.toFixed(7);
                    document.getElementById('emergencyLng').value = pos.coords.longitude.toFixed(7);
                    document.getElementById('gpsStatus').innerHTML = '✅ Lokasi berhasil didapatkan!';
                    document.getElementById('gpsStatus').className = 'p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-center';
                    document.getElementById('btnKirimDarurat').disabled = false;
                },
                (err) => {
                    document.getElementById('gpsStatus').innerHTML = '❌ Gagal mendapatkan lokasi GPS: ' + err.message;
                    document.getElementById('gpsStatus').className = 'p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-300 text-center';
                },
                { enableHighAccuracy: true, timeout: 10000, maximumAge: 0 }
            );
        } else {
            document.getElementById('gpsStatus').innerHTML = '❌ GPS tidak didukung perangkat';
            document.getElementById('gpsStatus').className = 'p-4 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-300 text-center';
        }
    }
    
    function hideEmergencyModal() {
        document.getElementById('emergencyModal').classList.add('hidden');
    }
    
    // Kirim laporan darurat
    document.getElementById('emergencyForm').addEventListener('submit', async (e) => {
        e.preventDefault();
        document.getElementById('btnKirimDarurat').disabled = true;
        document.getElementById('btnKirimDarurat').innerHTML = '<span class="animate-pulse">📡 Mengirim laporan...</span>';
        
        try {
            const formData = new FormData();
            formData.append('lat', document.getElementById('emergencyLat').value);
            formData.append('lng', document.getElementById('emergencyLng').value);
            formData.append('keterangan', document.getElementById('emergencyKet').value);
            
            if (document.getElementById('emergencyFoto').files[0]) {
                formData.append('foto', document.getElementById('emergencyFoto').files[0]);
            }
            
            const res = await fetch('/api/emergency/report', {
                method: 'POST',
                body: formData
            });
            
            const result = await res.json();
            
            if (result.ok) {
                document.getElementById('gpsStatus').innerHTML = '✅ LAPORAN DARURAT BERHASIL DIKIRIM! Admin sedang menuju lokasi Anda.';
                document.getElementById('gpsStatus').className = 'p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 text-center';
                setTimeout(() => {
                    hideEmergencyModal();
                    alert('✅ Laporan darurat berhasil dikirim ke semua Admin dan Direktur');
                }, 2000);
            } else {
                alert('❌ Gagal mengirim laporan: ' + (result.error || 'Server error'));
                document.getElementById('btnKirimDarurat').disabled = false;
                document.getElementById('btnKirimDarurat').innerHTML = '🚨 KIRIM LAPORAN DARURAT';
            }
        } catch (err) {
            alert('❌ Gagal terhubung ke server');
            document.getElementById('btnKirimDarurat').disabled = false;
            document.getElementById('btnKirimDarurat').innerHTML = '🚨 KIRIM LAPORAN DARURAT';
        }
    });
    </script>
    """, user=user, rekening_list=rekening_list)
    return render_page("Beranda Satpam", body, user)


# ==============================
# FITUR MANAJEMEN BUJP
# ==============================

@app.route("/bujp/management")
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_management():
    db = get_db()
    bujp_list = db.execute("""
        SELECT b.*, u.username, u.is_active as user_active 
        FROM bujp b 
        LEFT JOIN users u ON b.user_id = u.id 
        ORDER BY b.nama_bujp ASC
    """).fetchall()
    
    body = render_template_string("""
    <style>
    @keyframes pulse-red {
        0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 20px rgba(239, 68, 68, 0); }
        100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    .pengajuan-pending {
        animation: pulse-red 1.5s infinite;
        box-shadow: 0 0 15px rgba(239, 68, 68, 0.3);
        border: 2px solid rgba(239, 68, 68, 0.4) !important;
    }
    </style>
    
    <div class="mt-6">
        <div class="flex justify-between items-center mb-6">
            <h1 class="text-3xl font-black">📋 Manajemen BUJP</h1>
            <button onclick="showAddBujpModal()" class="bg-amber-500 hover:bg-amber-400 text-slate-950 font-bold px-6 py-3 rounded-2xl">
                ➕ Tambah BUJP Baru
            </button>
        </div>
        
        <div class="glass rounded-3xl overflow-hidden">
            <div class="overflow-x-auto">
                <table class="w-full">
                    <thead>
                        <tr class="bg-white/5 border-b border-white/10">
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Nama BUJP</th>
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">No Izin</th>
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Penanggung Jawab</th>
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">No HP</th>
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Masa Berlaku</th>
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Status</th>
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Akun Login</th>
                            <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Aksi</th>
                        </tr>
                    </thead>
                    <tbody class="divide-y divide-white/5">
                    {% for bujp in bujp_list %}
                        <tr class="hover:bg-white/5 transition">
                            <td class="px-6 py-4">
                                <div class="font-bold">{{ bujp.nama_bujp }}</div>
                            </td>
                            <td class="px-6 py-4 text-sm">{{ bujp.no_izin or '-' }}</td>
                            <td class="px-6 py-4 text-sm">{{ bujp.penanggung_jawab or '-' }}</td>
                            <td class="px-6 py-4 text-sm">{{ bujp.no_hp or '-' }}</td>
                            <td class="px-6 py-4 text-sm">{{ bujp.masa_berlaku_izin or '-' }}</td>
                            <td class="px-6 py-4">
                                {% if bujp.is_active %}
                                <span class="inline-block px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold">✅ Aktif</span>
                                {% else %}
                                <span class="inline-block px-3 py-1 rounded-full bg-red-500/20 text-red-400 text-xs font-bold">❌ Nonaktif</span>
                                {% endif %}
                            </td>
                            <td class="px-6 py-4">
                                {% if bujp.has_account %}
                                    <div>
                                        <span class="inline-block px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold">✅ Akun Sudah Dibuat</span>
                                        <div class="text-xs text-slate-400 mt-1">Username: @{{ bujp.username }}</div>
                                    </div>
                                {% else %}
                                    <span class="inline-block px-3 py-1 rounded-full bg-amber-500/20 text-amber-400 text-xs font-bold">⚠️ Belum Ada Akun</span>
                                {% endif %}
                            </td>
                            <td class="px-6 py-4">
                                <div class="flex gap-2">
                                    {% if not bujp.has_account %}
                                    <button onclick='createBujpAccount({{ bujp.id }}, "{{ bujp.nama_bujp.replace("'", "\\'") }}")' class="bg-emerald-500/20 text-emerald-400 px-3 py-2 rounded-xl text-xs font-bold">
                                        🔐 Buat Akun
                                    </button>
                                    {% else %}
                                    <button class="bg-slate-500/20 text-slate-400 px-3 py-2 rounded-xl text-xs font-bold" disabled>
                                        ✅ Akun Aktif
                                    </button>
                                    {% endif %}
                                    <button onclick="editBujp(
                                        {{ bujp.id }},
                                        '{{ bujp.nama_bujp.replace("'", "\\'") }}',
                                        '{{ bujp.no_izin.replace("'", "\\'") if bujp.no_izin else '' }}',
                                        '{{ bujp.penanggung_jawab.replace("'", "\\'") if bujp.penanggung_jawab else '' }}',
                                        '{{ bujp.no_hp.replace("'", "\\'") if bujp.no_hp else '' }}',
                                        '{{ bujp.email.replace("'", "\\'") if bujp.email else '' }}',
                                        '{{ bujp.masa_berlaku_izin if bujp.masa_berlaku_izin else '' }}',
                                        '{{ bujp.alamat.replace("'", "\\'") if bujp.alamat else '' }}',
                                        {{ bujp.latitude if bujp.latitude is not none else 'null' }},
                                        {{ bujp.longitude if bujp.longitude is not none else 'null' }},
                                        {{ bujp.geofence_radius if bujp.geofence_radius is not none else '100' }}
                                    )" class="bg-cyan-500/20 text-cyan-400 px-3 py-2 rounded-xl text-xs font-bold">
                                        ✏️ Edit
                                    </button>
                                    <form method="post" action="{{ url_for('bujp_delete', bujp_id=bujp.id) }}" onsubmit="return confirm('Yakin ingin menghapus BUJP ini?');">
                                        <button type="submit" class="bg-red-500/20 text-red-400 px-3 py-2 rounded-xl text-xs font-bold">
                                            🗑️ Hapus
                                        </button>
                                    </form>
                                    <a href="{{ url_for('bujp_detail', bujp_id=bujp.id) }}" class="bg-slate-500/20 text-slate-300 px-3 py-2 rounded-xl text-xs font-bold text-center">
                                        📊 Detail
                                    </a>
                                </div>
                            </td>
                        </tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
            {% if not bujp_list %}
            <div class="text-center py-12 text-slate-400">
                <div class="text-4xl mb-3">📋</div>
                <div>Belum ada data BUJP. Silakan tambahkan BUJP baru.</div>
            </div>
            {% endif %}
        </div>
    </div>
    
    <!-- Modal Tambah BUJP -->
    <div id="addBujpModal" class="fixed inset-0 bg-black/80 z-50 hidden flex items-center justify-center p-4">
        <div class="glass rounded-3xl p-6 w-full max-w-lg">
            <h2 class="text-2xl font-bold mb-4">Tambah BUJP Baru</h2>
            <form method="post" action="{{ url_for('bujp_add') }}" class="space-y-4">
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Nama BUJP</label>
                    <input name="nama_bujp" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="text-sm text-slate-400 block mb-1">Nomor Izin</label>
                        <input name="no_izin" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                    </div>
                    <div>
                        <label class="text-sm text-slate-400 block mb-1">Masa Berlaku Izin</label>
                        <input name="masa_berlaku_izin" type="date" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                    </div>
                </div>
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Penanggung Jawab</label>
                    <input name="penanggung_jawab" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                <div class="grid grid-cols-2 gap-4">
                    <div>
                        <label class="text-sm text-slate-400 block mb-1">No HP</label>
                        <input name="no_hp" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                    </div>
                    <div>
                        <label class="text-sm text-slate-400 block mb-1">Email</label>
                        <input name="email" type="email" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                    </div>
                </div>
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Alamat</label>
                    <textarea name="alamat" rows="2" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none"></textarea>
                </div>
                <div class="flex gap-3 mt-6">
                    <button type="button" onclick="hideAddBujpModal()" class="flex-1 bg-slate-500/20 text-slate-300 px-6 py-3 rounded-2xl font-bold">Batal</button>
                    <button type="submit" class="flex-1 bg-amber-500 text-slate-950 px-6 py-3 rounded-2xl font-bold">Simpan BUJP</button>
                </div>
            </form>
        </div>
    </div>
    
    <!-- Modal EDIT BUJP -->
    <div id="editBujpModal" class="fixed inset-0 bg-black/80 z-50 hidden flex items-start justify-center p-2 sm:p-4 overflow-auto">
        <div class="glass rounded-3xl p-4 sm:p-6 w-full max-w-2xl my-4">
            <h2 class="text-xl sm:text-2xl font-bold mb-4">✏️ Edit BUJP</h2>
            <form method="post" id="editBujpForm" action="/bujp/edit" class="space-y-4">
                <input type="hidden" name="bujpId" id="editBujpId">
                
                <div class="grid grid-cols-1 gap-4">
                    <div>
                        <label class="text-sm text-slate-400 block mb-1">Nama BUJP</label>
                        <input name="nama_bujp" id="edit_nama_bujp" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
                    </div>
                    
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="text-sm text-slate-400 block mb-1">Nomor Izin</label>
                            <input name="no_izin" id="edit_no_izin" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
                        </div>
                        <div>
                            <label class="text-sm text-slate-400 block mb-1">Masa Berlaku Izin</label>
                            <input name="masa_berlaku_izin" id="edit_masa_berlaku_izin" type="date" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
                        </div>
                    </div>
                    
                    <div>
                        <label class="text-sm text-slate-400 block mb-1">Penanggung Jawab</label>
                        <input name="penanggung_jawab" id="edit_penanggung_jawab" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
                    </div>
                    
                    <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        <div>
                            <label class="text-sm text-slate-400 block mb-1">No HP</label>
                            <input name="no_hp" id="edit_no_hp" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
                        </div>
                        <div>
                            <label class="text-sm text-slate-400 block mb-1">Email</label>
                            <input name="email" id="edit_email" type="email" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
                        </div>
                    </div>
                    
                    <div>
                        <label class="text-sm text-slate-400 block mb-1">Alamat</label>
                        <textarea name="alamat" id="edit_alamat" rows="2" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500"></textarea>
                    </div>
                    
                    <div class="border-t border-white/10 pt-4">
                        <label class="text-sm text-slate-400 block mb-2 font-bold">📍 PILIH LOKASI PERUSAHAAN</label>
                        <div class="text-xs text-slate-500 mb-3">
                            ✅ Klik di peta untuk menentukan lokasi<br>
                            ✅ Drag marker untuk memindahkan posisi<br>
                            ✅ Atur radius geofence area perusahaan
                        </div>
                        <div id="bujpLocationPicker" class="h-[300px] sm:h-[380px] w-full rounded-2xl mb-3 border border-amber-500/20"></div>
                        
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
                            <div>
                                <label class="text-sm text-slate-400 block mb-1">Latitude</label>
                                <input name="latitude" id="edit_latitude" readonly class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none text-sm">
                            </div>
                            <div>
                                <label class="text-sm text-slate-400 block mb-1">Longitude</label>
                                <input name="longitude" id="edit_longitude" readonly class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none text-sm">
                            </div>
                        </div>
                        
                        <div class="grid grid-cols-1 sm:grid-cols-2 gap-4 mt-3">
                            <div>
                                <label class="text-sm text-slate-400 block mb-1">🟡 Radius Geofence (meter)</label>
                                <input name="geofence_radius" id="edit_geofence_radius" type="range" min="50" max="2000" value="100" 
                                    class="w-full h-3 bg-white/10 rounded-full appearance-none cursor-pointer accent-amber-500"
                                    oninput="document.getElementById('radiusDisplay').textContent = this.value + ' m'">
                                <div class="flex justify-between text-xs text-slate-500 mt-1">
                                    <span>50m</span>
                                    <span id="radiusDisplay" class="text-amber-400 font-bold">100 m</span>
                                    <span>2000m</span>
                                </div>
                            </div>
                            <div class="flex items-end">
                                <button type="button" onclick="resetBujpLocation()" class="w-full px-4 py-3 rounded-xl bg-slate-500/20 text-slate-300 text-sm font-bold hover:bg-slate-500/30 transition">
                                    🗑️ Reset Lokasi
                                </button>
                            </div>
                        </div>
                    </div>
                </div>
                
                <div class="flex flex-col sm:flex-row gap-3 mt-6">
                    <button type="button" onclick="hideEditBujpModal()" class="flex-1 bg-slate-500/20 text-slate-300 px-6 py-3 rounded-2xl font-bold hover:bg-slate-500/30 transition">
                        ❌ Batal
                    </button>
                    <button type="submit" class="flex-1 bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-slate-950 px-6 py-3 rounded-2xl font-bold transition">
                        ✅ Simpan Perubahan
                    </button>
                </div>
            </form>
        </div>
    </div>
    

    <!-- Modal BUAT AKUN BUJP -->
    <div id="createAccountModal" class="fixed inset-0 bg-black/80 z-50 hidden flex items-center justify-center p-4">
        <div class="glass rounded-3xl p-6 w-full max-w-md">
            <h2 class="text-2xl font-bold mb-4">🔐 Buat Akun Login BUJP</h2>
            <h3 id="namaBujpTitle" class="text-lg font-bold text-emerald-400 mb-6"></h3>
            
            <form method="post" action="{{ url_for('bujp_create_account') }}" class="space-y-4">
                <input type="hidden" name="bujpId" id="bujpId">
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Username Login BUJP</label>
                    <input name="username" id="suggestedUsername" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Password</label>
                    <input name="password" type="password" required value="ChangeMe123!" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                    <div class="text-xs text-slate-500 mt-1">Password default: ChangeMe123! (silahkan ganti setelah login pertama)</div>
                </div>
                
                <div class="flex gap-3 mt-6">
                    <button type="button" onclick="hideCreateAccountModal()" class="flex-1 bg-slate-500/20 text-slate-300 px-6 py-3 rounded-2xl font-bold">Batal</button>
                    <button type="submit" class="flex-1 bg-emerald-500 text-slate-950 px-6 py-3 rounded-2xl font-bold">✅ Buat Akun</button>
                </div>
            </form>
        </div>
    </div>
    
    <script>
    function showAddBujpModal() {
        document.getElementById('addBujpModal').classList.remove('hidden');
    }
    function hideAddBujpModal() {
        document.getElementById('addBujpModal').classList.add('hidden');
    }
    
    // FUNGSI BUAT AKUN BUJP
    function createBujpAccount(bujpId, namaBujp) {
        document.getElementById('bujpId').value = bujpId;
        document.getElementById('namaBujpTitle').textContent = namaBujp;
        document.getElementById('suggestedUsername').value = 'bujp_' + bujpId;
        document.getElementById('createAccountModal').classList.remove('hidden');
    }
    
    function hideCreateAccountModal() {
        document.getElementById('createAccountModal').classList.add('hidden');
    }
    
    function editBujp(bujpId, namaBujp, noIzin, penanggungJawab, noHp, email, masaBerlaku, alamat) {
        document.getElementById('editBujpId').value = bujpId;
        document.getElementById('edit_nama_bujp').value = namaBujp;
        document.getElementById('edit_no_izin').value = noIzin || '';
        document.getElementById('edit_penanggung_jawab').value = penanggungJawab || '';
        document.getElementById('edit_no_hp').value = noHp || '';
        document.getElementById('edit_email').value = email || '';
        document.getElementById('edit_masa_berlaku_izin').value = masaBerlaku || '';
        document.getElementById('edit_alamat').value = alamat || '';
        document.getElementById('editBujpModal').classList.remove('hidden');
    }
    
    function hideEditBujpModal() {
        document.getElementById('editBujpModal').classList.add('hidden');
    }
    
    // 📍 MAP PICKER JAVASCRIPT
    var pickerMap, pickerMarker, pickerCircle;
    
    function editBujp(bujpId, namaBujp, noIzin, penanggungJawab, noHp, email, masaBerlaku, alamat, latitude, longitude, geofenceRadius) {
        document.getElementById('editBujpId').value = bujpId;
        document.getElementById('edit_nama_bujp').value = namaBujp;
        document.getElementById('edit_no_izin').value = noIzin || '';
        document.getElementById('edit_penanggung_jawab').value = penanggungJawab || '';
        document.getElementById('edit_no_hp').value = noHp || '';
        document.getElementById('edit_email').value = email || '';
        document.getElementById('edit_masa_berlaku_izin').value = masaBerlaku || '';
        document.getElementById('edit_alamat').value = alamat || '';
        document.getElementById('edit_latitude').value = latitude || '';
        document.getElementById('edit_longitude').value = longitude || '';
        document.getElementById('edit_geofence_radius').value = geofenceRadius || 100;
        
        document.getElementById('editBujpModal').classList.remove('hidden');
        
        // Inisialisasi Peta Picker setelah modal tampil
        setTimeout(() => {
            if (pickerMap) {
                pickerMap.remove();
            }
            
            pickerMap = L.map('bujpLocationPicker').setView([-6.2, 106.816666], 13);
            L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
                maxZoom: 19,
                attribution: '&copy; OpenStreetMap'
            }).addTo(pickerMap);
            
            // Jika sudah ada lokasi, tampilkan marker
            if (latitude && longitude) {
                var pos = [parseFloat(latitude), parseFloat(longitude)];
                pickerMarker = L.marker(pos, {draggable: true}).addTo(pickerMap);
                pickerMarker.bindPopup('📍 Lokasi Perusahaan. Drag untuk memindahkan.').openPopup();
                
                var radius = parseInt(geofenceRadius) || 100;
                pickerCircle = L.circle(pos, {
                    radius: radius,
                    color: '#f59e0b',
                    fillColor: '#f59e0b',
                    fillOpacity: 0.15,
                    weight: 2,
                    dashArray: '5, 5'
                }).addTo(pickerMap);
                
                pickerMap.fitBounds(pickerCircle.getBounds().pad(0.2));
                
                // Update ketika marker di drag
                pickerMarker.on('dragend', function(e) {
                    var newPos = pickerMarker.getLatLng();
                    document.getElementById('edit_latitude').value = newPos.lat.toFixed(7);
                    document.getElementById('edit_longitude').value = newPos.lng.toFixed(7);
                    pickerCircle.setLatLng(newPos);
                });
            }
            
            // Klik di peta untuk menentukan lokasi
            pickerMap.on('click', function(e) {
                var clickedPos = e.latlng;
                
                if (pickerMarker) {
                    pickerMarker.setLatLng(clickedPos);
                    pickerCircle.setLatLng(clickedPos);
                } else {
                    pickerMarker = L.marker(clickedPos, {draggable: true}).addTo(pickerMap);
                    pickerMarker.bindPopup('📍 Lokasi Perusahaan. Drag untuk memindahkan.').openPopup();
                    
                    var rad = parseInt(document.getElementById('edit_geofence_radius').value) || 100;
                    pickerCircle = L.circle(clickedPos, {
                        radius: rad,
                        color: '#f59e0b',
                        fillColor: '#f59e0b',
                        fillOpacity: 0.15,
                        weight: 2,
                        dashArray: '5, 5'
                    }).addTo(pickerMap);
                    
                    // Update ketika marker di drag
                    pickerMarker.on('dragend', function() {
                        var newPos = pickerMarker.getLatLng();
                        document.getElementById('edit_latitude').value = newPos.lat.toFixed(7);
                        document.getElementById('edit_longitude').value = newPos.lng.toFixed(7);
                        pickerCircle.setLatLng(newPos);
                    });
                }
                
                document.getElementById('edit_latitude').value = clickedPos.lat.toFixed(7);
                document.getElementById('edit_longitude').value = clickedPos.lng.toFixed(7);
            });
            
            // Update radius ketika diubah
            document.getElementById('edit_geofence_radius').addEventListener('input', function() {
                if (pickerCircle) {
                    pickerCircle.setRadius(parseInt(this.value) || 100);
                }
            });
            
            pickerMap.invalidateSize();
            
        }, 300);
    }
    
    function resetBujpLocation() {
        if (pickerMarker) pickerMap.removeLayer(pickerMarker);
        if (pickerCircle) pickerMap.removeLayer(pickerCircle);
        pickerMarker = null;
        pickerCircle = null;
        document.getElementById('edit_latitude').value = '';
        document.getElementById('edit_longitude').value = '';
    }
    </script>
    """, bujp_list=bujp_list)
    
    return render_page("Manajemen BUJP", body, current_user())


@app.route("/bujp/delete/<int:bujp_id>", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_delete(bujp_id):
    db = get_db()
    ts = now_str()
    
    db.execute("UPDATE bujp SET is_active = 0, updated_at = ? WHERE id = ?", (ts, bujp_id))
    db.commit()
    log_action("BUJP_DELETE", "bujp", bujp_id)
    
    return redirect(url_for("bujp_management"))


@app.route("/bujp/add", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_add():
    db = get_db()
    ts = now_str()
    
    db.execute("""
        INSERT INTO bujp (
            nama_bujp, 
            no_izin, 
            alamat, 
            penanggung_jawab, 
            no_hp, 
            email, 
            masa_berlaku_izin, 
            keterangan, 
            is_active, 
            created_at, 
            updated_at
        )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?)
    """, (
        request.form.get("nama_bujp"),
        request.form.get("no_izin") or '',
        request.form.get("alamat") or '',
        request.form.get("penanggung_jawab") or '',
        request.form.get("no_hp") or '',
        request.form.get("email") or '',
        request.form.get("masa_berlaku_izin") or '',
        request.form.get("keterangan") or '',
        ts, ts
    ))
    db.commit()
    log_action("BUJP_CREATE", "bujp", db.execute("SELECT last_insert_rowid()").fetchone()[0])
    
    return redirect(url_for("bujp_management"))


@app.route("/bujp/edit", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_edit():
    db = get_db()
    ts = now_str()
    bujp_id = int(request.form.get("bujpId"))
    
    db.execute("""
        UPDATE bujp SET
            nama_bujp = ?,
            no_izin = ?,
            alamat = ?,
            penanggung_jawab = ?,
            no_hp = ?,
            email = ?,
            masa_berlaku_izin = ?,
            latitude = ?,
            longitude = ?,
            geofence_radius = ?,
            updated_at = ?
        WHERE id = ?
    """, (
        request.form.get("nama_bujp"),
        request.form.get("no_izin") or '',
        request.form.get("alamat") or '',
        request.form.get("penanggung_jawab") or '',
        request.form.get("no_hp") or '',
        request.form.get("email") or '',
        request.form.get("masa_berlaku_izin") or '',
        request.form.get("latitude") or None,
        request.form.get("longitude") or None,
        request.form.get("geofence_radius") or 100,
        ts,
        bujp_id
    ))
    db.commit()
    log_action("BUJP_EDIT", "bujp", bujp_id)
    
    return redirect(url_for("bujp_management"))


@app.route("/bujp/nonaktif/<int:bujp_id>", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_nonaktif(bujp_id):
    db = get_db()
    ts = now_str()
    
    # SET IS_ACTIVE = 0 (tidak dihapus permanen, cuma nonaktif)
    db.execute("UPDATE bujp SET is_active = 0, updated_at = ? WHERE id = ?", (ts, bujp_id))
    db.commit()
    log_action("BUJP_NONAKTIF", "bujp", bujp_id)
    
    return redirect(url_for("bujp_management"))


@app.route("/bujp/aktifkan/<int:bujp_id>", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_aktifkan(bujp_id):
    db = get_db()
    ts = now_str()
    
    db.execute("UPDATE bujp SET is_active = 1, updated_at = ? WHERE id = ?", (ts, bujp_id))
    db.commit()
    log_action("BUJP_AKTIFKAN", "bujp", bujp_id)
    
    return redirect(url_for("bujp_management"))


@app.route("/bujp/create-account", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_create_account():
    db = get_db()
    ts = now_str()
    
    bujp_id = int(request.form.get("bujpId"))
    username = (request.form.get("username") or "").strip()
    password = request.form.get("password") or "ChangeMe123!"
    
    # Cek apakah BUJP ada dan belum punya akun
    bujp = db.execute("SELECT id, nama_bujp, has_account FROM bujp WHERE id = ?", (bujp_id,)).fetchone()
    if not bujp:
        return "BUJP tidak ditemukan", 404
    if bujp['has_account'] == 1:
        return "BUJP ini sudah punya akun login", 400
    
    # Cek apakah username sudah terpakai
    exist = db.execute("SELECT id FROM users WHERE username = ?", (username,)).fetchone()
    if exist:
        return "Username sudah terpakai, silakan gunakan username lain", 400
    
    # Buat user baru dengan role anggota
    cursor = db.execute(
        "INSERT INTO users (username, full_name, role, password_hash, bujp_id, is_active, created_at, updated_at) VALUES (?, ?, 'anggota', ?, ?, 1, ?, ?)",
        (username, bujp['nama_bujp'], hash_password(password), bujp_id, ts, ts)
    )
    user_id = cursor.lastrowid
    
    # Update tabel bujp
    db.execute("UPDATE bujp SET has_account = 1, user_id = ?, updated_at = ? WHERE id = ?", (user_id, ts, bujp_id))
    db.commit()
    
    log_action("BUJP_CREATE_ACCOUNT", "bujp", bujp_id, f"created_user_id={user_id};username={username}")
    
    return redirect(url_for("bujp_management"))


@app.route("/bujp/<int:bujp_id>")
@login_required
@roles_required("admin", "direktur_binmas")
def bujp_detail(bujp_id):
    db = get_db()
    bujp = db.execute("SELECT * FROM bujp WHERE id = ?", (bujp_id,)).fetchone()
    anggota_bujp = db.execute("SELECT * FROM users WHERE bujp_id = ? ORDER BY full_name ASC", (bujp_id,)).fetchall()
    
    body = render_template_string("""
    <div class="mt-6">
        <a href="{{ url_for('bujp_management') }}" class="text-amber-400 mb-4 inline-block">← Kembali ke Daftar BUJP</a>
        
        <div class="glass rounded-3xl p-6 mb-6">
            <h1 class="text-3xl font-black mb-4">{{ bujp.nama_bujp }}</h1>
            <div class="grid md:grid-cols-3 gap-4">
                <div>
                    <div class="text-slate-400 text-sm">No Izin</div>
                    <div class="font-bold">{{ bujp.no_izin or '-' }}</div>
                </div>
                <div>
                    <div class="text-slate-400 text-sm">Penanggung Jawab</div>
                    <div class="font-bold">{{ bujp.penanggung_jawab or '-' }}</div>
                </div>
                <div>
                    <div class="text-slate-400 text-sm">Total Anggota Satpam</div>
                    <div class="font-bold text-2xl text-amber-400">{{ anggota_bujp|length }}</div>
                </div>
            </div>
        </div>
        
        <!-- 🔍 PENCARIAN DAN TAMBAH SATPAM -->
        <div class="glass rounded-3xl p-6 mb-6">
            <h2 class="text-xl font-bold mb-4">🔍 Cari & Tambah Satpam ke BUJP Ini</h2>
            
            <div class="mb-6">
                <input id="searchSatpam" type="text" placeholder="Cari satpam berdasarkan nama / No KTA / No HP..." 
                    class="w-full rounded-2xl bg-white/5 border border-white/10 px-5 py-4 outline-none focus:ring-2 focus:ring-amber-500 text-lg"
                    oninput="searchSatpam()">
            </div>
            
            <div id="searchResults" class="space-y-3">
                <div class="text-center py-8 text-slate-400">
                    <div class="text-4xl mb-3">🔍</div>
                    <div>Ketik nama atau nomor KTA satpam untuk mulai pencarian</div>
                </div>
            </div>
        </div>
        
        <!-- ✅ DAFTAR SATPAM TERDAFTAR DI BUJP INI -->
        <div class="glass rounded-3xl p-6">
            <h2 class="text-xl font-bold mb-4">✅ Daftar Satpam BUJP Ini</h2>
            
            <div id="anggotaList" class="space-y-3">
            {% for anggota in anggota_bujp %}
                <div class="grid grid-cols-12 gap-4 p-4 rounded-2xl bg-white/5 border border-white/10 items-center">
                    <div class="col-span-1 text-3xl">👮</div>
                    <div class="col-span-4">
                        <div class="font-bold">{{ anggota.full_name }}</div>
                        <div class="text-xs text-slate-400">@{{ anggota.username }}</div>
                    </div>
                    <div class="col-span-3">
                        <div class="text-cyan-300">{{ anggota.no_kta or '-' }}</div>
                        <div class="text-xs text-slate-400">{{ anggota.jabatan or 'Satpam' }}</div>
                    </div>
                    <div class="col-span-1 text-center">
                        {% if anggota.bujp_verified == 1 %}
                        <span class="text-2xl text-emerald-400" title="Sudah diverifikasi oleh BUJP">✅</span>
                        {% else %}
                        <span class="text-2xl text-slate-500" title="Belum diverifikasi oleh BUJP">⏳</span>
                        {% endif %}
                    </div>
                    <div class="col-span-2">
                        {% if anggota.is_active %}
                        <span class="text-emerald-400">✅ Aktif</span>
                        {% else %}
                        <span class="text-slate-400">⚪ Nonaktif</span>
                        {% endif %}
                    </div>
                    <div class="col-span-1">
                        <button onclick="removeSatpamFromBujp({{ anggota.id }})" class="w-full px-3 py-2 rounded-xl bg-red-500/20 text-red-400 text-sm font-bold">
                            ❌
                        </button>
                    </div>
                </div>
            {% else %}
                <div class="text-center py-8 text-slate-400">
                    <div class="text-4xl mb-3">📋</div>
                    <div>Belum ada satpam yang terdaftar di BUJP ini</div>
                </div>
            {% endfor %}
            </div>
        </div>
    </div>
    
    <script>
    const BUJP_ID = {{ bujp.id }};
    
    async function searchSatpam() {
        const query = document.getElementById('searchSatpam').value.trim();
        const resultsDiv = document.getElementById('searchResults');
        
        if (query.length < 2) {
            resultsDiv.innerHTML = `
                <div class="text-center py-8 text-slate-400">
                    <div class="text-4xl mb-3">🔍</div>
                    <div>Ketik minimal 2 karakter untuk mulai pencarian</div>
                </div>
            `;
            return;
        }
        
        resultsDiv.innerHTML = `
            <div class="text-center py-8 text-slate-400">
                <div class="text-2xl mb-3 animate-pulse">🔄</div>
                <div>Mencari satpam...</div>
            </div>
        `;
        
        try {
            const res = await fetch(`/api/search/satpam?q=${encodeURIComponent(query)}&bujp_id=${BUJP_ID}`);
            const satpamList = await res.json();
            
            if (satpamList.length === 0) {
                resultsDiv.innerHTML = `
                    <div class="text-center py-8 text-slate-400">
                        <div class="text-4xl mb-3">❌</div>
                        <div>Tidak ditemukan satpam dengan kata kunci "${query}"</div>
                    </div>
                `;
                return;
            }
            
            resultsDiv.innerHTML = satpamList.map(satpam => `
                <div class="grid grid-cols-12 gap-4 p-4 rounded-2xl ${satpam.bujp_id && satpam.bujp_id != BUJP_ID ? 'bg-slate-500/10 border border-slate-500/20 opacity-60' : 'bg-white/5 border border-white/10'} items-center">
                    <div class="col-span-1 text-3xl">👮</div>
                    <div class="col-span-4">
                        <div class="font-bold">${satpam.full_name}</div>
                        <div class="text-xs text-slate-400">@${satpam.username}</div>
                    </div>
                    <div class="col-span-3">
                        <div class="text-cyan-300">${satpam.no_kta || '-'}</div>
                        <div class="text-xs text-slate-400">${satpam.no_hp || '-'}</div>
                    </div>
                    <div class="col-span-2">
                        ${satpam.bujp_id == BUJP_ID ? 
                            '<span class="text-emerald-400">✅ Sudah ada disini</span>' : 
                            satpam.bujp_id ? 
                                '<span class="text-amber-400">⚠️ Sudah di BUJP lain</span>' : 
                                '<span class="text-slate-300">✅ Tersedia</span>'
                        }
                    </div>
                    <div class="col-span-2">
                        ${satpam.bujp_id == BUJP_ID ? 
                            '' : 
                            satpam.bujp_id ? 
                                '<button disabled class="w-full px-3 py-2 rounded-xl bg-slate-500/20 text-slate-400 text-sm font-bold">Sudah ada di BUJP lain</button>' : 
                                `<button onclick="assignSatpamToBujp(${satpam.id})" class="w-full px-3 py-2 rounded-xl bg-emerald-500/20 text-emerald-400 text-sm font-bold">✅ Tambahkan</button>`
                        }
                    </div>
                </div>
            `).join('');
            
        } catch (err) {
            resultsDiv.innerHTML = `
                <div class="text-center py-8 text-red-400">
                    <div class="text-4xl mb-3">❌</div>
                    <div>Gagal mencari satpam: ${err.message}</div>
                </div>
            `;
        }
    }
    
    async function assignSatpamToBujp(satpamId) {
        try {
            const res = await fetch(`/api/bujp/${BUJP_ID}/assign-satpam/${satpamId}`, { method: 'POST' });
            const result = await res.json();
            
            if (result.ok) {
                searchSatpam();
                window.location.reload();
            } else {
                alert(result.error || 'Gagal menambahkan satpam');
            }
        } catch (err) {
            alert('Gagal terhubung ke server');
        }
    }
    
    async function removeSatpamFromBujp(satpamId) {
        if (!confirm('Yakin ingin mengeluarkan satpam ini dari BUJP?')) return;
        
        try {
            const res = await fetch(`/api/bujp/${BUJP_ID}/remove-satpam/${satpamId}`, { method: 'POST' });
            const result = await res.json();
            
            if (result.ok) {
                window.location.reload();
            } else {
                alert(result.error || 'Gagal mengeluarkan satpam');
            }
        } catch (err) {
            alert('Gagal terhubung ke server');
        }
    }
    </script>
    """, bujp=bujp, anggota_bujp=anggota_bujp)
    
    return render_page("Detail BUJP", body, current_user())


@app.route("/api/search/satpam")
@login_required
@roles_required("admin", "direktur_binmas")
def api_search_satpam():
    query = (request.args.get("q") or "").strip()
    bujp_id = request.args.get("bujp_id", type=int)
    
    if len(query) < 2:
        return jsonify([])
    
    db = get_db()
    
    # Cari satpam berdasarkan nama, username, no_kta, no_hp
    satpam_list = db.execute("""
        SELECT id, username, full_name, no_kta, no_hp, role, bujp_id, is_active
        FROM users 
        WHERE role = 'satpam'
        AND is_active = 1
        AND (
            full_name LIKE ? 
            OR username LIKE ? 
            OR no_kta LIKE ? 
            OR no_hp LIKE ?
        )
        ORDER BY full_name ASC
        LIMIT 50
    """, (
        f"%{query}%",
        f"%{query}%",
        f"%{query}%",
        f"%{query}%"
    )).fetchall()
    
    return jsonify([dict(row) for row in satpam_list])


@app.route("/api/bujp/<int:bujp_id>/assign-satpam/<int:satpam_id>", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def api_assign_satpam(bujp_id, satpam_id):
    db = get_db()
    ts = now_str()
    
    # Cek apakah satpam ada dan memang role satpam
    satpam = db.execute("SELECT id, role, bujp_id FROM users WHERE id = ? AND role = 'satpam'", (satpam_id,)).fetchone()
    if not satpam:
        return jsonify({"ok": False, "error": "Satpam tidak ditemukan"}), 404
    
    # Cek apakah satpam sudah terdaftar di BUJP lain
    if satpam['bujp_id'] and satpam['bujp_id'] != bujp_id:
        return jsonify({"ok": False, "error": "Satpam ini sudah terdaftar di BUJP lain"}), 400
    
    # Update satpam masuk ke BUJP ini
    db.execute("""
        UPDATE users SET bujp_id = ?, updated_at = ? WHERE id = ?
    """, (bujp_id, ts, satpam_id))
    
    db.commit()
    log_action("BUJP_ASSIGN_SATPAM", "bujp", bujp_id, f"satpam_id={satpam_id}")
    
    return jsonify({"ok": True})


@app.route("/api/bujp/<int:bujp_id>/remove-satpam/<int:satpam_id>", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def api_remove_satpam(bujp_id, satpam_id):
    db = get_db()
    ts = now_str()
    
    # Set bujp_id menjadi NULL (keluarkan dari BUJP)
    db.execute("""
        UPDATE users SET bujp_id = NULL, updated_at = ? WHERE id = ?
    """, (ts, satpam_id))
    
    db.commit()
    log_action("BUJP_REMOVE_SATPAM", "bujp", bujp_id, f"satpam_id={satpam_id}")
    
    return jsonify({"ok": True})


@app.route("/api/bujp/verify/<int:user_id>", methods=["POST"])
@login_required
@roles_required("anggota")
def api_bujp_verify_anggota(user_id):
    user = current_user()
    db = get_db()
    ts = now_str()

    target = db.execute("""
        SELECT id, full_name, role, bujp_id, COALESCE(bujp_verified, 0) AS bujp_verified
        FROM users
        WHERE id = ? AND role IN ('anggota', 'satpam')
    """, (user_id,)).fetchone()

    if not target:
        return jsonify({"ok": False, "error": "Anggota tidak ditemukan"}), 404

    if not user["bujp_id"]:
        return jsonify({"ok": False, "error": "Akun BUJP Anda belum terhubung ke data BUJP"}), 400

    if target["bujp_id"] != user["bujp_id"]:
        return jsonify({"ok": False, "error": "Anda hanya dapat memverifikasi anggota di BUJP Anda sendiri"}), 403

    if target["bujp_verified"] == 1:
        return jsonify({"ok": True, "message": "Anggota sudah diverifikasi"})

    db.execute("""
        UPDATE users
        SET bujp_verified = 1,
            bujp_verified_at = ?,
            bujp_verified_by = ?,
            updated_at = ?
        WHERE id = ?
    """, (ts, user["id"], ts, user_id))
    db.commit()
    log_action("BUJP_VERIFY_ANGGOTA", "user", user_id, f"verified_by={user['id']};bujp_id={user['bujp_id']}")

    return jsonify({"ok": True, "message": f"{target['full_name']} berhasil diverifikasi"})


@app.route("/api/bujp/unverify/<int:user_id>", methods=["POST"])
@login_required
@roles_required("anggota")
def api_bujp_unverify_anggota(user_id):
    user = current_user()
    db = get_db()
    ts = now_str()

    target = db.execute("""
        SELECT id, full_name, role, bujp_id, COALESCE(bujp_verified, 0) AS bujp_verified
        FROM users
        WHERE id = ? AND role IN ('anggota', 'satpam')
    """, (user_id,)).fetchone()

    if not target:
        return jsonify({"ok": False, "error": "Anggota tidak ditemukan"}), 404

    if not user["bujp_id"]:
        return jsonify({"ok": False, "error": "Akun BUJP Anda belum terhubung ke data BUJP"}), 400

    if target["bujp_id"] != user["bujp_id"]:
        return jsonify({"ok": False, "error": "Anda hanya dapat membatalkan verifikasi anggota di BUJP Anda sendiri"}), 403

    if target["bujp_verified"] == 0:
        return jsonify({"ok": True, "message": "Anggota sudah berstatus belum diverifikasi"})

    db.execute("""
        UPDATE users
        SET bujp_verified = 0,
            bujp_verified_at = NULL,
            bujp_verified_by = NULL,
            updated_at = ?
        WHERE id = ?
    """, (ts, user_id))
    db.commit()
    log_action("BUJP_UNVERIFY_ANGGOTA", "user", user_id, f"unverified_by={user['id']};bujp_id={user['bujp_id']}")

    return jsonify({"ok": True, "message": f"Verifikasi {target['full_name']} berhasil dibatalkan"})


@app.route("/satpam/absen")
@login_required
@roles_required("satpam")
def satpam_absen():
    user = current_user()
    today = datetime.now().strftime("%Y-%m-%d")
    
    # Cek status absen hari ini - MODE BARU MULTI ABSEN
    db = get_db()
    absen_hari_ini = db.execute("""
        SELECT * FROM absensi 
        WHERE user_id = ? AND DATE(tanggal) = ? 
        ORDER BY id DESC LIMIT 1
    """, (user['id'], today)).fetchone()
    
    tipe_terakhir = None
    waktu_terakhir = None
    total_absen_hari_ini = db.execute("SELECT COUNT(*) FROM absensi WHERE user_id = ? AND DATE(tanggal) = ?", (user['id'], today)).fetchone()[0]
    
    if absen_hari_ini:
        tipe_terakhir = absen_hari_ini['tipe']
        waktu_terakhir = absen_hari_ini['waktu']
    
    # Bisa absen MASUK kapanpun, kecuali jika terakhir adalah MASUK maka bisa absen KELUAR
    bisa_absen_masuk = (tipe_terakhir is None) or (tipe_terakhir == 'KELUAR')
    bisa_absen_keluar = (tipe_terakhir == 'MASUK')
    
    # Riwayat absensi MAX 25 records
    riwayat_absen = db.execute("""
        SELECT tanggal, waktu, tipe, status, lokasi, lat, lng
        FROM absensi 
        WHERE user_id = ? 
        ORDER BY id DESC LIMIT 25
    """, (user['id'],)).fetchall()
    
    body = render_template_string("""
    <div class="max-w-2xl mx-auto mt-6 space-y-6">
      
      <!-- Status Absen Hari Ini -->
      <div class="glass rounded-3xl p-6">
        <h1 class="text-2xl font-black mb-4 text-center">📅 Absen Harian Satpam</h1>
        
        <!-- Status Absen Hari Ini MODE BARU MULTI ABSEN -->
        <div class="mb-6">
          <div class="text-center text-slate-400 text-sm mb-4">
            Total absensi hari ini: <span class="font-bold text-white text-xl">{{ total_absen_hari_ini }}</span> kali
          </div>
          
          <div class="grid grid-cols-2 gap-4 mb-6">
            <div class="rounded-2xl p-4 text-center {% if tipe_terakhir == 'MASUK' %}bg-emerald-500/20 border border-emerald-500/30{% else %}bg-white/5 border border-white/10{% endif %}">
              <div class="text-3xl mb-2">✅</div>
              <div class="font-bold">MASUK</div>
              <div class="text-xs {% if tipe_terakhir == 'MASUK' %}text-emerald-300{% else %}text-slate-400{% endif %}">
                {% if tipe_terakhir == 'MASUK' %}{{ waktu_terakhir }}{% else %}{% if tipe_terakhir == 'KELUAR' %}Siap absen MASUK{% else %}Belum absen{% endif %}{% endif %}
              </div>
            </div>
            <div class="rounded-2xl p-4 text-center {% if tipe_terakhir == 'KELUAR' %}bg-orange-500/20 border border-orange-500/30{% else %}bg-white/5 border border-white/10{% endif %}">
              <div class="text-3xl mb-2">🏠</div>
              <div class="font-bold">KELUAR / PULANG</div>
              <div class="text-xs {% if tipe_terakhir == 'KELUAR' %}text-orange-300{% else %}text-slate-400{% endif %}">
                {% if tipe_terakhir == 'KELUAR' %}{{ waktu_terakhir }}{% else %}{% if tipe_terakhir == 'MASUK' %}Siap absen KELUAR{% else %}Belum absen{% endif %}{% endif %}
              </div>
            </div>
          </div>
          
          <div class="grid grid-cols-2 gap-4">
            <button id="btnAbsenMasuk" onclick="kirimAbsen('MASUK')" class="rounded-2xl bg-gradient-to-r from-green-500 to-emerald-600 hover:from-green-400 hover:to-emerald-500 text-white font-black px-4 py-5 transition text-lg">
              ✅<br>ABSEN DATANG
            </button>
            <button id="btnAbsenPulang" onclick="kirimAbsen('KELUAR')" class="rounded-2xl bg-gradient-to-r from-orange-500 to-red-600 hover:from-orange-400 hover:to-red-500 text-white font-black px-4 py-5 transition text-lg">
              🏠<br>ABSEN PULANG
            </button>
          </div>
        
        <div id="statusMessage" class="mt-4 p-3 rounded-2xl hidden text-center text-sm"></div>
      </div>
      
      <!-- Riwayat Absensi -->
      <div class="glass rounded-3xl p-6">
        <h2 class="text-xl font-black mb-4">📋 Riwayat Absensi 7 Hari Terakhir</h2>
        <div class="space-y-3">
          {% for absen in riwayat_absen %}
          <div class="grid grid-cols-12 gap-3 p-4 rounded-2xl bg-white/5 border border-white/10 items-center">
            <div class="col-span-3">
              <div class="font-bold">{{ absen.tanggal }}</div>
              <div class="text-xs text-slate-400">{{ absen.waktu }}</div>
            </div>
            <div class="col-span-2 text-center">
              <div class="font-bold {% if absen.tipe == 'MASUK' %}text-emerald-300{% else %}text-orange-300{% endif %}">{{ absen.tipe }}</div>
              <div class="text-xs text-slate-400">{{ absen.status }}</div>
            </div>
            <div class="col-span-7">
              <div class="text-xs text-cyan-300">📍 {{ absen.lokasi }}</div>
              <div class="text-xs text-slate-500">🧭 {{ '%0.6f, %0.6f' % (absen.lat | default(0), absen.lng | default(0)) }}</div>
            </div>
          </div>
          {% else %}
          <div class="text-center text-slate-400 py-6">Belum ada riwayat absensi</div>
          {% endfor %}
        </div>
      </div>
      
    </div>
    
    <script>
    function getCurrentLocation() {
      return new Promise((resolve, reject) => {
        if (!navigator.geolocation) {
          reject(new Error("Geolocation tidak didukung browser"));
          return;
        }
        navigator.geolocation.getCurrentPosition(resolve, reject, {
          enableHighAccuracy: true,
          timeout: 10000,
          maximumAge: 0
        });
      });
    }
    
    async function kirimAbsen(tipe) {
      const statusEl = document.getElementById('statusMessage');
      statusEl.className = 'mt-4 p-3 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-200 text-center text-sm';
      statusEl.textContent = '📡 Mendapatkan lokasi GPS...';
      statusEl.classList.remove('hidden');
      
      try {
        const position = await getCurrentLocation();
        const data = {
          tipe: tipe,
          lat: position.coords.latitude,
          lng: position.coords.longitude,
          accuracy: position.coords.accuracy,
          altitude: position.coords.altitude
        };
        
        const res = await fetch('/api/absen', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(data)
        });
        
        const result = await res.json();
        
        if (result.ok) {
          statusEl.className = 'mt-4 p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-center text-sm';
          statusEl.textContent = '✅ Absen berhasil disimpan! Refresh halaman...';
          setTimeout(() => window.location.reload(), 1500);
        } else {
          statusEl.className = 'mt-4 p-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-center text-sm';
          statusEl.textContent = '❌ ' + (result.error || 'Gagal absen');
        }
        
      } catch (err) {
        statusEl.className = 'mt-4 p-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-center text-sm';
        statusEl.textContent = '❌ Gagal mendapatkan lokasi GPS: ' + err.message;
      }
    }
    
    document.addEventListener('DOMContentLoaded', () => {
      const btnMasuk = document.getElementById('btnAbsenMasuk');
      const btnPulang = document.getElementById('btnAbsenPulang');
      
      if (btnMasuk) {
        btnMasuk.addEventListener('click', () => kirimAbsen('masuk'));
      }
      
      if (btnPulang) {
        // ✅ [FIX] Kirim 'keluar' bukan 'pulang' — konsisten dengan API
        btnPulang.addEventListener('click', () => kirimAbsen('keluar'));
      }
      

    });
    </script>
    """, 
    bisa_absen_masuk=bisa_absen_masuk,
    bisa_absen_keluar=bisa_absen_keluar,
    tipe_terakhir=tipe_terakhir,
    waktu_terakhir=waktu_terakhir,
    total_absen_hari_ini=total_absen_hari_ini,
    riwayat_absen=riwayat_absen
    )
    return render_page("Absen Harian", body, user)


@app.route("/api/absen", methods=["POST"])
@login_required
@roles_required("satpam", "anggota", "admin_bujp")
def api_absen():
    user = current_user()
    data = request.get_json(silent=True) or {}

    try:
        lat = float(data.get("lat"))
        lng = float(data.get("lng"))
        accuracy = float(data.get("accuracy")) if data.get("accuracy") else None
        tipe = data.get("tipe")

        # ✅ [FIX] Konsisten: terima 'masuk'/'keluar'
        if tipe not in ('masuk', 'keluar'):
            return jsonify({"ok": False, "error": "Tipe absen tidak valid. Gunakan 'masuk' atau 'keluar'"}), 400

        if not (-90 <= lat <= 90 and -180 <= lng <= 180):
            return jsonify({"ok": False, "error": "Koordinat tidak valid"}), 400

        db = get_db()
        now_wib_dt = now_wib()
        today      = now_wib_dt.strftime("%Y-%m-%d")
        waktu_str  = now_wib_dt.strftime("%H:%M:%S")
        jam_menit  = now_wib_dt.hour * 60 + now_wib_dt.minute

        # ✅ [NEW] Cek mode absensi — jika mode='sesi', harus ada sesi aktif
        config = get_absensi_config(db)
        sesi_aktif = None
        sesi_id = None

        if config["absensi_mode"] == "sesi":
            sesi_aktif = get_sesi_aktif(bujp_id=user["bujp_id"], db=db)
            if not sesi_aktif:
                return jsonify({
                    "ok": False,
                    "error": "❌ Absensi ditutup. Belum ada sesi absensi yang aktif hari ini. Hubungi Admin."
                }), 403
            sesi_id = sesi_aktif["id"]

            # ✅ [NEW] Validasi jam absen sesuai sesi
            if tipe == "masuk":
                buka = sesi_aktif["jam_buka_masuk"]   # "07:00"
                tutup = sesi_aktif["jam_tutup_masuk"]  # "09:00"
            else:
                buka = sesi_aktif["jam_buka_keluar"] or "16:00"
                tutup = sesi_aktif["jam_tutup_keluar"] or "23:59"

            buka_menit  = int(buka.split(":")[0]) * 60 + int(buka.split(":")[1])
            tutup_menit = int(tutup.split(":")[0]) * 60 + int(tutup.split(":")[1])

            if not (buka_menit <= jam_menit <= tutup_menit):
                tipe_label = 'masuk' if tipe == 'masuk' else 'keluar'
                return jsonify({
                    "ok": False,
                    "error": f"❌ Di luar jam absensi {tipe_label}. Jam absensi {tipe_label}: {buka} – {tutup}"
                }), 403

            # ✅ [NEW] Status keterlambatan berdasarkan batas_terlambat sesi
            if tipe == "masuk":
                batas = sesi_aktif["batas_terlambat"] or "08:00"
                batas_menit = int(batas.split(":")[0]) * 60 + int(batas.split(":")[1])
                if jam_menit > batas_menit:
                    status = "Terlambat"
                elif jam_menit <= buka_menit + 30:
                    status = "Tepat Waktu"
                else:
                    status = "Normal"
            else:
                status = "Normal"
        else:
            # Mode bebas — status berdasarkan jam standar
            tipe_db_temp = tipe
            if tipe == 'masuk':
                status = "Tepat Waktu" if jam_menit <= (7 * 60 + 30) else \
                         "Terlambat" if jam_menit > (8 * 60) else "Normal"
            else:
                status = "Normal"

        tipe_db = 'MASUK' if tipe == 'masuk' else 'KELUAR'

        db.execute("""
            INSERT INTO absensi
            (user_id, tanggal, waktu, tipe, lat, lng, akurasi, status, lokasi, sesi_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            user['id'], today, waktu_str, tipe_db,
            lat, lng, accuracy, status,
            json.dumps(geofence_hits(lat, lng)),
            sesi_id, now_str()
        ))
        db.commit()

        persist_location(user['id'], lat, lng, accuracy, None, None, source="absensi")
        broadcast_presence()
        log_action(f"ABSEN_{tipe.upper()}", "absensi", sesi_id,
                   f"lat={lat:.6f};lng={lng:.6f};status={status}")

        return jsonify({"ok": True, "status": status, "waktu": waktu_str,
                        "sesi": sesi_aktif['nama_sesi'] if sesi_aktif else None})

    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400




# ==============================
# ✅ [NEW] SISTEM ABSENSI ADMIN-CONTROLLED
# ==============================

def get_absensi_config(db=None):
    """Ambil semua config absensi sebagai dict."""
    if db is None:
        db = get_db()
    rows = db.execute("SELECT config_key, config_value FROM absensi_config").fetchall()
    return {row["config_key"]: row["config_value"] for row in rows}


def get_sesi_aktif(bujp_id=None, db=None):
    """Ambil sesi absensi yang sedang aktif (TANPA BATAS WAKTU TANGGAL)"""
    if db is None:
        db = get_db()
    if bujp_id:
        return db.execute("""
            SELECT * FROM absensi_sesi
            WHERE status = 'aktif'
            AND (bujp_id IS NULL OR bujp_id = ?)
            ORDER BY id DESC LIMIT 1
        """, (bujp_id,)).fetchone()
    else:
        return db.execute("""
            SELECT * FROM absensi_sesi
            WHERE status = 'aktif'
            ORDER BY id DESC LIMIT 1
        """).fetchone()


@app.route("/admin/absensi/sesi")
@login_required
@roles_required("admin")
def admin_absensi_sesi():
    user = current_user()
    db = get_db()

    # Ambil semua sesi 30 hari terakhir
    sesi_list = db.execute("""
        SELECT s.*, u.full_name AS dibuat_oleh_nama,
               b.nama_bujp,
               (SELECT COUNT(*) FROM absensi a WHERE a.sesi_id = s.id AND a.tipe='MASUK') AS total_masuk,
               (SELECT COUNT(*) FROM absensi a WHERE a.sesi_id = s.id AND a.tipe='KELUAR') AS total_keluar
        FROM absensi_sesi s
        LEFT JOIN users u ON u.id = s.dibuat_oleh
        LEFT JOIN bujp b ON b.id = s.bujp_id
        ORDER BY s.id DESC
        LIMIT 60
    """).fetchall()

    bujp_list = db.execute("SELECT id, nama_bujp FROM bujp WHERE is_active=1 ORDER BY nama_bujp").fetchall()
    config = get_absensi_config(db)

    body = render_template_string("""
    <div class="mt-6 space-y-6">

      <!-- Header -->
      <div class="flex flex-col md:flex-row justify-between items-start md:items-center gap-4">
        <div>
          <h1 class="text-3xl font-black mb-1">📅 KELOLA SESI ABSENSI</h1>
          <p class="text-slate-400">Buat dan kontrol sesi absensi satpam. Satpam hanya bisa absen ketika sesi aktif.</p>
        </div>
        <button onclick="document.getElementById('modalBuatSesi').classList.remove('hidden')"
          class="px-6 py-3 rounded-2xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black transition">
          ➕ BUAT SESI BARU
        </button>
      </div>

      <!-- Config Card -->
      <div class="glass rounded-3xl p-5">
        <h2 class="text-lg font-bold mb-4">⚙️ Konfigurasi Absensi Global</h2>
        <form method="post" action="/admin/absensi/config" class="grid md:grid-cols-3 gap-4">
          <div>
            <label class="text-xs text-slate-400 block mb-1">Mode Absensi</label>
            <select name="absensi_mode" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
              <option value="bebas" {% if config.get('absensi_mode')=='bebas' %}selected{% endif %}>Bebas (satpam absen kapan saja)</option>
              <option value="sesi" {% if config.get('absensi_mode')=='sesi' %}selected{% endif %}>Sesi (hanya saat ada sesi aktif)</option>
            </select>
          </div>
          <div>
            <label class="text-xs text-slate-400 block mb-1">Radius Absen Default (meter)</label>
            <input type="number" name="radius_absen_default" value="{{ config.get('radius_absen_default','200') }}"
              class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
          </div>
          <div class="flex items-end">
            <button class="w-full rounded-2xl bg-emerald-500 text-slate-950 font-bold px-4 py-3">
              💾 Simpan Config
            </button>
          </div>
        </form>
        <div class="mt-3 text-xs text-slate-500">
          Mode saat ini: <span class="font-bold text-cyan-300">{{ config.get('absensi_mode','bebas').upper() }}</span>
          {% if config.get('absensi_mode') == 'sesi' %}
          — Satpam HANYA bisa absen ketika ada sesi yang aktif hari ini.
          {% else %}
          — Satpam bisa absen kapan saja tanpa perlu sesi.
          {% endif %}
        </div>
      </div>

      <!-- Tabel Sesi -->
      <div class="glass rounded-3xl overflow-hidden">
        <div class="px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <h2 class="text-xl font-bold">📋 Daftar Sesi Absensi</h2>
          <span class="text-slate-400 text-sm">{{ sesi_list|length }} sesi ditampilkan</span>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="bg-white/5 border-b border-white/10 text-sm text-slate-300">
                <th class="text-left px-5 py-3">Nama Sesi</th>
                <th class="text-left px-5 py-3">Tanggal</th>
                <th class="text-left px-5 py-3">Jam Masuk</th>
                <th class="text-left px-5 py-3">Jam Keluar</th>
                <th class="text-left px-5 py-3">BUJP</th>
                <th class="text-left px-5 py-3">Status</th>
                <th class="text-left px-5 py-3">Hadir</th>
                <th class="text-left px-5 py-3">Aksi</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
            {% for s in sesi_list %}
              <tr class="hover:bg-white/5 transition">
                <td class="px-5 py-3 font-bold">{{ s.nama_sesi }}</td>
                <td class="px-5 py-3 text-sm">
                  {% if s.status == 'aktif' %}
                    <span class="text-emerald-300 font-bold">✅ TERUS BERJALAN</span>
                    <div class="text-[10px] text-slate-400">Mulai: {{ s.tanggal }}</div>
                  {% else %}
                    {{ s.tanggal }}
                  {% endif %}
                </td>
                <td class="px-5 py-3 text-sm text-emerald-300">{{ s.jam_buka_masuk }}–{{ s.jam_tutup_masuk }}</td>
                <td class="px-5 py-3 text-sm text-orange-300">{{ s.jam_buka_keluar or '-' }}–{{ s.jam_tutup_keluar or '-' }}</td>
                <td class="px-5 py-3 text-sm text-amber-300">{{ s.nama_bujp or 'Semua BUJP' }}</td>
                <td class="px-5 py-3">
                  {% if s.status == 'aktif' %}
                  <span class="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold animate-pulse">🟢 AKTIF</span>
                  {% elif s.status == 'draft' %}
                  <span class="px-3 py-1 rounded-full bg-amber-500/20 text-amber-400 text-xs font-bold">📝 Draft</span>
                  {% elif s.status == 'selesai' %}
                  <span class="px-3 py-1 rounded-full bg-slate-500/20 text-slate-300 text-xs font-bold">✅ Selesai</span>
                  {% else %}
                  <span class="px-3 py-1 rounded-full bg-red-500/20 text-red-400 text-xs font-bold">🔴 Ditutup</span>
                  {% endif %}
                </td>
                <td class="px-5 py-3 text-sm">
                  <span class="text-emerald-400">↑{{ s.total_masuk }}</span> /
                  <span class="text-orange-400">↓{{ s.total_keluar }}</span>
                </td>
                <td class="px-5 py-3">
                  <div class="flex gap-2">
                    <!-- ✅ EDIT STATUS SESI LANGSUNG DARI DAFTAR -->
                    <form method="post" action="/admin/absensi/sesi/{{ s.id }}/update-status" class="flex gap-1">
                      <select name="status" onchange="this.form.submit()"
                        class="px-2 py-1 rounded-xl bg-white/5 border border-white/10 text-xs font-bold outline-none">
                        <option value="draft" {% if s.status == 'draft' %}selected{% endif %}>📝 Draft</option>
                        <option value="aktif" {% if s.status == 'aktif' %}selected{% endif %}>🟢 Aktif</option>
                        <option value="selesai" {% if s.status == 'selesai' %}selected{% endif %}>✅ Selesai</option>
                        <option value="ditutup" {% if s.status == 'ditutup' %}selected{% endif %}>🔴 Ditutup</option>
                      </select>
                    </form>
                    
                    <a href="/admin/absensi/sesi/{{ s.id }}/detail"
                      class="px-3 py-1 rounded-xl bg-cyan-500/20 text-cyan-400 text-xs font-bold">👁 Detail</a>
                  </div>
                </td>
              </tr>
            {% else %}
              <tr>
                <td colspan="8" class="py-12 text-center text-slate-400">
                  <div class="text-4xl mb-3">📅</div>
                  <div>Belum ada sesi absensi. Klik "Buat Sesi Baru" untuk memulai.</div>
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- MODAL BUAT SESI -->
    <div id="modalBuatSesi" class="fixed inset-0 bg-black/80 z-50 hidden flex items-center justify-center p-4">
      <div class="glass rounded-3xl p-6 w-full max-w-xl max-h-[95vh] overflow-y-auto">
        <div class="flex justify-between items-center mb-5">
          <h2 class="text-2xl font-black">➕ Buat Sesi Absensi Baru</h2>
          <button onclick="document.getElementById('modalBuatSesi').classList.add('hidden')"
            class="w-10 h-10 rounded-2xl bg-white/5 hover:bg-white/10 flex items-center justify-center">✕</button>
        </div>
        <form method="post" action="/admin/absensi/sesi/buat" class="space-y-4">
          <div>
            <label class="text-sm text-slate-400 block mb-1">Nama Sesi</label>
            <input name="nama_sesi" required placeholder="cth: Shift Pagi Senin 14 April"
              class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-sm text-slate-400 block mb-1">Tanggal Sesi</label>
              <input name="tanggal" type="date" required
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-cyan-500">
            </div>
            <div>
              <label class="text-sm text-slate-400 block mb-1">BUJP (kosong = semua)</label>
              <select name="bujp_id"
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                <option value="">Semua BUJP</option>
                {% for b in bujp_list %}
                <option value="{{ b.id }}">{{ b.nama_bujp }}</option>
                {% endfor %}
              </select>
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-sm text-slate-400 block mb-1">⬆️ Jam Buka Absen Masuk</label>
              <input name="jam_buka_masuk" type="time" value="07:00" required
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
            </div>
            <div>
              <label class="text-sm text-slate-400 block mb-1">⬆️ Jam Tutup Absen Masuk</label>
              <input name="jam_tutup_masuk" type="time" value="09:00" required
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-sm text-slate-400 block mb-1">⬇️ Jam Buka Absen Keluar</label>
              <input name="jam_buka_keluar" type="time" value="16:00"
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
            </div>
            <div>
              <label class="text-sm text-slate-400 block mb-1">⬇️ Jam Tutup Absen Keluar</label>
              <input name="jam_tutup_keluar" type="time" value="23:59"
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
            </div>
          </div>
          <div class="grid grid-cols-2 gap-3">
            <div>
              <label class="text-sm text-slate-400 block mb-1">⏰ Batas Terlambat</label>
              <input name="batas_terlambat" type="time" value="08:00"
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
            </div>
            <div>
              <label class="text-sm text-slate-400 block mb-1">📍 Radius Geofence (meter)</label>
              <input name="radius_meter" type="number" value="200" min="50" max="5000"
                class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
            </div>
          </div>
          <div>
            <label class="text-sm text-slate-400 block mb-1">Keterangan (opsional)</label>
            <textarea name="keterangan" rows="2"
              class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none"></textarea>
          </div>
          <div class="flex items-center gap-3">
            <input type="checkbox" name="langsung_aktif" id="cb_aktif" value="1" class="w-5 h-5 rounded">
            <label for="cb_aktif" class="text-sm text-slate-300">Langsung aktifkan sesi setelah dibuat</label>
          </div>
          <div class="flex gap-3 pt-2">
            <button type="button" onclick="document.getElementById('modalBuatSesi').classList.add('hidden')"
              class="flex-1 rounded-2xl bg-white/5 border border-white/10 px-5 py-3 font-bold">Batal</button>
            <button type="submit"
              class="flex-1 rounded-2xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black px-5 py-3">
              ✅ Buat Sesi
            </button>
          </div>
        </form>
      </div>
    </div>
    """, sesi_list=sesi_list, bujp_list=bujp_list, config=config)
    return render_page("Kelola Sesi Absensi", body, user)


@app.route("/admin/absensi/config", methods=["POST"])
@login_required
@roles_required("admin")
def admin_absensi_config():
    db = get_db()
    ts = now_str()
    user = current_user()
    for key in ("absensi_mode", "radius_absen_default", "geofence_wajib_global"):
        val = request.form.get(key)
        if val is not None:
            db.execute("""
                INSERT INTO absensi_config (config_key, config_value, updated_by, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(config_key) DO UPDATE SET
                    config_value = excluded.config_value,
                    updated_by = excluded.updated_by,
                    updated_at = excluded.updated_at
            """, (key, val.strip(), user["id"], ts))
    db.commit()
    log_action("ADMIN_UPDATE_ABSENSI_CONFIG", "absensi_config", None)
    return redirect(url_for("admin_absensi_sesi"))


@app.route("/admin/absensi/sesi/buat", methods=["POST"])
@login_required
@roles_required("admin")
def admin_absensi_sesi_buat():
    db = get_db()
    ts = now_str()
    user = current_user()

    nama_sesi     = (request.form.get("nama_sesi") or "").strip()
    tanggal       = request.form.get("tanggal") or now_wib().strftime("%Y-%m-%d")
    bujp_id       = request.form.get("bujp_id") or None
    jam_buka_masuk  = request.form.get("jam_buka_masuk") or "07:00"
    jam_tutup_masuk = request.form.get("jam_tutup_masuk") or "09:00"
    jam_buka_keluar  = request.form.get("jam_buka_keluar") or "16:00"
    jam_tutup_keluar = request.form.get("jam_tutup_keluar") or "23:59"
    batas_terlambat  = request.form.get("batas_terlambat") or "08:00"
    radius_meter    = int(request.form.get("radius_meter") or 200)
    keterangan    = (request.form.get("keterangan") or "").strip()
    langsung_aktif  = request.form.get("langsung_aktif") == "1"

    if not nama_sesi:
        return redirect(url_for("admin_absensi_sesi"))

    status_awal = "aktif" if langsung_aktif else "draft"
    diaktifkan_oleh = user["id"] if langsung_aktif else None
    diaktifkan_at   = ts if langsung_aktif else None

    cur = db.execute("""
        INSERT INTO absensi_sesi (
            nama_sesi, tanggal, jam_buka_masuk, jam_tutup_masuk,
            jam_buka_keluar, jam_tutup_keluar, batas_terlambat,
            status, radius_meter, bujp_id, keterangan,
            dibuat_oleh, diaktifkan_oleh, diaktifkan_at, created_at, updated_at
        ) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        nama_sesi, tanggal, jam_buka_masuk, jam_tutup_masuk,
        jam_buka_keluar, jam_tutup_keluar, batas_terlambat,
        status_awal, radius_meter, bujp_id, keterangan,
        user["id"], diaktifkan_oleh, diaktifkan_at, ts, ts
    ))
    db.commit()
    log_action("ADMIN_BUAT_SESI_ABSENSI", "absensi_sesi", cur.lastrowid,
               f"nama={nama_sesi};tanggal={tanggal};aktif={langsung_aktif}")
    return redirect(url_for("admin_absensi_sesi"))


@app.route("/admin/absensi/sesi/<int:sesi_id>/aktifkan", methods=["POST"])
@login_required
@roles_required("admin")
def admin_absensi_sesi_aktifkan(sesi_id):
    db = get_db()
    ts = now_str()
    user = current_user()
    db.execute("""
        UPDATE absensi_sesi SET status='aktif', diaktifkan_oleh=?, diaktifkan_at=?, updated_at=?
        WHERE id=?
    """, (user["id"], ts, ts, sesi_id))
    db.commit()
    log_action("ADMIN_AKTIFKAN_SESI", "absensi_sesi", sesi_id)
    return redirect(url_for("admin_absensi_sesi"))


@app.route("/admin/absensi/sesi/<int:sesi_id>/tutup", methods=["POST"])
@login_required
@roles_required("admin")
def admin_absensi_sesi_tutup(sesi_id):
    db = get_db()
    ts = now_str()
    db.execute("""
        UPDATE absensi_sesi SET status='ditutup', updated_at=? WHERE id=?
    """, (ts, sesi_id))
    db.commit()
    log_action("ADMIN_TUTUP_SESI", "absensi_sesi", sesi_id)
    return redirect(url_for("admin_absensi_sesi"))


# ✅ ROUTE BARU UNTUK UPDATE STATUS SESI LANGSUNG DARI DAFTAR
@app.route("/admin/absensi/sesi/<int:sesi_id>/update-status", methods=["POST"])
@login_required
@roles_required("admin")
def admin_absensi_sesi_update_status(sesi_id):
    db = get_db()
    ts = now_str()
    user = current_user()
    
    status_baru = request.form.get("status")
    # Validasi status hanya boleh nilai yang diizinkan
    if status_baru not in ('draft', 'aktif', 'selesai', 'ditutup'):
        return redirect(url_for("admin_absensi_sesi"))
    
    # Jika diaktifkan, set juga diaktifkan_oleh dan diaktifkan_at
    if status_baru == 'aktif':
        db.execute("""
            UPDATE absensi_sesi 
            SET status=?, diaktifkan_oleh=?, diaktifkan_at=?, updated_at=? 
            WHERE id=?
        """, (status_baru, user["id"], ts, ts, sesi_id))
    else:
        db.execute("""
            UPDATE absensi_sesi SET status=?, updated_at=? WHERE id=?
        """, (status_baru, ts, sesi_id))
    
    db.commit()
    log_action("ADMIN_UPDATE_STATUS_SESI", "absensi_sesi", sesi_id, f"status_baru={status_baru}")
    return redirect(url_for("admin_absensi_sesi"))


@app.route("/admin/absensi/sesi/<int:sesi_id>/detail")
@login_required
@roles_required("admin")
def admin_absensi_sesi_detail(sesi_id):
    db = get_db()
    user = current_user()

    sesi = db.execute("""
        SELECT s.*, 
               COALESCE(b.nama_bujp, 'Semua BUJP') AS nama_bujp, 
               u.full_name AS dibuat_oleh_nama
        FROM absensi_sesi s
        LEFT JOIN bujp b ON b.id = s.bujp_id
        LEFT JOIN users u ON u.id = s.dibuat_oleh
        WHERE s.id = ?
    """, (sesi_id,)).fetchone()

    if not sesi:
        abort(404)

    # Absensi dalam sesi ini
    absensi_list = db.execute("""
        SELECT a.*, 
               COALESCE(u.full_name, 'User Dihapus') AS full_name, 
               COALESCE(u.username, 'deleted_user') AS username, 
               COALESCE(b.nama_bujp, '-') AS nama_bujp
        FROM absensi a
        LEFT JOIN users u ON u.id = a.user_id
        LEFT JOIN bujp b ON b.id = u.bujp_id
        WHERE a.sesi_id = ?
        ORDER BY a.id DESC
    """, (sesi_id,)).fetchall()

    # Hitung statistik
    masuk_count  = sum(1 for a in absensi_list if a["tipe"] == "MASUK")
    keluar_count = sum(1 for a in absensi_list if a["tipe"] == "KELUAR")
    terlambat    = sum(1 for a in absensi_list if a["tipe"] == "MASUK" and a["status"] == "Terlambat")

    body = render_template_string("""
    <div class="mt-6 space-y-6">
      <div class="flex items-center gap-4">
        <a href="{{ url_for('admin_absensi_sesi') }}"
          class="px-4 py-2 rounded-2xl bg-white/5 border border-white/10 text-sm">← Kembali</a>
        <h1 class="text-2xl font-black">📅 Detail Sesi: {{ sesi.nama_sesi }}</h1>
        {% if sesi.status == 'aktif' %}
        <span class="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold animate-pulse">🟢 AKTIF</span>
        {% endif %}
      </div>

      <!-- Info Sesi -->
      <div class="glass rounded-3xl p-5 grid md:grid-cols-4 gap-4 text-sm">
        <div><div class="text-slate-400 mb-1">Tanggal</div><div class="font-bold">{{ sesi.tanggal }}</div></div>
        <div><div class="text-slate-400 mb-1">⬆️ Jam Masuk</div><div class="font-bold text-emerald-300">{{ sesi.jam_buka_masuk }} – {{ sesi.jam_tutup_masuk }}</div></div>
        <div><div class="text-slate-400 mb-1">⬇️ Jam Keluar</div><div class="font-bold text-orange-300">{{ sesi.jam_buka_keluar or '-' }} – {{ sesi.jam_tutup_keluar or '-' }}</div></div>
        <div><div class="text-slate-400 mb-1">BUJP</div><div class="font-bold text-amber-300">{{ sesi.nama_bujp or 'Semua BUJP' }}</div></div>
        <div><div class="text-slate-400 mb-1">Batas Terlambat</div><div class="font-bold text-red-300">{{ sesi.batas_terlambat }}</div></div>
        <div><div class="text-slate-400 mb-1">Dibuat Oleh</div><div class="font-bold">{{ sesi.dibuat_oleh_nama }}</div></div>
        <div><div class="text-slate-400 mb-1">Radius Geofence</div><div class="font-bold">{{ sesi.radius_meter }} meter</div></div>
        <div><div class="text-slate-400 mb-1">Keterangan</div><div class="font-bold">{{ sesi.keterangan or '-' }}</div></div>
      </div>

      <!-- Statistik -->
      <div class="grid grid-cols-3 gap-4">
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-emerald-400">{{ masuk_count }}</div>
          <div class="text-sm text-slate-400">Total Absen Masuk</div>
        </div>
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-orange-400">{{ keluar_count }}</div>
          <div class="text-sm text-slate-400">Total Absen Keluar</div>
        </div>
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-red-400">{{ terlambat }}</div>
          <div class="text-sm text-slate-400">Terlambat</div>
        </div>
      </div>

      <!-- Tabel Absensi -->
      <div class="glass rounded-3xl overflow-hidden">
        <div class="px-6 py-4 border-b border-white/10">
          <h2 class="text-xl font-bold">📋 Daftar Absensi Sesi Ini</h2>
        </div>
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="bg-white/5 border-b border-white/10 text-sm text-slate-300">
                <th class="text-left px-5 py-3">Nama Satpam</th>
                <th class="text-left px-5 py-3">BUJP</th>
                <th class="text-left px-5 py-3">Tipe</th>
                <th class="text-left px-5 py-3">Waktu</th>
                <th class="text-left px-5 py-3">Status</th>
                <th class="text-left px-5 py-3">Lokasi GPS</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
            {% for a in absensi_list %}
              <tr class="hover:bg-white/5 transition">
                <td class="px-5 py-3">
                  <div class="font-bold">{{ a.full_name }}</div>
                  <div class="text-xs text-slate-400">@{{ a.username }}</div>
                </td>
                <td class="px-5 py-3 text-amber-300 text-sm">{{ a.nama_bujp or '-' }}</td>
                <td class="px-5 py-3">
                  {% if a.tipe == 'MASUK' %}
                  <span class="px-2 py-1 rounded-lg bg-emerald-500/20 text-emerald-400 text-xs font-bold">⬆️ MASUK</span>
                  {% else %}
                  <span class="px-2 py-1 rounded-lg bg-orange-500/20 text-orange-400 text-xs font-bold">⬇️ KELUAR</span>
                  {% endif %}
                </td>
                <td class="px-5 py-3 text-sm">{{ a.tanggal }} {{ a.waktu }}</td>
                <td class="px-5 py-3 text-sm">
                  {% if a.status == 'Terlambat' %}
                  <span class="text-red-400">⚠️ Terlambat</span>
                  {% elif a.status == 'Tepat Waktu' %}
                  <span class="text-emerald-400">✅ Tepat Waktu</span>
                  {% else %}
                  <span class="text-slate-300">{{ a.status or '-' }}</span>
                  {% endif %}
                </td>
                <td class="px-5 py-3 text-xs font-mono text-cyan-300">
                  {% if a.lat %} {{ '%.5f'|format(a.lat) }}, {{ '%.5f'|format(a.lng) }}
                  <a href="https://www.google.com/maps/search/?api=1&query={{ a.lat }},{{ a.lng }}"
                    target="_blank" class="ml-1 text-cyan-500">🗺</a>
                  {% else %} - {% endif %}
                </td>
              </tr>
            {% else %}
              <tr>
                <td colspan="6" class="py-10 text-center text-slate-400">
                  <div class="text-4xl mb-3">📭</div>
                  <div>Belum ada absensi dalam sesi ini</div>
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """, sesi=sesi, absensi_list=absensi_list,
         masuk_count=masuk_count, keluar_count=keluar_count, terlambat=terlambat)
    return render_page(f"Detail Sesi: {sesi['nama_sesi']}", body, user)


@app.route("/admin/absensi/rekap")
@login_required
@roles_required("admin")
def admin_absensi_rekap():
    db = get_db()
    user = current_user()

    tanggal_dari = request.args.get("dari") or now_wib().strftime("%Y-%m-01")
    tanggal_ke   = request.args.get("ke") or now_wib().strftime("%Y-%m-%d")
    bujp_filter  = request.args.get("bujp_id", type=int)

    query = """
        SELECT a.*, u.full_name, u.username, b.nama_bujp
        FROM absensi a
        JOIN users u ON u.id = a.user_id
        LEFT JOIN bujp b ON b.id = u.bujp_id
        WHERE DATE(a.tanggal) BETWEEN ? AND ?
    """
    params = [tanggal_dari, tanggal_ke]
    if bujp_filter:
        query += " AND u.bujp_id = ?"
        params.append(bujp_filter)
    query += " ORDER BY a.id DESC LIMIT 500"

    absensi_list = db.execute(query, params).fetchall()
    bujp_list = db.execute("SELECT id, nama_bujp FROM bujp WHERE is_active=1 ORDER BY nama_bujp").fetchall()

    total_masuk  = sum(1 for a in absensi_list if a["tipe"] == "MASUK")
    total_keluar = sum(1 for a in absensi_list if a["tipe"] == "KELUAR")
    terlambat    = sum(1 for a in absensi_list if a["tipe"] == "MASUK" and a["status"] == "Terlambat")

    body = render_template_string("""
    <div class="mt-6 space-y-6">
      <div>
        <h1 class="text-3xl font-black mb-1">📊 REKAP ABSENSI SATPAM</h1>
        <p class="text-slate-400">Laporan kehadiran satpam semua BUJP yang dapat difilter berdasarkan tanggal dan BUJP</p>
      </div>

      <!-- Filter -->
      <div class="glass rounded-3xl p-5">
        <form method="get" class="grid md:grid-cols-4 gap-4 items-end">
          <div>
            <label class="text-xs text-slate-400 block mb-1">Tanggal Dari</label>
            <input type="date" name="dari" value="{{ tanggal_dari }}"
              class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
          </div>
          <div>
            <label class="text-xs text-slate-400 block mb-1">Tanggal Sampai</label>
            <input type="date" name="ke" value="{{ tanggal_ke }}"
              class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
          </div>
          <div>
            <label class="text-xs text-slate-400 block mb-1">Filter BUJP</label>
            <select name="bujp_id" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
              <option value="">Semua BUJP</option>
              {% for b in bujp_list %}
              <option value="{{ b.id }}" {% if bujp_filter == b.id %}selected{% endif %}>{{ b.nama_bujp }}</option>
              {% endfor %}
            </select>
          </div>
          <button class="rounded-2xl bg-cyan-500 text-slate-950 font-bold px-5 py-3">🔍 Filter</button>
        </form>
      </div>

      <!-- Statistik -->
      <div class="grid grid-cols-3 gap-4">
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-emerald-400">{{ total_masuk }}</div>
          <div class="text-sm text-slate-400">Total Absen Masuk</div>
        </div>
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-orange-400">{{ total_keluar }}</div>
          <div class="text-sm text-slate-400">Total Absen Keluar</div>
        </div>
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-red-400">{{ terlambat }}</div>
          <div class="text-sm text-slate-400">Terlambat</div>
        </div>
      </div>

      <!-- Tabel -->
      <div class="glass rounded-3xl overflow-hidden">
        <div class="px-6 py-4 border-b border-white/10 flex items-center justify-between">
          <h2 class="text-xl font-bold">📋 Data Absensi ({{ absensi_list|length }} records)</h2>
          <a href="/admin/absensi/rekap/export?dari={{ tanggal_dari }}&ke={{ tanggal_ke }}&bujp_id={{ bujp_filter or '' }}"
            class="px-4 py-2 rounded-2xl bg-emerald-500/20 text-emerald-400 text-sm font-bold">
            📥 Export Excel
          </a>
        </div>
        <div class="overflow-x-auto max-h-[60vh]">
          <table class="w-full">
            <thead class="sticky top-0 bg-slate-900">
              <tr class="bg-white/5 border-b border-white/10 text-sm text-slate-300">
                <th class="text-left px-5 py-3">Nama Satpam</th>
                <th class="text-left px-5 py-3">BUJP</th>
                <th class="text-left px-5 py-3">Tanggal</th>
                <th class="text-left px-5 py-3">Waktu</th>
                <th class="text-left px-5 py-3">Tipe</th>
                <th class="text-left px-5 py-3">Status</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
            {% for a in absensi_list %}
              <tr class="hover:bg-white/5 transition text-sm">
                <td class="px-5 py-3">
                  <div class="font-bold">{{ a.full_name }}</div>
                  <div class="text-xs text-slate-400">@{{ a.username }}</div>
                </td>
                <td class="px-5 py-3 text-amber-300">{{ a.nama_bujp or '-' }}</td>
                <td class="px-5 py-3">{{ a.tanggal }}</td>
                <td class="px-5 py-3">{{ a.waktu }}</td>
                <td class="px-5 py-3">
                  {% if a.tipe == 'MASUK' %}
                  <span class="text-emerald-400">⬆️ MASUK</span>
                  {% else %}
                  <span class="text-orange-400">⬇️ KELUAR</span>
                  {% endif %}
                </td>
                <td class="px-5 py-3">
                  {% if a.status == 'Terlambat' %}<span class="text-red-400">⚠️ Terlambat</span>
                  {% elif a.status == 'Tepat Waktu' %}<span class="text-emerald-400">✅ Tepat Waktu</span>
                  {% else %}<span class="text-slate-300">{{ a.status or 'Normal' }}</span>{% endif %}
                </td>
              </tr>
            {% else %}
              <tr>
                <td colspan="6" class="py-10 text-center text-slate-400">Tidak ada data absensi untuk filter ini</td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    """, absensi_list=absensi_list, bujp_list=bujp_list,
         tanggal_dari=tanggal_dari, tanggal_ke=tanggal_ke,
         bujp_filter=bujp_filter,
         total_masuk=total_masuk, total_keluar=total_keluar, terlambat=terlambat)
    return render_page("Rekap Absensi", body, user)


@app.route("/admin/absensi/rekap/export")
@login_required
@roles_required("admin")
def admin_absensi_rekap_export():
    db = get_db()
    tanggal_dari = request.args.get("dari") or now_wib().strftime("%Y-%m-01")
    tanggal_ke   = request.args.get("ke") or now_wib().strftime("%Y-%m-%d")
    bujp_filter  = request.args.get("bujp_id", type=int)

    query = """
        SELECT u.full_name AS "Nama Satpam", u.username AS "Username",
               u.no_kta AS "No KTA", b.nama_bujp AS "BUJP",
               a.tanggal AS "Tanggal", a.waktu AS "Waktu",
               a.tipe AS "Tipe", a.status AS "Status",
               a.lat AS "Latitude", a.lng AS "Longitude", a.akurasi AS "Akurasi GPS"
        FROM absensi a
        JOIN users u ON u.id = a.user_id
        LEFT JOIN bujp b ON b.id = u.bujp_id
        WHERE DATE(a.tanggal) BETWEEN ? AND ?
    """
    params = [tanggal_dari, tanggal_ke]
    if bujp_filter:
        query += " AND u.bujp_id = ?"
        params.append(bujp_filter)
    query += " ORDER BY a.tanggal DESC, a.waktu DESC"

    rows = db.execute(query, params).fetchall()
    df = pd.DataFrame([dict(row) for row in rows])

    output = io.BytesIO()
    with pd.ExcelWriter(output, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Rekap Absensi")
    output.seek(0)

    log_action("ADMIN_EXPORT_ABSENSI", "absensi", None,
               f"dari={tanggal_dari};ke={tanggal_ke};bujp={bujp_filter}")
    filename = f"rekap_absensi_{tanggal_dari}_sd_{tanggal_ke}.xlsx"
    resp = make_response(output.read())
    resp.headers["Content-Type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    resp.headers["Content-Disposition"] = f"attachment; filename={filename}"
    return resp


@app.route("/api/satpam/<int:user_id>/trail")
@login_required
@roles_required("admin", "direktur_binmas")
def api_satpam_trail(user_id):
    """✅ [NEW] Ambil riwayat lokasi satpam hari ini untuk ditampilkan sebagai trail di peta."""
    db = get_db()
    today = now_wib().strftime("%Y-%m-%d")
    rows = db.execute("""
        SELECT lat, lng, accuracy, created_at
        FROM locations
        WHERE user_id = ? AND DATE(created_at) = ?
        ORDER BY id ASC
        LIMIT 200
    """, (user_id, today)).fetchall()
    return jsonify({"trail": [dict(r) for r in rows]})


@app.route("/emergency-alert-map")
@app.route("/alert")
@login_required
@roles_required("direktur_binmas", "admin")
def emergency_alert_map():
    user = current_user()
    db = get_db()
    
    # Ambil SEMUA laporan darurat yang masih pending
    emergency_reports = db.execute("""
        SELECT e.*, u.full_name, u.username
        FROM emergency_reports e
        JOIN users u ON u.id = e.user_id
        WHERE e.status = 'pending'
        ORDER BY e.created_at DESC
    """).fetchall()
    
    # ✅ CONVERT SQLITE ROW OBJECT KE DICTIONARY AGAR BISA DI SERIALISASI JSON
    emergency_reports = [dict(row) for row in emergency_reports]
    
    total_pending = len(emergency_reports)
    
    body = render_template_string("""
    <style>
    @keyframes pulse-red {
        0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
        70% { transform: scale(1.15); box-shadow: 0 0 0 20px rgba(239, 68, 68, 0); }
        100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
    }
    </style>
    
    <div class="mt-6">
        <!-- Header -->
        <div class="glass rounded-[2rem] p-6 text-center mb-6">
            <div class="flex items-center justify-center gap-6">
                <div class="text-5xl mb-2" style="animation: pulse-red 1.5s infinite">🚨</div>
                <div>
                    <h1 class="text-3xl font-black mb-1 text-red-400">MAPS ALERT EMERGENCY</h1>
                    <p class="text-sm text-slate-400">Realtime Dashboard Laporan Darurat Satpam</p>
                </div>
                <div class="px-4 py-2 rounded-2xl bg-red-500/15 border border-red-500/30">
                    <div class="text-2xl font-black text-red-400">{{ total_pending }}</div>
                    <div class="text-xs text-red-300">LAPORAN AKTIF</div>
                </div>
            </div>
        </div>

        <!-- Map + Tabel 2 Kolom -->
        <div class="grid lg:grid-cols-3 gap-6">
            <!-- Map Besar Kiri -->
            <div class="lg:col-span-2 glass rounded-[2rem] overflow-hidden">
                <div id="emergencyAlertMap" class="h-[65vh] w-full"></div>
            </div>

            <!-- Tabel Compact Kanan -->
            <div class="glass rounded-[2rem] p-4">
                <h2 class="text-lg font-black mb-3">📋 Daftar Laporan Aktif</h2>
                
                <div class="overflow-auto max-h-[55vh]">
                    <table class="w-full text-xs">
                        <thead class="sticky top-0 bg-[#0f172a]">
                            <tr class="border-b border-white/10 text-left text-slate-400">
                                <th class="py-2 px-1">Satpam</th>
                                <th class="py-2 px-1">Waktu</th>
                                <th class="py-2 px-1 text-center">Foto</th>
                                <th class="py-2 px-1 text-center">Status</th>
                            </tr>
                        </thead>
                        <tbody>
                        {% for report in emergency_reports %}
                            <tr class="border-b border-white/5 hover:bg-red-500/10 transition">
                                <td class="py-2 px-1">
                                    <div class="font-bold">{{ report.full_name }}</div>
                                    <div class="text-[10px] text-slate-500">@{{ report.username }}</div>
                                </td>
                                <td class="py-2 px-1 text-slate-300">
                                    <div>{{ report.created_at.split(' ')[1] }}</div>
                                    <div class="text-[10px] text-slate-500">{{ report.created_at.split(' ')[0] }}</div>
                                </td>
                                <td class="py-2 px-1 text-center">
                                    {% if report.foto_url %}
                                    <button onclick="showFotoPopup('{{ report.foto_url }}')" class="text-cyan-300 hover:text-cyan-200 font-bold text-sm">📸</button>
                                    {% else %}
                                    <span class="text-slate-600">-</span>
                                    {% endif %}
                                </td>
                                <td class="py-2 px-1 text-center">
                                    <span class="px-2 py-1 rounded-full bg-red-500/20 text-red-300 font-bold text-[10px]" style="animation: pulse-red 1.5s infinite">
                                        AKTIF
                                    </span>
                                </td>
                            </tr>
                        {% else %}
                            <tr>
                                <td colspan="4" class="py-8 text-center text-slate-400">
                                    <div class="text-3xl mb-2">✅</div>
                                    <div class="font-bold">TIDAK ADA LAPORAN DARURAT</div>
                                    <div class="text-xs">Semua Satpam dalam kondisi aman</div>
                                </td>
                            </tr>
                        {% endfor %}
                        </tbody>
                    </table>
                </div>
            </div>
        </div>
    </div>
    
    <!-- Popup Foto Bukti -->
    <div id="fotoPopupOverlay" class="fixed inset-0 bg-black/90 z-50 hidden flex items-center justify-center p-4 cursor-pointer" onclick="hideFotoPopup()">
        <img id="fotoPopupImage" src="" alt="Foto Bukti" class="max-w-full max-h-[90vh] rounded-2xl shadow-2xl">
    </div>
    
    <script>
    function showFotoPopup(url) {
        document.getElementById('fotoPopupImage').src = url;
        document.getElementById('fotoPopupOverlay').classList.remove('hidden');
    }
    
    function hideFotoPopup() {
        document.getElementById('fotoPopupOverlay').classList.add('hidden');
    }
    const MAP_EMERGENCY_WS = {{ ws_monitor_url|tojson }};
    const map = L.map('emergencyAlertMap').setView([-6.2, 106.816666], 12);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19, attribution: '&copy; OpenStreetMap'}).addTo(map);

    const emergencyMarkers = {};

        // Tambahkan marker untuk emergency yang sudah ada saat ini
    const existingReports = {{ emergency_reports|tojson }};
    existingReports.forEach(report => {
        createEmergencyMarker(report.id, report.lat, report.lng, report);
    });
    
    function createEmergencyMarker(reportId, lat, lng, data) {
        const pos = [lat, lng];
        
        // Marker MERAH dengan animasi pulse terus menerus
        const emergencyIcon = L.divIcon({
            className: 'emergency-marker',
            html: `<div style="
                background: #ef4444;
                width: 42px;
                height: 42px;
                border-radius: 50%;
                border: 6px solid white;
                box-shadow: 0 0 40px #ef4444;
                display: flex;
                align-items: center;
                justify-content: center;
                animation: pulse-red 1.5s infinite;
                font-weight: 900;
                font-size: 20px;
            ">🚨</div>`,
            iconSize: [42, 42],
            iconAnchor: [21, 21]
        });
        
        emergencyMarkers[reportId] = L.marker(pos, {icon: emergencyIcon}).addTo(map);
        
        // ✅ POPUP DETAIL LENGKAP LANGSUNG DI MAPS
        emergencyMarkers[reportId].bindPopup(`
            <div style="min-width: 400px; padding: 16px;">
                <div style="font-weight: 900; font-size: 26px; color: #ef4444; margin-bottom: 12px; text-align: center;">
                    🚨 LAPORAN DARURAT!
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 12px;">
                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;">👮 NAMA SATPAM</div>
                        <div style="font-weight: 900; font-size: 16px;">${data.full_name || data.satpam_nama || '-'}</div>
                        <div style="font-size: 11px; color: #64748b;">@${data.username || '-'}</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 12px;">
                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;">🏢 ASAL BUJP</div>
                        <div style="font-weight: 900; font-size: 16px; color: #fbbf24;">${data.nama_bujp || 'Umum'}</div>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin-bottom: 12px;">
                    <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 12px;">
                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;">⏱️ WAKTU LAPORAN</div>
                        <div style="font-weight: 700;">${data.created_at || '-'}</div>
                    </div>
                    <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 12px;">
                        <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;">📍 AKURASI GPS</div>
                        <div style="font-weight: 700;">${data.akurasi ? data.akurasi + ' meter' : '-'}</div>
                    </div>
                </div>
                
                <div style="background: rgba(255,255,255,0.05); padding: 12px; border-radius: 12px; margin-bottom: 12px;">
                    <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">📝 KETERANGAN KEJADIAN</div>
                    <div style="font-size: 14px; line-height: 1.6;">${data.keterangan || 'Tidak ada keterangan'}</div>
                </div>
                
                <div style="background: rgba(255,255,255,0.05); padding: 10px; border-radius: 12px; margin-bottom: 12px;">
                    <div style="font-size: 11px; color: #94a3b8; margin-bottom: 4px;">🧭 KOORDINAT LOKASI</div>
                    <div style="font-family: monospace; font-weight: 700; color: #22d3ee;">${Number(lat).toFixed(7)}, ${Number(lng).toFixed(7)}</div>
                </div>
                
                ${data.foto_url ? `
                <div style="margin-bottom: 14px;">
                    <div style="font-size: 11px; color: #94a3b8; margin-bottom: 6px;">📸 FOTO BUKTI</div>
                    <a href="${data.foto_url}" target="_blank">
                        <img src="${data.foto_url}" style="width: 100%; border-radius: 12px; border: 2px solid rgba(255,255,255,0.1);" alt="Foto Bukti">
                    </a>
                </div>
                ` : ''}
                
                <div style="display: grid; grid-template-columns: 1fr 1fr; gap: 10px;">
                    <a href="https://www.google.com/maps/search/?api=1&query=${lat},${lng}" target="_blank" style="display: block; padding: 12px; background: rgba(34, 211, 238, 0.2); color: #22d3ee; text-align: center; border-radius: 12px; font-weight: 900; text-decoration: none;">
                        🗺️ BUKA DI GOOGLE MAPS
                    </a>
                    <button onclick="prosesLaporanDariMaps(${reportId})" style="padding: 12px; background: #10b981; color: #0f172a; text-align: center; border-radius: 12px; font-weight: 900; border: none; cursor: pointer;">
                        ✅ PROSES LAPORAN
                    </button>
                </div>
            </div>
        `, {maxWidth: 450, autoClose: false, closeOnClick: false});
    }
    
    // ✅ FUNGSI PROSES LAPORAN LANGSUNG DARI MAPS
    async function prosesLaporanDariMaps(reportId) {
        if (!confirm('✅ YAKIN INGIN MEMPROSES LAPORAN INI?')) return;
        
        try {
            const res = await fetch(`/api/emergency/process/${reportId}`, { method: 'POST' });
            const result = await res.json();
            
            if (result.ok) {
                alert('✅ LAPORAN BERHASIL DIPROSES!');
                // Hapus marker dari maps
                if (emergencyMarkers[reportId]) {
                    map.removeLayer(emergencyMarkers[reportId]);
                    delete emergencyMarkers[reportId];
                }
                window.location.reload();
            } else {
                alert('❌ GAGAL MEMPROSES LAPORAN: ' + (result.error || 'Server error'));
            }
        } catch (err) {
            alert('❌ GAGAL TERHUBUNG KE SERVER');
        }
    }

    // WebSocket untuk menerima emergency alert realtime
    let emergencySocket = new WebSocket(MAP_EMERGENCY_WS);

    emergencySocket.onmessage = (event) => {
        try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'emergency_alert') {
                alert('🚨 ADA LAPORAN DARURAT BARU MASUK!');
                
                // Buat marker emergency baru
                createEmergencyMarker(msg.report_id, msg.lat, msg.lng, msg);
                
                // Auto fokus ke lokasi laporan terbaru
                map.setView([msg.lat, msg.lng], 17);
                emergencyMarkers[msg.report_id].openPopup();
                
                // Refresh halaman setelah 3 detik untuk menampilkan di list
                setTimeout(() => {
                    window.location.reload();
                }, 3000);
            }
        } catch (e) {}
    };
    
    // Auto fit semua marker emergency jika ada
    setTimeout(() => {
        const markerValues = Object.values(emergencyMarkers);
        if (markerValues.length > 0) {
            map.fitBounds(L.featureGroup(markerValues).getBounds().pad(0.2));
        }
    }, 500);
    </script>
    
    """, ws_monitor_url=ws_url("/ws/monitor"), emergency_reports=emergency_reports, total_pending=total_pending)
    return render_page("🚨 MAPS ALERT EMERGENCY", body, user)

@app.route("/monitor")
@login_required
@roles_required("direktur_binmas", "admin")
def monitor_map():
    user = current_user()
    
    # Hitung statistik dashboard Direktur
    db = get_db()
    total_satpam = db.execute("SELECT COUNT(*) FROM users WHERE role='satpam' AND is_active=1").fetchone()[0]
    total_bujp = db.execute("SELECT COUNT(*) FROM bujp WHERE is_active=1").fetchone()[0]
    # ✅ AMBIL SEMUA DAFTAR BUJP UNTUK DROPDOWN DI FORM TAMBAH USER
    bujp_list = db.execute("SELECT id, nama_bujp FROM bujp WHERE is_active=1 ORDER BY nama_bujp ASC").fetchall()
    total_anggota_bujp = db.execute("SELECT COUNT(*) FROM users WHERE bujp_id IS NOT NULL AND is_active=1").fetchone()[0]
    
    snapshot = latest_snapshot()
    online_satpam = sum(1 for item in snapshot if item.get('online'))
    inside_geofence = sum(1 for item in snapshot if item.get('geofences') and len(item.get('geofences')) > 0)
    kta_complete = db.execute("SELECT COUNT(*) FROM users WHERE role='satpam' AND no_kta != '' AND is_active=1").fetchone()[0]
    on_shift = len(snapshot)
    offline_satpam = max(total_satpam - online_satpam, 0)
    avg_accuracy = round(sum(float(item.get('accuracy') or 0) for item in snapshot) / len(snapshot), 1) if snapshot else 0
    geofence_names = []
    for item in snapshot:
        geofence_names.extend(item.get('geofences') or [])
    top_geofences = sorted({name for name in geofence_names})[:5]
    recent_logs = db.execute("""
        SELECT l.created_at, u.full_name, u.username, l.lat, l.lng, l.accuracy
        FROM locations l
        JOIN users u ON u.id = l.user_id
        WHERE u.role='satpam'
        ORDER BY l.id DESC LIMIT 8
    """).fetchall()
    
    body = render_template_string("""
    <style>
    .neo-panel {
      background: linear-gradient(135deg, rgba(15,23,42,.92), rgba(30,41,59,.82));
      border: 1px solid rgba(148,163,184,.14);
      box-shadow: 0 25px 80px rgba(2,6,23,.45);
      backdrop-filter: blur(18px);
    }
    .hero-grid {
      background:
        radial-gradient(circle at top left, rgba(34,211,238,.18), transparent 28%),
        radial-gradient(circle at top right, rgba(168,85,247,.18), transparent 30%),
        linear-gradient(135deg, rgba(15,23,42,.98), rgba(17,24,39,.95));
    }
    .metric-card {
      position: relative;
      overflow: hidden;
      background: linear-gradient(135deg, rgba(255,255,255,.08), rgba(255,255,255,.03));
      border: 1px solid rgba(255,255,255,.08);
    }
    .metric-card::after {
      content: "";
      position: absolute;
      inset: auto -20% -40% auto;
      width: 120px;
      height: 120px;
      background: radial-gradient(circle, rgba(255,255,255,.12), transparent 70%);
      pointer-events: none;
    }
    .command-btn { transition: all .2s ease; }
    .command-btn:hover { transform: translateY(-2px); }
    .intel-row { border-bottom: 1px solid rgba(255,255,255,.06); }
    .intel-row:last-child { border-bottom: none; }
    .satpam-card {
      background: linear-gradient(135deg, rgba(15,23,42,.95), rgba(30,41,59,.75));
      border: 1px solid rgba(255,255,255,.08);
      transition: .2s ease;
    }
    .satpam-card.online { 
      box-shadow: inset 5px 0 0 #16a34a, 0 0 20px rgba(22, 163, 74, 0.35);
      background: linear-gradient(90deg, rgba(22, 163, 74, 0.08) 0%, transparent 25%);
      border: 1px solid rgba(34, 197, 94, 0.3) !important;
    }
    .satpam-card.offline { box-shadow: inset 3px 0 0 #f97316; }
    
    @keyframes pulse-glow {
      0%, 100% { opacity: 1; box-shadow: 0 0 4px #22c55e; }
      50% { opacity: 0.6; box-shadow: 0 0 12px #22c55e, 0 0 20px #22c55e; }
    }
    .satpam-card:hover { transform: translateX(3px); border-color: rgba(34,211,238,.25); }
    </style>

    <div class="mt-6 space-y-6">
      <section class="neo-panel hero-grid rounded-[2rem] p-8">
        <div class="flex flex-col xl:flex-row gap-8 xl:items-center xl:justify-between">
          <div class="max-w-3xl">
            <div class="inline-flex items-center gap-2 px-4 py-2 rounded-full bg-cyan-500/10 border border-cyan-400/20 text-cyan-200 text-sm font-bold mb-4">
              <span>🛰️</span><span>COMMAND CENTER DIREKTUR BINMAS</span>
            </div>
            <h1 class="text-5xl xl:text-6xl font-black leading-tight mb-3">
              <span class="bg-gradient-to-r from-cyan-300 via-sky-400 to-violet-400 bg-clip-text text-transparent">Executive Monitoring</span>
            </h1>
            <p class="text-lg text-slate-300 max-w-2xl">Tampilan baru untuk direktur dengan ringkasan taktis, command shortcuts, live map, feed pergerakan, dan analisis cepat kondisi satpam di lapangan.</p>
            <div class="flex flex-wrap gap-3 mt-6">
              <a href="{{ url_for('bujp_management') }}" class="command-btn px-5 py-3 rounded-2xl bg-amber-500 text-slate-950 font-black">🏢 Kelola BUJP</a>
              <a href="{{ url_for('direktur_maps_bujp') }}" class="command-btn px-5 py-3 rounded-2xl bg-violet-500/20 border border-violet-400/20 text-violet-200 font-bold">🗺️ Maps Perusahaan</a>
              <button onclick="fitAll()" class="command-btn px-5 py-3 rounded-2xl bg-white/5 border border-white/10 text-slate-100 font-bold">🎯 Fokus Semua Unit</button>
              <button onclick="bootstrapSnapshot()" class="command-btn px-5 py-3 rounded-2xl bg-cyan-500/15 border border-cyan-400/20 text-cyan-100 font-bold">🔄 Refresh Intel</button>
            </div>
          </div>

          <div class="grid grid-cols-2 gap-4 xl:w-[360px]">
            <div class="metric-card rounded-3xl p-5">
              <div class="text-xs text-slate-400 mb-1">Unit Online</div>
              <div class="text-4xl font-black text-emerald-400">{{ online_satpam }}</div>
              <div class="text-xs text-emerald-200 mt-2">Siap dipantau real-time</div>
            </div>
            <div class="metric-card rounded-3xl p-5">
              <div class="text-xs text-slate-400 mb-1">Unit Offline</div>
              <div class="text-4xl font-black text-orange-400">{{ offline_satpam }}</div>
              <div class="text-xs text-orange-200 mt-2">Perlu atensi konektivitas</div>
            </div>
            <div class="metric-card rounded-3xl p-5">
              <div class="text-xs text-slate-400 mb-1">Dalam Geofence</div>
              <div class="text-4xl font-black text-cyan-300">{{ inside_geofence }}</div>
              <div class="text-xs text-cyan-100 mt-2">Posisi sesuai area</div>
            </div>
            <div class="metric-card rounded-3xl p-5">
              <div class="text-xs text-slate-400 mb-1">Akurasi Rata-rata</div>
              <div class="text-4xl font-black text-fuchsia-300">{{ avg_accuracy }}</div>
              <div class="text-xs text-fuchsia-100 mt-2">Meter GPS lapangan</div>
            </div>
          </div>
        </div>
      </section>

      <section class="grid xl:grid-cols-12 gap-6">
        <div class="xl:col-span-8 space-y-6">
          <div class="neo-panel rounded-[2rem] overflow-hidden">
            <div class="p-6 border-b border-white/10 flex flex-col lg:flex-row lg:items-center justify-between gap-4">
              <div>
                <h2 class="text-2xl font-black">🗺️ Tactical Live Map</h2>
                <p class="text-sm text-slate-400 mt-1">Pantau perpindahan unit, status websocket, dan geofence secara langsung.</p>
              </div>
              <div class="flex flex-wrap items-center gap-3">
                <span id="monitorWsStatus" class="px-4 py-2 rounded-2xl bg-amber-500/15 border border-amber-500/30 text-amber-200 text-sm font-bold">Menghubungkan WS...</span>
                <span id="totalSatpam" class="px-4 py-2 rounded-2xl bg-cyan-500/15 border border-cyan-500/30 text-cyan-200 text-sm font-bold">0 Satpam</span>
                <span id="wsLastEvent" class="text-xs text-slate-500">Update terakhir: -</span>
              </div>
            </div>
            <div id="monitorMap" class="h-[68vh] w-full"></div>
          </div>

      <div class="grid md:grid-cols-4 gap-4">
        <div class="neo-panel rounded-3xl p-5">
          <div class="text-sm text-slate-400 mb-2">Total Satpam</div>
          <div class="text-3xl font-black text-cyan-300">{{ total_satpam }}</div>
          <div class="text-xs text-slate-500 mt-2">Seluruh personel aktif dalam sistem</div>
        </div>
        <div class="neo-panel rounded-3xl p-5">
          <div class="text-sm text-slate-400 mb-2">BUJP Terdaftar</div>
          <div class="text-3xl font-black text-amber-400">{{ total_bujp }}</div>
          <div class="text-xs text-slate-500 mt-2">Perusahaan yang dapat dipantau direktur</div>
        </div>
        <div class="neo-panel rounded-3xl p-5">
          <div class="text-sm text-slate-400 mb-2">KTA Lengkap</div>
          <div class="text-3xl font-black text-pink-400">{{ kta_complete }}</div>
          <div class="text-xs text-slate-500 mt-2">Satpam dengan identitas administrasi lengkap</div>
        </div>
        <a href="{{ url_for('direktur_maps_bujp') }}" class="neo-panel rounded-3xl p-5 flex flex-col justify-center hover:bg-amber-500/10 hover:border-amber-500/20 transition cursor-pointer">
          <div class="text-sm text-slate-400 mb-2">🗺️ PETA SEMUA LOKASI BUJP</div>
          <div class="text-3xl font-black text-amber-400">KLIK DISINI</div>
          <div class="text-xs text-slate-500 mt-2">Lihat semua lokasi perusahaan di peta</div>
        </a>
      </div>
        </div>

        <div class="xl:col-span-4 space-y-6">
          <aside class="neo-panel rounded-[2rem] p-6">
            <div class="flex items-center justify-between mb-4">
              <h2 class="text-xl font-black">⚡ Live Unit Feed</h2>
              <span class="text-xs text-slate-500">{{ on_shift }} snapshot</span>
            </div>
            <div id="satpamList" class="space-y-4 max-h-[58vh] overflow-auto pr-1"></div>
          </aside>

          <aside class="neo-panel rounded-[2rem] p-6">
            <h2 class="text-xl font-black mb-4">🧠 Advanced Insight</h2>
            <div class="space-y-4 text-sm">
              <div class="intel-row pb-3">
                <div class="text-slate-400">Anggota BUJP Terhubung</div>
                <div class="text-2xl font-black text-orange-300">{{ total_anggota_bujp }}</div>
              </div>
              <div class="intel-row pb-3">
                <div class="text-slate-400">Top Area Geofence</div>
                <div class="mt-2 flex flex-wrap gap-2">
                  {% for name in top_geofences %}
                  <span class="px-3 py-1 rounded-full bg-violet-500/15 border border-violet-400/20 text-violet-200 text-xs font-bold">{{ name }}</span>
                  {% else %}
                  <span class="text-slate-500">Belum ada area dominan</span>
                  {% endfor %}
                </div>
              </div>
              <div>
                <div class="text-slate-400 mb-2">Recent Movement Feed</div>
                <div class="space-y-2 max-h-56 overflow-auto pr-1">
                  {% for log in recent_logs %}
                  <div class="rounded-2xl bg-white/5 border border-white/5 p-3">
                    <div class="font-bold text-slate-100">{{ log.full_name }}</div>
                    <div class="text-xs text-slate-400">@{{ log.username }} • {{ log.created_at }}</div>
                    <div class="text-xs text-cyan-300 mt-1">{{ '%.6f'|format(log.lat) }}, {{ '%.6f'|format(log.lng) }}</div>
                    <div class="text-[11px] text-slate-500 mt-1">Akurasi {{ log.accuracy or 0 }} m</div>
                  </div>
                  {% else %}
                  <div class="text-slate-500">Belum ada feed pergerakan.</div>
                  {% endfor %}
                </div>
              </div>
            </div>
          </aside>
        </div>
      </section>

      <script>
      const MONITOR_WS = {{ ws_monitor_url|tojson }};
      const map = L.map('monitorMap').setView([-6.2, 106.816666], 13);
      L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {maxZoom: 19, attribution: '&copy; OpenStreetMap'}).addTo(map);

      const markers = {};
      const emergencyMarkers = {}; // 🚨 MARKER EMERGENCY MERAH KHUSUS
      let stateRows = {};
      const geofenceLayer = L.geoJSON([], {style: {color:'#8b5cf6', weight:3, fillColor:'#8b5cf6', fillOpacity:0.10}}).addTo(map);
      let monitorSocket = null;
      let reconnectTimer = null;

      async function loadGeofences() {
        const res = await fetch('/api/geofences');
        const geos = await res.json();
        geofenceLayer.clearLayers();
        geos.forEach(g => geofenceLayer.addData(g));
      }

      function setWsStatus(text, cls) {
        const el = document.getElementById('monitorWsStatus');
        el.className = 'px-4 py-2 rounded-2xl border text-sm font-bold ' + cls;
        el.textContent = text;
      }

      function cardHtml(row) {
        const when = row.created_at || '-';
        const online = row.online ? 'online' : 'offline';
        const onlineText = row.online ? 
          '<span class="text-emerald-300 font-extrabold flex items-center gap-2 text-sm"><span class="w-3 h-3 rounded-full bg-emerald-400" style="animation: pulse-glow 1.2s infinite"></span> 🟢 <b>SEDANG ONLINE AKTIF</b></span>' : 
          '<span class="text-slate-500 flex items-center gap-1"><span class="w-2 h-2 rounded-full bg-slate-600"></span> ⚪ Offline</span>';
        const geofence = row.geofences && row.geofences.length ? row.geofences.join(', ') : 'Di luar area geofence';
        return `
          <div class="satpam-card rounded-2xl p-4 ${online}">
            <div class="font-black text-lg">${row.full_name}</div>
            <div class="text-xs text-slate-400 mb-3">@${row.username} • ${onlineText}</div>
            <div class="text-xs space-y-1 text-slate-300">
              <div>🧭 ${Number(row.lat).toFixed(6)}, ${Number(row.lng).toFixed(6)}</div>
              <div>📡 Akurasi: ${Number(row.accuracy || 0).toFixed(1)} meter</div>
              <div>📍 Lokasi: ${geofence}</div>
              <div>⏱️ Update: ${when}</div>
            </div>
            <button onclick="focusSatpam(${row.user_id})" class="mt-3 w-full px-4 py-2 rounded-xl bg-gradient-to-r from-cyan-500 to-blue-600 hover:from-cyan-400 hover:to-blue-500 text-white text-xs font-bold">
              🔍 FOKUS KE LOKASI
            </button>
          </div>`;
      }

      window.focusSatpam = function(uid) {
        if (markers[uid]) {
          map.setView(markers[uid].getLatLng(), 17);
          markers[uid].openPopup();
        }
      }

      function renderRows(rows) {
        const ordered = rows.slice().sort((a, b) => String(b.created_at || '').localeCompare(String(a.created_at || '')));
        document.getElementById('satpamList').innerHTML = ordered.map(cardHtml).join('') || `
          <div class="text-center py-12 text-slate-500">
            <div class="text-5xl mb-4">📡</div>
            <div>Belum ada data lokasi satpam yang terkirim</div>
          </div>`;
        document.getElementById('totalSatpam').textContent = ordered.length + ' Satpam';
      }

      function upsertMarker(row) {
        stateRows[row.user_id] = Object.assign({}, stateRows[row.user_id] || {}, row);
        const newLatLng = [row.lat, row.lng];
        const iconColor = row.online ? '#22c55e' : '#f97316';
        
        if (!markers[row.user_id]) {
          const customIcon = L.divIcon({
            className: 'custom-marker',
            html: `<div style="background: ${iconColor}; width: 18px; height: 18px; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 12px ${iconColor};"></div>`,
            iconSize: [18, 18],
            iconAnchor: [9, 9]
          });
          markers[row.user_id] = L.marker(newLatLng, {icon: customIcon}).addTo(map);
        } else {
          // ✅ PERBAIKAN SELESAI: ANIMASI MARKER TIDAK LONCAT LAGI
          if (row.online) {
            const current = markers[row.user_id].getLatLng();
            const steps = 25;
            const dLat = (newLatLng[0] - current.lat) / steps;
            const dLng = (newLatLng[1] - current.lng) / steps;
            let step = 0;
            
            function move() {
              if (step >= steps) {
                markers[row.user_id].setLatLng(newLatLng);
                return;
              }
              markers[row.user_id].setLatLng([
                current.lat + dLat * step,
                current.lng + dLng * step
              ]);
              step++;
              requestAnimationFrame(move);
            }
            move();
          } else {
            markers[row.user_id].setLatLng(newLatLng);
          }
        }
        
        const gf = row.geofences && row.geofences.length ? row.geofences.join(', ') : 'Di luar area geofence';
        markers[row.user_id].bindPopup(`
          <div style="min-width: 280px; padding: 8px;">
            <div style="font-weight: 900; font-size: 18px; margin-bottom: 8px;">${row.full_name}</div>
            <div style="font-size: 13px; color: #94a3b8;">@${row.username}</div>
            <hr style="margin: 10px 0; border-color: rgba(255,255,255,0.1);">
            <div style="font-size: 13px; line-height: 1.6;">
              🧭 Lokasi: ${Number(row.lat).toFixed(6)}, ${Number(row.lng).toFixed(6)}<br>
              📡 Akurasi: ${Number(row.accuracy || 0).toFixed(1)} m<br>
              📍 Geofence: ${gf}<br>
              ⏱️ Update: ${row.created_at}
            </div>
          </div>
        `, {maxWidth: 320});
      }

      function fitAll() {
        const vals = Object.values(markers);
        if (vals.length > 0) {
          try {
            map.fitBounds(L.featureGroup(vals).getBounds().pad(0.25));
          } catch (e) {}
        }
      }

      function connectMonitorWS() {
        if (monitorSocket && (monitorSocket.readyState === WebSocket.OPEN || monitorSocket.readyState === WebSocket.CONNECTING)) return;
        monitorSocket = new WebSocket(MONITOR_WS);
        setWsStatus('Menghubungkan WS...', 'bg-amber-500/15 border-amber-500/30 text-amber-200');
        monitorSocket.onopen = () => setWsStatus('✅ WEBSOCKET AKTIF', 'bg-emerald-500/15 border-emerald-500/30 text-emerald-200');
        monitorSocket.onclose = () => {
          setWsStatus('⚠️ WS Terputus | Reconnect...', 'bg-red-500/15 border-red-500/30 text-red-200');
          clearTimeout(reconnectTimer);
          reconnectTimer = setTimeout(connectMonitorWS, 2500);
        };
        monitorSocket.onerror = () => setWsStatus('❌ WS Error', 'bg-red-500/15 border-red-500/30 text-red-200');

        monitorSocket.onmessage = (event) => {
          document.getElementById('wsLastEvent').textContent = 'Update terakhir: ' + new Date().toLocaleTimeString();
          try {
            const msg = JSON.parse(event.data);
            if (msg.type === 'snapshot') {
              stateRows = {};
              (msg.payload || []).forEach(upsertMarker);
              renderRows(Object.values(stateRows));
              fitAll();
            } else if (msg.type === 'location_update') {
              upsertMarker(msg.payload || {});
              renderRows(Object.values(stateRows));
            } else if (msg.type === 'presence') {
              stateRows = {};
              (msg.snapshot || []).forEach(upsertMarker);
              renderRows(Object.values(stateRows));
            } else if (msg.type === 'geofences') {
              geofenceLayer.clearLayers();
              (msg.payload || []).forEach(g => geofenceLayer.addData(g));
            } else if (msg.type === 'emergency_alert') {
              // 🚨 ADA LAPORAN DARURAT BARU MASUK!
              alert('🚨 ADA LAPORAN DARURAT DARI SATPAM: ' + msg.satpam_nama);
              
              const emergencyData = msg;
              const pos = [emergencyData.lat, emergencyData.lng];
              
              // Buat marker MERAH KHUSUS emergency dengan animasi pulse
              const emergencyIcon = L.divIcon({
                className: 'emergency-marker',
                html: `<div style="
                  background: #ef4444;
                  width: 32px;
                  height: 32px;
                  border-radius: 50%;
                  border: 4px solid white;
                  box-shadow: 0 0 25px #ef4444;
                  display: flex;
                  align-items: center;
                  justify-content: center;
                  animation: pulse 1.5s infinite;
                ">🚨</div>
                <style>
                @keyframes pulse {
                  0% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0.7); }
                  70% { transform: scale(1.1); box-shadow: 0 0 0 15px rgba(239, 68, 68, 0); }
                  100% { transform: scale(1); box-shadow: 0 0 0 0 rgba(239, 68, 68, 0); }
                }
                </style>`,
                iconSize: [32, 32],
                iconAnchor: [16, 16]
              });
              
              if (emergencyMarkers[emergencyData.report_id]) {
                emergencyMarkers[emergencyData.report_id].setLatLng(pos);
              } else {
                emergencyMarkers[emergencyData.report_id] = L.marker(pos, {icon: emergencyIcon}).addTo(map);
              }
              
              // Popup detail laporan darurat
              emergencyMarkers[emergencyData.report_id].bindPopup(`
                <div style="min-width: 320px; padding: 10px;">
                  <div style="font-weight: 900; font-size: 20px; color: #ef4444; margin-bottom: 8px;">
                    🚨 LAPORAN DARURAT!
                  </div>
                  <div style="font-weight: 900; font-size: 16px; margin-bottom: 8px;">${emergencyData.satpam_nama}</div>
                  <hr style="margin: 10px 0; border-color: rgba(255,255,255,0.1);">
                  <div style="font-size: 13px; line-height: 1.6;">
                    📝 Keterangan: ${emergencyData.keterangan || 'Tidak ada keterangan'}<br>
                    🧭 Lokasi: ${Number(emergencyData.lat).toFixed(6)}, ${Number(emergencyData.lng).toFixed(6)}<br>
                    ⏱️ Waktu: ${emergencyData.created_at}<br>
                    ${emergencyData.foto_url ? `<br>📸 <a href="${emergencyData.foto_url}" target="_blank">Lihat Foto Bukti</a>` : ''}
                  </div>
                </div>
              `, {maxWidth: 350}).openPopup();
              
              // Auto fokus map ke lokasi emergency
              map.setView(pos, 17);
            }
          } catch (e) {}
        };
      }

      async function bootstrapSnapshot() {
        const res = await fetch('/api/locations/latest');
        const rows = await res.json();
        stateRows = {};
        rows.forEach(upsertMarker);
        renderRows(Object.values(stateRows));
        fitAll();
      }

      loadGeofences();
      bootstrapSnapshot();
      connectMonitorWS();
      setInterval(() => {
        if (monitorSocket && monitorSocket.readyState === WebSocket.OPEN) {
          try { monitorSocket.send(JSON.stringify({type:'ping'})); } catch (e) {}
        }
      }, 20000);
    </script>

    """, 
        ws_monitor_url=ws_url("/ws/monitor"),
        total_satpam=total_satpam,
        online_satpam=online_satpam,
        offline_satpam=offline_satpam,
        inside_geofence=inside_geofence,
        kta_complete=kta_complete,
    total_bujp=total_bujp,
    bujp_list=bujp_list,
        total_anggota_bujp=total_anggota_bujp,
        on_shift=on_shift,
        avg_accuracy=avg_accuracy,
        top_geofences=top_geofences,
        recent_logs=recent_logs
    )
    return render_page("Map Satpam Live", body, user)


@app.route("/admin")
@login_required
@roles_required("admin")
def admin_dashboard():
    user = current_user()
    db = get_db()
    
    # Statistik Dashboard
    total_users = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    total_satpam = db.execute("SELECT COUNT(*) FROM users WHERE role='satpam' AND is_active=1").fetchone()[0]
    total_bujp = db.execute("SELECT COUNT(*) FROM bujp WHERE is_active=1").fetchone()[0]
    total_geofences = db.execute("SELECT COUNT(*) FROM geofences").fetchone()[0]
    
    # Ambil semua data (tanpa pagination untuk client side)
    users_all = db.execute("""
        SELECT id, username, full_name, role, is_active, no_kta, no_hp, created_at, updated_at 
        FROM users ORDER BY id DESC
    """).fetchall()
    
    geofences = db.execute("SELECT * FROM geofences ORDER BY id DESC").fetchall()
    logs = db.execute(
        "SELECT a.*, u.username AS actor_username, u.full_name AS actor_name FROM audit_logs a LEFT JOIN users u ON u.id = a.actor_user_id ORDER BY a.id DESC LIMIT 100"
    ).fetchall()

    # ✅ MANAJEMEN NOMOR REKENING
    rekening_list = db.execute("""
        SELECT * FROM rekening_bank 
        ORDER BY urutan ASC, id ASC
    """).fetchall()
    
    # ✅ DAFTAR BUJP UNTUK DROPDOWN TAMBAH USER
    bujp_list = db.execute("SELECT id, nama_bujp FROM bujp WHERE is_active=1 ORDER BY nama_bujp ASC").fetchall()

    body = render_template_string("""
    <div class="mt-6">

      <!-- Statistik Dashboard -->
      <div class="grid grid-cols-4 gap-4 mb-8">
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-cyan-300">{{ total_users }}</div>
          <div class="text-sm text-slate-400">Total User</div>
        </div>
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-emerald-400">{{ total_satpam }}</div>
          <div class="text-sm text-slate-400">Satpam Aktif</div>
        </div>
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-amber-400">{{ total_bujp }}</div>
          <div class="text-sm text-slate-400">BUJP Terdaftar</div>
        </div>
        <div class="glass rounded-3xl p-5 text-center">
          <div class="text-4xl font-black text-violet-400">{{ total_geofences }}</div>
          <div class="text-sm text-slate-400">Area Geofence</div>
        </div>
      </div>

      <!-- Tab Navigation -->
      <div class="flex gap-2 mb-6 border-b border-white/10 pb-3">
        <button id="tabUsers" onclick="showTab('users')" class="px-5 py-3 rounded-2xl bg-cyan-500 text-slate-950 font-bold tab-btn">👥 Data Satpam</button>
        <button id="tabGeofence" onclick="showTab('geofence')" class="px-5 py-3 rounded-2xl bg-white/5 border border-white/10 tab-btn">🗺️ Pemetaan Perusahaan</button>
        <button id="tabAudit" onclick="showTab('audit')" class="px-5 py-3 rounded-2xl bg-white/5 border border-white/10 tab-btn">📋 History Aktifitas</button>
      </div>

      <!-- Tab Users -->
      <div id="tabUsersContent" class="glass rounded-3xl p-5">
        <div class="flex items-center justify-between gap-3 mb-5 flex-wrap">
          <h2 class="text-2xl font-black">Data Satpam</h2>
          <div class="flex gap-3 items-center flex-wrap">
            <input id="searchUser" oninput="filterUsers()" placeholder="🔍 Cari user..." class="rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none w-64">
            <button onclick="showAddUserModal()" class="px-4 py-3 rounded-2xl bg-emerald-500 text-slate-950 font-bold">
              ➕ Tambah User
            </button>
          </div>
        </div>
        <div class="overflow-auto max-h-[70vh]">
          <table class="w-full text-xs">
            <thead class="sticky top-0 bg-[#0f172a] z-10">
              <tr class="border-b border-white/10 text-slate-400">
                <th class="py-3 px-2 text-left">ID</th>
                <th class="py-3 px-2 text-left">Nama / Username</th>
                <th class="py-3 px-2 text-center">Role</th>
                <th class="py-3 px-2 text-center">KTA</th>
                <th class="py-3 px-2 text-center">No HP</th>
                <th class="py-3 px-2 text-center">Status</th>
                <th class="py-3 px-2 text-center">Update</th>
                <th class="py-3 px-2 text-center">Aksi</th>
              </tr>
            </thead>
            <tbody id="usersTableBody">
            {% for u in users_all %}
              <tr class="border-b border-white/5 hover:bg-white/5 transition user-row" data-name="{{ u.full_name.lower() }} {{ u.username.lower() }} {{ u.no_kta.lower() }}">
                <td class="py-2 px-2 text-slate-500 font-mono">#{{ u.id }}</td>
                <td class="py-2 px-2">
                  <div class="font-bold">{{ u.full_name }}</div>
                  <div class="text-[10px] text-slate-500">@{{ u.username }}</div>
                </td>
                <td class="py-2 px-2 text-center">
                  <span class="inline-block px-2 py-1 rounded-lg bg-white/5 border border-white/10">{{ u.role }}</span>
                </td>
                <td class="py-2 px-2 text-center">
                  {% if u.no_kta %}
                    <span class="text-emerald-400 font-mono">{{ u.no_kta }}</span>
                  {% else %}
                    <span class="text-slate-500">-</span>
                  {% endif %}
                </td>
                <td class="py-2 px-2 text-center text-slate-300">{{ u.no_hp or '-' }}</td>
                <td class="py-2 px-2 text-center">
                  {% if u.is_active %}
                    <span class="text-emerald-400">✅</span>
                  {% else %}
                    <span class="text-slate-500">⚪</span>
                  {% endif %}
                </td>
                <td class="py-2 px-2 text-center text-slate-500 text-[10px]">{{ u.updated_at.split(' ')[0] }}</td>
                <td class="py-2 px-2 text-center">
                <div class="flex items-center justify-center gap-1">
                    <button onclick="resetPassword({{ u.id }})" title="Reset Password" class="w-7 h-7 rounded-lg bg-amber-500/20 text-amber-400 hover:bg-amber-500/30">🔑</button>
                    <button onclick="resetLocations({{ u.id }})" title="Reset Lokasi & Absensi" class="w-7 h-7 rounded-lg bg-orange-500/20 text-orange-400 hover:bg-orange-500/30">🔄</button>
                    <button onclick="editUser({{ u.id }}, '{{ u.full_name.replace("'", "\\'") }}', '{{ u.role }}')" title="Edit User" class="w-7 h-7 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30">✏️</button>
                    {% if u.id != me.id %}
                    <button onclick="deleteUser({{ u.id }})" title="Hapus User" class="w-7 h-7 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30">🗑️</button>
                    {% endif %}
                  </div>
                </td>
              </tr>
            {% else %}
              <tr><td colspan="8" class="py-8 text-center text-slate-400">Belum ada user terdaftar</td></tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>

      <!-- Tab Geofence -->
      <div id="tabGeofenceContent" class="glass rounded-3xl p-5 hidden">
        <div class="p-4 border-b border-white/10 flex items-center justify-between">
          <div>
            <h2 class="text-xl font-black">Pemetaan Perusahaan</h2>
            <p class="text-sm text-slate-400">Gambar polygon/rectangle lalu simpan. Update area langsung dibroadcast ke map monitoring via WebSocket.</p>
          </div>
          <button id="clearShapes" class="px-3 py-2 rounded-xl bg-white/5 border border-white/10 text-sm">Clear Draft</button>
        </div>
        <div id="adminGeofenceMap" class="h-[55vh]"></div>
        
        <div class="mt-4 flex items-center justify-between border-t border-white/10 pt-4">
          <form id="saveFenceForm" class="flex gap-3 items-center w-full">
            <input id="fenceName" required placeholder="Nama geofence" class="flex-1 rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
            <button type="submit" class="px-6 py-3 rounded-2xl bg-cyan-500 text-slate-950 font-bold">✅ Simpan Geofence</button>
          </form>
        </div>
        
        <div id="geofenceStatus" class="mt-2 text-sm text-slate-400"></div>
        
        <div class="mt-4">
          <h3 class="font-bold mb-3">Daftar Geofence Tersimpan</h3>
          <div class="space-y-3 max-h-[40vh] overflow-auto">
            {% for gf in geofences %}
            <div class="rounded-2xl bg-white/5 border border-white/10 p-4 flex items-center justify-between gap-3">
              <div>
                <div>
                  <button onclick='focusGeofence({{ gf.id }})' class="font-bold hover:text-cyan-400 transition cursor-pointer">
                    📍 {{ gf.name }}
                  </button>
                </div>
                <div class="text-xs text-slate-400">ID #{{ gf.id }} • {{ gf.updated_at }}</div>
              </div>
              <form method="post" action="{{ url_for('admin_geofence_delete', geofence_id=gf.id) }}" onsubmit="return confirm('Hapus geofence?')">
                <button class="px-3 py-2 rounded-xl bg-red-500 text-white text-sm font-bold">Hapus</button>
              </form>
            </div>
            {% else %}<div class="text-sm text-slate-400 py-4">Belum ada geofence yang dibuat.</div>{% endfor %}
          </div>
        </div>
      </div>

      <!-- Tab Rekening -->
      <div id="tabRekeningContent" class="glass rounded-3xl p-5 hidden">
        <div class="flex justify-between items-center mb-6 flex-wrap gap-4">
          <h2 class="text-2xl font-black">💳 Manajemen Nomor Rekening Resmi</h2>

<!-- Modal Tambah Rekening -->
<div id="addRekeningModal" class="fixed inset-0 bg-black/90 z-50 hidden flex items-center justify-center p-2 sm:p-4">
    <div class="glass rounded-3xl w-full max-w-lg max-h-[95vh] overflow-auto">
        <div class="sticky top-0 bg-gradient-to-b from-[#0f172a] to-[#0f172a]/95 p-4 sm:p-6 border-b border-white/10">
            <div class="flex justify-between items-center gap-3">
                <div class="text-xl sm:text-2xl font-black text-emerald-400">➕ TAMBAH REKENING BARU</div>
                <button onclick="closeAddRekeningModal()" class="w-12 h-12 rounded-2xl bg-white/5 hover:bg-white/10 text-xl flex items-center justify-center transition">✕</button>
            </div>
        </div>
        <div class="p-4 sm:p-6 space-y-4">
            <form id="formAddRekening" onsubmit="submitRekening(event)">
                <div class="space-y-3">
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Nama Bank</label>
                        <input type="text" name="nama_bank" required class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Nomor Rekening</label>
                        <input type="text" name="nomor_rekening" required class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Atas Nama</label>
                        <input type="text" name="atas_nama" required class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Keterangan (Opsional)</label>
                        <textarea name="keterangan" rows="2" class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition"></textarea>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-3 pt-4">
                    <button type="button" onclick="closeAddRekeningModal()" class="px-4 py-3 rounded-2xl bg-white/5 border border-white/10 text-center font-bold hover:bg-white/10 transition">
                        ❌ BATAL
                    </button>
                    <button type="submit" class="px-4 py-3 rounded-2xl bg-emerald-500 text-slate-950 text-center font-bold hover:bg-emerald-400 transition">
                        ✅ SIMPAN
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

          </button>
        </div>
        
        
        
        
            <tbody>
            {% for rekening in rekening_list %}
              <tr class="border-b border-white/5 hover:bg-white/5 transition">
                <td class="py-2 px-2 text-slate-500 font-mono">#{{ rekening.id }}</td>
                <td class="py-2 px-2 font-bold">{{ rekening.nama_bank }}</td>
                <td class="py-2 px-2 font-mono text-cyan-300">{{ rekening.nomor_rekening }}</td>
                <td class="py-2 px-2">{{ rekening.atas_nama }}</td>
                <td class="py-2 px-2 text-center">
                  {% if rekening.is_active %}
                    <span class="text-emerald-400">✅ Aktif</span>
                  {% else %}
                    <span class="text-slate-500">⚪ Nonaktif</span>
                  {% endif %}
                </td>
                <td class="py-2 px-2 text-center text-slate-500 text-xs">{{ rekening.updated_at.split(' ')[0] }}</td>
                <td class="py-2 px-2 text-center">
                  <div class="flex items-center justify-center gap-1">
                    <button onclick="editRekening({{ rekening.id }}, '{{ rekening.nama_bank.replace("'", "\\'") }}', '{{ rekening.nomor_rekening }}', '{{ rekening.atas_nama.replace("'", "\\'") }}', '{{ rekening.keterangan.replace("'", "\\'") }}', {{ rekening.is_active }})" class="w-7 h-7 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30">✏️</button>
                    <button onclick="toggleRekening({{ rekening.id }}, {{ 0 if rekening.is_active else 1 }})" class="w-7 h-7 rounded-lg bg-amber-500/20 text-amber-400 hover:bg-amber-500/30">
                      {% if rekening.is_active %}🔴{% else %}🟢{% endif %}
                    </button>
                    <button onclick="deleteRekening({{ rekening.id }})" class="w-7 h-7 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30">🗑️</button>
                    <button onclick="showRekeningHistory({{ rekening.id }})" class="w-7 h-7 rounded-lg bg-violet-500/20 text-violet-400 hover:bg-violet-500/30">📋</button>
                  </div>
                </td>
              </tr>
            {% else %}
              <tr><td colspan="7" class="py-8 text-center text-slate-400">Belum ada nomor rekening yang didaftarkan</td></tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>


      <!-- Tab History Aktifitas -->
      <div id="tabAuditContent" class="glass rounded-3xl p-5 hidden">
        <h2 class="text-xl font-black mb-4">History Aktifitas (200 terbaru)</h2>
        <div class="overflow-auto max-h-[60vh]">
          <table class="w-full text-sm">
            <thead class="text-left text-slate-400"><tr><th class="py-2 pr-3">Waktu</th><th class="py-2 pr-3">Aktor</th><th class="py-2 pr-3">Action</th><th class="py-2 pr-3">Type</th><th class="py-2 pr-3">Target</th><th class="py-2 pr-3">Detail</th><th class="py-2 pr-3">IP</th></tr></thead>
            <tbody>
              {% for log in logs %}
              <tr class="border-b border-white/5 text-sm">
                <td class="py-2 pr-3 whitespace-nowrap">{{ log.created_at }}</td>
                <td class="py-2 pr-3">{{ log.actor_name or log.actor_username or 'system' }}</td>
                <td class="py-2 pr-3">{{ log.action }}</td>
                <td class="py-2 pr-3">{{ log.target_type or '-' }}</td>
                <td class="py-2 pr-3">{{ log.target_id or '-' }}</td>
                <td class="py-2 pr-3">{{ log.detail or '-' }}</td>
                <td class="py-2 pr-3">{{ log.ip_address or '-' }}</td>
              </tr>
              {% else %}<tr><td colspan="7" class="py-3 text-slate-400">Belum ada History Aktifitas.</td></tr>{% endfor %}
            </tbody>
          </table>
        </div>
      </div>

    </div>

    <script>
      function showTab(tab) {
        // Hide semua tab
        document.querySelectorAll('[id$="Content"]').forEach(el => el.classList.add('hidden'));
        document.querySelectorAll('.tab-btn').forEach(btn => {
          btn.classList.remove('bg-cyan-500', 'text-slate-950');
          btn.classList.add('bg-white/5', 'border', 'border-white/10');
        });
        
        // Tampilkan tab yang dipilih
        document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1) + 'Content').classList.remove('hidden');
        document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.remove('bg-white/5', 'border', 'border-white/10');
        document.getElementById('tab' + tab.charAt(0).toUpperCase() + tab.slice(1)).classList.add('bg-cyan-500', 'text-slate-950');
      }

      function filterUsers() {
        const query = document.getElementById('searchUser').value.toLowerCase().trim();
        document.querySelectorAll('.user-row').forEach(row => {
          const match = row.dataset.name.includes(query);
          row.style.display = match ? '' : 'none';
        });
      }

      function showAddUserModal() {
        document.getElementById('addUserModal').classList.remove('hidden');
      }

      function hideAddUserModal() {
        document.getElementById('addUserModal').classList.add('hidden');
      }
      
      window.resetPassword = function(userId) {
        if (!confirm('Reset password user ini? Password akan direset menjadi password default')) return;
        window.location.href = '/admin/users/' + userId + '/reset';
      }

      window.resetLocations = function(userId) {
        if (!confirm('Reset SEMUA riwayat lokasi dan absensi hari ini user ini? Marker akan hilang dari semua map')) return;
        window.location.href = '/admin/users/' + userId + '/reset-locations';
      }

      window.deleteUser = function(userId) {
        if (!confirm('Hapus user ini PERMANEN?')) return;
        window.location.href = '/admin/users/' + userId + '/delete';
      }

      window.editUser = function(userId, nama, role) {
        alert(`Edit User ID: ${userId} \\nNama: ${nama} \\nRole: ${role}`);
      }

      window.showAddRekeningModal = function() {
          document.getElementById('addRekeningModal').classList.remove('hidden');
      }

      window.closeAddRekeningModal = function() {
          document.getElementById('addRekeningModal').classList.add('hidden');
          document.getElementById('formAddRekening').reset();
      }

      window.submitRekening = async function(e) {
          e.preventDefault();
          
          const form = document.getElementById('formAddRekening');
          const formData = new FormData(form);
          const submitBtn = form.querySelector('button[type="submit"]');
          const originalText = submitBtn.textContent;
          
          try {
              submitBtn.disabled = true;
              submitBtn.textContent = '⏳ Menyimpan...';
              
              const response = await fetch('/admin/rekening/save', {
                  method: 'POST',
                  body: formData,
                  credentials: 'same-origin'
              });
              
              const result = await response.json();
              
              if (result.ok) {
                  alert('✅ Rekening berhasil disimpan!');
                  closeAddRekeningModal();
                  window.location.reload();
              } else {
                  alert('❌ Gagal menyimpan: ' + (result.error || 'Terjadi kesalahan'));
              }
          } catch (err) {
              alert('❌ Gagal terhubung ke server: ' + err.message);
          } finally {
              submitBtn.disabled = false;
              submitBtn.textContent = originalText;
          }
      }

      window.focusGeofence = function(geofenceId) {
        // Temukan geofence yang sesuai di existingItems
        if (!gmap) {
          // Jika map belum diinisialisasi, buka tab Geofence dulu
          showTab('geofence');
          setTimeout(() => {
            focusGeofence(geofenceId);
          }, 500);
          return;
        }
        
        // Loop semua layer di existingItems
        existingItems.eachLayer(function(layer) {
          if (layer.feature && layer.feature.properties && layer.feature.properties.db_id == geofenceId) {
            // Fokus map ke geofence ini dengan zoom level 15
            gmap.fitBounds(layer.getBounds().pad(0.2));
            // Tambahkan animasi highlight
            layer.setStyle({weight: 4, color: '#06b6d4'});
            setTimeout(() => {
              layer.setStyle({color:'#f472b6', weight:2});
            }, 2000);
          }
        });
      }

      // ✅ [FIX] FUNGSI MODAL REKENING TIDAK TERDEFINISI
      window.showAddRekeningModal = function() {
          document.getElementById('addRekeningModal').classList.remove('hidden');
      }

      window.closeAddRekeningModal = function() {
          document.getElementById('addRekeningModal').classList.add('hidden');
          document.getElementById('formAddRekening').reset();
      }

      window.submitRekening = async function(e) {
          e.preventDefault();
          
          const form = document.getElementById('formAddRekening');
          const formData = new FormData(form);
          const submitBtn = form.querySelector('button[type="submit"]');
          const originalText = submitBtn.textContent;
          
          try {
              submitBtn.disabled = true;
              submitBtn.textContent = '⏳ Menyimpan...';
              
              const response = await fetch('/admin/rekening/save', {
                  method: 'POST',
                  body: formData,
                  credentials: 'same-origin'
              });
              
              const result = await response.json();
              
              if (result.ok) {
                  alert('✅ Rekening berhasil disimpan!');
                  closeAddRekeningModal();
                  window.location.reload();
              } else {
                  alert('❌ Gagal menyimpan: ' + (result.error || 'Terjadi kesalahan'));
              }
          } catch (err) {
              alert('❌ Gagal terhubung ke server: ' + err.message);
          } finally {
              submitBtn.disabled = false;
              submitBtn.textContent = originalText;
          }
      }

      // ==============================================
      // INISIALISASI GEOFENCE EDITOR MAP LEAFLET
      // ==============================================
      let gmap;
      let drawnItems;
      let existingItems;
      let drawControl;

      function initGeofenceMap() {
        if (gmap) {
          gmap.invalidateSize();
          return;
        }
        
        gmap = L.map('adminGeofenceMap').setView([-6.2, 106.816666], 12);
        L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
          maxZoom: 19, 
          attribution: '&copy; OpenStreetMap'
        }).addTo(gmap);
        
        drawnItems = new L.FeatureGroup().addTo(gmap);
        existingItems = new L.FeatureGroup().addTo(gmap);
        
        drawControl = new L.Control.Draw({ 
          edit: { featureGroup: drawnItems }, 
          draw: { polyline: false, marker: false, circle: false, circlemarker: false } 
        });
        gmap.addControl(drawControl);

        fetch('/api/geofences')
          .then(r => r.json())
          .then(list => {
            existingItems.clearLayers();
            list.forEach(g => L.geoJSON(g, {
              style: {color:'#f472b6', weight:2, fillOpacity:0.05}
            }).eachLayer(l => existingItems.addLayer(l)));
          }).catch(() => {});

        gmap.on(L.Draw.Event.CREATED, function (e) { 
          drawnItems.clearLayers(); 
          drawnItems.addLayer(e.layer); 
        });

        document.getElementById('clearShapes').addEventListener('click', () => drawnItems.clearLayers());

        document.getElementById('saveFenceForm').addEventListener('submit', async (e) => {
          e.preventDefault();
          const layer = drawnItems.getLayers()[0];
          const status = document.getElementById('geofenceStatus');
          if (!layer) { 
            status.textContent = 'Buat area dulu dengan toolbar Draw.'; 
            return; 
          }
          const name = document.getElementById('fenceName').value.trim();
          if (!name) { 
            status.textContent = 'Nama geofence wajib diisi.'; 
            return; 
          }
          let geojson = layer.toGeoJSON();
          geojson.properties = Object.assign({}, geojson.properties || {}, {name});
          try {
            const res = await fetch('/admin/geofence/save', { 
              method:'POST', 
              headers:{'Content-Type':'application/json'}, 
              body: JSON.stringify({name, geojson}) 
            });
            const data = await res.json();
            status.textContent = data.ok ? '✅ Geofence tersimpan! Refresh halaman untuk lihat daftar terbaru.' : (data.error || 'Gagal menyimpan');
            if (data.ok) { 
              document.getElementById('fenceName').value = ''; 
              drawnItems.clearLayers(); 
            }
          } catch (err) {
            status.textContent = '❌ Gagal menyimpan ke server';
          }
        });
      }

      // ✅ [PERBAIKAN] FUNGSI MODAL REKENING DI DEFINE DI GLOBAL SCOPE, AGAR BISA DI KLIK LANGSUNG KETIKA HALAMAN DI LOAD
      window.showAddRekeningModal = function() {
          document.getElementById('addRekeningModal').classList.remove('hidden');
      }

      window.closeAddRekeningModal = function() {
          document.getElementById('addRekeningModal').classList.add('hidden');
          document.getElementById('formAddRekening').reset();
      }

      window.submitRekening = async function(e) {
          e.preventDefault();
          
          const form = document.getElementById('formAddRekening');
          const formData = new FormData(form);
          const submitBtn = form.querySelector('button[type="submit"]');
          const originalText = submitBtn.textContent;
          
          try {
              submitBtn.disabled = true;
              submitBtn.textContent = '⏳ Menyimpan...';
              
              const response = await fetch('/admin/rekening/save', {
                  method: 'POST',
                  body: formData,
                  credentials: 'same-origin'
              });
              
              const result = await response.json();
              
              if (result.ok) {
                  alert('✅ Rekening berhasil disimpan!');
                  closeAddRekeningModal();
                  window.location.reload();
              } else {
                  alert('❌ Gagal menyimpan: ' + (result.error || 'Terjadi kesalahan'));
              }
          } catch (err) {
              alert('❌ Gagal terhubung ke server: ' + err.message);
          } finally {
              submitBtn.disabled = false;
              submitBtn.textContent = originalText;
          }
      }

      // Ketika user klik tab Geofence baru inisialisasi mapnya
      let originalShowTab = showTab;
      window.showTab = function(tab) {
        originalShowTab(tab);
        if (tab === 'geofence') {
          setTimeout(() => {
            initGeofenceMap();
          }, 100);
        }
      }
    </script>

    <!-- MODAL TAMBAH USER BARU -->
    <div id="addUserModal" class="fixed inset-0 bg-black/80 z-50 hidden flex items-center justify-center p-4">
        <div class="glass rounded-3xl p-6 w-full max-w-lg">
            <h2 class="text-2xl font-bold mb-4">➕ Tambah User Baru</h2>
            <form method="post" action="{{ url_for('admin_user_create') }}" class="space-y-4">
                <div class="grid grid-cols-2 gap-4">
                  <div>
                      <label class="text-sm text-slate-400 block mb-1">Username</label>
                      <input name="username" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                  </div>
                  <div>
                      <label class="text-sm text-slate-400 block mb-1">Password</label>
                      <input name="password" type="password" required value="{{ reset_pw }}" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                  </div>
                </div>
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Nama Lengkap</label>
                    <input name="full_name" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Role</label>
                    <select name="role" id="selectRole" required class="w-full rounded-2xl bg-slate-900 border border-white/10 px-4 py-3 outline-none" onchange="toggleBujpSelect()">
                        {% for r in roles %}<option value="{{ r }}">{{ r }}</option>{% endfor %}
                    </select>
                </div>
                
                <!-- ✅ BARU: FIELD PILIHAN BUJP - WAJIB UNTUK ROLE SATPAM & ANGGOTA -->
                <div id="bujpFieldContainer" class="hidden">
                    <label class="text-sm text-slate-400 block mb-1">🏢 BUJP * (WAJIB UNTUK SATPAM)</label>
                    <select name="bujp_id" id="bujpIdSelect" class="w-full rounded-2xl bg-slate-900 border border-white/10 px-4 py-3 outline-none">
                        <option value="">-- Pilih BUJP --</option>
                        {% for b in bujp_list %}
                        <option value="{{ b.id }}">{{ b.nama_bujp }}</option>
                        {% endfor %}
                    </select>
                    <p class="text-xs text-amber-400 mt-1">⚠️ Untuk role Satpam / Anggota, field ini WAJIB diisi!</p>
                </div>

                <script>
                // ✅ PERBAIKAN FINAL: SCRIPT YANG TIDAK BISA GAGAL
                // Tidak peduli kapan modal dibuka, tidak peduli ada error javascript lain
                // Tetap jalan terus menerus setiap 50ms
                setInterval(function() {
                    try {
                        const selectRole = document.getElementById('selectRole');
                        const container = document.getElementById('bujpFieldContainer');
                        const select = document.getElementById('bujpIdSelect');
                        
                        if(selectRole && container && select) {
                            const role = selectRole.value.trim().toLowerCase();
                            if (role === 'satpam' || role === 'anggota') {
                                container.style.cssText = 'display: block !important; visibility: visible !important; opacity: 1 !important;';
                                container.classList.remove('hidden');
                                select.required = true;
                            } else {
                                container.style.cssText = 'display: none !important;';
                                container.classList.add('hidden');
                                select.required = false;
                                select.value = '';
                            }
                        }
                    } catch(e) {
                        // Abaikan semua error, lanjut jalan lagi nanti
                    }
                }, 50);
                </script>
                <div class="flex gap-3 mt-6">
                    <button type="button" onclick="hideAddUserModal()" class="flex-1 bg-slate-500/20 text-slate-300 px-6 py-3 rounded-2xl font-bold">Batal</button>
                    <button type="submit" class="flex-1 bg-emerald-500 text-slate-950 px-6 py-3 rounded-2xl font-bold">✅ Simpan User</button>
                </div>
            </form>
        </div>
    </div>
    """, 
    total_users=total_users, 
    total_satpam=total_satpam, 
    total_bujp=total_bujp, 
    total_geofences=total_geofences, 
    users_all=users_all, 
    geofences=geofences, 
    logs=logs, 
    roles=ROLES, 
    me=user, 
    reset_pw=DEFAULT_RESET_PASSWORD)

    # ✅ FIX BUG: bujp_list yang sudah di query tapi tidak pernah dikirim ke template!
    return render_page("Admin", body, user, bujp_list=bujp_list)


@app.route("/admin/users/create", methods=["POST"])
@login_required
@roles_required("admin")
def admin_user_create():
    username = (request.form.get("username") or "").strip()
    full_name = (request.form.get("full_name") or "").strip()
    role = (request.form.get("role") or "").strip()
    password = request.form.get("password") or ""
    bujp_id = request.form.get("bujp_id", type=int) or None
    
    error_msg = None
    if not username:
        error_msg = "Username wajib diisi"
    elif not full_name:
        error_msg = "Nama lengkap wajib diisi"
    elif role not in ROLES:
        error_msg = "Role tidak valid"
    elif len(password) < 4:
        error_msg = "Password minimal 4 karakter"
    # ✅ VALIDASI BARU: untuk role satpam/anggota, bujp_id WAJIB diisi
    elif role in ('satpam', 'anggota') and not bujp_id:
        error_msg = "Untuk role Satpam / Anggota, wajib memilih BUJP terlebih dahulu"
    
    if error_msg:
        return f"<script>alert('{error_msg}'); window.history.back();</script>", 400
        
    try:
        db = get_db()
        ts = now_str()
        
        # ✅ SET DEFAULT: bujp_verified = 0 ketika dibuat oleh admin (akan diverifikasi oleh BUJP)
        cur = db.execute(
            "INSERT INTO users (username, full_name, role, password_hash, is_active, bujp_id, bujp_verified, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, 0, ?, ?)",
            (username, full_name, role, hash_password(password), bujp_id, ts, ts),
        )
        user_id = cur.lastrowid
        db.commit()
        
        log_action("ADMIN_CREATE_USER", "user", user_id, f"username={username};role={role};bujp_id={bujp_id};bujp_verified=0")
        
        # ✅ KIRIM NOTIFIKASI KE ADMIN BUJP TERKAIT
        if bujp_id:
            # TODO: Tambahkan notifikasi push ke admin BUJP
            bujp = db.execute("SELECT nama_bujp, user_id FROM bujp WHERE id = ?", (bujp_id,)).fetchone()
            if bujp:
                log_action("BUJP_NEW_MEMBER_PENDING", "bujp", bujp_id, f"satpam_baru_id={user_id};satpam_nama={full_name}")
        
    except sqlite3.IntegrityError:
        log_action("ADMIN_CREATE_USER_FAILED", "user", None, f"username={username};duplicate=1")
        return "<script>alert('Username sudah terdaftar!'); window.history.back();</script>", 400
        
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/edit", methods=["POST"])
@login_required
@roles_required("admin")
def admin_user_edit(user_id):
    full_name = (request.form.get("full_name") or "").strip()
    role = (request.form.get("role") or "").strip()
    is_active = 1 if (request.form.get("is_active") or "1") == "1" else 0
    if not full_name or role not in ROLES:
        abort(400)
    get_db().execute("UPDATE users SET full_name=?, role=?, is_active=?, updated_at=? WHERE id=?", (full_name, role, is_active, now_str(), user_id))
    get_db().commit()
    log_action("ADMIN_EDIT_USER", "user", user_id, f"role={role};is_active={is_active}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/reset", methods=["POST"])
@login_required
@roles_required("admin")
def admin_user_reset(user_id):
    get_db().execute("UPDATE users SET password_hash=?, updated_at=? WHERE id=?", (hash_password(DEFAULT_RESET_PASSWORD), now_str(), user_id))
    get_db().commit()
    log_action("ADMIN_RESET_PASSWORD", "user", user_id, f"default={DEFAULT_RESET_PASSWORD}")
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def admin_user_delete(user_id):
    if user_id == session.get("user_id"):
        abort(400)
    get_db().execute("DELETE FROM users WHERE id=?", (user_id,))
    get_db().commit()
    log_action("ADMIN_DELETE_USER", "user", user_id)
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/users/<int:user_id>/reset-locations", methods=["POST"])
@login_required
@roles_required("admin")
def admin_reset_locations(user_id):
    # Hapus SEMUA riwayat lokasi dan koordinat satpam ini
    get_db().execute("DELETE FROM locations WHERE user_id = ?", (user_id,))
    
    # HAPUS JUGA ABSENSI HARI INI AGAR SATPAM HARUS ABSEN ULANG
    today = datetime.now().strftime("%Y-%m-%d")
    get_db().execute("DELETE FROM absensi WHERE user_id = ? AND DATE(tanggal) = ?", (user_id, today))
    
    get_db().commit()
    log_action("ADMIN_RESET_LOCATIONS", "user", user_id, f"reset_absensi={today}")
    
    # KIRIM NOTIF LANGSUNG KE SATPAM TERKAIT JIKA SEDANG ONLINE
    with WS_LOCK:
        if user_id in SATPAM_SOCKETS:
            for ws in SATPAM_SOCKETS[user_id]:
                safe_ws_send(ws, {
                    "type": "admin_reset",
                    "message": "⚠️ Lokasi & Absensi Anda telah direset oleh Admin. Silahkan Absen KEMBALI hari ini!",
                    "server_time": now_str()
                })
    
    # Kirim update ke semua monitor agar marker dihapus
    broadcast_presence()
    
    return redirect(url_for("admin_dashboard"))


@app.route("/admin/geofence/save", methods=["POST"])
@login_required
@roles_required("admin")
def admin_geofence_save():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    geojson = data.get("geojson")
    if not name or not geojson:
        return jsonify({"ok": False, "error": "Data tidak lengkap"}), 400
    cur = get_db().execute(
        "INSERT INTO geofences (name, geojson, created_by, created_at, updated_at) VALUES (?, ?, ?, ?, ?)",
        (name, json.dumps(geojson), session.get("user_id"), now_str(), now_str()),
    )
    get_db().commit()
    log_action("ADMIN_CREATE_GEOFENCE", "geofence", cur.lastrowid, name)
    broadcast_monitors({"type": "geofences", "payload": get_geofences_data(), "server_time": now_str()})
    return jsonify({"ok": True, "id": cur.lastrowid})


@app.route("/admin/geofence/<int:geofence_id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def admin_geofence_delete(geofence_id):
    get_db().execute("DELETE FROM geofences WHERE id=?", (geofence_id,))
    get_db().commit()
    log_action("ADMIN_DELETE_GEOFENCE", "geofence", geofence_id)
    broadcast_monitors({"type": "geofences", "payload": get_geofences_data(), "server_time": now_str()})
    return redirect(url_for("admin_dashboard"))


# ==============================================
# ✅ ROUTE CRUD MANAJEMEN NOMOR REKENING
# ==============================================

@app.route("/admin/rekening/tambah", methods=["POST"])
@login_required
@roles_required("admin")
def admin_rekening_tambah():
    db = get_db()
    ts = now_str()
    user = current_user()
    
    nama_bank = (request.form.get("nama_bank") or "").strip()
    nomor_rekening = (request.form.get("nomor_rekening") or "").strip()
    atas_nama = (request.form.get("atas_nama") or "").strip()
    keterangan = (request.form.get("keterangan") or "").strip()
    urutan = int(request.form.get("urutan") or 0)
    
    if not nama_bank or not nomor_rekening or not atas_nama:
        abort(400, "Semua field wajib diisi")
    
    cur = db.execute("""
        INSERT INTO rekening_bank (
            nama_bank, nomor_rekening, atas_nama, keterangan, urutan, is_active,
            created_at, updated_at, created_by, updated_by
        ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
    """, (
        nama_bank, nomor_rekening, atas_nama, keterangan, urutan,
        ts, ts, user["id"], user["id"]
    ))
    
    rekening_id = cur.lastrowid
    
    # ✅ CATAT HISTORY
    db.execute("""
        INSERT INTO rekening_history (
            rekening_id, aksi, data_baru, user_id, created_at, keterangan
        ) VALUES (?, 'tambah', ?, ?, ?, ?)
    """, (
        rekening_id,
        json.dumps({
            "nama_bank": nama_bank,
            "nomor_rekening": nomor_rekening,
            "atas_nama": atas_nama,
            "keterangan": keterangan,
            "urutan": urutan
        }),
        user["id"],
        ts,
        "Rekening baru ditambahkan"
    ))
    
    db.commit()
    log_action("ADMIN_TAMBAH_REKENING", "rekening_bank", rekening_id)
    
    return redirect(url_for("admin_dashboard") + "#tabRekening")


@app.route("/admin/rekening/<int:id>/edit", methods=["POST"])
@login_required
@roles_required("admin")
def admin_rekening_edit(id):
    db = get_db()
    ts = now_str()
    user = current_user()
    
    # Ambil data lama sebelum diubah
    data_lama = db.execute("SELECT * FROM rekening_bank WHERE id = ?", (id,)).fetchone()
    if not data_lama:
        abort(404)
    
    nama_bank = (request.form.get("nama_bank") or "").strip()
    nomor_rekening = (request.form.get("nomor_rekening") or "").strip()
    atas_nama = (request.form.get("atas_nama") or "").strip()
    keterangan = (request.form.get("keterangan") or "").strip()
    urutan = int(request.form.get("urutan") or 0)
    
    if not nama_bank or not nomor_rekening or not atas_nama:
        abort(400, "Semua field wajib diisi")
    
    db.execute("""
        UPDATE rekening_bank SET
            nama_bank = ?,
            nomor_rekening = ?,
            atas_nama = ?,
            keterangan = ?,
            urutan = ?,
            updated_at = ?,
            updated_by = ?
        WHERE id = ?
    """, (
        nama_bank, nomor_rekening, atas_nama, keterangan, urutan,
        ts, user["id"], id
    ))
    
    # ✅ CATAT HISTORY PERUBAHAN
    db.execute("""
        INSERT INTO rekening_history (
            rekening_id, aksi, data_lama, data_baru, user_id, created_at, keterangan
        ) VALUES (?, 'ubah', ?, ?, ?, ?, ?)
    """, (
        id,
        json.dumps(dict(data_lama)),
        json.dumps({
            "nama_bank": nama_bank,
            "nomor_rekening": nomor_rekening,
            "atas_nama": atas_nama,
            "keterangan": keterangan,
            "urutan": urutan
        }),
        user["id"],
        ts,
        "Data rekening diubah"
    ))
    
    db.commit()
    log_action("ADMIN_EDIT_REKENING", "rekening_bank", id)
    
    return redirect(url_for("admin_dashboard") + "#tabRekening")


@app.route("/admin/rekening/<int:id>/toggle", methods=["POST"])
@login_required
@roles_required("admin")
def admin_rekening_toggle(id):
    db = get_db()
    ts = now_str()
    user = current_user()
    
    rekening = db.execute("SELECT id, is_active FROM rekening_bank WHERE id = ?", (id,)).fetchone()
    if not rekening:
        abort(404)
    
    status_baru = 0 if rekening["is_active"] == 1 else 1
    aksi = "nonaktifkan" if status_baru == 0 else "aktifkan"
    
    db.execute("""
        UPDATE rekening_bank SET is_active = ?, updated_at = ?, updated_by = ? WHERE id = ?
    """, (status_baru, ts, user["id"], id))
    
    # ✅ CATAT HISTORY
    db.execute("""
        INSERT INTO rekening_history (
            rekening_id, aksi, user_id, created_at, keterangan
        ) VALUES (?, ?, ?, ?, ?)
    """, (
        id,
        aksi,
        user["id"],
        ts,
        f"Status rekening diubah menjadi {'nonaktif' if status_baru == 0 else 'aktif'}"
    ))
    
    db.commit()
    log_action(f"ADMIN_{aksi.upper()}_REKENING", "rekening_bank", id)
    
    return redirect(url_for("admin_dashboard") + "#tabRekening")


@app.route("/admin/rekening/<int:id>/delete", methods=["POST"])
@login_required
@roles_required("admin")
def admin_rekening_delete(id):
    db = get_db()
    ts = now_str()
    user = current_user()
    
    try:
        # ✅ [PERBAIKAN FINAL v3]: MATIKAN FOREIGN KEY PADA AWAL FUNGSI DI KONEKSI YANG SAMA
        db.execute("PRAGMA foreign_keys = OFF")
        
        # Ambil data sebelum dihapus
        data_lama = db.execute("SELECT * FROM rekening_bank WHERE id = ?", (id,)).fetchone()
        if not data_lama:
            db.execute("PRAGMA foreign_keys = ON")
            abort(404)
        
        # ✅ CATAT HISTORY
        db.execute("""
            INSERT INTO rekening_history (
                rekening_id, aksi, data_lama, user_id, created_at, keterangan
            ) VALUES (?, 'hapus', ?, ?, ?, ?)
        """, (
            id,
            json.dumps(dict(data_lama)),
            user["id"],
            ts,
            f"Rekening ID #{id} dihapus permanen oleh Admin"
        ))
        
        # ✅ HAPUS DATA UTAMA
        db.execute("DELETE FROM rekening_bank WHERE id = ?", (id,))
        
        # ✅ COMMIT TERLEBIH DAHULU BARU AKTIFKAN KEMBALI FK
        db.commit()
        
        # ✅ AKTIFKAN KEMBALI FOREIGN KEY
        db.execute("PRAGMA foreign_keys = ON")
        
        log_action("ADMIN_HAPUS_REKENING", "rekening_bank", id)
        
        return redirect(url_for("admin_rekening_management"))
        
    except Exception as e:
        # ✅ SELALU AKTIFKAN KEMBALI FOREIGN KEY JIKA TERJADI ERROR
        try:
            db.execute("PRAGMA foreign_keys = ON")
            db.rollback()
        except:
            pass
            
        logger.error(f"❌ ERROR DELETE REKENING ID {id}: {str(e)}", exc_info=True)
        abort(500, str(e))


@app.route("/admin/rekening")
@app.route("/admin/rekening/save", methods=["POST"])
@login_required
@roles_required("admin")
def admin_rekening_save():
    db = get_db()
    ts = now_str()
    user = current_user()
    
    nama_bank = (request.form.get("nama_bank") or "").strip()
    nomor_rekening = (request.form.get("nomor_rekening") or "").strip()
    atas_nama = (request.form.get("atas_nama") or "").strip()
    keterangan = (request.form.get("keterangan") or "").strip()
    
    if not nama_bank or not nomor_rekening or not atas_nama:
        return jsonify({"ok": False, "error": "Semua field wajib diisi"})
    
    try:
        cur = db.execute("""
            INSERT INTO rekening_bank (
                nama_bank, nomor_rekening, atas_nama, keterangan, urutan, is_active,
                created_at, updated_at, created_by, updated_by
            ) VALUES (?, ?, ?, ?, ?, 1, ?, ?, ?, ?)
        """, (
            nama_bank, nomor_rekening, atas_nama, keterangan, 0,
            ts, ts, user["id"], user["id"]
        ))
        
        rekening_id = cur.lastrowid
        
        # ✅ CATAT HISTORY
        db.execute("""
            INSERT INTO rekening_history (
                rekening_id, aksi, data_baru, user_id, created_at, keterangan
            ) VALUES (?, 'tambah', ?, ?, ?, ?)
        """, (
            rekening_id,
            json.dumps({
                "nama_bank": nama_bank,
                "nomor_rekening": nomor_rekening,
                "atas_nama": atas_nama,
                "keterangan": keterangan
            }),
            user["id"],
            ts,
            "Rekening baru ditambahkan melalui dashboard admin"
        ))
        
        # ✅ [FIX BUG] TIDAK ADA db.commit() DISINI SEBELUMNYA!
        db.commit()
        
        log_action("ADMIN_SAVE_REKENING", "rekening_bank", rekening_id)
        
        return jsonify({"ok": True, "id": rekening_id, "message": "Rekening berhasil disimpan"})
        
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)})


@app.route("/admin/rekening/management")
@login_required
@roles_required("admin")
def admin_rekening_management():
    user = current_user()
    db = get_db()
    
    # ✅ MANAJEMEN NOMOR REKENING
    rekening_list = db.execute("""
        SELECT * FROM rekening_bank 
        ORDER BY urutan ASC, id ASC
    """).fetchall()
    
    body = render_template_string("""
    <div class="mt-6">
        <div class="flex justify-between items-center mb-6 flex-wrap gap-4">
            <div>
                <h1 class="text-3xl font-black">💳 Manajemen Nomor Rekening Resmi</h1>
                <p class="text-slate-400 mt-1">Kelola daftar nomor rekening yang digunakan untuk pembayaran KTA SATPAM</p>
            </div>
            <button onclick="showAddRekeningModal()" class="px-4 py-3 rounded-2xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold transition">
                + Tambah Rekening Baru
            </button>
        </div>

<!-- Modal Tambah Rekening -->
<div id="addRekeningModal" class="fixed inset-0 bg-black/90 z-50 hidden flex items-center justify-center p-2 sm:p-4">
    <div class="glass rounded-3xl w-full max-w-lg max-h-[95vh] overflow-auto">
        <div class="sticky top-0 bg-gradient-to-b from-[#0f172a] to-[#0f172a]/95 p-4 sm:p-6 border-b border-white/10">
            <div class="flex justify-between items-center gap-3">
                <div class="text-xl sm:text-2xl font-black text-emerald-400">➕ TAMBAH REKENING BARU</div>
                <button onclick="closeAddRekeningModal()" class="w-12 h-12 rounded-2xl bg-white/5 hover:bg-white/10 text-xl flex items-center justify-center transition">✕</button>
            </div>
        </div>
        <div class="p-4 sm:p-6 space-y-4">
            <form id="formAddRekening" onsubmit="submitRekening(event)">
                <div class="space-y-3">
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Nama Bank</label>
                        <input type="text" name="nama_bank" required class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Nomor Rekening</label>
                        <input type="text" name="nomor_rekening" required class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Atas Nama</label>
                        <input type="text" name="atas_nama" required class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition">
                    </div>
                    <div>
                        <label class="text-xs text-slate-400 mb-1 block">Keterangan (Opsional)</label>
                        <textarea name="keterangan" rows="2" class="w-full px-4 py-3 rounded-xl bg-white/5 border border-white/10 focus:border-emerald-500 outline-none transition"></textarea>
                    </div>
                </div>
                <div class="grid grid-cols-2 gap-3 pt-4">
                    <button type="button" onclick="closeAddRekeningModal()" class="px-4 py-3 rounded-2xl bg-white/5 border border-white/10 text-center font-bold hover:bg-white/10 transition">
                        ❌ BATAL
                    </button>
                    <button type="submit" class="px-4 py-3 rounded-2xl bg-emerald-500 text-slate-950 text-center font-bold hover:bg-emerald-400 transition">
                        ✅ SIMPAN
                    </button>
                </div>
            </form>
        </div>
    </div>
</div>

<script>
window.showAddRekeningModal = function() {
    document.getElementById('addRekeningModal').classList.remove('hidden');
}

window.closeAddRekeningModal = function() {
    document.getElementById('addRekeningModal').classList.add('hidden');
    document.getElementById('formAddRekening').reset();
}

window.submitRekening = async function(e) {
    e.preventDefault();
    
    const form = document.getElementById('formAddRekening');
    const formData = new FormData(form);
    const submitBtn = form.querySelector('button[type="submit"]');
    const originalText = submitBtn.textContent;
    
    try {
        submitBtn.disabled = true;
        submitBtn.textContent = '⏳ Menyimpan...';
        
        const response = await fetch('/admin/rekening/save', {
            method: 'POST',
            body: formData,
            credentials: 'same-origin'
        });
        
        const result = await response.json();
        
        if (result.ok) {
            alert('✅ Rekening berhasil disimpan!');
            closeAddRekeningModal();
            window.location.reload();
        } else {
            alert('❌ Gagal menyimpan: ' + (result.error || 'Terjadi kesalahan'));
        }
    } catch (err) {
        alert('❌ Gagal terhubung ke server: ' + err.message);
    } finally {
        submitBtn.disabled = false;
        submitBtn.textContent = originalText;
    }
}

window.editRekening = function(id, nama_bank, nomor_rekening, atas_nama, keterangan, is_active) {
    alert(`Fungsi Edit Rekening ID: ${id} sudah siap diimplementasikan`);
}

window.toggleRekening = async function(id, status_baru) {
    if (!confirm(status_baru == 1 ? '✅ Aktifkan rekening ini?' : '🔴 Nonaktifkan rekening ini?')) return;
    
    try {
        const response = await fetch(`/admin/rekening/${id}/toggle`, {
            method: 'POST',
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            alert(status_baru == 1 ? '✅ Rekening berhasil diaktifkan!' : '🔴 Rekening berhasil dinonaktifkan!');
            window.location.reload();
        } else {
            alert('❌ Gagal merubah status');
        }
    } catch (err) {
        alert('❌ Gagal terhubung ke server: ' + err.message);
    }
}

window.deleteRekening = async function(id) {
    if (!confirm('🗑️ YAKIN INGIN MENGHAPUS REKENING INI SECARA PERMANEN?')) return;
    
    try {
        const response = await fetch(`/admin/rekening/${id}/delete`, {
            method: 'POST',
            credentials: 'same-origin'
        });
        
        if (response.ok) {
            alert('✅ Rekening berhasil dihapus!');
            window.location.reload();
        } else {
            alert('❌ Gagal menghapus rekening');
        }
    } catch (err) {
        alert('❌ Gagal terhubung ke server: ' + err.message);
    }
}

window.showRekeningHistory = async function(id) {
    alert(`📋 Tampilkan History Perubahan Rekening ID: ${id}`);
}
</script>
        
        <div class="p-3 mb-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20 text-sm text-slate-300">
            ✅ Daftar nomor rekening yang tercantum disini akan muncul otomatis di halaman pengajuan pembayaran KTA SATPAM. Setiap perubahan akan dicatat di history dengan nama admin yang mengubah.
        </div>
        
        <div class="glass rounded-3xl p-5">
            <div class="overflow-auto max-h-[75vh]">
                <table class="w-full text-sm">
                    <thead class="sticky top-0 bg-[#0f172a] z-10">
                        <tr class="border-b border-white/10 text-slate-400">
                            <th class="py-3 px-2 text-left">No</th>
                            <th class="py-3 px-2 text-left">Nama Bank</th>
                            <th class="py-3 px-2 text-left">Nomor Rekening</th>
                            <th class="py-3 px-2 text-left">Atas Nama</th>
                            <th class="py-3 px-2 text-center">Status</th>
                            <th class="py-3 px-2 text-center">Update</th>
                            <th class="py-3 px-2 text-center">Aksi</th>
                        </tr>
                    </thead>
                    <tbody>
                    {% for rekening in rekening_list %}
                        <tr class="border-b border-white/5 hover:bg-white/5 transition">
                            <td class="py-2 px-2 text-slate-500 font-mono">#{{ rekening.id }}</td>
                            <td class="py-2 px-2 font-bold">{{ rekening.nama_bank }}</td>
                            <td class="py-2 px-2 font-mono text-cyan-300">{{ rekening.nomor_rekening }}</td>
                            <td class="py-2 px-2">{{ rekening.atas_nama }}</td>
                            <td class="py-2 px-2 text-center">
                                {% if rekening.is_active %}
                                    <span class="text-emerald-400">✅ Aktif</span>
                                {% else %}
                                    <span class="text-slate-500">⚪ Nonaktif</span>
                                {% endif %}
                            </td>
                            <td class="py-2 px-2 text-center text-slate-500 text-xs">{{ rekening.updated_at.split(' ')[0] }}</td>
                            <td class="py-2 px-2 text-center">
                                <div class="flex items-center justify-center gap-1">
                                    <button onclick="editRekening({{ rekening.id }}, '{{ rekening.nama_bank.replace("'", "\\'") }}', '{{ rekening.nomor_rekening }}', '{{ rekening.atas_nama.replace("'", "\\'") }}', '{{ rekening.keterangan.replace("'", "\\'") }}', {{ rekening.is_active }})" class="w-7 h-7 rounded-lg bg-cyan-500/20 text-cyan-400 hover:bg-cyan-500/30">✏️</button>
                                    <button onclick="toggleRekening({{ rekening.id }}, {{ 0 if rekening.is_active else 1 }})" class="w-7 h-7 rounded-lg bg-amber-500/20 text-amber-400 hover:bg-amber-500/30">
                                        {% if rekening.is_active %}🔴{% else %}🟢{% endif %}
                                    </button>
                                    <button onclick="deleteRekening({{ rekening.id }})" class="w-7 h-7 rounded-lg bg-red-500/20 text-red-400 hover:bg-red-500/30">🗑️</button>
                                    <button onclick="showRekeningHistory({{ rekening.id }})" class="w-7 h-7 rounded-lg bg-violet-500/20 text-violet-400 hover:bg-violet-500/30">📋</button>
                                </div>
                            </td>
                        </tr>
                    {% else %}
                        <tr><td colspan="7" class="py-8 text-center text-slate-400">Belum ada nomor rekening yang didaftarkan</td></tr>
                    {% endfor %}
                    </tbody>
                </table>
            </div>
        </div>
    </div>
    """, rekening_list=rekening_list)

    return render_page("Manajemen Rekening", body, user)


@app.route("/admin/rekening/<int:id>/history")
@login_required
@roles_required("admin")
def admin_rekening_history(id):
    db = get_db()
    
    history = db.execute("""
        SELECT h.*, u.full_name, u.username
        FROM rekening_history h
        JOIN users u ON u.id = h.user_id
        WHERE h.rekening_id = ?
        ORDER BY h.id DESC
    """, (id,)).fetchall()
    
    return jsonify([dict(row) for row in history])


@app.route("/api/geofences")
@login_required
def api_geofences():
    return jsonify(get_geofences_data())


@app.route("/api/location", methods=["POST"])
@login_required
@roles_required("satpam")
def api_location():
    data = request.get_json(silent=True) or {}
    try:
        lat = float(data.get("lat"))
        lng = float(data.get("lng"))
        accuracy = float(data.get("accuracy")) if data.get("accuracy") is not None else None
        speed = float(data.get("speed")) if data.get("speed") is not None else None
        altitude = float(data.get("altitude")) if data.get("altitude") is not None else None
    except Exception:
        return jsonify({"ok": False, "error": "Koordinat tidak valid"}), 400
    if not (-90 <= lat <= 90 and -180 <= lng <= 180):
        return jsonify({"ok": False, "error": "Koordinat di luar batas"}), 400
    payload = persist_location(session["user_id"], lat, lng, accuracy, speed, altitude, source="http")
    log_action("SATPAM_SEND_LOCATION_HTTP", "location", None, f"lat={lat:.6f};lng={lng:.6f}")
    broadcast_monitors({"type": "location_update", "payload": payload, "server_time": now_str()})
    return jsonify({"ok": True, "payload": payload})


@app.route("/api/locations/latest")
@login_required
@roles_required("direktur_binmas", "admin")
def api_locations_latest():
    snapshot = latest_snapshot()
    for item in snapshot:
        item["geofences"] = geofence_hits(item["lat"], item["lng"])
    return jsonify(snapshot)


@sock.route('/ws/location')
def ws_location(ws):
    user = current_user()
    if not user or user['role'] != 'satpam':
        try:
            ws.close()
        except Exception:
            pass
        return
    uid = user['id']
    with WS_LOCK:
        SATPAM_SOCKETS.setdefault(uid, set()).add(ws)
    log_action('WS_SATPAM_CONNECTED', 'user', uid, 'live tracking')
    broadcast_presence()
    safe_ws_send(ws, {'type': 'welcome', 'payload': {'user_id': uid, 'server_time': now_str()}})
    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break
            try:
                msg = json.loads(raw)
            except Exception:
                safe_ws_send(ws, {'type': 'error', 'message': 'JSON tidak valid'})
                continue
            msg_type = msg.get('type')
            if msg_type == 'ping':
                safe_ws_send(ws, {'type': 'pong', 'server_time': now_str()})
                continue
            if msg_type != 'location':
                safe_ws_send(ws, {'type': 'error', 'message': 'Tipe pesan tidak didukung'})
                continue
            try:
                lat = float(msg.get('lat'))
                lng = float(msg.get('lng'))
                accuracy = float(msg.get('accuracy')) if msg.get('accuracy') is not None else None
                speed = float(msg.get('speed')) if msg.get('speed') is not None else None
                altitude = float(msg.get('altitude')) if msg.get('altitude') is not None else None
            except Exception:
                safe_ws_send(ws, {'type': 'error', 'message': 'Koordinat tidak valid'})
                continue
            if not (-90 <= lat <= 90 and -180 <= lng <= 180):
                safe_ws_send(ws, {'type': 'error', 'message': 'Koordinat di luar batas'})
                continue
            payload = persist_location(uid, lat, lng, accuracy, speed, altitude, source='ws')
            log_action('SATPAM_SEND_LOCATION_WS', 'location', None, f'lat={lat:.6f};lng={lng:.6f}')
            safe_ws_send(ws, {'type': 'ack', 'payload': payload, 'server_time': now_str()})
            broadcast_monitors({'type': 'location_update', 'payload': payload, 'server_time': now_str()})
    finally:
        with WS_LOCK:
            sockset = SATPAM_SOCKETS.get(uid, set())
            sockset.discard(ws)
            if not sockset and uid in SATPAM_SOCKETS:
                SATPAM_SOCKETS.pop(uid, None)
        try:
            log_action('WS_SATPAM_DISCONNECTED', 'user', uid, 'live tracking')
        except Exception:
            pass
        try:
            broadcast_presence()
        except Exception:
            pass


@sock.route('/ws/monitor')
def ws_monitor(ws):
    user = current_user()
    if not user or user['role'] not in ('direktur_binmas', 'admin'):
        try:
            ws.close()
        except Exception:
            pass
        return
    with WS_LOCK:
        MONITOR_SOCKETS.add(ws)
    log_action('WS_MONITOR_CONNECTED', 'user', user['id'], user['role'])
    safe_ws_send(ws, {'type': 'snapshot', 'payload': latest_snapshot(), 'server_time': now_str()})
    safe_ws_send(ws, {'type': 'geofences', 'payload': get_geofences_data(), 'server_time': now_str()})
    try:
        while True:
            raw = ws.receive()
            if raw is None:
                break
            try:
                msg = json.loads(raw)
            except Exception:
                continue
            if msg.get('type') == 'ping':
                safe_ws_send(ws, {'type': 'pong', 'server_time': now_str()})
            elif msg.get('type') == 'resync':
                safe_ws_send(ws, {'type': 'snapshot', 'payload': latest_snapshot(), 'server_time': now_str()})
    finally:
        with WS_LOCK:
            MONITOR_SOCKETS.discard(ws)
        try:
            log_action('WS_MONITOR_DISCONNECTED', 'user', user['id'], user['role'])
        except Exception:
            pass


# ==============================
# FITUR MAPS PERUSAHAAN DIREKTUR
# ==============================

# ROUTE MAPS BUJP - BISA DIAKSES OLEH ADMIN DAN DIREKTUR
@app.route("/direktur/maps")
@app.route("/admin/maps")
@login_required
@roles_required("direktur_binmas", "admin")
def direktur_maps_bujp():
    db = get_db()
    bujp_list = db.execute("""
        SELECT id, nama_bujp, alamat, latitude, longitude, geofence_radius, no_izin, penanggung_jawab, no_hp
        FROM bujp 
        WHERE is_active = 1
        ORDER BY nama_bujp ASC
    """).fetchall()
    
    bujp_data = []
    for b in bujp_list:
        item = dict(b)
        if item['latitude'] is not None and item['longitude'] is not None:
            bujp_data.append(item)
    
    body = render_template_string("""
    <style>
    .bujp-popup {
        min-width: 280px;
        padding: 12px;
    }
    </style>
    
    <div class="mt-6">
        <div class="text-center mb-6">
            <h1 class="text-4xl font-black mb-2">🗺️ PETA LOKASI BUJP TERDAFTAR</h1>
            <p class="text-lg text-slate-400">Peta Geofence Semua Perusahaan Jasa Pengamanan Binmas</p>
        </div>
        
        <!-- MAPS UTAMA -->
        <div class="glass rounded-3xl p-6 mb-6">
            <div id="bujpMap" class="h-[75vh] w-full rounded-2xl"></div>
        </div>
        
        <!-- DAFTAR BUJP -->
        <div class="glass rounded-3xl p-6">
            <div class="flex items-center justify-between mb-5">
                <h2 class="text-xl font-bold">📋 Daftar BUJP Terdaftar</h2>
                <span class="px-3 py-1 rounded-full bg-amber-500/10 border border-amber-500/20 text-amber-300 text-sm font-bold">
                    {{ bujp_data|length }} Perusahaan
                </span>
            </div>
            
            <div class="grid md:grid-cols-2 lg:grid-cols-3 gap-3">
            {% for bujp in bujp_data %}
                <div class="p-3 rounded-xl bg-white/5 border border-white/10 hover:bg-amber-500/10 hover:border-amber-500/20 cursor-pointer transition" onclick="focusBujp({{ bujp.latitude }}, {{ bujp.longitude }})">
                    <div class="flex items-center gap-3">
                        <div class="w-10 h-10 rounded-xl bg-amber-500/20 flex items-center justify-center flex-shrink-0">
                            🏢
                        </div>
                        <div class="flex-1 min-w-0">
                            <div class="font-bold text-sm truncate">{{ bujp.nama_bujp }}</div>
                            <div class="text-[11px] text-slate-400 truncate">{{ bujp.alamat or 'Alamat belum diisi' }}</div>
                            <div class="text-[10px] text-cyan-300 mt-1">🟡 Radius {{ bujp.geofence_radius or 100 }}m</div>
                        </div>
                    </div>
                </div>
            {% endfor %}
            </div>
        </div>
    </div>
    
    <script>
    const map = L.map('bujpMap').setView([-6.2, 106.816666], 12);
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        maxZoom: 19,
        attribution: '&copy; OpenStreetMap contributors'
    }).addTo(map);
    
    const bujpList = {{ bujp_data|tojson }};
    const markers = {};
    const geofenceCircles = {};
    
    bujpList.forEach(bujp => {
        if (bujp.latitude && bujp.longitude) {
            const pos = [bujp.latitude, bujp.longitude];
            
            // Marker utama BUJP
            const markerIcon = L.divIcon({
                className: 'bujp-marker',
                html: `<div style="
                    background: linear-gradient(135deg, #f59e0b, #d97706);
                    width: 28px;
                    height: 28px;
                    border-radius: 50%;
                    border: 4px solid white;
                    box-shadow: 0 0 20px rgba(245, 158, 11, 0.6);
                    display: flex;
                    align-items: center;
                    justify-content: center;
                    font-weight: 900;
                    font-size: 12px;
                    color: white;
                ">🏢</div>`,
                iconSize: [28, 28],
                iconAnchor: [14, 14]
            });
            
            markers[bujp.id] = L.marker(pos, {icon: markerIcon}).addTo(map);
            
            // Geofence Radius BUJP
            const radius = bujp.geofence_radius || 100;
            geofenceCircles[bujp.id] = L.circle(pos, {
                radius: radius,
                color: '#f59e0b',
                fillColor: '#f59e0b',
                fillOpacity: 0.12,
                weight: 2,
                dashArray: '5, 5'
            }).addTo(map);
            
            // Popup detail
            markers[bujp.id].bindPopup(`
                <div class="bujp-popup">
                    <div class="font-black text-xl mb-2">🏢 ${bujp.nama_bujp}</div>
                    <div class="text-sm space-y-1">
                        <div>📋 No Izin: ${bujp.no_izin || '-'}</div>
                        <div>👤 PJ: ${bujp.penanggung_jawab || '-'}</div>
                        <div>📞 HP: ${bujp.no_hp || '-'}</div>
                        <div>📍 Alamat: ${bujp.alamat || '-'}</div>
                        <div>🧭 Koordinat: ${bujp.latitude}, ${bujp.longitude}</div>
                        <div>🟡 Geofence Radius: ${radius} meter</div>
                    </div>
                </div>
            `, {maxWidth: 320});
        }
    });
    
    // Fokus ke BUJP ketika di klik daftar
    window.focusBujp = function(lat, lng) {
        map.setView([lat, lng], 17);
    }
    
    // Auto fit semua markers
    setTimeout(() => {
        const markerValues = Object.values(markers);
        if (markerValues.length > 0) {
            map.fitBounds(L.featureGroup(markerValues).getBounds().pad(0.15));
        }
    }, 500);
    </script>
    """, bujp_data=bujp_data)
    
    return render_page("Maps Perusahaan BUJP", body, current_user())


@app.errorhandler(403)
def forbidden(_e):
    body = """
    <div class="max-w-xl mx-auto mt-8 glass rounded-3xl p-6 text-center">
      <div class="text-5xl font-black text-red-300">403</div>
      <div class="text-xl font-bold mt-2">Akses ditolak</div>
      <p class="text-slate-400 mt-2">Role Anda tidak memiliki izin untuk membuka halaman ini.</p>
      <a href="/" class="inline-block mt-5 px-4 py-3 rounded-2xl bg-cyan-500 text-slate-950 font-black">Kembali</a>
    </div>
    """
    return render_page("403", body, current_user()), 403


@app.errorhandler(404)
def not_found(_e):
    body = """
    <div class="max-w-xl mx-auto mt-8 glass rounded-3xl p-6 text-center">
      <div class="text-5xl font-black text-amber-300">404</div>
      <div class="text-xl font-bold mt-2">Halaman tidak ditemukan</div>
      <a href="/" class="inline-block mt-5 px-4 py-3 rounded-2xl bg-cyan-500 text-slate-950 font-black">Kembali</a>
    </div>
    """
    return render_page("404", body, current_user()), 404



# 📁 UPLOAD BUKTI PEMBAYARAN KTA
@app.route("/satpam/kta/<int:id>/pilih-metode", methods=["POST"])
@login_required
@roles_required("satpam")
def satpam_kta_pilih_metode(id):
    user = current_user()
    db = get_db()
    ts = now_str()
    
    pengajuan = db.execute("SELECT * FROM kta_perpanjangan WHERE id = ? AND user_id = ?", (id, user["id"])).fetchone()
    if not pengajuan:
        abort(404)
    
    metode = request.form.get("metode") or ""
    if metode not in ('aplikasi', 'langsung'):
        abort(400)
    
    db.execute("""
        UPDATE kta_perpanjangan 
        SET metode_pembayaran = ?,
            tanggal_pengajuan = ?
        WHERE id = ?
    """, (metode, ts, id))
    db.commit()
    log_action(f"SATPAM_PILIH_METODE_BAYAR_{metode.upper()}", "kta_perpanjangan", id)
    
    return redirect(url_for("satpam_perpanjang_kta"))


@app.route("/satpam/kta/<int:id>/upload-bukti", methods=["POST"])
@login_required
@roles_required("satpam")
def satpam_kta_upload_bukti(id):
    user = current_user()
    db = get_db()
    ts = now_str()
    
    pengajuan = db.execute("SELECT * FROM kta_perpanjangan WHERE id = ? AND user_id = ?", (id, user["id"])).fetchone()
    if not pengajuan:
        abort(404)
    
    if 'bukti_pembayaran' in request.files:
        foto = request.files['bukti_pembayaran']
        if foto.filename != '':
            upload_dir = os.path.join(os.path.dirname(__file__), "uploads", "kta_pembayaran")
            os.makedirs(upload_dir, exist_ok=True)
            ext = os.path.splitext(foto.filename)[1]
            filename = f"kta_bayar_{user['id']}_{int(datetime.now().timestamp())}{ext}"
            file_path = os.path.join(upload_dir, filename)
            foto.save(file_path)
            
            db.execute("""
                UPDATE kta_perpanjangan 
                SET bukti_pembayaran_url = ?, 
                    tanggal_upload_bukti = ?, 
                    status_pembayaran = 'menunggu_verifikasi'
                WHERE id = ?
            """, (f"/uploads/kta_pembayaran/{filename}", ts, id))
            db.commit()
            log_action("SATPAM_UPLOAD_BUKTI_BAYAR_KTA", "kta_perpanjangan", id)
    
    return redirect(url_for("satpam_perpanjang_kta"))

# 📁 SERVE UPLOAD PEMBAYARAN
@app.route('/uploads/kta_pembayaran/<path:filename>')
def serve_kta_pembayaran(filename):
    upload_dir = os.path.join(os.path.dirname(__file__), "uploads", "kta_pembayaran")
    return send_from_directory(upload_dir, filename)

    # ✅ ADMIN KIRIM NOMOR REKENING
@app.route("/admin/kta/<int:id>/kirim-rekening", methods=["POST"])
@login_required
@roles_required("admin")
def admin_kta_kirim_rekening(id):
    db = get_db()
    ts = now_str()
    nomor_rekening = request.form.get("nomor_rekening") or ""
    catatan = request.form.get("catatan") or ""
    
    db.execute("""
        UPDATE kta_perpanjangan 
        SET nomor_rekening_admin = ?, 
            metode_pembayaran = 'aplikasi',
            catatan_admin = ?,
            tanggal_verifikasi = ?
        WHERE id = ?
    """, (nomor_rekening, catatan, ts, id))
    
    # ✅ [FIX BUG] TIDAK ADA db.commit() DISINI SEBELUMNYA!
    db.commit()
    
    log_action("ADMIN_KIRIM_REKENING_KTA", "kta_perpanjangan", id)
    return redirect(url_for("admin_kta_perpanjangan"))

# ✅ ADMIN VERIFIKASI PEMBAYARAN
@app.route("/admin/kta/<int:id>/verifikasi-pembayaran", methods=["POST"])
@login_required
@roles_required("admin")
def admin_kta_verifikasi_pembayaran(id):
    db = get_db()
    ts = now_str()
    admin_id = current_user()["id"]
    status = request.form.get("status") or "terverifikasi"
    catatan = request.form.get("catatan_verifikasi") or ""
    
    db.execute("""
        UPDATE kta_perpanjangan 
        SET status_pembayaran = ?, 
            catatan_verifikasi_pembayaran = ?,
            admin_verifikasi_pembayaran_id = ?,
            tanggal_verifikasi_pembayaran = ?
        WHERE id = ?
    """, (status, catatan, admin_id, ts, id))
    db.commit()
    log_action(f"ADMIN_VERIFIKASI_BAYAR_KTA_{status.upper()}", "kta_perpanjangan", id)
    return redirect(url_for("admin_kta_perpanjangan"))


@app.route("/satpam/perpanjang-kta", methods=["GET", "POST"])
@login_required
@roles_required("satpam")
def satpam_perpanjang_kta():
    user = current_user()
    
    # Fix IndexError: Cek apakah kolom kta_expiry_date sudah ada
    if 'kta_expiry_date' not in user.keys():
        # Jika kolom belum ada, jalankan ALTER TABLE manual sekali untuk menambahkan kolom
        try:
            db = get_db()
            db.execute("ALTER TABLE users ADD COLUMN kta_expiry_date TEXT DEFAULT ''")
            db.commit()
            # Reload ulang data user setelah kolom ditambahkan
            user = get_db().execute("SELECT * FROM users WHERE id=?", (user["id"],)).fetchone()
        except:
            pass  # Kolom sudah ada, abaikan error
    
    db = get_db()
    msg = ""
    error = ""
    
    # Cek apakah sudah ada pengajuan yang pending
    pending = db.execute("SELECT * FROM kta_perpanjangan WHERE user_id=? AND status='pending' ORDER BY id DESC LIMIT 1", (user["id"],)).fetchone()
    
    if request.method == "POST" and not pending:
        alasan = (request.form.get("alasan") or "").strip()
        if not alasan:
            error = "Alasan perpanjangan wajib diisi"
        else:
            ts = now_str()
            db.execute("""
                INSERT INTO kta_perpanjangan (
                    user_id, no_kta_lama, tanggal_pengajuan, alasan_perpanjangan, 
                    masa_berlaku_lama, status
                ) VALUES (?, ?, ?, ?, ?, 'pending')
            """, (
                user["id"],
                user["no_kta"],
                ts,
                alasan,
                user["kta_expiry_date"]
            ))
            cursor = db.execute("SELECT last_insert_rowid()")
            last_id = cursor.fetchone()[0]
            db.commit()
            log_action("SATPAM_AJUKAN_PERPANJANGAN_KTA", "kta_perpanjangan", last_id)
            msg = "✅ Pengajuan perpanjangan KTA berhasil dikirim! Silahkan tunggu verifikasi Admin."
            pending = db.execute("SELECT * FROM kta_perpanjangan WHERE user_id=? AND status='pending' ORDER BY id DESC LIMIT 1", (user["id"],)).fetchone()
    
    # Ambil riwayat perpanjangan
    riwayat = db.execute("SELECT * FROM kta_perpanjangan WHERE user_id=? ORDER BY id DESC LIMIT 10", (user["id"],)).fetchall()
    
    body = render_template_string("""
    <div class="max-w-xl mx-auto mt-6 space-y-6">
    
      <div class="glass rounded-3xl p-6">
        <h1 class="text-2xl font-black mb-2">🔄 Ajukan Perpanjangan KTA</h1>
        <p class="text-sm text-slate-400 mb-6">Isi form dibawah untuk mengajukan perpanjangan masa berlaku Kartu Tanda Anggota Satpam Binmas</p>
        
        {% if msg %}
        <div class="mb-4 p-3 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-200 text-sm">{{ msg }}</div>
        {% endif %}
        
        {% if error %}
        <div class="mb-4 p-3 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-200 text-sm">{{ error }}</div>
        {% endif %}
        
        {% if pending %}
        <div class="mb-6 p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20">
          <div class="text-center mb-4">
            <div class="text-4xl mb-2">⏳</div>
            <div class="font-bold text-amber-300">PENGAJUAN SEDANG DIPROSES</div>
            <div class="text-xs text-slate-500 mt-2">Tanggal Pengajuan: {{ pending.tanggal_pengajuan }}</div>
          </div>

          <!-- ✅ PROGRESS BAR STEP PENGAJUAN KTA -->
          <div class="mb-4">
            <div class="flex justify-between text-xs text-slate-400 mb-2">
              <span class="{{ 'text-emerald-400 font-bold' }}">1. Ajukan</span>
              <span class="{{ 'text-amber-400 font-bold' if pending.metode_pembayaran else '' }}">2. Bayar</span>
              <span class="{{ 'text-emerald-400 font-bold' if pending.status_pembayaran == 'terverifikasi' else '' }}">3. Verifikasi</span>
              <span class="{{ 'text-emerald-400 font-bold' if pending.status == 'disetujui' else '' }}">4. Selesai</span>
            </div>
            <div class="h-2 bg-white/10 rounded-full overflow-hidden">
              <div class="h-full bg-gradient-to-r from-amber-500 to-emerald-500 rounded-full transition-all" style="width: {% if pending.status == 'disetujui' %}100%{% elif pending.status_pembayaran == 'terverifikasi' %}75%{% elif pending.bukti_pembayaran_url %}50%{% else %}25%{% endif %}"></div>
            </div>
          </div>

          <!-- ✅ PILIHAN METODE PEMBAYARAN -->
          {% if not pending.metode_pembayaran %}
          <div class="grid grid-cols-2 gap-3 mb-4">
            <form method="post" action="/satpam/kta/{{ pending.id }}/pilih-metode">
              <input type="hidden" name="metode" value="langsung">
              <button type="submit" class="w-full p-4 rounded-2xl bg-white/5 hover:bg-emerald-500/10 border border-white/10 hover:border-emerald-500/30 transition text-center">
                <div class="text-3xl mb-2">📍</div>
                <div class="font-bold">BAYAR LANGSUNG</div>
                <div class="text-xs text-slate-400 mt-1">Datang langsung ke kantor Binmas</div>
              </button>
            </form>
            <form method="post" action="/satpam/kta/{{ pending.id }}/pilih-metode">
              <input type="hidden" name="metode" value="aplikasi">
              <button type="submit" class="w-full p-4 rounded-2xl bg-white/5 hover:bg-cyan-500/10 border border-white/10 hover:border-cyan-500/30 transition text-center">
                <div class="text-3xl mb-2">💳</div>
                <div class="font-bold">BAYAR VIA APLIKASI</div>
                <div class="text-xs text-slate-400 mt-1">Transfer ke rekening resmi</div>
              </button>
            </form>
          </div>
          {% endif %}

          <!-- ✅ JIKA SUDAH PILIH METODE APLIKASI -->
          {% if pending.metode_pembayaran == 'aplikasi' %}
            {% if pending.nomor_rekening_admin %}
            <div class="mb-4 p-4 rounded-2xl bg-cyan-500/10 border border-cyan-500/20">
              <div class="text-center mb-2">
                <div class="font-bold text-cyan-300">✅ NOMOR REKENING RESMI</div>
                <div class="text-2xl font-black mt-2 text-white">{{ pending.nomor_rekening_admin }}</div>
              </div>
            </div>
            {% else %}
            <div class="mb-4 p-3 rounded-2xl bg-white/5 text-center text-sm text-slate-400">
              ⏳ Menunggu admin mengirim nomor rekening...
            </div>
            {% endif %}

            <!-- ✅ UPLOAD BUKTI PEMBAYARAN -->
            {% if pending.nomor_rekening_admin and not pending.bukti_pembayaran_url %}
            <form method="post" action="/satpam/kta/{{ pending.id }}/upload-bukti" enctype="multipart/form-data" class="mb-4">
              <div class="p-4 rounded-2xl bg-white/5 border border-white/10">
                <div class="font-bold mb-2">📤 Upload Bukti Pembayaran</div>
                <input type="file" name="bukti_pembayaran" accept="image/*" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3">
                <button type="submit" class="w-full mt-3 rounded-2xl bg-emerald-500 hover:bg-emerald-400 text-slate-950 font-bold px-5 py-3">
                  ✅ KIRIM BUKTI PEMBAYARAN
                </button>
              </div>
            </form>
            {% endif %}

            {% if pending.bukti_pembayaran_url %}
            <div class="mb-4 p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20">
              <div class="text-center">
                <div class="font-bold text-emerald-300">✅ BUKTI PEMBAYARAN SUDAH DIKIRIM</div>
                <div class="text-xs text-slate-400 mt-1">Menunggu verifikasi admin</div>
                <a href="{{ pending.bukti_pembayaran_url }}" target="_blank" class="inline-block mt-3 px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 text-sm font-bold">
                  👁️ Lihat Bukti Pembayaran
                </a>
              </div>
            </div>
            {% endif %}

            {% if pending.status_pembayaran == 'terverifikasi' %}
            <div class="mb-4 p-4 rounded-2xl bg-emerald-500/10 border border-emerald-500/20">
              <div class="text-center">
                <div class="font-bold text-emerald-300 text-lg">✅ PEMBAYARAN TERVERIFIKASI</div>
                <div class="text-sm text-slate-400 mt-1">Pembayaran Anda sudah diverifikasi oleh Admin</div>
              </div>
            </div>
            {% endif %}
          {% endif %}

          {% if pending.metode_pembayaran == 'langsung' %}
          <div class="mb-4 p-4 rounded-2xl bg-amber-500/10 border border-amber-500/20">
            <div class="text-center">
              <div class="font-bold text-amber-300">📍 ANDA MEMILIH BAYAR LANGSUNG</div>
              <div class="text-sm text-slate-400 mt-1">Silahkan datang langsung ke kantor Binmas pada jam kerja</div>
            </div>
          </div>
          {% endif %}

        </div>
        {% else %}
        
        <div class="mb-6 p-4 rounded-2xl bg-white/5 border border-white/10">
          <div class="grid grid-cols-2 gap-4 text-sm">
            <div>
              <div class="text-slate-400">Nomor KTA Saat Ini</div>
              <div class="font-bold text-cyan-300">{{ user.no_kta or '-' }}</div>
            </div>
            <div>
              <div class="text-slate-400">Masa Berlaku</div>
              <div class="font-bold">{{ user.kta_expiry_date or '-' }}</div>
            </div>
          </div>
        </div>
        
        <form method="post" class="space-y-4">
          <div>
            <label class="text-sm text-slate-400 mb-2 block">Alasan Perpanjangan KTA</label>
            <select name="alasan" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500">
              <option value="">-- Pilih Alasan --</option>
              <option value="masa_habis">⏳ Masa berlaku KTA akan habis / sudah kadaluarsa</option>
              <option value="rusak">📄 KTA rusak / tidak bisa dibaca</option>
              <option value="hilang">❌ KTA hilang / dicuri</option>
              <option value="perubahan_data">✏️ Perubahan data pribadi</option>
              <option value="lainnya">📝 Lainnya</option>
            </select>
          </div>
          
          <div>
            <label class="text-sm text-slate-400 mb-2 block">Keterangan Tambahan (Opsional)</label>
            <textarea name="keterangan" rows="3" placeholder="Jelaskan secara singkat jika perlu..." class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none focus:ring-2 focus:ring-amber-500"></textarea>
          </div>
          
          <div class="p-3 rounded-2xl bg-white/5 border border-white/10 text-xs text-slate-400">
            ✅ Dengan mengirim pengajuan ini, Anda menyatakan bahwa semua data yang diberikan adalah benar dan dapat dipertanggungjawabkan.
          </div>
          
          <button type="submit" class="w-full rounded-2xl bg-gradient-to-r from-amber-500 to-orange-600 hover:from-amber-400 hover:to-orange-500 text-slate-950 font-black px-5 py-4">
            📤 Kirim Pengajuan Perpanjangan KTA
          </button>
        </form>
        {% endif %}
      </div>
      
      <!-- Riwayat Perpanjangan -->
      <div class="glass rounded-3xl p-6">
        <h2 class="text-xl font-black mb-4">📋 Riwayat Pengajuan Perpanjangan</h2>
        <div class="space-y-3">
          {% for item in riwayat %}
          <div class="p-4 rounded-2xl bg-white/5 border border-white/10">
            <div class="flex justify-between items-center mb-2">
              <div class="font-bold">{{ item.tanggal_pengajuan }}</div>
              <div>
                {% if item.status == 'pending' %}
                <span class="px-3 py-1 rounded-full bg-amber-500/20 text-amber-300 text-sm font-bold">⏳ Pending</span>
                {% elif item.status == 'disetujui' %}
                <span class="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 text-sm font-bold">✅ Disetujui</span>
                {% else %}
                <span class="px-3 py-1 rounded-full bg-red-500/20 text-red-300 text-sm font-bold">❌ Ditolak</span>
                {% endif %}
              </div>
            </div>
            <div class="text-sm text-slate-400">Alasan: {{ item.alasan_perpanjangan }}</div>
            {% if item.catatan_admin %}
            <div class="text-sm text-cyan-300 mt-2">💬 Balasan Admin: {{ item.catatan_admin }}</div>
            {% endif %}
            {% if item.jadwal_pengambilan %}
            <div class="text-sm text-emerald-300 mt-1">📅 Jadwal Pengambilan: {{ item.jadwal_pengambilan }}</div>
            {% endif %}
            {% if item.lokasi_pengambilan %}
            <div class="text-sm text-amber-300 mt-1">📍 Lokasi Pengambilan: {{ item.lokasi_pengambilan }}</div>
            {% endif %}
            {% if item.no_kta_baru %}
            <div class="text-sm font-bold text-white mt-1">🪪 Nomor KTA Baru: {{ item.no_kta_baru }}</div>
            {% endif %}
          </div>
          {% else %}
          <div class="text-center py-6 text-slate-400">
            Belum ada riwayat pengajuan perpanjangan KTA
          </div>
          {% endfor %}
        </div>
      </div>
      
    </div>
    """, user=user, pending=pending, riwayat=riwayat, msg=msg, error=error)
    return render_page("Perpanjang KTA", body, user)


@app.route("/admin/kta-perpanjangan", methods=["GET", "POST"])
@login_required
@roles_required("admin")
def admin_kta_perpanjangan():
    user = current_user()
    db = get_db()
    
    # ✅ AMBIL DATA NOMOR REKENING YANG AKTIF
    daftar_rekening = db.execute("""
        SELECT id, nama_bank, nomor_rekening, atas_nama 
        FROM rekening_bank 
        WHERE is_active = 1 
        ORDER BY urutan ASC
    """).fetchall()
    
    # ✅ INI YANG KURANG SEBELUMNYA: rekening_list untuk modal kirim rekening
    rekening_list = db.execute("""
        SELECT * FROM rekening_bank 
        WHERE is_active = 1
        ORDER BY urutan ASC, id ASC
    """).fetchall()
    
    # Ambil semua pengajuan
    pengajuan = db.execute("""
        SELECT p.*, u.full_name, u.no_kta, u.no_hp, u.bujp_id, b.nama_bujp
        FROM kta_perpanjangan p
        JOIN users u ON u.id = p.user_id
        LEFT JOIN bujp b ON u.bujp_id = b.id
        ORDER BY p.id DESC
    """).fetchall()
    
    # ✅ AMBIL SEMUA REKENING AKTIF UNTUK DROPDOWN
    rekening_rows = db.execute("""
        SELECT * FROM rekening_bank 
        WHERE is_active = 1
        ORDER BY urutan ASC, id ASC
    """).fetchall()
    
    # ✅ KONVERSI KE LIST DICT AGAR KOMPATIBEL DENGAN TEMPLATE
    rekening_list = []
    for row in rekening_rows:
        rekening_list.append({
            "id": row["id"],
            "nama_bank": row["nama_bank"],
            "nomor_rekening": row["nomor_rekening"],
            "atas_nama": row["atas_nama"],
            "keterangan": row["keterangan"],
            "is_active": row["is_active"]
        })
    
    # ✅ JIKA TIDAK ADA REKENING SAMA SEKALI, TAMPILKAN PESAN PETUNJUK
    if not rekening_list or len(rekening_list) == 0:
        rekening_list.append({
            "id": 0,
            "nama_bank": "⚠️ BELUM ADA REKENING TERDAFTAR",
            "nomor_rekening": "",
            "atas_nama": "Silahkan tambahkan rekening terlebih dahulu di Manajemen Rekening",
            "is_active": 1
        })
    
    total_pending = sum(1 for p in pengajuan if p["status"] == "pending")
    total_disetujui = sum(1 for p in pengajuan if p["status"] == "disetujui")
    total_ditolak = sum(1 for p in pengajuan if p["status"] == "ditolak")
    
    body = render_template_string("""
    <div class="mt-6">
    
      <div class="flex justify-between items-center mb-6">
        <div>
          <h1 class="text-3xl font-black">📋 Pengajuan Perpanjangan KTA Satpam</h1>
          <p class="text-slate-400 mt-1">Daftar semua pengajuan perpanjangan Kartu Tanda Anggota</p>
        </div>
        <div class="flex gap-3">
          <span class="px-4 py-2 rounded-2xl bg-amber-500/10 border border-amber-500/20 text-amber-300 font-bold">
            ⏳ Pending: {{ total_pending }}
          </span>
          <span class="px-4 py-2 rounded-2xl bg-emerald-500/10 border border-emerald-500/20 text-emerald-300 font-bold">
            ✅ Disetujui: {{ total_disetujui }}
          </span>
        </div>
      </div>
      
      <div class="glass rounded-3xl overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="bg-white/5 border-b border-white/10">
                <th class="text-left px-4 py-3 text-sm font-bold text-slate-300">✅ Langkah</th>
                <th class="text-left px-4 py-3 text-sm font-bold text-slate-300">Tanggal</th>
                <th class="text-left px-4 py-3 text-sm font-bold text-slate-300">Nama Satpam</th>
                <th class="text-left px-4 py-3 text-sm font-bold text-slate-300">No KTA</th>
                <th class="text-left px-4 py-3 text-sm font-bold text-slate-300">Status Pembayaran</th>
                <th class="text-left px-4 py-3 text-sm font-bold text-slate-300">Aksi Yang Perlu Dilakukan</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-white/5">
            {% for p in pengajuan %}
              <tr class="hover:bg-white/5 transition 
                {% if p.status == 'pending' and p.bukti_pembayaran_url and p.status_pembayaran == 'menunggu_verifikasi' %}
                bg-emerald-500/10 border-l-4 border-l-emerald-500 pengajuan-pending
                {% elif p.status == 'pending' and p.metode_pembayaran == 'aplikasi' and not p.nomor_rekening_admin %}
                bg-cyan-500/10 border-l-4 border-l-cyan-500 pengajuan-pending
                {% elif p.status == 'pending' %}
                bg-amber-500/10 border-l-4 border-l-amber-500 pengajuan-pending
                {% elif p.status == 'disetujui' %}
                bg-emerald-800/10 border-l-4 border-l-emerald-700
                {% else %}
                bg-slate-800/20
                {% endif %}
              ">
                <td class="px-4 py-3">
                  <div class="flex gap-1">
                    <span class="w-8 h-8 rounded-full text-center flex items-center justify-center text-xs font-black {% if p.metode_pembayaran %}bg-emerald-500/20 text-emerald-300{% else %}bg-white/5 text-slate-500{% endif %}">1</span>
                    <span class="w-8 h-8 rounded-full text-center flex items-center justify-center text-xs font-black {% if p.nomor_rekening_admin %}bg-emerald-500/20 text-emerald-300{% else %}bg-white/5 text-slate-500{% endif %}">2</span>
                    <span class="w-8 h-8 rounded-full text-center flex items-center justify-center text-xs font-black {% if p.bukti_pembayaran_url %}bg-emerald-500/20 text-emerald-300{% else %}bg-white/5 text-slate-500{% endif %}">3</span>
                    <span class="w-8 h-8 rounded-full text-center flex items-center justify-center text-xs font-black {% if p.status_pembayaran == 'terverifikasi' %}bg-emerald-500/20 text-emerald-300{% else %}bg-white/5 text-slate-500{% endif %}">4</span>
                    <span class="w-8 h-8 rounded-full text-center flex items-center justify-center text-xs font-black {% if p.status == 'disetujui' %}bg-emerald-500/20 text-emerald-300{% else %}bg-white/5 text-slate-500{% endif %}">5</span>
                  </div>
                </td>
                <td class="px-4 py-3 text-sm">{{ p.tanggal_pengajuan.split(' ')[0] }}</td>
                <td class="px-4 py-3">
                  <div class="font-bold">{{ p.full_name }}</div>
                  <div class="text-xs text-slate-500">{{ p.no_hp or '-' }}</div>
                </td>
                <td class="px-4 py-3 text-cyan-300 font-mono">{{ p.no_kta_lama }}</td>
                <td class="px-4 py-3">
                  {% if p.status_pembayaran == 'terverifikasi' %}
                  <span class="inline-block px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold">✅ SUDAH DIBAYAR</span>
                  {% elif p.status_pembayaran == 'menunggu_verifikasi' %}
                  <span class="inline-block px-3 py-1 rounded-full bg-emerald-500/10 text-emerald-300 text-xs font-bold animate-pulse">⏳ BUKTI DIKIRIM - PERLU VERIFIKASI</span>
                  {% elif p.metode_pembayaran == 'aplikasi' and not p.nomor_rekening_admin %}
                  <span class="inline-block px-3 py-1 rounded-full bg-cyan-500/20 text-cyan-400 text-xs font-bold animate-pulse">💳 PERLU KIRIM NO REKENING</span>
                  {% elif p.metode_pembayaran == 'langsung' %}
                  <span class="inline-block px-3 py-1 rounded-full bg-amber-500/20 text-amber-400 text-xs font-bold">📍 BAYAR LANGSUNG</span>
                  {% else %}
                  <span class="inline-block px-3 py-1 rounded-full bg-white/5 text-slate-400 text-xs font-bold">⏳ BELUM PILIH METODE</span>
                  {% endif %}
                </td>
                <td class="px-4 py-3">
                  {% if p.status == 'pending' %}
                  <div class="flex flex-wrap gap-2">
                    
                    {% if p.metode_pembayaran == 'aplikasi' and not p.nomor_rekening_admin %}
                    <button onclick="kirimRekening({{ p.id }})" class="px-4 py-2 rounded-xl bg-cyan-500 text-slate-950 text-xs font-bold hover:bg-cyan-400">
                      👉 KIRIM NO REKENING
                    </button>
                    {% endif %}
                    
                    {% if p.bukti_pembayaran_url and p.status_pembayaran == 'menunggu_verifikasi' %}
                    <button onclick="verifikasiPembayaran({{ p.id }}, '{{ p.bukti_pembayaran_url }}')" class="px-4 py-2 rounded-xl bg-emerald-500 text-slate-950 text-xs font-bold hover:bg-emerald-400 animate-pulse">
                      👉 VERIFIKASI BUKTI BAYAR
                    </button>
                    {% endif %}
                    
                    {% if p.status_pembayaran == 'terverifikasi' %}
                    <button onclick="prosesPengajuan({{ p.id }}, {{ p.user_id }}, 'setujui')" class="px-4 py-2 rounded-xl bg-violet-500 text-slate-950 text-xs font-bold hover:bg-violet-400">
                      ✅ SETUJUI & TERBITKAN KTA BARU
                    </button>
                    {% endif %}
                    
                    {% if not p.status_pembayaran or p.status_pembayaran == 'pending' %}
                    <span class="inline-block px-4 py-2 rounded-xl bg-amber-500/10 text-amber-300 text-xs font-bold animate-pulse">
                      ⏳ MENUNGGU PEMBAYARAN SATPAM
                    </span>
                    {% endif %}
                  </div>
                  {% else %}
                    {% if p.status == 'disetujui' %}
                    <span class="text-emerald-400 font-bold text-sm">✅ SUDAH SELESAI</span>
                    {% else %}
                    <span class="text-red-400 font-bold text-sm">❌ DITOLAK</span>
                    {% endif %}
                  {% endif %}
                </td>
              </tr>
            {% else %}
              <tr>
                <td colspan="6" class="py-12 text-center text-slate-400">
                  <div class="text-4xl mb-3">📋</div>
                  <div>Belum ada pengajuan perpanjangan KTA yang masuk</div>
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
      
    </div>
    
    <script>
    function prosesPengajuan(pengajuanId, userId, aksi) {
        // Jika Setujui, buka modal lengkap dengan jadwal dan lokasi
        if (aksi === 'setujui') {
            document.getElementById('pengajuanId').value = pengajuanId;
            document.getElementById('userId').value = userId;
            document.getElementById('formSetujui').action = '/admin/kta-perpanjangan/' + pengajuanId + '/setujui';
            document.getElementById('prosesModal').classList.remove('hidden');
        } else {
            // Jika Tolak, langsung tanya catatan
            const catatan = prompt('Masukkan alasan penolakan:');
            if (catatan === null) return;
            
            const form = document.createElement('form');
            form.method = 'POST';
            form.action = '/admin/kta-perpanjangan/' + pengajuanId + '/tolak';
            
            const input = document.createElement('input');
            input.type = 'hidden';
            input.name = 'catatan';
            input.value = catatan || '';
            form.appendChild(input);
            
            document.body.appendChild(form);
            form.submit();
        }
    }
    
    function hideProsesModal() {
        document.getElementById('prosesModal').classList.add('hidden');
    }

    function kirimRekening(pengajuanId) {
        document.getElementById('kirimRekeningId').value = pengajuanId;
        document.getElementById('formKirimRekening').action = '/admin/kta/' + pengajuanId + '/kirim-rekening';
        document.getElementById('kirimRekeningModal').classList.remove('hidden');
    }

    function hideKirimRekeningModal() {
        document.getElementById('kirimRekeningModal').classList.add('hidden');
    }

    function verifikasiPembayaran(pengajuanId, buktiUrl) {
        document.getElementById('verifikasiPembayaranId').value = pengajuanId;
        document.getElementById('formVerifikasiPembayaran').action = '/admin/kta/' + pengajuanId + '/verifikasi-pembayaran';
        
        // ✅ Tampilkan foto bukti pembayaran dengan layout yang bagus
        const buktiContainer = document.getElementById('buktiPembayaranContainer');
        const buktiImage = document.getElementById('buktiPembayaranImage');
        const buktiLink = document.getElementById('buktiPembayaranLink');
        
        if (buktiUrl && buktiUrl.trim() !== '') {
            buktiImage.src = buktiUrl;
            buktiLink.href = buktiUrl;
            buktiContainer.classList.remove('hidden');
        } else {
            buktiContainer.classList.add('hidden');
        }
        
        document.getElementById('verifikasiPembayaranModal').classList.remove('hidden');
    }

    function hideVerifikasiPembayaranModal() {
        document.getElementById('verifikasiPembayaranModal').classList.add('hidden');
    }
    </script>
    
    <!-- MODAL KIRIM NO REKENING -->
    <div id="kirimRekeningModal" class="fixed inset-0 bg-black/80 z-50 hidden flex items-center justify-center p-4">
        <div class="glass rounded-3xl p-6 w-full max-w-lg">
            <h2 class="text-2xl font-bold mb-4">💳 Kirim Nomor Rekening</h2>
            <form method="post" id="formKirimRekening" action="" class="space-y-4">
                <input type="hidden" name="pengajuanId" id="kirimRekeningId">
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Nomor Rekening Resmi</label>
                    <select name="nomor_rekening" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                        <option value="">-- Pilih Nomor Rekening --</option>
                        {% for rekening in rekening_list %}
                        <option value="{{ rekening.nama_bank }} {{ rekening.nomor_rekening }} a/n {{ rekening.atas_nama }}">
                            ✅ {{ rekening.nama_bank }} | {{ rekening.nomor_rekening }} | a/n {{ rekening.atas_nama }}
                        </option>
                        {% endfor %}
                    </select>
                </div>
                
                <div class="flex gap-3 mt-6">
                    <button type="button" onclick="hideKirimRekeningModal()" class="flex-1 bg-slate-500/20 text-slate-300 px-6 py-3 rounded-2xl font-bold">Batal</button>
                    <button type="submit" class="flex-1 bg-cyan-500 text-slate-950 px-6 py-3 rounded-2xl font-bold">✅ Kirim Rekening</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL VERIFIKASI PEMBAYARAN -->
    <div id="verifikasiPembayaranModal" class="fixed inset-0 bg-black/80 z-50 hidden flex items-center justify-center p-4">
        <div class="glass rounded-3xl p-6 w-full max-w-lg max-h-[95vh] overflow-auto">
            <h2 class="text-2xl font-bold mb-4">✅ Verifikasi Pembayaran</h2>
            
            <!-- ✅ Container Foto Bukti Pembayaran -->
            <div id="buktiPembayaranContainer" class="hidden space-y-2 mb-4">
                <h3 class="font-bold text-sm text-slate-300">📸 Bukti Pembayaran:</h3>
                <div class="rounded-2xl overflow-hidden border border-white/10 bg-black/50 max-h-80">
                    <img id="buktiPembayaranImage" src="" alt="Bukti Pembayaran" class="w-full h-auto object-contain max-h-80">
                </div>
                <a id="buktiPembayaranLink" href="" target="_blank" class="text-xs text-cyan-400 hover:text-cyan-300">🔗 Buka gambar di tab baru</a>
            </div>
            
            <form method="post" id="formVerifikasiPembayaran" action="" class="space-y-4">
                <input type="hidden" name="pengajuanId" id="verifikasiPembayaranId">
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Status Verifikasi</label>
                    <select name="status" class="w-full rounded-2xl bg-slate-900 border border-white/10 px-4 py-3 outline-none">
                        <option value="terverifikasi">✅ TERVERIFIKASI (Pembayaran Benar)</option>
                        <option value="ditolak">❌ DITOLAK (Pembayaran Salah/Tidak Sesuai)</option>
                    </select>
                </div>
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Catatan Verifikasi (Opsional)</label>
                    <textarea name="catatan" rows="2" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none"></textarea>
                </div>
                
                <div class="flex gap-3 mt-6">
                    <button type="button" onclick="hideVerifikasiPembayaranModal()" class="flex-1 bg-slate-500/20 text-slate-300 px-6 py-3 rounded-2xl font-bold">Batal</button>
                    <button type="submit" class="flex-1 bg-emerald-500 text-slate-950 px-6 py-3 rounded-2xl font-bold">✅ Simpan Verifikasi</button>
                </div>
            </form>
        </div>
    </div>

    <!-- MODAL PROSES SETUJUI PENGAJUAN -->
    <div id="prosesModal" class="fixed inset-0 bg-black/80 z-50 hidden flex items-center justify-center p-4">
        <div class="glass rounded-3xl p-6 w-full max-w-lg">
            <h2 class="text-2xl font-bold mb-4">✅ Setujui Pengajuan Perpanjangan KTA</h2>
            <form method="post" id="formSetujui" action="/admin/kta-perpanjangan/" + document.getElementById('pengajuanId').value + "/setujui" class="space-y-4">
                <input type="hidden" name="pengajuanId" id="pengajuanId">
                <input type="hidden" name="userId" id="userId">
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Nomor KTA Baru</label>
                    <input name="no_kta_baru" placeholder="Isi nomor KTA yang baru" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Masa Berlaku Baru</label>
                    <input name="masa_berlaku_baru" type="date" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Jadwal Pengambilan</label>
                    <input name="jadwal_pengambilan" type="date" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Lokasi Pengambilan</label>
                    <input name="lokasi_pengambilan" placeholder="Alamat lokasi pengambilan KTA" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
                </div>
                
                <div>
                    <label class="text-sm text-slate-400 block mb-1">Catatan Admin (Opsional)</label>
                    <textarea name="catatan_admin" rows="2" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none"></textarea>
                </div>
                
                <div class="flex gap-3 mt-6">
                    <button type="button" onclick="hideProsesModal()" class="flex-1 bg-slate-500/20 text-slate-300 px-6 py-3 rounded-2xl font-bold">Batal</button>
                    <button type="submit" class="flex-1 bg-emerald-500 text-slate-950 px-6 py-3 rounded-2xl font-bold">✅ Setujui & Proses</button>
                </div>
            </form>
        </div>
    </div>
    """, pengajuan=pengajuan, total_pending=total_pending, total_disetujui=total_disetujui, total_ditolak=total_ditolak, rekening_list=rekening_list)
    return render_page("Admin Pengajuan KTA", body, user)


@app.route("/admin/kta-perpanjangan/<int:id>/setujui", methods=["POST"])
@login_required
@roles_required("admin")
def admin_kta_setujui(id):
    db = get_db()
    ts = now_str()
    admin_id = current_user()["id"]
    
    # Ambil SEMUA field dari form modal admin
    no_kta_baru = request.form.get("no_kta_baru") or ""
    masa_berlaku_baru = request.form.get("masa_berlaku_baru") or ""
    jadwal_pengambilan = request.form.get("jadwal_pengambilan") or ""
    lokasi_pengambilan = request.form.get("lokasi_pengambilan") or ""
    catatan_admin = request.form.get("catatan_admin") or ""
    
    # Update SEMUA status dan field pengajuan
    db.execute("""
        UPDATE kta_perpanjangan 
        SET status='disetujui', 
            no_kta_baru=?,
            masa_berlaku_baru=?,
            jadwal_pengambilan=?,
            lokasi_pengambilan=?,
            catatan_admin=?, 
            tanggal_verifikasi=?, 
            admin_id=?
        WHERE id=?
    """, (no_kta_baru, masa_berlaku_baru, jadwal_pengambilan, lokasi_pengambilan, catatan_admin, ts, admin_id, id))
    
    db.commit()
    log_action("ADMIN_SETUJUI_PERPANJANGAN_KTA", "kta_perpanjangan", id)
    
    return redirect(url_for("admin_kta_perpanjangan"))


@app.route("/admin/kta-perpanjangan/<int:id>/tolak", methods=["POST"])
@login_required
@roles_required("admin")
def admin_kta_tolak(id):
    db = get_db()
    ts = now_str()
    admin_id = current_user()["id"]
    catatan = request.form.get("catatan") or ""
    
    # Update status pengajuan
    db.execute("""
        UPDATE kta_perpanjangan 
        SET status='ditolak', catatan_admin=?, tanggal_verifikasi=?, admin_id=?
        WHERE id=?
    """, (catatan, ts, admin_id, id))
    
    db.commit()
    log_action("ADMIN_TOLAK_PERPANJANGAN_KTA", "kta_perpanjangan", id)
    
    return redirect(url_for("admin_kta_perpanjangan"))


# ==============================
# FITUR EXPORT LAPORAN EXCEL BUJP
# ==============================

@app.route("/bujp/export/satpam")
@login_required
@roles_required("anggota")
def bujp_export_satpam():
    user = current_user()
    if not user["bujp_id"]:
        abort(400, "Akun BUJP Anda belum terhubung ke data BUJP")
    
    db = get_db()
    satpam_list = db.execute("""
        SELECT 
            id, username, full_name, no_kta, nik, no_hp, alamat, jabatan, 
            tanggal_lahir, tanggal_masuk, bujp_verified, created_at, updated_at
        FROM users 
        WHERE role = 'satpam'
        AND bujp_id = ?
        ORDER BY full_name ASC
    """, (user["bujp_id"],)).fetchall()
    
    # Konversi ke DataFrame
    df = pd.DataFrame([dict(row) for row in satpam_list])
    
    # Rename kolom untuk tampilan yang lebih baik
    df.columns = [
        "ID", "Username", "Nama Lengkap", "No KTA", "NIK", "No HP", "Alamat", 
        "Jabatan", "Tanggal Lahir", "Tanggal Masuk", "Status Verifikasi BUJP", 
        "Tanggal Daftar", "Terakhir Update"
    ]
    
    # Buat Excel file di memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Data Satpam', index=False)
    
    output.seek(0)
    
    # Buat response
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=data_satpam_bujp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    
    log_action("BUJP_EXPORT_SATPAM", "export", None, f"bujp_id={user['bujp_id']};total_rows={len(satpam_list)}")
    
    return response


@app.route("/bujp/export/absensi")
@login_required
@roles_required("anggota")
def bujp_export_absensi():
    user = current_user()
    if not user["bujp_id"]:
        abort(400, "Akun BUJP Anda belum terhubung ke data BUJP")
    
    db = get_db()
    absensi_list = db.execute("""
        SELECT 
            a.id, u.full_name, a.tanggal, a.waktu, a.tipe, a.status, 
            a.lat, a.lng, a.akurasi, a.lokasi, a.created_at
        FROM absensi a
        JOIN users u ON u.id = a.user_id
        WHERE u.role = 'satpam'
        AND u.bujp_id = ?
        ORDER BY a.tanggal DESC, a.waktu DESC
    """, (user["bujp_id"],)).fetchall()
    
    # Konversi ke DataFrame
    df = pd.DataFrame([dict(row) for row in absensi_list])
    
    # Rename kolom untuk tampilan yang lebih baik
    df.columns = [
        "ID Absen", "Nama Satpam", "Tanggal", "Waktu", "Tipe Absen", "Status Absen",
        "Latitude", "Longitude", "Akurasi GPS (meter)", "Lokasi Geofence", "Waktu Catat"
    ]
    
    # Buat Excel file di memory
    output = io.BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        df.to_excel(writer, sheet_name='Rekap Absensi', index=False)
    
    output.seek(0)
    
    # Buat response
    response = make_response(output.getvalue())
    response.headers["Content-Disposition"] = f"attachment; filename=rekap_absensi_bujp_{datetime.now().strftime('%Y%m%d_%H%M%S')}.xlsx"
    response.headers["Content-type"] = "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    
    log_action("BUJP_EXPORT_ABSENSI", "export", None, f"bujp_id={user['bujp_id']};total_rows={len(absensi_list)}")
    
    return response


# ==============================
# 🚨 FITUR EMERGENCY BUTTON DARURAT
# ==============================

@app.route("/api/emergency/process/<int:report_id>", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def api_emergency_process(report_id):
    try:
        user = current_user()
        if not user:
            return jsonify({"ok": False, "error": "User tidak terautentikasi"}), 401
            
        db = get_db()
        ts = now_str()
        
        # Cek apakah laporan ada dan masih pending
        cur = db.execute("SELECT id, user_id, status FROM emergency_reports WHERE id = ?", (report_id,))
        report_row = cur.fetchone()
        if not report_row:
            return jsonify({"ok": False, "error": "Laporan tidak ditemukan"}), 404
        
        # 100% SAFE CONVERT KE DICTIONARY
        report = {
            "id": report_row[0],
            "user_id": report_row[1],
            "status": report_row[2]
        }
        
        if report["status"] != 'pending':
            return jsonify({"ok": False, "error": "Laporan ini sudah diproses sebelumnya"}), 400
        
        # Update status laporan menjadi processed
        db.execute("""
            UPDATE emergency_reports 
            SET status = 'processed', 
                handled_by = ?, 
                handled_at = ?, 
                updated_at = ? 
            WHERE id = ?
        """, (user["id"], ts, ts, report_id))
        db.commit()
        
        log_action("EMERGENCY_PROCESSED", "emergency", report_id, f"handled_by={user['id']};satpam_id={report['user_id']}")
        
        # ✅ Kirim NOTIFIKASI LANGSUNG ke SATPAM yang mengirim laporan
        satpam_id = report["user_id"]
        with WS_LOCK:
            if satpam_id in SATPAM_SOCKETS:
                for ws in SATPAM_SOCKETS[satpam_id]:
                    safe_ws_send(ws, {
                        "type": "emergency_processed",
                        "report_id": report_id,
                        "message": "✅ Laporan darurat Anda sudah diterima dan sudah diproses oleh Admin / Direktur",
                        "handled_by": user["full_name"],
                        "handled_at": ts,
                        "server_time": ts
                    })
        
        # ✅ Broadcast ke SEMUA MONITOR agar laporan dihilangkan dari Maps Alert
        broadcast_monitors({
            "type": "emergency_processed",
            "report_id": report_id,
            "server_time": ts
        })
        
        return jsonify({"ok": True, "message": "Laporan berhasil diproses. Satpam sudah menerima notifikasi"})
    
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"ok": False, "error": str(e), "traceback": traceback.format_exc()}), 500


@app.route("/api/emergency/report", methods=["POST"])
@login_required
@roles_required("satpam")
def api_emergency_report():
    user = current_user()
    db = get_db()
    ts = now_str()
    
    try:
        lat = float(request.form.get("lat"))
        lng = float(request.form.get("lng"))
        keterangan = (request.form.get("keterangan") or "").strip()
        foto_url = ""
        
        # Simpan foto jika diupload
        if 'foto' in request.files:
            foto = request.files['foto']
            if foto.filename != '':
                # Buat direktori uploads jika belum ada
                upload_dir = os.path.join(os.path.dirname(__file__), "uploads", "emergency")
                os.makedirs(upload_dir, exist_ok=True)
                
                # Generate nama file unik
                ext = os.path.splitext(foto.filename)[1]
                filename = f"emergency_{user['id']}_{int(datetime.now().timestamp())}{ext}"
                file_path = os.path.join(upload_dir, filename)
                
                foto.save(file_path)
                foto_url = f"/uploads/emergency/{filename}"
        
        # Insert laporan darurat ke database
        cur = db.execute("""
            INSERT INTO emergency_reports (
                user_id, lat, lng, akurasi, keterangan, foto_url, status, created_at
            ) VALUES (?, ?, ?, ?, ?, ?, 'pending', ?)
        """, (
            user["id"],
            lat,
            lng,
            None,
            keterangan,
            foto_url,
            ts
        ))
        
        report_id = cur.lastrowid
        db.commit()
        
        log_action("EMERGENCY_REPORT", "emergency", report_id, f"satpam_id={user['id']};lat={lat:.6f};lng={lng:.6f}")
        
        # 🚨 BROADCAST LANGSUNG KE SEMUA ADMIN DAN DIREKTUR YANG ONLINE
        emergency_payload = {
            "type": "emergency_alert",
            "report_id": report_id,
            "satpam_id": user["id"],
            "satpam_nama": user["full_name"],
            "satpam_username": user["username"],
            "lat": lat,
            "lng": lng,
            "keterangan": keterangan,
            "foto_url": foto_url,
            "created_at": ts,
            "server_time": ts
        }
        
        # Kirim notifikasi realtime ke semua monitor (Admin & Direktur)
        broadcast_monitors(emergency_payload)
        
        return jsonify({
            "ok": True,
            "report_id": report_id,
            "message": "Laporan darurat berhasil dikirim ke semua Admin dan Direktur"
        })
        
    except Exception as e:
        return jsonify({"ok": False, "error": str(e)}), 400


@app.route("/satpam/emergency-history")
@login_required
@roles_required("satpam")
def satpam_emergency_history():
    user = current_user()
    db = get_db()
    
    # Ambil semua riwayat laporan darurat Satpam ini
    emergency_list = db.execute("""
        SELECT * FROM emergency_reports 
        WHERE user_id = ? 
        ORDER BY created_at DESC 
        LIMIT 50
    """, (user["id"],)).fetchall()
    
    body = render_template_string("""
    <div class="max-w-2xl mx-auto mt-6 space-y-6">
    
      <div class="glass rounded-3xl p-6">
        <div class="text-center mb-6">
          <div class="text-5xl mb-3">🚨</div>
          <h1 class="text-3xl font-black mb-2">RIWAYAT LAPORAN DARURAT</h1>
          <p class="text-slate-400">Daftar semua laporan darurat yang pernah Anda kirim</p>
        </div>
        
        <div class="space-y-4">
          {% for report in emergency_list %}
          <div class="rounded-2xl bg-white/5 border border-white/10 p-5">
            <div class="flex justify-between items-start mb-3">
              <div>
                <div class="font-bold text-lg">📅 {{ report.created_at }}</div>
                <div class="text-xs text-slate-400">ID Laporan: #{{ report.id }}</div>
              </div>
              <div>
                {% if report.status == 'pending' %}
                <span class="px-3 py-1 rounded-full bg-amber-500/20 text-amber-300 text-sm font-bold">⏳ Sedang Diproses</span>
                {% elif report.status == 'processed' %}
                <span class="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-300 text-sm font-bold">✅ Sudah Ditangani</span>
                {% else %}
                <span class="px-3 py-1 rounded-full bg-red-500/20 text-red-300 text-sm font-bold">❌ Ditutup</span>
                {% endif %}
              </div>
            </div>
            
            <div class="mb-3 p-3 rounded-xl bg-white/5">
              <div class="text-sm text-slate-300">📝 {{ report.keterangan or 'Tidak ada keterangan' }}</div>
            </div>
            
            <div class="grid grid-cols-2 gap-3 text-sm">
              <div>
                <div class="text-slate-400 text-xs">Koordinat Lokasi</div>
                <div class="font-mono text-cyan-300">{{ '%.6f'|format(report.lat) }}, {{ '%.6f'|format(report.lng) }}</div>
              </div>
              <div>
                <div class="text-slate-400 text-xs">Akurasi GPS</div>
                <div>{{ report.akurasi or '-' }} meter</div>
              </div>
            </div>
            
            {% if report.foto_url %}
            <div class="mt-3">
              <a href="{{ report.foto_url }}" target="_blank" class="inline-block px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 text-sm font-bold">
                📸 Lihat Foto Bukti
              </a>
            </div>
            {% endif %}
            
            {% if report.admin_note %}
            <div class="mt-3 p-3 rounded-xl bg-emerald-500/10 border border-emerald-500/20">
              <div class="text-xs text-emerald-400 mb-1">💬 Balasan Admin:</div>
              <div class="text-sm text-emerald-200">{{ report.admin_note }}</div>
            </div>
            {% endif %}
          </div>
          {% else %}
          <div class="text-center py-12 text-slate-400">
            <div class="text-5xl mb-4">✅</div>
            <div class="text-lg font-bold">Belum ada riwayat laporan darurat</div>
            <div class="text-sm">Anda belum pernah mengirim laporan darurat</div>
          </div>
          {% endfor %}
        </div>
        
        <div class="mt-6 text-center">
          <a href="{{ url_for('satpam_page') }}" class="inline-block px-6 py-3 rounded-2xl bg-cyan-500 text-slate-950 font-bold">
            ← Kembali ke Beranda
          </a>
        </div>
      </div>
      
    </div>
    """, emergency_list=emergency_list)
    
    return render_page("Riwayat Laporan Darurat", body, user)


@app.route("/admin/emergency-reports")
@login_required
@roles_required("admin", "direktur_binmas")
def admin_emergency_reports():
    user = current_user()
    db = get_db()
    
    # Ambil SEMUA laporan darurat dari semua Satpam
    emergency_rows = db.execute("""
        SELECT e.*, u.full_name, u.username, u.bujp_id, b.nama_bujp
        FROM emergency_reports e
        JOIN users u ON u.id = e.user_id
        LEFT JOIN bujp b ON u.bujp_id = b.id
        ORDER BY e.created_at DESC 
        LIMIT 100
    """).fetchall()
    
    # ✅ CONVERT SQLITE ROW OBJECT KE DICTIONARY AGAR BISA DI SERIALISASI JSON
    emergency_list = [dict(row) for row in emergency_rows]
    
    body = render_template_string("""
    <div class="mt-6">
      <div class="flex justify-between items-center mb-6">
        <div>
          <h1 class="text-3xl font-black mb-2">🚨 DAFTAR SEMUA LAPORAN DARURAT</h1>
          <p class="text-slate-400">Semua riwayat laporan darurat dari Satpam seluruhnya</p>
        </div>
        <div class="px-4 py-2 rounded-2xl bg-red-500/10 border border-red-500/20 text-red-300 font-bold">
          Total: {{ emergency_list|length }} Laporan
        </div>
      </div>
      
      <div class="glass rounded-3xl overflow-hidden">
        <div class="overflow-x-auto">
          <table class="w-full">
            <thead>
              <tr class="bg-white/5 border-b border-white/10">
                <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Waktu</th>
                <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Nama Satpam</th>
                <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">BUJP</th>
                <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Keterangan</th>
                <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Lokasi</th>
                <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Status</th>
                <th class="text-left px-6 py-4 text-sm font-bold text-slate-300">Aksi</th>
              </tr>
            </thead>
          <tbody class="divide-y divide-white/5">
            {% for report in emergency_list %}
              <tr class="hover:bg-white/5 transition" data-report-row="{{ report.id }}">
                <td class="px-6 py-4 text-sm">{{ report.created_at }}</td>
                <td class="px-6 py-4">
                  <div class="font-bold">{{ report.full_name }}</div>
                  <div class="text-xs text-slate-500">@{{ report.username }}</div>
                </td>
                <td class="px-6 py-4 text-amber-300 text-sm">{{ report.nama_bujp or 'Umum' }}</td>
                <td class="px-6 py-4 text-sm">{{ report.keterangan[:50] }}{{ '...' if report.keterangan|length > 50 else '' }}</td>
                <td class="px-6 py-4 text-cyan-300 text-xs font-mono">{{ '%.6f'|format(report.lat) }}</td>
                <td class="px-6 py-4">
                  {% if report.status == 'pending' %}
                  <span class="inline-block px-3 py-1 rounded-full bg-amber-500/20 text-amber-400 text-xs font-bold">⏳ Pending</span>
                  {% elif report.status == 'processed' %}
                  <span class="inline-block px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 text-xs font-bold">✅ Diproses</span>
                  {% else %}
                  <span class="inline-block px-3 py-1 rounded-full bg-slate-500/20 text-slate-300 text-xs font-bold">❌ Ditutup</span>
                  {% endif %}
                </td>
                <td class="px-6 py-4">
                  <div class="flex gap-2">
                  {% if report.status == 'pending' %}
                  <button data-report-process="{{ report.id }}" class="px-3 py-2 rounded-xl bg-emerald-500/20 text-emerald-400 text-xs font-bold">
                    ✅ Proses
                  </button>
                  {% endif %}
                  <button data-report-view="{{ report.id }}" class="px-3 py-2 rounded-xl bg-cyan-500/20 text-cyan-400 text-xs font-bold">
                    👁️ Detail
                  </button>
                  </div>
                </td>
              </tr>
            {% else %}
              <tr>
                <td colspan="7" class="py-12 text-center text-slate-400">
                  <div class="text-4xl mb-3">✅</div>
                  <div>Belum ada laporan darurat yang masuk</div>
                </td>
              </tr>
            {% endfor %}
            </tbody>
          </table>
        </div>
      </div>
    </div>
    
    <script>
    let currentReportId = null;
    const emergencyData = {{ emergency_list|tojson }};
    
    function openEmergencyDetail(reportId) {
        currentReportId = reportId;
        const report = emergencyData.find(r => r.id === reportId);
        if (!report) return;
        
        document.getElementById('modalReportId').textContent = `ID Laporan: #${report.id}`;
        document.getElementById('modalSatpamNama').textContent = report.full_name;
        document.getElementById('modalSatpamUsername').textContent = `@${report.username}`;
        document.getElementById('modalBujp').textContent = report.nama_bujp || 'Umum';
        document.getElementById('modalWaktu').textContent = report.created_at;
        document.getElementById('modalKeterangan').textContent = report.keterangan || 'Tidak ada keterangan';
        document.getElementById('modalLat').textContent = report.lat.toFixed(7);
        document.getElementById('modalLng').textContent = report.lng.toFixed(7);
        document.getElementById('modalAkurasi').textContent = report.akurasi ? `${report.akurasi} meter` : '-';
        
        // Status
        if (report.status === 'pending') {
            document.getElementById('modalStatus').innerHTML = '<span class="px-3 py-1 rounded-full bg-amber-500/20 text-amber-400 font-bold">⏳ SEDANG PENDING</span>';
            document.getElementById('modalBtnProses').style.display = 'block';
        } else if (report.status === 'processed') {
            document.getElementById('modalStatus').innerHTML = '<span class="px-3 py-1 rounded-full bg-emerald-500/20 text-emerald-400 font-bold">✅ SUDAH DIPROSES</span>';
            document.getElementById('modalBtnProses').style.display = 'none';
        } else {
            document.getElementById('modalStatus').innerHTML = '<span class="px-3 py-1 rounded-full bg-slate-500/20 text-slate-300 font-bold">❌ DITUTUP</span>';
            document.getElementById('modalBtnProses').style.display = 'none';
        }
        
        // Foto
        const fotoContainer = document.getElementById('modalFotoContainer');
        if (report.foto_url) {
            fotoContainer.innerHTML = `
                <a href="${report.foto_url}" target="_blank">
                    <img src="${report.foto_url}" alt="Foto Bukti" class="w-full rounded-2xl border border-white/10 max-h-[300px] object-cover">
                </a>
            `;
        } else {
            fotoContainer.innerHTML = `<div class="text-center py-4 text-slate-500">Tidak ada foto yang dilampirkan</div>`;
        }
        
        // Link Google Maps
        document.getElementById('modalBtnGMaps').href = `https://www.google.com/maps/search/?api=1&query=${report.lat},${report.lng}`;
        
        // Tampilkan modal dengan animasi
        document.getElementById('emergencyDetailModal').classList.remove('hidden');
    }
    
    function closeEmergencyModal() {
        document.getElementById('emergencyDetailModal').classList.add('hidden');
        currentReportId = null;
    }
    
    async function prosesLaporanModal() {
        if (!currentReportId) return;
        if (!confirm('Yakin ingin memproses laporan darurat ini?')) return;
        
        try {
            const res = await fetch(`/api/emergency/process/${currentReportId}`, { method: 'POST' });
            const result = await res.json();
            
            if (result.ok) {
                alert('✅ Laporan berhasil diproses!');
                closeEmergencyModal();
                window.location.reload();
            } else {
                alert('❌ Gagal memproses laporan: ' + (result.error || 'Server error'));
            }
        } catch (err) {
            alert('❌ Gagal terhubung ke server');
        }
    }
    
    // Close modal ketika klik diluar
    document.getElementById('emergencyDetailModal').addEventListener('click', function(e) {
        if (e.target === this) {
            closeEmergencyModal();
        }
    });
    
    // Close modal dengan tombol ESC
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            closeEmergencyModal();
        }
    });
    
    // Bind event klik di tabel
    document.addEventListener('DOMContentLoaded', function() {
        document.querySelectorAll('[data-report-view]').forEach(btn => {
            btn.addEventListener('click', function() {
                const reportId = parseInt(this.getAttribute('data-report-view'));
                openEmergencyDetail(reportId);
            });
        });
        document.querySelectorAll('[data-report-process]').forEach(btn => {
            btn.addEventListener('click', function() {
                const reportId = parseInt(this.getAttribute('data-report-process'));
                openEmergencyDetail(reportId);
            });
        });
    });
    </script>
    """, emergency_list=emergency_list)
    
    return render_page("Daftar Laporan Darurat", body, user)


# ==============================================
# ✅ SISTEM NOTIFIKASI ADMIN
# ==============================================

# ✅ API NOTIFIKASI USER
@app.route("/api/notifications", methods=["GET"])
@login_required
def api_get_notifications():
    user = current_user()
    db = get_db()
    
    # Ambil notifikasi untuk user ini
    notifications = db.execute("""
        SELECT n.*, u.full_name AS admin_nama
        FROM admin_notifications n
        LEFT JOIN users u ON u.id = n.admin_id
        WHERE (n.target_user_id = ? OR n.target_role = ? OR n.target_role IS NULL)
        ORDER BY n.created_at DESC
        LIMIT 50
    """, (user["id"], user["role"])).fetchall()
    
    return jsonify([dict(n) for n in notifications])

@app.route("/api/notifications/unread-count", methods=["GET"])
@login_required
def api_notifications_unread_count():
    user = current_user()
    db = get_db()
    
    count = db.execute("""
        SELECT COUNT(*) FROM admin_notifications
        WHERE (target_user_id = ? OR target_role = ? OR target_role IS NULL)
        AND is_read = 0
    """, (user["id"], user["role"])).fetchone()[0]
    
    return jsonify({"count": count})

@app.route("/api/notifications/<int:id>/read", methods=["POST"])
@login_required
def api_mark_notification_read(id):
    user = current_user()
    db = get_db()
    
    db.execute("""
        UPDATE admin_notifications 
        SET is_read = 1, read_at = ? 
        WHERE id = ? 
        AND (target_user_id = ? OR target_role = ? OR target_role IS NULL)
    """, (now_str(), id, user["id"], user["role"]))
    db.commit()
    
    return jsonify({"ok": True})

# ✅ API ADMIN KIRIM NOTIFIKASI
@app.route("/api/admin/notifications/send", methods=["POST"])
@login_required
@roles_required("admin", "direktur_binmas")
def api_admin_send_notification():
    admin = current_user()
    db = get_db()
    data = request.get_json(silent=True) or {}
    
    target_user_id = data.get("target_user_id")
    target_role = data.get("target_role")
    title = data.get("title", "").strip()
    message = data.get("message", "").strip()
    notif_type = data.get("type", "info")
    
    if not title or not message:
        return jsonify({"ok": False, "error": "Judul dan pesan wajib diisi"}), 400
    
    if notif_type not in ('info', 'warning', 'important', 'emergency'):
        notif_type = 'info'
    
    ts = now_str()
    cur = db.execute("""
        INSERT INTO admin_notifications (
            admin_id, target_user_id, target_role, title, message, type, created_at
        ) VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        admin["id"],
        target_user_id,
        target_role,
        title,
        message,
        notif_type,
        ts
    ))
    notif_id = cur.lastrowid
    db.commit()
    
    # ✅ BROADCAST NOTIFIKASI REAL-TIME KE SEMUA USER ONLINE
    notification_payload = {
        "type": "admin_notification",
        "notification_id": notif_id,
        "title": title,
        "message": message,
        "notif_type": notif_type,
        "admin_nama": admin["full_name"],
        "created_at": ts
    }
    
    # Kirim ke semua monitor dan user yang online
    broadcast_monitors(notification_payload)
    
    log_action("ADMIN_SEND_NOTIFICATION", "admin_notifications", notif_id, f"target_user={target_user_id};target_role={target_role}")
    
    return jsonify({"ok": True, "id": notif_id})

# ✅ HALAMAN NOTIFIKASI USER
@app.route("/notifications")
@login_required
def notifications_page():
    user = current_user()
    
    body = render_template_string("""
    <div class="max-w-2xl mx-auto mt-6 space-y-6">
      
      <div class="glass rounded-3xl p-6">
        <div class="flex justify-between items-center mb-6">
          <h1 class="text-2xl font-black">🔔 Notifikasi Anda</h1>
          <button onclick="markAllRead()" class="px-4 py-2 rounded-xl bg-cyan-500/20 text-cyan-300 text-sm font-bold">
            Tandai Semua Dibaca
          </button>
        </div>
        
        <div id="notificationsList" class="space-y-4">
          <div class="text-center py-12 text-slate-400">
            <div class="text-4xl mb-3 animate-pulse">⏳</div>
            <div>Memuat notifikasi...</div>
          </div>
        </div>
      </div>
      
    </div>
    
    <script>
    async function loadNotifications() {
      try {
        const res = await fetch('/api/notifications');
        const notifications = await res.json();
        const el = document.getElementById('notificationsList');
        
        if (notifications.length === 0) {
          el.innerHTML = `
            <div class="text-center py-12 text-slate-400">
              <div class="text-4xl mb-3">✅</div>
              <div>Tidak ada notifikasi</div>
            </div>
          `;
          return;
        }
        
        el.innerHTML = notifications.map(n => `
          <div class="p-4 rounded-2xl ${n.is_read ? 'bg-white/5' : 'bg-cyan-500/10 border border-cyan-500/20'}">
            <div class="flex justify-between items-start gap-4">
              <div class="flex-1">
                <div class="flex items-center gap-3 mb-2">
                  <span class="px-2 py-1 rounded-lg ${
                    n.type === 'emergency' ? 'bg-red-500/20 text-red-300' :
                    n.type === 'important' ? 'bg-amber-500/20 text-amber-300' :
                    n.type === 'warning' ? 'bg-orange-500/20 text-orange-300' :
                    'bg-cyan-500/20 text-cyan-300'
                  } text-xs font-bold">${n.type.toUpperCase()}</span>
                  <span class="text-xs text-slate-400">${n.created_at}</span>
                  ${n.admin_nama ? `<span class="text-xs text-slate-400">Oleh: ${n.admin_nama}</span>` : ''}
                </div>
                <div class="font-bold text-lg mb-1">${n.title}</div>
                <div class="text-sm text-slate-300">${n.message}</div>
              </div>
              ${!n.is_read ? `
                <button onclick="markRead(${n.id})" class="px-3 py-1 rounded-xl bg-cyan-500 text-slate-950 text-xs font-bold flex-shrink-0">
                  ✓ Dibaca
                </button>
              ` : ''}
            </div>
          </div>
        `).join('');
        
      } catch (e) {
        console.error(e);
      }
    }
    
    async function markRead(id) {
      await fetch(`/api/notifications/${id}/read`, { method: 'POST' });
      loadNotifications();
      updateBadgeCount();
    }
    
    async function markAllRead() {
      const res = await fetch('/api/notifications');
      const notifications = await res.json();
      for (const n of notifications) {
        if (!n.is_read) {
          await fetch(`/api/notifications/${n.id}/read`, { method: 'POST' });
        }
      }
      loadNotifications();
      updateBadgeCount();
    }
    
    async function updateBadgeCount() {
      try {
        const res = await fetch('/api/notifications/unread-count');
        const data = await res.json();
        const badge = document.getElementById('notifBadgeCount');
        if (badge) {
          badge.textContent = data.count;
          badge.style.display = data.count > 0 ? 'flex' : 'none';
        }
      } catch (e) {}
    }
    
    window.addEventListener('load', () => {
      loadNotifications();
      updateBadgeCount();
      setInterval(updateBadgeCount, 30000);
    });
    </script>
    """, user=user)
    
    return render_page("Notifikasi", body, user)

# ✅ HALAMAN ADMIN KIRIM NOTIFIKASI
@app.route("/admin/send-notification")
@login_required
@roles_required("admin", "direktur_binmas")
def admin_send_notification():
    user = current_user()
    db = get_db()
    
    users = db.execute("SELECT id, full_name, role FROM users WHERE is_active = 1 ORDER BY full_name ASC").fetchall()
    
    body = render_template_string("""
    <div class="max-w-2xl mx-auto mt-6 space-y-6">
      
      <div class="glass rounded-3xl p-6">
        <h1 class="text-2xl font-black mb-6">📤 Kirim Notifikasi ke User</h1>
        
        <form id="sendNotifForm" class="space-y-4">
          <div>
            <label class="text-sm text-slate-400 block mb-2">Tujuan Notifikasi</label>
            <select id="targetType" onchange="toggleTarget()" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
              <option value="all">✅ Kirim ke SEMUA USER</option>
              <option value="role">Kirim ke Role Tertentu</option>
              <option value="user">Kirim ke User Individu</option>
            </select>
          </div>
          
          <div id="targetRoleContainer" class="hidden">
            <label class="text-sm text-slate-400 block mb-2">Pilih Role</label>
            <select id="targetRole" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
              <option value="satpam">👮 Satpam</option>
              <option value="anggota">🎖️ Anggota / BUJP</option>
              <option value="admin">⚙️ Admin</option>
              <option value="direktur_binmas">👨‍💼 Direktur</option>
            </select>
          </div>
          
          <div id="targetUserContainer" class="hidden">
            <label class="text-sm text-slate-400 block mb-2">Pilih User</label>
            <select id="targetUser" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
              {% for u in users %}
              <option value="{{ u.id }}">{{ u.full_name }} ({{ u.role }})</option>
              {% endfor %}
            </select>
          </div>
          
          <div>
            <label class="text-sm text-slate-400 block mb-2">Tipe Notifikasi</label>
            <select id="notifType" class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none">
              <option value="info">ℹ️ Informasi</option>
              <option value="warning">⚠️ Peringatan</option>
              <option value="important">📢 Penting</option>
              <option value="emergency">🚨 Darurat</option>
            </select>
          </div>
          
          <div>
            <label class="text-sm text-slate-400 block mb-2">Judul Notifikasi</label>
            <input id="notifTitle" type="text" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none" placeholder="Judul pesan">
          </div>
          
          <div>
            <label class="text-sm text-slate-400 block mb-2">Pesan Notifikasi</label>
            <textarea id="notifMessage" rows="4" required class="w-full rounded-2xl bg-white/5 border border-white/10 px-4 py-3 outline-none" placeholder="Tulis pesan notifikasi disini..."></textarea>
          </div>
          
          <button type="submit" id="submitBtn" class="w-full rounded-2xl bg-cyan-500 hover:bg-cyan-400 text-slate-950 font-black px-5 py-4">
            📤 KIRIM NOTIFIKASI
          </button>
        </form>
      </div>
      
    </div>
    
    <script>
    function toggleTarget() {
      const type = document.getElementById('targetType').value;
      document.getElementById('targetRoleContainer').classList.toggle('hidden', type !== 'role');
      document.getElementById('targetUserContainer').classList.toggle('hidden', type !== 'user');
    }
    
    document.getElementById('sendNotifForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      
      const btn = document.getElementById('submitBtn');
      btn.disabled = true;
      btn.textContent = '⏳ Mengirim...';
      
      try {
        const targetType = document.getElementById('targetType').value;
        const data = {
          title: document.getElementById('notifTitle').value,
          message: document.getElementById('notifMessage').value,
          type: document.getElementById('notifType').value,
          target_user_id: null,
          target_role: null
        };
        
        if (targetType === 'role') {
          data.target_role = document.getElementById('targetRole').value;
        } else if (targetType === 'user') {
          data.target_user_id = parseInt(document.getElementById('targetUser').value);
        }
        
        const res = await fetch('/api/admin/notifications/send', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(data)
        });
        
        const result = await res.json();
        
        if (result.ok) {
          alert('✅ Notifikasi berhasil dikirim!');
          document.getElementById('sendNotifForm').reset();
        } else {
          alert('❌ Gagal mengirim: ' + (result.error || 'Terjadi kesalahan'));
        }
        
      } catch (err) {
        alert('❌ Gagal terhubung ke server');
      } finally {
        btn.disabled = false;
        btn.textContent = '📤 KIRIM NOTIFIKASI';
      }
    });
    </script>
    """, user=user, users=users)
    
    return render_page("Kirim Notifikasi", body, user)

# ✅ TAMBAH MENU NOTIFIKASI DI NAVBAR SEMUA ROLE
def nav_html(user):
    if not user:
        return ""
    
    db = get_db()
    # Hitung notifikasi yang belum dibaca
    unread_notif = 0
    try:
        unread_notif = db.execute("""
            SELECT COUNT(*) FROM admin_notifications
            WHERE (target_user_id = ? OR target_role = ? OR target_role IS NULL)
            AND is_read = 0
        """, (user["id"], user["role"])).fetchone()[0]
    except:
        pass
        
    # Hitung jumlah laporan emergency pending untuk badge notifikasi
    emergency_pending_count = 0
    kta_pending_count = 0
    if user["role"] in ("admin", "direktur_binmas"):
        try:
            emergency_pending_count = get_db().execute("SELECT COUNT(*) FROM emergency_reports WHERE status = 'pending'").fetchone()[0]
            kta_pending_count = get_db().execute("SELECT COUNT(*) FROM kta_perpanjangan WHERE status = 'pending'").fetchone()[0]
        except:
            emergency_pending_count = 0
            kta_pending_count = 0


    if user["role"] == "admin":
        items = [
            (url_for("admin_dashboard"), "Admin"),
            (url_for("admin_send_notification"), "📤 Kirim Notifikasi"),
            (url_for("notifications_page"), f"🔔 Notifikasi", unread_notif),
            (url_for("admin_kta_perpanjangan"), "📋 Pengajuan KTA", kta_pending_count),
            (url_for("bujp_management"), "Manajemen BUJP"),
            (url_for("monitor_map"), "Map Monitor"),
            (url_for("emergency_alert_map"), "🚨 Maps Alert", emergency_pending_count),
            (url_for("admin_emergency_reports"), "📋 Daftar Laporan Darurat"),
            (url_for("admin_absensi_sesi"), "📅 Kelola Absensi"),
            (url_for("admin_absensi_rekap"), "📊 Rekap Absensi"),
            (url_for("admin_rekening_management"), "💳 Manajemen Rekening"),
            (url_for("change_password"), "Ganti Password"),
            (url_for("logout"), "Logout"),
        ]


    elif user["role"] == "direktur_binmas":
        items = [
            (url_for("monitor_map"), "Map Satpam"),
            (url_for("notifications_page"), f"🔔 Notifikasi", unread_notif),
            (url_for("emergency_alert_map"), "🚨 Maps Alert", emergency_pending_count),
            (url_for("admin_emergency_reports"), "📋 Daftar Laporan Darurat"),
            (url_for("direktur_maps_bujp"), "🗺️ Maps Perusahaan"),
            (url_for("bujp_management"), "Manajemen BUJP"),
            (url_for("change_password"), "Ganti Password"),
            (url_for("logout"), "Logout"),
        ]
    elif user["role"] == "satpam":
        items = [
            (url_for("satpam_page"), "🏠 Beranda"),
            (url_for("notifications_page"), f"🔔 Notifikasi", unread_notif),
            (url_for("satpam_profile"), "👤 Profil KTA"),
            (url_for("change_password"), "🔑 Ganti Password"),
            (url_for("logout"), "🚪 Logout"),
        ]
    else:
        items = [
            (url_for("bujp_dashboard"), "Beranda"),
            (url_for("notifications_page"), f"🔔 Notifikasi", unread_notif),
            (url_for("change_password"), "Ganti Password"),
            (url_for("logout"), "Logout"),
        ]
    nav_items = []
    for item in items:
        if len(item) == 3:
            href, label, badge_count = item
            if badge_count and badge_count > 0:
                # Tampilkan badge notifikasi merah dengan angka
                nav_items.append(f'''
                <a href="{href}" class="px-3 py-2 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition relative">
                    {label}
                    <span class="emergency-badge absolute -top-1 -right-1 bg-red-500 text-white text-xs font-black rounded-full w-5 h-5 flex items-center justify-center animate-pulse">
                        {badge_count}
                    </span>
                </a>
                ''')
            else:
                nav_items.append(f'<a href="{href}" class="px-3 py-2 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition">{label}</a>')
        else:
            href, label = item
            nav_items.append(f'<a href="{href}" class="px-3 py-2 rounded-xl text-sm bg-white/5 hover:bg-cyan-500/20 border border-white/10 transition">{label}</a>')

    return "".join(nav_items)


init_db()

if __name__ == '__main__':
    # ✅ AUTO RELOAD AKTIF SECARA DEFAULT: Tidak perlu restart server ketika edit file
    # Setiap ada perubahan kode, server akan reload otomatis, cukup refresh browser saja
    print("✅ AUTO RELOAD MODE AKTIF - Server akan reload otomatis ketika ada perubahan file")
    print("🔗 Akses Halaman Utama: http://localhost:5010")

    app.run(
        host='0.0.0.0',
        port=int(os.environ.get('PORT', 5010)),
        debug=True,
        use_reloader=True,
        reloader_type='stat'
    )
