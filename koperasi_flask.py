from flask import Flask, request, redirect, url_for, render_template_string, session, flash, send_file, jsonify
import sqlite3
import pandas as pd
from datetime import datetime, date, timedelta
from functools import wraps
from io import BytesIO
from pathlib import Path
import hashlib
import math
import json
import os
from werkzeug.utils import secure_filename
from reportlab.lib.pagesizes import A4
from reportlab.pdfgen import canvas
from reportlab.lib.units import mm

APP_TITLE = 'Koperasi Enterprise V3 Final'
APP_SHORT = 'KOPERASI'
DB_NAME = 'koperasi_enterprise_v3.db'
SECRET_KEY = 'ganti-rahasia-ini-untuk-produksi'
LOAN_AUTO_APPROVE_LIMIT = 5000000
MANUAL_JOURNAL_APPROVE_LIMIT = 10000000
LOAN_VERIFICATION_REQUIRED = True
LATE_PENALTY_PERCENT = 0.005

app = Flask(__name__)
app.secret_key = SECRET_KEY

def get_conn():
    conn = sqlite3.connect(DB_NAME)
    conn.row_factory = sqlite3.Row
    conn.execute('PRAGMA foreign_keys = ON')
    return conn

def q_all(sql, params=None):
    conn = get_conn()
    rows = conn.execute(sql, params or []).fetchall()
    conn.close()
    return rows

def q_one(sql, params=None):
    conn = get_conn()
    row = conn.execute(sql, params or []).fetchone()
    conn.close()
    return row

def exec_sql(sql, params=None, many=False):
    conn = get_conn()
    cur = conn.cursor()
    if many:
        cur.executemany(sql, params)
    else:
        cur.execute(sql, params or [])
    conn.commit()
    rid = cur.lastrowid
    conn.close()
    return rid

def hash_password(text):
    return hashlib.sha256(text.encode()).hexdigest()

def now_str():
    return datetime.now().strftime('%Y-%m-%d %H:%M:%S')

def today_str():
    return str(date.today())

def month_key(date_str):
    return str(date_str)[:7]

def gen_code(prefix):
    return f"{prefix}-{datetime.now().strftime('%Y%m%d%H%M%S')}"

def rupiah(x):
    try:
        return f"Rp {float(x):,.0f}".replace(',', '.')
    except Exception:
        return 'Rp 0'

def to_excel(data_dict, filename):
    """Export dict of lists to Excel file."""
    output = BytesIO()
    with pd.ExcelWriter(output, engine='openpyxl') as writer:
        for sheet_name, rows in data_dict.items():
            df = pd.DataFrame(rows)
            df.to_excel(writer, sheet_name=sheet_name, index=False)
    output.seek(0)
    return send_file(output, as_attachment=True, download_name=filename, mimetype='application/vnd.openxmlformats-officedocument.spreadsheetml.sheet')

def add_timeline(loan_id, status, note='', created_by=None):
    exec_sql('INSERT INTO loan_timeline(loan_id, status, note, created_by) VALUES (?, ?, ?, ?)', [loan_id, status, note, created_by or session.get('user_id')])

def parse_float(v, default=0.0):
    try:
        return float(v)
    except Exception:
        return default

def current_user():
    if 'user_id' not in session:
        return None
    return q_one('SELECT * FROM users WHERE id=?', [session['user_id']])

def get_ip():
    return request.headers.get('X-Forwarded-For', request.remote_addr or '-')

def get_ua():
    return (request.headers.get('User-Agent') or '-')[:250]

def log_action(action, entity, entity_id='', detail=''):
    username = session.get('username', 'system')
    exec_sql(
        'INSERT INTO audit_logs(log_time, username, action, entity, entity_id, detail, ip_address, user_agent) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        [now_str(), username, action, entity, str(entity_id), detail, get_ip(), get_ua()]
    )

def get_account_id(code):
    row = q_one('SELECT id FROM accounts WHERE account_code=?', [code])
    return int(row['id']) if row else None

def post_journal(entry_date, description, lines, ref_type=None, ref_id=None, created_by=None):
    entry_no = gen_code('JU')
    payload = []
    for line in lines:
        payload.append((entry_no, entry_date, description, line['account_id'], line.get('debit', 0), line.get('credit', 0), ref_type, ref_id, created_by))
    exec_sql('''
        INSERT INTO journal_entries(entry_no, entry_date, description, account_id, debit, credit, ref_type, ref_id, created_by)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    ''', payload, many=True)
    return entry_no

def reverse_journal(entry_date, description, original_ref_type, original_ref_id, created_by=None):
    rows = q_all('SELECT account_id, debit, credit FROM journal_entries WHERE ref_type=? AND ref_id=?', [original_ref_type, original_ref_id])
    if not rows:
        return None
    lines = []
    for r in rows:
        lines.append({'account_id': r['account_id'], 'debit': float(r['credit']), 'credit': float(r['debit'])})
    return post_journal(entry_date, description, lines, ref_type=f'reversal_{original_ref_type}', ref_id=original_ref_id, created_by=created_by)

def is_period_locked(date_str):
    mk = month_key(date_str)
    row = q_one('SELECT 1 FROM period_locks WHERE period_month=? AND is_locked=1', [mk])
    return row is not None

def require_open_period(date_str):
    if is_period_locked(date_str):
        flash(f'Periode {month_key(date_str)} sudah ditutup / dikunci.', 'error')
        return False
    return True

def get_setting(key, default=None):
    row = q_one('SELECT value FROM settings WHERE key=?', [key])
    return row['value'] if row else default

def set_setting(key, value):
    exec_sql('INSERT INTO settings(key, value) VALUES(?, ?) ON CONFLICT(key) DO UPDATE SET value=excluded.value', [key, str(value)])

def date_range_from_request(prefix=''):
    start = request.args.get(f'{prefix}start', '') or request.form.get(f'{prefix}start', '')
    end = request.args.get(f'{prefix}end', '') or request.form.get(f'{prefix}end', '')
    return start, end

def add_date_filter(sql, date_field, start, end, params):
    if start:
        sql += f' AND {date_field} >= ?'
        params.append(start)
    if end:
        sql += f' AND {date_field} <= ?'
        params.append(end)
    return sql, params

def get_cart():
    if 'cart' not in session:
        session['cart'] = []
    return session['cart']

def save_cart(cart):
    session['cart'] = cart
    session.modified = True

DEFAULT_PER_PAGE = 20

def paginate_query(sql, params, page=None, per_page=None):
    """Generic pagination: count total, fetch page, return dict."""
    if per_page is None:
        per_page = int(get_setting('per_page', str(DEFAULT_PER_PAGE)))
    page = max(1, int(page or 1))
    # count
    count_sql = f"SELECT COUNT(*) as n FROM ({sql})"
    total = q_one(count_sql, params)['n'] or 0
    total_pages = max(1, (total + per_page - 1) // per_page)
    if page > total_pages:
        page = total_pages
    offset = (page - 1) * per_page
    data_sql = f"{sql} LIMIT ? OFFSET ?"
    rows = q_all(data_sql, params + [per_page, offset])
    return {'rows': rows, 'page': page, 'per_page': per_page, 'total': total, 'total_pages': total_pages}

def render_pagination(p, endpoint, extra_params=None):
    """HTML pagination controls."""
    if p['total_pages'] <= 1:
        return ''
    if extra_params is None:
        extra_params = {}
    parts = ['<nav style="display:flex;gap:6px;align-items:center;justify-content:center;margin:16px 0;flex-wrap:wrap;">']
    def lnk(pg, label, disabled=False):
        cls = 'btn btn-sm btn-ghost' if not disabled else 'btn btn-sm btn-ghost" style="pointer-events:none;opacity:0.4'
        params = '&'.join(f'{k}={v}' for k, v in extra_params.items() if v)
        sep = '&' if params else ''
        return f'<a class="{cls}" href="{url_for(endpoint, page=pg)}{sep}{params}">{label}</a>'
    parts.append(lnk(1, '«', p['page'] == 1))
    parts.append(lnk(max(1, p['page']-1), '‹', p['page'] == 1))
    start = max(1, p['page'] - 2)
    end = min(p['total_pages'], p['page'] + 2)
    for pg in range(start, end + 1):
        if pg == p['page']:
            parts.append(f'<span class="btn btn-sm btn-ghost" style="background:var(--primary);color:white;border-color:var(--primary);pointer-events:none;">{pg}</span>')
        else:
            parts.append(lnk(pg, str(pg)))
    parts.append(lnk(min(p['total_pages'], p['page']+1), '›', p['page'] == p['total_pages']))
    parts.append(lnk(p['total_pages'], '»', p['page'] == p['total_pages']))
    parts.append(f'<span class="muted small" style="margin-left:8px;">Hal {p["page"]}/{p["total_pages"]} ({p["total"]} data)</span>')
    parts.append('</nav>')
    return ''.join(parts)

# =========================
# DB Init
# =========================
def init_db():
    conn = get_conn()
    cur = conn.cursor()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            full_name TEXT,
            phone TEXT,
            address TEXT,
            employee_number TEXT UNIQUE,
            password_hash TEXT,
            role TEXT DEFAULT 'user',
            status TEXT DEFAULT 'PENDING_APPROVAL',
            approved_by INTEGER,
            approved_at TEXT,
            reject_reason TEXT,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(approved_by) REFERENCES users(id)
        )
    ''')

    def add_column_if_not_exists(table, column, definition):
        try:
            cur.execute(f'ALTER TABLE {table} ADD COLUMN {column} {definition}')
            conn.commit()
        except:
            pass
    
    add_column_if_not_exists('users', 'phone', 'TEXT')
    add_column_if_not_exists('users', 'address', 'TEXT')
    add_column_if_not_exists('users', 'status', 'TEXT DEFAULT "PENDING_APPROVAL"')
    add_column_if_not_exists('users', 'approved_by', 'INTEGER')
    add_column_if_not_exists('users', 'approved_at', 'TEXT')
    add_column_if_not_exists('users', 'employee_number', 'TEXT UNIQUE')
    add_column_if_not_exists('users', 'reject_reason', 'TEXT')
    add_column_if_not_exists('users', 'active', 'INTEGER DEFAULT 1')
    
    add_column_if_not_exists('loans', 'loan_type_id', 'INTEGER')
    add_column_if_not_exists('loans', 'interest_rate', 'REAL DEFAULT 0')
    add_column_if_not_exists('loans', 'admin_note', 'TEXT')
    add_column_if_not_exists('loans', 'calculated_by', 'INTEGER')
    add_column_if_not_exists('loans', 'calculated_at', 'TEXT')
    add_column_if_not_exists('loans', 'total_paid', 'REAL DEFAULT 0')
    add_column_if_not_exists('loans', 'late_penalty', 'REAL DEFAULT 0')
    
    conn.commit()

    cur.execute('''
        CREATE TABLE IF NOT EXISTS members (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_code TEXT UNIQUE,
            name TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            join_date TEXT,
            status TEXT DEFAULT 'Aktif',
            saldo REAL DEFAULT 0,
            shu_balance REAL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    try:
        cur.execute('ALTER TABLE members ADD COLUMN saldo REAL DEFAULT 0')
    except:
        pass
    try:
        cur.execute('ALTER TABLE members ADD COLUMN shu_balance REAL DEFAULT 0')
    except:
        pass

    cur.execute('''
        CREATE TABLE IF NOT EXISTS topup_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER,
            nominal REAL DEFAULT 0,
            bukti_foto TEXT,
            status TEXT DEFAULT 'PENDING',
            note TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            approved_at TEXT,
            approved_by INTEGER,
            FOREIGN KEY(member_id) REFERENCES members(id),
            FOREIGN KEY(approved_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS saldo_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            member_id INTEGER,
            tipe TEXT,
            nominal REAL DEFAULT 0,
            saldo_sebelum REAL DEFAULT 0,
            saldo_setelah REAL DEFAULT 0,
            keterangan TEXT,
            reference_id INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            created_by INTEGER,
            FOREIGN KEY(member_id) REFERENCES members(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS products (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            barcode TEXT UNIQUE,
            product_name TEXT NOT NULL,
            category TEXT,
            unit TEXT DEFAULT 'pcs',
            buy_price REAL DEFAULT 0,
            sell_price REAL DEFAULT 0,
            stock REAL DEFAULT 0,
            min_stock REAL DEFAULT 0,
            active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS sales (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_no TEXT UNIQUE,
            trx_date TEXT,
            member_id INTEGER,
            cashier_id INTEGER,
            customer_name TEXT,
            total REAL DEFAULT 0,
            paid REAL DEFAULT 0,
            change_amount REAL DEFAULT 0,
            note TEXT,
            status TEXT DEFAULT 'Posted',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(member_id) REFERENCES members(id),
            FOREIGN KEY(cashier_id) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS sales_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sales_id INTEGER,
            product_id INTEGER,
            barcode TEXT,
            product_name TEXT,
            qty REAL DEFAULT 0,
            price REAL DEFAULT 0,
            subtotal REAL DEFAULT 0,
            FOREIGN KEY(sales_id) REFERENCES sales(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS savings_transactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            trx_no TEXT,
            trx_date TEXT,
            member_id INTEGER,
            saving_type TEXT,
            direction TEXT,
            amount REAL DEFAULT 0,
            note TEXT,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(member_id) REFERENCES members(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS loan_types (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            description TEXT,
            interest_rate_monthly REAL DEFAULT 0,
            admin_fee_fixed REAL DEFAULT 0,
            admin_fee_percent REAL DEFAULT 0,
            min_tenor INTEGER DEFAULT 1,
            max_tenor INTEGER DEFAULT 36,
            max_amount REAL DEFAULT 25000000,
            metode_bunga TEXT DEFAULT 'FLAT',
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    add_column_if_not_exists('loan_types', 'metode_bunga', 'TEXT DEFAULT "FLAT"')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS loans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            loan_no TEXT UNIQUE,
            member_id INTEGER,
            loan_type_id INTEGER,
            loan_date TEXT,
            principal REAL DEFAULT 0,
            service_fee REAL DEFAULT 0,
            interest_rate REAL DEFAULT 0,
            tenor_month INTEGER DEFAULT 1,
            total_receivable REAL DEFAULT 0,
            monthly_installment REAL DEFAULT 0,
            admin_note TEXT,
            status TEXT DEFAULT 'DRAFT',
            note TEXT,
            created_by INTEGER,
            calculated_by INTEGER,
            calculated_at TEXT,
            approved_by INTEGER,
            approved_at TEXT,
            total_paid REAL DEFAULT 0,
            late_penalty REAL DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(member_id) REFERENCES members(id),
            FOREIGN KEY(loan_type_id) REFERENCES loan_types(id),
            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(calculated_by) REFERENCES users(id),
            FOREIGN KEY(approved_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS loan_schedules (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            loan_id INTEGER,
            installment_number INTEGER,
            due_date TEXT,
            amount REAL DEFAULT 0,
            principal_amount REAL DEFAULT 0,
            interest_amount REAL DEFAULT 0,
            paid_date TEXT,
            paid_amount REAL DEFAULT 0,
            penalty_amount REAL DEFAULT 0,
            status TEXT DEFAULT 'BELUM_BAYAR',
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(loan_id) REFERENCES loans(id) ON DELETE CASCADE
        )
    ''')
    add_column_if_not_exists('loan_schedules', 'penalty_amount', 'REAL DEFAULT 0')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS loan_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            loan_id INTEGER,
            payment_date TEXT,
            amount REAL DEFAULT 0,
            penalty_amount REAL DEFAULT 0,
            payment_method TEXT DEFAULT 'tunai',
            transfer_bank TEXT,
            transfer_proof TEXT,
            status TEXT DEFAULT 'VERIFIED',
            verified_by INTEGER,
            verified_at TEXT,
            note TEXT,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(loan_id) REFERENCES loans(id) ON DELETE CASCADE,
            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(verified_by) REFERENCES users(id)
        )
    ''')
    add_column_if_not_exists('loan_payments', 'penalty_amount', 'REAL DEFAULT 0')
    
    add_column_if_not_exists('loan_payments', 'payment_method', 'TEXT DEFAULT "tunai"')
    add_column_if_not_exists('loan_payments', 'transfer_bank', 'TEXT')
    add_column_if_not_exists('loan_payments', 'transfer_proof', 'TEXT')
    add_column_if_not_exists('loan_payments', 'status', 'TEXT DEFAULT "VERIFIED"')
    add_column_if_not_exists('loan_payments', 'verified_by', 'INTEGER')
    add_column_if_not_exists('loan_payments', 'verified_at', 'TEXT')
    add_column_if_not_exists('loan_schedules', 'payment_id', 'INTEGER')
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS loan_documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            loan_id INTEGER,
            name TEXT,
            description TEXT,
            required INTEGER DEFAULT 1,
            file_name TEXT,
            uploaded_at TEXT,
            uploaded_by INTEGER,
            status TEXT DEFAULT 'PENDING',
            admin_note TEXT,
            verified_by INTEGER,
            verified_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(loan_id) REFERENCES loans(id) ON DELETE CASCADE
        )
    ''')
    
    cur.execute('''
        CREATE TABLE IF NOT EXISTS loan_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            loan_id INTEGER,
            status TEXT,
            note TEXT,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(loan_id) REFERENCES loans(id) ON DELETE CASCADE
        )
    ''')
    
    add_column_if_not_exists('loans', 'current_stage', 'TEXT DEFAULT "SUBMITTED"')
    add_column_if_not_exists('loans', 'progress_percent', 'INTEGER DEFAULT 10')
    add_column_if_not_exists('sales', 'payment_method', 'TEXT DEFAULT "tunai"')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS stock_movements (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            product_id INTEGER,
            movement_type TEXT,
            qty REAL DEFAULT 0,
            unit_cost REAL DEFAULT 0,
            note TEXT,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS suppliers (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            supplier_code TEXT UNIQUE,
            name TEXT NOT NULL,
            phone TEXT,
            address TEXT,
            contact_person TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS purchase_orders (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            po_no TEXT UNIQUE,
            po_date TEXT,
            supplier_id INTEGER,
            total REAL DEFAULT 0,
            status TEXT DEFAULT 'DRAFT',
            note TEXT,
            created_by INTEGER,
            received_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(supplier_id) REFERENCES suppliers(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS purchase_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            po_id INTEGER,
            product_id INTEGER,
            qty REAL DEFAULT 0,
            price REAL DEFAULT 0,
            subtotal REAL DEFAULT 0,
            FOREIGN KEY(po_id) REFERENCES purchase_orders(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS accounts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            account_code TEXT UNIQUE,
            account_name TEXT,
            category TEXT,
            normal_balance TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS journal_entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            entry_no TEXT,
            entry_date TEXT,
            description TEXT,
            account_id INTEGER,
            debit REAL DEFAULT 0,
            credit REAL DEFAULT 0,
            ref_type TEXT,
            ref_id INTEGER,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(account_id) REFERENCES accounts(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS approval_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            request_type TEXT,
            ref_table TEXT,
            ref_id INTEGER,
            status TEXT DEFAULT 'Pending',
            reason TEXT,
            created_by INTEGER,
            approved_by INTEGER,
            approved_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(approved_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS period_locks (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            period_month TEXT UNIQUE,
            is_locked INTEGER DEFAULT 1,
            note TEXT,
            locked_by INTEGER,
            locked_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(locked_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            log_time TEXT,
            username TEXT,
            action TEXT,
            entity TEXT,
            entity_id TEXT,
            detail TEXT,
            ip_address TEXT,
            user_agent TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS notifications (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            title TEXT,
            message TEXT,
            is_read INTEGER DEFAULT 0,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(user_id) REFERENCES users(id)
        )
    ''')

    default_users = [
        ('admin', 'Administrator', hash_password('admin123'), 'admin', 1, 'ACTIVE'),
        ('kasir', 'User Kasir', hash_password('kasir123'), 'kasir', 1, 'ACTIVE'),
        ('bendahara', 'User Bendahara', hash_password('bendahara123'), 'bendahara', 1, 'ACTIVE'),
        ('supervisor', 'User Supervisor', hash_password('supervisor123'), 'supervisor', 1, 'ACTIVE'),
    ]
    cur.executemany('INSERT OR IGNORE INTO users(username, full_name, password_hash, role, active, status) VALUES (?, ?, ?, ?, ?, ?)', default_users)

    default_accounts = [
        ('1001', 'Kas', 'Aset', 'Debit'),
        ('1101', 'Piutang Pinjaman', 'Aset', 'Debit'),
        ('1102', 'Piutang Denda', 'Aset', 'Debit'),
        ('1201', 'Persediaan Barang', 'Aset', 'Debit'),
        ('2001', 'Simpanan Anggota', 'Kewajiban', 'Kredit'),
        ('2101', 'SHU Belum Dibagi', 'Kewajiban', 'Kredit'),
        ('3001', 'Modal', 'Modal', 'Kredit'),
        ('4001', 'Penjualan', 'Pendapatan', 'Kredit'),
        ('4101', 'Pendapatan Jasa Pinjaman', 'Pendapatan', 'Kredit'),
        ('4201', 'Pendapatan Denda', 'Pendapatan', 'Kredit'),
        ('5001', 'Harga Pokok Penjualan', 'Beban', 'Debit'),
        ('6001', 'Beban Operasional', 'Beban', 'Debit')
    ]
    cur.executemany('INSERT OR IGNORE INTO accounts(account_code, account_name, category, normal_balance) VALUES (?, ?, ?, ?)', default_accounts)

    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('loan_auto_approve_limit', ?)", (str(LOAN_AUTO_APPROVE_LIMIT),))
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('manual_journal_approve_limit', ?)", (str(MANUAL_JOURNAL_APPROVE_LIMIT),))
    cur.execute("INSERT OR IGNORE INTO settings(key, value) VALUES('late_penalty_percent', ?)", (str(LATE_PENALTY_PERCENT),))

    cur.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT UNIQUE NOT NULL,
            description TEXT,
            is_active INTEGER DEFAULT 1,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS quick_cashier_queue (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            invoice_no TEXT,
            trx_date TEXT,
            total REAL DEFAULT 0,
            payment_method TEXT DEFAULT 'tunai',
            member_id INTEGER,
            customer_name TEXT,
            note TEXT,
            status TEXT DEFAULT 'PENDING',
            created_by INTEGER,
            verified_by INTEGER,
            verified_at TEXT,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(member_id) REFERENCES members(id),
            FOREIGN KEY(created_by) REFERENCES users(id),
            FOREIGN KEY(verified_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS quick_cashier_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            queue_id INTEGER,
            product_id INTEGER,
            product_name TEXT,
            qty REAL DEFAULT 0,
            price REAL DEFAULT 0,
            subtotal REAL DEFAULT 0,
            FOREIGN KEY(queue_id) REFERENCES quick_cashier_queue(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS sales_returns (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_no TEXT UNIQUE,
            sales_id INTEGER,
            member_id INTEGER,
            return_date TEXT,
            total REAL DEFAULT 0,
            reason TEXT,
            status TEXT DEFAULT 'Posted',
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(sales_id) REFERENCES sales(id),
            FOREIGN KEY(member_id) REFERENCES members(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS sales_return_items (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            return_id INTEGER,
            product_id INTEGER,
            qty REAL DEFAULT 0,
            price REAL DEFAULT 0,
            subtotal REAL DEFAULT 0,
            FOREIGN KEY(return_id) REFERENCES sales_returns(id) ON DELETE CASCADE,
            FOREIGN KEY(product_id) REFERENCES products(id)
        )
    ''')

    cur.execute('''
        CREATE TABLE IF NOT EXISTS supplier_payments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            po_id INTEGER,
            supplier_id INTEGER,
            amount REAL DEFAULT 0,
            payment_date TEXT,
            payment_method TEXT DEFAULT 'tunai',
            note TEXT,
            created_by INTEGER,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            FOREIGN KEY(po_id) REFERENCES purchase_orders(id),
            FOREIGN KEY(supplier_id) REFERENCES suppliers(id),
            FOREIGN KEY(created_by) REFERENCES users(id)
        )
    ''')

    cur.execute('SELECT COUNT(*) FROM members')
    if cur.fetchone()[0] == 0:
        cur.execute('INSERT INTO members(member_code, name, phone, address, join_date, status) VALUES (?, ?, ?, ?, ?, ?)', ('MBR-001', 'Member Demo', '08123456789', 'Alamat Demo', today_str(), 'Aktif'))

    cur.execute('SELECT COUNT(*) FROM products')
    if cur.fetchone()[0] == 0:
        demo_products = [
            ('899100100001', 'Beras 5 Kg', 'Sembako', 'sak', 60000, 67000, 25, 5, 1),
            ('899100100002', 'Minyak 1 L', 'Sembako', 'botol', 14500, 16500, 60, 10, 1),
            ('899100100003', 'Gula 1 Kg', 'Sembako', 'kg', 15500, 17500, 40, 8, 1),
        ]
        cur.executemany('INSERT INTO products(barcode, product_name, category, unit, buy_price, sell_price, stock, min_stock, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', demo_products)

    conn.commit()
    conn.close()

# =========================
# Helper: Notifikasi
# =========================
def add_notification(user_id, title, message):
    exec_sql('INSERT INTO notifications(user_id, title, message) VALUES (?, ?, ?)', [user_id, title, message])

def get_unread_notifications(user_id):
    return q_all('SELECT * FROM notifications WHERE user_id = ? AND is_read = 0 ORDER BY id DESC LIMIT 10', [user_id])

def notify_member(member_id, title, message):
    """Buat notifikasi untuk user yang terhubung ke member."""
    member_code = member_id if isinstance(member_id, str) else 'EMP-' + str(member_id)
    emp_no = member_code.replace('EMP-', '')
    user = q_one('SELECT id FROM users WHERE employee_number = ?', [emp_no])
    if user:
        add_notification(user['id'], title, message)

# =========================
# Notifications Page for Member
# =========================
@app.route('/member/notifications')
@login_required
def member_notifications():
    user = current_user()
    notifs = q_all('SELECT * FROM notifications WHERE user_id = ? ORDER BY id DESC LIMIT 100', [user['id']])
    unread_count = q_one('SELECT COUNT(*) as n FROM notifications WHERE user_id = ? AND is_read = 0', [user['id']])['n'] or 0
    if request.args.get('mark_read'):
        exec_sql('UPDATE notifications SET is_read = 1 WHERE user_id = ?', [user['id']])
        flash('Semua notifikasi ditandai sudah dibaca.', 'success')
        return redirect(url_for('member_notifications'))
    body = render_template_string('''
    <div class="card">
        <div class="kartu">
            <h2>🔔 Notifikasi Saya</h2>
            {% if unread_count > 0 %}
            <a href="?mark_read=1" class="btn btn-sm">✅ Tandai Semua Dibaca</a>
            {% endif %}
        </div>
        <div class="muted small">{{ unread_count }} belum dibaca dari {{ notifs|length }} total</div>
        <hr>
        {% for n in notifs %}
        <div style="padding:14px;border-bottom:1px solid var(--border);{% if not n.is_read %}background:var(--primary-light);border-left:3px solid var(--primary);{% endif %}border-radius:8px;margin-bottom:8px;">
            <div style="display:flex;justify-content:space-between;gap:8px;">
                <div>
                    <strong style="font-size:14px;">{{ n.title }}</strong>
                    <div style="font-size:13px;color:var(--text-muted);margin-top:4px;">{{ n.message }}</div>
                </div>
                <div class="muted small" style="white-space:nowrap;padding-top:2px;">{{ n.created_at[:16] }}</div>
            </div>
            {% if not n.is_read %}
            <div style="margin-top:6px;">
                <span class="badge badge-info" style="font-size:10px;">Baru</span>
            </div>
            {% endif %}
        </div>
        {% else %}
        <div class="muted text-center" style="padding:40px 0;">
            <div style="font-size:48px;margin-bottom:16px;">🔔</div>
            <div>Tidak ada notifikasi</div>
            <div class="small muted">Notifikasi akan muncul saat ada aktivitas terkait akun Anda.</div>
        </div>
        {% endfor %}
    </div>
    ''', notifs=notifs, unread_count=unread_count)
    return render_page('Notifikasi', body)

# =========================
# Helper: Hitung Denda
# =========================
def calculate_penalty(due_date_str, payment_date_str, amount, penalty_rate=None):
    if penalty_rate is None:
        penalty_rate = float(get_setting('late_penalty_percent', LATE_PENALTY_PERCENT))
    try:
        due = datetime.strptime(due_date_str, '%Y-%m-%d').date()
        pay = datetime.strptime(payment_date_str, '%Y-%m-%d').date()
        if pay <= due:
            return 0
        diff_days = (pay - due).days
        diff_months = max(1, diff_days // 30)
        penalty = amount * penalty_rate * diff_months
        return round(penalty, 2)
    except:
        return 0

# =========================
# Helper: Hitung SHU
# =========================
def calculate_shu(member_id, year=None):
    if year is None:
        year = datetime.now().year
    year_start = f"{year}-01-01"
    year_end = f"{year}-12-31"
    total_simpanan = q_one('SELECT COALESCE(SUM(CASE WHEN direction="Masuk" THEN amount ELSE -amount END), 0) as x FROM savings_transactions WHERE member_id = ? AND trx_date >= ? AND trx_date <= ?', [member_id, year_start, year_end])['x']
    total_belanja = q_one('SELECT COALESCE(SUM(total), 0) as x FROM sales WHERE member_id = ? AND trx_date >= ? AND trx_date <= ? AND status="Posted"', [member_id, year_start, year_end])['x']
    tb = q_all('SELECT category, COALESCE(SUM(debit),0) as debit, COALESCE(SUM(credit),0) as credit FROM journal_entries j JOIN accounts a ON a.id=j.account_id WHERE j.entry_date >= ? AND j.entry_date <= ? GROUP BY a.category', [year_start, year_end])
    revenue = 0
    expense = 0
    for r in tb:
        if r['category'] == 'Pendapatan':
            revenue += float(r['credit']) - float(r['debit'])
        elif r['category'] == 'Beban':
            expense += float(r['debit']) - float(r['credit'])
    laba_bersih = revenue - expense
    if laba_bersih <= 0:
        return 0
    alokasi_simpanan = laba_bersih * 0.30
    alokasi_belanja = laba_bersih * 0.30
    total_simpanan_all = q_one('SELECT COALESCE(SUM(CASE WHEN direction="Masuk" THEN amount ELSE -amount END), 0) as x FROM savings_transactions WHERE trx_date >= ? AND trx_date <= ?', [year_start, year_end])['x']
    total_belanja_all = q_one('SELECT COALESCE(SUM(total), 0) as x FROM sales WHERE trx_date >= ? AND trx_date <= ? AND status="Posted"', [year_start, year_end])['x']
    shu_simpanan = (total_simpanan / total_simpanan_all * alokasi_simpanan) if total_simpanan_all > 0 else 0
    shu_belanja = (total_belanja / total_belanja_all * alokasi_belanja) if total_belanja_all > 0 else 0
    return round(shu_simpanan + shu_belanja, 2)

# =========================
# Decorators
# =========================
def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if 'user_id' not in session:
            return redirect(url_for('login'))
        return func(*args, **kwargs)
    return wrapper

def role_required(*roles):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            user = current_user()
            if not user:
                return redirect(url_for('login'))
            if user['role'] not in roles:
                flash('Akses ditolak untuk role Anda.', 'error')
                return redirect(url_for('dashboard'))
            return func(*args, **kwargs)
        return wrapper
    return decorator

# =========================
# UI Helpers
# =========================
def bar_chart_svg(items, title='Chart', width=560, height=220, color='#22c55e'):
    if not items:
        return '<div class="muted">Belum ada data.</div>'
    values = [float(v) for _, v in items]
    maxv = max(values) if max(values) > 0 else 1
    left, top, bottom = 40, 20, 30
    plot_w = width - left - 10
    plot_h = height - top - bottom
    bw = max(20, plot_w // max(1, len(items) * 2))
    gap = bw
    x = left
    parts = [f'<svg width="100%" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">']
    parts.append(f'<text x="10" y="15" fill="#93c5fd" font-size="12">{title}</text>')
    parts.append(f'<line x1="{left}" y1="{top+plot_h}" x2="{left+plot_w}" y2="{top+plot_h}" stroke="#334155"/>')
    for label, val in items:
        h = (float(val) / maxv) * (plot_h - 10)
        y = top + plot_h - h
        parts.append(f'<rect x="{x}" y="{y}" width="{bw}" height="{h}" rx="6" fill="{color}"/>')
        parts.append(f'<text x="{x+bw/2}" y="{top+plot_h+14}" text-anchor="middle" fill="#94a3b8" font-size="10">{label}</text>')
        parts.append(f'<text x="{x+bw/2}" y="{max(top+12, y-4)}" text-anchor="middle" fill="#e5e7eb" font-size="10">{int(val)}</text>')
        x += bw + gap
    parts.append('</svg>')
    return ''.join(parts)

def grouped_bar_chart_svg(items_a, items_b, title='Chart', width=560, height=240, color_a='#2563eb', color_b='#10b981', label_a='Series A', label_b='Series B'):
    if not items_a and not items_b:
        return '<div class="muted">Belum ada data.</div>'
    labels = [l for l, _ in items_a]
    vals_a = [float(v) for _, v in items_a]
    b_map = {l: float(v) for l, v in items_b}
    vals_b = [b_map.get(l, 0) for l in labels]
    all_vals = vals_a + vals_b
    maxv = max(all_vals) if all_vals and max(all_vals) > 0 else 1
    left, top, bottom = 45, 20, 35
    plot_w = width - left - 10
    plot_h = height - top - bottom
    n = max(1, len(labels))
    group_w = plot_w / n
    bw = max(8, group_w / 4)
    x = left
    parts = [f'<svg width="100%" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">']
    parts.append(f'<text x="10" y="15" fill="#93c5fd" font-size="12">{title}</text>')
    parts.append(f'<line x1="{left}" y1="{top+plot_h}" x2="{left+plot_w}" y2="{top+plot_h}" stroke="#334155"/>')
    lx = left + 10
    parts.append(f'<rect x="{lx}" y="{height-14}" width="10" height="10" rx="2" fill="{color_a}"/>')
    parts.append(f'<text x="{lx+14}" y="{height-5}" fill="#94a3b8" font-size="10">{label_a}</text>')
    lx2 = lx + 80
    parts.append(f'<rect x="{lx2}" y="{height-14}" width="10" height="10" rx="2" fill="{color_b}"/>')
    parts.append(f'<text x="{lx2+14}" y="{height-5}" fill="#94a3b8" font-size="10">{label_b}</text>')
    for i, label in enumerate(labels):
        va = vals_a[i] if i < len(vals_a) else 0
        vb = vals_b[i] if i < len(vals_b) else 0
        ha = (va / maxv) * (plot_h - 10) if maxv > 0 else 0
        hb = (vb / maxv) * (plot_h - 10) if maxv > 0 else 0
        mid = x + group_w / 2
        ax = mid - bw - 1
        bx = mid + 1
        ya = top + plot_h - ha
        yb = top + plot_h - hb
        if ha > 0:
            parts.append(f'<rect x="{ax}" y="{ya}" width="{bw}" height="{ha}" rx="4" fill="{color_a}"/>')
            parts.append(f'<text x="{ax+bw/2}" y="{max(top+12, ya-3)}" text-anchor="middle" fill="#e5e7eb" font-size="9">{int(va):,}</text>')
        if hb > 0:
            parts.append(f'<rect x="{bx}" y="{yb}" width="{bw}" height="{hb}" rx="4" fill="{color_b}"/>')
            parts.append(f'<text x="{bx+bw/2}" y="{max(top+12, yb-3)}" text-anchor="middle" fill="#e5e7eb" font-size="9">{int(vb):,}</text>')
        parts.append(f'<text x="{mid}" y="{top+plot_h+14}" text-anchor="middle" fill="#94a3b8" font-size="10">{label}</text>')
        x += group_w
    parts.append('</svg>')
    return ''.join(parts)

def pie_chart_svg(items, title='Chart', width=400, height=280, colors=None):
    """SVG pie chart sederhana."""
    if not items:
        return '<div class="muted">Belum ada data.</div>'
    if colors is None:
        colors = ['#4f46e5','#10b981','#f59e0b','#ef4444','#8b5cf6','#ec4899','#14b8a6','#f97316','#6366f1','#84cc16']
    values = [max(0, float(v)) for _, v in items]
    total = sum(values)
    if total <= 0:
        return '<div class="muted">Belum ada data.</div>'
    cx, cy, r = 130, 140, 110
    parts = [f'<svg width="100%" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">']
    parts.append(f'<text x="10" y="15" fill="#93c5fd" font-size="12">{title}</text>')
    angle_start = -90
    cos = math.cos
    sin = math.sin
    for i, (label, val) in enumerate(items):
        val_f = max(0, float(val))
        if val_f <= 0: continue
        angle = (val_f / total) * 360
        angle_end = angle_start + angle
        a1_rad = angle_start * 3.14159 / 180
        a2_rad = angle_end * 3.14159 / 180
        x1 = cx + r * cos(a1_rad)
        y1 = cy + r * sin(a1_rad)
        x2 = cx + r * cos(a2_rad)
        y2 = cy + r * sin(a2_rad)
        large = 1 if angle > 180 else 0
        color = colors[i % len(colors)]
        parts.append(f'<path d="M{cx},{cy} L{x1:.1f},{y1:.1f} A{r},{r} 0 {large},1 {x2:.1f},{y2:.1f} Z" fill="{color}" stroke="white" stroke-width="2"/>')
        parts.append(f'<text x="260" y="{30 + i*22}" fill="#e5e7eb" font-size="12"><tspan fill="{color}" font-size="14">●</tspan> {label[:18]}</text>')
        parts.append(f'<text x="350" y="{30 + i*22}" text-anchor="end" fill="#94a3b8" font-size="12">{int(val_f):,}</text>')
        angle_start = angle_end
    parts.append('</svg>')
    return ''.join(parts)

def simple_qr_svg(data, size=140):
    """Generate a simplified QR-like pattern SVG for member card."""
    h = hashlib.md5(data.encode()).hexdigest()
    bits = ''.join(format(int(c, 16), '04b') for c in h)
    n = 11
    cell = size / n
    parts = [f'<svg width="{size}" height="{size}" viewBox="0 0 {size} {size}" xmlns="http://www.w3.org/2000/svg">']
    # White background
    parts.append(f'<rect width="{size}" height="{size}" rx="8" fill="white"/>')
    # Fixed corner patterns
    for cx, cy in [(1,1), (1,n-3-1), (n-3-1,1)]:
        parts.append(f'<rect x="{cx*cell}" y="{cy*cell}" width="{3*cell}" height="{3*cell}" rx="4" fill="#1e293b"/>')
        if cx == 1 and cy == 1:
            parts.append(f'<rect x="{(cx+0.5)*cell}" y="{(cy+0.5)*cell}" width="{2*cell}" height="{2*cell}" rx="2" fill="white"/>')
        elif cx == 1:
            parts.append(f'<rect x="{(cx+0.5)*cell}" y="{(cy+0.5)*cell}" width="{2*cell}" height="{2*cell}" rx="2" fill="white"/>')
        elif cy == 1:
            parts.append(f'<rect x="{(cx+0.5)*cell}" y="{(cy+0.5)*cell}" width="{2*cell}" height="{2*cell}" rx="2" fill="white"/>')
    # Data modules from hash
    idx = 0
    for row in range(n):
        for col in range(n):
            if (row < 4 and col < 4) or (row < 4 and col >= n-4) or (row >= n-4 and col < 4):
                if row < 3 and col < 3: continue
                if row < 3 and col >= n-3: continue
                if row >= n-3 and col < 3: continue
            if idx < len(bits) and bits[idx] == '1':
                parts.append(f'<rect x="{col*cell+cell*0.15}" y="{row*cell+cell*0.15}" width="{cell*0.7}" height="{cell*0.7}" rx="2" fill="#1e293b"/>')
            idx += 1
    parts.append('</svg>')
    return ''.join(parts)

def horizontal_bar_chart_svg(items, title='Chart', width=560, height=200, colors=None):
    if not items:
        return '<div class="muted">Belum ada data.</div>'
    if colors is None:
        colors = ['#2563eb', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899']
    values = [float(v) for _, v in items]
    maxv = max(values) if max(values) > 0 else 1
    left = 110
    bar_h = max(14, min(24, (height - 20) // len(items)))
    gap = 4
    parts = [f'<svg width="100%" viewBox="0 0 {width} {height}" xmlns="http://www.w3.org/2000/svg">']
    parts.append(f'<text x="10" y="15" fill="#93c5fd" font-size="12">{title}</text>')
    y = 28
    for i, (label, val) in enumerate(items):
        color = colors[i % len(colors)]
        bw = (float(val) / maxv) * (width - left - 20)
        bw = max(2, bw)
        parts.append(f'<text x="{left-8}" y="{y+bar_h/2+4}" text-anchor="end" fill="#94a3b8" font-size="11">{label[:16]}</text>')
        parts.append(f'<rect x="{left}" y="{y}" width="{bw}" height="{bar_h}" rx="4" fill="{color}"/>')
        parts.append(f'<text x="{left+bw+6}" y="{y+bar_h/2+4}" fill="#e5e7eb" font-size="10">{int(val):,}</text>')
        y += bar_h + gap
    parts.append('</svg>')
    return ''.join(parts)

# =========================
# UI REDESIGN: render_page with modern, clean design
# =========================
CSS_DESIGN = '''
*{box-sizing:border-box;margin:0;padding:0}
:root{
  --bg:#f5f7fa;
  --card:#ffffff;
  --text:#1e293b;
  --text-muted:#64748b;
  --border:#e2e8f0;
  --primary:#4f46e5;
  --primary-hover:#4338ca;
  --primary-light:#eef2ff;
  --success:#059669;
  --success-bg:#ecfdf5;
  --danger:#dc2626;
  --danger-bg:#fef2f2;
  --warn:#d97706;
  --warn-bg:#fffbeb;
  --info:#2563eb;
  --info-bg:#eff6ff;
  --radius:16px;
  --radius-sm:10px;
  --radius-xs:6px;
  --shadow:0 1px 3px rgba(0,0,0,0.04),0 1px 2px rgba(0,0,0,0.03);
  --shadow-md:0 4px 12px rgba(0,0,0,0.06);
  --shadow-lg:0 10px 30px rgba(0,0,0,0.08);
  --sidebar-width:260px;
}
body{
  font-family:'Plus Jakarta Sans','Inter','Segoe UI',system-ui,sans-serif;
  background:var(--bg);
  color:var(--text);
  min-height:100vh;
  line-height:1.6;
}
a{color:var(--primary);text-decoration:none}
a:hover{text-decoration:underline}

/* ====== LOGIN PAGE ====== */
.login-wrap{
  min-height:100vh;
  display:flex;
  position:relative;
  overflow:hidden;
}
.login-left{
  flex:1;
  display:flex;
  flex-direction:column;
  justify-content:center;
  align-items:center;
  padding:48px 40px;
  text-align:center;
  background:linear-gradient(160deg,#047857 0%,#059669 30%,#10b981 60%,#34d399 100%);
  position:relative;
  overflow:hidden;
}
.login-left::before{
  content:'';
  position:absolute;
  top:-120px;right:-120px;
  width:350px;height:350px;
  border-radius:50%;
  background:rgba(255,255,255,0.08);
}
.login-left::after{
  content:'';
  position:absolute;
  bottom:-80px;left:-80px;
  width:260px;height:260px;
  border-radius:50%;
  background:rgba(255,255,255,0.06);
}
.login-brand{position:relative;z-index:1}
.login-brand-icon{
  width:80px;height:80px;
  background:rgba(255,255,255,0.2);
  border-radius:24px;
  display:flex;align-items:center;justify-content:center;
  margin:0 auto 28px auto;
  font-size:40px;
  backdrop-filter:blur(10px);
  border:2px solid rgba(255,255,255,0.25);
  box-shadow:0 8px 32px rgba(0,0,0,0.1);
}
.login-brand h1{font-size:30px;font-weight:800;color:white;margin-bottom:6px;text-shadow:0 2px 8px rgba(0,0,0,0.15)}
.login-brand p{font-size:15px;color:rgba(255,255,255,0.85);max-width:380px;line-height:1.7;margin-bottom:36px}
.login-features{
  display:grid;
  grid-template-columns:1fr 1fr;
  gap:12px;
  max-width:420px;
  position:relative;z-index:1;
}
.login-feat{
  background:rgba(255,255,255,0.15);
  backdrop-filter:blur(8px);
  border:1px solid rgba(255,255,255,0.2);
  border-radius:14px;
  padding:16px 14px;
  text-align:left;
  transition:transform 0.2s,background 0.2s;
}
.login-feat:hover{transform:translateY(-2px);background:rgba(255,255,255,0.22)}
.login-feat-icon{font-size:24px;margin-bottom:8px;display:block}
.login-feat-title{font-size:13px;font-weight:700;color:white;margin-bottom:2px}
.login-feat-desc{font-size:11px;color:rgba(255,255,255,0.75);line-height:1.4}
.login-right{
  width:460px;
  min-width:380px;
  display:flex;
  align-items:center;
  justify-content:center;
  padding:48px 40px;
  background:white;
  position:relative;
}
.login-right::before{
  content:'';
  position:absolute;
  top:0;left:0;bottom:0;
  width:4px;
  background:linear-gradient(to bottom,#059669,#10b981,#34d399);
}
.login-card{
  width:100%;
  max-width:370px;
  animation:slideUp 0.5s ease;
}
.login-logo{
  width:60px;height:60px;
  background:linear-gradient(135deg,#059669,#10b981);
  border-radius:18px;
  display:flex;align-items:center;justify-content:center;
  margin:0 auto 24px auto;
  font-size:28px;
  color:white;
  box-shadow:0 6px 20px rgba(5,150,105,0.3);
}
.login-title{
  text-align:center;
  font-size:22px;font-weight:700;
  margin-bottom:4px;
  color:var(--text);
}
.login-sub{
  text-align:center;
  color:var(--text-muted);
  font-size:14px;
  margin-bottom:28px;
}
.login-field{
  margin-bottom:16px;
}
.login-field label{
  display:block;
  font-size:13px;font-weight:600;
  margin-bottom:6px;
  color:var(--text);
}
.login-input-wrap{
  position:relative;
}
.login-input-wrap input{
  width:100%;
  padding:12px 14px 12px 42px;
  background:var(--bg);
  border:1.5px solid var(--border);
  border-radius:var(--radius-sm);
  font-size:14px;
  outline:none;
  transition:all 0.2s;
  color:var(--text);
}
.login-input-wrap .login-input-icon{
  position:absolute;
  left:14px;top:50%;
  transform:translateY(-50%);
  font-size:16px;
  opacity:0.4;
  pointer-events:none;
}
.login-input-wrap input::placeholder{color:#94a3b8}
.login-input-wrap input:focus{
  border-color:#059669;
  background:white;
  box-shadow:0 0 0 3px rgba(5,150,105,0.1);
}
.login-pw-toggle{
  position:absolute;
  right:12px;top:50%;
  transform:translateY(-50%);
  background:none;border:none;
  cursor:pointer;font-size:16px;
  opacity:0.4;
  transition:opacity 0.2s;
  padding:4px;
}
.login-pw-toggle:hover{opacity:0.7}
.login-btn{
  width:100%;
  padding:13px;
  background:linear-gradient(135deg,#059669,#10b981);
  color:white;
  border:none;
  border-radius:var(--radius-sm);
  font-size:15px;
  font-weight:700;
  cursor:pointer;
  transition:all 0.2s;
  margin-top:8px;
  box-shadow:0 4px 14px rgba(5,150,105,0.3);
}
.login-btn:hover{
  background:linear-gradient(135deg,#047857,#059669);
  box-shadow:0 6px 20px rgba(5,150,105,0.4);
  transform:translateY(-1px);
}
.login-footer{
  text-align:center;
  margin-top:24px;
}
.login-footer a{font-size:13px;color:var(--text-muted)}
.login-footer a:hover{color:#059669}
.demo-toggle{
  text-align:center;
  margin-top:12px;
}
.demo-toggle a{
  font-size:12px;
  color:var(--text-muted);
  cursor:pointer;
  border-bottom:1px dashed var(--text-muted);
}
.demo-list{
  display:none;
  margin-top:12px;
  padding:12px;
  background:var(--bg);
  border-radius:var(--radius-sm);
  text-align:left;
}
.demo-list.show{display:block}
.demo-list div{font-size:12px;color:var(--text-muted);margin-bottom:4px;font-family:monospace}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-6px)}}
.login-brand-icon{animation:float 3s ease-in-out infinite}
@media(max-width:768px){
  .login-left{display:none}
  .login-right{width:100%;min-width:unset;border-left:none}
}

/* ====== APP LAYOUT ====== */
.app-wrap{display:flex;min-height:100vh}

/* Sidebar */
.sidebar{
  width:var(--sidebar-width);
  background:white;
  border-right:1px solid var(--border);
  position:fixed;
  top:0;left:0;bottom:0;
  z-index:100;
  overflow-y:auto;
  display:flex;
  flex-direction:column;
  transition:all 0.3s;
}
.sidebar-brand{
  padding:16px 20px;
  display:flex;align-items:center;gap:12px;
  border-bottom:1px solid var(--border);
}
.sidebar-brand .brand-icon{
  width:36px;height:36px;
  background:var(--primary);
  border-radius:10px;
  display:flex;align-items:center;justify-content:center;
  font-size:18px;
  color:white;
  flex-shrink:0;
}
.sidebar-brand .brand-text{font-weight:700;font-size:16px;color:var(--text)}
.sidebar-user{
  padding:12px 20px;
  border-bottom:1px solid var(--border);
  display:flex;align-items:center;gap:10px;
}
.sidebar-user .avatar{
  width:32px;height:32px;
  background:var(--primary-light);
  border-radius:8px;
  display:flex;align-items:center;justify-content:center;
  font-size:14px;
  flex-shrink:0;
}
.sidebar-user .user-info .uname{font-size:13px;font-weight:600;color:var(--text)}
.sidebar-user .user-info .urole{font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:0.5px}
.sidebar-nav{
  flex:1;
  padding:8px 0;
  overflow-y:auto;
}
/* Sidebar grouped sections */
.sidebar-section{margin-bottom:4px}
.sidebar-section-header{
  display:flex;align-items:center;justify-content:space-between;
  padding:8px 20px;
  font-size:11px;font-weight:700;
  color:var(--text-muted);
  text-transform:uppercase;
  letter-spacing:0.8px;
  cursor:pointer;
  user-select:none;
  transition:color 0.15s;
}
.sidebar-section-header:hover{color:var(--text)}
.sidebar-section-header .chevron{
  font-size:10px;
  transition:transform 0.2s;
}
.sidebar-section.collapsed .chevron{transform:rotate(-90deg)}
.sidebar-section.collapsed .sidebar-section-items{display:none}
.sidebar-section-items{padding:0 0 4px 0}
.sidebar-section-items a{
  display:flex;align-items:center;gap:10px;
  padding:8px 20px 8px 24px;
  color:var(--text);
  font-size:13px;
  transition:all 0.12s;
  border-radius:0;
  text-decoration:none;
}
.sidebar-section-items a:hover{
  background:var(--bg);
  text-decoration:none;
  color:var(--primary);
}
.sidebar-section-items a.active{
  background:var(--primary-light);
  color:var(--primary);
  font-weight:600;
  border-right:3px solid var(--primary);
}
.sidebar-section-items a .nav-icon{font-size:16px;width:22px;text-align:center;flex-shrink:0}
.sidebar-footer{
  padding:12px 20px;
  border-top:1px solid var(--border);
}
.sidebar-footer a{
  display:flex;align-items:center;gap:8px;
  padding:8px 0;
  color:var(--text-muted);
  font-size:13px;
  text-decoration:none;
}
.sidebar-footer a:hover{color:var(--danger);text-decoration:none}

/* Main content */
.main-content{
  margin-left:var(--sidebar-width);
  flex:1;
  padding:28px;
  min-width:0;
}
.topbar{
  display:flex;
  justify-content:space-between;
  align-items:center;
  margin-bottom:28px;
}
.page-header h1{font-size:22px;font-weight:700;color:var(--text)}
.page-header p{font-size:14px;color:var(--text-muted);margin-top:2px}
.hamburger{
  display:none;
  background:var(--card);border:1px solid var(--border);
  border-radius:var(--radius-sm);
  font-size:20px;
  cursor:pointer;padding:8px 12px;
  box-shadow:var(--shadow);
}
.topbar-actions{display:flex;gap:8px;align-items:center}

/* Quick actions */
.quick-actions{
  display:flex;gap:8px;flex-wrap:wrap;margin-bottom:24px;
}
.quick-actions a,.quick-actions button{
  display:inline-flex;align-items:center;gap:6px;
  padding:8px 16px;
  background:white;
  border:1.5px solid var(--border);
  border-radius:var(--radius-sm);
  font-size:13px;font-weight:600;
  color:var(--text);
  text-decoration:none;
  transition:all 0.15s;
}
.quick-actions a:hover,.quick-actions button:hover{
  border-color:var(--primary);
  color:var(--primary);
  background:var(--primary-light);
  text-decoration:none;
}

/* Cards */
.card{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:24px;
  box-shadow:var(--shadow);
  margin-bottom:16px;
}
.card h2{font-size:15px;font-weight:700;margin-bottom:14px;color:var(--text)}
.card h3{font-size:13px;font-weight:700;margin-bottom:10px;color:var(--text)}

/* Metric cards */
.metrics{display:grid;grid-template-columns:repeat(auto-fill,minmax(200px,1fr));gap:14px;margin-bottom:24px}
.metric{
  background:var(--card);
  border:1px solid var(--border);
  border-radius:var(--radius);
  padding:18px 20px;
  box-shadow:var(--shadow);
  transition:box-shadow 0.2s;
}
.metric:hover{box-shadow:var(--shadow-md)}
.metric .label{font-size:12px;color:var(--text-muted);font-weight:500}
.metric .value{font-size:22px;font-weight:800;margin-top:4px}
.metric .sub{font-size:11px;color:var(--text-muted);margin-top:4px}

/* Tables */
.table-wrap{overflow-x:auto;margin-top:8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{
  text-align:left;
  padding:10px 14px;
  border-bottom:2px solid var(--border);
  color:var(--text-muted);
  font-size:11px;
  font-weight:700;
  text-transform:uppercase;
  letter-spacing:0.5px;
  white-space:nowrap;
  background:var(--bg);
}
td{
  padding:10px 14px;
  border-bottom:1px solid var(--border);
  vertical-align:middle;
}
tr:hover td{background:#f8fafc}

/* Forms */
.form-group{margin-bottom:14px}
.form-group label{display:block;font-size:13px;font-weight:600;margin-bottom:6px;color:var(--text)}
input,select,textarea{
  width:100%;
  padding:10px 14px;
  border:1.5px solid var(--border);
  border-radius:var(--radius-sm);
  font-size:14px;
  outline:none;
  background:white;
  color:var(--text);
  transition:all 0.2s;
  font-family:inherit;
}
input:focus,select:focus,textarea:focus{
  border-color:var(--primary);
  box-shadow:0 0 0 3px rgba(79,70,229,0.08);
}
textarea{min-height:80px;resize:vertical}
button,.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:10px 20px;
  background:var(--primary);
  color:white;
  border:none;
  border-radius:var(--radius-sm);
  font-size:13px;font-weight:600;
  cursor:pointer;
  transition:all 0.15s;
  font-family:inherit;
}
button:hover,.btn:hover{background:var(--primary-hover);text-decoration:none}
.btn-sm{padding:6px 12px;font-size:12px}
.btn-success{background:var(--success)}
.btn-success:hover{background:#047857}
.btn-danger{background:var(--danger)}
.btn-danger:hover{background:#b91c1c}
.btn-warn{background:var(--warn);color:white}
.btn-warn:hover{background:#b45309}
.btn-ghost{background:transparent;border:1.5px solid var(--border);color:var(--text)}
.btn-ghost:hover{background:var(--bg);border-color:#cbd5e1}

/* Badges */
.badge{
  display:inline-block;
  padding:3px 10px;
  border-radius:var(--radius-xs);
  font-size:11px;
  font-weight:600;
}
.badge-success{background:var(--success-bg);color:#065f46}
.badge-danger{background:var(--danger-bg);color:#991b1b}
.badge-warn{background:var(--warn-bg);color:#92400e}
.badge-info{background:var(--info-bg);color:#1e40af}
.badge-gray{background:#f1f5f9;color:var(--text-muted)}

/* Flash */
.flash{
  padding:12px 16px;
  border-radius:var(--radius-sm);
  margin-bottom:14px;
  font-size:13px;
  font-weight:500;
  display:flex;align-items:center;gap:8px;
}
.flash-success{background:var(--success-bg);color:#065f46;border:1px solid #a7f3d0}
.flash-error{background:var(--danger-bg);color:#991b1b;border:1px solid #fca5a5}
.flash-warning{background:var(--warn-bg);color:#92400e;border:1px solid #fcd34d}

/* Grid */
.grid{display:grid;grid-template-columns:repeat(12,1fr);gap:16px}
.col-12{grid-column:span 12}
.col-9{grid-column:span 9}
.col-8{grid-column:span 8}
.col-6{grid-column:span 6}
.col-4{grid-column:span 4}
.col-3{grid-column:span 3}

/* Misc */
.muted{color:var(--text-muted)}
.small{font-size:12px}
.text-right{text-align:right}
.text-center{text-align:center}
hr{border:none;border-top:1px solid var(--border);margin:16px 0}
.kartu{display:flex;gap:12px;justify-content:space-between;align-items:flex-start;flex-wrap:wrap}
.top-actions{display:flex;gap:8px;flex-wrap:wrap}
.footer{text-align:center;font-size:11px;color:var(--text-muted);padding:20px 0;margin-top:24px;border-top:1px solid var(--border)}
code{background:var(--bg);padding:2px 6px;border-radius:4px;font-size:12px;color:var(--danger)}

/* Progress bar */
.progress-bar{height:6px;background:var(--border);border-radius:999px;overflow:hidden;margin:12px 0}
.progress-fill{height:100%;background:linear-gradient(90deg,var(--primary),var(--success));transition:all 0.5s ease}

/* Timeline */
.timeline{position:relative;padding-left:28px;margin:16px 0}
.timeline::before{content:'';position:absolute;left:8px;top:0;bottom:0;width:2px;background:var(--border)}
.timeline-item{position:relative;margin-bottom:16px}
.timeline-dot{
  position:absolute;left:-24px;top:3px;
  width:14px;height:14px;
  border-radius:50%;
  background:var(--primary);
  border:3px solid white;
  box-shadow:0 0 0 2px var(--border);
}

/* Member Grid Menu */
.member-grid{
  display:grid;
  grid-template-columns:repeat(2,1fr);
  gap:12px;
  margin-top:4px;
}
@media(min-width:640px){
  .member-grid{grid-template-columns:repeat(4,1fr);gap:14px;}
}
.member-grid a{
  display:flex;
  flex-direction:column;
  align-items:center;
  justify-content:center;
  gap:8px;
  padding:20px 12px;
  border-radius:var(--radius);
  text-align:center;
  text-decoration:none;
  font-size:13px;
  font-weight:600;
  color:var(--text);
  border:1px solid var(--border);
  background:white;
  transition:all 0.2s;
  min-height:100px;
}
.member-grid a:hover{
  transform:translateY(-2px);
  box-shadow:var(--shadow-md);
  text-decoration:none;
  border-color:var(--primary);
}
.member-grid a .mg-icon{font-size:28px;line-height:1}
@media(max-width:640px){
  .member-grid a{min-height:85px;padding:14px 8px;font-size:12px;}
  .member-grid a .mg-icon{font-size:24px;}
}
.metric-compact{
  display:grid;
  grid-template-columns:repeat(auto-fill,minmax(150px,1fr));
  gap:10px;
  margin-bottom:16px;
}
.metric-compact .mc{
  background:white;
  border:1px solid var(--border);
  border-radius:var(--radius-sm);
  padding:14px;
}
.metric-compact .mc .lbl{font-size:11px;color:var(--text-muted);font-weight:500}
.metric-compact .mc .val{font-size:18px;font-weight:700;margin-top:4px}

@keyframes slideUp{
  from{opacity:0;transform:translateY(16px)}
  to{opacity:1;transform:translateY(0)}
}

@media(max-width:768px){
  .sidebar{transform:translateX(-100%)}
  .sidebar.open{transform:translateX(0);box-shadow:var(--shadow-lg)}
  .main-content{margin-left:0;padding:16px}
  .hamburger{display:block}
  .grid{grid-template-columns:1fr!important}
  .col-12,.col-9,.col-8,.col-6,.col-4,.col-3{grid-column:span 1!important}
  .metrics{grid-template-columns:repeat(2,1fr)}
}
'''

def render_page(title, body, **ctx):
    user = current_user()
    notif_count = 0
    if user:
        notif_count = q_one('SELECT COUNT(*) as n FROM notifications WHERE user_id = ? AND is_read = 0', [user['id']])['n'] or 0
    # Build grouped sidebar HTML
    def _sidebar_section(label, icon, items):
        sec_id = label.replace(' ','_').lower()
        html = f'<div class="sidebar-section collapsed">'
        html += f'<div class="sidebar-section-header" onclick="toggleSection(this)"><span>{icon} {label}</span><span class="chevron">▼</span></div>'
        html += '<div class="sidebar-section-items">'
        for href, icon_i, text in items:
            html += f'<a href="{href}"><span class="nav-icon">{icon_i}</span>{text}</a>'
        html += '</div></div>'
        return html
    def _sidebar_link(href, icon, text):
        return f'<a href="{href}"><span class="nav-icon">{icon}</span>{text}</a>'
    nav_html = ''
    if user:
        role = user['role']
        if role == 'user':
            nav_html += _sidebar_section('Beranda', '🏠', [
                (url_for('member_dashboard'), '🏠', 'Dashboard'),
            ])
            nav_html += _sidebar_section('Layanan', '💡', [
                (url_for('wallet'), '💰', 'Wallet'),
                (url_for('member_purchases'), '🛒', 'Riwayat Belanja'),
                (url_for('member_digital_card'), '💎', 'Kartu Digital'),
                (url_for('member_card_pdf'), '💳', 'Kartu PDF'),
            ])
            nav_html += _sidebar_section('Pinjaman', '📋', [
                (url_for('loans'), '📋', 'Pinjaman Saya'),
                (url_for('apply_loan'), '📝', 'Ajukan Pinjaman'),
                (url_for('my_payments'), '💸', 'Riwayat Bayar'),
            ])
            nav_html += _sidebar_section('Lainnya', '📊', [
                (url_for('shu_member'), '📊', 'SHU Saya'),
                (url_for('settings'), '⚙️', 'Pengaturan'),
                (url_for('logout'), '🚪', 'Keluar'),
            ])
        elif role == 'kasir':
            nav_html += _sidebar_section('Beranda', '🏠', [
                (url_for('dashboard'), '🏠', 'Dashboard'),
            ])
            nav_html += _sidebar_section('Transaksi', '🛒', [
                (url_for('quick_cashier'), '⚡', 'Quick Cashier'),
                (url_for('cashier'), '🧾', 'Kasir'),
                (url_for('sales_history'), '📊', 'Riwayat Penjualan'),
            ])
            nav_html += _sidebar_section('Barang', '📦', [
                (url_for('products'), '📦', 'Master Barang'),
                (url_for('stock_movements'), '📥', 'Mutasi Stok'),
            ])
            nav_html += _sidebar_section('Sistem', '⚙️', [
                (url_for('settings'), '⚙️', 'Pengaturan'),
                (url_for('logout'), '🚪', 'Keluar'),
            ])
        elif role == 'bendahara':
            nav_html += _sidebar_section('Beranda', '🏠', [
                (url_for('dashboard'), '🏠', 'Dashboard'),
            ])
            nav_html += _sidebar_section('Pinjaman', '📋', [
                (url_for('loans'), '📋', 'Daftar Pinjaman'),
                (url_for('loan_types'), '🎯', 'Jenis Pinjaman'),
                (url_for('verify_loan_payments'), '✅', 'Verifikasi Bayar'),
            ])
            nav_html += _sidebar_section('Laporan', '📊', [
                (url_for('reports'), '📊', 'Laporan'),
                (url_for('shu_report'), '📈', 'SHU'),
            ])
            nav_html += _sidebar_section('Sistem', '⚙️', [
                (url_for('settings'), '⚙️', 'Pengaturan'),
                (url_for('logout'), '🚪', 'Keluar'),
            ])
        else:  # admin
            nav_html += _sidebar_section('Beranda', '🏠', [
                (url_for('dashboard'), '🏠', 'Dashboard'),
            ])
            nav_html += _sidebar_section('Transaksi', '🛒', [
                (url_for('quick_cashier'), '⚡', 'Quick Cashier'),
                (url_for('cashier'), '🧾', 'Kasir'),
                (url_for('cashier_discount'), '🧾', 'Kasir + Diskon'),
                (url_for('sales_history'), '📊', 'Riwayat Penjualan'),
                (url_for('sales_returns'), '🔄', 'Retur'),
            ])
            nav_html += _sidebar_section('Anggota', '👥', [
                (url_for('members'), '👥', 'Member'),
                (url_for('import_members'), '📥', 'Import Member'),
                (url_for('ewallet_dashboard'), '💰', 'E-Wallet Admin'),
            ])
            nav_html += _sidebar_section('Barang', '📦', [
                (url_for('products'), '📦', 'Master Barang'),
                (url_for('stock_movements'), '📥', 'Mutasi Stok'),
                (url_for('categories'), '🏷️', 'Kategori'),
                (url_for('quick_cashier_queue'), '⏳', 'Verifikasi Quick Cashier'),
            ])
            nav_html += _sidebar_section('Pembelian', '🏭', [
                (url_for('suppliers'), '🏭', 'Supplier'),
                (url_for('purchase_orders'), '📦', 'Pembelian (PO)'),
                (url_for('supplier_payments'), '🏦', 'Hutang Supplier'),
            ])
            nav_shu_badge = ' 🔔' if notif_count > 0 else ''
            nav_html += _sidebar_section('Keuangan', '💰', [
                (url_for('savings'), '💰', 'Simpanan'),
                (url_for('loans'), '📋', 'Pinjaman'),
                (url_for('loan_types'), '🎯', 'Jenis Pinjaman'),
                (url_for('verify_loan_payments'), '✅', 'Verifikasi Bayar'),
                (url_for('reports'), '📊', 'Laporan'),
                (url_for('financial_statements'), '📒', 'Laba Rugi & Neraca'),
                (url_for('shu_report'), '📈', f'SHU{nav_shu_badge}'),
            ])
            nav_html += _sidebar_section('Sistem', '⚙️', [
                (url_for('approvals'), '👌', 'Approval'),
                (url_for('user_approval'), '👤', 'Approve User'),
                (url_for('users'), '🔧', 'Kelola User'),
                (url_for('accounting'), '📒', 'Akuntansi'),
                (url_for('audit'), '🔍', 'Audit Log'),
                (url_for('settings'), '⚙️', 'Pengaturan'),
                (url_for('logout'), '🚪', 'Keluar'),
            ])
    base = f'''<!doctype html><html lang="id"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
    <title>{{{{ title }}}} - {{{{ app_title }}}}</title><style>{CSS_DESIGN}</style></head><body>
    {{% if user %}}
    <div class="app-wrap">
      <div class="sidebar" id="sidebar">
        <div class="sidebar-brand"><div class="brand-icon">🏪</div><div class="brand-text">{{{{ app_short }}}}</div></div>
        <div class="sidebar-user"><div class="avatar">👤</div><div class="user-info"><div class="uname">{{{{ user['full_name'] }}}}</div><div class="urole">{{{{ user['role'] }}}}</div></div></div>
        <div class="sidebar-nav">
          {{{{ nav_html|safe }}}}
        </div>
      </div>
      <div class="main-content">
        <div class="topbar">
          <div>
            <button class="hamburger" onclick="document.getElementById('sidebar').classList.toggle('open')">☰</button>
            <div class="page-header"><h1>{{{{ title }}}}</h1><p>{{{{ app_title }}}}</p></div>
          </div>
        </div>
        {{% with messages = get_flashed_messages(with_categories=true) %}}{{% if messages %}}{{% for c,m in messages %}}<div class="flash flash-{{{{ c }}}}">{{{{ m }}}}</div>{{% endfor %}}{{% endif %}}{{% endwith %}}
        {{{{ body|safe }}}}
        <div class="footer">© {{{{ now().year }}}} {{{{ app_title }}}} — v3.0</div>
      </div>
    </div>
    <script>
    function toggleSection(el){{ el.parentElement.classList.toggle('collapsed'); }}
    document.addEventListener('click', function(e){{
      var s=document.getElementById('sidebar');
      if(s.classList.contains('open') && !s.contains(e.target) && !e.target.matches('.hamburger')){{
        s.classList.remove('open');
      }}
    }});
    </script>
    {{% else %}}
    {{% with messages = get_flashed_messages(with_categories=true) %}}{{% if messages %}}{{% for c,m in messages %}}<div class="flash flash-{{{{ c }}}}" style="max-width:420px;margin:16px auto;">{{{{ m }}}}</div>{{% endfor %}}{{% endif %}}{{% endwith %}}
    {{{{ body|safe }}}}
    {{% endif %}}
    </body></html>'''
    return render_template_string(base, title=title, body=body, app_title=APP_TITLE, app_short=APP_SHORT, user=user, q_one=q_one, notif_count=notif_count, nav_html=nav_html, now=lambda: datetime.now, **ctx)

# =========================
# Login Page - Fresh & Clean (Split Layout)
# =========================
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        user = q_one('SELECT * FROM users WHERE username=?', [username])
        if user and user['password_hash'] == hash_password(password):
            if not user['active']:
                flash('Akun Anda telah dinonaktifkan oleh admin.', 'error')
                log_action('LOGIN_BLOCKED', 'users', user['id'], 'Login ditolak: akun dinonaktifkan')
                return redirect(url_for('login'))
            if user['role'] != 'admin':
                if str(user['status'] or '').strip().upper() == 'PENDING_APPROVAL':
                    flash('Akun menunggu persetujuan admin.', 'warning')
                    log_action('LOGIN_BLOCKED', 'users', user['id'], 'Login ditolak: status PENDING_APPROVAL')
                    return redirect(url_for('login'))
            session['user_id'] = user['id']
            session['username'] = user['username']
            log_action('LOGIN', 'users', user['id'], 'Login berhasil')
            flash(f'✅ Selamat datang, {user["full_name"] or ""}!', 'success')
            return redirect(url_for('dashboard'))
        flash('Username atau password salah.', 'error')
    body = '''
    <div class="login-wrap">
      <div class="login-left">
        <div class="login-brand">
          <div class="login-brand-icon">🏠</div>
          <h1>Koperasi Enterprise</h1>
          <p>Sistem manajemen koperasi terintegrasi — mudah digunakan untuk mengelola transaksi, pinjaman, simpanan, dan laporan keuangan.</p>
          <div class="login-features">
            <div class="login-feat">
              <span class="login-feat-icon">💰</span>
              <div class="login-feat-title">Transaksi Harian</div>
              <div class="login-feat-desc">Kasir, penjualan, dan riwayat transaksi</div>
            </div>
            <div class="login-feat">
              <span class="login-feat-icon">📋</span>
              <div class="login-feat-title">Pinjaman & Simpanan</div>
              <div class="login-feat-desc">Kelola pinjaman, angsuran, dan simpanan</div>
            </div>
            <div class="login-feat">
              <span class="login-feat-icon">📊</span>
              <div class="login-feat-title">Laporan Keuangan</div>
              <div class="login-feat-desc">Laba rugi, neraca, dan SHU otomatis</div>
            </div>
            <div class="login-feat">
              <span class="login-feat-icon">👥</span>
              <div class="login-feat-title">Manajemen Anggota</div>
              <div class="login-feat-desc">Data member, e-wallet, dan approval</div>
            </div>
          </div>
        </div>
      </div>
      <div class="login-right">
        <div class="login-card">
          <div class="login-logo">🏠</div>
          <div class="login-title">Selamat Datang</div>
          <div class="login-sub">Masuk ke akun koperasi Anda</div>
          {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
              {% for c, m in messages %}
                <div class="flash flash-{{ c }}">{{ m }}</div>
              {% endfor %}
            {% endif %}
          {% endwith %}
          <form method="post">
            <div class="login-field">
              <label for="username">Username</label>
              <div class="login-input-wrap">
                <span class="login-input-icon">👤</span>
                <input type="text" id="username" name="username" placeholder="Masukkan username" autofocus>
              </div>
            </div>
            <div class="login-field">
              <label for="password">Password</label>
              <div class="login-input-wrap">
                <span class="login-input-icon">🔒</span>
                <input type="password" id="password" name="password" placeholder="Masukkan password">
                <button type="button" class="login-pw-toggle" onclick="togglePw()">👁️</button>
              </div>
            </div>
            <button type="submit" class="login-btn">Masuk →</button>
          </form>
          <div class="login-footer">
            <a href="{{url_for('register')}}">Daftar akun baru</a>
          </div>
          <div class="demo-toggle">
            <a onclick="document.getElementById('demoList').classList.toggle('show')">Lihat akun demo →</a>
            <div class="demo-list" id="demoList">
              <div>admin / admin123</div>
              <div>kasir / kasir123</div>
              <div>bendahara / bendahara123</div>
            </div>
          </div>
        </div>
      </div>
    </div>
    <script>
    function togglePw(){
      var p = document.getElementById('password');
      var btn = document.querySelector('.login-pw-toggle');
      if(p.type==='password'){p.type='text'; btn.textContent='🙈';}
      else{p.type='password'; btn.textContent='👁️';}
    }
    </script>
    '''
    return render_page('Login', render_template_string(body))

# =========================
# Auth - Register
# =========================
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'user_id' in session:
        return redirect(url_for('dashboard'))
    
    try:
        conn = get_conn()
        cur = conn.cursor()
        try:
            cur.execute('ALTER TABLE users ADD COLUMN employee_number TEXT')
            conn.commit()
        except:
            pass
        conn.close()
    except:
        pass
    
    step = request.args.get('step', '1')
    
    if request.method == 'POST':
        if step == '1':
            employee_number = request.form.get('employee_number', '').strip()
            if not employee_number:
                flash('Nomor karyawan wajib diisi.', 'error')
            else:
                exist = q_one('SELECT id FROM users WHERE employee_number = ?', [employee_number])
                if exist:
                    flash('Nomor karyawan ini sudah terdaftar.', 'error')
                else:
                    session['temp_employee_number'] = employee_number
                    flash('Nomor karyawan terverifikasi, silahkan isi data pribadi.', 'success')
                    return redirect(url_for('register', step='2'))
        elif step == '2':
            if 'temp_employee_number' not in session:
                flash('Silahkan masukkan nomor karyawan terlebih dahulu.', 'warning')
                return redirect(url_for('register'))
            full_name = request.form.get('full_name', '').strip()
            phone = request.form.get('phone', '').strip()
            address = request.form.get('address', '').strip()
            password = request.form.get('password', '').strip()
            password_confirm = request.form.get('password_confirm', '').strip()
            if not full_name or not password:
                flash('Nama lengkap dan password wajib diisi.', 'error')
            elif password != password_confirm:
                flash('Password dan konfirmasi password tidak sama.', 'error')
            else:
                exist_user = q_one('SELECT id FROM users WHERE username = ?', [session['temp_employee_number']])
                if exist_user:
                    flash('Nomor karyawan ini sudah terdaftar.', 'error')
                else:
                    try:
                        conn = get_conn()
                        conn.row_factory = sqlite3.Row
                        cur = conn.cursor()
                        try:
                            cur.execute('ALTER TABLE users ADD COLUMN employee_number TEXT UNIQUE')
                        except:
                            pass
                        cur.execute('INSERT INTO users(employee_number, username, full_name, phone, address, password_hash, status, role, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [
                            session['temp_employee_number'], session['temp_employee_number'], full_name, phone, address, hash_password(password), 'PENDING_APPROVAL', 'user', 0
                        ])
                        uid = cur.lastrowid
                        try:
                            cur.execute('ALTER TABLE members ADD COLUMN member_code TEXT UNIQUE')
                        except:
                            pass
                        try:
                            cur.execute('INSERT INTO members(member_code, name, phone, address, join_date, status) VALUES (?, ?, ?, ?, ?, ?)', [
                                f'EMP-{session["temp_employee_number"]}', full_name, phone, address, today_str(), 'Aktif'
                            ])
                        except sqlite3.IntegrityError:
                            pass
                        conn.commit()
                        conn.close()
                        log_action('REGISTER', 'users', uid, f'Registrasi pegawai {full_name}')
                        session.pop('temp_employee_number', None)
                        admin_users = q_all('SELECT id FROM users WHERE role = "admin"')
                        for a in admin_users:
                            add_notification(a['id'], 'User Baru Mendaftar', f'{full_name} telah mendaftar dan menunggu approval.')
                        flash('Registrasi berhasil! Akun Anda menunggu persetujuan admin.', 'success')
                        return redirect(url_for('login'))
                    except sqlite3.IntegrityError as e:
                        conn.rollback(); conn.close()
                        flash('Terjadi kesalahan saat pendaftaran, silahkan coba lagi.', 'error')
                    except Exception as e:
                        conn.rollback(); conn.close()
                        flash(f'Terjadi error: {str(e)}', 'error')
                    finally:
                        session.pop('temp_employee_number', None)
    
    step_template = '''
    <div class="login-wrap">
      <div class="login-card">
        <div class="login-logo">{% if step == '1' %}👤{% else %}✅{% endif %}</div>
        <div class="login-title">Daftar Pegawai</div>
        <div class="login-sub">{% if step == '1' %}Langkah 1/2 — Verifikasi Nomor Karyawan{% else %}Langkah 2/2 — Isi Data Pribadi{% endif %}</div>
        {% if step == '1' %}
        <form method="post">
          <div class="login-field">
            <label>Nomor Karyawan</label>
            <input name="employee_number" placeholder="Masukkan Nomor Karyawan" autofocus>
          </div>
          <button type="submit" class="login-btn">🔍 Verifikasi Nomor Karyawan</button>
        </form>
        {% else %}
        <div class="badge badge-info" style="text-align:center;display:block;margin-bottom:16px;">Nomor Karyawan: {{ session.temp_employee_number }}</div>
        <form method="post">
          <div class="login-field"><label>Nama Lengkap</label><input name="full_name" placeholder="Nama Lengkap"></div>
          <div class="login-field"><label>Nomor HP</label><input name="phone" placeholder="Nomor HP"></div>
          <div class="login-field"><label>Alamat</label><textarea name="address" placeholder="Alamat" style="min-height:60px;"></textarea></div>
          <div class="login-field"><label>Buat Password</label><input type="password" name="password" placeholder="Minimal 4 karakter"></div>
          <div class="login-field"><label>Konfirmasi Password</label><input type="password" name="password_confirm" placeholder="Ulangi password"></div>
          <button type="submit" class="login-btn">📝 Kirim Pendaftaran</button>
        </form>
        {% endif %}
        <div class="login-footer"><a href="{{ url_for('login') }}">Sudah punya akun? Login disini</a></div>
      </div>
    </div>
    '''
    body = render_template_string(step_template, step=step)
    return render_page('Daftar Pegawai', body)

# =========================
# Logout
# =========================
@app.route('/logout')
@login_required
def logout():
    log_action('LOGOUT', 'users', session.get('user_id'), 'Logout')
    session.clear()
    flash('Logout berhasil. Sampai jumpa!', 'success')
    return redirect(url_for('login'))

# =========================
# User Approval (Admin)
# =========================
@app.route('/admin/user-approval', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def user_approval():
    if request.method == 'POST':
        user_id = int(request.form.get('user_id'))
        action = request.form.get('action')
        reject_reason = request.form.get('reject_reason', '').strip()
        target = q_one('SELECT * FROM users WHERE id = ?', [user_id])
        if not target:
            flash('User tidak ditemukan atau sudah diproses.', 'error')
            return redirect(url_for('user_approval'))
        if action == 'approve':
            exec_sql('UPDATE users SET active = 1, status = "ACTIVE", approved_by = ?, approved_at = ? WHERE id = ?', [session.get('user_id'), now_str(), user_id])
            add_notification(user_id, 'Akun Disetujui', 'Akun Anda telah disetujui oleh admin. Silahkan login.')
            log_action('USER_APPROVED', 'users', user_id, f'Akun {target["full_name"]} disetujui')
            flash(f'Akun {target["full_name"]} berhasil diaktifkan.', 'success')
        elif action == 'reject':
            exec_sql('UPDATE users SET status = "REJECTED", reject_reason = ?, active = 0 WHERE id = ?', [reject_reason, user_id])
            log_action('USER_REJECTED', 'users', user_id, f'Akun {target["full_name"]} ditolak: {reject_reason}')
            flash(f'Akun {target["full_name"]} ditolak.', 'warning')
        elif action == 'delete':
            member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{target["employee_number"]}'])
            if member:
                loans = q_all('SELECT id FROM loans WHERE member_id = ?', [member['id']])
                for loan in loans:
                    exec_sql('DELETE FROM loan_schedules WHERE loan_id = ?', [loan['id']])
                    exec_sql('DELETE FROM loan_payments WHERE loan_id = ?', [loan['id']])
                    exec_sql('DELETE FROM loan_documents WHERE loan_id = ?', [loan['id']])
                    exec_sql('DELETE FROM loan_timeline WHERE loan_id = ?', [loan['id']])
                exec_sql('DELETE FROM loans WHERE member_id = ?', [member['id']])
                exec_sql('DELETE FROM savings_transactions WHERE member_id = ?', [member['id']])
                exec_sql('DELETE FROM saldo_history WHERE member_id = ?', [member['id']])
                exec_sql('DELETE FROM topup_requests WHERE member_id = ?', [member['id']])
                exec_sql('DELETE FROM sales WHERE member_id = ?', [member['id']])
                exec_sql('DELETE FROM members WHERE id = ?', [member['id']])
            exec_sql('DELETE FROM approval_requests WHERE created_by = ?', [user_id])
            exec_sql('DELETE FROM notifications WHERE user_id = ?', [user_id])
            exec_sql('DELETE FROM users WHERE id = ?', [user_id])
            log_action('DELETE', 'users', user_id, f'Akun {target["full_name"]} dihapus oleh admin')
            flash(f'Data akun {target["full_name"]} beserta member terkait berhasil dihapus permanen.', 'success')
        return redirect(url_for('user_approval'))
    pending = q_all('SELECT * FROM users WHERE status = "PENDING_APPROVAL" ORDER BY id ASC')
    history = q_all('SELECT u.*, ua.full_name as approver_name FROM users u LEFT JOIN users ua ON ua.id = u.approved_by WHERE u.status != "PENDING_APPROVAL" ORDER BY u.id DESC LIMIT 100')
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><div><h2>👤 Approval User Baru</h2><div class="muted small">Setujui atau tolak pendaftaran pegawai baru</div></div></div>
        <hr><h3>⏳ Menunggu Approval</h3>
        <div class="table-wrap"><table><thead><tr><th>ID</th><th>Nama</th><th>No Karyawan</th><th>HP</th><th>Daftar</th><th>Aksi</th></tr></thead>
        <tbody>{% for p in pending %}<tr><td>{{ p.id }}</td><td>{{ p.full_name }}</td><td>{{ p.employee_number }}</td><td>{{ p.phone }}</td><td>{{ p.created_at }}</td>
        <td><form method="POST" style="display:flex;gap:8px;flex-wrap:wrap;"><input type="hidden" name="user_id" value="{{ p.id }}"><input name="reject_reason" placeholder="Alasan tolak" style="width:150px;"><button name="action" value="approve" class="btn-sm btn-success">✅</button><button name="action" value="reject" class="btn-sm btn-danger">❌</button><button name="action" value="delete" class="btn-sm btn-danger" onclick="return confirm('Hapus permanen data {{ p.full_name }}?')">🗑️</button></form></td></tr>{% else %}<tr><td colspan="6" class="muted text-center">Tidak ada user yang menunggu approval.</td></tr>{% endfor %}</tbody></table></div>
        <hr><h3>📜 Riwayat</h3>
        <div class="table-wrap"><table><thead><tr><th>Nama</th><th>Status</th><th>Approver</th><th>Alasan</th><th>Aksi</th></tr></thead>
        <tbody>{% for h in history %}<tr><td>{{ h.full_name }}</td><td><span class="badge {{ 'badge-success' if h.status == 'ACTIVE' else 'badge-danger' }}">{{ h.status }}</span></td><td>{{ h.approver_name or '-' }}</td><td>{{ h.reject_reason or '-' }}</td><td><form method="POST" style="margin:0;"><input type="hidden" name="user_id" value="{{ h.id }}"><button name="action" value="delete" class="btn-sm btn-danger" onclick="return confirm('Hapus permanen {{ h.full_name }}? Semua datanya akan hilang.')">🗑️</button></form></td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada riwayat.</td></tr>{% endfor %}</tbody></table></div>
    </div>
    ''', pending=pending, history=history)
    return render_page('Approval User', body)

# =========================
# SHU Member
# =========================
@app.route('/shu/member', methods=['GET'])
@login_required
def shu_member():
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Akun member tidak ditemukan.', 'warning')
        return redirect(url_for('dashboard'))
    year = request.args.get('year', str(datetime.now().year))
    shu = calculate_shu(member['id'], int(year))
    body = render_template_string('''
    <div class="card">
        <div class="kartu">
            <div><h2>📊 SHU Saya</h2><div class="muted small">{{ member.member_code }} — {{ member.name }}</div></div>
            <form method="GET" style="width:auto;"><select name="year" onchange="this.form.submit()" style="width:120px;">
                {% for y in range(2024, 2027) %}<option value="{{ y }}" {% if year|int == y %}selected{% endif %}>{{ y }}</option>{% endfor %}
            </select></form>
        </div>
        <div class="metrics">
            <div class="metric"><div class="label">SHU Tahun {{ year }}</div><div class="value" style="color:#2563eb;">{{ rupiah(shu) }}</div></div>
            <div class="metric"><div class="label">Saldo SHU Akumulasi</div><div class="value" style="color:#10b981;">{{ rupiah(member.shu_balance or 0) }}</div></div>
        </div>
        <div class="muted small">* SHU dihitung dari jasa simpanan (30%) dan jasa belanja (30%) laba bersih tahun berjalan.</div>
    </div>
    ''', member=member, shu=shu, year=year, rupiah=rupiah)
    return render_page('SHU Saya', body)

# =========================
# SHU Report
# =========================
@app.route('/shu/report', methods=['GET'])
@login_required
@role_required('admin', 'bendahara')
def shu_report():
    year = request.args.get('year', str(datetime.now().year))
    members = q_all('SELECT * FROM members ORDER BY member_code')
    shu_data = []; total_shu = 0
    for m in members:
        shu = calculate_shu(m['id'], int(year))
        shu_data.append({'member': m, 'shu': shu}); total_shu += shu
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><div><h2>📈 Laporan SHU {{ year }}</h2></div>
        <form method="GET" style="width:auto;"><select name="year" onchange="this.form.submit()" style="width:120px;">
            {% for y in range(2024, 2027) %}<option value="{{ y }}" {% if year|int == y %}selected{% endif %}>{{ y }}</option>{% endfor %}
        </select></form></div>
        <div class="metrics">
            <div class="metric"><div class="label">Total SHU</div><div class="value" style="color:#2563eb;">{{ rupiah(total_shu) }}</div></div>
            <div class="metric"><div class="label">Member</div><div class="value">{{ members|length }}</div></div>
        </div>
        <div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama</th><th>Total SHU</th></tr></thead>
        <tbody>{% for d in shu_data %}<tr><td>{{ d.member.member_code }}</td><td>{{ d.member.name }}</td><td><strong>{{ rupiah(d.shu) }}</strong></td></tr>{% else %}<tr><td colspan="3" class="muted text-center">Belum ada data.</td></tr>{% endfor %}</tbody></table></div>
        <div class="top-actions" style="margin-top:16px;"><a href="{{ url_for('distribute_shu', year=year) }}" class="btn btn-warn">📤 Distribusikan SHU</a></div>
    </div>
    ''', shu_data=shu_data, total_shu=total_shu, members=members, year=year, rupiah=rupiah)
    return render_page('Laporan SHU', body)

@app.route('/shu/distribute/<int:year>', methods=['GET'])
@login_required
@role_required('admin')
def distribute_shu(year):
    members = q_all('SELECT * FROM members ORDER BY member_code')
    total = 0
    for m in members:
        shu = calculate_shu(m['id'], year)
        if shu > 0:
            exec_sql('UPDATE members SET shu_balance = COALESCE(shu_balance, 0) + ? WHERE id = ?', [shu, m['id']])
            total += shu
    if total > 0:
        post_journal(f"{year}-12-31", f'Distribusi SHU Tahun {year}', [
            {'account_id': get_account_id('2101'), 'debit': total, 'credit': 0},
            {'account_id': get_account_id('2001'), 'debit': 0, 'credit': total}
        ], 'shu_distribution', year, session.get('user_id'))
        log_action('SHU_DISTRIBUTED', 'members', year, f'SHU {year} Rp {total}')
        flash(f'SHU tahun {year} didistribusikan: {rupiah(total)}', 'success')
    else:
        flash('Tidak ada SHU yang dapat didistribusikan.', 'warning')
    return redirect(url_for('shu_report'))

# =========================
# My Payments
# =========================
@app.route('/loans/member-dashboard', methods=['GET'])
@login_required
def member_loan_dashboard():
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Akun member tidak ditemukan.', 'warning')
        return redirect(url_for('dashboard'))
    saldo = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id = ?', [member['id']])['saldo']
    active_loans = q_all('SELECT l.*, COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id AND lp.status="VERIFIED"),0) as paid, l.total_receivable - COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id AND lp.status="VERIFIED"),0) as remaining FROM loans l WHERE l.member_id = ? AND l.status IN ("SUBMITTED","CALCULATED","Berjalan") ORDER BY l.id DESC', [member['id']])
    all_loans = q_all('SELECT l.*, COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id AND lp.status="VERIFIED"),0) as paid, l.total_receivable - COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id AND lp.status="VERIFIED"),0) as remaining FROM loans l WHERE l.member_id = ? ORDER BY l.id DESC', [member['id']])
    total_paid_all = q_one('SELECT COALESCE(SUM(amount),0) as x FROM loan_payments lp JOIN loans l ON l.id=lp.loan_id WHERE l.member_id=? AND lp.status="VERIFIED"', [member['id']])['x'] or 0
    total_loan = q_one('SELECT COALESCE(SUM(total_receivable),0) as x FROM loans WHERE member_id=? AND status="Berjalan"', [member['id']])['x'] or 0
    body = render_template_string('''<div class="card"><h2>🏦 Dashboard Pinjaman Saya</h2><div class="muted small">{{ member.member_code }} — {{ member.name }}</div></div>
    <div class="metrics">
        <div class="metric" style="background:linear-gradient(135deg,#fffbeb,#fef3c7);border-color:#fcd34d;"><div class="label">Saldo Wallet</div><div class="value" style="color:#f59e0b;">{{ rupiah(saldo) }}</div></div>
        <div class="metric" style="background:linear-gradient(135deg,#eff6ff,#dbeafe);border-color:#93c5fd;"><div class="label">Total Pinjaman Aktif</div><div class="value" style="color:#2563eb;">{{ rupiah(total_loan) }}</div></div>
        <div class="metric" style="background:linear-gradient(135deg,#ecfdf5,#d1fae5);border-color:#6ee7b7;"><div class="label">Total Terbayar</div><div class="value" style="color:#10b981;">{{ rupiah(total_paid_all) }}</div></div>
        <div class="metric"><div class="label">Pinjaman Aktif</div><div class="value">{{ active_loans|length }}</div></div>
    </div>
    <div class="grid"><div class="col-12"><div class="card"><h3>📋 Status Pinjaman</h3>
    <div class="table-wrap"><table><thead><tr><th>No Pinjaman</th><th>Tanggal</th><th>Pokok</th><th>Tagihan</th><th>Terbayar</th><th>Sisa</th><th>Status</th><th>Aksi</th></tr></thead>
    <tbody>{% for r in all_loans %}<tr><td>{{ r.loan_no }}</td><td>{{ r.loan_date }}</td><td>{{ rupiah(r.principal) }}</td><td>{{ rupiah(r.total_receivable) }}</td><td>{{ rupiah(r.paid) }}</td><td>{{ rupiah(r.remaining) }}</td>
    <td><span class="badge {% if r.status == 'Berjalan' %}badge-success{% elif r.status == 'Lunas' %}badge-info{% elif r.status == 'SUBMITTED' %}badge-warn{% else %}badge-gray{% endif %}">{{ r.status }}</span></td>
    <td>{% if r.status == 'Berjalan' %}<a href="/loans/pay/{{ r.id }}" class="btn btn-sm btn-success">💸 Bayar Angsuran</a>{% endif %}</td></tr>{% else %}<tr><td colspan="8" class="muted text-center">Anda belum memiliki pinjaman.</td></tr>{% endfor %}</tbody></table></div>
    </div></div></div>''', member=member, saldo=saldo, active_loans=active_loans, all_loans=all_loans, total_paid_all=total_paid_all, total_loan=total_loan, rupiah=rupiah)
    return render_page('Dashboard Pinjaman', body)

@app.route('/loans/my-payments', methods=['GET'])
@login_required
def my_payments():
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Akun member tidak ditemukan.', 'warning')
        return redirect(url_for('dashboard'))
    payments = q_all('SELECT lp.*, l.loan_no FROM loan_payments lp JOIN loans l ON l.id = lp.loan_id WHERE l.member_id = ? ORDER BY lp.id DESC LIMIT 100', [member['id']])
    body = render_template_string('''
    <div class="card">
        <h2>💸 Riwayat Pembayaran Angsuran</h2>
        <div class="muted small">Semua pembayaran angsuran pinjaman anda</div>
        <div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Pinjaman</th><th>Nominal</th><th>Denda</th><th>Total</th><th>Status</th></tr></thead>
        <tbody>{% for p in payments %}<tr><td>{{ p.payment_date }}</td><td>{{ p.loan_no }}</td><td>{{ rupiah(p.amount) }}</td><td>{{ rupiah(p.penalty_amount or 0) }}</td><td>{{ rupiah((p.amount or 0)+(p.penalty_amount or 0)) }}</td><td><span class="badge {{ 'badge-success' if p.status == 'VERIFIED' else 'badge-warn' }}">{{ p.status }}</span></td></tr>{% else %}<tr><td colspan="6" class="muted text-center">Belum ada pembayaran.</td></tr>{% endfor %}</tbody></table></div>
    </div>
    ''', payments=payments, rupiah=rupiah)
    return render_page('Riwayat Pembayaran', body)

@app.route('/wallet', methods=['GET', 'POST'])
@login_required
def wallet():
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Akun wallet anda belum aktif. Silahkan hubungi admin.', 'warning')
        return redirect(url_for('dashboard'))
    if request.method == 'POST':
        nominal = parse_float(request.form.get('nominal', 0))
        bukti = request.files.get('bukti_transfer')
        if nominal < 10000:
            flash('Nominal topup minimal Rp 10.000', 'error')
        elif not bukti or bukti.filename == '':
            flash('Harap upload bukti transfer', 'error')
        else:
            os.makedirs('uploads', exist_ok=True)
            filename = secure_filename(f'bukti_{user["employee_number"]}_{int(datetime.now().timestamp())}_{bukti.filename}')
            bukti.save(f'uploads/{filename}')
            exec_sql('INSERT INTO topup_requests(member_id, nominal, bukti_foto, status) VALUES (?, ?, ?, ?)', [member['id'], nominal, filename, 'PENDING'])
            log_action('TOPUP_REQUEST', 'topup_requests', member['id'], f'Request topup Rp {nominal}')
            flash('Request topup berhasil dikirim. Menunggu verifikasi admin.', 'success')
            return redirect(url_for('wallet'))
    saldo = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id = ?', [member['id']])['saldo']
    requests = q_all('SELECT * FROM topup_requests WHERE member_id = ? ORDER BY id DESC LIMIT 50', [member['id']])
    history = q_all('SELECT * FROM saldo_history WHERE member_id = ? ORDER BY id DESC LIMIT 50', [member['id']])
    body = render_template_string('''
    <div class="metrics">
        <div class="metric" style="background:linear-gradient(135deg,#eff6ff,#dbeafe);border-color:#bfdbfe;">
            <div class="label">Saldo Wallet</div><div class="value" style="color:#2563eb;">{{ rupiah(saldo) }}</div>
            <div class="sub">{{ member.member_code }}</div>
        </div>
    </div>
    <div class="grid">
        <div class="col-4"><div class="card"><h3>📥 Topup Wallet</h3>
            <form method="post" enctype="multipart/form-data">
                <div class="form-group"><label>Nominal</label><input type="number" name="nominal" min="10000" step="1000" placeholder="Min Rp 10.000"></div>
                <div class="form-group" style="padding:12px;background:#f9fafb;border-radius:8px;text-align:center;border:1px dashed var(--border);">
                    <div style="font-size:13px;color:var(--text-muted);">Transfer ke:</div>
                    <div style="font-size:18px;font-weight:700;color:#2563eb;">BCA 1234567890</div>
                    <div class="muted small">a.n. Koperasi Enterprise</div>
                </div>
                <div class="form-group"><label>Bukti Transfer</label><input type="file" name="bukti_transfer" accept="image/*" required></div>
                <button type="submit">📤 Kirim Request</button>
            </form>
        </div></div>
        <div class="col-8"><div class="card"><h3>📋 Riwayat Topup</h3>
            <div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Nominal</th><th>Status</th></tr></thead>
            <tbody>{% for r in requests %}<tr><td>{{ r.created_at }}</td><td>{{ rupiah(r.nominal) }}</td>
            <td><span class="badge {{ 'badge-warn' if r.status == 'PENDING' else 'badge-success' if r.status == 'APPROVED' else 'badge-danger' }}">{{ r.status }}</span></td></tr>{% else %}<tr><td colspan="3" class="muted text-center">Belum ada request.</td></tr>{% endfor %}</tbody></table></div>
        </div></div>
    </div>
    ''', member=member, saldo=saldo, requests=requests, history=history, rupiah=rupiah)
    return render_page('Wallet Saya', body)

# =========================
# Member Dashboard (for user role)
# =========================
@app.route('/member/dashboard', methods=['GET'])
@login_required
def member_dashboard():
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Akun member tidak ditemukan. Silahkan hubungi admin.', 'warning')
        return redirect(url_for('dashboard'))
    saldo_wallet = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id = ?', [member['id']])['saldo']
    total_belanja = q_one('SELECT COALESCE(SUM(total), 0) as x FROM sales WHERE member_id = ? AND status="Posted"', [member['id']])['x']
    total_simpanan = q_one("SELECT COALESCE(SUM(CASE WHEN direction='Masuk' THEN amount ELSE -amount END), 0) as x FROM savings_transactions WHERE member_id = ?", [member['id']])['x']
    total_pinjaman = q_one('SELECT COALESCE(SUM(total_receivable), 0) as x FROM loans WHERE member_id=? AND status="Berjalan"', [member['id']])['x']
    total_terbayar = q_one('SELECT COALESCE(SUM(amount), 0) as x FROM loan_payments lp JOIN loans l ON l.id=lp.loan_id WHERE l.member_id=? AND lp.status="VERIFIED"', [member['id']])['x']
    recent_belanja = q_all('SELECT invoice_no, trx_date, total FROM sales WHERE member_id=? AND status="Posted" ORDER BY id DESC LIMIT 10', [member['id']])
    shu = calculate_shu(member['id'], datetime.now().year)
    body = render_template_string('''
    <div class="card" style="padding:16px;">
        <div class="kartu" style="gap:8px;">
            <div><h2 style="font-size:15px;margin:0;">{{ member.name }}</h2><div class="muted small">{{ member.member_code }}</div></div>
            <div style="display:flex;gap:6px;"><a href="{{ url_for('wallet') }}" class="btn btn-sm btn-ghost" style="padding:6px 10px;font-size:11px;">💰</a><a href="{{ url_for('member_card_pdf') }}" class="btn btn-sm btn-ghost" style="padding:6px 10px;font-size:11px;">💳</a></div>
        </div>
    </div>
    <div class="metric-compact">
        <div class="mc" style="background:linear-gradient(135deg,#eff6ff,#dbeafe)"><div class="lbl" style="color:#1e40af;">Wallet</div><div class="val" style="color:#2563eb;">{{ rupiah(saldo_wallet) }}</div></div>
        <div class="mc" style="background:linear-gradient(135deg,#ecfdf5,#d1fae5)"><div class="lbl" style="color:#065f46;">Belanja</div><div class="val" style="color:#059669;">{{ rupiah(total_belanja) }}</div></div>
        <div class="mc" style="background:linear-gradient(135deg,#fffbeb,#fef3c7)"><div class="lbl" style="color:#92400e;">Simpanan</div><div class="val" style="color:#d97706;">{{ rupiah(total_simpanan) }}</div></div>
        <div class="mc" style="background:linear-gradient(135deg,#fef2f2,#fee2e2)"><div class="lbl" style="color:#991b1b;">Pinjaman</div><div class="val" style="color:#dc2626;">{{ rupiah(total_pinjaman) }}</div></div>
        <div class="mc"><div class="lbl">Terbayar</div><div class="val">{{ rupiah(total_terbayar) }}</div></div>
        <div class="mc"><div class="lbl">SHU {{ now().year }}</div><div class="val" style="color:#2563eb;">{{ rupiah(shu) }}</div></div>
    </div>
    <div class="member-grid">
        <a href="{{ url_for('wallet') }}" style="background:linear-gradient(135deg,#eff6ff,#dbeafe);border-color:#93c5fd;"><span class="mg-icon">💰</span>Topup Wallet</a>
        <a href="{{ url_for('member_purchases') }}" style="background:linear-gradient(135deg,#ecfdf5,#d1fae5);border-color:#6ee7b7;"><span class="mg-icon">🛒</span>Riwayat Belanja</a>
        <a href="{{ url_for('apply_loan') }}" style="background:linear-gradient(135deg,#fffbeb,#fef3c7);border-color:#fcd34d;"><span class="mg-icon">📝</span>Ajukan Pinjaman</a>
        <a href="{{ url_for('loans') }}" style="background:linear-gradient(135deg,#fef2f2,#fee2e2);border-color:#fca5a5;"><span class="mg-icon">📋</span>Pinjaman Saya</a>
        <a href="{{ url_for('my_payments') }}" style="background:linear-gradient(135deg,#f3e8ff,#ede9fe);border-color:#c4b5fd;"><span class="mg-icon">💸</span>Riwayat Bayar</a>
        <a href="{{ url_for('shu_member') }}" style="background:linear-gradient(135deg,#e0f2fe,#bae6fd);border-color:#7dd3fc;"><span class="mg-icon">📊</span>SHU Saya</a>
        <a href="{{ url_for('member_card_pdf') }}" style="background:linear-gradient(135deg,#ecfdf5,#d1fae5);border-color:#6ee7b7;"><span class="mg-icon">💳</span>Kartu Member</a>
        <a href="{{ url_for('settings') }}" style="background:#f9fafb;border-color:#d1d5db;"><span class="mg-icon">⚙️</span>Pengaturan</a>
    </div>
    {% if recent_belanja %}
    <div class="card" style="padding:16px;margin-top:4px;"><h2 style="font-size:14px;margin:0 0 8px 0;">🛒 Belanja Terakhir</h2>
        <div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Total</th></tr></thead>
        <tbody>{% for r in recent_belanja %}<tr><td>{{ r['invoice_no'] }}</td><td>{{ rupiah(r['total']) }}</td></tr>{% endfor %}</tbody></table></div>
    </div>
    {% endif %}
    ''', member=member, saldo_wallet=saldo_wallet, total_belanja=total_belanja, total_simpanan=total_simpanan, total_pinjaman=total_pinjaman, total_terbayar=total_terbayar, recent_belanja=recent_belanja, shu=shu, rupiah=rupiah, now=lambda: datetime.now)
    return render_page('Dashboard Member', body)

# =========================
# Member Purchase History
# =========================
@app.route('/member/purchases', methods=['GET'])
@login_required
def member_purchases():
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Akun member tidak ditemukan.', 'warning')
        return redirect(url_for('dashboard'))
    start, end = date_range_from_request()
    params = [member['id']]
    sql = 'SELECT s.*, u.full_name as kasir_name FROM sales s LEFT JOIN users u ON u.id=s.cashier_id WHERE s.member_id = ? AND s.status="Posted"'
    if start:
        sql += ' AND s.trx_date >= ?'; params.append(start)
    if end:
        sql += ' AND s.trx_date <= ?'; params.append(end)
    sql += ' ORDER BY s.id DESC LIMIT 200'
    rows = q_all(sql, params)
    total_all = q_one('SELECT COALESCE(SUM(total),0) as x FROM sales WHERE member_id=? AND status="Posted"', [member['id']])['x']
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><div><h2>🛒 Riwayat Belanja</h2><div class="muted small">{{ member.member_code }} — {{ member.name }} | Total: <strong>{{ rupiah(total_all) }}</strong></div></div>
        <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;width:auto;">
            <div><div class="small muted">Dari</div><input type="date" name="start" value="{{ start }}" style="width:140px;"></div>
            <div><div class="small muted">Sampai</div><input type="date" name="end" value="{{ end }}" style="width:140px;"></div>
            <button class="btn-ghost" type="submit">Filter</button>
        </form></div>
        <div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Tanggal</th><th>Total</th><th>Kasir</th><th>Aksi</th></tr></thead>
        <tbody>{% for r in rows %}<tr><td>{{ r['invoice_no'] }}</td><td>{{ r['trx_date'] }}</td><td>{{ rupiah(r['total']) }}</td><td>{{ r['kasir_name'] or '-' }}</td><td><a href="{{ url_for('receipt_pdf', sale_id=r['id']) }}" class="btn btn-sm btn-ghost">Struk</a></td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada transaksi.</td></tr>{% endfor %}</tbody></table></div>
    </div>
    ''', rows=rows, member=member, total_all=total_all, rupiah=rupiah, start=start, end=end)
    return render_page('Riwayat Belanja', body)

# =========================
# Member Card PDF
# =========================
@app.route('/member/card-pdf')
@login_required
def member_card_pdf():
    user = current_user()
    member_id = request.args.get('member_id', '')
    if user['role'] == 'admin' and member_id:
        member = q_one('SELECT * FROM members WHERE id=?', [member_id])
    else:
        member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Member tidak ditemukan.', 'error')
        return redirect(url_for('dashboard'))
    from reportlab.lib.pagesizes import landscape, A6
    buf = BytesIO()
    c = canvas.Canvas(buf, pagesize=landscape(A6))
    w, h = landscape(A6)
    c.setStrokeColorRGB(0.15, 0.39, 0.92)
    c.setLineWidth(3)
    c.rect(5, 5, w-10, h-10)
    c.setFillColorRGB(0.15, 0.39, 0.92)
    c.setFont('Helvetica-Bold', 14)
    c.drawString(15, h-30, 'KOPERASI ENTERPRISE')
    c.setFillColorRGB(0, 0, 0)
    c.setFont('Helvetica', 10)
    c.drawString(15, h-50, f'Kode: {member["member_code"]}')
    c.drawString(15, h-65, f'Nama: {member["name"]}')
    c.drawString(15, h-80, f'HP: {member["phone"] or "-"}')
    c.drawString(15, h-95, f'Status: {member["status"]}')
    c.setFont('Helvetica', 7)
    c.drawString(15, 15, f'Cetak: {now_str()[:10]}')
    c.showPage()
    c.save()
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f'kartu_{member["member_code"]}.pdf', mimetype='application/pdf')

# =========================
# Digital Member Card — QR + Premium Style
# =========================
@app.route('/member/digital-card')
@login_required
def member_digital_card():
    user = current_user()
    member_id = request.args.get('member_id', '')
    if user['role'] == 'admin' and member_id:
        member = q_one('SELECT * FROM members WHERE id=?', [member_id])
    else:
        member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Member tidak ditemukan.', 'error')
        return redirect(url_for('dashboard'))
    saldo_wallet = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id = ?', [member['id']])['saldo']
    total_belanja = q_one('SELECT COALESCE(SUM(total), 0) as x FROM sales WHERE member_id = ? AND status="Posted"', [member['id']])['x']
    qr_svg = simple_qr_svg(f"KOPERASI:{member['member_code']}:{member['name']}", 180)
    card_html = f'''
    <div style="max-width:420px;margin:0 auto;">
        <div style="background:linear-gradient(135deg,#1e293b,#334155,#475569);border-radius:24px;padding:32px 24px;box-shadow:0 20px 60px rgba(0,0,0,0.3);position:relative;overflow:hidden;margin-bottom:20px;">
            <div style="position:absolute;top:-40px;right:-40px;width:160px;height:160px;border-radius:50%;background:rgba(255,255,255,0.04);"></div>
            <div style="position:absolute;bottom:-30px;left:-30px;width:120px;height:120px;border-radius:50%;background:rgba(255,255,255,0.03);"></div>
            <div style="display:flex;justify-content:space-between;align-items:flex-start;position:relative;z-index:1;">
                <div>
                    <div style="color:rgba(255,255,255,0.5);font-size:11px;letter-spacing:1px;text-transform:uppercase;font-weight:600;">KOPERASI ENTERPRISE</div>
                    <div style="color:white;font-size:22px;font-weight:800;margin-top:4px;">{member['name']}</div>
                    <div style="color:#94a3b8;font-size:13px;margin-top:6px;">{member['member_code']}</div>
                </div>
                <div style="width:90px;height:90px;background:rgba(255,255,255,0.1);border-radius:16px;padding:8px;border:1px solid rgba(255,255,255,0.15);">
                    {qr_svg}
                </div>
            </div>
            <div style="display:flex;gap:16px;margin-top:28px;position:relative;z-index:1;">
                <div style="flex:1;background:rgba(255,255,255,0.08);border-radius:12px;padding:12px;text-align:center;">
                    <div style="color:#94a3b8;font-size:10px;text-transform:uppercase;">Wallet</div>
                    <div style="color:#10b981;font-size:16px;font-weight:700;margin-top:4px;">{rupiah(saldo_wallet)}</div>
                </div>
                <div style="flex:1;background:rgba(255,255,255,0.08);border-radius:12px;padding:12px;text-align:center;">
                    <div style="color:#94a3b8;font-size:10px;text-transform:uppercase;">Belanja</div>
                    <div style="color:#60a5fa;font-size:16px;font-weight:700;margin-top:4px;">{rupiah(total_belanja)}</div>
                </div>
                <div style="flex:1;background:rgba(255,255,255,0.08);border-radius:12px;padding:12px;text-align:center;">
                    <div style="color:#94a3b8;font-size:10px;text-transform:uppercase;">Status</div>
                    <div style="color:#34d399;font-size:14px;font-weight:700;margin-top:4px;">{member['status']}</div>
                </div>
            </div>
        </div>
        <div style="text-align:center;margin-bottom:20px;">
            <button class="btn" onclick="window.print()" style="background:linear-gradient(135deg,#4f46e5,#6366f1);">🖨️ Cetak / Simpan PDF</button>
            <a href="/member/card-pdf" class="btn btn-ghost" style="margin-left:8px;">💳 Download PDF</a>
        </div>
        <div style="background:white;border:1px solid var(--border);border-radius:16px;padding:20px;box-shadow:var(--shadow);">
            <h3 style="margin:0 0 12px 0;font-size:14px;">📋 Detail Member</h3>
            <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;font-size:13px;">
                <div><span class="muted">Kode</span><br>{member['member_code']}</div>
                <div><span class="muted">Nama</span><br>{member['name']}</div>
                <div><span class="muted">HP</span><br>{member['phone'] or '-'}</div>
                <div><span class="muted">Bergabung</span><br>{member['join_date'] or '-'}</div>
                <div><span class="muted">Alamat</span><br>{member['address'] or '-'}</div>
                <div><span class="muted">Status</span><br>{member['status']}</div>
            </div>
        </div>
    </div>
    <style>
    @media print {{ body * {{ visibility:hidden; }} .card, .card * {{ visibility:visible; }} .card {{ position:absolute;left:0;top:0;width:100%;padding:20px; }} .btn {{ display:none!important; }} }}
    </style>
    '''
    body = render_template_string(card_html, rupiah=rupiah)
    return render_page('Kartu Digital', body)

# =========================
# Admin E-Wallet Dashboard
# =========================
@app.route('/admin/ewallet-dashboard', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def ewallet_dashboard():
    if request.method == 'POST':
        request_id = int(request.form.get('request_id'))
        action = request.form.get('action')
        note = request.form.get('note', '')
        topup = q_one('SELECT * FROM topup_requests WHERE id = ? AND status = "PENDING"', [request_id])
        if not topup:
            flash('Request tidak ditemukan atau sudah diproses.', 'error')
            return redirect(url_for('ewallet_dashboard'))
        if action == 'approve':
            exec_sql('UPDATE topup_requests SET status = "APPROVED", approved_at = ?, approved_by = ? WHERE id = ?', [now_str(), session.get('user_id'), request_id])
            saldo_sebelum = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id = ?', [topup['member_id']])['saldo']
            saldo_setelah = saldo_sebelum + topup['nominal']
            exec_sql('INSERT INTO saldo_history(member_id, tipe, nominal, saldo_sebelum, saldo_setelah, keterangan, reference_id, created_by) VALUES (?, "MASUK", ?, ?, ?, "Topup via transfer admin", ?, ?)', [topup['member_id'], topup['nominal'], saldo_sebelum, saldo_setelah, request_id, session.get('user_id')])
            log_action('TOPUP_APPROVED', 'topup_requests', request_id, f'Topup Rp {topup["nominal"]} disetujui')
            flash('Topup disetujui, saldo sudah masuk ke wallet member.', 'success')
        elif action == 'reject':
            exec_sql('UPDATE topup_requests SET status = "REJECTED", note = ?, approved_at = ?, approved_by = ? WHERE id = ?', [note, now_str(), session.get('user_id'), request_id])
            log_action('TOPUP_REJECTED', 'topup_requests', request_id, f'Topup ditolak: {note}')
            flash('Request topup ditolak.', 'warning')
        return redirect(url_for('ewallet_dashboard'))
    
    pending = q_all('SELECT t.*, m.member_code, m.name as member_name FROM topup_requests t LEFT JOIN members m ON m.id = t.member_id WHERE t.status = "PENDING" ORDER BY t.id ASC')
    total_pending = q_one('SELECT COUNT(*) as n FROM topup_requests WHERE status = "PENDING"')['n'] or 0
    total_approved = q_one("SELECT COUNT(*) as n FROM topup_requests WHERE status = 'APPROVED'")['n'] or 0
    total_amount_approved = q_one("SELECT COALESCE(SUM(nominal), 0) as x FROM topup_requests WHERE status = 'APPROVED'")['x'] or 0
    total_amount_pending = q_one("SELECT COALESCE(SUM(nominal), 0) as x FROM topup_requests WHERE status = 'PENDING'")['x'] or 0
    recent_approved = q_all('SELECT t.*, m.name as member_name FROM topup_requests t LEFT JOIN members m ON m.id = t.member_id WHERE t.status IN ("APPROVED","REJECTED") ORDER BY t.id DESC LIMIT 20')
    
    body = render_template_string('''<div class="card"><div class="kartu"><div><h2>💰 Dashboard E-Wallet Admin</h2><div class="muted small">Kelola topup wallet pegawai — Dana masuk ke member setelah approval</div></div></div></div>
    <div class="metrics">
        <div class="metric" style="background:linear-gradient(135deg,#fffbeb,#fef3c7);border-color:#fcd34d;"><div class="label">Pending</div><div class="value" style="color:#f59e0b;">{{ total_pending }}</div><div class="sub">{{ rupiah(total_amount_pending) }}</div></div>
        <div class="metric" style="background:linear-gradient(135deg,#ecfdf5,#d1fae5);border-color:#6ee7b7;"><div class="label">Approved</div><div class="value" style="color:#10b981;">{{ total_approved }}</div><div class="sub">Rp {{ "{:,.0f}".format(total_amount_approved).replace(",", ".") }}</div></div>
    </div>
    <div class="grid"><div class="col-12">
    <div class="card"><h3>⏳ Menunggu Persetujuan</h3>
    <div class="table-wrap"><table><thead><tr><th>ID</th><th>Tanggal</th><th>Pegawai</th><th>No Karyawan</th><th>Nominal</th><th>Bukti</th><th>Catatan</th><th>Aksi</th></tr></thead>
    <tbody>{% for p in pending %}<tr><td>{{ p.id }}</td><td>{{ p.created_at }}</td><td>{{ p.member_name or '-' }}</td><td>{{ p.member_code }}</td><td style="font-weight:700;color:#2563eb;">{{ rupiah(p.nominal) }}</td>
    <td>{% if p.bukti_foto %}<a href="/uploads/{{ p.bukti_foto }}" target="_blank" class="btn btn-sm btn-ghost">🔍 Bukti</a>{% else %}<span class="muted">-</span>{% endif %}</td>
    <td><input name="note" placeholder="Catatan" style="width:120px;"></td>
    <td><form method="POST" style="display:flex;gap:6px;flex-wrap:wrap;"><input type="hidden" name="request_id" value="{{ p.id }}"><button name="action" value="approve" class="btn-sm btn-success">✅ Setujui</button><button name="action" value="reject" class="btn-sm btn-danger">❌ Tolak</button></form></td></tr>{% else %}<tr><td colspan="8" class="muted text-center">✅ Semua request sudah diproses.</td></tr>{% endfor %}</tbody></table></div>
    <hr><h3>📜 Riwayat Terakhir</h3>
    <div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Pegawai</th><th>Nominal</th><th>Status</th></tr></thead>
    <tbody>{% for h in recent_approved %}<tr><td>{{ h.created_at }}</td><td>{{ h.member_name or '-' }}</td><td>{{ rupiah(h.nominal) }}</td><td><span class="badge {% if h.status == 'APPROVED' %}badge-success{% else %}badge-danger{% endif %}">{{ h.status }}</span></td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Belum ada riwayat.</td></tr>{% endfor %}</tbody></table></div>
    </div></div></div></div>''', pending=pending, recent_approved=recent_approved, total_pending=total_pending, total_approved=total_approved, total_amount_approved=total_amount_approved, total_amount_pending=total_amount_pending, rupiah=rupiah)
    return render_page('E-Wallet Admin', body)

@app.route('/admin/topup-approval', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def topup_approval():
    if request.method == 'POST':
        request_id = int(request.form.get('request_id'))
        action = request.form.get('action')
        note = request.form.get('note', '')
        topup = q_one('SELECT * FROM topup_requests WHERE id = ? AND status = "PENDING"', [request_id])
        if not topup:
            flash('Request tidak ditemukan atau sudah diproses.', 'error')
            return redirect(url_for('topup_approval'))
        if action == 'approve':
            exec_sql('UPDATE topup_requests SET status = "APPROVED", approved_at = ?, approved_by = ? WHERE id = ?', [now_str(), session.get('user_id'), request_id])
            saldo_sebelum = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id = ?', [topup['member_id']])['saldo']
            saldo_setelah = saldo_sebelum + topup['nominal']
            exec_sql('INSERT INTO saldo_history(member_id, tipe, nominal, saldo_sebelum, saldo_setelah, keterangan, reference_id, created_by) VALUES (?, "MASUK", ?, ?, ?, "Topup via transfer admin", ?, ?)', [topup['member_id'], topup['nominal'], saldo_sebelum, saldo_setelah, request_id, session.get('user_id')])
            log_action('TOPUP_APPROVED', 'topup_requests', request_id, f'Topup Rp {topup["nominal"]} disetujui')
            flash('Topup berhasil disetujui, saldo sudah masuk ke wallet user.', 'success')
        elif action == 'reject':
            exec_sql('UPDATE topup_requests SET status = "REJECTED", note = ?, approved_at = ?, approved_by = ? WHERE id = ?', [note, now_str(), session.get('user_id'), request_id])
            log_action('TOPUP_REJECTED', 'topup_requests', request_id, f'Topup ditolak: {note}')
            flash('Request topup ditolak.', 'warning')
        return redirect(url_for('topup_approval'))
    pending = q_all('SELECT t.*, m.member_code, m.name as member_name FROM topup_requests t LEFT JOIN members m ON m.id = t.member_id WHERE t.status = "PENDING" ORDER BY t.id ASC')
    history = q_all('SELECT t.*, m.member_code, m.name as member_name, u.full_name as admin_name FROM topup_requests t LEFT JOIN members m ON m.id = t.member_id LEFT JOIN users u ON u.id = t.approved_by WHERE t.status != "PENDING" ORDER BY t.id DESC LIMIT 100')
    body = render_template_string('''
    <div class="card">
        <h2>✅ Approval Topup Wallet</h2>
        <div class="muted small">Verifikasi bukti transfer dan setujui / tolak request topup pegawai</div>
        <hr><h3>⏳ Menunggu</h3>
        <div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Pegawai</th><th>Nominal</th><th>Bukti</th><th>Aksi</th></tr></thead>
        <tbody>{% for p in pending %}<tr><td>{{ p.created_at }}</td><td>{{ p.member_code }} — {{ p.member_name }}</td><td style="font-weight:700;color:#2563eb;">{{ rupiah(p.nominal) }}</td>
        <td>{% if p.bukti_foto %}<a href="/uploads/{{ p.bukti_foto }}" target="_blank" class="btn btn-sm btn-ghost">🔍 Lihat</a>{% endif %}</td>
        <td><form method="POST" style="display:flex;gap:8px;"><input type="hidden" name="request_id" value="{{ p.id }}"><button name="action" value="approve" class="btn-sm btn-success">✅ Setujui</button><button name="action" value="reject" class="btn-sm btn-danger">❌ Tolak</button></form></td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Tidak ada pending request.</td></tr>{% endfor %}</tbody></table></div>
        <hr><h3>📜 Riwayat</h3>
        <div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Pegawai</th><th>Nominal</th><th>Status</th><th>Admin</th></tr></thead>
        <tbody>{% for h in history %}<tr><td>{{ h.created_at }}</td><td>{{ h.member_code }} — {{ h.member_name }}</td><td>{{ rupiah(h.nominal) }}</td><td><span class="badge {{ 'badge-success' if h.status == 'APPROVED' else 'badge-danger' }}">{{ h.status }}</span></td><td>{{ h.admin_name or '-' }}</td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada riwayat.</td></tr>{% endfor %}</tbody></table></div>
    </div>
    ''', pending=pending, history=history, rupiah=rupiah)
    return render_page('Approval Topup Wallet', body)

# =========================
# Dashboard
# =========================
@app.route('/')
@login_required
def dashboard():
    m_count = q_one('SELECT COUNT(*) as n FROM members')['n']
    p_count = q_one('SELECT COUNT(*) as n FROM products')['n']
    sale_today = q_one('SELECT COALESCE(SUM(total),0) as x FROM sales WHERE trx_date=? AND status="Posted"', [today_str()])['x']
    savings_total = q_one("SELECT COALESCE(SUM(CASE WHEN direction='Masuk' THEN amount ELSE -amount END),0) as x FROM savings_transactions")['x']
    pending_approval = q_one("SELECT COUNT(*) as n FROM approval_requests WHERE status='Pending'")['n']
    pending_users = q_one("SELECT COUNT(*) as n FROM users WHERE status='PENDING_APPROVAL'")['n']
    loan_outstanding = q_one('''SELECT COALESCE(SUM(l.total_receivable - COALESCE(p.paid,0)),0) as x FROM loans l LEFT JOIN (SELECT loan_id, SUM(amount) as paid FROM loan_payments GROUP BY loan_id) p ON p.loan_id=l.id WHERE l.status IN ('Berjalan','Menunggu Approval')''')['x']
    # --- New dashboard metrics ---
    now = datetime.now()
    cur_month = now.strftime('%Y-%m')
    prev_month_dt = (now.replace(day=1) - timedelta(days=1))
    prev_month = prev_month_dt.strftime('%Y-%m')
    sale_month = q_one('SELECT COALESCE(SUM(total),0) as x FROM sales WHERE substr(trx_date,1,7)=? AND status="Posted"', [cur_month])['x']
    sale_prev_month = q_one('SELECT COALESCE(SUM(total),0) as x FROM sales WHERE substr(trx_date,1,7)=? AND status="Posted"', [prev_month])['x']
    active_loan_count = q_one("SELECT COUNT(*) as n FROM loans WHERE status='Berjalan'")['n']
    angsuran_month = q_one('SELECT COALESCE(SUM(amount),0) as x FROM loan_payments lp JOIN loans l ON l.id=lp.loan_id WHERE lp.status="VERIFIED" AND substr(lp.payment_date,1,7)=?', [cur_month])['x']
    low_stock_count = q_one('SELECT COUNT(*) as n FROM products WHERE active=1 AND stock<=min_stock')['n']
    profit_month = q_one("SELECT COALESCE(SUM(credit)-SUM(debit),0) as x FROM journal_entries j JOIN accounts a ON a.id=j.account_id WHERE a.category='Pendapatan' AND substr(j.entry_date,1,7)=?", [cur_month])['x']
    expense_month = q_one("SELECT COALESCE(SUM(debit)-SUM(credit),0) as x FROM journal_entries j JOIN accounts a ON a.id=j.account_id WHERE a.category='Beban' AND substr(j.entry_date,1,7)=?", [cur_month])['x']
    # --- Charts ---
    sales_month = q_all("SELECT substr(trx_date,1,7) as m, COALESCE(SUM(total),0) as total FROM sales WHERE status='Posted' GROUP BY substr(trx_date,1,7) ORDER BY m DESC LIMIT 6")
    savings_month = q_all("SELECT substr(trx_date,1,7) as m, COALESCE(SUM(CASE WHEN direction='Masuk' THEN amount ELSE -amount END),0) as total FROM savings_transactions GROUP BY substr(trx_date,1,7) ORDER BY m DESC LIMIT 6")
    sales_chart = bar_chart_svg(list(reversed([(r['m'][5:7]+'/'+r['m'][:4], float(r['total'])) for r in sales_month])), 'Penjualan 6 Bulan', color='#2563eb')
    savings_chart = bar_chart_svg(list(reversed([(r['m'][5:7]+'/'+r['m'][:4], float(r['total'])) for r in savings_month])), 'Simpanan 6 Bulan', color='#10b981')
    # Loan vs payment grouped chart
    loan_month = q_all("SELECT substr(loan_date,1,7) as m, COALESCE(SUM(total_receivable),0) as total FROM loans WHERE status IN ('Berjalan','Lunas') GROUP BY substr(loan_date,1,7) ORDER BY m DESC LIMIT 6")
    payment_month = q_all("SELECT substr(payment_date,1,7) as m, COALESCE(SUM(amount),0) as total FROM loan_payments WHERE status='VERIFIED' GROUP BY substr(payment_date,1,7) ORDER BY m DESC LIMIT 6")
    loan_labels = [(r['m'][5:7]+'/'+r['m'][:4], 0) for r in reversed(loan_month)] if loan_month else []
    loan_chart = grouped_bar_chart_svg(
        loan_labels if loan_labels else [('No Data', 0)],
        [(r['m'][5:7]+'/'+r['m'][:4], float(r['total'])) for r in reversed(payment_month)],
        'Pinjaman vs Angsuran', label_a='Diberikan', label_b='Diterima',
        color_a='#f59e0b', color_b='#10b981'
    )
    # Top 5 products
    top_products = q_all('''SELECT p.product_name, COALESCE(SUM(si.subtotal),0) as revenue
        FROM sales_items si JOIN sales s ON s.id=si.sales_id JOIN products p ON p.id=si.product_id
        WHERE s.status='Posted' AND substr(s.trx_date,1,7)=?
        GROUP BY si.product_id ORDER BY revenue DESC LIMIT 5''', [cur_month])
    top_products_chart = horizontal_bar_chart_svg(
        [(r['product_name'][:12], float(r['revenue'])) for r in top_products],
        f'Top 5 Produk {cur_month[5:]}/{cur_month[:4]}', colors=['#2563eb','#10b981','#f59e0b','#ef4444','#8b5cf6']
    )
    # Payment method chart
    pay_method = q_all('''SELECT payment_method, COUNT(*) as cnt, COALESCE(SUM(total),0) as total
        FROM sales WHERE status='Posted' AND substr(trx_date,1,7)=?
        GROUP BY payment_method ORDER BY total DESC''', [cur_month])
    pay_chart = horizontal_bar_chart_svg(
        [(f"{r['payment_method']} ({r['cnt']})", float(r['total'])) for r in pay_method],
        f'Komposisi Pembayaran {cur_month[5:]}/{cur_month[:4]}', colors=['#3b82f6','#8b5cf6','#f59e0b']
    )
    # Existing tables
    low_stock = q_all('SELECT barcode, product_name, stock, min_stock FROM products WHERE active=1 AND stock<=min_stock ORDER BY stock ASC LIMIT 5')
    recent = q_all('SELECT invoice_no, trx_date, total FROM sales WHERE status="Posted" ORDER BY id DESC LIMIT 5')
    body = render_template_string('''
    <div class="metrics">
        <div class="metric" style="background:linear-gradient(135deg,#eff6ff,#dbeafe);border-color:#93c5fd;">
            <div class="label">Penjualan Bulan Ini</div>
            <div class="value" style="color:#2563eb;">{{ rupiah(sale_month) }}</div>
            <div class="sub">Hari ini: {{ rupiah(sale_today) }}</div>
        </div>
        <div class="metric" style="background:linear-gradient(135deg,#ecfdf5,#d1fae5);border-color:#6ee7b7;">
            <div class="label">Angsuran Diterima</div>
            <div class="value" style="color:#10b981;">{{ rupiah(angsuran_month) }}</div>
            <div class="sub">{{ active_loan_count }} pinjaman aktif</div>
        </div>
        <div class="metric" style="background:linear-gradient(135deg,#fef2f2,#fee2e2);border-color:#fca5a5;">
            <div class="label">Piutang Pinjaman</div>
            <div class="value" style="color:#ef4444;">{{ rupiah(loan_outstanding) }}</div>
        </div>
        <div class="metric" style="background:linear-gradient(135deg,#fffbeb,#fef3c7);border-color:#fcd34d;">
            <div class="label">Laba Bersih Bulan Ini</div>
            <div class="value" style="color:{{ '#10b981' if profit_month >= expense_month else '#ef4444' }}">{{ rupiah(profit_month - expense_month) }}</div>
        </div>
        <div class="metric">
            <div class="label">Simpanan Bersih</div>
            <div class="value">{{ rupiah(savings_total) }}</div>
        </div>
        <div class="metric">
            <div class="label">Member / Barang</div>
            <div class="value">{{ m_count }} / {{ p_count }}</div>
        </div>
    </div>
    <div class="grid">
        <div class="col-6"><div class="card"><h2>📈 Penjualan 6 Bulan</h2>{{ sales_chart|safe }}</div></div>
        <div class="col-6"><div class="card"><h2>🏦 Pinjaman vs Angsuran</h2>{{ loan_chart|safe }}</div></div>
        <div class="col-6"><div class="card"><h2>⭐ Top 5 Produk</h2>{{ top_products_chart|safe }}</div></div>
        <div class="col-6"><div class="card"><h2>🛒 Transaksi Terakhir</h2>
            <div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Total</th></tr></thead>
            <tbody>{% for r in recent %}<tr><td>{{ r['invoice_no'] }}</td><td>{{ rupiah(r['total']) }}</td></tr>{% else %}<tr><td colspan="2" class="muted text-center">Belum ada transaksi.</td></tr>{% endfor %}</tbody></table></div>
        </div></div>
    </div>
    ''', m_count=m_count, p_count=p_count, sale_today=sale_today, sale_month=sale_month, sale_prev_month=sale_prev_month, pending_approval=pending_approval, pending_users=pending_users, savings_total=savings_total, loan_outstanding=loan_outstanding, active_loan_count=active_loan_count, angsuran_month=angsuran_month, low_stock_count=low_stock_count, profit_month=profit_month, expense_month=expense_month, sales_chart=sales_chart, savings_chart=savings_chart, loan_chart=loan_chart, top_products_chart=top_products_chart, pay_chart=pay_chart, low_stock=low_stock, recent=recent, rupiah=rupiah)
    return render_page('Dashboard', body)

# =========================
# Members
# =========================
@app.route('/members', methods=['GET', 'POST'])
@login_required
def members():
    edit_id = request.args.get('edit_id', '')
    edit_row = q_one('SELECT * FROM members WHERE id=?', [edit_id]) if edit_id else None
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        code = request.form.get('member_code', '').strip() or gen_code('MBR')
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        join_date = request.form.get('join_date', today_str())
        status = request.form.get('status', 'Aktif')
        if action == 'create':
            if not name:
                flash('Nama member wajib diisi.', 'error')
            else:
                try:
                    mid = exec_sql('INSERT INTO members(member_code, name, phone, address, join_date, status) VALUES (?, ?, ?, ?, ?, ?)', [code, name, phone, address, join_date, status])
                    log_action('CREATE', 'members', mid, f'Tambah member {name}')
                    flash('Member berhasil disimpan.', 'success')
                    return redirect(url_for('members'))
                except sqlite3.IntegrityError:
                    flash('Kode member sudah ada.', 'error')
        elif action == 'update':
            member_id = int(request.form.get('member_id'))
            exec_sql('UPDATE members SET member_code=?, name=?, phone=?, address=?, join_date=?, status=? WHERE id=?', [code, name, phone, address, join_date, status, member_id])
            log_action('UPDATE', 'members', member_id, f'Update member {name}')
            flash('Member berhasil diupdate.', 'success')
            return redirect(url_for('members'))
    key = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    if key:
        base_sql = 'SELECT * FROM members WHERE member_code LIKE ? OR name LIKE ? OR phone LIKE ? ORDER BY id DESC'
        p = paginate_query(base_sql, [f'%{key}%', f'%{key}%', f'%{key}%'], page)
    else:
        base_sql = 'SELECT * FROM members ORDER BY id DESC'
        p = paginate_query(base_sql, [], page)
    rows = p['rows']
    pag_html = render_pagination(p, 'members', {'q': key})
    body = render_template_string('''
    <div class="grid">
        <div class="col-4"><div class="card">
            <h2>{{ 'Edit Member' if edit_row else 'Tambah Member' }}</h2>
            <form method="post">
                {% if edit_row %}<input type="hidden" name="action" value="update"><input type="hidden" name="member_id" value="{{ edit_row['id'] }}">{% else %}<input type="hidden" name="action" value="create">{% endif %}
                <div class="form-group"><label>Kode Member</label><input name="member_code" value="{{ edit_row['member_code'] if edit_row else default_code }}"></div>
                <div class="form-group"><label>Nama</label><input name="name" value="{{ edit_row['name'] if edit_row else '' }}" required></div>
                <div class="form-group"><label>No. HP</label><input name="phone" value="{{ edit_row['phone'] if edit_row else '' }}"></div>
                <div class="form-group"><label>Alamat</label><textarea name="address">{{ edit_row['address'] if edit_row else '' }}</textarea></div>
                <div class="form-group"><label>Tanggal Bergabung</label><input type="date" name="join_date" value="{{ edit_row['join_date'] if edit_row else today }}"></div>
                <div class="form-group"><label>Status</label><select name="status"><option value="Aktif" {% if edit_row and edit_row['status']=='Aktif' %}selected{% endif %}>Aktif</option><option value="Nonaktif" {% if edit_row and edit_row['status']=='Nonaktif' %}selected{% endif %}>Nonaktif</option></select></div>
                <button type="submit">{{ 'Update' if edit_row else 'Simpan' }}</button>
                {% if edit_row %}<a href="{{ url_for('members') }}" class="btn btn-ghost" style="margin-top:8px;">Batal</a>{% endif %}
            </form>
        </div></div>
        <div class="col-8"><div class="card">
            <div class="kartu"><h2>Data Member</h2>
            <form method="get" style="display:flex;gap:8px;width:auto;"><input name="q" value="{{ key }}" placeholder="Cari..." style="width:200px;"><button class="btn-ghost" type="submit">Cari</button></form></div>
            <div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama</th><th>HP</th><th>Simpanan</th><th>SHU</th><th>Status</th><th>Aksi</th></tr></thead>
            <tbody>{% for r in rows %}<tr><td>{{ r['member_code'] }}</td><td>{{ r['name'] }}</td><td>{{ r['phone'] }}</td><td>{{ rupiah(r['saldo']) }}</td><td>{{ rupiah(r['shu_balance']) }}</td><td><span class="badge badge-info">{{ r['status'] }}</span></td><td><a class="btn btn-sm btn-ghost" href="{{ url_for('members', edit_id=r['id']) }}">Edit</a></td></tr>{% else %}<tr><td colspan="7" class="muted text-center">Belum ada member.</td></tr>{% endfor %}</tbody></table></div>
            {{ pag_html|safe }}
        </div></div>
    </div>
    ''', rows=rows, key=key, edit_row=edit_row, default_code=gen_code('MBR'), today=today_str(), rupiah=rupiah, pag_html=pag_html)
    return render_page('Member', body)

# =========================
# Products
# =========================
@app.route('/products', methods=['GET', 'POST'])
@login_required
def products():
    edit_id = request.args.get('edit_id', '')
    edit_row = q_one('SELECT * FROM products WHERE id=?', [edit_id]) if edit_id else None
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        barcode = request.form.get('barcode', '').strip()
        product_name = request.form.get('product_name', '').strip()
        category = request.form.get('category', 'Umum').strip()
        unit = request.form.get('unit', 'pcs').strip()
        buy_price = parse_float(request.form.get('buy_price', 0) or 0)
        sell_price = parse_float(request.form.get('sell_price', 0) or 0)
        stock = parse_float(request.form.get('stock', 0) or 0)
        min_stock = parse_float(request.form.get('min_stock', 0) or 0)
        active = 1 if request.form.get('active', '1') == '1' else 0
        if not barcode or not product_name:
            flash('Barcode dan nama barang wajib diisi.', 'error')
        else:
            try:
                if action == 'create':
                    pid = exec_sql('INSERT INTO products(barcode, product_name, category, unit, buy_price, sell_price, stock, min_stock, active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)', [barcode, product_name, category, unit, buy_price, sell_price, stock, min_stock, active])
                    log_action('CREATE', 'products', pid, f'Tambah barang {product_name}')
                    flash('Barang berhasil disimpan.', 'success')
                else:
                    product_id = int(request.form.get('product_id'))
                    exec_sql('UPDATE products SET barcode=?, product_name=?, category=?, unit=?, buy_price=?, sell_price=?, stock=?, min_stock=?, active=? WHERE id=?', [barcode, product_name, category, unit, buy_price, sell_price, stock, min_stock, active, product_id])
                    log_action('UPDATE', 'products', product_id, f'Update barang {product_name}')
                    flash('Barang berhasil diupdate.', 'success')
                return redirect(url_for('products'))
            except sqlite3.IntegrityError:
                flash('Barcode sudah ada.', 'error')
    key = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)
    if key:
        p = paginate_query("SELECT *, CASE WHEN active=1 THEN 'Aktif' ELSE 'Nonaktif' END AS stat FROM products WHERE barcode LIKE ? OR product_name LIKE ? OR category LIKE ? ORDER BY id DESC", [f'%{key}%', f'%{key}%', f'%{key}%'], page)
    else:
        p = paginate_query("SELECT *, CASE WHEN active=1 THEN 'Aktif' ELSE 'Nonaktif' END AS stat FROM products ORDER BY id DESC", [], page)
    rows = p['rows']
    pag_html = render_pagination(p, 'products', {'q': key})
    body = render_template_string('''
    <div class="grid">
        <div class="col-4"><div class="card"><h2>{{ 'Edit' if edit_row else 'Tambah Barang' }}</h2>
            <form method="post">
                {% if edit_row %}<input type="hidden" name="action" value="update"><input type="hidden" name="product_id" value="{{ edit_row['id'] }}">{% else %}<input type="hidden" name="action" value="create">{% endif %}
                <div class="form-group"><label>Barcode</label><input name="barcode" value="{{ edit_row['barcode'] if edit_row else '' }}"></div>
                <div class="form-group"><label>Nama Barang</label><input name="product_name" value="{{ edit_row['product_name'] if edit_row else '' }}" required></div>
                <div class="form-group"><label>Kategori</label><input name="category" value="{{ edit_row['category'] if edit_row else 'Umum' }}"></div>
                <div class="form-group"><label>Satuan</label><input name="unit" value="{{ edit_row['unit'] if edit_row else 'pcs' }}"></div>
                <div class="form-group"><label>Harga Beli</label><input type="number" name="buy_price" value="{{ edit_row['buy_price'] if edit_row else '' }}"></div>
                <div class="form-group"><label>Harga Jual</label><input type="number" name="sell_price" value="{{ edit_row['sell_price'] if edit_row else '' }}"></div>
                <div class="form-group"><label>Stok</label><input type="number" name="stock" value="{{ edit_row['stock'] if edit_row else '' }}"></div>
                <div class="form-group"><label>Min Stok</label><input type="number" name="min_stock" value="{{ edit_row['min_stock'] if edit_row else '0' }}"></div>
                <button type="submit">{{ 'Update' if edit_row else 'Simpan' }}</button>
                {% if edit_row %}<a href="{{ url_for('products') }}" class="btn btn-ghost" style="margin-top:8px;">Batal</a>{% endif %}
            </form>
        </div></div>
        <div class="col-8"><div class="card">
            <div class="kartu"><h2>Master Barang</h2><div style="display:flex;gap:8px;flex-wrap:wrap;align-items:center;"><form method="get" style="display:flex;gap:8px;width:auto;margin:0;"><input name="q" value="{{ key }}" placeholder="Cari..." style="width:200px;"><button class="btn-ghost" type="submit">Cari</button></form><a href="{{ url_for('product_barcode_labels') }}" class="btn btn-sm btn-ghost">🏷️ Cetak Barcode</a></div></div>
            <div class="table-wrap"><table><thead><tr><th>Barcode</th><th>Nama</th><th>Beli</th><th>Jual</th><th>Stok</th><th>Min</th><th>Status</th><th>Aksi</th></tr></thead>
            <tbody>{% for r in rows %}<tr><td>{{ r['barcode'] }}</td><td>{{ r['product_name'] }}</td><td>{{ rupiah(r['buy_price']) }}</td><td>{{ rupiah(r['sell_price']) }}</td><td>{{ r['stock'] }}</td><td>{{ r['min_stock'] }}</td><td><span class="badge {{ 'badge-success' if r['active'] else 'badge-gray' }}">{{ r['stat'] }}</span></td><td><a class="btn btn-sm btn-ghost" href="{{ url_for('products', edit_id=r['id']) }}">Edit</a> <a href="{{ url_for('product_barcode_labels') }}?barcode={{ r['barcode'] }}" class="btn btn-sm btn-ghost" title="Cetak label barcode">🏷️</a></td></tr>{% else %}<tr><td colspan="8" class="muted text-center">Belum ada barang.</td></tr>{% endfor %}</tbody></table></div>
            {{ pag_html|safe }}
        </div></div>
    </div>
    ''', rows=rows, key=key, rupiah=rupiah, edit_row=edit_row, pag_html=pag_html)
    return render_page('Barang', body)

# =========================
# Cashier
# =========================
# =========================
# Quick Cashier — Bayar Cepat, Stok Dikurangi Nanti
# =========================
@app.route('/quick-cashier', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def quick_cashier():
    if request.method == 'POST':
        total = parse_float(request.form.get('total', 0) or 0)
        paid = parse_float(request.form.get('paid', 0) or 0)
        payment_method = request.form.get('payment_method', 'tunai')
        member_id = request.form.get('member_id') or None
        customer_name = request.form.get('customer_name', '').strip()
        note = request.form.get('note', '').strip()
        invoice = gen_code('INV')
        if total <= 0:
            flash('Total belanja harus lebih dari 0.', 'error')
            return redirect(url_for('quick_cashier'))
        change_amount = 0
        if payment_method == 'tunai':
            if paid < total:
                flash(f'Nominal bayar kurang. Total {rupiah(total)}', 'error')
                return redirect(url_for('quick_cashier'))
            change_amount = paid - total
        elif payment_method == 'wallet':
            if not member_id:
                flash('Bayar wallet wajib pilih member.', 'error')
                return redirect(url_for('quick_cashier'))
            member_saldo = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id=?', [member_id])['saldo']
            if member_saldo < total:
                flash(f'Saldo wallet tidak cukup. Saldo: {rupiah(member_saldo)}', 'error')
                return redirect(url_for('quick_cashier'))
            saldo_sebelum = member_saldo
            saldo_setelah = saldo_sebelum - total
            exec_sql('INSERT INTO saldo_history(member_id, tipe, nominal, saldo_sebelum, saldo_setelah, keterangan, reference_id, created_by) VALUES (?, "KELUAR", ?, ?, ?, "Pembayaran quick cashier", ?, ?)',
                [member_id, total, saldo_sebelum, saldo_setelah, 0, session.get('user_id')])
            paid = total
        else:
            paid = total
        # Simpan ke antrian verifikasi (PENDING) — stok belum dikurangi
        qid = exec_sql('INSERT INTO quick_cashier_queue(invoice_no, trx_date, total, payment_method, member_id, customer_name, note, status, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, "PENDING", ?)',
            [invoice, today_str(), total, payment_method, member_id, customer_name, note, session.get('user_id')])
        log_action('QUICK_CASHIER_PENDING', 'quick_cashier_queue', qid, f'Total {total} metode {payment_method} — menunggu verifikasi')
        flash(f'✅ Transaksi antri verifikasi! Invoice: {invoice} — {rupiah(total)}. Status: PENDING. Admin akan verifikasi untuk kurangi stok.', 'success')
        return redirect(url_for('quick_cashier'))
    members_rows = q_all("SELECT id, member_code, name FROM members WHERE status='Aktif' ORDER BY name ASC")
    body = render_template_string('''
    <div class="grid">
        <div class="col-6">
            <div class="card" style="text-align:center;">
                <h2>⚡ Quick Cashier</h2>
                <div class="muted small">Input total belanja langsung — tanpa scan barang 1 per 1. Stok dikurangi nanti.</div>
                <hr>
                <form method="post" id="quickForm">
                    <div class="form-group" style="text-align:left;">
                        <label>Member (opsional)</label>
                        <select name="member_id">
                            <option value="">🏷️ Umum</option>
                            {% for m in members_rows %}
                            <option value="{{ m['id'] }}">{{ m['member_code'] }} — {{ m['name'] }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group" style="text-align:left;">
                        <label>Nama Pelanggan (opsional)</label>
                        <input name="customer_name" placeholder="Nama pelanggan">
                    </div>
                    <div style="display:flex;gap:16px;align-items:center;justify-content:center;margin:24px 0;">
                        <div style="font-size:14px;color:var(--text-muted);">Total Belanja</div>
                        <div style="font-size:48px;font-weight:800;color:#059669;" id="totalDisplay">Rp 0</div>
                    </div>
                    <input type="hidden" name="total" id="totalInput" value="0">
                    <div class="keypad" style="display:grid;grid-template-columns:repeat(3,1fr);gap:8px;max-width:320px;margin:0 auto;">
                        <button type="button" class="btn btn-ghost" onclick="press('1')" style="font-size:24px;padding:16px;">1</button>
                        <button type="button" class="btn btn-ghost" onclick="press('2')" style="font-size:24px;padding:16px;">2</button>
                        <button type="button" class="btn btn-ghost" onclick="press('3')" style="font-size:24px;padding:16px;">3</button>
                        <button type="button" class="btn btn-ghost" onclick="press('4')" style="font-size:24px;padding:16px;">4</button>
                        <button type="button" class="btn btn-ghost" onclick="press('5')" style="font-size:24px;padding:16px;">5</button>
                        <button type="button" class="btn btn-ghost" onclick="press('6')" style="font-size:24px;padding:16px;">6</button>
                        <button type="button" class="btn btn-ghost" onclick="press('7')" style="font-size:24px;padding:16px;">7</button>
                        <button type="button" class="btn btn-ghost" onclick="press('8')" style="font-size:24px;padding:16px;">8</button>
                        <button type="button" class="btn btn-ghost" onclick="press('9')" style="font-size:24px;padding:16px;">9</button>
                        <button type="button" class="btn btn-ghost" onclick="press('00')" style="font-size:24px;padding:16px;">00</button>
                        <button type="button" class="btn btn-ghost" onclick="press('0')" style="font-size:24px;padding:16px;">0</button>
                        <button type="button" class="btn btn-ghost" onclick="pressDel()" style="font-size:24px;padding:16px;">⌫</button>
                    </div>
                    <hr>
                    <div class="form-group" style="text-align:left;">
                        <label>Metode Bayar</label>
                        <div style="display:flex;gap:12px;flex-wrap:wrap;">
                            <label class="btn btn-ghost" style="flex:1;cursor:pointer;padding:12px;">
                                <input type="radio" name="payment_method" value="tunai" checked onchange="toggleMethod()"> 💰 Tunai
                            </label>
                            <label class="btn btn-ghost" style="flex:1;cursor:pointer;padding:12px;">
                                <input type="radio" name="payment_method" value="wallet" onchange="toggleMethod()"> 💳 Wallet
                            </label>
                        </div>
                    </div>
                    <div class="form-group" id="paidSection" style="text-align:left;">
                        <label>💰 Uang Dibayar</label>
                        <div class="login-input-wrap">
                            <span class="login-input-icon">💵</span>
                            <input type="number" id="paidInput" name="paid" min="0" placeholder="Jumlah uang" style="font-size:20px;font-weight:700;padding:14px 14px 14px 42px;">
                        </div>
                        <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;">
                            <button type="button" class="btn btn-sm btn-ghost" onclick="setPaid(parseInt(document.getElementById('totalInput').value)||0)">Uang Pas</button>
                            <button type="button" class="btn btn-sm btn-ghost" onclick="setPaid(Math.ceil((parseInt(document.getElementById('totalInput').value)||0)/1000)*1000+5000)">+5rb</button>
                            <button type="button" class="btn btn-sm btn-ghost" onclick="setPaid(Math.ceil((parseInt(document.getElementById('totalInput').value)||0)/10000)*10000)">+10rb</button>
                            <button type="button" class="btn btn-sm btn-ghost" onclick="setPaid(Math.ceil((parseInt(document.getElementById('totalInput').value)||0)/50000)*50000)">+50rb</button>
                            <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;border-top:1px solid var(--border);padding-top:8px;">
                                <span class="small muted">Simpanan nominal:</span>
                                <button type="button" class="btn btn-sm btn-ghost" onclick="setPaid(50000)">50rb</button>
                                <button type="button" class="btn btn-sm btn-ghost" onclick="setPaid(100000)">100rb</button>
                                <button type="button" class="btn btn-sm btn-ghost" onclick="setPaid(200000)">200rb</button>
                                <button type="button" class="btn btn-sm btn-ghost" onclick="saveCustom()">💾 Simpan nominal</button>
                                <input type="number" id="customSaveAmount" placeholder="Nominal" style="width:100px;font-size:12px;padding:6px 10px;">
                                <button type="button" class="btn btn-sm btn-ghost" id="savedBtn" style="display:none;" onclick="setPaid(parseInt(this.dataset.val)||0)">💾 <span id="savedLabel"></span></button>
                            </div>
                        </div>
                    </div>
                    <div class="form-group" style="text-align:left;">
                        <label>Catatan</label>
                        <textarea name="note" style="min-height:40px;" placeholder="Catatan (opsional)"></textarea>
                    </div>
                    <button type="submit" class="btn-success" style="font-size:18px;padding:16px;">💾 Simpan Transaksi</button>
                </form>
            </div>
        </div>
        <div class="col-6">
            <div class="card" id="paymentInfo">
                <h2>💰 Ringkasan</h2>
                <div style="padding:20px;text-align:center;">
                    <div class="muted small">Total Belanja</div>
                    <div style="font-size:42px;font-weight:800;color:#059669;" id="ringkasanTotal">Rp 0</div>
                    <hr>
                    <div class="muted small">Uang Dibayar</div>
                    <div style="font-size:32px;font-weight:700;color:#2563eb;" id="ringkasanBayar">Rp 0</div>
                    <hr>
                    <div class="muted small">Kembalian</div>
                    <div style="font-size:36px;font-weight:800;" id="ringkasanKembali">Rp 0</div>
                </div>
            </div>
            <div class="card">
                <h2>📌 Panduan</h2>
                <ol style="font-size:13px;line-height:2;">
                    <li><strong>Input total</strong> belanja menggunakan keypad</li>
                    <li>Pilih <strong>metode bayar</strong> (Tunai / Wallet)</li>
                    <li>Masukkan <strong>uang dibayar</strong> (atau tekan "Uang Pas")</li>
                    <li>Klik <strong>Simpan Transaksi</strong></li>
                    <li>Setelah antrian selesai, lakukan <strong>Adjustment Stok</strong> untuk mengurangi barang</li>
                </ol>
            </div>
        </div>
    </div>
    <script>
    function press(n){ var inp=document.getElementById('totalInput'); var v=inp.value.replace(/[^0-9]/g,''); v=v+n; inp.value=v.replace(/^0+/,'')||'0'; updateDisplay(); }
    function pressDel(){ var inp=document.getElementById('totalInput'); var v=inp.value.replace(/[^0-9]/g,''); v=v.slice(0,-1)||'0'; inp.value=v; updateDisplay(); }
    function updateDisplay(){
        var v=parseInt(document.getElementById('totalInput').value)||0;
        document.getElementById('totalDisplay').textContent='Rp '+v.toLocaleString('id-ID');
        document.getElementById('ringkasanTotal').textContent='Rp '+v.toLocaleString('id-ID');
        hitungKembalian();
    }
    function setPaid(v){ document.getElementById('paidInput').value=v; hitungKembalian(); }
    function hitungKembalian(){
        var total=parseInt(document.getElementById('totalInput').value)||0;
        var paid=parseFloat(document.getElementById('paidInput').value)||0;
        if(paid>0){document.getElementById('ringkasanBayar').textContent='Rp '+paid.toLocaleString('id-ID');}
        var kembali=paid-total; if(kembali<0)kembali=0;
        document.getElementById('ringkasanKembali').textContent='Rp '+kembali.toLocaleString('id-ID');
        document.getElementById('ringkasanKembali').style.color=kembali>=0?'#059669':'#ef4444';
    }
    function toggleMethod(){
        var pw=document.querySelector('input[name="payment_method"]:checked').value;
        document.getElementById('paidSection').style.display=pw==='wallet'?'none':'block';
        if(pw==='wallet'){document.getElementById('paidInput').value=document.getElementById('totalInput').value;hitungKembalian();}
    }
    document.getElementById('paidInput').addEventListener('input',hitungKembalian);
    </script>
    ''', members_rows=members_rows, total=0, rupiah=rupiah)
    return render_page('Quick Cashier', body)

# =========================
# Quick Cashier Queue — Verifikasi Admin untuk Kurangi Stok
# =========================
@app.route('/quick-cashier/queue', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def quick_cashier_queue():
    if request.method == 'POST':
        qid = int(request.form.get('qid'))
        action = request.form.get('action')
        queue = q_one('SELECT * FROM quick_cashier_queue WHERE id = ? AND status = "PENDING"', [qid])
        if not queue:
            flash('Antrian tidak ditemukan atau sudah diproses.', 'error')
            return redirect(url_for('quick_cashier_queue'))
        
        if action == 'reject':
            # Jika bayar wallet, refund saldo
            if queue['payment_method'] == 'wallet' and queue['member_id']:
                member_saldo = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id=?', [queue['member_id']])['saldo']
                new_saldo = member_saldo + queue['total']
                exec_sql('INSERT INTO saldo_history(member_id, tipe, nominal, saldo_sebelum, saldo_setelah, keterangan, reference_id, created_by) VALUES (?, "MASUK", ?, ?, ?, "Refund quick cashier ditolak", ?, ?)',
                    [queue['member_id'], queue['total'], member_saldo, new_saldo, qid, session.get('user_id')])
                flash(f'💰 Saldo wallet dikembalikan Rp {queue["total"]}', 'success')
            
            exec_sql('UPDATE quick_cashier_queue SET status = "REJECTED", verified_by = ?, verified_at = ? WHERE id = ?',
                [session.get('user_id'), now_str(), qid])
            log_action('QUICK_CASHIER_REJECTED', 'quick_cashier_queue', qid, f'Ditolak: {queue["invoice_no"]}')
            flash(f'❌ Transaksi {queue["invoice_no"]} ditolak.', 'warning')
        
        return redirect(url_for('quick_cashier_queue'))
    
    # Tampilkan antrian
    pending = q_all('SELECT q.*, u.full_name as creator_name, m.member_code, m.name as member_name FROM quick_cashier_queue q LEFT JOIN users u ON u.id=q.created_by LEFT JOIN members m ON m.id=q.member_id WHERE q.status = "PENDING" ORDER BY q.id ASC')
    verified = q_all('SELECT q.*, u.full_name as creator_name, vu.full_name as verifier_name, m.name as member_name FROM quick_cashier_queue q LEFT JOIN users u ON u.id=q.created_by LEFT JOIN users vu ON vu.id=q.verified_by LEFT JOIN members m ON m.id=q.member_id WHERE q.status != "PENDING" ORDER BY q.id DESC LIMIT 50')
    
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><h2>⏳ Antrian Verifikasi Quick Cashier</h2><div class="muted small">Transaksi pending menunggu verifikasi admin untuk pengurangan stok</div></div>
    </div>
    <div class="grid">
        <div class="col-12">
            <div class="card" style="border-left:4px solid #f59e0b;">
                <h3>⏳ Menunggu Verifikasi ({{ pending|length }})</h3>
                <div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Tanggal</th><th>Total</th><th>Metode</th><th>Member</th><th>Kasir</th><th>Aksi</th></tr></thead>
                <tbody>
                {% for q in pending %}
                <tr>
                    <td><strong>{{ q.invoice_no }}</strong></td>
                    <td>{{ q.trx_date }}</td>
                    <td style="font-weight:700;color:#2563eb;">{{ rupiah(q.total) }}</td>
                    <td><span class="badge {{ 'badge-success' if q.payment_method == 'tunai' else 'badge-info' }}">{{ q.payment_method }}</span></td>
                    <td>{{ q.member_name or 'Umum' }}</td>
                    <td>{{ q.creator_name or '-' }}</td>
                    <td>
                        <div style="display:flex;gap:6px;flex-wrap:wrap;">
                            <a href="/quick-cashier/verify/{{ q.id }}" class="btn btn-sm btn-success">✅ Input Barang & Verifikasi</a>
                            <form method="POST" style="display:inline;">
                                <input type="hidden" name="qid" value="{{ q.id }}">
                                <button name="action" value="reject" class="btn-sm btn-danger" onclick="return confirm('Yakin tolak transaksi ini?')">❌ Tolak</button>
                            </form>
                        </div>
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="7" class="muted text-center">✅ Tidak ada antrian pending. Semua sudah diproses.</td></tr>
                {% endfor %}
                </tbody></table></div>
            </div>
        </div>
        <div class="col-12">
            <div class="card">
                <h3>📜 Riwayat Verifikasi</h3>
                <div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Total</th><th>Status</th><th>Verifikator</th><th>Terverifikasi</th></tr></thead>
                <tbody>
                {% for q in verified %}
                <tr>
                    <td>{{ q.invoice_no }}</td>
                    <td>{{ rupiah(q.total) }}</td>
                    <td><span class="badge {{ 'badge-success' if q.status == 'VERIFIED' else 'badge-danger' }}">{{ q.status }}</span></td>
                    <td>{{ q.verifier_name or '-' }}</td>
                    <td>{{ q.verified_at or '-' }}</td>
                </tr>
                {% else %}
                <tr><td colspan="5" class="muted text-center">Belum ada riwayat.</td></tr>
                {% endfor %}
                </tbody></table></div>
            </div>
        </div>
    </div>
    ''', pending=pending, verified=verified, rupiah=rupiah)
    return render_page('Verifikasi Quick Cashier', body)

# =========================
# Quick Cashier Verify — Input Barang & Validasi Total
# =========================
@app.route('/quick-cashier/verify/<int:qid>', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def quick_cashier_verify(qid):
    queue = q_one('SELECT * FROM quick_cashier_queue WHERE id = ? AND status = "PENDING"', [qid])
    if not queue:
        flash('Antrian tidak ditemukan atau sudah diproses.', 'error')
        return redirect(url_for('quick_cashier_queue'))
    
    products = q_all("SELECT id, barcode, product_name, sell_price, stock FROM products WHERE active=1 ORDER BY product_name ASC")
    items = q_all('SELECT qi.*, p.barcode, p.stock FROM quick_cashier_items qi LEFT JOIN products p ON p.id=qi.product_id WHERE qi.queue_id = ?', [qid])
    total_barang = sum(float(i['subtotal']) for i in items)
    selisih = round(total_barang - float(queue['total']), 2)
    
    if request.method == 'POST':
        action = request.form.get('action')
        
        if action == 'add_item':
            product_id = int(request.form.get('product_id'))
            qty = parse_float(request.form.get('qty', 1))
            prod = q_one('SELECT id, product_name, sell_price FROM products WHERE id=? AND active=1', [product_id])
            if not prod:
                flash('Barang tidak ditemukan.', 'error')
            elif qty <= 0:
                flash('Qty harus > 0.', 'error')
            else:
                subtotal = qty * float(prod['sell_price'])
                exec_sql('INSERT INTO quick_cashier_items(queue_id, product_id, product_name, qty, price, subtotal) VALUES (?, ?, ?, ?, ?, ?)',
                    [qid, product_id, prod['product_name'], qty, prod['sell_price'], subtotal])
                log_action('QUICK_CASHIER_ADD_ITEM', 'quick_cashier_items', product_id, f'Tambah {prod["product_name"]} x{qty}')
                flash(f'{prod["product_name"]} x{qty} ditambahkan.', 'success')
            return redirect(url_for('quick_cashier_verify', qid=qid))
        
        elif action == 'remove_item':
            item_id = int(request.form.get('item_id'))
            exec_sql('DELETE FROM quick_cashier_items WHERE id=? AND queue_id=?', [item_id, qid])
            flash('Item dihapus.', 'warning')
            return redirect(url_for('quick_cashier_verify', qid=qid))
        
        elif action == 'final_verify':
            items_final = q_all('SELECT * FROM quick_cashier_items WHERE queue_id = ?', [qid])
            if not items_final:
                flash('Belum ada barang yang diinput.', 'error')
                return redirect(url_for('quick_cashier_verify', qid=qid))
            
            total_items = sum(float(i['subtotal']) for i in items_final)
            diff = round(total_items - float(queue['total']), 2)
            
            invoice = queue['invoice_no']
            member_id = queue['member_id']
            customer_name = queue['customer_name'] or ''
            payment_method = queue['payment_method']
            note = queue['note'] or ''
            
            if diff != 0:
                note = f'[SELISIH Rp {diff:,.0f}] ' + note
            
            # Insert ke sales
            sid = exec_sql('INSERT INTO sales(invoice_no, trx_date, member_id, cashier_id, customer_name, total, paid, change_amount, note, status, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "Posted", ?)',
                [invoice, queue['trx_date'], member_id, queue['created_by'], customer_name, total_items, total_items, 0, note, payment_method])
            
            # Insert sales_items + kurangi stok
            for it in items_final:
                exec_sql('INSERT INTO sales_items(sales_id, product_id, barcode, product_name, qty, price, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)',
                    [sid, it['product_id'], '', it['product_name'], it['qty'], it['price'], it['subtotal']])
                exec_sql('UPDATE products SET stock = stock - ? WHERE id=?', [it['qty'], it['product_id']])
            
            # Tandai queue selesai
            exec_sql('UPDATE quick_cashier_queue SET status = "VERIFIED", verified_by = ?, verified_at = ? WHERE id = ?',
                [session.get('user_id'), now_str(), qid])
            
            # Journal
            kas_account = get_account_id('1001')
            penjualan_account = get_account_id('4001')
            if kas_account and penjualan_account:
                post_journal(queue['trx_date'], f'Quick Cashier {invoice}', [
                    {'account_id': kas_account, 'debit': total_items, 'credit': 0},
                    {'account_id': penjualan_account, 'debit': 0, 'credit': total_items}
                ], 'sales', sid, session.get('user_id'))
            
            msg = f'✅ Transaksi {invoice} diverifikasi. Stok berkurang.'
            if diff != 0:
                msg += f' ⚠️ Selisih Rp {abs(diff):,.0f} ({"kelebihan" if diff > 0 else "kekurangan"} barang)'
            flash(msg, 'success')
            log_action('QUICK_CASHIER_VERIFIED', 'quick_cashier_queue', qid, f'Verifikasi {invoice} total barang {total_items} selisih {diff}')
            return redirect(url_for('quick_cashier_queue'))
    
    abs_selisih = abs(selisih)
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><h2>📦 Input Barang — {{ queue.invoice_no }}</h2>
        <div class="muted small">Total bayar: <strong>{{ rupiah(queue.total) }}</strong> | Metode: {{ queue.payment_method }} | {{ queue.trx_date }}</div></div>
        <div style="background:#f0fdf4;padding:12px;border-radius:8px;margin:12px 0;display:flex;gap:16px;flex-wrap:wrap;">
            <div><span class="muted small">Total Barang</span><div style="font-size:20px;font-weight:700;color:#2563eb;">{{ rupiah(total_barang) }}</div></div>
            <div><span class="muted small">Total Bayar</span><div style="font-size:20px;font-weight:700;color:#059669;">{{ rupiah(queue.total) }}</div></div>
            <div><span class="muted small">Selisih</span>
                <div style="font-size:20px;font-weight:700;color:{{ '#ef4444' if selisih != 0 else '#10b981' }};">
                    {% if selisih > 0 %}➕ Kelebihan {{ rupiah(abs_selisih) }}{% elif selisih < 0 %}➖ Kekurangan {{ rupiah(abs_selisih) }}{% else %}✅ Sesuai{% endif %}
                </div>
            </div>
        </div>
    </div>
    <div class="grid">
        <div class="col-4">
            <div class="card">
                <h3>➕ Tambah Barang</h3>
                <form method="POST">
                    <input type="hidden" name="action" value="add_item">
                    <div class="form-group"><label>Pilih Barang</label>
                        <select name="product_id" required>
                            <option value="">— Pilih —</option>
                            {% for p in products %}
                            <option value="{{ p['id'] }}" data-price="{{ p['sell_price'] }}">{{ p['barcode'] }} — {{ p['product_name'] }} (Rp {{ '{:,.0f}'.format(p['sell_price'])|replace(',','.') }}) Stok: {{ p['stock'] }}</option>
                            {% endfor %}
                        </select>
                    </div>
                    <div class="form-group"><label>Qty</label><input type="number" name="qty" value="1" min="1"></div>
                    <button type="submit" class="btn-success">➕ Tambah</button>
                </form>
            </div>
        </div>
        <div class="col-8">
            <div class="card">
                <div class="kartu"><h3>📋 Daftar Barang</h3>
                    <form method="POST" style="display:inline;">
                        <input type="hidden" name="action" value="final_verify">
                        <button type="submit" class="btn-success" onclick="return confirm('Verifikasi final? Stok akan berkurang sesuai barang di atas.')">✅ Verifikasi & Kurangi Stok</button>
                    </form>
                </div>
                <div class="table-wrap"><table><thead><tr><th>Barang</th><th>Qty</th><th>Harga</th><th>Subtotal</th><th>Aksi</th></tr></thead>
                <tbody>
                {% for i in items %}
                <tr>
                    <td>{{ i['product_name'] }}</td>
                    <td>{{ i['qty'] }}</td>
                    <td>{{ rupiah(i['price']) }}</td>
                    <td>{{ rupiah(i['subtotal']) }}</td>
                    <td>
                        <form method="POST" style="display:inline;">
                            <input type="hidden" name="action" value="remove_item">
                            <input type="hidden" name="item_id" value="{{ i['id'] }}">
                            <button class="btn-sm btn-danger" onclick="return confirm('Hapus item?')">❌</button>
                        </form>
                    </td>
                </tr>
                {% else %}
                <tr><td colspan="5" class="muted text-center">Belum ada barang. Silahkan tambah barang di samping.</td></tr>
                {% endfor %}
                </tbody>
                <tfoot>
                <tr style="font-weight:700;background:#f9fafb;">
                    <td colspan="3">Total Barang</td>
                    <td>{{ rupiah(total_barang) }}</td>
                    <td></td>
                </tr>
                <tr style="font-weight:700;background:#f9fafb;color:{{ '#ef4444' if selisih != 0 else '#10b981' }};">
                    <td colspan="3">Selisih (Barang - Bayar)</td>
                    <td>{% if selisih > 0 %}➕ {{ rupiah(selisih) }}{% elif selisih < 0 %}➖ {{ rupiah(abs_selisih) }}{% else %}✅ 0{% endif %}</td>
                    <td></td>
                </tr>
                </tfoot>
                </table></div>
            </div>
        </div>
    </div>
    <a href="{{ url_for('quick_cashier_queue') }}" class="btn btn-ghost">← Kembali ke Antrian</a>
    ''', queue=queue, items=items, products=products, total_barang=total_barang, selisih=selisih, rupiah=rupiah)
    return render_page('Verifikasi Barang', body)

@app.route('/cashier', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def cashier():
    cart = get_cart()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_item':
            barcode = request.form.get('barcode', '').strip()
            qty = parse_float(request.form.get('qty', 1) or 1)
            prod = q_one('SELECT id, barcode, product_name, sell_price, stock FROM products WHERE barcode=? AND active=1', [barcode])
            if not barcode:
                flash('Barcode wajib diisi / discan.', 'warning')
            elif not prod:
                flash('Barang tidak ditemukan.', 'error')
            elif float(prod['stock']) < qty:
                flash('Stok tidak mencukupi.', 'error')
            else:
                found = False
                for item in cart:
                    if item['product_id'] == int(prod['id']):
                        item['qty'] += qty; item['subtotal'] = item['qty'] * item['price']
                        found = True; break
                if not found:
                    cart.append({'product_id': int(prod['id']), 'barcode': prod['barcode'], 'product_name': prod['product_name'], 'qty': qty, 'price': float(prod['sell_price']), 'subtotal': qty * float(prod['sell_price'])})
                save_cart(cart)
                flash(f"{prod['product_name']} masuk keranjang.", 'success')
            return redirect(url_for('cashier'))
        elif action == 'clear':
            save_cart([]); flash('Keranjang dikosongkan.', 'warning')
            return redirect(url_for('cashier'))
        elif action == 'save_sale':
            if not cart:
                flash('Keranjang kosong.', 'error')
                return redirect(url_for('cashier'))
            total = sum(float(i['subtotal']) for i in cart)
            member_id = request.form.get('member_id') or None
            customer_name = request.form.get('customer_name', '').strip()
            paid = parse_float(request.form.get('paid', 0) or 0)
            note = request.form.get('note', '').strip()
            payment_method = request.form.get('payment_method', 'tunai')
            invoice = gen_code('INV')
            change_amount = 0
            if payment_method == 'tunai':
                if paid < total:
                    flash('Nominal bayar kurang dari total.', 'error')
                    return redirect(url_for('cashier'))
                change_amount = paid - total
            elif payment_method == 'wallet':
                if not member_id:
                    flash('Bayar wallet wajib pilih member.', 'error')
                    return redirect(url_for('cashier'))
                member_saldo = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id=?', [member_id])['saldo']
                if member_saldo < total:
                    flash(f'Saldo wallet member tidak cukup. Saldo {rupiah(member_saldo)}', 'error')
                    return redirect(url_for('cashier'))
                saldo_sebelum = member_saldo
                saldo_setelah = saldo_sebelum - total
                exec_sql('INSERT INTO saldo_history(member_id, tipe, nominal, saldo_sebelum, saldo_setelah, keterangan, reference_id, created_by) VALUES (?, "KELUAR", ?, ?, ?, "Pembayaran via wallet kasir", ?, ?)', [member_id, total, saldo_sebelum, saldo_setelah, 0, session.get('user_id')])
                paid = total
            else:
                paid = total
            sid = exec_sql('INSERT INTO sales(invoice_no, trx_date, member_id, cashier_id, customer_name, total, paid, change_amount, note, status, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "Posted", ?)', [invoice, today_str(), member_id, session.get('user_id'), customer_name, total, paid, change_amount, note, payment_method])
            payload = []
            for item in cart:
                payload.append((sid, item['product_id'], item['barcode'], item['product_name'], item['qty'], item['price'], item['subtotal']))
                exec_sql('UPDATE products SET stock = stock - ? WHERE id=?', [item['qty'], item['product_id']])
            exec_sql('INSERT INTO sales_items(sales_id, product_id, barcode, product_name, qty, price, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)', payload, many=True)
            log_action('CREATE', 'sales', sid, f'Transaksi {invoice} total {total} metode {payment_method}')
            save_cart([])
            flash(f'Transaksi tersimpan. Invoice {invoice}. Kembalian {rupiah(change_amount)}', 'success')
            return redirect(url_for('cashier'))
    members_rows = q_all("SELECT id, member_code, name FROM members WHERE status='Aktif' ORDER BY name ASC")
    total = sum(float(i['subtotal']) for i in cart)
    body = render_template_string('''
    <div class="grid">
        <div class="col-4"><div class="card"><h2>🧾 Kasir</h2>
            <div class="muted small">Scan barcode untuk menambah item</div>
            <hr>
            <form method="post"><input type="hidden" name="action" value="add_item">
                <div class="form-group"><label>Barcode</label><input name="barcode" placeholder="Scan barcode..." autofocus></div>
                <div class="form-group"><label>Qty</label><input type="number" name="qty" value="1"></div>
                <button type="submit">➕ Tambah</button>
            </form>
            <hr>
            <h3>Total: <strong>{{ rupiah(total) }}</strong></h3>
            <form method="post" id="saleForm"><input type="hidden" name="action" value="save_sale">
                <div class="form-group"><label>Member</label><select name="member_id" id="member_id" onchange="toggleMemberInfo()"><option value="">Umum</option>{% for m in members_rows %}<option value="{{ m['id'] }}">{{ m['member_code'] }} — {{ m['name'] }}</option>{% endfor %}</select></div>
                <div class="form-group"><label>Nama Pelanggan</label><input name="customer_name" placeholder="(opsional)"></div>
                <div class="form-group"><label>Metode Bayar</label>
                    <select name="payment_method" id="payment_method" onchange="togglePaid()">
                        <option value="tunai">💰 Tunai</option>
                        <option value="wallet">💳 Wallet (Saldo Member)</option>
                    </select>
                </div>
                <div class="form-group" id="paid_row"><label>Bayar</label><input type="number" name="paid" id="paid_input" value="{{ total }}"></div>
                <div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:50px;"></textarea></div>
                <button type="submit" class="btn-success">💾 Simpan Transaksi</button>
            </form>
            <form method="post" style="margin-top:8px;"><input type="hidden" name="action" value="clear"><button class="btn-ghost btn-danger" type="submit">🗑️ Kosongkan</button></form>
        </div></div>
        <div class="col-8"><div class="card"><h2>Keranjang</h2>
            <div class="table-wrap"><table><thead><tr><th>Barang</th><th>Qty</th><th>Harga</th><th>Subtotal</th></tr></thead>
            <tbody>{% for i in cart %}<tr><td>{{ i['product_name'] }}</td><td>{{ i['qty'] }}</td><td>{{ rupiah(i['price']) }}</td><td>{{ rupiah(i['subtotal']) }}</td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Keranjang kosong.</td></tr>{% endfor %}</tbody></table></div>
        </div></div>
    </div>
    <script>
    function togglePaid(){
        var pm = document.getElementById('payment_method').value;
        var row = document.getElementById('paid_row');
        var inp = document.getElementById('paid_input');
        var total = {{ total }};
        if(pm==='wallet'){row.style.display='none';inp.value=total;}
        else{row.style.display='block';}
    }
    function toggleMemberInfo(){
        var mid = document.getElementById('member_id').value;
        var pm = document.getElementById('payment_method');
        if(!mid){pm.value='tunai';togglePaid();}
    }
    </script>
    ''', cart=cart, total=total, members_rows=members_rows, rupiah=rupiah)
    return render_page('Kasir', body)

# =========================
# Sales History
# =========================
@app.route('/sales-history', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def sales_history():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'request_void':
            sale_id = int(request.form.get('sale_id'))
            reason = request.form.get('reason', '').strip() or 'Void transaksi'
            sale = q_one('SELECT * FROM sales WHERE id=?', [sale_id])
            if not sale:
                flash('Transaksi tidak ditemukan.', 'error')
            elif sale['status'] != 'Posted':
                flash('Transaksi tidak bisa diajukan void.', 'error')
            else:
                exist = q_one('SELECT id FROM approval_requests WHERE request_type="sales_void" AND ref_table="sales" AND ref_id=? AND status="Pending"', [sale_id])
                if exist:
                    flash('Void transaksi ini sudah menunggu approval.', 'warning')
                else:
                    aid = exec_sql('INSERT INTO approval_requests(request_type, ref_table, ref_id, status, reason, created_by) VALUES (?, ?, ?, "Pending", ?, ?)', ['sales_void', 'sales', sale_id, reason, session.get('user_id')])
                    exec_sql('UPDATE sales SET status="VoidRequested" WHERE id=?', [sale_id])
                    log_action('REQUEST_APPROVAL', 'approval_requests', aid, f'Request void {sale["invoice_no"]}')
                    flash('Void transaksi diajukan ke admin.', 'warning')
            return redirect(url_for('sales_history'))
    start, end = date_range_from_request()
    page = request.args.get('page', 1, type=int)
    params = []
    base_sql = 'SELECT s.*, COALESCE(m.name, s.customer_name, "Umum") as pelanggan, u.full_name as kasir_name FROM sales s LEFT JOIN members m ON m.id=s.member_id LEFT JOIN users u ON u.id=s.cashier_id WHERE 1=1'
    base_sql, params = add_date_filter(base_sql, 's.trx_date', start, end, params)
    p = paginate_query(base_sql + ' ORDER BY s.id DESC', params, page)
    rows = p['rows']
    pag_html = render_pagination(p, 'sales_history', {'start': start, 'end': end})
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><h2>🛒 Riwayat Penjualan</h2>
        <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;width:auto;">
            <div><div class="small muted">Dari</div><input type="date" name="start" value="{{ start }}" style="width:140px;"></div>
            <div><div class="small muted">Sampai</div><input type="date" name="end" value="{{ end }}" style="width:140px;"></div>
            <button class="btn-ghost" type="submit">Filter</button>
        </form></div>
        <div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Tanggal</th><th>Pelanggan</th><th>Total</th><th>Status</th><th>Aksi</th></tr></thead>
        <tbody>{% for r in rows %}<tr><td>{{ r['invoice_no'] }}</td><td>{{ r['trx_date'] }}</td><td>{{ r['pelanggan'] }}</td><td>{{ rupiah(r['total']) }}</td><td><span class="badge {{ 'badge-success' if r['status']=='Posted' else 'badge-warn' if r['status']=='VoidRequested' else 'badge-danger' }}">{{ r['status'] }}</span></td>
        <td><a href="{{ url_for('receipt_pdf', sale_id=r['id']) }}" class="btn btn-sm btn-ghost">Struk</a>{% if r['status']=='Posted' %}<form method="post" style="display:inline;"><input type="hidden" name="action" value="request_void"><input type="hidden" name="sale_id" value="{{ r['id'] }}"><button class="btn-sm btn-danger" type="submit">Void</button></form>{% endif %}</td></tr>{% else %}<tr><td colspan="6" class="muted text-center">Belum ada transaksi.</td></tr>{% endfor %}</tbody></table></div>
        {{ pag_html|safe }}
    </div>
    ''', rows=rows, rupiah=rupiah, start=start, end=end, pag_html=pag_html)
    return render_page('Riwayat Sales', body)

@app.route('/receipt-pdf/<int:sale_id>')
@login_required
def receipt_pdf(sale_id):
    sale = q_one('SELECT s.*, COALESCE(m.name, s.customer_name, "Umum") as pelanggan, u.full_name as kasir_name FROM sales s LEFT JOIN members m ON m.id=s.member_id LEFT JOIN users u ON u.id=s.cashier_id WHERE s.id=?', [sale_id])
    if not sale:
        flash('Transaksi tidak ditemukan.', 'error')
        return redirect(url_for('sales_history'))
    items = q_all('SELECT * FROM sales_items WHERE sales_id=?', [sale_id])
    buf = BytesIO(); c = canvas.Canvas(buf, pagesize=A4); w,h = A4; y = h - 15*mm
    c.setFont('Helvetica-Bold', 14); c.drawString(15*mm, y, APP_TITLE); y -= 6*mm
    c.setFont('Helvetica', 10); c.drawString(15*mm, y, f'Invoice: {sale["invoice_no"]}'); y -= 5*mm
    c.drawString(15*mm, y, f'Tanggal: {sale["trx_date"]}'); y -= 5*mm
    c.drawString(15*mm, y, f'Pelanggan: {sale["pelanggan"]}'); y -= 5*mm
    c.drawString(15*mm, y, f'Kasir: {sale["kasir_name"] or "-"}'); y -= 8*mm
    c.setFont('Helvetica-Bold', 10); c.drawString(15*mm, y, 'Barang'); c.drawRightString(120*mm, y, 'Qty')
    c.drawRightString(155*mm, y, 'Harga'); c.drawRightString(195*mm, y, 'Subtotal'); y -= 3*mm
    c.line(15*mm, y, 195*mm, y); y -= 5*mm; c.setFont('Helvetica', 9)
    for it in items:
        c.drawString(15*mm, y, str(it['product_name'])[:38]); c.drawRightString(120*mm, y, f"{it['qty']}")
        c.drawRightString(155*mm, y, rupiah(it['price'])); c.drawRightString(195*mm, y, rupiah(it['subtotal']))
        y -= 5*mm
        if y < 20*mm: c.showPage(); y = h - 20*mm; c.setFont('Helvetica', 9)
    y -= 4*mm; c.line(15*mm, y, 195*mm, y); y -= 6*mm
    c.setFont('Helvetica-Bold', 10)
    c.drawRightString(195*mm, y, f'Total: {rupiah(sale["total"])}'); y -= 5*mm
    c.drawRightString(195*mm, y, f'Bayar: {rupiah(sale["paid"])}'); y -= 5*mm
    c.drawRightString(195*mm, y, f'Kembalian: {rupiah(sale["change_amount"])}')
    c.showPage(); c.save(); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f'struk_{sale["invoice_no"]}.pdf', mimetype='application/pdf')

# =========================
# Savings
# =========================
@app.route('/savings', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'bendahara')
def savings():
    if request.method == 'POST':
        member_id = int(request.form.get('member_id'))
        trx_date = request.form.get('trx_date', today_str())
        saving_type = request.form.get('saving_type', 'Sukarela')
        direction = request.form.get('direction', 'Masuk')
        amount = parse_float(request.form.get('amount', 0) or 0)
        note = request.form.get('note', '').strip()
        if amount <= 0:
            flash('Nominal harus lebih dari 0.', 'error')
        else:
            trx_no = gen_code('SMP')
            sid = exec_sql('INSERT INTO savings_transactions(trx_no, trx_date, member_id, saving_type, direction, amount, note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [trx_no, trx_date, member_id, saving_type, direction, amount, note, session.get('user_id')])
            log_action('CREATE', 'savings_transactions', sid, f'{saving_type} {direction} {amount}')
            flash('Transaksi simpanan berhasil disimpan.', 'success')
            return redirect(url_for('savings'))
    members_rows = q_all("SELECT id, member_code, name FROM members WHERE status='Aktif' ORDER BY name ASC")
    tx_rows = q_all('SELECT s.*, m.member_code, m.name FROM savings_transactions s LEFT JOIN members m ON m.id=s.member_id ORDER BY s.id DESC LIMIT 300')
    balance_rows = q_all('SELECT m.member_code, m.name, COALESCE(SUM(CASE WHEN st.direction="Masuk" THEN st.amount ELSE -st.amount END),0) as saldo FROM members m LEFT JOIN savings_transactions st ON st.member_id=m.id GROUP BY m.id, m.member_code, m.name ORDER BY m.name ASC')
    body = render_template_string('''
    <div class="grid">
        <div class="col-4"><div class="card"><h2>💰 Input Simpanan</h2>
            <form method="post">
                <div class="form-group"><label>Member</label><select name="member_id">{% for m in members_rows %}<option value="{{ m['id'] }}">{{ m['member_code'] }} — {{ m['name'] }}</option>{% endfor %}</select></div>
                <div class="form-group"><label>Tanggal</label><input type="date" name="trx_date" value="{{ today }}"></div>
                <div class="form-group"><label>Jenis</label><select name="saving_type"><option>Pokok</option><option>Wajib</option><option>Sukarela</option></select></div>
                <div class="form-group"><label>Arah</label><select name="direction"><option>Masuk</option><option>Keluar</option></select></div>
                <div class="form-group"><label>Nominal</label><input type="number" name="amount" placeholder="Nominal"></div>
                <div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:50px;"></textarea></div>
                <button type="submit">Simpan</button>
            </form>
        </div></div>
        <div class="col-8">
            <div class="card"><h2>Saldo per Member</h2>
            <div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama</th><th>Saldo</th></tr></thead>
            <tbody>{% for r in balance_rows %}<tr><td>{{ r['member_code'] }}</td><td>{{ r['name'] }}</td><td>{{ rupiah(r['saldo']) }}</td></tr>{% else %}<tr><td colspan="3" class="muted text-center">Tidak ada data.</td></tr>{% endfor %}</tbody></table></div></div>
            <div class="card"><h2>Riwayat</h2>
            <div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Member</th><th>Jenis</th><th>Nominal</th></tr></thead>
            <tbody>{% for r in tx_rows %}<tr><td>{{ r['trx_date'] }}</td><td>{{ r['member_code'] }} — {{ r['name'] }}</td><td>{{ r['saving_type'] }} {{ r['direction'] }}</td><td>{{ rupiah(r['amount']) }}</td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Belum ada transaksi.</td></tr>{% endfor %}</tbody></table></div></div>
        </div>
    </div>
    ''', members_rows=members_rows, tx_rows=tx_rows, balance_rows=balance_rows, today=today_str(), rupiah=rupiah)
    return render_page('Simpanan', body)

# =========================
# Loans
# =========================
@app.route('/loans', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'bendahara', 'user')
def loans():
    user = current_user()
    is_admin = user['role'] in ['admin', 'bendahara']
    my_member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'approve_loan':
            loan_id = int(request.form.get('loan_id'))
            loan = q_one('SELECT * FROM loans WHERE id = ? AND status = "CALCULATED"', [loan_id])
            if not loan:
                flash('Pinjaman tidak ditemukan atau belum dikalkulasi.', 'error')
                return redirect(url_for('loans'))
            exec_sql('UPDATE loans SET status = "Berjalan", approved_by = ?, approved_at = ? WHERE id = ?', [session.get('user_id'), now_str(), loan_id])
            add_timeline(loan_id, 'BERJALAN', 'Pinjaman disetujui dan mulai berjalan')
            log_action('LOAN_APPROVED', 'loans', loan_id, f'Pinjaman {loan["loan_no"]} disetujui → Berjalan')
            flash(f'Pinjaman {loan["loan_no"]} disetujui dan status Berjalan.', 'success')
            return redirect(url_for('loans'))
        if action == 'new_loan':
            if not is_admin:
                if not my_member:
                    flash('Akun member anda belum terdaftar.', 'error')
                    return redirect(url_for('loans'))
                member_id = my_member['id']
            else:
                member_id = int(request.form.get('member_id'))
            loan_date = request.form.get('loan_date', today_str())
            principal = parse_float(request.form.get('principal', 0) or 0)
            service_fee = parse_float(request.form.get('service_fee', 0) or 0)
            tenor_month = int(parse_float(request.form.get('tenor_month', 1) or 1))
            note = request.form.get('note', '').strip()
            if principal <= 0:
                flash('Nominal pinjaman harus lebih dari 0.', 'error')
                return redirect(url_for('loans'))
            if tenor_month < 1 or tenor_month > 36:
                flash('Tenor harus antara 1-36 bulan.', 'error')
                return redirect(url_for('loans'))
            exist_running = q_one('SELECT id FROM loans WHERE member_id = ? AND status IN ("Berjalan","SUBMITTED","CALCULATED")', [member_id])
            if exist_running:
                flash('Member masih memiliki pinjaman yang belum lunas.', 'error')
                return redirect(url_for('loans'))
            total_receivable = principal + service_fee
            monthly = total_receivable / tenor_month if tenor_month else total_receivable
            loan_no = gen_code('LOAN')
            lid = exec_sql('INSERT INTO loans(loan_no, member_id, loan_date, principal, service_fee, tenor_month, total_receivable, monthly_installment, status, note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, "SUBMITTED", ?, ?)', [
                loan_no, member_id, loan_date, principal, service_fee, tenor_month, total_receivable, monthly, note, session.get('user_id')
            ])
            add_timeline(lid, 'SUBMITTED', 'Pinjaman diajukan')
            log_action('LOAN_SUBMIT', 'loans', lid, f'Pinjaman {loan_no} Rp {principal}')
            flash('Pinjaman berhasil diajukan. Silahkan lakukan kalkulasi.', 'success')
            return redirect(url_for('loans'))
    
    if is_admin:
        members_rows = q_all("SELECT id, member_code, name FROM members WHERE status='Aktif' ORDER BY name ASC")
        loans_rows = q_all('SELECT l.*, m.member_code, m.name, COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id),0) as paid, l.total_receivable - COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id),0) as remaining FROM loans l LEFT JOIN members m ON m.id=l.member_id ORDER BY l.id DESC')
        running = [r for r in loans_rows if r['status'] == 'Berjalan']
    else:
        members_rows = []
        loans_rows = q_all('SELECT l.*, m.member_code, m.name, COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id),0) as paid, l.total_receivable - COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id),0) as remaining FROM loans l LEFT JOIN members m ON m.id=l.member_id WHERE l.member_id = ? ORDER BY l.id DESC', [my_member['id']]) if my_member else []
        running = []
    
    if is_admin:
        body = render_template_string('''
        <div class="grid">
            <div class="col-4"><div class="card"><h2>📋 Input Pinjaman</h2>
                <form method="post"><input type="hidden" name="action" value="new_loan">
                    <div class="form-group"><label>Member</label><select name="member_id">{% for m in members_rows %}<option value="{{ m['id'] }}">{{ m['member_code'] }} — {{ m['name'] }}</option>{% endfor %}</select></div>
                    <div class="form-group"><label>Tanggal</label><input type="date" name="loan_date" value="{{ today }}"></div>
                    <div class="form-group"><label>Pokok</label><input type="number" name="principal" placeholder="Jumlah pinjaman"></div>
                    <div class="form-group"><label>Jasa / Fee</label><input type="number" name="service_fee" placeholder="Biaya jasa"></div>
                    <div class="form-group"><label>Tenor (bulan)</label><input type="number" name="tenor_month" value="6"></div>
                    <div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:50px;"></textarea></div>
                    <button type="submit">Simpan</button>
                </form>
            </div></div>
            <div class="col-8"><div class="card"><h2>Semua Pinjaman</h2>
                <div class="table-wrap"><table><thead><tr><th>No</th><th>Member</th><th>Pokok</th><th>Tagihan</th><th>Terbayar</th><th>Sisa</th><th>Status</th><th>Aksi</th></tr></thead>
                <tbody>{% for r in loans_rows %}<tr><td>{{ r['loan_no'] }}</td><td>{{ r['member_code'] }} — {{ r['name'] }}</td><td>{{ rupiah(r['principal']) }}</td><td>{{ rupiah(r['total_receivable']) }}</td><td>{{ rupiah(r['paid']) }}</td><td>{{ rupiah(r['remaining']) }}</td><td><span class="badge {{ 'badge-success' if r['status'] == 'Berjalan' else 'badge-info' if r['status'] == 'Lunas' else 'badge-warn' }}">{{ r['status'] }}</span></td>
                <td><a href="{{ url_for('loan_detail', loan_id=r['id']) }}" class="btn btn-sm btn-ghost">Detail</a>{% if r['status'] == 'SUBMITTED' %}<a href="{{ url_for('calculate_loan', loan_id=r['id']) }}" class="btn btn-sm btn-warn">Hitung</a>{% endif %}{% if r['status'] == 'CALCULATED' %}<form method="POST" style="display:inline;"><input type="hidden" name="action" value="approve_loan"><input type="hidden" name="loan_id" value="{{ r['id'] }}"><button class="btn btn-sm btn-success" onclick="return confirm('Setujui pinjaman ini?')">Setujui</button></form>{% endif %}{% if r['status'] == 'Berjalan' %}<a href="{{ url_for('loan_contract_pdf', loan_id=r['id']) }}" class="btn btn-sm btn-ghost">Kontrak</a>{% endif %}</td></tr>{% else %}<tr><td colspan="8" class="muted text-center">Belum ada pinjaman.</td></tr>{% endfor %}</tbody></table></div>
            </div></div>
        </div>
        ''', members_rows=members_rows, loans_rows=loans_rows, running=running, today=today_str(), rupiah=rupiah)
    else:
        body = render_template_string('''
        <div class="grid">
            <div class="col-4"><div class="card"><h2>📝 Ajukan Pinjaman</h2>
                <div class="muted small">Pinjaman akan diproses oleh admin</div>
                {% if my_member %}<div class="badge badge-info" style="margin-bottom:12px;">{{ my_member.member_code }} — {{ my_member.name }}</div>
                <form method="post"><input type="hidden" name="action" value="new_loan">
                    <div class="form-group"><label>Jumlah</label><input type="number" name="principal" placeholder="Jumlah pinjaman"></div>
                    <div class="form-group"><label>Tenor (bulan)</label><input type="number" name="tenor_month" value="6"></div>
                    <div class="form-group"><label>Keperluan</label><textarea name="note" style="min-height:50px;"></textarea></div>
                    <button type="submit">📤 Kirim Pengajuan</button>
                </form>{% else %}<div class="flash flash-warning">Akun member belum terdaftar.</div>{% endif %}
            </div></div>
            <div class="col-8"><div class="card"><h2>Riwayat Pinjaman</h2>
                <div class="table-wrap"><table><thead><tr><th>No</th><th>Pokok</th><th>Tagihan</th><th>Angsuran/bln</th><th>Terbayar</th><th>Sisa</th><th>Status</th><th>Aksi</th></tr></thead>
                <tbody>{% for r in loans_rows %}<tr><td>{{ r['loan_no'] }}</td><td>{{ rupiah(r['principal']) }}</td><td>{{ rupiah(r['total_receivable']) }}</td><td>{{ rupiah(r['monthly_installment']) }}</td><td>{{ rupiah(r['paid']) }}</td><td>{{ rupiah(r['remaining']) }}</td><td><span class="badge {{ 'badge-success' if r['status'] == 'Berjalan' else 'badge-info' if r['status'] == 'Lunas' else 'badge-warn' }}">{{ r['status'] }}</span></td>
                <td>{% if r['status'] == 'Berjalan' %}<a href="{{ url_for('pay_loan_installment', loan_id=r['id']) }}" class="btn btn-sm btn-success">Bayar</a>{% endif %}</td></tr>{% else %}<tr><td colspan="8" class="muted text-center">Belum ada pinjaman.</td></tr>{% endfor %}</tbody></table></div>
            </div></div>
        </div>
        ''', my_member=my_member, loans_rows=loans_rows, today=today_str(), rupiah=rupiah)
    return render_page('Pinjaman', body)

# =========================
# Pegawai
# =========================
@app.route('/pegawai', methods=['GET'])
@login_required
def pegawai():
    rows = q_all('SELECT id, username, full_name, role, active, status, created_at FROM users ORDER BY id DESC')
    body = '<div class="card"><h2>👥 Daftar Pegawai</h2><div class="table-wrap"><table><thead><tr><th>Username</th><th>Nama</th><th>Role</th><th>Status</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{ r.username }}</td><td>{{ r.full_name }}</td><td><span class="badge badge-info">{{ r.role }}</span></td><td><span class="badge {% if r.active %}badge-success{% else %}badge-danger{% endif %}">{% if r.active %}Aktif{% else %}Nonaktif{% endif %}</span></td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Belum ada.</td></tr>{% endfor %}</tbody></table></div></div>'
    body = render_template_string(body, rows=rows)
    return render_page('Daftar Pegawai', body)

@app.route('/users', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def users():
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        if action == 'toggle_status':
            user_id = int(request.form.get('user_id'))
            current = q_one('SELECT active, full_name FROM users WHERE id = ?', [user_id])
            new_active = 0 if current['active'] else 1
            exec_sql('UPDATE users SET active = ?, status = ? WHERE id = ?', [new_active, 'ACTIVE' if new_active else 'NONACTIVE', user_id])
            log_action('UPDATE', 'users', user_id, f'Ubah status {current["full_name"]}')
            flash(f'Status user {current["full_name"]} diubah.', 'success')
            return redirect(url_for('users'))
        elif action == 'create':
            username = request.form.get('username', '').strip()
            full_name = request.form.get('full_name', '').strip()
            password = request.form.get('password', '').strip()
            role = request.form.get('role', 'kasir')
            if not username or not full_name or not password:
                flash('Username, nama, password wajib diisi.', 'error')
            else:
                try:
                    uid = exec_sql('INSERT INTO users(username, full_name, password_hash, role, active) VALUES (?, ?, ?, ?, 0)', [username, full_name, hash_password(password), role])
                    flash('User ditambahkan. Default NONAKTIF.', 'warning')
                    log_action('CREATE', 'users', uid, f'Buat user {username}')
                    flash('User berhasil ditambahkan.', 'success')
                    return redirect(url_for('users'))
                except sqlite3.IntegrityError:
                    flash('Username sudah ada.', 'error')
    rows = q_all('SELECT id, username, full_name, role, active, created_at FROM users ORDER BY id DESC')
    users_body = '<div class="grid"><div class="col-4"><div class="card"><h2>Tambah User</h2><form method="post"><div class="form-group"><label>Username</label><input name="username" placeholder="Username"></div><div class="form-group"><label>Nama</label><input name="full_name" placeholder="Nama"></div><div class="form-group"><label>Password</label><input type="password" name="password" placeholder="Password"></div><div class="form-group"><label>Role</label><select name="role"><option value="admin">admin</option><option value="kasir">kasir</option><option value="bendahara">bendahara</option><option value="supervisor">supervisor</option></select></div><button type="submit">Simpan</button></form></div></div><div class="col-8"><div class="card"><h2>Daftar User</h2><div class="table-wrap"><table><thead><tr><th>Username</th><th>Nama</th><th>Role</th><th>Status</th><th>Aksi</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{ r.username }}</td><td>{{ r.full_name }}</td><td><span class="badge badge-info">{{ r.role }}</span></td><td><span class="badge {% if r.active %}badge-success{% else %}badge-danger{% endif %}">{% if r.active %}Aktif{% else %}Nonaktif{% endif %}</span></td><td><form method="post" style="margin:0;display:inline;"><input type="hidden" name="action" value="toggle_status"><input type="hidden" name="user_id" value="{{ r.id }}"><button type="submit" class="btn-sm {% if r.active %}btn-danger{% else %}btn-success{% endif %}">{% if r.active %}Nonaktifkan{% else %}Aktifkan{% endif %}</button></form></td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada user.</td></tr>{% endfor %}</tbody></table></div></div></div></div>'
    body = render_template_string(users_body, rows=rows)
    return render_page('Kelola User', body)

# =========================
# Approvals, Accounting, Reports, Audit, Settings
# (These are kept compact since they were already working)
# =========================
@app.route('/approvals', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def approvals():
    if request.method == 'POST':
        approval_id = int(request.form.get('approval_id'))
        action = request.form.get('action')
        note = request.form.get('reason', '').strip()
        ap = q_one('SELECT * FROM approval_requests WHERE id=? AND status="Pending"', [approval_id])
        if not ap:
            flash('Approval request tidak ditemukan / sudah diproses.', 'error')
            return redirect(url_for('approvals'))
        if ap['request_type'] in ('loan_create',):
            loan = q_one('SELECT * FROM loans WHERE id=?', [ap['ref_id']])
            if not loan:
                flash('Data pinjaman tidak ditemukan.', 'error')
                return redirect(url_for('approvals'))
            if action == 'approve':
                new_status = 'Berjalan' if loan['status'] == 'CALCULATED' else 'Berjalan'
                exec_sql('UPDATE approval_requests SET status="Approved", approved_by=?, approved_at=? WHERE id=?', [session.get('user_id'), now_str(), approval_id])
                exec_sql('UPDATE loans SET status=?, approved_by=?, approved_at=? WHERE id=?', [new_status, session.get('user_id'), now_str(), loan['id']])
                add_timeline(loan['id'], new_status, 'Pinjaman disetujui oleh admin')
                log_action('APPROVE', 'approval_requests', approval_id, f'Approve loan {loan["loan_no"]}')
                flash('Pinjaman disetujui dan diposting.', 'success')
            else:
                exec_sql('UPDATE approval_requests SET status="Rejected", approved_by=?, approved_at=?, reason=? WHERE id=?', [session.get('user_id'), now_str(), note or ap['reason'], approval_id])
                exec_sql('UPDATE loans SET status="Ditolak" WHERE id=?', [loan['id']])
                add_timeline(loan['id'], 'DITOLAK', note or ap.get('reason', ''))
                log_action('REJECT', 'approval_requests', approval_id, f'Reject loan {loan["loan_no"]}')
                flash('Pinjaman ditolak.', 'warning')
        elif ap['request_type'] == 'sales_void':
            sale = q_one('SELECT * FROM sales WHERE id=?', [ap['ref_id']])
            if not sale:
                flash('Data sales tidak ditemukan.', 'error')
                return redirect(url_for('approvals'))
            if action == 'approve':
                items = q_all('SELECT * FROM sales_items WHERE sales_id=?', [sale['id']])
                for it in items:
                    exec_sql('UPDATE products SET stock = stock + ? WHERE id=?', [it['qty'], it['product_id']])
                exec_sql('UPDATE approval_requests SET status="Approved", approved_by=?, approved_at=? WHERE id=?', [session.get('user_id'), now_str(), approval_id])
                exec_sql('UPDATE sales SET status="Void" WHERE id=?', [sale['id']])
                log_action('APPROVE', 'approval_requests', approval_id, f'Approve void {sale["invoice_no"]}')
                flash('Void transaksi disetujui.', 'success')
            else:
                exec_sql('UPDATE approval_requests SET status="Rejected", approved_by=?, approved_at=?, reason=? WHERE id=?', [session.get('user_id'), now_str(), note or ap['reason'], approval_id])
                exec_sql('UPDATE sales SET status="Posted" WHERE id=?', [sale['id']])
                log_action('REJECT', 'approval_requests', approval_id, f'Reject void {sale["invoice_no"]}')
                flash('Void transaksi ditolak.', 'warning')
        return redirect(url_for('approvals'))
    rows = q_all("SELECT a.*, u.full_name as creator_name FROM approval_requests a LEFT JOIN users u ON u.id=a.created_by WHERE a.status='Pending' ORDER BY a.id DESC")
    hist = q_all("SELECT a.*, u.full_name as creator_name, ua.full_name as approver_name FROM approval_requests a LEFT JOIN users u ON u.id=a.created_by LEFT JOIN users ua ON ua.id=a.approved_by ORDER BY a.id DESC LIMIT 200")
    body = render_template_string("""<div class="card"><h2>👌 Approval Requests</h2><div class="table-wrap"><table><thead><tr><th>Jenis</th><th>Pemohon</th><th>Alasan</th><th>Aksi</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{ r.request_type }}</td><td>{{ r.creator_name or '-' }}</td><td>{{ r.reason }}</td><td><form method="post" style="display:flex;gap:8px;"><input type="hidden" name="approval_id" value="{{ r.id }}"><button name="action" value="approve" class="btn-sm btn-success">✅</button><button name="action" value="reject" class="btn-sm btn-danger">❌</button></form></td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Tidak ada pending.</td></tr>{% endfor %}</tbody></table></div><hr><h3>Riwayat</h3><div class="table-wrap"><table><thead><tr><th>Jenis</th><th>Status</th><th>Pemohon</th></tr></thead><tbody>{% for r in hist %}<tr><td>{{ r.request_type }}</td><td><span class="badge {% if r.status == 'Approved' %}badge-success{% else %}badge-danger{% endif %}">{{ r.status }}</span></td><td>{{ r.creator_name or '-' }}</td></tr>{% else %}<tr><td colspan="3" class="muted text-center">Belum ada.</td></tr>{% endfor %}</tbody></table></div></div>""", rows=rows, hist=hist)
    return render_page('Approval', body)

@app.route('/accounting', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'bendahara')
def accounting():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_account':
            code = request.form.get('account_code', '').strip()
            name = request.form.get('account_name', '').strip()
            category = request.form.get('category', 'Aset')
            normal = request.form.get('normal_balance', 'Debit')
            try:
                exec_sql('INSERT INTO accounts(account_code, account_name, category, normal_balance) VALUES (?, ?, ?, ?)', [code, name, category, normal])
                flash('Akun berhasil ditambahkan.', 'success')
                return redirect(url_for('accounting'))
            except sqlite3.IntegrityError:
                flash('Kode akun sudah ada.', 'error')
    coa = q_all('SELECT * FROM accounts ORDER BY account_code ASC')
    journal = q_all('SELECT j.entry_no, j.entry_date, j.description, a.account_code, a.account_name, j.debit, j.credit FROM journal_entries j LEFT JOIN accounts a ON a.id=j.account_id ORDER BY j.id DESC LIMIT 400')
    body = render_template_string('<div class="card"><h2>📒 Akuntansi</h2><div class="grid"><div class="col-4"><h3>Tambah Akun</h3><form method="post"><input type="hidden" name="action" value="add_account"><div class="form-group"><label>Kode</label><input name="account_code" placeholder="Kode"></div><div class="form-group"><label>Nama</label><input name="account_name" placeholder="Nama akun"></div><div class="form-group"><label>Kategori</label><select name="category"><option>Aset</option><option>Kewajiban</option><option>Modal</option><option>Pendapatan</option><option>Beban</option></select></div><div class="form-group"><label>Saldo Normal</label><select name="normal_balance"><option>Debit</option><option>Kredit</option></select></div><button type="submit">Simpan</button></form></div><div class="col-8"><h3>COA</h3><div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama</th><th>Kategori</th></tr></thead><tbody>{% for a in coa %}<tr><td>{{ a.account_code }}</td><td>{{ a.account_name }}</td><td>{{ a.category }}</td></tr>{% else %}<tr><td colspan="3" class="muted text-center">Belum ada.</td></tr>{% endfor %}</tbody></table></div><hr><h3>Jurnal</h3><div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Deskripsi</th><th>Akun</th><th>Debit</th><th>Kredit</th></tr></thead><tbody>{% for j in journal %}<tr><td>{{ j.entry_date }}</td><td>{{ j.description }}</td><td>{{ j.account_code }} — {{ j.account_name }}</td><td>{{ rupiah(j.debit) }}</td><td>{{ rupiah(j.credit) }}</td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada jurnal.</td></tr>{% endfor %}</tbody></table></div></div></div></div>', coa=coa, journal=journal, rupiah=rupiah)
    return render_page('Akuntansi', body)

@app.route('/reports')
@login_required
def reports():
    start, end = date_range_from_request()
    params = []
    sql = 'SELECT invoice_no, trx_date, total, paid, change_amount, note FROM sales WHERE status="Posted"'
    sql, params = add_date_filter(sql, 'trx_date', start, end, params)
    sql += ' ORDER BY id DESC LIMIT 300'
    sales_rows = q_all(sql, params)
    params = []
    sql = 'SELECT s.trx_no, s.trx_date, m.member_code, m.name, s.saving_type, s.direction, s.amount FROM savings_transactions s LEFT JOIN members m ON m.id=s.member_id WHERE 1=1'
    sql, params = add_date_filter(sql, 's.trx_date', start, end, params)
    sql += ' ORDER BY s.id DESC LIMIT 300'
    savings_rows = q_all(sql, params)
    loan_rows = q_all('SELECT l.loan_no, m.member_code, m.name, l.loan_date, l.total_receivable, COALESCE((SELECT SUM(amount) FROM loan_payments lp WHERE lp.loan_id=l.id),0) as paid, l.status FROM loans l LEFT JOIN members m ON m.id=l.member_id ORDER BY l.id DESC LIMIT 300')
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><h2>📊 Laporan</h2>
        <form method="get" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;width:auto;">
            <div><div class="small muted">Dari</div><input type="date" name="start" value="{{ start }}" style="width:140px;"></div>
            <div><div class="small muted">Sampai</div><input type="date" name="end" value="{{ end }}" style="width:140px;"></div>
            <button class="btn-ghost" type="submit">Filter</button>
            <a href="{{ url_for('export_report', start=start, end=end) }}" class="btn btn-sm">📥 Excel</a>
        </form></div>
        <h3>Penjualan</h3><div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Total</th></tr></thead><tbody>{% for r in sales_rows %}<tr><td>{{ r.invoice_no }}</td><td>{{ rupiah(r.total) }}</td></tr>{% else %}<tr><td colspan="2" class="muted text-center">Belum ada.</td></tr>{% endfor %}</tbody></table></div>
        <hr><h3>Pinjaman</h3><div class="table-wrap"><table><thead><tr><th>No</th><th>Member</th><th>Total</th><th>Terbayar</th><th>Status</th></tr></thead><tbody>{% for r in loan_rows %}<tr><td>{{ r.loan_no }}</td><td>{{ r.member_code }} — {{ r.name }}</td><td>{{ rupiah(r.total_receivable) }}</td><td>{{ rupiah(r.paid) }}</td><td><span class="badge badge-info">{{ r.status }}</span></td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada.</td></tr>{% endfor %}</tbody></table></div>
    </div>
    ''', sales_rows=sales_rows, savings_rows=savings_rows, loan_rows=loan_rows, rupiah=rupiah, start=start, end=end)
    return render_page('Laporan', body)

@app.route('/export-report')
@login_required
def export_report():
    start, end = date_range_from_request()
    params=[]; sql='SELECT invoice_no, trx_date, total, paid, change_amount, note FROM sales WHERE 1=1'
    sql, params = add_date_filter(sql, 'trx_date', start, end, params)
    sales=[dict(r) for r in q_all(sql, params)]
    members=[dict(r) for r in q_all('SELECT member_code, name, phone, address, join_date, status FROM members ORDER BY id DESC')]
    return to_excel({'member': members, 'penjualan': sales}, 'koperasi_enterprise_report.xlsx')

@app.route('/audit')
@login_required
@role_required('admin', 'supervisor')
def audit():
    page = request.args.get('page', 1, type=int)
    p = paginate_query('SELECT * FROM audit_logs ORDER BY id DESC', [], page)
    rows = p['rows']
    pag_html = render_pagination(p, 'audit')
    body = render_template_string('<div class="card"><h2>🔍 Audit Log</h2><div class="table-wrap"><table><thead><tr><th>Waktu</th><th>User</th><th>Aksi</th><th>Detail</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{ r.log_time }}</td><td>{{ r.username }}</td><td>{{ r.action }}</td><td>{{ r.detail }}</td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Belum ada log.</td></tr>{% endfor %}</tbody></table></div>{{ pag_html|safe }}</div>', rows=rows, pag_html=pag_html)
    return render_page('Audit Log', body)

@app.route('/settings', methods=['GET', 'POST'])
@login_required
def settings():
    user = current_user()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'change_password':
            old_pass = request.form.get('old_password', '')
            new_pass = request.form.get('new_password', '')
            if hash_password(old_pass) != user['password_hash']:
                flash('Password lama salah.', 'error')
            elif len(new_pass) < 4:
                flash('Password baru minimal 4 karakter.', 'error')
            else:
                exec_sql('UPDATE users SET password_hash=? WHERE id=?', [hash_password(new_pass), user['id']])
                log_action('UPDATE', 'users', user['id'], 'Ganti password')
                flash('Password berhasil diubah.', 'success')
                return redirect(url_for('settings'))
        elif action == 'restore_db' and user['role'] == 'admin':
            f = request.files.get('db_file')
            if not f or f.filename == '':
                flash('Pilih file database.', 'error')
            else:
                data = f.read()
                if data:
                    backup_path = Path(DB_NAME + '.pre_restore.bak')
                    current_path = Path(DB_NAME)
                    if current_path.exists():
                        backup_path.write_bytes(current_path.read_bytes())
                    current_path.write_bytes(data)
                    init_db()
                    flash('Database berhasil direstore.', 'success')
                else:
                    flash('File kosong.', 'error')
            return redirect(url_for('settings'))
    locks = q_all('SELECT p.*, u.full_name FROM period_locks p LEFT JOIN users u ON u.id=p.locked_by ORDER BY period_month DESC')
    body = render_template_string("""<div class="grid"><div class="col-6"><div class="card"><h2>🔑 Ubah Password</h2><form method="post"><input type="hidden" name="action" value="change_password"><div class="form-group"><label>Password Lama</label><input type="password" name="old_password" placeholder="Password lama"></div><div class="form-group"><label>Password Baru</label><input type="password" name="new_password" placeholder="Min 4 karakter"></div><button type="submit">Simpan</button></form></div></div><div class="col-6"><div class="card"><h2>💾 Backup Database</h2><a href="{{ url_for('download_db') }}" class="btn">📥 Download Backup</a><p class="muted small" style="margin-top:8px;">Database: <code>{{ db_name }}</code></p></div></div></div>""", db_name=DB_NAME, locks=locks)
    return render_page('Pengaturan', body)

@app.route('/download-db')
@login_required
def download_db():
    path = Path(DB_NAME)
    if not path.exists():
        flash('Database belum tersedia.', 'error')
        return redirect(url_for('settings'))
    return send_file(path, as_attachment=True, download_name='koperasi_enterprise_v3_backup.db')

# =========================
# Loan Types, Apply, Pay, Verify, Detail, Calculate, Contract PDF
# (Kept concise - essential loan management)
# =========================
@app.route('/admin/loan-types', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'bendahara')
def loan_types():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            name = request.form.get('name', '').strip()
            description = request.form.get('description', '').strip()
            interest_rate_monthly = parse_float(request.form.get('interest_rate_monthly', 1.5))
            admin_fee_fixed = parse_float(request.form.get('admin_fee_fixed', 0))
            admin_fee_percent = parse_float(request.form.get('admin_fee_percent', 0))
            min_tenor = int(request.form.get('min_tenor', 1))
            max_tenor = int(request.form.get('max_tenor', 36))
            max_amount = parse_float(request.form.get('max_amount', 25000000))
            metode_bunga = request.form.get('metode_bunga', 'FLAT')
            exec_sql('INSERT INTO loan_types(name, description, interest_rate_monthly, admin_fee_fixed, admin_fee_percent, min_tenor, max_tenor, max_amount, metode_bunga, is_active) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 1)', [name, description, interest_rate_monthly, admin_fee_fixed, admin_fee_percent, min_tenor, max_tenor, max_amount, metode_bunga])
            flash('Jenis pinjaman ditambahkan.', 'success')
        elif action == 'toggle':
            lid = int(request.form.get('lid'))
            current = q_one('SELECT is_active FROM loan_types WHERE id = ?', [lid])
            exec_sql('UPDATE loan_types SET is_active = ? WHERE id = ?', [0 if current['is_active'] else 1, lid])
            flash('Status diubah.', 'success')
        return redirect(url_for('loan_types'))
    types = q_all('SELECT * FROM loan_types ORDER BY id DESC')
    body = render_template_string("""<div class="card"><div class="grid"><div class="col-4"><h3>➕ Tambah</h3><form method="POST"><input type="hidden" name="action" value="create"><div class="form-group"><label>Nama</label><input name="name" required></div><div class="form-group"><label>Bunga/bulan (%)</label><input type="number" name="interest_rate_monthly" value="1.5"></div><div class="form-group"><label>Biaya Admin</label><div class="grid"><div class="col-6"><input type="number" name="admin_fee_fixed" value="0" placeholder="Fix"></div><div class="col-6"><input type="number" name="admin_fee_percent" value="0" placeholder="%"></div></div></div><div class="form-group"><label>Metode Bunga</label><select name="metode_bunga"><option value="FLAT">Flat</option><option value="ANUITAS">Anuitas</option></select></div><div class="form-group"><label>Tenor</label><div class="grid"><div class="col-6"><input type="number" name="min_tenor" value="1" placeholder="Min"></div><div class="col-6"><input type="number" name="max_tenor" value="36" placeholder="Maks"></div></div></div><div class="form-group"><label>Maksimal</label><input type="number" name="max_amount" value="25000000"></div><button type="submit">Simpan</button></form></div><div class="col-8"><h3>📋 Daftar</h3><div class="table-wrap"><table><thead><tr><th>Nama</th><th>Bunga</th><th>Metode</th><th>Tenor</th><th>Maks</th><th>Status</th><th>Aksi</th></tr></thead><tbody>{% for t in types %}<tr><td>{{ t.name }}</td><td>{{ t.interest_rate_monthly }}%</td><td>{{ t.metode_bunga or 'FLAT' }}</td><td>{{ t.min_tenor }}-{{ t.max_tenor }}</td><td>{{ rupiah(t.max_amount) }}</td><td><span class="badge {% if t.is_active %}badge-success{% else %}badge-gray{% endif %}">{% if t.is_active %}Aktif{% else %}Nonaktif{% endif %}</span></td><td><form method="POST" style="margin:0;"><input type="hidden" name="action" value="toggle"><input type="hidden" name="lid" value="{{ t.id }}"><button class="btn-sm btn-ghost">{% if t.is_active %}Nonaktifkan{% else %}Aktifkan{% endif %}</button></form></td></tr>{% else %}<tr><td colspan="7" class="muted text-center">Belum ada.</td></tr>{% endfor %}</tbody></table></div></div></div></div>""", types=types, rupiah=rupiah)
    return render_page('Jenis Pinjaman', body)

@app.route('/loans/apply', methods=['GET', 'POST'])
@login_required
def apply_loan():
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    if not member:
        flash('Akun member belum terdaftar.', 'error')
        return redirect(url_for('loans'))
    active_types = q_all('SELECT * FROM loan_types WHERE is_active = 1 ORDER BY name')
    if request.method == 'POST':
        loan_type_id = int(request.form.get('loan_type_id'))
        principal = parse_float(request.form.get('principal', 0))
        tenor_month = int(request.form.get('tenor_month', 6))
        note = request.form.get('note', '').strip()
        loan_type = q_one('SELECT * FROM loan_types WHERE id = ? AND is_active = 1', [loan_type_id])
        if not loan_type:
            flash('Jenis pinjaman tidak valid', 'error')
        elif principal < 100000:
            flash('Minimal Rp 100.000', 'error')
        elif principal > loan_type['max_amount']:
            flash(f'Maksimal {rupiah(loan_type["max_amount"])}', 'error')
        elif tenor_month < loan_type['min_tenor'] or tenor_month > loan_type['max_tenor']:
            flash(f'Tenor {loan_type["min_tenor"]}-{loan_type["max_tenor"]} bulan', 'error')
        else:
            exist_running = q_one('SELECT id FROM loans WHERE member_id = ? AND status IN ("Berjalan","SUBMITTED","CALCULATED")', [member['id']])
            if exist_running:
                flash('Anda masih memiliki pinjaman yang belum lunas.', 'error')
                return redirect(url_for('apply_loan'))
            admin_fee = loan_type['admin_fee_fixed'] + (principal * loan_type['admin_fee_percent'] / 100)
            total = principal + admin_fee
            monthly = total / tenor_month
            lid = exec_sql('INSERT INTO loans(loan_no, member_id, loan_type_id, loan_date, principal, service_fee, interest_rate, tenor_month, total_receivable, monthly_installment, status, note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, "SUBMITTED", ?, ?)', [
                gen_code('LOAN'), member['id'], loan_type_id, today_str(), principal, admin_fee, loan_type['interest_rate_monthly'], tenor_month, total, monthly, note, user['id']
            ])
            log_action('LOAN_SUBMIT', 'loans', lid, f'Pengajuan {principal}')
            flash('Pengajuan pinjaman berhasil dikirim.', 'success')
            return redirect(url_for('loans'))
    body = render_template_string('''
    <div class="card"><h2>📝 Ajukan Pinjaman</h2>
    <div class="grid">
        <div class="col-6"><form method="POST" id="loanForm">
            <div class="form-group"><label>Jenis Pinjaman</label><select name="loan_type_id" id="loan_type_id" required onchange="updateLimits()"><option value="">— Pilih —</option>{% for t in active_types %}<option value="{{ t.id }}" data-min="{{ t.min_tenor }}" data-max="{{ t.max_tenor }}" data-maxamount="{{ t.max_amount }}" data-bunga="{{ t.interest_rate_monthly }}" data-adminfix="{{ t.admin_fee_fixed }}" data-adminpct="{{ t.admin_fee_percent }}" data-metode="{{ t.metode_bunga }}">{{ t.name }} — {{ t.interest_rate_monthly }}%/bln ({{ t.metode_bunga }})</option>{% endfor %}</select></div>
            <div class="form-group"><label>Jumlah Pinjaman</label><input type="number" id="principal" name="principal" min="100000" step="100000" placeholder="Jumlah" oninput="calculate()"></div>
            <div class="form-group"><label>Tenor <span id="tenorLabel">6 bulan</span></label><input type="range" id="tenor_month" name="tenor_month" min="1" max="36" value="6" oninput="updateTenor();calculate()"></div>
            <div class="form-group"><label>Catatan</label><textarea name="note" placeholder="Keperluan pinjaman" style="min-height:60px;"></textarea></div>
            <button type="submit">📤 Kirim Pengajuan</button>
        </form></div>
        <div class="col-6"><div class="card" style="background:#f9fafb;border:1px solid #bfdbfe;margin:0;"><h3 style="color:#2563eb;">💡 Simulasi</h3>
            <div style="padding:12px 0;"><div class="grid"><div class="col-6 muted">Pokok</div><div class="col-6 text-right" id="sim_principal">Rp 0</div>
            <div class="col-6 muted">Biaya Admin</div><div class="col-6 text-right" id="sim_admin">Rp 0</div>
            <div class="col-6 muted" style="font-weight:600;">Angsuran /bln</div><div class="col-6 text-right" style="font-weight:700;color:#2563eb;font-size:20px;" id="sim_monthly">Rp 0</div></div></div>
            <div class="muted small">* Perhitungan final oleh admin</div>
        </div></div>
    </div></div>
    <script>
    function updateLimits(){var s=document.getElementById('loan_type_id'),o=s.options[s.selectedIndex];if(o.value){document.getElementById('tenor_month').min=o.dataset.min;document.getElementById('tenor_month').max=o.dataset.max;document.getElementById('principal').max=o.dataset.maxamount;updateTenor();calculate()}}
    function updateTenor(){document.getElementById('tenorLabel').textContent=document.getElementById('tenor_month').value+' bulan'}
    function calculate(){var s=document.getElementById('loan_type_id'),o=s.options[s.selectedIndex],p=parseFloat(document.getElementById('principal').value)||0,t=parseInt(document.getElementById('tenor_month').value)||1;if(o.value&&p>0){var af=parseFloat(o.dataset.adminfix)||0,ap=parseFloat(o.dataset.adminpct)||0,adm=af+(p*ap/100),tot=p+adm,mon=tot/t;document.getElementById('sim_principal').textContent='Rp '+p.toLocaleString('id-ID');document.getElementById('sim_admin').textContent='Rp '+adm.toLocaleString('id-ID');document.getElementById('sim_monthly').textContent='Rp '+mon.toLocaleString('id-ID')}}
    </script>
    ''', active_types=active_types, rupiah=rupiah)
    return render_page('Ajukan Pinjaman', body)

@app.route('/loans/pay/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def pay_loan_installment(loan_id):
    user = current_user()
    member = q_one('SELECT * FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
    loan = q_one('SELECT l.*, m.member_code, m.name FROM loans l LEFT JOIN members m ON m.id=l.member_id WHERE l.id = ? AND l.status = "Berjalan"', [loan_id])
    if not loan:
        flash('Pinjaman tidak ditemukan atau belum berjalan', 'error')
        return redirect(url_for('loans'))
    if not user['role'] in ['admin', 'bendahara']:
        if loan['member_id'] != member['id']:
            flash('Akses ditolak.', 'error')
            return redirect(url_for('loans'))
    if request.method == 'POST':
        payment_method = request.form.get('payment_method', 'tunai')
        amount = parse_float(request.form.get('amount', 0))
        note = request.form.get('note', '')
        if amount <= 0:
            flash('Nominal harus lebih dari 0', 'error')
        else:
            os.makedirs('uploads', exist_ok=True)
            transfer_proof = ''
            status = 'VERIFIED' if payment_method == 'tunai' else 'PENDING_VERIFICATION'
            pid = exec_sql('INSERT INTO loan_payments(loan_id, payment_date, amount, payment_method, transfer_proof, status, note, created_by) VALUES (?, ?, ?, ?, ?, ?, ?, ?)', [loan_id, today_str(), amount, payment_method, transfer_proof, status, note, user['id']])
            if status == 'VERIFIED':
                exec_sql('UPDATE loan_payments SET verified_by = ?, verified_at = ? WHERE id = ?', [user['id'], now_str(), pid])
                exec_sql('UPDATE loan_schedules SET status = "LUNAS", paid_date = ?, paid_amount = ?, payment_id = ? WHERE loan_id = ? AND status = "BELUM_BAYAR" ORDER BY installment_number ASC LIMIT 1', [today_str(), amount, pid, loan_id])
                exec_sql('UPDATE loans SET total_paid = COALESCE(total_paid, 0) + ? WHERE id = ?', [amount, loan_id])
                unpaid = q_one('SELECT COUNT(*) as n FROM loan_schedules WHERE loan_id = ? AND status != "LUNAS"', [loan_id])
                if unpaid and unpaid['n'] == 0:
                    exec_sql("UPDATE loans SET status='Lunas' WHERE id=?", [loan_id])
                    add_timeline(loan_id, 'LUNAS', 'Pinjaman lunas')
                flash('Pembayaran berhasil dicatat.', 'success')
            else:
                flash('Bukti transfer berhasil dikirim. Menunggu verifikasi admin.', 'success')
            return redirect(url_for('loans'))
    schedules = q_all('SELECT * FROM loan_schedules WHERE loan_id = ? ORDER BY installment_number', [loan_id])
    body = render_template_string('''
    <div class="card">
        <div class="kartu"><div><h2>💸 Bayar Angsuran #{{ loan.loan_no }}</h2><div class="muted small">{{ loan.member_code }} — {{ loan.name }}</div></div></div>
        <div class="grid">
            <div class="col-6"><form method="POST" enctype="multipart/form-data">
                <h3>Metode Bayar</h3>
                <div style="display:flex;gap:12px;margin-bottom:12px;flex-wrap:wrap;">
                    <label><input type="radio" name="payment_method" value="tunai" checked> 💰 Tunai</label>
                    <label><input type="radio" name="payment_method" value="transfer"> 🏦 Transfer</label>
                </div>
                <div class="form-group"><label>Nominal</label><input type="number" name="amount" value="{{ loan.monthly_installment }}"></div>
                <div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:50px;"></textarea></div>
                <button type="submit">📤 Bayar</button>
            </form></div>
            <div class="col-6"><div class="metric"><div class="label">Angsuran/Bulan</div><div class="value" style="color:#2563eb;">{{ rupiah(loan.monthly_installment) }}</div></div></div>
        </div>
        <hr><h3>📅 Jadwal</h3>
        <div class="table-wrap"><table><thead><tr><th>Ke</th><th>Jatuh Tempo</th><th>Total</th><th>Status</th></tr></thead><tbody>{% for s in schedules %}<tr><td>{{ s.installment_number }}</td><td>{{ s.due_date }}</td><td>{{ rupiah(s.amount) }}</td><td><span class="badge {{ 'badge-success' if s.status == 'LUNAS' else 'badge-warn' }}">{{ '✅ LUNAS' if s.status == 'LUNAS' else '⏳' }}</span></td></tr>{% endfor %}</tbody></table></div>
    </div>
    ''', loan=loan, schedules=schedules, rupiah=rupiah)
    return render_page('Bayar Angsuran', body)

@app.route('/loans/verify-payments', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'bendahara')
def verify_loan_payments():
    if request.method == 'POST':
        pid = int(request.form.get('payment_id'))
        action = request.form.get('action')
        payment = q_one('SELECT * FROM loan_payments WHERE id = ? AND status = "PENDING_VERIFICATION"', [pid])
        if not payment:
            flash('Pembayaran tidak ditemukan.', 'error')
            return redirect(url_for('verify_loan_payments'))
        if action == 'approve':
            exec_sql('UPDATE loan_payments SET status = "VERIFIED", verified_by = ?, verified_at = ? WHERE id = ?', [session['user_id'], now_str(), pid])
            next_schedule = q_one('SELECT id FROM loan_schedules WHERE loan_id = ? AND status = "BELUM_BAYAR" ORDER BY installment_number ASC LIMIT 1', [payment['loan_id']])
            if next_schedule:
                exec_sql('UPDATE loan_schedules SET status = "LUNAS", paid_date = ?, paid_amount = ?, payment_id = ? WHERE id = ?', [today_str(), payment['amount'], pid, next_schedule['id']])
            unpaid = q_one('SELECT COUNT(*) as n FROM loan_schedules WHERE loan_id = ? AND status != "LUNAS"', [payment['loan_id']])
            if unpaid and unpaid['n'] == 0:
                exec_sql("UPDATE loans SET status='Lunas' WHERE id=?", [payment['loan_id']])
            flash('Pembayaran diverifikasi.', 'success')
        elif action == 'reject':
            exec_sql('UPDATE loan_payments SET status = "REJECTED", verified_by = ?, verified_at = ? WHERE id = ?', [session['user_id'], now_str(), pid])
            flash('Pembayaran ditolak.', 'warning')
        return redirect(url_for('verify_loan_payments'))
    pending = q_all('SELECT lp.*, l.loan_no, m.member_code, m.name FROM loan_payments lp LEFT JOIN loans l ON l.id = lp.loan_id LEFT JOIN members m ON m.id = l.member_id WHERE lp.status = "PENDING_VERIFICATION" ORDER BY lp.id DESC')
    body = render_template_string('<div class="card"><h2>✅ Verifikasi Pembayaran</h2><div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Member</th><th>Nominal</th><th>Aksi</th></tr></thead><tbody>{% for p in pending %}<tr><td>{{ p.payment_date }}</td><td>{{ p.member_code }} — {{ p.name }}</td><td>{{ rupiah(p.amount) }}</td><td><form method="POST" style="display:flex;gap:8px;"><input type="hidden" name="payment_id" value="{{ p.id }}"><button name="action" value="approve" class="btn-sm btn-success">✅</button><button name="action" value="reject" class="btn-sm btn-danger">❌</button></form></td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Tidak ada.</td></tr>{% endfor %}</tbody></table></div></div>', pending=pending, rupiah=rupiah)
    return render_page('Verifikasi Pembayaran', body)

@app.route('/loans/detail/<int:loan_id>', methods=['GET', 'POST'])
@login_required
def loan_detail(loan_id):
    user = current_user()
    is_admin = user['role'] in ['admin', 'bendahara']
    loan = q_one('SELECT l.*, m.member_code, m.name, lt.name as loan_type_name FROM loans l LEFT JOIN members m ON m.id=l.member_id LEFT JOIN loan_types lt ON lt.id=l.loan_type_id WHERE l.id = ?', [loan_id])
    if not loan:
        flash('Pinjaman tidak ditemukan', 'error')
        return redirect(url_for('loans'))
    if not is_admin:
        member = q_one('SELECT id FROM members WHERE member_code = ?', [f'EMP-{user["employee_number"]}'])
        if not member or loan['member_id'] != member['id']:
            flash('Akses ditolak.', 'error')
            return redirect(url_for('loans'))
    documents = q_all('SELECT * FROM loan_documents WHERE loan_id = ? ORDER BY id ASC', [loan_id])
    timeline = q_all('SELECT t.*, u.full_name FROM loan_timeline t LEFT JOIN users u ON u.id = t.created_by WHERE loan_id = ? ORDER BY id ASC', [loan_id])
    body = render_template_string('<div class="card"><div class="kartu"><div><h2>#{{ loan.loan_no }}</h2><div class="muted small">{{ loan.member_code }} — {{ loan.name }}</div></div><div class="badge badge-info">{{ loan.status }}</div></div><div class="grid"><div class="col-6"><h3>📋 Informasi</h3><table><tr><td>Pokok</td><td>{{ rupiah(loan.principal) }}</td></tr><tr><td>Fee</td><td>{{ rupiah(loan.service_fee) }}</td></tr><tr><td>Total Tagihan</td><td>{{ rupiah(loan.total_receivable) }}</td></tr><tr><td>Angsuran/bln</td><td>{{ rupiah(loan.monthly_installment) }}</td></tr><tr><td>Tenor</td><td>{{ loan.tenor_month }} bulan</td></tr><tr><td>Bunga</td><td>{{ loan.interest_rate }}%/bln</td></tr></table></div><div class="col-6"><h3>⏱️ Timeline</h3><div class="timeline">{% for t in timeline %}<div class="timeline-item"><div class="timeline-dot"></div><div><strong>{{ t.status }}</strong><div class="muted small">{{ t.full_name }} • {{ t.created_at }}</div>{% if t.note %}<div class="small">{{ t.note }}</div>{% endif %}</div></div>{% else %}<div class="muted">Belum ada timeline.</div>{% endfor %}</div></div></div></div>', loan=loan, documents=documents, timeline=timeline, rupiah=rupiah)
    return render_page(f'Detail #{loan["loan_no"]}', body)

@app.route('/loans/calculate/<int:loan_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'bendahara')
def calculate_loan(loan_id):
    loan = q_one('SELECT l.*, m.name, m.member_code, lt.name as loan_type_name, lt.metode_bunga FROM loans l LEFT JOIN members m ON m.id=l.member_id LEFT JOIN loan_types lt ON lt.id=l.loan_type_id WHERE l.id = ?', [loan_id])
    if not loan:
        flash('Pengajuan pinjaman tidak ditemukan', 'error')
        return redirect(url_for('loans'))
    if request.method == 'POST':
        principal = parse_float(request.form.get('principal', loan['principal']))
        service_fee = parse_float(request.form.get('service_fee', loan['service_fee']))
        interest_rate = parse_float(request.form.get('interest_rate', loan['interest_rate']))
        tenor_month = int(request.form.get('tenor_month', loan['tenor_month']))
        admin_note = request.form.get('admin_note', '').strip()
        total_receivable = principal + service_fee
        monthly_installment = total_receivable / tenor_month
        exec_sql('UPDATE loans SET principal = ?, service_fee = ?, interest_rate = ?, tenor_month = ?, total_receivable = ?, monthly_installment = ?, admin_note = ?, status = "CALCULATED", calculated_by = ?, calculated_at = ? WHERE id = ?', [
            principal, service_fee, interest_rate, tenor_month, total_receivable, monthly_installment, admin_note, session['user_id'], now_str(), loan_id
        ])
        exec_sql('DELETE FROM loan_schedules WHERE loan_id = ?', [loan_id])
        schedules = []
        loan_date_parsed = datetime.strptime(loan['loan_date'], '%Y-%m-%d') if loan['loan_date'] else datetime.now()
        for i in range(1, tenor_month + 1):
            due_month = loan_date_parsed.month + i
            due_year = loan_date_parsed.year + (due_month - 1) // 12
            due_month = ((due_month - 1) % 12) + 1
            due_date = f"{due_year}-{due_month:02d}-25"
            schedules.append((loan_id, i, due_date, monthly_installment, principal/tenor_month, monthly_installment - principal/tenor_month))
        exec_sql('INSERT INTO loan_schedules(loan_id, installment_number, due_date, amount, principal_amount, interest_amount) VALUES (?, ?, ?, ?, ?, ?)', schedules, many=True)
        flash('Kalkulasi berhasil. Jadwal angsuran dibuat.', 'success')
        return redirect(url_for('loans'))
    schedules = q_all('SELECT * FROM loan_schedules WHERE loan_id = ? ORDER BY installment_number', [loan_id])
    body = render_template_string('<div class="card"><h2>🔢 Kalkulasi #{{ loan.loan_no }}</h2><div class="badge badge-info">{{ loan.member_code }} — {{ loan.name }}</div><hr><div class="grid"><div class="col-6"><form method="POST"><div class="form-group"><label>Pokok</label><input type="number" name="principal" value="{{ loan.principal }}"></div><div class="form-group"><label>Fee</label><input type="number" name="service_fee" value="{{ loan.service_fee }}"></div><div class="form-group"><label>Bunga %</label><input type="number" name="interest_rate" value="{{ loan.interest_rate }}"></div><div class="form-group"><label>Tenor</label><input type="number" name="tenor_month" value="{{ loan.tenor_month }}"></div><div class="form-group"><label>Catatan</label><textarea name="admin_note">{{ loan.admin_note }}</textarea></div><button type="submit">✅ Hitung</button></form></div><div class="col-6"><div class="metric"><div class="label">Angsuran/Bulan</div><div class="value" style="color:#2563eb;">{{ rupiah(loan.monthly_installment) }}</div></div></div></div>{% if schedules %}<hr><h3>📅 Jadwal</h3><div class="table-wrap"><table><thead><tr><th>Ke</th><th>Jatuh Tempo</th><th>Pokok</th><th>Bunga</th><th>Total</th></tr></thead><tbody>{% for s in schedules %}<tr><td>{{ s.installment_number }}</td><td>{{ s.due_date }}</td><td>{{ rupiah(s.principal_amount) }}</td><td>{{ rupiah(s.interest_amount) }}</td><td>{{ rupiah(s.amount) }}</td></tr>{% endfor %}</tbody></table></div>{% endif %}</div>', loan=loan, schedules=schedules, rupiah=rupiah)
    return render_page('Kalkulasi Pinjaman', body)

@app.route('/loans/contract-pdf/<int:loan_id>')
@login_required
def loan_contract_pdf(loan_id):
    loan = q_one('SELECT l.*, m.member_code, m.name FROM loans l LEFT JOIN members m ON m.id=l.member_id WHERE l.id = ?', [loan_id])
    if not loan:
        flash('Pinjaman tidak ditemukan', 'error')
        return redirect(url_for('loans'))
    buf = BytesIO(); c = canvas.Canvas(buf, pagesize=A4); w,h = A4; y = h - 15*mm
    c.setFont('Helvetica-Bold', 16); c.drawString(15*mm, y, APP_TITLE); y -= 8*mm
    c.setFont('Helvetica-Bold', 14); c.drawString(15*mm, y, 'KONTRAK PINJAMAN'); y -= 10*mm
    c.setFont('Helvetica', 10)
    for l in [f'No: {loan["loan_no"]}', f'Tanggal: {loan["loan_date"]}', '', 'Peminjam:', f'{loan["name"]} ({loan["member_code"]})', '', 'Pinjaman:', f'Pokok: {rupiah(loan["principal"])}', f'Fee: {rupiah(loan["service_fee"])}', f'Total: {rupiah(loan["total_receivable"])}', f'Tenor: {loan["tenor_month"]} bulan', f'Angsuran: {rupiah(loan["monthly_installment"])}/bulan']:
        c.drawString(15*mm, y, l); y -= 5*mm
    y -= 10*mm; c.drawString(15*mm, y, 'Dengan ini peminjam setuju membayar angsuran tepat waktu.'); c.showPage(); c.save()
    buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f'kontrak_{loan["loan_no"]}.pdf', mimetype='application/pdf')

# =========================
# Stock Movements
# =========================
@app.route('/stock-movements', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def stock_movements():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_movement':
            product_id = int(request.form.get('product_id') or 0)
            movement_type = request.form.get('movement_type', 'Masuk')
            qty = parse_float(request.form.get('qty', 0) or 0)
            unit_cost = parse_float(request.form.get('unit_cost', 0) or 0)
            note = request.form.get('note', '').strip()
            if product_id <= 0 or qty <= 0:
                flash('Pilih barang dan qty > 0.', 'error')
                return redirect(url_for('stock_movements'))
            product = q_one('SELECT * FROM products WHERE id=?', [product_id])
            if not product:
                flash('Barang tidak ditemukan.', 'error')
                return redirect(url_for('stock_movements'))
            new_stock = float(product['stock']) + (qty if movement_type == 'Masuk' else -qty)
            if movement_type != 'Masuk' and new_stock < 0:
                flash('Stok tidak cukup.', 'error')
                return redirect(url_for('stock_movements'))
            mid = exec_sql('INSERT INTO stock_movements(product_id, movement_type, qty, unit_cost, note, created_by) VALUES (?, ?, ?, ?, ?, ?)', [product_id, movement_type, qty, unit_cost, note, session.get('user_id')])
            exec_sql('UPDATE products SET stock=? WHERE id=?', [new_stock, product_id])
            log_action('CREATE', 'stock_movements', mid, f'{movement_type} {qty} {product["product_name"]}')
            flash('Mutasi stok berhasil.', 'success')
            return redirect(url_for('stock_movements'))
    products_rows = q_all("SELECT id, barcode, product_name, stock FROM products WHERE active=1 ORDER BY product_name ASC")
    rows = q_all('SELECT sm.*, p.barcode, p.product_name FROM stock_movements sm LEFT JOIN products p ON p.id=sm.product_id ORDER BY sm.id DESC LIMIT 300')
    body = render_template_string('''<div class="grid"><div class="col-4"><div class="card"><h2>📥 Mutasi Stok</h2><form method="post"><input type="hidden" name="action" value="add_movement"><div class="form-group"><label>Barang</label><select name="product_id" required><option value="">— Pilih —</option>{% for p in products_rows %}<option value="{{ p['id'] }}">{{ p['barcode'] }} — {{ p['product_name'] }} (Stok: {{ p['stock'] }})</option>{% endfor %}</select></div><div class="form-group"><label>Jenis</label><select name="movement_type"><option value="Masuk">📥 Masuk</option><option value="Keluar">📤 Keluar</option><option value="Opname">📝 Opname</option></select></div><div class="form-group"><label>Qty</label><input type="number" name="qty" step="0.01" min="0.01"></div><div class="form-group"><label>Harga Satuan</label><input type="number" name="unit_cost"></div><div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:50px;"></textarea></div><button type="submit">Simpan</button></form></div></div><div class="col-8"><div class="card"><h2>Riwayat Mutasi</h2><div class="table-wrap"><table><thead><tr><th>Tgl</th><th>Barang</th><th>Jenis</th><th>Qty</th><th>Harga</th><th>Catatan</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{ r['created_at'][:16] }}</td><td>{{ r['barcode'] }} — {{ r['product_name'] }}</td><td><span class="badge {{ 'badge-success' if r['movement_type']=='Masuk' else 'badge-warn' if r['movement_type']=='Opname' else 'badge-danger' }}">{{ r['movement_type'] }}</span></td><td>{{ r['qty'] }}</td><td>{% if r['unit_cost'] %}{{ rupiah(r['unit_cost']) }}{% else %}-{% endif %}</td><td>{{ r['note'] or '-' }}</td></tr>{% else %}<tr><td colspan="6" class="muted text-center">Belum ada mutasi.</td></tr>{% endfor %}</tbody></table></div></div></div></div>''', products_rows=products_rows, rows=rows, rupiah=rupiah)
    return render_page('Mutasi Stok', body)

# =========================
# Suppliers
# =========================
@app.route('/suppliers', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def suppliers():
    edit_id = request.args.get('edit_id', '')
    edit_row = q_one('SELECT * FROM suppliers WHERE id=?', [edit_id]) if edit_id else None
    if request.method == 'POST':
        action = request.form.get('action', 'create')
        code = request.form.get('supplier_code', '').strip() or gen_code('SUP')
        name = request.form.get('name', '').strip()
        phone = request.form.get('phone', '').strip()
        address = request.form.get('address', '').strip()
        contact_person = request.form.get('contact_person', '').strip()
        if action == 'create':
            if not name:
                flash('Nama supplier wajib diisi.', 'error')
            else:
                try:
                    sid = exec_sql('INSERT INTO suppliers(supplier_code, name, phone, address, contact_person) VALUES (?, ?, ?, ?, ?)', [code, name, phone, address, contact_person])
                    log_action('CREATE', 'suppliers', sid, f'Tambah supplier {name}')
                    flash('Supplier berhasil disimpan.', 'success')
                    return redirect(url_for('suppliers'))
                except sqlite3.IntegrityError:
                    flash('Kode supplier sudah ada.', 'error')
        elif action == 'update':
            sid = int(request.form.get('supplier_id'))
            exec_sql('UPDATE suppliers SET supplier_code=?, name=?, phone=?, address=?, contact_person=? WHERE id=?', [code, name, phone, address, contact_person, sid])
            log_action('UPDATE', 'suppliers', sid, f'Update supplier {name}')
            flash('Supplier berhasil diupdate.', 'success')
            return redirect(url_for('suppliers'))
    key = request.args.get('q', '').strip()
    if key:
        rows = q_all('SELECT * FROM suppliers WHERE name LIKE ? OR phone LIKE ? ORDER BY id DESC', [f'%{key}%', f'%{key}%'])
    else:
        rows = q_all('SELECT * FROM suppliers ORDER BY id DESC')
    body = render_template_string('''
    <div class="grid">
        <div class="col-4"><div class="card">
            <h2>{{ 'Edit' if edit_row else 'Tambah Supplier' }}</h2>
            <form method="post">
                {% if edit_row %}<input type="hidden" name="action" value="update"><input type="hidden" name="supplier_id" value="{{ edit_row['id'] }}">{% else %}<input type="hidden" name="action" value="create">{% endif %}
                <div class="form-group"><label>Kode Supplier</label><input name="supplier_code" value="{{ edit_row['supplier_code'] if edit_row else default_code }}"></div>
                <div class="form-group"><label>Nama Supplier</label><input name="name" value="{{ edit_row['name'] if edit_row else '' }}" required></div>
                <div class="form-group"><label>No. HP</label><input name="phone" value="{{ edit_row['phone'] if edit_row else '' }}"></div>
                <div class="form-group"><label>Kontak Person</label><input name="contact_person" value="{{ edit_row['contact_person'] if edit_row else '' }}"></div>
                <div class="form-group"><label>Alamat</label><textarea name="address">{{ edit_row['address'] if edit_row else '' }}</textarea></div>
                <button type="submit">{{ 'Update' if edit_row else 'Simpan' }}</button>
                {% if edit_row %}<a href="{{ url_for('suppliers') }}" class="btn btn-ghost" style="margin-top:8px;">Batal</a>{% endif %}
            </form>
        </div></div>
        <div class="col-8"><div class="card">
            <div class="kartu"><h2>Daftar Supplier</h2>
            <form method="get" style="display:flex;gap:8px;width:auto;"><input name="q" value="{{ key }}" placeholder="Cari..." style="width:200px;"><button class="btn-ghost" type="submit">Cari</button></form></div>
            <div class="table-wrap"><table><thead><tr><th>Kode</th><th>Nama</th><th>HP</th><th>Kontak</th><th>Aksi</th></tr></thead>
            <tbody>{% for r in rows %}<tr><td>{{ r['supplier_code'] }}</td><td>{{ r['name'] }}</td><td>{{ r['phone'] or '-' }}</td><td>{{ r['contact_person'] or '-' }}</td><td><a class="btn btn-sm btn-ghost" href="{{ url_for('suppliers', edit_id=r['id']) }}">Edit</a></td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada supplier.</td></tr>{% endfor %}</tbody></table></div>
        </div></div>
    </div>
    ''', rows=rows, key=key, edit_row=edit_row, default_code=gen_code('SUP'))
    return render_page('Supplier', body)

# =========================
# Purchase Orders
# =========================
@app.route('/purchase-orders', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def purchase_orders():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create_po':
            supplier_id = int(request.form.get('supplier_id') or 0)
            po_date = request.form.get('po_date', today_str())
            note = request.form.get('note', '').strip()
            if supplier_id <= 0:
                flash('Pilih supplier.', 'error')
                return redirect(url_for('purchase_orders'))
            po_no = gen_code('PO')
            po_id = exec_sql('INSERT INTO purchase_orders(po_no, po_date, supplier_id, note, created_by) VALUES (?, ?, ?, ?, ?)', [po_no, po_date, supplier_id, note, session.get('user_id')])
            flash(f'PO {po_no} berhasil dibuat.', 'success')
            return redirect(url_for('purchase_orders'))
        elif action == 'add_item':
            po_id = int(request.form.get('po_id'))
            product_id = int(request.form.get('product_id') or 0)
            qty = parse_float(request.form.get('qty', 0))
            price = parse_float(request.form.get('price', 0))
            if product_id <= 0 or qty <= 0:
                flash('Pilih barang dan qty > 0.', 'error')
            else:
                subtotal = qty * price
                exec_sql('INSERT INTO purchase_items(po_id, product_id, qty, price, subtotal) VALUES (?, ?, ?, ?, ?)', [po_id, product_id, qty, price, subtotal])
                exec_sql('UPDATE purchase_orders SET total = COALESCE((SELECT SUM(subtotal) FROM purchase_items WHERE po_id=?), 0) WHERE id=?', [po_id, po_id])
                flash('Item ditambahkan.', 'success')
            return redirect(url_for('purchase_orders', po_id=po_id))
        elif action == 'receive':
            po_id = int(request.form.get('po_id'))
            po = q_one('SELECT * FROM purchase_orders WHERE id=? AND status="DRAFT"', [po_id])
            if not po:
                flash('PO tidak ditemukan atau sudah diterima.', 'error')
                return redirect(url_for('purchase_orders'))
            items = q_all('SELECT * FROM purchase_items WHERE po_id=?', [po_id])
            for it in items:
                exec_sql('UPDATE products SET stock = stock + ?, buy_price = ? WHERE id=?', [it['qty'], it['price'], it['product_id']])
            exec_sql('UPDATE purchase_orders SET status="RECEIVED", received_at=? WHERE id=?', [now_str(), po_id])
            log_action('RECEIVE', 'purchase_orders', po_id, f'PO {po["po_no"]} diterima')
            flash(f'PO {po["po_no"]} diterima, stok bertambah.', 'success')
            return redirect(url_for('purchase_orders'))
    suppliers_rows = q_all("SELECT id, supplier_code, name FROM suppliers WHERE is_active=1 ORDER BY name ASC")
    products_rows = q_all("SELECT id, barcode, product_name FROM products WHERE active=1 ORDER BY product_name ASC")
    po_id = request.args.get('po_id', '')
    po_edit = q_one('SELECT po.*, s.name as supplier_name FROM purchase_orders po LEFT JOIN suppliers s ON s.id=po.supplier_id WHERE po.id=?', [po_id]) if po_id else None
    po_items = q_all('SELECT pi.*, p.barcode, p.product_name FROM purchase_items pi LEFT JOIN products p ON p.id=pi.product_id WHERE pi.po_id=?', [po_id]) if po_id else []
    rows = q_all('SELECT po.*, s.name as supplier_name FROM purchase_orders po LEFT JOIN suppliers s ON s.id=po.supplier_id ORDER BY po.id DESC LIMIT 100')
    body = render_template_string('''
    <div class="grid">
        <div class="col-4"><div class="card"><h2>📋 Buat PO</h2>
            <form method="post"><input type="hidden" name="action" value="create_po">
                <div class="form-group"><label>Supplier</label><select name="supplier_id">{% for s in suppliers_rows %}<option value="{{ s['id'] }}">{{ s['supplier_code'] }} — {{ s['name'] }}</option>{% endfor %}</select></div>
                <div class="form-group"><label>Tanggal</label><input type="date" name="po_date" value="{{ today }}"></div>
                <div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:50px;"></textarea></div>
                <button type="submit">📤 Buat PO</button>
            </form>
        </div></div>
        <div class="col-8"><div class="card"><h2>Daftar Purchase Order</h2>
            <div class="table-wrap"><table><thead><tr><th>PO</th><th>Tanggal</th><th>Supplier</th><th>Total</th><th>Status</th><th>Aksi</th></tr></thead>
            <tbody>{% for r in rows %}<tr><td>{{ r['po_no'] }}</td><td>{{ r['po_date'] }}</td><td>{{ r['supplier_name'] or '-' }}</td><td>{{ rupiah(r['total']) }}</td><td><span class="badge {{ 'badge-warn' if r['status']=='DRAFT' else 'badge-success' }}">{{ r['status'] }}</span></td><td><a href="{{ url_for('purchase_orders', po_id=r['id']) }}" class="btn btn-sm btn-ghost">Detail</a></td></tr>{% else %}<tr><td colspan="6" class="muted text-center">Belum ada PO.</td></tr>{% endfor %}</tbody></table></div>
        </div></div>
    </div>
    {% if po_edit %}
    <div class="card"><div class="kartu"><div><h2>📄 {{ po_edit['po_no'] }} — {{ po_edit['supplier_name'] }}</h2><div class="muted small">{{ po_edit['note'] or '-' }} | Status: <span class="badge {{ 'badge-warn' if po_edit['status']=='DRAFT' else 'badge-success' }}">{{ po_edit['status'] }}</span></div></div>
    <div>Total: <strong>{{ rupiah(po_edit['total']) }}</strong></div></div>
    {% if po_edit['status'] == 'DRAFT' %}
    <form method="post" style="display:flex;gap:8px;flex-wrap:wrap;align-items:end;"><input type="hidden" name="action" value="add_item"><input type="hidden" name="po_id" value="{{ po_edit['id'] }}">
        <div><label class="small muted">Barang</label><select name="product_id" style="width:200px;">{% for p in products_rows %}<option value="{{ p['id'] }}">{{ p['barcode'] }} — {{ p['product_name'] }}</option>{% endfor %}</select></div>
        <div><label class="small muted">Qty</label><input type="number" name="qty" step="0.01" min="0.01" style="width:80px;"></div>
        <div><label class="small muted">Harga</label><input type="number" name="price" style="width:120px;"></div>
        <button class="btn-sm" type="submit">➕ Tambah</button>
    </form>
    <form method="post" style="margin-top:8px;"><input type="hidden" name="action" value="receive"><input type="hidden" name="po_id" value="{{ po_edit['id'] }}"><button class="btn-success" type="submit" onclick="return confirm('Terima PO ini? Stok akan bertambah.')">📦 Terima Barang</button></form>
    {% endif %}
    <div class="table-wrap" style="margin-top:12px;"><table><thead><tr><th>Barang</th><th>Qty</th><th>Harga</th><th>Subtotal</th></tr></thead>
    <tbody>{% for i in po_items %}<tr><td>{{ i['barcode'] }} — {{ i['product_name'] }}</td><td>{{ i['qty'] }}</td><td>{{ rupiah(i['price']) }}</td><td>{{ rupiah(i['subtotal']) }}</td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Belum ada item.</td></tr>{% endfor %}</tbody></table></div>
    </div>
    {% endif %}
    ''', suppliers_rows=suppliers_rows, products_rows=products_rows, rows=rows, po_edit=po_edit, po_items=po_items, today=today_str(), rupiah=rupiah)
    return render_page('Purchase Order', body)

# =========================
# Barcode SVG
# =========================
def barcode_svg(code):
    if not code: return ''
    pattern = []
    for ch in code:
        bh = bin(ord(ch))[2:].zfill(8)
        pattern.extend([1 if b == '1' else 0 for b in bh])
        pattern.append(0)
    w = len(pattern) * 3
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w+20}" height="80" viewBox="0 0 {w+20} 80"><rect width="{w+20}" height="80" fill="white"/>']
    x = 10
    for bit in pattern:
        if bit == 1:
            parts.append(f'<rect x="{x}" y="5" width="2" height="55" fill="black"/>')
        x += 3
    parts.append(f'<text x="{w//2+10}" y="72" text-anchor="middle" font-size="12" font-family="monospace">{code}</text></svg>')
    return ''.join(parts)

@app.route('/barcode/<barcode>')
@login_required
def barcode_image(barcode):
    return barcode_svg(barcode), 200, {'Content-Type': 'image/svg+xml'}

@app.route('/products/barcode-labels')
@login_required
def product_barcode_labels():
    single = request.args.get('barcode', '').strip()
    if single:
        rows = q_all("SELECT barcode, product_name, sell_price FROM products WHERE active=1 AND barcode=? AND barcode IS NOT NULL AND barcode != '' ORDER BY product_name ASC", [single])
    else:
        rows = q_all("SELECT barcode, product_name, sell_price FROM products WHERE active=1 AND barcode IS NOT NULL AND barcode != '' ORDER BY product_name ASC")
    html_parts = ['''<!doctype html><html><head><meta charset="utf-8"><title>Label Barcode</title><style>body{font-family:Arial,sans-serif;padding:20px;}.lg{display:grid;grid-template-columns:repeat(auto-fill,minmax(180px,1fr));gap:12px;}.lb{border:1px solid #ddd;border-radius:8px;padding:12px;text-align:center;}.lb h4{margin:4px 0;font-size:13px;}.lb .pr{font-size:14px;font-weight:700;color:#2563eb;margin-bottom:6px;}@media print{.np{display:none!important;}}</style></head><body><div class="np" style="margin-bottom:16px;"><a href="'''+url_for('products')+'''" class="btn btn-ghost">← Kembali</a> <button class="btn" onclick="window.print()">🖨️ Cetak</button></div><div class="lg">''']
    for r in rows:
        html_parts.append(f'<div class="lb"><h4>{r["product_name"]}</h4><div class="pr">{rupiah(r["sell_price"])}</div>{barcode_svg(r["barcode"])}</div>')
    html_parts.append('</div></body></html>')
    return ''.join(html_parts)

# =========================
# Fitur 7: Kategori Produk
# =========================
@app.route('/categories', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def categories():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'create':
            name = request.form.get('name', '').strip()
            desc = request.form.get('description', '').strip()
            if not name:
                flash('Nama kategori wajib diisi.', 'error')
            else:
                try:
                    exec_sql('INSERT INTO categories(name, description) VALUES (?, ?)', [name, desc])
                    flash('Kategori ditambahkan.', 'success')
                except sqlite3.IntegrityError:
                    flash('Kategori sudah ada.', 'error')
            return redirect(url_for('categories'))
        elif action == 'toggle':
            cid = int(request.form.get('cat_id'))
            c = q_one('SELECT is_active FROM categories WHERE id=?', [cid])
            exec_sql('UPDATE categories SET is_active=? WHERE id=?', [0 if c['is_active'] else 1, cid])
            flash('Status kategori diubah.', 'success')
            return redirect(url_for('categories'))
    cats = q_all('SELECT * FROM categories ORDER BY id DESC')
    body = render_template_string('''<div class="grid"><div class="col-4"><div class="card"><h2>🏷️ Tambah Kategori</h2><form method="post"><input type="hidden" name="action" value="create"><div class="form-group"><label>Nama</label><input name="name" required placeholder="Nama kategori"></div><div class="form-group"><label>Deskripsi</label><textarea name="description" style="min-height:50px;"></textarea></div><button type="submit">Simpan</button></form></div></div><div class="col-8"><div class="card"><h2>Daftar Kategori</h2><div class="table-wrap"><table><thead><tr><th>Nama</th><th>Deskripsi</th><th>Status</th><th>Aksi</th></tr></thead><tbody>{% for c in cats %}<tr><td>{{ c.name }}</td><td>{{ c.description or '-' }}</td><td><span class="badge {{ 'badge-success' if c.is_active else 'badge-gray' }}">{{ 'Aktif' if c.is_active else 'Nonaktif' }}</span></td><td><form method="post" style="margin:0;display:inline;"><input type="hidden" name="action" value="toggle"><input type="hidden" name="cat_id" value="{{ c.id }}"><button class="btn-sm btn-ghost">{{ 'Nonaktifkan' if c.is_active else 'Aktifkan' }}</button></form></td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Belum ada kategori.</td></tr>{% endfor %}</tbody></table></div></div></div></div>''', cats=cats)
    return render_page('Kategori', body)

# =========================
# Fitur 1: Retur Penjualan
# =========================
@app.route('/sales-returns', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def sales_returns():
    if request.method == 'POST':
        sales_id = int(request.form.get('sales_id') or 0)
        reason = request.form.get('reason', '').strip()
        items_json = request.form.get('return_items', '[]')
        items = json.loads(items_json)
        sale = q_one('SELECT * FROM sales WHERE id=? AND status="Posted"', [sales_id])
        if not sale:
            flash('Transaksi tidak ditemukan atau sudah diproses.', 'error')
            return redirect(url_for('sales_returns'))
        if not items:
            flash('Pilih minimal 1 item untuk diretur.', 'error')
            return redirect(url_for('sales_returns'))
        total_return = 0
        ret_items = []
        for item in items:
            prod = q_one('SELECT id FROM products WHERE id=?', [item['product_id']])
            if prod:
                subtotal = float(item['qty']) * float(item['price'])
                total_return += subtotal
                ret_items.append((prod['id'], float(item['qty']), float(item['price']), subtotal))
        if total_return <= 0:
            flash('Total retur harus lebih dari 0.', 'error')
            return redirect(url_for('sales_returns'))
        ret_no = gen_code('RET')
        ret_id = exec_sql('INSERT INTO sales_returns(return_no, sales_id, member_id, return_date, total, reason, created_by) VALUES (?, ?, ?, ?, ?, ?, ?)', [ret_no, sales_id, sale['member_id'], today_str(), total_return, reason, session.get('user_id')])
        for pid, qty, price, sub in ret_items:
            exec_sql('INSERT INTO sales_return_items(return_id, product_id, qty, price, subtotal) VALUES (?, ?, ?, ?, ?)', [ret_id, pid, qty, price, sub])
            exec_sql('UPDATE products SET stock = stock + ? WHERE id=?', [qty, pid])
        if sale['member_id'] and sale['payment_method'] == 'wallet':
            saldo_sebelum = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id=?', [sale['member_id']])['saldo']
            saldo_setelah = saldo_sebelum + total_return
            exec_sql('INSERT INTO saldo_history(member_id, tipe, nominal, saldo_sebelum, saldo_setelah, keterangan, reference_id, created_by) VALUES (?, "MASUK", ?, ?, ?, "Retur penjualan "+?, ?, ?)', [sale['member_id'], total_return, saldo_sebelum, saldo_setelah, ret_no, ret_id, session.get('user_id')])
        log_action('CREATE', 'sales_returns', ret_id, f'Retur {ret_no} dari {sale["invoice_no"]} total {total_return}')
        flash(f'Retur berhasil. {ret_no} — Stok dikembalikan.', 'success')
        return redirect(url_for('sales_returns_list'))
    sales = q_all('SELECT s.*, COALESCE(m.name, s.customer_name, "Umum") as pelanggan FROM sales s LEFT JOIN members m ON m.id=s.member_id WHERE s.status="Posted" ORDER BY s.id DESC LIMIT 50')
    body = render_template_string('''<div class="card"><h2>🔄 Retur Penjualan</h2><div class="muted small">Pilih transaksi lalu centang item yang ingin diretur</div><div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Tanggal</th><th>Pelanggan</th><th>Total</th><th>Aksi</th></tr></thead><tbody>{% for s in sales %}<tr><td>{{ s.invoice_no }}</td><td>{{ s.trx_date }}</td><td>{{ s.pelanggan }}</td><td>{{ rupiah(s.total) }}</td><td><a href="{{ url_for('sales_returns_process', sales_id=s.id) }}" class="btn btn-sm btn-warn">🔄 Retur</a></td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada transaksi.</td></tr>{% endfor %}</tbody></table></div></div>''', sales=sales, rupiah=rupiah)
    return render_page('Retur Penjualan', body)

@app.route('/sales-returns/process/<int:sales_id>', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def sales_returns_process(sales_id):
    sale = q_one('SELECT s.*, COALESCE(m.name, s.customer_name, "Umum") as pelanggan FROM sales s LEFT JOIN members m ON m.id=s.member_id WHERE s.id=?', [sales_id])
    items = q_all('SELECT si.*, p.stock FROM sales_items si LEFT JOIN products p ON p.id=si.product_id WHERE si.sales_id=?', [sales_id])
    body = render_template_string('''<div class="card"><h2>🔄 Retur — {{ sale.invoice_no }}</h2><div class="muted small">{{ sale.pelanggan }} | {{ sale.trx_date }}</div><form method="post" id="retForm"><input type="hidden" name="sales_id" value="{{ sale.id }}"><input type="hidden" name="return_items" id="return_items" value="[]"><div class="form-group"><label>Alasan Retur</label><textarea name="reason" style="min-height:50px;"></textarea></div><div class="table-wrap"><table><thead><tr><th><input type="checkbox" id="checkAll" onchange="toggleAll(this)"></th><th>Barang</th><th>Qty Beli</th><th>Harga</th><th>Stok Skrg</th><th>Qty Retur</th></tr></thead><tbody>{% for i in items %}<tr><td><input type="checkbox" class="ret-check" data-pid="{{ i.product_id }}" data-price="{{ i.price }}" data-max="{{ i.qty }}" data-name="{{ i.product_name }}"></td><td>{{ i.product_name }}</td><td>{{ i.qty }}</td><td>{{ rupiah(i.price) }}</td><td>{{ i.stock }}</td><td><input type="number" class="ret-qty" min="1" max="{{ i.qty }}" value="{{ i.qty }}" disabled style="width:80px;"></td></tr>{% endfor %}</tbody></table></div><button type="submit" class="btn-warn">📤 Proses Retur</button></form></div><script>document.getElementById('checkAll')&&document.getElementById('checkAll').addEventListener('change',function(){document.querySelectorAll('.ret-check').forEach(c=>{c.checked=this.checked;c.closest('tr').querySelector('.ret-qty').disabled=!this.checked})});function toggleAll(s){document.querySelectorAll('.ret-check').forEach(c=>{c.checked=s.checked;c.closest('tr').querySelector('.ret-qty').disabled=!s.checked})}document.getElementById('retForm').addEventListener('submit',function(e){var items=[];document.querySelectorAll('.ret-check:checked').forEach(c=>{var q=parseInt(c.closest('tr').querySelector('.ret-qty').value)||0;if(q>0)items.push({product_id:parseInt(c.dataset.pid),qty:q,price:parseFloat(c.dataset.price)})});document.getElementById('return_items').value=JSON.stringify(items)})</script>''', sale=sale, items=items, rupiah=rupiah)
    return render_page(f'Retur {sale["invoice_no"]}', body)

@app.route('/sales-returns/list')
@login_required
@role_required('admin', 'kasir')
def sales_returns_list():
    rows = q_all('SELECT r.*, s.invoice_no FROM sales_returns r LEFT JOIN sales s ON s.id=r.sales_id ORDER BY r.id DESC LIMIT 200')
    body = render_template_string('''<div class="card"><h2>📋 Riwayat Retur</h2><div class="table-wrap"><table><thead><tr><th>No Retur</th><th>Invoice Asal</th><th>Tanggal</th><th>Total</th><th>Alasan</th><th>Status</th></tr></thead><tbody>{% for r in rows %}<tr><td>{{ r.return_no }}</td><td>{{ r.invoice_no }}</td><td>{{ r.return_date }}</td><td>{{ rupiah(r.total) }}</td><td>{{ r.reason or '-' }}</td><td><span class="badge badge-warn">{{ r.status }}</span></td></tr>{% else %}<tr><td colspan="6" class="muted text-center">Belum ada retur.</td></tr>{% endfor %}</tbody></table></div></div>''', rows=rows, rupiah=rupiah)
    return render_page('Riwayat Retur', body)

# =========================
# Fitur 2: Diskon di Kasir
# =========================
@app.route('/cashier-with-discount', methods=['GET', 'POST'])
@login_required
@role_required('admin', 'kasir')
def cashier_discount():
    cart = get_cart()
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'add_item':
            barcode = request.form.get('barcode', '').strip()
            qty = parse_float(request.form.get('qty', 1) or 1)
            prod = q_one('SELECT id, barcode, product_name, sell_price, stock FROM products WHERE barcode=? AND active=1', [barcode])
            if not barcode:
                flash('Barcode wajib diisi / discan.', 'warning')
            elif not prod:
                flash('Barang tidak ditemukan.', 'error')
            elif float(prod['stock']) < qty:
                flash('Stok tidak mencukupi.', 'error')
            else:
                found = False
                for item in cart:
                    if item['product_id'] == int(prod['id']):
                        item['qty'] += qty; item['subtotal'] = item['qty'] * item['price']
                        found = True; break
                if not found:
                    cart.append({'product_id': int(prod['id']), 'barcode': prod['barcode'], 'product_name': prod['product_name'], 'qty': qty, 'price': float(prod['sell_price']), 'subtotal': qty * float(prod['sell_price']), 'discount': 0, 'discount_type': '%'})
                save_cart(cart)
                flash(f"{prod['product_name']} masuk keranjang.", 'success')
            return redirect(url_for('cashier_discount'))
        elif action == 'set_discount':
            idx = int(request.form.get('item_idx', 0))
            disc_val = parse_float(request.form.get('discount_value', 0) or 0)
            disc_type = request.form.get('discount_type', '%')
            if 0 <= idx < len(cart):
                cart[idx]['discount'] = disc_val
                cart[idx]['discount_type'] = disc_type
                item = cart[idx]
                base = item['qty'] * item['price']
                if disc_type == '%':
                    item['discount_amount'] = base * disc_val / 100
                else:
                    item['discount_amount'] = disc_val
                item['subtotal'] = max(0, base - item['discount_amount'])
                save_cart(cart)
                flash('Diskon diterapkan.', 'success')
            return redirect(url_for('cashier_discount'))
        elif action == 'clear':
            save_cart([]); flash('Keranjang dikosongkan.', 'warning')
            return redirect(url_for('cashier_discount'))
        elif action == 'save_sale':
            if not cart:
                flash('Keranjang kosong.', 'error')
                return redirect(url_for('cashier_discount'))
            total = sum(float(i.get('subtotal', i['qty'] * i['price'])) for i in cart)
            global_disc = parse_float(request.form.get('global_discount', 0) or 0)
            global_disc_type = request.form.get('global_disc_type', '%')
            if global_disc_type == '%':
                global_disc_amount = total * global_disc / 100
            else:
                global_disc_amount = global_disc
            final_total = max(0, total - global_disc_amount)
            member_id = request.form.get('member_id') or None
            customer_name = request.form.get('customer_name', '').strip()
            paid = parse_float(request.form.get('paid', 0) or 0)
            note = request.form.get('note', '').strip()
            payment_method = request.form.get('payment_method', 'tunai')
            invoice = gen_code('INV')
            change_amount = 0
            if payment_method == 'tunai':
                if paid < final_total:
                    flash('Nominal bayar kurang dari total.', 'error')
                    return redirect(url_for('cashier_discount'))
                change_amount = paid - final_total
            elif payment_method == 'wallet':
                if not member_id:
                    flash('Bayar wallet wajib pilih member.', 'error')
                    return redirect(url_for('cashier_discount'))
                member_saldo = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id=?', [member_id])['saldo']
                if member_saldo < final_total:
                    flash(f'Saldo wallet tidak cukup. Saldo {rupiah(member_saldo)}', 'error')
                    return redirect(url_for('cashier_discount'))
                saldo_sebelum = member_saldo
                saldo_setelah = saldo_sebelum - final_total
                exec_sql('INSERT INTO saldo_history(member_id, tipe, nominal, saldo_sebelum, saldo_setelah, keterangan, reference_id, created_by) VALUES (?, "KELUAR", ?, ?, ?, "Bayar kasir diskon", ?, ?)', [member_id, final_total, saldo_sebelum, saldo_setelah, 0, session.get('user_id')])
                paid = final_total
            else:
                paid = final_total
            disc_note = ''
            if global_disc_amount > 0:
                disc_note = f'Diskon {global_disc}{"" if global_disc_type==chr(37) else "Rp"}={rupiah(global_disc_amount)}'
            sid = exec_sql('INSERT INTO sales(invoice_no, trx_date, member_id, cashier_id, customer_name, total, paid, change_amount, note, status, payment_method) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, "Posted", ?)', [invoice, today_str(), member_id, session.get('user_id'), customer_name, final_total, paid, change_amount, note + ' ' + disc_note, payment_method])
            for item in cart:
                exec_sql('INSERT INTO sales_items(sales_id, product_id, barcode, product_name, qty, price, subtotal) VALUES (?, ?, ?, ?, ?, ?, ?)', [sid, item['product_id'], item['barcode'], item['product_name'], item['qty'], item['price'], item.get('subtotal', item['qty'] * item['price'])])
                exec_sql('UPDATE products SET stock = stock - ? WHERE id=?', [item['qty'], item['product_id']])
            log_action('CREATE', 'sales', sid, f'Transaksi diskon {invoice} total {final_total}')
            save_cart([])
            flash(f'Transaksi tersimpan. Invoice {invoice}. Total {rupiah(final_total)}. Kembalian {rupiah(change_amount)}', 'success')
            return redirect(url_for('cashier_discount'))
    for i, item in enumerate(cart):
        if 'discount' not in item:
            item['discount'] = 0
            item['discount_type'] = '%'
            item['discount_amount'] = 0
        if 'discount_amount' not in item:
            item['discount_amount'] = 0
    members_rows = q_all("SELECT id, member_code, name FROM members WHERE status='Aktif' ORDER BY name ASC")
    total = sum(float(i.get('subtotal', i['qty'] * i['price'])) for i in cart)
    body = render_template_string('''<div class="grid"><div class="col-4"><div class="card"><h2>🧾 Kasir + Diskon</h2><hr><form method="post"><input type="hidden" name="action" value="add_item"><div class="form-group"><label>Barcode</label><input name="barcode" placeholder="Scan barcode..." autofocus></div><div class="form-group"><label>Qty</label><input type="number" name="qty" value="1"></div><button type="submit">➕ Tambah</button></form><hr><h3>Total: <strong>{{ rupiah(total) }}</strong></h3><form method="post"><input type="hidden" name="action" value="save_sale"><div class="form-group"><label>Member</label><select name="member_id"><option value="">Umum</option>{% for m in members_rows %}<option value="{{ m['id'] }}">{{ m['member_code'] }} — {{ m['name'] }}</option>{% endfor %}</select></div><div class="form-group"><label>Nama Pelanggan</label><input name="customer_name" placeholder="(opsional)"></div><div class="form-group"><label>🛒 Diskon Global</label><div style="display:flex;gap:8px;"><input type="number" name="global_discount" value="0" style="width:100px;"><select name="global_disc_type" style="width:60px;"><option value="%">% </option><option value="rp">Rp</option></select></div></div><div class="form-group"><label>Metode Bayar</label><select name="payment_method"><option value="tunai">💰 Tunai</option><option value="wallet">💳 Wallet</option></select></div><div class="form-group"><label>Bayar</label><input type="number" name="paid" value="{{ total }}"></div><div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:40px;"></textarea></div><button type="submit" class="btn-success">💾 Simpan Transaksi</button></form><form method="post" style="margin-top:8px;"><input type="hidden" name="action" value="clear"><button class="btn-ghost btn-danger" type="submit">🗑️ Kosongkan</button></form></div></div><div class="col-8"><div class="card"><h2>Keranjang</h2><div class="table-wrap"><table><thead><tr><th>Barang</th><th>Qty</th><th>Harga</th><th>Diskon</th><th>Subtotal</th><th>Aksi</th></tr></thead><tbody>{% for i in cart %}<tr><td>{{ i['product_name'] }}</td><td>{{ i['qty'] }}</td><td>{{ rupiah(i['price']) }}</td><td>{% if i.get('discount_amount',0) > 0 %}<span style="color:#ef4444;">-{{ rupiah(i['discount_amount']) }}</span>{% else %}-{% endif %}</td><td>{{ rupiah(i.get('subtotal', i['qty']*i['price'])) }}</td><td><form method="post" style="display:flex;gap:4px;"><input type="hidden" name="action" value="set_discount"><input type="hidden" name="item_idx" value="{{ loop.index0 }}"><input type="number" name="discount_value" placeholder="Diskon" style="width:70px;"><select name="discount_type" style="width:50px;"><option value="%">%</option><option value="rp">Rp</option></select><button class="btn-sm btn-warn" type="submit">💾</button></form></td></tr>{% else %}<tr><td colspan="6" class="muted text-center">Keranjang kosong.</td></tr>{% endfor %}</tbody></table></div></div></div></div>''', cart=cart, total=total, members_rows=members_rows, rupiah=rupiah)
    return render_page('Kasir + Diskon', body)

# =========================
# Fitur 4: Import Member dari Excel
# =========================
@app.route('/members/import', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def import_members():
    if request.method == 'POST':
        file = request.files.get('file')
        if not file or not file.filename.endswith(('.xlsx', '.xls')):
            flash('Upload file Excel (.xlsx/.xls).', 'error')
            return redirect(url_for('import_members'))
        df = pd.read_excel(file)
        count = 0
        errors = []
        for _, row in df.iterrows():
            code = str(row.get('member_code', '')).strip() or gen_code('MBR')
            name = str(row.get('name', '')).strip()
            phone = str(row.get('phone', '')).strip()
            address = str(row.get('address', '')).strip()
            if not name:
                errors.append(f'Baris {count+2}: nama kosong')
                continue
            try:
                exec_sql('INSERT INTO members(member_code, name, phone, address, join_date, status) VALUES (?, ?, ?, ?, ?, ?)', [code, name, phone, address, today_str(), 'Aktif'])
                count += 1
            except sqlite3.IntegrityError:
                errors.append(f'Baris {count+2}: kode {code} sudah ada')
        flash(f'{count} member berhasil diimpor. {len(errors)} error.', 'success' if count > 0 else 'error')
        if errors:
            for e in errors[:5]:
                flash(e, 'warning')
        return redirect(url_for('members'))
    template_path = 'imports/member_template.xlsx'
    return render_page('Import Member', render_template_string('''<div class="grid"><div class="col-6"><div class="card"><h2>📥 Import Member dari Excel</h2><p class="muted small">Format kolom: member_code, name, phone, address</p><form method="post" enctype="multipart/form-data"><div class="form-group"><label>File Excel</label><input type="file" name="file" accept=".xlsx,.xls" required></div><button type="submit">📤 Upload & Import</button></form></div></div><div class="col-6"><div class="card"><h2>📄 Template</h2><p class="muted small">Download template kosong lalu isi data member</p><a href="data:text/csv;base64,bWVtYmVyX2NvZGUsbmFtZSxwaG9uZSxhZGRyZXNzCk1CUi0wMDIsTmFtYSBEaXNpbmksMDgxMjM0NTY3ODkwLkFsbGFtYXQgRGVtbw==" download="member_template.csv" class="btn">📥 Download Template CSV</a></div></div></div>'''))

# =========================
# Fitur 5: Hutang Supplier
# =========================
@app.route('/supplier-payments', methods=['GET', 'POST'])
@login_required
@role_required('admin')
def supplier_payments():
    if request.method == 'POST':
        action = request.form.get('action')
        if action == 'pay':
            supplier_id = int(request.form.get('supplier_id'))
            amount = parse_float(request.form.get('amount', 0))
            pay_method = request.form.get('payment_method', 'tunai')
            note = request.form.get('note', '').strip()
            if amount <= 0:
                flash('Nominal harus > 0.', 'error')
            else:
                exec_sql('INSERT INTO supplier_payments(supplier_id, amount, payment_date, payment_method, note, created_by) VALUES (?, ?, ?, ?, ?, ?)', [supplier_id, amount, today_str(), pay_method, note, session.get('user_id')])
                log_action('CREATE', 'supplier_payments', supplier_id, f'Bayar supplier {amount}')
                flash('Pembayaran supplier dicatat.', 'success')
            return redirect(url_for('supplier_payments'))
    suppliers = q_all('SELECT * FROM suppliers WHERE is_active=1 ORDER BY name ASC')
    payments = q_all('SELECT sp.*, s.name as supplier_name FROM supplier_payments sp LEFT JOIN suppliers s ON s.id=sp.supplier_id ORDER BY sp.id DESC LIMIT 200')
    summary = []
    for s in suppliers:
        total_po = q_one('SELECT COALESCE(SUM(total),0) as x FROM purchase_orders WHERE supplier_id=? AND status="RECEIVED"', [s['id']])['x'] or 0
        total_paid = q_one('SELECT COALESCE(SUM(amount),0) as x FROM supplier_payments WHERE supplier_id=?', [s['id']])['x'] or 0
        hutang = total_po - total_paid
        summary.append({'name': s['name'], 'code': s['supplier_code'], 'total_po': total_po, 'total_paid': total_paid, 'hutang': max(0, hutang), 'id': s['id']})
    body = render_template_string('''<div class="grid"><div class="col-4"><div class="card"><h2>🏦 Bayar Hutang Supplier</h2><form method="post"><input type="hidden" name="action" value="pay"><div class="form-group"><label>Supplier</label><select name="supplier_id">{% for s in suppliers %}<option value="{{ s['id'] }}">{{ s['name'] }}</option>{% endfor %}</select></div><div class="form-group"><label>Nominal</label><input type="number" name="amount"></div><div class="form-group"><label>Metode</label><select name="payment_method"><option value="tunai">Tunai</option><option value="transfer">Transfer</option></select></div><div class="form-group"><label>Catatan</label><textarea name="note" style="min-height:50px;"></textarea></div><button type="submit">📤 Bayar</button></form></div></div><div class="col-8"><div class="card"><h2>📊 Saldo Hutang per Supplier</h2><div class="table-wrap"><table><thead><tr><th>Supplier</th><th>Total PO</th><th>Total Bayar</th><th>Hutang</th></tr></thead><tbody>{% for s in summary %}<tr><td>{{ s.name }}</td><td>{{ rupiah(s.total_po) }}</td><td>{{ rupiah(s.total_paid) }}</td><td style="font-weight:700;color:{{ '#ef4444' if s.hutang > 0 else '#10b981' }}">{{ rupiah(s.hutang) }}</td></tr>{% else %}<tr><td colspan="4" class="muted text-center">Belum ada data.</td></tr>{% endfor %}</tbody></table></div><hr><h3>📜 Riwayat Pembayaran</h3><div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Supplier</th><th>Nominal</th><th>Metode</th><th>Catatan</th></tr></thead><tbody>{% for p in payments %}<tr><td>{{ p.payment_date }}</td><td>{{ p.supplier_name or '-' }}</td><td>{{ rupiah(p.amount) }}</td><td>{{ p.payment_method }}</td><td>{{ p.note or '-' }}</td></tr>{% else %}<tr><td colspan="5" class="muted text-center">Belum ada pembayaran.</td></tr>{% endfor %}</tbody></table></div></div></div></div>''', suppliers=suppliers, payments=payments, summary=summary, rupiah=rupiah)
    return render_page('Hutang Supplier', body)

# =========================
# Fitur 3: Laporan Keuangan PDF (Laba Rugi + Neraca)
# =========================
@app.route('/financial-statements')
@login_required
@role_required('admin', 'bendahara')
def financial_statements():
    year = request.args.get('year', str(datetime.now().year))
    start = f'{year}-01-01'; end = f'{year}-12-31'
    tb = q_all('SELECT a.account_code, a.account_name, a.category, a.normal_balance, COALESCE(SUM(j.debit),0) as debit, COALESCE(SUM(j.credit),0) as credit FROM accounts a LEFT JOIN journal_entries j ON j.account_id=a.id AND j.entry_date >= ? AND j.entry_date <= ? GROUP BY a.id ORDER BY a.account_code', [start, end])
    revenue_items = []; expense_items = []; asset_items = []; liab_items = []; modal_items = []
    total_revenue = 0; total_expense = 0; total_asset = 0; total_liab = 0; total_modal = 0
    for r in tb:
        cat = r['category']
        saldo = float(r['debit']) - float(r['credit']) if r['normal_balance'] == 'Debit' else float(r['credit']) - float(r['debit'])
        item = {'code': r['account_code'], 'name': r['account_name'], 'amount': abs(saldo)}
        if cat == 'Pendapatan': revenue_items.append(item); total_revenue += abs(saldo)
        elif cat == 'Beban': expense_items.append(item); total_expense += abs(saldo)
        elif cat == 'Aset': asset_items.append(item); total_asset += abs(saldo)
        elif cat == 'Kewajiban': liab_items.append(item); total_liab += abs(saldo)
        elif cat == 'Modal': modal_items.append(item); total_modal += abs(saldo)
    laba_bersih = total_revenue - total_expense
    body = render_template_string('''<div class="grid"><div class="col-6"><div class="card"><h2>📊 Laba Rugi {{ year }}</h2><form method="get" style="display:flex;gap:8px;margin-bottom:12px;"><select name="year" onchange="this.form.submit()">{% for y in range(2024,2028) %}<option value="{{ y }}" {% if y|string==year %}selected{% endif %}>{{ y }}</option>{% endfor %}</select><a href="{{ url_for('financial_statements_pdf', year=year, report_type='lr') }}" class="btn btn-sm">🖨️ Cetak PDF</a></form><h3>Pendapatan</h3><table><tbody>{% for i in revenue_items %}<tr><td>{{ i.code }} — {{ i.name }}</td><td class="text-right">{{ rupiah(i.amount) }}</td></tr>{% endfor %}</tbody><tfoot><tr><td><strong>Total Pendapatan</strong></td><td class="text-right"><strong>{{ rupiah(total_revenue) }}</strong></td></tr></tfoot></table><hr><h3>Beban</h3><table><tbody>{% for i in expense_items %}<tr><td>{{ i.code }} — {{ i.name }}</td><td class="text-right">{{ rupiah(i.amount) }}</td></tr>{% endfor %}</tbody><tfoot><tr><td><strong>Total Beban</strong></td><td class="text-right"><strong>{{ rupiah(total_expense) }}</strong></td></tr></tfoot></table><hr><div style="background:#f0fdf4;padding:12px;border-radius:8px;"><strong>LABA BERSIH: {{ rupiah(laba_bersih) }}</strong></div></div></div><div class="col-6"><div class="card"><h2>📊 Neraca {{ year }}</h2><a href="{{ url_for('financial_statements_pdf', year=year, report_type='neraca') }}" class="btn btn-sm" style="margin-bottom:12px;">🖨️ Cetak PDF</a><h3>Aset</h3><table><tbody>{% for i in asset_items %}<tr><td>{{ i.code }} — {{ i.name }}</td><td class="text-right">{{ rupiah(i.amount) }}</td></tr>{% endfor %}</tbody><tfoot><tr><td><strong>Total Aset</strong></td><td class="text-right"><strong>{{ rupiah(total_asset) }}</strong></td></tr></tfoot></table><hr><h3>Kewajiban</h3><table><tbody>{% for i in liab_items %}<tr><td>{{ i.code }} — {{ i.name }}</td><td class="text-right">{{ rupiah(i.amount) }}</td></tr>{% endfor %}</tbody><tfoot><tr><td><strong>Total Kewajiban</strong></td><td class="text-right"><strong>{{ rupiah(total_liab) }}</strong></td></tr></tfoot></table><hr><h3>Modal</h3><table><tbody>{% for i in modal_items %}<tr><td>{{ i.code }} — {{ i.name }}</td><td class="text-right">{{ rupiah(i.amount) }}</td></tr>{% endfor %}</tbody><tfoot><tr><td><strong>Total Modal</strong></td><td class="text-right"><strong>{{ rupiah(total_modal) }}</strong></td></tr></tfoot></table></div></div></div>''', year=year, revenue_items=revenue_items, expense_items=expense_items, asset_items=asset_items, liab_items=liab_items, modal_items=modal_items, total_revenue=total_revenue, total_expense=total_expense, total_asset=total_asset, total_liab=total_liab, total_modal=total_modal, laba_bersih=laba_bersih, rupiah=rupiah)
    return render_page('Laporan Keuangan', body)

@app.route('/financial-statements/pdf/<int:year>/<report_type>')
@login_required
@role_required('admin', 'bendahara')
def financial_statements_pdf(year, report_type):
    start = f'{year}-01-01'; end = f'{year}-12-31'
    tb = q_all('SELECT a.account_code, a.account_name, a.category, a.normal_balance, COALESCE(SUM(j.debit),0) as debit, COALESCE(SUM(j.credit),0) as credit FROM accounts a LEFT JOIN journal_entries j ON j.account_id=a.id AND j.entry_date >= ? AND j.entry_date <= ? GROUP BY a.id ORDER BY a.account_code', [start, end])
    buf = BytesIO(); c = canvas.Canvas(buf, pagesize=A4); w, h = A4; y = h - 15*mm
    title = 'LABA RUGI' if report_type == 'lr' else 'NERACA'
    c.setFont('Helvetica-Bold', 16); c.drawString(15*mm, y, APP_TITLE); y -= 8*mm
    c.setFont('Helvetica-Bold', 14); c.drawString(15*mm, y, f'{title} TAHUN {year}'); y -= 10*mm
    c.setFont('Helvetica', 10)
    if report_type == 'lr':
        c.drawString(15*mm, y, 'PENDAPATAN:'); y -= 6*mm
        total_rev = 0
        for r in tb:
            if r['category'] == 'Pendapatan':
                amt = abs(float(r['credit']) - float(r['debit']))
                if amt > 0: c.drawString(20*mm, y, f"{r['account_code']} — {r['account_name']}"); c.drawRightString(195*mm, y, rupiah(amt)); y -= 5*mm; total_rev += amt
        c.setFont('Helvetica-Bold', 10); c.drawString(20*mm, y, 'Total Pendapatan'); c.drawRightString(195*mm, y, rupiah(total_rev)); y -= 8*mm
        c.setFont('Helvetica', 10); c.drawString(15*mm, y, 'BEBAN:'); y -= 6*mm
        total_exp = 0
        for r in tb:
            if r['category'] == 'Beban':
                amt = abs(float(r['debit']) - float(r['credit']))
                if amt > 0: c.drawString(20*mm, y, f"{r['account_code']} — {r['account_name']}"); c.drawRightString(195*mm, y, rupiah(amt)); y -= 5*mm; total_exp += amt
        c.setFont('Helvetica-Bold', 10); c.drawString(20*mm, y, 'Total Beban'); c.drawRightString(195*mm, y, rupiah(total_exp)); y -= 10*mm
        c.setFont('Helvetica-Bold', 12); c.drawString(15*mm, y, f'LABA BERSIH: {rupiah(total_rev - total_exp)}')
    else:
        for section, cat_list in [('ASET', ['Aset']), ('KEWAJIBAN', ['Kewajiban']), ('MODAL', ['Modal'])]:
            c.setFont('Helvetica-Bold', 10); c.drawString(15*mm, y, f'{section}:'); y -= 6*mm
            for r in tb:
                if r['category'] in cat_list:
                    saldo = abs(float(r['debit']) - float(r['credit'])) if r['normal_balance'] == 'Debit' else abs(float(r['credit']) - float(r['debit']))
                    if saldo > 0: c.drawString(20*mm, y, f"{r['account_code']} — {r['account_name']}"); c.drawRightString(195*mm, y, rupiah(saldo)); y -= 5*mm
            y -= 3*mm
    c.showPage(); c.save(); buf.seek(0)
    return send_file(buf, as_attachment=True, download_name=f'{title}_{year}.pdf', mimetype='application/pdf')

# =========================
# Fitur 6: Laporan Keuangan Per Anggota
# =========================
@app.route('/member-statement/<int:member_id>')
@login_required
@role_required('admin')
def member_statement(member_id):
    member = q_one('SELECT * FROM members WHERE id=?', [member_id])
    if not member:
        flash('Member tidak ditemukan.', 'error')
        return redirect(url_for('members'))
    start = request.args.get('start', ''); end = request.args.get('end', '')
    purchases = q_all('SELECT * FROM sales WHERE member_id=? AND status="Posted"' + (' AND trx_date>=?' if start else '') + (' AND trx_date<=?' if end else '') + ' ORDER BY id DESC', [member_id] + ([start] if start else []) + ([end] if end else []))
    savings = q_all('SELECT * FROM savings_transactions WHERE member_id=? ORDER BY id DESC', [member_id])
    loan_payments = q_all('SELECT lp.*, l.loan_no FROM loan_payments lp JOIN loans l ON l.id=lp.loan_id WHERE l.member_id=? ORDER BY lp.id DESC', [member_id])
    saldo_wallet = q_one('SELECT COALESCE(SUM(CASE WHEN tipe="MASUK" THEN nominal ELSE -nominal END), 0) as saldo FROM saldo_history WHERE member_id=?', [member_id])['saldo']
    total_purchases = sum(float(r['total']) for r in purchases)
    shu = calculate_shu(member_id)
    body = render_template_string('''<div class="card"><h2>📋 Laporan Keuangan — {{ member.name }}</h2><div class="muted small">{{ member.member_code }}</div><form method="get" style="display:flex;gap:8px;margin:12px 0;"><input type="date" name="start" value="{{ start }}" style="width:140px;"><input type="date" name="end" value="{{ end }}" style="width:140px;"><button class="btn-ghost" type="submit">Filter</button></form><div class="metrics"><div class="metric"><div class="label">Saldo Wallet</div><div class="value" style="color:#2563eb;">{{ rupiah(saldo_wallet) }}</div></div><div class="metric"><div class="label">Total Belanja</div><div class="value" style="color:#10b981;">{{ rupiah(total_purchases) }}</div></div><div class="metric"><div class="label">SHU</div><div class="value" style="color:#6366f1;">{{ rupiah(shu) }}</div></div></div><hr><h3>🛒 Riwayat Belanja</h3><div class="table-wrap"><table><thead><tr><th>Invoice</th><th>Tanggal</th><th>Total</th></tr></thead><tbody>{% for r in purchases %}<tr><td>{{ r.invoice_no }}</td><td>{{ r.trx_date }}</td><td>{{ rupiah(r.total) }}</td></tr>{% else %}<tr><td colspan="3" class="muted">-</td></tr>{% endfor %}</tbody></table></div><hr><h3>💰 Simpanan</h3><div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Jenis</th><th>Arah</th><th>Nominal</th></tr></thead><tbody>{% for r in savings %}<tr><td>{{ r.trx_date }}</td><td>{{ r.saving_type }}</td><td><span class="badge {{ 'badge-success' if r.direction=='Masuk' else 'badge-danger' }}">{{ r.direction }}</span></td><td>{{ rupiah(r.amount) }}</td></tr>{% else %}<tr><td colspan="4" class="muted">-</td></tr>{% endfor %}</tbody></table></div><hr><h3>💸 Pembayaran Pinjaman</h3><div class="table-wrap"><table><thead><tr><th>Tanggal</th><th>Pinjaman</th><th>Nominal</th><th>Status</th></tr></thead><tbody>{% for r in loan_payments %}<tr><td>{{ r.payment_date }}</td><td>{{ r.loan_no }}</td><td>{{ rupiah(r.amount) }}</td><td><span class="badge {{ 'badge-success' if r.status=='VERIFIED' else 'badge-warn' }}">{{ r.status }}</span></td></tr>{% else %}<tr><td colspan="4" class="muted">-</td></tr>{% endfor %}</tbody></table></div></div>''', member=member, purchases=purchases, savings=savings, loan_payments=loan_payments, saldo_wallet=saldo_wallet, total_purchases=total_purchases, shu=shu, start=start, end=end, rupiah=rupiah)
    return render_page(f'Laporan — {member["name"]}', body)

# =========================
# Boot
# =========================
init_db()

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)