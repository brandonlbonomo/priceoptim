import os, json, secrets, hashlib, hmac, time, base64, struct, urllib.request, urllib.parse, re
from datetime import timedelta, date
from flask import Flask, request, jsonify, session, Response
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(__name__)

# ── SESSION CONFIG ─────────────────────────────────────────────────────────────
_sk = os.environ.get('SECRET_KEY')
if not _sk:
    print('WARNING: SECRET_KEY not set — sessions will reset on restart')
    _sk = 'dev_secret_change_in_prod_propertypigeon'
app.secret_key = _sk
app.config.update(
    SESSION_COOKIE_SECURE=False,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE='Lax',
    PERMANENT_SESSION_LIFETIME=timedelta(days=30),
)
CORS(app, supports_credentials=True)

# ── DB ─────────────────────────────────────────────────────────────────────────
DATABASE_URL = os.environ.get('DATABASE_URL', '')
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

def get_db():
    return psycopg2.connect(DATABASE_URL)

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        # Users - matches ORIGINAL live schema
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100),
                portfolio_name VARCHAR(100),
                ticker VARCHAR(10) UNIQUE,
                bio TEXT DEFAULT '',
                location VARCHAR(100) DEFAULT '',
                avatar VARCHAR(10) DEFAULT '🏠',
                avatar_color VARCHAR(7) DEFAULT '#1a56db',
                accent_color VARCHAR(7) DEFAULT '#1a56db',
                is_public BOOLEAN DEFAULT true,
                totp_secret VARCHAR(64),
                mfa_enabled BOOLEAN DEFAULT false,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS properties (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                location TEXT DEFAULT '',
                purchase_price DECIMAL(12,2) DEFAULT 0,
                down_payment DECIMAL(12,2) DEFAULT 0,
                equity DECIMAL(12,2) DEFAULT 0,
                mortgage DECIMAL(10,2) DEFAULT 0,
                insurance DECIMAL(10,2) DEFAULT 0,
                hoa DECIMAL(10,2) DEFAULT 0,
                property_tax DECIMAL(10,2) DEFAULT 0,
                monthly_revenue DECIMAL(10,2) DEFAULT 0,
                monthly_expenses DECIMAL(10,2) DEFAULT 0,
                zestimate DECIMAL(12,2) DEFAULT 0,
                zpid VARCHAR(50) DEFAULT '',
                bedrooms INTEGER DEFAULT 0,
                bathrooms DECIMAL(4,1) DEFAULT 0,
                sqft INTEGER DEFAULT 0,
                year_built INTEGER DEFAULT 0,
                last_value_refresh TIMESTAMP,
                zillow_url TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS follows (
                follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                PRIMARY KEY (follower_id, following_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS portfolio_metrics (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                total_value DECIMAL(12,2) DEFAULT 0,
                total_equity DECIMAL(12,2) DEFAULT 0,
                monthly_cashflow DECIMAL(12,2) DEFAULT 0,
                annual_cashflow DECIMAL(12,2) DEFAULT 0,
                property_count INTEGER DEFAULT 0,
                health_score INTEGER DEFAULT 0,
                share_price DECIMAL(10,4) DEFAULT 1.0,
                price_history JSONB DEFAULT '[]',
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS monthly_snapshots (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                snapshot_month DATE NOT NULL,
                total_value DECIMAL(12,2) DEFAULT 0,
                total_equity DECIMAL(12,2) DEFAULT 0,
                total_debt DECIMAL(12,2) DEFAULT 0,
                gross_revenue DECIMAL(12,2) DEFAULT 0,
                total_expenses DECIMAL(12,2) DEFAULT 0,
                net_cashflow DECIMAL(12,2) DEFAULT 0,
                noi DECIMAL(12,2) DEFAULT 0,
                property_count INTEGER DEFAULT 0,
                avg_cap_rate DECIMAL(6,4) DEFAULT 0,
                avg_cash_on_cash DECIMAL(6,4) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, snapshot_month)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS plaid_items (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                access_token TEXT NOT NULL,
                item_id TEXT UNIQUE,
                institution_name TEXT DEFAULT '',
                institution_id TEXT DEFAULT '',
                cursor TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS plaid_txn_categories (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                txn_id TEXT NOT NULL,
                txn_name TEXT,
                original_category TEXT,
                user_category TEXT NOT NULL,
                amount NUMERIC,
                txn_date DATE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(user_id, txn_id)
            )
        """)
        conn.commit()
        cur.close()

def migrate_db():
    """Add any missing columns to existing tables safely"""
    cols = [
        ("users", "full_name", "VARCHAR(100)"),
        ("users", "portfolio_name", "VARCHAR(100)"),
        ("users", "avatar_color", "VARCHAR(7) DEFAULT '#1a56db'"),
        ("users", "accent_color", "VARCHAR(7) DEFAULT '#1a56db'"),
        ("users", "is_public", "BOOLEAN DEFAULT true"),
        ("users", "totp_secret", "VARCHAR(64)"),
        ("users", "mfa_enabled", "BOOLEAN DEFAULT false"),
        ("users", "bio", "TEXT DEFAULT ''"),
        ("users", "location", "VARCHAR(100) DEFAULT ''"),
        ("users", "avatar", "VARCHAR(10) DEFAULT '🏠'"),
        ("properties", "zestimate", "DECIMAL(12,2) DEFAULT 0"),
        ("properties", "zpid", "VARCHAR(50) DEFAULT ''"),
        ("properties", "bedrooms", "INTEGER DEFAULT 0"),
        ("properties", "bathrooms", "DECIMAL(4,1) DEFAULT 0"),
        ("properties", "sqft", "INTEGER DEFAULT 0"),
        ("properties", "year_built", "INTEGER DEFAULT 0"),
        ("plaid_items", "institution_id", "TEXT DEFAULT ''"),
        ("plaid_items", "cursor", "TEXT DEFAULT ''"),
        ("plaid_items", "updated_at", "TIMESTAMP DEFAULT CURRENT_TIMESTAMP"),
        ("properties", "last_value_refresh", "TIMESTAMP"),
        ("properties", "zillow_url", "TEXT DEFAULT ''"),
        ("properties", "monthly_expenses", "DECIMAL(10,2) DEFAULT 0"),
        ("properties", "equity", "DECIMAL(12,2) DEFAULT 0"),
        ("properties", "location", "TEXT DEFAULT ''"),
        ("portfolio_metrics", "total_value", "DECIMAL(12,2) DEFAULT 0"),
        ("portfolio_metrics", "total_equity", "DECIMAL(12,2) DEFAULT 0"),
        ("portfolio_metrics", "monthly_cashflow", "DECIMAL(12,2) DEFAULT 0"),
        ("portfolio_metrics", "price_history", "JSONB DEFAULT '[]'"),
        ("portfolio_metrics", "health_score", "INTEGER DEFAULT 0"),
        ("portfolio_metrics", "share_price", "DECIMAL(10,4) DEFAULT 1.0"),
    ]
    # Add unique constraint to plaid_items.item_id if missing
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                DO $$ BEGIN
                    IF NOT EXISTS (
                        SELECT 1 FROM pg_constraint WHERE conname = 'plaid_items_item_id_key'
                    ) THEN
                        ALTER TABLE plaid_items ADD CONSTRAINT plaid_items_item_id_key UNIQUE (item_id);
                    END IF;
                END $$;
            """)
            conn.commit(); cur.close()
    except Exception as e:
        print(f'Constraint migration skipped: {e}')

    try:
        with get_db() as conn:
            cur = conn.cursor()
            for table, col, dtype in cols:
                try:
                    cur.execute(f"ALTER TABLE {table} ADD COLUMN IF NOT EXISTS {col} {dtype}")
                    conn.commit()
                    print(f"Migration OK: {table}.{col}")
                except Exception as me:
                    conn.rollback()
                    print(f"Migration skip {table}.{col}: {me}")
            cur.close()
    except Exception as e:
        print(f'Migration warning: {e}')

try:
    init_db()
    migrate_db()
except Exception as e:
    print(f'DB init error: {e}')

# ── HELPERS ────────────────────────────────────────────────────────────────────
def hash_password(password):
    salt = secrets.token_hex(16)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return f"{salt}${pwd_hash.hex()}"

def verify_password(password, stored):
    if not stored: return False
    # Format: salt$hash (original app format)
    try:
        if '$' in stored:
            salt, pwd_hash = stored.split('$', 1)
            return hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex(), pwd_hash)
    except: pass
    # Fallback: salt:hash format (from some rebuilds)
    try:
        if ':' in stored:
            salt, pwd_hash = stored.split(':', 1)
            for iters in [100000, 260000]:
                if hmac.compare_digest(hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), iters).hex(), pwd_hash):
                    return True
    except: pass
    return False

def _totp(secret, t=None):
    if t is None: t = int(time.time()) // 30
    key = base64.b32decode(secret.upper() + '=' * (-len(secret) % 8))
    msg = struct.pack('>Q', t)
    h = hmac.new(key, msg, 'sha1').digest()
    o = h[-1] & 0xf
    return str(struct.unpack('>I', h[o:o+4])[0] & 0x7fffffff % 1000000).zfill(6)

def verify_totp(secret, token):
    return any(_totp(secret, int(time.time())//30 + d) == str(token) for d in [-1,0,1])

def generate_ticker(name):
    words = re.findall(r'[A-Za-z]+', name)
    if len(words) >= 2: base = ''.join(w[0] for w in words[:4]).upper()
    else: base = (name[:4]).upper().replace(' ','')
    base = base or 'USER'
    with get_db() as conn:
        cur = conn.cursor()
        ticker = base
        for i in range(1, 100):
            cur.execute("SELECT id FROM users WHERE ticker=%s", (ticker,))
            if not cur.fetchone(): break
            ticker = base[:3] + str(i)
        cur.close()
    return ticker

def update_metrics(user_id):
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM properties WHERE user_id=%s", (user_id,))
            props = cur.fetchall()
            # zestimate may not exist in old schema - fallback to purchase_price
            tv = sum(float(p.get('zestimate') or p.get('purchase_price') or 0) for p in props)
            te = sum(float(p.get('equity') or 0) for p in props)
            mcf = sum(float(p.get('monthly_revenue') or 0) - float(p.get('monthly_expenses') or 0) for p in props)
            cur.execute("SELECT price_history FROM portfolio_metrics WHERE user_id=%s", (user_id,))
            row = cur.fetchone()
            hist = json.loads(row['price_history']) if row and row.get('price_history') else []
            base = 1.0
            if props:
                base += (te/100000)*0.1 + (mcf*12/10000)*0.05
            sp = round(max(0.01, base), 4)
            hs = min(100, 50 + (min(25, int(mcf/200)) if mcf>0 else 0) + (min(25, int((te/tv)*25)) if tv>0 else 0))
            hist.append({'date': time.strftime('%Y-%m-%d'), 'price': sp})
            hist = hist[-365:]
            cur.execute("""
                INSERT INTO portfolio_metrics (user_id,total_value,total_equity,monthly_cashflow,annual_cashflow,property_count,health_score,share_price,price_history)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(user_id) DO UPDATE SET
                total_value=EXCLUDED.total_value, total_equity=EXCLUDED.total_equity,
                monthly_cashflow=EXCLUDED.monthly_cashflow, annual_cashflow=EXCLUDED.annual_cashflow,
                property_count=EXCLUDED.property_count, health_score=EXCLUDED.health_score,
                share_price=EXCLUDED.share_price, price_history=EXCLUDED.price_history,
                updated_at=CURRENT_TIMESTAMP
            """, (user_id,tv,te,mcf,mcf*12,len(props),hs,sp,json.dumps(hist)))
            conn.commit(); cur.close()
    except Exception as e:
        print(f'update_metrics: {e}')

def record_snapshot(user_id):
    today = date.today()
    month = date(today.year, today.month, 1)
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM properties WHERE user_id=%s", (user_id,))
            props = cur.fetchall()
            if not props: cur.close(); return
            tv = sum(float(p.get('zestimate') or p.get('purchase_price') or 0) for p in props)
            te = sum(float(p.get('equity') or 0) for p in props)
            gr = sum(float(p.get('monthly_revenue') or 0) for p in props)
            ex = sum(float(p.get('monthly_expenses') or 0) for p in props)
            noi = gr - sum(float(p.get('property_tax') or 0)+float(p.get('insurance') or 0)+float(p.get('hoa') or 0) for p in props)
            cur.execute("""
                INSERT INTO monthly_snapshots (user_id,snapshot_month,total_value,total_equity,total_debt,gross_revenue,total_expenses,net_cashflow,noi,property_count,avg_cap_rate,avg_cash_on_cash)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT(user_id,snapshot_month) DO UPDATE SET
                total_value=EXCLUDED.total_value, total_equity=EXCLUDED.total_equity,
                total_debt=EXCLUDED.total_debt, gross_revenue=EXCLUDED.gross_revenue,
                total_expenses=EXCLUDED.total_expenses, net_cashflow=EXCLUDED.net_cashflow,
                noi=EXCLUDED.noi, property_count=EXCLUDED.property_count
            """, (user_id,month,tv,te,tv-te,gr,ex,gr-ex,noi,len(props),
                  (noi*12/tv) if tv>0 else 0, ((gr-ex)*12/(sum(float(p.get('down_payment') or 0) for p in props))) if sum(float(p.get('down_payment') or 0) for p in props)>0 else 0))
            conn.commit(); cur.close()
    except Exception as e:
        print(f'snapshot error: {e}')

# ── AUTH ROUTES ────────────────────────────────────────────────────────────────
@app.route('/api/auth/signup', methods=['POST'])
def signup():
    d = request.json or {}
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            ticker = generate_ticker(d.get('portfolio_name') or d.get('username',''))
            cur.execute("""
                INSERT INTO users (username,email,password_hash,full_name,portfolio_name,ticker,avatar_color,accent_color)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
            """, (
                d['username'], d['email'], hash_password(d['password']),
                d.get('full_name',''), d.get('portfolio_name',''),
                ticker, '#1a56db', '#1a56db'
            ))
            user = dict(cur.fetchone())
            uid = user['id']
            cur.execute("INSERT INTO portfolio_metrics (user_id) VALUES (%s) ON CONFLICT DO NOTHING", (uid,))
            conn.commit(); cur.close()
            session.permanent = True
            session['user_id'] = uid
            user.pop('password_hash', None); user.pop('totp_secret', None)
            return jsonify({'user': user})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/auth/login', methods=['POST'])
def login():
    d = request.json or {}
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM users WHERE username=%s OR email=%s", (d.get('username',''), d.get('username','')))
            u = cur.fetchone()
            if not u or not verify_password(d.get('password',''), u['password_hash']):
                return jsonify({'error': 'Invalid username or password'}), 401
            if u.get('mfa_enabled'):
                session['mfa_pending'] = u['id']
                return jsonify({'mfa_required': True})
            session.permanent = True
            session['user_id'] = u['id']
            update_metrics(u['id'])
            cur.close()
            u = dict(u); u.pop('password_hash', None); u.pop('totp_secret', None)
            return jsonify({'user': u})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'ok': True})

@app.route('/api/auth/me')
def get_me():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
        u = cur.fetchone(); cur.close()
    if not u: return jsonify({'error': 'Not found'}), 404
    u = dict(u); u.pop('password_hash', None); u.pop('totp_secret', None)
    return jsonify({'user': u})

@app.route('/api/auth/mfa/setup', methods=['POST'])
def mfa_setup():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    secret = base64.b32encode(secrets.token_bytes(20)).decode()
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET totp_secret=%s WHERE id=%s", (secret, uid))
        conn.commit(); cur.close()
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT username FROM users WHERE id=%s", (uid,))
        u = cur.fetchone(); cur.close()
    uri = f"otpauth://totp/PropertyPigeon:{u['username']}?secret={secret}&issuer=PropertyPigeon"
    return jsonify({'secret': secret, 'uri': uri})

@app.route('/api/auth/mfa/enable', methods=['POST'])
def mfa_enable():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json or {}
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT totp_secret FROM users WHERE id=%s", (uid,))
        u = cur.fetchone(); cur.close()
    if not verify_totp(u['totp_secret'], d.get('token','')):
        return jsonify({'error': 'Invalid code'}), 401
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET mfa_enabled=true WHERE id=%s", (uid,))
        conn.commit(); cur.close()
    return jsonify({'ok': True})

@app.route('/api/auth/mfa/verify', methods=['POST'])
def mfa_verify():
    uid = session.get('mfa_pending')
    if not uid: return jsonify({'error': 'No pending MFA'}), 400
    d = request.json or {}
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM users WHERE id=%s", (uid,))
        u = dict(cur.fetchone()); cur.close()
    if not verify_totp(u['totp_secret'], d.get('token','')):
        return jsonify({'error': 'Invalid code'}), 401
    session.pop('mfa_pending', None)
    session.permanent = True
    session['user_id'] = uid
    u.pop('password_hash', None); u.pop('totp_secret', None)
    return jsonify({'user': u})

# ── PASSWORD RESET (emergency) ─────────────────────────────────────────────────
@app.route('/api/auth/reset')
def emergency_reset():
    token = request.args.get('t','')
    env_token = os.environ.get('RESET_TOKEN','')
    if not env_token or not token or not hmac.compare_digest(token, env_token):
        return jsonify({'error': 'Invalid token. Set RESET_TOKEN env var on Render.'}), 403
    username = request.args.get('u','')
    new_pw = request.args.get('p','')
    if not username or not new_pw:
        return jsonify({'error': 'u= username and p= new_password required'}), 400
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("UPDATE users SET password_hash=%s WHERE username=%s OR email=%s RETURNING id", (hash_password(new_pw), username, username))
        row = cur.fetchone()
        conn.commit(); cur.close()
    if row: return jsonify({'ok': True, 'message': f'Password reset for {username}. You can now log in.'})
    return jsonify({'error': 'User not found'}), 404

# ── TICKER CHECK ───────────────────────────────────────────────────────────────
@app.route('/api/ticker/check/<ticker>')
def check_ticker(ticker):
    with get_db() as conn:
        cur = conn.cursor()
        try:
            cur.execute("SELECT id FROM users WHERE ticker=%s", (ticker.upper(),))
            taken = cur.fetchone() is not None
        except: taken = False
        cur.close()
    return jsonify({'available': not taken})

# ── USER SETTINGS ──────────────────────────────────────────────────────────────
@app.route('/api/user/settings', methods=['POST'])
def user_settings():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json or {}
    allowed = ['full_name','portfolio_name','bio','location','avatar_color','accent_color','is_public']
    sets = {k: d[k] for k in allowed if k in d}
    if not sets: return jsonify({'error': 'Nothing to update'}), 400
    cols = ', '.join(f"{k}=%s" for k in sets)
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute(f"UPDATE users SET {cols} WHERE id=%s RETURNING *", list(sets.values()) + [uid])
        u = dict(cur.fetchone())
        conn.commit(); cur.close()
    u.pop('password_hash', None); u.pop('totp_secret', None)
    return jsonify({'user': u})

# ── PORTFOLIO ──────────────────────────────────────────────────────────────────
@app.route('/api/portfolio/<int:uid>')
def get_portfolio(uid):
    uid_s = session.get('user_id')
    if not uid_s: return jsonify({'error': 'Not authenticated'}), 401
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT u.*, pm.total_value, pm.total_equity, pm.monthly_cashflow,
                   pm.annual_cashflow, pm.property_count, pm.health_score,
                   pm.share_price, pm.price_history, pm.updated_at as metrics_updated
            FROM users u LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
            WHERE u.id=%s
        """, (uid,))
        row = cur.fetchone(); cur.close()
    if not row: return jsonify({'error': 'Not found'}), 404
    r = dict(row); r.pop('password_hash', None); r.pop('totp_secret', None)
    if r.get('metrics_updated'): r['metrics_updated'] = r['metrics_updated'].isoformat()
    return jsonify(r)

# ── PROPERTIES ─────────────────────────────────────────────────────────────────
@app.route('/api/properties/<int:uid>', methods=['GET','POST'])
def properties(uid):
    req_uid = session.get('user_id')
    if not req_uid: return jsonify({'error': 'Not authenticated'}), 401
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        if request.method == 'GET':
            cur.execute("SELECT * FROM properties WHERE user_id=%s ORDER BY created_at DESC", (uid,))
            props = [dict(r) for r in cur.fetchall()]
            for p in props:
                if p.get('created_at'): p['created_at'] = p['created_at'].isoformat()
                if p.get('last_value_refresh'): p['last_value_refresh'] = p['last_value_refresh'].isoformat()
            cur.close()
            return jsonify(props)
        else:
            d = request.json or {}
            try:
                exp = sum(float(d.get(k,0) or 0) for k in ['mortgage','insurance','hoa','property_tax'])
                pp = float(d.get('purchase_price',0) or 0)
                dp = float(d.get('down_payment',0) or 0)
                zest = float(d.get('zestimate') or d.get('purchase_price') or 0)
                eq = zest - (pp - dp)
                name = str(d.get('name') or d.get('location') or 'Property')
                location = str(d.get('location') or '')
                saved = False
                # Try full insert first
                try:
                    cur.execute("""
                        INSERT INTO properties (user_id,name,location,purchase_price,down_payment,
                          mortgage,insurance,hoa,property_tax,monthly_revenue,monthly_expenses,
                          zestimate,zpid,bedrooms,bathrooms,sqft,year_built,zillow_url,equity)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
                    """, (uid, name, location, pp, dp,
                          float(d.get('mortgage',0) or 0), float(d.get('insurance',0) or 0),
                          float(d.get('hoa',0) or 0), float(d.get('property_tax',0) or 0),
                          float(d.get('monthly_revenue',0) or 0), exp, zest,
                          str(d.get('zpid','') or ''),
                          int(float(d.get('bedrooms',0) or 0)),
                          float(d.get('bathrooms',0) or 0),
                          int(float(d.get('sqft',0) or 0)),
                          int(float(d.get('year_built',0) or 0)),
                          str(d.get('zillow_url','') or ''), max(0,eq)))
                    saved = True
                except Exception as e1:
                    print(f'Full insert failed ({e1}), trying fallback')
                    conn.rollback()
                    # Fallback to minimal schema
                    cur.execute("""
                        INSERT INTO properties (user_id,name,location,purchase_price,down_payment,
                          equity,mortgage,insurance,hoa,property_tax,monthly_revenue,monthly_expenses)
                        VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
                    """, (uid, name, location, pp, dp, max(0,eq),
                          float(d.get('mortgage',0) or 0), float(d.get('insurance',0) or 0),
                          float(d.get('hoa',0) or 0), float(d.get('property_tax',0) or 0),
                          float(d.get('monthly_revenue',0) or 0), exp))
                    saved = True
                prop = dict(cur.fetchone())
                conn.commit()
                cur.close()
                try: update_metrics(uid)
                except Exception as me: print(f'Metrics update failed: {me}')
                if prop.get('created_at'): prop['created_at'] = prop['created_at'].isoformat()
                return jsonify(prop), 201
            except Exception as e:
                import traceback; traceback.print_exc()
                try: conn.rollback()
                except: pass
                try: cur.close()
                except: pass
                return jsonify({'error': str(e), 'type': type(e).__name__}), 400

@app.route('/api/property/<int:pid>', methods=['PUT','DELETE'])
def property_detail(pid):
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT user_id FROM properties WHERE id=%s", (pid,))
        p = cur.fetchone()
        if not p or p['user_id'] != uid:
            cur.close(); return jsonify({'error': 'Not found'}), 404
        if request.method == 'DELETE':
            cur.execute("DELETE FROM properties WHERE id=%s", (pid,))
            conn.commit(); cur.close()
            update_metrics(uid)
            return jsonify({'ok': True})
        d = request.json or {}
        exp = sum(float(d.get(k,0)) for k in ['mortgage','insurance','hoa','property_tax'])
        eq = float(d.get('zestimate') or d.get('purchase_price',0)) - (float(d.get('purchase_price',0)) - float(d.get('down_payment',0)))
        cur.execute("""
            UPDATE properties SET name=%s,location=%s,purchase_price=%s,down_payment=%s,
            mortgage=%s,insurance=%s,hoa=%s,property_tax=%s,monthly_revenue=%s,
            monthly_expenses=%s,zestimate=%s,equity=%s WHERE id=%s RETURNING *
        """, (d.get('name',''), d.get('location',''), float(d.get('purchase_price',0)),
              float(d.get('down_payment',0)), float(d.get('mortgage',0)), float(d.get('insurance',0)),
              float(d.get('hoa',0)), float(d.get('property_tax',0)), float(d.get('monthly_revenue',0)),
              exp, float(d.get('zestimate') or d.get('purchase_price',0)), max(0,eq), pid))
        prop = dict(cur.fetchone())
        conn.commit(); cur.close()
        update_metrics(uid)
        if prop.get('created_at'): prop['created_at'] = prop['created_at'].isoformat()
        return jsonify(prop)

# ── SOCIAL ─────────────────────────────────────────────────────────────────────
@app.route('/api/users/discover')
def discover():
    uid = session.get('user_id')
    if not uid: return jsonify([])
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,u.avatar_color,u.bio,
                   pm.total_value,pm.monthly_cashflow,pm.health_score,pm.share_price,pm.property_count,
                   EXISTS(SELECT 1 FROM follows WHERE follower_id=%s AND following_id=u.id) as is_following
            FROM users u LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
            WHERE u.id!=%s AND u.is_public=true ORDER BY pm.total_value DESC NULLS LAST LIMIT 20
        """, (uid,uid))
        users = [dict(r) for r in cur.fetchall()]; cur.close()
    return jsonify(users)

@app.route('/api/follow/<int:fid>', methods=['POST'])
def follow(fid):
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO follows (follower_id,following_id) VALUES (%s,%s) ON CONFLICT DO NOTHING", (uid,fid))
        conn.commit(); cur.close()
    return jsonify({'ok': True})

@app.route('/api/unfollow/<int:fid>', methods=['POST'])
def unfollow(fid):
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("DELETE FROM follows WHERE follower_id=%s AND following_id=%s", (uid,fid))
        conn.commit(); cur.close()
    return jsonify({'ok': True})

@app.route('/api/following')
def get_following():
    uid = session.get('user_id')
    if not uid: return jsonify([])
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,u.avatar_color,
                   pm.total_value,pm.monthly_cashflow,pm.health_score,pm.share_price
            FROM follows f JOIN users u ON u.id=f.following_id
            LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
            WHERE f.follower_id=%s
        """, (uid,))
        rows = [dict(r) for r in cur.fetchall()]; cur.close()
    return jsonify(rows)

# ── ZILLOW SCRAPER ─────────────────────────────────────────────────────────────
@app.route('/api/zillow/zestimate', methods=['POST'])
def zillow_zestimate():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    url = (request.json or {}).get('url','').strip()
    if 'zillow.com' not in url: return jsonify({'error': 'Must be a Zillow URL'}), 400
    import gzip as _gzip

    USER_AGENTS = [
        'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
        'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1',
        'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
    ]

    html = ''
    for ua in USER_AGENTS:
        try:
            req = urllib.request.Request(url, headers={
                'User-Agent': ua,
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate',
                'Referer': 'https://www.zillow.com/',
                'Cache-Control': 'no-cache',
            })
            resp = urllib.request.urlopen(req, timeout=15)
            raw = resp.read()
            try: html = _gzip.decompress(raw).decode('utf-8','ignore')
            except: html = raw.decode('utf-8','ignore')
            if len(html) > 10000: break
        except Exception as e:
            html = ''
            continue

    if len(html) < 1000:
        return jsonify({'error': 'Zillow is blocking server requests from cloud hosting (this is a Zillow anti-bot restriction on cloud IPs). See the Redfin alternative below.', 'blocked': True})

    result = {}

    # ── Parse __NEXT_DATA__ JSON blob (most reliable) ─────────────────────────
    def find_val(obj, *keys, mn=None, mx=None):
        if isinstance(obj, dict):
            for k,v in obj.items():
                if k in keys and v is not None:
                    try:
                        fv=float(str(v).replace(',',''))
                        if mn is not None and fv<mn: pass
                        elif mx is not None and fv>mx: pass
                        else: return v
                    except:
                        if mn is None and mx is None: return v
                r=find_val(v,*keys,mn=mn,mx=mx)
                if r is not None: return r
        elif isinstance(obj,list):
            for item in obj:
                r=find_val(item,*keys,mn=mn,mx=mx)
                if r is not None: return r
        return None

    m = re.search(r'<script[^>]*id="__NEXT_DATA__"[^>]*>(.*?)</script>', html, re.DOTALL)
    nd = None
    if m:
        try: nd = json.loads(m.group(1))
        except: pass

    if nd:
        z = find_val(nd,'zestimate','zestimateValue','homeValue',mn=50000,mx=50000000)
        if z: result['zestimate'] = int(float(str(z).replace(',','')))

        p = find_val(nd,'price','listPrice',mn=50000,mx=50000000)
        if p and 'zestimate' not in result: result['zestimate'] = int(float(str(p).replace(',','')))

        beds = find_val(nd,'bedrooms','beds',mn=0,mx=50)
        if beds: result['bedrooms'] = str(int(float(str(beds))))

        baths = find_val(nd,'bathrooms','baths',mn=0,mx=30)
        if baths: result['bathrooms'] = str(float(str(baths)))

        sqft = find_val(nd,'livingArea','livingAreaValue','finishedSqFt',mn=100,mx=100000)
        if sqft: result['sqft'] = str(int(float(str(sqft).replace(',',''))))

        yr = find_val(nd,'yearBuilt','builtYear',mn=1800,mx=2025)
        if yr: result['year_built'] = str(int(float(str(yr))))

        street = find_val(nd,'streetAddress')
        city = find_val(nd,'city')
        state = find_val(nd,'state')
        zipcode = find_val(nd,'zipcode','zip')
        if street:
            addr = str(street)
            if city: addr += f', {city}'
            if state: addr += f', {state}'
            if zipcode: addr += f' {zipcode}'
            result['address'] = addr
        elif city:
            result['address'] = ', '.join(filter(None,[str(city), str(state) if state else '', str(zipcode) if zipcode else '']))

        tax = find_val(nd,'taxAnnualAmount','annualTax',mn=1)
        if tax: result['tax_annual'] = float(str(tax).replace(',',''))

        hoa = find_val(nd,'monthlyHoaFee','hoaFee',mn=0,mx=10000)
        if hoa:
            try: result['hoa'] = float(str(hoa))
            except: pass

        desc = find_val(nd,'description')
        if isinstance(desc,str) and len(desc)>30: result['description'] = desc[:400]

        ptype = find_val(nd,'homeType','propertyType','homeTypeDimension')
        if ptype: result['property_type'] = str(ptype)

    # ── Regex fallbacks ────────────────────────────────────────────────────────
    rgx = {
        'zestimate':  [r'"zestimate":\{"value":(\d+)', r'"homeValue":(\d+)', r'"zestimate":(\d{5,8})'],
        'bedrooms':   [r'"bedrooms":(\d+)', r'"beds":(\d+)'],
        'bathrooms':  [r'"bathrooms":([\d.]+)', r'"baths":([\d.]+)'],
        'sqft':       [r'"livingArea":(\d+)', r'"finishedSqFt":(\d+)'],
        'year_built': [r'"yearBuilt":(\d{4})'],
        'address':    [r'"streetAddress":"([^"]+)"'],
        'tax_annual': [r'"taxAnnualAmount":([\d.]+)'],
    }
    for key, pats in rgx.items():
        if key in result: continue
        for pat in pats:
            mm = re.search(pat, html)
            if mm:
                v = mm.group(1).replace(',','')
                if key=='zestimate':
                    try:
                        if 50000<=int(float(v))<=50000000: result[key]=int(float(v))
                    except: pass
                elif key=='year_built':
                    try:
                        if 1800<=int(v)<=2025: result[key]=v
                    except: pass
                else: result[key]=v
                break

    if result.get('tax_annual'):
        try: result['monthly_tax'] = round(float(str(result['tax_annual']))/12)
        except: pass

    if not result.get('zestimate') and not result.get('address'):
        return jsonify({'error': 'Could not extract data from Zillow. Make sure you paste the full homedetails URL (zillow.com/homedetails/...).'})

    result['fields_found'] = [k for k in ['zestimate','address','bedrooms','bathrooms','sqft','year_built','monthly_tax','hoa'] if k in result]
    return jsonify(result)



@app.route('/api/redfin/lookup', methods=['POST'])
def redfin_lookup():
    """Scrape Redfin for property data - Redfin is less aggressive about blocking"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    url = (request.json or {}).get('url','').strip()
    if not url: return jsonify({'error': 'URL required'}), 400
    # Allow both zillow and redfin
    if 'redfin.com' not in url and 'zillow.com' not in url:
        return jsonify({'error': 'Must be a Redfin or Zillow URL'}), 400
    import gzip as _gzip
    result = {}
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,*/*;q=0.9',
            'Accept-Language': 'en-US,en;q=0.9',
            'Accept-Encoding': 'gzip, deflate',
        })
        resp = urllib.request.urlopen(req, timeout=15)
        raw = resp.read()
        try: html = _gzip.decompress(raw).decode('utf-8','ignore')
        except: html = raw.decode('utf-8','ignore')

        if 'redfin.com' in url:
            # Redfin price
            pm = re.search(r'"price":(\d+)', html) or re.search(r'\$([0-9,]+)(?:\s*</span>)', html)
            if pm:
                v = pm.group(1).replace(',','')
                try:
                    fv = int(float(v))
                    if 10000 < fv < 50000000: result['zestimate'] = fv
                except: pass
            # Redfin address
            am = re.search(r'"streetLine":"([^"]+)"', html)
            cm = re.search(r'"city":"([^"]+)"', html)
            sm = re.search(r'"state":"([^"]+)"', html)
            zm = re.search(r'"zip":"([^"]+)"', html)
            if am:
                addr = am.group(1)
                if cm: addr += f", {cm.group(1)}"
                if sm: addr += f", {sm.group(1)}"
                if zm: addr += f" {zm.group(1)}"
                result['address'] = addr
            beds = re.search(r'"beds":(\d+)', html)
            baths = re.search(r'"baths":([\d.]+)', html)
            sqft = re.search(r'"sqFt":(\d+)', html) or re.search(r'"livingArea":(\d+)', html)
            yr = re.search(r'"yearBuilt":(\d{4})', html)
            if beds: result['bedrooms'] = beds.group(1)
            if baths: result['bathrooms'] = baths.group(1)
            if sqft: result['sqft'] = sqft.group(1)
            if yr: result['year_built'] = yr.group(1)
            tax = re.search(r'"taxesDue":([\d.]+)', html) or re.search(r'"propertyTaxes":([\d.]+)', html)
            if tax:
                try: result['monthly_tax'] = round(float(tax.group(1))/12)
                except: pass

        result['source'] = 'redfin' if 'redfin.com' in url else 'zillow'
        if not result.get('zestimate') and not result.get('address'):
            return jsonify({'error': f'Could not parse data from this page. The site may be blocking requests. Try Redfin.com for better results.'}), 422
        return jsonify(result)
    except Exception as e:
        print(f'Redfin lookup error: {e}')
        return jsonify({'error': f'Failed: {str(e)}'}), 500


@app.route('/api/rentcast/lookup', methods=['POST'])
def rentcast_lookup():
    """RentCast API - address-based property value + rent estimate"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    api_key = os.environ.get('RENTCAST_API_KEY','')
    data = request.json or {}
    address = data.get('address','').strip()
    if not address: return jsonify({'error': 'Address required'}), 400
    if not api_key: return jsonify({'error': 'RENTCAST_API_KEY not configured — see setup instructions'}), 422

    result = {}
    headers = {'X-Api-Key': api_key, 'Accept': 'application/json'}
    encoded_addr = urllib.parse.quote(address)

    try:
        # 1. Property value estimate
        val_url = f'https://api.rentcast.io/v1/avm/value?address={encoded_addr}'
        req = urllib.request.Request(val_url, headers=headers)
        try:
            resp = urllib.request.urlopen(req, timeout=10)
            val_data = json.loads(resp.read())
            if val_data.get('price'): result['zestimate'] = int(val_data['price'])
            if val_data.get('priceLow'): result['value_low'] = int(val_data['priceLow'])
            if val_data.get('priceHigh'): result['value_high'] = int(val_data['priceHigh'])
            sp = val_data.get('subjectProperty', {})
            if sp.get('bedrooms'): result['bedrooms'] = str(sp['bedrooms'])
            if sp.get('bathrooms'): result['bathrooms'] = str(sp['bathrooms'])
            if sp.get('squareFootage'): result['sqft'] = str(int(sp['squareFootage']))
            if sp.get('yearBuilt'): result['year_built'] = str(sp['yearBuilt'])
            if sp.get('propertyType'): result['property_type'] = sp['propertyType']
            if sp.get('formattedAddress'): result['address'] = sp['formattedAddress']
            elif sp.get('addressLine1'):
                a = sp['addressLine1']
                if sp.get('city'): a += f", {sp['city']}"
                if sp.get('state'): a += f", {sp['state']}"
                if sp.get('zipCode'): a += f" {sp['zipCode']}"
                result['address'] = a
        except urllib.error.HTTPError as e:
            body = e.read().decode('utf-8','ignore')
            print(f'RentCast value error: {e.code} {body}')
            if e.code == 401: return jsonify({'error': 'Invalid RentCast API key'}), 401
            if e.code == 404: return jsonify({'error': f'Property not found: {address}. Check the address format (e.g. "123 Main St, Houston, TX 77001")'}), 404
            if e.code == 429: return jsonify({'error': 'RentCast API rate limit reached — upgrade plan at rentcast.io'}), 429

        # 2. Rent estimate (separate call)
        if result.get('zestimate'):
            rent_url = f'https://api.rentcast.io/v1/avm/rent/long-term?address={encoded_addr}'
            req2 = urllib.request.Request(rent_url, headers=headers)
            try:
                resp2 = urllib.request.urlopen(req2, timeout=10)
                rent_data = json.loads(resp2.read())
                if rent_data.get('rent'): result['rent_estimate'] = int(rent_data['rent'])
                if rent_data.get('rentLow'): result['rent_low'] = int(rent_data['rentLow'])
                if rent_data.get('rentHigh'): result['rent_high'] = int(rent_data['rentHigh'])
            except: pass

        # 3. Property records for tax data
        prop_url = f'https://api.rentcast.io/v1/properties?address={encoded_addr}&limit=1'
        req3 = urllib.request.Request(prop_url, headers=headers)
        try:
            resp3 = urllib.request.urlopen(req3, timeout=10)
            prop_list = json.loads(resp3.read())
            if isinstance(prop_list, list) and prop_list:
                pr = prop_list[0]
                if pr.get('lastSalePrice') and not result.get('zestimate'):
                    result['last_sale_price'] = int(pr['lastSalePrice'])
                if pr.get('lastSaleDate'): result['last_sale_date'] = pr['lastSaleDate']
                if not result.get('bedrooms') and pr.get('bedrooms'): result['bedrooms'] = str(pr['bedrooms'])
                if not result.get('bathrooms') and pr.get('bathrooms'): result['bathrooms'] = str(pr['bathrooms'])
                if not result.get('sqft') and pr.get('squareFootage'): result['sqft'] = str(int(pr['squareFootage']))
                if not result.get('year_built') and pr.get('yearBuilt'): result['year_built'] = str(pr['yearBuilt'])
        except: pass

        if not result:
            return jsonify({'error': 'No data found for this address'}), 404

        result['source'] = 'rentcast'
        return jsonify(result)

    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': f'RentCast lookup failed: {str(e)}'}), 500


@app.route('/api/properties/<int:pid>/refresh-value', methods=['POST'])
def refresh_property_value(pid):
    """Re-fetch RentCast value for an existing property"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    api_key = os.environ.get('RENTCAST_API_KEY','')
    if not api_key: return jsonify({'error': 'RENTCAST_API_KEY not set'}), 422
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM properties WHERE id=%s AND user_id=%s", (pid, uid))
            prop = cur.fetchone()
            cur.close()
        if not prop: return jsonify({'error': 'Property not found'}), 404
        address = prop.get('location') or prop.get('name','')
        if not address: return jsonify({'error': 'No address on file'}), 400
        headers = {'X-Api-Key': api_key, 'Accept': 'application/json'}
        encoded = urllib.parse.quote(address)
        req = urllib.request.Request(f'https://api.rentcast.io/v1/avm/value?address={encoded}', headers=headers)
        resp = urllib.request.urlopen(req, timeout=10)
        d = json.loads(resp.read())
        new_val = int(d.get('price', 0))
        if not new_val: return jsonify({'error': 'No value returned'}), 422
        # Also get rent estimate
        new_rent = None
        try:
            req2 = urllib.request.Request(f'https://api.rentcast.io/v1/avm/rent/long-term?address={encoded}', headers=headers)
            resp2 = urllib.request.urlopen(req2, timeout=10)
            rd = json.loads(resp2.read())
            new_rent = int(rd.get('rent', 0)) or None
        except: pass
        # Update property
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            try:
                if new_rent:
                    cur.execute("UPDATE properties SET zestimate=%s, last_value_refresh=NOW() WHERE id=%s AND user_id=%s RETURNING *", (new_val, pid, uid))
                else:
                    cur.execute("UPDATE properties SET zestimate=%s, last_value_refresh=NOW() WHERE id=%s AND user_id=%s RETURNING *", (new_val, pid, uid))
            except:
                cur.execute("UPDATE properties SET purchase_price=%s WHERE id=%s AND user_id=%s RETURNING *", (new_val, pid, uid))
            updated = dict(cur.fetchone())
            conn.commit(); cur.close()
        try: update_metrics(uid)
        except: pass
        if updated.get('created_at'): updated['created_at'] = updated['created_at'].isoformat()
        updated['new_value'] = new_val
        updated['new_rent'] = new_rent
        return jsonify(updated)
    except urllib.error.HTTPError as e:
        return jsonify({'error': f'RentCast error {e.code}'}), e.code
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/attom/lookup', methods=['POST'])
def attom_lookup():
    """ATTOM API - property AVM + details. Free trial at api.developer.attomdata.com"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    api_key = os.environ.get('ATTOM_API_KEY','')
    if not api_key: return jsonify({'error': 'ATTOM_API_KEY not configured'}), 422
    data = request.json or {}
    address = data.get('address','').strip()
    if not address: return jsonify({'error': 'Address required'}), 400

    # Parse address into parts
    parts = address.split(',')
    address1 = parts[0].strip() if parts else address
    address2 = ','.join(parts[1:]).strip() if len(parts)>1 else ''
    encoded1 = urllib.parse.quote(address1)
    encoded2 = urllib.parse.quote(address2)

    headers = {'apikey': api_key, 'Accept': 'application/json'}
    result = {}
    try:
        # ATTOM AVM endpoint
        avm_url = f'https://api.gateway.attomdata.com/propertyapi/v1.0.0/attomavm/detail?address1={encoded1}&address2={encoded2}'
        req = urllib.request.Request(avm_url, headers=headers)
        resp = urllib.request.urlopen(req, timeout=10)
        d = json.loads(resp.read())
        prop = d.get('property',[{}])[0] if d.get('property') else {}
        avm = prop.get('avm',{})
        if avm.get('amount',{}).get('value'):
            result['zestimate'] = int(avm['amount']['value'])
        if avm.get('amount',{}).get('low'):
            result['value_low'] = int(avm['amount']['low'])
        if avm.get('amount',{}).get('high'):
            result['value_high'] = int(avm['amount']['high'])
        building = prop.get('building',{})
        rooms = building.get('rooms',{})
        if rooms.get('beds'): result['bedrooms'] = str(rooms['beds'])
        if rooms.get('bathstotal'): result['bathrooms'] = str(rooms['bathstotal'])
        size = building.get('size',{})
        if size.get('livingsize'): result['sqft'] = str(int(size['livingsize']))
        if building.get('yearbuilt'): result['year_built'] = str(building['yearbuilt'])
        addr = prop.get('address',{})
        if addr.get('line1'):
            a = addr['line1']
            if addr.get('locality'): a += f", {addr['locality']}"
            if addr.get('countrySubd'): a += f", {addr['countrySubd']}"
            if addr.get('postal1'): a += f" {addr['postal1']}"
            result['address'] = a
        tax = prop.get('assessment',{}).get('tax',{})
        if tax.get('taxamt'): result['monthly_tax'] = round(float(tax['taxamt'])/12)
        result['source'] = 'attom'
        return jsonify(result)
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8','ignore')
        print(f'ATTOM error {e.code}: {body[:200]}')
        if e.code == 401: return jsonify({'error': 'Invalid ATTOM API key'}), 401
        if e.code == 404: return jsonify({'error': f'Property not found in ATTOM: {address}'}), 404
        return jsonify({'error': f'ATTOM error {e.code}'}), e.code
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500


@app.route('/api/property/blended-lookup', methods=['POST'])
def blended_lookup():
    """Calls RentCast + ATTOM in parallel and returns a blended/best estimate"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    address = (request.json or {}).get('address','').strip()
    if not address: return jsonify({'error': 'Address required'}), 400

    results = []
    sources = []

    # Try RentCast
    rc_key = os.environ.get('RENTCAST_API_KEY','')
    if rc_key:
        try:
            encoded = urllib.parse.quote(address)
            headers = {'X-Api-Key': rc_key, 'Accept': 'application/json'}
            req = urllib.request.Request(f'https://api.rentcast.io/v1/avm/value?address={encoded}', headers=headers)
            resp = urllib.request.urlopen(req, timeout=10)
            d = json.loads(resp.read())
            if d.get('price'):
                rc_result = {'value': int(d['price']), 'source': 'RentCast'}
                if d.get('priceLow'): rc_result['low'] = int(d['priceLow'])
                if d.get('priceHigh'): rc_result['high'] = int(d['priceHigh'])
                sp = d.get('subjectProperty',{})
                rc_result.update({k: sp.get(k) for k in ['bedrooms','bathrooms','squareFootage','yearBuilt','propertyType','formattedAddress'] if sp.get(k)})
                results.append(rc_result)
                sources.append('RentCast')
            # Also get rent estimate
            try:
                req2 = urllib.request.Request(f'https://api.rentcast.io/v1/avm/rent/long-term?address={encoded}', headers=headers)
                resp2 = urllib.request.urlopen(req2, timeout=8)
                rd = json.loads(resp2.read())
                if rd.get('rent'): rc_result['rent_estimate'] = int(rd['rent'])
                if rd.get('rentLow'): rc_result['rent_low'] = int(rd['rentLow'])
                if rd.get('rentHigh'): rc_result['rent_high'] = int(rd['rentHigh'])
            except: pass
        except Exception as e:
            print(f'RentCast blended error: {e}')

    # Try ATTOM
    at_key = os.environ.get('ATTOM_API_KEY','')
    if at_key:
        try:
            parts = address.split(',')
            a1 = urllib.parse.quote(parts[0].strip())
            a2 = urllib.parse.quote(','.join(parts[1:]).strip()) if len(parts)>1 else ''
            headers = {'apikey': at_key, 'Accept': 'application/json'}
            req = urllib.request.Request(f'https://api.gateway.attomdata.com/propertyapi/v1.0.0/attomavm/detail?address1={a1}&address2={a2}', headers=headers)
            resp = urllib.request.urlopen(req, timeout=10)
            d = json.loads(resp.read())
            prop = (d.get('property') or [{}])[0]
            avm_val = prop.get('avm',{}).get('amount',{}).get('value')
            if avm_val:
                at_result = {'value': int(avm_val), 'source': 'ATTOM'}
                avm = prop.get('avm',{}).get('amount',{})
                if avm.get('low'): at_result['low'] = int(avm['low'])
                if avm.get('high'): at_result['high'] = int(avm['high'])
                bldg = prop.get('building',{})
                rooms = bldg.get('rooms',{})
                if rooms.get('beds'): at_result['bedrooms'] = rooms['beds']
                if rooms.get('bathstotal'): at_result['bathrooms'] = rooms['bathstotal']
                if bldg.get('size',{}).get('livingsize'): at_result['squareFootage'] = int(bldg['size']['livingsize'])
                if bldg.get('yearbuilt'): at_result['yearBuilt'] = bldg['yearbuilt']
                tax = prop.get('assessment',{}).get('tax',{})
                if tax.get('taxamt'): at_result['monthly_tax'] = round(float(tax['taxamt'])/12)
                results.append(at_result)
                sources.append('ATTOM')
        except Exception as e:
            print(f'ATTOM blended error: {e}')

    if not results:
        return jsonify({'error': 'No API keys configured. Add RENTCAST_API_KEY (required) and optionally ATTOM_API_KEY in Render environment variables.'}), 422

    # Blend values - average if both available
    values = [r['value'] for r in results if r.get('value')]
    blended_value = int(sum(values)/len(values)) if values else None

    # Use best available data (prefer RentCast for rent, ATTOM for tax)
    primary = results[0]
    output = {
        'zestimate': blended_value,
        'value_sources': sources,
        'values_by_source': {r['source']: r['value'] for r in results if r.get('value')},
        'address': primary.get('formattedAddress') or address,
        'bedrooms': str(primary.get('bedrooms','')) if primary.get('bedrooms') else None,
        'bathrooms': str(primary.get('bathrooms','')) if primary.get('bathrooms') else None,
        'sqft': str(int(primary.get('squareFootage',0))) if primary.get('squareFootage') else None,
        'year_built': str(primary.get('yearBuilt','')) if primary.get('yearBuilt') else None,
        'rent_estimate': primary.get('rent_estimate'),
        'rent_low': primary.get('rent_low'),
        'rent_high': primary.get('rent_high'),
        'monthly_tax': primary.get('monthly_tax'),
        'source': ' + '.join(sources),
    }
    # Value range (min of lows, max of highs)
    lows = [r['low'] for r in results if r.get('low')]
    highs = [r['high'] for r in results if r.get('high')]
    if lows: output['value_low'] = min(lows)
    if highs: output['value_high'] = max(highs)
    return jsonify(output)


@app.route('/api/property/lookup')
def property_lookup():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    addr = request.args.get('address','')
    if not addr: return jsonify({'error': 'address required'}), 400
    if not ATTOM_KEY: return jsonify({'error': 'ATTOM not configured'}), 400
    try:
        parts = addr.rsplit(',', 1)
        a1 = urllib.parse.quote(parts[0].strip())
        a2 = urllib.parse.quote(parts[1].strip() if len(parts)>1 else '')
        url = f'https://api.gateway.attomdata.com/propertyapi/v1.0.0/property/detail?address1={a1}&address2={a2}'
        req = urllib.request.Request(url, headers={'apikey': ATTOM_KEY, 'Accept': 'application/json'})
        resp = urllib.request.urlopen(req, timeout=10)
        data = json.loads(resp.read())
        prop = data.get('property',[{}])[0] if data.get('property') else {}
        bldg = prop.get('building',{})
        summary = prop.get('summary',{})
        val = prop.get('avm',{})
        return jsonify({
            'address': addr, 'beds': bldg.get('rooms',{}).get('beds'),
            'baths': bldg.get('rooms',{}).get('bathstotal'),
            'sqft': bldg.get('size',{}).get('livingsize'),
            'year_built': summary.get('yearbuilt'),
            'avm': val.get('amount',{}).get('value'),
            'tax_annual': prop.get('assessment',{}).get('tax',{}).get('taxamt')
        })
    except Exception as e:
        return jsonify({'error': str(e)})

# ── STOCKS ─────────────────────────────────────────────────────────────────────
@app.route('/api/stocks/quote')
def stock_quote():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    ticker = request.args.get('ticker','').upper()
    if not ticker: return jsonify({'error': 'ticker required'}), 400
    try:
        url = f'https://query1.finance.yahoo.com/v8/finance/chart/{ticker}?interval=1d&range=1d'
        req = urllib.request.Request(url, headers={'User-Agent': 'Mozilla/5.0', 'Accept': 'application/json'})
        data = json.loads(urllib.request.urlopen(req, timeout=6).read())
        meta = data.get('chart',{}).get('result',[{}])[0].get('meta',{})
        price = meta.get('regularMarketPrice') or meta.get('previousClose')
        prev = meta.get('previousClose', price)
        return jsonify({'ticker': ticker, 'price': price, 'change_pct': ((price-prev)/prev*100) if prev else 0})
    except Exception as e:
        return jsonify({'error': str(e), 'price': None})

# ── PERFORMANCE ────────────────────────────────────────────────────────────────
@app.route('/api/performance/portfolio/<int:uid>')
def perf_portfolio(uid):
    req_uid = session.get('user_id')
    if not req_uid: return jsonify({'error': 'Not authenticated'}), 401
    months = int(request.args.get('months', 12))
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT snapshot_month::text, total_value, total_equity, net_cashflow,
                   gross_revenue, total_expenses, noi, property_count, avg_cap_rate, avg_cash_on_cash
            FROM monthly_snapshots WHERE user_id=%s
            ORDER BY snapshot_month DESC LIMIT %s
        """, (uid, months))
        snaps = [dict(r) for r in cur.fetchall()]; cur.close()
    return jsonify({'snapshots': list(reversed(snaps))})

@app.route('/api/performance/snapshot', methods=['POST'])
def save_snapshot():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    record_snapshot(uid)
    return jsonify({'ok': True})

# ── PLAID ──────────────────────────────────────────────────────────────────────
PLAID_CLIENT_ID = os.environ.get('PLAID_CLIENT_ID','')
PLAID_SECRET    = os.environ.get('PLAID_SECRET','')
PLAID_ENV       = os.environ.get('PLAID_ENV','production')   # production | sandbox

def plaid_post(path, payload):
    """Helper: POST to Plaid API, returns parsed JSON"""
    body = json.dumps({**payload, "client_id": PLAID_CLIENT_ID, "secret": PLAID_SECRET}).encode()
    req  = urllib.request.Request(
        f"https://{PLAID_ENV}.plaid.com{path}",
        data=body,
        headers={'Content-Type': 'application/json'}
    )
    try:
        resp = urllib.request.urlopen(req, timeout=20)
        return json.loads(resp.read())
    except OSError as e:
        if 'Name or service not known' in str(e) or 'Errno -2' in str(e) or 'Errno 11001' in str(e):
            raise RuntimeError(
                'NETWORK_BLOCKED: Render free tier blocks outbound requests. '
                'Upgrade your Render service to Starter ($7/mo) at dashboard.render.com '
                'to enable outbound network access required for Plaid.'
            )
        raise

@app.route('/api/plaid/create-link-token', methods=['GET','POST'])
def plaid_link():
    """Create a Plaid Link token to initialise the Link flow"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    if not PLAID_CLIENT_ID: return jsonify({'error': 'Plaid not configured — add PLAID_CLIENT_ID, PLAID_SECRET to Render env'}), 400
    # Check for update mode (re-authenticating an existing item)
    d = request.json or {}
    access_token = d.get('access_token')
    try:
        payload = {
            "user": {"client_user_id": str(uid)},
            "client_name": "Property Pigeon",
            "products": ["transactions"],
            "country_codes": ["US"],
            "language": "en",
        }
        if access_token:
            # Update mode — user re-authenticating
            payload.pop("products", None)
            payload["access_token"] = access_token
        data = plaid_post("/link/token/create", payload)
        return jsonify({'link_token': data.get('link_token')})
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8','ignore')
        return jsonify({'error': f'Plaid {e.code}: {body[:300]}'}), e.code
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/exchange-token', methods=['POST'])
def plaid_exchange():
    """Exchange public token for access token, store item"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json or {}
    try:
        data = plaid_post("/item/public_token/exchange", {"public_token": d['public_token']})
        access_token   = data['access_token']
        item_id        = data.get('item_id','')
        inst_name      = d.get('institution_name', '')
        inst_id        = d.get('institution_id', '')

        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            if item_id:
                # Check if item already exists, update if so
                cur.execute("SELECT id FROM plaid_items WHERE item_id=%s AND user_id=%s", (item_id, uid))
                existing = cur.fetchone()
                if existing:
                    cur.execute("""
                        UPDATE plaid_items SET access_token=%s, institution_name=%s, updated_at=CURRENT_TIMESTAMP
                        WHERE item_id=%s AND user_id=%s
                    """, (access_token, inst_name, item_id, uid))
                else:
                    cur.execute("""
                        INSERT INTO plaid_items (user_id, access_token, item_id, institution_name, institution_id)
                        VALUES (%s,%s,%s,%s,%s)
                    """, (uid, access_token, item_id, inst_name, inst_id))
            else:
                cur.execute("""
                    INSERT INTO plaid_items (user_id, access_token, item_id, institution_name, institution_id)
                    VALUES (%s,%s,%s,%s,%s)
                """, (uid, access_token, None, inst_name, inst_id))
            conn.commit(); cur.close()
        return jsonify({'ok': True, 'item_id': item_id})
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8','ignore')
        import traceback; traceback.print_exc()
        return jsonify({'error': f'Plaid {e.code}: {body[:500]}'}), 500
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/accounts')
def plaid_accounts():
    """Return all connected Plaid items + their accounts + balances"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM plaid_items WHERE user_id=%s ORDER BY created_at", (uid,))
            items = [dict(r) for r in cur.fetchall()]; cur.close()

        result = []
        for item in items:
            try:
                data = plaid_post("/accounts/balance/get", {"access_token": item['access_token']})
                accounts = data.get('accounts', [])
                result.append({
                    'item_id':    item['item_id'],
                    'institution': item.get('institution_name','Unknown'),
                    'institution_id': item.get('institution_id',''),
                    'access_token': item['access_token'],  # needed for update mode
                    'needs_update': False,
                    'accounts': [{
                        'id':        a['account_id'],
                        'name':      a['name'],
                        'mask':      a.get('mask',''),
                        'type':      a['type'],
                        'subtype':   a.get('subtype',''),
                        'balance':   a['balances'].get('current') or a['balances'].get('available') or 0,
                        'available': a['balances'].get('available'),
                        'limit':     a['balances'].get('limit'),
                        'currency':  a['balances'].get('iso_currency_code','USD'),
                    } for a in accounts]
                })
            except urllib.error.HTTPError as e:
                body = e.read().decode('utf-8','ignore')
                # ITEM_LOGIN_REQUIRED — bank needs re-auth
                needs_update = 'ITEM_LOGIN_REQUIRED' in body or 'LOGIN_REQUIRED' in body
                result.append({
                    'item_id':    item['item_id'],
                    'institution': item.get('institution_name','Unknown'),
                    'institution_id': item.get('institution_id',''),
                    'access_token': item['access_token'],
                    'needs_update': needs_update,
                    'error': 'Re-authentication required' if needs_update else f'Error {e.code}',
                    'accounts': []
                })
        return jsonify({'items': result})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/transactions', methods=['POST'])
def plaid_transactions():
    """Fetch recent transactions for an item"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json or {}
    access_token = d.get('access_token')
    days = int(d.get('days', 90))
    if not access_token: return jsonify({'error': 'access_token required'}), 400
    import datetime as dt
    end   = dt.date.today().isoformat()
    start = (dt.date.today() - dt.timedelta(days=days)).isoformat()
    try:
        data = plaid_post("/transactions/get", {
            "access_token": access_token,
            "start_date": start, "end_date": end,
            "options": {"count": 250, "include_personal_finance_category": True}
        })
        txns = data.get('transactions', [])
        # Summarise by category
        by_cat = {}
        for t in txns:
            cat = (t.get('personal_finance_category',{}).get('primary') or
                   (t.get('category',[None])[0]) or 'Other')
            amt = t.get('amount', 0)  # Plaid: positive = debit, negative = credit
            by_cat.setdefault(cat, 0)
            by_cat[cat] += amt
        return jsonify({
            'transactions': [{
                'id':     t['transaction_id'],
                'date':   t['date'],
                'name':   t['name'],
                'amount': t['amount'],
                'category': (t.get('personal_finance_category',{}).get('primary') or
                             (t.get('category',['Other'])[0])),
                'pending': t.get('pending', False),
            } for t in txns[:100]],
            'by_category': by_cat,
            'total': len(txns),
            'start': start, 'end': end,
        })
    except urllib.error.HTTPError as e:
        body = e.read().decode('utf-8','ignore')
        return jsonify({'error': f'Plaid {e.code}: {body[:300]}'}), e.code
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/remove', methods=['POST'])
def plaid_remove():
    """Remove a Plaid item (disconnect a bank)"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json or {}
    item_id = d.get('item_id','')
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT access_token FROM plaid_items WHERE item_id=%s AND user_id=%s", (item_id, uid))
            row = cur.fetchone()
            if not row: cur.close(); return jsonify({'error': 'Item not found'}), 404
            access_token = row['access_token']
            try:
                plaid_post("/item/remove", {"access_token": access_token})
            except Exception:
                pass  # Best effort — still remove from DB
            cur.execute("DELETE FROM plaid_items WHERE item_id=%s AND user_id=%s", (item_id, uid))
            conn.commit(); cur.close()
        return jsonify({'ok': True})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ── PLAID TRANSACTION CATEGORIES ─────────────────────────────────────────────

@app.route('/api/plaid/txn-categories', methods=['GET'])
def get_txn_categories():
    """Get all user transaction category overrides"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)

            cur.execute("SELECT * FROM plaid_txn_categories WHERE user_id=%s", (uid,))
            rows = [dict(r) for r in cur.fetchall()]; cur.close()
        return jsonify({'categories': rows})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/txn-categories', methods=['POST'])
def set_txn_category():
    """Override a transaction's category"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json or {}
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS plaid_txn_categories (
                    id SERIAL PRIMARY KEY,
                    user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                    txn_id TEXT NOT NULL,
                    txn_name TEXT,
                    original_category TEXT,
                    user_category TEXT NOT NULL,
                    amount NUMERIC,
                    txn_date DATE,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    UNIQUE(user_id, txn_id)
                )
            """)
            cur.execute("""
                INSERT INTO plaid_txn_categories (user_id, txn_id, txn_name, original_category, user_category, amount, txn_date)
                VALUES (%s,%s,%s,%s,%s,%s,%s)
                ON CONFLICT (user_id, txn_id) DO UPDATE
                  SET user_category=EXCLUDED.user_category, original_category=EXCLUDED.original_category
            """, (uid, d['txn_id'], d.get('txn_name',''), d.get('original_category',''),
                  d['user_category'], d.get('amount',0), d.get('txn_date')))
            conn.commit(); cur.close()
        return jsonify({'ok': True})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/cashflow-summary')
def plaid_cashflow_summary():
    """Compute revenue, expenses, net CF from Plaid transactions with user overrides applied"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        # Get all items
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT access_token FROM plaid_items WHERE user_id=%s", (uid,))
            items = [dict(r) for r in cur.fetchall()]
            cur.execute("SELECT txn_id, user_category FROM plaid_txn_categories WHERE user_id=%s", (uid,))
            overrides = {r['txn_id']: r['user_category'] for r in cur.fetchall()}
            cur.close()

        import datetime as dt
        end   = dt.date.today().isoformat()
        start = (dt.date.today() - dt.timedelta(days=90)).isoformat()

        revenue = 0; mortgage = 0; expenses = 0; internal = 0
        all_txns = []

        for item in items:
            try:
                data = plaid_post("/transactions/get", {
                    "access_token": item['access_token'],
                    "start_date": start, "end_date": end,
                    "options": {"count": 250}
                })
                for t in data.get('transactions', []):
                    tid = t['transaction_id']
                    amt = t['amount']  # positive=debit, negative=credit
                    raw_cat = (t.get('personal_finance_category',{}).get('primary') or
                               (t.get('category',['OTHER'])[0]) or 'OTHER').upper()

                    # Apply user override if exists
                    cat = overrides.get(tid, auto_categorize(t['name'], amt, raw_cat))

                    all_txns.append({
                        'id': tid,
                        'date': t['date'],
                        'name': t['name'],
                        'amount': amt,
                        'raw_category': raw_cat,
                        'category': cat,
                        'pending': t.get('pending', False),
                        'user_overridden': tid in overrides,
                    })

                    if cat == 'INTERNAL_TRANSFER':
                        internal += abs(amt)
                    elif amt < 0:  # credit = money in
                        revenue += abs(amt)
                    elif cat == 'MORTGAGE':
                        mortgage += amt
                    else:
                        expenses += amt
            except Exception:
                pass

        return jsonify({
            'revenue': round(revenue, 2),
            'mortgage': round(mortgage, 2),
            'expenses': round(expenses, 2),
            'internal_transfers': round(internal, 2),
            'net_cashflow': round(revenue - mortgage - expenses, 2),
            'period_days': 90,
            'transactions': sorted(all_txns, key=lambda x: x['date'], reverse=True)
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

def auto_categorize(name, amount, raw_cat):
    """Auto-categorize a transaction based on name and Plaid category"""
    name_up = name.upper()
    # Credits (money coming in)
    if amount < 0:
        if any(x in name_up for x in ['DEPOSIT', 'PAYROLL', 'DIRECT DEP', 'ACH CREDIT', 'ZELLE IN', 'VENMO IN']):
            return 'REVENUE'
        if any(x in name_up for x in ['TRANSFER FROM', 'XFER FROM']):
            return 'INTERNAL_TRANSFER'
        return 'REVENUE'
    # Debits (money going out)
    if any(x in name_up for x in ['MORTGAGE', 'LOAN PMT', 'LOAN PAY', 'HOME LOAN', 'MTG']):
        return 'MORTGAGE'
    if any(x in name_up for x in ['TRANSFER TO', 'XFER TO', 'ZELLE TO', 'ACH BATCH', 'INTERNAL', 'MOVE MONEY']):
        return 'INTERNAL_TRANSFER'
    if any(x in name_up for x in ['INSURANCE', 'HOMEOWNER', 'ALLSTATE', 'STATE FARM', 'GEICO']):
        return 'INSURANCE'
    if any(x in name_up for x in ['HOA', 'HOMEOWNERS ASSOC', 'CONDO FEE']):
        return 'HOA'
    if any(x in name_up for x in ['PROPERTY TAX', 'COUNTY TAX', 'TAX PAYMENT']):
        return 'PROPERTY_TAX'
    if any(x in name_up for x in ['REPAIR', 'MAINTENANCE', 'PLUMBER', 'HVAC', 'CONTRACTOR']):
        return 'MAINTENANCE'
    if raw_cat in ('TRANSFER_IN', 'TRANSFER_OUT'):
        return 'INTERNAL_TRANSFER'
    return 'EXPENSE'

# ── PLAID CONNECTIVITY TEST ───────────────────────────────────────────────────
@app.route('/api/plaid/test')
def plaid_test():
    """Diagnostic: test Plaid connectivity and config"""
    results = {
        'client_id_set': bool(PLAID_CLIENT_ID),
        'secret_set': bool(PLAID_SECRET),
        'env': PLAID_ENV,
        'network': False,
        'auth': False,
        'error': None,
    }
    # Test basic network connectivity
    try:
        test_req = urllib.request.Request(
            f'https://{PLAID_ENV}.plaid.com/link/token/create',
            data=b'{}',
            headers={'Content-Type': 'application/json'}
        )
        urllib.request.urlopen(test_req, timeout=5)
    except urllib.error.HTTPError as e:
        results['network'] = True  # Got a response = network works
        if e.code == 400:
            results['auth'] = True  # 400 = reached Plaid, just bad payload
        elif e.code in (401, 403):
            results['network'] = True
            results['error'] = 'Invalid credentials — check PLAID_CLIENT_ID and PLAID_SECRET'
    except OSError as e:
        results['network'] = False
        results['error'] = f'Network blocked: {e}. Upgrade Render to Starter plan to enable outbound requests.'
    except Exception as e:
        results['error'] = str(e)
    return jsonify(results)

# ── DEBUG ──────────────────────────────────────────────────────────────────────
@app.route('/api/debug/schema')
def debug_schema():
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT table_name,column_name,data_type FROM information_schema.columns WHERE table_schema='public' ORDER BY table_name,ordinal_position")
            rows = cur.fetchall(); cur.close()
        schema = {}
        for t,c,d in rows: schema.setdefault(t,[]).append(f"{c}({d})")
        return jsonify(schema)
    except Exception as e: return jsonify({'error': str(e)})

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1,viewport-fit=cover,maximum-scale=1">
<title>Property Pigeon</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&family=SF+Pro+Display:wght@400;600;700&display=swap" rel="stylesheet">
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;600&display=swap" rel="stylesheet">
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;-webkit-tap-highlight-color:transparent;}
:root{
  --ink:#0a0c10;--ink2:#1c2030;--muted:#6b7280;--dim:#9ca3af;
  --line:rgba(255,255,255,.1);--line2:rgba(0,0,0,.08);
  --blue:#2563eb;--blue-l:#3b82f6;--green:#10b981;--red:#f43f5e;--gold:#f59e0b;
  --glass:rgba(255,255,255,.65);--glassh:rgba(255,255,255,.88);--glassb:rgba(255,255,255,.75);
  --blur:blur(28px) saturate(200%);--blur2:blur(16px) saturate(180%);
  --sh:0 4px 24px rgba(0,0,0,.07),0 1px 4px rgba(0,0,0,.04);
  --sh2:0 16px 48px rgba(0,0,0,.12),0 4px 16px rgba(0,0,0,.06);
  --sh3:0 32px 80px rgba(0,0,0,.18),0 8px 24px rgba(0,0,0,.08);
  --r:14px;--r2:20px;--r3:28px;
  --nav:64px;--top:54px;
  --sb:env(safe-area-inset-bottom,0px);
  --accent:#2563eb;
}
html,body{height:100%;overflow:hidden;background:#f0f4ff;}
body{font-family:'Inter',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;color:var(--ink);-webkit-font-smoothing:antialiased;}
input,button,select,textarea{font-family:'Inter',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;}
*::selection{background:rgba(37,99,235,.15);}

/* ── ANIMATED BG ─────────────────────────────────────────────────────── */
.bg{position:fixed;inset:0;z-index:-1;overflow:hidden;}
.bg::before{content:'';position:absolute;inset:-40%;
  background:radial-gradient(ellipse 80% 60% at 20% 20%,#c7d9ff 0%,transparent 50%),
             radial-gradient(ellipse 60% 80% at 80% 80%,#d1fae5 0%,transparent 50%),
             radial-gradient(ellipse 70% 50% at 50% 60%,#ede9fe 0%,transparent 60%),
             #f0f4ff;
  animation:bgshift 20s ease-in-out infinite alternate;}
.bg::after{content:'';position:absolute;inset:0;
  background:repeating-linear-gradient(0deg,transparent,transparent 48px,rgba(99,102,241,.025) 49px),
             repeating-linear-gradient(90deg,transparent,transparent 48px,rgba(99,102,241,.025) 49px);}
@keyframes bgshift{0%{transform:scale(1) rotate(0deg)}100%{transform:scale(1.1) rotate(3deg)}}

/* ── SCROLLBARS ──────────────────────────────────────────────────────── */
::-webkit-scrollbar{width:3px;height:3px;}
::-webkit-scrollbar-thumb{background:rgba(0,0,0,.12);border-radius:99px;}
::-webkit-scrollbar-track{background:transparent;}

/* ── TYPOGRAPHY ──────────────────────────────────────────────────────── */
.mono{font-family:'JetBrains Mono',ui-monospace,monospace;}
.lbl{font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1px;}
.big-num{font-size:36px;font-weight:800;letter-spacing:-1.5px;line-height:1;}
.med-num{font-size:22px;font-weight:700;letter-spacing:-.5px;}
.sm-num{font-size:15px;font-weight:700;}

/* ── GLASS SURFACES ──────────────────────────────────────────────────── */
.glass{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.7);box-shadow:var(--sh);}
.glass-h{background:var(--glassh);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.9);box-shadow:var(--sh2);}
.glass-card{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.72);border-radius:var(--r2);box-shadow:var(--sh);transition:all .22s cubic-bezier(.34,1.56,.64,1);}
.glass-card:hover{transform:translateY(-3px) scale(1.005);box-shadow:var(--sh2);border-color:rgba(255,255,255,.9);}

/* ── AUTH ─────────────────────────────────────────────────────────────── */
.auth-wrap{display:flex;height:100dvh;overflow:hidden;}
.auth-side{width:340px;flex-shrink:0;position:relative;overflow:hidden;display:flex;flex-direction:column;justify-content:flex-end;padding:40px;}
.auth-side-bg{position:absolute;inset:0;background:linear-gradient(160deg,#1e3a8a 0%,#1d4ed8 40%,#2563eb 70%,#3b82f6 100%);}
.auth-side-bg::after{content:'';position:absolute;inset:0;background:url("data:image/svg+xml,%3Csvg width='60' height='60' viewBox='0 0 60 60' xmlns='http://www.w3.org/2000/svg'%3E%3Cg fill='none' fill-rule='evenodd'%3E%3Cg fill='%23ffffff' fill-opacity='0.04'%3E%3Ccircle cx='30' cy='30' r='20'/%3E%3C/g%3E%3C/g%3E%3C/svg%3E");}
.auth-side-content{position:relative;z-index:2;}
.auth-bird{font-size:52px;margin-bottom:18px;display:block;filter:drop-shadow(0 8px 24px rgba(0,0,0,.3));animation:float 4s ease-in-out infinite;}
@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-8px)}}
.auth-brand{font-size:26px;font-weight:800;color:#fff;letter-spacing:-.5px;margin-bottom:8px;}
.auth-tagline{font-size:13px;color:rgba(255,255,255,.7);line-height:1.6;max-width:240px;}
.auth-main{flex:1;display:flex;align-items:center;justify-content:center;padding:32px 24px;overflow-y:auto;}
.auth-card{width:100%;max-width:400px;background:var(--glassh);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.92);border-radius:var(--r3);padding:36px;box-shadow:var(--sh3),inset 0 1px 0 rgba(255,255,255,.9);}
.auth-eyebrow{font-size:10px;font-weight:700;color:var(--blue);text-transform:uppercase;letter-spacing:2px;margin-bottom:16px;}
.auth-card h2{font-size:26px;font-weight:800;letter-spacing:-.5px;margin-bottom:4px;}
.auth-sub{font-size:13px;color:var(--muted);margin-bottom:24px;}
.auth-field{margin-bottom:14px;}
.auth-field label{display:block;font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:5px;}
.auth-input{width:100%;padding:11px 14px;border:1.5px solid rgba(0,0,0,.1);border-radius:11px;font-size:14px;background:rgba(255,255,255,.8);transition:all .2s;outline:none;color:var(--ink);}
.auth-input:focus{border-color:var(--blue);background:rgba(255,255,255,.95);box-shadow:0 0 0 3px rgba(37,99,235,.12);}
.auth-submit{width:100%;padding:13px;background:linear-gradient(135deg,var(--blue),var(--blue-l));color:#fff;border:none;border-radius:11px;font-size:15px;font-weight:700;cursor:pointer;margin-top:4px;position:relative;overflow:hidden;transition:all .2s;letter-spacing:.2px;}
.auth-submit::before{content:'';position:absolute;inset:0;background:linear-gradient(135deg,rgba(255,255,255,.15),transparent);pointer-events:none;}
.auth-submit:hover{transform:translateY(-1px);box-shadow:0 8px 24px rgba(37,99,235,.4);}
.auth-submit:active{transform:scale(.97);}
.auth-submit:disabled{opacity:.5;cursor:not-allowed;transform:none;}
.auth-switch{background:none;border:none;font-size:13px;color:var(--blue);cursor:pointer;display:block;width:100%;text-align:center;padding:11px;margin-top:6px;font-weight:500;}
.auth-switch:hover{text-decoration:underline;}
.hint-ok{font-size:11px;font-weight:600;color:var(--green);margin-top:4px;}
.hint-bad{font-size:11px;font-weight:600;color:var(--red);margin-top:4px;}

/* ── ALERTS ──────────────────────────────────────────────────────────── */
.alert{border-radius:11px;padding:11px 14px;font-size:13px;margin-bottom:14px;display:flex;align-items:flex-start;gap:8px;}
.alert-err{background:rgba(244,63,94,.07);border:1px solid rgba(244,63,94,.2);color:#be123c;}
.alert-ok{background:rgba(16,185,129,.07);border:1px solid rgba(16,185,129,.2);color:#047857;}
.alert-info{background:rgba(37,99,235,.06);border:1px solid rgba(37,99,235,.15);color:#1d4ed8;}

/* ── SHELL ───────────────────────────────────────────────────────────── */
.shell{display:flex;flex-direction:column;height:100dvh;overflow:hidden;position:relative;}

/* ── TOPBAR ──────────────────────────────────────────────────────────── */
.topbar{
  flex-shrink:0;height:var(--top);padding:0 18px;
  display:flex;align-items:center;justify-content:space-between;
  background:rgba(255,255,255,.6);
  backdrop-filter:var(--blur2);-webkit-backdrop-filter:var(--blur2);
  border-bottom:1px solid rgba(255,255,255,.55);
  position:relative;z-index:30;
}
.topbar-left{display:flex;align-items:center;gap:10px;}
.topbar-logo{font-size:18px;font-weight:800;letter-spacing:-.3px;background:linear-gradient(135deg,var(--blue),var(--blue-l));-webkit-background-clip:text;-webkit-text-fill-color:transparent;background-clip:text;}
.topbar-title{font-size:16px;font-weight:700;letter-spacing:-.2px;}
.topbar-right{display:flex;align-items:center;gap:10px;}
.av-btn{width:36px;height:36px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:13px;font-weight:700;color:#fff;cursor:pointer;box-shadow:0 2px 12px rgba(0,0,0,.25);transition:.2s;border:2px solid rgba(255,255,255,.6);}
.av-btn:hover{transform:scale(1.08);}

/* ── PAGE AREA ───────────────────────────────────────────────────────── */
.page-area{flex:1;overflow:hidden;position:relative;}
.page{height:100%;overflow-y:auto;padding:16px 16px calc(var(--nav) + 20px + var(--sb));overscroll-behavior:contain;}
@keyframes slideUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:translateY(0)}}
@keyframes slideIn{from{opacity:0;transform:translateX(14px)}to{opacity:1;transform:translateX(0)}}
.page-in{animation:slideUp .25s cubic-bezier(.25,.46,.45,.94) both;}
.page-in-r{animation:slideIn .25s cubic-bezier(.25,.46,.45,.94) both;}

/* ── BOTTOM NAV ──────────────────────────────────────────────────────── */
.bottom-nav{
  position:fixed;bottom:0;left:0;right:0;z-index:40;
  height:calc(var(--nav) + var(--sb));padding-bottom:var(--sb);
  background:rgba(255,255,255,.75);
  backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border-top:1px solid rgba(255,255,255,.7);
  display:flex;align-items:center;justify-content:space-around;
  box-shadow:0 -8px 32px rgba(0,0,0,.07);
}
.nav-item{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;cursor:pointer;transition:all .18s;padding:6px 4px;position:relative;-webkit-tap-highlight-color:transparent;}
.nav-item svg{width:22px;height:22px;stroke:var(--dim);transition:all .2s;}
.nav-item span{font-size:9.5px;font-weight:600;color:var(--dim);transition:all .2s;letter-spacing:.3px;}
.nav-item.on svg{stroke:var(--accent);}
.nav-item.on span{color:var(--accent);}
.nav-pip{width:4px;height:4px;border-radius:50%;background:transparent;margin-top:1px;transition:.2s;}
.nav-item.on .nav-pip{background:var(--accent);}
.nav-item:active{transform:scale(.88);}

/* ── SUB NAV (inside tab) ────────────────────────────────────────────── */
.subnav{display:flex;gap:3px;background:rgba(0,0,0,.05);border-radius:13px;padding:3px;margin-bottom:18px;}
.subnav-btn{flex:1;text-align:center;padding:8px 4px;border-radius:10px;font-size:12px;font-weight:600;color:var(--muted);cursor:pointer;transition:all .18s;border:none;background:transparent;}
.subnav-btn.on{background:white;color:var(--ink);box-shadow:0 2px 8px rgba(0,0,0,.1);}

/* ── STAT CARDS ──────────────────────────────────────────────────────── */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;}
.scard{padding:14px 15px;border-radius:var(--r);background:rgba(255,255,255,.62);backdrop-filter:var(--blur2);-webkit-backdrop-filter:var(--blur2);border:1px solid rgba(255,255,255,.8);transition:all .2s;position:relative;overflow:hidden;}
.scard::before{content:'';position:absolute;top:0;left:0;right:0;height:2px;background:var(--accent);opacity:.4;}
.scard:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.08);}
.scard-lbl{font-size:10px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:.8px;margin-bottom:6px;}
.scard-val{font-size:20px;font-weight:800;letter-spacing:-.5px;line-height:1.1;}
.scard-sub{font-size:11px;color:var(--dim);margin-top:4px;}
.scard-delta{font-size:11px;font-weight:600;margin-top:3px;display:flex;align-items:center;gap:3px;}

/* ── HERO ────────────────────────────────────────────────────────────── */
.hero{border-radius:var(--r3);padding:24px 22px 20px;margin-bottom:14px;position:relative;overflow:hidden;}
.hero-glass{background:rgba(255,255,255,.55);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.72);box-shadow:var(--sh2);}
.hero-lbl{font-size:11px;font-weight:600;color:rgba(255,255,255,.7);text-transform:uppercase;letter-spacing:1.2px;margin-bottom:6px;}
.hero-lbl-dark{font-size:11px;font-weight:600;color:var(--muted);text-transform:uppercase;letter-spacing:1.2px;margin-bottom:6px;}
.hero-val{font-size:40px;font-weight:800;letter-spacing:-2px;line-height:1;color:#fff;}
.hero-val-dark{font-size:38px;font-weight:800;letter-spacing:-2px;line-height:1;}
.hero-sub{font-size:13px;color:rgba(255,255,255,.7);margin-top:6px;}
.hero-sub-dark{font-size:13px;color:var(--muted);margin-top:6px;}
.hero-chart{height:72px;margin:14px 0 4px;}
.hero-gradient{background:linear-gradient(135deg,var(--accent) 0%,#6366f1 100%);}

/* ── HEALTH RING ─────────────────────────────────────────────────────── */
.ring-wrap{position:relative;display:inline-flex;align-items:center;justify-content:center;}
.ring-inner{position:absolute;text-align:center;}

/* ── PROPERTY ROWS ───────────────────────────────────────────────────── */
.prop-row{
  display:flex;align-items:center;gap:13px;padding:14px 15px;
  border-radius:var(--r2);margin-bottom:8px;cursor:pointer;
  background:rgba(255,255,255,.6);
  backdrop-filter:var(--blur2);-webkit-backdrop-filter:var(--blur2);
  border:1px solid rgba(255,255,255,.78);
  transition:all .22s cubic-bezier(.34,1.56,.64,1);
  position:relative;overflow:hidden;
}
.prop-row::before{content:'';position:absolute;left:0;top:0;bottom:0;width:3px;background:var(--accent);opacity:.7;border-radius:0 2px 2px 0;}
.prop-row:hover{background:rgba(255,255,255,.92);transform:translateX(4px) translateY(-2px);box-shadow:var(--sh2);}
.prop-icon{width:44px;height:44px;border-radius:13px;display:flex;align-items:center;justify-content:center;font-size:20px;flex-shrink:0;}
.prop-name{font-size:14px;font-weight:700;line-height:1.2;}
.prop-loc{font-size:11px;color:var(--muted);margin-top:2px;}
.prop-meta{font-size:11px;color:var(--blue);font-weight:600;margin-top:3px;}

/* ── TIMELINE / SNAPSHOTS ────────────────────────────────────────────── */
.snap-row{display:flex;align-items:center;padding:12px 15px;border-radius:12px;background:rgba(255,255,255,.5);margin-bottom:5px;gap:12px;cursor:pointer;transition:.18s;}
.snap-row:hover{background:rgba(255,255,255,.82);transform:translateX(3px);}
.snap-month{font-size:13px;font-weight:700;min-width:90px;}
.snap-val{font-size:13px;font-weight:600;text-align:right;}
.snap-delta{font-size:11px;font-weight:700;text-align:right;display:flex;align-items:center;justify-content:flex-end;gap:2px;}
.delta-up{color:var(--green);}
.delta-dn{color:var(--red);}
.delta-flat{color:var(--muted);}

/* ── CF ROWS ─────────────────────────────────────────────────────────── */
.cf-row{display:flex;justify-content:space-between;align-items:center;padding:10px 14px;border-radius:10px;background:rgba(255,255,255,.48);margin-bottom:5px;transition:.15s;}
.cf-row:hover{background:rgba(255,255,255,.72);}
.cf-row.cf-total{background:rgba(37,99,235,.06);border:1px solid rgba(37,99,235,.15);}
.cf-lbl{font-size:13px;font-weight:500;}
.cf-val{font-size:13px;font-weight:700;font-family:'JetBrains Mono',ui-monospace,monospace;}

/* ── SLIDERS ─────────────────────────────────────────────────────────── */
.slider-block{margin-bottom:20px;}
.slider-hdr{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:8px;}
.slider-name{font-size:13px;font-weight:600;}
.slider-val{font-size:16px;font-weight:800;color:var(--accent);font-family:'JetBrains Mono',ui-monospace,monospace;}
.slider-track{position:relative;height:6px;border-radius:99px;background:var(--line2);}
.slider-fill{position:absolute;left:0;top:0;height:100%;border-radius:99px;background:linear-gradient(90deg,var(--accent),var(--blue-l));pointer-events:none;}
.slider-input{position:absolute;inset:0;width:100%;opacity:0;height:24px;top:-9px;cursor:pointer;-webkit-appearance:none;appearance:none;}
.slider-thumb{
  position:absolute;width:24px;height:24px;border-radius:50%;top:50%;transform:translate(-50%,-50%);
  background:white;box-shadow:0 2px 12px rgba(37,99,235,.35),0 0 0 3px var(--accent);
  pointer-events:none;transition:box-shadow .15s,transform .15s;
}
.slider-track:has(.slider-input:active) .slider-thumb{transform:translate(-50%,-50%) scale(1.15);box-shadow:0 4px 20px rgba(37,99,235,.5),0 0 0 4px var(--accent);}

/* ── PROJ TABLE ──────────────────────────────────────────────────────── */
.proj-table{width:100%;border-collapse:collapse;font-size:12px;}
.proj-table th{padding:9px 12px;text-align:right;font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.6px;border-bottom:1px solid var(--line2);}
.proj-table th:first-child{text-align:left;}
.proj-table td{padding:8px 12px;text-align:right;border-bottom:1px solid rgba(0,0,0,.03);font-family:'JetBrains Mono',ui-monospace,monospace;font-size:11.5px;transition:.1s;}
.proj-table td:first-child{text-align:left;font-family:'Inter',-apple-system,BlinkMacSystemFont,system-ui,sans-serif;font-size:12px;font-weight:700;}
.proj-table tr:hover td{background:rgba(37,99,235,.03);}
.proj-table tr.milestone td{background:rgba(37,99,235,.05);font-weight:600;}
.proj-table tr.milestone td:first-child{color:var(--blue);}

/* ── SEARCH ──────────────────────────────────────────────────────────── */
.search-wrap{position:relative;margin-bottom:18px;}
.search-wrap svg{position:absolute;left:14px;top:50%;transform:translateY(-50%);width:17px;height:17px;stroke:var(--dim);pointer-events:none;}
.search-inp{width:100%;padding:12px 14px 12px 42px;border:1.5px solid rgba(255,255,255,.7);border-radius:var(--r2);font-size:14px;background:rgba(255,255,255,.78);backdrop-filter:var(--blur2);-webkit-backdrop-filter:var(--blur2);transition:all .2s;outline:none;color:var(--ink);box-shadow:var(--sh);}
.search-inp:focus{border-color:var(--blue);background:rgba(255,255,255,.95);box-shadow:0 0 0 3px rgba(37,99,235,.1),var(--sh2);}
.user-card{
  display:flex;align-items:center;gap:13px;padding:14px 16px;
  border-radius:var(--r2);margin-bottom:8px;cursor:pointer;
  background:rgba(255,255,255,.62);
  backdrop-filter:var(--blur2);-webkit-backdrop-filter:var(--blur2);
  border:1px solid rgba(255,255,255,.8);
  transition:all .2s cubic-bezier(.34,1.56,.64,1);
}
.user-card:hover{background:rgba(255,255,255,.92);transform:translateY(-2px);box-shadow:var(--sh2);}
.ticker-pill{display:inline-flex;align-items:center;padding:3px 9px;background:rgba(37,99,235,.1);color:var(--blue);border-radius:20px;font-size:10px;font-weight:700;letter-spacing:.5px;font-family:'JetBrains Mono',ui-monospace,monospace;}

/* ── PROFILE (PUBLIC) ────────────────────────────────────────────────── */
.profile-cover{height:130px;border-radius:var(--r2) var(--r2) 0 0;position:relative;overflow:hidden;}
.profile-cover-inner{position:absolute;inset:0;background:linear-gradient(135deg,var(--accent) 0%,#6366f1 100%);}
.profile-cover-grain{position:absolute;inset:0;opacity:.4;background-image:url("data:image/svg+xml,%3Csvg viewBox='0 0 256 256' xmlns='http://www.w3.org/2000/svg'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='.85' numOctaves='4'/%3E%3C/filter%3E%3Crect width='100%25' height='100%25' filter='url(%23n)' opacity='.4'/%3E%3C/svg%3E");}
.profile-av-wrap{position:relative;margin:-32px 0 0 20px;margin-bottom:12px;}
.profile-av{width:64px;height:64px;border-radius:50%;border:3px solid white;display:flex;align-items:center;justify-content:center;font-size:22px;font-weight:800;color:#fff;box-shadow:var(--sh2);}
.profile-card{border-radius:0 0 var(--r2) var(--r2);background:rgba(255,255,255,.7);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.8);border-top:none;padding:0 20px 20px;margin-bottom:14px;box-shadow:var(--sh);}
.profile-name{font-size:22px;font-weight:800;letter-spacing:-.4px;}
.profile-meta{font-size:13px;color:var(--muted);margin-top:3px;display:flex;align-items:center;gap:8px;flex-wrap:wrap;}
.profile-bio{font-size:13px;color:var(--ink2);margin-top:10px;line-height:1.6;}

/* ── BTNS ────────────────────────────────────────────────────────────── */
.btn{padding:10px 18px;border-radius:11px;font-size:13px;font-weight:700;border:none;cursor:pointer;transition:all .18s;display:inline-flex;align-items:center;gap:6px;letter-spacing:.1px;}
.btn:hover:not(:disabled){transform:translateY(-1px);}
.btn:active:not(:disabled){transform:scale(.95);}
.btn:disabled{opacity:.45;cursor:not-allowed;}
.btn-prime{background:linear-gradient(135deg,var(--accent),var(--blue-l));color:#fff;box-shadow:0 4px 16px rgba(37,99,235,.3);}
.btn-prime:hover{box-shadow:0 8px 24px rgba(37,99,235,.4);}
.btn-ghost{background:rgba(0,0,0,.05);color:var(--ink2);}
.btn-ghost:hover{background:rgba(0,0,0,.09);}
.btn-outline{background:transparent;border:1.5px solid rgba(0,0,0,.12);color:var(--ink2);}
.btn-outline:hover{border-color:var(--blue);color:var(--blue);}
.btn-danger{background:rgba(244,63,94,.08);color:#be123c;border:1.5px solid rgba(244,63,94,.2);}
.btn-danger:hover{background:rgba(244,63,94,.14);}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:8px;}
.btn-follow{padding:6px 16px;border-radius:20px;font-size:12px;font-weight:700;border:1.5px solid var(--accent);background:transparent;color:var(--accent);cursor:pointer;transition:all .18s;}
.btn-follow.on{background:var(--accent);color:#fff;border-color:transparent;}
.btn-follow:hover{transform:scale(1.04);}

/* ── MODAL / SHEET ───────────────────────────────────────────────────── */
.overlay{position:fixed;inset:0;background:rgba(10,12,24,.5);backdrop-filter:blur(10px);-webkit-backdrop-filter:blur(10px);z-index:100;display:flex;align-items:flex-end;justify-content:center;}
@media(min-width:580px){.overlay{align-items:center;padding:20px;}}
@keyframes sheetUp{from{opacity:0;transform:translateY(30px) scale(.97)}to{opacity:1;transform:translateY(0) scale(1)}}
.sheet{
  background:var(--glassh);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border:1px solid rgba(255,255,255,.9);
  border-radius:var(--r3) var(--r3) 0 0;
  width:100%;max-width:580px;max-height:92dvh;overflow-y:auto;
  padding:10px 22px calc(28px + var(--sb));
  box-shadow:0 -16px 60px rgba(0,0,0,.18);
  animation:sheetUp .26s cubic-bezier(.34,1.56,.64,1);
}
@media(min-width:580px){.sheet{border-radius:var(--r3);max-height:88dvh;padding:28px;}}
.sheet-handle{width:40px;height:4px;background:rgba(0,0,0,.12);border-radius:99px;margin:0 auto 20px;}
.sheet h3{font-size:18px;font-weight:800;letter-spacing:-.3px;margin-bottom:4px;}
.sheet-sub{font-size:13px;color:var(--muted);margin-bottom:20px;}
.sheet-foot{display:flex;gap:8px;margin-top:22px;}
.form-row{margin-bottom:13px;}
.form-row label{display:block;font-size:10px;font-weight:700;color:var(--muted);text-transform:uppercase;letter-spacing:.7px;margin-bottom:5px;}
.form-2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:13px;}
.sinput{width:100%;padding:10px 13px;border:1.5px solid rgba(0,0,0,.1);border-radius:10px;font-size:14px;background:rgba(255,255,255,.78);transition:all .18s;outline:none;color:var(--ink);}
.sinput:focus{border-color:var(--blue);background:rgba(255,255,255,.98);box-shadow:0 0 0 3px rgba(37,99,235,.1);}

/* ── ZILLOW CTA ──────────────────────────────────────────────────────── */
.zillow-cta{background:linear-gradient(135deg,rgba(37,99,235,.07),rgba(99,102,241,.07));border:1.5px solid rgba(37,99,235,.14);border-radius:var(--r);padding:18px;margin-bottom:18px;}
.zillow-cta h4{font-size:13px;font-weight:700;color:var(--blue);margin-bottom:4px;display:flex;align-items:center;gap:6px;}
.zillow-cta p{font-size:12px;color:var(--muted);line-height:1.55;}
.back-btn{background:none;border:none;font-size:12px;color:var(--muted);cursor:pointer;display:flex;align-items:center;gap:4px;margin-bottom:14px;padding:0;font-weight:600;transition:.15s;}
.back-btn:hover{color:var(--ink);}
.manual-link{background:none;border:none;font-size:11px;color:var(--dim);cursor:pointer;display:block;width:100%;text-align:center;padding:10px;margin-top:8px;transition:.15s;}
.manual-link:hover{color:var(--muted);}

/* ── PLAID CTA ───────────────────────────────────────────────────────── */
.plaid-cta{
  border:2px dashed rgba(37,99,235,.2);border-radius:var(--r2);
  padding:36px 24px;text-align:center;cursor:pointer;transition:all .2s;
  background:rgba(255,255,255,.4);
}
.plaid-cta:hover{background:rgba(255,255,255,.75);border-style:solid;border-color:var(--blue);transform:translateY(-2px);box-shadow:var(--sh2);}

/* ── NET WORTH BAR ───────────────────────────────────────────────────── */
.nw-bar{height:8px;border-radius:99px;overflow:hidden;display:flex;gap:2px;margin:12px 0;}
.nw-seg{border-radius:99px;min-width:4px;transition:width .5s cubic-bezier(.25,.46,.45,.94);}

/* ── SWATCH ──────────────────────────────────────────────────────────── */
.swatch-row{display:flex;gap:8px;flex-wrap:wrap;}
.swatch{width:30px;height:30px;border-radius:8px;cursor:pointer;transition:all .15s;position:relative;}
.swatch::after{content:'';position:absolute;inset:-3px;border-radius:10px;border:2px solid transparent;transition:.15s;}
.swatch.on::after,.swatch:hover::after{border-color:rgba(0,0,0,.3);}

/* ── SECTION HEADER ──────────────────────────────────────────────────── */
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.sec-hdr h4{font-size:15px;font-weight:700;letter-spacing:-.2px;}

/* ── EMPTY STATES ────────────────────────────────────────────────────── */
.empty{text-align:center;padding:52px 20px;}
.empty-icon{font-size:44px;margin-bottom:12px;opacity:.6;}
.empty-title{font-size:16px;font-weight:700;margin-bottom:6px;}
.empty-sub{font-size:13px;color:var(--muted);line-height:1.5;margin-bottom:20px;}

/* ── QUARTERLY ──────────────────────────────────────────────────────────── */
.qtr-banner{background:linear-gradient(135deg,#0f172a,#1e3a5f);border-radius:16px;padding:16px 18px;color:#fff;margin-bottom:14px;}
.q-up{color:#6ee7b7;background:rgba(16,185,129,.2);padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;display:inline-block;}
.q-down{color:#fca5a5;background:rgba(239,68,68,.2);padding:2px 8px;border-radius:20px;font-size:11px;font-weight:700;display:inline-block;}
</style>
</head>
<body>
<div class="bg"></div>
<div id="root"></div>
<script type="text/babel">
const {useState,useEffect,useRef,useCallback,useMemo}=React;


// ── QUARTERLY RESULTS COMPONENTS ─────────────────────────────────────────────

// Compact badge used in property cards and overview rows
function QBadge({label,value,delta,deltaLabel,color='var(--accent)',mono=true}){
  const pos=delta>0,neg=delta<0;
  return(
    <div style={{display:'flex',flexDirection:'column',alignItems:'center',gap:2}}>
      <div style={{fontSize:10,color:'var(--muted)',textTransform:'uppercase',letterSpacing:.5,whiteSpace:'nowrap'}}>{label}</div>
      <div style={{fontSize:15,fontWeight:800,fontFamily:mono?'JetBrains Mono':'inherit',color}}>{value}</div>
      {delta!=null&&<div style={{fontSize:10,fontWeight:700,
        color:pos?'#10b981':neg?'#ef4444':'var(--muted)',
        background:pos?'rgba(16,185,129,.1)':neg?'rgba(239,68,68,.08)':'rgba(0,0,0,.04)',
        padding:'1px 6px',borderRadius:20,whiteSpace:'nowrap'}}>
        {pos?'▲':'▼'} {Math.abs(delta).toFixed(delta>-10&&delta<100?1:0)}{deltaLabel||''}
      </div>}
    </div>
  );
}

// Full quarterly results strip — used inside Overview, Analytics, Portfolio
function QuarterlyStrip({uid, accent='#2563eb', compact=false}){
  const [data,setData]=useState(null);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{
    fetch(`/api/quarterly/results/${uid}`,{credentials:'include'})
      .then(r=>r.json()).then(d=>{setData(d);setLoading(false);}).catch(()=>setLoading(false));
  },[uid]);

  if(loading) return <div style={{padding:'12px 0',textAlign:'center',color:'var(--muted)',fontSize:12}}>Loading…</div>;
  if(!data||!data.quarters?.length) return(
    <div style={{padding:'14px',textAlign:'center',color:'var(--muted)',fontSize:12,borderRadius:12,background:'rgba(0,0,0,.03)'}}>
      No quarterly data yet — save a performance snapshot in Analytics to begin tracking
    </div>
  );

  const qs=data.quarters;
  const cur=qs[0]; // most recent
  const prev=qs[1];

  if(compact){
    // Compact 2-row strip: current quarter headline + QoQ change
    const rev=+cur.gross_revenue||0;
    const cf=+cur.net_cashflow||0;
    const val=+cur.total_value||0;
    const revQoQ=prev?(rev-(+prev.gross_revenue||0)):null;
    const cfQoQ=prev?(cf-(+prev.net_cashflow||0)):null;
    return(
      <div style={{background:'rgba(0,0,0,.025)',borderRadius:14,padding:'12px 16px',marginBottom:12}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:8}}>
          <div style={{fontSize:11,fontWeight:800,color:'var(--muted)',letterSpacing:.5}}>
            {cur.full_label} RESULTS
          </div>
          {cur.value_yoy_pct!=null&&<div style={{fontSize:11,fontWeight:700,
            color:cur.value_yoy_pct>=0?'#10b981':'#ef4444',
            background:cur.value_yoy_pct>=0?'rgba(16,185,129,.1)':'rgba(239,68,68,.08)',
            padding:'2px 8px',borderRadius:20}}>
            {cur.value_yoy_pct>=0?'▲':'▼'} {Math.abs(cur.value_yoy_pct).toFixed(1)}% YoY
          </div>}
        </div>
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10}}>
          <QBadge label="Revenue" value={fmt$k(rev)} delta={revQoQ?revQoQ/1000:null} deltaLabel="K" color={accent}/>
          <QBadge label="Net CF" value={fmt$s(cf)} delta={cfQoQ?cfQoQ/1000:null} deltaLabel="K" color={cf>=0?'#10b981':'#ef4444'}/>
          <QBadge label="Value" value={fmt$k(val)} delta={cur.value_qoq?cur.value_qoq/1000:null} deltaLabel="K" color="var(--fg)"/>
        </div>
      </div>
    );
  }

  // Full quarterly results table + chart
  const chartVals=qs.slice(0,8).reverse().map(q=>+q.net_cashflow||0);
  const chartLabels=qs.slice(0,8).reverse().map(q=>q.label);
  const revChart=qs.slice(0,8).reverse().map(q=>+q.gross_revenue||0);

  return(
    <div>
      {/* Big headline card */}
      <div style={{background:`linear-gradient(135deg,${accent} 0%,${accent}bb 100%)`,
        borderRadius:18,padding:'20px 20px',marginBottom:14,position:'relative',overflow:'hidden'}}>
        <div style={{position:'absolute',top:-20,right:-20,width:100,height:100,
          borderRadius:'50%',background:'rgba(255,255,255,.06)'}}/>
        <div style={{position:'absolute',bottom:-30,left:-10,width:80,height:80,
          borderRadius:'50%',background:'rgba(255,255,255,.04)'}}/>
        <div style={{position:'relative'}}>
          <div style={{fontSize:11,color:'rgba(255,255,255,.6)',fontWeight:700,letterSpacing:.8,marginBottom:6}}>
            LATEST QUARTERLY RESULTS
          </div>
          <div style={{fontSize:26,fontWeight:900,color:'#fff',letterSpacing:'-1px',marginBottom:2}}>
            {cur.full_label}
          </div>
          <div style={{fontSize:13,color:'rgba(255,255,255,.7)',marginBottom:16}}>
            {cur.property_count} {+cur.property_count===1?'property':'properties'}
            {cur.value_yoy_pct!=null&&<span style={{marginLeft:8,fontWeight:700,
              color:cur.value_yoy_pct>=0?'#6ee7b7':'#fca5a5'}}>
              {cur.value_yoy_pct>=0?'▲':'▼'} {Math.abs(cur.value_yoy_pct).toFixed(1)}% YoY
            </span>}
          </div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12}}>
            {[
              ['Revenue',fmt$k(cur.gross_revenue),null],
              ['Net CF',fmt$s(cur.net_cashflow),cur.cf_qoq],
              ['Portfolio',fmt$k(cur.total_value),cur.value_qoq],
            ].map(([lbl,val,dlt])=>(
              <div key={lbl} style={{background:'rgba(255,255,255,.12)',borderRadius:12,padding:'10px 12px'}}>
                <div style={{fontSize:10,color:'rgba(255,255,255,.55)',marginBottom:4}}>{lbl}</div>
                <div style={{fontSize:17,fontWeight:800,color:'#fff',fontFamily:'JetBrains Mono'}}>{val}</div>
                {dlt!=null&&<div style={{fontSize:10,fontWeight:700,marginTop:4,
                  color:dlt>=0?'#6ee7b7':'#fca5a5'}}>
                  {dlt>=0?'▲':'▼'} {fmt$k(Math.abs(dlt))} QoQ
                </div>}
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Net CF bar chart */}
      {chartVals.length>1&&<div className="glass-card" style={{padding:'18px',marginBottom:12}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
          <div style={{fontSize:12,fontWeight:700}}>Quarterly Net Cash Flow</div>
          <div style={{fontSize:11,color:'var(--muted)'}}>Last {chartVals.length} quarters</div>
        </div>
        <BarChart data={chartVals} labels={chartLabels} color={accent} height={110}/>
      </div>}

      {/* Revenue bar chart */}
      {revChart.length>1&&<div className="glass-card" style={{padding:'18px',marginBottom:12}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:12}}>
          <div style={{fontSize:12,fontWeight:700}}>Quarterly Revenue</div>
        </div>
        <BarChart data={revChart} labels={chartLabels} color="#10b981" height={110}/>
      </div>}

      {/* Quarterly table */}
      <div className="glass-card" style={{padding:0,overflow:'hidden',marginBottom:12}}>
        <div style={{overflowX:'auto'}}>
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
            <thead><tr style={{borderBottom:'1px solid rgba(0,0,0,.07)',background:'rgba(0,0,0,.02)'}}>
              {['Quarter','Value','Equity','Revenue','Net CF','QoQ CF','YoY'].map(h=>(
                <th key={h} style={{padding:'10px 13px',textAlign:h==='Quarter'?'left':'right',
                  fontWeight:700,color:'var(--muted)',fontSize:10,textTransform:'uppercase',
                  letterSpacing:.6,whiteSpace:'nowrap'}}>{h}</th>
              ))}
            </tr></thead>
            <tbody>{qs.map((q,i)=>(
              <tr key={i} style={{borderBottom:'1px solid rgba(0,0,0,.04)',
                background:i===0?`${accent}08`:'transparent'}}>
                <td style={{padding:'10px 13px',fontWeight:i===0?800:600,fontSize:13,
                  color:i===0?accent:'var(--fg)',whiteSpace:'nowrap'}}>
                  {q.full_label}
                </td>
                <td style={{padding:'10px 13px',textAlign:'right',fontFamily:'JetBrains Mono',fontWeight:600}}>{fmt$k(q.total_value)}</td>
                <td style={{padding:'10px 13px',textAlign:'right',fontFamily:'JetBrains Mono',color:'var(--green)'}}>{fmt$k(q.total_equity)}</td>
                <td style={{padding:'10px 13px',textAlign:'right',fontFamily:'JetBrains Mono',color:'var(--green)'}}>{fmt$k(q.gross_revenue)}</td>
                <td style={{padding:'10px 13px',textAlign:'right',fontFamily:'JetBrains Mono',fontWeight:700,
                  color:+q.net_cashflow>=0?'#10b981':'#ef4444'}}>{fmt$s(q.net_cashflow)}</td>
                <td style={{padding:'10px 13px',textAlign:'right'}}>
                  {q.cf_qoq!=null
                    ?<span style={{fontSize:11,fontWeight:700,color:q.cf_qoq>=0?'#10b981':'#ef4444'}}>
                        {q.cf_qoq>=0?'▲':'▼'}{fmt$k(Math.abs(q.cf_qoq))}
                      </span>
                    :<span style={{color:'var(--dim)',fontSize:11}}>—</span>}
                </td>
                <td style={{padding:'10px 13px',textAlign:'right'}}>
                  {q.value_yoy_pct!=null
                    ?<span style={{fontSize:11,fontWeight:700,color:q.value_yoy_pct>=0?'#10b981':'#ef4444'}}>
                        {q.value_yoy_pct>=0?'▲':'▼'}{Math.abs(q.value_yoy_pct).toFixed(1)}%
                      </span>
                    :<span style={{color:'var(--dim)',fontSize:11}}>—</span>}
                </td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>
    </div>
  );
}

// ── UTILS ────────────────────────────────────────────────────────────────────
const fmt$=v=>v==null?'—':'$'+Math.abs(+v).toLocaleString('en-US',{maximumFractionDigits:0});
const fmt$s=v=>v==null?'—':((+v<0?'-':'')+fmt$(v));
const fmt$k=v=>{if(v==null)return'—';const a=Math.abs(+v);const s=+v<0?'-':'';return a>=1e6?s+'$'+(a/1e6).toFixed(1)+'M':a>=1e3?s+'$'+(a/1e3).toFixed(0)+'K':fmt$s(v);};
const clr=v=>+v>0?'var(--green)':+v<0?'var(--red)':'var(--muted)';
const arrow=v=>+v>0?'↑':+v<0?'↓':'';
const initials=s=>(s||'').split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,2)||'??';
const monthName=s=>{
  if(!s)return'—';
  const d=new Date(s+'T00:00:00');
  return d.toLocaleString('en-US',{month:'long',year:'numeric'});
};
const monthShort=s=>{
  if(!s)return'—';
  const d=new Date(s+'T00:00:00');
  return d.toLocaleString('en-US',{month:'short',year:'2-digit'});
};
const deltaStyle=v=>({color:+v>0?'var(--green)':+v<0?'var(--red)':'var(--muted)',display:'flex',alignItems:'center',gap:2,fontSize:11,fontWeight:700});

// ── MINI LINE CHART ──────────────────────────────────────────────────────────
function MiniLine({data=[],color='#2563eb',height=72,fill=true}){
  const ref=useRef();const inst=useRef();
  useEffect(()=>{
    if(!ref.current)return;
    if(inst.current)inst.current.destroy();
    if(data.length<2)return;
    inst.current=new Chart(ref.current,{type:'line',
      data:{labels:data.map((_,i)=>i),datasets:[{data,borderColor:color,borderWidth:2.5,
        fill,backgroundColor:fill?color+'18':'transparent',tension:.4,pointRadius:0,pointHoverRadius:0}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{enabled:false}},
        scales:{x:{display:false},y:{display:false}},animation:{duration:600,easing:'easeInOutCubic'}}});
    return()=>{if(inst.current){inst.current.destroy();inst.current=null;}};
  },[JSON.stringify(data),color,fill]);
  return <canvas ref={ref} style={{width:'100%',height}}/>;
}

// ── BAR CHART ────────────────────────────────────────────────────────────────
function BarChart({data=[],labels=[],color='#2563eb',height=120}){
  const ref=useRef();const inst=useRef();
  useEffect(()=>{
    if(!ref.current||data.length<1)return;
    if(inst.current){inst.current.destroy();inst.current=null;}
    inst.current=new Chart(ref.current,{type:'bar',
      data:{labels,datasets:[{data,
        backgroundColor:data.map(v=>+v>=0?color+'bb':color2+'bb'),
        borderRadius:4,borderSkipped:false,maxBarThickness:40}]},
      options:{responsive:false,maintainAspectRatio:false,
        plugins:{legend:{display:false},tooltip:{callbacks:{label:ctx=>' '+fmt$k(ctx.parsed.y)}}},
        scales:{x:{display:true,grid:{display:false},ticks:{font:{size:9},color:'rgba(0,0,0,.4)',maxRotation:0}},
          y:{display:true,grid:{color:'rgba(0,0,0,.04)'},ticks:{font:{size:9},color:'rgba(0,0,0,.4)',callback:v=>fmt$k(v)}}},
        animation:{duration:500}}});
    return()=>{if(inst.current){inst.current.destroy();inst.current=null;}};
  },[JSON.stringify(data),JSON.stringify(labels),color]);
  return <div style={{width:'100%',height,position:'relative'}}><canvas ref={ref} style={{position:'absolute',inset:0,width:'100%!important',height:'100%!important'}}/></div>;
}
const color2='#f43f5e';

// ── HEALTH RING ──────────────────────────────────────────────────────────────
function HealthRing({score=0,size=76}){
  const r=30,c=2*Math.PI*r,dash=c*(score/100);
  const col=score>=70?'#10b981':score>=40?'#f59e0b':'#f43f5e';
  return(
    <div className="ring-wrap" style={{width:size,height:size}}>
      <svg width={size} height={size} viewBox="0 0 72 72">
        <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(0,0,0,.07)" strokeWidth="6"/>
        <circle cx="36" cy="36" r={r} fill="none" stroke={col} strokeWidth="6"
          strokeDasharray={`${dash} ${c-dash}`} strokeDashoffset={c*.25} strokeLinecap="round"
          style={{transition:'stroke-dasharray .6s cubic-bezier(.25,.46,.45,.94)'}}/>
      </svg>
      <div className="ring-inner">
        <div style={{fontSize:17,fontWeight:800,color:col,lineHeight:1}}>{score}</div>
        <div style={{fontSize:8,fontWeight:700,textTransform:'uppercase',letterSpacing:.6,color:'var(--muted)'}}>score</div>
      </div>
    </div>
  );
}

// ── SMOOTH SLIDER ────────────────────────────────────────────────────────────
function Slider({label,value,set,min,max,step,fmt}){
  const pct=((value-min)/(max-min)*100).toFixed(1);
  return(
    <div className="slider-block">
      <div className="slider-hdr">
        <span className="slider-name">{label}</span>
        <span className="slider-val">{fmt(value)}</span>
      </div>
      <div className="slider-track">
        <div className="slider-fill" style={{width:pct+'%'}}/>
        <div className="slider-thumb" style={{left:pct+'%'}}/>
        <input type="range" className="slider-input" min={min} max={max} step={step} value={value}
          onChange={e=>set(+e.target.value)}
          onInput={e=>set(+e.target.value)}
          style={{position:'absolute',inset:0,width:'100%',height:24,top:-9,cursor:'pointer',WebkitAppearance:'none',appearance:'none',background:'transparent',margin:0,padding:0}}/>
      </div>
    </div>
  );
}

// ── AUTH ─────────────────────────────────────────────────────────────────────
function AuthScreen({onLogin}){
  const [mode,setMode]=useState('login');
  const [err,setErr]=useState('');
  const [loading,setLoading]=useState(false);
  const [tickerOk,setTickerOk]=useState(null);
  const [f,setF]=useState({username:'',email:'',password:'',full_name:'',portfolio_name:'',ticker:''});
  const set=k=>e=>setF(p=>({...p,[k]:e.target.value}));

  useEffect(()=>{
    if(mode!=='signup'||f.ticker.length!==4){setTickerOk(null);return;}
    const t=setTimeout(async()=>{
      try{const r=await fetch('/api/ticker/check/'+f.ticker);const d=await r.json();setTickerOk(d.available);}catch{}
    },400);return()=>clearTimeout(t);
  },[f.ticker,mode]);

  const submit=async e=>{
    e.preventDefault();setErr('');setLoading(true);
    try{
      const r=await fetch(mode==='login'?'/api/auth/login':'/api/auth/signup',{
        method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(d.mfa_required){setMode('mfa');setLoading(false);return;}
      if(!r.ok){setErr(d.error||'Something went wrong');setLoading(false);return;}
      onLogin(d.user);
    }catch{setErr('Network error — check connection');}
    setLoading(false);
  };

  return(
    <div className="auth-wrap">
      <div className="auth-side">
        <div className="auth-side-bg"/>
        <div className="auth-side-content">
          <span className="auth-bird">🐦</span>
          <div className="auth-brand">Property Pigeon</div>
          <div className="auth-tagline">The social investment network for real estate investors. Track your portfolio, discover top performers.</div>
        </div>
      </div>
      <div className="auth-main">
        <div className="auth-card">
          <div className="auth-eyebrow">Property Pigeon</div>
          <h2>{mode==='login'?'Welcome back':mode==='mfa'?'Two-factor auth':'Create account'}</h2>
          <p className="auth-sub">{mode==='login'?'Sign in to your account':mode==='mfa'?'Enter your 6-digit authenticator code':'Join real estate investors worldwide'}</p>
          {err&&<div className="alert alert-err">⚠️ {err}</div>}
          <form onSubmit={submit}>
            {mode==='signup'&&<>
              <div className="auth-field"><label>Full name</label><input className="auth-input" value={f.full_name} onChange={set('full_name')} placeholder="Brandon Bonomo" required/></div>
              <div className="auth-field"><label>Portfolio name</label><input className="auth-input" value={f.portfolio_name} onChange={set('portfolio_name')} placeholder="BLB Realty" required/></div>
              <div className="auth-field">
                <label>Ticker — 4 letters, your public ID</label>
                <input className="auth-input mono" value={f.ticker} onChange={e=>setF(p=>({...p,ticker:e.target.value.toUpperCase().replace(/[^A-Z]/g,'').slice(0,4)}))} placeholder="BBLB" maxLength={4} style={{letterSpacing:4,fontSize:18}} required/>
                {f.ticker.length===4&&tickerOk!==null&&<div className={tickerOk?'hint-ok':'hint-bad'}>{tickerOk?'✓ Available — grab it':'✗ Already taken — try another'}</div>}
              </div>
            </>}
            {mode!=='mfa'&&<div className="auth-field"><label>{mode==='login'?'Username or email':'Username'}</label><input className="auth-input" value={f.username} onChange={set('username')} placeholder="brandonb" required/></div>}
            {mode==='signup'&&<div className="auth-field"><label>Email</label><input className="auth-input" type="email" value={f.email} onChange={set('email')} required/></div>}
            {mode!=='mfa'&&<div className="auth-field"><label>Password</label><input className="auth-input" type="password" value={f.password} onChange={set('password')} required/></div>}
            {mode==='mfa'&&<div className="auth-field"><label>6-digit code</label><input className="auth-input mono" value={f.token||''} onChange={e=>setF(p=>({...p,token:e.target.value}))} placeholder="000 000" maxLength={6} style={{letterSpacing:8,fontSize:22,textAlign:'center'}}/></div>}
            <button type="submit" className="auth-submit" disabled={loading}>{loading?'Please wait…':mode==='login'?'Sign in':mode==='mfa'?'Verify':'Create account'}</button>
          </form>
          {mode!=='mfa'&&<button className="auth-switch" onClick={()=>{setMode(m=>m==='login'?'signup':'login');setErr('');}}>
            {mode==='login'?'New here? Create an account':'Already have an account? Sign in'}
          </button>}
        </div>
      </div>
    </div>
  );
}

// ── ADD PROPERTY SHEET ────────────────────────────────────────────────────────
function AddPropSheet({uid,onClose,onSave}){
  const [step,setStep]=useState('address'); // address | review | manual
  const [address,setAddress]=useState('');
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState('');
  const [f,setF]=useState({name:'',location:'',purchase_price:'',down_payment:'',
    mortgage:'',insurance:'',hoa:'',property_tax:'',monthly_revenue:'',
    zestimate:'',bedrooms:'',bathrooms:'',sqft:'',year_built:'',zillow_url:''});
  const [fetched,setFetched]=useState(null); // rentcast result
  const set=k=>e=>setF(p=>({...p,[k]:e.target.value}));

  const lookup=async()=>{
    if(!address.trim()){setErr('Enter a property address');return;}
    setLoading(true);setErr('');
    try{
      const r=await fetch('/api/rentcast/lookup',{method:'POST',
        headers:{'Content-Type':'application/json'},credentials:'include',
        body:JSON.stringify({address:address.trim()})});
      const d=await r.json();
      if(!r.ok||d.error){
        const msg = d.error||'Lookup failed';
        if(msg.includes('RENTCAST_API_KEY')){
          setErr('RentCast API key not set. Add RENTCAST_API_KEY to Render environment variables, or enter manually below.');
        } else {
          setErr(msg);
        }
        setLoading(false);return;
      }
      setFetched(d);
      setF(p=>({...p,
        name:d.address||address,
        location:d.address||address,
        zestimate:d.zestimate||'',
        purchase_price:d.zestimate||'',
        monthly_revenue:d.rent_estimate||'',
        bedrooms:d.bedrooms||'',
        bathrooms:d.bathrooms||'',
        sqft:d.sqft||'',
        year_built:d.year_built||'',
        property_tax:d.monthly_tax||'',
      }));
      setStep('review');
    }catch(e){setErr('Network error');}
    setLoading(false);
  };

  const save=async()=>{
    const name=f.name||f.location||address||'Property';
    setLoading(true);setErr('');
    try{
      const body={...f,name};
      const r=await fetch(`/api/properties/${uid}`,{method:'POST',
        headers:{'Content-Type':'application/json'},credentials:'include',
        body:JSON.stringify(body)});
      const text=await r.text();
      let d;try{d=JSON.parse(text);}catch{d={error:text.slice(0,200)};}
      if(!r.ok){setErr(d.error||`Save failed (${r.status})`);setLoading(false);return;}
      onSave(d);onClose();
    }catch(e){setErr('Save error: '+e.message);}
    setLoading(false);
  };

  const Inp=(lbl,k,type='text',ph='')=>(
    <div className="form-row"><label>{lbl}</label>
      <input className="sinput" type={type} value={f[k]} onChange={set(k)} placeholder={ph}/>
    </div>
  );

  return(
    <div className="overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="sheet">
        <div className="sheet-handle"/>

        {step==='address'&&<>
          <h3>Add Property</h3>
          <p className="sheet-sub">Enter the property address to look up current value, rent estimate, and details</p>

          {err&&<div className="alert alert-err" onClick={()=>setErr('')}>✕ {err}</div>}

          <div className="form-row" style={{marginBottom:8}}>
            <label>Property Address</label>
            <input className="sinput" value={address} onChange={e=>setAddress(e.target.value)}
              placeholder="123 Main St, Houston, TX 77001"
              onKeyDown={e=>e.key==='Enter'&&lookup()}
              autoFocus style={{fontSize:15}}/>
          </div>
          <div style={{fontSize:11,color:'var(--muted)',marginBottom:16}}>
            Include street, city, state, and ZIP for best results
          </div>

          <div className="sheet-foot">
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-prime" onClick={lookup} disabled={loading}>
              {loading?'Looking up…':'Look Up Property'}
            </button>
          </div>
          <button className="manual-link" onClick={()=>setStep('manual')}>Skip lookup — enter manually</button>
        </>}

        {step==='review'&&<>
          <button className="back-btn" onClick={()=>setStep('address')}>← Back</button>
          <h3>Confirm Details</h3>
          <p className="sheet-sub">{fetched?.address||address}</p>

          {fetched&&<div style={{background:'rgba(16,185,129,.07)',border:'1px solid rgba(16,185,129,.2)',borderRadius:12,padding:'14px 16px',marginBottom:16}}>
            <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:12}}>
              {fetched.zestimate&&<div><div style={{fontSize:10,fontWeight:700,color:'var(--muted)',textTransform:'uppercase',letterSpacing:.5,marginBottom:3}}>Est. Value</div><div style={{fontSize:15,fontWeight:800,color:'var(--green)'}}>${(fetched.zestimate/1000).toFixed(0)}K</div></div>}
              {fetched.rent_estimate&&<div><div style={{fontSize:10,fontWeight:700,color:'var(--muted)',textTransform:'uppercase',letterSpacing:.5,marginBottom:3}}>Est. Rent</div><div style={{fontSize:15,fontWeight:800,color:'#2563eb'}}>${fetched.rent_estimate?.toLocaleString()}/mo</div></div>}
              {fetched.bedrooms&&<div><div style={{fontSize:10,fontWeight:700,color:'var(--muted)',textTransform:'uppercase',letterSpacing:.5,marginBottom:3}}>Beds/Baths</div><div style={{fontSize:15,fontWeight:800}}>{fetched.bedrooms}bd/{fetched.bathrooms}ba</div></div>}
            </div>
            {(fetched.value_low||fetched.rent_low)&&<div style={{fontSize:11,color:'var(--muted)',marginTop:10}}>
              {fetched.value_low&&<span>Value range: ${(fetched.value_low/1000).toFixed(0)}K – ${(fetched.value_high/1000).toFixed(0)}K</span>}
              {fetched.rent_low&&<span style={{marginLeft:12}}>Rent range: ${fetched.rent_low?.toLocaleString()} – ${fetched.rent_high?.toLocaleString()}</span>}
            </div>}
            <div style={{fontSize:10,color:'var(--dim)',marginTop:6}}>
              Sources: {fetched?.source||'RentCast'} AVM
              {fetched?.values_by_source&&Object.keys(fetched.values_by_source).length>1&&
                <span> · Blended avg of {Object.entries(fetched.values_by_source).map(([s,v])=>`${s}: $${(v/1000).toFixed(0)}K`).join(' + ')}</span>
              }
            </div>
          </div>}

          {err&&<div className="alert alert-err" onClick={()=>setErr('')}>✕ {err}</div>}

          <div className="form-2">
            <div className="form-row"><label>Purchase price ($)</label><input className="sinput" type="number" value={f.purchase_price} onChange={set('purchase_price')}/></div>
            <div className="form-row"><label>Down payment ($)</label><input className="sinput" type="number" value={f.down_payment} onChange={set('down_payment')}/></div>
          </div>
          <div className="form-2">
            <div className="form-row"><label>Monthly rent ($)</label><input className="sinput" type="number" value={f.monthly_revenue} onChange={set('monthly_revenue')}/></div>
            <div className="form-row"><label>Mortgage /mo ($)</label><input className="sinput" type="number" value={f.mortgage} onChange={set('mortgage')}/></div>
          </div>
          <div className="form-2">
            <div className="form-row"><label>Property tax /mo ($)</label><input className="sinput" type="number" value={f.property_tax} onChange={set('property_tax')}/></div>
            <div className="form-row"><label>Insurance /mo ($)</label><input className="sinput" type="number" value={f.insurance} onChange={set('insurance')}/></div>
          </div>

          <div className="sheet-foot">
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-prime" onClick={save} disabled={loading}>{loading?'Saving…':'Add Property'}</button>
          </div>
        </>}

        {step==='manual'&&<>
          <button className="back-btn" onClick={()=>setStep('address')}>← Back</button>
          <h3>Manual Entry</h3>
          <p className="sheet-sub">Enter property details manually</p>
          {err&&<div className="alert alert-err" onClick={()=>setErr('')}>✕ {err}</div>}
          {Inp('Property name','name','text','22 B Street')}
          {Inp('Location','location','text','Houston, TX 77001')}
          <div className="form-2">
            <div className="form-row">{Inp('Purchase price ($)','purchase_price','number')}</div>
            <div className="form-row">{Inp('Down payment ($)','down_payment','number')}</div>
          </div>
          <div className="form-2">
            <div className="form-row">{Inp('Current value ($)','zestimate','number')}</div>
            <div className="form-row">{Inp('Monthly rent ($)','monthly_revenue','number')}</div>
          </div>
          <div className="form-2">
            <div className="form-row">{Inp('Mortgage /mo ($)','mortgage','number')}</div>
            <div className="form-row">{Inp('Property tax /mo ($)','property_tax','number')}</div>
          </div>
          <div className="form-2">
            <div className="form-row">{Inp('Insurance /mo ($)','insurance','number')}</div>
            <div className="form-row">{Inp('HOA /mo ($)','hoa','number')}</div>
          </div>
          <div className="sheet-foot">
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-prime" onClick={save} disabled={loading}>{loading?'Saving…':'Add Property'}</button>
          </div>
        </>}
      </div>
    </div>
  );
}

// ── EDIT PROPERTY SHEET ───────────────────────────────────────────────────────
function EditPropSheet({prop,onClose,onSave,onDelete}){
  const [f,setF]=useState({...prop});
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState('');
  const set=k=>e=>setF(p=>({...p,[k]:e.target.value}));
  const Inp=(lbl,k,type='text')=>(<div className="form-row"><label>{lbl}</label><input className="sinput" type={type} value={f[k]||''} onChange={set(k)}/></div>);
  const Inp2=(a,b)=>(<div className="form-2">{Inp(...a)}{Inp(...b)}</div>);

  const save=async()=>{
    setLoading(true);setErr('');
    try{
      const r=await fetch(`/api/property/${prop.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(!r.ok){setErr(d.error||'Failed');setLoading(false);return;}
      onSave(d);onClose();
    }catch{setErr('Failed');}
    setLoading(false);
  };

  const del=async()=>{
    if(!confirm(`Delete "${prop.name}"?`))return;
    await fetch(`/api/property/${prop.id}`,{method:'DELETE',credentials:'include'});
    onDelete(prop.id);onClose();
  };

  return(
    <div className="overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="sheet">
        <div className="sheet-handle"/>
        <h3>Edit Property</h3>
        <p className="sheet-sub">{prop.name}</p>
        {/* Property quarterly performance */}
        <div style={{marginBottom:16}}>
          <div style={{fontSize:10,fontWeight:800,color:'var(--muted)',letterSpacing:.5,marginBottom:6}}>THIS PROPERTY</div>
          <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8,
            background:'rgba(0,0,0,.025)',borderRadius:12,padding:'12px 14px'}}>
            {[
              ['Revenue', `$${((+prop.monthly_revenue||0)*3).toLocaleString()}`, 'Qtr'],
              ['Expenses', `$${((+prop.mortgage+ +prop.insurance+ +prop.hoa+ +prop.property_tax)*3||0).toLocaleString()}`, 'Qtr'],
              ['Net CF', `${((+prop.monthly_revenue||0)*3 - (+prop.mortgage+ +prop.insurance+ +prop.hoa+ +prop.property_tax)*3)>=0?'+':''}$${Math.abs(((+prop.monthly_revenue||0)*3 - (+prop.mortgage+ +prop.insurance+ +prop.hoa+ +prop.property_tax)*3)).toLocaleString()}`, 'Qtr'],
            ].map(([l,v,u])=>(
              <div key={l} style={{textAlign:'center'}}>
                <div style={{fontSize:9,color:'var(--muted)',textTransform:'uppercase',letterSpacing:.4,marginBottom:3}}>{l}</div>
                <div style={{fontSize:14,fontWeight:800,fontFamily:'JetBrains Mono'}}>{v}</div>
                <div style={{fontSize:9,color:'var(--dim)'}}>{u}</div>
              </div>
            ))}
          </div>
        </div>
        {err&&<div className="alert alert-err">{err}</div>}
        {Inp('Property name','name')}{Inp('Location','location')}
        {Inp2(['Purchase price','purchase_price','number'],['Down payment','down_payment','number'])}
        {Inp2(['Current value ($)','zestimate','number'],['Monthly rent ($)','monthly_revenue','number'])}
        {Inp2(['Mortgage /mo ($)','mortgage','number'],['Property tax /mo ($)','property_tax','number'])}
        {Inp2(['Insurance /mo ($)','insurance','number'],['HOA /mo ($)','hoa','number'])}
        <div className="sheet-foot">
          <button className="btn btn-danger btn-sm" onClick={del}>Delete</button>
          <div style={{flex:1}}/>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-prime" onClick={save} disabled={loading}>{loading?'Saving…':'Save Changes'}</button>
        </div>
      </div>
    </div>
  );
}

// ── PORTFOLIO TAB ─────────────────────────────────────────────────────────────
function PortfolioTab({user,props,portfolio,onAdd,onEdit,onRefreshValue}){
  const [plaidSummary,setPlaidSummary]=useState(null);
  useEffect(()=>{
    fetch('/api/plaid/accounts',{credentials:'include'}).then(r=>r.json())
      .then(d=>{
        if(!d.items?.length) return;
        const assets=d.items.flatMap(i=>i.accounts).filter(a=>a.type==='depository'||a.type==='investment').reduce((s,a)=>s+(+a.balance||0),0);
        const liabs=d.items.flatMap(i=>i.accounts).filter(a=>a.type==='credit'||a.type==='loan').reduce((s,a)=>s+(+a.balance||0),0);
        setPlaidSummary({assets,liabs,banks:d.items.length,accounts:d.items.flatMap(i=>i.accounts).length});
      }).catch(()=>{});
  },[]);
  const tv=+portfolio.total_value||0,te=+portfolio.total_equity||0,mcf=+portfolio.monthly_cashflow||0,hs=+portfolio.health_score||0;
  const accent=user.accent_color||'#2563eb';
  const history=useMemo(()=>{try{const h=portfolio.price_history;return(typeof h==='string'?JSON.parse(h):h)||[];}catch{return[];}});
  const chartData=history.map(h=>+h.price);
  const capRate=tv>0?(props.reduce((s,p)=>s+(+p.monthly_revenue*12-(+p.property_tax+ +p.insurance+ +p.hoa)*12),0)/tv)*100:0;

  return(
    <div className="page page-in">
      {/* Hero */}
      <div className="hero hero-gradient" style={{background:`linear-gradient(135deg,${accent} 0%,${accent}cc 100%)`}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
          <div>
            <div className="hero-lbl">Portfolio Value</div>
            <div className="hero-val">{fmt$k(tv)}</div>
            <div className="hero-sub">{props.length} {props.length===1?'property':'properties'} · Equity {fmt$k(te)}</div>
          </div>
          <HealthRing score={hs}/>
        </div>
        {chartData.length>1&&<div className="hero-chart"><MiniLine data={chartData} color="rgba(255,255,255,.9)" height={72}/></div>}
        <div style={{display:'flex',gap:6,marginTop:8,flexWrap:'wrap'}}>
          <span style={{fontSize:12,color:'rgba(255,255,255,.85)',fontWeight:600}}>Cap Rate {capRate.toFixed(1)}%</span>
          <span style={{color:'rgba(255,255,255,.4)'}}>·</span>
          <span style={{fontSize:12,color:'rgba(255,255,255,.85)',fontWeight:600,color:mcf>=0?'#6ee7b7':'#fca5a5'}}>CF {mcf>=0?'+':''}{fmt$(mcf)}/mo</span>
        </div>
      </div>

      {/* Quarterly Results */}
      <div style={{marginBottom:14}}>
        <div style={{fontSize:11,fontWeight:800,color:'var(--muted)',letterSpacing:.5,marginBottom:8}}>QUARTERLY RESULTS</div>
        <QuarterlyStrip uid={user.id} accent={accent} compact={true}/>
      </div>

      {/* Stats */}
      <div className="grid2" style={{marginBottom:14}}>
        <div className="scard"><div className="scard-lbl">Monthly Cash Flow</div><div className="scard-val" style={{color:clr(mcf)}}>{fmt$s(mcf)}</div><div className="scard-sub">Annual {fmt$k(mcf*12)}</div></div>
        <div className="scard"><div className="scard-lbl">Total Equity</div><div className="scard-val">{fmt$k(te)}</div><div className="scard-sub">{tv>0?((te/tv)*100).toFixed(0)+'% LTV':''}</div></div>
        <div className="scard"><div className="scard-lbl">Cap Rate</div><div className="scard-val">{capRate.toFixed(2)}%</div></div>
        <div className="scard"><div className="scard-lbl">Share Price</div><div className="scard-val mono">${(+portfolio.share_price||1).toFixed(2)}</div></div>
      </div>
      {plaidSummary&&<div className="glass-card" style={{padding:'12px 16px',marginBottom:14,display:'flex',justifyContent:'space-between',alignItems:'center'}}>
        <div style={{display:'flex',alignItems:'center',gap:10}}>
          <span style={{fontSize:20}}>🏦</span>
          <div>
            <div style={{fontSize:12,fontWeight:700}}>Bank Accounts</div>
            <div style={{fontSize:11,color:'var(--muted)'}}>{plaidSummary.banks} institution{plaidSummary.banks!==1?'s':''} · {plaidSummary.accounts} accounts</div>
          </div>
        </div>
        <div style={{textAlign:'right'}}>
          <div style={{fontSize:15,fontWeight:800,fontFamily:'JetBrains Mono',color:'#10b981'}}>{fmt$k(plaidSummary.assets)}</div>
          {plaidSummary.liabs>0&&<div style={{fontSize:11,color:'#ef4444',fontFamily:'JetBrains Mono'}}>-{fmt$k(plaidSummary.liabs)} debt</div>}
        </div>
      </div>}

      {/* Properties */}
      <div className="sec-hdr"><h4>Properties</h4><button className="btn btn-prime btn-sm" onClick={onAdd}>+ Add</button></div>
      {props.length===0&&<div className="empty">
        <div className="empty-icon">🏠</div>
        <div className="empty-title">No properties yet</div>
        <div className="empty-sub">Add your first property to start tracking your portfolio</div>
        <button className="btn btn-prime" onClick={onAdd}>Add First Property</button>
      </div>}
      {props.map(p=>{
        const val=+p.zestimate||+p.purchase_price||0;
        const cf=+p.monthly_revenue-(+p.mortgage+ +p.insurance+ +p.hoa+ +p.property_tax);
        return(
          <div key={p.id} className="prop-row" onClick={()=>onEdit(p)} style={{'--accent':accent}}>
            <div className="prop-icon" style={{background:accent+'18'}}>{+p.bedrooms>0?'🏠':'🏢'}</div>
            <div style={{flex:1,minWidth:0}}>
              <div className="prop-name">{p.name}</div>
              <div className="prop-loc">{p.location}</div>
              <div style={{display:'flex',gap:5,marginTop:3,flexWrap:'wrap'}}>
                {+p.zestimate>0&&<span className="prop-meta">{fmt$(p.zestimate)} Zest</span>}
              </div>
            </div>
            <div style={{textAlign:'right',flexShrink:0}}>
              <div style={{fontSize:16,fontWeight:800,letterSpacing:'-.3px'}}>{fmt$k(val)}</div>
              <div style={{fontSize:12,fontWeight:700,color:clr(cf)}}>{cf>=0?'+':''}{fmt$(cf)}/mo</div>
              <div style={{fontSize:10,color:'var(--dim)',marginTop:3,cursor:'pointer'}}
                onClick={e=>{e.stopPropagation();onRefreshValue&&onRefreshValue(p.id);}}>↻ refresh</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}


// ── ANALYTICS TAB (Performance + Cashflow + Projections) ─────────────────────
function AnalyticsTab({user,props,portfolio}){
  const [sub,setSub]=useState('quarterly');
  return(
    <div className="page page-in" style={{paddingTop:14}}>
      <div className="subnav">
        {[['quarterly','📊 Quarterly'],['performance','Performance'],['cashflow','Cash Flow'],['projections','Projections']].map(([id,lbl])=>(
          <button key={id} className={`subnav-btn${sub===id?' on':''}`} onClick={()=>setSub(id)}>{lbl}</button>
        ))}
      </div>
      {sub==='quarterly'&&<QuarterlyStrip uid={user.id} accent={user.accent_color||'#2563eb'}/>}
      {sub==='performance'&&<PerfPane user={user} props={props} portfolio={portfolio}/>}
      {sub==='cashflow'&&<CashflowPane props={props}/>}
      {sub==='projections'&&<ProjectionsPane props={props} portfolio={portfolio} user={user}/>}
    </div>
  );
}

function PerfPane({user,props,portfolio}){
  const [snaps,setSnaps]=useState([]);
  const uid=user.id;
  const tv=+portfolio.total_value||0,te=+portfolio.total_equity||0,mcf=+portfolio.monthly_cashflow||0;
  const totalDown=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const coc=totalDown>0?(mcf*12/totalDown*100):0;
  const capRate=tv>0?(props.reduce((s,p)=>s+(+p.monthly_revenue*12-(+p.property_tax+ +p.insurance+ +p.hoa)*12),0)/tv)*100:0;

  useEffect(()=>{
    fetch(`/api/performance/portfolio/${uid}?months=24`,{credentials:'include'})
      .then(r=>r.json()).then(d=>setSnaps(d.snapshots||[])).catch(()=>{});
  },[uid]);

  const saveSnap=async()=>{
    await fetch('/api/performance/snapshot',{method:'POST',credentials:'include'});
    const r=await fetch(`/api/performance/portfolio/${uid}?months=24`,{credentials:'include'});
    const d=await r.json();setSnaps(d.snapshots||[]);
  };

  // YoY comparison
  const yoyData=useMemo(()=>{
    if(snaps.length<13)return null;
    const latest=snaps[snaps.length-1];
    const yearAgo=snaps[snaps.length-13];
    if(!latest||!yearAgo)return null;
    return{
      valueChg:+latest.total_value - +yearAgo.total_value,
      equityChg:+latest.total_equity - +yearAgo.total_equity,
      cfChg:+latest.net_cashflow - +yearAgo.net_cashflow,
      valuePct:yearAgo.total_value>0?((+latest.total_value/+yearAgo.total_value-1)*100):0,
    };
  },[snaps]);

  const chartData=snaps.map(s=>+s.total_value);
  const chartLabels=snaps.map(s=>monthShort(s.snapshot_month));
  const accent=user.accent_color||'#2563eb';

  const [perfView, setPerfView] = useState('overview');
  return(<>
    <div className="subnav" style={{marginBottom:14}}>
      {[['overview','Overview'],['quarterly','Quarterly'],['history','History']].map(([id,lbl])=>(
        <button key={id} className={`subnav-btn${perfView===id?' on':''}`} onClick={()=>setPerfView(id)}>{lbl}</button>
      ))}
    </div>
    {perfView==='quarterly'&&<QuarterlyStrip uid={uid} accent={accent}/>}
    {(perfView==='overview'||perfView==='history')&&<>
    <div className="grid2" style={{marginBottom:12}}>
      <div className="scard"><div className="scard-lbl">Portfolio Value</div><div className="scard-val">{fmt$k(tv)}</div>
        {yoyData&&<div className="scard-delta" style={deltaStyle(yoyData.valuePct)}>{arrow(yoyData.valuePct)}{Math.abs(yoyData.valuePct).toFixed(1)}% YoY</div>}
      </div>
      <div className="scard"><div className="scard-lbl">Total Equity</div><div className="scard-val">{fmt$k(te)}</div>
        {yoyData&&<div className="scard-delta" style={deltaStyle(yoyData.equityChg)}>{arrow(yoyData.equityChg)}{fmt$k(Math.abs(yoyData.equityChg))} YoY</div>}
      </div>
      <div className="scard"><div className="scard-lbl">Cash-on-Cash</div><div className="scard-val" style={{color:clr(coc)}}>{coc.toFixed(1)}%</div></div>
      <div className="scard"><div className="scard-lbl">Cap Rate</div><div className="scard-val">{capRate.toFixed(1)}%</div></div>
    </div>
    {chartData.length>1&&<div className="glass-card" style={{padding:18,marginBottom:12}}>
      <div className="lbl" style={{marginBottom:10}}>Portfolio Value History</div>
      <MiniLine data={chartData} color={accent} height={90}/>
      <div style={{display:'flex',justifyContent:'space-between',marginTop:8,fontSize:10,color:'var(--muted)',fontWeight:600}}>
        {chartLabels.filter((_,i)=>i%Math.ceil(chartLabels.length/5)===0).map((l,i)=><span key={i}>{l}</span>)}
      </div>
    </div>}
    <div className="sec-hdr">
      <h4 style={{fontSize:14}}>Month-over-Month</h4>
    </div>
    {snaps.length===0&&<div className="empty"><div className="empty-icon">📊</div><div className="empty-title">No history yet</div><div className="empty-sub">Save a snapshot to start tracking over time</div></div>}
    {snaps.length>0&&<div className="glass-card" style={{padding:0,overflow:'hidden'}}>
      <div style={{overflowX:'auto'}}>
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
          <thead><tr style={{borderBottom:'1px solid rgba(0,0,0,.06)',background:'rgba(0,0,0,.02)'}}>
            {['Month','Value','Δ YoY','Equity','Revenue','Net CF'].map(h=>(
              <th key={h} style={{padding:'10px 13px',textAlign:h==='Month'?'left':'right',fontWeight:700,color:'var(--muted)',fontSize:10,textTransform:'uppercase',letterSpacing:.6,whiteSpace:'nowrap'}}>{h}</th>
            ))}
          </tr></thead>
          <tbody>{[...snaps].reverse().map((s,i,arr)=>{
            const prev=arr[i+1];
            const valDelta=prev?+s.total_value - +prev.total_value:null;
            const isYoY=arr.length>i+12?+s.total_value - +arr[i+12].total_value:null;
            return(
              <tr key={i} style={{borderBottom:'1px solid rgba(0,0,0,.04)'}}>
                <td style={{padding:'10px 13px',fontWeight:700,fontSize:13}}>{monthName(s.snapshot_month)}</td>
                <td style={{padding:'10px 13px',textAlign:'right',fontFamily:'JetBrains Mono',fontWeight:600}}>{fmt$k(s.total_value)}</td>
                <td style={{padding:'10px 13px',textAlign:'right'}}>
                  {isYoY!==null?<span style={{fontSize:11,fontWeight:700,color:clr(isYoY)}}>{arrow(isYoY)}{Math.abs(isYoY/+arr[i+12].total_value*100).toFixed(1)}%</span>:<span style={{color:'var(--dim)',fontSize:11}}>—</span>}
                </td>
                <td style={{padding:'10px 13px',textAlign:'right',fontFamily:'JetBrains Mono'}}>{fmt$k(s.total_equity)}</td>
                <td style={{padding:'10px 13px',textAlign:'right',color:'var(--green)',fontFamily:'JetBrains Mono'}}>{fmt$(s.gross_revenue)}</td>
                <td style={{padding:'10px 13px',textAlign:'right',fontWeight:700,color:clr(s.net_cashflow),fontFamily:'JetBrains Mono'}}>{fmt$s(s.net_cashflow)}</td>
              </tr>
            );
          })}</tbody>
        </table>
      </div>
    </div>}
    </>}
  </>);
}

function CashflowPane({props}){
  const revenue=props.reduce((s,p)=>s+(+p.monthly_revenue||0),0);
  const mortgage=props.reduce((s,p)=>s+(+p.mortgage||0),0);
  const tax=props.reduce((s,p)=>s+(+p.property_tax||0),0);
  const ins=props.reduce((s,p)=>s+(+p.insurance||0),0);
  const hoa=props.reduce((s,p)=>s+(+p.hoa||0),0);
  const total_exp=mortgage+tax+ins+hoa;
  const noi=revenue-tax-ins-hoa;
  const ncf=revenue-total_exp;

  // Bar chart: last 12 months simulated (will be real data when snapshots exist)
  const barData=[revenue,-mortgage,-tax,-ins,-hoa,ncf];
  const barLabels=['Revenue','Mortgage','Tax','Insurance','HOA','Net CF'];

  return(<>
    <div style={{marginBottom:14}}>
      <div style={{fontSize:11,fontWeight:700,color:'var(--muted)',textTransform:'uppercase',letterSpacing:.8,marginBottom:6}}>Net Cash Flow / Month</div>
      <div style={{fontSize:40,fontWeight:800,letterSpacing:-2,color:clr(ncf)}}>{fmt$s(ncf)}</div>
      <div style={{fontSize:13,color:'var(--muted)',marginTop:4}}>Annual {fmt$k(ncf*12)}</div>
    </div>
    <div className="glass-card" style={{padding:18,marginBottom:12}}>
      <div className="lbl" style={{marginBottom:12}}>Breakdown</div>
      <BarChart data={barData} labels={barLabels} color="var(--blue)" height={130}/>
    </div>
    <div className="glass-card" style={{padding:18,marginBottom:12}}>
      <div className="lbl" style={{marginBottom:12}}>Monthly Detail</div>
      {[['Gross Revenue',revenue,true],['Mortgage',-mortgage],['Property Tax',-tax],['Insurance',-ins],['HOA',-hoa]].map(([lbl,val,inc])=>(
        <div key={lbl} className="cf-row">
          <span className="cf-lbl">{lbl}</span>
          <span className="cf-val" style={{color:inc?'var(--green)':+val<0?'var(--red)':'var(--muted)'}}>{fmt$s(inc?val:val)}</span>
        </div>
      ))}
      <div style={{borderTop:'1px solid rgba(0,0,0,.08)',margin:'8px 0'}}/>
      <div className="cf-row cf-total">
        <span className="cf-lbl" style={{fontWeight:700}}>Net Operating Income</span>
        <span className="cf-val" style={{color:clr(noi),fontSize:14}}>{fmt$s(noi)}</span>
      </div>
      <div className="cf-row cf-total" style={{marginTop:4}}>
        <span className="cf-lbl" style={{fontWeight:700}}>Net Cash Flow</span>
        <span className="cf-val" style={{color:clr(ncf),fontSize:14}}>{fmt$s(ncf)}</span>
      </div>
    </div>
    <div className="grid2">
      <div className="scard"><div className="scard-lbl">Annual Revenue</div><div className="scard-val">{fmt$k(revenue*12)}</div></div>
      <div className="scard"><div className="scard-lbl">Annual Expenses</div><div className="scard-val" style={{color:'var(--red)'}}>{fmt$k(total_exp*12)}</div></div>
      <div className="scard"><div className="scard-lbl">Expense Ratio</div><div className="scard-val">{revenue>0?((total_exp/revenue)*100).toFixed(0)+'%':'—'}</div></div>
      <div className="scard"><div className="scard-lbl">Annual NOI</div><div className="scard-val" style={{color:clr(noi)}}>{fmt$k(noi*12)}</div></div>
    </div>
  </>);
}

function ProjectionsPane({props,portfolio,user}){
  const [appreciation,setAppreciation]=useState(3.5);
  const [rentGrowth,setRentGrowth]=useState(2.5);
  const [vacancy,setVacancy]=useState(5);
  const [expInflation,setExpInflation]=useState(2.0);

  const tv=+portfolio.total_value||0;
  const rev=props.reduce((s,p)=>s+(+p.monthly_revenue||0),0)*12;
  const exp=props.reduce((s,p)=>s+(+p.mortgage||0)+(+p.insurance||0)+(+p.hoa||0)+(+p.property_tax||0),0)*12;
  const down=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const debt=tv-(+portfolio.total_equity||0);
  const accent=user.accent_color||'#2563eb';

  const proj=useMemo(()=>{
    if(!tv)return[];
    const vf=1-(vacancy/100);
    return Array.from({length:30},(_,i)=>{
      const y=i+1,val=tv*Math.pow(1+appreciation/100,y),r=rev*Math.pow(1+rentGrowth/100,y)*vf,e=exp*Math.pow(1+expInflation/100,y),ncf=r-e,dr=debt*Math.pow(1-(.012+y*.001),y),eq=val-Math.max(0,dr);
      const cumCF=Array.from({length:y},(_,j)=>rev*Math.pow(1+rentGrowth/100,j)*vf-exp*Math.pow(1+expInflation/100,j)).reduce((a,b)=>a+b,0);
      return{y,val,eq,rev:r,ncf,cumCF,coc:down>0?ncf/down:0};
    });
  },[tv,rev,exp,down,debt,appreciation,rentGrowth,vacancy,expInflation]);

  if(!tv)return(<div className="empty"><div className="empty-icon">📈</div><div className="empty-title">Add a property first</div><div className="empty-sub">Projections require at least one property with a value</div></div>);

  const milestones=[proj[4],proj[9],proj[14],proj[19],proj[24],proj[29]].filter(Boolean);
  const chartVals=proj.filter(p=>[5,10,15,20,25,30].includes(p.y)).map(p=>p.val);
  const chartLabels=['Yr 5','Yr 10','Yr 15','Yr 20','Yr 25','Yr 30'];
  const ncfChart=proj.map(p=>p.ncf);

  return(<>
    <div className="glass-card" style={{padding:18,marginBottom:14}}>
      <div className="lbl" style={{marginBottom:16}}>Adjust Assumptions</div>
      <Slider label="Appreciation" value={appreciation} set={setAppreciation} min={0} max={10} step={0.5} fmt={v=>v.toFixed(1)+'%'}/>
      <Slider label="Rent Growth" value={rentGrowth} set={setRentGrowth} min={0} max={8} step={0.5} fmt={v=>v.toFixed(1)+'%'}/>
      <Slider label="Vacancy Rate" value={vacancy} set={setVacancy} min={0} max={20} step={1} fmt={v=>v+'%'}/>
      <Slider label="Expense Inflation" value={expInflation} set={setExpInflation} min={0} max={6} step={0.5} fmt={v=>v.toFixed(1)+'%'}/>
    </div>
    <div className="glass-card" style={{padding:18,marginBottom:12}}>
      <div className="lbl" style={{marginBottom:10}}>Portfolio Value at Milestones</div>
      <BarChart data={chartVals} labels={chartLabels} color={accent} height={140}/>
    </div>
    <div className="glass-card" style={{padding:18,marginBottom:12}}>
      <div className="lbl" style={{marginBottom:10}}>Annual Cash Flow Growth (30yr)</div>
      <MiniLine data={ncfChart} color={ncfChart[ncfChart.length-1]>0?'#10b981':'#f43f5e'} height={80}/>
    </div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:8,marginBottom:14}}>
      {milestones.map((m,i)=>(<div key={m.y} className="scard" style={{borderTop:`3px solid ${[accent,'#6366f1','#10b981','#f59e0b','#f43f5e','#0891b2'][i]}`}}>
        <div style={{fontSize:10,fontWeight:700,color:'var(--muted)',marginBottom:6}}>YEAR {m.y}</div>
        <div style={{fontSize:17,fontWeight:800,letterSpacing:'-.5px'}}>{fmt$k(m.val)}</div>
        <div style={{fontSize:11,color:'var(--green)',fontWeight:700,marginTop:4}}>Eq {fmt$k(m.eq)}</div>
      </div>))}
    </div>
    <div className="glass-card" style={{padding:0,overflow:'hidden'}}>
      <div style={{overflowX:'auto'}}>
        <table className="proj-table">
          <thead><tr>{['Yr','Value','Equity','Ann Rev','Net CF','Cum CF','CoC'].map(h=><th key={h}>{h}</th>)}</tr></thead>
          <tbody>{proj.map(r=>(
            <tr key={r.y} className={[5,10,15,20,25,30].includes(r.y)?'milestone':''}>
              <td>{r.y}</td><td>{fmt$k(r.val)}</td>
              <td style={{color:'var(--green)'}}>{fmt$k(r.eq)}</td>
              <td>{fmt$k(r.rev)}</td>
              <td style={{color:clr(r.ncf)}}>{fmt$k(r.ncf)}</td>
              <td style={{color:clr(r.cumCF)}}>{fmt$k(r.cumCF)}</td>
              <td style={{color:clr(r.coc)}}>{(r.coc*100).toFixed(1)}%</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>
  </>);
}


// ── PLAID CASHFLOW CATEGORIZER ────────────────────────────────────────────────
const CAT_LABELS = {
  REVENUE:           {label:'Revenue',        color:'#10b981', icon:'📈', impacts:'revenue'},
  MORTGAGE:          {label:'Mortgage',        color:'#ef4444', icon:'🏠', impacts:'mortgage'},
  INSURANCE:         {label:'Insurance',       color:'#f59e0b', icon:'🛡', impacts:'expense'},
  HOA:               {label:'HOA',             color:'#f59e0b', icon:'🏘', impacts:'expense'},
  PROPERTY_TAX:      {label:'Property Tax',    color:'#f59e0b', icon:'📋', impacts:'expense'},
  MAINTENANCE:       {label:'Maintenance',     color:'#8b5cf6', icon:'🔧', impacts:'expense'},
  EXPENSE:           {label:'Expense',         color:'#6b7280', icon:'💸', impacts:'expense'},
  INTERNAL_TRANSFER: {label:'Internal Transfer',color:'#94a3b8',icon:'↔️', impacts:'none'},
};
const CAT_OPTIONS = Object.entries(CAT_LABELS).map(([k,v])=>({value:k,...v}));

function PlaidCashflow({uid, accent}){
  const [data, setData]   = useState(null);
  const [loading, setLoading] = useState(true);
  const [overriding, setOverriding] = useState(null); // txn id being edited
  const [saving, setSaving] = useState(false);
  const [showAll, setShowAll] = useState(false);
  const [filterCat, setFilterCat] = useState('ALL');

  const load = async()=>{
    setLoading(true);
    try{
      const r = await fetch('/api/plaid/cashflow-summary',{credentials:'include'});
      const d = await r.json();
      setData(d);
    }catch{}
    setLoading(false);
  };

  useEffect(()=>{load();},[]);

  const saveOverride = async(txn, newCat)=>{
    setSaving(true);
    await fetch('/api/plaid/txn-categories',{
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        txn_id: txn.id,
        txn_name: txn.name,
        original_category: txn.raw_category,
        user_category: newCat,
        amount: txn.amount,
        txn_date: txn.date,
      })
    });
    setSaving(false);
    setOverriding(null);
    await load();
  };

  if(loading) return <div style={{textAlign:'center',padding:20,color:'var(--muted)',fontSize:12}}>Loading bank data…</div>;
  if(!data||data.error) return null;

  const txns = data.transactions||[];
  const visible = txns.filter(t=>filterCat==='ALL'||t.category===filterCat);
  const shown = showAll ? visible : visible.slice(0,20);

  return(
    <div style={{marginBottom:16}}>
      {/* ── Summary bar ── */}
      <div style={{background:`linear-gradient(135deg,${accent} 0%,${accent}bb 100%)`,
        borderRadius:16,padding:'16px 18px',marginBottom:12,color:'#fff'}}>
        <div style={{fontSize:11,fontWeight:700,color:'rgba(255,255,255,.6)',letterSpacing:.5,marginBottom:10}}>
          BANK CASH FLOW · LAST 90 DAYS
        </div>
        <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10}}>
          {[
            ['Revenue',   fmt$k(data.revenue),    '#6ee7b7'],
            ['Mortgage',  fmt$k(data.mortgage),   '#fca5a5'],
            ['Net CF',    fmt$s(data.net_cashflow), data.net_cashflow>=0?'#6ee7b7':'#fca5a5'],
          ].map(([l,v,c])=>(
            <div key={l} style={{background:'rgba(255,255,255,.12)',borderRadius:10,padding:'8px 10px'}}>
              <div style={{fontSize:10,color:'rgba(255,255,255,.55)',marginBottom:3}}>{l}</div>
              <div style={{fontSize:16,fontWeight:800,color:c,fontFamily:'JetBrains Mono'}}>{v}</div>
            </div>
          ))}
        </div>
        {data.internal_transfers>0&&
          <div style={{fontSize:11,color:'rgba(255,255,255,.5)',marginTop:8}}>
            ↔ {fmt$k(data.internal_transfers)} excluded as internal transfers
          </div>}
      </div>

      {/* ── Category filter tabs ── */}
      <div style={{display:'flex',gap:6,overflowX:'auto',paddingBottom:4,marginBottom:10}}>
        {[['ALL','All'],['REVENUE','Revenue'],['MORTGAGE','Mortgage'],['EXPENSE','Expense'],['INTERNAL_TRANSFER','Internal']].map(([k,l])=>(
          <button key={k} onClick={()=>setFilterCat(k)}
            style={{flexShrink:0,padding:'5px 12px',borderRadius:20,border:'none',cursor:'pointer',fontSize:11,fontWeight:700,
              background:filterCat===k?accent:'rgba(0,0,0,.06)',
              color:filterCat===k?'#fff':'var(--muted)'}}>
            {l}
          </button>
        ))}
      </div>

      {/* ── Transaction list ── */}
      <div className="glass-card" style={{padding:0,overflow:'hidden'}}>
        {shown.length===0&&<div style={{textAlign:'center',padding:24,color:'var(--muted)',fontSize:12}}>No transactions</div>}
        {shown.map(t=>{
          const ci = CAT_LABELS[t.category]||CAT_LABELS.EXPENSE;
          const isEditing = overriding===t.id;
          return(
            <div key={t.id} style={{padding:'12px 16px',borderBottom:'1px solid rgba(0,0,0,.05)',
              background: t.user_overridden?'rgba(99,102,241,.04)':'transparent'}}>
              <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',gap:8}}>
                <div style={{flex:1,minWidth:0}}>
                  <div style={{fontSize:13,fontWeight:600,overflow:'hidden',textOverflow:'ellipsis',whiteSpace:'nowrap'}}>
                    {t.name}
                    {t.user_overridden&&<span style={{fontSize:9,marginLeft:6,color:'#6366f1',fontWeight:700}}>EDITED</span>}
                  </div>
                  <div style={{fontSize:11,color:'var(--muted)',marginTop:2}}>{t.date}</div>
                </div>
                <div style={{textAlign:'right',flexShrink:0}}>
                  <div style={{fontSize:14,fontWeight:800,fontFamily:'JetBrains Mono',
                    color:t.amount<0?'#10b981':ci.color}}>
                    {t.amount<0?'+':'-'}{fmt$(Math.abs(t.amount))}
                  </div>
                  <button onClick={()=>setOverriding(isEditing?null:t.id)}
                    style={{marginTop:3,fontSize:10,fontWeight:700,color:ci.color,
                      background:ci.color+'18',border:'none',borderRadius:10,padding:'2px 8px',cursor:'pointer'}}>
                    {ci.icon} {ci.label}
                  </button>
                </div>
              </div>
              {isEditing&&(
                <div style={{marginTop:10,padding:'10px 12px',background:'rgba(0,0,0,.03)',borderRadius:10}}>
                  <div style={{fontSize:11,fontWeight:700,marginBottom:8,color:'var(--muted)'}}>Recategorize as:</div>
                  <div style={{display:'grid',gridTemplateColumns:'repeat(2,1fr)',gap:6}}>
                    {CAT_OPTIONS.map(opt=>(
                      <button key={opt.value}
                        onClick={()=>!saving&&saveOverride(t, opt.value)}
                        style={{padding:'7px 10px',borderRadius:10,border:'none',cursor:'pointer',
                          textAlign:'left',fontSize:12,fontWeight:700,
                          background: t.category===opt.value?opt.color+'22':'rgba(0,0,0,.04)',
                          color: t.category===opt.value?opt.color:'var(--fg)',
                          opacity: saving?0.5:1}}>
                        {opt.icon} {opt.label}
                        {opt.impacts==='none'&&<span style={{fontSize:9,display:'block',color:'var(--muted)',fontWeight:400}}>won't affect numbers</span>}
                        {opt.impacts==='revenue'&&<span style={{fontSize:9,display:'block',color:'#10b981',fontWeight:400}}>counts as income</span>}
                        {opt.impacts==='mortgage'&&<span style={{fontSize:9,display:'block',color:'#ef4444',fontWeight:400}}>counts as mortgage</span>}
                        {opt.impacts==='expense'&&<span style={{fontSize:9,display:'block',color:'#f59e0b',fontWeight:400}}>counts as expense</span>}
                      </button>
                    ))}
                  </div>
                  {saving&&<div style={{fontSize:11,color:'var(--muted)',marginTop:8,textAlign:'center'}}>Saving…</div>}
                </div>
              )}
            </div>
          );
        })}
        {visible.length>20&&!showAll&&(
          <div style={{padding:'12px 16px',textAlign:'center'}}>
            <button onClick={()=>setShowAll(true)}
              style={{fontSize:12,fontWeight:700,color:accent,background:'none',border:'none',cursor:'pointer'}}>
              Show all {visible.length} transactions
            </button>
          </div>
        )}
      </div>
    </div>
  );
}

// ── NET WORTH TAB ─────────────────────────────────────────────────────────────
function NetWorthTab({user,portfolio,props}){
  const [showManual,setShowManual]=useState(false);
  const [stocks,setStocks]=useState([]);
  const [stockInput,setStockInput]=useState('');
  const [manuals,setManuals]=useState([]);
  const [newLabel,setNewLabel]=useState('');
  const [newVal,setNewVal]=useState('');
  const [newType,setNewType]=useState('asset');
  const accent=user.accent_color||'#2563eb';
  const [plaidItems,setPlaidItems]=useState([]);
  const [plaidLoading,setPlaidLoading]=useState(false);
  const [plaidError,setPlaidError]=useState('');


  useEffect(()=>{loadPlaid();},[]);

  const loadPlaid=async()=>{
    try{
      const r=await fetch('/api/plaid/accounts',{credentials:'include'});
      const d=await r.json();
      if(d.items) setPlaidItems(d.items);
    }catch{}
  };

  const openPlaidLink=async(accessToken=null)=>{
    setPlaidLoading(true); setPlaidError('');
    try{
      const body = accessToken ? JSON.stringify({access_token:accessToken}) : '{}';
      const r=await fetch('/api/plaid/create-link-token',{method:'POST',credentials:'include',
        headers:{'Content-Type':'application/json'},body});
      const d=await r.json();
      if(d.error){
        let msg = d.error;
        if(msg.includes('NETWORK_BLOCKED')){
          msg = '⚠️ Render free tier blocks outbound network calls. Upgrade your Render service to Starter ($7/mo) at dashboard.render.com → your service → Settings → Instance Type.';
        } else if(msg.includes('Plaid not configured')){
          msg = '⚠️ Missing env vars. Add PLAID_CLIENT_ID, PLAID_SECRET, PLAID_ENV=production in Render → Environment.';
        }
        setPlaidError(msg);setPlaidLoading(false);return;
      }
      const linkToken=d.link_token;
      // Load Plaid Link SDK dynamically
      if(!window.Plaid){
        await new Promise((res,rej)=>{
          const s=document.createElement('script');
          s.src='https://cdn.plaid.com/link/v2/stable/link-initialize.js';
          s.onload=res; s.onerror=rej;
          document.head.appendChild(s);
        });
      }
      const handler=window.Plaid.create({
        token: linkToken,
        onSuccess: async(publicToken, meta)=>{
          setPlaidLoading(true);
          setPlaidError('');
          try{
            const r=await fetch('/api/plaid/exchange-token',{
              method:'POST', credentials:'include',
              headers:{'Content-Type':'application/json'},
              body:JSON.stringify({
                public_token: publicToken,
                institution_name: meta?.institution?.name||'',
                institution_id: meta?.institution?.institution_id||'',
              })
            });
            const d=await r.json();
            if(!r.ok||d.error){
              setPlaidError('Bank link failed: '+(d.error||r.status));
              setPlaidLoading(false);
              return;
            }
          }catch(e){
            setPlaidError('Bank link error: '+e.message);
            setPlaidLoading(false);
            return;
          }
          await loadPlaid();
          setPlaidLoading(false);
        },
        onExit:(err)=>{
          if(err) setPlaidError(err.display_message||err.error_message||'Link exited');
          setPlaidLoading(false);
        },
      });
      handler.open();
    }catch(e){
      setPlaidError(e.message);
      setPlaidLoading(false);
    }
  };

  const removeItem=async(itemId)=>{
    if(!confirm('Disconnect this bank account?')) return;
    await fetch('/api/plaid/remove',{method:'POST',credentials:'include',
      headers:{'Content-Type':'application/json'},body:JSON.stringify({item_id:itemId})});
    await loadPlaid();
  };



  const plaidConnected=plaidItems.length>0;

  // Totals from Plaid
  const plaidAssets = plaidItems.flatMap(i=>i.accounts)
    .filter(a=>a.type==='depository'||a.type==='investment')
    .reduce((s,a)=>s+(+a.balance||0),0);
  const plaidLiabilities = plaidItems.flatMap(i=>i.accounts)
    .filter(a=>a.type==='credit'||a.type==='loan')
    .reduce((s,a)=>s+(+a.balance||0),0);

  const re=+portfolio.total_equity||0;
  const stockVal=stocks.reduce((s,st)=>s+(+st.shares*(+st.price||0)),0);
  const manualA=manuals.filter(m=>m.type==='asset').reduce((s,m)=>s+(+m.value||0),0);
  const manualL=manuals.filter(m=>m.type==='liability').reduce((s,m)=>s+(+m.value||0),0);
  const totalA=re+stockVal+manualA+plaidAssets;
  const nw=totalA-manualL-plaidLiabilities;

  const addStock=async()=>{
    const parts=stockInput.toUpperCase().trim().split(':');
    const ticker=parts[0].trim(),shares=parseFloat(parts[1])||1;
    if(!ticker)return;
    try{const r=await fetch(`/api/stocks/quote?ticker=${ticker}`,{credentials:'include'});const d=await r.json();if(d.price)setStocks(p=>[...p.filter(s=>s.ticker!==ticker),{ticker,shares,price:d.price,change:d.change_pct||0}]);}catch{}
    setStockInput('');
  };

  return(
    <div className="page page-in">
      <div style={{marginBottom:18}}>
        <div className="lbl" style={{marginBottom:6}}>Total Net Worth</div>
        <div style={{fontSize:44,fontWeight:800,letterSpacing:-2,color:clr(nw),lineHeight:1}}>{fmt$k(nw)}</div>
        {totalA>0&&<>
          <div className="nw-bar">
            <div className="nw-seg" style={{width:`${(re/totalA*100).toFixed(0)}%`,background:accent}}/>
            <div className="nw-seg" style={{width:`${(stockVal/totalA*100).toFixed(0)}%`,background:'#6366f1'}}/>
            <div className="nw-seg" style={{width:`${(manualA/totalA*100).toFixed(0)}%`,background:'#10b981'}}/>
          </div>
          <div style={{display:'flex',gap:14,fontSize:11,color:'var(--muted)',flexWrap:'wrap'}}>
            <span><span style={{display:'inline-block',width:8,height:8,borderRadius:2,background:accent,marginRight:4}}/> RE {fmt$k(re)}</span>
            {stockVal>0&&<span><span style={{display:'inline-block',width:8,height:8,borderRadius:2,background:'#6366f1',marginRight:4}}/> Stocks {fmt$k(stockVal)}</span>}
            {plaidAssets>0&&<span><span style={{display:'inline-block',width:8,height:8,borderRadius:2,background:'#10b981',marginRight:4}}/> Bank {fmt$k(plaidAssets)}</span>}
            {plaidLiabilities>0&&<span><span style={{display:'inline-block',width:8,height:8,borderRadius:2,background:'#ef4444',marginRight:4}}/> Debt {fmt$k(plaidLiabilities)}</span>}
          </div>
        </>}
      </div>

      {/* ── PLAID BANKS ─────────────────────────────────────────────────── */}
      <div style={{marginBottom:16}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:10}}>
          <div style={{fontSize:11,fontWeight:800,color:'var(--muted)',letterSpacing:.5}}>CONNECTED BANKS</div>
          <button className="btn btn-prime btn-sm"
            onClick={()=>openPlaidLink()} disabled={plaidLoading}
            style={{fontSize:12,padding:'5px 12px'}}>
            {plaidLoading?'Connecting…':'+ Connect Bank'}
          </button>
        </div>
        {plaidError&&<div className="alert alert-err" style={{marginBottom:10}}>{plaidError}</div>}

        {!plaidConnected&&<div className="plaid-cta" onClick={()=>openPlaidLink()}>
          <div style={{fontSize:40,marginBottom:10}}>🏦</div>
          <div style={{fontSize:16,fontWeight:800,marginBottom:6}}>Connect Your Bank</div>
          <div style={{fontSize:13,color:'var(--muted)',lineHeight:1.6,marginBottom:20,maxWidth:280,margin:'0 auto 20px'}}>
            Pull in live balances from checking, savings, credit cards, loans, and investments to get your true net worth.
          </div>
          <button className="btn btn-prime" disabled={plaidLoading}>{plaidLoading?'Opening Plaid…':'Connect with Plaid'}</button>
        </div>}

        {plaidItems.map(item=>(
          <div key={item.item_id} className="glass-card" style={{padding:'16px 18px',marginBottom:10}}>
            <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',marginBottom:item.accounts?.length?12:0}}>
              <div style={{display:'flex',alignItems:'center',gap:10}}>
                <div style={{width:36,height:36,borderRadius:10,background:'rgba(37,99,235,.1)',
                  display:'flex',alignItems:'center',justifyContent:'center',fontSize:18}}>🏦</div>
                <div>
                  <div style={{fontWeight:700,fontSize:14}}>{item.institution}</div>
                  {item.needs_update
                    ?<div style={{fontSize:11,color:'#f59e0b',fontWeight:600}}>⚠ Re-authentication required</div>
                    :<div style={{fontSize:11,color:'var(--muted)'}}>{item.accounts?.length||0} accounts</div>
                  }
                </div>
              </div>
              <div style={{display:'flex',gap:8,alignItems:'center'}}>
                {item.needs_update&&<button className="btn btn-sm"
                  style={{fontSize:11,color:'#f59e0b',border:'1px solid #f59e0b'}}
                  onClick={()=>openPlaidLink(item.access_token)}>Fix</button>}
              </div>
            </div>
            {item.accounts?.map(a=>(
              <div key={a.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',
                padding:'8px 0',borderTop:'1px solid rgba(0,0,0,.05)'}}>
                <div>
                  <div style={{fontSize:13,fontWeight:600}}>{a.name} <span style={{fontSize:11,color:'var(--muted)'}}>····{a.mask}</span></div>
                  <div style={{fontSize:11,color:'var(--muted)',textTransform:'capitalize'}}>{a.subtype||a.type}</div>
                </div>
                <div style={{textAlign:'right'}}>
                  <div style={{fontSize:15,fontWeight:800,fontFamily:'JetBrains Mono',
                    color:(a.type==='credit'||a.type==='loan')?'#ef4444':'var(--fg)'}}>
                    {(a.type==='credit'||a.type==='loan')?'-':''}{fmt$(a.balance)}
                  </div>
                  {a.available!=null&&a.available!==a.balance&&
                    <div style={{fontSize:10,color:'var(--dim)'}}>Avail {fmt$(a.available)}</div>}
                </div>
              </div>
            ))}
            {item.error&&<div style={{fontSize:11,color:'#ef4444',paddingTop:8,fontWeight:600}}>{item.error}</div>}
          </div>
        ))}
      </div>

      {/* ── CASHFLOW FROM BANK ───────────────────────────────────────────── */}
      {plaidConnected&&<PlaidCashflow uid={user.id} accent={accent}/>}

      <div className="glass-card" style={{padding:20,marginTop:14}}>
        <div className="sec-hdr"><h4>Stocks &amp; ETFs</h4></div>
        <div style={{display:'flex',gap:8,marginBottom:14}}>
          <input className="sinput" value={stockInput} onChange={e=>setStockInput(e.target.value)} placeholder="AAPL:10  (ticker:shares)" onKeyDown={e=>e.key==='Enter'&&addStock()} style={{fontSize:13}}/>
          <button className="btn btn-prime btn-sm" onClick={addStock}>Add</button>
        </div>
        {stocks.length===0&&<div style={{fontSize:12,color:'var(--dim)',textAlign:'center',padding:'12px 0'}}>No holdings — type AAPL:10 and press Add</div>}
        {stocks.map(s=>(
          <div key={s.ticker} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'10px 0',borderBottom:'1px solid rgba(0,0,0,.05)'}}>
            <div><div style={{fontSize:14,fontWeight:800,fontFamily:'JetBrains Mono'}}>{s.ticker}</div><div style={{fontSize:11,color:'var(--muted)'}}>{s.shares} shares @ {fmt$(s.price)}</div></div>
            <div style={{textAlign:'right'}}>
              <div style={{fontSize:15,fontWeight:700,fontFamily:'JetBrains Mono'}}>{fmt$k(s.shares*s.price)}</div>
              <div style={{fontSize:11,fontWeight:700,color:clr(s.change)}}>{arrow(s.change)}{Math.abs(s.change).toFixed(1)}%</div>
            </div>
          </div>
        ))}
      </div>

      <button className="manual-link" onClick={()=>setShowManual(v=>!v)}>{showManual?'Hide manual entries':'+ Manual entry'}</button>
      {showManual&&<div className="glass-card" style={{padding:16,marginTop:4}}>
        {manuals.map(m=>(
          <div key={m.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'7px 0',borderBottom:'1px solid rgba(0,0,0,.05)'}}>
            <span style={{fontSize:13,color:m.type==='liability'?'var(--red)':'var(--ink)'}}>{m.label}</span>
            <input value={m.value} onChange={e=>setManuals(p=>p.map(x=>x.id===m.id?{...x,value:e.target.value}:x))} style={{width:90,padding:'5px 9px',border:'1.5px solid rgba(0,0,0,.1)',borderRadius:8,fontSize:13,textAlign:'right',outline:'none'}}/>
          </div>
        ))}
        <div style={{display:'flex',gap:6,marginTop:10}}>
          <input className="sinput" value={newLabel} onChange={e=>setNewLabel(e.target.value)} placeholder="Label" style={{fontSize:12}}/>
          <input className="sinput" value={newVal} onChange={e=>setNewVal(e.target.value)} placeholder="Amount" style={{width:80,fontSize:12}}/>
          <select value={newType} onChange={e=>setNewType(e.target.value)} className="sinput" style={{width:95,fontSize:12}}>
            <option value="asset">Asset</option><option value="liability">Liability</option>
          </select>
          <button className="btn btn-prime btn-sm" onClick={()=>{if(newLabel&&newVal){setManuals(p=>[...p,{id:Date.now(),label:newLabel,value:newVal,type:newType}]);setNewLabel('');setNewVal('');}}}>+</button>
        </div>
      </div>}
    </div>
  );
}

// ── SEARCH TAB ────────────────────────────────────────────────────────────────
function SearchTab({currentUser,onViewProfile}){
  const [q,setQ]=useState('');
  const [results,setResults]=useState([]);
  const [loading,setLoading]=useState(false);
  const [followed,setFollowed]=useState(new Set());

  useEffect(()=>{
    if(q.length<2){setResults([]);return;}
    const t=setTimeout(async()=>{
      setLoading(true);
      try{
        const r=await fetch(`/api/users/search?q=${encodeURIComponent(q)}`,{credentials:'include'});
        const d=await r.json();
        setResults(Array.isArray(d)?d:[]);
        setFollowed(new Set((Array.isArray(d)?d:[]).filter(u=>u.is_following).map(u=>u.id)));
      }catch{}
      setLoading(false);
    },320);
    return()=>clearTimeout(t);
  },[q]);

  const toggleFollow=async(uid,e)=>{
    e.stopPropagation();
    const isF=followed.has(uid);
    await fetch(`/api/${isF?'un':''}follow/${uid}`,{method:'POST',credentials:'include'});
    setFollowed(p=>{const n=new Set(p);isF?n.delete(uid):n.add(uid);return n;});
  };

  return(
    <div className="page page-in">
      <div className="search-wrap">
        <svg fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
        <input className="search-inp" value={q} onChange={e=>setQ(e.target.value)} placeholder="Search by name, username, or ticker…" autoComplete="off"/>
      </div>

      {q.length<2&&<div className="empty">
        <div className="empty-icon">🔍</div>
        <div className="empty-title">Find Investors</div>
        <div className="empty-sub">Search by name, username, or 4-letter ticker to view their public portfolio</div>
      </div>}

      {loading&&<div style={{textAlign:'center',padding:32,color:'var(--muted)',fontSize:13}}>Searching…</div>}

      {!loading&&results.map(u=>{
        const history=u.price_history?(typeof u.price_history==='string'?JSON.parse(u.price_history):u.price_history)||[]:[];
        const chartData=history.map(h=>+h.price);
        const isF=followed.has(u.id);
        const tv=+u.total_value||0;
        const mcf=+u.monthly_cashflow||0;
        return(
          <div key={u.id} className="user-card" onClick={()=>onViewProfile(u.id)}>
            <div style={{width:44,height:44,borderRadius:'50%',display:'flex',alignItems:'center',justifyContent:'center',fontSize:15,fontWeight:800,color:'#fff',background:u.avatar_color||'#2563eb',flexShrink:0,boxShadow:'0 3px 12px rgba(0,0,0,.2)'}}>{initials(u.full_name||u.username)}</div>
            <div style={{flex:1,minWidth:0}}>
              <div style={{display:'flex',alignItems:'center',gap:7,marginBottom:2}}>
                <span style={{fontSize:14,fontWeight:700}}>{u.full_name||u.username}</span>
                <span className="ticker-pill">{u.ticker}</span>
              </div>
              <div style={{fontSize:12,color:'var(--muted)'}}>{u.portfolio_name||u.username} · {u.property_count||0} properties</div>
              <div style={{fontSize:11,color:'var(--dim)',marginTop:2,display:'flex',gap:8}}>
                <span style={{color:mcf>=0?'var(--green)':'var(--red)',fontWeight:600}}>{mcf>=0?'+':''}{fmt$(mcf)}/mo</span>
                <span>{fmt$k(tv)} portfolio</span>
              </div>
            </div>
            {chartData.length>2&&<div style={{width:56,height:30,flexShrink:0}}><MiniLine data={chartData} color={u.avatar_color||'#2563eb'} height={30} fill={false}/></div>}
            <div style={{flexShrink:0,textAlign:'right',minWidth:64}}>
              <div style={{fontSize:15,fontWeight:800,fontFamily:'JetBrains Mono'}}>${(+u.share_price||1).toFixed(2)}</div>
              <button className={`btn-follow${isF?' on':''}`} style={{marginTop:5,fontSize:11}} onClick={e=>toggleFollow(u.id,e)}>{isF?'Following':'Follow'}</button>
            </div>
          </div>
        );
      })}

      {!loading&&q.length>=2&&results.length===0&&<div style={{textAlign:'center',padding:32,color:'var(--muted)',fontSize:13}}>No investors found for "{q}"</div>}
    </div>
  );
}

// ── PUBLIC PROFILE ────────────────────────────────────────────────────────────
function PublicProfile({uid,currentUser,onBack}){
  const [profile,setProfile]=useState(null);
  const [following,setFollowing]=useState(false);
  const [err,setErr]=useState('');
  const isOwn=currentUser?.id===uid;

  useEffect(()=>{
    setProfile(null);setErr('');
    fetch(`/api/users/${uid}/public`,{credentials:'include'})
      .then(r=>{if(!r.ok)throw new Error('Failed');return r.json();})
      .then(d=>setProfile(d))
      .catch(e=>setErr('Could not load profile'));
    if(!isOwn){
      fetch(`/api/users/${uid}/following-status`,{credentials:'include'})
        .then(r=>r.json()).then(d=>setFollowing(d.following)).catch(()=>{});
    }
  },[uid]);

  const toggleFollow=async()=>{
    await fetch(`/api/${following?'un':''}follow/${uid}`,{method:'POST',credentials:'include'});
    setFollowing(f=>!f);
  };

  if(err)return(<div className="page page-in-r">
    {onBack&&<button className="back-btn" style={{marginBottom:14}} onClick={onBack}>← Back</button>}
    <div className="alert alert-err">{err}</div>
  </div>);

  if(!profile)return(<div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'60vh',color:'var(--muted)',fontSize:13}}>Loading profile…</div>);

  const history=profile.price_history?(typeof profile.price_history==='string'?JSON.parse(profile.price_history):profile.price_history)||[]:[];
  const chartData=history.map(h=>+h.price);
  const tv=+profile.total_value||0,te=+profile.total_equity||0,mcf=+profile.monthly_cashflow||0;
  const props=profile.properties||[];
  const capRate=tv>0?(props.reduce((s,p)=>s+(+p.monthly_revenue*12-(+p.property_tax+ +p.insurance+ +p.hoa)*12),0)/tv)*100:0;
  const totalDown=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const coc=totalDown>0?(mcf*12/totalDown*100):0;
  const accent=profile.avatar_color||'#2563eb';

  return(
    <div className="page page-in-r">
      {onBack&&<button className="back-btn" style={{marginBottom:14}} onClick={onBack}>← Back to Search</button>}
      {isOwn&&<div className="alert alert-info" style={{marginBottom:12}}>👁 This is how your profile appears publicly</div>}

      {/* Cover + Avatar (Instagram/Twitter style) */}
      <div style={{borderRadius:'20px',overflow:'hidden',marginBottom:14,boxShadow:'0 16px 48px rgba(0,0,0,.12)'}}>
        <div className="profile-cover">
          <div className="profile-cover-inner" style={{background:`linear-gradient(135deg,${accent} 0%,${accent}88 100%)`}}/>
          <div className="profile-cover-grain"/>
          {/* Share price watermark on cover */}
          <div style={{position:'absolute',right:16,bottom:12,textAlign:'right'}}>
            <div style={{fontSize:10,fontWeight:700,color:'rgba(255,255,255,.7)',textTransform:'uppercase',letterSpacing:.8}}>Share Price</div>
            <div style={{fontSize:22,fontWeight:800,color:'#fff',fontFamily:'JetBrains Mono',letterSpacing:-.5}}>${(+profile.share_price||1).toFixed(2)}</div>
          </div>
        </div>
        <div className="profile-card">
          <div className="profile-av-wrap">
            <div className="profile-av" style={{background:accent}}>{initials(profile.full_name||profile.username)}</div>
          </div>
          <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start',marginTop:4}}>
            <div>
              <div className="profile-name">{profile.full_name||profile.username}</div>
              <div className="profile-meta">
                <span className="ticker-pill">{profile.ticker}</span>
                {profile.portfolio_name&&<span>{profile.portfolio_name}</span>}
                {profile.location&&<span style={{color:'var(--muted)'}}>📍 {profile.location}</span>}
              </div>
            </div>
            {!isOwn&&<button className={`btn-follow${following?' on':''}`} style={{flexShrink:0}} onClick={toggleFollow}>{following?'Following':'Follow'}</button>}
          </div>
          {profile.bio&&<div className="profile-bio">{profile.bio}</div>}
          <div style={{display:'flex',gap:18,marginTop:12,paddingTop:12,borderTop:'1px solid rgba(0,0,0,.06)'}}>
            <div><div style={{fontSize:16,fontWeight:800}}>{props.length}</div><div style={{fontSize:11,color:'var(--muted)',fontWeight:600}}>Properties</div></div>
            <div><div style={{fontSize:16,fontWeight:800,color:clr(mcf)}}>{fmt$s(mcf)}</div><div style={{fontSize:11,color:'var(--muted)',fontWeight:600}}>Monthly CF</div></div>
            <div><div style={{fontSize:16,fontWeight:800}}>{profile.health_score||0}</div><div style={{fontSize:11,color:'var(--muted)',fontWeight:600}}>Health Score</div></div>
          </div>
        </div>
      </div>

      {/* Share price chart */}
      {chartData.length>1&&<div className="glass-card" style={{padding:18,marginBottom:12}}>
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'baseline',marginBottom:12}}>
          <div className="lbl">Share Price History</div>
          <div style={{fontFamily:'JetBrains Mono',fontWeight:800,fontSize:18}}>${(+profile.share_price||1).toFixed(2)}</div>
        </div>
        <MiniLine data={chartData} color={accent} height={80}/>
      </div>}

      {/* Key metrics */}
      <div className="grid2" style={{marginBottom:12}}>
        <div className="scard" style={{'--accent':accent}}><div className="scard-lbl">Portfolio Value</div><div className="scard-val">{fmt$k(tv)}</div></div>
        <div className="scard"><div className="scard-lbl">Total Equity</div><div className="scard-val">{fmt$k(te)}</div></div>
        <div className="scard"><div className="scard-lbl">Monthly Cash Flow</div><div className="scard-val" style={{color:clr(mcf)}}>{fmt$s(mcf)}</div></div>
        <div className="scard"><div className="scard-lbl">Annual Cash Flow</div><div className="scard-val">{fmt$k(mcf*12)}</div></div>
        <div className="scard"><div className="scard-lbl">Cap Rate</div><div className="scard-val">{capRate.toFixed(1)}%</div></div>
        <div className="scard"><div className="scard-lbl">Cash-on-Cash</div><div className="scard-val">{coc.toFixed(1)}%</div></div>
      </div>

      {/* Properties */}
      {props.length>0&&<>
        <div className="sec-hdr" style={{marginBottom:10}}><h4>{props.length} {props.length===1?'Property':'Properties'}</h4></div>
        {props.map((p,i)=>{
          const val=+p.zestimate||+p.purchase_price||0;
          const cf=+p.monthly_revenue-(+p.mortgage+ +p.property_tax+ +p.insurance+ +p.hoa);
          return(
            <div key={i} className="prop-row" style={{'--accent':accent}}>
              <div className="prop-icon" style={{background:accent+'18'}}>🏠</div>
              <div style={{flex:1,minWidth:0}}>
                <div className="prop-name">{p.name}</div>
                {p.location&&<div className="prop-loc">📍 {p.location}</div>}
                {p.bedrooms>0&&<div className="prop-meta">{p.bedrooms}bd · {fmt$k(val)}</div>}
              </div>
              <div style={{textAlign:'right',flexShrink:0}}>
                <div style={{fontSize:15,fontWeight:800}}>{fmt$k(val)}</div>
                <div style={{fontSize:11,fontWeight:700,color:clr(cf)}}>{cf>=0?'+':''}{fmt$(cf)}/mo</div>
              </div>
            </div>
          );
        })}
      </>}
    </div>
  );
}

// ── PROFILE TAB ───────────────────────────────────────────────────────────────
function ProfileTab({user}){
  return(
    <div className="page page-in">
      <PublicProfile uid={user.id} currentUser={user} onBack={null}/>
    </div>
  );
}


// ── SETTINGS SHEET ────────────────────────────────────────────────────────────
function SettingsSheet({user,onClose,onUpdate,onLogout}){
  const [f,setF]=useState({full_name:user.full_name||'',portfolio_name:user.portfolio_name||'',bio:user.bio||'',location:user.location||'',accent_color:user.accent_color||'#2563eb'});
  const [msg,setMsg]=useState('');const [err,setErr]=useState('');
  const COLORS=['#2563eb','#6366f1','#10b981','#f43f5e','#f59e0b','#0891b2','#db2777','#ea580c'];

  const save=async()=>{
    setErr('');setMsg('');
    try{
      const r=await fetch('/api/user/settings',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(!r.ok){setErr(d.error||'Failed');return;}
      onUpdate(d.user);setMsg('Saved!');setTimeout(()=>setMsg(''),2000);
    }catch{setErr('Failed');}
  };

  return(
    <div className="overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="sheet">
        <div className="sheet-handle"/>
        <div style={{display:'flex',alignItems:'center',gap:12,marginBottom:20}}>
          <div style={{width:48,height:48,borderRadius:'50%',background:f.accent_color||'#2563eb',display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,fontWeight:800,color:'#fff'}}>{initials(user.full_name||user.username)}</div>
          <div><div style={{fontSize:17,fontWeight:800}}>{user.full_name||user.username}</div><div style={{fontSize:12,color:'var(--muted)',fontFamily:'JetBrains Mono'}}>{user.ticker}</div></div>
        </div>
        {err&&<div className="alert alert-err">{err}</div>}
        {msg&&<div className="alert alert-ok">✓ {msg}</div>}
        <div className="form-row"><label>Full name</label><input className="sinput" value={f.full_name} onChange={e=>setF(p=>({...p,full_name:e.target.value}))} placeholder="Brandon Bonomo"/></div>
        <div className="form-row"><label>Portfolio name</label><input className="sinput" value={f.portfolio_name} onChange={e=>setF(p=>({...p,portfolio_name:e.target.value}))} placeholder="BLB Realty"/></div>
        <div className="form-row"><label>Location</label><input className="sinput" value={f.location} onChange={e=>setF(p=>({...p,location:e.target.value}))} placeholder="Houston, TX"/></div>
        <div className="form-row"><label>Bio</label><input className="sinput" value={f.bio} onChange={e=>setF(p=>({...p,bio:e.target.value}))} placeholder="Real estate investor…"/></div>
        <div className="form-row" style={{marginBottom:20}}>
          <label>Accent color</label>
          <div className="swatch-row">{COLORS.map(c=><div key={c} className={`swatch${f.accent_color===c?' on':''}`} style={{background:c}} onClick={()=>setF(p=>({...p,accent_color:c}))}/>)}</div>
        </div>
        <div style={{display:'flex',gap:8}}>
          <button className="btn btn-prime" style={{flex:1}} onClick={save}>Save</button>
          <button className="btn btn-danger" onClick={async()=>{if(confirm('Sign out?')){await fetch('/api/auth/logout',{method:'POST',credentials:'include'});onLogout();}}}>Sign Out</button>
        </div>
      </div>
    </div>
  );
}



// ── MAIN APP ──────────────────────────────────────────────────────────────────
function MainApp({user:initUser,onLogout}){
  const [user,setUser]=useState(initUser);
  const [tab,setTab]=useState('portfolio');
  const [props,setProps]=useState([]);
  const [portfolio,setPortfolio]=useState({});
  const [showAdd,setShowAdd]=useState(false);
  const [editProp,setEditProp]=useState(null);
  const [profileUID,setProfileUID]=useState(null);
  const [showSettings,setShowSettings]=useState(false);
  const accent=user.accent_color||'#2563eb';

  useEffect(()=>{document.documentElement.style.setProperty('--accent',accent);},[accent]);

  const loadData=useCallback(async()=>{
    try{
      const [pf,pr]=await Promise.all([
        fetch(`/api/portfolio/${user.id}`,{credentials:'include'}).then(r=>r.json()),
        fetch(`/api/properties/${user.id}`,{credentials:'include'}).then(r=>r.json())
      ]);
      setPortfolio(pf||{});setProps(Array.isArray(pr)?pr:[]);
    }catch{}
  },[user.id]);

  useEffect(()=>{loadData();},[loadData]);

  const NAV=[
    {id:'portfolio',label:'Portfolio',d:'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6'},
    {id:'analytics',label:'Analytics',d:'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z'},
    {id:'networth',label:'Net Worth',d:'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z'},
    {id:'search',label:'Search',d:'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'},
    {id:'profile',label:'Profile',d:'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z'},
  ];

  const TITLES={portfolio:'Portfolio',analytics:'Analytics',networth:'Net Worth',search:'Search',profile:'Profile'};
  const tp={user,props,portfolio};

  return(
    <div className="shell">
      <div className="topbar">
        <div className="topbar-left">
          {profileUID&&<button className="back-btn" style={{margin:0}} onClick={()=>setProfileUID(null)}>←</button>}
          <span className="topbar-logo">🐦 PP</span>
          <span className="topbar-title">{profileUID?'Profile':TITLES[tab]}</span>
        </div>
        <div className="topbar-right">
          {tab==='portfolio'&&!profileUID&&<button className="btn btn-prime btn-sm" onClick={()=>setShowAdd(true)}>+ Add</button>}
          <div className="av-btn" style={{background:accent}} onClick={()=>setShowSettings(true)}>{initials(user.full_name||user.username)}</div>
        </div>
      </div>

      <div className="page-area">
        {profileUID
          ?<PublicProfile uid={profileUID} currentUser={user} onBack={()=>setProfileUID(null)}/>
          :<>
            {tab==='portfolio'&&<PortfolioTab {...tp} onAdd={()=>setShowAdd(true)} onEdit={setEditProp}
              onRefreshValue={async pid=>{
                try{
                  const r=await fetch(`/api/properties/${pid}/refresh-value`,{method:'POST',credentials:'include'});
                  const d=await r.json();
                  if(d.new_value){loadData();alert(`Updated: $${d.new_value.toLocaleString()}`);}
                  else if(d.error){
                    if(d.error.includes('RENTCAST_API_KEY'))alert('Set RENTCAST_API_KEY in Render environment to enable live value refresh.');
                    else alert('Refresh: '+d.error);
                  }
                }catch(e){alert('Refresh failed: '+e.message);}
              }}
            />}
            {tab==='analytics'&&<AnalyticsTab {...tp}/>}
            {tab==='networth'&&<NetWorthTab {...tp}/>}
            {tab==='search'&&<SearchTab currentUser={user} onViewProfile={uid=>{setProfileUID(uid);}}/>}
            {tab==='profile'&&<ProfileTab user={user}/>}
          </>
        }
      </div>

      <nav className="bottom-nav">
        {NAV.map(n=>(
          <div key={n.id} className={`nav-item${tab===n.id&&!profileUID?' on':''}`} onClick={()=>{setProfileUID(null);setTab(n.id);}}>
            <svg fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d={n.d}/></svg>
            <span>{n.label}</span>
            <div className="nav-pip"/>
          </div>
        ))}
      </nav>

      {showSettings&&<SettingsSheet user={user} onClose={()=>setShowSettings(false)} onUpdate={u=>setUser(u)} onLogout={onLogout}/>}
      {showAdd&&<AddPropSheet uid={user.id} onClose={()=>setShowAdd(false)} onSave={p=>{setProps(v=>[p,...v]);loadData();setShowAdd(false);}}/>}
      {editProp&&<EditPropSheet prop={editProp} onClose={()=>setEditProp(null)} onSave={p=>{setProps(v=>v.map(x=>x.id===p.id?p:x));setEditProp(null);loadData();}} onDelete={id=>{setProps(v=>v.filter(x=>x.id!==id));setEditProp(null);loadData();}}/>}
    </div>
  );
}

// ── ROOT ──────────────────────────────────────────────────────────────────────
function App(){
  const [user,setUser]=useState(null);const [loading,setLoading]=useState(true);
  useEffect(()=>{
    fetch('/api/auth/me',{credentials:'include'}).then(r=>r.ok?r.json():null)
      .then(d=>{if(d?.user)setUser(d.user);}).catch(()=>{}).finally(()=>setLoading(false));
  },[]);
  if(loading)return(
    <div style={{height:'100dvh',display:'flex',alignItems:'center',justifyContent:'center'}}>
      <div style={{textAlign:'center'}}><div style={{fontSize:52,animation:'float 2s ease-in-out infinite'}}>🐦</div><div style={{fontWeight:700,color:'var(--muted)',marginTop:12,fontSize:14}}>Loading…</div></div>
      <style>{`@keyframes float{0%,100%{transform:translateY(0)}50%{transform:translateY(-10px)}}`}</style>
    </div>
  );
  if(!user)return <AuthScreen onLogin={setUser}/>;
  return <MainApp user={user} onLogout={()=>setUser(null)}/>;
}
ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>
</body>
</html>"""



@app.route('/api/users/search')
def search_users():
    q = request.args.get('q','').strip()
    if not q or len(q) < 2: return jsonify([])
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,
                       u.avatar_color,u.bio,u.location,
                       pm.total_value,pm.total_equity,pm.monthly_cashflow,
                       pm.health_score,pm.share_price,pm.price_history,pm.property_count
                FROM users u
                LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
                WHERE u.is_public=true
                  AND (LOWER(u.username) LIKE %s OR LOWER(u.ticker) LIKE %s OR LOWER(u.full_name) LIKE %s)
                ORDER BY pm.total_value DESC NULLS LAST LIMIT 20
            """, (f'%{q.lower()}%','%'+q.lower()+'%','%'+q.lower()+'%'))
            users = [dict(r) for r in cur.fetchall()]
            cur.close()
        # Check following status
        uid = session.get('user_id')
        if uid and users:
            ids = [u['id'] for u in users]
            with get_db() as conn:
                cur = conn.cursor()
                cur.execute("SELECT following_id FROM follows WHERE follower_id=%s AND following_id=ANY(%s)",(uid,ids))
                following_ids = {r[0] for r in cur.fetchall()}; cur.close()
            for u in users:
                u['is_following'] = u['id'] in following_ids
        return jsonify(users)
    except Exception as e:
        print(f'search_users error: {e}')
        return jsonify([])

@app.route('/api/users/<int:uid>/public')
def user_public(uid):
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,
                       u.avatar_color,u.bio,u.location,u.is_public,
                       pm.total_value,pm.total_equity,pm.monthly_cashflow,pm.annual_cashflow,
                       pm.property_count,pm.health_score,pm.share_price,pm.price_history,pm.updated_at
                FROM users u
                LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
                WHERE u.id=%s
            """, (uid,))
            row = cur.fetchone()
            if not row:
                cur.close()
                return jsonify({'error':'User not found'}), 404
            u = dict(row)
            # Get properties (safe column selection)
            try:
                cur.execute("""
                    SELECT name,location,purchase_price,
                           COALESCE(zestimate, purchase_price, 0) as zestimate,
                           COALESCE(bedrooms,0) as bedrooms,
                           COALESCE(monthly_revenue,0) as monthly_revenue,
                           COALESCE(mortgage,0) as mortgage,
                           COALESCE(property_tax,0) as property_tax,
                           COALESCE(insurance,0) as insurance,
                           COALESCE(hoa,0) as hoa,
                           COALESCE(equity,0) as equity
                    FROM properties WHERE user_id=%s ORDER BY purchase_price DESC NULLS LAST
                """, (uid,))
            except Exception:
                cur.execute("SELECT name,location,purchase_price FROM properties WHERE user_id=%s", (uid,))
            u['properties'] = [dict(r) for r in cur.fetchall()]
            cur.close()
        # Privacy check — own profile always visible
        req_uid = session.get('user_id')
        if req_uid != uid and not u.get('is_public'):
            return jsonify({'error':'Private profile'}), 403
        u.pop('password_hash', None); u.pop('totp_secret', None)
        if u.get('price_history') and isinstance(u['price_history'], str):
            try: u['price_history'] = json.loads(u['price_history'])
            except: u['price_history'] = []
        if u.get('updated_at'): u['updated_at'] = str(u['updated_at'])
        return jsonify(u)
    except Exception as e:
        print(f'user_public error: {e}')
        import traceback; traceback.print_exc()
        return jsonify({'error': f'Server error: {str(e)}'}), 500

@app.route('/api/users/<int:uid>/following-status')
def following_status(uid):
    req_uid = session.get('user_id')
    if not req_uid: return jsonify({'following': False})
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM follows WHERE follower_id=%s AND following_id=%s", (req_uid, uid))
            following = cur.fetchone() is not None; cur.close()
        return jsonify({'following': following})
    except Exception as e:
        return jsonify({'following': False})



# ── QUARTERLY RESULTS ─────────────────────────────────────────────────────────

@app.route('/api/quarterly/results/<int:uid>')
def quarterly_results(uid):
    """Return quarterly aggregated performance from monthly_snapshots"""
    req_uid = session.get('user_id')
    if not req_uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""
                SELECT
                    EXTRACT(YEAR FROM snapshot_month)::int AS year,
                    EXTRACT(QUARTER FROM snapshot_month)::int AS quarter,
                    MAX(snapshot_month::text) AS period_end,
                    MAX(total_value)          AS total_value,
                    MAX(total_equity)         AS total_equity,
                    SUM(gross_revenue)        AS gross_revenue,
                    SUM(net_cashflow)         AS net_cashflow,
                    SUM(total_expenses)       AS total_expenses,
                    AVG(avg_cap_rate)         AS avg_cap_rate,
                    MAX(property_count)       AS property_count
                FROM monthly_snapshots
                WHERE user_id = %s
                GROUP BY year, quarter
                ORDER BY year ASC, quarter ASC
            """, (uid,))
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()

        # Compute QoQ deltas and YoY deltas
        quarters = []
        for i, row in enumerate(rows):
            q = dict(row)
            q['label'] = f"Q{int(q['quarter'])} '{str(int(q['year']))[-2:]}"
            q['full_label'] = f"Q{int(q['quarter'])} {int(q['year'])}"

            # QoQ delta
            prev = rows[i-1] if i > 0 else None
            q['value_qoq'] = float(q['total_value'] or 0) - float(prev['total_value'] or 0) if prev else None
            q['cf_qoq']    = float(q['net_cashflow'] or 0) - float(prev['net_cashflow'] or 0) if prev else None
            q['rev_qoq']   = float(q['gross_revenue'] or 0) - float(prev['gross_revenue'] or 0) if prev else None

            # YoY delta (4 quarters back)
            yoy = rows[i-4] if i >= 4 else None
            q['value_yoy_pct'] = ((float(q['total_value'] or 0) / float(yoy['total_value']) - 1) * 100) if yoy and yoy['total_value'] and float(yoy['total_value']) > 0 else None
            q['cf_yoy_pct']    = ((float(q['net_cashflow'] or 0) / float(yoy['net_cashflow']) - 1) * 100) if yoy and yoy['net_cashflow'] and float(yoy['net_cashflow'] or 0) != 0 else None

            quarters.append(q)

        # Current quarter summary (most recent)
        current = quarters[-1] if quarters else {}
        # Best quarter
        if quarters:
            best_cf = max(quarters, key=lambda q: float(q['net_cashflow'] or 0))
        else:
            best_cf = {}

        return jsonify({
            'quarters': list(reversed(quarters)),   # newest first
            'current': current,
            'best_cf': best_cf,
            'total_quarters': len(quarters),
        })
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

@app.route('/api/quarterly/property/<int:pid>')
def quarterly_property(pid):
    """Per-property quarterly revenue from monthly snapshots (estimated from property data)"""
    req_uid = session.get('user_id')
    if not req_uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            # Verify ownership
            cur.execute("SELECT * FROM properties WHERE id=%s AND user_id=%s", (pid, req_uid))
            prop = cur.fetchone()
            if not prop: cur.close(); return jsonify({'error': 'Not found'}), 404

            # Get portfolio quarterly data and estimate this property's share
            cur.execute("""
                SELECT
                    EXTRACT(YEAR FROM snapshot_month)::int AS year,
                    EXTRACT(QUARTER FROM snapshot_month)::int AS quarter,
                    SUM(gross_revenue) AS gross_revenue,
                    SUM(net_cashflow)  AS net_cashflow,
                    MAX(property_count) AS property_count
                FROM monthly_snapshots WHERE user_id=%s
                GROUP BY year, quarter ORDER BY year, quarter
            """, (req_uid,))
            rows = [dict(r) for r in cur.fetchall()]
            cur.close()

        monthly_rev = float(prop.get('monthly_revenue') or 0)
        monthly_exp = (float(prop.get('mortgage') or 0) + float(prop.get('insurance') or 0) +
                       float(prop.get('hoa') or 0) + float(prop.get('property_tax') or 0))

        quarters = []
        for row in rows:
            q = dict(row)
            pc = max(1, int(q.get('property_count') or 1))
            # Estimate this property's contribution
            q['est_revenue']  = monthly_rev * 3
            q['est_expenses'] = monthly_exp * 3
            q['est_cf']       = q['est_revenue'] - q['est_expenses']
            q['label'] = f"Q{int(q['quarter'])} '{str(int(q['year']))[-2:]}"
            quarters.append(q)

        return jsonify({'quarters': list(reversed(quarters)), 'property': dict(prop)})
    except Exception as e:
        import traceback; traceback.print_exc()
        return jsonify({'error': str(e)}), 500

# ── SERVE ──────────────────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_app(path):
    return Response(HTML, mimetype='text/html')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
