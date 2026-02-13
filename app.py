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
                item_id TEXT,
                institution_name TEXT DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
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
            exp = sum(float(d.get(k,0)) for k in ['mortgage','insurance','hoa','property_tax'])
            eq = float(d.get('zestimate') or d.get('purchase_price',0)) - (float(d.get('purchase_price',0)) - float(d.get('down_payment',0)))
            # Try full insert with all columns; fall back to core columns if new ones don't exist yet
            try:
                cur.execute("""
                    INSERT INTO properties (user_id,name,location,purchase_price,down_payment,mortgage,insurance,hoa,property_tax,monthly_revenue,monthly_expenses,zestimate,zpid,bedrooms,bathrooms,sqft,year_built,zillow_url,equity)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
                """, (uid, d.get('name','Property'), d.get('location',''),
                      float(d.get('purchase_price',0)), float(d.get('down_payment',0)),
                      float(d.get('mortgage',0)), float(d.get('insurance',0)),
                      float(d.get('hoa',0)), float(d.get('property_tax',0)),
                      float(d.get('monthly_revenue',0)), exp,
                      float(d.get('zestimate') or d.get('purchase_price',0)),
                      d.get('zpid',''), int(d.get('bedrooms',0) or 0),
                      float(d.get('bathrooms',0) or 0), int(d.get('sqft',0) or 0),
                      int(d.get('year_built',0) or 0), d.get('zillow_url',''), max(0,eq)))
            except Exception as col_err:
                conn.rollback()
                # Fallback: core columns only (matches original DB schema)
                cur.execute("""
                    INSERT INTO properties (user_id,name,location,purchase_price,down_payment,equity,mortgage,insurance,hoa,property_tax,monthly_revenue,monthly_expenses)
                    VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
                """, (uid, d.get('name','Property'), d.get('location',''),
                      float(d.get('purchase_price',0)), float(d.get('down_payment',0)),
                      max(0,eq), float(d.get('mortgage',0)), float(d.get('insurance',0)),
                      float(d.get('hoa',0)), float(d.get('property_tax',0)),
                      float(d.get('monthly_revenue',0)), exp))
            prop = dict(cur.fetchone())
            conn.commit(); cur.close()
            update_metrics(uid)
            if prop.get('created_at'): prop['created_at'] = prop['created_at'].isoformat()
            return jsonify(prop), 201

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
        return jsonify({'error': 'Zillow is blocking this request. Open the property page in your browser first, then paste the URL.'})

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


# ── ATTOM ──────────────────────────────────────────────────────────────────────
ATTOM_KEY = os.environ.get('ATTOM_API_KEY','')

@app.route('/api/property/lookup')
def attom_lookup():
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
PLAID_SECRET = os.environ.get('PLAID_SECRET','')
PLAID_ENV = os.environ.get('PLAID_ENV','sandbox')

@app.route('/api/plaid/create-link-token')
def plaid_link():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    if not PLAID_CLIENT_ID: return jsonify({'error': 'Plaid not configured'}), 400
    try:
        payload = json.dumps({"client_id": PLAID_CLIENT_ID, "secret": PLAID_SECRET,
            "user": {"client_user_id": str(uid)}, "client_name": "Property Pigeon",
            "products": ["transactions"], "country_codes": ["US"], "language": "en"}).encode()
        req = urllib.request.Request(f"https://{PLAID_ENV}.plaid.com/link/token/create",
            data=payload, headers={'Content-Type': 'application/json'})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        return jsonify({'link_token': data.get('link_token')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/exchange-token', methods=['POST'])
def plaid_exchange():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json or {}
    try:
        payload = json.dumps({"client_id": PLAID_CLIENT_ID, "secret": PLAID_SECRET,
            "public_token": d['public_token']}).encode()
        req = urllib.request.Request(f"https://{PLAID_ENV}.plaid.com/item/public_token/exchange",
            data=payload, headers={'Content-Type': 'application/json'})
        data = json.loads(urllib.request.urlopen(req, timeout=10).read())
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO plaid_items (user_id,access_token,item_id,institution_name) VALUES (%s,%s,%s,%s)",
                (uid, data['access_token'], data.get('item_id',''), d.get('institution_name','')))
            conn.commit(); cur.close()
        return jsonify({'ok': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

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
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<title>Property Pigeon</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;0,9..40,800;1,9..40,400&display=swap" rel="stylesheet">
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0;}
:root{
  --blue:#1a56db;--green:#059669;--red:#d92d20;--purple:#7c3aed;--amber:#f59e0b;
  --g50:#f9fafb;--g100:#f3f4f6;--g200:#e5e7eb;--g300:#d1d5db;
  --g400:#9ca3af;--g500:#6b7280;--g700:#374151;--g900:#111827;
  --glass:rgba(255,255,255,0.68);--glassh:rgba(255,255,255,0.88);
  --gb:rgba(255,255,255,0.82);
  --gsh:0 8px 32px rgba(31,38,135,.1),0 2px 8px rgba(31,38,135,.06);
  --gsh2:0 16px 48px rgba(31,38,135,.15),0 4px 16px rgba(31,38,135,.08);
  --blur:blur(24px) saturate(180%);--r:12px;--r2:18px;
  --nav-h:68px;--top-h:52px;
  --safe-b:env(safe-area-inset-bottom, 0px);
}
html,body{height:100%;overflow:hidden;-webkit-font-smoothing:antialiased;}
body{font-family:'DM Sans',sans-serif;background:linear-gradient(135deg,#dce8ff 0%,#eef2ff 25%,#e6f7ef 55%,#f0e8ff 100%);background-attachment:fixed;color:var(--g900);}
input,button,select,textarea{font-family:inherit;}
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-thumb{background:rgba(0,0,0,.14);border-radius:99px;}
::-webkit-scrollbar-track{background:transparent;}

/* ── AUTH ───────────────────────────────────────────────────────────────── */
.auth-wrap{display:flex;height:100vh;height:100dvh;}
.auth-panel{width:360px;flex-shrink:0;padding:56px 44px;display:flex;flex-direction:column;justify-content:center;background:var(--blue);position:relative;overflow:hidden;}
.auth-panel::after{content:'';position:absolute;inset:0;background:linear-gradient(160deg,rgba(255,255,255,.1) 0%,transparent 60%);pointer-events:none;}
.auth-bird{font-size:48px;margin-bottom:20px;}
.auth-panel h1{font-size:28px;font-weight:800;color:#fff;letter-spacing:-.5px;margin-bottom:10px;}
.auth-panel p{font-size:14px;color:rgba(255,255,255,.78);line-height:1.65;}
.auth-main{flex:1;display:flex;align-items:center;justify-content:center;padding:28px;}
.auth-card{width:100%;max-width:400px;background:var(--glassh);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.9);border-radius:24px;padding:34px;box-shadow:var(--gsh2),inset 0 1px 0 rgba(255,255,255,.95);}
.auth-logo{font-size:10px;font-weight:700;color:var(--g400);letter-spacing:2px;text-transform:uppercase;margin-bottom:20px;}
.auth-card h2{font-size:23px;font-weight:800;letter-spacing:-.4px;margin-bottom:3px;}
.auth-sub{font-size:13px;color:var(--g500);margin-bottom:22px;}
.field{margin-bottom:13px;}
.field label{display:block;font-size:10px;font-weight:700;color:var(--g500);text-transform:uppercase;letter-spacing:.6px;margin-bottom:4px;}
.field input{width:100%;padding:10px 12px;border:1.5px solid var(--g200);border-radius:10px;font-size:14px;background:rgba(255,255,255,.75);transition:.15s;}
.field input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(26,86,219,.1);}
.field .hint{font-size:11px;margin-top:3px;font-weight:600;}
.hint-ok{color:var(--green);}
.hint-bad{color:var(--red);}
.btn-primary{width:100%;padding:12px;background:var(--blue);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;transition:.15s;margin-top:2px;}
.btn-primary:hover{filter:brightness(1.08);transform:translateY(-1px);box-shadow:0 6px 18px rgba(26,86,219,.3);}
.btn-primary:active{transform:scale(.97);}
.btn-link{background:none;border:none;font-size:13px;color:var(--blue);cursor:pointer;display:block;width:100%;text-align:center;padding:10px;margin-top:4px;}
.btn-link:hover{text-decoration:underline;}
.alert{border-radius:9px;padding:10px 13px;font-size:13px;margin-bottom:13px;}
.alert-err{background:rgba(217,45,32,.06);border:1px solid rgba(217,45,32,.2);color:#b91c1c;}
.alert-ok{background:rgba(5,150,105,.06);border:1px solid rgba(5,150,105,.2);color:var(--green);}
.alert-warn{background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.2);color:#92400e;}
.alert-info{background:rgba(26,86,219,.05);border:1px solid rgba(26,86,219,.15);color:var(--blue);}

/* ── SHELL ──────────────────────────────────────────────────────────────── */
.shell{display:flex;flex-direction:column;height:100vh;height:100dvh;overflow:hidden;}
.topbar{
  flex-shrink:0;height:var(--top-h);
  display:flex;align-items:center;justify-content:space-between;padding:0 18px;
  background:rgba(255,255,255,.6);
  backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border-bottom:1px solid rgba(255,255,255,.65);
  position:relative;z-index:10;
}
.topbar-title{font-size:17px;font-weight:800;letter-spacing:-.3px;}
.topbar-av{width:34px;height:34px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;cursor:pointer;box-shadow:0 2px 8px rgba(0,0,0,.2);}
.page-area{flex:1;overflow:hidden;position:relative;}
.page{height:100%;overflow-y:auto;padding:18px 16px;padding-bottom:calc(var(--nav-h) + 12px + var(--safe-b));}
@keyframes fadeUp{from{opacity:0;transform:translateY(8px)}to{opacity:1;transform:translateY(0)}}
.page-in{animation:fadeUp .18s ease;}

/* ── BOTTOM NAV ─────────────────────────────────────────────────────────── */
.bottom-nav{
  flex-shrink:0;
  position:fixed;bottom:0;left:0;right:0;
  height:calc(var(--nav-h) + var(--safe-b));
  padding-bottom:var(--safe-b);
  background:rgba(255,255,255,.72);
  backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border-top:1px solid rgba(255,255,255,.75);
  display:flex;align-items:stretch;justify-content:space-around;
  z-index:50;
  box-shadow:0 -4px 24px rgba(31,38,135,.08);
}
.nav-tab{flex:1;display:flex;flex-direction:column;align-items:center;justify-content:center;gap:3px;cursor:pointer;transition:all .15s;padding:0 4px;-webkit-tap-highlight-color:transparent;}
.nav-tab svg{width:22px;height:22px;transition:.15s;}
.nav-tab span{font-size:10px;font-weight:600;transition:.15s;color:var(--g400);}
.nav-tab svg{stroke:var(--g400);}
.nav-tab.on svg{stroke:var(--blue);}
.nav-tab.on span{color:var(--blue);}
.nav-tab.on .nav-dot{background:var(--blue);}
.nav-dot{width:4px;height:4px;border-radius:50%;background:transparent;margin-top:-2px;}

/* ── SUB TABS (inside Performance) ──────────────────────────────────────── */
.sub-tabs{display:flex;gap:4px;background:rgba(0,0,0,.05);border-radius:12px;padding:3px;margin-bottom:18px;}
.sub-tab{flex:1;text-align:center;padding:7px 8px;border-radius:9px;font-size:12px;font-weight:600;color:var(--g500);cursor:pointer;transition:.15s;border:none;background:transparent;}
.sub-tab.on{background:white;color:var(--g900);box-shadow:0 1px 4px rgba(0,0,0,.1);}

/* ── CARDS ──────────────────────────────────────────────────────────────── */
.card{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--gb);border-radius:var(--r2);box-shadow:var(--gsh);transition:.2s;}
.glass-row{background:rgba(255,255,255,.58);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.75);border-radius:13px;margin-bottom:7px;transition:all .18s cubic-bezier(.34,1.56,.64,1);}
.glass-row:hover{background:rgba(255,255,255,.88)!important;transform:translateY(-2px)!important;box-shadow:0 8px 24px rgba(26,86,219,.1)!important;}

/* ── STATS ──────────────────────────────────────────────────────────────── */
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:10px;}
.stat{background:rgba(255,255,255,.65);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.8);border-radius:var(--r);padding:14px 14px;transition:.2s;}
.stat-lbl{font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px;}
.stat-val{font-size:20px;font-weight:800;letter-spacing:-.5px;line-height:1.1;}
.stat-sub{font-size:11px;color:var(--g500);margin-top:3px;}

/* ── HERO ───────────────────────────────────────────────────────────────── */
.hero{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--gb);border-radius:var(--r2);padding:20px;margin-bottom:14px;box-shadow:var(--gsh);}
.lbl{font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;}
.big{font-size:32px;font-weight:800;letter-spacing:-1px;line-height:1;}
.chart-wrap{height:68px;margin:10px 0 4px;}

/* ── PROP ROWS ──────────────────────────────────────────────────────────── */
.prop-row{display:flex;align-items:center;gap:12px;padding:12px 13px;cursor:pointer;}
.prop-icon{width:40px;height:40px;border-radius:11px;display:flex;align-items:center;justify-content:center;font-size:17px;flex-shrink:0;}
.prop-name{font-size:14px;font-weight:700;line-height:1.2;}
.prop-loc{font-size:11px;color:var(--g400);margin-top:1px;}
.prop-zest{font-size:11px;color:var(--blue);font-weight:600;margin-top:2px;}
.prop-right{text-align:right;flex-shrink:0;}
.prop-val{font-size:15px;font-weight:800;}
.prop-cf{font-size:11px;margin-top:1px;}

/* ── CF ROWS ────────────────────────────────────────────────────────────── */
.cf-row{display:flex;justify-content:space-between;align-items:center;padding:9px 12px;border-radius:8px;background:rgba(255,255,255,.5);margin-bottom:4px;}
.cf-row.total-row{background:rgba(26,86,219,.06);border:1px solid rgba(26,86,219,.14);}
.cf-lbl{font-size:13px;}
.cf-val{font-size:13px;font-weight:700;}

/* ── SLIDERS ────────────────────────────────────────────────────────────── */
.slider-row{margin-bottom:16px;}
.slider-hdr{display:flex;justify-content:space-between;align-items:baseline;margin-bottom:6px;}
.slider-name{font-size:13px;font-weight:600;}
.slider-val{font-size:14px;font-weight:800;color:var(--blue);}
input[type=range]{width:100%;height:4px;border-radius:99px;-webkit-appearance:none;appearance:none;background:var(--g200);outline:none;cursor:pointer;}
input[type=range]::-webkit-slider-thumb{-webkit-appearance:none;appearance:none;width:18px;height:18px;border-radius:50%;background:var(--blue);box-shadow:0 2px 8px rgba(26,86,219,.4);border:2px solid #fff;transition:.1s;}
input[type=range]::-moz-range-thumb{width:18px;height:18px;border-radius:50%;background:var(--blue);box-shadow:0 2px 8px rgba(26,86,219,.4);border:2px solid #fff;cursor:pointer;}

/* ── PROJ TABLE ─────────────────────────────────────────────────────────── */
.proj-table{width:100%;border-collapse:collapse;font-size:12px;}
.proj-table th{padding:7px 10px;text-align:right;font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--g200);white-space:nowrap;}
.proj-table th:first-child{text-align:left;}
.proj-table td{padding:7px 10px;text-align:right;border-bottom:1px solid rgba(0,0,0,.04);}
.proj-table td:first-child{text-align:left;font-weight:700;}
.proj-table tr.milestone-row td{background:rgba(26,86,219,.04);font-weight:600;}

/* ── SEARCH / PROFILE ───────────────────────────────────────────────────── */
.search-input-wrap{position:relative;margin-bottom:16px;}
.search-input-wrap svg{position:absolute;left:12px;top:50%;transform:translateY(-50%);width:16px;height:16px;stroke:var(--g400);}
.search-inp{width:100%;padding:11px 12px 11px 36px;border:1.5px solid var(--g200);border-radius:12px;font-size:14px;background:rgba(255,255,255,.8);transition:.15s;}
.search-inp:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(26,86,219,.1);}
.user-result{display:flex;align-items:center;gap:12px;padding:13px 14px;border-radius:13px;background:rgba(255,255,255,.65);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.8);margin-bottom:8px;cursor:pointer;transition:.18s;}
.user-result:hover{background:rgba(255,255,255,.9);transform:translateY(-1px);box-shadow:0 6px 20px rgba(26,86,219,.08);}
.ur-name{font-size:14px;font-weight:700;}
.ur-sub{font-size:12px;color:var(--g500);margin-top:1px;}
.ur-right{margin-left:auto;text-align:right;flex-shrink:0;}
.ur-price{font-size:15px;font-weight:800;}
.ur-delta{font-size:11px;margin-top:1px;}
.ticker-badge{display:inline-block;padding:2px 8px;border-radius:20px;font-size:10px;font-weight:800;background:rgba(26,86,219,.1);color:var(--blue);letter-spacing:.5px;}

/* ── PUBLIC PROFILE ─────────────────────────────────────────────────────── */
.profile-header{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--gb);border-radius:var(--r2);padding:20px;margin-bottom:14px;box-shadow:var(--gsh);}
.profile-av{width:56px;height:56px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:18px;font-weight:800;color:#fff;box-shadow:0 4px 16px rgba(0,0,0,.2);}
.profile-name{font-size:20px;font-weight:800;letter-spacing:-.4px;margin-top:10px;}
.profile-handle{font-size:13px;color:var(--g500);margin-top:2px;}
.profile-bio{font-size:13px;color:var(--g700);margin-top:8px;line-height:1.5;}
.pub-preview-banner{display:flex;align-items:center;gap:8px;padding:8px 12px;background:rgba(5,150,105,.08);border:1px solid rgba(5,150,105,.2);border-radius:10px;margin-bottom:14px;font-size:12px;font-weight:600;color:var(--green);}

/* ── SHARE PRICE CHART ──────────────────────────────────────────────────── */
.share-price-card{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--gb);border-radius:var(--r2);padding:18px;margin-bottom:14px;box-shadow:var(--gsh);}

/* ── NET WORTH ──────────────────────────────────────────────────────────── */
.nw-big{font-size:40px;font-weight:800;letter-spacing:-1.5px;line-height:1;}
.nw-bar{height:10px;border-radius:99px;overflow:hidden;display:flex;gap:2px;margin:12px 0;}
.nw-seg{border-radius:99px;transition:width .4s ease;}
.plaid-cta{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:2px dashed rgba(26,86,219,.25);border-radius:var(--r2);padding:32px;text-align:center;cursor:pointer;transition:.2s;}
.plaid-cta:hover{background:rgba(255,255,255,.85);border-style:solid;}
.manual-link{background:none;border:none;font-size:11px;color:var(--g300);cursor:pointer;margin-top:12px;display:block;width:100%;text-align:center;}
.manual-link:hover{color:var(--g500);}

/* ── BTNS ───────────────────────────────────────────────────────────────── */
.btn{padding:9px 16px;border-radius:9px;font-size:13px;font-weight:600;border:none;cursor:pointer;transition:.15s;display:inline-flex;align-items:center;gap:6px;}
.btn:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.06);box-shadow:0 4px 12px rgba(0,0,0,.1);}
.btn:active:not(:disabled){transform:scale(.97);}
.btn:disabled{opacity:.45;cursor:not-allowed;}
.btn-blue{background:var(--blue);color:#fff;}
.btn-ghost{background:rgba(0,0,0,.05);color:var(--g700);}
.btn-outline{background:transparent;border:1.5px solid var(--g200);color:var(--g700);}
.btn-danger{background:rgba(217,45,32,.07);color:#b91c1c;border:1.5px solid rgba(217,45,32,.2);}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:7px;}

/* ── MODAL ──────────────────────────────────────────────────────────────── */
.overlay{position:fixed;inset:0;background:rgba(10,15,40,.45);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);z-index:200;display:flex;align-items:flex-end;justify-content:center;padding:0;}
@media(min-width:600px){.overlay{align-items:center;padding:20px;}}
@keyframes sheetUp{from{opacity:0;transform:translateY(40px)}to{opacity:1;transform:translateY(0)}}
.modal{background:var(--glassh);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.92);border-radius:22px 22px 0 0;width:100%;max-width:560px;max-height:92vh;overflow-y:auto;padding:24px 22px calc(22px + var(--safe-b));box-shadow:0 -8px 48px rgba(0,0,0,.18);animation:sheetUp .22s cubic-bezier(.34,1.56,.64,1);}
@media(min-width:600px){.modal{border-radius:22px;max-height:90vh;padding:28px;}}
.modal-handle{width:36px;height:4px;background:var(--g200);border-radius:99px;margin:0 auto 18px;}
.modal h3{font-size:17px;font-weight:800;letter-spacing:-.2px;margin-bottom:4px;}
.modal .msub{font-size:13px;color:var(--g500);margin-bottom:18px;}
.modal-foot{display:flex;gap:8px;margin-top:20px;}
.form-row{margin-bottom:12px;}
.form-row label{display:block;font-size:10px;font-weight:700;color:var(--g500);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;}
.form-row2{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:12px;}
.sinput{width:100%;padding:9px 11px;border:1.5px solid var(--g200);border-radius:9px;font-size:14px;background:rgba(255,255,255,.75);transition:.15s;}
.sinput:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(26,86,219,.1);}

/* ── ZILLOW BOX ─────────────────────────────────────────────────────────── */
.zillow-box{background:rgba(26,86,219,.05);border:1.5px solid rgba(26,86,219,.14);border-radius:12px;padding:16px;margin-bottom:14px;}
.zillow-box h4{font-size:13px;font-weight:700;color:var(--blue);margin-bottom:4px;}
.zillow-box p{font-size:12px;color:var(--g500);line-height:1.5;}
.back-btn{background:none;border:none;font-size:12px;color:var(--g400);cursor:pointer;display:flex;align-items:center;gap:3px;margin-bottom:12px;padding:0;}
.back-btn:hover{color:var(--g700);}

/* ── SWATCH ─────────────────────────────────────────────────────────────── */
.swatch-row{display:flex;gap:8px;flex-wrap:wrap;}
.swatch{width:28px;height:28px;border-radius:7px;cursor:pointer;border:2px solid transparent;transition:.15s;}
.swatch.on,.swatch:hover{border-color:rgba(0,0,0,.25);box-shadow:0 0 0 2px rgba(255,255,255,.8);}
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:12px;}
.sec-hdr h4{font-size:15px;font-weight:700;}
</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const {useState,useEffect,useRef,useCallback,useMemo}=React;
const fmt$=v=>v==null?'—':'$'+Number(v).toLocaleString('en-US',{maximumFractionDigits:0});
const fmt$k=v=>{if(v==null)return'—';const a=Math.abs(+v);return a>=1e6?'$'+(v/1e6).toFixed(1)+'M':a>=1e3?'$'+(v/1e3).toFixed(0)+'K':fmt$(v);};
const clr=v=>+v>0?'#059669':+v<0?'#d92d20':'#6b7280';
const initials=s=>(s||'').split(' ').map(w=>w[0]||'').join('').toUpperCase().slice(0,2)||'??';

function MiniChart({data=[],color='#1a56db',height=68}){
  const ref=useRef();
  useEffect(()=>{
    if(!ref.current||data.length<2)return;
    const ch=new Chart(ref.current,{type:'line',
      data:{labels:data.map((_,i)=>i),datasets:[{data,borderColor:color,borderWidth:2,fill:true,
        backgroundColor:color+'1a',tension:0.4,pointRadius:0}]},
      options:{responsive:true,maintainAspectRatio:false,
        plugins:{legend:{display:false},tooltip:{enabled:false}},
        scales:{x:{display:false},y:{display:false}},animation:{duration:300}}});
    return()=>ch.destroy();
  },[data.join(','),color]);
  return <canvas ref={ref} style={{width:'100%',height}}/>;
}

function HealthRing({score=0,size=72}){
  const r=28,c=2*Math.PI*r,dash=c*(score/100);
  const col=score>=70?'#059669':score>=40?'#f59e0b':'#d92d20';
  return(
    <div style={{position:'relative',width:size,height:size,display:'inline-flex',alignItems:'center',justifyContent:'center'}}>
      <svg width={size} height={size} viewBox="0 0 64 64">
        <circle cx="32" cy="32" r={r} fill="none" stroke="rgba(0,0,0,.08)" strokeWidth="5"/>
        <circle cx="32" cy="32" r={r} fill="none" stroke={col} strokeWidth="5"
          strokeDasharray={`${dash} ${c-dash}`} strokeDashoffset={c*.25} strokeLinecap="round"/>
      </svg>
      <div style={{position:'absolute',textAlign:'center'}}>
        <div style={{fontSize:16,fontWeight:800,color:col,lineHeight:1}}>{score}</div>
        <div style={{fontSize:8,fontWeight:700,textTransform:'uppercase',letterSpacing:.5,color:'var(--g500)'}}>score</div>
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
      try{const r=await fetch('/api/ticker/check/'+f.ticker);const d=await r.json();setTickerOk(d.available);}catch(e){}
    },350);return()=>clearTimeout(t);
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
    }catch(e){setErr('Network error');}
    setLoading(false);
  };

  return(
    <div className="auth-wrap">
      <div className="auth-panel">
        <div className="auth-bird">🐦</div>
        <h1>Property Pigeon</h1>
        <p>The social investment network for real estate investors. Track your portfolio, discover top performers, and connect.</p>
      </div>
      <div className="auth-main">
        <div className="auth-card">
          <div className="auth-logo">Property Pigeon</div>
          <h2>{mode==='login'?'Welcome back':mode==='mfa'?'Two-Factor Auth':'Create account'}</h2>
          <p className="auth-sub">{mode==='login'?'Sign in to your account':mode==='mfa'?'Enter your authenticator code':'Join real estate investors worldwide'}</p>
          {err&&<div className="alert alert-err">{err}</div>}
          <form onSubmit={submit}>
            {mode==='signup'&&<>
              <div className="field"><label>Full name</label><input value={f.full_name} onChange={set('full_name')} placeholder="Brandon Bonomo" required/></div>
              <div className="field"><label>Portfolio name</label><input value={f.portfolio_name} onChange={set('portfolio_name')} placeholder="BLB Realty" required/></div>
              <div className="field">
                <label>Ticker <span style={{textTransform:'none',letterSpacing:0,fontWeight:400,color:'var(--g400)'}}>— 4 letters, your public ID</span></label>
                <input value={f.ticker} onChange={e=>setF(p=>({...p,ticker:e.target.value.toUpperCase().replace(/[^A-Z]/g,'').slice(0,4)}))} placeholder="BBLB" maxLength={4} style={{fontFamily:'monospace',letterSpacing:3}} required/>
                {f.ticker.length===4&&tickerOk!==null&&<div className={`hint ${tickerOk?'hint-ok':'hint-bad'}`}>{tickerOk?'✓ Available':'✗ Already taken'}</div>}
              </div>
            </>}
            {mode!=='mfa'&&<div className="field"><label>{mode==='login'?'Username or email':'Username'}</label><input value={f.username} onChange={set('username')} placeholder="brandonb" required/></div>}
            {mode==='signup'&&<div className="field"><label>Email</label><input type="email" value={f.email} onChange={set('email')} required/></div>}
            {mode!=='mfa'&&<div className="field"><label>Password</label><input type="password" value={f.password} onChange={set('password')} required/></div>}
            {mode==='mfa'&&<div className="field"><label>6-digit code</label><input value={f.token||''} onChange={e=>setF(p=>({...p,token:e.target.value}))} placeholder="000000" maxLength={6} style={{fontFamily:'monospace',letterSpacing:6,fontSize:22,textAlign:'center'}}/></div>}
            <button type="submit" className="btn-primary" disabled={loading}>{loading?'Please wait…':mode==='login'?'Sign in':mode==='mfa'?'Verify':'Create account'}</button>
          </form>
          {mode!=='mfa'&&<button className="btn-link" onClick={()=>{setMode(m=>m==='login'?'signup':'login');setErr('');}}>
            {mode==='login'?'New here? Create an account':'Have an account? Sign in'}
          </button>}
        </div>
      </div>
    </div>
  );
}

// ── ADD PROPERTY MODAL ────────────────────────────────────────────────────────
function AddPropModal({uid,onClose,onSave}){
  const [step,setStep]=useState('zillow');
  const [url,setUrl]=useState('');
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState('');
  const [msg,setMsg]=useState('');
  const [f,setF]=useState({name:'',location:'',purchase_price:'',down_payment:'',mortgage:'',insurance:'',hoa:'',property_tax:'',monthly_revenue:'',zestimate:'',bedrooms:'',bathrooms:'',sqft:'',year_built:'',zillow_url:''});
  const set=k=>e=>setF(p=>({...p,[k]:e.target.value}));

  const fetchZillow=async()=>{
    if(!url.includes('zillow.com')){setErr('Must be a Zillow URL');return;}
    setLoading(true);setErr('');
    try{
      const r=await fetch('/api/zillow/zestimate',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({url})});
      const d=await r.json();
      if(d.error&&!d.zestimate){setErr(d.error);setLoading(false);return;}
      setF(p=>({...p,name:d.address||'',location:d.address||'',zestimate:d.zestimate||'',purchase_price:d.zestimate||'',property_tax:d.monthly_tax||'',bedrooms:d.bedrooms||'',bathrooms:d.bathrooms||'',sqft:d.sqft||'',year_built:d.year_built||'',zillow_url:url}));
      setMsg(`Zestimate: ${fmt$(d.zestimate)}`);setStep('form');
    }catch(e){setErr('Failed — try again');}
    setLoading(false);
  };

  const save=async()=>{
    if(!f.name&&!f.location){setErr('Property name required');return;}
    if(!f.name)setF(p=>({...p,name:p.location||'Property'}));
    setLoading(true);setErr('');
    try{
      const body={...f,name:f.name||f.location||'Property'};
      const r=await fetch(`/api/properties/${uid}`,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(body)});
      const d=await r.json();
      if(!r.ok){setErr(d.error||'Failed to save');setLoading(false);return;}
      onSave(d);onClose();
    }catch(e){setErr('Failed to save');}
    setLoading(false);
  };

  const inp=(lbl,k,type='text',ph='')=>(
    <div className="form-row"><label>{lbl}</label><input className="sinput" type={type} value={f[k]} onChange={set(k)} placeholder={ph}/></div>
  );

  return(
    <div className="overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-handle"/>
        {step==='zillow'&&<>
          <h3>Add Property</h3><p className="msub">Paste a Zillow listing URL</p>
          <div className="zillow-box">
            <h4>🏠 Auto-fill from Zillow</h4>
            <p>Find your property on zillow.com and paste the URL below to auto-populate all details.</p>
          </div>
          {err&&<div className="alert alert-err">{err}</div>}
          <div className="form-row"><label>Zillow URL</label><input className="sinput" value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://www.zillow.com/homedetails/..."/></div>
          <div className="modal-foot">
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-blue" onClick={fetchZillow} disabled={loading}>{loading?'Fetching…':'Get Details'}</button>
          </div>
          <button className="manual-link" onClick={()=>setStep('form')}>Enter manually instead</button>
        </>}
        {step==='form'&&<>
          <button className="back-btn" onClick={()=>setStep('zillow')}>← Back</button>
          <h3>Property Details</h3><p className="msub">{msg||'Fill in the details below'}</p>
          {err&&<div className="alert alert-err">{err}</div>}
          {inp('Property name','name','text','22 B Street')}
          {inp('Location','location','text','Houston, TX')}
          <div className="form-row2">{inp('Purchase price ($)','purchase_price','number')}{inp('Down payment ($)','down_payment','number')}</div>
          <div className="form-row2">{inp('Current value / Zestimate ($)','zestimate','number')}{inp('Monthly rent ($)','monthly_revenue','number')}</div>
          <div className="form-row2">{inp('Mortgage /mo ($)','mortgage','number')}{inp('Property tax /mo ($)','property_tax','number')}</div>
          <div className="form-row2">{inp('Insurance /mo ($)','insurance','number')}{inp('HOA /mo ($)','hoa','number')}</div>
          <div className="form-row2">{inp('Beds','bedrooms','number')}{inp('Baths','bathrooms','number')}</div>
          <div className="modal-foot">
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-blue" onClick={save} disabled={loading}>{loading?'Saving…':'Add Property'}</button>
          </div>
        </>}
      </div>
    </div>
  );
}

// ── EDIT PROPERTY MODAL ───────────────────────────────────────────────────────
function EditPropModal({prop,onClose,onSave,onDelete}){
  const [f,setF]=useState({...prop});
  const [loading,setLoading]=useState(false);
  const [err,setErr]=useState('');
  const set=k=>e=>setF(p=>({...p,[k]:e.target.value}));

  const save=async()=>{
    setLoading(true);setErr('');
    try{
      const r=await fetch(`/api/property/${prop.id}`,{method:'PUT',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(!r.ok){setErr(d.error||'Failed');setLoading(false);return;}
      onSave(d);onClose();
    }catch(e){setErr('Failed');}
    setLoading(false);
  };

  const del=async()=>{
    if(!confirm('Delete this property?'))return;
    await fetch(`/api/property/${prop.id}`,{method:'DELETE',credentials:'include'});
    onDelete(prop.id);onClose();
  };

  const inp=(lbl,k,type='text')=>(<div className="form-row"><label>{lbl}</label><input className="sinput" type={type} value={f[k]||''} onChange={set(k)}/></div>);

  return(
    <div className="overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <div className="modal-handle"/>
        <h3>Edit Property</h3><p className="msub">{prop.name}</p>
        {err&&<div className="alert alert-err">{err}</div>}
        {inp('Property name','name')}{inp('Location','location')}
        <div className="form-row2">{inp('Purchase price','purchase_price','number')}{inp('Down payment','down_payment','number')}</div>
        <div className="form-row2">{inp('Current value','zestimate','number')}{inp('Monthly rent','monthly_revenue','number')}</div>
        <div className="form-row2">{inp('Mortgage /mo','mortgage','number')}{inp('Property tax /mo','property_tax','number')}</div>
        <div className="form-row2">{inp('Insurance /mo','insurance','number')}{inp('HOA /mo','hoa','number')}</div>
        <div className="modal-foot">
          <button className="btn btn-danger btn-sm" onClick={del}>Delete</button>
          <div style={{flex:1}}/>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-blue" onClick={save} disabled={loading}>{loading?'Saving…':'Save'}</button>
        </div>
      </div>
    </div>
  );
}

// ── PORTFOLIO TAB ─────────────────────────────────────────────────────────────
function PortfolioTab({user,props,portfolio,onAddProp,onEditProp}){
  const tv=+portfolio.total_value||0;
  const te=+portfolio.total_equity||0;
  const mcf=+portfolio.monthly_cashflow||0;
  const hs=+portfolio.health_score||0;
  const history=useMemo(()=>{
    try{const h=portfolio.price_history;return(typeof h==='string'?JSON.parse(h):h)||[];}catch{return[];}
  },[portfolio.price_history]);
  const chartData=history.map(h=>+h.price);
  const accent=user.accent_color||'#1a56db';
  const capRate=tv>0?(props.reduce((s,p)=>s+(+p.monthly_revenue*12-(+p.property_tax+ +p.insurance+ +p.hoa)*12),0)/tv)*100:0;

  return(
    <div className="page page-in">
      <div className="hero">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
          <div>
            <div className="lbl">Portfolio Value</div>
            <div className="big" style={{color:accent}}>{fmt$k(tv)}</div>
            <div style={{fontSize:12,color:'var(--g500)',marginTop:4}}>{props.length} {props.length===1?'property':'properties'} · Equity {fmt$k(te)}</div>
          </div>
          <HealthRing score={hs}/>
        </div>
        {chartData.length>1&&<div className="chart-wrap"><MiniChart data={chartData} color={accent}/></div>}
      </div>
      <div className="grid2" style={{marginBottom:12}}>
        <div className="stat"><div className="stat-lbl">Monthly CF</div><div className="stat-val" style={{color:clr(mcf)}}>{fmt$(mcf)}</div></div>
        <div className="stat"><div className="stat-lbl">Annual CF</div><div className="stat-val">{fmt$k(mcf*12)}</div></div>
        <div className="stat"><div className="stat-lbl">Cap Rate</div><div className="stat-val">{capRate.toFixed(1)}%</div></div>
        <div className="stat"><div className="stat-lbl">Health Score</div><div className="stat-val">{hs}</div></div>
      </div>
      <div className="sec-hdr">
        <h4>Properties</h4>
        <button className="btn btn-blue btn-sm" onClick={onAddProp}>+ Add</button>
      </div>
      {props.length===0&&<div style={{textAlign:'center',padding:'40px 20px',color:'var(--g400)'}}>
        <div style={{fontSize:36,marginBottom:8}}>🏠</div>
        <div style={{fontWeight:600}}>No properties yet</div>
        <div style={{fontSize:13,marginTop:4,marginBottom:16}}>Add your first property to get started</div>
        <button className="btn btn-blue" onClick={onAddProp}>+ Add Property</button>
      </div>}
      {props.map(p=>{
        const val=+p.zestimate||+p.purchase_price||0;
        const cf=+p.monthly_revenue-(+p.mortgage+ +p.insurance+ +p.hoa+ +p.property_tax);
        return(
          <div key={p.id} className="glass-row prop-row" onClick={()=>onEditProp(p)}>
            <div className="prop-icon" style={{background:accent+'18'}}>{p.bedrooms>0?'🏠':'🏢'}</div>
            <div style={{flex:1,minWidth:0}}>
              <div className="prop-name">{p.name}</div>
              <div className="prop-loc">{p.location}</div>
              {+p.zestimate>0&&<div className="prop-zest">Zestimate {fmt$(p.zestimate)}</div>}
            </div>
            <div className="prop-right">
              <div className="prop-val">{fmt$k(val)}</div>
              <div className="prop-cf" style={{color:clr(cf)}}>{cf>=0?'+':''}{fmt$(cf)}/mo</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── PERFORMANCE PARENT (with sub-tabs) ───────────────────────────────────────
function PerformanceTab({user,props,portfolio}){
  const [sub,setSub]=useState('performance');
  return(
    <div className="page page-in" style={{paddingTop:14}}>
      <div className="sub-tabs">
        {[['performance','Performance'],['cashflow','Cash Flow'],['projections','Projections']].map(([id,lbl])=>(
          <button key={id} className={`sub-tab${sub===id?' on':''}`} onClick={()=>setSub(id)}>{lbl}</button>
        ))}
      </div>
      {sub==='performance'&&<PerfContent user={user} props={props} portfolio={portfolio}/>}
      {sub==='cashflow'&&<CashflowContent props={props}/>}
      {sub==='projections'&&<ProjectionsContent props={props} portfolio={portfolio}/>}
    </div>
  );
}

function PerfContent({user,props,portfolio}){
  const [snaps,setSnaps]=useState([]);
  const uid=user.id;
  const tv=+portfolio.total_value||0;
  const te=+portfolio.total_equity||0;
  const mcf=+portfolio.monthly_cashflow||0;
  const totalDown=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const coc=totalDown>0?(mcf*12/totalDown*100):0;
  const capRate=tv>0?(props.reduce((s,p)=>s+(+p.monthly_revenue*12-(+p.property_tax+ +p.insurance+ +p.hoa)*12),0)/tv)*100:0;

  useEffect(()=>{
    fetch(`/api/performance/portfolio/${uid}?months=12`,{credentials:'include'})
      .then(r=>r.json()).then(d=>setSnaps(d.snapshots||[])).catch(()=>{});
  },[uid]);

  const saveSnap=async()=>{
    await fetch('/api/performance/snapshot',{method:'POST',credentials:'include'});
    const r=await fetch(`/api/performance/portfolio/${uid}?months=12`,{credentials:'include'});
    const d=await r.json();setSnaps(d.snapshots||[]);
  };

  const chartVals=snaps.map(s=>+s.total_value);

  return(<>
    <div className="grid2" style={{marginBottom:12}}>
      <div className="stat"><div className="stat-lbl">Portfolio Value</div><div className="stat-val">{fmt$k(tv)}</div></div>
      <div className="stat"><div className="stat-lbl">Total Equity</div><div className="stat-val">{fmt$k(te)}</div></div>
      <div className="stat"><div className="stat-lbl">Cash-on-Cash</div><div className="stat-val" style={{color:clr(coc)}}>{coc.toFixed(1)}%</div></div>
      <div className="stat"><div className="stat-lbl">Cap Rate</div><div className="stat-val">{capRate.toFixed(1)}%</div></div>
    </div>
    {chartVals.length>1&&<div className="card" style={{padding:18,marginBottom:12}}>
      <div className="lbl" style={{marginBottom:8}}>Value History ({snaps.length}mo)</div>
      <MiniChart data={chartVals} color={user.accent_color||'#1a56db'} height={80}/>
    </div>}
    <div className="sec-hdr">
      <h4 style={{fontSize:13}}>Monthly Snapshots</h4>
      <button className="btn btn-blue btn-sm" onClick={saveSnap}>Save Now</button>
    </div>
    {snaps.length===0&&<div style={{textAlign:'center',padding:'32px 20px',color:'var(--g400)',fontSize:13}}>No snapshots yet — tap Save Now to start tracking</div>}
    {snaps.length>0&&<div className="card" style={{padding:0,overflow:'hidden'}}>
      <div style={{overflowX:'auto'}}>
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
          <thead><tr style={{borderBottom:'1px solid var(--g200)'}}>
            {['Month','Value','Equity','Revenue','Net CF'].map(h=>(
              <th key={h} style={{padding:'8px 12px',textAlign:h==='Month'?'left':'right',fontWeight:700,color:'var(--g500)',fontSize:10,textTransform:'uppercase',whiteSpace:'nowrap'}}>{h}</th>
            ))}
          </tr></thead>
          <tbody>{[...snaps].reverse().slice(0,12).map((s,i)=>(
            <tr key={i} style={{borderBottom:'1px solid rgba(0,0,0,.04)'}}>
              <td style={{padding:'8px 12px',fontWeight:600}}>{s.snapshot_month}</td>
              <td style={{padding:'8px 12px',textAlign:'right'}}>{fmt$k(s.total_value)}</td>
              <td style={{padding:'8px 12px',textAlign:'right'}}>{fmt$k(s.total_equity)}</td>
              <td style={{padding:'8px 12px',textAlign:'right',color:'var(--green)'}}>{fmt$(s.gross_revenue)}</td>
              <td style={{padding:'8px 12px',textAlign:'right',fontWeight:700,color:clr(s.net_cashflow)}}>{fmt$(s.net_cashflow)}</td>
            </tr>
          ))}</tbody>
        </table>
      </div>
    </div>}
  </>);
}

function CashflowContent({props}){
  const revenue=props.reduce((s,p)=>s+(+p.monthly_revenue||0),0);
  const mortgage=props.reduce((s,p)=>s+(+p.mortgage||0),0);
  const tax=props.reduce((s,p)=>s+(+p.property_tax||0),0);
  const ins=props.reduce((s,p)=>s+(+p.insurance||0),0);
  const hoa=props.reduce((s,p)=>s+(+p.hoa||0),0);
  const total_exp=mortgage+tax+ins+hoa;
  const noi=revenue-tax-ins-hoa;
  const ncf=revenue-total_exp;

  return(<>
    <div className="grid2" style={{marginBottom:14}}>
      <div className="stat"><div className="stat-lbl">Monthly Revenue</div><div className="stat-val" style={{color:'var(--green)'}}>{fmt$(revenue)}</div></div>
      <div className="stat"><div className="stat-lbl">Monthly Expenses</div><div className="stat-val" style={{color:'var(--red)'}}>{fmt$(total_exp)}</div></div>
      <div className="stat"><div className="stat-lbl">NOI</div><div className="stat-val" style={{color:clr(noi)}}>{fmt$(noi)}</div></div>
      <div className="stat"><div className="stat-lbl">Net Cash Flow</div><div className="stat-val" style={{color:clr(ncf),fontWeight:800}}>{fmt$(ncf)}</div></div>
    </div>
    <div className="card" style={{padding:18}}>
      <div style={{fontSize:12,fontWeight:700,color:'var(--g400)',textTransform:'uppercase',letterSpacing:.5,marginBottom:10}}>Monthly Breakdown</div>
      {[['Gross Revenue',revenue,true],['Mortgage',mortgage],['Property Taxes',tax],['Insurance',ins],['HOA',hoa]].map(([lbl,val,isIncome])=>(
        <div key={lbl} className="cf-row">
          <span className="cf-lbl">{lbl}</span>
          <span className="cf-val" style={{color:isIncome?'var(--green)':+val>0?'var(--red)':'var(--g700)'}}>{isIncome?'':'-'}{fmt$(Math.abs(val))}</span>
        </div>
      ))}
      <div style={{borderTop:'1px solid var(--g200)',margin:'10px 0'}}/>
      <div className="cf-row total-row"><span className="cf-lbl" style={{fontWeight:700}}>Net Cash Flow</span><span className="cf-val" style={{color:clr(ncf),fontSize:15}}>{fmt$(ncf)}</span></div>
      <div style={{marginTop:12,fontSize:12,color:'var(--g500)'}}>Annual: {fmt$k(ncf*12)} · Annual Revenue: {fmt$k(revenue*12)}</div>
    </div>
  </>);
}

function ProjectionsContent({props,portfolio}){
  const [appreciation,setAppreciation]=useState(3.5);
  const [rentGrowth,setRentGrowth]=useState(2.5);
  const [vacancy,setVacancy]=useState(5);
  const [expInflation,setExpInflation]=useState(2.0);

  const tv=+portfolio.total_value||0;
  const rev=props.reduce((s,p)=>s+(+p.monthly_revenue||0),0)*12;
  const exp=props.reduce((s,p)=>s+(+p.mortgage||0)+(+p.insurance||0)+(+p.hoa||0)+(+p.property_tax||0),0)*12;
  const down=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const debt=tv-(+portfolio.total_equity||0);

  const proj=useMemo(()=>{
    if(!tv)return[];
    const vacFactor=1-(vacancy/100);
    return Array.from({length:30},(_,i)=>{
      const y=i+1;
      const val=tv*Math.pow(1+appreciation/100,y);
      const r=rev*Math.pow(1+rentGrowth/100,y)*vacFactor;
      const e=exp*Math.pow(1+expInflation/100,y);
      const ncf=r-e;
      const debtRemain=debt*Math.pow(1-(.012+y*.001),y);
      const eq=val-Math.max(0,debtRemain);
      const cumCF=Array.from({length:y},(_,j)=>rev*Math.pow(1+rentGrowth/100,j)*vacFactor-exp*Math.pow(1+expInflation/100,j)).reduce((a,b)=>a+b,0);
      return{y,val,eq,rev:r,ncf,cumCF,coc:down>0?ncf/down:0};
    });
  },[tv,rev,exp,down,debt,appreciation,rentGrowth,vacancy,expInflation]);

  if(!tv)return(
    <div style={{textAlign:'center',padding:'48px 20px',color:'var(--g400)'}}>
      <div style={{fontSize:36,marginBottom:8}}>📈</div>
      <div style={{fontWeight:600}}>Add a property to see projections</div>
    </div>
  );

  const yr10=proj[9];const yr20=proj[19];const yr30=proj[29];

  const Slider=({label,value,set,min,max,step,format})=>(
    <div className="slider-row">
      <div className="slider-hdr">
        <span className="slider-name">{label}</span>
        <span className="slider-val">{format(value)}</span>
      </div>
      <input type="range" min={min} max={max} step={step} value={value} onChange={e=>set(+e.target.value)}/>
    </div>
  );

  return(<>
    <div className="card" style={{padding:18,marginBottom:14}}>
      <div style={{fontSize:12,fontWeight:700,color:'var(--g400)',textTransform:'uppercase',letterSpacing:.5,marginBottom:14}}>Assumptions</div>
      <Slider label="Appreciation" value={appreciation} set={setAppreciation} min={0} max={10} step={0.5} format={v=>v.toFixed(1)+'%'}/>
      <Slider label="Rent Growth" value={rentGrowth} set={setRentGrowth} min={0} max={8} step={0.5} format={v=>v.toFixed(1)+'%'}/>
      <Slider label="Vacancy Rate" value={vacancy} set={setVacancy} min={0} max={20} step={1} format={v=>v+'%'}/>
      <Slider label="Expense Inflation" value={expInflation} set={setExpInflation} min={0} max={6} step={0.5} format={v=>v.toFixed(1)+'%'}/>
    </div>
    <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:10,marginBottom:14}}>
      {[[10,yr10,'#1a56db'],[20,yr20,'#7c3aed'],[30,yr30,'#059669']].map(([y,d,c])=>(
        <div key={y} className="card" style={{padding:14,borderTop:`3px solid ${c}`}}>
          <div style={{fontSize:10,fontWeight:800,color:c,marginBottom:6}}>YEAR {y}</div>
          <div style={{fontSize:10,color:'var(--g400)',marginBottom:1}}>Value</div>
          <div style={{fontSize:16,fontWeight:800,letterSpacing:'-.5px'}}>{fmt$k(d?.val)}</div>
          <div style={{fontSize:10,color:'var(--g400)',marginTop:6,marginBottom:1}}>Equity</div>
          <div style={{fontSize:13,fontWeight:700,color:'var(--green)'}}>{fmt$k(d?.eq)}</div>
        </div>
      ))}
    </div>
    <div className="card" style={{padding:0,overflow:'hidden'}}>
      <div style={{overflowX:'auto'}}>
        <table className="proj-table">
          <thead><tr>
            {['Yr','Value','Equity','Annual Rev','Net CF','Cum CF','CoC'].map(h=><th key={h}>{h}</th>)}
          </tr></thead>
          <tbody>{proj.map(r=>(
            <tr key={r.y} className={[5,10,15,20,25,30].includes(r.y)?'milestone-row':''}>
              <td>{r.y}</td>
              <td>{fmt$k(r.val)}</td>
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

// ── NET WORTH TAB ─────────────────────────────────────────────────────────────
function NetWorthTab({user,portfolio,props}){
  const [showManual,setShowManual]=useState(false);
  const [stocks,setStocks]=useState([]);
  const [stockInput,setStockInput]=useState('');
  const [manuals,setManuals]=useState([]);
  const [newLabel,setNewLabel]=useState('');
  const [newVal,setNewVal]=useState('');
  const [newType,setNewType]=useState('asset');
  const plaidConnected=false; // Will be true when Plaid connected

  const re=+portfolio.total_equity||0;
  const stockVal=stocks.reduce((s,st)=>s+(+st.shares*(+st.price||0)),0);
  const manualAssets=manuals.filter(m=>m.type==='asset').reduce((s,m)=>s+(+m.value||0),0);
  const manualLiab=manuals.filter(m=>m.type==='liability').reduce((s,m)=>s+(+m.value||0),0);
  const totalAssets=re+stockVal+manualAssets;
  const netWorth=totalAssets-manualLiab;
  const accent=user.accent_color||'#1a56db';

  const addStock=async()=>{
    const parts=stockInput.toUpperCase().trim().split(':');
    const ticker=parts[0].trim();const shares=parseFloat(parts[1])||1;
    if(!ticker)return;
    try{
      const r=await fetch(`/api/stocks/quote?ticker=${ticker}`,{credentials:'include'});
      const d=await r.json();
      if(d.price)setStocks(p=>[...p.filter(s=>s.ticker!==ticker),{ticker,shares,price:d.price,change:d.change_pct||0}]);
    }catch(e){}
    setStockInput('');
  };

  return(
    <div className="page page-in">
      <div style={{marginBottom:16}}>
        <div className="lbl">Net Worth</div>
        <div className="nw-big" style={{color:clr(netWorth)}}>{fmt$k(netWorth)}</div>
        {totalAssets>0&&<div className="nw-bar">
          <div className="nw-seg" style={{width:`${(re/totalAssets*100).toFixed(0)}%`,background:accent}}/>
          <div className="nw-seg" style={{width:`${(stockVal/totalAssets*100).toFixed(0)}%`,background:'#7c3aed'}}/>
          <div className="nw-seg" style={{width:`${(manualAssets/totalAssets*100).toFixed(0)}%`,background:'#059669'}}/>
        </div>}
        <div style={{display:'flex',gap:12,fontSize:11,color:'var(--g500)',marginTop:4}}>
          <span style={{display:'flex',alignItems:'center',gap:4}}><span style={{width:8,height:8,borderRadius:2,background:accent,display:'inline-block'}}/> RE Equity {fmt$k(re)}</span>
          <span style={{display:'flex',alignItems:'center',gap:4}}><span style={{width:8,height:8,borderRadius:2,background:'#7c3aed',display:'inline-block'}}/> Stocks {fmt$k(stockVal)}</span>
        </div>
      </div>

      {/* Plaid */}
      {!plaidConnected&&<div className="plaid-cta" onClick={()=>{}}>
        <div style={{fontSize:32,marginBottom:8}}>🏦</div>
        <div style={{fontWeight:700,fontSize:15,marginBottom:4}}>Connect Your Bank</div>
        <div style={{fontSize:13,color:'var(--g500)',lineHeight:1.5,marginBottom:16}}>Connect via Plaid to automatically pull in all your account balances, cash, and liabilities into your net worth.</div>
        <button className="btn btn-blue">Connect with Plaid</button>
      </div>}

      {/* Stocks section */}
      <div className="card" style={{padding:18,marginTop:14}}>
        <div className="sec-hdr">
          <h4>Stocks &amp; ETFs</h4>
        </div>
        <div style={{display:'flex',gap:8,marginBottom:12}}>
          <input className="sinput" value={stockInput} onChange={e=>setStockInput(e.target.value)}
            placeholder="AAPL:10 (ticker:shares)" onKeyDown={e=>e.key==='Enter'&&addStock()} style={{fontSize:13}}/>
          <button className="btn btn-blue btn-sm" onClick={addStock}>Add</button>
        </div>
        {stocks.length===0&&<div style={{fontSize:12,color:'var(--g400)',textAlign:'center',padding:'8px 0'}}>No holdings — add by ticker:shares</div>}
        {stocks.map(s=>(
          <div key={s.ticker} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'9px 0',borderBottom:'1px solid var(--g100)'}}>
            <div>
              <div style={{fontSize:13,fontWeight:700}}>{s.ticker}</div>
              <div style={{fontSize:11,color:'var(--g400)'}}>{s.shares} shares · {fmt$(s.price)}</div>
            </div>
            <div style={{textAlign:'right'}}>
              <div style={{fontSize:14,fontWeight:700}}>{fmt$k(s.shares*s.price)}</div>
              <div style={{fontSize:11,color:clr(s.change)}}>{s.change>=0?'+':''}{s.change.toFixed(1)}%</div>
            </div>
          </div>
        ))}
      </div>

      {/* Manual override - barely visible */}
      <button className="manual-link" onClick={()=>setShowManual(p=>!p)}>
        {showManual?'Hide manual entries':'+ Add manual entry'}
      </button>
      {showManual&&<div className="card" style={{padding:16,marginTop:8}}>
        {manuals.map(m=>(
          <div key={m.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'6px 0',borderBottom:'1px solid var(--g100)'}}>
            <div style={{fontSize:13,color:m.type==='liability'?'var(--red)':'var(--g700)'}}>{m.label}</div>
            <input value={m.value} onChange={e=>setManuals(p=>p.map(x=>x.id===m.id?{...x,value:e.target.value}:x))}
              placeholder="0" style={{width:80,padding:'4px 8px',border:'1.5px solid var(--g200)',borderRadius:7,fontSize:13,textAlign:'right'}}/>
          </div>
        ))}
        <div style={{display:'flex',gap:6,marginTop:10}}>
          <input className="sinput" value={newLabel} onChange={e=>setNewLabel(e.target.value)} placeholder="Label" style={{fontSize:12}}/>
          <input className="sinput" value={newVal} onChange={e=>setNewVal(e.target.value)} placeholder="$" style={{width:70,fontSize:12}}/>
          <select value={newType} onChange={e=>setNewType(e.target.value)} className="sinput" style={{width:90,fontSize:12}}>
            <option value="asset">Asset</option>
            <option value="liability">Liability</option>
          </select>
          <button className="btn btn-blue btn-sm" onClick={()=>{if(newLabel&&newVal){setManuals(p=>[...p,{id:Date.now(),label:newLabel,value:newVal,type:newType}]);setNewLabel('');setNewVal('');}}}>+</button>
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
  const [following,setFollowing]=useState(new Set());

  useEffect(()=>{
    if(q.length<2){setResults([]);return;}
    const t=setTimeout(async()=>{
      setLoading(true);
      try{
        const r=await fetch(`/api/users/search?q=${encodeURIComponent(q)}`,{credentials:'include'});
        const d=await r.json();setResults(d);
        setFollowing(new Set(d.filter(u=>u.is_following).map(u=>u.id)));
      }catch(e){}
      setLoading(false);
    },300);
    return()=>clearTimeout(t);
  },[q]);

  const toggle=async(uid,e)=>{
    e.stopPropagation();
    const isF=following.has(uid);
    await fetch(`/api/${isF?'un':''}follow/${uid}`,{method:'POST',credentials:'include'});
    setFollowing(p=>{const n=new Set(p);isF?n.delete(uid):n.add(uid);return n;});
  };

  return(
    <div className="page page-in">
      <div className="search-input-wrap">
        <svg fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
        <input className="search-inp" value={q} onChange={e=>setQ(e.target.value)} placeholder="Search by name, username, or ticker…" autoComplete="off"/>
      </div>
      {q.length<2&&<div style={{textAlign:'center',padding:'48px 20px',color:'var(--g400)'}}>
        <div style={{fontSize:36,marginBottom:8}}>🔍</div>
        <div style={{fontWeight:600,fontSize:15}}>Find investors</div>
        <div style={{fontSize:13,marginTop:4}}>Search by name, username, or 4-letter ticker</div>
      </div>}
      {loading&&<div style={{textAlign:'center',padding:'32px',color:'var(--g400)',fontSize:13}}>Searching…</div>}
      {!loading&&q.length>=2&&results.length===0&&<div style={{textAlign:'center',padding:'32px',color:'var(--g400)',fontSize:13}}>No results for "{q}"</div>}
      {results.map(u=>{
        const isF=following.has(u.id);
        const history=useMemo(()=>{try{const h=u.price_history;return(typeof h==='string'?JSON.parse(h):h)||[];}catch{return[];}});
        const chartData=history.map(h=>+h.price);
        return(
          <div key={u.id} className="user-result" onClick={()=>onViewProfile(u.id)}>
            <div style={{width:42,height:42,borderRadius:50,display:'flex',alignItems:'center',justifyContent:'center',fontSize:14,fontWeight:800,color:'#fff',background:u.avatar_color||'#1a56db',flexShrink:0,boxShadow:'0 2px 8px rgba(0,0,0,.2)',borderRadius:'50%'}}>{initials(u.full_name||u.username)}</div>
            <div style={{flex:1,minWidth:0}}>
              <div style={{display:'flex',alignItems:'center',gap:6,marginBottom:2}}>
                <span className="ur-name">{u.full_name||u.username}</span>
                <span className="ticker-badge">{u.ticker}</span>
              </div>
              <div className="ur-sub">{u.portfolio_name||u.username} · {u.property_count||0} properties</div>
              <div style={{fontSize:11,color:'var(--g500)',marginTop:1}}>{fmt$k(u.total_value)} portfolio · {fmt$(u.monthly_cashflow)}/mo</div>
            </div>
            {chartData.length>2&&<div style={{width:60,height:32,flexShrink:0,margin:'0 8px'}}><MiniChart data={chartData} color={u.avatar_color||'#1a56db'} height={32}/></div>}
            <div style={{flexShrink:0,textAlign:'right'}}>
              <div className="ur-price">${(+u.share_price||1).toFixed(2)}</div>
              <button className={`follow-btn btn btn-sm${isF?' following':''}`}
                style={{marginTop:4,padding:'4px 10px',borderRadius:20,fontSize:11,fontWeight:700,border:`1.5px solid ${isF?'transparent':'var(--blue)'}`,background:isF?'var(--blue)':'transparent',color:isF?'#fff':'var(--blue)',cursor:'pointer'}}
                onClick={e=>toggle(u.id,e)}>{isF?'Following':'Follow'}</button>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── PUBLIC PROFILE VIEW ───────────────────────────────────────────────────────
function PublicProfileView({uid,currentUser,onBack}){
  const [profile,setProfile]=useState(null);
  const [following,setFollowing]=useState(false);
  const isOwn=currentUser?.id===uid;

  useEffect(()=>{
    fetch(`/api/users/${uid}/public`,{credentials:'include'}).then(r=>r.json()).then(d=>{setProfile(d);}).catch(()=>{});
    if(!isOwn){
      fetch(`/api/users/${uid}/following-status`,{credentials:'include'}).then(r=>r.json()).then(d=>setFollowing(d.following)).catch(()=>{});
    }
  },[uid]);

  const toggle=async()=>{
    await fetch(`/api/${following?'un':''}follow/${uid}`,{method:'POST',credentials:'include'});
    setFollowing(f=>!f);
  };

  if(!profile)return<div style={{textAlign:'center',padding:60,color:'var(--g400)'}}>Loading…</div>;

  const history=useMemo(()=>{try{const h=profile.price_history;return(typeof h==='string'?JSON.parse(h):h)||[];}catch{return[];}});
  const chartData=history.map(h=>+h.price);
  const tv=+profile.total_value||0;
  const te=+profile.total_equity||0;
  const mcf=+profile.monthly_cashflow||0;
  const props=profile.properties||[];
  const capRate=tv>0?(props.reduce((s,p)=>s+(+p.monthly_revenue*12-(+p.property_tax+ +p.insurance+ +p.hoa)*12),0)/tv)*100:0;
  const totalDown=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const coc=totalDown>0?(mcf*12/totalDown*100):0;

  return(
    <div className="page page-in">
      {onBack&&<button className="back-btn" style={{marginBottom:14}} onClick={onBack}>← Back to search</button>}
      {isOwn&&<div className="pub-preview-banner">👁 This is how your profile appears to others</div>}

      {/* Header */}
      <div className="profile-header">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'flex-start'}}>
          <div className="profile-av" style={{background:profile.avatar_color||'#1a56db'}}>{initials(profile.full_name||profile.username)}</div>
          {!isOwn&&<button className={`btn btn-sm${following?' btn-blue':' btn-outline'}`} onClick={toggle}>{following?'Following':'Follow'}</button>}
        </div>
        <div className="profile-name">{profile.full_name||profile.username}</div>
        <div className="profile-handle">
          <span className="ticker-badge" style={{marginRight:6}}>{profile.ticker}</span>
          {profile.portfolio_name||profile.username}
          {profile.location&&<span style={{color:'var(--g400)',marginLeft:6}}>· {profile.location}</span>}
        </div>
        {profile.bio&&<div className="profile-bio">{profile.bio}</div>}
      </div>

      {/* Share price chart */}
      {chartData.length>1&&<div className="share-price-card">
        <div style={{display:'flex',justifyContent:'space-between',alignItems:'baseline',marginBottom:4}}>
          <div>
            <div className="lbl">Share Price</div>
            <div style={{fontSize:26,fontWeight:800,letterSpacing:'-.5px'}}>${(+profile.share_price||1).toFixed(2)}</div>
          </div>
          <div style={{textAlign:'right'}}>
            <div style={{fontSize:10,color:'var(--g400)',fontWeight:700,textTransform:'uppercase',letterSpacing:.4}}>Health Score</div>
            <div style={{fontSize:22,fontWeight:800}}>{profile.health_score||0}</div>
          </div>
        </div>
        <MiniChart data={chartData} color={profile.avatar_color||'#1a56db'} height={72}/>
      </div>}

      {/* Key stats */}
      <div className="grid2" style={{marginBottom:12}}>
        <div className="stat"><div className="stat-lbl">Portfolio Value</div><div className="stat-val">{fmt$k(tv)}</div></div>
        <div className="stat"><div className="stat-lbl">Total Equity</div><div className="stat-val">{fmt$k(te)}</div></div>
        <div className="stat"><div className="stat-lbl">Monthly CF</div><div className="stat-val" style={{color:clr(mcf)}}>{fmt$(mcf)}</div></div>
        <div className="stat"><div className="stat-lbl">Annual CF</div><div className="stat-val">{fmt$k(mcf*12)}</div></div>
        <div className="stat"><div className="stat-lbl">Cap Rate</div><div className="stat-val">{capRate.toFixed(1)}%</div></div>
        <div className="stat"><div className="stat-lbl">Cash-on-Cash</div><div className="stat-val">{coc.toFixed(1)}%</div></div>
      </div>

      {/* Properties */}
      {props.length>0&&<>
        <div className="sec-hdr"><h4>{props.length} {props.length===1?'Property':'Properties'}</h4></div>
        {props.map((p,i)=>{
          const val=+p.zestimate||+p.purchase_price||0;
          return(
            <div key={i} className="glass-row" style={{padding:'12px 13px',display:'flex',alignItems:'center',gap:12}}>
              <div style={{width:38,height:38,borderRadius:10,background:(profile.avatar_color||'#1a56db')+'18',display:'flex',alignItems:'center',justifyContent:'center',fontSize:16,flexShrink:0}}>🏠</div>
              <div style={{flex:1,minWidth:0}}>
                <div style={{fontSize:13,fontWeight:700}}>{p.name}</div>
                <div style={{fontSize:11,color:'var(--g400)'}}>{p.location}</div>
              </div>
              <div style={{textAlign:'right',flexShrink:0}}>
                <div style={{fontSize:14,fontWeight:800}}>{fmt$k(val)}</div>
                {p.bedrooms>0&&<div style={{fontSize:11,color:'var(--g400)'}}>{p.bedrooms}bd</div>}
              </div>
            </div>
          );
        })}
      </>}
    </div>
  );
}

// ── PROFILE TAB (your own) ────────────────────────────────────────────────────
function ProfileTab({user,portfolio,props,onUpdate,onLogout}){
  const [view,setView]=useState('settings'); // settings | public
  const [f,setF]=useState({full_name:user.full_name||'',portfolio_name:user.portfolio_name||'',bio:user.bio||'',location:user.location||'',accent_color:user.accent_color||'#1a56db'});
  const [msg,setMsg]=useState('');
  const [err,setErr]=useState('');
  const COLORS=['#1a56db','#7c3aed','#059669','#d92d20','#f59e0b','#0891b2','#db2777','#ea580c'];

  const save=async()=>{
    setErr('');setMsg('');
    try{
      const r=await fetch('/api/user/settings',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(!r.ok){setErr(d.error||'Failed');return;}
      onUpdate(d.user);setMsg('Saved!');setTimeout(()=>setMsg(''),2500);
    }catch(e){setErr('Failed');}
  };

  return(
    <div className="page page-in">
      <div className="sub-tabs" style={{marginBottom:16}}>
        <button className={`sub-tab${view==='settings'?' on':''}`} onClick={()=>setView('settings')}>Settings</button>
        <button className={`sub-tab${view==='public'?' on':''}`} onClick={()=>setView('public')}>Public Profile</button>
      </div>

      {view==='public'&&<PublicProfileView uid={user.id} currentUser={user} onBack={null}/>}

      {view==='settings'&&<div style={{maxWidth:500}}>
        {err&&<div className="alert alert-err">{err}</div>}
        {msg&&<div className="alert alert-ok">{msg}</div>}
        <div className="card" style={{padding:20,marginBottom:12}}>
          <div style={{fontWeight:700,fontSize:13,marginBottom:14}}>Profile Info</div>
          {[['Full name','full_name','Brandon Bonomo'],['Portfolio name','portfolio_name','BLB Realty'],['Location','location','Houston, TX'],['Bio','bio','Real estate investor…']].map(([lbl,k,ph])=>(
            <div key={k} className="form-row">
              <label style={{fontSize:10,fontWeight:700,color:'var(--g500)',textTransform:'uppercase',letterSpacing:.5,marginBottom:4,display:'block'}}>{lbl}</label>
              <input className="sinput" value={f[k]} onChange={e=>setF(p=>({...p,[k]:e.target.value}))} placeholder={ph}/>
            </div>
          ))}
        </div>
        <div className="card" style={{padding:20,marginBottom:12}}>
          <div style={{fontWeight:700,fontSize:13,marginBottom:12}}>Accent Color</div>
          <div className="swatch-row">
            {COLORS.map(c=><div key={c} className={`swatch${f.accent_color===c?' on':''}`} style={{background:c}} onClick={()=>setF(p=>({...p,accent_color:c}))}/>)}
          </div>
        </div>
        <div style={{display:'flex',gap:10}}>
          <button className="btn btn-blue" onClick={save}>Save Changes</button>
          <button className="btn btn-danger" onClick={async()=>{await fetch('/api/auth/logout',{method:'POST',credentials:'include'});onLogout();}}>Sign Out</button>
        </div>
      </div>}
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
  const [viewingProfile,setViewingProfile]=useState(null);
  const accent=user.accent_color||'#1a56db';

  useEffect(()=>{document.documentElement.style.setProperty('--blue',accent);},[accent]);

  const loadData=useCallback(async()=>{
    try{
      const [pf,pr]=await Promise.all([
        fetch(`/api/portfolio/${user.id}`,{credentials:'include'}).then(r=>r.json()),
        fetch(`/api/properties/${user.id}`,{credentials:'include'}).then(r=>r.json())
      ]);
      setPortfolio(pf||{});setProps(Array.isArray(pr)?pr:[]);
    }catch(e){}
  },[user.id]);

  useEffect(()=>{loadData();},[loadData]);

  const NAV=[
    {id:'portfolio',label:'Portfolio',icon:'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6'},
    {id:'performance',label:'Analytics',icon:'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z'},
    {id:'networth',label:'Net Worth',icon:'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z'},
    {id:'search',label:'Search',icon:'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'},
    {id:'profile',label:'Profile',icon:'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z'},
  ];

  const PAGE_TITLES={portfolio:'Portfolio',performance:'Analytics',networth:'Net Worth',search:'Search',profile:'Profile'};
  const tabProps={user,props,portfolio,onRefresh:loadData};

  return(
    <div className="shell">
      <div className="topbar">
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          <span style={{fontSize:20}}>🐦</span>
          <span className="topbar-title">{viewingProfile?'Profile':PAGE_TITLES[tab]}</span>
        </div>
        <div style={{display:'flex',alignItems:'center',gap:8}}>
          {tab==='portfolio'&&!viewingProfile&&<button className="btn btn-blue btn-sm" onClick={()=>setShowAdd(true)}>+ Add</button>}
          <div className="topbar-av" style={{background:accent}} onClick={()=>setTab('profile')}>{initials(user.full_name||user.username)}</div>
        </div>
      </div>

      <div className="page-area">
        {viewingProfile
          ?<PublicProfileView uid={viewingProfile} currentUser={user} onBack={()=>setViewingProfile(null)}/>
          :<>
            {tab==='portfolio'&&<PortfolioTab {...tabProps} onAddProp={()=>setShowAdd(true)} onEditProp={setEditProp}/>}
            {tab==='performance'&&<PerformanceTab {...tabProps}/>}
            {tab==='networth'&&<NetWorthTab {...tabProps}/>}
            {tab==='search'&&<SearchTab currentUser={user} onViewProfile={uid=>{setViewingProfile(uid);}}/>}
            {tab==='profile'&&<ProfileTab user={user} portfolio={portfolio} props={props} onUpdate={u=>setUser(u)} onLogout={onLogout}/>}
          </>
        }
      </div>

      <nav className="bottom-nav">
        {NAV.map(n=>(
          <div key={n.id} className={`nav-tab${tab===n.id&&!viewingProfile?' on':''}`} onClick={()=>{setViewingProfile(null);setTab(n.id);}}>
            <svg fill="none" stroke="currentColor" strokeWidth="1.8" viewBox="0 0 24 24">
              <path strokeLinecap="round" strokeLinejoin="round" d={n.icon}/>
            </svg>
            <span>{n.label}</span>
            <div className="nav-dot"/>
          </div>
        ))}
      </nav>

      {showAdd&&<AddPropModal uid={user.id} onClose={()=>setShowAdd(false)} onSave={p=>{setProps(prev=>[p,...prev]);loadData();setShowAdd(false);}}/>}
      {editProp&&<EditPropModal prop={editProp} onClose={()=>setEditProp(null)} onSave={p=>{setProps(prev=>prev.map(x=>x.id===p.id?p:x));setEditProp(null);loadData();}} onDelete={id=>{setProps(prev=>prev.filter(x=>x.id!==id));setEditProp(null);loadData();}}/>}
    </div>
  );
}

// ── ROOT ──────────────────────────────────────────────────────────────────────
function App(){
  const [user,setUser]=useState(null);
  const [loading,setLoading]=useState(true);

  useEffect(()=>{
    fetch('/api/auth/me',{credentials:'include'})
      .then(r=>r.ok?r.json():null)
      .then(d=>{if(d?.user)setUser(d.user);})
      .catch(()=>{}).finally(()=>setLoading(false));
  },[]);

  if(loading)return(
    <div style={{height:'100vh',display:'flex',alignItems:'center',justifyContent:'center',background:'linear-gradient(135deg,#dce8ff,#f0e8ff)'}}>
      <div style={{textAlign:'center'}}>
        <div style={{fontSize:48,animation:'spin 2s linear infinite'}}>🐦</div>
        <div style={{fontWeight:600,color:'var(--g500)',marginTop:12}}>Loading…</div>
      </div>
      <style>{`@keyframes spin{to{transform:rotate(360deg)}}`}</style>
    </div>
  );

  if(!user)return <AuthScreen onLogin={setUser}/>;
  return <MainApp user={user} onLogout={()=>setUser(null)}/>;
}

ReactDOM.createRoot(document.getElementById('root')).render(<App/>);
</script>
</body>
</html>"""



@app.route('/api/debug/test-insert')
def test_insert():
    """Test what columns exist in properties table"""
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT column_name FROM information_schema.columns WHERE table_name='properties' AND table_schema='public' ORDER BY ordinal_position")
            cols = [r[0] for r in cur.fetchall()]
            cur.close()
        return jsonify({'properties_columns': cols, 'count': len(cols)})
    except Exception as e:
        return jsonify({'error': str(e)})


@app.route('/api/users/search')
def search_users():
    q = request.args.get('q','').strip()
    if not q: return jsonify([])
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,u.avatar_color,u.bio,u.is_public,
                   pm.total_value,pm.total_equity,pm.monthly_cashflow,pm.annual_cashflow,
                   pm.property_count,pm.health_score,pm.share_price,pm.price_history
            FROM users u LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
            WHERE u.is_public=true AND (
                LOWER(u.username) LIKE %s OR LOWER(u.ticker) LIKE %s OR LOWER(u.full_name) LIKE %s
            )
            ORDER BY pm.total_value DESC NULLS LAST LIMIT 20
        """, (f'%{q.lower()}%', f'%{q.lower()}%', f'%{q.lower()}%'))
        users = [dict(r) for r in cur.fetchall()]
        cur.close()
    for u in users:
        if u.get('price_history') and isinstance(u['price_history'], str):
            try: u['price_history'] = json.loads(u['price_history'])
            except: u['price_history'] = []
    return jsonify(users)

@app.route('/api/users/<int:uid>/public')
def user_public(uid):
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,u.avatar_color,u.bio,u.location,u.is_public,
                   pm.total_value,pm.total_equity,pm.monthly_cashflow,pm.annual_cashflow,
                   pm.property_count,pm.health_score,pm.share_price,pm.price_history,pm.updated_at
            FROM users u LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
            WHERE u.id=%s
        """, (uid,))
        u = cur.fetchone()
        if not u: cur.close(); return jsonify({'error':'Not found'}),404
        u = dict(u)
        cur.execute("""
            SELECT name,location,purchase_price,zestimate,bedrooms,monthly_revenue,
                   mortgage,property_tax,insurance,hoa,equity
            FROM properties WHERE user_id=%s ORDER BY zestimate DESC NULLS LAST
        """, (uid,))
        u['properties'] = [dict(r) for r in cur.fetchall()]
        cur.close()
    if not u.get('is_public'):
        req_uid = session.get('user_id')
        if req_uid != uid: return jsonify({'error':'Private profile'}),403
    u.pop('password_hash', None); u.pop('totp_secret', None)
    if u.get('price_history') and isinstance(u['price_history'], str):
        try: u['price_history'] = json.loads(u['price_history'])
        except: u['price_history'] = []
    if u.get('updated_at'): u['updated_at'] = u['updated_at'].isoformat()
    return jsonify(u)

@app.route('/api/users/<int:uid>/following-status')
def following_status(uid):
    req_uid = session.get('user_id')
    if not req_uid: return jsonify({'following': False})
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("SELECT 1 FROM follows WHERE follower_id=%s AND following_id=%s",(req_uid,uid))
        following = cur.fetchone() is not None; cur.close()
    return jsonify({'following': following})

# ── SERVE ──────────────────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_app(path):
    return Response(HTML, mimetype='text/html')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
