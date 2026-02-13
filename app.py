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
                except Exception:
                    conn.rollback()
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
    try:
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15',
            'Accept': 'text/html,application/xhtml+xml,*/*',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        import gzip
        resp = urllib.request.urlopen(req, timeout=12)
        raw = resp.read()
        try: html = gzip.decompress(raw).decode('utf-8','ignore')
        except: html = raw.decode('utf-8','ignore')
        result = {}
        for pat in [r'"zestimate":\{"value":(\d+)', r'"homeValue":(\d+)', r'"price":(\d{5,8})']:
            m = re.search(pat, html)
            if m and int(m.group(1)) > 50000:
                result['zestimate'] = int(m.group(1)); break
        for key, pat in [('address', r'"streetAddress":"([^"]+)"'), ('bedrooms', r'"bedrooms":(\d+)'),
                         ('bathrooms', r'"bathrooms":([\d.]+)'), ('sqft', r'"livingArea":(\d+)'),
                         ('year_built', r'"yearBuilt":(\d{4})'), ('tax_annual', r'"taxAnnualAmount":(\d+)')]:
            m = re.search(pat, html)
            if m: result[key] = m.group(1)
        if result.get('tax_annual'):
            result['monthly_tax'] = round(int(result['tax_annual'])/12)
        if not result.get('zestimate'):
            result['error'] = 'Could not find Zestimate. Try a direct zillow.com/homedetails/ URL.'
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)})

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
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Property Pigeon</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;0,9..40,800;1,9..40,400&display=swap" rel="stylesheet">
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<style>
*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}
:root{
  --blue:#1a56db;--green:#059669;--red:#d92d20;--purple:#7c3aed;
  --g50:#f9fafb;--g100:#f3f4f6;--g200:#e5e7eb;--g300:#d1d5db;
  --g400:#9ca3af;--g500:#6b7280;--g700:#374151;--g900:#111827;
  --glass:rgba(255,255,255,0.68);--glassh:rgba(255,255,255,0.88);
  --gb:rgba(255,255,255,0.82);--gsh:0 8px 32px rgba(31,38,135,.1),0 2px 8px rgba(31,38,135,.06);
  --gsh2:0 16px 48px rgba(31,38,135,.15),0 4px 16px rgba(31,38,135,.08);
  --blur:blur(24px) saturate(180%);--r:12px;--r2:18px;
}
html,body{height:100%;overflow:hidden;}
body{font-family:'DM Sans',sans-serif;background:linear-gradient(135deg,#dce8ff 0%,#eef2ff 25%,#e6f7ef 55%,#f0e8ff 100%);background-attachment:fixed;color:var(--g900);}
input,button,select,textarea{font-family:inherit;}
::-webkit-scrollbar{width:4px;height:4px;}
::-webkit-scrollbar-thumb{background:rgba(0,0,0,.15);border-radius:99px;}
::-webkit-scrollbar-track{background:transparent;}

/* AUTH */
.auth-wrap{display:flex;height:100vh;}
.auth-panel{width:380px;flex-shrink:0;padding:56px 48px;display:flex;flex-direction:column;justify-content:center;position:relative;overflow:hidden;}
.auth-panel::before{content:'';position:absolute;inset:0;background:var(--blue);z-index:0;}
.auth-panel::after{content:'';position:absolute;inset:0;background:linear-gradient(160deg,rgba(255,255,255,.08) 0%,transparent 60%);z-index:1;}
.auth-panel>*{position:relative;z-index:2;}
.auth-bird{font-size:44px;margin-bottom:20px;filter:drop-shadow(0 4px 12px rgba(0,0,0,.2));}
.auth-panel h1{font-size:30px;font-weight:800;color:#fff;letter-spacing:-.5px;margin-bottom:10px;line-height:1.1;}
.auth-panel p{font-size:14px;color:rgba(255,255,255,.8);line-height:1.6;}
.auth-main{flex:1;display:flex;align-items:center;justify-content:center;padding:32px;}
.auth-card{
  width:100%;max-width:420px;
  background:var(--glassh);
  backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border:1px solid rgba(255,255,255,.9);
  border-radius:24px;padding:36px;
  box-shadow:var(--gsh2),inset 0 1px 0 rgba(255,255,255,.95);
}
.auth-logo{font-size:11px;font-weight:700;color:var(--g400);letter-spacing:1.5px;text-transform:uppercase;margin-bottom:22px;}
.auth-card h2{font-size:24px;font-weight:800;letter-spacing:-.4px;margin-bottom:4px;}
.auth-card .sub{font-size:13px;color:var(--g500);margin-bottom:24px;}
.field{margin-bottom:14px;}
.field label{display:block;font-size:11px;font-weight:700;color:var(--g500);text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;}
.field input{width:100%;padding:10px 13px;border:1.5px solid var(--g200);border-radius:10px;font-size:14px;background:rgba(255,255,255,.75);transition:.15s;}
.field input:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(26,86,219,.1);}
.field .hint{font-size:11px;margin-top:4px;font-weight:600;}
.field .hint.ok{color:var(--green);}
.field .hint.bad{color:var(--red);}
.btn-primary{width:100%;padding:12px;background:var(--blue);color:#fff;border:none;border-radius:10px;font-size:15px;font-weight:700;cursor:pointer;transition:.15s;margin-top:4px;}
.btn-primary:hover{filter:brightness(1.08);transform:translateY(-1px);box-shadow:0 6px 18px rgba(26,86,219,.35);}
.btn-primary:active{transform:scale(.97);}
.btn-ghost-link{background:none;border:none;font-size:13px;color:var(--blue);cursor:pointer;display:block;width:100%;text-align:center;padding:10px;margin-top:4px;}
.btn-ghost-link:hover{text-decoration:underline;}
.err{background:rgba(217,45,32,.06);border:1px solid rgba(217,45,32,.25);border-radius:9px;padding:10px 13px;font-size:13px;color:#b91c1c;margin-bottom:14px;}
.success{background:rgba(5,150,105,.06);border:1px solid rgba(5,150,105,.25);border-radius:9px;padding:10px 13px;font-size:13px;color:var(--green);margin-bottom:14px;}
.warn{background:rgba(245,158,11,.06);border:1px solid rgba(245,158,11,.25);border-radius:9px;padding:10px 13px;font-size:13px;color:#92400e;margin-bottom:14px;}

/* SHELL */
.shell{display:flex;height:100vh;overflow:hidden;}
.sidebar{
  width:218px;flex-shrink:0;
  background:var(--glass);
  backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border-right:1px solid rgba(255,255,255,.65);
  display:flex;flex-direction:column;
}
.sb-logo{padding:20px 18px 14px;font-size:15px;font-weight:800;letter-spacing:-.2px;display:flex;align-items:center;gap:8px;border-bottom:1px solid rgba(255,255,255,.5);}
.nav{flex:1;padding:10px 8px;overflow-y:auto;}
.ni{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:11px;font-size:13px;font-weight:500;color:var(--g500);cursor:pointer;margin-bottom:2px;transition:all .18s cubic-bezier(.34,1.56,.64,1);}
.ni svg{width:17px;height:17px;flex-shrink:0;}
.ni:hover{background:rgba(255,255,255,.8);color:var(--g900);transform:translateX(2px);}
.ni.on{background:rgba(26,86,219,.1);color:var(--blue);font-weight:600;}
.ni.on svg{stroke:var(--blue);}
.sb-foot{padding:10px 8px 14px;border-top:1px solid rgba(255,255,255,.5);}
.user-chip{display:flex;align-items:center;gap:9px;padding:8px 10px;border-radius:10px;cursor:pointer;transition:.15s;}
.user-chip:hover{background:rgba(255,255,255,.7);}
.av{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:11px;font-weight:800;color:#fff;flex-shrink:0;box-shadow:0 2px 8px rgba(0,0,0,.18);}
.av-lg{width:52px;height:52px;font-size:16px;}
.uname{font-size:13px;font-weight:600;line-height:1.2;}
.uticker{font-size:11px;color:var(--g400);}
.content{flex:1;display:flex;flex-direction:column;min-width:0;overflow:hidden;}
.topbar{
  height:52px;flex-shrink:0;padding:0 22px;
  display:flex;align-items:center;justify-content:space-between;
  background:rgba(255,255,255,.55);
  backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border-bottom:1px solid rgba(255,255,255,.6);
}
.topbar h3{font-size:16px;font-weight:700;letter-spacing:-.2px;}
.page{flex:1;overflow-y:auto;padding:22px;}
@keyframes fadeUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
.page-in{animation:fadeUp .2s ease;}

/* GLASS CARD */
.card{
  background:var(--glass);
  backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border:1px solid var(--gb);border-radius:var(--r2);
  box-shadow:var(--gsh);transition:.2s;
}
.card:hover{transform:translateY(-2px);box-shadow:var(--gsh2);}

/* STATS GRID */
.grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:12px;}
.grid4{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;}
.stat{background:rgba(255,255,255,.65);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid rgba(255,255,255,.8);border-radius:var(--r);padding:15px 16px;transition:.2s;}
.stat:hover{transform:translateY(-2px);box-shadow:0 6px 20px rgba(0,0,0,.08);}
.stat-lbl{font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;}
.stat-val{font-size:22px;font-weight:800;letter-spacing:-.5px;}
.stat-sub{font-size:11px;color:var(--g500);margin-top:3px;}

/* HERO */
.hero{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--gb);border-radius:var(--r2);padding:22px;margin-bottom:16px;box-shadow:var(--gsh);}
.hero-top{display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:16px;}
.lbl{font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.5px;margin-bottom:4px;}
.big{font-size:34px;font-weight:800;letter-spacing:-1px;line-height:1;}
.chart-wrap{height:72px;margin:4px 0;}

/* PROPERTY ROWS */
.prop-row{display:flex;align-items:center;gap:13px;padding:12px 14px;border-radius:13px;margin-bottom:6px;background:rgba(255,255,255,.58);backdrop-filter:blur(12px);-webkit-backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,.75);cursor:pointer;transition:all .18s cubic-bezier(.34,1.56,.64,1);}
.prop-row:hover{background:rgba(255,255,255,.92)!important;transform:translateY(-2px)!important;box-shadow:0 8px 24px rgba(26,86,219,.1)!important;}
.prop-icon{width:42px;height:42px;border-radius:12px;display:flex;align-items:center;justify-content:center;font-size:18px;flex-shrink:0;}
.prop-name{font-size:14px;font-weight:700;}
.prop-loc{font-size:12px;color:var(--g400);margin-top:1px;}
.prop-zest{font-size:11px;color:var(--blue);font-weight:600;margin-top:2px;}
.prop-val{font-size:16px;font-weight:800;text-align:right;}
.prop-cf{font-size:11px;text-align:right;margin-top:1px;}

/* CASHFLOW ROWS */
.cf-row{display:flex;justify-content:space-between;align-items:center;padding:10px 13px;border-radius:9px;background:rgba(255,255,255,.5);margin-bottom:5px;}
.cf-row.total{background:rgba(26,86,219,.06);border:1px solid rgba(26,86,219,.15);}
.cf-lbl{font-size:13px;color:var(--g700);}
.cf-val{font-size:14px;font-weight:700;}

/* FEED */
.feed-item{background:var(--glass);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--gb);border-radius:var(--r);padding:16px;margin-bottom:10px;}
.feed-hdr{display:flex;align-items:center;gap:10px;margin-bottom:12px;}
.feed-name{font-size:14px;font-weight:700;}
.feed-time{font-size:11px;color:var(--g400);}
.feed-grid{display:grid;grid-template-columns:repeat(3,1fr);gap:8px;}
.feed-cell{background:rgba(255,255,255,.45);border-radius:8px;padding:8px 10px;}
.feed-cell-lbl{font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.4px;}
.feed-cell-val{font-size:14px;font-weight:700;margin-top:2px;}

/* DISCOVER */
.disc-row{display:flex;align-items:center;gap:12px;padding:13px 15px;border-radius:13px;background:rgba(255,255,255,.6);border:1px solid rgba(255,255,255,.75);margin-bottom:8px;transition:.18s;}
.disc-row:hover{background:rgba(255,255,255,.88);transform:translateY(-1px);}
.disc-name{font-size:14px;font-weight:700;}
.disc-sub{font-size:12px;color:var(--g500);margin-top:1px;}
.follow-btn{margin-left:auto;padding:6px 16px;border-radius:20px;font-size:12px;font-weight:700;border:1.5px solid var(--blue);background:transparent;color:var(--blue);cursor:pointer;transition:.15s;white-space:nowrap;}
.follow-btn:hover,.follow-btn.on{background:var(--blue);color:#fff;}

/* BUTTONS */
.btn{padding:9px 16px;border-radius:9px;font-size:13px;font-weight:600;border:none;cursor:pointer;transition:.15s;display:inline-flex;align-items:center;gap:6px;}
.btn:hover:not(:disabled){transform:translateY(-1px);filter:brightness(1.06);box-shadow:0 4px 12px rgba(0,0,0,.1);}
.btn:active:not(:disabled){transform:scale(.97);}
.btn:disabled{opacity:.5;cursor:not-allowed;}
.btn-blue{background:var(--blue);color:#fff;}
.btn-green{background:var(--green);color:#fff;}
.btn-ghost{background:rgba(0,0,0,.05);color:var(--g700);}
.btn-outline{background:transparent;border:1.5px solid var(--g200);color:var(--g700);}
.btn-outline:hover{border-color:var(--blue);color:var(--blue);}
.btn-sm{padding:6px 12px;font-size:12px;border-radius:7px;}
.btn-danger{background:rgba(217,45,32,.08);color:#b91c1c;border:1.5px solid rgba(217,45,32,.2);}
.btn-danger:hover{background:rgba(217,45,32,.15);}

/* MODAL */
.overlay{position:fixed;inset:0;background:rgba(10,15,40,.45);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);z-index:100;display:flex;align-items:center;justify-content:center;padding:20px;}
@keyframes mIn{from{opacity:0;transform:scale(.93) translateY(20px)}to{opacity:1;transform:scale(1) translateY(0)}}
.modal{
  background:var(--glassh);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);
  border:1px solid rgba(255,255,255,.92);border-radius:22px;
  width:100%;max-width:540px;max-height:92vh;overflow-y:auto;padding:28px;
  box-shadow:0 32px 80px rgba(0,0,0,.2),inset 0 1px 0 rgba(255,255,255,.95);
  animation:mIn .22s cubic-bezier(.34,1.56,.64,1);
}
.modal h3{font-size:17px;font-weight:800;letter-spacing:-.2px;margin-bottom:6px;}
.modal .msub{font-size:13px;color:var(--g500);margin-bottom:20px;}
.modal-foot{display:flex;gap:8px;margin-top:22px;}
.sinput{width:100%;padding:9px 12px;border:1.5px solid var(--g200);border-radius:9px;font-size:14px;background:rgba(255,255,255,.75);transition:.15s;}
.sinput:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(26,86,219,.1);}
.label{display:block;font-size:11px;font-weight:700;color:var(--g500);text-transform:uppercase;letter-spacing:.4px;margin-bottom:5px;}
.form-row{margin-bottom:14px;}
.form-row2{display:grid;grid-template-columns:1fr 1fr;gap:12px;margin-bottom:14px;}

/* PROJECTIONS TABLE */
.proj-table{width:100%;border-collapse:collapse;font-size:12px;}
.proj-table th{padding:8px 10px;text-align:right;font-size:10px;font-weight:700;color:var(--g400);text-transform:uppercase;letter-spacing:.4px;border-bottom:1px solid var(--g200);}
.proj-table th:first-child{text-align:left;}
.proj-table td{padding:8px 10px;text-align:right;border-bottom:1px solid rgba(0,0,0,.04);}
.proj-table td:first-child{text-align:left;font-weight:700;}
.proj-table tr.milestone td{background:rgba(26,86,219,.04);}
.proj-table tr:hover td{background:rgba(26,86,219,.03);}

/* COLOR SWATCHES */
.swatch-row{display:flex;gap:8px;flex-wrap:wrap;}
.swatch{width:30px;height:30px;border-radius:8px;cursor:pointer;border:2px solid transparent;transition:.15s;}
.swatch:hover,.swatch.on{border-color:rgba(0,0,0,.3);box-shadow:0 0 0 2px rgba(255,255,255,.8);}

/* PLAID BAR */
.plaid-bar{background:rgba(26,86,219,.05);border:1px solid rgba(26,86,219,.12);border-radius:12px;padding:12px 16px;display:flex;align-items:center;gap:12px;margin-bottom:16px;}

/* HEALTH RING */
.ring-wrap{position:relative;display:inline-flex;align-items:center;justify-content:center;}
.ring-center{position:absolute;text-align:center;}
.ring-num{font-size:20px;font-weight:800;line-height:1;}
.ring-lbl{font-size:9px;font-weight:700;text-transform:uppercase;letter-spacing:.5px;color:var(--g500);}

/* ZILLOW STEP */
.zillow-box{background:rgba(26,86,219,.05);border:1.5px solid rgba(26,86,219,.15);border-radius:13px;padding:18px;margin-bottom:16px;}
.zillow-box h4{font-size:14px;font-weight:700;color:var(--blue);margin-bottom:6px;}
.zillow-box p{font-size:12px;color:var(--g500);line-height:1.5;}
.step-back{background:none;border:none;font-size:12px;color:var(--g400);cursor:pointer;padding:0;display:flex;align-items:center;gap:4px;margin-bottom:14px;}
.step-back:hover{color:var(--g700);}

/* SECTION HEADER */
.sec-hdr{display:flex;align-items:center;justify-content:space-between;margin-bottom:14px;}
.sec-hdr h4{font-size:14px;font-weight:700;}

/* INFO PILL */
.pill{display:inline-flex;align-items:center;gap:4px;padding:3px 10px;border-radius:20px;font-size:11px;font-weight:700;}
.pill-blue{background:rgba(26,86,219,.1);color:var(--blue);}
.pill-green{background:rgba(5,150,105,.1);color:var(--green);}
.pill-red{background:rgba(217,45,32,.1);color:var(--red);}
</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const {useState,useEffect,useRef,useCallback,useMemo}=React;
const fmt$=v=>v==null?'—':'$'+Number(v).toLocaleString('en-US',{maximumFractionDigits:0});
const fmt$k=v=>v==null?'—':Math.abs(v)>=1000000?'$'+(v/1000000).toFixed(1)+'M':Math.abs(v)>=1000?'$'+(v/1000).toFixed(0)+'K':fmt$(v);
const fmtPct=v=>v==null?'—':(+v*100).toFixed(1)+'%';
const pct=(v,t)=>t?((v/t)*100).toFixed(1)+'%':'0%';
const clr=v=>v>0?'#059669':v<0?'#d92d20':'#6b7280';
const initials=s=>(s||'').split(' ').map(w=>w[0]).join('').toUpperCase().slice(0,2)||'?';

// ── MINI CHART ────────────────────────────────────────────────────────────────
function MiniChart({data=[],color='#1a56db'}){
  const ref=useRef();
  useEffect(()=>{
    if(!ref.current||!data.length)return;
    const ch=new Chart(ref.current,{
      type:'line',
      data:{labels:data.map((_,i)=>i),datasets:[{data,borderColor:color,borderWidth:2,fill:true,
        backgroundColor:color+'22',tension:0.4,pointRadius:0}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false},tooltip:{enabled:false}},
        scales:{x:{display:false},y:{display:false}},animation:{duration:400}}
    });
    return()=>ch.destroy();
  },[data,color]);
  return <canvas ref={ref} style={{width:'100%',height:'100%'}}/>;
}

// ── HEALTH RING ───────────────────────────────────────────────────────────────
function HealthRing({score=0,size=80}){
  const r=30,c=2*Math.PI*r,dash=c*(score/100);
  const col=score>=70?'#059669':score>=40?'#f59e0b':'#d92d20';
  return(
    <div className="ring-wrap" style={{width:size,height:size}}>
      <svg width={size} height={size} viewBox="0 0 72 72">
        <circle cx="36" cy="36" r={r} fill="none" stroke="rgba(0,0,0,.08)" strokeWidth="6"/>
        <circle cx="36" cy="36" r={r} fill="none" stroke={col} strokeWidth="6"
          strokeDasharray={`${dash} ${c-dash}`} strokeDashoffset={c*.25} strokeLinecap="round"/>
      </svg>
      <div className="ring-center">
        <div className="ring-num" style={{color:col}}>{score}</div>
        <div className="ring-lbl">score</div>
      </div>
    </div>
  );
}

// ── AUTH SCREEN ───────────────────────────────────────────────────────────────
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
        method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',
        body:JSON.stringify(f)
      });
      const d=await r.json();
      if(d.mfa_required){setMode('mfa');setLoading(false);return;}
      if(!r.ok){setErr(d.error||'Something went wrong');setLoading(false);return;}
      onLogin(d.user);
    }catch(e){setErr('Network error — try again');}
    setLoading(false);
  };

  return(
    <div className="auth-wrap">
      <div className="auth-panel">
        <div className="auth-bird">🐦</div>
        <h1>Property Pigeon</h1>
        <p>The social investment network for real estate investors. Track your portfolio, discover top performers, and connect with the community.</p>
      </div>
      <div className="auth-main">
        <div className="auth-card">
          <div className="auth-logo">Property Pigeon</div>
          <h2>{mode==='login'?'Welcome back':mode==='mfa'?'Two-Factor Auth':'Create account'}</h2>
          <p className="sub">{mode==='login'?'Sign in to your account':mode==='mfa'?'Enter your authenticator code':'Join real estate investors worldwide'}</p>
          {err&&<div className="err">{err}</div>}
          <form onSubmit={submit}>
            {mode==='signup'&&<>
              <div className="field"><label>Full name</label><input value={f.full_name} onChange={set('full_name')} placeholder="Brandon Bonomo" required/></div>
              <div className="field"><label>Portfolio name</label><input value={f.portfolio_name} onChange={set('portfolio_name')} placeholder="BLB Realty" required/></div>
              <div className="field">
                <label>Ticker <span style={{color:'var(--g400)',fontWeight:400,textTransform:'none',letterSpacing:0}}>(4 letters — your public ID)</span></label>
                <input value={f.ticker} onChange={e=>setF(p=>({...p,ticker:e.target.value.toUpperCase().replace(/[^A-Z]/g,'').slice(0,4)}))} placeholder="BBLB" maxLength={4} style={{fontFamily:'monospace',letterSpacing:2}} required/>
                {f.ticker.length===4&&tickerOk!==null&&<div className={`hint ${tickerOk?'ok':'bad'}`}>{tickerOk?'✓ Available':'✗ Already taken'}</div>}
              </div>
            </>}
            {mode!=='mfa'&&<div className="field"><label>{mode==='login'?'Username or email':'Username'}</label><input value={f.username} onChange={set('username')} placeholder="brandonb" required/></div>}
            {mode==='signup'&&<div className="field"><label>Email</label><input type="email" value={f.email} onChange={set('email')} required/></div>}
            {mode!=='mfa'&&<div className="field"><label>Password</label><input type="password" value={f.password} onChange={set('password')} required/></div>}
            {mode==='mfa'&&<div className="field"><label>6-digit code</label><input value={f.token||''} onChange={e=>setF(p=>({...p,token:e.target.value}))} placeholder="000000" maxLength={6} style={{fontFamily:'monospace',letterSpacing:4,fontSize:20,textAlign:'center'}}/></div>}
            <button type="submit" className="btn-primary" disabled={loading}>{loading?'Please wait…':mode==='login'?'Sign in':mode==='mfa'?'Verify':'Create account'}</button>
          </form>
          {mode!=='mfa'&&<button className="btn-ghost-link" onClick={()=>{setMode(mode==='login'?'signup':'login');setErr('');}}>
            {mode==='login'?'New here? Create an account':'Have an account? Sign in'}
          </button>}
        </div>
      </div>
    </div>
  );
}

// ── ADD PROPERTY MODAL ────────────────────────────────────────────────────────
function AddPropModal({uid,onClose,onSave}){
  const [step,setStep]=useState('zillow'); // zillow | form | manual
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
      if(d.error){setErr(d.error);setLoading(false);return;}
      setF(p=>({...p,
        name:d.address||'',location:d.address||'',
        zestimate:d.zestimate||'',purchase_price:d.zestimate||'',
        property_tax:d.monthly_tax||'',bedrooms:d.bedrooms||'',
        bathrooms:d.bathrooms||'',sqft:d.sqft||'',year_built:d.year_built||'',
        zillow_url:url
      }));
      setMsg(`Zestimate: ${fmt$(d.zestimate)}`);
      setStep('form');
    }catch(e){setErr('Failed to fetch — try again');}
    setLoading(false);
  };

  const save=async()=>{
    if(!f.name){setErr('Name required');return;}
    setLoading(true);setErr('');
    try{
      const r=await fetch(`/api/properties/${uid}`,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(!r.ok){setErr(d.error||'Failed');setLoading(false);return;}
      onSave(d);onClose();
    }catch(e){setErr('Failed to save');}
    setLoading(false);
  };

  const inp=(lbl,k,type='text',placeholder='')=>(
    <div className="form-row">
      <label className="label">{lbl}</label>
      <input className="sinput" type={type} value={f[k]} onChange={set(k)} placeholder={placeholder}/>
    </div>
  );

  return(
    <div className="overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        {step==='zillow'&&<>
          <h3>Add Property</h3>
          <p className="msub">Paste a Zillow URL to auto-fill details</p>
          <div className="zillow-box">
            <h4>🏠 Find on Zillow</h4>
            <p>Go to zillow.com, find the property, and copy the URL from your browser.</p>
          </div>
          {err&&<div className="err">{err}</div>}
          <div className="form-row">
            <label className="label">Zillow URL</label>
            <input className="sinput" value={url} onChange={e=>setUrl(e.target.value)} placeholder="https://www.zillow.com/homedetails/..."/>
          </div>
          <div className="modal-foot">
            <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
            <button className="btn btn-blue" onClick={fetchZillow} disabled={loading}>{loading?'Fetching…':'Get Details'}</button>
          </div>
          <button className="step-back" style={{marginTop:12}} onClick={()=>setStep('manual')}>Enter manually instead →</button>
        </>}
        {(step==='form'||step==='manual')&&<>
          {step==='form'&&<button className="step-back" onClick={()=>setStep('zillow')}>← Back to Zillow</button>}
          {step==='manual'&&<button className="step-back" onClick={()=>setStep('zillow')}>← Back</button>}
          <h3>{step==='form'?'Review Details':'Add Manually'}</h3>
          <p className="msub">{step==='form'?msg||'Review and adjust as needed':'Enter all property details'}</p>
          {err&&<div className="err">{err}</div>}
          {inp('Property name','name','text','123 Main St')}
          {inp('Location','location','text','Houston, TX')}
          <div className="form-row2">
            {inp('Purchase price ($)','purchase_price','number')}
            {inp('Down payment ($)','down_payment','number')}
          </div>
          <div className="form-row2">
            {inp('Current value / Zestimate ($)','zestimate','number')}
            {inp('Monthly rent ($)','monthly_revenue','number')}
          </div>
          <div className="form-row2">
            {inp('Mortgage /mo ($)','mortgage','number')}
            {inp('Property tax /mo ($)','property_tax','number')}
          </div>
          <div className="form-row2">
            {inp('Insurance /mo ($)','insurance','number')}
            {inp('HOA /mo ($)','hoa','number')}
          </div>
          <div className="form-row2">
            {inp('Bedrooms','bedrooms','number')}
            {inp('Bathrooms','bathrooms','number')}
          </div>
          <div className="form-row2">
            {inp('Sqft','sqft','number')}
            {inp('Year built','year_built','number')}
          </div>
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
    setLoading(true);
    await fetch(`/api/property/${prop.id}`,{method:'DELETE',credentials:'include'});
    onDelete(prop.id);onClose();
  };

  const inp=(lbl,k,type='text')=>(
    <div className="form-row">
      <label className="label">{lbl}</label>
      <input className="sinput" type={type} value={f[k]||''} onChange={set(k)}/>
    </div>
  );

  return(
    <div className="overlay" onClick={e=>e.target===e.currentTarget&&onClose()}>
      <div className="modal">
        <h3>Edit Property</h3>
        <p className="msub">{prop.name}</p>
        {err&&<div className="err">{err}</div>}
        {inp('Property name','name')}
        {inp('Location','location')}
        <div className="form-row2">
          {inp('Purchase price ($)','purchase_price','number')}
          {inp('Down payment ($)','down_payment','number')}
        </div>
        <div className="form-row2">
          {inp('Current value ($)','zestimate','number')}
          {inp('Monthly rent ($)','monthly_revenue','number')}
        </div>
        <div className="form-row2">
          {inp('Mortgage /mo ($)','mortgage','number')}
          {inp('Property tax /mo ($)','property_tax','number')}
        </div>
        <div className="form-row2">
          {inp('Insurance /mo ($)','insurance','number')}
          {inp('HOA /mo ($)','hoa','number')}
        </div>
        <div className="modal-foot">
          <button className="btn btn-danger btn-sm" onClick={del}>Delete</button>
          <div style={{flex:1}}/>
          <button className="btn btn-ghost" onClick={onClose}>Cancel</button>
          <button className="btn btn-blue" onClick={save} disabled={loading}>{loading?'Saving…':'Save Changes'}</button>
        </div>
      </div>
    </div>
  );
}

// ── PORTFOLIO TAB ─────────────────────────────────────────────────────────────
function PortfolioTab({user,props,portfolio,onAddProp,onEditProp,onRefresh}){
  const tv=+portfolio.total_value||0;
  const te=+portfolio.total_equity||0;
  const mcf=+portfolio.monthly_cashflow||0;
  const hs=+portfolio.health_score||0;
  const history=portfolio.price_history?JSON.parse(typeof portfolio.price_history==='string'?portfolio.price_history:'[]'):[];
  const chartData=history.map(h=>h.price);
  const accent=user.accent_color||'#1a56db';

  return(
    <div className="page page-in">
      {/* Plaid connect bar */}
      <div className="plaid-bar">
        <span style={{fontSize:20}}>🏦</span>
        <div style={{flex:1}}>
          <div style={{fontSize:13,fontWeight:700}}>Connect your bank</div>
          <div style={{fontSize:11,color:'var(--g500)'}}>Sync rental income &amp; expenses automatically</div>
        </div>
        <button className="btn btn-blue btn-sm">Connect</button>
      </div>

      {/* Hero */}
      <div className="hero">
        <div className="hero-top">
          <div>
            <div className="lbl">Portfolio Value</div>
            <div className="big" style={{color:accent}}>{fmt$k(tv)}</div>
            <div style={{fontSize:12,color:'var(--g500)',marginTop:4}}>Equity: {fmt$k(te)} · {props.length} {props.length===1?'property':'properties'}</div>
          </div>
          <HealthRing score={hs}/>
        </div>
        {chartData.length>1&&<div className="chart-wrap"><MiniChart data={chartData} color={accent}/></div>}
        <div style={{display:'flex',gap:6,marginTop:8}}>
          {['1M','3M','6M','1Y'].map(t=><button key={t} className="btn btn-outline btn-sm">{t}</button>)}
        </div>
      </div>

      {/* Stats */}
      <div className="grid4" style={{marginBottom:16}}>
        <div className="stat"><div className="stat-lbl">Monthly CF</div><div className="stat-val" style={{color:clr(mcf)}}>{fmt$(mcf)}</div></div>
        <div className="stat"><div className="stat-lbl">Annual CF</div><div className="stat-val">{fmt$(mcf*12)}</div></div>
        <div className="stat"><div className="stat-lbl">Total Equity</div><div className="stat-val">{fmt$k(te)}</div></div>
        <div className="stat"><div className="stat-lbl">Avg Cap Rate</div><div className="stat-val">{tv>0?((props.reduce((s,p)=>s+(+p.monthly_revenue*12-+p.property_tax*12-+p.insurance*12-+p.hoa*12),0)/tv)*100).toFixed(1)+'%':'—'}</div></div>
      </div>

      {/* Properties */}
      <div className="sec-hdr">
        <h4>Properties</h4>
        <button className="btn btn-blue btn-sm" onClick={onAddProp}>+ Add Property</button>
      </div>
      {props.length===0&&<div style={{textAlign:'center',padding:'40px 20px',color:'var(--g400)'}}>
        <div style={{fontSize:36,marginBottom:8}}>🏠</div>
        <div style={{fontWeight:600}}>No properties yet</div>
        <div style={{fontSize:13,marginTop:4}}>Add your first property to get started</div>
      </div>}
      {props.map(p=>{
        const val=+p.zestimate||+p.purchase_price||0;
        const cf=+p.monthly_revenue-(+p.mortgage+ +p.insurance+ +p.hoa+ +p.property_tax);
        return(
          <div key={p.id} className="prop-row" onClick={()=>onEditProp(p)}>
            <div className="prop-icon" style={{background:accent+'18'}}>{p.bedrooms?'🏠':'🏢'}</div>
            <div style={{flex:1,minWidth:0}}>
              <div className="prop-name">{p.name}</div>
              <div className="prop-loc">{p.location}</div>
              {p.zestimate>0&&<div className="prop-zest">Zestimate {fmt$(p.zestimate)}</div>}
            </div>
            <div>
              <div className="prop-val">{fmt$k(val)}</div>
              <div className="prop-cf" style={{color:clr(cf)}}>{cf>=0?'+':''}{fmt$(cf)}/mo</div>
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ── CASHFLOW TAB ──────────────────────────────────────────────────────────────
function CashflowTab({props}){
  const revenue=props.reduce((s,p)=>s+(+p.monthly_revenue||0),0);
  const mortgage=props.reduce((s,p)=>s+(+p.mortgage||0),0);
  const tax=props.reduce((s,p)=>s+(+p.property_tax||0),0);
  const ins=props.reduce((s,p)=>s+(+p.insurance||0),0);
  const hoa=props.reduce((s,p)=>s+(+p.hoa||0),0);
  const total_exp=mortgage+tax+ins+hoa;
  const noi=revenue-tax-ins-hoa;
  const ncf=revenue-total_exp;

  const Row=({label,val,sub,bold,green})=>(
    <div className={`cf-row${bold?' total':''}`}>
      <span className="cf-lbl" style={{fontWeight:bold?700:400}}>{label}</span>
      <span className="cf-val" style={{color:green?clr(val):bold?clr(val):'var(--g700)'}}>{val>=0?'':'-'}{fmt$(Math.abs(val))}{sub?<span style={{fontSize:10,fontWeight:400,color:'var(--g500)',marginLeft:4}}>{sub}</span>:null}</span>
    </div>
  );

  return(
    <div className="page page-in">
      <div style={{maxWidth:560}}>
        <div style={{marginBottom:20}}>
          <h3 style={{fontSize:20,fontWeight:800,letterSpacing:'-.3px'}}>Monthly Cash Flow</h3>
          <p style={{fontSize:13,color:'var(--g500)',marginTop:4}}>Across all {props.length} properties</p>
        </div>
        <div className="card" style={{padding:20,marginBottom:16}}>
          <div style={{fontSize:12,fontWeight:700,color:'var(--g400)',textTransform:'uppercase',letterSpacing:.5,marginBottom:12}}>Income</div>
          <Row label="Gross Rental Revenue" val={revenue} green/>
          <div style={{borderTop:'1px solid var(--g100)',margin:'12px 0'}}/>
          <div style={{fontSize:12,fontWeight:700,color:'var(--g400)',textTransform:'uppercase',letterSpacing:.5,marginBottom:12}}>Expenses</div>
          <Row label="Mortgage Payments" val={-mortgage}/>
          <Row label="Property Taxes" val={-tax}/>
          <Row label="Insurance" val={-ins}/>
          <Row label="HOA Fees" val={-hoa}/>
          <div style={{borderTop:'1px solid var(--g200)',margin:'12px 0'}}/>
          <Row label="Net Operating Income (NOI)" val={noi} bold green/>
          <Row label="Net Cash Flow" val={ncf} bold green/>
        </div>
        <div className="grid3">
          <div className="stat"><div className="stat-lbl">Annual Revenue</div><div className="stat-val">{fmt$k(revenue*12)}</div></div>
          <div className="stat"><div className="stat-lbl">Annual Expenses</div><div className="stat-val">{fmt$k(total_exp*12)}</div></div>
          <div className="stat"><div className="stat-lbl">Annual NOI</div><div className="stat-val" style={{color:clr(noi)}}>{fmt$k(noi*12)}</div></div>
        </div>
      </div>
    </div>
  );
}

// ── PERFORMANCE TAB ───────────────────────────────────────────────────────────
function PerformanceTab({user,portfolio,props}){
  const [snaps,setSnaps]=useState([]);
  const uid=user.id;

  useEffect(()=>{
    fetch(`/api/performance/portfolio/${uid}?months=12`,{credentials:'include'})
      .then(r=>r.json()).then(d=>setSnaps(d.snapshots||[])).catch(()=>{});
  },[uid]);

  const tv=+portfolio.total_value||0;
  const te=+portfolio.total_equity||0;
  const mcf=+portfolio.monthly_cashflow||0;
  const totalDown=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const coc=totalDown>0?(mcf*12/totalDown)*100:0;
  const capRate=tv>0?(props.reduce((s,p)=>s+(+p.monthly_revenue*12-+p.property_tax*12-+p.insurance*12-+p.hoa*12),0)/tv)*100:0;
  const chartVals=snaps.map(s=>+s.total_value);

  const saveSnap=async()=>{
    await fetch('/api/performance/snapshot',{method:'POST',credentials:'include'});
    const r=await fetch(`/api/performance/portfolio/${uid}?months=12`,{credentials:'include'});
    const d=await r.json();setSnaps(d.snapshots||[]);
  };

  return(
    <div className="page page-in">
      <div className="sec-hdr" style={{marginBottom:20}}>
        <div>
          <h3 style={{fontSize:20,fontWeight:800,letterSpacing:'-.3px'}}>Performance</h3>
          <p style={{fontSize:13,color:'var(--g500)',marginTop:2}}>Portfolio analytics &amp; historical tracking</p>
        </div>
        <button className="btn btn-blue btn-sm" onClick={saveSnap}>Save Snapshot</button>
      </div>
      <div className="grid4" style={{marginBottom:16}}>
        <div className="stat"><div className="stat-lbl">Total Value</div><div className="stat-val">{fmt$k(tv)}</div></div>
        <div className="stat"><div className="stat-lbl">Total Equity</div><div className="stat-val">{fmt$k(te)}</div></div>
        <div className="stat"><div className="stat-lbl">Cash-on-Cash</div><div className="stat-val" style={{color:clr(coc)}}>{coc.toFixed(1)}%</div></div>
        <div className="stat"><div className="stat-lbl">Cap Rate</div><div className="stat-val">{capRate.toFixed(1)}%</div></div>
      </div>
      {chartVals.length>1&&<div className="card" style={{padding:20,marginBottom:16}}>
        <div className="lbl" style={{marginBottom:8}}>Portfolio Value — Last {snaps.length} months</div>
        <div style={{height:120}}><MiniChart data={chartVals} color={user.accent_color||'#1a56db'}/></div>
      </div>}
      {snaps.length>0&&<div className="card" style={{padding:0,overflow:'hidden'}}>
        <div style={{padding:'14px 18px',borderBottom:'1px solid rgba(0,0,0,.06)',fontWeight:700,fontSize:13}}>Monthly Snapshots</div>
        <div style={{overflowX:'auto'}}>
          <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
            <thead><tr style={{background:'rgba(0,0,0,.03)'}}>
              {['Month','Value','Equity','Revenue','Expenses','Net CF'].map(h=><th key={h} style={{padding:'8px 14px',textAlign:'right',fontWeight:700,color:'var(--g500)',fontSize:10,textTransform:'uppercase',letterSpacing:.4,whiteSpace:'nowrap'}}>{h}</th>)}
            </tr></thead>
            <tbody>{snaps.slice(-12).reverse().map((s,i)=>(
              <tr key={i} style={{borderBottom:'1px solid rgba(0,0,0,.04)'}}>
                <td style={{padding:'8px 14px',fontWeight:600}}>{s.snapshot_month}</td>
                <td style={{padding:'8px 14px',textAlign:'right'}}>{fmt$k(s.total_value)}</td>
                <td style={{padding:'8px 14px',textAlign:'right'}}>{fmt$k(s.total_equity)}</td>
                <td style={{padding:'8px 14px',textAlign:'right',color:'var(--green)'}}>{fmt$(s.gross_revenue)}</td>
                <td style={{padding:'8px 14px',textAlign:'right',color:'var(--red)'}}>{fmt$(s.total_expenses)}</td>
                <td style={{padding:'8px 14px',textAlign:'right',fontWeight:700,color:clr(s.net_cashflow)}}>{fmt$(s.net_cashflow)}</td>
              </tr>
            ))}</tbody>
          </table>
        </div>
      </div>}
      {snaps.length===0&&<div style={{textAlign:'center',padding:'40px',color:'var(--g400)'}}>
        <div style={{fontSize:32,marginBottom:8}}>📊</div>
        <div style={{fontWeight:600}}>No snapshots yet</div>
        <div style={{fontSize:13,marginTop:4}}>Click "Save Snapshot" to start tracking over time</div>
      </div>}
    </div>
  );
}

// ── PROJECTIONS TAB ───────────────────────────────────────────────────────────
function ProjectionsTab({props,portfolio}){
  const tv=+portfolio.total_value||0;
  const rev=props.reduce((s,p)=>s+(+p.monthly_revenue||0),0)*12;
  const exp=props.reduce((s,p)=>s+(+p.mortgage||0)+(+p.insurance||0)+(+p.hoa||0)+(+p.property_tax||0),0)*12;
  const down=props.reduce((s,p)=>s+(+p.down_payment||0),0);
  const debt=tv-+portfolio.total_equity;

  const proj=useMemo(()=>{
    if(!tv)return[];
    return Array.from({length:30},(_,i)=>{
      const y=i+1;
      const val=tv*Math.pow(1.035,y);
      const r=rev*Math.pow(1.025,y);
      const e=exp*Math.pow(1.02,y);
      const vacAdj=r*.95;
      const ncf=vacAdj-e;
      const debtRemain=debt*Math.pow(1-.012-y*.001,y);
      const eq=val-Math.max(0,debtRemain);
      const cumCF=Array.from({length:y},(_,j)=>rev*Math.pow(1.025,j)*.95-exp*Math.pow(1.02,j)).reduce((a,b)=>a+b,0);
      const totalReturn=eq-down+cumCF;
      return{y,val,eq,debt:Math.max(0,debtRemain),rev:r,ncf,cumCF,capRate:tv>0?(vacAdj-exp*.7)/val:0,coc:down>0?ncf/down:0,totalReturn};
    });
  },[tv,rev,exp,down,debt]);

  const milestones=proj.filter(p=>[5,10,15,20,25,30].includes(p.y));
  const milColors=['#1a56db','#7c3aed','#059669','#f59e0b','#d92d20','#0891b2'];

  if(!tv)return(
    <div className="page page-in" style={{textAlign:'center',paddingTop:80}}>
      <div style={{fontSize:40,marginBottom:12}}>📈</div>
      <div style={{fontWeight:700,fontSize:18}}>No properties to project</div>
      <div style={{fontSize:13,color:'var(--g500)',marginTop:6}}>Add a property to see 30-year projections</div>
    </div>
  );

  return(
    <div className="page page-in">
      <div style={{marginBottom:20}}>
        <h3 style={{fontSize:20,fontWeight:800,letterSpacing:'-.3px'}}>30-Year Projections</h3>
        <p style={{fontSize:12,color:'var(--g500)',marginTop:4}}>3.5% appreciation · 2.5% rent growth · 2% expense inflation · 5% vacancy</p>
      </div>
      <div className="grid3" style={{marginBottom:20}}>
        {milestones.slice(0,3).map((m,i)=>(
          <div key={m.y} className="card" style={{padding:16,borderTop:`3px solid ${milColors[i]}`}}>
            <div style={{fontSize:11,fontWeight:700,color:milColors[i],marginBottom:8}}>YEAR {m.y}</div>
            <div style={{fontSize:10,color:'var(--g400)',marginBottom:2}}>Portfolio Value</div>
            <div style={{fontSize:20,fontWeight:800,letterSpacing:'-.5px'}}>{fmt$k(m.val)}</div>
            <div style={{fontSize:10,color:'var(--g400)',marginTop:8,marginBottom:2}}>Equity</div>
            <div style={{fontSize:15,fontWeight:700,color:'var(--green)'}}>{fmt$k(m.eq)}</div>
          </div>
        ))}
      </div>
      <div className="card" style={{padding:0,overflow:'hidden'}}>
        <div style={{overflowX:'auto'}}>
          <table className="proj-table">
            <thead><tr>
              {['Yr','Value','Equity','Revenue','Cash Flow','Cum CF','CoC'].map(h=>(
                <th key={h}>{h}</th>
              ))}
            </tr></thead>
            <tbody>{proj.map(r=>(
              <tr key={r.y} className={[5,10,15,20,25,30].includes(r.y)?'milestone':''}>
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
    </div>
  );
}

// ── NET WORTH TAB ─────────────────────────────────────────────────────────────
function NetWorthTab({portfolio,props}){
  const [stocks,setStocks]=useState([]);
  const [manuals,setManuals]=useState([
    {id:1,label:'Cash & Savings',value:'',type:'asset'},
    {id:2,label:'Vehicle',value:'',type:'asset'},
    {id:3,label:'Student Loans',value:'',type:'liability'},
    {id:4,label:'Credit Cards',value:'',type:'liability'},
  ]);
  const [newLabel,setNewLabel]=useState('');
  const [newVal,setNewVal]=useState('');
  const [newType,setNewType]=useState('asset');
  const [stockInput,setStockInput]=useState('');
  const [stockLoading,setStockLoading]=useState(false);

  const re=+portfolio.total_equity||0;
  const manualAssets=manuals.filter(m=>m.type==='asset').reduce((s,m)=>s+(+m.value||0),0);
  const manualLiab=manuals.filter(m=>m.type==='liability').reduce((s,m)=>s+(+m.value||0),0);
  const stockVal=stocks.reduce((s,st)=>s+(+st.shares*(+st.price||0)),0);
  const totalAssets=re+manualAssets+stockVal;
  const totalLiab=manualLiab;
  const netWorth=totalAssets-totalLiab;

  const addStock=async()=>{
    if(!stockInput)return;
    const parts=stockInput.toUpperCase().split(':');
    const ticker=parts[0].trim();
    const shares=parseFloat(parts[1])||1;
    setStockLoading(true);
    try{
      const r=await fetch(`/api/stocks/quote?ticker=${ticker}`,{credentials:'include'});
      const d=await r.json();
      if(d.price)setStocks(p=>[...p.filter(s=>s.ticker!==ticker),{ticker,shares,price:d.price,change:d.change_pct}]);
    }catch(e){}
    setStockInput('');setStockLoading(false);
  };

  const addManual=()=>{
    if(!newLabel||!newVal)return;
    setManuals(p=>[...p,{id:Date.now(),label:newLabel,value:newVal,type:newType}]);
    setNewLabel('');setNewVal('');
  };

  return(
    <div className="page page-in">
      <div style={{marginBottom:20}}>
        <h3 style={{fontSize:20,fontWeight:800,letterSpacing:'-.3px'}}>Net Worth</h3>
        <div style={{fontSize:32,fontWeight:800,letterSpacing:'-1px',color:clr(netWorth),marginTop:8}}>{fmt$k(netWorth)}</div>
      </div>
      <div className="grid3" style={{marginBottom:16}}>
        <div className="stat"><div className="stat-lbl">Total Assets</div><div className="stat-val">{fmt$k(totalAssets)}</div></div>
        <div className="stat"><div className="stat-lbl">Total Liabilities</div><div className="stat-val" style={{color:'var(--red)'}}>{fmt$k(totalLiab)}</div></div>
        <div className="stat"><div className="stat-lbl">RE Equity</div><div className="stat-val">{fmt$k(re)}</div></div>
      </div>
      {totalAssets>0&&<div style={{display:'flex',height:10,borderRadius:99,overflow:'hidden',marginBottom:16,gap:2}}>
        <div style={{width:pct(re,totalAssets),background:'#1a56db',borderRadius:99}}/>
        <div style={{width:pct(stockVal,totalAssets),background:'#7c3aed',borderRadius:99}}/>
        <div style={{width:pct(manualAssets,totalAssets),background:'#059669',borderRadius:99}}/>
      </div>}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16}}>
        {/* Stocks */}
        <div className="card" style={{padding:18}}>
          <div className="sec-hdr" style={{marginBottom:12}}>
            <h4>Stocks &amp; ETFs</h4>
          </div>
          <div style={{display:'flex',gap:6,marginBottom:12}}>
            <input className="sinput" value={stockInput} onChange={e=>setStockInput(e.target.value)} placeholder="AAPL:10 (ticker:shares)" onKeyDown={e=>e.key==='Enter'&&addStock()} style={{fontSize:12}}/>
            <button className="btn btn-blue btn-sm" onClick={addStock} disabled={stockLoading}>{stockLoading?'…':'Add'}</button>
          </div>
          {stocks.length===0&&<div style={{fontSize:12,color:'var(--g400)',textAlign:'center',padding:'12px 0'}}>No holdings yet</div>}
          {stocks.map(s=>(
            <div key={s.ticker} style={{display:'flex',justifyContent:'space-between',padding:'8px 0',borderBottom:'1px solid var(--g100)'}}>
              <div>
                <div style={{fontSize:13,fontWeight:700}}>{s.ticker}</div>
                <div style={{fontSize:11,color:'var(--g400)'}}>{s.shares} shares · {fmt$(s.price)}</div>
              </div>
              <div style={{textAlign:'right'}}>
                <div style={{fontSize:13,fontWeight:700}}>{fmt$k(s.shares*s.price)}</div>
                <div style={{fontSize:11,color:clr(s.change)}}>{s.change>=0?'+':''}{(s.change||0).toFixed(1)}%</div>
              </div>
            </div>
          ))}
        </div>
        {/* Manual entries */}
        <div className="card" style={{padding:18}}>
          <div className="sec-hdr" style={{marginBottom:12}}>
            <h4>Other Assets &amp; Liabilities</h4>
          </div>
          {manuals.map(m=>(
            <div key={m.id} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'7px 0',borderBottom:'1px solid var(--g100)'}}>
              <div style={{fontSize:13,color:m.type==='liability'?'var(--red)':'var(--g700)'}}>{m.label}</div>
              <input value={m.value} onChange={e=>setManuals(p=>p.map(x=>x.id===m.id?{...x,value:e.target.value}:x))} placeholder="0" style={{width:90,padding:'4px 8px',border:'1.5px solid var(--g200)',borderRadius:7,fontSize:13,textAlign:'right'}}/>
            </div>
          ))}
          <div style={{display:'flex',gap:6,marginTop:12}}>
            <input className="sinput" value={newLabel} onChange={e=>setNewLabel(e.target.value)} placeholder="Label" style={{fontSize:12}}/>
            <input className="sinput" value={newVal} onChange={e=>setNewVal(e.target.value)} placeholder="$" style={{width:80,fontSize:12}}/>
            <select value={newType} onChange={e=>setNewType(e.target.value)} className="sinput" style={{width:90,fontSize:12}}>
              <option value="asset">Asset</option>
              <option value="liability">Liability</option>
            </select>
            <button className="btn btn-blue btn-sm" onClick={addManual}>+</button>
          </div>
        </div>
      </div>
    </div>
  );
}

// ── DISCOVER TAB ──────────────────────────────────────────────────────────────
function DiscoverTab({user}){
  const [users,setUsers]=useState([]);
  const [following,setFollowing]=useState(new Set());

  useEffect(()=>{
    fetch('/api/users/discover',{credentials:'include'}).then(r=>r.json()).then(d=>{
      setUsers(d);
      setFollowing(new Set(d.filter(u=>u.is_following).map(u=>u.id)));
    }).catch(()=>{});
  },[]);

  const toggle=async(uid)=>{
    const isF=following.has(uid);
    await fetch(`/api/${isF?'un':''}follow/${uid}`,{method:'POST',credentials:'include'});
    setFollowing(p=>{const n=new Set(p);isF?n.delete(uid):n.add(uid);return n;});
  };

  return(
    <div className="page page-in">
      <div style={{marginBottom:20}}>
        <h3 style={{fontSize:20,fontWeight:800,letterSpacing:'-.3px'}}>Discover Investors</h3>
        <p style={{fontSize:13,color:'var(--g500)',marginTop:4}}>Follow top performers to track their portfolios</p>
      </div>
      {users.length===0&&<div style={{textAlign:'center',padding:'60px 20px',color:'var(--g400)'}}>
        <div style={{fontSize:36,marginBottom:8}}>🔍</div>
        <div style={{fontWeight:600}}>No other users yet</div>
      </div>}
      {users.map(u=>{
        const isF=following.has(u.id);
        return(
          <div key={u.id} className="disc-row">
            <div className="av" style={{background:u.avatar_color||'#1a56db',fontSize:12}}>{initials(u.full_name||u.username)}</div>
            <div style={{flex:1,minWidth:0}}>
              <div className="disc-name">{u.full_name||u.username}</div>
              <div className="disc-sub">{u.portfolio_name||u.username} · {u.property_count||0} properties · {fmt$k(u.total_value)}</div>
            </div>
            <button className={`follow-btn${isF?' on':''}`} onClick={()=>toggle(u.id)}>{isF?'Following':'Follow'}</button>
          </div>
        );
      })}
    </div>
  );
}

// ── FEED TAB ──────────────────────────────────────────────────────────────────
function FeedTab({user}){
  const [feed,setFeed]=useState([]);

  useEffect(()=>{
    fetch('/api/following',{credentials:'include'}).then(r=>r.json()).then(setFeed).catch(()=>{});
  },[]);

  return(
    <div className="page page-in">
      <div style={{marginBottom:20}}>
        <h3 style={{fontSize:20,fontWeight:800,letterSpacing:'-.3px'}}>Following</h3>
        <p style={{fontSize:13,color:'var(--g500)',marginTop:4}}>Portfolios you track</p>
      </div>
      {feed.length===0&&<div style={{textAlign:'center',padding:'60px 20px',color:'var(--g400)'}}>
        <div style={{fontSize:36,marginBottom:8}}>📰</div>
        <div style={{fontWeight:600}}>No one followed yet</div>
        <div style={{fontSize:13,marginTop:4}}>Go to Discover to follow investors</div>
      </div>}
      {feed.map(u=>(
        <div key={u.id} className="feed-item">
          <div className="feed-hdr">
            <div className="av" style={{background:u.avatar_color||'#1a56db',fontSize:12}}>{initials(u.full_name||u.username)}</div>
            <div>
              <div className="feed-name">{u.full_name||u.username}</div>
              <div style={{display:'flex',gap:6,marginTop:2}}>
                <span className="pill pill-blue">{u.ticker}</span>
                <span className="feed-time">Updated recently</span>
              </div>
            </div>
          </div>
          <div className="feed-grid">
            <div className="feed-cell"><div className="feed-cell-lbl">Portfolio Value</div><div className="feed-cell-val">{fmt$k(u.total_value)}</div></div>
            <div className="feed-cell"><div className="feed-cell-lbl">Monthly CF</div><div className="feed-cell-val" style={{color:clr(u.monthly_cashflow)}}>{fmt$(u.monthly_cashflow)}</div></div>
            <div className="feed-cell"><div className="feed-cell-lbl">Share Price</div><div className="feed-cell-val">${(+u.share_price||1).toFixed(2)}</div></div>
          </div>
        </div>
      ))}
    </div>
  );
}

// ── SETTINGS TAB ─────────────────────────────────────────────────────────────
function SettingsTab({user,onUpdate,onLogout}){
  const [f,setF]=useState({full_name:user.full_name||'',portfolio_name:user.portfolio_name||'',bio:user.bio||'',accent_color:user.accent_color||'#1a56db'});
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
      <div style={{maxWidth:520}}>
        <h3 style={{fontSize:20,fontWeight:800,letterSpacing:'-.3px',marginBottom:20}}>Settings</h3>
        {err&&<div className="err">{err}</div>}
        {msg&&<div className="success">{msg}</div>}
        <div className="card" style={{padding:22,marginBottom:14}}>
          <div style={{fontWeight:700,fontSize:13,marginBottom:16}}>Profile</div>
          <div className="form-row">
            <label className="label">Full name</label>
            <input className="sinput" value={f.full_name} onChange={e=>setF(p=>({...p,full_name:e.target.value}))}/>
          </div>
          <div className="form-row">
            <label className="label">Portfolio name</label>
            <input className="sinput" value={f.portfolio_name} onChange={e=>setF(p=>({...p,portfolio_name:e.target.value}))}/>
          </div>
          <div className="form-row">
            <label className="label">Bio</label>
            <input className="sinput" value={f.bio} onChange={e=>setF(p=>({...p,bio:e.target.value}))} placeholder="Real estate investor..."/>
          </div>
        </div>
        <div className="card" style={{padding:22,marginBottom:14}}>
          <div style={{fontWeight:700,fontSize:13,marginBottom:14}}>Accent Color</div>
          <div className="swatch-row">
            {COLORS.map(c=><div key={c} className={`swatch${f.accent_color===c?' on':''}`} style={{background:c}} onClick={()=>setF(p=>({...p,accent_color:c}))}/>)}
          </div>
        </div>
        <div style={{display:'flex',gap:10}}>
          <button className="btn btn-blue" onClick={save}>Save Changes</button>
          <button className="btn btn-danger" onClick={onLogout}>Sign Out</button>
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
  const accent=user.accent_color||'#1a56db';

  useEffect(()=>{
    document.documentElement.style.setProperty('--blue',accent);
  },[accent]);

  const loadData=useCallback(async()=>{
    try{
      const [pf,pr]=await Promise.all([
        fetch(`/api/portfolio/${user.id}`,{credentials:'include'}).then(r=>r.json()),
        fetch(`/api/properties/${user.id}`,{credentials:'include'}).then(r=>r.json())
      ]);
      setPortfolio(pf||{});
      setProps(Array.isArray(pr)?pr:[]);
    }catch(e){}
  },[user.id]);

  useEffect(()=>{loadData();},[loadData]);

  const NAV=[
    {id:'portfolio',label:'Portfolio',path:'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6'},
    {id:'cashflow',label:'Cash Flow',path:'M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v8m0 0v1m0-1c-1.11 0-2.08-.402-2.599-1M21 12a9 9 0 11-18 0 9 9 0 0118 0z'},
    {id:'performance',label:'Performance',path:'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z'},
    {id:'projections',label:'Projections',path:'M13 7h8m0 0v8m0-8l-8 8-4-4-6 6'},
    {id:'networth',label:'Net Worth',path:'M9 7h6m0 10H9m3-3v3m-7 1h14a2 2 0 002-2V5a2 2 0 00-2-2H5a2 2 0 00-2 2v14a2 2 0 002 2z'},
    {id:'discover',label:'Discover',path:'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'},
    {id:'feed',label:'Feed',path:'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z'},
    {id:'settings',label:'Settings',path:'M10.325 4.317c.426-1.756 2.924-1.756 3.35 0a1.724 1.724 0 002.573 1.066c1.543-.94 3.31.826 2.37 2.37a1.724 1.724 0 001.065 2.572c1.756.426 1.756 2.924 0 3.35a1.724 1.724 0 00-1.066 2.573c.94 1.543-.826 3.31-2.37 2.37a1.724 1.724 0 00-2.572 1.065c-.426 1.756-2.924 1.756-3.35 0a1.724 1.724 0 00-2.573-1.066c-1.543.94-3.31-.826-2.37-2.37a1.724 1.724 0 00-1.065-2.572c-1.756-.426-1.756-2.924 0-3.35a1.724 1.724 0 001.066-2.573c-.94-1.543.826-3.31 2.37-2.37.996.608 2.296.07 2.572-1.065z M15 12a3 3 0 11-6 0 3 3 0 016 0z'},
  ];

  const PAGE_TITLES={portfolio:'Portfolio',cashflow:'Cash Flow',performance:'Performance',projections:'Projections',networth:'Net Worth',discover:'Discover',feed:'Feed',settings:'Settings'};

  const tabProps={user,props,portfolio,onRefresh:loadData};

  return(
    <div className="shell">
      <div className="sidebar">
        <div className="sb-logo">
          <span>🐦</span> Property Pigeon
        </div>
        <nav className="nav">
          {NAV.map(n=>(
            <div key={n.id} className={`ni${tab===n.id?' on':''}`} onClick={()=>setTab(n.id)}>
              <svg fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24">
                <path strokeLinecap="round" strokeLinejoin="round" d={n.path}/>
              </svg>
              {n.label}
            </div>
          ))}
        </nav>
        <div className="sb-foot">
          <div className="user-chip" onClick={()=>setTab('settings')}>
            <div className="av" style={{background:accent}}>{initials(user.full_name||user.username)}</div>
            <div>
              <div className="uname">{user.full_name||user.username}</div>
              <div className="uticker">{user.ticker||user.username}</div>
            </div>
          </div>
        </div>
      </div>
      <div className="content">
        <div className="topbar">
          <h3>{PAGE_TITLES[tab]}</h3>
          {tab==='portfolio'&&<button className="btn btn-blue btn-sm" onClick={()=>setShowAdd(true)}>+ Add Property</button>}
        </div>
        {tab==='portfolio'&&<PortfolioTab {...tabProps} onAddProp={()=>setShowAdd(true)} onEditProp={setEditProp}/>}
        {tab==='cashflow'&&<CashflowTab {...tabProps}/>}
        {tab==='performance'&&<PerformanceTab {...tabProps}/>}
        {tab==='projections'&&<ProjectionsTab {...tabProps}/>}
        {tab==='networth'&&<NetWorthTab {...tabProps}/>}
        {tab==='discover'&&<DiscoverTab {...tabProps}/>}
        {tab==='feed'&&<FeedTab {...tabProps}/>}
        {tab==='settings'&&<SettingsTab user={user} onUpdate={u=>{setUser(u);}} onLogout={async()=>{await fetch('/api/auth/logout',{method:'POST',credentials:'include'});onLogout();}}/>}
      </div>
      {showAdd&&<AddPropModal uid={user.id} onClose={()=>setShowAdd(false)} onSave={p=>{setProps(prev=>[p,...prev]);loadData();}}/>}
      {editProp&&<EditPropModal prop={editProp} onClose={()=>setEditProp(null)} onSave={p=>{setProps(prev=>prev.map(x=>x.id===p.id?p:x));setEditProp(null);loadData();}} onDelete={id=>{setProps(prev=>prev.filter(x=>x.id!==id));setEditProp(null);loadData();}}/>}
    </div>
  );
}

// ── ROOT ───────────────────────────────────────────────────────────────────────
function App(){
  const [user,setUser]=useState(null);
  const [loading,setLoading]=useState(true);

  useEffect(()=>{
    fetch('/api/auth/me',{credentials:'include'})
      .then(r=>r.ok?r.json():null)
      .then(d=>{if(d?.user)setUser(d.user);})
      .catch(()=>{})
      .finally(()=>setLoading(false));
  },[]);

  if(loading)return(
    <div style={{height:'100vh',display:'flex',alignItems:'center',justifyContent:'center',background:'linear-gradient(135deg,#dce8ff,#f0e8ff)'}}>
      <div style={{textAlign:'center'}}>
        <div style={{fontSize:44,marginBottom:12,animation:'spin 2s linear infinite'}}>🐦</div>
        <div style={{fontWeight:600,color:'#6b7280'}}>Loading…</div>
      </div>
      <style>{`@keyframes spin{from{transform:rotate(0)}to{transform:rotate(360deg)}}`}</style>
    </div>
  );

  if(!user)return <AuthScreen onLogin={setUser}/>;
  return <MainApp user={user} onLogout={()=>setUser(null)}/>;
}

const _root=ReactDOM.createRoot(document.getElementById('root'));
_root.render(<App/>);
</script>
</body>
</html>"""

# ── SERVE ──────────────────────────────────────────────────────────────────────
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_app(path):
    return Response(HTML, mimetype='text/html')

if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=int(os.environ.get('PORT', 5000)))
