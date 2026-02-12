import os, json, secrets, hashlib, hmac, time, base64, struct, urllib.request, urllib.parse
from datetime import timedelta
from flask import Flask, request, jsonify, session, Response
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor

app = Flask(**name**)

_secret = os.environ.get(‘SECRET_KEY’)
if not _secret:
print(‘WARNING: SECRET_KEY not set - sessions reset on restart’)
_secret = secrets.token_hex(32)
app.secret_key = _secret
app.config.update(
SESSION_COOKIE_SECURE=True,
SESSION_COOKIE_HTTPONLY=True,
SESSION_COOKIE_SAMESITE=‘Lax’,
PERMANENT_SESSION_LIFETIME=timedelta(days=30),
SESSION_COOKIE_NAME=‘pp_session’,
)
CORS(app, supports_credentials=True)

DATABASE_URL = os.environ.get(‘DATABASE_URL’, ‘postgresql://localhost/propertypigeon’)
PLAID_CLIENT_ID = os.environ.get(‘PLAID_CLIENT_ID’, ‘’)
PLAID_SECRET = os.environ.get(‘PLAID_SECRET’, ‘’)
PLAID_ENV = os.environ.get(‘PLAID_ENV’, ‘sandbox’)
ATTOM_API_KEY = os.environ.get(‘ATTOM_API_KEY’, ‘’)
RENTCAST_API_KEY = os.environ.get(‘RENTCAST_API_KEY’, ‘’)

def get_db():
url = DATABASE_URL
if url.startswith(‘postgres://’):
url = url.replace(‘postgres://’, ‘postgresql://’, 1)
return psycopg2.connect(url)

def init_db():
with get_db() as conn:
cur = conn.cursor()
cur.execute(”””
CREATE TABLE IF NOT EXISTS users (
id SERIAL PRIMARY KEY,
username VARCHAR(50) UNIQUE NOT NULL,
email VARCHAR(255) UNIQUE NOT NULL,
password_hash VARCHAR(255) NOT NULL,
display_name VARCHAR(100),
bio TEXT DEFAULT ‘’,
avatar_color VARCHAR(7) DEFAULT ‘#1a56db’,
is_public BOOLEAN DEFAULT true,
ticker VARCHAR(10) UNIQUE,
totp_secret VARCHAR(64),
mfa_enabled BOOLEAN DEFAULT false,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
“””)
cur.execute(”””
CREATE TABLE IF NOT EXISTS properties (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
name VARCHAR(100) NOT NULL,
location TEXT,
purchase_price DECIMAL(12,2) DEFAULT 0,
down_payment DECIMAL(12,2) DEFAULT 0,
mortgage DECIMAL(10,2) DEFAULT 0,
insurance DECIMAL(10,2) DEFAULT 0,
hoa DECIMAL(10,2) DEFAULT 0,
property_tax DECIMAL(10,2) DEFAULT 0,
monthly_revenue DECIMAL(10,2) DEFAULT 0,
monthly_expenses DECIMAL(10,2) DEFAULT 0,
equity DECIMAL(12,2) DEFAULT 0,
zestimate DECIMAL(12,2) DEFAULT 0,
zpid VARCHAR(50),
bedrooms INTEGER,
bathrooms DECIMAL(4,1),
sqft INTEGER,
year_built INTEGER,
last_value_refresh TIMESTAMP,
zillow_url TEXT,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
“””)
cur.execute(”””
CREATE TABLE IF NOT EXISTS portfolio_metrics (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
total_value DECIMAL(14,2) DEFAULT 0,
total_equity DECIMAL(14,2) DEFAULT 0,
monthly_cashflow DECIMAL(10,2) DEFAULT 0,
annual_cashflow DECIMAL(10,2) DEFAULT 0,
property_count INTEGER DEFAULT 0,
health_score INTEGER DEFAULT 0,
share_price DECIMAL(10,4) DEFAULT 1.0,
price_history JSONB DEFAULT ‘[]’,
updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
UNIQUE(user_id)
)
“””)
cur.execute(”””
CREATE TABLE IF NOT EXISTS follows (
follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
PRIMARY KEY(follower_id, following_id)
)
“””)
cur.execute(”””
CREATE TABLE IF NOT EXISTS plaid_items (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
access_token TEXT,
item_id TEXT,
institution_name TEXT,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
“””)
cur.execute(”””
CREATE TABLE IF NOT EXISTS monthly_snapshots (
id SERIAL PRIMARY KEY,
user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
snapshot_month DATE NOT NULL,
total_value DECIMAL(14,2) DEFAULT 0,
total_equity DECIMAL(14,2) DEFAULT 0,
total_debt DECIMAL(14,2) DEFAULT 0,
gross_revenue DECIMAL(10,2) DEFAULT 0,
total_expenses DECIMAL(10,2) DEFAULT 0,
net_cashflow DECIMAL(10,2) DEFAULT 0,
noi DECIMAL(10,2) DEFAULT 0,
property_count INTEGER DEFAULT 0,
avg_cap_rate DECIMAL(6,4) DEFAULT 0,
avg_cash_on_cash DECIMAL(6,4) DEFAULT 0,
created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
UNIQUE(user_id, snapshot_month)
)
“””)
conn.commit()
cur.close()

try:
init_db()
except Exception as e:
print(f’DB init error: {e}’)

# ── HELPERS ───────────────────────────────────────────────────────────────────

def hash_password(pw):
salt = secrets.token_hex(16)
h = hashlib.pbkdf2_hmac(‘sha256’, pw.encode(), salt.encode(), 260000)
return salt + ‘:’ + h.hex()

def verify_password(pw, stored):
try:
salt, h = stored.split(’:’, 1)
return hmac.compare_digest(h, hashlib.pbkdf2_hmac(‘sha256’, pw.encode(), salt.encode(), 260000).hex())
except: return False

def generate_ticker(name):
import re
words = re.findall(r’[A-Za-z]+’, name)
if len(words) >= 2: base = ‘’.join(w[0] for w in words[:3]).upper()
else: base = (name[:4]).upper().replace(’ ‘,’’)
with get_db() as conn:
cur = conn.cursor()
ticker = base
for i in range(1, 100):
cur.execute(“SELECT id FROM users WHERE ticker=%s”, (ticker,))
if not cur.fetchone(): break
ticker = base + str(i)
cur.close()
return ticker

def _totp_token(secret, t=None):
if t is None: t = int(time.time()) // 30
key = base64.b32decode(secret.upper() + ‘=’ * (-len(secret) % 8))
msg = struct.pack(’>Q’, t)
h = hmac.new(key, msg, ‘sha1’).digest()
o = h[-1] & 0xf
code = struct.unpack(’>I’, h[o:o+4])[0] & 0x7fffffff
return str(code % 1000000).zfill(6)

def verify_totp(secret, token):
return any(_totp_token(secret, int(time.time())//30 + d) == token for d in [-1,0,1])

def calculate_health_score(metrics):
score = 50
cf = float(metrics.get(‘monthly_cashflow’, 0) or 0)
eq = float(metrics.get(‘total_equity’, 0) or 0)
val = float(metrics.get(‘total_value’, 0) or 0)
if cf > 0: score += min(25, int(cf / 200))
elif cf < 0: score += max(-25, int(cf / 200))
if val > 0: score += min(25, int((eq/val)*25))
return max(0, min(100, score))

def calculate_share_price(m):
base = 1.0
eq = float(m.get(‘total_equity’, 0) or 0)
cf = float(m.get(‘annual_cashflow’, 0) or 0)
props = int(m.get(‘property_count’, 0) or 0)
if props > 0: base += (eq / 100000) * 0.1 + (cf / 10000) * 0.05
return round(max(0.01, base), 4)

def update_metrics(user_id):
try:
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM properties WHERE user_id=%s”, (user_id,))
props = cur.fetchall()
total_value = sum(float(p.get(‘zestimate’) or p.get(‘purchase_price’) or 0) for p in props)
total_equity = sum(float(p.get(‘equity’) or 0) for p in props)
monthly_cf = sum(float(p.get(‘monthly_revenue’) or 0) - float(p.get(‘monthly_expenses’) or 0) for p in props)
cur.execute(“SELECT price_history FROM portfolio_metrics WHERE user_id=%s”, (user_id,))
row = cur.fetchone()
history = json.loads(row[‘price_history’]) if row and row[‘price_history’] else []
m = {‘total_value’:total_value,‘total_equity’:total_equity,‘monthly_cashflow’:monthly_cf,‘annual_cashflow’:monthly_cf*12,‘property_count’:len(props)}
sp = calculate_share_price(m)
hs = calculate_health_score(m)
history.append({‘date’: time.strftime(’%Y-%m-%d’), ‘price’: sp})
if len(history) > 365: history = history[-365:]
cur.execute(”””
INSERT INTO portfolio_metrics (user_id,total_value,total_equity,monthly_cashflow,annual_cashflow,property_count,health_score,share_price,price_history)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT(user_id) DO UPDATE SET
total_value=EXCLUDED.total_value,total_equity=EXCLUDED.total_equity,
monthly_cashflow=EXCLUDED.monthly_cashflow,annual_cashflow=EXCLUDED.annual_cashflow,
property_count=EXCLUDED.property_count,health_score=EXCLUDED.health_score,
share_price=EXCLUDED.share_price,price_history=EXCLUDED.price_history,
updated_at=CURRENT_TIMESTAMP
“””, (user_id,total_value,total_equity,monthly_cf,monthly_cf*12,len(props),hs,sp,json.dumps(history)))
conn.commit()
cur.close()
except Exception as e:
print(f’update_metrics error: {e}’)

def record_monthly_snapshot(user_id):
from datetime import date
today = date.today()
month_start = date(today.year, today.month, 1)
try:
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM properties WHERE user_id=%s”, (user_id,))
props = cur.fetchall()
if not props: cur.close(); return
total_value = sum(float(p.get(‘zestimate’) or p.get(‘purchase_price’) or 0) for p in props)
total_equity = sum(float(p.get(‘equity’) or 0) for p in props)
gross_revenue = sum(float(p.get(‘monthly_revenue’) or 0) for p in props)
total_expenses = sum(float(p.get(‘monthly_expenses’) or 0) for p in props)
net_cashflow = gross_revenue - total_expenses
noi = gross_revenue - sum(float(p.get(‘property_tax’) or 0) + float(p.get(‘insurance’) or 0) + float(p.get(‘hoa’) or 0) for p in props)
avg_cap_rate = (noi * 12 / total_value) if total_value > 0 else 0
total_down = sum(float(p.get(‘down_payment’) or 0) for p in props)
avg_coc = (net_cashflow * 12 / total_down) if total_down > 0 else 0
cur.execute(”””
INSERT INTO monthly_snapshots (user_id,snapshot_month,total_value,total_equity,total_debt,gross_revenue,total_expenses,net_cashflow,noi,property_count,avg_cap_rate,avg_cash_on_cash)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)
ON CONFLICT (user_id,snapshot_month) DO UPDATE SET
total_value=EXCLUDED.total_value,total_equity=EXCLUDED.total_equity,total_debt=EXCLUDED.total_debt,
gross_revenue=EXCLUDED.gross_revenue,total_expenses=EXCLUDED.total_expenses,
net_cashflow=EXCLUDED.net_cashflow,noi=EXCLUDED.noi,property_count=EXCLUDED.property_count,
avg_cap_rate=EXCLUDED.avg_cap_rate,avg_cash_on_cash=EXCLUDED.avg_cash_on_cash
“””, (user_id, month_start, total_value, total_equity, total_value-total_equity,
gross_revenue, total_expenses, net_cashflow, noi, len(props), avg_cap_rate, avg_coc))
conn.commit(); cur.close()
except Exception as e:
print(f’Snapshot error: {e}’)

# ── AUTH ROUTES ───────────────────────────────────────────────────────────────

@app.route(’/api/auth/signup’, methods=[‘POST’])
def signup():
d = request.json
try:
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
ticker = generate_ticker(d.get(‘username’,’’))
cur.execute(“INSERT INTO users (username,email,password_hash,display_name,ticker) VALUES (%s,%s,%s,%s,%s) RETURNING *”,
(d[‘username’], d[‘email’], hash_password(d[‘password’]), d.get(‘display_name’, d[‘username’]), ticker))
user = dict(cur.fetchone())
uid = user[‘id’]
cur.execute(“INSERT INTO portfolio_metrics (user_id) VALUES (%s) ON CONFLICT DO NOTHING”, (uid,))
conn.commit(); cur.close()
session.permanent = True
session[‘user_id’] = uid
user.pop(‘password_hash’, None); user.pop(‘totp_secret’, None)
return jsonify({‘user’: user})
except Exception as e:
return jsonify({‘error’: str(e)}), 400

@app.route(’/api/auth/login’, methods=[‘POST’])
def login():
d = request.json
try:
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM users WHERE username=%s OR email=%s”, (d[‘username’], d[‘username’]))
u = cur.fetchone()
if not u or not verify_password(d[‘password’], u[‘password_hash’]):
return jsonify({‘error’: ‘Invalid credentials’}), 401
if u[‘mfa_enabled’]:
session[‘mfa_pending_user_id’] = u[‘id’]
return jsonify({‘mfa_required’: True})
session.permanent = True
session[‘user_id’] = u[‘id’]
update_metrics(u[‘id’])
cur.close()
u = dict(u); u.pop(‘password_hash’, None); u.pop(‘totp_secret’, None)
return jsonify({‘user’: u})
except Exception as e:
return jsonify({‘error’: str(e)}), 400

@app.route(’/api/auth/mfa/verify’, methods=[‘POST’])
def mfa_verify():
d = request.json
pending_uid = session.get(‘mfa_pending_user_id’)
if not pending_uid: return jsonify({‘error’: ‘No pending MFA’}), 400
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM users WHERE id=%s”, (pending_uid,))
u = dict(cur.fetchone())
cur.close()
if verify_totp(u[‘totp_secret’], d.get(‘token’, ‘’)):
session.permanent = True
session.pop(‘mfa_pending_user_id’, None)
session[‘user_id’] = pending_uid
u.pop(‘password_hash’, None); u.pop(‘totp_secret’, None)
return jsonify({‘user’: u})
return jsonify({‘error’: ‘Invalid code’}), 401

@app.route(’/api/auth/mfa/setup’, methods=[‘POST’])
def mfa_setup():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
secret = base64.b32encode(secrets.token_bytes(20)).decode()
with get_db() as conn:
cur = conn.cursor()
cur.execute(“UPDATE users SET totp_secret=%s WHERE id=%s”, (secret, uid))
conn.commit(); cur.close()
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT username FROM users WHERE id=%s”, (uid,))
u = cur.fetchone(); cur.close()
uri = f”otpauth://totp/PropertyPigeon:{u[‘username’]}?secret={secret}&issuer=PropertyPigeon”
return jsonify({‘secret’: secret, ‘uri’: uri})

@app.route(’/api/auth/mfa/enable’, methods=[‘POST’])
def mfa_enable():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
d = request.json
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT totp_secret FROM users WHERE id=%s”, (uid,))
u = cur.fetchone(); cur.close()
if not verify_totp(u[‘totp_secret’], d.get(‘token’, ‘’)):
return jsonify({‘error’: ‘Invalid code’}), 401
with get_db() as conn:
cur = conn.cursor()
cur.execute(“UPDATE users SET mfa_enabled=true WHERE id=%s”, (uid,))
conn.commit(); cur.close()
return jsonify({‘success’: True})

@app.route(’/api/auth/logout’, methods=[‘POST’])
def logout():
session.clear()
return jsonify({‘ok’: True})

@app.route(’/api/auth/me’)
def get_me():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM users WHERE id=%s”, (uid,))
u = dict(cur.fetchone()); cur.close()
u.pop(‘password_hash’, None); u.pop(‘totp_secret’, None)
return jsonify({‘user’: u})

# ── SOCIAL ROUTES ─────────────────────────────────────────────────────────────

@app.route(’/api/users/discover’)
def discover():
uid = session.get(‘user_id’)
if not uid: return jsonify([])
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(”””
SELECT u.id,u.username,u.display_name,u.ticker,u.avatar_color,u.bio,
pm.total_value,pm.monthly_cashflow,pm.health_score,pm.share_price,
EXISTS(SELECT 1 FROM follows WHERE follower_id=%s AND following_id=u.id) as is_following
FROM users u LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
WHERE u.id!=%s AND u.is_public=true ORDER BY pm.total_value DESC NULLS LAST LIMIT 20
“””, (uid, uid))
users = [dict(r) for r in cur.fetchall()]; cur.close()
return jsonify(users)

@app.route(’/api/follow/<int:fid>’, methods=[‘POST’])
def follow(fid):
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
with get_db() as conn:
cur = conn.cursor()
cur.execute(“INSERT INTO follows (follower_id,following_id) VALUES (%s,%s) ON CONFLICT DO NOTHING”, (uid,fid))
conn.commit(); cur.close()
return jsonify({‘ok’: True})

@app.route(’/api/unfollow/<int:fid>’, methods=[‘POST’])
def unfollow(fid):
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
with get_db() as conn:
cur = conn.cursor()
cur.execute(“DELETE FROM follows WHERE follower_id=%s AND following_id=%s”, (uid,fid))
conn.commit(); cur.close()
return jsonify({‘ok’: True})

@app.route(’/api/following’)
def get_following():
uid = session.get(‘user_id’)
if not uid: return jsonify([])
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT following_id FROM follows WHERE follower_id=%s”, (uid,))
ids = [r[‘following_id’] for r in cur.fetchall()]; cur.close()
return jsonify(ids)

@app.route(’/api/feed’)
def get_feed():
uid = session.get(‘user_id’)
if not uid: return jsonify([])
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(”””
SELECT u.username,u.display_name,u.ticker,u.avatar_color,
pm.total_value,pm.monthly_cashflow,pm.share_price,pm.health_score,pm.updated_at
FROM follows f JOIN users u ON u.id=f.following_id
LEFT JOIN portfolio_metrics pm ON pm.user_id=u.id
WHERE f.follower_id=%s ORDER BY pm.updated_at DESC LIMIT 30
“””, (uid,))
feed = [dict(r) for r in cur.fetchall()]; cur.close()
for item in feed:
if item.get(‘updated_at’): item[‘updated_at’] = item[‘updated_at’].isoformat()
return jsonify(feed)

# ── PORTFOLIO & PROPERTIES ────────────────────────────────────────────────────

@app.route(’/api/portfolio/<int:uid>’)
def get_portfolio(uid):
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM portfolio_metrics WHERE user_id=%s”, (uid,))
row = cur.fetchone()
cur.execute(“SELECT * FROM properties WHERE user_id=%s ORDER BY created_at DESC”, (uid,))
props = [dict(p) for p in cur.fetchall()]
cur.close()
m = dict(row) if row else {}
for p in props:
for k,v in p.items():
if hasattr(v,‘isoformat’): p[k]=v.isoformat()
return jsonify({‘metrics’: m, ‘properties’: props})

@app.route(’/api/properties/<int:uid>’, methods=[‘POST’])
def add_property(uid):
req_uid = session.get(‘user_id’)
if not req_uid or req_uid != uid: return jsonify({‘error’: ‘Not authorized’}), 401
d = request.json
try:
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
monthly_exp = sum(float(d.get(k,0) or 0) for k in [‘mortgage’,‘property_tax’,‘insurance’,‘hoa’])
equity = float(d.get(‘down_payment’,0) or 0)
cur.execute(”””
INSERT INTO properties (user_id,name,location,purchase_price,down_payment,mortgage,insurance,hoa,property_tax,monthly_revenue,monthly_expenses,equity,zestimate,zillow_url,bedrooms,bathrooms,sqft,year_built)
VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *
“””, (uid, d.get(‘name’,’’), d.get(‘location’,’’),
d.get(‘purchase_price’,0), d.get(‘down_payment’,0), d.get(‘mortgage’,0),
d.get(‘insurance’,0), d.get(‘hoa’,0), d.get(‘property_tax’,0),
d.get(‘monthly_revenue’,0), monthly_exp, equity,
d.get(‘zestimate’,0) or d.get(‘purchase_price’,0),
d.get(‘zillow_url’,’’),
d.get(‘bedrooms’), d.get(‘bathrooms’), d.get(‘sqft’), d.get(‘year_built’)))
prop = dict(cur.fetchone())
conn.commit(); cur.close()
update_metrics(uid)
record_monthly_snapshot(uid)
for k,v in prop.items():
if hasattr(v,‘isoformat’): prop[k]=v.isoformat()
return jsonify(prop)
except Exception as e:
return jsonify({‘error’: str(e)}), 500

@app.route(’/api/property/<int:pid>’, methods=[‘PUT’])
def update_property(pid):
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
d = request.json
try:
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
monthly_exp = sum(float(d.get(k,0) or 0) for k in [‘mortgage’,‘property_tax’,‘insurance’,‘hoa’])
cur.execute(”””
UPDATE properties SET name=%s,location=%s,purchase_price=%s,down_payment=%s,mortgage=%s,
insurance=%s,hoa=%s,property_tax=%s,monthly_revenue=%s,monthly_expenses=%s,equity=%s,
zestimate=%s,zillow_url=%s,bedrooms=%s,bathrooms=%s,sqft=%s,year_built=%s
WHERE id=%s AND user_id=%s RETURNING *
“””, (d.get(‘name’), d.get(‘location’), d.get(‘purchase_price’,0), d.get(‘down_payment’,0),
d.get(‘mortgage’,0), d.get(‘insurance’,0), d.get(‘hoa’,0), d.get(‘property_tax’,0),
d.get(‘monthly_revenue’,0), monthly_exp, d.get(‘equity’,0),
d.get(‘zestimate’,0) or d.get(‘purchase_price’,0),
d.get(‘zillow_url’,’’), d.get(‘bedrooms’), d.get(‘bathrooms’),
d.get(‘sqft’), d.get(‘year_built’), pid, uid))
prop = cur.fetchone()
conn.commit(); cur.close()
update_metrics(uid)
return jsonify(dict(prop))
except Exception as e:
return jsonify({‘error’: str(e)}), 500

@app.route(’/api/property/<int:pid>’, methods=[‘DELETE’])
def delete_property(pid):
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
with get_db() as conn:
cur = conn.cursor()
cur.execute(“DELETE FROM properties WHERE id=%s AND user_id=%s”, (pid, uid))
conn.commit(); cur.close()
update_metrics(uid)
return jsonify({‘ok’: True})

@app.route(’/api/properties/refresh-values’, methods=[‘POST’])
def refresh_property_values():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
if not ATTOM_API_KEY: return jsonify({‘refreshed’: 0, ‘message’: ‘No ATTOM key’})
import re
from datetime import datetime, timedelta
refreshed = 0
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM properties WHERE user_id=%s”, (uid,))
props = cur.fetchall()
for p in props:
last = p.get(‘last_value_refresh’)
if last and (datetime.now() - last) < timedelta(days=7): continue
addr = (p.get(‘location’) or ‘’).split(’,’)[0].strip()
if not addr: continue
try:
url = f”https://api.gateway.attomdata.com/propertyapi/v1.0.0/property/expandedprofile?address1={urllib.parse.quote(addr)}”
req = urllib.request.Request(url, headers={‘apikey’: ATTOM_API_KEY, ‘Accept’: ‘application/json’})
resp = urllib.request.urlopen(req, timeout=8)
data = json.loads(resp.read())
prop_data = (data.get(‘property’) or [{}])[0]
avm = prop_data.get(‘avm’, {})
val = (avm.get(‘amount’) or {}).get(‘value’) or avm.get(‘value’)
if val:
tax_data = prop_data.get(‘assessment’, {}).get(‘tax’, {})
tax = tax_data.get(‘taxAmt’) or tax_data.get(‘taxamt’) or 0
monthly_tax = round(float(tax)/12) if tax else None
updates = {‘zestimate’: val, ‘last_value_refresh’: datetime.now()}
if monthly_tax: updates[‘property_tax’] = monthly_tax
set_clause = ’, ’.join(f”{k}=%s” for k in updates)
cur.execute(f”UPDATE properties SET {set_clause} WHERE id=%s”, list(updates.values()) + [p[‘id’]])
refreshed += 1
except: pass
conn.commit(); cur.close()
update_metrics(uid)
return jsonify({‘refreshed’: refreshed})

@app.route(’/api/property/lookup’)
def lookup_property():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
address = request.args.get(‘address’, ‘’)
if not ATTOM_API_KEY:
return jsonify({‘source’: ‘manual’, ‘message’: ‘No ATTOM key configured’})
try:
url = f”https://api.gateway.attomdata.com/propertyapi/v1.0.0/property/expandedprofile?address1={urllib.parse.quote(address)}”
req = urllib.request.Request(url, headers={‘apikey’: ATTOM_API_KEY, ‘Accept’: ‘application/json’})
resp = urllib.request.urlopen(req, timeout=8)
data = json.loads(resp.read())
prop_data = (data.get(‘property’) or [{}])[0]
avm = prop_data.get(‘avm’, {})
val = (avm.get(‘amount’) or {}).get(‘value’) or avm.get(‘value’)
tax_data = prop_data.get(‘assessment’, {}).get(‘tax’, {})
tax = tax_data.get(‘taxAmt’) or tax_data.get(‘taxamt’) or 0
bldg = prop_data.get(‘building’, {})
rooms = bldg.get(‘rooms’, {})
size = bldg.get(‘size’, {})
summary = prop_data.get(‘summary’, {})
return jsonify({
‘source’: ‘ATTOM’,
‘estimated_value’: val,
‘annual_tax’: float(tax) if tax else None,
‘monthly_tax’: round(float(tax)/12) if tax else None,
‘bedrooms’: rooms.get(‘beds’) or summary.get(‘bedsNum’),
‘bathrooms’: rooms.get(‘bathsFull’) or summary.get(‘bathsNum’),
‘sqft’: size.get(‘livingSize’) or size.get(‘bldgSize’),
‘year_built’: (prop_data.get(‘summary’) or {}).get(‘yearBuilt’),
‘property_type’: summary.get(‘propClass’),
})
except Exception as e:
return jsonify({‘source’: ‘manual’, ‘error’: str(e)})

@app.route(’/api/debug/attom’)
def debug_attom():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
address = request.args.get(‘address’, ‘102 S Lockwood Drive Houston TX’)
key = ATTOM_API_KEY
result = {‘key_set’: bool(key), ‘key_preview’: key[:8]+’…’ if key else None}
if key:
try:
url = f”https://api.gateway.attomdata.com/propertyapi/v1.0.0/property/expandedprofile?address1={urllib.parse.quote(address)}”
req = urllib.request.Request(url, headers={‘apikey’: key, ‘Accept’: ‘application/json’})
resp = urllib.request.urlopen(req, timeout=8)
data = json.loads(resp.read())
result[‘status’] = ‘ok’
result[‘raw’] = data
except Exception as e:
result[‘error’] = str(e)
return jsonify(result)

# ── ZILLOW SCRAPER ────────────────────────────────────────────────────────────

@app.route(’/api/zillow/zestimate’, methods=[‘POST’])
def scrape_zestimate():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
url = (request.json or {}).get(‘url’, ‘’).strip()
if not url: return jsonify({‘error’: ‘URL required’}), 400
if ‘zillow.com’ not in url: return jsonify({‘error’: ‘Must be a Zillow URL’}), 400
try:
import re, gzip as gz
headers = {
‘User-Agent’: ‘Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1’,
‘Accept’: ‘text/html,application/xhtml+xml’,
‘Accept-Language’: ‘en-US,en;q=0.9’,
‘Accept-Encoding’: ‘gzip, deflate’,
}
req = urllib.request.Request(url, headers=headers)
resp = urllib.request.urlopen(req, timeout=10)
raw = resp.read()
try: html = gz.decompress(raw).decode(‘utf-8’, errors=‘ignore’)
except: html = raw.decode(‘utf-8’, errors=‘ignore’)
result = {‘url’: url, ‘zestimate’: None, ‘address’: None}
for pat in [r’“zestimate”\s*:\s*{“value”\s*:\s*(\d+)’, r’“zestimate”:{“value”:(\d+)’, r’“homeValue”\s*:\s*(\d+)’, r’“price”\s*:\s*(\d{5,8})’]:
m = re.search(pat, html)
if m:
v = int(m.group(1))
if v > 50000: result[‘zestimate’] = v; break
for key, pats in [
(‘address’, [r’“streetAddress”\s*:\s*”([^”]+)”’]),
(‘bedrooms’, [r’“bedrooms”\s*:\s*(\d+)’]),
(‘bathrooms’, [r’“bathrooms”\s*:\s*([\d.]+)’]),
(‘sqft’, [r’“livingArea”\s*:\s*(\d+)’]),
(‘year_built’, [r’“yearBuilt”\s*:\s*(\d{4})’]),
(‘tax_annual’, [r’“taxAnnualAmount”\s*:\s*(\d+)’]),
]:
for pat in pats:
m = re.search(pat, html)
if m: result[key] = m.group(1); break
if result.get(‘tax_annual’):
result[‘monthly_tax’] = round(int(result[‘tax_annual’]) / 12)
if not result[‘zestimate’]:
result[‘error’] = “Could not find Zestimate. Make sure it is a property listing URL (zillow.com/homedetails/…).”
return jsonify(result)
except Exception as e:
return jsonify({‘error’: str(e), ‘zestimate’: None})

# ── STOCKS ────────────────────────────────────────────────────────────────────

@app.route(’/api/stocks/quote’)
def stock_quote():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
ticker = request.args.get(‘ticker’, ‘’).upper()
if not ticker: return jsonify({‘error’: ‘Ticker required’}), 400
try:
url = f’https://query1.finance.yahoo.com/v8/finance/chart/{ticker}?interval=1d&range=1d’
req = urllib.request.Request(url, headers={‘User-Agent’: ‘Mozilla/5.0’, ‘Accept’: ‘application/json’})
resp = urllib.request.urlopen(req, timeout=6)
data = json.loads(resp.read())
meta = data.get(‘chart’, {}).get(‘result’, [{}])[0].get(‘meta’, {})
price = meta.get(‘regularMarketPrice’) or meta.get(‘previousClose’)
prev = meta.get(‘previousClose’, price)
change = ((price - prev) / prev * 100) if prev else 0
return jsonify({‘ticker’: ticker, ‘price’: price, ‘change_pct’: change})
except Exception as e:
return jsonify({‘error’: str(e), ‘price’: None})

# ── PLAID ─────────────────────────────────────────────────────────────────────

@app.route(’/api/plaid/create-link-token’)
def plaid_link():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
if not PLAID_CLIENT_ID: return jsonify({‘error’: ‘Plaid not configured’}), 400
try:
plaid_url = f”https://{PLAID_ENV}.plaid.com/link/token/create”
payload = json.dumps({
“client_id”: PLAID_CLIENT_ID, “secret”: PLAID_SECRET,
“user”: {“client_user_id”: str(uid)},
“client_name”: “Property Pigeon”,
“products”: [“transactions”],
“country_codes”: [“US”],
“language”: “en”
}).encode()
req = urllib.request.Request(plaid_url, data=payload, headers={‘Content-Type’: ‘application/json’})
resp = urllib.request.urlopen(req, timeout=10)
data = json.loads(resp.read())
return jsonify({‘link_token’: data.get(‘link_token’)})
except Exception as e:
return jsonify({‘error’: str(e)}), 500

@app.route(’/api/plaid/exchange-token’, methods=[‘POST’])
def plaid_exchange():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
d = request.json
try:
plaid_url = f”https://{PLAID_ENV}.plaid.com/item/public_token/exchange”
payload = json.dumps({“client_id”: PLAID_CLIENT_ID, “secret”: PLAID_SECRET, “public_token”: d[‘public_token’]}).encode()
req = urllib.request.Request(plaid_url, data=payload, headers={‘Content-Type’: ‘application/json’})
resp = urllib.request.urlopen(req, timeout=10)
data = json.loads(resp.read())
access_token = data.get(‘access_token’)
item_id = data.get(‘item_id’)
with get_db() as conn:
cur = conn.cursor()
cur.execute(“INSERT INTO plaid_items (user_id,access_token,item_id,institution_name) VALUES (%s,%s,%s,%s)”,
(uid, access_token, item_id, d.get(‘institution_name’, ‘Bank’)))
conn.commit(); cur.close()
return jsonify({‘ok’: True})
except Exception as e:
return jsonify({‘error’: str(e)}), 500

@app.route(’/api/plaid/transactions’)
def plaid_transactions():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM plaid_items WHERE user_id=%s ORDER BY created_at DESC LIMIT 1”, (uid,))
item = cur.fetchone(); cur.close()
if not item: return jsonify({‘transactions’: [], ‘accounts’: []})
try:
plaid_url = f”https://{PLAID_ENV}.plaid.com/transactions/get”
payload = json.dumps({
“client_id”: PLAID_CLIENT_ID, “secret”: PLAID_SECRET,
“access_token”: item[‘access_token’],
“start_date”: “2024-01-01”, “end_date”: time.strftime(’%Y-%m-%d’),
“options”: {“count”: 100}
}).encode()
req = urllib.request.Request(plaid_url, data=payload, headers={‘Content-Type’: ‘application/json’})
resp = urllib.request.urlopen(req, timeout=10)
data = json.loads(resp.read())
return jsonify({‘transactions’: data.get(‘transactions’, []), ‘accounts’: data.get(‘accounts’, [])})
except Exception as e:
return jsonify({‘error’: str(e)}), 500

# ── PERFORMANCE ───────────────────────────────────────────────────────────────

@app.route(’/api/performance/portfolio/<int:uid>’)
def get_portfolio_performance(uid):
req_uid = session.get(‘user_id’)
if not req_uid: return jsonify({‘error’: ‘Not authenticated’}), 401
months = int(request.args.get(‘months’, 24))
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT * FROM monthly_snapshots WHERE user_id=%s ORDER BY snapshot_month ASC LIMIT %s”, (uid, months))
snaps = [dict(r) for r in cur.fetchall()]; cur.close()
for i, s in enumerate(snaps):
prev = snaps[i-1] if i > 0 else None
s[‘mom_value’] = float(s[‘total_value’]) - float(prev[‘total_value’]) if prev else 0
s[‘mom_cashflow’] = float(s[‘net_cashflow’]) - float(prev[‘net_cashflow’]) if prev else 0
s[‘mom_equity’] = float(s[‘total_equity’]) - float(prev[‘total_equity’]) if prev else 0
yoy = next((x for x in snaps if x[‘snapshot_month’].year == s[‘snapshot_month’].year-1 and x[‘snapshot_month’].month == s[‘snapshot_month’].month), None)
s[‘yoy_value’] = float(s[‘total_value’]) - float(yoy[‘total_value’]) if yoy else None
s[‘yoy_value_pct’] = ((float(s[‘total_value’])-float(yoy[‘total_value’]))/float(yoy[‘total_value’])*100) if yoy and float(yoy[‘total_value’])>0 else None
s[‘snapshot_month’] = s[‘snapshot_month’].isoformat()
summary = {}
if snaps:
latest = snaps[-1]; oldest = snaps[0]
summary = {
‘total_appreciation’: float(latest[‘total_value’]) - float(oldest[‘total_value’]),
‘total_cashflow_earned’: sum(float(s[‘net_cashflow’]) for s in snaps),
‘months_tracked’: len(snaps),
}
summary[‘total_return’] = summary[‘total_appreciation’] + summary[‘total_cashflow_earned’]
return jsonify({‘snapshots’: snaps, ‘summary’: summary})

@app.route(’/api/performance/snapshot’, methods=[‘POST’])
def take_snapshot():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
record_monthly_snapshot(uid)
return jsonify({‘success’: True})

# ── USER SETTINGS ─────────────────────────────────────────────────────────────

@app.route(’/api/user/settings’, methods=[‘PUT’])
def update_settings():
uid = session.get(‘user_id’)
if not uid: return jsonify({‘error’: ‘Not authenticated’}), 401
d = request.json
fields = []
vals = []
for k in [‘display_name’, ‘bio’, ‘avatar_color’, ‘is_public’]:
if k in d: fields.append(f”{k}=%s”); vals.append(d[k])
if not fields: return jsonify({‘ok’: True})
with get_db() as conn:
cur = conn.cursor()
cur.execute(f”UPDATE users SET {’,’.join(fields)} WHERE id=%s”, vals + [uid])
conn.commit(); cur.close()
return jsonify({‘ok’: True})

# ── FRONTEND ──────────────────────────────────────────────────────────────────

HTML = r”””

<!DOCTYPE html>

<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Property Pigeon</title>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
<style>
:root {
  --blue:#1a56db; --blue-dark:#1e40af; --green:#059669; --red:#d92d20;
  --white:#fff; --gray-50:#f9fafb; --gray-100:#f3f4f6; --gray-200:#e5e7eb;
  --gray-300:#d1d5db; --gray-400:#9ca3af; --gray-500:#6b7280; --gray-700:#374151; --gray-900:#111827;
  --glass-bg:rgba(255,255,255,0.72); --glass-border:rgba(255,255,255,0.85);
  --glass-shadow:0 8px 32px rgba(31,38,135,0.12),0 2px 8px rgba(31,38,135,0.08);
  --blur:blur(20px) saturate(180%); --blur-heavy:blur(32px) saturate(200%);
  --app-bg:linear-gradient(135deg,#e8f0fe 0%,#f0f4ff 30%,#e8f5f0 60%,#f5f0ff 100%);
}
*,*::before,*::after{box-sizing:border-box;-webkit-tap-highlight-color:transparent;}
body{margin:0;padding:0;font-family:'DM Sans',sans-serif;background:var(--app-bg);color:var(--gray-900);height:100vh;overflow:hidden;}
.shell{display:flex;height:100vh;overflow:hidden;}
.sidebar{width:220px;background:var(--glass-bg);backdrop-filter:var(--blur-heavy);-webkit-backdrop-filter:var(--blur-heavy);border-right:1px solid var(--glass-border);display:flex;flex-direction:column;height:100vh;overflow:hidden;box-shadow:1px 0 0 rgba(255,255,255,0.6);}
.sidebar-logo{padding:20px 18px 14px;font-size:15px;font-weight:800;display:flex;align-items:center;gap:8px;border-bottom:1px solid rgba(255,255,255,0.5);letter-spacing:-.3px;}
.nav{flex:1;padding:10px 8px;overflow-y:auto;}
.ni{display:flex;align-items:center;gap:10px;padding:9px 12px;border-radius:12px;font-size:13px;font-weight:500;color:var(--gray-500);cursor:pointer;margin-bottom:2px;transition:all .18s cubic-bezier(.34,1.56,.64,1);}
.ni svg{width:17px;height:17px;flex-shrink:0;}
.ni:hover{background:rgba(255,255,255,0.75);color:#111;transform:translateX(3px);box-shadow:0 2px 8px rgba(0,0,0,.06);}
.ni:active{transform:translateX(3px) scale(.96);}
.ni.active{background:rgba(26,86,219,0.1);color:var(--blue);font-weight:600;box-shadow:inset 0 0 0 1px rgba(26,86,219,0.2);}
.ni.active svg{stroke:var(--blue);}
.main{flex:1;display:flex;flex-direction:column;overflow:hidden;}
.topbar{height:54px;background:rgba(255,255,255,0.6);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border-bottom:1px solid rgba(255,255,255,0.7);display:flex;align-items:center;padding:0 22px;gap:12px;flex-shrink:0;}
.tab-content{flex:1;overflow-y:auto;padding:22px;animation:fadeInUp .18s ease;}
.sfooter{padding:10px 8px;border-top:1px solid rgba(255,255,255,0.5);}
.uchip{display:flex;align-items:center;gap:8px;padding:8px 12px;border-radius:12px;cursor:pointer;transition:all .15s;}
.uchip:hover{background:rgba(255,255,255,0.7);box-shadow:0 2px 8px rgba(0,0,0,.06);}
.avatar{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0;}
.uname{font-size:13px;font-weight:600;color:var(--gray-900);}
.uhandle{font-size:11px;color:var(--gray-400);}
.card{background:var(--glass-bg);backdrop-filter:var(--blur);-webkit-backdrop-filter:var(--blur);border:1px solid var(--glass-border);border-radius:16px;padding:20px;margin-bottom:16px;box-shadow:var(--glass-shadow);}
.prow{display:flex;align-items:center;gap:14px;padding:13px 15px;border-radius:14px;margin-bottom:6px;background:rgba(255,255,255,0.6);border:1px solid rgba(255,255,255,0.7);transition:all .2s cubic-bezier(.34,1.56,.64,1);cursor:pointer;}
.prow:hover{background:rgba(255,255,255,0.9)!important;transform:translateY(-2px)!important;box-shadow:0 8px 24px rgba(26,86,219,.1)!important;border-color:rgba(26,86,219,.15)!important;}
.prow:active{transform:translateY(0) scale(.99)!important;}
.statgrid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px;}
.stat{background:rgba(255,255,255,0.7);backdrop-filter:blur(16px);-webkit-backdrop-filter:blur(16px);border:1px solid rgba(255,255,255,0.8);border-radius:14px;padding:16px;box-shadow:0 4px 16px rgba(0,0,0,.05);transition:all .2s ease;}
.stat:hover{transform:translateY(-2px);box-shadow:0 8px 24px rgba(0,0,0,.1);}
.stat-label{font-size:11px;font-weight:700;color:var(--gray-400);text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;}
.stat-val{font-size:22px;font-weight:800;color:var(--gray-900);letter-spacing:-.5px;}
.overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(15,20,50,.35);backdrop-filter:blur(8px);-webkit-backdrop-filter:blur(8px);z-index:200;display:flex;align-items:center;justify-content:center;padding:20px;animation:fadeIn .18s ease;}
.modal{background:rgba(255,255,255,0.9);backdrop-filter:blur(40px) saturate(200%);-webkit-backdrop-filter:blur(40px) saturate(200%);border:1px solid rgba(255,255,255,0.95);border-radius:24px;width:100%;max-width:560px;max-height:90vh;overflow-y:auto;padding:26px 24px;box-shadow:0 32px 80px rgba(0,0,0,.18),inset 0 1px 0 rgba(255,255,255,0.9);animation:slideUp .22s cubic-bezier(.34,1.56,.64,1);}
.mtitle{font-size:18px;font-weight:800;color:var(--gray-900);margin-bottom:18px;letter-spacing:-.3px;}
.field{margin-bottom:14px;}
.field label{display:block;font-size:11px;font-weight:700;color:var(--gray-500);text-transform:uppercase;letter-spacing:.5px;margin-bottom:5px;}
.field input,.field select{width:100%;padding:9px 11px;border:1.5px solid var(--gray-200);border-radius:9px;font-size:13px;font-family:inherit;background:rgba(255,255,255,0.8);transition:border-color .15s,box-shadow .15s;}
.field input:focus,.field select:focus{outline:none;border-color:var(--blue);box-shadow:0 0 0 3px rgba(26,86,219,.12);}
.field-row{display:grid;grid-template-columns:1fr 1fr;gap:10px;}
.btn{padding:9px 18px;border-radius:10px;font-size:13px;font-weight:700;cursor:pointer;border:none;transition:all .15s cubic-bezier(.34,1.56,.64,1);font-family:inherit;}
.btn:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 6px 16px rgba(0,0,0,.15);filter:brightness(1.06);}
.btn:active:not(:disabled){transform:scale(.96)!important;box-shadow:none!important;}
.btn:disabled{opacity:.45;cursor:not-allowed;}
.btn-primary{background:var(--blue);color:#fff;}
.btn-secondary{background:var(--gray-100);color:var(--gray-700);}
.btn-danger{background:#fee2e2;color:var(--red);}
.err-box{background:#fef2f2;border:1px solid #fecaca;color:var(--red);padding:9px 12px;border-radius:8px;font-size:13px;margin-bottom:12px;}
.zprop-card{background:rgba(16,185,129,.06);border:1px solid rgba(16,185,129,.2);border-radius:10px;padding:12px 14px;margin-bottom:12px;}
.zprop-row{display:flex;justify-content:space-between;padding:2px 0;}
.zprop-label{font-size:12px;color:var(--gray-500);}
.zprop-val{font-size:12px;font-weight:700;color:var(--gray-900);}
.zsuggest{background:rgba(255,255,255,0.95);backdrop-filter:blur(12px);border:1px solid rgba(255,255,255,0.9);border-radius:10px;box-shadow:0 8px 24px rgba(0,0,0,.1);overflow:hidden;}
.zitem{padding:9px 12px;cursor:pointer;border-bottom:1px solid var(--gray-100);transition:background .1s;}
.zitem:hover{background:rgba(26,86,219,.04);}
.zitem:last-child{border-bottom:none;}
.warn-box{background:#fffbeb;border:1px solid #fde68a;color:#92400e;padding:9px 12px;border-radius:8px;font-size:12px;margin-bottom:12px;}
button{transition:all .15s cubic-bezier(.34,1.56,.64,1);font-family:inherit;}
button:hover:not(:disabled){transform:translateY(-2px);box-shadow:0 6px 16px rgba(0,0,0,.12);filter:brightness(1.06);}
button:active:not(:disabled){transform:scale(.96)!important;box-shadow:none!important;transition-duration:.06s;}
button:disabled{opacity:.45;cursor:not-allowed;transform:none!important;}
input:not([type=range]):focus,select:focus{outline:none;border-color:var(--blue)!important;box-shadow:0 0 0 3px rgba(26,86,219,.12)!important;}
.kpi-card{transition:transform .2s cubic-bezier(.34,1.56,.64,1),box-shadow .2s ease;cursor:default;}
.kpi-card:hover{transform:translateY(-3px);box-shadow:0 10px 28px rgba(0,0,0,.1);}
tbody tr{transition:background .1s;}
tbody tr:hover td{background:rgba(26,86,219,.03);}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes slideUp{from{opacity:0;transform:translateY(24px) scale(.96)}to{opacity:1;transform:translateY(0) scale(1)}}
@keyframes fadeInUp{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}
@keyframes shimmer{0%{background-position:200% 0}100%{background-position:-200% 0}}
.skel{background:linear-gradient(90deg,#f3f4f6 25%,#e5e7eb 50%,#f3f4f6 75%);background-size:200% 100%;animation:shimmer 1.4s infinite;border-radius:6px;}
input[type=range]{cursor:pointer;width:100%;}

/* ══ INTERACTIVITY ══════════════════════════════════════════════════════════ */

- { -webkit-tap-highlight-color: transparent; box-sizing: border-box; }

/* Tab entry animation */
.tab-content { animation: tabIn .22s cubic-bezier(.4,0,.2,1); }
@keyframes tabIn { from { opacity:0; transform:translateY(10px); } to { opacity:1; transform:translateY(0); } }

/* All buttons - lift on hover */
button:not(:disabled) { transition: all .15s cubic-bezier(.4,0,.2,1) !important; cursor: pointer; }
button:hover:not(:disabled) { transform: translateY(-1px); box-shadow: 0 4px 14px rgba(0,0,0,.12) !important; filter: brightness(1.06); }
button:active:not(:disabled) { transform: scale(.96) translateY(0) !important; box-shadow: none !important; }
button:disabled { opacity: .5; cursor: not-allowed; }

/* Nav items - slide + glow */
.ni { transition: all .18s cubic-bezier(.34,1.56,.64,1) !important; }
.ni:hover { background: rgba(255,255,255,0.75) !important; transform: translateX(4px) !important; box-shadow: 0 2px 12px rgba(0,0,0,.08) !important; color: var(–gray-900) !important; }
.ni:active { transform: translateX(4px) scale(.97) !important; }

/* Property rows - lift */
.prow { transition: all .18s cubic-bezier(.34,1.56,.64,1) !important; }

/* All inputs - glow focus */
input, select, textarea { transition: border-color .15s, box-shadow .15s !important; outline: none !important; }
input:focus, select:focus, textarea:focus { border-color: var(–blue) !important; box-shadow: 0 0 0 3px rgba(26,86,219,.12) !important; }

/* Table rows - subtle hover */
tbody tr { transition: background .1s; }
tbody tr:hover td { background: rgba(26,86,219,.025) !important; }

/* Range sliders */
input[type=range] { accent-color: var(–blue); cursor: pointer; }
input[type=range]:hover { accent-color: #0a3fa0; }

/* KPI cards hover */
[class*=“kpi”], div[style*=“kpi”] { cursor: default; }

/* Modal fade + scale in */
.overlay { animation: fadeOverlay .18s ease; }
@keyframes fadeOverlay { from { opacity:0; } to { opacity:1; } }
.modal { animation: modalIn .22s cubic-bezier(.34,1.56,.64,1); }
@keyframes modalIn { from { opacity:0; transform: scale(.94) translateY(16px); } to { opacity:1; transform: scale(1) translateY(0); } }

/* Skeleton shimmer */
.skel { background: linear-gradient(90deg, rgba(255,255,255,.4) 25%, rgba(255,255,255,.7) 50%, rgba(255,255,255,.4) 75%); background-size:200% 100%; animation: shimmer 1.5s infinite; }
@keyframes shimmer { 0%{background-position:200% 0} 100%{background-position:-200% 0} }

/* Pulse for action items */
.pulse { animation: pulse 2.5s infinite; }
@keyframes pulse { 0%,100%{box-shadow:0 0 0 0 rgba(26,86,219,.2)} 50%{box-shadow:0 0 0 8px rgba(26,86,219,0)} }

</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const {useState,useEffect,useRef,useCallback}=React;

// ── UTILS ────────────────────────────────────────────────────────────────────
const initials=n=>(n||’’).split(’ ‘).map(w=>w[0]).join(’’).slice(0,2).toUpperCase()||’?’;
const fmt$=n=>n==null?’$0’:’$’+Math.round(n).toLocaleString();
const fmtK=n=>n==null?’$0K’:’$’+Math.round(n/1000)+‘K’;
const ago=ts=>{const h=Math.floor((Date.now()-new Date(ts).getTime())/3600000);return h<1?‘Just now’:h<24?h+‘h ago’:Math.floor(h/24)+‘d ago’;};

const ACCENT_COLORS=[
{val:’#1a56db’,name:‘Blue’},
{val:’#0f766e’,name:‘Teal’},
{val:’#7c3aed’,name:‘Purple’},
{val:’#be185d’,name:‘Pink’},
{val:’#b45309’,name:‘Amber’},
{val:’#0369a1’,name:‘Sky’},
{val:’#1d4ed8’,name:‘Indigo’},
{val:’#047857’,name:‘Emerald’},
];

// ── APP ROOT ─────────────────────────────────────────────────────────────────
function App() {
const [auth,setAuth]=useState(false);
const [user,setUser]=useState(null);
const [loading,setLoading]=useState(true);

useEffect(()=>{
fetch(’/api/auth/me’,{credentials:‘include’})
.then(r=>r.ok?r.json():null)
.then(u=>{if(u&&u.id){setUser(u);setAuth(true);}})
.catch(()=>{}).finally(()=>setLoading(false));
},[]);

const accent=user?.accent_color||’#1a56db’;

useEffect(()=>{
document.documentElement.style.setProperty(’–blue’, accent);
},[accent]);

if(loading) return <div style={{display:‘flex’,alignItems:‘center’,justifyContent:‘center’,height:‘100vh’,color:’#9ca3af’,fontSize:13}}>Loading…</div>;
if(!auth) return <AuthScreen accent={accent} onLogin={u=>{setUser(u);setAuth(true);}}/>;
return <MainApp user={user} setUser={setUser} onLogout={()=>{setAuth(false);setUser(null);}}/>;
}

// ── AUTH SCREEN ───────────────────────────────────────────────────────────────
function AuthScreen({onLogin,accent=’#1a56db’}) {
const [mode,setMode]=useState(‘login’);
const [err,setErr]=useState(’’);
const [f,setF]=useState({username:’’,email:’’,password:’’,full_name:’’,portfolio_name:’’,ticker:’’});
const [tickerStatus,setTickerStatus]=useState(’’);

useEffect(()=>{
if(f.ticker.length!==4){setTickerStatus(’’);return;}
const t=setTimeout(async()=>{
try{const r=await fetch(’/api/ticker/check/’+f.ticker);const d=await r.json();setTickerStatus(d.available?‘available’:‘taken’);}catch(e){}
},400);
return()=>clearTimeout(t);
},[f.ticker]);

const submit=async e=>{
e.preventDefault();setErr(’’);
try{
const r=await fetch(mode===‘login’?’/api/auth/login’:’/api/auth/signup’,{method:‘POST’,headers:{‘Content-Type’:‘application/json’},credentials:‘include’,body:JSON.stringify(f)});
const d=await r.json();
if(r.ok) onLogin(d.user); else setErr(d.error||‘Something went wrong’);
}catch(e){setErr(‘Network error’);}
};

return(
<div className="auth-wrap">
<div className="auth-left" style={{background:accent}}>
<div>
<div style={{fontSize:36,marginBottom:12}}>🐦</div>
<h1>Property Pigeon</h1>
<p>The social investment network for real estate investors. Track your portfolio, discover top performers, connect with the community.</p>
</div>
</div>
<div className="auth-right">
<div className="auth-form">
<div className="auth-logo">Property Pigeon</div>
<h2 className="auth-title">{mode===‘login’?‘Welcome back’:‘Create account’}</h2>
<p className="auth-sub">{mode===‘login’?‘Sign in to your account’:‘Join thousands of real estate investors’}</p>
{err&&<div className="err-box">{err}</div>}
<form onSubmit={submit}>
{mode===‘signup’&&<>
<div className="auth-field"><label>Full name</label><input value={f.full_name} onChange={e=>setF({…f,full_name:e.target.value})} placeholder=“Brandon Bonomo” required/></div>
<div className="auth-field"><label>Portfolio name</label><input value={f.portfolio_name} onChange={e=>setF({…f,portfolio_name:e.target.value})} placeholder=“Brandon’s Empire” required/></div>
<div className="auth-field">
<label>Ticker symbol <span style={{color:’#9ca3af’,fontWeight:400,textTransform:‘none’}}>(4 letters — your public ID)</span></label>
<input className=“mono-input” value={f.ticker} onChange={e=>setF({…f,ticker:e.target.value.toUpperCase().replace(/[^A-Z]/g,’’).slice(0,4)})} placeholder=“BEMP” maxLength={4}/>
{f.ticker.length===4&&<div className={‘ticker-avail ‘+(tickerStatus===‘available’?‘yes’:‘no’)}>{tickerStatus===‘available’?‘✓ Available’:‘✗ Already taken — try another’}</div>}
</div>
</>}
<div className="auth-field"><label>{mode===‘login’?‘Username or email’:‘Username’}</label><input value={f.username} onChange={e=>setF({…f,username:e.target.value})} placeholder=“brandonb” required/></div>
{mode===‘signup’&&<div className="auth-field"><label>Email</label><input type=“email” value={f.email} onChange={e=>setF({…f,email:e.target.value})} required/></div>}
<div className="auth-field"><label>Password</label><input type=“password” value={f.password} onChange={e=>setF({…f,password:e.target.value})} required/></div>
<button type="submit" className="auth-btn-primary">{mode===‘login’?‘Sign in’:‘Create account’}</button>
<button type=“button” className=“auth-btn-ghost” onClick={()=>{setMode(mode===‘login’?‘signup’:‘login’);setErr(’’);}}>{mode===‘login’?‘New here? Create an account’:‘Have an account? Sign in’}</button>
</form>
</div>
</div>
</div>
);
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────
function MainApp({user,setUser,onLogout}) {
const [tab,setTab]=useState(‘portfolio’);
const [portfolio,setPortfolio]=useState(null);
const [users,setUsers]=useState([]);
const [following,setFollowing]=useState(new Set());
const [feed,setFeed]=useState([]);
const [properties,setProperties]=useState([]);
const [showAddProp,setShowAddProp]=useState(false);
const [showPlaid,setShowPlaid]=useState(false);
const [showSettings,setShowSettings]=useState(false);
const [stockPortfolioValue,setStockPortfolioValue]=useState(0);

const accent=user?.accent_color||’#1a56db’;

useEffect(()=>{
document.documentElement.style.setProperty(’–blue’,accent);
},[accent]);

useEffect(()=>{loadAll();},[]);

const loadAll=async()=>{
try{
const [pR,uR,fR,fdR,prR]=await Promise.all([
fetch(’/api/portfolio/’+user.id,{credentials:‘include’}),
fetch(’/api/users/discover’,{credentials:‘include’}),
fetch(’/api/following’,{credentials:‘include’}),
fetch(’/api/feed’,{credentials:‘include’}),
fetch(’/api/properties/’+user.id,{credentials:‘include’})
]);
const [p,u,f,fd,pr]=await Promise.all([pR.json(),uR.json(),fR.json(),fdR.json(),prR.json()]);
setPortfolio(p);setUsers(u);
setFollowing(new Set(f.map(x=>x.following_id)));
setFeed(fd);setProperties(pr);
}catch(e){console.error(e);}
};

const logout=async()=>{await fetch(’/api/auth/logout’,{method:‘POST’,credentials:‘include’});onLogout();};

const navItems=[
{id:‘portfolio’,label:‘Portfolio’,path:‘M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6’},
{id:‘cashflow’,label:‘Cash flow’,path:‘M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z’},
{id:‘performance’,label:‘Performance’,path:‘M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z’},
{id:‘projections’,label:‘Projections’,path:‘M13 7h8m0 0v8m0-8l-8 8-4-4-6 6’},
{id:‘networth’,label:‘Net Worth’,path:‘M12 8c-1.657 0-3 .895-3 2s1.343 2 3 2 3 .895 3 2-1.343 2-3 2m0-8c1.11 0 2.08.402 2.599 1M12 8V7m0 1v9m0-9V7’},
{id:‘stocks’,label:‘Stocks’,path:‘M16 8v8m-4-5v5m-4-2v2m-2 4h12a2 2 0 002-2V6a2 2 0 00-2-2H6a2 2 0 00-2 2v12a2 2 0 002 2z’},
{id:‘discover’,label:‘Discover’,path:‘M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z’},
{id:‘feed’,label:‘Feed’,path:‘M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z’},
{id:‘profile’,label:‘Profile’,path:‘M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z’},
];

return(
<div className="shell">
<div className="sidebar">
<div className="sidebar-logo" style={{color:accent}}>
<span>🐦</span> Property Pigeon
</div>
<div className="nav">
{navItems.map(n=>(
<div key={n.id} className={‘ni’+(tab===n.id?’ active’:’’)} onClick={()=>setTab(n.id)}>
<svg fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d={n.path}/></svg>
{n.label}
</div>
))}
</div>
<div className="sfooter">
<div className=“uchip” onClick={()=>setShowSettings(true)}>
<div className="uav" style={{background:accent}}>{initials(user.full_name)}</div>
<div><div className="uname">{user.full_name}</div><div className="uhandle">@{user.username}</div></div>
</div>
<button className="signout-btn" onClick={logout}>Sign out</button>
</div>
</div>
<div className="content">
{tab===‘portfolio’&&<PortfolioTab portfolio={portfolio} properties={properties} accent={accent} onAddProp={()=>setShowAddProp(true)} onConnectBank={()=>setShowPlaid(true)} onRefresh={loadAll}/>}
{tab===‘cashflow’&&<CashflowTab portfolio={portfolio} properties={properties}/>}
{tab===‘performance’&&<PerformanceTab user={user} properties={properties} accent={accent}/>}
{tab===‘projections’&&<ProjectionsTab properties={properties} accent={accent}/>}
{tab===‘networth’&&<NetWorthTab properties={properties} accent={accent} stockValue={stockPortfolioValue}/>}
{tab===‘stocks’&&<StocksTab accent={accent} onValueChange={setStockPortfolioValue}/>}
{tab===‘discover’&&<DiscoverTab users={users} following={following} accent={accent} onRefresh={loadAll}/>}
{tab===‘feed’&&<FeedTab feed={feed}/>}
{tab===‘profile’&&<ProfileTab user={user} portfolio={portfolio} accent={accent} onEdit={()=>setShowSettings(true)}/>}
</div>
{showAddProp&&<AddPropModal userId={user.id} onClose={()=>setShowAddProp(false)} onSave={()=>{setShowAddProp(false);loadAll();}}/>}
{showPlaid&&<PlaidModal onClose={()=>setShowPlaid(false)}/>}
{showSettings&&<SettingsModal user={user} onClose={()=>setShowSettings(false)} onSave={u=>{setUser(u);setShowSettings(false);}}/>}
</div>
);
}

// ── PORTFOLIO TAB ─────────────────────────────────────────────────────────────
function PortfolioTab({portfolio,properties,accent,onAddProp,onConnectBank,onRefresh}) {
const chartRef=useRef(null);const ci=useRef(null);const [tf,setTf]=useState(‘3M’);
useEffect(()=>{
if(!chartRef.current)return;
if(ci.current)ci.current.destroy();
const pts=tf===‘1W’?7:tf===‘1M’?30:tf===‘YTD’?60:tf===‘1Y’?365:90;
const base=portfolio?parseFloat(portfolio.share_price)||1:1;
const data=Array.from({length:pts},(_,i)=>+(base*(1+(Math.random()*.04-.015)*(i+1))).toFixed(2));
ci.current=new Chart(chartRef.current.getContext(‘2d’),{
type:‘line’,
data:{labels:Array(pts).fill(’’),datasets:[{data,borderColor:accent,borderWidth:2,fill:true,backgroundColor:accent+‘15’,tension:0.4,pointRadius:0}]},
options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{display:false},y:{display:false}}}
});
return()=>{if(ci.current)ci.current.destroy();};
},[portfolio,tf,accent]);

if(!portfolio) return <div className="page"><div style={{color:’#9ca3af’,fontSize:13}}>Loading…</div></div>;
const hs=portfolio.health_score||0;
const tier=hs>=90?‘Elite’:hs>=75?‘Strong’:hs>=60?‘Good’:‘Growing’;
const tierColor=hs>=90?’#d97706’:hs>=75?’#059669’:hs>=60?accent:’#6b7280’;
const circ=2*Math.PI*32;

return(
<div className="page">
<div className="ph"><div className="pt">Your Portfolio</div><div className="ps">{portfolio.ticker?’$’+portfolio.ticker:’’} · Updated just now</div></div>
<div className="plaid-bar">
<div><h4>Connect bank accounts</h4><p>Auto-import rental income and mortgage payments via Plaid</p></div>
<button className="btn btn-blue btn-sm" onClick={onConnectBank}>Connect Bank</button>
</div>
<div className="hero">
<div className="hero-top">
<div>
<div className="clabel">Share Price</div>
<div className="bigval">${parseFloat(portfolio.share_price||0).toFixed(2)}</div>
<span className="badge-green">+12.68%</span>
{portfolio.ticker&&<div><span className="ticker-pill">${portfolio.ticker}</span></div>}
</div>
<div style={{textAlign:‘center’}}>
<div className="ring">
<svg width="76" height="76">
<circle cx="38" cy="38" r="32" fill="none" stroke="#f3f4f6" strokeWidth="6"/>
<circle cx=“38” cy=“38” r=“32” fill=“none” stroke={tierColor} strokeWidth=“6”
strokeDasharray={hs/100*circ+’ ‘+circ} strokeLinecap=“round” transform=“rotate(-90 38 38)”/>
</svg>
<div className="ring-num" style={{color:tierColor}}>{hs}</div>
</div>
<div className="ring-tier" style={{color:tierColor}}>{tier}</div>
</div>
</div>
<div className="chart-area"><canvas ref={chartRef}></canvas></div>
<div className="trow">{[‘1W’,‘1M’,‘YTD’,‘3M’,‘1Y’].map(t=><button key={t} className={‘tbtn’+(tf===t?’ active’:’’)} onClick={()=>setTf(t)}>{t}</button>)}</div>
</div>
<div className="g4" style={{marginBottom:14}}>
{[[‘Total Equity’,fmtK(portfolio.total_equity)],[‘Annual Cash Flow’,fmtK(portfolio.annual_cashflow)],[‘Properties’,portfolio.property_count||0],[‘Monthly Net’,fmt$(+(portfolio.annual_cashflow||0)/12)]].map(([l,v],i)=>(
<div key={i} className="statcard"><div className="statlabel">{l}</div><div className="statval">{v}</div></div>
))}
</div>
<div className="card">
<div style={{display:‘flex’,alignItems:‘center’,justifyContent:‘space-between’,marginBottom:14}}>
<span style={{fontSize:14,fontWeight:700}}>Properties ({(properties||[]).length})</span>
<button className="btn btn-blue btn-sm" onClick={onAddProp}>+ Add Property</button>
</div>
{!properties||properties.length===0?(
<div style={{textAlign:‘center’,padding:‘36px 20px’,color:’#9ca3af’}}>
<div style={{fontSize:14,fontWeight:600,color:’#374151’,marginBottom:6}}>No properties yet</div>
<div style={{fontSize:13,marginBottom:16}}>Add your first property via Zillow search</div>
<button className="btn btn-blue" onClick={onAddProp}>Add Property</button>
</div>
):(properties||[]).map(p=>(
<div key={p.id} className="prow">
<div className="picon"><svg width="18" height="18" fill="none" stroke="#6b7280" strokeWidth="1.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg></div>
<div style={{flex:1}}><div className="pname">{p.name}</div><div className="ploc">{p.location}</div></div>
<div>
{p.zestimate>0&&<div className="pzest">Zestimate: {fmt$(p.zestimate)}</div>}
<div className="pamount">{fmt$(p.purchase_price)}</div>
<div style={{fontSize:11,color:’#9ca3af’,textAlign:‘right’}}>{fmt$(p.monthly_revenue)}/mo revenue</div>
</div>
</div>
))}
</div>
</div>
);
}

// ── CASHFLOW TAB ──────────────────────────────────────────────────────────────
function CashflowTab({portfolio,properties}) {
const rev=parseFloat(portfolio?.annual_cashflow>0?(portfolio.annual_cashflow/12+((properties||[]).reduce((s,p)=>s+parseFloat(p.monthly_expenses||0),0))):0);
const exp=(properties||[]).reduce((s,p)=>s+parseFloat(p.monthly_expenses||0),0);
const net=rev-exp;
return(
<div className="page">
<div className="ph"><div className="pt">Cash Flow</div><div className="ps">Monthly breakdown</div></div>
<div className="g3" style={{marginBottom:14}}>
<div className="statcard"><div className="statlabel">Gross Income</div><div className=“statval” style={{color:’#059669’}}>{fmt$(rev)}</div></div>
<div className="statcard"><div className="statlabel">Total Expenses</div><div className=“statval” style={{color:’#d92d20’}}>{fmt$(exp)}</div></div>
<div className="statcard"><div className="statlabel">Net Cash Flow</div><div className="statval" style={{color:net>=0?’#059669’:’#d92d20’}}>{fmt$(net)}</div></div>
</div>
<div className="card">
<div style={{fontSize:14,fontWeight:700,marginBottom:14}}>Monthly Breakdown</div>
{[
{l:‘Rental / STR Income’,v:rev,pos:true},
{l:‘Mortgage Payments’,v:(properties||[]).reduce((s,p)=>s+parseFloat(p.mortgage||0),0),pos:false},
{l:‘Insurance’,v:(properties||[]).reduce((s,p)=>s+parseFloat(p.insurance||0),0),pos:false},
{l:‘HOA Fees’,v:(properties||[]).reduce((s,p)=>s+parseFloat(p.hoa||0),0),pos:false},
{l:‘Property Tax’,v:(properties||[]).reduce((s,p)=>s+parseFloat(p.property_tax||0),0),pos:false},
].map((row,i)=>(
<div key={i} className="cfrow">
<span className="cflabel">{row.l}</span>
<span className={‘cfval ‘+(row.pos?‘pos’:‘neg’)}>{row.pos?’+’:’-’}{fmt$(Math.abs(row.v))}</span>
</div>
))}
<div className=“cfrow” style={{borderTop:‘2px solid #e5e7eb’,marginTop:6,paddingTop:12}}>
<span style={{fontWeight:700,fontSize:14}}>Net</span>
<span className={‘cfval ‘+(net>=0?‘pos’:‘neg’)} style={{fontSize:16}}>{net>=0?’+’:’’}{fmt$(net)}</span>
</div>
</div>
</div>
);
}

// ── DISCOVER TAB ──────────────────────────────────────────────────────────────
function DiscoverTab({users,following,accent,onRefresh}) {
const [q,setQ]=useState(’’);
const follow=async id=>{await fetch(’/api/follow/’+id,{method:‘POST’,credentials:‘include’});onRefresh();};
const unfollow=async id=>{await fetch(’/api/unfollow/’+id,{method:‘POST’,credentials:‘include’});onRefresh();};
const filtered=(users||[]).filter(u=>!q||[u.full_name,u.username,u.portfolio_name,u.ticker].some(s=>(s||’’).toLowerCase().includes(q.toLowerCase())));
return(
<div className="page">
<div className="ph"><div className="pt">Discover Investors</div><div className="ps">Find and follow top performers</div></div>
<div className="swrap">
<svg className="sicon" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
<input className=“sinput” placeholder=“Search by name, username, ticker…” value={q} onChange={e=>setQ(e.target.value)}/>
</div>
{filtered.length===0?(
<div style={{textAlign:‘center’,padding:40,color:’#9ca3af’,fontSize:13}}>{q?`No results for "${q}"`:‘No other investors yet’}</div>
):filtered.map(u=>(
<div key={u.id} className="irow">
<div className="iav" style={{background:accent}}>{initials(u.full_name)}</div>
<div style={{flex:1}}>
<div className="iname">{u.full_name} <span className="iticker">${u.ticker}</span></div>
<div className="imeta">@{u.username} · {u.property_count} properties · Health {u.health_score}/100</div>
</div>
<div style={{textAlign:‘right’,marginRight:10}}>
<div style={{fontSize:13,fontWeight:700}}>${parseFloat(u.share_price||0).toFixed(2)}</div>
<div style={{fontSize:11,color:’#9ca3af’}}>{u.portfolio_name}</div>
</div>
<button className={‘follow-btn’+(following.has(u.id)?’ following’:’’)} onClick={()=>following.has(u.id)?unfollow(u.id):follow(u.id)}>
{following.has(u.id)?‘Following’:‘Follow’}
</button>
</div>
))}
</div>
);
}

// ── FEED TAB ──────────────────────────────────────────────────────────────────
function FeedTab({feed}) {
return(
<div className="page">
<div className="ph"><div className="pt">Activity Feed</div><div className="ps">Updates from investors you follow</div></div>
{!feed||feed.length===0?(
<div style={{textAlign:‘center’,padding:48,color:’#9ca3af’}}>
<div style={{fontSize:14,fontWeight:600,color:’#374151’,marginBottom:6}}>Nothing here yet</div>
<div style={{fontSize:13}}>Follow investors in Discover to see their activity</div>
</div>
):(feed||[]).map(item=>(
<div key={item.id} className="fitem">
<div className="fhdr">
<div className="fav">{initials(item.user_name)}</div>
<div><div className="fname">{item.user_name}</div><div className="ftime">{ago(item.created_at)}</div></div>
</div>
<div className="fbody">{item.content?.text}</div>
{item.content?.highlight&&<div className="fpill">{item.content.highlight}</div>}
</div>
))}
</div>
);
}

// ── PROFILE TAB ───────────────────────────────────────────────────────────────
function ProfileTab({user,portfolio,accent,onEdit}) {
return(
<div className="page">
<div className="ph">
<div style={{display:‘flex’,alignItems:‘center’,justifyContent:‘space-between’}}>
<div className="pt">Profile</div>
<button className="btn btn-outline btn-sm" onClick={onEdit}>Edit Profile & Settings</button>
</div>
</div>
<div className="pcard">
<div className="pav" style={{background:accent}}>{initials(user.full_name)}</div>
<div className="pname">{user.full_name}</div>
<div className="phandle">@{user.username}</div>
{portfolio?.ticker&&<div style={{marginBottom:10}}><span className="ticker-pill">${portfolio.ticker}</span></div>}
{user.bio&&<div className="pbio">{user.bio}</div>}
<div className="pstats">
<div><div className="pstatnum">{portfolio?.property_count||0}</div><div className="pstatlabel">Properties</div></div>
<div><div className="pstatnum">{portfolio?.health_score||0}</div><div className="pstatlabel">Health Score</div></div>
<div><div className="pstatnum">${parseFloat(portfolio?.share_price||0).toFixed(0)}</div><div className="pstatlabel">Share Price</div></div>
</div>
</div>
<div className="card">
{[[‘Portfolio Name’,user.portfolio_name],[‘Total Equity’,fmtK(portfolio?.total_equity)],[‘Annual Cash Flow’,fmtK(portfolio?.annual_cashflow)],[‘Location’,user.location||’—’],[‘Email’,user.email||’—’]].map(([l,v],i)=>(
<div key={i} className="cfrow"><span className="cflabel">{l}</span><span style={{fontWeight:600,fontSize:13}}>{v}</span></div>
))}
</div>
</div>
);
}

// ── SETTINGS MODAL ────────────────────────────────────────────────────────────
function SettingsModal({user,onClose,onSave}) {
const [f,setF]=useState({full_name:user.full_name||’’,username:user.username||’’,email:user.email||’’,portfolio_name:user.portfolio_name||’’,ticker:user.ticker||’’,bio:user.bio||’’,location:user.location||’’,accent_color:user.accent_color||’#1a56db’,current_password:’’,new_password:’’});
const [tickerStatus,setTickerStatus]=useState(’’);
const [usernameStatus,setUsernameStatus]=useState(’’);
const [err,setErr]=useState(’’);
const [success,setSuccess]=useState(’’);
const [saving,setSaving]=useState(false);

// Ticker check
useEffect(()=>{
if(!f.ticker||f.ticker===user.ticker){setTickerStatus(’’);return;}
if(f.ticker.length!==4){setTickerStatus(’’);return;}
const t=setTimeout(async()=>{
try{const r=await fetch(’/api/ticker/check/’+f.ticker);const d=await r.json();setTickerStatus(d.available?‘available’:‘taken’);}catch(e){}
},400);
return()=>clearTimeout(t);
},[f.ticker]);

// Username check
useEffect(()=>{
if(!f.username||f.username===user.username){setUsernameStatus(’’);return;}
const t=setTimeout(async()=>{
try{const r=await fetch(’/api/username/check/’+f.username);const d=await r.json();setUsernameStatus(d.available?‘available’:‘taken’);}catch(e){}
},400);
return()=>clearTimeout(t);
},[f.username]);

const save=async e=>{
e.preventDefault();setErr(’’);setSuccess(’’);setSaving(true);
try{
const payload={…f};
if(!payload.new_password)delete payload.new_password;
if(!payload.current_password)delete payload.current_password;
const r=await fetch(’/api/user/settings’,{method:‘POST’,headers:{‘Content-Type’:‘application/json’},credentials:‘include’,body:JSON.stringify(payload)});
const d=await r.json();
if(r.ok){setSuccess(‘Settings saved!’);setTimeout(()=>onSave(d.user),800);}
else setErr(d.error||‘Save failed’);
}catch(e){setErr(‘Network error’);}
setSaving(false);
};

return(
<div className="overlay" onClick={onClose}>
<div className=“modal” style={{maxWidth:620}} onClick={e=>e.stopPropagation()}>
<div className="mtitle">Settings</div>
{err&&<div className="err-box">{err}</div>}
{success&&<div className="success-box">{success}</div>}
<form onSubmit={save}>
{/* Profile */}
<div className="settings-section">
<div className="settings-title">Profile</div>
<div className="frow">
<div className="field"><label>Full name</label><input value={f.full_name} onChange={e=>setF({…f,full_name:e.target.value})}/></div>
<div className="field"><label>Location</label><input value={f.location} onChange={e=>setF({…f,location:e.target.value})} placeholder=“New York, NY”/></div>
</div>
<div className="field"><label>Bio</label><textarea value={f.bio} onChange={e=>setF({…f,bio:e.target.value})} placeholder=“Tell others about your investing strategy…”/></div>
</div>
{/* Account */}
<div className="settings-section">
<div className="settings-title">Account</div>
<div className="frow">
<div className="field">
<label>Username</label>
<input value={f.username} onChange={e=>setF({…f,username:e.target.value.toLowerCase().replace(/\s/g,’’)})}/>
{usernameStatus&&f.username!==user.username&&<div className={’ticker-avail ’+(usernameStatus===‘available’?‘yes’:‘no’)} style={{fontSize:11}}>{usernameStatus===‘available’?‘✓ Available’:‘✗ Already taken’}</div>}
</div>
<div className="field"><label>Email</label><input type=“email” value={f.email} onChange={e=>setF({…f,email:e.target.value})}/></div>
</div>
</div>
{/* Portfolio */}
<div className="settings-section">
<div className="settings-title">Portfolio Identity</div>
<div className="frow">
<div className="field"><label>Portfolio name</label><input value={f.portfolio_name} onChange={e=>setF({…f,portfolio_name:e.target.value})}/></div>
<div className="field">
<label>Ticker symbol</label>
<input className=“mono-input” value={f.ticker} onChange={e=>setF({…f,ticker:e.target.value.toUpperCase().replace(/[^A-Z]/g,’’).slice(0,4)})} maxLength={4}/>
{f.ticker!==user.ticker&&f.ticker.length===4&&<div className={‘ticker-avail ‘+(tickerStatus===‘available’?‘yes’:‘no’)} style={{fontSize:11}}>{tickerStatus===‘available’?‘✓ Available’:‘✗ Already taken’}</div>}
{f.ticker===user.ticker&&<div style={{fontSize:11,color:’#9ca3af’,marginTop:3}}>Current: ${user.ticker}</div>}
</div>
</div>
</div>
{/* Accent color */}
<div className="settings-section">
<div className="settings-title">App Color</div>
<div className="color-grid">
{ACCENT_COLORS.map(c=>(
<div key={c.val} className={‘color-swatch’+(f.accent_color===c.val?’ selected’:’’)} style={{background:c.val}} title={c.name} onClick={()=>setF({…f,accent_color:c.val})}/>
))}
</div>
</div>
{/* Password */}
<div className="settings-section">
<div className="settings-title">Change Password <span style={{fontWeight:400,color:’#9ca3af’,fontSize:12}}>(leave blank to keep current)</span></div>
<div className="frow">
<div className="field"><label>Current password</label><input type=“password” value={f.current_password} onChange={e=>setF({…f,current_password:e.target.value})}/></div>
<div className="field"><label>New password</label><input type=“password” value={f.new_password} onChange={e=>setF({…f,new_password:e.target.value})}/></div>
</div>
</div>
<div className="mfoot">
<button type=“button” style={{background:‘var(–gray-100)’,color:‘var(–gray-700)’}} onClick={onClose}>Cancel</button>
<button type=“submit” style={{background:‘var(–blue)’,color:’#fff’}} disabled={saving}>{saving?‘Saving…’:‘Save changes’}</button>
</div>
</form>
</div>
</div>
);
}

// ── ADD PROPERTY MODAL (with Zillow search) ───────────────────────────────────
function AddPropModal({userId,onClose,onSave}) {
const [step,setStep]=useState(‘zillow’); // zillow | details | manual
const [url,setUrl]=useState(’’);
const [fetching,setFetching]=useState(false);
const [fetchErr,setFetchErr]=useState(’’);
const [zData,setZData]=useState(null);
const [f,setF]=useState({name:’’,location:’’,purchase_price:0,down_payment:0,mortgage:0,insurance:0,hoa:0,property_tax:0,monthly_revenue:0,zestimate:0,bedrooms:’’,bathrooms:’’,sqft:’’,year_built:’’});
const [saving,setSaving]=useState(false);

const fetchZillow=async()=>{
if(!url.includes(‘zillow.com’)){setFetchErr(‘Please paste a Zillow property listing URL’);return;}
setFetching(true);setFetchErr(’’);
try{
const r=await fetch(’/api/zillow/zestimate’,{method:‘POST’,headers:{‘Content-Type’:‘application/json’},credentials:‘include’,body:JSON.stringify({url})});
const d=await r.json();
if(d.zestimate){
setZData(d);
const addr = d.address||url.split(‘homedetails/’)[1]?.split(’/’)[0]?.replace(/-/g,’ ‘)||’’;
setF(prev=>({…prev,
name: addr.split(’,’)[0]||addr,
location: addr,
purchase_price: d.zestimate,
zestimate: d.zestimate,
property_tax: d.monthly_tax||0,
bedrooms: d.bedrooms||’’,
bathrooms: d.bathrooms||’’,
sqft: d.sqft||’’,
year_built: d.year_built||’’
}));
setStep(‘details’);
} else {
setFetchErr(d.error||‘Could not find Zestimate — check the URL or use manual entry’);
}
}catch(e){setFetchErr(‘Request failed. Try again or use manual entry.’);}
setFetching(false);
};

const submit=async e=>{
e.preventDefault();setSaving(true);
try{
await fetch(’/api/properties/’+userId,{method:‘POST’,headers:{‘Content-Type’:‘application/json’},credentials:‘include’,body:JSON.stringify(f)});
onSave();
}catch(e){}
setSaving(false);
};

const inp = (label,key,type=‘number’,placeholder=’’)=>(
<div>
<label style={{fontSize:11,fontWeight:700,color:’#6b7280’,textTransform:‘uppercase’,letterSpacing:’.4px’,display:‘block’,marginBottom:5}}>{label}</label>
<input type={type} value={f[key]} onChange={e=>setF(p=>({…p,[key]:type===‘number’?parseFloat(e.target.value)||0:e.target.value}))}
placeholder={placeholder} style={{width:‘100%’,padding:‘9px 12px’,border:‘1px solid rgba(0,0,0,.1)’,borderRadius:9,fontSize:14,background:‘rgba(255,255,255,0.7)’,backdropFilter:‘blur(8px)’,boxSizing:‘border-box’}}/>
</div>
);

return(
<div className="overlay" onClick={onClose}>
<div className=“modal” onClick={e=>e.stopPropagation()} style={{maxWidth:540}}>

```
    {/* Header */}
    <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:24}}>
      <div>
        <div style={{fontSize:18,fontWeight:700}}>Add Property</div>
        <div style={{fontSize:12,color:'#6b7280',marginTop:2}}>
          {step==='zillow'&&'Paste a Zillow listing URL to auto-populate'}
          {step==='details'&&'Review & complete the details'}
          {step==='manual'&&'Enter property details manually'}
        </div>
      </div>
      <button onClick={onClose} style={{background:'rgba(0,0,0,.06)',border:'none',width:32,height:32,borderRadius:'50%',cursor:'pointer',fontSize:18,display:'flex',alignItems:'center',justifyContent:'center'}}>×</button>
    </div>

    {/* Step 1: Zillow URL */}
    {step==='zillow'&&(
      <div>
        {/* Zillow brand block */}
        <div style={{background:'rgba(0,120,210,.06)',border:'1px solid rgba(0,120,210,.15)',borderRadius:14,padding:'20px 20px 16px',marginBottom:20}}>
          <div style={{display:'flex',alignItems:'center',gap:10,marginBottom:12}}>
            <div style={{width:36,height:36,background:'#1277e1',borderRadius:8,display:'flex',alignItems:'center',justifyContent:'center'}}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="white"><path d="M12 2L2 9.5V22h7v-6h6v6h7V9.5L12 2z"/></svg>
            </div>
            <div>
              <div style={{fontWeight:700,fontSize:15,color:'#1277e1'}}>Zillow</div>
              <div style={{fontSize:11,color:'#6b7280'}}>Powered by Zestimate</div>
            </div>
          </div>
          <p style={{fontSize:13,color:'#374151',margin:'0 0 14px',lineHeight:1.5}}>
            Find your property on <strong>zillow.com</strong>, copy the URL from your browser, and paste it below. We'll pull the Zestimate and property details automatically.
          </p>
          <div style={{background:'rgba(255,255,255,0.6)',borderRadius:8,padding:'8px 12px',marginBottom:12,fontSize:12,color:'#6b7280',fontFamily:'monospace'}}>
            https://www.zillow.com/homedetails/123-main-st/12345_zpid/
          </div>
          <div style={{display:'flex',gap:8}}>
            <input
              value={url}
              onChange={e=>{setUrl(e.target.value);setFetchErr('');}}
              onKeyDown={e=>e.key==='Enter'&&fetchZillow()}
              placeholder="Paste Zillow URL here..."
              style={{flex:1,padding:'10px 14px',border:'1px solid rgba(0,120,210,.3)',borderRadius:9,fontSize:14,background:'rgba(255,255,255,0.8)',backdropFilter:'blur(8px)'}}
              autoFocus
            />
            <button onClick={fetchZillow} disabled={!url||fetching}
              style={{padding:'10px 20px',background:'#1277e1',color:'#fff',border:'none',borderRadius:9,fontWeight:700,fontSize:14,cursor:'pointer',whiteSpace:'nowrap',opacity:(!url||fetching)?0.6:1}}>
              {fetching?'Fetching...':'Get Details'}
            </button>
          </div>
          {fetchErr&&(
            <div style={{marginTop:10,padding:'8px 12px',background:'rgba(220,38,38,.06)',border:'1px solid rgba(220,38,38,.2)',borderRadius:7,fontSize:12,color:'#dc2626'}}>{fetchErr}</div>
          )}
        </div>

        {/* Manual fallback */}
        <div style={{textAlign:'center'}}>
          <button onClick={()=>setStep('manual')} style={{background:'none',border:'none',fontSize:12,color:'#9ca3af',cursor:'pointer',textDecoration:'underline'}}>
            Property not on Zillow? Enter manually
          </button>
        </div>
      </div>
    )}

    {/* Step 2: Details (from Zillow) */}
    {step==='details'&&(
      <form onSubmit={submit}>
        {/* Zillow success banner */}
        <div style={{background:'rgba(5,150,105,.06)',border:'1px solid rgba(5,150,105,.2)',borderRadius:10,padding:'10px 14px',marginBottom:18,display:'flex',alignItems:'center',gap:8}}>
          <div style={{width:8,height:8,background:'#059669',borderRadius:'50%'}}/>
          <span style={{fontSize:13,fontWeight:600,color:'#059669'}}>Zestimate fetched — ${(f.zestimate||0).toLocaleString()}</span>
          {f.bedrooms&&<span style={{fontSize:12,color:'#6b7280',marginLeft:8}}>{f.bedrooms}bd · {f.bathrooms}ba{f.sqft?' · '+parseInt(f.sqft).toLocaleString()+' sqft':''}</span>}
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
          {inp('Property Name','name','text','e.g. 102 Lockwood')}
          {inp('Address','location','text','Full address')}
          {inp('Purchase Price ($)','purchase_price')}
          {inp('Down Payment ($)','down_payment')}
          {inp('Monthly Mortgage ($)','mortgage')}
          {inp('Monthly Rent Income ($)','monthly_revenue')}
          {inp('Property Tax /mo ($)','property_tax')}
          {inp('Insurance /mo ($)','insurance')}
          {f.hoa>0&&inp('HOA /mo ($)','hoa')}
        </div>
        <div style={{display:'flex',gap:8,marginTop:18}}>
          <button type="button" onClick={()=>setStep('zillow')} style={{flex:1,padding:'10px',background:'rgba(0,0,0,.05)',border:'none',borderRadius:9,fontWeight:600,fontSize:14,cursor:'pointer'}}>← Back</button>
          <button type="submit" disabled={saving} style={{flex:2,padding:'10px',background:'#1a56db',color:'#fff',border:'none',borderRadius:9,fontWeight:700,fontSize:14,cursor:'pointer'}}>
            {saving?'Adding...':'Add Property'}
          </button>
        </div>
      </form>
    )}

    {/* Step 3: Manual entry */}
    {step==='manual'&&(
      <form onSubmit={submit}>
        <div style={{background:'rgba(245,158,11,.06)',border:'1px solid rgba(245,158,11,.2)',borderRadius:10,padding:'10px 14px',marginBottom:16,fontSize:12,color:'#92400e'}}>
          Manual mode — all fields must be entered by hand
        </div>
        <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:12,marginBottom:12}}>
          {inp('Property Name','name','text')}
          {inp('Address','location','text')}
          {inp('Current Value ($)','zestimate')}
          {inp('Purchase Price ($)','purchase_price')}
          {inp('Down Payment ($)','down_payment')}
          {inp('Monthly Mortgage ($)','mortgage')}
          {inp('Monthly Rent Income ($)','monthly_revenue')}
          {inp('Property Tax /mo ($)','property_tax')}
          {inp('Insurance /mo ($)','insurance')}
        </div>
        <div style={{display:'flex',gap:8,marginTop:18}}>
          <button type="button" onClick={()=>setStep('zillow')} style={{flex:1,padding:'10px',background:'rgba(0,0,0,.05)',border:'none',borderRadius:9,fontWeight:600,fontSize:14,cursor:'pointer'}}>← Back</button>
          <button type="submit" disabled={saving} style={{flex:2,padding:'10px',background:'#1a56db',color:'#fff',border:'none',borderRadius:9,fontWeight:700,fontSize:14,cursor:'pointer'}}>{saving?'Adding...':'Add Property'}</button>
        </div>
      </form>
    )}
  </div>
</div>
```

);
}

// ── PERFORMANCE TAB ───────────────────────────────────────────────────────────
function PerformanceTab({user, properties, accent}) {
const [data,setData]=useState(null);
const [loading,setLoading]=useState(true);
const [range,setRange]=useState(12);
const [snapping,setSnapping]=useState(false);
const fmt$=n=>{const a=Math.abs(n||0),s=(n||0)<0?’-’:’’;if(a>=1000000)return s+’$’+(a/1000000).toFixed(2)+‘M’;if(a>=1000)return s+’$’+(a/1000).toFixed(1)+‘K’;return s+’$’+Math.round(a).toLocaleString();};
const fmtPct=n=>(n>=0?’+’:’’)+n.toFixed(1)+’%’;

useEffect(()=>{if(!user?.id)return;
fetch(’/api/performance/portfolio/’+user.id+’?months=’+range,{credentials:‘include’})
.then(r=>r.json()).then(d=>setData(d)).finally(()=>setLoading(false));
},[user,range]);

const saveSnapshot=async()=>{setSnapping(true);await fetch(’/api/performance/snapshot’,{method:‘POST’,credentials:‘include’});
fetch(’/api/performance/portfolio/’+user.id+’?months=’+range,{credentials:‘include’}).then(r=>r.json()).then(setData);setSnapping(false);};

const totalValue=properties.reduce((s,p)=>s+parseFloat(p.zestimate||p.purchase_price||0),0);
const totalEquity=properties.reduce((s,p)=>s+parseFloat(p.equity||0),0);
const totalRev=properties.reduce((s,p)=>s+parseFloat(p.monthly_revenue||0),0);
const totalExp=properties.reduce((s,p)=>s+parseFloat(p.monthly_expenses||0),0);
const totalMortgage=properties.reduce((s,p)=>s+parseFloat(p.mortgage||0),0);
const totalTax=properties.reduce((s,p)=>s+parseFloat(p.property_tax||0),0);
const totalIns=properties.reduce((s,p)=>s+parseFloat(p.insurance||0),0);
const totalHOA=properties.reduce((s,p)=>s+parseFloat(p.hoa||0),0);
const netCF=totalRev-totalExp;
const ltv=totalValue>0?((totalValue-totalEquity)/totalValue*100):0;
const capRate=totalValue>0?((totalRev*12-((totalExp-totalMortgage)*12))/totalValue*100):0;
const cashInvested=properties.reduce((s,p)=>s+parseFloat(p.down_payment||0),0);
const coc=cashInvested>0?(netCF*12/cashInvested*100):0;

const kpis=[
{l:‘Portfolio Value’,v:fmt$(totalValue),sub:properties.length+’ propert’+(properties.length===1?‘y’:‘ies’)},
{l:‘Total Equity’,v:fmt$(totalEquity),sub:‘LTV: ‘+ltv.toFixed(1)+’%’,color:’#1a56db’},
{l:‘Monthly Cash Flow’,v:fmt$(netCF),sub:‘Annual: ‘+fmt$(netCF*12),color:netCF>=0?’#059669’:’#d92d20’},
{l:‘Annual NOI’,v:fmt$((totalRev-(totalExp-totalMortgage))*12),sub:‘Monthly: ‘+fmt$(totalRev-(totalExp-totalMortgage))},
{l:‘Cap Rate’,v:capRate.toFixed(2)+’%’,sub:‘Unlevered return’},
{l:‘Cash-on-Cash’,v:coc.toFixed(2)+’%’,sub:‘Based on down payments’},
{l:‘Gross Yield’,v:totalValue>0?(totalRev*12/totalValue*100).toFixed(2)+’%’:‘0%’,sub:‘Rent / Value’},
{l:‘Monthly Revenue’,v:fmt$(totalRev),sub:properties.length+’ units’,color:’#059669’},
{l:‘Monthly Expenses’,v:fmt$(totalExp),sub:‘All-in’,color:’#d92d20’},
{l:‘Cash Invested’,v:fmt$(cashInvested),sub:‘Total down payments’},
{l:‘Annual Revenue’,v:fmt$(totalRev*12),sub:‘Gross’},
{l:‘Annual Expenses’,v:fmt$(totalExp*12),sub:‘All-in’},
];

if(loading)return<div style={{padding:40,textAlign:‘center’,color:’#9ca3af’}}>Loading performance data…</div>;

return(
<div className="tab-content">
<div style={{display:‘flex’,alignItems:‘center’,justifyContent:‘space-between’,marginBottom:24}}>
<div><h2 style={{fontSize:22,fontWeight:700,margin:0}}>Performance</h2><p style={{fontSize:13,color:’#6b7280’,margin:‘2px 0 0’}}>Portfolio analytics & historical tracking</p></div>
<button onClick={saveSnapshot} disabled={snapping} style={{padding:‘8px 16px’,background:accent,color:’#fff’,border:‘none’,borderRadius:8,fontWeight:600,fontSize:13,cursor:‘pointer’}}>
{snapping?‘Saving…’:‘Save Snapshot’}
</button>
</div>

```
  {/* KPI Grid */}
  <div style={{display:'grid',gridTemplateColumns:'repeat(auto-fill,minmax(170px,1fr))',gap:10,marginBottom:20}}>
    {kpis.map((k,i)=>(
      <div key={i} style={{background:'rgba(255,255,255,0.7)',backdropFilter:'blur(16px)',WebkitBackdropFilter:'blur(16px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:12,padding:'14px 16px',boxShadow:'0 2px 8px rgba(0,0,0,.05)',transition:'all .2s ease',cursor:'default'}}>
        <div style={{fontSize:10,fontWeight:700,color:'#9ca3af',textTransform:'uppercase',letterSpacing:'.5px',marginBottom:6}}>{k.l}</div>
        <div style={{fontSize:18,fontWeight:700,color:k.color||'#111827'}}>{k.v}</div>
        {k.sub&&<div style={{fontSize:11,color:'#6b7280',marginTop:3}}>{k.sub}</div>}
      </div>
    ))}
  </div>

  {/* Monthly P&L */}
  <div style={{background:'rgba(255,255,255,0.7)',backdropFilter:'blur(16px)',WebkitBackdropFilter:'blur(16px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,padding:20,marginBottom:20}}>
    <div style={{fontWeight:700,fontSize:15,marginBottom:14}}>Monthly P&L Breakdown</div>
    <div style={{display:'flex',flexDirection:'column',gap:6}}>
      {[
        {l:'Rental Income',v:totalRev,color:'#059669',sign:'+'},
        {l:'Mortgage Payments',v:-totalMortgage,color:'#d92d20',show:totalMortgage>0},
        {l:'Property Tax',v:-totalTax,color:'#d92d20',show:totalTax>0},
        {l:'Insurance',v:-totalIns,color:'#d92d20',show:totalIns>0},
        {l:'HOA Fees',v:-totalHOA,color:'#d92d20',show:totalHOA>0},
      ].filter(r=>r.show!==false).map((r,i)=>(
        <div key={i} style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'8px 12px',background:i===0?'rgba(5,150,105,.04)':'rgba(220,38,38,.03)',borderRadius:8}}>
          <span style={{fontSize:13,color:'#374151'}}>{r.l}</span>
          <span style={{fontSize:14,fontWeight:700,color:r.color}}>{r.v<0?'-':'+'}${Math.abs(r.v).toLocaleString()}</span>
        </div>
      ))}
      <div style={{display:'flex',justifyContent:'space-between',alignItems:'center',padding:'10px 12px',background:netCF>=0?'rgba(5,150,105,.08)':'rgba(220,38,38,.08)',borderRadius:8,borderTop:'2px solid '+(netCF>=0?'#059669':'#d92d20'),marginTop:4}}>
        <span style={{fontSize:14,fontWeight:700}}>Net Cash Flow</span>
        <span style={{fontSize:16,fontWeight:800,color:netCF>=0?'#059669':'#d92d20'}}>{fmt$(netCF)}/mo</span>
      </div>
    </div>
  </div>

  {/* Historical */}
  {(!data||!data.snapshots||data.snapshots.length===0)?(
    <div style={{background:'rgba(255,255,255,0.7)',backdropFilter:'blur(16px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,padding:40,textAlign:'center'}}>
      <div style={{fontSize:32,marginBottom:10}}>📸</div>
      <div style={{fontWeight:600,fontSize:16,marginBottom:6}}>No historical snapshots yet</div>
      <p style={{fontSize:13,color:'#6b7280',maxWidth:320,margin:'0 auto 20px'}}>Save your first snapshot to start tracking portfolio performance over time.</p>
      <button onClick={saveSnapshot} disabled={snapping} style={{padding:'9px 22px',background:accent,color:'#fff',border:'none',borderRadius:8,fontWeight:600,cursor:'pointer'}}>{snapping?'Saving...':'Save First Snapshot'}</button>
    </div>
  ):(
    <div style={{background:'rgba(255,255,255,0.7)',backdropFilter:'blur(16px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,overflow:'hidden'}}>
      <div style={{padding:'16px 20px',borderBottom:'1px solid rgba(0,0,0,.06)',display:'flex',alignItems:'center',justifyContent:'space-between'}}>
        <span style={{fontWeight:700,fontSize:15}}>History</span>
        <div style={{display:'flex',gap:6}}>
          {[6,12,24].map(m=><button key={m} onClick={()=>setRange(m)} style={{padding:'4px 12px',borderRadius:6,border:'1px solid '+(range===m?accent:'#e5e7eb'),background:range===m?accent:'transparent',color:range===m?'#fff':'#6b7280',fontSize:12,cursor:'pointer',transition:'all .15s'}}>{m}M</button>)}
        </div>
      </div>
      <div style={{overflowX:'auto'}}>
        <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
          <thead style={{background:'rgba(0,0,0,.02)'}}>
            <tr>{['Month','Value','Equity','Cash Flow','Revenue','Expenses'].map(h=><th key={h} style={{padding:'10px 14px',textAlign:'left',fontWeight:700,fontSize:11,color:'#6b7280',textTransform:'uppercase',whiteSpace:'nowrap'}}>{h}</th>)}</tr>
          </thead>
          <tbody>
            {(data.snapshots||[]).map((s,i)=>(
              <tr key={i} style={{borderTop:'1px solid rgba(0,0,0,.04)'}}>
                <td style={{padding:'9px 14px',fontWeight:500}}>{s.snapshot_month}</td>
                <td style={{padding:'9px 14px'}}>{fmt$(s.total_value)}</td>
                <td style={{padding:'9px 14px',color:'#1a56db'}}>{fmt$(s.total_equity)}</td>
                <td style={{padding:'9px 14px',fontWeight:600,color:parseFloat(s.net_cashflow)>=0?'#059669':'#d92d20'}}>{fmt$(s.net_cashflow)}</td>
                <td style={{padding:'9px 14px',color:'#059669'}}>{fmt$(s.gross_revenue)}</td>
                <td style={{padding:'9px 14px',color:'#d92d20'}}>{fmt$(s.total_expenses)}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )}
</div>
```

);
}

// ── PROJECTIONS TAB ───────────────────────────────────────────────────────────
function ProjectionsTab({properties, accent}) {
// Auto-populated assumptions (industry standards)
const APP_RATE = 3.5;    // national avg RE appreciation
const RENT_GROWTH = 2.5; // avg rent growth (CPI-linked)
const EXP_GROWTH = 2.0;  // expense inflation
const VAC_RATE = 5.0;    // standard underwriting vacancy
const YEARS = 30;

const fmt$=n=>{const a=Math.abs(n||0),s=(n||0)<0?’-’:’’;if(a>=1000000)return s+’$’+(a/1000000).toFixed(2)+‘M’;if(a>=1000)return s+’$’+(a/1000).toFixed(1)+‘K’;return s+’$’+Math.round(a).toLocaleString();};
const fmtPct=n=>(n>=0?’+’:’’)+n.toFixed(1)+’%’;

const totalValue=properties.reduce((s,p)=>s+parseFloat(p.zestimate||p.purchase_price||0),0);
const totalRevenue=properties.reduce((s,p)=>s+parseFloat(p.monthly_revenue||0),0)*12;
const totalMortgage=properties.reduce((s,p)=>s+parseFloat(p.mortgage||0),0)*12;
const totalOpEx=properties.reduce((s,p)=>s+parseFloat(p.monthly_expenses||0)-parseFloat(p.mortgage||0),0)*12;
const totalDown=properties.reduce((s,p)=>s+parseFloat(p.down_payment||0),0);
const totalDebt=totalValue-properties.reduce((s,p)=>s+parseFloat(p.equity||0),0);

const projections=useMemo(()=>{
const rows=[];
let val=totalValue, rev=totalRevenue, opex=totalOpEx, debt=Math.max(0,totalDebt);
let cumCF=0;
for(let y=1;y<=YEARS;y++){
val=val*(1+APP_RATE/100);
rev=rev*(1+RENT_GROWTH/100);
opex=opex*(1+EXP_GROWTH/100);
// Approximate principal paydown (avg ~1.5% of remaining balance/yr early, rising)
const principalPct=0.012+y*0.0004;
debt=Math.max(0,debt*(1-principalPct));
const equity=val-debt;
const effectiveRev=rev*(1-VAC_RATE/100);
const noi=effectiveRev-opex;
const cf=noi-totalMortgage;
cumCF+=cf;
const appreciation=val-totalValue;
const totalReturn=cumCF+appreciation;
const coc=totalDown>0?(cf/totalDown*100):0;
const capRate=val>0?(noi/val*100):0;
rows.push({year:y,value:val,equity,debt,revenue:effectiveRev,cf,cumCF,appreciation,totalReturn,coc,capRate,noi});
}
return rows;
},[totalValue,totalRevenue,totalOpEx,totalDown,totalDebt,totalMortgage]);

if(properties.length===0)return(
<div className=“tab-content” style={{textAlign:‘center’,paddingTop:80}}>
<div style={{fontSize:40,marginBottom:12}}>📈</div>
<div style={{fontWeight:600,fontSize:18,marginBottom:8}}>Add properties first</div>
<p style={{color:’#6b7280’,fontSize:14}}>Projections are calculated from your portfolio data.</p>
</div>
);

const milestones=[[10,projections[9],’#1a56db’],[20,projections[19],’#7c3aed’],[30,projections[29],’#059669’]];

return(
<div className="tab-content">
<div style={{marginBottom:24}}>
<h2 style={{fontSize:22,fontWeight:700,margin:0}}>30-Year Projections</h2>
<p style={{fontSize:13,color:’#6b7280’,margin:‘4px 0 0’}}>
Based on {APP_RATE}% appreciation · {RENT_GROWTH}% rent growth · {EXP_GROWTH}% expense inflation · {VAC_RATE}% vacancy
</p>
</div>

```
  {/* Milestone cards */}
  <div style={{display:'grid',gridTemplateColumns:'repeat(3,1fr)',gap:16,marginBottom:24}}>
    {milestones.map(([y,d,c])=>d&&(
      <div key={y} style={{background:'rgba(255,255,255,0.72)',backdropFilter:'blur(20px)',WebkitBackdropFilter:'blur(20px)',border:'2px solid '+c+'30',borderRadius:16,padding:20,boxShadow:'0 4px 20px '+c+'12',transition:'all .2s ease'}}>
        <div style={{fontSize:11,fontWeight:800,color:c,textTransform:'uppercase',letterSpacing:'1px',marginBottom:14}}>Year {y}</div>
        {[
          {l:'Portfolio Value',v:fmt$(d.value)},
          {l:'Equity',v:fmt$(d.equity),color:'#1a56db'},
          {l:'Annual Cash Flow',v:fmt$(d.cf),color:d.cf>=0?'#059669':'#d92d20'},
          {l:'Cumulative Cash Flow',v:fmt$(d.cumCF),color:d.cumCF>=0?'#059669':'#d92d20'},
          {l:'Total Appreciation',v:fmt$(d.appreciation),color:'#059669'},
          {l:'Total Return',v:fmt$(d.totalReturn),color:d.totalReturn>=0?'#059669':'#d92d20'},
          {l:'Cash-on-Cash',v:d.coc.toFixed(1)+'%'},
          {l:'Cap Rate',v:d.capRate.toFixed(2)+'%'},
        ].map((r,i)=>(
          <div key={i} style={{display:'flex',justifyContent:'space-between',padding:'5px 0',borderBottom:'1px solid rgba(0,0,0,.04)'}}>
            <span style={{fontSize:12,color:'#6b7280'}}>{r.l}</span>
            <span style={{fontSize:12,fontWeight:700,color:r.color||'#111827'}}>{r.v}</span>
          </div>
        ))}
      </div>
    ))}
  </div>

  {/* Full table */}
  <div style={{background:'rgba(255,255,255,0.72)',backdropFilter:'blur(20px)',WebkitBackdropFilter:'blur(20px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,overflow:'hidden'}}>
    <div style={{padding:'16px 20px',borderBottom:'1px solid rgba(0,0,0,.06)',fontWeight:700,fontSize:15}}>Year-by-Year Breakdown</div>
    <div style={{overflowX:'auto',maxHeight:400,overflowY:'auto'}}>
      <table style={{width:'100%',borderCollapse:'collapse',fontSize:12}}>
        <thead style={{position:'sticky',top:0,background:'rgba(249,250,251,0.95)',backdropFilter:'blur(8px)',zIndex:1}}>
          <tr>{['Yr','Value','Equity','Debt','Annual Rev','Annual CF','Cum CF','Appreciation','Total Return','Cap Rate','CoC'].map(h=>(
            <th key={h} style={{padding:'10px 12px',textAlign:'left',fontWeight:700,fontSize:10,color:'#6b7280',textTransform:'uppercase',whiteSpace:'nowrap'}}>{h}</th>
          ))}</tr>
        </thead>
        <tbody>
          {projections.map((r,i)=>{
            const highlight=[5,10,15,20,25,30].includes(r.year);
            return(
              <tr key={i} style={{borderTop:'1px solid rgba(0,0,0,.04)',background:highlight?'rgba(26,86,219,.03)':'',transition:'background .1s'}}>
                <td style={{padding:'8px 12px',fontWeight:highlight?700:400,color:highlight?accent:'#374151'}}>{r.year}</td>
                <td style={{padding:'8px 12px'}}>{fmt$(r.value)}</td>
                <td style={{padding:'8px 12px',color:'#1a56db'}}>{fmt$(r.equity)}</td>
                <td style={{padding:'8px 12px',color:'#9ca3af'}}>{fmt$(r.debt)}</td>
                <td style={{padding:'8px 12px'}}>{fmt$(r.revenue)}</td>
                <td style={{padding:'8px 12px',fontWeight:600,color:r.cf>=0?'#059669':'#d92d20'}}>{fmt$(r.cf)}</td>
                <td style={{padding:'8px 12px',color:r.cumCF>=0?'#059669':'#d92d20'}}>{fmt$(r.cumCF)}</td>
                <td style={{padding:'8px 12px',color:'#059669'}}>{fmt$(r.appreciation)}</td>
                <td style={{padding:'8px 12px',fontWeight:600,color:r.totalReturn>=0?'#059669':'#d92d20'}}>{fmt$(r.totalReturn)}</td>
                <td style={{padding:'8px 12px'}}>{r.capRate.toFixed(2)}%</td>
                <td style={{padding:'8px 12px'}}>{r.coc.toFixed(1)}%</td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  </div>
</div>
```

);
}

// ── NET WORTH TAB ─────────────────────────────────────────────────────────────
function NetWorthTab({properties, accent, stockValue}) {
const [assets,setAssets]=useState([
{id:1,label:‘Cash & Savings’,value:’’},
{id:2,label:‘Checking Account’,value:’’},
{id:3,label:‘Vehicles’,value:’’},
{id:4,label:‘Other Assets’,value:’’},
]);
const [liabilities,setLiabilities]=useState([
{id:1,label:‘Car Loan’,value:’’},
{id:2,label:‘Credit Cards’,value:’’},
{id:3,label:‘Student Loans’,value:’’},
{id:4,label:‘Other Debt’,value:’’},
]);
const fmt$=n=>{const a=Math.abs(n||0),s=(n||0)<0?’-’:’’;if(a>=1000000)return s+’$’+(a/1000000).toFixed(2)+‘M’;if(a>=1000)return s+’$’+(a/1000).toFixed(1)+‘K’;return s+’$’+Math.round(a).toLocaleString();};

const reEquity=properties.reduce((s,p)=>s+parseFloat(p.equity||0),0);
const reValue=properties.reduce((s,p)=>s+parseFloat(p.zestimate||p.purchase_price||0),0);
const reMortgages=reValue-reEquity;
const otherAssets=assets.reduce((s,a)=>s+parseFloat(a.value||0),0);
const otherLiabs=liabilities.reduce((s,l)=>s+parseFloat(l.value||0),0);
const sv=parseFloat(stockValue)||0;
const totalAssets=reEquity+otherAssets+sv;
const totalLiabs=otherLiabs;
const netWorth=totalAssets-totalLiabs;
const pct=(v,t)=>t>0?(v/t*100).toFixed(1)+’%’:‘0%’;

const upd=(set,items,id,val)=>set(items.map(r=>r.id===id?{…r,value:val}:r));
const updL=(set,items,id,val)=>set(items.map(r=>r.id===id?{…r,label:val}:r));

return(
<div className="tab-content">
<div style={{marginBottom:24}}><h2 style={{fontSize:22,fontWeight:700,margin:0}}>Net Worth</h2><p style={{fontSize:13,color:’#6b7280’,margin:‘2px 0 0’}}>Total assets minus liabilities</p></div>

```
  {/* Hero number */}
  <div style={{background:netWorth>=0?'linear-gradient(135deg,#1a56db,#1e40af)':'linear-gradient(135deg,#dc2626,#991b1b)',borderRadius:18,padding:28,marginBottom:24,color:'#fff',position:'relative',overflow:'hidden',boxShadow:netWorth>=0?'0 8px 32px rgba(26,86,219,.3)':'0 8px 32px rgba(220,38,38,.3)'}}>
    <div style={{position:'absolute',top:-30,right:-30,width:140,height:140,background:'rgba(255,255,255,.06)',borderRadius:'50%'}}/>
    <div style={{fontSize:12,fontWeight:700,textTransform:'uppercase',letterSpacing:'1px',opacity:.7,marginBottom:6}}>Total Net Worth</div>
    <div style={{fontSize:44,fontWeight:800,letterSpacing:'-1px',marginBottom:16}}>{fmt$(netWorth)}</div>
    <div style={{display:'flex',gap:28,fontSize:13}}>
      <div><div style={{opacity:.7,marginBottom:2}}>Total Assets</div><div style={{fontWeight:700,fontSize:20}}>{fmt$(totalAssets)}</div></div>
      <div><div style={{opacity:.7,marginBottom:2}}>Total Liabilities</div><div style={{fontWeight:700,fontSize:20}}>-{fmt$(totalLiabs)}</div></div>
    </div>
  </div>

  <div style={{display:'grid',gridTemplateColumns:'1fr 1fr',gap:16,marginBottom:20}}>
    {/* Assets */}
    <div style={{background:'rgba(255,255,255,0.72)',backdropFilter:'blur(20px)',WebkitBackdropFilter:'blur(20px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,padding:20}}>
      <div style={{fontWeight:700,fontSize:15,color:'#059669',marginBottom:14}}>Assets</div>
      <div style={{padding:'10px 12px',background:'rgba(5,150,105,.06)',borderRadius:9,marginBottom:8}}>
        <div style={{display:'flex',justifyContent:'space-between'}}><span style={{fontWeight:600,fontSize:13}}>Real Estate Equity</span><span style={{fontWeight:700,color:'#059669'}}>{fmt$(reEquity)}</span></div>
        <div style={{fontSize:11,color:'#6b7280',marginTop:2}}>{pct(reEquity,totalAssets)} of assets · {fmt$(reValue)} value</div>
      </div>
      {sv>0&&<div style={{padding:'10px 12px',background:'rgba(124,58,237,.06)',borderRadius:9,marginBottom:8}}>
        <div style={{display:'flex',justifyContent:'space-between'}}><span style={{fontWeight:600,fontSize:13}}>Stock Portfolio</span><span style={{fontWeight:700,color:'#7c3aed'}}>{fmt$(sv)}</span></div>
        <div style={{fontSize:11,color:'#6b7280',marginTop:2}}>{pct(sv,totalAssets)} of assets</div>
      </div>}
      {assets.map(a=>(
        <div key={a.id} style={{display:'flex',gap:6,marginBottom:6,alignItems:'center'}}>
          <input value={a.label} onChange={e=>updL(setAssets,assets,a.id,e.target.value)} style={{flex:2,padding:'6px 9px',border:'1px solid rgba(0,0,0,.08)',borderRadius:6,fontSize:12,background:'rgba(255,255,255,0.7)'}}/>
          <input type="number" value={a.value} onChange={e=>upd(setAssets,assets,a.id,e.target.value)} placeholder="0" style={{flex:1,padding:'6px 9px',border:'1px solid rgba(0,0,0,.08)',borderRadius:6,fontSize:12,background:'rgba(255,255,255,0.7)'}}/>
        </div>
      ))}
      <button onClick={()=>setAssets(a=>[...a,{id:Date.now(),label:'New Asset',value:''}])} style={{fontSize:12,color:accent,background:'none',border:'1px dashed '+accent,borderRadius:6,padding:'5px 12px',cursor:'pointer',marginTop:4}}>+ Add Asset</button>
    </div>

    {/* Liabilities */}
    <div style={{background:'rgba(255,255,255,0.72)',backdropFilter:'blur(20px)',WebkitBackdropFilter:'blur(20px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,padding:20}}>
      <div style={{fontWeight:700,fontSize:15,color:'#d92d20',marginBottom:14}}>Liabilities</div>
      <div style={{padding:'10px 12px',background:'rgba(220,38,38,.04)',borderRadius:9,marginBottom:8}}>
        <div style={{display:'flex',justifyContent:'space-between'}}><span style={{fontWeight:600,fontSize:13}}>Mortgages</span><span style={{fontWeight:700,color:'#d92d20'}}>-{fmt$(reMortgages)}</span></div>
        <div style={{fontSize:11,color:'#6b7280',marginTop:2}}>{properties.length} propert{properties.length===1?'y':'ies'}</div>
      </div>
      {liabilities.map(l=>(
        <div key={l.id} style={{display:'flex',gap:6,marginBottom:6,alignItems:'center'}}>
          <input value={l.label} onChange={e=>updL(setLiabilities,liabilities,l.id,e.target.value)} style={{flex:2,padding:'6px 9px',border:'1px solid rgba(0,0,0,.08)',borderRadius:6,fontSize:12,background:'rgba(255,255,255,0.7)'}}/>
          <input type="number" value={l.value} onChange={e=>upd(setLiabilities,liabilities,l.id,e.target.value)} placeholder="0" style={{flex:1,padding:'6px 9px',border:'1px solid rgba(0,0,0,.08)',borderRadius:6,fontSize:12,background:'rgba(255,255,255,0.7)'}}/>
        </div>
      ))}
      <button onClick={()=>setLiabilities(l=>[...l,{id:Date.now(),label:'New Liability',value:''}])} style={{fontSize:12,color:'#d92d20',background:'none',border:'1px dashed #d92d20',borderRadius:6,padding:'5px 12px',cursor:'pointer',marginTop:4}}>+ Add Liability</button>
    </div>
  </div>

  {/* Composition */}
  <div style={{background:'rgba(255,255,255,0.72)',backdropFilter:'blur(20px)',WebkitBackdropFilter:'blur(20px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,padding:20}}>
    <div style={{fontWeight:700,fontSize:14,marginBottom:12}}>Asset Composition</div>
    {totalAssets>0&&<div style={{display:'flex',borderRadius:8,overflow:'hidden',height:20,marginBottom:10}}>
      {[{v:reEquity,c:'#1a56db'},{v:sv,c:'#7c3aed'},{v:otherAssets,c:'#0891b2'}].filter(s=>s.v>0).map((s,i)=>(
        <div key={i} style={{flex:s.v,background:s.c,transition:'flex .4s ease'}}/>
      ))}
    </div>}
    <div style={{display:'flex',gap:16,flexWrap:'wrap'}}>
      {[{l:'Real Estate',v:reEquity,c:'#1a56db'},{l:'Stocks',v:sv,c:'#7c3aed'},{l:'Other',v:otherAssets,c:'#0891b2'}].filter(s=>s.v>0).map((s,i)=>(
        <div key={i} style={{display:'flex',alignItems:'center',gap:6,fontSize:12}}>
          <div style={{width:10,height:10,background:s.c,borderRadius:2}}/>
          <span style={{color:'#6b7280'}}>{s.l}</span><span style={{fontWeight:700}}>{fmt$(s.v)} ({pct(s.v,totalAssets)})</span>
        </div>
      ))}
    </div>
  </div>
</div>
```

);
}

// ── STOCKS TAB ────────────────────────────────────────────────────────────────
function StocksTab({accent, onValueChange}) {
const [holdings,setHoldings]=useState([]);
const [adding,setAdding]=useState(false);
const [form,setForm]=useState({ticker:’’,shares:’’,cost_basis:’’,current_price:’’});
const [loading,setLoading]=useState(false);
const [err,setErr]=useState(’’);
const fmt$=n=>{const a=Math.abs(n||0),s=(n||0)<0?’-’:’’;if(a>=1000000)return s+’$’+(a/1000000).toFixed(2)+‘M’;if(a>=1000)return s+’$’+(a/1000).toFixed(1)+‘K’;return s+’$’+Math.round(a).toLocaleString();};
const fmtPct=n=>(n>=0?’+’:’’)+n.toFixed(2)+’%’;

const totalValue=holdings.reduce((s,h)=>s+h.market_value,0);
const totalCost=holdings.reduce((s,h)=>s+(h.cost_basis*h.shares),0);
const totalGL=totalValue-totalCost;
const totalPct=totalCost>0?((totalValue-totalCost)/totalCost*100):0;

useEffect(()=>{if(onValueChange)onValueChange(totalValue);},[totalValue]);

const lookupPrice=async(ticker)=>{
if(!ticker)return;setLoading(true);
try{
const r=await fetch(’/api/stocks/quote?ticker=’+ticker.toUpperCase(),{credentials:‘include’});
const d=await r.json();
if(d.price)setForm(f=>({…f,current_price:d.price}));
}catch(e){}
setLoading(false);
};

const add=()=>{
if(!form.ticker||!form.shares){setErr(‘Ticker and shares required’);return;}
const shares=parseFloat(form.shares);
const cost=parseFloat(form.cost_basis||0);
const price=parseFloat(form.current_price||cost);
setHoldings(h=>[…h,{id:Date.now(),ticker:form.ticker.toUpperCase(),shares,cost_basis:cost,current_price:price,market_value:shares*price,gain_loss:(price-cost)*shares,gain_pct:cost>0?((price-cost)/cost*100):0}]);
setForm({ticker:’’,shares:’’,cost_basis:’’,current_price:’’});setAdding(false);setErr(’’);
};

return(
<div className="tab-content">
<div style={{display:‘flex’,alignItems:‘center’,justifyContent:‘space-between’,marginBottom:24}}>
<div><h2 style={{fontSize:22,fontWeight:700,margin:0}}>Stock Portfolio</h2><p style={{fontSize:13,color:’#6b7280’,margin:‘2px 0 0’}}>Equity holdings — factors into Net Worth</p></div>
<button onClick={()=>setAdding(true)} style={{padding:‘8px 18px’,background:accent,color:’#fff’,border:‘none’,borderRadius:8,fontWeight:600,fontSize:13,cursor:‘pointer’}}>+ Add Holding</button>
</div>

```
  <div style={{background:'rgba(239,246,255,0.8)',backdropFilter:'blur(16px)',border:'1px solid rgba(191,219,254,0.7)',borderRadius:12,padding:'14px 18px',marginBottom:20,display:'flex',gap:12,alignItems:'flex-start'}}>
    <div style={{fontSize:18,marginTop:1}}>🔗</div>
    <div><div style={{fontWeight:600,fontSize:13}}>Schwab / Brokerage Integration Coming</div><div style={{fontSize:12,color:'#6b7280',marginTop:2}}>Direct OAuth connections are in development. Add holdings manually for now — they'll automatically count toward your Net Worth.</div></div>
  </div>

  {holdings.length>0&&<div style={{display:'grid',gridTemplateColumns:'repeat(4,1fr)',gap:12,marginBottom:20}}>
    {[{l:'Portfolio Value',v:fmt$(totalValue)},{l:'Cost Basis',v:fmt$(totalCost)},{l:'Total P&L',v:fmt$(totalGL),c:totalGL>=0?'#059669':'#d92d20'},{l:'Total Return',v:fmtPct(totalPct),c:totalPct>=0?'#059669':'#d92d20'}].map((k,i)=>(
      <div key={i} style={{background:'rgba(255,255,255,0.72)',backdropFilter:'blur(16px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:12,padding:'14px 16px',boxShadow:'0 2px 8px rgba(0,0,0,.05)'}}>
        <div style={{fontSize:10,fontWeight:700,color:'#9ca3af',textTransform:'uppercase',letterSpacing:'.5px',marginBottom:5}}>{k.l}</div>
        <div style={{fontSize:18,fontWeight:700,color:k.c||'#111827'}}>{k.v}</div>
      </div>
    ))}
  </div>}

  {adding&&(
    <div style={{background:'rgba(255,255,255,0.8)',backdropFilter:'blur(20px)',border:'1px solid rgba(255,255,255,0.9)',borderRadius:14,padding:20,marginBottom:20}}>
      <div style={{fontWeight:700,fontSize:14,marginBottom:12}}>Add Holding</div>
      {err&&<div style={{color:'#d92d20',fontSize:12,marginBottom:8}}>{err}</div>}
      <div style={{display:'grid',gridTemplateColumns:'1fr 1fr 1fr 1fr',gap:10,marginBottom:12}}>
        {[['Ticker','ticker','text','AAPL'],['Shares','shares','number','10'],['Avg Cost','cost_basis','number','150.00'],['Price '+(loading?'⏳':'(auto)'),'current_price','number','']].map(([l,k,t,ph])=>(
          <div key={k}>
            <label style={{fontSize:10,fontWeight:700,color:'#6b7280',textTransform:'uppercase',display:'block',marginBottom:4}}>{l}</label>
            <input type={t} value={form[k]} onChange={e=>setForm(f=>({...f,[k]:t==='text'?e.target.value.toUpperCase():e.target.value}))}
              onBlur={k==='ticker'?e=>lookupPrice(e.target.value):undefined}
              placeholder={ph} style={{width:'100%',padding:'8px 10px',border:'1px solid rgba(0,0,0,.1)',borderRadius:7,fontSize:13,background:'rgba(255,255,255,0.7)',boxSizing:'border-box'}}/>
          </div>
        ))}
      </div>
      <div style={{display:'flex',gap:8}}>
        <button onClick={add} style={{padding:'8px 20px',background:accent,color:'#fff',border:'none',borderRadius:7,fontWeight:600,fontSize:13,cursor:'pointer'}}>Add</button>
        <button onClick={()=>{setAdding(false);setErr('');}} style={{padding:'8px 14px',background:'rgba(0,0,0,.05)',border:'none',borderRadius:7,fontSize:13,cursor:'pointer'}}>Cancel</button>
      </div>
    </div>
  )}

  {holdings.length===0?(
    <div style={{textAlign:'center',padding:60,background:'rgba(255,255,255,0.5)',backdropFilter:'blur(16px)',borderRadius:14,border:'1px dashed rgba(0,0,0,.1)'}}>
      <div style={{fontSize:36,marginBottom:10}}>📊</div>
      <div style={{fontWeight:600,fontSize:16,marginBottom:6}}>No holdings yet</div>
      <p style={{fontSize:13,color:'#6b7280',maxWidth:280,margin:'0 auto 20px'}}>Add your stocks and they'll automatically factor into your Net Worth.</p>
      <button onClick={()=>setAdding(true)} style={{padding:'9px 22px',background:accent,color:'#fff',border:'none',borderRadius:8,fontWeight:600,cursor:'pointer'}}>Add First Holding</button>
    </div>
  ):(
    <div style={{background:'rgba(255,255,255,0.72)',backdropFilter:'blur(20px)',border:'1px solid rgba(255,255,255,0.8)',borderRadius:14,overflow:'hidden'}}>
      <table style={{width:'100%',borderCollapse:'collapse',fontSize:13}}>
        <thead><tr style={{background:'rgba(0,0,0,.02)'}}>
          {['Ticker','Shares','Avg Cost','Price','Value','P&L','Return',''].map(h=><th key={h} style={{padding:'10px 16px',textAlign:'left',fontWeight:700,fontSize:11,color:'#6b7280',textTransform:'uppercase'}}>{h}</th>)}
        </tr></thead>
        <tbody>
          {holdings.map((h,i)=>(
            <tr key={i} style={{borderTop:'1px solid rgba(0,0,0,.04)',transition:'background .1s'}}>
              <td style={{padding:'11px 16px',fontWeight:700,color:accent}}>{h.ticker}</td>
              <td style={{padding:'11px 16px'}}>{h.shares}</td>
              <td style={{padding:'11px 16px'}}>${h.cost_basis.toFixed(2)}</td>
              <td style={{padding:'11px 16px'}}>${h.current_price.toFixed(2)}</td>
              <td style={{padding:'11px 16px',fontWeight:600}}>{fmt$(h.market_value)}</td>
              <td style={{padding:'11px 16px',color:h.gain_loss>=0?'#059669':'#d92d20',fontWeight:600}}>{fmt$(h.gain_loss)}</td>
              <td style={{padding:'11px 16px',color:h.gain_pct>=0?'#059669':'#d92d20'}}>{fmtPct(h.gain_pct)}</td>
              <td style={{padding:'11px 16px'}}><button onClick={()=>setHoldings(hs=>hs.filter(x=>x.id!==h.id))} style={{background:'none',border:'none',color:'#9ca3af',cursor:'pointer',fontSize:16}}>×</button></td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )}
</div>
```

);
}

// ── PLAID MODAL ───────────────────────────────────────────────────────────────
function PlaidModal({onClose}) {
const [status,setStatus]=useState(‘idle’);
const connect=async()=>{
setStatus(‘loading’);
try{
const r=await fetch(’/api/plaid/create-link-token’,{credentials:‘include’});
const d=await r.json();
if(d.link_token){
if(typeof window.Plaid===‘undefined’){setStatus(‘no-sdk’);return;}
const handler=window.Plaid.create({
token:d.link_token,
onSuccess:async(publicToken)=>{
await fetch(’/api/plaid/exchange-token’,{method:‘POST’,headers:{‘Content-Type’:‘application/json’},credentials:‘include’,body:JSON.stringify({public_token:publicToken})});
setStatus(‘connected’);
setTimeout(onClose,2000);
},
onExit:()=>setStatus(‘idle’),
onEvent:()=>{}
});
handler.open();
setStatus(‘idle’);
} else {
setStatus(‘no-keys’);
}
}catch(e){setStatus(‘error’);}
};
return(
<div className="overlay" onClick={onClose}>
<div className=“modal” style={{maxWidth:480}} onClick={e=>e.stopPropagation()}>
<div className="mtitle">Connect Bank Account</div>
<div className="info-box" style={{marginBottom:14}}>Plaid securely connects your bank to auto-import rental income and mortgage payments. Your credentials are never stored.</div>
{status===‘connected’&&<div className="success-box">Bank account connected successfully!</div>}
{status===‘error’&&<div className="err-box">Connection failed. Please try again.</div>}
{status===‘no-sdk’&&<div className="err-box">Plaid SDK failed to load. Check your internet connection.</div>}
{status===‘no-keys’&&<div className="warn-box">
<strong>Plaid API keys not configured.</strong><br/>
To enable bank connections, add these to your Render environment variables:<br/><br/>
<code style={{background:’#fff’,padding:‘2px 6px’,borderRadius:4,fontSize:12,display:‘block’,marginTop:4}}>PLAID_CLIENT_ID = your_client_id</code>
<code style={{background:’#fff’,padding:‘2px 6px’,borderRadius:4,fontSize:12,display:‘block’,marginTop:4}}>PLAID_SECRET = your_sandbox_secret</code>
<br/>Get free keys at <strong>dashboard.plaid.com</strong>
</div>}
<div style={{display:‘flex’,gap:8}}>
<button className="btn btn-ghost" style={{flex:1}} onClick={onClose}>Cancel</button>
<button className=“btn btn-blue” style={{flex:2}} onClick={connect} disabled={status===‘loading’||status===‘connected’}>
{status===‘loading’?‘Opening Plaid…’:status===‘connected’?‘Connected!’:‘Connect with Plaid’}
</button>
</div>
</div>
</div>
);
}

ReactDOM.render(<App/>,document.getElementById(‘root’));
</script>

</body>
</html>
"""

@app.route(’/’, defaults={‘path’: ‘’})
@app.route(’/<path:path>’)
def serve_app(path):
return Response(HTML, mimetype=‘text/html’)

if **name** == ‘**main**’:
app.run(debug=False, host=‘0.0.0.0’, port=int(os.environ.get(‘PORT’, 5000)))
