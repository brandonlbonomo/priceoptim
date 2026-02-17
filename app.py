import os, json, secrets, hashlib, hmac, time, base64, struct, urllib.request, urllib.parse, re
from flask import Flask, request, session, jsonify, send_from_directory
from flask_cors import CORS
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager
import datetime as dt

app = Flask(**name**, static_folder=‘static’)
app.secret_key = os.environ.get(‘SECRET_KEY’, secrets.token_hex(32))
CORS(app, supports_credentials=True)

DATABASE_URL = os.environ.get(‘DATABASE_URL’, ‘’).replace(‘postgres://’, ‘postgresql://’)
PLAID_CLIENT_ID = os.environ.get(‘PLAID_CLIENT_ID’, ‘’)
PLAID_SECRET = os.environ.get(‘PLAID_SECRET’, ‘’)
PLAID_ENV = os.environ.get(‘PLAID_ENV’, ‘production’)

@contextmanager
def get_db():
conn = psycopg2.connect(DATABASE_URL)
try:
yield conn
finally:
conn.close()

# ── DATABASE INIT ──────────────────────────────────────────────────────────────

def init_db():
with get_db() as conn:
cur = conn.cursor()

```
    # Users
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Properties
    cur.execute("""
        CREATE TABLE IF NOT EXISTS properties (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            address TEXT NOT NULL,
            purchase_price NUMERIC DEFAULT 0,
            current_value NUMERIC DEFAULT 0,
            down_payment NUMERIC DEFAULT 0,
            equity NUMERIC DEFAULT 0,
            mortgage NUMERIC DEFAULT 0,
            monthly_revenue NUMERIC DEFAULT 0,
            monthly_expenses NUMERIC DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Plaid items (bank connections)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS plaid_items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            access_token TEXT NOT NULL,
            item_id TEXT UNIQUE,
            institution_name TEXT DEFAULT '',
            institution_id TEXT DEFAULT '',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Transaction categorizations
    cur.execute("""
        CREATE TABLE IF NOT EXISTS plaid_txn_categories (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            txn_id TEXT NOT NULL,
            txn_name TEXT,
            original_category TEXT,
            user_category TEXT NOT NULL,
            property_id INTEGER REFERENCES properties(id) ON DELETE SET NULL,
            amount NUMERIC,
            txn_date DATE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(user_id, txn_id)
        )
    """)
    
    conn.commit()
    cur.close()
```

init_db()

# ── AUTH ───────────────────────────────────────────────────────────────────────

@app.route(’/api/register’, methods=[‘POST’])
def register():
d = request.json or {}
email = d.get(‘email’, ‘’).lower().strip()
password = d.get(‘password’, ‘’)

```
if not email or not password:
    return jsonify({'error': 'Email and password required'}), 400

pw_hash = hashlib.sha256(password.encode()).hexdigest()

try:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("INSERT INTO users (email, password_hash) VALUES (%s, %s) RETURNING id", 
                   (email, pw_hash))
        user_id = cur.fetchone()[0]
        conn.commit()
        cur.close()
    
    session['user_id'] = user_id
    return jsonify({'ok': True, 'user_id': user_id})
except psycopg2.IntegrityError:
    return jsonify({'error': 'Email already exists'}), 400
```

@app.route(’/api/login’, methods=[‘POST’])
def login():
d = request.json or {}
email = d.get(‘email’, ‘’).lower().strip()
password = d.get(‘password’, ‘’)
pw_hash = hashlib.sha256(password.encode()).hexdigest()

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM users WHERE email=%s AND password_hash=%s", (email, pw_hash))
    user = cur.fetchone()
    cur.close()

if not user:
    return jsonify({'error': 'Invalid credentials'}), 401

session['user_id'] = user['id']
return jsonify({'ok': True, 'user': dict(user)})
```

@app.route(’/api/logout’, methods=[‘POST’])
def logout():
session.clear()
return jsonify({‘ok’: True})

@app.route(’/api/me’)
def me():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT id, email FROM users WHERE id=%s", (uid,))
    user = cur.fetchone()
    cur.close()

return jsonify(dict(user) if user else {'error': 'User not found'})
```

# ── PROPERTIES ─────────────────────────────────────────────────────────────────

@app.route(’/api/properties’, methods=[‘GET’, ‘POST’])
def properties():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
if request.method == 'GET':
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT * FROM properties WHERE user_id=%s ORDER BY created_at DESC", (uid,))
        props = [dict(r) for r in cur.fetchall()]
        cur.close()
    return jsonify(props)

# POST - create property
d = request.json or {}
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        INSERT INTO properties (user_id, address, purchase_price, current_value, down_payment, equity, mortgage)
        VALUES (%s, %s, %s, %s, %s, %s, %s)
        RETURNING *
    """, (uid, d.get('address', ''), float(d.get('purchase_price', 0)),
          float(d.get('current_value') or d.get('purchase_price', 0)),
          float(d.get('down_payment', 0)),
          float(d.get('current_value', 0)) - (float(d.get('purchase_price', 0)) - float(d.get('down_payment', 0))),
          float(d.get('mortgage', 0))))
    prop = dict(cur.fetchone())
    conn.commit()
    cur.close()

return jsonify(prop), 201
```

@app.route(’/api/properties/<int:pid>’, methods=[‘PUT’, ‘DELETE’])
def property_detail(pid):
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM properties WHERE id=%s AND user_id=%s", (pid, uid))
    prop = cur.fetchone()
    
    if not prop:
        cur.close()
        return jsonify({'error': 'Not found'}), 404
    
    if request.method == 'DELETE':
        cur.execute("DELETE FROM properties WHERE id=%s", (pid,))
        conn.commit()
        cur.close()
        return jsonify({'ok': True})
    
    # PUT - update
    d = request.json or {}
    cur.execute("""
        UPDATE properties 
        SET address=%s, purchase_price=%s, current_value=%s, down_payment=%s, mortgage=%s
        WHERE id=%s
        RETURNING *
    """, (d.get('address', prop['address']),
          float(d.get('purchase_price', prop['purchase_price'])),
          float(d.get('current_value', prop['current_value'])),
          float(d.get('down_payment', prop['down_payment'])),
          float(d.get('mortgage', prop['mortgage'])),
          pid))
    updated = dict(cur.fetchone())
    conn.commit()
    cur.close()
    
    return jsonify(updated)
```

# ── PLAID ──────────────────────────────────────────────────────────────────────

def plaid_post(path, payload):
“”“Helper to call Plaid API”””
url = f’https://{PLAID_ENV}.plaid.com{path}’
payload[‘client_id’] = PLAID_CLIENT_ID
payload[‘secret’] = PLAID_SECRET

```
req = urllib.request.Request(url, json.dumps(payload).encode(), {'Content-Type': 'application/json'})
try:
    with urllib.request.urlopen(req, timeout=30) as resp:
        return json.loads(resp.read())
except urllib.error.HTTPError as e:
    body = e.read().decode('utf-8', 'ignore')
    raise Exception(f'Plaid {e.code}: {body[:200]}')
```

@app.route(’/api/plaid/create-link-token’, methods=[‘POST’])
def create_link_token():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
d = request.json or {}
access_token = d.get('access_token')  # For update mode

payload = {
    'user': {'client_user_id': str(uid)},
    'client_name': 'Property Pigeon',
    'products': ['transactions'],
    'country_codes': ['US'],
    'language': 'en',
}

if access_token:
    payload['access_token'] = access_token

result = plaid_post('/link/token/create', payload)
return jsonify({'link_token': result['link_token']})
```

@app.route(’/api/plaid/exchange-token’, methods=[‘POST’])
def exchange_token():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
d = request.json or {}
public_token = d.get('public_token')

result = plaid_post('/item/public_token/exchange', {'public_token': public_token})
access_token = result['access_token']
item_id = result['item_id']

inst_name = d.get('institution_name', 'Bank')
inst_id = d.get('institution_id', '')

with get_db() as conn:
    cur = conn.cursor()
    cur.execute("SELECT id FROM plaid_items WHERE item_id=%s AND user_id=%s", (item_id, uid))
    existing = cur.fetchone()
    
    if existing:
        cur.execute("UPDATE plaid_items SET access_token=%s WHERE item_id=%s", (access_token, item_id))
    else:
        cur.execute("""
            INSERT INTO plaid_items (user_id, access_token, item_id, institution_name, institution_id)
            VALUES (%s, %s, %s, %s, %s)
        """, (uid, access_token, item_id, inst_name, inst_id))
    
    conn.commit()
    cur.close()

return jsonify({'ok': True, 'item_id': item_id})
```

@app.route(’/api/plaid/accounts’)
def plaid_accounts():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM plaid_items WHERE user_id=%s", (uid,))
    items = [dict(r) for r in cur.fetchall()]
    cur.close()

results = []
for item in items:
    try:
        data = plaid_post('/accounts/balance/get', {'access_token': item['access_token']})
        results.append({
            'item_id': item['item_id'],
            'institution': item['institution_name'],
            'accounts': data.get('accounts', []),
        })
    except Exception as e:
        results.append({
            'item_id': item['item_id'],
            'institution': item['institution_name'],
            'error': str(e),
            'accounts': [],
        })

return jsonify(results)
```

@app.route(’/api/plaid/transactions/<item_id>’)
def plaid_transactions(item_id):
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT access_token FROM plaid_items WHERE item_id=%s AND user_id=%s", (item_id, uid))
    item = cur.fetchone()
    cur.close()

if not item:
    return jsonify({'error': 'Not found'}), 404

end = dt.date.today().isoformat()
start = (dt.date.today() - dt.timedelta(days=90)).isoformat()

data = plaid_post('/transactions/get', {
    'access_token': item['access_token'],
    'start_date': start,
    'end_date': end,
    'options': {'count': 500}
})

return jsonify({'transactions': data.get('transactions', [])})
```

# ── TRANSACTION CATEGORIZATION ────────────────────────────────────────────────

@app.route(’/api/plaid/categorize’, methods=[‘POST’])
def categorize_transaction():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
d = request.json or {}

with get_db() as conn:
    cur = conn.cursor()
    cur.execute("""
        INSERT INTO plaid_txn_categories 
        (user_id, txn_id, txn_name, original_category, user_category, property_id, amount, txn_date)
        VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
        ON CONFLICT (user_id, txn_id) DO UPDATE
        SET user_category=EXCLUDED.user_category, property_id=EXCLUDED.property_id
    """, (uid, d['txn_id'], d.get('txn_name'), d.get('original_category'),
          d['user_category'], d.get('property_id'), d.get('amount'), d.get('txn_date')))
    conn.commit()
    cur.close()

# Sync to properties
sync_bank_to_properties(uid)

return jsonify({'ok': True})
```

def sync_bank_to_properties(uid):
“”“Update property monthly_revenue/expenses from categorized transactions”””
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)
cur.execute(“SELECT id FROM properties WHERE user_id=%s”, (uid,))
props = [r[‘id’] for r in cur.fetchall()]

```
    start = (dt.date.today() - dt.timedelta(days=90)).isoformat()
    
    for pid in props:
        cur.execute("""
            SELECT user_category, SUM(ABS(amount)) as total
            FROM plaid_txn_categories
            WHERE user_id=%s AND property_id=%s AND txn_date >= %s
            GROUP BY user_category
        """, (uid, pid, start))
        
        cats = {r['user_category']: float(r['total']) for r in cur.fetchall()}
        
        revenue = cats.get('REVENUE', 0)
        mortgage = cats.get('MORTGAGE', 0)
        expenses = sum(cats.get(k, 0) for k in ['INSURANCE', 'HOA', 'PROPERTY_TAX', 'MAINTENANCE', 'EXPENSE'])
        
        # 90 days / 3 = monthly average
        cur.execute("""
            UPDATE properties
            SET monthly_revenue=%s, monthly_expenses=%s, mortgage=%s
            WHERE id=%s
        """, (round(revenue/3, 2), round(expenses/3, 2), round(mortgage/3, 2), pid))
    
    conn.commit()
    cur.close()
```

@app.route(’/api/plaid/categorized-transactions’)
def categorized_transactions():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("""
        SELECT * FROM plaid_txn_categories 
        WHERE user_id=%s 
        ORDER BY txn_date DESC 
        LIMIT 100
    """, (uid,))
    txns = [dict(r) for r in cur.fetchall()]
    cur.close()

return jsonify(txns)
```

# ── DASHBOARD ──────────────────────────────────────────────────────────────────

@app.route(’/api/dashboard’)
def dashboard():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM properties WHERE user_id=%s", (uid,))
    props = [dict(r) for r in cur.fetchall()]
    cur.close()

total_value = sum(float(p.get('current_value', 0)) for p in props)
total_equity = sum(float(p.get('equity', 0)) for p in props)
total_revenue = sum(float(p.get('monthly_revenue', 0)) for p in props)
total_expenses = sum(float(p.get('monthly_expenses', 0)) for p in props)
net_cf = total_revenue - total_expenses

return jsonify({
    'properties': props,
    'total_value': round(total_value, 2),
    'total_equity': round(total_equity, 2),
    'monthly_revenue': round(total_revenue, 2),
    'monthly_expenses': round(total_expenses, 2),
    'net_cashflow': round(net_cf, 2),
    'property_count': len(props),
})
```

# ── QUARTERLY ──────────────────────────────────────────────────────────────────

@app.route(’/api/quarterly’)
def quarterly():
uid = session.get(‘user_id’)
if not uid:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
with get_db() as conn:
    cur = conn.cursor(cursor_factory=RealDictCursor)
    cur.execute("SELECT * FROM properties WHERE user_id=%s", (uid,))
    props = [dict(r) for r in cur.fetchall()]
    cur.close()

total_value = sum(float(p.get('current_value', 0)) for p in props)
total_equity = sum(float(p.get('equity', 0)) for p in props)
monthly_revenue = sum(float(p.get('monthly_revenue', 0)) for p in props)
monthly_expenses = sum(float(p.get('monthly_expenses', 0)) for p in props)

today = dt.date.today()
quarter = (today.month - 1) // 3 + 1

return jsonify({
    'year': today.year,
    'quarter': quarter,
    'total_value': round(total_value, 2),
    'total_equity': round(total_equity, 2),
    'gross_revenue': round(monthly_revenue * 3, 2),
    'total_expenses': round(monthly_expenses * 3, 2),
    'net_cashflow': round((monthly_revenue - monthly_expenses) * 3, 2),
    'property_count': len(props),
})
```

# ── FRONTEND ───────────────────────────────────────────────────────────────────

HTML = ‘’’<!DOCTYPE html>

<html>
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>Property Pigeon</title>
<style>
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; background: #f5f7fa; }
.container { max-width: 1200px; margin: 0 auto; padding: 20px; }
.card { background: white; border-radius: 12px; padding: 20px; margin-bottom: 16px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
.btn { padding: 10px 20px; border: none; border-radius: 8px; cursor: pointer; font-weight: 600; font-size: 14px; }
.btn-primary { background: #2563eb; color: white; }
.btn-primary:hover { background: #1d4ed8; }
input { width: 100%; padding: 10px; border: 1.5px solid #e5e7eb; border-radius: 8px; font-size: 14px; }
input:focus { outline: none; border-color: #2563eb; }
h1 { font-size: 24px; margin-bottom: 8px; }
h2 { font-size: 20px; margin-bottom: 12px; }
h3 { font-size: 16px; margin-bottom: 10px; }
.nav { display: flex; gap: 8px; margin-bottom: 20px; border-bottom: 2px solid #e5e7eb; }
.nav-btn { padding: 12px 20px; background: none; border: none; cursor: pointer; font-weight: 600; color: #6b7280; border-bottom: 2px solid transparent; margin-bottom: -2px; }
.nav-btn.active { color: #2563eb; border-bottom-color: #2563eb; }
.stat { text-align: center; }
.stat-label { font-size: 12px; color: #6b7280; margin-bottom: 4px; }
.stat-value { font-size: 28px; font-weight: 800; color: #111827; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 16px; }
.property { display: flex; justify-content: space-between; padding: 12px 0; border-bottom: 1px solid #f3f4f6; }
.error { color: #dc2626; font-size: 14px; margin-top: 8px; }
.txn { display: flex; justify-content: space-between; padding: 10px; border-bottom: 1px solid #f3f4f6; }
.txn-cat { display: inline-block; padding: 4px 8px; border-radius: 6px; font-size: 11px; font-weight: 600; margin-top: 4px; }
</style>
</head>
<body>
<div id="root"></div>
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://cdn.plaid.com/link/v2/stable/link-initialize.js"></script>
<script>
const {useState, useEffect} = React;

function App() {
const [user, setUser] = useState(null);
const [loading, setLoading] = useState(true);
const [tab, setTab] = useState(‘dashboard’);

useEffect(() => {
fetch(’/api/me’, {credentials: ‘include’})
.then(r => r.json())
.then(d => {
if (!d.error) setUser(d);
setLoading(false);
});
}, []);

if (loading) return React.createElement(‘div’, {className: ‘container’}, ‘Loading…’);
if (!user) return React.createElement(Auth, {onAuth: setUser});

return React.createElement(‘div’, {className: ‘container’},
React.createElement(‘div’, {style: {display: ‘flex’, justifyContent: ‘space-between’, marginBottom: 20}},
React.createElement(‘h1’, null, ‘🐦 Property Pigeon’),
React.createElement(‘button’, {className: ‘btn’, onClick: () => {
fetch(’/api/logout’, {method: ‘POST’, credentials: ‘include’});
setUser(null);
}}, ‘Logout’)
),
React.createElement(‘div’, {className: ‘nav’},
React.createElement(‘button’, {className: `nav-btn ${tab==='dashboard'?'active':''}`, onClick: () => setTab(‘dashboard’)}, ‘Dashboard’),
React.createElement(‘button’, {className: `nav-btn ${tab==='bank'?'active':''}`, onClick: () => setTab(‘bank’)}, ‘Bank’),
React.createElement(‘button’, {className: `nav-btn ${tab==='analytics'?'active':''}`, onClick: () => setTab(‘analytics’)}, ‘Analytics’)
),
tab === ‘dashboard’ && React.createElement(Dashboard, {user}),
tab === ‘bank’ && React.createElement(Bank, {user}),
tab === ‘analytics’ && React.createElement(Analytics, {user})
);
}

function Auth({onAuth}) {
const [isLogin, setIsLogin] = useState(true);
const [email, setEmail] = useState(’’);
const [password, setPassword] = useState(’’);
const [error, setError] = useState(’’);

const submit = async () => {
const r = await fetch(isLogin ? ‘/api/login’ : ‘/api/register’, {
method: ‘POST’,
headers: {‘Content-Type’: ‘application/json’},
credentials: ‘include’,
body: JSON.stringify({email, password})
});
const d = await r.json();
if (d.error) setError(d.error);
else onAuth(d.user || {id: d.user_id, email});
};

return React.createElement(‘div’, {className: ‘container’, style: {maxWidth: 400, marginTop: 100}},
React.createElement(‘div’, {className: ‘card’},
React.createElement(‘h2’, null, isLogin ? ‘Login’ : ‘Register’),
React.createElement(‘input’, {placeholder: ‘Email’, value: email, onChange: e => setEmail(e.target.value), style: {marginBottom: 12}}),
React.createElement(‘input’, {type: ‘password’, placeholder: ‘Password’, value: password, onChange: e => setPassword(e.target.value), style: {marginBottom: 12}, onKeyDown: e => e.key === ‘Enter’ && submit()}),
React.createElement(‘button’, {className: ‘btn btn-primary’, onClick: submit, style: {width: ‘100%’}}, isLogin ? ‘Login’ : ‘Register’),
error && React.createElement(‘div’, {className: ‘error’}, error),
React.createElement(‘div’, {style: {marginTop: 12, textAlign: ‘center’, fontSize: 14}},
React.createElement(‘a’, {href: ‘#’, onClick: e => {e.preventDefault(); setIsLogin(!isLogin); setError(’’);}}, isLogin ? ‘Need an account?’ : ‘Have an account?’)
)
)
);
}

function Dashboard({user}) {
const [data, setData] = useState(null);
const [showAdd, setShowAdd] = useState(false);

useEffect(() => {
fetch(’/api/dashboard’, {credentials: ‘include’})
.then(r => r.json())
.then(setData);
}, [showAdd]);

if (!data) return React.createElement(‘div’, null, ‘Loading…’);

return React.createElement(‘div’, null,
React.createElement(‘div’, {className: ‘grid’, style: {marginBottom: 20}},
React.createElement(‘div’, {className: ‘card stat’},
React.createElement(‘div’, {className: ‘stat-label’}, ‘REVENUE’),
React.createElement(‘div’, {className: ‘stat-value’, style: {color: ‘#10b981’}}, ‘$’ + data.monthly_revenue.toLocaleString())
),
React.createElement(‘div’, {className: ‘card stat’},
React.createElement(‘div’, {className: ‘stat-label’}, ‘EXPENSES’),
React.createElement(‘div’, {className: ‘stat-value’, style: {color: ‘#ef4444’}}, ‘$’ + data.monthly_expenses.toLocaleString())
),
React.createElement(‘div’, {className: ‘card stat’},
React.createElement(‘div’, {className: ‘stat-label’}, ‘NET CF’),
React.createElement(‘div’, {className: ‘stat-value’}, ‘$’ + data.net_cashflow.toLocaleString())
)
),

```
React.createElement('div', {className: 'card'},
  React.createElement('div', {style: {display: 'flex', justifyContent: 'space-between', marginBottom: 16}},
    React.createElement('h3', null, 'Properties'),
    React.createElement('button', {className: 'btn btn-primary', onClick: () => setShowAdd(!showAdd)}, showAdd ? 'Cancel' : '+ Add')
  ),
  
  showAdd && React.createElement(AddProperty, {onAdd: () => setShowAdd(false)}),
  
  data.properties.map(p => React.createElement('div', {key: p.id, className: 'property'},
    React.createElement('div', null,
      React.createElement('div', {style: {fontWeight: 600}}, p.address),
      React.createElement('div', {style: {fontSize: 12, color: '#6b7280'}}, 
        'Rev: $' + (p.monthly_revenue || 0).toLocaleString() + ' | Exp: $' + (p.monthly_expenses || 0).toLocaleString()
      )
    ),
    React.createElement('div', {style: {fontWeight: 700}}, '$' + p.current_value.toLocaleString())
  ))
)
```

);
}

function AddProperty({onAdd}) {
const [form, setForm] = useState({address: ‘’, purchase_price: ‘’, current_value: ‘’, down_payment: ‘’, mortgage: ‘’});

const save = async () => {
await fetch(’/api/properties’, {
method: ‘POST’,
headers: {‘Content-Type’: ‘application/json’},
credentials: ‘include’,
body: JSON.stringify(form)
});
onAdd();
};

return React.createElement(‘div’, {style: {padding: 16, background: ‘#f9fafb’, borderRadius: 8, marginBottom: 16}},
React.createElement(‘input’, {placeholder: ‘Address’, value: form.address, onChange: e => setForm({…form, address: e.target.value}), style: {marginBottom: 8}}),
React.createElement(‘input’, {placeholder: ‘Purchase Price’, type: ‘number’, value: form.purchase_price, onChange: e => setForm({…form, purchase_price: e.target.value, current_value: e.target.value}), style: {marginBottom: 8}}),
React.createElement(‘input’, {placeholder: ‘Down Payment’, type: ‘number’, value: form.down_payment, onChange: e => setForm({…form, down_payment: e.target.value}), style: {marginBottom: 8}}),
React.createElement(‘input’, {placeholder: ‘Monthly Mortgage’, type: ‘number’, value: form.mortgage, onChange: e => setForm({…form, mortgage: e.target.value}), style: {marginBottom: 8}}),
React.createElement(‘button’, {className: ‘btn btn-primary’, onClick: save}, ‘Save’)
);
}

function Bank({user}) {
const [items, setItems] = useState([]);
const [txns, setTxns] = useState([]);
const [props, setProps] = useState([]);
const [selectedItem, setSelectedItem] = useState(null);

useEffect(() => {
fetch(’/api/plaid/accounts’, {credentials: ‘include’})
.then(r => r.json())
.then(setItems);
fetch(’/api/properties’, {credentials: ‘include’})
.then(r => r.json())
.then(setProps);
}, []);

const connectBank = async () => {
const r = await fetch(’/api/plaid/create-link-token’, {method: ‘POST’, credentials: ‘include’});
const {link_token} = await r.json();

```
const handler = Plaid.create({
  token: link_token,
  onSuccess: async (public_token, metadata) => {
    await fetch('/api/plaid/exchange-token', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      credentials: 'include',
      body: JSON.stringify({public_token, institution_name: metadata.institution.name, institution_id: metadata.institution.institution_id})
    });
    window.location.reload();
  }
});
handler.open();
```

};

const loadTxns = async (item_id) => {
setSelectedItem(item_id);
const r = await fetch(`/api/plaid/transactions/${item_id}`, {credentials: ‘include’});
const d = await r.json();
setTxns(d.transactions || []);
};

const categorize = async (txn, category, property_id) => {
await fetch(’/api/plaid/categorize’, {
method: ‘POST’,
headers: {‘Content-Type’: ‘application/json’},
credentials: ‘include’,
body: JSON.stringify({
txn_id: txn.transaction_id,
txn_name: txn.name,
original_category: txn.category ? txn.category[0] : ‘’,
user_category: category,
property_id,
amount: txn.amount,
txn_date: txn.date
})
});
alert(‘Categorized! Properties updated.’);
};

return React.createElement(‘div’, null,
React.createElement(‘div’, {className: ‘card’},
React.createElement(‘h3’, null, ‘Connected Banks’),
React.createElement(‘button’, {className: ‘btn btn-primary’, onClick: connectBank, style: {marginTop: 12}}, ‘+ Connect Bank’),
items.map(item => React.createElement(‘div’, {key: item.item_id, style: {marginTop: 16}},
React.createElement(‘div’, {style: {fontWeight: 600, marginBottom: 8}}, item.institution),
item.error && React.createElement(‘div’, {className: ‘error’}, item.error),
!item.error && React.createElement(‘button’, {className: ‘btn’, onClick: () => loadTxns(item.item_id)}, ‘View Transactions’)
))
),

```
selectedItem && React.createElement('div', {className: 'card'},
  React.createElement('h3', null, 'Transactions (Last 90 Days)'),
  txns.map(t => React.createElement(Transaction, {key: t.transaction_id, txn: t, props, onCategorize: categorize}))
)
```

);
}

function Transaction({txn, props, onCategorize}) {
const [cat, setCat] = useState(’’);
const [prop, setProp] = useState(’’);

return React.createElement(‘div’, {className: ‘txn’},
React.createElement(‘div’, {style: {flex: 1}},
React.createElement(‘div’, {style: {fontWeight: 600}}, txn.name),
React.createElement(‘div’, {style: {fontSize: 12, color: ‘#6b7280’}}, txn.date),
React.createElement(‘div’, {style: {marginTop: 8}},
React.createElement(‘select’, {value: cat, onChange: e => setCat(e.target.value), style: {marginRight: 8, padding: ‘4px 8px’}},
React.createElement(‘option’, {value: ‘’}, ‘Category…’),
React.createElement(‘option’, {value: ‘REVENUE’}, ‘Revenue’),
React.createElement(‘option’, {value: ‘MORTGAGE’}, ‘Mortgage’),
React.createElement(‘option’, {value: ‘INSURANCE’}, ‘Insurance’),
React.createElement(‘option’, {value: ‘HOA’}, ‘HOA’),
React.createElement(‘option’, {value: ‘PROPERTY_TAX’}, ‘Property Tax’),
React.createElement(‘option’, {value: ‘MAINTENANCE’}, ‘Maintenance’),
React.createElement(‘option’, {value: ‘EXPENSE’}, ‘Expense’),
React.createElement(‘option’, {value: ‘INTERNAL_TRANSFER’}, ‘Internal Transfer’)
),
cat && React.createElement(‘select’, {value: prop, onChange: e => setProp(e.target.value), style: {marginRight: 8, padding: ‘4px 8px’}},
React.createElement(‘option’, {value: ‘’}, ‘Property…’),
props.map(p => React.createElement(‘option’, {key: p.id, value: p.id}, p.address))
),
cat && React.createElement(‘button’, {className: ‘btn btn-primary’, onClick: () => onCategorize(txn, cat, prop || null)}, ‘Save’)
)
),
React.createElement(‘div’, {style: {fontWeight: 700, color: txn.amount < 0 ? ‘#10b981’ : ‘#000’}},
(txn.amount < 0 ? ‘+’ : ‘-’) + ‘$’ + Math.abs(txn.amount).toFixed(2)
)
);
}

function Analytics({user}) {
const [data, setData] = useState(null);

useEffect(() => {
fetch(’/api/quarterly’, {credentials: ‘include’})
.then(r => r.json())
.then(setData);
}, []);

if (!data) return React.createElement(‘div’, null, ‘Loading…’);

return React.createElement(‘div’, null,
React.createElement(‘div’, {className: ‘card’},
React.createElement(‘h3’, null, `Q${data.quarter} ${data.year} Results`),
React.createElement(‘div’, {className: ‘grid’, style: {marginTop: 16}},
React.createElement(‘div’, {className: ‘stat’},
React.createElement(‘div’, {className: ‘stat-label’}, ‘REVENUE’),
React.createElement(‘div’, {className: ‘stat-value’, style: {fontSize: 20, color: ‘#10b981’}}, ‘$’ + data.gross_revenue.toLocaleString())
),
React.createElement(‘div’, {className: ‘stat’},
React.createElement(‘div’, {className: ‘stat-label’}, ‘EXPENSES’),
React.createElement(‘div’, {className: ‘stat-value’, style: {fontSize: 20, color: ‘#ef4444’}}, ‘$’ + data.total_expenses.toLocaleString())
),
React.createElement(‘div’, {className: ‘stat’},
React.createElement(‘div’, {className: ‘stat-label’}, ‘NET CF’),
React.createElement(‘div’, {className: ‘stat-value’, style: {fontSize: 20}}, ‘$’ + data.net_cashflow.toLocaleString())
),
React.createElement(‘div’, {className: ‘stat’},
React.createElement(‘div’, {className: ‘stat-label’}, ‘PORTFOLIO’),
React.createElement(‘div’, {className: ‘stat-value’, style: {fontSize: 20}}, ‘$’ + data.total_value.toLocaleString())
)
)
),

```
React.createElement('div', {className: 'card'},
  React.createElement('h3', null, 'Projections'),
  React.createElement('div', {style: {color: '#6b7280', fontSize: 14}}, 'Coming soon: 30-year forecasts based on your actual bank data')
)
```

);
}

ReactDOM.render(React.createElement(App), document.getElementById(‘root’));
</script>

</body>
</html>
'''

@app.route(’/’)
def index():
return HTML

if **name** == ‘**main**’:
port = int(os.environ.get(‘PORT’, 5000))
app.run(host=‘0.0.0.0’, port=port)
