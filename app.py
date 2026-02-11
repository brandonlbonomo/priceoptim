from flask import Flask, jsonify, request, session
from flask_cors import CORS
import os, hashlib, secrets, json
from datetime import datetime
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app, supports_credentials=True)

DATABASE_URL = os.environ.get('DATABASE_URL', 'postgresql://localhost/propertypigeon')
PLAID_CLIENT_ID = os.environ.get('PLAID_CLIENT_ID', '')
PLAID_SECRET = os.environ.get('PLAID_SECRET', '')
PLAID_ENV = os.environ.get('PLAID_ENV', 'sandbox')

@contextmanager
def get_db():
    conn = psycopg2.connect(DATABASE_URL)
    try:
        yield conn
    finally:
        conn.close()

def init_db():
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id SERIAL PRIMARY KEY,
                username VARCHAR(50) UNIQUE NOT NULL,
                email VARCHAR(255) UNIQUE NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                full_name VARCHAR(100),
                portfolio_name VARCHAR(100) NOT NULL,
                ticker VARCHAR(10) UNIQUE,
                bio TEXT DEFAULT '',
                location VARCHAR(100) DEFAULT '',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS properties (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                location VARCHAR(100),
                purchase_price DECIMAL(12,2) DEFAULT 0,
                down_payment DECIMAL(12,2) DEFAULT 0,
                equity DECIMAL(12,2) DEFAULT 0,
                mortgage DECIMAL(10,2) DEFAULT 0,
                insurance DECIMAL(10,2) DEFAULT 0,
                hoa DECIMAL(10,2) DEFAULT 0,
                property_tax DECIMAL(10,2) DEFAULT 0,
                monthly_revenue DECIMAL(10,2) DEFAULT 0,
                monthly_expenses DECIMAL(10,2) DEFAULT 0,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS follows (
                follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                PRIMARY KEY (follower_id, following_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS feed_items (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                type VARCHAR(50) NOT NULL,
                content JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS portfolio_metrics (
                user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
                health_score INTEGER DEFAULT 0,
                share_price DECIMAL(10,2) DEFAULT 0,
                total_equity DECIMAL(12,2) DEFAULT 0,
                annual_cashflow DECIMAL(12,2) DEFAULT 0,
                property_count INTEGER DEFAULT 0,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS plaid_items (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                access_token VARCHAR(255),
                item_id VARCHAR(255),
                institution_name VARCHAR(100),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        conn.commit()
        cur.close()

def hash_password(password):
    salt = secrets.token_hex(16)
    h = hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000)
    return salt + '$' + h.hex()

def verify_password(password, stored):
    try:
        salt, h = stored.split('$', 1)
        return hashlib.pbkdf2_hmac('sha256', password.encode(), salt.encode(), 100000).hex() == h
    except Exception:
        return False

def generate_ticker(name):
    words = name.upper().replace("'S","").replace("'","").replace("-"," ").split()
    if not words:
        return 'XXXX'
    if len(words) == 1:
        return words[0][:4].ljust(4,'X')
    return ''.join(w[0] for w in words[:4]).ljust(4,'X')

def calculate_health_score(m):
    if not m or m.get('property_count', 0) == 0:
        return 0
    financial = min(40, min(15, m.get('dscr',0)*10) + min(15, m.get('coc_return',0)/2) + min(10, m.get('equity_ratio',0)*10))
    performance = min(30, min(15, m.get('avg_occupancy',0)*0.3) + min(10, m.get('revenue_growth',0)*50) + min(5, m.get('profit_margin',0)*0.5))
    risk = min(10, m.get('property_count',0)*1.5) + min(5, m.get('cash_reserves',0)/10000) + max(0, 5 - m.get('debt_ratio',0)*5)
    growth = min(10, m.get('growth_rate',0)*2.5 + m.get('momentum',0)*2.5)
    return min(100, max(0, round(financial + performance + risk + growth)))

def calculate_share_price(m):
    p = (m.get('total_equity',0)/1000)*0.4 + (m.get('annual_cashflow',0)*2)*0.3 + (m.get('health_score',0)*5)*0.2 + (m.get('property_count',0)*10)*0.1
    return round(max(1, p), 2)

def update_metrics(user_id):
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT COUNT(*) as pc, COALESCE(SUM(equity),0) as eq,
                   COALESCE(SUM(monthly_revenue),0) as rev, COALESCE(SUM(monthly_expenses),0) as exp
            FROM properties WHERE user_id=%s
        """, (user_id,))
        d = cur.fetchone()
        inc = float(d['rev'] or 0)
        exp = float(d['exp'] or 0)
        acf = (inc - exp) * 12
        m = {
            'property_count': d['pc'], 'total_equity': float(d['eq'] or 0),
            'annual_cashflow': acf, 'dscr': inc/exp if exp > 0 else 1.45,
            'coc_return': 15.5, 'equity_ratio': 0.35, 'avg_occupancy': 78,
            'revenue_growth': 0.125, 'profit_margin': ((inc-exp)/inc*100) if inc > 0 else 35,
            'cash_reserves': 50000, 'debt_ratio': 0.65, 'growth_rate': 2.1, 'momentum': 3.2
        }
        hs = calculate_health_score(m)
        m['health_score'] = hs
        sp = calculate_share_price(m)
        cur.execute("""
            INSERT INTO portfolio_metrics (user_id,health_score,share_price,total_equity,annual_cashflow,property_count,updated_at)
            VALUES (%s,%s,%s,%s,%s,%s,CURRENT_TIMESTAMP)
            ON CONFLICT (user_id) DO UPDATE SET
                health_score=EXCLUDED.health_score, share_price=EXCLUDED.share_price,
                total_equity=EXCLUDED.total_equity, annual_cashflow=EXCLUDED.annual_cashflow,
                property_count=EXCLUDED.property_count, updated_at=CURRENT_TIMESTAMP
        """, (user_id, hs, sp, m['total_equity'], acf, d['pc']))
        conn.commit()
        cur.close()
        return m

try:
    init_db()
except Exception as e:
    print('DB init error:', e)


HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Property Pigeon</title>
<script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600;700&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --blue:#1a56db; --blue-light:#e8f0fe; --green:#0a9162; --green-light:#e6f4f1;
  --red:#d92d20; --red-light:#fef3f2; --gray-50:#f9fafb; --gray-100:#f3f4f6;
  --gray-200:#e5e7eb; --gray-300:#d1d5db; --gray-500:#6b7280; --gray-700:#374151;
  --gray-900:#111827; --white:#ffffff;
}
* { margin:0; padding:0; box-sizing:border-box; }
body { font-family:'DM Sans',sans-serif; background:#f9fafb; color:#111827; min-height:100vh; }

/* AUTH */
.auth-wrap { min-height:100vh; display:flex; }
.auth-left { flex:1; background:#1a56db; display:flex; align-items:center; justify-content:center; padding:60px; }
.auth-left-content h1 { font-size:42px; font-weight:700; color:#fff; margin-bottom:16px; letter-spacing:-1px; }
.auth-left-content p { font-size:18px; color:rgba(255,255,255,0.75); line-height:1.6; max-width:360px; }
.auth-right { width:480px; background:#fff; display:flex; align-items:center; justify-content:center; padding:60px 48px; }
.auth-form-wrap { width:100%; }
.auth-logo { font-size:22px; font-weight:700; color:#1a56db; margin-bottom:40px; letter-spacing:-0.5px; }
.auth-title { font-size:26px; font-weight:700; margin-bottom:6px; letter-spacing:-0.5px; }
.auth-sub { font-size:14px; color:#6b7280; margin-bottom:32px; }
.field { margin-bottom:18px; }
.field label { display:block; font-size:13px; font-weight:600; color:#374151; margin-bottom:6px; }
.field input { width:100%; padding:11px 14px; border:1.5px solid #e5e7eb; border-radius:8px; font-size:14px; font-family:inherit; color:#111827; transition:border-color 0.15s; }
.field input:focus { outline:none; border-color:#1a56db; }
.field-row { display:grid; grid-template-columns:1fr 1fr; gap:12px; }
.btn-primary { width:100%; padding:12px; background:#1a56db; color:#fff; border:none; border-radius:8px; font-size:14px; font-weight:600; cursor:pointer; font-family:inherit; transition:background 0.15s; margin-bottom:12px; }
.btn-primary:hover { background:#1648c0; }
.btn-ghost { width:100%; padding:12px; background:transparent; color:#6b7280; border:1.5px solid #e5e7eb; border-radius:8px; font-size:14px; font-weight:500; cursor:pointer; font-family:inherit; }
.btn-ghost:hover { border-color:#d1d5db; color:#374151; }
.err { background:#fef2f2; color:#991b1b; padding:10px 14px; border-radius:8px; font-size:13px; margin-bottom:16px; border:1px solid #fee2e2; }

/* APP SHELL */
.shell { display:flex; height:100vh; overflow:hidden; }
.sidebar { width:220px; background:#fff; border-right:1px solid #e5e7eb; display:flex; flex-direction:column; padding:0; flex-shrink:0; }
.sidebar-logo { padding:24px 20px 20px; font-size:18px; font-weight:700; color:#1a56db; letter-spacing:-0.5px; border-bottom:1px solid #f3f4f6; }
.nav { padding:12px 0; flex:1; }
.nav-item { display:flex; align-items:center; gap:10px; padding:10px 20px; font-size:14px; font-weight:500; color:#6b7280; cursor:pointer; transition:all 0.15s; border-left:3px solid transparent; }
.nav-item:hover { background:#f9fafb; color:#111827; }
.nav-item.active { background:#eff6ff; color:#1a56db; border-left-color:#1a56db; font-weight:600; }
.nav-icon { width:18px; height:18px; opacity:0.7; }
.nav-item.active .nav-icon { opacity:1; }
.sidebar-footer { padding:16px 20px; border-top:1px solid #f3f4f6; }
.user-chip { display:flex; align-items:center; gap:10px; }
.user-avatar { width:32px; height:32px; border-radius:50%; background:#1a56db; display:flex; align-items:center; justify-content:center; font-size:13px; font-weight:700; color:#fff; flex-shrink:0; }
.user-name { font-size:13px; font-weight:600; color:#111827; }
.user-handle { font-size:12px; color:#9ca3af; }
.signout { margin-top:8px; width:100%; padding:8px; background:transparent; border:1px solid #e5e7eb; border-radius:6px; font-size:12px; color:#6b7280; cursor:pointer; font-family:inherit; }
.signout:hover { background:#f9fafb; }

/* MAIN CONTENT */
.content { flex:1; overflow-y:auto; background:#f9fafb; }
.page { padding:32px; max-width:1100px; }
.page-header { margin-bottom:28px; }
.page-title { font-size:24px; font-weight:700; letter-spacing:-0.5px; margin-bottom:4px; }
.page-sub { font-size:14px; color:#6b7280; }

/* CARDS */
.card { background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:24px; }
.card + .card { margin-top:16px; }
.card-sm { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:18px; }
.card-label { font-size:12px; font-weight:600; color:#9ca3af; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:10px; }
.big-val { font-size:36px; font-weight:700; letter-spacing:-1px; line-height:1; margin-bottom:6px; }
.change { display:inline-flex; align-items:center; gap:4px; font-size:13px; font-weight:600; padding:3px 8px; border-radius:20px; }
.change.up { background:#ecfdf5; color:#065f46; }
.change.down { background:#fef2f2; color:#991b1b; }
.grid2 { display:grid; grid-template-columns:1fr 1fr; gap:14px; }
.grid3 { display:grid; grid-template-columns:1fr 1fr 1fr; gap:14px; }
.grid4 { display:grid; grid-template-columns:1fr 1fr 1fr 1fr; gap:14px; }

/* HERO CARD */
.hero-card { background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:28px; margin-bottom:16px; }
.hero-top { display:flex; align-items:flex-start; justify-content:space-between; margin-bottom:20px; }
.ticker-badge { font-family:'DM Mono',monospace; font-size:13px; font-weight:500; color:#1a56db; background:#eff6ff; padding:4px 10px; border-radius:6px; border:1px solid #bfdbfe; }
.health-ring { position:relative; width:80px; height:80px; }
.health-ring-num { position:absolute; top:50%; left:50%; transform:translate(-50%,-50%); font-size:20px; font-weight:700; }
.chart-area { height:160px; position:relative; margin:16px 0 10px; }
.time-row { display:flex; gap:4px; }
.time-btn { padding:5px 12px; border-radius:6px; background:transparent; border:none; font-size:13px; font-weight:500; color:#9ca3af; cursor:pointer; font-family:inherit; }
.time-btn.active { background:#f3f4f6; color:#111827; }

/* STAT CARDS */
.stat-card { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:18px; }
.stat-label { font-size:12px; font-weight:600; color:#9ca3af; text-transform:uppercase; letter-spacing:0.5px; margin-bottom:8px; }
.stat-val { font-size:24px; font-weight:700; letter-spacing:-0.5px; }
.stat-change { font-size:12px; color:#0a9162; margin-top:4px; }

/* DISCOVER / SEARCH */
.search-wrap { position:relative; margin-bottom:20px; }
.search-input { width:100%; padding:11px 14px 11px 40px; border:1.5px solid #e5e7eb; border-radius:8px; font-size:14px; font-family:inherit; background:#fff; }
.search-input:focus { outline:none; border-color:#1a56db; }
.search-icon { position:absolute; left:13px; top:50%; transform:translateY(-50%); color:#9ca3af; }
.investor-row { display:flex; align-items:center; gap:14px; padding:16px 20px; background:#fff; border:1px solid #e5e7eb; border-radius:10px; margin-bottom:8px; transition:border-color 0.15s; }
.investor-row:hover { border-color:#d1d5db; }
.inv-avatar { width:44px; height:44px; border-radius:50%; background:#1a56db; display:flex; align-items:center; justify-content:center; font-size:16px; font-weight:700; color:#fff; flex-shrink:0; }
.inv-info { flex:1; }
.inv-name { font-size:15px; font-weight:600; margin-bottom:2px; }
.inv-meta { font-size:13px; color:#6b7280; }
.inv-ticker { font-family:'DM Mono',monospace; font-size:12px; color:#1a56db; background:#eff6ff; padding:2px 7px; border-radius:4px; }
.btn-follow { padding:7px 18px; border-radius:20px; border:1.5px solid #1a56db; background:transparent; color:#1a56db; font-size:13px; font-weight:600; cursor:pointer; font-family:inherit; transition:all 0.15s; white-space:nowrap; }
.btn-follow:hover { background:#1a56db; color:#fff; }
.btn-following { border-color:#e5e7eb; color:#6b7280; }
.btn-following:hover { background:#f3f4f6; border-color:#d1d5db; color:#374151; }

/* FEED */
.feed-item { background:#fff; border:1px solid #e5e7eb; border-radius:10px; padding:18px 20px; margin-bottom:10px; }
.feed-header { display:flex; align-items:center; gap:12px; margin-bottom:12px; }
.feed-av { width:36px; height:36px; border-radius:50%; background:#111827; display:flex; align-items:center; justify-content:center; font-size:13px; font-weight:700; color:#fff; flex-shrink:0; }
.feed-name { font-size:14px; font-weight:600; }
.feed-time { font-size:12px; color:#9ca3af; }
.feed-body { font-size:14px; color:#374151; line-height:1.5; }
.feed-pill { display:inline-block; margin-top:10px; padding:6px 12px; background:#f3f4f6; border-radius:6px; font-size:13px; font-weight:500; color:#374151; }

/* PROPERTIES */
.prop-row { display:flex; align-items:center; gap:14px; padding:14px 0; border-bottom:1px solid #f3f4f6; }
.prop-row:last-child { border-bottom:none; }
.prop-icon { width:40px; height:40px; border-radius:8px; background:#f3f4f6; display:flex; align-items:center; justify-content:center; flex-shrink:0; }
.prop-name { font-size:14px; font-weight:600; }
.prop-loc { font-size:13px; color:#9ca3af; }
.prop-amount { font-size:15px; font-weight:700; text-align:right; }
.prop-equity { font-size:12px; color:#0a9162; text-align:right; }
.add-btn { display:flex; align-items:center; gap:6px; padding:9px 18px; background:#1a56db; color:#fff; border:none; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; font-family:inherit; }
.add-btn:hover { background:#1648c0; }

/* PLAID BANNER */
.plaid-banner { background:#eff6ff; border:1px solid #bfdbfe; border-radius:10px; padding:16px 20px; margin-bottom:16px; display:flex; align-items:center; justify-content:space-between; gap:16px; }
.plaid-text h4 { font-size:14px; font-weight:600; color:#1e40af; margin-bottom:2px; }
.plaid-text p { font-size:13px; color:#3b82f6; }
.plaid-btn { padding:8px 18px; background:#1a56db; color:#fff; border:none; border-radius:8px; font-size:13px; font-weight:600; cursor:pointer; font-family:inherit; white-space:nowrap; }

/* MODAL */
.overlay { position:fixed; top:0; left:0; right:0; bottom:0; background:rgba(0,0,0,0.4); z-index:100; display:flex; align-items:flex-end; justify-content:center; }
.modal { background:#fff; border-radius:16px 16px 0 0; width:100%; max-width:560px; max-height:90vh; overflow-y:auto; padding:28px 24px; }
.modal-title { font-size:18px; font-weight:700; letter-spacing:-0.3px; margin-bottom:24px; }
.modal-footer { display:flex; gap:10px; margin-top:24px; }
.modal-footer button { flex:1; padding:11px; border-radius:8px; font-size:14px; font-weight:600; cursor:pointer; font-family:inherit; border:none; }
.btn-cancel { background:#f3f4f6; color:#374151; }
.btn-save { background:#1a56db; color:#fff; }

/* SECTION HEAD */
.sec-head { display:flex; align-items:center; justify-content:space-between; margin-bottom:16px; }
.sec-title { font-size:15px; font-weight:700; color:#374151; }
.sec-link { font-size:13px; color:#1a56db; cursor:pointer; }

/* EMPTY */
.empty { text-align:center; padding:48px 24px; color:#9ca3af; }
.empty-title { font-size:15px; font-weight:600; color:#374151; margin-bottom:6px; }
.empty-sub { font-size:13px; margin-bottom:20px; }

/* PROFILE */
.profile-card { background:#fff; border:1px solid #e5e7eb; border-radius:12px; padding:32px; text-align:center; margin-bottom:16px; }
.profile-av { width:72px; height:72px; border-radius:50%; background:#1a56db; display:flex; align-items:center; justify-content:center; font-size:26px; font-weight:700; color:#fff; margin:0 auto 16px; }
.profile-name { font-size:22px; font-weight:700; letter-spacing:-0.3px; margin-bottom:4px; }
.profile-handle { font-size:14px; color:#6b7280; margin-bottom:8px; }
.profile-bio { font-size:14px; color:#374151; margin-bottom:16px; }
.profile-stats { display:flex; justify-content:center; gap:32px; }
.profile-stat-num { font-size:20px; font-weight:700; }
.profile-stat-label { font-size:12px; color:#9ca3af; }

/* CASHFLOW */
.cf-row { display:flex; justify-content:space-between; padding:12px 0; border-bottom:1px solid #f3f4f6; }
.cf-row:last-child { border-bottom:none; }
.cf-label { font-size:14px; color:#374151; }
.cf-val { font-size:14px; font-weight:600; }
.cf-val.pos { color:#065f46; }
.cf-val.neg { color:#991b1b; }
</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const {useState,useEffect,useRef} = React;

function App() {
  const [auth,setAuth]=useState(false);
  const [user,setUser]=useState(null);
  const [loading,setLoading]=useState(true);
  useEffect(()=>{
    fetch('/api/auth/me',{credentials:'include'})
      .then(r=>r.ok?r.json():null)
      .then(u=>{ if(u&&u.id){setUser(u);setAuth(true);} })
      .catch(()=>{}).finally(()=>setLoading(false));
  },[]);
  if(loading) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'100vh',color:'#6b7280',fontSize:14}}>Loading...</div>;
  if(!auth) return <AuthScreen onLogin={u=>{setUser(u);setAuth(true);}}/>;
  return <MainApp user={user} onLogout={()=>{setAuth(false);setUser(null);}}/>;
}

function AuthScreen({onLogin}) {
  const [mode,setMode]=useState('login');
  const [err,setErr]=useState('');
  const [f,setF]=useState({username:'',email:'',password:'',full_name:'',portfolio_name:''});
  const submit=async e=>{
    e.preventDefault(); setErr('');
    try {
      const r=await fetch(mode==='login'?'/api/auth/login':'/api/auth/signup',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(r.ok) onLogin(d.user); else setErr(d.error||'Something went wrong');
    } catch(e){setErr('Network error');}
  };
  return (
    <div className="auth-wrap">
      <div className="auth-left">
        <div className="auth-left-content">
          <h1>Property Pigeon</h1>
          <p>The social investment network for real estate investors. Track portfolios, discover opportunities, connect with top performers.</p>
        </div>
      </div>
      <div className="auth-right">
        <div className="auth-form-wrap">
          <div className="auth-logo">Property Pigeon</div>
          <h2 className="auth-title">{mode==='login'?'Welcome back':'Create account'}</h2>
          <p className="auth-sub">{mode==='login'?'Sign in to your account':'Join the network of real estate investors'}</p>
          {err&&<div className="err">{err}</div>}
          <form onSubmit={submit}>
            {mode==='signup'&&<>
              <div className="field"><label>Full name</label><input value={f.full_name} onChange={e=>setF({...f,full_name:e.target.value})} placeholder="Brandon Bonomo" required/></div>
              <div className="field"><label>Portfolio name</label><input value={f.portfolio_name} onChange={e=>setF({...f,portfolio_name:e.target.value})} placeholder="Brandon's Empire" required/></div>
            </>}
            <div className="field"><label>{mode==='login'?'Username or email':'Username'}</label><input value={f.username} onChange={e=>setF({...f,username:e.target.value})} placeholder="brandonb" required/></div>
            {mode==='signup'&&<div className="field"><label>Email</label><input type="email" value={f.email} onChange={e=>setF({...f,email:e.target.value})} placeholder="brandon@email.com" required/></div>}
            <div className="field"><label>Password</label><input type="password" value={f.password} onChange={e=>setF({...f,password:e.target.value})} required/></div>
            <button type="submit" className="btn-primary">{mode==='login'?'Sign in':'Create account'}</button>
            <button type="button" className="btn-ghost" onClick={()=>setMode(mode==='login'?'signup':'login')}>{mode==='login'?'New? Create an account':'Have an account? Sign in'}</button>
          </form>
        </div>
      </div>
    </div>
  );
}

function MainApp({user,onLogout}) {
  const [tab,setTab]=useState('portfolio');
  const [portfolio,setPortfolio]=useState(null);
  const [users,setUsers]=useState([]);
  const [following,setFollowing]=useState(new Set());
  const [feed,setFeed]=useState([]);
  const [properties,setProperties]=useState([]);
  const [showAddProp,setShowAddProp]=useState(false);
  const [showPlaid,setShowPlaid]=useState(false);

  useEffect(()=>{loadAll();},[]);

  const loadAll=async()=>{
    try {
      const [pR,uR,fR,fdR,prR]=await Promise.all([
        fetch('/api/portfolio/'+user.id,{credentials:'include'}),
        fetch('/api/users/discover',{credentials:'include'}),
        fetch('/api/following',{credentials:'include'}),
        fetch('/api/feed',{credentials:'include'}),
        fetch('/api/properties/'+user.id,{credentials:'include'})
      ]);
      const [p,u,f,fd,pr]=await Promise.all([pR.json(),uR.json(),fR.json(),fdR.json(),prR.json()]);
      setPortfolio(p); setUsers(u);
      setFollowing(new Set(f.map(x=>x.following_id)));
      setFeed(fd); setProperties(pr);
    } catch(e){console.error(e);}
  };

  const logout=async()=>{ await fetch('/api/auth/logout',{method:'POST',credentials:'include'}); onLogout(); };
  const initials=name=>(name||'').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()||'U';

  const navItems=[
    {id:'portfolio',label:'Portfolio',icon:'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6'},
    {id:'cashflow',label:'Cash flow',icon:'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z'},
    {id:'discover',label:'Discover',icon:'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'},
    {id:'feed',label:'Feed',icon:'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z'},
    {id:'profile',label:'Profile',icon:'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z'},
  ];

  return (
    <div className="shell">
      <div className="sidebar">
        <div className="sidebar-logo">Property Pigeon</div>
        <div className="nav">
          {navItems.map(n=>(
            <div key={n.id} className={'nav-item'+(tab===n.id?' active':'')} onClick={()=>setTab(n.id)}>
              <svg className="nav-icon" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d={n.icon}/></svg>
              {n.label}
            </div>
          ))}
        </div>
        <div className="sidebar-footer">
          <div className="user-chip">
            <div className="user-avatar">{initials(user.full_name)}</div>
            <div><div className="user-name">{user.full_name}</div><div className="user-handle">@{user.username}</div></div>
          </div>
          <button className="signout" onClick={logout}>Sign out</button>
        </div>
      </div>
      <div className="content">
        {tab==='portfolio'&&<PortfolioTab portfolio={portfolio} properties={properties} onAddProp={()=>setShowAddProp(true)} onConnectBank={()=>setShowPlaid(true)}/>}
        {tab==='cashflow'&&<CashflowTab portfolio={portfolio} properties={properties}/>}
        {tab==='discover'&&<DiscoverTab users={users} following={following} onRefresh={loadAll}/>}
        {tab==='feed'&&<FeedTab feed={feed}/>}
        {tab==='profile'&&<ProfileTab user={user} portfolio={portfolio}/>}
      </div>
      {showAddProp&&<AddPropModal userId={user.id} onClose={()=>setShowAddProp(false)} onSave={()=>{setShowAddProp(false);loadAll();}}/>}
      {showPlaid&&<PlaidModal onClose={()=>setShowPlaid(false)}/>}
    </div>
  );
}

function PortfolioTab({portfolio,properties,onAddProp,onConnectBank}) {
  const chartRef=useRef(null); const ci=useRef(null); const [tf,setTf]=useState('3M');
  useEffect(()=>{
    if(!chartRef.current) return;
    if(ci.current) ci.current.destroy();
    const pts=tf==='1W'?7:tf==='1M'?30:tf==='YTD'?60:tf==='1Y'?365:90;
    const base=portfolio?parseFloat(portfolio.share_price)||100:100;
    const data=Array.from({length:pts},(_,i)=>+(base+(Math.random()*20-8)*(1+i/pts)).toFixed(2));
    ci.current=new Chart(chartRef.current.getContext('2d'),{
      type:'line',
      data:{labels:Array(pts).fill(''),datasets:[{data,borderColor:'#1a56db',borderWidth:2,fill:true,backgroundColor:'rgba(26,86,219,0.06)',tension:0.4,pointRadius:0}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{display:false},y:{display:false}}}
    });
    return ()=>{if(ci.current)ci.current.destroy();};
  },[portfolio,tf]);

  if(!portfolio) return <div className="page"><div className="page-header"><div className="page-title">Portfolio</div></div><div style={{color:'#9ca3af',fontSize:14}}>Loading...</div></div>;

  const hs=portfolio.health_score||0;
  const tier=hs>=90?'Elite':hs>=75?'Strong':hs>=60?'Good':'Growing';
  const tierColor=hs>=90?'#d97706':hs>=75?'#059669':hs>=60?'#1a56db':'#6b7280';
  const circ=2*Math.PI*34;

  return (
    <div className="page">
      <div className="page-header">
        <div className="page-title">Your Portfolio</div>
        <div className="page-sub">{portfolio.ticker?'$'+portfolio.ticker:''} &bull; Updated just now</div>
      </div>

      <div style={{marginBottom:16}}>
        <div className="plaid-banner">
          <div className="plaid-text">
            <h4>Connect your bank accounts</h4>
            <p>Import transactions and auto-track income with Plaid</p>
          </div>
          <button className="plaid-btn" onClick={onConnectBank}>Connect Bank</button>
        </div>
      </div>

      <div className="hero-card">
        <div className="hero-top">
          <div>
            <div className="card-label">Share Price</div>
            <div className="big-val">${parseFloat(portfolio.share_price||0).toFixed(2)}</div>
            <span className="change up">+12.68%</span>
          </div>
          <div style={{textAlign:'center'}}>
            <div className="health-ring">
              <svg width="80" height="80">
                <circle cx="40" cy="40" r="34" fill="none" stroke="#f3f4f6" strokeWidth="7"/>
                <circle cx="40" cy="40" r="34" fill="none" stroke={tierColor} strokeWidth="7"
                  strokeDasharray={hs/100*circ+' '+circ} strokeLinecap="round" transform="rotate(-90 40 40)"/>
              </svg>
              <div className="health-ring-num" style={{color:tierColor}}>{hs}</div>
            </div>
            <div style={{fontSize:12,fontWeight:600,color:tierColor,marginTop:4}}>{tier}</div>
          </div>
        </div>
        {portfolio.ticker&&<div style={{marginBottom:8}}><span className="ticker-badge">${portfolio.ticker}</span></div>}
        <div className="chart-area"><canvas ref={chartRef}></canvas></div>
        <div className="time-row">
          {['1W','1M','YTD','3M','1Y'].map(t=><button key={t} className={'time-btn'+(tf===t?' active':'')} onClick={()=>setTf(t)}>{t}</button>)}
        </div>
      </div>

      <div className="grid4" style={{marginBottom:16}}>
        {[
          {label:'Total Equity',val:'$'+Math.round((portfolio.total_equity||0)/1000)+'K',ch:''},
          {label:'Annual Cash Flow',val:'$'+Math.round((portfolio.annual_cashflow||0)/1000)+'K',ch:''},
          {label:'Properties',val:portfolio.property_count||0,ch:''},
          {label:'Monthly',val:'$'+Math.round((portfolio.annual_cashflow||0)/12),ch:''},
        ].map((s,i)=>(
          <div key={i} className="stat-card">
            <div className="stat-label">{s.label}</div>
            <div className="stat-val">{s.val}</div>
          </div>
        ))}
      </div>

      <div className="card">
        <div className="sec-head">
          <span className="sec-title">Properties ({(properties||[]).length})</span>
          <button className="add-btn" onClick={onAddProp}>
            <svg width="14" height="14" fill="none" stroke="currentColor" strokeWidth="2.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M12 4v16m8-8H4"/></svg>
            Add Property
          </button>
        </div>
        {!properties||properties.length===0?(
          <div className="empty"><div className="empty-title">No properties yet</div><div className="empty-sub">Add your first property to start tracking performance</div><button className="add-btn" onClick={onAddProp}>Add Property</button></div>
        ):(properties||[]).map(p=>(
          <div key={p.id} className="prop-row">
            <div className="prop-icon"><svg width="20" height="20" fill="none" stroke="#6b7280" strokeWidth="1.5" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6"/></svg></div>
            <div style={{flex:1}}><div className="prop-name">{p.name}</div><div className="prop-loc">{p.location}</div></div>
            <div><div className="prop-amount">${parseFloat(p.purchase_price||0).toLocaleString()}</div><div className="prop-equity">+${parseFloat(p.equity||0).toLocaleString()} equity</div></div>
          </div>
        ))}
      </div>
    </div>
  );
}

function CashflowTab({portfolio,properties}) {
  const inc=(portfolio&&portfolio.annual_cashflow>0)?portfolio.annual_cashflow/12:0;
  const exp=properties?(properties.reduce((s,p)=>s+parseFloat(p.monthly_expenses||0),0)):0;
  const net=inc-exp;
  return (
    <div className="page">
      <div className="page-header"><div className="page-title">Cash Flow</div><div className="page-sub">Jan 1 - Feb 11, 2026</div></div>
      <div className="grid3" style={{marginBottom:16}}>
        <div className="stat-card"><div className="stat-label">Net Income (MTD)</div><div className="stat-val" style={{color:'#059669'}}>+${Math.round(inc).toLocaleString()}</div><div className="stat-change">vs last month</div></div>
        <div className="stat-card"><div className="stat-label">Total Expenses</div><div className="stat-val" style={{color:'#d92d20'}}>-${Math.round(exp).toLocaleString()}</div></div>
        <div className="stat-card"><div className="stat-label">Net Cash Flow</div><div className="stat-val" style={{color:net>=0?'#059669':'#d92d20'}}>{net>=0?'+':''}{Math.round(net).toLocaleString()}</div></div>
      </div>
      <div className="card">
        <div className="sec-title" style={{marginBottom:16}}>Monthly Breakdown</div>
        {[{l:'Rental Income',v:inc,pos:true},{l:'Mortgage Payments',v:properties?properties.reduce((s,p)=>s+parseFloat(p.mortgage||0),0):0,pos:false},{l:'Insurance',v:properties?properties.reduce((s,p)=>s+parseFloat(p.insurance||0),0):0,pos:false},{l:'HOA Fees',v:properties?properties.reduce((s,p)=>s+parseFloat(p.hoa||0),0):0,pos:false},{l:'Property Tax',v:properties?properties.reduce((s,p)=>s+parseFloat(p.property_tax||0),0):0,pos:false}].map((row,i)=>(
          <div key={i} className="cf-row">
            <span className="cf-label">{row.l}</span>
            <span className={'cf-val '+(row.pos?'pos':'neg')}>{row.pos?'+':'-'}${Math.round(Math.abs(row.v)).toLocaleString()}</span>
          </div>
        ))}
        <div className="cf-row" style={{borderTop:'2px solid #e5e7eb',borderBottom:'none',marginTop:8,paddingTop:14}}>
          <span style={{fontWeight:700}}>Net</span>
          <span className={'cf-val '+(net>=0?'pos':'neg')} style={{fontSize:16}}>{net>=0?'+':''} ${Math.round(net).toLocaleString()}</span>
        </div>
      </div>
    </div>
  );
}

function DiscoverTab({users,following,onRefresh}) {
  const [q,setQ]=useState('');
  const follow=async id=>{ await fetch('/api/follow/'+id,{method:'POST',credentials:'include'}); onRefresh(); };
  const unfollow=async id=>{ await fetch('/api/unfollow/'+id,{method:'POST',credentials:'include'}); onRefresh(); };
  const filtered=(users||[]).filter(u=>!q||(u.full_name||'').toLowerCase().includes(q.toLowerCase())||(u.username||'').toLowerCase().includes(q.toLowerCase())||(u.portfolio_name||'').toLowerCase().includes(q.toLowerCase()));
  const initials=n=>(n||'').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()||'U';
  return (
    <div className="page">
      <div className="page-header"><div className="page-title">Discover Investors</div><div className="page-sub">Find and follow top performers</div></div>
      <div className="search-wrap">
        <svg className="search-icon" width="16" height="16" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
        <input className="search-input" placeholder="Search by name, username, or portfolio..." value={q} onChange={e=>setQ(e.target.value)}/>
      </div>
      {filtered.length===0?(
        <div className="empty"><div className="empty-title">{q?'No results for "'+q+'"':'No investors yet'}</div><div className="empty-sub">{q?'Try a different search':'Invite others to join'}</div></div>
      ):filtered.map(u=>(
        <div key={u.id} className="investor-row">
          <div className="inv-avatar">{initials(u.full_name)}</div>
          <div className="inv-info">
            <div className="inv-name">{u.full_name} <span className="inv-ticker">${u.ticker}</span></div>
            <div className="inv-meta">@{u.username} &bull; {u.property_count} properties &bull; Health: {u.health_score}/100</div>
          </div>
          <div style={{textAlign:'right',marginRight:12}}>
            <div style={{fontSize:14,fontWeight:700}}>${parseFloat(u.share_price||0).toFixed(2)}</div>
            <div style={{fontSize:12,color:'#9ca3af'}}>{u.portfolio_name}</div>
          </div>
          <button className={'btn-follow'+(following.has(u.id)?' btn-following':'')} onClick={()=>following.has(u.id)?unfollow(u.id):follow(u.id)}>
            {following.has(u.id)?'Following':'Follow'}
          </button>
        </div>
      ))}
    </div>
  );
}

function FeedTab({feed}) {
  const ago=ts=>{const h=Math.floor((Date.now()-new Date(ts).getTime())/3600000);return h<1?'Just now':h<24?h+'h ago':Math.floor(h/24)+'d ago';};
  const initials=n=>(n||'').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()||'U';
  return (
    <div className="page">
      <div className="page-header"><div className="page-title">Activity Feed</div><div className="page-sub">Updates from investors you follow</div></div>
      {!feed||feed.length===0?(
        <div className="empty"><div className="empty-title">Nothing here yet</div><div className="empty-sub">Follow investors in Discover to see their activity</div></div>
      ):(feed||[]).map(item=>(
        <div key={item.id} className="feed-item">
          <div className="feed-header">
            <div className="feed-av">{initials(item.user_name)}</div>
            <div><div className="feed-name">{item.user_name}</div><div className="feed-time">{ago(item.created_at)}</div></div>
          </div>
          <div className="feed-body">{item.content&&item.content.text}</div>
          {item.content&&item.content.highlight&&<div className="feed-pill">{item.content.highlight}</div>}
        </div>
      ))}
    </div>
  );
}

function ProfileTab({user,portfolio}) {
  const initials=n=>(n||'').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()||'U';
  return (
    <div className="page">
      <div className="page-header"><div className="page-title">Profile</div></div>
      <div className="profile-card">
        <div className="profile-av">{initials(user.full_name)}</div>
        <div className="profile-name">{user.full_name}</div>
        <div className="profile-handle">@{user.username}</div>
        {portfolio&&portfolio.ticker&&<div style={{marginBottom:12}}><span className="ticker-badge">${portfolio.ticker}</span></div>}
        <div className="profile-stats">
          <div><div className="profile-stat-num">{portfolio?portfolio.property_count||0:0}</div><div className="profile-stat-label">Properties</div></div>
          <div><div className="profile-stat-num">{portfolio?portfolio.health_score||0:0}</div><div className="profile-stat-label">Health Score</div></div>
          <div><div className="profile-stat-num">${portfolio?parseFloat(portfolio.share_price||0).toFixed(0):0}</div><div className="profile-stat-label">Share Price</div></div>
        </div>
      </div>
      <div className="card">
        <div className="sec-title" style={{marginBottom:16}}>Portfolio Overview</div>
        {[
          {l:'Portfolio Name',v:user.portfolio_name},
          {l:'Total Equity',v:'$'+(portfolio?Math.round((portfolio.total_equity||0)/1000):0)+'K'},
          {l:'Annual Cash Flow',v:'$'+(portfolio?Math.round((portfolio.annual_cashflow||0)/1000):0)+'K'},
          {l:'Member Since',v:new Date().getFullYear().toString()},
        ].map((r,i)=>(
          <div key={i} className="cf-row">
            <span className="cf-label">{r.l}</span>
            <span style={{fontWeight:600,fontSize:14}}>{r.v}</span>
          </div>
        ))}
      </div>
    </div>
  );
}

function AddPropModal({userId,onClose,onSave}) {
  const [f,setF]=useState({name:'',location:'',purchase_price:0,down_payment:0,mortgage:0,insurance:0,hoa:0,property_tax:0,monthly_revenue:0});
  const submit=async e=>{
    e.preventDefault();
    await fetch('/api/properties/'+userId,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
    onSave();
  };
  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={e=>e.stopPropagation()}>
        <div className="modal-title">Add Property</div>
        <form onSubmit={submit}>
          <div className="field"><label>Property name</label><input value={f.name} onChange={e=>setF({...f,name:e.target.value})} placeholder="Downtown Loft" required/></div>
          <div className="field"><label>Location</label><input value={f.location} onChange={e=>setF({...f,location:e.target.value})} placeholder="Houston, TX"/></div>
          <div className="field-row">
            <div className="field"><label>Purchase price</label><input type="number" value={f.purchase_price} onChange={e=>setF({...f,purchase_price:parseFloat(e.target.value)||0})} placeholder="350000"/></div>
            <div className="field"><label>Down payment</label><input type="number" value={f.down_payment} onChange={e=>setF({...f,down_payment:parseFloat(e.target.value)||0})} placeholder="70000"/></div>
          </div>
          <div className="field-row">
            <div className="field"><label>Monthly mortgage</label><input type="number" value={f.mortgage} onChange={e=>setF({...f,mortgage:parseFloat(e.target.value)||0})} placeholder="1800"/></div>
            <div className="field"><label>Monthly revenue</label><input type="number" value={f.monthly_revenue} onChange={e=>setF({...f,monthly_revenue:parseFloat(e.target.value)||0})} placeholder="2800"/></div>
          </div>
          <div className="field-row">
            <div className="field"><label>Insurance /mo</label><input type="number" value={f.insurance} onChange={e=>setF({...f,insurance:parseFloat(e.target.value)||0})} placeholder="150"/></div>
            <div className="field"><label>Property tax /mo</label><input type="number" value={f.property_tax} onChange={e=>setF({...f,property_tax:parseFloat(e.target.value)||0})} placeholder="300"/></div>
          </div>
          <div className="modal-footer">
            <button type="button" className="btn-cancel" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-save">Add Property</button>
          </div>
        </form>
      </div>
    </div>
  );
}

function PlaidModal({onClose}) {
  const [status,setStatus]=useState('idle');
  const connect=async()=>{
    setStatus('connecting');
    try {
      const r=await fetch('/api/plaid/create-link-token',{credentials:'include'});
      const d=await r.json();
      if(d.link_token&&window.Plaid) {
        const h=window.Plaid.create({token:d.link_token,onSuccess:async(pub)=>{
          await fetch('/api/plaid/exchange-token',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({public_token:pub})});
          setStatus('connected'); setTimeout(onClose,2000);
        },onExit:()=>setStatus('idle')});
        h.open();
      } else { setStatus('sandbox'); }
    } catch(e){setStatus('error');}
  };
  return (
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={e=>e.stopPropagation()}>
        <div className="modal-title">Connect Bank Account</div>
        <div className="card-sm" style={{marginBottom:16,background:'#f9fafb'}}>
          <div style={{fontSize:14,color:'#374151',lineHeight:1.6}}>
            Connect your bank accounts via Plaid to automatically import rental income and expenses. Your data is encrypted and secure.
          </div>
        </div>
        {status==='connected'&&<div style={{background:'#ecfdf5',border:'1px solid #a7f3d0',borderRadius:8,padding:'12px 16px',color:'#065f46',fontSize:14,marginBottom:16}}>Bank account connected successfully!</div>}
        {status==='error'&&<div style={{background:'#fef2f2',border:'1px solid #fecaca',borderRadius:8,padding:'12px 16px',color:'#991b1b',fontSize:14,marginBottom:16}}>Connection failed. Check your Plaid API keys in settings.</div>}
        {status==='sandbox'&&<div style={{background:'#eff6ff',border:'1px solid #bfdbfe',borderRadius:8,padding:'12px 16px',color:'#1e40af',fontSize:14,marginBottom:16}}>Plaid running in sandbox mode. Add PLAID_CLIENT_ID and PLAID_SECRET to enable live connections.</div>}
        <div style={{display:'flex',gap:10}}>
          <button className="btn-cancel modal-footer" style={{flex:1,padding:11,borderRadius:8,background:'#f3f4f6',border:'none',cursor:'pointer',fontFamily:'inherit',fontWeight:600}} onClick={onClose}>Cancel</button>
          <button className="btn-save" style={{flex:2,padding:11,borderRadius:8,background:'#1a56db',color:'#fff',border:'none',cursor:'pointer',fontFamily:'inherit',fontWeight:600,fontSize:14}} onClick={connect} disabled={status==='connecting'||status==='connected'}>
            {status==='connecting'?'Connecting...':status==='connected'?'Connected!':'Connect with Plaid'}
          </button>
        </div>
      </div>
    </div>
  );
}

ReactDOM.render(<App/>,document.getElementById('root'));
</script>
</body>
</html>"""


@app.route('/')
def index():
    return HTML

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    d=request.json
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id FROM users WHERE username=%s OR email=%s",(d['username'],d['email']))
            if cur.fetchone(): return jsonify({'error':'Username or email already exists'}),400
            ticker=generate_ticker(d['portfolio_name'])
            cur.execute("INSERT INTO users(username,email,password_hash,full_name,portfolio_name,ticker) VALUES(%s,%s,%s,%s,%s,%s) RETURNING id,username,full_name,portfolio_name,ticker",
                (d['username'],d['email'],hash_password(d['password']),d.get('full_name',''),d['portfolio_name'],ticker))
            u=dict(cur.fetchone()); conn.commit(); cur.close()
            session['user_id']=u['id']
            update_metrics(u['id'])
            return jsonify({'user':u})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/auth/login', methods=['POST'])
def login():
    d=request.json
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id,username,password_hash,full_name,portfolio_name,ticker FROM users WHERE username=%s OR email=%s",(d['username'],d['username']))
            u=cur.fetchone(); cur.close()
            if not u or not verify_password(d['password'],u['password_hash']): return jsonify({'error':'Invalid username or password'}),401
            session['user_id']=u['id']
            ud=dict(u); del ud['password_hash']
            return jsonify({'user':ud})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear(); return jsonify({'success':True})

@app.route('/api/auth/me')
def get_me():
    uid=session.get('user_id')
    if not uid: return jsonify({'error':'Not authenticated'}),401
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id,username,full_name,portfolio_name,ticker,bio,location FROM users WHERE id=%s",(uid,))
            u=cur.fetchone(); cur.close()
            if not u: return jsonify({'error':'Not found'}),404
            return jsonify(dict(u))
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/users/discover')
def discover():
    uid=session.get('user_id')
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,
                COALESCE(pm.health_score,0) as health_score,COALESCE(pm.share_price,0) as share_price,COALESCE(pm.property_count,0) as property_count
                FROM users u LEFT JOIN portfolio_metrics pm ON u.id=pm.user_id
                WHERE u.id!=%s ORDER BY pm.health_score DESC NULLS LAST LIMIT 50""",(uid or 0,))
            rows=cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/follow/<int:fid>', methods=['POST'])
def follow(fid):
    uid=session.get('user_id')
    if not uid: return jsonify({'error':'Not authenticated'}),401
    try:
        with get_db() as conn:
            cur=conn.cursor()
            cur.execute("INSERT INTO follows(follower_id,following_id) VALUES(%s,%s) ON CONFLICT DO NOTHING",(uid,fid))
            conn.commit(); cur.close()
            return jsonify({'success':True})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/unfollow/<int:fid>', methods=['POST'])
def unfollow(fid):
    uid=session.get('user_id')
    if not uid: return jsonify({'error':'Not authenticated'}),401
    try:
        with get_db() as conn:
            cur=conn.cursor()
            cur.execute("DELETE FROM follows WHERE follower_id=%s AND following_id=%s",(uid,fid))
            conn.commit(); cur.close()
            return jsonify({'success':True})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/following')
def get_following():
    uid=session.get('user_id')
    if not uid: return jsonify([])
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT following_id FROM follows WHERE follower_id=%s",(uid,))
            rows=cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/feed')
def get_feed():
    uid=session.get('user_id')
    if not uid: return jsonify([])
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""SELECT fi.id,fi.type,fi.content,fi.created_at,u.full_name as user_name
                FROM feed_items fi JOIN users u ON fi.user_id=u.id
                WHERE fi.user_id IN(SELECT following_id FROM follows WHERE follower_id=%s)
                ORDER BY fi.created_at DESC LIMIT 50""",(uid,))
            rows=cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/portfolio/<int:uid>')
def get_portfolio(uid):
    try:
        update_metrics(uid)
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT u.ticker,pm.* FROM portfolio_metrics pm JOIN users u ON pm.user_id=u.id WHERE pm.user_id=%s",(uid,))
            p=cur.fetchone(); cur.close()
            if not p: return jsonify({'ticker':'XXXX','health_score':0,'share_price':0,'total_equity':0,'annual_cashflow':0,'property_count':0})
            return jsonify(dict(p))
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/properties/<int:uid>')
def get_properties(uid):
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM properties WHERE user_id=%s ORDER BY created_at DESC",(uid,))
            rows=cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/properties/<int:uid>', methods=['POST'])
def add_property(uid):
    d=request.json
    try:
        with get_db() as conn:
            cur=conn.cursor(cursor_factory=RealDictCursor)
            exp=(d.get('mortgage',0)+d.get('insurance',0)+d.get('hoa',0)+d.get('property_tax',0))
            cur.execute("""INSERT INTO properties(user_id,name,location,purchase_price,down_payment,equity,mortgage,insurance,hoa,property_tax,monthly_revenue,monthly_expenses)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (uid,d['name'],d.get('location',''),d.get('purchase_price',0),d.get('down_payment',0),d.get('down_payment',0),
                 d.get('mortgage',0),d.get('insurance',0),d.get('hoa',0),d.get('property_tax',0),d.get('monthly_revenue',0),exp))
            prop=dict(cur.fetchone())
            content_str = json.dumps({"text": "Added a new property: " + d['name'], "highlight": str(d.get('location', ''))})
            cur.execute("INSERT INTO feed_items(user_id,type,content) VALUES(%s,%s,%s::jsonb)",(uid,'acquisition',content_str))
            conn.commit(); cur.close()
            update_metrics(uid)
            return jsonify(prop)
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/plaid/create-link-token')
def plaid_link():
    uid=session.get('user_id')
    if not uid: return jsonify({'error':'Not authenticated'}),401
    if not PLAID_CLIENT_ID: return jsonify({'link_token':None,'message':'Plaid not configured'})
    try:
        import urllib.request
        env_url='https://sandbox.plaid.com' if PLAID_ENV=='sandbox' else 'https://production.plaid.com'
        payload=json.dumps({'client_id':PLAID_CLIENT_ID,'secret':PLAID_SECRET,'user':{'client_user_id':str(uid)},'client_name':'Property Pigeon','products':['transactions'],'country_codes':['US'],'language':'en'}).encode()
        req=urllib.request.Request(env_url+'/link/token/create',data=payload,headers={'Content-Type':'application/json'})
        resp=urllib.request.urlopen(req)
        data=json.loads(resp.read())
        return jsonify({'link_token':data.get('link_token')})
    except Exception as e: return jsonify({'error':str(e)}),500

@app.route('/api/plaid/exchange-token', methods=['POST'])
def plaid_exchange():
    uid=session.get('user_id')
    if not uid: return jsonify({'error':'Not authenticated'}),401
    d=request.json
    if not PLAID_CLIENT_ID: return jsonify({'success':True,'message':'Sandbox mode'})
    try:
        import urllib.request
        env_url='https://sandbox.plaid.com' if PLAID_ENV=='sandbox' else 'https://production.plaid.com'
        payload=json.dumps({'client_id':PLAID_CLIENT_ID,'secret':PLAID_SECRET,'public_token':d.get('public_token')}).encode()
        req=urllib.request.Request(env_url+'/item/public_token/exchange',data=payload,headers={'Content-Type':'application/json'})
        resp=urllib.request.urlopen(req)
        data=json.loads(resp.read())
        with get_db() as conn:
            cur=conn.cursor()
            cur.execute("INSERT INTO plaid_items(user_id,access_token,item_id) VALUES(%s,%s,%s)",(uid,data.get('access_token'),data.get('item_id')))
            conn.commit(); cur.close()
        return jsonify({'success':True})
    except Exception as e: return jsonify({'error':str(e)}),500

if __name__=='__main__':
    port=int(os.environ.get('PORT',10000))
    app.run(host='0.0.0.0',port=port)


