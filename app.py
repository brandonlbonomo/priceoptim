from flask import Flask, jsonify, request, session
from flask_cors import CORS
import os, hashlib, secrets, json, re, urllib.request, urllib.parse
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
                accent_color VARCHAR(20) DEFAULT '#1a56db',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            cur.execute("ALTER TABLE users ADD COLUMN IF NOT EXISTS accent_color VARCHAR(20) DEFAULT '#1a56db'")
        except Exception:
            pass
        cur.execute("""
            CREATE TABLE IF NOT EXISTS properties (
                id SERIAL PRIMARY KEY,
                user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
                name VARCHAR(100) NOT NULL,
                location VARCHAR(100),
                purchase_price DECIMAL(12,2) DEFAULT 0,
                down_payment DECIMAL(12,2) DEFAULT 0,
                equity DECIMAL(12,2) DEFAULT 0,
                zestimate DECIMAL(12,2) DEFAULT 0,
                mortgage DECIMAL(10,2) DEFAULT 0,
                insurance DECIMAL(10,2) DEFAULT 0,
                hoa DECIMAL(10,2) DEFAULT 0,
                property_tax DECIMAL(10,2) DEFAULT 0,
                monthly_revenue DECIMAL(10,2) DEFAULT 0,
                monthly_expenses DECIMAL(10,2) DEFAULT 0,
                zpid VARCHAR(50),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        try:
            cur.execute("ALTER TABLE properties ADD COLUMN IF NOT EXISTS zestimate DECIMAL(12,2) DEFAULT 0")
            cur.execute("ALTER TABLE properties ADD COLUMN IF NOT EXISTS zpid VARCHAR(50)")
        except Exception:
            pass
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
    if not words: return 'XXXX'
    if len(words) == 1: return words[0][:4].ljust(4,'X')
    return ''.join(w[0] for w in words[:4]).ljust(4,'X')

def calculate_health_score(m):
    if not m or m.get('property_count', 0) == 0: return 0
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
            SELECT COUNT(*) as pc,
                   COALESCE(SUM(GREATEST(COALESCE(zestimate,0), COALESCE(purchase_price,0))),0) as eq,
                   COALESCE(SUM(monthly_revenue),0) as rev,
                   COALESCE(SUM(monthly_expenses),0) as exp
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

# ─── HTML FRONTEND ─────────────────────────────────────────────────────────────
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
<script src="https://cdn.plaid.com/link/v2/stable/link-initialize.js"></script>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,300;0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700;1,9..40,400&family=DM+Mono:wght@400;500&display=swap" rel="stylesheet">
<style>
:root {
  --blue:#1a56db; --bg:#f9fafb; --white:#ffffff;
  --gray-50:#f9fafb; --gray-100:#f3f4f6; --gray-200:#e5e7eb;
  --gray-300:#d1d5db; --gray-500:#6b7280; --gray-700:#374151; --gray-900:#111827;
  --green:#059669; --red:#d92d20; --gold:#d97706;
}
*{margin:0;padding:0;box-sizing:border-box;}
body{font-family:'DM Sans',sans-serif;background:var(--bg);color:var(--gray-900);min-height:100vh;}
/* LAYOUT */
.shell{display:flex;height:100vh;overflow:hidden;}
.sidebar{width:224px;background:var(--white);border-right:1px solid var(--gray-200);display:flex;flex-direction:column;flex-shrink:0;}
.sidebar-logo{padding:22px 20px 18px;font-size:17px;font-weight:700;color:var(--blue);letter-spacing:-0.4px;border-bottom:1px solid var(--gray-100);display:flex;align-items:center;gap:8px;}
.nav{padding:10px 0;flex:1;}
.ni{display:flex;align-items:center;gap:9px;padding:9px 16px;font-size:13.5px;font-weight:500;color:var(--gray-500);cursor:pointer;border-left:2px solid transparent;transition:all .15s;}
.ni:hover{background:var(--gray-50);color:var(--gray-900);}
.ni.active{background:#eff6ff;color:var(--blue);border-left-color:var(--blue);font-weight:600;}
.ni svg{width:16px;height:16px;flex-shrink:0;}
.sfooter{padding:14px 16px;border-top:1px solid var(--gray-100);}
.uchip{display:flex;align-items:center;gap:10px;cursor:pointer;padding:8px;border-radius:8px;transition:background .15s;}
.uchip:hover{background:var(--gray-100);}
.uav{width:32px;height:32px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0;}
.uname{font-size:13px;font-weight:600;}
.uhandle{font-size:11px;color:var(--gray-500);}
.signout-btn{margin-top:8px;width:100%;padding:7px;background:transparent;border:1px solid var(--gray-200);border-radius:7px;font-size:12px;color:var(--gray-500);cursor:pointer;font-family:inherit;}
.signout-btn:hover{background:var(--gray-50);}
/* CONTENT */
.content{flex:1;overflow-y:auto;background:var(--bg);}
.page{padding:28px 32px;max-width:1080px;}
.ph{margin-bottom:24px;}
.pt{font-size:22px;font-weight:700;letter-spacing:-.5px;}
.ps{font-size:13px;color:var(--gray-500);margin-top:2px;}
/* CARDS */
.card{background:var(--white);border:1px solid var(--gray-200);border-radius:12px;padding:22px;}
.card+.card{margin-top:14px;}
.clabel{font-size:11px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.6px;margin-bottom:8px;}
.bigval{font-size:34px;font-weight:700;letter-spacing:-1px;line-height:1;margin-bottom:6px;}
.badge-green{display:inline-flex;align-items:center;gap:3px;font-size:12px;font-weight:600;padding:3px 8px;border-radius:20px;background:#ecfdf5;color:#065f46;}
.badge-red{display:inline-flex;align-items:center;gap:3px;font-size:12px;font-weight:600;padding:3px 8px;border-radius:20px;background:#fef2f2;color:#991b1b;}
.g2{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
.g3{display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;}
.g4{display:grid;grid-template-columns:1fr 1fr 1fr 1fr;gap:12px;}
.statcard{background:var(--white);border:1px solid var(--gray-200);border-radius:10px;padding:16px;}
.statlabel{font-size:11px;font-weight:700;color:#9ca3af;text-transform:uppercase;letter-spacing:.5px;margin-bottom:6px;}
.statval{font-size:22px;font-weight:700;letter-spacing:-.5px;}
/* HERO */
.hero{background:var(--white);border:1px solid var(--gray-200);border-radius:12px;padding:24px;margin-bottom:14px;}
.hero-top{display:flex;align-items:flex-start;justify-content:space-between;margin-bottom:16px;}
.ticker-pill{font-family:'DM Mono',monospace;font-size:12px;font-weight:500;color:var(--blue);background:#eff6ff;padding:3px 9px;border-radius:5px;border:1px solid #bfdbfe;margin-top:6px;display:inline-block;}
.ring{position:relative;width:76px;height:76px;}
.ring-num{position:absolute;top:50%;left:50%;transform:translate(-50%,-50%);font-size:18px;font-weight:700;}
.ring-tier{font-size:11px;font-weight:700;text-align:center;margin-top:2px;}
.chart-area{height:150px;position:relative;margin:12px 0 8px;}
.trow{display:flex;gap:2px;}
.tbtn{padding:4px 11px;border-radius:5px;background:transparent;border:none;font-size:12px;font-weight:500;color:#9ca3af;cursor:pointer;font-family:inherit;}
.tbtn.active{background:var(--gray-100);color:var(--gray-900);}
/* PLAID BANNER */
.plaid-bar{background:#eff6ff;border:1px solid #bfdbfe;border-radius:10px;padding:14px 18px;margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;gap:12px;}
.plaid-bar h4{font-size:13px;font-weight:700;color:#1e40af;}
.plaid-bar p{font-size:12px;color:#3b82f6;margin-top:1px;}
/* BUTTONS */
.btn{padding:9px 18px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;border:none;font-family:inherit;transition:all .15s;}
.btn-blue{background:var(--blue);color:#fff;}
.btn-blue:hover{background:#1648c0;}
.btn-outline{background:transparent;border:1.5px solid var(--blue);color:var(--blue);}
.btn-outline:hover{background:var(--blue);color:#fff;}
.btn-ghost{background:var(--gray-100);color:var(--gray-700);}
.btn-ghost:hover{background:var(--gray-200);}
.btn-sm{padding:6px 14px;font-size:12px;}
.btn-danger{background:#fef2f2;color:#991b1b;border:1px solid #fecaca;}
/* SEARCH */
.swrap{position:relative;margin-bottom:16px;}
.sinput{width:100%;padding:10px 14px 10px 38px;border:1.5px solid var(--gray-200);border-radius:8px;font-size:13.5px;font-family:inherit;background:var(--white);}
.sinput:focus{outline:none;border-color:var(--blue);}
.sicon{position:absolute;left:12px;top:50%;transform:translateY(-50%);color:#9ca3af;}
/* INVESTOR ROW */
.irow{display:flex;align-items:center;gap:12px;padding:14px 18px;background:var(--white);border:1px solid var(--gray-200);border-radius:10px;margin-bottom:8px;transition:border-color .15s;}
.irow:hover{border-color:var(--gray-300);}
.iav{width:42px;height:42px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:14px;font-weight:700;color:#fff;flex-shrink:0;}
.iname{font-size:14px;font-weight:600;margin-bottom:1px;}
.imeta{font-size:12px;color:var(--gray-500);}
.iticker{font-family:'DM Mono',monospace;font-size:11px;color:var(--blue);background:#eff6ff;padding:2px 6px;border-radius:4px;}
.follow-btn{padding:6px 16px;border-radius:20px;border:1.5px solid var(--blue);background:transparent;color:var(--blue);font-size:12px;font-weight:600;cursor:pointer;font-family:inherit;transition:all .15s;white-space:nowrap;}
.follow-btn:hover{background:var(--blue);color:#fff;}
.follow-btn.following{border-color:var(--gray-200);color:var(--gray-500);}
.follow-btn.following:hover{background:var(--gray-100);color:var(--gray-700);}
/* FEED */
.fitem{background:var(--white);border:1px solid var(--gray-200);border-radius:10px;padding:16px 18px;margin-bottom:8px;}
.fhdr{display:flex;align-items:center;gap:10px;margin-bottom:10px;}
.fav{width:34px;height:34px;border-radius:50%;background:var(--gray-900);display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;flex-shrink:0;}
.fname{font-size:13px;font-weight:600;}
.ftime{font-size:11px;color:#9ca3af;}
.fbody{font-size:13px;color:var(--gray-700);line-height:1.5;}
.fpill{display:inline-block;margin-top:8px;padding:5px 10px;background:var(--gray-100);border-radius:6px;font-size:12px;font-weight:600;}
/* PROPERTIES */
.prow{display:flex;align-items:center;gap:12px;padding:12px 0;border-bottom:1px solid var(--gray-100);}
.prow:last-child{border-bottom:none;}
.picon{width:38px;height:38px;border-radius:8px;background:var(--gray-100);display:flex;align-items:center;justify-content:center;flex-shrink:0;}
.pname{font-size:13.5px;font-weight:600;}
.ploc{font-size:12px;color:#9ca3af;}
.pamount{font-size:14px;font-weight:700;text-align:right;}
.pzest{font-size:11px;color:var(--green);text-align:right;}
/* FORM */
.field{margin-bottom:16px;}
.field label{display:block;font-size:12px;font-weight:700;color:var(--gray-700);margin-bottom:5px;text-transform:uppercase;letter-spacing:.3px;}
.field input,.field textarea,.field select{width:100%;padding:10px 12px;border:1.5px solid var(--gray-200);border-radius:8px;font-size:13.5px;font-family:inherit;color:var(--gray-900);transition:border-color .15s;background:var(--white);}
.field input:focus,.field textarea:focus,.field select:focus{outline:none;border-color:var(--blue);}
.field textarea{resize:vertical;min-height:70px;}
.frow{display:grid;grid-template-columns:1fr 1fr;gap:12px;}
/* MODAL */
.overlay{position:fixed;top:0;left:0;right:0;bottom:0;background:rgba(0,0,0,.45);z-index:200;display:flex;align-items:center;justify-content:center;padding:20px;}
.modal{background:var(--white);border-radius:16px;width:100%;max-width:580px;max-height:88vh;overflow-y:auto;padding:28px 26px;box-shadow:0 20px 60px rgba(0,0,0,.2);}
.mtitle{font-size:17px;font-weight:700;letter-spacing:-.3px;margin-bottom:20px;}
.mfoot{display:flex;gap:8px;margin-top:20px;}
.mfoot button{flex:1;padding:10px;border-radius:8px;font-size:13px;font-weight:600;cursor:pointer;font-family:inherit;border:none;}
/* ZILLOW SEARCH */
.zsuggest{background:var(--white);border:1.5px solid var(--gray-200);border-radius:8px;overflow:hidden;margin-top:-10px;margin-bottom:16px;box-shadow:0 4px 16px rgba(0,0,0,.08);}
.zitem{padding:11px 14px;font-size:13px;cursor:pointer;border-bottom:1px solid var(--gray-100);transition:background .1s;}
.zitem:last-child{border-bottom:none;}
.zitem:hover{background:var(--gray-50);}
.zprop-card{background:#f0fdf4;border:1.5px solid #bbf7d0;border-radius:10px;padding:16px;margin-bottom:16px;}
.zprop-row{display:flex;justify-content:space-between;padding:6px 0;border-bottom:1px solid #dcfce7;font-size:13px;}
.zprop-row:last-child{border-bottom:none;}
.zprop-label{color:var(--gray-500);}
.zprop-val{font-weight:700;}
/* SETTINGS */
.settings-section{margin-bottom:24px;}
.settings-title{font-size:14px;font-weight:700;color:var(--gray-900);margin-bottom:14px;padding-bottom:8px;border-bottom:1px solid var(--gray-200);}
.color-grid{display:flex;gap:10px;flex-wrap:wrap;margin-top:8px;}
.color-swatch{width:36px;height:36px;border-radius:50%;cursor:pointer;border:3px solid transparent;transition:all .15s;}
.color-swatch.selected{border-color:var(--gray-900);transform:scale(1.1);}
/* PROFILE */
.pcard{background:var(--white);border:1px solid var(--gray-200);border-radius:12px;padding:28px;text-align:center;margin-bottom:14px;}
.pav{width:68px;height:68px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:24px;font-weight:700;color:#fff;margin:0 auto 14px;}
.pname{font-size:20px;font-weight:700;letter-spacing:-.3px;margin-bottom:3px;}
.phandle{font-size:13px;color:var(--gray-500);margin-bottom:6px;}
.pbio{font-size:13px;color:var(--gray-700);margin-bottom:14px;line-height:1.5;}
.pstats{display:flex;justify-content:center;gap:28px;}
.pstatnum{font-size:18px;font-weight:700;}
.pstatlabel{font-size:11px;color:#9ca3af;margin-top:1px;}
/* CF */
.cfrow{display:flex;justify-content:space-between;align-items:center;padding:11px 0;border-bottom:1px solid var(--gray-100);}
.cfrow:last-child{border-bottom:none;}
.cflabel{font-size:13px;color:var(--gray-700);}
.cfval{font-size:13px;font-weight:700;}
.cfval.pos{color:var(--green);}
.cfval.neg{color:var(--red);}
/* INFO ALERT */
.info-box{background:#eff6ff;border:1px solid #bfdbfe;border-radius:8px;padding:12px 14px;font-size:13px;color:#1e40af;margin-bottom:14px;}
.warn-box{background:#fffbeb;border:1px solid #fde68a;border-radius:8px;padding:12px 14px;font-size:13px;color:#92400e;margin-bottom:14px;}
.success-box{background:#f0fdf4;border:1px solid #bbf7d0;border-radius:8px;padding:12px 14px;font-size:13px;color:#065f46;margin-bottom:14px;}
.err-box{background:#fef2f2;border:1px solid #fecaca;border-radius:8px;padding:12px 14px;font-size:13px;color:#991b1b;margin-bottom:14px;}
/* AUTH */
.auth-wrap{min-height:100vh;display:flex;}
.auth-left{flex:1;display:flex;align-items:center;justify-content:center;padding:60px;}
.auth-left h1{font-size:38px;font-weight:700;color:#fff;letter-spacing:-1px;margin-bottom:12px;}
.auth-left p{font-size:16px;color:rgba(255,255,255,.75);line-height:1.6;max-width:340px;}
.auth-right{width:460px;background:var(--white);display:flex;align-items:center;justify-content:center;padding:52px 44px;}
.auth-form{width:100%;}
.auth-logo{font-size:16px;font-weight:700;color:var(--blue);margin-bottom:36px;}
.auth-title{font-size:24px;font-weight:700;letter-spacing:-.5px;margin-bottom:4px;}
.auth-sub{font-size:13px;color:var(--gray-500);margin-bottom:28px;}
.auth-field{margin-bottom:14px;}
.auth-field label{display:block;font-size:12px;font-weight:700;color:var(--gray-700);margin-bottom:5px;text-transform:uppercase;letter-spacing:.3px;}
.auth-field input{width:100%;padding:10px 12px;border:1.5px solid var(--gray-200);border-radius:8px;font-size:14px;font-family:inherit;}
.auth-field input:focus{outline:none;border-color:var(--blue);}
.auth-btn-primary{width:100%;padding:11px;background:var(--blue);color:#fff;border:none;border-radius:8px;font-size:14px;font-weight:600;cursor:pointer;font-family:inherit;margin-bottom:10px;}
.auth-btn-primary:hover{background:#1648c0;}
.auth-btn-ghost{width:100%;padding:11px;background:transparent;border:1.5px solid var(--gray-200);border-radius:8px;font-size:13px;font-weight:500;color:var(--gray-500);cursor:pointer;font-family:inherit;}
.ticker-avail{font-size:11px;font-weight:700;margin-top:4px;}
.ticker-avail.yes{color:var(--green);}
.ticker-avail.no{color:var(--red);}
.mono-input{font-family:'DM Mono',monospace !important;font-weight:600 !important;letter-spacing:2px !important;text-transform:uppercase !important;}
</style>
</head>
<body>
<div id="root"></div>
<script type="text/babel">
const {useState,useEffect,useRef,useCallback}=React;

// ── UTILS ────────────────────────────────────────────────────────────────────
const initials=n=>(n||'').split(' ').map(w=>w[0]).join('').slice(0,2).toUpperCase()||'?';
const fmt$=n=>n==null?'$0':'$'+Math.round(n).toLocaleString();
const fmtK=n=>n==null?'$0K':'$'+Math.round(n/1000)+'K';
const ago=ts=>{const h=Math.floor((Date.now()-new Date(ts).getTime())/3600000);return h<1?'Just now':h<24?h+'h ago':Math.floor(h/24)+'d ago';};

const ACCENT_COLORS=[
  {val:'#1a56db',name:'Blue'},
  {val:'#0f766e',name:'Teal'},
  {val:'#7c3aed',name:'Purple'},
  {val:'#be185d',name:'Pink'},
  {val:'#b45309',name:'Amber'},
  {val:'#0369a1',name:'Sky'},
  {val:'#1d4ed8',name:'Indigo'},
  {val:'#047857',name:'Emerald'},
];

// ── APP ROOT ─────────────────────────────────────────────────────────────────
function App() {
  const [auth,setAuth]=useState(false);
  const [user,setUser]=useState(null);
  const [loading,setLoading]=useState(true);

  useEffect(()=>{
    fetch('/api/auth/me',{credentials:'include'})
      .then(r=>r.ok?r.json():null)
      .then(u=>{if(u&&u.id){setUser(u);setAuth(true);}})
      .catch(()=>{}).finally(()=>setLoading(false));
  },[]);

  const accent=user?.accent_color||'#1a56db';

  useEffect(()=>{
    document.documentElement.style.setProperty('--blue', accent);
  },[accent]);

  if(loading) return <div style={{display:'flex',alignItems:'center',justifyContent:'center',height:'100vh',color:'#9ca3af',fontSize:13}}>Loading...</div>;
  if(!auth) return <AuthScreen accent={accent} onLogin={u=>{setUser(u);setAuth(true);}}/>;
  return <MainApp user={user} setUser={setUser} onLogout={()=>{setAuth(false);setUser(null);}}/>;
}

// ── AUTH SCREEN ───────────────────────────────────────────────────────────────
function AuthScreen({onLogin,accent='#1a56db'}) {
  const [mode,setMode]=useState('login');
  const [err,setErr]=useState('');
  const [f,setF]=useState({username:'',email:'',password:'',full_name:'',portfolio_name:'',ticker:''});
  const [tickerStatus,setTickerStatus]=useState('');

  useEffect(()=>{
    if(f.ticker.length!==4){setTickerStatus('');return;}
    const t=setTimeout(async()=>{
      try{const r=await fetch('/api/ticker/check/'+f.ticker);const d=await r.json();setTickerStatus(d.available?'available':'taken');}catch(e){}
    },400);
    return()=>clearTimeout(t);
  },[f.ticker]);

  const submit=async e=>{
    e.preventDefault();setErr('');
    try{
      const r=await fetch(mode==='login'?'/api/auth/login':'/api/auth/signup',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      const d=await r.json();
      if(r.ok) onLogin(d.user); else setErr(d.error||'Something went wrong');
    }catch(e){setErr('Network error');}
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
          <h2 className="auth-title">{mode==='login'?'Welcome back':'Create account'}</h2>
          <p className="auth-sub">{mode==='login'?'Sign in to your account':'Join thousands of real estate investors'}</p>
          {err&&<div className="err-box">{err}</div>}
          <form onSubmit={submit}>
            {mode==='signup'&&<>
              <div className="auth-field"><label>Full name</label><input value={f.full_name} onChange={e=>setF({...f,full_name:e.target.value})} placeholder="Brandon Bonomo" required/></div>
              <div className="auth-field"><label>Portfolio name</label><input value={f.portfolio_name} onChange={e=>setF({...f,portfolio_name:e.target.value})} placeholder="Brandon's Empire" required/></div>
              <div className="auth-field">
                <label>Ticker symbol <span style={{color:'#9ca3af',fontWeight:400,textTransform:'none'}}>(4 letters — your public ID)</span></label>
                <input className="mono-input" value={f.ticker} onChange={e=>setF({...f,ticker:e.target.value.toUpperCase().replace(/[^A-Z]/g,'').slice(0,4)})} placeholder="BEMP" maxLength={4}/>
                {f.ticker.length===4&&<div className={'ticker-avail '+(tickerStatus==='available'?'yes':'no')}>{tickerStatus==='available'?'✓ Available':'✗ Already taken — try another'}</div>}
              </div>
            </>}
            <div className="auth-field"><label>{mode==='login'?'Username or email':'Username'}</label><input value={f.username} onChange={e=>setF({...f,username:e.target.value})} placeholder="brandonb" required/></div>
            {mode==='signup'&&<div className="auth-field"><label>Email</label><input type="email" value={f.email} onChange={e=>setF({...f,email:e.target.value})} required/></div>}
            <div className="auth-field"><label>Password</label><input type="password" value={f.password} onChange={e=>setF({...f,password:e.target.value})} required/></div>
            <button type="submit" className="auth-btn-primary">{mode==='login'?'Sign in':'Create account'}</button>
            <button type="button" className="auth-btn-ghost" onClick={()=>{setMode(mode==='login'?'signup':'login');setErr('');}}>{mode==='login'?'New here? Create an account':'Have an account? Sign in'}</button>
          </form>
        </div>
      </div>
    </div>
  );
}

// ── MAIN APP ──────────────────────────────────────────────────────────────────
function MainApp({user,setUser,onLogout}) {
  const [tab,setTab]=useState('portfolio');
  const [portfolio,setPortfolio]=useState(null);
  const [users,setUsers]=useState([]);
  const [following,setFollowing]=useState(new Set());
  const [feed,setFeed]=useState([]);
  const [properties,setProperties]=useState([]);
  const [showAddProp,setShowAddProp]=useState(false);
  const [showPlaid,setShowPlaid]=useState(false);
  const [showSettings,setShowSettings]=useState(false);

  const accent=user?.accent_color||'#1a56db';

  useEffect(()=>{
    document.documentElement.style.setProperty('--blue',accent);
  },[accent]);

  useEffect(()=>{loadAll();},[]);

  const loadAll=async()=>{
    try{
      const [pR,uR,fR,fdR,prR]=await Promise.all([
        fetch('/api/portfolio/'+user.id,{credentials:'include'}),
        fetch('/api/users/discover',{credentials:'include'}),
        fetch('/api/following',{credentials:'include'}),
        fetch('/api/feed',{credentials:'include'}),
        fetch('/api/properties/'+user.id,{credentials:'include'})
      ]);
      const [p,u,f,fd,pr]=await Promise.all([pR.json(),uR.json(),fR.json(),fdR.json(),prR.json()]);
      setPortfolio(p);setUsers(u);
      setFollowing(new Set(f.map(x=>x.following_id)));
      setFeed(fd);setProperties(pr);
    }catch(e){console.error(e);}
  };

  const logout=async()=>{await fetch('/api/auth/logout',{method:'POST',credentials:'include'});onLogout();};

  const navItems=[
    {id:'portfolio',label:'Portfolio',path:'M3 12l2-2m0 0l7-7 7 7M5 10v10a1 1 0 001 1h3m10-11l2 2m-2-2v10a1 1 0 01-1 1h-3m-6 0a1 1 0 001-1v-4a1 1 0 011-1h2a1 1 0 011 1v4a1 1 0 001 1m-6 0h6'},
    {id:'cashflow',label:'Cash flow',path:'M9 19v-6a2 2 0 00-2-2H5a2 2 0 00-2 2v6a2 2 0 002 2h2a2 2 0 002-2zm0 0V9a2 2 0 012-2h2a2 2 0 012 2v10m-6 0a2 2 0 002 2h2a2 2 0 002-2m0 0V5a2 2 0 012-2h2a2 2 0 012 2v14a2 2 0 01-2 2h-2a2 2 0 01-2-2z'},
    {id:'discover',label:'Discover',path:'M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z'},
    {id:'feed',label:'Feed',path:'M19 20H5a2 2 0 01-2-2V6a2 2 0 012-2h10a2 2 0 012 2v1m2 13a2 2 0 01-2-2V7m2 13a2 2 0 002-2V9a2 2 0 00-2-2h-2m-4-3H9M7 16h6M7 8h6v4H7V8z'},
    {id:'profile',label:'Profile',path:'M16 7a4 4 0 11-8 0 4 4 0 018 0zM12 14a7 7 0 00-7 7h14a7 7 0 00-7-7z'},
  ];

  return(
    <div className="shell">
      <div className="sidebar">
        <div className="sidebar-logo" style={{color:accent}}>
          <span>🐦</span> Property Pigeon
        </div>
        <div className="nav">
          {navItems.map(n=>(
            <div key={n.id} className={'ni'+(tab===n.id?' active':'')} onClick={()=>setTab(n.id)}>
              <svg fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d={n.path}/></svg>
              {n.label}
            </div>
          ))}
        </div>
        <div className="sfooter">
          <div className="uchip" onClick={()=>setShowSettings(true)}>
            <div className="uav" style={{background:accent}}>{initials(user.full_name)}</div>
            <div><div className="uname">{user.full_name}</div><div className="uhandle">@{user.username}</div></div>
          </div>
          <button className="signout-btn" onClick={logout}>Sign out</button>
        </div>
      </div>
      <div className="content">
        {tab==='portfolio'&&<PortfolioTab portfolio={portfolio} properties={properties} accent={accent} onAddProp={()=>setShowAddProp(true)} onConnectBank={()=>setShowPlaid(true)} onRefresh={loadAll}/>}
        {tab==='cashflow'&&<CashflowTab portfolio={portfolio} properties={properties}/>}
        {tab==='discover'&&<DiscoverTab users={users} following={following} accent={accent} onRefresh={loadAll}/>}
        {tab==='feed'&&<FeedTab feed={feed}/>}
        {tab==='profile'&&<ProfileTab user={user} portfolio={portfolio} accent={accent} onEdit={()=>setShowSettings(true)}/>}
      </div>
      {showAddProp&&<AddPropModal userId={user.id} onClose={()=>setShowAddProp(false)} onSave={()=>{setShowAddProp(false);loadAll();}}/>}
      {showPlaid&&<PlaidModal onClose={()=>setShowPlaid(false)}/>}
      {showSettings&&<SettingsModal user={user} onClose={()=>setShowSettings(false)} onSave={u=>{setUser(u);setShowSettings(false);}}/>}
    </div>
  );
}

// ── PORTFOLIO TAB ─────────────────────────────────────────────────────────────
function PortfolioTab({portfolio,properties,accent,onAddProp,onConnectBank,onRefresh}) {
  const chartRef=useRef(null);const ci=useRef(null);const [tf,setTf]=useState('3M');
  useEffect(()=>{
    if(!chartRef.current)return;
    if(ci.current)ci.current.destroy();
    const pts=tf==='1W'?7:tf==='1M'?30:tf==='YTD'?60:tf==='1Y'?365:90;
    const base=portfolio?parseFloat(portfolio.share_price)||1:1;
    const data=Array.from({length:pts},(_,i)=>+(base*(1+(Math.random()*.04-.015)*(i+1))).toFixed(2));
    ci.current=new Chart(chartRef.current.getContext('2d'),{
      type:'line',
      data:{labels:Array(pts).fill(''),datasets:[{data,borderColor:accent,borderWidth:2,fill:true,backgroundColor:accent+'15',tension:0.4,pointRadius:0}]},
      options:{responsive:true,maintainAspectRatio:false,plugins:{legend:{display:false}},scales:{x:{display:false},y:{display:false}}}
    });
    return()=>{if(ci.current)ci.current.destroy();};
  },[portfolio,tf,accent]);

  if(!portfolio) return <div className="page"><div style={{color:'#9ca3af',fontSize:13}}>Loading...</div></div>;
  const hs=portfolio.health_score||0;
  const tier=hs>=90?'Elite':hs>=75?'Strong':hs>=60?'Good':'Growing';
  const tierColor=hs>=90?'#d97706':hs>=75?'#059669':hs>=60?accent:'#6b7280';
  const circ=2*Math.PI*32;

  return(
    <div className="page">
      <div className="ph"><div className="pt">Your Portfolio</div><div className="ps">{portfolio.ticker?'$'+portfolio.ticker:''} · Updated just now</div></div>
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
          <div style={{textAlign:'center'}}>
            <div className="ring">
              <svg width="76" height="76">
                <circle cx="38" cy="38" r="32" fill="none" stroke="#f3f4f6" strokeWidth="6"/>
                <circle cx="38" cy="38" r="32" fill="none" stroke={tierColor} strokeWidth="6"
                  strokeDasharray={hs/100*circ+' '+circ} strokeLinecap="round" transform="rotate(-90 38 38)"/>
              </svg>
              <div className="ring-num" style={{color:tierColor}}>{hs}</div>
            </div>
            <div className="ring-tier" style={{color:tierColor}}>{tier}</div>
          </div>
        </div>
        <div className="chart-area"><canvas ref={chartRef}></canvas></div>
        <div className="trow">{['1W','1M','YTD','3M','1Y'].map(t=><button key={t} className={'tbtn'+(tf===t?' active':'')} onClick={()=>setTf(t)}>{t}</button>)}</div>
      </div>
      <div className="g4" style={{marginBottom:14}}>
        {[['Total Equity',fmtK(portfolio.total_equity)],['Annual Cash Flow',fmtK(portfolio.annual_cashflow)],['Properties',portfolio.property_count||0],['Monthly Net',fmt$(+(portfolio.annual_cashflow||0)/12)]].map(([l,v],i)=>(
          <div key={i} className="statcard"><div className="statlabel">{l}</div><div className="statval">{v}</div></div>
        ))}
      </div>
      <div className="card">
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between',marginBottom:14}}>
          <span style={{fontSize:14,fontWeight:700}}>Properties ({(properties||[]).length})</span>
          <button className="btn btn-blue btn-sm" onClick={onAddProp}>+ Add Property</button>
        </div>
        {!properties||properties.length===0?(
          <div style={{textAlign:'center',padding:'36px 20px',color:'#9ca3af'}}>
            <div style={{fontSize:14,fontWeight:600,color:'#374151',marginBottom:6}}>No properties yet</div>
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
              <div style={{fontSize:11,color:'#9ca3af',textAlign:'right'}}>{fmt$(p.monthly_revenue)}/mo revenue</div>
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
        <div className="statcard"><div className="statlabel">Gross Income</div><div className="statval" style={{color:'#059669'}}>{fmt$(rev)}</div></div>
        <div className="statcard"><div className="statlabel">Total Expenses</div><div className="statval" style={{color:'#d92d20'}}>{fmt$(exp)}</div></div>
        <div className="statcard"><div className="statlabel">Net Cash Flow</div><div className="statval" style={{color:net>=0?'#059669':'#d92d20'}}>{fmt$(net)}</div></div>
      </div>
      <div className="card">
        <div style={{fontSize:14,fontWeight:700,marginBottom:14}}>Monthly Breakdown</div>
        {[
          {l:'Rental / STR Income',v:rev,pos:true},
          {l:'Mortgage Payments',v:(properties||[]).reduce((s,p)=>s+parseFloat(p.mortgage||0),0),pos:false},
          {l:'Insurance',v:(properties||[]).reduce((s,p)=>s+parseFloat(p.insurance||0),0),pos:false},
          {l:'HOA Fees',v:(properties||[]).reduce((s,p)=>s+parseFloat(p.hoa||0),0),pos:false},
          {l:'Property Tax',v:(properties||[]).reduce((s,p)=>s+parseFloat(p.property_tax||0),0),pos:false},
        ].map((row,i)=>(
          <div key={i} className="cfrow">
            <span className="cflabel">{row.l}</span>
            <span className={'cfval '+(row.pos?'pos':'neg')}>{row.pos?'+':'-'}{fmt$(Math.abs(row.v))}</span>
          </div>
        ))}
        <div className="cfrow" style={{borderTop:'2px solid #e5e7eb',marginTop:6,paddingTop:12}}>
          <span style={{fontWeight:700,fontSize:14}}>Net</span>
          <span className={'cfval '+(net>=0?'pos':'neg')} style={{fontSize:16}}>{net>=0?'+':''}{fmt$(net)}</span>
        </div>
      </div>
    </div>
  );
}

// ── DISCOVER TAB ──────────────────────────────────────────────────────────────
function DiscoverTab({users,following,accent,onRefresh}) {
  const [q,setQ]=useState('');
  const follow=async id=>{await fetch('/api/follow/'+id,{method:'POST',credentials:'include'});onRefresh();};
  const unfollow=async id=>{await fetch('/api/unfollow/'+id,{method:'POST',credentials:'include'});onRefresh();};
  const filtered=(users||[]).filter(u=>!q||[u.full_name,u.username,u.portfolio_name,u.ticker].some(s=>(s||'').toLowerCase().includes(q.toLowerCase())));
  return(
    <div className="page">
      <div className="ph"><div className="pt">Discover Investors</div><div className="ps">Find and follow top performers</div></div>
      <div className="swrap">
        <svg className="sicon" width="15" height="15" fill="none" stroke="currentColor" strokeWidth="2" viewBox="0 0 24 24"><path strokeLinecap="round" strokeLinejoin="round" d="M21 21l-6-6m2-5a7 7 0 11-14 0 7 7 0 0114 0z"/></svg>
        <input className="sinput" placeholder="Search by name, username, ticker..." value={q} onChange={e=>setQ(e.target.value)}/>
      </div>
      {filtered.length===0?(
        <div style={{textAlign:'center',padding:40,color:'#9ca3af',fontSize:13}}>{q?`No results for "${q}"`:'No other investors yet'}</div>
      ):filtered.map(u=>(
        <div key={u.id} className="irow">
          <div className="iav" style={{background:accent}}>{initials(u.full_name)}</div>
          <div style={{flex:1}}>
            <div className="iname">{u.full_name} <span className="iticker">${u.ticker}</span></div>
            <div className="imeta">@{u.username} · {u.property_count} properties · Health {u.health_score}/100</div>
          </div>
          <div style={{textAlign:'right',marginRight:10}}>
            <div style={{fontSize:13,fontWeight:700}}>${parseFloat(u.share_price||0).toFixed(2)}</div>
            <div style={{fontSize:11,color:'#9ca3af'}}>{u.portfolio_name}</div>
          </div>
          <button className={'follow-btn'+(following.has(u.id)?' following':'')} onClick={()=>following.has(u.id)?unfollow(u.id):follow(u.id)}>
            {following.has(u.id)?'Following':'Follow'}
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
        <div style={{textAlign:'center',padding:48,color:'#9ca3af'}}>
          <div style={{fontSize:14,fontWeight:600,color:'#374151',marginBottom:6}}>Nothing here yet</div>
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
        <div style={{display:'flex',alignItems:'center',justifyContent:'space-between'}}>
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
        {[['Portfolio Name',user.portfolio_name],['Total Equity',fmtK(portfolio?.total_equity)],['Annual Cash Flow',fmtK(portfolio?.annual_cashflow)],['Location',user.location||'—'],['Email',user.email||'—']].map(([l,v],i)=>(
          <div key={i} className="cfrow"><span className="cflabel">{l}</span><span style={{fontWeight:600,fontSize:13}}>{v}</span></div>
        ))}
      </div>
    </div>
  );
}

// ── SETTINGS MODAL ────────────────────────────────────────────────────────────
function SettingsModal({user,onClose,onSave}) {
  const [f,setF]=useState({full_name:user.full_name||'',username:user.username||'',email:user.email||'',portfolio_name:user.portfolio_name||'',ticker:user.ticker||'',bio:user.bio||'',location:user.location||'',accent_color:user.accent_color||'#1a56db',current_password:'',new_password:''});
  const [tickerStatus,setTickerStatus]=useState('');
  const [usernameStatus,setUsernameStatus]=useState('');
  const [err,setErr]=useState('');
  const [success,setSuccess]=useState('');
  const [saving,setSaving]=useState(false);

  // Ticker check
  useEffect(()=>{
    if(!f.ticker||f.ticker===user.ticker){setTickerStatus('');return;}
    if(f.ticker.length!==4){setTickerStatus('');return;}
    const t=setTimeout(async()=>{
      try{const r=await fetch('/api/ticker/check/'+f.ticker);const d=await r.json();setTickerStatus(d.available?'available':'taken');}catch(e){}
    },400);
    return()=>clearTimeout(t);
  },[f.ticker]);

  // Username check
  useEffect(()=>{
    if(!f.username||f.username===user.username){setUsernameStatus('');return;}
    const t=setTimeout(async()=>{
      try{const r=await fetch('/api/username/check/'+f.username);const d=await r.json();setUsernameStatus(d.available?'available':'taken');}catch(e){}
    },400);
    return()=>clearTimeout(t);
  },[f.username]);

  const save=async e=>{
    e.preventDefault();setErr('');setSuccess('');setSaving(true);
    try{
      const payload={...f};
      if(!payload.new_password)delete payload.new_password;
      if(!payload.current_password)delete payload.current_password;
      const r=await fetch('/api/user/settings',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(payload)});
      const d=await r.json();
      if(r.ok){setSuccess('Settings saved!');setTimeout(()=>onSave(d.user),800);}
      else setErr(d.error||'Save failed');
    }catch(e){setErr('Network error');}
    setSaving(false);
  };

  return(
    <div className="overlay" onClick={onClose}>
      <div className="modal" style={{maxWidth:620}} onClick={e=>e.stopPropagation()}>
        <div className="mtitle">Settings</div>
        {err&&<div className="err-box">{err}</div>}
        {success&&<div className="success-box">{success}</div>}
        <form onSubmit={save}>
          {/* Profile */}
          <div className="settings-section">
            <div className="settings-title">Profile</div>
            <div className="frow">
              <div className="field"><label>Full name</label><input value={f.full_name} onChange={e=>setF({...f,full_name:e.target.value})}/></div>
              <div className="field"><label>Location</label><input value={f.location} onChange={e=>setF({...f,location:e.target.value})} placeholder="New York, NY"/></div>
            </div>
            <div className="field"><label>Bio</label><textarea value={f.bio} onChange={e=>setF({...f,bio:e.target.value})} placeholder="Tell others about your investing strategy..."/></div>
          </div>
          {/* Account */}
          <div className="settings-section">
            <div className="settings-title">Account</div>
            <div className="frow">
              <div className="field">
                <label>Username</label>
                <input value={f.username} onChange={e=>setF({...f,username:e.target.value.toLowerCase().replace(/\s/g,'')})}/>
                {usernameStatus&&f.username!==user.username&&<div className={'ticker-avail '+(usernameStatus==='available'?'yes':'no')} style={{fontSize:11}}>{usernameStatus==='available'?'✓ Available':'✗ Already taken'}</div>}
              </div>
              <div className="field"><label>Email</label><input type="email" value={f.email} onChange={e=>setF({...f,email:e.target.value})}/></div>
            </div>
          </div>
          {/* Portfolio */}
          <div className="settings-section">
            <div className="settings-title">Portfolio Identity</div>
            <div className="frow">
              <div className="field"><label>Portfolio name</label><input value={f.portfolio_name} onChange={e=>setF({...f,portfolio_name:e.target.value})}/></div>
              <div className="field">
                <label>Ticker symbol</label>
                <input className="mono-input" value={f.ticker} onChange={e=>setF({...f,ticker:e.target.value.toUpperCase().replace(/[^A-Z]/g,'').slice(0,4)})} maxLength={4}/>
                {f.ticker!==user.ticker&&f.ticker.length===4&&<div className={'ticker-avail '+(tickerStatus==='available'?'yes':'no')} style={{fontSize:11}}>{tickerStatus==='available'?'✓ Available':'✗ Already taken'}</div>}
                {f.ticker===user.ticker&&<div style={{fontSize:11,color:'#9ca3af',marginTop:3}}>Current: ${user.ticker}</div>}
              </div>
            </div>
          </div>
          {/* Accent color */}
          <div className="settings-section">
            <div className="settings-title">App Color</div>
            <div className="color-grid">
              {ACCENT_COLORS.map(c=>(
                <div key={c.val} className={'color-swatch'+(f.accent_color===c.val?' selected':'')} style={{background:c.val}} title={c.name} onClick={()=>setF({...f,accent_color:c.val})}/>
              ))}
            </div>
          </div>
          {/* Password */}
          <div className="settings-section">
            <div className="settings-title">Change Password <span style={{fontWeight:400,color:'#9ca3af',fontSize:12}}>(leave blank to keep current)</span></div>
            <div className="frow">
              <div className="field"><label>Current password</label><input type="password" value={f.current_password} onChange={e=>setF({...f,current_password:e.target.value})}/></div>
              <div className="field"><label>New password</label><input type="password" value={f.new_password} onChange={e=>setF({...f,new_password:e.target.value})}/></div>
            </div>
          </div>
          <div className="mfoot">
            <button type="button" style={{background:'var(--gray-100)',color:'var(--gray-700)'}} onClick={onClose}>Cancel</button>
            <button type="submit" style={{background:'var(--blue)',color:'#fff'}} disabled={saving}>{saving?'Saving...':'Save changes'}</button>
          </div>
        </form>
      </div>
    </div>
  );
}

// ── ADD PROPERTY MODAL (with Zillow search) ───────────────────────────────────
function AddPropModal({userId,onClose,onSave}) {
  const [step,setStep]=useState('search'); // search | manual | confirm
  const [query,setQuery]=useState('');
  const [suggestions,setSuggestions]=useState([]);
  const [searching,setSearching]=useState(false);
  const [zData,setZData]=useState(null);
  const [f,setF]=useState({name:'',location:'',purchase_price:0,down_payment:0,mortgage:0,insurance:0,hoa:0,property_tax:0,monthly_revenue:0,zestimate:0,zpid:''});
  const [saving,setSaving]=useState(false);

  // Debounced Zillow search - direct from browser to bypass server blocks
  useEffect(()=>{
    if(query.length<5){setSuggestions([]);return;}
    const t=setTimeout(async()=>{
      setSearching(true);
      try{
        // Try direct Zillow autocomplete from browser
        const encoded=encodeURIComponent(query);
        const r=await fetch(`https://www.zillowstatic.com/autocomplete/v3/suggestions?q=${encoded}&abKey=&clientId=homepage-render`,{
          headers:{'Accept':'application/json'}
        });
        if(r.ok){
          const d=await r.json();
          setSuggestions((d.results||[]).slice(0,6).map(i=>({display:i.display||'',zpid:i.zpid||'',type:i.resultType||''})));
        } else {
          // Fallback to server proxy
          const r2=await fetch('/api/zillow/search?address='+encoded,{credentials:'include'});
          const d2=await r2.json();
          setSuggestions(d2.results||[]);
        }
      }catch(e){
        // Final fallback to server
        try{
          const r3=await fetch('/api/zillow/search?address='+encodeURIComponent(query),{credentials:'include'});
          const d3=await r3.json();
          setSuggestions(d3.results||[]);
        }catch(e2){}
      }
      setSearching(false);
    },500);
    return()=>clearTimeout(t);
  },[query]);

  const selectAddress=async item=>{
    setSuggestions([]);
    setQuery(item.display);
    setF(prev=>({...prev,
      name: item.display.split(',')[0],
      location: item.display,
      zpid: item.zpid||''
    }));
    if(item.zpid){
      setSearching(true);
      try{
        const r=await fetch('/api/zillow/property?zpid='+item.zpid+'&address='+encodeURIComponent(item.display),{credentials:'include'});
        const d=await r.json();
        setZData(d);
        setF(prev=>({...prev,
          name: item.display.split(',')[0],
          location: item.display,
          purchase_price: d.zestimate||0,
          zestimate: d.zestimate||0,
          property_tax: d.monthlyTax||0,
          zpid: item.zpid||''
        }));
      }catch(e){}
      setSearching(false);
    }
    setStep('confirm');
  };

  const submit=async e=>{
    e.preventDefault();setSaving(true);
    try{
      await fetch('/api/properties/'+userId,{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify(f)});
      onSave();
    }catch(e){}
    setSaving(false);
  };

  return(
    <div className="overlay" onClick={onClose}>
      <div className="modal" onClick={e=>e.stopPropagation()}>
        <div className="mtitle">Add Property</div>

        {/* Step 1: Zillow search */}
        {(step==='search'||step==='confirm')&&<>
          <div className="field">
            <label>Search Zillow</label>
            <input value={query} onChange={e=>setQuery(e.target.value)} placeholder="123 Main St, Houston, TX" autoFocus/>
            {searching&&<div style={{fontSize:12,color:'#9ca3af',marginTop:4}}>Searching...</div>}
          </div>
          {suggestions.length>0&&(
            <div className="zsuggest">
              {suggestions.map((s,i)=>(
                <div key={i} className="zitem" onClick={()=>selectAddress(s)}>
                  <div style={{fontWeight:500}}>{s.display}</div>
                  <div style={{fontSize:11,color:'#9ca3af',marginTop:1}}>{s.type}</div>
                </div>
              ))}
            </div>
          )}
        </>}

        {/* Zillow data preview */}
        {step==='confirm'&&zData&&(
          <div className="zprop-card">
            <div style={{fontSize:13,fontWeight:700,marginBottom:8,color:'#065f46'}}>Data from Zillow</div>
            <div className="zprop-row"><span className="zprop-label">Zestimate</span><span className="zprop-val">{zData.zestimate?fmt$(zData.zestimate):'Not available'}</span></div>
            <div className="zprop-row"><span className="zprop-label">Est. Monthly Tax</span><span className="zprop-val">{zData.monthlyTax?fmt$(zData.monthlyTax)+'/mo':'Not available'}</span></div>
            <div className="zprop-row"><span className="zprop-label">Tax Assessed Value</span><span className="zprop-val">{zData.taxAssessedValue?fmt$(zData.taxAssessedValue):'Not available'}</span></div>
          </div>
        )}

        {/* Property form */}
        {(step==='confirm'||step==='manual')&&(
          <form onSubmit={submit}>
            <div className="frow">
              <div className="field"><label>Property name</label><input value={f.name} onChange={e=>setF({...f,name:e.target.value})} required/></div>
              <div className="field"><label>Location</label><input value={f.location} onChange={e=>setF({...f,location:e.target.value})}/></div>
            </div>
            <div className="frow">
              <div className="field"><label>Purchase / List Price</label><input type="number" value={f.purchase_price} onChange={e=>setF({...f,purchase_price:+e.target.value||0})}/></div>
              <div className="field"><label>Down Payment</label><input type="number" value={f.down_payment} onChange={e=>setF({...f,down_payment:+e.target.value||0})}/></div>
            </div>
            <div className="frow">
              <div className="field"><label>Monthly Mortgage</label><input type="number" value={f.mortgage} onChange={e=>setF({...f,mortgage:+e.target.value||0})}/></div>
              <div className="field"><label>Monthly Revenue</label><input type="number" value={f.monthly_revenue} onChange={e=>setF({...f,monthly_revenue:+e.target.value||0})}/></div>
            </div>
            <div className="frow">
              <div className="field"><label>Insurance /mo</label><input type="number" value={f.insurance} onChange={e=>setF({...f,insurance:+e.target.value||0})}/></div>
              <div className="field"><label>Property Tax /mo</label><input type="number" value={f.property_tax} onChange={e=>setF({...f,property_tax:+e.target.value||0})}/></div>
            </div>
            {f.zestimate>0&&<div className="info-box">Zestimate of {fmt$(f.zestimate)} will be used for equity calculation. Update purchase price to override.</div>}
            <div className="mfoot">
              <button type="button" style={{background:'var(--gray-100)',color:'var(--gray-700)'}} onClick={()=>setStep('search')}>Back</button>
              <button type="submit" style={{background:'var(--blue)',color:'#fff'}} disabled={saving}>{saving?'Saving...':'Add Property'}</button>
            </div>
          </form>
        )}

        {/* Manual entry link */}
        {step==='search'&&!searching&&(
          <div style={{textAlign:'center',marginTop:16}}>
            <button className="btn btn-ghost btn-sm" onClick={()=>setStep('manual')}>Enter manually instead</button>
          </div>
        )}
        {step==='manual'&&(
          <form onSubmit={submit}>
            <div className="frow">
              <div className="field"><label>Property name</label><input value={f.name} onChange={e=>setF({...f,name:e.target.value})} required/></div>
              <div className="field"><label>Location</label><input value={f.location} onChange={e=>setF({...f,location:e.target.value})}/></div>
            </div>
            <div className="frow">
              <div className="field"><label>Purchase Price</label><input type="number" value={f.purchase_price} onChange={e=>setF({...f,purchase_price:+e.target.value||0})}/></div>
              <div className="field"><label>Down Payment</label><input type="number" value={f.down_payment} onChange={e=>setF({...f,down_payment:+e.target.value||0})}/></div>
            </div>
            <div className="frow">
              <div className="field"><label>Monthly Mortgage</label><input type="number" value={f.mortgage} onChange={e=>setF({...f,mortgage:+e.target.value||0})}/></div>
              <div className="field"><label>Monthly Revenue</label><input type="number" value={f.monthly_revenue} onChange={e=>setF({...f,monthly_revenue:+e.target.value||0})}/></div>
            </div>
            <div className="frow">
              <div className="field"><label>Insurance /mo</label><input type="number" value={f.insurance} onChange={e=>setF({...f,insurance:+e.target.value||0})}/></div>
              <div className="field"><label>Property Tax /mo</label><input type="number" value={f.property_tax} onChange={e=>setF({...f,property_tax:+e.target.value||0})}/></div>
            </div>
            <div className="mfoot">
              <button type="button" style={{background:'var(--gray-100)',color:'var(--gray-700)'}} onClick={onClose}>Cancel</button>
              <button type="submit" style={{background:'var(--blue)',color:'#fff'}} disabled={saving}>{saving?'Saving...':'Add Property'}</button>
            </div>
          </form>
        )}
      </div>
    </div>
  );
}

// ── PLAID MODAL ───────────────────────────────────────────────────────────────
function PlaidModal({onClose}) {
  const [status,setStatus]=useState('idle');
  const connect=async()=>{
    setStatus('loading');
    try{
      const r=await fetch('/api/plaid/create-link-token',{credentials:'include'});
      const d=await r.json();
      if(d.link_token){
        if(typeof window.Plaid==='undefined'){setStatus('no-sdk');return;}
        const handler=window.Plaid.create({
          token:d.link_token,
          onSuccess:async(publicToken)=>{
            await fetch('/api/plaid/exchange-token',{method:'POST',headers:{'Content-Type':'application/json'},credentials:'include',body:JSON.stringify({public_token:publicToken})});
            setStatus('connected');
            setTimeout(onClose,2000);
          },
          onExit:()=>setStatus('idle'),
          onEvent:()=>{}
        });
        handler.open();
        setStatus('idle');
      } else {
        setStatus('no-keys');
      }
    }catch(e){setStatus('error');}
  };
  return(
    <div className="overlay" onClick={onClose}>
      <div className="modal" style={{maxWidth:480}} onClick={e=>e.stopPropagation()}>
        <div className="mtitle">Connect Bank Account</div>
        <div className="info-box" style={{marginBottom:14}}>Plaid securely connects your bank to auto-import rental income and mortgage payments. Your credentials are never stored.</div>
        {status==='connected'&&<div className="success-box">Bank account connected successfully!</div>}
        {status==='error'&&<div className="err-box">Connection failed. Please try again.</div>}
        {status==='no-sdk'&&<div className="err-box">Plaid SDK failed to load. Check your internet connection.</div>}
        {status==='no-keys'&&<div className="warn-box">
          <strong>Plaid API keys not configured.</strong><br/>
          To enable bank connections, add these to your Render environment variables:<br/><br/>
          <code style={{background:'#fff',padding:'2px 6px',borderRadius:4,fontSize:12,display:'block',marginTop:4}}>PLAID_CLIENT_ID = your_client_id</code>
          <code style={{background:'#fff',padding:'2px 6px',borderRadius:4,fontSize:12,display:'block',marginTop:4}}>PLAID_SECRET = your_sandbox_secret</code>
          <br/>Get free keys at <strong>dashboard.plaid.com</strong>
        </div>}
        <div style={{display:'flex',gap:8}}>
          <button className="btn btn-ghost" style={{flex:1}} onClick={onClose}>Cancel</button>
          <button className="btn btn-blue" style={{flex:2}} onClick={connect} disabled={status==='loading'||status==='connected'}>
            {status==='loading'?'Opening Plaid...':status==='connected'?'Connected!':'Connect with Plaid'}
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


# ── AUTH ROUTES ───────────────────────────────────────────────────────────────
@app.route('/')
def index():
    return HTML

@app.route('/api/auth/signup', methods=['POST'])
def signup():
    d = request.json
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id FROM users WHERE username=%s OR email=%s", (d['username'], d['email']))
            if cur.fetchone():
                return jsonify({'error': 'Username or email already exists'}), 400
            chosen = (d.get('ticker') or '').upper().strip()[:4]
            ticker = chosen if chosen else generate_ticker(d['portfolio_name'])
            if chosen:
                cur.execute("SELECT id FROM users WHERE ticker=%s", (ticker,))
                if cur.fetchone():
                    return jsonify({'error': 'Ticker already taken, please choose another'}), 400
            cur.execute("""INSERT INTO users(username,email,password_hash,full_name,portfolio_name,ticker)
                VALUES(%s,%s,%s,%s,%s,%s) RETURNING id,username,full_name,portfolio_name,ticker""",
                (d['username'], d['email'], hash_password(d['password']), d.get('full_name',''), d['portfolio_name'], ticker))
            u = dict(cur.fetchone())
            conn.commit(); cur.close()
            session['user_id'] = u['id']
            update_metrics(u['id'])
            return jsonify({'user': u})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/login', methods=['POST'])
def login():
    d = request.json
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id,username,password_hash,full_name,portfolio_name,ticker,accent_color FROM users WHERE username=%s OR email=%s", (d['username'], d['username']))
            u = cur.fetchone(); cur.close()
            if not u or not verify_password(d['password'], u['password_hash']):
                return jsonify({'error': 'Invalid username or password'}), 401
            session['user_id'] = u['id']
            ud = dict(u); del ud['password_hash']
            return jsonify({'user': ud})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/auth/logout', methods=['POST'])
def logout():
    session.clear()
    return jsonify({'success': True})

@app.route('/api/auth/me')
def get_me():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT id,username,full_name,portfolio_name,ticker,bio,location,accent_color,email FROM users WHERE id=%s", (uid,))
            u = cur.fetchone(); cur.close()
            if not u: return jsonify({'error': 'Not found'}), 404
            return jsonify(dict(u))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── USER ROUTES ───────────────────────────────────────────────────────────────
@app.route('/api/ticker/check/<ticker>')
def check_ticker(ticker):
    t = ticker.upper().strip()[:4]
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE ticker=%s", (t,))
            taken = cur.fetchone() is not None
            cur.close()
            return jsonify({'available': not taken, 'ticker': t})
    except Exception as e:
        return jsonify({'available': False, 'error': str(e)})

@app.route('/api/username/check/<username>')
def check_username(username):
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("SELECT id FROM users WHERE username=%s", (username.lower(),))
            taken = cur.fetchone() is not None
            cur.close()
            return jsonify({'available': not taken})
    except Exception as e:
        return jsonify({'available': False})

@app.route('/api/user/settings', methods=['POST'])
def update_settings():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            if d.get('ticker'):
                new_ticker = d['ticker'].upper().strip()[:4]
                cur.execute("SELECT id FROM users WHERE ticker=%s AND id!=%s", (new_ticker, uid))
                if cur.fetchone(): return jsonify({'error': 'Ticker already taken'}), 400
                d['ticker'] = new_ticker
            if d.get('username'):
                cur.execute("SELECT id FROM users WHERE username=%s AND id!=%s", (d['username'], uid))
                if cur.fetchone(): return jsonify({'error': 'Username already taken'}), 400
            if d.get('email'):
                cur.execute("SELECT id FROM users WHERE email=%s AND id!=%s", (d['email'], uid))
                if cur.fetchone(): return jsonify({'error': 'Email already in use'}), 400
            if d.get('new_password'):
                if not d.get('current_password'):
                    return jsonify({'error': 'Current password required'}), 400
                cur.execute("SELECT password_hash FROM users WHERE id=%s", (uid,))
                row = cur.fetchone()
                if not verify_password(d['current_password'], row['password_hash']):
                    return jsonify({'error': 'Current password incorrect'}), 400
                d['password_hash'] = hash_password(d['new_password'])
            allowed = ['full_name','username','email','bio','location','portfolio_name','ticker','password_hash','accent_color']
            updates = {k: v for k, v in d.items() if k in allowed and v is not None and v != ''}
            if not updates: return jsonify({'error': 'Nothing to update'}), 400
            set_clause = ', '.join(f"{k}=%s" for k in updates)
            values = list(updates.values()) + [uid]
            cur.execute(f"UPDATE users SET {set_clause} WHERE id=%s RETURNING id,username,full_name,portfolio_name,ticker,bio,location,accent_color,email", values)
            user = dict(cur.fetchone())
            conn.commit(); cur.close()
            if 'ticker' in updates: update_metrics(uid)
            return jsonify({'user': user})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/users/discover')
def discover():
    uid = session.get('user_id')
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""SELECT u.id,u.username,u.full_name,u.portfolio_name,u.ticker,
                COALESCE(pm.health_score,0) as health_score, COALESCE(pm.share_price,0) as share_price,
                COALESCE(pm.property_count,0) as property_count
                FROM users u LEFT JOIN portfolio_metrics pm ON u.id=pm.user_id
                WHERE u.id!=%s ORDER BY pm.health_score DESC NULLS LAST LIMIT 50""", (uid or 0,))
            rows = cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── FOLLOW ROUTES ─────────────────────────────────────────────────────────────
@app.route('/api/follow/<int:fid>', methods=['POST'])
def follow(fid):
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO follows(follower_id,following_id) VALUES(%s,%s) ON CONFLICT DO NOTHING", (uid, fid))
            conn.commit(); cur.close()
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/unfollow/<int:fid>', methods=['POST'])
def unfollow(fid):
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    try:
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM follows WHERE follower_id=%s AND following_id=%s", (uid, fid))
            conn.commit(); cur.close()
            return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/following')
def get_following():
    uid = session.get('user_id')
    if not uid: return jsonify([])
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT following_id FROM follows WHERE follower_id=%s", (uid,))
            rows = cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/feed')
def get_feed():
    uid = session.get('user_id')
    if not uid: return jsonify([])
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("""SELECT fi.id,fi.type,fi.content,fi.created_at,u.full_name as user_name
                FROM feed_items fi JOIN users u ON fi.user_id=u.id
                WHERE fi.user_id IN(SELECT following_id FROM follows WHERE follower_id=%s)
                ORDER BY fi.created_at DESC LIMIT 50""", (uid,))
            rows = cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── PORTFOLIO & PROPERTY ROUTES ───────────────────────────────────────────────
@app.route('/api/portfolio/<int:uid>')
def get_portfolio(uid):
    try:
        update_metrics(uid)
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT u.ticker,pm.* FROM portfolio_metrics pm JOIN users u ON pm.user_id=u.id WHERE pm.user_id=%s", (uid,))
            p = cur.fetchone(); cur.close()
            if not p: return jsonify({'ticker':'XXXX','health_score':0,'share_price':0,'total_equity':0,'annual_cashflow':0,'property_count':0})
            return jsonify(dict(p))
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/properties/<int:uid>')
def get_properties(uid):
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            cur.execute("SELECT * FROM properties WHERE user_id=%s ORDER BY created_at DESC", (uid,))
            rows = cur.fetchall(); cur.close()
            return jsonify([dict(r) for r in rows])
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/properties/<int:uid>', methods=['POST'])
def add_property(uid):
    d = request.json
    try:
        with get_db() as conn:
            cur = conn.cursor(cursor_factory=RealDictCursor)
            exp = d.get('mortgage',0) + d.get('insurance',0) + d.get('hoa',0) + d.get('property_tax',0)
            zest = d.get('zestimate', 0) or 0
            cur.execute("""INSERT INTO properties(user_id,name,location,purchase_price,down_payment,equity,zestimate,mortgage,insurance,hoa,property_tax,monthly_revenue,monthly_expenses,zpid)
                VALUES(%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING *""",
                (uid, d['name'], d.get('location',''), d.get('purchase_price',0), d.get('down_payment',0),
                 max(zest, d.get('down_payment',0)), zest,
                 d.get('mortgage',0), d.get('insurance',0), d.get('hoa',0), d.get('property_tax',0),
                 d.get('monthly_revenue',0), exp, d.get('zpid','')))
            prop = dict(cur.fetchone())
            content_str = json.dumps({"text": f"Added a new property: {d['name']}", "highlight": str(d.get('location',''))})
            cur.execute("INSERT INTO feed_items(user_id,type,content) VALUES(%s,%s,%s::jsonb)", (uid, 'acquisition', content_str))
            conn.commit(); cur.close()
            update_metrics(uid)
            return jsonify(prop)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ── ZILLOW ROUTES ─────────────────────────────────────────────────────────────
@app.route('/api/zillow/search')
def zillow_search():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    address = request.args.get('address', '')
    if not address: return jsonify({'results': []})
    try:
        encoded = urllib.parse.quote(address)
        # Try multiple Zillow autocomplete endpoints
        urls = [
            f'https://www.zillowstatic.com/autocomplete/v3/suggestions?q={encoded}&abKey=&clientId=homepage-render',
            f'https://www.zillow.com/search/GetSearchPageState.htm?searchQueryState=%7B%22usersSearchTerm%22%3A%22{encoded}%22%7D',
        ]
        headers = {
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json, text/plain, */*',
            'Accept-Language': 'en-US,en;q=0.9',
            'Referer': 'https://www.zillow.com/',
            'Origin': 'https://www.zillow.com',
            'sec-ch-ua': '"Not_A Brand";v="8", "Chromium";v="120"',
            'sec-ch-ua-mobile': '?0',
            'sec-ch-ua-platform': '"macOS"',
        }
        req = urllib.request.Request(urls[0], headers=headers)
        resp = urllib.request.urlopen(req, timeout=8)
        data = json.loads(resp.read())
        results = []
        for item in (data.get('results') or [])[:6]:
            results.append({
                'display': item.get('display',''),
                'zpid': item.get('zpid',''),
                'type': item.get('resultType','')
            })
        return jsonify({'results': results})
    except Exception as e:
        # Fallback: use Census geocoder to at least validate address
        try:
            encoded2 = urllib.parse.quote(address)
            census_url = f'https://geocoding.geo.census.gov/geocoder/locations/onelineaddress?address={encoded2}&benchmark=2020&format=json'
            req2 = urllib.request.Request(census_url, headers={'User-Agent': 'PropertyPigeon/1.0'})
            resp2 = urllib.request.urlopen(req2, timeout=5)
            cdata = json.loads(resp2.read())
            matches = cdata.get('result',{}).get('addressMatches',[])
            results = []
            for m in matches[:3]:
                addr = m.get('matchedAddress','')
                coords = m.get('coordinates',{})
                results.append({
                    'display': addr,
                    'zpid': '',
                    'type': 'address',
                    'lat': coords.get('y'),
                    'lon': coords.get('x')
                })
            return jsonify({'results': results})
        except Exception as e2:
            return jsonify({'results': [], 'error': str(e)+' | '+str(e2)})

@app.route('/api/zillow/property')
def zillow_property():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    address = request.args.get('address', '')
    try:
        encoded_addr = urllib.parse.quote(address.replace(' ','-').replace(',','-').replace('--','-'))
        url = f'https://www.zillow.com/homes/{encoded_addr}_rb/'
        req = urllib.request.Request(url, headers={
            'User-Agent': 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.9',
        })
        resp = urllib.request.urlopen(req, timeout=8)
        html = resp.read().decode('utf-8', errors='ignore')
        zestimate = None
        tax_annual = None
        tax_assessed = None
        m = re.search(r'"zestimate"\s*:\s*\{[^}]*"amount"\s*:\s*(\d+)', html)
        if m: zestimate = int(m.group(1))
        m2 = re.search(r'"taxAnnualAmount"\s*:\s*(\d+)', html)
        if m2: tax_annual = int(m2.group(1))
        m3 = re.search(r'"taxAssessedValue"\s*:\s*(\d+)', html)
        if m3: tax_assessed = int(m3.group(1))
        return jsonify({
            'address': address,
            'zestimate': zestimate,
            'taxAssessedValue': tax_assessed,
            'taxAnnualAmount': tax_annual,
            'monthlyTax': round(tax_annual / 12) if tax_annual else None,
        })
    except Exception as e:
        return jsonify({'address': address, 'zestimate': None, 'error': str(e)})

# ── PLAID ROUTES ──────────────────────────────────────────────────────────────
@app.route('/api/plaid/create-link-token')
def plaid_link():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    if not PLAID_CLIENT_ID or not PLAID_SECRET:
        return jsonify({'link_token': None, 'message': 'Plaid not configured'})
    try:
        env_url = 'https://sandbox.plaid.com' if PLAID_ENV == 'sandbox' else 'https://production.plaid.com'
        payload = json.dumps({
            'client_id': PLAID_CLIENT_ID, 'secret': PLAID_SECRET,
            'user': {'client_user_id': str(uid)},
            'client_name': 'Property Pigeon',
            'products': ['transactions'],
            'country_codes': ['US'],
            'language': 'en'
        }).encode()
        req = urllib.request.Request(env_url + '/link/token/create', data=payload, headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        return jsonify({'link_token': data.get('link_token')})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/plaid/exchange-token', methods=['POST'])
def plaid_exchange():
    uid = session.get('user_id')
    if not uid: return jsonify({'error': 'Not authenticated'}), 401
    d = request.json
    if not PLAID_CLIENT_ID: return jsonify({'success': True, 'message': 'Sandbox'})
    try:
        env_url = 'https://sandbox.plaid.com' if PLAID_ENV == 'sandbox' else 'https://production.plaid.com'
        payload = json.dumps({'client_id': PLAID_CLIENT_ID, 'secret': PLAID_SECRET, 'public_token': d.get('public_token')}).encode()
        req = urllib.request.Request(env_url + '/item/public_token/exchange', data=payload, headers={'Content-Type': 'application/json'})
        resp = urllib.request.urlopen(req)
        data = json.loads(resp.read())
        with get_db() as conn:
            cur = conn.cursor()
            cur.execute("INSERT INTO plaid_items(user_id,access_token,item_id) VALUES(%s,%s,%s)", (uid, data.get('access_token'), data.get('item_id')))
            conn.commit(); cur.close()
        return jsonify({'success': True})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
