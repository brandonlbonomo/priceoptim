from flask import Flask, jsonify, request, session, redirect
from flask_cors import CORS
import os
import hashlib
import secrets
from datetime import datetime, timedelta
import psycopg2
from psycopg2.extras import RealDictCursor
from contextlib import contextmanager

app = Flask(**name**)
app.secret_key = os.environ.get(‘SECRET_KEY’, secrets.token_hex(32))
CORS(app, supports_credentials=True)

# Database connection

DATABASE_URL = os.environ.get(‘DATABASE_URL’, ‘postgresql://localhost/propertypigeon’)

@contextmanager
def get_db():
conn = psycopg2.connect(DATABASE_URL)
try:
yield conn
finally:
conn.close()

def init_db():
“”“Initialize database tables”””
with get_db() as conn:
cur = conn.cursor()

```
    # Users table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id SERIAL PRIMARY KEY,
            username VARCHAR(50) UNIQUE NOT NULL,
            email VARCHAR(255) UNIQUE NOT NULL,
            password_hash VARCHAR(255) NOT NULL,
            full_name VARCHAR(100),
            portfolio_name VARCHAR(100) NOT NULL,
            ticker VARCHAR(10) UNIQUE,
            bio TEXT,
            location VARCHAR(100),
            avatar VARCHAR(10) DEFAULT '👤',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Properties table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS properties (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            name VARCHAR(100) NOT NULL,
            location VARCHAR(100),
            purchase_price DECIMAL(12, 2) DEFAULT 0,
            down_payment DECIMAL(12, 2) DEFAULT 0,
            equity DECIMAL(12, 2) DEFAULT 0,
            mortgage DECIMAL(10, 2) DEFAULT 0,
            insurance DECIMAL(10, 2) DEFAULT 0,
            hoa DECIMAL(10, 2) DEFAULT 0,
            property_tax DECIMAL(10, 2) DEFAULT 0,
            monthly_revenue DECIMAL(10, 2) DEFAULT 0,
            monthly_expenses DECIMAL(10, 2) DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Follows table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS follows (
            follower_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            following_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            PRIMARY KEY (follower_id, following_id)
        )
    """)
    
    # Feed items table
    cur.execute("""
        CREATE TABLE IF NOT EXISTS feed_items (
            id SERIAL PRIMARY KEY,
            user_id INTEGER REFERENCES users(id) ON DELETE CASCADE,
            type VARCHAR(50) NOT NULL,
            content JSONB,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    # Portfolio metrics table (cached calculations)
    cur.execute("""
        CREATE TABLE IF NOT EXISTS portfolio_metrics (
            user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
            health_score INTEGER DEFAULT 0,
            share_price DECIMAL(10, 2) DEFAULT 0,
            total_equity DECIMAL(12, 2) DEFAULT 0,
            annual_cashflow DECIMAL(12, 2) DEFAULT 0,
            property_count INTEGER DEFAULT 0,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    
    conn.commit()
    cur.close()
```

def hash_password(password):
“”“Hash password with salt”””
salt = secrets.token_hex(16)
pwd_hash = hashlib.pbkdf2_hmac(‘sha256’, password.encode(), salt.encode(), 100000)
return f”{salt}${pwd_hash.hex()}”

def verify_password(password, password_hash):
“”“Verify password against hash”””
try:
salt, pwd_hash = password_hash.split(’$’)
new_hash = hashlib.pbkdf2_hmac(‘sha256’, password.encode(), salt.encode(), 100000)
return new_hash.hex() == pwd_hash
except:
return False

def generate_ticker(name):
“”“Generate 4-letter ticker from portfolio name”””
words = name.upper().replace(”‘S”, “”).replace(”’”, “”).split()
if len(words) == 1:
return words[0][:4].ljust(4, ‘X’)
return ‘’.join(w[0] for w in words[:4]).ljust(4, ‘X’)

def calculate_health_score(metrics):
“”“Calculate 0-100 health score”””
if not metrics or metrics.get(‘property_count’, 0) == 0:
return 0

```
# Financial Strength (40 pts)
dscr = metrics.get('dscr', 0)
coc_return = metrics.get('coc_return', 0)
equity_ratio = metrics.get('equity_ratio', 0)
financial = min(40, min(15, dscr * 10) + min(15, coc_return / 2) + min(10, equity_ratio * 10))

# Performance (30 pts)
occupancy = metrics.get('avg_occupancy', 0)
revenue_growth = metrics.get('revenue_growth', 0)
profit_margin = metrics.get('profit_margin', 0)
performance = min(30, min(15, occupancy * 0.3) + min(10, revenue_growth * 50) + min(5, profit_margin * 0.5))

# Risk Management (20 pts)
property_count = metrics.get('property_count', 0)
diversification = min(10, property_count * 1.5)
cash_reserves = min(5, metrics.get('cash_reserves', 0) / 10000)
debt_ratio = max(0, 5 - (metrics.get('debt_ratio', 0) * 5))
risk = diversification + cash_reserves + debt_ratio

# Growth (10 pts)
growth_rate = metrics.get('growth_rate', 0)
momentum = metrics.get('momentum', 0)
growth = min(10, (growth_rate * 2.5) + (momentum * 2.5))

return min(100, max(0, round(financial + performance + risk + growth)))
```

def calculate_share_price(metrics):
“”“Calculate portfolio share price”””
equity = metrics.get(‘total_equity’, 0)
annual_cashflow = metrics.get(‘annual_cashflow’, 0)
health_score = metrics.get(‘health_score’, 0)
property_count = metrics.get(‘property_count’, 0)

```
price = (
    (equity / 1000) * 0.4 +
    (annual_cashflow * 2) * 0.3 +
    (health_score * 5) * 0.2 +
    (property_count * 10) * 0.1
)
return round(max(1, price), 2)
```

def update_portfolio_metrics(user_id):
“”“Recalculate and cache portfolio metrics”””
with get_db() as conn:
cur = conn.cursor(cursor_factory=RealDictCursor)

```
    # Get properties
    cur.execute("""
        SELECT 
            COUNT(*) as property_count,
            COALESCE(SUM(equity), 0) as total_equity,
            COALESCE(SUM(monthly_revenue), 0) as monthly_revenue,
            COALESCE(SUM(monthly_expenses), 0) as monthly_expenses
        FROM properties
        WHERE user_id = %s
    """, (user_id,))
    
    data = cur.fetchone()
    
    # Calculate metrics
    monthly_income = float(data['monthly_revenue'] or 0)
    monthly_expenses = float(data['monthly_expenses'] or 0)
    annual_cashflow = (monthly_income - monthly_expenses) * 12
    
    metrics = {
        'property_count': data['property_count'],
        'total_equity': float(data['total_equity'] or 0),
        'annual_cashflow': annual_cashflow,
        'dscr': monthly_income / monthly_expenses if monthly_expenses > 0 else 1.45,
        'coc_return': 15.5,  # Will calculate from real data
        'equity_ratio': 0.35,
        'avg_occupancy': 78,
        'revenue_growth': 0.125,
        'profit_margin': ((monthly_income - monthly_expenses) / monthly_income * 100) if monthly_income > 0 else 35,
        'cash_reserves': 50000,
        'debt_ratio': 0.65,
        'growth_rate': 2.1,
        'momentum': 3.2
    }
    
    health_score = calculate_health_score(metrics)
    metrics['health_score'] = health_score
    share_price = calculate_share_price(metrics)
    
    # Update cache
    cur.execute("""
        INSERT INTO portfolio_metrics (user_id, health_score, share_price, total_equity, annual_cashflow, property_count, updated_at)
        VALUES (%s, %s, %s, %s, %s, %s, CURRENT_TIMESTAMP)
        ON CONFLICT (user_id) 
        DO UPDATE SET 
            health_score = EXCLUDED.health_score,
            share_price = EXCLUDED.share_price,
            total_equity = EXCLUDED.total_equity,
            annual_cashflow = EXCLUDED.annual_cashflow,
            property_count = EXCLUDED.property_count,
            updated_at = CURRENT_TIMESTAMP
    """, (user_id, health_score, share_price, metrics['total_equity'], annual_cashflow, data['property_count']))
    
    conn.commit()
    cur.close()
    
    return metrics
```

# Initialize database on startup

try:
init_db()
except Exception as e:
print(f”Database initialization error: {e}”)

HTML = “””<!DOCTYPE html>

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Property Pigeon - Social Investment Network</title>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { font-family: 'Inter', sans-serif; background: linear-gradient(180deg, #1e66f5 0%, #2874f7 100%); color: #1a1a1a; min-height: 100vh; }

```
    /* Auth Screen */
    .auth-container { min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 20px; }
    .auth-card { background: #fff; border-radius: 20px; padding: 40px; max-width: 440px; width: 100%; box-shadow: 0 8px 32px rgba(0,0,0,0.2); }
    .auth-logo { font-size: 48px; text-align: center; margin-bottom: 16px; }
    .auth-title { font-size: 28px; font-weight: 800; text-align: center; margin-bottom: 8px; }
    .auth-subtitle { font-size: 14px; color: #666; text-align: center; margin-bottom: 32px; }
    
    .form-group { margin-bottom: 20px; }
    .form-label { display: block; font-size: 14px; font-weight: 600; margin-bottom: 8px; }
    .form-input { width: 100%; padding: 12px 16px; border: 2px solid #e0e0e0; border-radius: 12px; font-size: 15px; font-family: inherit; }
    .form-input:focus { outline: none; border-color: #1e66f5; }
    
    .btn { width: 100%; padding: 14px; border-radius: 12px; font-size: 15px; font-weight: 600; cursor: pointer; border: none; font-family: inherit; transition: all 0.2s; }
    .btn-primary { background: #1e66f5; color: #fff; }
    .btn-primary:hover { background: #155cc7; }
    .btn-secondary { background: #f0f0f0; color: #1a1a1a; margin-top: 12px; }
    
    .error-message { background: #fee2e2; color: #991b1b; padding: 12px; border-radius: 8px; margin-bottom: 20px; font-size: 14px; }
    
    /* Main App Styles (same as before) */
    .app { display: flex; flex-direction: column; min-height: 100vh; }
    .header { padding: 20px 24px; display: flex; justify-content: space-between; align-items: center; }
    .logo { font-size: 28px; font-weight: 800; color: #fff; }
    .header-user { color: #fff; font-size: 14px; font-weight: 600; }
    .icon-btn { width: 40px; height: 40px; border-radius: 12px; background: rgba(255,255,255,0.15); border: none; color: #fff; font-size: 20px; cursor: pointer; }
    
    .tabs { display: flex; gap: 12px; padding: 0 24px 20px; overflow-x: auto; }
    .tab { padding: 8px 20px; border-radius: 20px; background: transparent; border: 1.5px solid rgba(255,255,255,0.3); color: rgba(255,255,255,0.8); font-size: 15px; font-weight: 600; cursor: pointer; white-space: nowrap; transition: all 0.2s; }
    .tab.active { background: #fff; border-color: #fff; color: #1e66f5; }
    
    .main { flex: 1; padding: 0 16px 80px; overflow-y: auto; }
    .card { background: #fff; border-radius: 20px; padding: 24px; margin-bottom: 16px; box-shadow: 0 2px 12px rgba(0,0,0,0.08); }
    .card-header { font-size: 15px; font-weight: 600; color: #666; margin-bottom: 16px; }
    .big-number { font-size: 48px; font-weight: 800; line-height: 1; margin-bottom: 8px; }
    .percentage { display: inline-flex; align-items: center; gap: 4px; font-size: 18px; font-weight: 700; margin-bottom: 12px; }
    .percentage.positive { color: #00c853; }
    
    .user-card { display: flex; align-items: center; gap: 12px; padding: 16px; background: #fff; border-radius: 16px; margin-bottom: 12px; }
    .user-avatar { width: 52px; height: 52px; border-radius: 50%; background: linear-gradient(135deg, #1e66f5, #2874f7); display: flex; align-items: center; justify-content: center; font-size: 24px; }
    .user-info { flex: 1; }
    .user-name { font-size: 16px; font-weight: 700; margin-bottom: 2px; }
    .user-meta { font-size: 13px; color: #666; }
    .ticker { font-family: 'Monaco', monospace; font-weight: 700; color: #1e66f5; }
    .btn-follow { padding: 8px 20px; border-radius: 20px; background: #1e66f5; color: #fff; font-size: 14px; border: none; cursor: pointer; }
    .btn-following { background: #f0f0f0; color: #666; }
</style>
```

</head>
<body>
    <div id="root"></div>

```
<script type="text/babel">
    const { useState, useEffect } = React;
    
    function App() {
        const [authenticated, setAuthenticated] = useState(false);
        const [currentUser, setCurrentUser] = useState(null);
        const [loading, setLoading] = useState(true);
        
        useEffect(() => {
            checkAuth();
        }, []);
        
        const checkAuth = async () => {
            try {
                const res = await fetch('/api/auth/me', { credentials: 'include' });
                if (res.ok) {
                    const user = await res.json();
                    setCurrentUser(user);
                    setAuthenticated(true);
                }
            } catch (error) {
                console.error('Auth check failed:', error);
            }
            setLoading(false);
        };
        
        const handleLogin = (user) => {
            setCurrentUser(user);
            setAuthenticated(true);
        };
        
        const handleLogout = async () => {
            await fetch('/api/auth/logout', { method: 'POST', credentials: 'include' });
            setAuthenticated(false);
            setCurrentUser(null);
        };
        
        if (loading) {
            return <div style={{display: 'flex', alignItems: 'center', justifyContent: 'center', minHeight: '100vh', color: '#fff'}}>Loading...</div>;
        }
        
        if (!authenticated) {
            return <AuthScreen onLogin={handleLogin} />;
        }
        
        return <MainApp currentUser={currentUser} onLogout={handleLogout} />;
    }
    
    function AuthScreen({ onLogin }) {
        const [mode, setMode] = useState('login');
        const [error, setError] = useState('');
        const [formData, setFormData] = useState({
            username: '', email: '', password: '', full_name: '', portfolio_name: ''
        });
        
        const handleSubmit = async (e) => {
            e.preventDefault();
            setError('');
            
            try {
                const endpoint = mode === 'login' ? '/api/auth/login' : '/api/auth/signup';
                const res = await fetch(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    credentials: 'include',
                    body: JSON.stringify(formData)
                });
                
                const data = await res.json();
                
                if (res.ok) {
                    onLogin(data.user);
                } else {
                    setError(data.error || 'Authentication failed');
                }
            } catch (error) {
                setError('Network error. Please try again.');
            }
        };
        
        return (
            <div className="auth-container">
                <div className="auth-card">
                    <div className="auth-logo">🐦</div>
                    <h1 className="auth-title">Property Pigeon</h1>
                    <p className="auth-subtitle">
                        {mode === 'login' ? 'Welcome back!' : 'Join the investment network'}
                    </p>
                    
                    {error && <div className="error-message">{error}</div>}
                    
                    <form onSubmit={handleSubmit}>
                        {mode === 'signup' && (
                            <>
                                <div className="form-group">
                                    <label className="form-label">Full Name</label>
                                    <input className="form-input" value={formData.full_name} onChange={e => setFormData({...formData, full_name: e.target.value})} required />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Portfolio Name</label>
                                    <input className="form-input" value={formData.portfolio_name} onChange={e => setFormData({...formData, portfolio_name: e.target.value})} placeholder="e.g., Brandon's Empire" required />
                                </div>
                            </>
                        )}
                        
                        <div className="form-group">
                            <label className="form-label">{mode === 'signup' ? 'Username' : 'Username or Email'}</label>
                            <input className="form-input" value={formData.username} onChange={e => setFormData({...formData, username: e.target.value})} required />
                        </div>
                        
                        {mode === 'signup' && (
                            <div className="form-group">
                                <label className="form-label">Email</label>
                                <input type="email" className="form-input" value={formData.email} onChange={e => setFormData({...formData, email: e.target.value})} required />
                            </div>
                        )}
                        
                        <div className="form-group">
                            <label className="form-label">Password</label>
                            <input type="password" className="form-input" value={formData.password} onChange={e => setFormData({...formData, password: e.target.value})} required />
                        </div>
                        
                        <button type="submit" className="btn btn-primary">
                            {mode === 'login' ? 'Log In' : 'Create Account'}
                        </button>
                        
                        <button type="button" className="btn btn-secondary" onClick={() => setMode(mode === 'login' ? 'signup' : 'login')}>
                            {mode === 'login' ? 'Need an account? Sign up' : 'Already have an account? Log in'}
                        </button>
                    </form>
                </div>
            </div>
        );
    }
    
    function MainApp({ currentUser, onLogout }) {
        const [currentTab, setCurrentTab] = useState('portfolio');
        const [users, setUsers] = useState([]);
        const [portfolio, setPortfolio] = useState(null);
        const [following, setFollowing] = useState(new Set());
        
        useEffect(() => {
            loadData();
        }, []);
        
        const loadData = async () => {
            try {
                const [usersRes, portfolioRes, followingRes] = await Promise.all([
                    fetch('/api/users/discover', { credentials: 'include' }),
                    fetch(`/api/portfolio/${currentUser.id}`, { credentials: 'include' }),
                    fetch('/api/following', { credentials: 'include' })
                ]);
                
                setUsers(await usersRes.json());
                setPortfolio(await portfolioRes.json());
                const followingData = await followingRes.json();
                setFollowing(new Set(followingData.map(f => f.following_id)));
            } catch (error) {
                console.error('Error loading data:', error);
            }
        };
        
        return (
            <div className="app">
                <div className="header">
                    <div className="logo">🐦 Property Pigeon</div>
                    <div style={{display: 'flex', alignItems: 'center', gap: 16}}>
                        <div className="header-user">@{currentUser.username}</div>
                        <button className="icon-btn" onClick={onLogout}>↪</button>
                    </div>
                </div>
                
                <div className="tabs">
                    <div className={`tab ${currentTab === 'portfolio' ? 'active' : ''}`} onClick={() => setCurrentTab('portfolio')}>Portfolio</div>
                    <div className={`tab ${currentTab === 'discover' ? 'active' : ''}`} onClick={() => setCurrentTab('discover')}>Discover</div>
                    <div className={`tab ${currentTab === 'feed' ? 'active' : ''}`} onClick={() => setCurrentTab('feed')}>Feed</div>
                </div>
                
                <div className="main">
                    {currentTab === 'portfolio' && <PortfolioView portfolio={portfolio} />}
                    {currentTab === 'discover' && <DiscoverView users={users} following={following} onFollow={loadData} />}
                    {currentTab === 'feed' && <FeedView />}
                </div>
            </div>
        );
    }
    
    function PortfolioView({ portfolio }) {
        if (!portfolio) return <div style={{color: '#fff', padding: 20}}>Loading...</div>;
        
        return (
            <div>
                <div className="card">
                    <div className="card-header">Portfolio value</div>
                    <div className="big-number">${portfolio.ticker || 'XXXX'} ${portfolio.share_price.toFixed(2)}</div>
                    <div className="percentage positive">↑ 12.68%</div>
                </div>
                
                <div className="card">
                    <div className="card-header">Health Score: {portfolio.health_score}/100</div>
                    <p style={{color: '#666', fontSize: 14}}>Add properties to calculate your full portfolio metrics.</p>
                </div>
            </div>
        );
    }
    
    function DiscoverView({ users, following, onFollow }) {
        const handleFollow = async (userId) => {
            try {
                await fetch(`/api/follow/${userId}`, {
                    method: 'POST',
                    credentials: 'include'
                });
                onFollow();
            } catch (error) {
                console.error('Follow error:', error);
            }
        };
        
        return (
            <div>
                <div style={{color: '#fff', fontSize: 20, fontWeight: 700, marginBottom: 16}}>Discover Investors</div>
                {users.map(user => (
                    <div key={user.id} className="user-card">
                        <div className="user-avatar">{user.avatar}</div>
                        <div className="user-info">
                            <div className="user-name">{user.full_name}</div>
                            <div className="user-meta">@{user.username} • <span className="ticker">${user.ticker}</span></div>
                        </div>
                        <button 
                            className={`btn-follow ${following.has(user.id) ? 'btn-following' : ''}`}
                            onClick={() => handleFollow(user.id)}
                        >
                            {following.has(user.id) ? 'Following' : 'Follow'}
                        </button>
                    </div>
                ))}
            </div>
        );
    }
    
    function FeedView() {
        return (
            <div>
                <div style={{color: '#fff', fontSize: 20, fontWeight: 700, marginBottom: 16}}>Your Feed</div>
                <div className="card">
                    <p style={{color: '#666', textAlign: 'center', padding: 40}}>Follow investors to see their activity here</p>
                </div>
            </div>
        );
    }
    
    ReactDOM.render(<App />, document.getElementById('root'));
</script>
```

</body>
</html>"""

@app.route(’/’)
def index():
return HTML

# Auth endpoints

@app.route(’/api/auth/signup’, methods=[‘POST’])
def signup():
data = request.json

```
try:
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Check if username/email exists
        cur.execute("SELECT id FROM users WHERE username = %s OR email = %s", 
                   (data['username'], data['email']))
        if cur.fetchone():
            return jsonify({'error': 'Username or email already exists'}), 400
        
        # Create user
        ticker = generate_ticker(data['portfolio_name'])
        password_hash = hash_password(data['password'])
        
        cur.execute("""
            INSERT INTO users (username, email, password_hash, full_name, portfolio_name, ticker)
            VALUES (%s, %s, %s, %s, %s, %s)
            RETURNING id, username, full_name, portfolio_name, ticker
        """, (data['username'], data['email'], password_hash, data['full_name'], 
              data['portfolio_name'], ticker))
        
        user = cur.fetchone()
        conn.commit()
        cur.close()
        
        # Set session
        session['user_id'] = user['id']
        
        # Initialize portfolio metrics
        update_portfolio_metrics(user['id'])
        
        return jsonify({'user': dict(user)})
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

@app.route(’/api/auth/login’, methods=[‘POST’])
def login():
data = request.json

```
try:
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        cur.execute("""
            SELECT id, username, password_hash, full_name, portfolio_name, ticker
            FROM users 
            WHERE username = %s OR email = %s
        """, (data['username'], data['username']))
        
        user = cur.fetchone()
        cur.close()
        
        if not user or not verify_password(data['password'], user['password_hash']):
            return jsonify({'error': 'Invalid credentials'}), 401
        
        session['user_id'] = user['id']
        user_dict = dict(user)
        del user_dict['password_hash']
        
        return jsonify({'user': user_dict})
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

@app.route(’/api/auth/logout’, methods=[‘POST’])
def logout():
session.clear()
return jsonify({‘success’: True})

@app.route(’/api/auth/me’)
def get_current_user():
user_id = session.get(‘user_id’)
if not user_id:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
try:
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("""
            SELECT id, username, full_name, portfolio_name, ticker, bio, location, avatar
            FROM users WHERE id = %s
        """, (user_id,))
        user = cur.fetchone()
        cur.close()
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify(dict(user))
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

# User endpoints

@app.route(’/api/users/discover’)
def discover_users():
user_id = session.get(‘user_id’)

```
try:
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get users with their metrics, excluding current user
        cur.execute("""
            SELECT u.id, u.username, u.full_name, u.portfolio_name, u.ticker, u.avatar,
                   COALESCE(pm.health_score, 0) as health_score,
                   COALESCE(pm.share_price, 0) as share_price,
                   COALESCE(pm.property_count, 0) as property_count
            FROM users u
            LEFT JOIN portfolio_metrics pm ON u.id = pm.user_id
            WHERE u.id != %s
            ORDER BY pm.health_score DESC NULLS LAST
            LIMIT 20
        """, (user_id or 0,))
        
        users = cur.fetchall()
        cur.close()
        
        return jsonify([dict(u) for u in users])
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

# Follow endpoints

@app.route(’/api/follow/<int:following_id>’, methods=[‘POST’])
def follow_user(following_id):
user_id = session.get(‘user_id’)
if not user_id:
return jsonify({‘error’: ‘Not authenticated’}), 401

```
try:
    with get_db() as conn:
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO follows (follower_id, following_id)
            VALUES (%s, %s)
            ON CONFLICT DO NOTHING
        """, (user_id, following_id))
        conn.commit()
        cur.close()
        
        return jsonify({'success': True})
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

@app.route(’/api/following’)
def get_following():
user_id = session.get(‘user_id’)
if not user_id:
return jsonify([])

```
try:
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        cur.execute("SELECT following_id FROM follows WHERE follower_id = %s", (user_id,))
        following = cur.fetchall()
        cur.close()
        
        return jsonify([dict(f) for f in following])
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

# Portfolio endpoint

@app.route(’/api/portfolio/<int:user_id>’)
def get_portfolio(user_id):
try:
# Update metrics first
metrics = update_portfolio_metrics(user_id)

```
    with get_db() as conn:
        cur = conn.cursor(cursor_factory=RealDictCursor)
        
        # Get cached metrics
        cur.execute("""
            SELECT u.ticker, pm.*
            FROM portfolio_metrics pm
            JOIN users u ON pm.user_id = u.id
            WHERE pm.user_id = %s
        """, (user_id,))
        
        portfolio = cur.fetchone()
        cur.close()
        
        if not portfolio:
            return jsonify({
                'ticker': 'XXXX',
                'health_score': 0,
                'share_price': 0,
                'total_equity': 0,
                'annual_cashflow': 0,
                'property_count': 0
            })
        
        return jsonify(dict(portfolio))
except Exception as e:
    return jsonify({'error': str(e)}), 500
```

if **name** == ‘**main**’:
port = int(os.environ.get(‘PORT’, 10000))
app.run(host=‘0.0.0.0’, port=port)
