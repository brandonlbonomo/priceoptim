from flask import Flask, jsonify, request, session, redirect, url_for
from flask_cors import CORS
import os
import json
from datetime import datetime, timedelta
import secrets

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', secrets.token_hex(32))
CORS(app)

# Database (in production: PostgreSQL)
properties = []
pricing_recommendations = {}
user_settings = {
    'airbnb_connected': False,
    'airbnb_access_token': None,
    'default_strategy': 'balanced',
    'auto_sync_enabled': False
}

# Airbnb OAuth configuration
AIRBNB_CLIENT_ID = os.environ.get('AIRBNB_CLIENT_ID', '')
AIRBNB_CLIENT_SECRET = os.environ.get('AIRBNB_CLIENT_SECRET', '')
AIRBNB_REDIRECT_URI = os.environ.get('AIRBNB_REDIRECT_URI', 'http://localhost:10000/auth/airbnb/callback')

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>PriceOptim - Airbnb Revenue Management</title>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
            background: #f8f9fa;
            color: #1a1a1a;
            line-height: 1.5;
        }
        
        .app {
            display: flex;
            min-height: 100vh;
        }
        
        /* Sidebar */
        .sidebar {
            width: 260px;
            background: #ffffff;
            border-right: 1px solid #e5e7eb;
            padding: 24px 0;
            position: fixed;
            height: 100vh;
            overflow-y: auto;
        }
        
        .logo {
            padding: 0 24px 24px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .logo-text {
            font-size: 20px;
            font-weight: 700;
            color: #1a1a1a;
            letter-spacing: -0.5px;
        }
        
        .nav {
            padding: 24px 12px;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            padding: 10px 16px;
            margin-bottom: 4px;
            border-radius: 6px;
            color: #6b7280;
            cursor: pointer;
            transition: all 0.15s;
            font-size: 14px;
            font-weight: 500;
        }
        
        .nav-item:hover {
            background: #f3f4f6;
            color: #1a1a1a;
        }
        
        .nav-item.active {
            background: #3b82f6;
            color: #ffffff;
        }
        
        .nav-icon {
            width: 20px;
            margin-right: 12px;
            text-align: center;
        }
        
        /* Main Content */
        .main {
            flex: 1;
            margin-left: 260px;
            padding: 32px 40px;
            max-width: 1600px;
        }
        
        .page-header {
            margin-bottom: 32px;
        }
        
        .page-title {
            font-size: 28px;
            font-weight: 700;
            color: #1a1a1a;
            margin-bottom: 8px;
        }
        
        .page-subtitle {
            font-size: 14px;
            color: #6b7280;
        }
        
        /* Cards */
        .card {
            background: #ffffff;
            border-radius: 8px;
            border: 1px solid #e5e7eb;
            padding: 24px;
            margin-bottom: 24px;
        }
        
        .card-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 20px;
        }
        
        .card-title {
            font-size: 16px;
            font-weight: 600;
            color: #1a1a1a;
        }
        
        /* Stats */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(240px, 1fr));
            gap: 20px;
            margin-bottom: 32px;
        }
        
        .stat-card {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
        }
        
        .stat-label {
            font-size: 13px;
            color: #6b7280;
            font-weight: 500;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 700;
            color: #1a1a1a;
            margin-bottom: 4px;
        }
        
        .stat-change {
            font-size: 13px;
            font-weight: 500;
        }
        
        .stat-change.positive { color: #10b981; }
        .stat-change.negative { color: #ef4444; }
        
        /* Buttons */
        .btn {
            padding: 10px 20px;
            border-radius: 6px;
            font-size: 14px;
            font-weight: 500;
            cursor: pointer;
            border: none;
            transition: all 0.15s;
            font-family: inherit;
        }
        
        .btn-primary {
            background: #3b82f6;
            color: #ffffff;
        }
        
        .btn-primary:hover {
            background: #2563eb;
        }
        
        .btn-secondary {
            background: #ffffff;
            color: #1a1a1a;
            border: 1px solid #e5e7eb;
        }
        
        .btn-secondary:hover {
            background: #f9fafb;
        }
        
        /* Connection Status */
        .connection-card {
            background: #f0f9ff;
            border: 1px solid #bfdbfe;
            border-radius: 8px;
            padding: 24px;
            margin-bottom: 32px;
        }
        
        .connection-card.connected {
            background: #f0fdf4;
            border-color: #bbf7d0;
        }
        
        .connection-status {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
        }
        
        .status-indicator {
            width: 12px;
            height: 12px;
            border-radius: 50%;
            background: #3b82f6;
        }
        
        .status-indicator.connected {
            background: #10b981;
        }
        
        .connection-title {
            font-size: 18px;
            font-weight: 600;
            color: #1a1a1a;
        }
        
        .connection-desc {
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 16px;
        }
        
        /* Table */
        .table-container {
            overflow-x: auto;
        }
        
        table {
            width: 100%;
            border-collapse: collapse;
        }
        
        thead {
            background: #f9fafb;
        }
        
        th {
            text-align: left;
            padding: 12px 16px;
            font-size: 12px;
            font-weight: 600;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        td {
            padding: 16px;
            border-top: 1px solid #e5e7eb;
            font-size: 14px;
            color: #1a1a1a;
        }
        
        tr:hover {
            background: #f9fafb;
        }
        
        .property-name {
            font-weight: 600;
            color: #1a1a1a;
        }
        
        .property-location {
            font-size: 13px;
            color: #6b7280;
            margin-top: 2px;
        }
        
        .badge {
            display: inline-block;
            padding: 4px 10px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: 500;
        }
        
        .badge-success {
            background: #d1fae5;
            color: #065f46;
        }
        
        .badge-warning {
            background: #fef3c7;
            color: #92400e;
        }
        
        .badge-info {
            background: #dbeafe;
            color: #1e40af;
        }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
        }
        
        .empty-icon {
            font-size: 48px;
            margin-bottom: 16px;
            opacity: 0.3;
        }
        
        .empty-title {
            font-size: 18px;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 8px;
        }
        
        .empty-desc {
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 24px;
        }
        
        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.5);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
        }
        
        .modal {
            background: #ffffff;
            border-radius: 12px;
            max-width: 500px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
        }
        
        .modal-header {
            padding: 24px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .modal-title {
            font-size: 20px;
            font-weight: 600;
            color: #1a1a1a;
        }
        
        .modal-body {
            padding: 24px;
        }
        
        .modal-footer {
            padding: 16px 24px;
            border-top: 1px solid #e5e7eb;
            display: flex;
            gap: 12px;
            justify-content: flex-end;
        }
        
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            font-size: 14px;
            font-weight: 500;
            color: #374151;
            margin-bottom: 6px;
        }
        
        .form-input {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
            font-family: inherit;
            color: #1a1a1a;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .loading {
            text-align: center;
            padding: 60px 20px;
            color: #6b7280;
        }
        
        @media (max-width: 768px) {
            .sidebar {
                display: none;
            }
            .main {
                margin-left: 0;
                padding: 20px;
            }
        }
    </style>
</head>
<body>
    <div id="root"></div>
    
    <script type="text/babel">
        const { useState, useEffect } = React;
        
        function App() {
            const [view, setView] = useState('dashboard');
            const [properties, setProperties] = useState([]);
            const [stats, setStats] = useState(null);
            const [connected, setConnected] = useState(false);
            const [loading, setLoading] = useState(true);
            const [showModal, setShowModal] = useState(false);
            
            useEffect(() => {
                loadData();
            }, []);
            
            const loadData = async () => {
                try {
                    const [propsRes, statsRes, settingsRes] = await Promise.all([
                        fetch('/api/properties'),
                        fetch('/api/stats'),
                        fetch('/api/settings')
                    ]);
                    
                    setProperties(await propsRes.json());
                    setStats(await statsRes.json());
                    const settings = await settingsRes.json();
                    setConnected(settings.airbnb_connected);
                    setLoading(false);
                } catch (error) {
                    console.error('Error loading data:', error);
                    setLoading(false);
                }
            };
            
            const connectAirbnb = () => {
                window.location.href = '/auth/airbnb';
            };
            
            if (loading) {
                return <div className="loading">Loading...</div>;
            }
            
            return (
                <div className="app">
                    <Sidebar view={view} setView={setView} />
                    <div className="main">
                        {view === 'dashboard' && (
                            <Dashboard 
                                stats={stats} 
                                properties={properties}
                                connected={connected}
                                onConnect={connectAirbnb}
                            />
                        )}
                        {view === 'properties' && (
                            <Properties 
                                properties={properties}
                                onRefresh={loadData}
                                onAdd={() => setShowModal(true)}
                            />
                        )}
                        {view === 'settings' && (
                            <Settings 
                                connected={connected}
                                onConnect={connectAirbnb}
                            />
                        )}
                    </div>
                    
                    {showModal && (
                        <AddPropertyModal 
                            onClose={() => setShowModal(false)}
                            onAdd={loadData}
                        />
                    )}
                </div>
            );
        }
        
        function Sidebar({ view, setView }) {
            const navItems = [
                { id: 'dashboard', label: 'Dashboard', icon: '◼' },
                { id: 'properties', label: 'Properties', icon: '◼' },
                { id: 'calendar', label: 'Calendar', icon: '◼' },
                { id: 'analytics', label: 'Analytics', icon: '◼' },
                { id: 'settings', label: 'Settings', icon: '◼' }
            ];
            
            return (
                <div className="sidebar">
                    <div className="logo">
                        <div className="logo-text">PriceOptim</div>
                    </div>
                    <div className="nav">
                        {navItems.map(item => (
                            <div
                                key={item.id}
                                className={`nav-item ${view === item.id ? 'active' : ''}`}
                                onClick={() => setView(item.id)}
                            >
                                <span className="nav-icon">{item.icon}</span>
                                {item.label}
                            </div>
                        ))}
                    </div>
                </div>
            );
        }
        
        function Dashboard({ stats, properties, connected, onConnect }) {
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Dashboard</h1>
                        <p className="page-subtitle">Revenue management overview</p>
                    </div>
                    
                    {!connected && (
                        <div className="connection-card">
                            <div className="connection-status">
                                <div className="status-indicator"></div>
                                <h3 className="connection-title">Connect Your Airbnb Account</h3>
                            </div>
                            <p className="connection-desc">
                                Connect your Airbnb account to import your listings and start optimizing your pricing automatically.
                            </p>
                            <button className="btn btn-primary" onClick={onConnect}>
                                Connect Airbnb Account
                            </button>
                        </div>
                    )}
                    
                    {stats && (
                        <div className="stats-grid">
                            <div className="stat-card">
                                <div className="stat-label">Monthly Revenue</div>
                                <div className="stat-value">
                                    ${Math.round(stats.totalRevenue).toLocaleString()}
                                </div>
                                <div className="stat-change positive">↑ 12.5% vs last month</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-label">Average Occupancy</div>
                                <div className="stat-value">{stats.avgOccupancy.toFixed(1)}%</div>
                                <div className="stat-change positive">↑ 8.2%</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-label">Average Daily Rate</div>
                                <div className="stat-value">${Math.round(stats.avgADR)}</div>
                                <div className="stat-change positive">↑ $15</div>
                            </div>
                            <div className="stat-card">
                                <div className="stat-label">RevPAR</div>
                                <div className="stat-value">
                                    ${Math.round(stats.avgOccupancy * stats.avgADR / 100)}
                                </div>
                                <div className="stat-change positive">↑ 18.3%</div>
                            </div>
                        </div>
                    )}
                    
                    <div className="card">
                        <div className="card-header">
                            <h3 className="card-title">Recent Activity</h3>
                        </div>
                        <p style={{color: '#6b7280', fontSize: '14px'}}>
                            Your pricing recommendations and sync history will appear here.
                        </p>
                    </div>
                </div>
            );
        }
        
        function Properties({ properties, onRefresh, onAdd }) {
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Properties</h1>
                        <p className="page-subtitle">Manage your Airbnb listings</p>
                    </div>
                    
                    <div className="card">
                        <div className="card-header">
                            <h3 className="card-title">Your Listings ({properties.length})</h3>
                            <div style={{display: 'flex', gap: '12px'}}>
                                <button className="btn btn-secondary" onClick={onRefresh}>
                                    Refresh
                                </button>
                                <button className="btn btn-primary" onClick={onAdd}>
                                    Add Property
                                </button>
                            </div>
                        </div>
                        
                        {properties.length === 0 ? (
                            <div className="empty-state">
                                <div className="empty-icon">◻</div>
                                <h3 className="empty-title">No properties yet</h3>
                                <p className="empty-desc">
                                    Connect your Airbnb account or manually add properties to get started.
                                </p>
                                <button className="btn btn-primary" onClick={onAdd}>
                                    Add Your First Property
                                </button>
                            </div>
                        ) : (
                            <div className="table-container">
                                <table>
                                    <thead>
                                        <tr>
                                            <th>Property</th>
                                            <th>Current Price</th>
                                            <th>Recommended</th>
                                            <th>Occupancy</th>
                                            <th>RevPAR</th>
                                            <th>Status</th>
                                        </tr>
                                    </thead>
                                    <tbody>
                                        {properties.map(p => (
                                            <tr key={p.id}>
                                                <td>
                                                    <div className="property-name">{p.name}</div>
                                                    <div className="property-location">{p.location}</div>
                                                </td>
                                                <td>${p.currentPrice}</td>
                                                <td><strong>${p.recommendedPrice}</strong></td>
                                                <td>{p.occupancy}%</td>
                                                <td>${p.revpar}</td>
                                                <td>
                                                    <span className={`badge badge-${p.status === 'optimized' ? 'success' : 'warning'}`}>
                                                        {p.status === 'optimized' ? 'Optimized' : 'Needs Attention'}
                                                    </span>
                                                </td>
                                            </tr>
                                        ))}
                                    </tbody>
                                </table>
                            </div>
                        )}
                    </div>
                </div>
            );
        }
        
        function Settings({ connected, onConnect }) {
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Settings</h1>
                        <p className="page-subtitle">Manage your account and integrations</p>
                    </div>
                    
                    <div className={`connection-card ${connected ? 'connected' : ''}`}>
                        <div className="connection-status">
                            <div className={`status-indicator ${connected ? 'connected' : ''}`}></div>
                            <h3 className="connection-title">
                                {connected ? 'Airbnb Connected' : 'Connect Airbnb'}
                            </h3>
                        </div>
                        <p className="connection-desc">
                            {connected 
                                ? 'Your Airbnb account is connected and syncing.'
                                : 'Connect your Airbnb account to automatically import listings and sync pricing.'}
                        </p>
                        {!connected && (
                            <button className="btn btn-primary" onClick={onConnect}>
                                Connect Now
                            </button>
                        )}
                    </div>
                    
                    <div className="card">
                        <div className="card-header">
                            <h3 className="card-title">Pricing Strategy</h3>
                        </div>
                        <div className="form-group">
                            <label className="form-label">Default Strategy</label>
                            <select className="form-input">
                                <option value="balanced">Balanced</option>
                                <option value="aggressive_revenue">Maximize Revenue</option>
                                <option value="aggressive_occupancy">Maximize Occupancy</option>
                                <option value="algorithm_boost">Algorithm Optimization</option>
                            </select>
                        </div>
                    </div>
                </div>
            );
        }
        
        function AddPropertyModal({ onClose, onAdd }) {
            const [formData, setFormData] = useState({
                name: '',
                location: '',
                currentPrice: 150
            });
            
            const handleSubmit = async (e) => {
                e.preventDefault();
                try {
                    await fetch('/api/properties', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify(formData)
                    });
                    onAdd();
                    onClose();
                } catch (error) {
                    console.error('Error adding property:', error);
                }
            };
            
            return (
                <div className="modal-overlay" onClick={onClose}>
                    <div className="modal" onClick={e => e.stopPropagation()}>
                        <div className="modal-header">
                            <h3 className="modal-title">Add Property</h3>
                        </div>
                        <form onSubmit={handleSubmit}>
                            <div className="modal-body">
                                <div className="form-group">
                                    <label className="form-label">Property Name</label>
                                    <input
                                        type="text"
                                        className="form-input"
                                        value={formData.name}
                                        onChange={e => setFormData({...formData, name: e.target.value})}
                                        placeholder="Downtown Loft"
                                        required
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Location</label>
                                    <input
                                        type="text"
                                        className="form-input"
                                        value={formData.location}
                                        onChange={e => setFormData({...formData, location: e.target.value})}
                                        placeholder="Houston, TX"
                                        required
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Current Nightly Rate</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={formData.currentPrice}
                                        onChange={e => setFormData({...formData, currentPrice: parseInt(e.target.value)})}
                                        required
                                    />
                                </div>
                            </div>
                            <div className="modal-footer">
                                <button type="button" className="btn btn-secondary" onClick={onClose}>
                                    Cancel
                                </button>
                                <button type="submit" className="btn btn-primary">
                                    Add Property
                                </button>
                            </div>
                        </form>
                    </div>
                </div>
            );
        }
        
        ReactDOM.render(<App />, document.getElementById('root'));
    </script>
</body>
</html>"""

# API Routes
@app.route('/')
def index():
    return HTML

@app.route('/api/properties')
def get_properties():
    return jsonify(properties)

@app.route('/api/properties', methods=['POST'])
def add_property():
    data = request.json
    new_id = len(properties) + 1
    
    new_property = {
        "id": new_id,
        "name": data.get('name'),
        "location": data.get('location'),
        "currentPrice": data.get('currentPrice'),
        "recommendedPrice": int(data.get('currentPrice') * 1.15),
        "occupancy": 70,
        "adr": data.get('currentPrice'),
        "revpar": int(data.get('currentPrice') * 0.7),
        "status": "optimized"
    }
    
    properties.append(new_property)
    return jsonify(new_property), 201

@app.route('/api/stats')
def get_stats():
    if not properties:
        return jsonify({
            "totalRevenue": 0,
            "avgOccupancy": 0,
            "avgADR": 0,
            "propertyCount": 0
        })
    
    total_revenue = sum(p['revpar'] * 30 for p in properties)
    avg_occupancy = sum(p['occupancy'] for p in properties) / len(properties)
    avg_adr = sum(p['adr'] for p in properties) / len(properties)
    
    return jsonify({
        "totalRevenue": total_revenue,
        "avgOccupancy": avg_occupancy,
        "avgADR": avg_adr,
        "propertyCount": len(properties)
    })

@app.route('/api/settings')
def get_settings():
    return jsonify(user_settings)

@app.route('/auth/airbnb')
def auth_airbnb():
    # Step 1: Redirect to Airbnb OAuth
    # In production: Generate real OAuth URL
    oauth_url = f"https://www.airbnb.com/oauth2/auth?client_id={AIRBNB_CLIENT_ID}&redirect_uri={AIRBNB_REDIRECT_URI}&response_type=code&scope=listings:read,pricing:write"
    
    # For demo: Just mark as connected
    user_settings['airbnb_connected'] = True
    return redirect('/?connected=true')

@app.route('/auth/airbnb/callback')
def auth_airbnb_callback():
    # Handle OAuth callback
    code = request.args.get('code')
    # Exchange code for access token
    # Store token securely
    user_settings['airbnb_connected'] = True
    return redirect('/')

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
