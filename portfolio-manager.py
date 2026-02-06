from flask import Flask, jsonify, request, session
from flask_cors import CORS
import os
import json
from datetime import datetime, timedelta
from icalendar import Calendar
import requests
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
CORS(app)

# Database (in production: PostgreSQL)
properties = []
bookings = []
expenses = []
fixed_costs = []

# Plaid configuration (for bank connection)
PLAID_CLIENT_ID = os.environ.get('PLAID_CLIENT_ID', '')
PLAID_SECRET = os.environ.get('PLAID_SECRET', '')

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Portfolio Manager - Airbnb Performance Tracking</title>
    <script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: #f8f9fa;
            color: #1a1a1a;
            line-height: 1.5;
        }
        
        .app { display: flex; min-height: 100vh; }
        
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
            font-size: 18px;
            font-weight: 700;
            color: #1a1a1a;
        }
        
        .logo-subtitle {
            font-size: 12px;
            color: #6b7280;
            margin-top: 4px;
        }
        
        .nav {
            padding: 24px 12px;
        }
        
        .nav-section {
            margin-bottom: 24px;
        }
        
        .nav-label {
            padding: 0 12px 8px;
            font-size: 11px;
            font-weight: 600;
            color: #9ca3af;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        .nav-item {
            display: flex;
            align-items: center;
            padding: 10px 16px;
            margin-bottom: 2px;
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
        
        /* Main Content */
        .main {
            flex: 1;
            margin-left: 260px;
            padding: 32px 40px;
            max-width: 1800px;
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
            transition: all 0.2s;
        }
        
        .stat-card:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
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
            margin-bottom: 8px;
        }
        
        .stat-change {
            font-size: 13px;
            font-weight: 500;
        }
        
        .stat-change.positive { color: #10b981; }
        .stat-change.negative { color: #ef4444; }
        
        /* Card */
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
            font-size: 18px;
            font-weight: 600;
            color: #1a1a1a;
        }
        
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
        
        .btn-success {
            background: #10b981;
            color: #ffffff;
        }
        
        .btn-danger {
            background: #ef4444;
            color: #ffffff;
        }
        
        /* Table */
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
            border-bottom: 1px solid #e5e7eb;
        }
        
        td {
            padding: 16px;
            border-bottom: 1px solid #f3f4f6;
            font-size: 14px;
            color: #1a1a1a;
        }
        
        tr:hover {
            background: #f9fafb;
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
            max-width: 600px;
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
        
        .form-input, .form-select, .form-textarea {
            width: 100%;
            padding: 10px 14px;
            border: 1px solid #d1d5db;
            border-radius: 6px;
            font-size: 14px;
            font-family: inherit;
            color: #1a1a1a;
        }
        
        .form-input:focus, .form-select:focus, .form-textarea:focus {
            outline: none;
            border-color: #3b82f6;
            box-shadow: 0 0 0 3px rgba(59, 130, 246, 0.1);
        }
        
        .form-textarea {
            resize: vertical;
            min-height: 80px;
        }
        
        .form-hint {
            font-size: 13px;
            color: #6b7280;
            margin-top: 4px;
        }
        
        /* Empty State */
        .empty-state {
            text-align: center;
            padding: 60px 20px;
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
        
        /* Chart Container */
        .chart-container {
            position: relative;
            height: 300px;
            margin: 20px 0;
        }
        
        /* Badge */
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
        
        .badge-danger {
            background: #fee2e2;
            color: #991b1b;
        }
        
        /* Property Card */
        .property-card {
            background: #ffffff;
            border: 1px solid #e5e7eb;
            border-radius: 8px;
            padding: 20px;
            margin-bottom: 16px;
            cursor: pointer;
            transition: all 0.2s;
        }
        
        .property-card:hover {
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.08);
        }
        
        .property-header {
            display: flex;
            justify-content: space-between;
            align-items: start;
            margin-bottom: 16px;
        }
        
        .property-name {
            font-size: 16px;
            font-weight: 600;
            color: #1a1a1a;
            margin-bottom: 4px;
        }
        
        .property-location {
            font-size: 13px;
            color: #6b7280;
        }
        
        .property-metrics {
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            padding-top: 16px;
            border-top: 1px solid #f3f4f6;
        }
        
        .metric {
            text-align: center;
        }
        
        .metric-value {
            font-size: 20px;
            font-weight: 700;
            color: #1a1a1a;
            margin-bottom: 4px;
        }
        
        .metric-label {
            font-size: 11px;
            color: #6b7280;
            text-transform: uppercase;
            letter-spacing: 0.5px;
        }
        
        @media (max-width: 768px) {
            .sidebar { display: none; }
            .main { margin-left: 0; padding: 20px; }
            .stats-grid { grid-template-columns: 1fr; }
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
            const [loading, setLoading] = useState(true);
            
            useEffect(() => {
                loadData();
            }, []);
            
            const loadData = async () => {
                try {
                    const [propsRes, statsRes] = await Promise.all([
                        fetch('/api/properties'),
                        fetch('/api/stats')
                    ]);
                    
                    setProperties(await propsRes.json());
                    setStats(await statsRes.json());
                    setLoading(false);
                } catch (error) {
                    console.error('Error loading data:', error);
                    setLoading(false);
                }
            };
            
            if (loading) {
                return <div style={{padding: '60px', textAlign: 'center', color: '#6b7280'}}>Loading...</div>;
            }
            
            return (
                <div className="app">
                    <Sidebar view={view} setView={setView} />
                    <div className="main">
                        {view === 'dashboard' && <Dashboard stats={stats} properties={properties} />}
                        {view === 'properties' && <Properties properties={properties} onRefresh={loadData} />}
                        {view === 'revenue' && <Revenue />}
                        {view === 'expenses' && <Expenses />}
                        {view === 'setup' && <Setup onRefresh={loadData} />}
                    </div>
                </div>
            );
        }
        
        function Sidebar({ view, setView }) {
            return (
                <div className="sidebar">
                    <div className="logo">
                        <div className="logo-text">Portfolio Manager</div>
                        <div className="logo-subtitle">Airbnb Performance Tracking</div>
                    </div>
                    <div className="nav">
                        <div className="nav-section">
                            <div className="nav-label">Overview</div>
                            <div className={`nav-item ${view === 'dashboard' ? 'active' : ''}`} onClick={() => setView('dashboard')}>
                                Dashboard
                            </div>
                            <div className={`nav-item ${view === 'properties' ? 'active' : ''}`} onClick={() => setView('properties')}>
                                Properties
                            </div>
                        </div>
                        <div className="nav-section">
                            <div className="nav-label">Financials</div>
                            <div className={`nav-item ${view === 'revenue' ? 'active' : ''}`} onClick={() => setView('revenue')}>
                                Revenue
                            </div>
                            <div className={`nav-item ${view === 'expenses' ? 'active' : ''}`} onClick={() => setView('expenses')}>
                                Expenses
                            </div>
                        </div>
                        <div className="nav-section">
                            <div className="nav-label">Settings</div>
                            <div className={`nav-item ${view === 'setup' ? 'active' : ''}`} onClick={() => setView('setup')}>
                                Setup & Sync
                            </div>
                        </div>
                    </div>
                </div>
            );
        }
        
        function Dashboard({ stats, properties }) {
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Portfolio Overview</h1>
                        <p className="page-subtitle">Real-time performance across all properties</p>
                    </div>
                    
                    <div className="stats-grid">
                        <div className="stat-card">
                            <div className="stat-label">Monthly Revenue</div>
                            <div className="stat-value">${stats?.totalRevenue?.toLocaleString() || '0'}</div>
                            <div className="stat-change positive">+12.5% vs last month</div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Total Expenses</div>
                            <div className="stat-value">${stats?.totalExpenses?.toLocaleString() || '0'}</div>
                            <div className="stat-change negative">+5.2% vs last month</div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Net Profit</div>
                            <div className="stat-value">${stats?.netProfit?.toLocaleString() || '0'}</div>
                            <div className="stat-change positive">+18.3% vs last month</div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Average Occupancy</div>
                            <div className="stat-value">{stats?.avgOccupancy?.toFixed(1) || '0'}%</div>
                            <div className="stat-change positive">+4.1%</div>
                        </div>
                    </div>
                    
                    <div className="card">
                        <div className="card-header">
                            <h3 className="card-title">Properties Performance</h3>
                        </div>
                        {properties.length === 0 ? (
                            <div className="empty-state">
                                <h3 className="empty-title">No properties added yet</h3>
                                <p className="empty-desc">Add your first property to start tracking performance</p>
                            </div>
                        ) : (
                            properties.map(p => (
                                <div key={p.id} className="property-card">
                                    <div className="property-header">
                                        <div>
                                            <div className="property-name">{p.name}</div>
                                            <div className="property-location">{p.location}</div>
                                        </div>
                                        <span className="badge badge-success">Active</span>
                                    </div>
                                    <div className="property-metrics">
                                        <div className="metric">
                                            <div className="metric-value">${p.monthlyRevenue || 0}</div>
                                            <div className="metric-label">Revenue</div>
                                        </div>
                                        <div className="metric">
                                            <div className="metric-value">${p.monthlyExpenses || 0}</div>
                                            <div className="metric-label">Expenses</div>
                                        </div>
                                        <div className="metric">
                                            <div className="metric-value">${p.netProfit || 0}</div>
                                            <div className="metric-label">Profit</div>
                                        </div>
                                        <div className="metric">
                                            <div className="metric-value">{p.occupancy || 0}%</div>
                                            <div className="metric-label">Occupancy</div>
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                </div>
            );
        }
        
        function Properties({ properties, onRefresh }) {
            const [showModal, setShowModal] = useState(false);
            
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Properties</h1>
                        <p className="page-subtitle">Manage your portfolio</p>
                    </div>
                    
                    <div className="card">
                        <div className="card-header">
                            <h3 className="card-title">All Properties ({properties.length})</h3>
                            <button className="btn btn-primary" onClick={() => setShowModal(true)}>
                                Add Property
                            </button>
                        </div>
                        
                        {properties.length === 0 ? (
                            <div className="empty-state">
                                <h3 className="empty-title">No properties yet</h3>
                                <p className="empty-desc">Add your first Airbnb property to start tracking</p>
                                <button className="btn btn-primary" onClick={() => setShowModal(true)}>
                                    Add Property
                                </button>
                            </div>
                        ) : (
                            properties.map(p => (
                                <div key={p.id} className="property-card">
                                    <div className="property-header">
                                        <div>
                                            <div className="property-name">{p.name}</div>
                                            <div className="property-location">{p.location}</div>
                                        </div>
                                    </div>
                                    <div className="property-metrics">
                                        <div className="metric">
                                            <div className="metric-value">${p.monthlyRevenue || 0}</div>
                                            <div className="metric-label">Revenue</div>
                                        </div>
                                        <div className="metric">
                                            <div className="metric-value">{p.occupancy || 0}%</div>
                                            <div className="metric-label">Occupancy</div>
                                        </div>
                                        <div className="metric">
                                            <div className="metric-value">${p.adr || 0}</div>
                                            <div className="metric-label">ADR</div>
                                        </div>
                                        <div className="metric">
                                            <div className="metric-value">${p.netProfit || 0}</div>
                                            <div className="metric-label">Net Profit</div>
                                        </div>
                                    </div>
                                </div>
                            ))
                        )}
                    </div>
                    
                    {showModal && <AddPropertyModal onClose={() => setShowModal(false)} onAdd={onRefresh} />}
                </div>
            );
        }
        
        function Revenue() {
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Revenue Tracking</h1>
                        <p className="page-subtitle">Bookings and income analysis</p>
                    </div>
                    <div className="card">
                        <p style={{color: '#6b7280'}}>Revenue tracking will show all bookings synced from iCal feeds</p>
                    </div>
                </div>
            );
        }
        
        function Expenses() {
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Expenses</h1>
                        <p className="page-subtitle">Track all property-related costs</p>
                    </div>
                    <div className="card">
                        <p style={{color: '#6b7280'}}>Expenses from connected bank accounts will appear here</p>
                    </div>
                </div>
            );
        }
        
        function Setup({ onRefresh }) {
            return (
                <div>
                    <div className="page-header">
                        <h1 className="page-title">Setup & Sync</h1>
                        <p className="page-subtitle">Configure data sources</p>
                    </div>
                    
                    <div className="card">
                        <h3 className="card-title" style={{marginBottom: '16px'}}>Revenue Sync (iCal)</h3>
                        <p style={{fontSize: '14px', color: '#6b7280', marginBottom: '16px'}}>
                            Paste your Airbnb iCal URL to automatically import bookings
                        </p>
                        <div className="form-group">
                            <label className="form-label">iCal Feed URL</label>
                            <input type="url" className="form-input" placeholder="https://www.airbnb.com/calendar/ical/..." />
                            <div className="form-hint">Find this in your Airbnb calendar settings</div>
                        </div>
                        <button className="btn btn-primary">Sync Calendar</button>
                    </div>
                    
                    <div className="card">
                        <h3 className="card-title" style={{marginBottom: '16px'}}>Bank Connection</h3>
                        <p style={{fontSize: '14px', color: '#6b7280', marginBottom: '16px'}}>
                            Connect your business credit card to auto-import expenses
                        </p>
                        <button className="btn btn-success">Connect Bank Account</button>
                    </div>
                </div>
            );
        }
        
        function AddPropertyModal({ onClose, onAdd }) {
            const [formData, setFormData] = useState({
                name: '',
                location: '',
                mortgage: 0,
                insurance: 0,
                hoa: 0,
                property_tax: 0
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
                                    <label className="form-label">Monthly Mortgage Payment</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={formData.mortgage}
                                        onChange={e => setFormData({...formData, mortgage: parseFloat(e.target.value)})}
                                        placeholder="2500"
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Monthly Insurance</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={formData.insurance}
                                        onChange={e => setFormData({...formData, insurance: parseFloat(e.target.value)})}
                                        placeholder="150"
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Monthly HOA</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={formData.hoa}
                                        onChange={e => setFormData({...formData, hoa: parseFloat(e.target.value)})}
                                        placeholder="200"
                                    />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Monthly Property Tax</label>
                                    <input
                                        type="number"
                                        className="form-input"
                                        value={formData.property_tax}
                                        onChange={e => setFormData({...formData, property_tax: parseFloat(e.target.value)})}
                                        placeholder="300"
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

@app.route('/')
def index():
    return HTML

@app.route('/api/properties')
def get_properties():
    return jsonify(properties)

@app.route('/api/properties', methods=['POST'])
def add_property():
    data = request.json
    new_property = {
        'id': len(properties) + 1,
        'name': data.get('name'),
        'location': data.get('location'),
        'mortgage': data.get('mortgage', 0),
        'insurance': data.get('insurance', 0),
        'hoa': data.get('hoa', 0),
        'property_tax': data.get('property_tax', 0),
        'ical_url': data.get('ical_url', ''),
        'monthlyRevenue': 0,
        'monthlyExpenses': data.get('mortgage', 0) + data.get('insurance', 0) + data.get('hoa', 0) + data.get('property_tax', 0),
        'netProfit': 0,
        'occupancy': 0,
        'adr': 0
    }
    properties.append(new_property)
    return jsonify(new_property), 201

@app.route('/api/stats')
def get_stats():
    if not properties:
        return jsonify({
            'totalRevenue': 0,
            'totalExpenses': 0,
            'netProfit': 0,
            'avgOccupancy': 0
        })
    
    total_revenue = sum(p.get('monthlyRevenue', 0) for p in properties)
    total_expenses = sum(p.get('monthlyExpenses', 0) for p in properties)
    net_profit = total_revenue - total_expenses
    avg_occupancy = sum(p.get('occupancy', 0) for p in properties) / len(properties) if properties else 0
    
    return jsonify({
        'totalRevenue': total_revenue,
        'totalExpenses': total_expenses,
        'netProfit': net_profit,
        'avgOccupancy': avg_occupancy
    })

@app.route('/api/sync/ical', methods=['POST'])
def sync_ical():
    """Sync bookings from iCal feed"""
    data = request.json
    ical_url = data.get('ical_url')
    property_id = data.get('property_id')
    
    try:
        # Fetch iCal data
        response = requests.get(ical_url)
        cal = Calendar.from_ical(response.content)
        
        # Parse events (bookings)
        new_bookings = []
        for event in cal.walk('VEVENT'):
            booking = {
                'property_id': property_id,
                'summary': str(event.get('SUMMARY')),
                'start': event.get('DTSTART').dt,
                'end': event.get('DTEND').dt,
                'description': str(event.get('DESCRIPTION', ''))
            }
            new_bookings.append(booking)
        
        bookings.extend(new_bookings)
        
        return jsonify({
            'success': True,
            'bookings_imported': len(new_bookings)
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
