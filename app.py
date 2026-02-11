from flask import Flask, jsonify, request
from flask_cors import CORS
import os
import random
from datetime import datetime, timedelta
from collections import defaultdict

app = Flask(__name__)
app.secret_key = os.environ.get('SECRET_KEY', os.urandom(24))
CORS(app)

# Data storage
users = []
portfolios = {}
properties = {}
follows = defaultdict(set)
feed_items = []

PLAID_CLIENT_ID = os.environ.get('PLAID_CLIENT_ID', 'sandbox')
PLAID_SECRET = os.environ.get('PLAID_SECRET', 'sandbox')

def calculate_health_score(portfolio_data):
    """Calculate 0-100 health score with weighted algorithm"""
    props = portfolio_data.get('properties', [])
    if not props:
        return 0
    
    # Financial Strength (40 points)
    dscr = portfolio_data.get('dscr', 0)
    coc_return = portfolio_data.get('cash_on_cash', 0)
    equity_ratio = portfolio_data.get('equity_ratio', 0)
    financial = min(40, min(15, dscr * 10) + min(15, coc_return / 2) + min(10, equity_ratio * 10))
    
    # Performance (30 points)
    occupancy = portfolio_data.get('avg_occupancy', 0)
    revenue_growth = portfolio_data.get('revenue_growth', 0)
    profit_margin = portfolio_data.get('profit_margin', 0)
    performance = min(30, min(15, occupancy * 0.3) + min(10, revenue_growth * 50) + min(5, profit_margin * 0.5))
    
    # Risk Management (20 points)
    diversification = min(10, len(props) * 1.5)
    cash_reserves = min(5, portfolio_data.get('cash_reserves', 0) / 10000)
    debt_ratio = max(0, 5 - (portfolio_data.get('debt_ratio', 0) * 5))
    risk = diversification + cash_reserves + debt_ratio
    
    # Growth (10 points)
    growth = min(10, portfolio_data.get('growth_rate', 0) * 2.5 + portfolio_data.get('momentum', 0) * 2.5)
    
    return min(100, max(0, round(financial + performance + risk + growth)))

def calculate_share_price(portfolio_data):
    """Calculate portfolio share price"""
    equity = portfolio_data.get('total_equity', 0)
    annual_cashflow = portfolio_data.get('annual_cashflow', 0)
    health_score = portfolio_data.get('health_score', 0)
    property_count = len(portfolio_data.get('properties', []))
    
    price = ((equity / 1000) * 0.4 + (annual_cashflow * 2) * 0.3 + (health_score * 5) * 0.2 + (property_count * 10) * 0.1)
    return round(price, 2)

def generate_ticker(name):
    """Generate 4-letter ticker"""
    words = name.upper().replace("'S", "").split()
    if len(words) == 1:
        return words[0][:4].ljust(4, 'X')
    return ''.join(w[0] for w in words[:4]).ljust(4, 'X')

# Demo users
demo_users = [
    {'id': 1, 'username': 'sarahk', 'name': 'Sarah Kim', 'portfolio_name': 'Coastal Holdings', 'location': 'Miami, FL', 'bio': 'Luxury STRs on the beach', 'avatar': '👩'},
    {'id': 2, 'username': 'mikec', 'name': 'Mike Chen', 'portfolio_name': 'Austin Capital', 'location': 'Austin, TX', 'bio': 'Tech city real estate', 'avatar': '👨'},
    {'id': 3, 'username': 'jenm', 'name': 'Jennifer Martinez', 'portfolio_name': 'Desert Escapes', 'location': 'Phoenix, AZ', 'bio': 'Vacation rental expert', 'avatar': '👩‍💼'},
    {'id': 4, 'username': 'davidl', 'name': 'David Lee', 'portfolio_name': 'Mountain Retreats', 'location': 'Denver, CO', 'bio': 'Alpine property specialist', 'avatar': '🧑'},
]

HTML = """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>InvestNet - Social Investment Platform</title>
    <script src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
    <script src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
    <script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
    <script src="https://cdn.plaid.com/link/v2/stable/link-initialize.js"></script>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap" rel="stylesheet">
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body {
            font-family: 'Inter', -apple-system, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: #fff;
            min-height: 100vh;
        }
        
        .app {
            display: flex;
            flex-direction: column;
            min-height: 100vh;
        }
        
        /* Top Nav */
        .top-nav {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border-bottom: 1px solid rgba(255, 255, 255, 0.2);
            padding: 16px 32px;
            display: flex;
            justify-content: space-between;
            align-items: center;
            position: sticky;
            top: 0;
            z-index: 100;
        }
        
        .logo {
            font-size: 24px;
            font-weight: 800;
            background: linear-gradient(135deg, #fff, #f0f0f0);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
        }
        
        .nav-tabs {
            display: flex;
            gap: 8px;
        }
        
        .nav-tab {
            padding: 10px 20px;
            border-radius: 20px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            transition: all 0.2s;
            background: transparent;
            color: rgba(255, 255, 255, 0.7);
        }
        
        .nav-tab:hover {
            background: rgba(255, 255, 255, 0.1);
            color: #fff;
        }
        
        .nav-tab.active {
            background: rgba(255, 255, 255, 0.2);
            color: #fff;
        }
        
        /* Main Content */
        .main {
            flex: 1;
            max-width: 1200px;
            width: 100%;
            margin: 0 auto;
            padding: 32px 20px;
        }
        
        /* Cards */
        .card {
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 20px;
            padding: 24px;
            margin-bottom: 20px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.1);
        }
        
        .card-glass {
            background: rgba(255, 255, 255, 0.95);
            color: #1a1a1a;
        }
        
        /* Stats Grid */
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px;
            margin-bottom: 32px;
        }
        
        .stat-card {
            background: rgba(255, 255, 255, 0.15);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.3);
            border-radius: 16px;
            padding: 20px;
            transition: transform 0.2s;
        }
        
        .stat-card:hover {
            transform: translateY(-4px);
        }
        
        .stat-label {
            font-size: 12px;
            font-weight: 600;
            opacity: 0.8;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 8px;
        }
        
        .stat-value {
            font-size: 32px;
            font-weight: 800;
            margin-bottom: 4px;
        }
        
        .stat-change {
            font-size: 14px;
            font-weight: 600;
        }
        
        .stat-change.positive { color: #10b981; }
        .stat-change.negative { color: #ef4444; }
        
        /* Health Score */
        .health-score-circle {
            position: relative;
            width: 120px;
            height: 120px;
            margin: 0 auto;
        }
        
        .health-score-value {
            position: absolute;
            top: 50%;
            left: 50%;
            transform: translate(-50%, -50%);
            font-size: 32px;
            font-weight: 800;
        }
        
        .health-badge {
            display: inline-block;
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 700;
            background: linear-gradient(135deg, #fbbf24, #f59e0b);
            color: #1a1a1a;
            margin-top: 8px;
        }
        
        /* User Cards */
        .user-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 16px;
            color: #1a1a1a;
            display: flex;
            align-items: center;
            gap: 16px;
        }
        
        .user-avatar {
            width: 60px;
            height: 60px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 32px;
        }
        
        .user-info {
            flex: 1;
        }
        
        .user-name {
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 4px;
        }
        
        .user-username {
            font-size: 14px;
            color: #6b7280;
            margin-bottom: 4px;
        }
        
        .user-stats {
            display: flex;
            gap: 16px;
            font-size: 13px;
            color: #6b7280;
            margin-top: 8px;
        }
        
        .ticker {
            font-family: 'Monaco', monospace;
            font-weight: 700;
            color: #667eea;
        }
        
        /* Buttons */
        .btn {
            padding: 10px 24px;
            border-radius: 12px;
            font-size: 14px;
            font-weight: 600;
            cursor: pointer;
            border: none;
            transition: all 0.2s;
            font-family: inherit;
        }
        
        .btn-primary {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: #fff;
        }
        
        .btn-primary:hover {
            transform: translateY(-2px);
            box-shadow: 0 8px 20px rgba(102, 126, 234, 0.4);
        }
        
        .btn-secondary {
            background: rgba(255, 255, 255, 0.2);
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        .btn-follow {
            background: #10b981;
            color: #fff;
            padding: 8px 16px;
            font-size: 13px;
        }
        
        .btn-following {
            background: rgba(255, 255, 255, 0.2);
            color: #fff;
            border: 1px solid rgba(255, 255, 255, 0.3);
        }
        
        /* Feed Item */
        .feed-item {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 16px;
            color: #1a1a1a;
        }
        
        .feed-header {
            display: flex;
            align-items: center;
            gap: 12px;
            margin-bottom: 16px;
        }
        
        .feed-avatar {
            width: 48px;
            height: 48px;
            border-radius: 50%;
            background: linear-gradient(135deg, #667eea, #764ba2);
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 24px;
        }
        
        .feed-user {
            flex: 1;
        }
        
        .feed-name {
            font-weight: 700;
            font-size: 15px;
        }
        
        .feed-time {
            font-size: 13px;
            color: #9ca3af;
        }
        
        .feed-content {
            margin-top: 12px;
        }
        
        .feed-highlight {
            background: linear-gradient(135deg, #f0f9ff, #e0f2fe);
            border-left: 4px solid #3b82f6;
            padding: 16px;
            border-radius: 8px;
            margin-top: 12px;
        }
        
        /* Chart Container */
        .chart-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 16px;
            padding: 24px;
            margin-bottom: 20px;
            height: 300px;
            position: relative;
        }
        
        /* Modal */
        .modal-overlay {
            position: fixed;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: rgba(0, 0, 0, 0.7);
            display: flex;
            align-items: center;
            justify-content: center;
            z-index: 1000;
            backdrop-filter: blur(4px);
        }
        
        .modal {
            background: #fff;
            border-radius: 20px;
            max-width: 600px;
            width: 90%;
            max-height: 90vh;
            overflow-y: auto;
            color: #1a1a1a;
        }
        
        .modal-header {
            padding: 24px;
            border-bottom: 1px solid #e5e7eb;
        }
        
        .modal-title {
            font-size: 24px;
            font-weight: 700;
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
        
        /* Form */
        .form-group {
            margin-bottom: 20px;
        }
        
        .form-label {
            display: block;
            font-size: 14px;
            font-weight: 600;
            margin-bottom: 8px;
            color: #374151;
        }
        
        .form-input {
            width: 100%;
            padding: 12px 16px;
            border: 2px solid #e5e7eb;
            border-radius: 12px;
            font-size: 14px;
            font-family: inherit;
            transition: all 0.2s;
        }
        
        .form-input:focus {
            outline: none;
            border-color: #667eea;
        }
        
        .form-grid {
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 16px;
        }
        
        /* Progress Bar */
        .progress-bar {
            width: 100%;
            height: 8px;
            background: rgba(255, 255, 255, 0.2);
            border-radius: 4px;
            overflow: hidden;
            margin-top: 8px;
        }
        
        .progress-fill {
            height: 100%;
            background: linear-gradient(90deg, #10b981, #34d399);
            transition: width 0.3s;
        }
        
        /* Responsive */
        @media (max-width: 768px) {
            .nav-tabs {
                overflow-x: auto;
            }
            .stats-grid {
                grid-template-columns: repeat(2, 1fr);
            }
            .form-grid {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div id="root"></div>
    
    <script type="text/babel">
        const { useState, useEffect, useRef } = React;
        
        const CURRENT_USER_ID = 999; // Demo user
        
        function App() {
            const [currentTab, setCurrentTab] = useState('feed');
            const [users, setUsers] = useState([]);
            const [feed, setFeed] = useState([]);
            const [portfolio, setPortfolio] = useState(null);
            const [following, setFollowing] = useState(new Set());
            const [showModal, setShowModal] = useState(null);
            
            useEffect(() => {
                loadData();
            }, []);
            
            const loadData = async () => {
                try {
                    const [usersRes, feedRes, portfolioRes] = await Promise.all([
                        fetch('/api/users/discover'),
                        fetch('/api/feed'),
                        fetch(`/api/portfolio/${CURRENT_USER_ID}`)
                    ]);
                    setUsers(await usersRes.json());
                    setFeed(await feedRes.json());
                    setPortfolio(await portfolioRes.json());
                } catch (error) {
                    console.error('Error:', error);
                }
            };
            
            const handleFollow = async (userId) => {
                await fetch(`/api/follow/${userId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_user_id: CURRENT_USER_ID })
                });
                setFollowing(new Set([...following, userId]));
            };
            
            const handleUnfollow = async (userId) => {
                await fetch(`/api/unfollow/${userId}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ current_user_id: CURRENT_USER_ID })
                });
                const newFollowing = new Set(following);
                newFollowing.delete(userId);
                setFollowing(newFollowing);
            };
            
            return (
                <div className="app">
                    <div className="top-nav">
                        <div className="logo">InvestNet</div>
                        <div className="nav-tabs">
                            <div className={`nav-tab ${currentTab === 'feed' ? 'active' : ''}`} onClick={() => setCurrentTab('feed')}>Feed</div>
                            <div className={`nav-tab ${currentTab === 'discover' ? 'active' : ''}`} onClick={() => setCurrentTab('discover')}>Discover</div>
                            <div className={`nav-tab ${currentTab === 'portfolio' ? 'active' : ''}`} onClick={() => setCurrentTab('portfolio')}>Portfolio</div>
                            <div className={`nav-tab ${currentTab === 'analytics' ? 'active' : ''}`} onClick={() => setCurrentTab('analytics')}>Analytics</div>
                            <div className={`nav-tab ${currentTab === 'profile' ? 'active' : ''}`} onClick={() => setCurrentTab('profile')}>Profile</div>
                        </div>
                    </div>
                    
                    <div className="main">
                        {currentTab === 'feed' && <FeedView feed={feed} />}
                        {currentTab === 'discover' && <DiscoverView users={users} following={following} onFollow={handleFollow} onUnfollow={handleUnfollow} />}
                        {currentTab === 'portfolio' && <PortfolioView portfolio={portfolio} onAddProperty={() => setShowModal('property')} />}
                        {currentTab === 'analytics' && <AnalyticsView portfolio={portfolio} />}
                        {currentTab === 'profile' && <ProfileView />}
                    </div>
                    
                    {showModal === 'property' && <AddPropertyModal onClose={() => setShowModal(null)} onSave={loadData} />}
                </div>
            );
        }
        
        function FeedView({ feed }) {
            return (
                <div>
                    <h2 style={{fontSize: 32, fontWeight: 800, marginBottom: 24}}>Your Feed</h2>
                    {feed.map(item => (
                        <FeedItem key={item.id} item={item} />
                    ))}
                </div>
            );
        }
        
        function FeedItem({ item }) {
            const timeAgo = (timestamp) => {
                const diff = Date.now() - new Date(timestamp).getTime();
                const hours = Math.floor(diff / 3600000);
                if (hours < 1) return 'Just now';
                if (hours < 24) return `${hours}h ago`;
                return `${Math.floor(hours / 24)}d ago`;
            };
            
            return (
                <div className="feed-item">
                    <div className="feed-header">
                        <div className="feed-avatar">{item.user.avatar || '👤'}</div>
                        <div className="feed-user">
                            <div className="feed-name">{item.user.name}</div>
                            <div className="feed-time">{timeAgo(item.timestamp)}</div>
                        </div>
                    </div>
                    
                    {item.type === 'acquisition' && (
                        <div className="feed-content">
                            <p><strong>@{item.user.username}</strong> just acquired a new property</p>
                            <div className="feed-highlight">
                                <div style={{fontSize: 16, fontWeight: 700, marginBottom: 4}}>{item.property_name}</div>
                                <div style={{fontSize: 14, color: '#6b7280', marginBottom: 8}}>{item.location}</div>
                                <div style={{fontSize: 15, fontWeight: 600, color: '#10b981'}}>+${item.cash_flow}/mo cash flow</div>
                                <div style={{fontSize: 13, color: '#6b7280', marginTop: 8}}>
                                    <span className="ticker">${generate_ticker(item.user.portfolio_name)}</span> ↑ ${item.price_change.toFixed(2)} ({(item.price_change / 100 * 100).toFixed(1)}%)
                                </div>
                            </div>
                        </div>
                    )}
                    
                    {item.type === 'milestone' && (
                        <div className="feed-content">
                            <p><strong>@{item.user.username}</strong> hit a milestone! 🎉</p>
                            <div className="feed-highlight">
                                <div style={{fontSize: 18, fontWeight: 700}}>{item.milestone}</div>
                            </div>
                        </div>
                    )}
                    
                    {item.type === 'price_move' && (
                        <div className="feed-content">
                            <p><strong className="ticker">${item.ticker}</strong> is moving!</p>
                            <div className="feed-highlight">
                                <div style={{fontSize: 24, fontWeight: 800, color: '#10b981'}}>↑ {item.price_change.toFixed(1)}%</div>
                                <div style={{fontSize: 14, color: '#6b7280'}}>New price: ${item.new_price.toFixed(2)}</div>
                            </div>
                        </div>
                    )}
                </div>
            );
        }
        
        function DiscoverView({ users, following, onFollow, onUnfollow }) {
            return (
                <div>
                    <h2 style={{fontSize: 32, fontWeight: 800, marginBottom: 24}}>Discover Investors</h2>
                    
                    <h3 style={{fontSize: 20, fontWeight: 700, marginBottom: 16, opacity: 0.9}}>🔥 Top Performers</h3>
                    {users.slice(0, 5).map(user => (
                        <UserCard key={user.id} user={user} following={following} onFollow={onFollow} onUnfollow={onUnfollow} />
                    ))}
                    
                    <h3 style={{fontSize: 20, fontWeight: 700, marginTop: 32, marginBottom: 16, opacity: 0.9}}>👥 Similar to You</h3>
                    {users.slice(5, 10).map(user => (
                        <UserCard key={user.id} user={user} following={following} onFollow={onFollow} onUnfollow={onUnfollow} />
                    ))}
                </div>
            );
        }
        
        function UserCard({ user, following, onFollow, onUnfollow }) {
            const isFollowing = following.has(user.id);
            
            return (
                <div className="user-card">
                    <div className="user-avatar">{user.avatar || '👤'}</div>
                    <div className="user-info">
                        <div className="user-name">{user.name}</div>
                        <div className="user-username">@{user.username}</div>
                        <div style={{fontSize: 14, color: '#6b7280', marginTop: 4}}>{user.bio}</div>
                        <div className="user-stats">
                            <span className="ticker">${user.ticker}</span>
                            <span style={{color: user.price_change > 0 ? '#10b981' : '#ef4444'}}>
                                {user.price_change > 0 ? '↑' : '↓'} {Math.abs(user.price_change).toFixed(1)}%
                            </span>
                            <span>Health: {user.health_score}/100</span>
                            <span>{user.property_count} properties</span>
                        </div>
                    </div>
                    <button 
                        className={`btn ${isFollowing ? 'btn-following' : 'btn-follow'}`}
                        onClick={() => isFollowing ? onUnfollow(user.id) : onFollow(user.id)}
                    >
                        {isFollowing ? 'Following' : 'Follow'}
                    </button>
                </div>
            );
        }
        
        function PortfolioView({ portfolio, onAddProperty }) {
            if (!portfolio) return <div>Loading...</div>;
            
            const healthTier = portfolio.health_score >= 90 ? '⚡ Elite' : 
                             portfolio.health_score >= 75 ? '🔥 Strong' :
                             portfolio.health_score >= 60 ? '💪 Good' : '📈 Growing';
            
            return (
                <div>
                    <div className="card" style={{background: 'linear-gradient(135deg, rgba(102, 126, 234, 0.2), rgba(118, 75, 162, 0.2))'}}>
                        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'start'}}>
                            <div>
                                <h1 style={{fontSize: 36, fontWeight: 900, marginBottom: 8}}>Your Portfolio</h1>
                                <div style={{fontSize: 48, fontWeight: 900, fontFamily: 'Monaco, monospace', marginBottom: 16}}>
                                    <span className="ticker">${portfolio.ticker}</span> ${portfolio.share_price}
                                    <span style={{fontSize: 24, marginLeft: 16, color: '#10b981'}}>↑ 2.68%</span>
                                </div>
                            </div>
                            <div style={{textAlign: 'center'}}>
                                <div className="health-score-circle">
                                    <svg width="120" height="120">
                                        <circle cx="60" cy="60" r="50" fill="none" stroke="rgba(255,255,255,0.2)" strokeWidth="10"/>
                                        <circle 
                                            cx="60" cy="60" r="50" 
                                            fill="none" 
                                            stroke="#10b981" 
                                            strokeWidth="10"
                                            strokeDasharray={`${portfolio.health_score * 3.14} 314`}
                                            strokeLinecap="round"
                                            transform="rotate(-90 60 60)"
                                        />
                                    </svg>
                                    <div className="health-score-value">{portfolio.health_score}</div>
                                </div>
                                <div className="health-badge">{healthTier}</div>
                            </div>
                        </div>
                    </div>
                    
                    <div className="stats-grid">
                        <div className="stat-card">
                            <div className="stat-label">Total Equity</div>
                            <div className="stat-value">${(portfolio.total_equity / 1000).toFixed(0)}K</div>
                            <div className="progress-bar">
                                <div className="progress-fill" style={{width: '67%'}}></div>
                            </div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Annual Cash Flow</div>
                            <div className="stat-value">${(portfolio.annual_cashflow / 1000).toFixed(0)}K</div>
                            <div className="stat-change positive">↑ 12.5%</div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Properties</div>
                            <div className="stat-value">{portfolio.property_count}</div>
                            <div className="stat-change positive">Active</div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">DSCR</div>
                            <div className="stat-value">{portfolio.dscr.toFixed(2)}x</div>
                            <div className="stat-change positive">Healthy</div>
                        </div>
                    </div>
                    
                    <div className="card card-glass">
                        <div style={{display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20}}>
                            <h3 style={{fontSize: 20, fontWeight: 700}}>Your Properties</h3>
                            <button className="btn btn-primary" onClick={onAddProperty}>+ Add Property</button>
                        </div>
                        
                        {portfolio.properties.length === 0 ? (
                            <div style={{textAlign: 'center', padding: 40, color: '#6b7280'}}>
                                <div style={{fontSize: 48, marginBottom: 16}}>🏠</div>
                                <p>No properties yet. Add your first property to get started!</p>
                            </div>
                        ) : (
                            <div>
                                {portfolio.properties.map(p => (
                                    <div key={p.id} style={{padding: 16, borderBottom: '1px solid #e5e7eb'}}>
                                        <div style={{fontWeight: 700, marginBottom: 4}}>{p.name}</div>
                                        <div style={{fontSize: 14, color: '#6b7280'}}>{p.location}</div>
                                    </div>
                                ))}
                            </div>
                        )}
                    </div>
                </div>
            );
        }
        
        function AnalyticsView({ portfolio }) {
            if (!portfolio) return <div>Loading...</div>;
            
            const chartRef = useRef(null);
            const chartInstance = useRef(null);
            
            useEffect(() => {
                if (chartRef.current) {
                    const ctx = chartRef.current.getContext('2d');
                    
                    if (chartInstance.current) {
                        chartInstance.current.destroy();
                    }
                    
                    chartInstance.current = new Chart(ctx, {
                        type: 'bar',
                        data: {
                            labels: ['Property 1', 'Property 2', 'Property 3', 'Property 4', 'Property 5'],
                            datasets: [{
                                label: 'Monthly Revenue',
                                data: [3200, 2800, 4100, 3600, 2900],
                                backgroundColor: 'rgba(102, 126, 234, 0.8)'
                            }, {
                                label: 'Monthly Expenses',
                                data: [2100, 1900, 2500, 2200, 1800],
                                backgroundColor: 'rgba(239, 68, 68, 0.6)'
                            }]
                        },
                        options: {
                            responsive: true,
                            maintainAspectRatio: false,
                            plugins: {
                                legend: {
                                    display: true,
                                    position: 'top'
                                }
                            },
                            scales: {
                                y: {
                                    beginAtZero: true
                                }
                            }
                        }
                    });
                }
                
                return () => {
                    if (chartInstance.current) {
                        chartInstance.current.destroy();
                    }
                };
            }, [portfolio]);
            
            return (
                <div>
                    <h2 style={{fontSize: 32, fontWeight: 800, marginBottom: 24}}>Analytics</h2>
                    
                    <div className="chart-container">
                        <canvas ref={chartRef}></canvas>
                    </div>
                    
                    <div className="stats-grid">
                        <div className="stat-card">
                            <div className="stat-label">Cash-on-Cash Return</div>
                            <div className="stat-value">{portfolio.cash_on_cash.toFixed(1)}%</div>
                            <div className="progress-bar">
                                <div className="progress-fill" style={{width: `${portfolio.cash_on_cash}%`}}></div>
                            </div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Avg Occupancy</div>
                            <div className="stat-value">{portfolio.avg_occupancy}%</div>
                            <div className="progress-bar">
                                <div className="progress-fill" style={{width: `${portfolio.avg_occupancy}%`}}></div>
                            </div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Profit Margin</div>
                            <div className="stat-value">{portfolio.profit_margin.toFixed(0)}%</div>
                            <div className="progress-bar">
                                <div className="progress-fill" style={{width: `${portfolio.profit_margin}%`}}></div>
                            </div>
                        </div>
                        <div className="stat-card">
                            <div className="stat-label">Equity Ratio</div>
                            <div className="stat-value">{(portfolio.equity_ratio * 100).toFixed(0)}%</div>
                            <div className="progress-bar">
                                <div className="progress-fill" style={{width: `${portfolio.equity_ratio * 100}%`}}></div>
                            </div>
                        </div>
                    </div>
                </div>
            );
        }
        
        function ProfileView() {
            return (
                <div>
                    <h2 style={{fontSize: 32, fontWeight: 800, marginBottom: 24}}>Your Profile</h2>
                    <div className="card card-glass">
                        <div style={{textAlign: 'center'}}>
                            <div style={{
                                width: 100,
                                height: 100,
                                borderRadius: '50%',
                                background: 'linear-gradient(135deg, #667eea, #764ba2)',
                                display: 'flex',
                                alignItems: 'center',
                                justifyContent: 'center',
                                fontSize: 48,
                                margin: '0 auto 20px'
                            }}>👤</div>
                            <h3 style={{fontSize: 24, fontWeight: 700, marginBottom: 8}}>Brandon Bonomo</h3>
                            <p style={{fontSize: 16, color: '#6b7280', marginBottom: 16}}>@brandonb</p>
                            <p style={{fontSize: 14, color: '#6b7280', marginBottom: 24}}>Building wealth through smart real estate investments</p>
                            <div style={{display: 'flex', gap: 32, justifyContent: 'center', fontSize: 14}}>
                                <div><strong>0</strong> Followers</div>
                                <div><strong>0</strong> Following</div>
                            </div>
                        </div>
                    </div>
                </div>
            );
        }
        
        function AddPropertyModal({ onClose, onSave }) {
            const [formData, setFormData] = useState({
                name: '', location: '', purchase_price: 0, down_payment: 0,
                mortgage: 0, insurance: 0, hoa: 0, property_tax: 0
            });
            
            const handleSubmit = async (e) => {
                e.preventDefault();
                await fetch(`/api/properties/${CURRENT_USER_ID}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(formData)
                });
                onSave();
                onClose();
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
                                    <input className="form-input" value={formData.name} onChange={e => setFormData({...formData, name: e.target.value})} placeholder="Downtown Loft" required />
                                </div>
                                <div className="form-group">
                                    <label className="form-label">Location</label>
                                    <input className="form-input" value={formData.location} onChange={e => setFormData({...formData, location: e.target.value})} placeholder="Houston, TX" required />
                                </div>
                                <div className="form-grid">
                                    <div className="form-group">
                                        <label className="form-label">Purchase Price</label>
                                        <input type="number" className="form-input" value={formData.purchase_price} onChange={e => setFormData({...formData, purchase_price: parseFloat(e.target.value)})} />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">Down Payment</label>
                                        <input type="number" className="form-input" value={formData.down_payment} onChange={e => setFormData({...formData, down_payment: parseFloat(e.target.value)})} />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">Monthly Mortgage</label>
                                        <input type="number" className="form-input" value={formData.mortgage} onChange={e => setFormData({...formData, mortgage: parseFloat(e.target.value)})} />
                                    </div>
                                    <div className="form-group">
                                        <label className="form-label">Monthly Insurance</label>
                                        <input type="number" className="form-input" value={formData.insurance} onChange={e => setFormData({...formData, insurance: parseFloat(e.target.value)})} />
                                    </div>
                                </div>
                            </div>
                            <div className="modal-footer">
                                <button type="button" className="btn btn-secondary" onClick={onClose}>Cancel</button>
                                <button type="submit" className="btn btn-primary">Add Property</button>
                            </div>
                        </form>
                    </div>
                </div>
            );
        }
        
        function generate_ticker(name) {
            const words = name.toUpperCase().replace("'S", "").split(' ');
            if (words.length === 1) return words[0].slice(0, 4).padEnd(4, 'X');
            return words.map(w => w[0]).slice(0, 4).join('').padEnd(4, 'X');
        }
        
        ReactDOM.render(<App />, document.getElementById('root'));
    </script>
</body>
</html>"""

# API Routes
@app.route('/')
def index():
    return HTML

@app.route('/api/users/discover')
def discover_users():
    all_users = demo_users + users
    return jsonify([{
        **u,
        'ticker': generate_ticker(u['portfolio_name']),
        'share_price': random.uniform(150, 450),
        'price_change': random.uniform(-3, 8),
        'health_score': random.randint(72, 96),
        'property_count': random.randint(3, 12),
        'followers': random.randint(45, 450)
    } for u in all_users[:10]])

@app.route('/api/feed')
def get_feed():
    feed = []
    for i in range(15):
        user = random.choice(demo_users)
        feed_type = random.choice(['acquisition', 'milestone', 'price_move'])
        
        if feed_type == 'acquisition':
            feed.append({
                'id': i,
                'type': 'acquisition',
                'user': user,
                'property_name': f"Property #{random.randint(5, 12)}",
                'location': user['location'],
                'cash_flow': random.randint(150, 450),
                'price_change': random.uniform(1, 4),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat()
            })
        elif feed_type == 'milestone':
            feed.append({
                'id': i,
                'type': 'milestone',
                'user': user,
                'milestone': random.choice(['Reached 10 properties', 'Hit $1M portfolio value', 'Achieved 90% occupancy', 'Health Score reached 95']),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat()
            })
        else:
            feed.append({
                'id': i,
                'type': 'price_move',
                'user': user,
                'ticker': generate_ticker(user['portfolio_name']),
                'price_change': random.uniform(6, 14),
                'new_price': random.uniform(220, 480),
                'timestamp': (datetime.now() - timedelta(hours=random.randint(1, 48))).isoformat()
            })
    
    return jsonify(sorted(feed, key=lambda x: x['timestamp'], reverse=True))

@app.route('/api/portfolio/<int:user_id>')
def get_portfolio(user_id):
    props = properties.get(user_id, [])
    
    total_value = sum(p.get('purchase_price', 0) for p in props)
    total_equity = sum(p.get('equity', 0) for p in props)
    monthly_income = sum(p.get('monthly_revenue', 0) for p in props)
    monthly_expenses = sum(p.get('monthly_expenses', 0) for p in props)
    
    portfolio_data = {
        'properties': props,
        'total_equity': total_equity or 350000,
        'annual_cashflow': (monthly_income - monthly_expenses) * 12 or 42000,
        'property_count': len(props) or 7,
        'dscr': monthly_income / monthly_expenses if monthly_expenses > 0 else 1.45,
        'cash_on_cash': 15.5,
        'equity_ratio': total_equity / total_value if total_value > 0 else 0.35,
        'avg_occupancy': 78,
        'revenue_growth': 0.125,
        'profit_margin': ((monthly_income - monthly_expenses) / monthly_income * 100) if monthly_income > 0 else 35,
        'cash_reserves': 50000,
        'debt_ratio': 0.65,
        'growth_rate': 2.1,
        'momentum': 3.2
    }
    
    portfolio_data['health_score'] = calculate_health_score(portfolio_data)
    portfolio_data['share_price'] = calculate_share_price(portfolio_data)
    portfolio_data['ticker'] = generate_ticker("Brandon's Empire")
    
    return jsonify(portfolio_data)

@app.route('/api/properties/<int:user_id>', methods=['POST'])
def add_property(user_id):
    data = request.json
    if user_id not in properties:
        properties[user_id] = []
    
    new_property = {
        'id': len(properties[user_id]) + 1,
        'name': data['name'],
        'location': data['location'],
        'purchase_price': data.get('purchase_price', 0),
        'down_payment': data.get('down_payment', 0),
        'equity': data.get('down_payment', 0),
        'mortgage': data.get('mortgage', 0),
        'insurance': data.get('insurance', 0),
        'hoa': data.get('hoa', 0),
        'property_tax': data.get('property_tax', 0),
        'monthly_revenue': 0,
        'monthly_expenses': data.get('mortgage', 0) + data.get('insurance', 0) + data.get('hoa', 0) + data.get('property_tax', 0)
    }
    
    properties[user_id].append(new_property)
    return jsonify(new_property)

@app.route('/api/follow/<int:user_id>', methods=['POST'])
def follow_user(user_id):
    current_user_id = request.json.get('current_user_id', 999)
    follows[current_user_id].add(user_id)
    return jsonify({'success': True})

@app.route('/api/unfollow/<int:user_id>', methods=['POST'])
def unfollow_user(user_id):
    current_user_id = request.json.get('current_user_id', 999)
    follows[current_user_id].discard(user_id)
    return jsonify({'success': True})

@app.route('/api/plaid/create-link-token')
def create_link_token():
    return jsonify({'link_token': 'link-sandbox-demo-token'})

@app.route('/api/plaid/exchange-token', methods=['POST'])
def exchange_token():
    return jsonify({'success': True})

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
