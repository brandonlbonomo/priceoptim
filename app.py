from flask import Flask, jsonify, request
from flask_cors import CORS
import os

app = Flask(__name__)
CORS(app)

# Data
properties = [
    {"id": 1, "name": "Modern Downtown Loft", "location": "Houston, TX", "icon": "🏢", "currentPrice": 175, "recommendedPrice": 195, "occupancy": 78, "adr": 182, "revpar": 142, "algorithmScore": 0.89, "status": "optimized"},
    {"id": 2, "name": "Cozy Midtown Apartment", "location": "Houston, TX", "icon": "🏠", "currentPrice": 140, "recommendedPrice": 155, "occupancy": 65, "adr": 145, "revpar": 94, "algorithmScore": 0.72, "status": "attention"},
    {"id": 3, "name": "Luxury Penthouse Suite", "location": "Houston, TX", "icon": "✨", "currentPrice": 350, "recommendedPrice": 380, "occupancy": 82, "adr": 365, "revpar": 299, "algorithmScore": 0.91, "status": "optimized"},
    {"id": 4, "name": "Heights Bungalow", "location": "Houston, TX", "icon": "🌳", "currentPrice": 165, "recommendedPrice": 170, "occupancy": 71, "adr": 167, "revpar": 119, "algorithmScore": 0.81, "status": "optimized"},
    {"id": 5, "name": "Memorial Park House", "location": "Houston, TX", "icon": "🌿", "currentPrice": 220, "recommendedPrice": 240, "occupancy": 74, "adr": 225, "revpar": 167, "algorithmScore": 0.85, "status": "optimized"},
    {"id": 6, "name": "Galleria Condo", "location": "Houston, TX", "icon": "🏙️", "currentPrice": 155, "recommendedPrice": 165, "occupancy": 69, "adr": 160, "revpar": 110, "algorithmScore": 0.78, "status": "optimized"},
    {"id": 7, "name": "Downtown Studio", "location": "Houston, TX", "icon": "🎨", "currentPrice": 95, "recommendedPrice": 105, "occupancy": 85, "adr": 98, "revpar": 83, "algorithmScore": 0.88, "status": "optimized"}
]

intelligence = [
    {"type": "flight", "title": "Flight Demand Increasing", "description": "TSA checkpoint throughput to Houston up 15% vs last week.", "score": 0.85, "icon": "✈️"},
    {"type": "event", "title": "Houston Rodeo Starting Soon", "description": "Feb 24-Mar 15. Expected 2.5M+ attendance. Price multiplier: 2.8x", "score": 0.92, "icon": "🎉"},
    {"type": "economy", "title": "Consumer Confidence Strong", "description": "CCI at 104.5, travel spending up 8% YoY.", "score": 0.78, "icon": "📊"},
    {"type": "competition", "title": "5 New Listings Detected", "description": "New competition. Average price $10 below portfolio.", "score": 0.65, "icon": "🏠"}
]

HTML = """<!DOCTYPE html>
<html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width, initial-scale=1.0"><title>PriceOptim</title>
<script crossorigin src="https://unpkg.com/react@18/umd/react.production.min.js"></script>
<script crossorigin src="https://unpkg.com/react-dom@18/umd/react-dom.production.min.js"></script>
<script src="https://unpkg.com/@babel/standalone/babel.min.js"></script>
<style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:-apple-system,BlinkMacSystemFont,sans-serif;background:#0a0e14;color:#fff;line-height:1.6}.container{max-width:1400px;margin:0 auto;padding:20px}.header{background:linear-gradient(135deg,#1a1f2e 0%,#0f1419 100%);padding:40px;border-radius:16px;margin-bottom:32px;text-align:center}.title{font-size:48px;font-weight:800;background:linear-gradient(135deg,#00ff88 0%,#00d4ff 100%);-webkit-background-clip:text;-webkit-text-fill-color:transparent;margin-bottom:12px}.subtitle{color:#8a99ad;font-size:18px}.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:20px;margin-bottom:32px}.stat-card{background:#141b24;padding:24px;border-radius:12px;border:1px solid #253342;transition:all .3s}.stat-card:hover{transform:translateY(-4px);border-color:#00ff88}.stat-label{font-size:12px;color:#8a99ad;text-transform:uppercase;margin-bottom:8px}.stat-value{font-size:36px;font-weight:800;margin-bottom:8px}.stat-change{font-size:14px;color:#00ff88}.properties{display:grid;grid-template-columns:repeat(auto-fill,minmax(350px,1fr));gap:24px}.property-card{background:#141b24;border-radius:16px;border:1px solid #253342;overflow:hidden;transition:all .3s}.property-card:hover{transform:translateY(-8px);border-color:#00ff88}.property-header{padding:24px;background:linear-gradient(135deg,#1c2530 0%,#141b24 100%);position:relative}.property-icon{font-size:48px;margin-bottom:12px}.property-badge{position:absolute;top:16px;right:16px;padding:6px 12px;border-radius:20px;font-size:11px;font-weight:700;text-transform:uppercase;background:rgba(0,255,136,.2);color:#00ff88;border:1px solid #00ff88}.property-name{font-size:20px;font-weight:700;margin-bottom:4px}.property-location{font-size:14px;color:#8a99ad}.property-body{padding:24px}.price-row{display:flex;justify-content:space-between;margin-bottom:20px;padding-bottom:20px;border-bottom:1px solid #253342}.price-label{font-size:12px;color:#8a99ad;text-transform:uppercase}.price-value{font-size:32px;font-weight:800;color:#00ff88}.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:16px}.metric{text-align:center}.metric-value{font-size:20px;font-weight:700;margin-bottom:4px}.metric-label{font-size:11px;color:#8a99ad;text-transform:uppercase}.intel{background:#141b24;padding:32px;border-radius:16px;border:1px solid #253342;margin-bottom:40px}.intel-item{padding:20px;margin-bottom:16px;background:#1c2530;border-radius:12px;border-left:4px solid #00d4ff}.intel-header{display:flex;align-items:center;gap:16px;margin-bottom:12px}.intel-icon{font-size:28px}.intel-title{font-weight:700;font-size:16px;flex:1}.intel-score{font-size:24px;font-weight:800;color:#00ff88}.intel-desc{font-size:14px;color:#8a99ad}.section-title{font-size:24px;font-weight:700;margin-bottom:24px}</style></head>
<body><div id="root"></div>
<script type="text/babel">
const {useState,useEffect}=React;
function App(){const[properties,setProperties]=useState([]);const[intelligence,setIntelligence]=useState([]);const[stats,setStats]=useState(null);const[loading,setLoading]=useState(true);useEffect(()=>{loadData()},[]);const loadData=async()=>{try{const[propsRes,intelRes,statsRes]=await Promise.all([fetch('/api/properties'),fetch('/api/intelligence'),fetch('/api/portfolio-stats')]);setProperties(await propsRes.json());setIntelligence(await intelRes.json());setStats(await statsRes.json());setLoading(false)}catch(error){console.error(error);setLoading(false)}};if(loading)return <div style={{textAlign:'center',padding:'60px',color:'#8a99ad'}}>Loading...</div>;return(<div className="container"><div className="header"><h1 className="title">PRICEOPTIM</h1><p className="subtitle">Advanced Airbnb Pricing Intelligence</p></div>{stats&&(<div className="stats"><div className="stat-card"><div className="stat-label">Monthly Revenue</div><div className="stat-value">${Math.round(stats.totalRevenue).toLocaleString()}</div><div className="stat-change">↑ 12.5% vs last month</div></div><div className="stat-card"><div className="stat-label">Avg Occupancy</div><div className="stat-value">{stats.avgOccupancy.toFixed(1)}%</div><div className="stat-change">↑ 8.2% vs market</div></div><div className="stat-card"><div className="stat-label">Avg Daily Rate</div><div className="stat-value">${Math.round(stats.avgADR)}</div><div className="stat-change">↑ $15 optimized</div></div><div className="stat-card"><div className="stat-label">Algorithm Score</div><div className="stat-value">{Math.round(stats.avgAlgorithmScore*100)}</div><div className="stat-change">↑ +5 pts</div></div></div>)}<div className="intel"><h2 className="section-title">🧠 Market Intelligence</h2>{intelligence.map((intel,idx)=>(<div key={idx} className="intel-item"><div className="intel-header"><span className="intel-icon">{intel.icon}</span><span className="intel-title">{intel.title}</span><span className="intel-score">{Math.round(intel.score*100)}</span></div><div className="intel-desc">{intel.description}</div></div>))}</div><h2 className="section-title">📊 Your {properties.length} Properties</h2><div className="properties">{properties.map(p=>{const change=((p.recommendedPrice-p.currentPrice)/p.currentPrice*100).toFixed(1);return(<div key={p.id} className="property-card"><div className="property-header"><span className="property-icon">{p.icon}</span><div className="property-badge">✓ OPTIMIZED</div><div className="property-name">{p.name}</div><div className="property-location">📍 {p.location}</div></div><div className="property-body"><div className="price-row"><div><div className="price-label">Recommended</div><div className="price-value">${p.recommendedPrice}</div></div><div style={{textAlign:'right'}}><div className="price-label">Current</div><div style={{fontSize:'20px',color:'#8a99ad'}}>${p.currentPrice}</div></div></div><div className="metrics"><div className="metric"><div className="metric-value">{p.occupancy}%</div><div className="metric-label">Occupancy</div></div><div className="metric"><div className="metric-value">${p.revpar}</div><div className="metric-label">RevPAR</div></div><div className="metric"><div className="metric-value" style={{color:change>0?'#00ff88':'#ff3366'}}>{change>0?'+':''}{change}%</div><div className="metric-label">Change</div></div></div></div></div>)})}</div></div>)}
ReactDOM.render(<App/>,document.getElementById('root'));
</script></body></html>"""

@app.route('/')
def index():
    return HTML

@app.route('/api/health')
def health():
    return jsonify({"status": "healthy"})

@app.route('/api/properties')
def get_properties():
    return jsonify(properties)

@app.route('/api/properties', methods=['POST'])
def add_property():
    data = request.json
    new_id = max([p['id'] for p in properties]) + 1
    new_property = {
        "id": new_id,
        "name": data.get('name'),
        "location": data.get('location'),
        "icon": data.get('icon', '🏠'),
        "currentPrice": data.get('currentPrice'),
        "recommendedPrice": int(data.get('currentPrice') * 1.1),
        "occupancy": 70,
        "adr": data.get('currentPrice'),
        "revpar": int(data.get('currentPrice') * 0.7),
        "algorithmScore": 0.75,
        "status": "optimized"
    }
    properties.append(new_property)
    return jsonify(new_property), 201

@app.route('/api/intelligence')
def get_intelligence():
    return jsonify(intelligence)

@app.route('/api/portfolio-stats')
def get_stats():
    total_revenue = sum(p['revpar'] * 30 for p in properties)
    avg_occupancy = sum(p['occupancy'] for p in properties) / len(properties)
    avg_adr = sum(p['adr'] for p in properties) / len(properties)
    avg_score = sum(p['algorithmScore'] for p in properties) / len(properties)
    return jsonify({
        "totalRevenue": total_revenue,
        "avgOccupancy": avg_occupancy,
        "avgADR": avg_adr,
        "avgAlgorithmScore": avg_score,
        "propertyCount": len(properties)
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
