from flask import Flask, request, jsonify, render_template, send_from_directory
from pymongo import MongoClient
from dotenv import load_dotenv
import os
import logging

load_dotenv()

app = Flask(__name__, static_folder='static', template_folder='templates')

# Configure basic logging so service debug messages are visible in console
logging.basicConfig(level=logging.INFO, format='%(asctime)s %(levelname)s %(name)s: %(message)s')

MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
client = MongoClient(MONGO_URI)
db = client.cti_dashboard

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/lookup', methods=['POST'])
def api_lookup():
    data = request.json or {}
    query = data.get('query')
    if not query:
        return jsonify({'error': 'query required (IP or domain)'}), 400

    cached = db.lookups.find_one({'query': query})
    if cached:
        return jsonify({'source': 'cache', 'data': cached['result']})

    from services.virustotal import vt_lookup
    from services.abuseipdb import abuse_lookup
    from services.otx import otx_lookup

    vt = vt_lookup(query)
    abuse = abuse_lookup(query)
    otx = otx_lookup(query)

    result = {'query': query, 'virustotal': vt, 'abuseipdb': abuse, 'otx': otx}
    from datetime import datetime
    db.lookups.insert_one({'query': query, 'result': result})
    db.iocs.update_one(
        {'ip': query},
        {'$set': {
            'ip': query,
            'virustotal': vt,
            'abuseipdb': abuse,
            'otx': otx,
            'timestamp': datetime.utcnow().isoformat()
        }},
        upsert=True
    )
    return jsonify({'source': 'live', 'data': result})

@app.route('/api/iocs', methods=['GET'])
def list_iocs():
    docs = list(db.iocs.find({}, {'_id': 0}).limit(100))
    return jsonify(docs)


# Debug helper: test VirusTotal lookup directly
@app.route('/api/test_vt', methods=['GET'])
def test_vt():
    q = request.args.get('q')
    if not q:
        return jsonify({'error': 'q parameter required'}), 400
    from services.virustotal import vt_lookup
    res = vt_lookup(q)
    return jsonify(res)

# Tagging endpoint
@app.route('/api/tag', methods=['POST'])
def tag_ioc():
    data = request.json or {}
    ioc = data.get('ioc')
    tags = data.get('tags', '')
    db.iocs.update_one({'ip': ioc}, {'$set': {'tags': tags}})
    return jsonify({'status': 'ok'})

@app.route('/outputs/<path:filename>')
def outputs(filename):
    return send_from_directory('outputs', filename)

if __name__ == '__main__':
    os.makedirs('outputs', exist_ok=True)
    app.run(host='0.0.0.0', port=5000, debug=True)
