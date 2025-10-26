import os, requests
from .utils import is_ip

ABUSE_KEY = os.getenv('ABUSEIPDB_API_KEY')
BASE = 'https://api.abuseipdb.com/api/v2'
HEADERS = {'Key': ABUSE_KEY, 'Accept': 'application/json'} if ABUSE_KEY else {}

def abuse_lookup(query):
    if not ABUSE_KEY:
        return {'error': 'no_api_key'}
    try:
        if not is_ip(query):
            return {'error': 'abuseipdb only supports IPs'}
        url = f'{BASE}/check'
        params = {'ipAddress': query, 'maxAgeInDays': 90}
        r = requests.get(url, headers=HEADERS, params=params, timeout=10)
        return r.json() if r.ok else {'error': r.status_code, 'text': r.text}
    except Exception as e:
        return {'error': str(e)}
