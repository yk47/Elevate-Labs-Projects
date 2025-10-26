import os, requests
from .utils import is_ip

OTX_KEY = os.getenv('OTX_API_KEY')
BASE = 'https://otx.alienvault.com/api/v1'
HEADERS = {'X-OTX-API-KEY': OTX_KEY} if OTX_KEY else {}

def otx_lookup(query):
    if not OTX_KEY:
        return {'error': 'no_api_key'}
    try:
        if is_ip(query):
            url = f'{BASE}/indicators/IPv4/{query}/general'
        else:
            url = f'{BASE}/indicators/domain/{query}/general'
        r = requests.get(url, headers=HEADERS, timeout=10)
        return r.json() if r.ok else {'error': r.status_code, 'text': r.text}
    except Exception as e:
        return {'error': str(e)}
