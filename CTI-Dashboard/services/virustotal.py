import os
import logging
import requests
from .utils import is_ip

logger = logging.getLogger(__name__)
VT_KEY = os.getenv('VT_API_KEY')
HEADERS = {'x-apikey': VT_KEY} if VT_KEY else {}


def vt_lookup(query):
    """Lookup a domain or IP on VirusTotal and return a normalized response.

    Returns a dict with either the full VT JSON on success or an {'error': ...}
    structure on failure. Logs useful debug info to help troubleshoot API issues.
    """
    if not VT_KEY:
        logger.warning('VirusTotal API key not set (VT_API_KEY)')
        return {'error': 'no_api_key'}

    try:
        if is_ip(query):
            url = f'https://www.virustotal.com/api/v3/ip_addresses/{query}'
        else:
            url = f'https://www.virustotal.com/api/v3/domains/{query}'

        logger.debug('VT lookup URL: %s', url)
        r = requests.get(url, headers=HEADERS, timeout=15)

        if not r.ok:
            logger.error('VirusTotal lookup failed: %s %s', r.status_code, r.text[:500])
            return {'error': r.status_code, 'text': r.text}

        j = r.json()
        # Basic normalization: expose last_analysis_stats at top-level for easier use
        data = j.get('data') or {}
        attrs = data.get('attributes', {}) if isinstance(data, dict) else {}
        # Attach some convenience fields if present
        if attrs:
            j['last_analysis_stats'] = attrs.get('last_analysis_stats', {})
            j['reputation'] = attrs.get('reputation')
            # country and as_owner used elsewhere
            j['country'] = attrs.get('country') or attrs.get('geo')
            j['attributes'] = attrs

        return j

    except requests.exceptions.RequestException as e:
        logger.exception('Network error during VirusTotal lookup: %s', e)
        return {'error': str(e)}
    except Exception as e:
        logger.exception('Unexpected error during VirusTotal lookup: %s', e)
        return {'error': str(e)}
