from apscheduler.schedulers.blocking import BlockingScheduler
from services.otx import otx_lookup
from services.virustotal import vt_lookup
from services.abuseipdb import abuse_lookup
from pymongo import MongoClient
import os

MONGO_URI = os.getenv('MONGO_URI', 'mongodb://localhost:27017')
client = MongoClient(MONGO_URI)
db = client.cti_dashboard

sched = BlockingScheduler()

@sched.scheduled_job('interval', minutes=10)
def poll_otx():
    sample = ['8.8.8.8', '1.1.1.1']  # Extend this list or load from config/file as needed
    for ip in sample:
            otx_res = otx_lookup(ip)
            vt_res = vt_lookup(ip)
            abuse_res = abuse_lookup(ip)
            from datetime import datetime
            db.iocs.update_one(
                {'ip': ip},
                {'$set': {
                    'ip': ip,
                    'otx': otx_res,
                    'virustotal': vt_res,
                    'abuseipdb': abuse_res,
                    'timestamp': datetime.utcnow().isoformat()
                }},
                upsert=True
            )

if __name__ == '__main__':
    sched.start()
