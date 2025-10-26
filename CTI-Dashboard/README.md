# CTI Dashboard (Minimal)

Simple Flask-based CTI dashboard that uses Docker MongoDB (mongo:6.0) for storage and integrates VirusTotal, AbuseIPDB and OTX (basic).

## Quickstart
1. Ensure Docker is running and start MongoDB container:
   docker run -d --name cti-mongo -p 27017:27017 -v ~/cti-dashboard/mongo-data:/data/db mongo:6.0
2. Create and activate virtualenv, install requirements:
   python3 -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
3. Fill `.env` with API keys.
4. Run the app:
   python app.py
5. Open http://127.0.0.1:5000
