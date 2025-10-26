# 🚀 CTI Dashboard (Minimal)

##  📝 Overview
CTI-Dashboard is a **Cyber Threat Intelligence (CTI) web application** that aggregates, analyzes, and visualizes threat data from multiple sources in real time.  
It helps security analysts monitor IOCs (Indicators of Compromise), track threat trends, and perform quick threat lookups for IPs, domains, and URLs.

**✨Key Features:**
- 📡Aggregate real-time CTI feeds from open sources and APIs (VirusTotal, AbuseIPDB, OTX)
- 📊 Display threat levels and IOC trends
- 🔍Lookup IPs, domains, or file hashes against threat databases
- 🏷️Tag indicators and export data for further analysis
- 📈Visual dashboards with charts and tables

---

##  🖼️ Dashboard Screenshot
<img width="1920" height="1080" alt="Dashboard" src="https://github.com/user-attachments/assets/838d7f90-5f94-4542-93b2-3a3c8ab36f4d" />

<img width="1920" height="1080" alt="Dashboard1" src="https://github.com/user-attachments/assets/506fee04-b703-46e8-969d-0bb37a8fd6b8" />

---

## 📂 Project Structure

```bash
CTI-Dashboard/
├─ app.py # Main Flask app
├─ requirements.txt # Python dependencies
├─ static/ # CSS, JS, images (dashboard screenshot goes here)
├─ templates/ # HTML templates
├─ outputs/ # Exported CSV/JSON files
├─ workers/ # Background worker scripts
├─ services/ # External CTI API modules
└─ docker-compose.yml # Docker configuration
```

---

## ⚙️ Installation (Using Docker)

1. Clone the repository:  
```bash
git clone https://github.com/yk47/Elevate-Labs-Projects.git
cd Elevate-Labs-Projects/CTI-Dashboard
```

2.Create a .env file in the CTI-Dashboard folder with your API keys:
```bash
MONGO_URI=mongodb://mongo:27017/ctidb
CELERY_BROKER=redis://redis:6379/0
VT_API_KEY=<your_virustotal_key>
ABUSEIPDB_KEY=<your_abuseipdb_key>
OTX_API_KEY=<your_otx_key>
```

3.Start the Docker stack:
```bash
docker compose up --build -d

```
4.Open the dashboard in your browser:
```bash
http://localhost:5000

```

## 🪧Usage
- 🔍Use the Lookup feature or /api/lookup endpoint to check IPs/domains.
- 📊Monitor threat trends on the dashboard charts.
- 🏷️Tag IOCs and export results for reporting or research.

---

## 🤝Contributing
- 1.Fork the repository.
- 2.Create a feature branch (git checkout -b feature-name).- 3.
- 3.Commit your changes (git commit -m "Add new feature").
- 4.Push to your branch (git push origin feature-name).
- 5.Open a Pull Request.

