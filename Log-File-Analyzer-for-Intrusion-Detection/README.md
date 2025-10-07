# 🚀 Project---Log-File-Analyzer-for-Intrusion-Detection
A simple Log File Analyzer for Intrusion Detection (Apache + SSH). Outputs incident CSV/JSON, alert log, and basic matplotlib visualizations.

## 🎯 Project plan
Goal: build a CLI Python tool that ingests Apache and SSH logs, finds suspicious patterns (brute-force, scanning, DoS), cross-checks IPs against a provided blacklist file, produces CSV/JSON incident reports, and generates visualizations.

**Minimum viable features:**
- Parse Apache "combined" log format and OpenSSH ```auth.log``` lines.
- Normalize events to a small event schema: ```{timestamp, ip, host, service, user, method, url, status, msg}```.
- Detection modules:
    - Bruteforce (SSH): multiple failed auth attempts from same IP -> flag if N fails within T minutes.
    - Bruteforce (Web): many failed login-like POSTs or many 401/403 codes for same IP within T.
    - Scanning: same IP hitting many distinct endpoints + many 404s.
    - DoS / High-rate: IP generating > R requests within time window W.
    - Port-scan-ish (if you have network logs): many distinct destination ports from same source.
- Cross-reference: user provides a blacklist file (one IP per line or CIDR). The tool marks incidents where IP in blacklist.
- Output:
    - ```incidents.csv``` (tabular), ```incidents.json``` (structured), and ```alerts.log``` (plain text).
    - Visualizations: histogram of requests per IP (top N), timeseries of requests per minute, map of top IPs by hits (optional: needs GeoIP).
- CLI options: specify input files, thresholds, output dir, which detection modules to run, blacklist file.

**Recommended thresholds (tweakable via CLI):**
- SSH brute-force: ```fails_threshold=10``` in ```window_minutes=10```.
- Web brute-force: ```fail_statuses={401,403}``` ```fails_threshold=20``` in ```window_minutes=10```.
- Scanning: ```distinct_paths_threshold=30``` within ```window_minutes=10``` or >50% 404s.
- DoS: ```requests_threshold=500``` requests in ```window_minutes=1``` (tune per server).

**🗂️File structure:**
```bash
└── Log-File-Analyzer-for-Intrusion-Detection
    ├── README.md
    ├── blacklist.txt
    ├── log_analyzer.py
    ├── output
        ├── alerts.log
        ├── incidents.csv
        ├── incidents.json
        ├── requests_per_minute.png
        └── top_ips.png
    ├── requirements.txt
    ├── sample_logs
        ├── apache.log
        └── auth.log
    └── screenshots
        ├── create&activate_virtual_environment.png
        ├── install_requirements.png
        ├── log_analyzer_code.png
        ├── output_files.png
        ├── requirments_blacklist.png
        ├── run_log_analyzer.png
        └── sample_logs.png
```

**Detection approach notes:**
- Use rolling windows by bucketing timestamps into minute bins and using sliding sums (pandas resample or groupby).
- Use regex to parse logs into structured rows; convert to pandas DataFrame for aggregation and detection.
- For performance on very large logs: process incrementally / chunking or use Dask; but initial version operates on logs that fit in memory.

**💻Now — code and docs below.**
```bash
```python
#!/usr/bin/env python3
"""
log_analyzer.py
A simple Log File Analyzer for Intrusion Detection (Apache + SSH).
Outputs incident CSV/JSON, alert log, and basic matplotlib visualizations.

Usage examples:
    python log_analyzer.py --apache access.log --ssh auth.log --blacklist blacklist.txt --outdir output

Author: Yash Karnik (starter template)
"""

import re
import argparse
import json
from datetime import datetime, timedelta
from collections import defaultdict, Counter
import pandas as pd
import matplotlib.pyplot as plt
import os
import ipaddress

# ---- Regex patterns ----
# Apache combined log example:
# 127.0.0.1 - frank [10/Oct/2000:13:55:36 -0700] "GET /apache_pb.gif HTTP/1.0" 200 2326 "http://example.com" "User-Agent"
APACHE_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<time>.+?)\] "(?P<method>\S+) (?P<url>\S+)[^"]*" (?P<status>\d{3}) (?P<size>\S+) "(?P<referer>[^"]*)" "(?P<ua>[^"]*)"'
)

# OpenSSH auth.log examples (various formats). We'll try to capture:
# "Nov 10 10:45:12 hostname sshd[12345]: Failed password for invalid user root from 1.2.3.4 port 54321 ssh2"
SSH_RE = re.compile(
    r'^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+sshd\[\d+\]:\s+(?P<msg>.+)$'
)
SSH_IP_RE = re.compile(r'from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})')
SSH_FAILED_RE = re.compile(r'Failed password for (invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')
SSH_ACCEPTED_RE = re.compile(r'Accepted password for (?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})')

# ---- Helpers ----

MONTHS = {m: i for i, m in enumerate(["Jan","Feb","Mar","Apr","May","Jun","Jul","Aug","Sep","Oct","Nov","Dec"], start=1)}

def parse_apache_line(line):
    m = APACHE_RE.search(line)
    if not m:
        return None
    gd = m.groupdict()
    # Example time format: 10/Oct/2000:13:55:36 -0700
    tstr = gd['time']
    try:
        dt = datetime.strptime(tstr.split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        # sometimes year missing -> try fallback (rare)
        dt = None
    return {
        "timestamp": dt,
        "ip": gd['ip'],
        "service": "apache",
        "method": gd['method'],
        "url": gd['url'],
        "status": int(gd['status']),
        "raw": line.strip()
    }

def parse_ssh_line(line, current_year=None):
    m = SSH_RE.search(line)
    if not m:
        return None
    gd = m.groupdict()
    month = MONTHS.get(gd['month'], 1)
    day = int(gd['day'])
    timestr = gd['time']
    if current_year is None:
        current_year = datetime.now().year
    dt = datetime.strptime(f"{current_year}-{month:02d}-{day:02d} {timestr}", "%Y-%m-%d %H:%M:%S")
    msg = gd['msg']
    ip_match = SSH_IP_RE.search(msg)
    ip = ip_match.group('ip') if ip_match else None
    res = {
        "timestamp": dt,
        "ip": ip,
        "service": "ssh",
        "raw_msg": msg,
        "raw": line.strip()
    }
    fm = SSH_FAILED_RE.search(msg)
    if fm:
        res.update({"event": "ssh_failed", "user": fm.group("user")})
    fa = SSH_ACCEPTED_RE.search(msg)
    if fa:
        res.update({"event": "ssh_success", "user": fa.group("user")})
    return res

def load_blacklist(path):
    """Load blacklist file (one IP or CIDR per line). Returns list of ipaddress networks."""
    if not path or not os.path.exists(path):
        return []
    nets = []
    with open(path) as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith('#'):
                continue
            try:
                if '/' in s:
                    nets.append(ipaddress.ip_network(s.strip()))
                else:
                    nets.append(ipaddress.ip_network(s.strip()+"/32"))
            except Exception:
                continue
    return nets

def ip_in_blacklist(ip, nets):
    if not ip:
        return False
    try:
        ipobj = ipaddress.ip_address(ip)
    except Exception:
        return False
    for n in nets:
        if ipobj in n:
            return True
    return False

# ---- Parsing and building DataFrame ----

def parse_logs(apache_path=None, ssh_path=None):
    rows = []
    # Apache
    if apache_path and os.path.exists(apache_path):
        with open(apache_path, errors='ignore') as f:
            for line in f:
                p = parse_apache_line(line)
                if p:
                    rows.append(p)
    # SSH
    if ssh_path and os.path.exists(ssh_path):
        for line in open(ssh_path, errors='ignore'):
            p = parse_ssh_line(line)
            if p:
                rows.append(p)
    if not rows:
        return pd.DataFrame()
    df = pd.DataFrame(rows)
    # Ensure timestamp column
    if 'timestamp' in df.columns:
        df = df[~df['timestamp'].isnull()].copy()
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df.sort_values('timestamp', inplace=True)
    return df

# ---- Detection functions ----

def detect_ssh_bruteforce(df, fails_threshold=10, window_minutes=10):
    """Detect SSH brute-force: count failed auths per IP in sliding windows."""
    df_ssh_failed = df[(df['service']=='ssh') & (df.get('event')=='ssh_failed')].copy()
    incidents = []
    if df_ssh_failed.empty:
        return incidents
    # Group by IP and slide via resample
    for ip, g in df_ssh_failed.groupby('ip'):
        times = g['timestamp'].sort_values()
        # sliding window count
        start_idx = 0
        times_list = times.tolist()
        for i, t in enumerate(times_list):
            # move start_idx so that times_list[start_idx] >= t - window
            while times_list[start_idx] < t - timedelta(minutes=window_minutes):
                start_idx += 1
                if start_idx > i:
                    break
            count = i - start_idx + 1
            if count >= fails_threshold:
                incidents.append({
                    "type": "ssh_bruteforce",
                    "ip": ip,
                    "start": times_list[start_idx].isoformat(),
                    "end": t.isoformat(),
                    "count": count,
                    "desc": f"{count} failed SSH auths within {window_minutes} min"
                })
                break  # one incident per IP is enough for starter
    return incidents

def detect_web_bruteforce_and_scanning(df, fail_statuses={401,403}, fail_threshold=20, scan_path_threshold=30, window_minutes=10):
    incidents = []
    # Web failed status-based bruteforce
    df_web = df[df['service']=='apache'].copy()
    if df_web.empty:
        return incidents
    df_web['minute'] = df_web['timestamp'].dt.floor('T')
    # Bruteforce by status codes
    fails = df_web[df_web['status'].isin(fail_statuses)]
    for ip, g in fails.groupby('ip'):
        # sliding window similar approach
        times = g['timestamp'].sort_values().tolist()
        start = 0
        for i, t in enumerate(times):
            while times[start] < t - timedelta(minutes=window_minutes):
                start += 1
                if start > i:
                    break
            cnt = i - start + 1
            if cnt >= fail_threshold:
                incidents.append({
                    "type": "web_bruteforce",
                    "ip": ip,
                    "start": times[start].isoformat(),
                    "end": t.isoformat(),
                    "count": cnt,
                    "desc": f"{cnt} failed HTTP statuses ({sorted(list(fail_statuses))}) in {window_minutes} min"
                })
                break
    # Scanning: many distinct URLs or a large fraction of 404s
    for ip, g in df_web.groupby('ip'):
        distinct_paths = g['url'].nunique()
        total = len(g)
        n404 = (g['status']==404).sum()
        if distinct_paths >= scan_path_threshold or (total>=20 and n404/total > 0.5):
            incidents.append({
                "type": "web_scanning",
                "ip": ip,
                "first": g['timestamp'].min().isoformat(),
                "last": g['timestamp'].max().isoformat(),
                "distinct_paths": distinct_paths,
                "total_hits": total,
                "n404": int(n404),
                "desc": f"Scanning-like activity: {distinct_paths} distinct paths, {n404}/{total} 404s"
            })
    return incidents

def detect_dos(df, requests_threshold=500, window_minutes=1):
    incidents = []
    if df.empty:
        return incidents
    # resample per IP per minute
    df['minute'] = df['timestamp'].dt.floor('T')
    cnts = df.groupby(['ip','minute']).size().reset_index(name='count')
    for ip, g in cnts.groupby('ip'):
        high = g[g['count'] >= requests_threshold]
        if not high.empty:
            for _, row in high.iterrows():
                incidents.append({
                    "type": "dos",
                    "ip": ip,
                    "minute": row['minute'].isoformat(),
                    "count": int(row['count']),
                    "desc": f"{int(row['count'])} requests in 1 minute"
                })
    return incidents

# ---- Reporting & Visualization ----

def export_incidents(incidents, outdir):
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    if not incidents:
        print("No incidents found.")
        return
    csv_path = os.path.join(outdir, 'incidents.csv')
    json_path = os.path.join(outdir, 'incidents.json')
    with open(json_path, 'w') as f:
        json.dump(incidents, f, indent=2)
    # normalize to flat table for CSV
    df = pd.json_normalize(incidents)
    df.to_csv(csv_path, index=False)
    # also a simple alerts log
    with open(os.path.join(outdir, 'alerts.log'), 'w') as f:
        for inc in incidents:
            f.write(f"[{inc.get('type')}] {inc.get('ip')} - {inc.get('desc')}\n")
    print(f"Exported incidents: {csv_path}, {json_path}, alerts.log")

def plot_basic_visuals(df, outdir, top_n=10):
    if df.empty:
        return
    if not os.path.exists(outdir):
        os.makedirs(outdir)
    # Top IPs by count
    top_ips = df['ip'].value_counts().head(top_n)
    plt.figure()
    top_ips.plot(kind='bar')
    plt.title('Top IPs by request count')
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, 'top_ips.png'))
    plt.close()

    # Requests per minute timeseries (global)
    df_min = df.set_index('timestamp').resample('T').size()
    plt.figure()
    df_min.plot()
    plt.title('Requests per minute (all services)')
    plt.tight_layout()
    plt.savefig(os.path.join(outdir, 'requests_per_minute.png'))
    plt.close()

    print(f"Saved plots in {outdir}")

# ---- Main CLI ----

def main():
    parser = argparse.ArgumentParser(description="Log File Analyzer for Intrusion Detection")
    parser.add_argument("--apache", help="Path to Apache access.log")
    parser.add_argument("--ssh", help="Path to SSH auth.log")
    parser.add_argument("--blacklist", help="Path to blacklist file (one IP/CIDR per line)")
    parser.add_argument("--outdir", default="output", help="Output directory")
    parser.add_argument("--ssh-fails-threshold", type=int, default=10)
    parser.add_argument("--ssh-window-minutes", type=int, default=10)
    parser.add_argument("--web-fail-threshold", type=int, default=20)
    parser.add_argument("--web-window-minutes", type=int, default=10)
    parser.add_argument("--dos-threshold", type=int, default=500)
    parser.add_argument("--dos-window-minutes", type=int, default=1)
    parser.add_argument("--no-plots", action="store_true", help="Skip plot generation")
    args = parser.parse_args()

    print("Parsing logs...")
    df = parse_logs(apache_path=args.apache, ssh_path=args.ssh)
    if df.empty:
        print("No parseable log entries found. Exiting.")
        return

    nets = load_blacklist(args.blacklist)
    incidents = []

    # Run detectors
    print("Detecting SSH brute-force...")
    inc_ssh = detect_ssh_bruteforce(df, fails_threshold=args.ssh_fails_threshold, window_minutes=args.ssh_window_minutes)
    incidents.extend(inc_ssh)

    print("Detecting web brute-force and scanning...")
    inc_web = detect_web_bruteforce_and_scanning(df, fail_threshold=args.web_fail_threshold, window_minutes=args.web_window_minutes)
    incidents.extend(inc_web)

    print("Detecting DoS/high-rate IPs...")
    inc_dos = detect_dos(df, requests_threshold=args.dos_threshold, window_minutes=args.dos_window_minutes)
    incidents.extend(inc_dos)

    # Cross-reference with blacklist
    for inc in incidents:
        ip = inc.get('ip')
        inc['blacklisted'] = ip_in_blacklist(ip, nets)

    # Save and visualize
    export_incidents(incidents, args.outdir)
    if not args.no_plots:
        plot_basic_visuals(df, args.outdir)

    print("Done.")

if __name__ == "__main__":
    main()
```

## 🔎 Log File Analyzer for Intrusion Detection

### 🧐 Overview This tool parses Apache access logs and OpenSSH auth logs, detects suspicious activity (SSH/web brute-force, scanning, DoS/high-rate), cross-references IPs with a user-provided blacklist, and exports incident reports and basic visualizations. 
### ✔ Requirements - Python 3.8+ - See `requirements.txt` for Python packages. 
### 🔧 Installation 
**1. Create a virtualenv:**
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

**2.Place your logs:**
- Apache access log (Combined format) e.g. ```access.log```
- SSH auth log e.g. ```/var/log/auth.log``` (you may need root access to read)

**3.Optional:** 

```blacklist.txt``` — one IP or CIDR per line
1.2.3.4
5.6.0.0/16

***Usage***
```bash
python log_analyzer.py --apache /path/to/access.log --ssh /path/to/auth.log --blacklist blacklist.txt --outdir output
```

### ꄗ Key CLI options:

- ```--ssh-fails-threshold``` (default 10)
- ```--ssh-window-minutes``` (default 10)
- ```--web-fail-threshold``` (default 20)
- ```--dos-threshold``` (default 500)
- ```--no-plots``` skip generating images


### ╰┈➤ Outputs (in ```--outdir```, default ```output```)

- ```incidents.csv``` — table of detected incidents
- ```incidents.json``` — structured incidents
- ```alerts.log``` — quick human-readable alerts
- ```top_ips.png```, ```requests_per_minute.png``` — visualizations

### 🕵🏻 Detection logic (summary

- SSH brute-force: X failed auths from same IP within Y minutes.
- Web brute-force: Too many HTTP 401/403 from an IP within window.
- Scanning: Many distinct URLs requested by IP or many 404s.
- DoS: >R requests in a single minute from same IP.

### ➡️ Next steps / Enhancements

- Integrate GeoIP to add country/org context to incidents.
- Query public blocklists (AbuseIPDB, IPVoid) via their APIs to automate blacklist checks.
- Add real-time tail mode that watches logs (like ```tail -F```).
- Store events in SQLite / Elastic / SIEM for long-term analysis.
- Add unit tests and benchmark on big logs (use chunked parsing).

### 📌 Notes & Caveats

- Parsing uses regex; formats must match expected samples.
- For very large logs, consider streaming parsing or tooling like Apache Spark / Dask.
- Tuning thresholds is essential — defaults are conservative starting points.
