# 🛡️ Cyber Threat Intelligence (CTI) Dashboard

[![Live Demo](https://img.shields.io/badge/🔴_Live-Demo-red?style=for-the-badge)](https://cti-dashboard-chandanswe.streamlit.app)
[![Python](https://img.shields.io/badge/Python-3.11-blue?style=for-the-badge&logo=python)](https://python.org)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.63-red?style=for-the-badge&logo=streamlit)](https://streamlit.io)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](LICENSE)

> Real-time threat intelligence dashboard aggregating IOCs from AlienVault OTX, AbuseIPDB, and VirusTotal — with automatic MITRE ATT&CK framework mapping.

---

## 🚀 Live Demo

**[→ View Live Dashboard](https://cti-dashboard-chandanswe.streamlit.app)**

---

## ✨ Features

| Feature | Description |
|---------|-------------|
| 🔴 **Live IOC Feed** | Ingests real-time Indicators of Compromise from AlienVault OTX |
| 🔍 **IP Reputation Lookup** | Live IP analysis with abuse scoring, geolocation, ISP, Tor detection |
| 🗺️ **MITRE ATT&CK Mapping** | Auto-maps every IOC to ATT&CK tactics (T1566, T1071, T1486...) |
| 📊 **Interactive Charts** | MITRE tactic breakdown, IOC type distribution, country heatmap |
| 🎯 **SOC Analyst Action Plan** | Risk-based recommendations (Block/Monitor/Allow) |
| 📋 **IOC Explorer** | Filter by type, country, tactic, threat actor — export CSV/JSON |
| ⚡ **Auto-Refresh** | Dashboard refreshes every 5 minutes from live feeds |

---

## 🛠️ Tech Stack





### Home Dashboard
> 445+ live IOCs · 8 MITRE tactics · 7 countries tracked

### IP Reputation Lookup
> Live gauge chart · Tor detection · SOC analyst action plan

### IOC Explorer
> Filterable table · CSV/JSON export · Country & tactic charts

---

## ⚙️ Local Setup

```bash
# 1. Clone the repository
git clone https://github.com/chandanswenepal-code/cti-dashboard.git
cd cti-dashboard

# 2. Create virtual environment
python -m venv venv
venv\Scripts\activate  # Windows
source venv/bin/activate  # Mac/Linux

# 3. Install dependencies
pip install -r requirements.txt

# 4. Add your API keys
cp .env.example .env
# Edit .env with your keys

# 5. Populate database
python scheduler.py

# 6. Run dashboard
streamlit run app/dashboard/home.py
```

---

## 🔑 API Keys Required

| API | Free Tier | Link |
|-----|-----------|------|
| AlienVault OTX | ✅ Free | [otx.alienvault.com](https://otx.alienvault.com) |
| AbuseIPDB | ✅ 1000 req/day | [abuseipdb.com](https://abuseipdb.com) |
| VirusTotal | ✅ 500 req/day | [virustotal.com](https://virustotal.com) |

---

## 📁 Project Structure

cti-dashboard/
├── app/
│ ├── api/
│ │ ├── otx_client.py # AlienVault OTX API
│ │ ├── abuseipdb_client.py # AbuseIPDB API
│ │ └── mitre_mapper.py # MITRE ATT&CK mapping
│ ├── data/
│ │ └── database.py # SQLAlchemy models
│ └── dashboard/
│ ├── home.py # Main dashboard
│ └── pages/
│ ├── ip_lookup.py # IP reputation tool
│ └── ioc_explorer.py # IOC search & filter
├── scheduler.py # Data pipeline
├── requirements.txt
└── README.md


---

## 🎯 MITRE ATT&CK Coverage

| Tactic | Technique | Example IOC Type |
|--------|-----------|-----------------|
| Initial Access | T1566 Phishing | Malicious domains |
| Command & Control | T1071 | C2 server IPs |
| Exfiltration | T1041 | Data exfil URLs |
| Impact | T1486 Ransomware | Ransomware C2 |
| Execution | T1059 | Malware hashes |
| Credential Access | T1110 | Brute force IPs |

---

## 👤 Author

**Chandan Yadav**  
SOC Analyst | Cybersecurity Enthusiast  
🏆 Top 6% Globally — HackTheBox CTF

linkedin: https://www.linkedin.com/in/chandan-yadavswe/


---

## 📄 License

MIT License — feel free to use and modify for your own projects.
