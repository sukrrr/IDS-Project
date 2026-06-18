#  Network Intrusion Detection System (IDS)

A lightweight Network Intrusion Detection System built in Python that monitors network traffic in real-time and detects suspicious activities including port scans, SYN floods, and DNS anomalies.

##  Features

- **Real-time Packet Capture** - Sniffs network traffic using Scapy
- **Traffic Analysis** - Analyzes packet flows and connection patterns
- **Signature-Based Detection** - Detects known attack patterns
- **Anomaly Detection** - Identifies unusual traffic behavior
- **Alert System** - Real-time alerts with severity levels (Critical, High, Medium)
- **Logging** - All alerts are logged for post-analysis
- **Attack Detection**:
  -  Port Scanning
  -  SYN Flood Attacks
  -  DNS Tunneling/Suspicious DNS Activity
  -  Brute Force Attempts

##  Technologies Used

- **Python 3.8+** - Core programming language
- **Scapy** - Packet manipulation and capture
- **Scikit-learn** - Machine learning for anomaly detection
- **Pandas** - Data analysis
- **Matplotlib** - Visualization (optional)

##  Installation

### Prerequisites

- Python 3.8 or higher
- Npcap (Windows) or libpcap (Linux)
- Administrator/root privileges

### Clone the Repository

```
git clone https://github.com/sukri/IDS-Project.git
cd IDS-Project
```

### Install Dependencies

```
pip install -r requirements.txt
```


### Windows Users - Install Npcap

1. Download Npcap from: https://npcap.com/
2. During installation, **CHECK** "WinPcap API-compatible Mode"
3. Run Command Prompt as Administrator

##  Usage

### Start the IDS

**On Windows (Wi-Fi):**

```
python src/main.py -i "Wi-Fi"
```


**On Windows (Ethernet):**

```
python src/main.py -i Ethernet
```


### Check Your Network Interface

**Windows:**
```
ipconfig
```

##  Testing the IDS

### From Kali Linux (Attacker Machine)

**1. Port Scan Detection:**

```
nmap -sS -p 1-1000 TARGET_IP
```


**2. SYN Flood Detection:**

```
sudo hping3 -S -p 80 --flood TARGET_IP
```


**3. DNS Anomaly Detection:**

```
for i in {1..1000}; do nslookup test$i.evil.com; done
```

### From Windows (Generate Traffic)

```
for /L %i in (1,1,50) do nslookup test%i.google.com
```

##  Sample Alert Output
```
==================================================
🚨 ALERT: Port Scan
Severity: HIGH
Source: 10.101.111.166
Confidence: 100%
Details: Packet: TCP 53->59331
==================================================
```

##  Detection Thresholds

| Attack Type | Threshold | Time Window |
|-------------|-----------|-------------|
| Port Scan | 20 unique ports | 60 seconds |
| SYN Flood | 100 packets | 10 seconds |
| DNS Tunnel | 50 queries | 10 seconds |

##  Customization

You can adjust detection thresholds in `src/detection_engine.py`:
self.thresholds = {
'port_scan': 20, # Increase for less sensitivity
'syn_flood': 100, # Decrease for more sensitivity
'dns_tunnel': 50,
'brute_force': 30
}


## 📝 Logs

Alerts are stored in:
- `logs/alerts.log` - Plain text format
- `logs/alerts.jsonl` - JSON format for parsing

##  Learning Outcomes

Through this project, I learned:

- Network packet analysis using Scapy
- TCP/IP protocol fundamentals
- Signature-based and anomaly-based detection
- Real-time monitoring and alerting
- Python threading for concurrent processing
- Security monitoring best practices

##  Future Improvements

- Machine learning for advanced anomaly detection
- Web dashboard with real-time visualization
- Email/SMS alerts
- Integration with Snort/Suricata rules
- Multi-threaded packet processing
- Report generation

##  License

This project is licensed under the MIT License.




