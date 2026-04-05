# 🔍 Home Lab SIEM — Splunk Detection & Monitoring

![Project Status](https://img.shields.io/badge/status-in%20progress-yellow)
![Difficulty](https://img.shields.io/badge/difficulty-beginner-green)
![Tools](https://img.shields.io/badge/SIEM-Splunk%20Free-black)
![Framework](https://img.shields.io/badge/framework-MITRE%20ATT%26CK-red)

> A home lab project simulating a basic Security Operations Centre (SOC) environment using Splunk Free to ingest, analyse, and visualise Windows and Linux log data for threat detection.

---

## 📋 Table of Contents

- [Overview](#overview)
- [Objectives](#objectives)
- [Lab Environment](#lab-environment)
- [Setup & Installation](#setup--installation)
- [Log Sources](#log-sources)
- [Dashboards & Detections](#dashboards--detections)
- [Findings & Alerts](#findings--alerts)
- [MITRE ATT&CK Coverage](#mitre-attck-coverage)
- [Lessons Learned](#lessons-learned)
- [References](#references)

---

## 📌 Overview

This project sets up a functional SIEM environment in a home lab using **Splunk Free (500MB/day)**. The goal is to simulate real-world SOC analyst tasks: ingesting logs from multiple sources, identifying suspicious activity, building detection dashboards, and documenting findings in analyst-style reports.

| Field         | Details                              |
|---------------|--------------------------------------|
| Difficulty    | Beginner                             |
| Duration      | [e.g. 2 weeks]                       |
| SIEM Platform | Splunk Free / Splunk Enterprise Trial|
| Environment   | VirtualBox / VMware                  |
| OS Targets    | Windows 10, Ubuntu 22.04             |

---

## 🎯 Objectives

- [x] Deploy Splunk Free on a local VM
- [x] Configure log forwarding from Windows and Linux hosts
- [x] Build dashboards to visualise authentication, process, and network events
- [ ] Write at least 5 detection rules (SPL queries) for common attack techniques
- [ ] Generate a simulated alert and document an IR timeline
- [ ] Map detections to MITRE ATT&CK techniques

---

## 🖥️ Lab Environment

```
┌──────────────────────────────────────────────────────────┐
│                     Home Lab Topology                    │
│                                                          │
│  ┌─────────────────┐        ┌─────────────────┐         │
│  │  Windows 10 VM  │        │  Ubuntu 22.04   │         │
│  │  Splunk UF      │        │  Splunk UF      │         │
│  │  Sysmon         │        │  syslog         │         │
│  └────────┬────────┘        └────────┬────────┘         │
│           │                          │                   │
│           └──────────┬───────────────┘                   │
│                      ▼                                   │
│          ┌───────────────────────┐                       │
│          │   Splunk Indexer/SH   │                       │
│          │   Ubuntu 22.04 VM     │                       │
│          │   192.168.x.x:8000   │                       │
│          └───────────────────────┘                       │
└──────────────────────────────────────────────────────────┘
```

### VM Specs

| VM              | OS             | RAM   | Role                  |
|-----------------|----------------|-------|-----------------------|
| splunk-server   | Ubuntu 22.04   | 4 GB  | Splunk indexer + UI   |
| windows-target  | Windows 10     | 2 GB  | Log source (Sysmon)   |
| linux-target    | Ubuntu 22.04   | 2 GB  | Log source (syslog)   |

---

## ⚙️ Setup & Installation

### 1. Install Splunk Free

```bash
# Download Splunk .deb package from splunk.com (requires free account)
wget -O splunk.deb 'https://download.splunk.com/...'
sudo dpkg -i splunk.deb
sudo /opt/splunk/bin/splunk start --accept-license
```

Access the Splunk web UI at: `http://localhost:8000`

### 2. Install Splunk Universal Forwarder (Windows)

```powershell
# Run as Administrator
msiexec.exe /i splunkforwarder.msi RECEIVING_INDEXER="192.168.x.x:9997" /quiet
```

### 3. Install Sysmon (Windows)

```powershell
# Download Sysmon from Microsoft Sysinternals
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```

> Recommended config: [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

### 4. Configure Inputs on the Forwarder

```ini
# inputs.conf — Windows Event Logs
[WinEventLog://Security]
index = wineventlog
disabled = 0

[WinEventLog://System]
index = wineventlog
disabled = 0

[monitor://C:\Windows\Sysmon\Operational]
index = sysmon
disabled = 0
```

---

## 📂 Log Sources

| Source                    | Type             | Index         | Key Event IDs / Fields          |
|---------------------------|------------------|---------------|---------------------------------|
| Windows Security Log      | Authentication   | `wineventlog` | 4624, 4625, 4648, 4720          |
| Sysmon                    | Process/Network  | `sysmon`      | EventCode 1, 3, 7, 11, 22      |
| Ubuntu syslog             | System activity  | `linux_logs`  | auth.log, syslog                |
| [Add your source here]    | —                | —             | —                               |

---

## 📊 Dashboards & Detections

### Dashboard 1 — Authentication Overview

Tracks successful and failed logins across all hosts.

**SPL Query — Failed Login Attempts:**
```spl
index=wineventlog EventCode=4625
| stats count by host, Account_Name, Source_Network_Address
| sort - count
| where count > 5
```

**Screenshot:** `screenshots/auth-dashboard.png`

---

### Dashboard 2 — Process Creation Monitor

Detects suspicious process executions using Sysmon Event ID 1.

**SPL Query — Suspicious PowerShell Execution:**
```spl
index=sysmon EventCode=1 Image="*powershell.exe*"
| table _time, host, User, CommandLine, ParentImage
| sort - _time
```

**Screenshot:** `screenshots/process-dashboard.png`

---

### Dashboard 3 — Network Connections

Maps outbound connections to detect potential C2 or data exfiltration.

**SPL Query — Outbound Connections by Destination:**
```spl
index=sysmon EventCode=3
| stats count by DestinationIp, DestinationPort, Image
| sort - count
```

**Screenshot:** `screenshots/network-dashboard.png`

---

### Detection Rules Summary

| # | Detection Name                  | SPL EventCode | MITRE Technique       | Severity |
|---|---------------------------------|---------------|-----------------------|----------|
| 1 | Brute force login attempt       | 4625          | T1110 – Brute Force   | High     |
| 2 | New local admin created         | 4720 + 4732   | T1136 – Create Account| High     |
| 3 | PowerShell encoded command      | Sysmon 1      | T1059.001             | Medium   |
| 4 | Outbound connection on port 443 | Sysmon 3      | T1071 – App Layer C2  | Low      |
| 5 | [Add your detection here]       | —             | —                     | —        |

---

## 🚨 Findings & Alerts

### Alert 1 — [Alert Name, e.g. Repeated Failed Logins from Internal Host]

| Field       | Details                                      |
|-------------|----------------------------------------------|
| Date        | [DD/MM/YYYY HH:MM]                           |
| Severity    | High                                         |
| Source Host | [e.g. DESKTOP-ABC123]                        |
| Account     | [e.g. Administrator]                         |
| Description | [Brief description of what was observed]     |
| Action Taken| [e.g. Investigated — confirmed test activity]|
| MITRE TTP   | T1110 — Brute Force                          |

**Evidence:**
```
[Paste relevant log snippet or SPL output here]
```

---

## 🗺️ MITRE ATT&CK Coverage

| Tactic              | Technique                        | ID        | Detected? |
|---------------------|----------------------------------|-----------|-----------|
| Credential Access   | Brute Force                      | T1110     | ✅        |
| Persistence         | Create Account                   | T1136     | ✅        |
| Execution           | PowerShell                       | T1059.001 | ✅        |
| Command & Control   | Application Layer Protocol       | T1071     | ⚠️ Partial|
| Lateral Movement    | [Add technique]                  | —         | ❌        |

> ✅ Detected  ⚠️ Partial coverage  ❌ Not yet implemented

---

## 📝 Lessons Learned

### What went well
- [e.g. Sysmon provided rich process telemetry that was easy to query in Splunk]
- [e.g. Building SPL queries from scratch improved my understanding of log structure]

### Challenges faced
- [e.g. The 500MB/day Splunk limit was reached quickly once Sysmon was enabled — had to tune verbosity]
- [e.g. Differentiating noisy legitimate activity from true anomalies required careful baselining]

### What I would do differently
- [e.g. Set up index lifecycle policies earlier to manage storage]
- [e.g. Use a pre-built Sysmon config rather than starting from scratch]

---

## 📁 Repository Structure

```
📦 home-lab-siem
 ┣ 📂 configs
 ┃ ┣ 📄 inputs.conf
 ┃ ┣ 📄 sysmonconfig.xml
 ┃ ┗ 📄 outputs.conf
 ┣ 📂 dashboards
 ┃ ┣ 📄 auth-overview.xml
 ┃ ┣ 📄 process-monitor.xml
 ┃ ┗ 📄 network-connections.xml
 ┣ 📂 detections
 ┃ ┗ 📄 detection-rules.spl
 ┣ 📂 screenshots
 ┣ 📂 reports
 ┃ ┗ 📄 incident-report-01.md
 ┗ 📄 README.md
```

---

## 📚 References

- [Splunk Free Download](https://www.splunk.com/en_us/download/splunk-enterprise.html)
- [Sysmon — Microsoft Sysinternals](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)
- [MITRE ATT&CK Framework](https://attack.mitre.org/)
- [Splunk SPL Reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/WhatsInThisManual)
- [Blue Team Labs Online](https://blueteamlabs.online/)

---

*Last updated: [Month Year] · Author: [Your Name]*
