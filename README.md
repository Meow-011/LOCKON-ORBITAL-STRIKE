# LOCKON: THE ORBITAL STRIKE 🛰️💥

![Version](https://img.shields.io/badge/Version-2.0-cyan) ![Status](https://img.shields.io/badge/Status-Active-green) ![License](https://img.shields.io/badge/License-MIT-orange)

**The Ultimate Advanced Web Application Security Scanner & Exploitation Framework.**

LOCKON is a next-generation security tool designed for Red Teamers and Bounty Hunters. It combines automated vulnerability scanning with "God Mode" active exploitation capabilities, targeting Web Apps, APIs, Cloud Infrastructure, and Corporate Networks.

---

## � Screenshots

> *Add your dashboard screenshots here*
>
> ![Dashboard Demo](assets/images/dashboard_placeholder.png)

---

## �🚀 Key Features

### 🔱 GOD MODE (Active Exploitation)
- **42+ RCE Arsenal**: Fully automated Remote Code Execution for major CVEs (Metabase, PaperCut, Solr, WebLogic, Struts, Log4Shell, etc.).
- **Infrastructure Killers**: Takeover Big Data systems (Hadoop YARN, RocketMQ, HugeGraph) and Monitor tools (Cacti, Zabbix).
- **Auto-Shell**: Automatically uploads Web Shells and establishes Reverse Shells (C2) upon successful exploit.

### 🕸️ Advanced Scanning
- **Deep Recon**: Subdomain enumeration (Subfinder), Tech Detection (Wappalyzer), and WAF Detection.
- **Injection Engine**: SQLi, XSS (DOM/Reflected), NoSQL, LDAP, SSTI, and Command Injection.
- **API Warfare**: GraphQL Introspection, JWT Attack, and Mass Assignment scanning.

### 🛡️ Active Stealth
- **WAF Evasion**: Jitter/Delay randomization and Header rotation.
- **Cortex AI**: Adaptive scanning patterns to avoid detection.

### 🔮 Visual Command Center
- **Orbital Attack Graph**: Visualize the Kill Chain from Recon to Action.
- **Loot Gallery**: Browse captured screenshots, secrets, and files directly in the UI.

---

## 🧠 System Architecture

```mermaid
graph TD
    A[User / UI] -->|Config| B(CORE: Scanner Engine)
    B -->|Stealth Mode| C{Cortex AI}
    C -->|Smart Headers| D[Recon Modules]
    C -->|Mutation| E[Active Exploits]
    D & E -->|Findings| F(Project DOMINO)
    F -->|Critical Found| G[Auto-Exploit / God Mode]
    G -->|Success| H((C2 REVERSE SHELL))
```

---

## 🎯 Supported Vulnerabilities (Active Arsenal)

| Category | Target System | CVE ID | Impact |
| :--- | :--- | :--- | :--- |
| **Enterprise** | Metabase BI | CVE-2023-38646 | **Pre-Auth RCE** |
| **Enterprise** | PaperCut MF/NG | CVE-2023-27350 | **Bypass & RCE** |
| **Enterprise** | SaltStack | CVE-2020-11651 | **Master Takeover** |
| **Big Data** | Apache HugeGraph | CVE-2024-27348 | **Gremlin RCE** |
| **Big Data** | Hadoop YARN | - | **Unauth RCE** |
| **Infrastructure** | Ivanti Connect Secure | CVE-2024-21887 | **Cmd Injection** |
| **Infrastructure** | Apache RocketMQ | CVE-2023-33246 | **Broker RCE** |
| **Web App** | Apache OFBiz | CVE-2024-38856 | **Pre-Auth RCE** |
| **Web App** | GeoServer | CVE-2024-36401 | **OGC RCE** |
| **Legacy** | Apache Struts 2 | CVE-2017-5638 | **Remote Code Exec** |
| **Legacy** | WebLogic Server | CVE-2020-14882 | **Console RCE** |
| **Legacy** | Log4j (Log4Shell) | CVE-2021-44228 | **JNDI Injection** |

*(And 30+ more modules covering SQLi, LFI, SSRF, IDOR, etc.)*

---

## 🛠️ Installation

1. **Clone the Repository**
   ```bash
   git clone https://github.com/Meow-011/LOCKON-ORBITAL-STRIKE.git
   cd LOCKON-ORBITAL-STRIKE
   ```

2. **Install Dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Verify Setup**
   - Run the tool and check the "SYSTEM" tab to verify external tools (Nuclei, Subfinder, Playwright) and Python libraries.

---

## 💻 Usage

Run the main application:
```bash
python main.py
```

1. Enter the **Target URL** in the Mission Tab.
2. Select your **Attack Profile** (Full Scan, SQLi Only, etc.).
3. Toggle **Active Stealth Mode** if WAF evasion is needed.
4. Click **INITIALIZE ATTACK VECTOR**.

---

## ⚠️ Disclaimer

**This tool is for EDUCATIONAL PURPOSES and AUTHORIZED PENETRATION TESTING ONLY.**
Do not use this tool on systems you do not own or do not have explicit permission to test. The authors are not responsible for any misuse or damage caused by this tool.

---

*Powered by LOCKON Security Research Team.*
