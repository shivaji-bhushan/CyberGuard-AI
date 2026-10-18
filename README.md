# CyberGuard AI — Unified Cyber Defense Platform

> **"One AI Brain. Multiple Specialized Defenses."**  
> An AI-powered cyber defense platform that coordinates specialized engines across phishing, digital payments, and network telemetry to detect multi-stage attack chains and execute automated containment policies.

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/)
[![Flask](https://img.shields.io/badge/Framework-Flask-black.svg)](https://flask.palletsprojects.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Status](https://img.shields.io/badge/Defense%20Nodes-3%2F3%20Online-emerald.svg)]()

---

## 🏛️ Platform Architecture

CyberGuard AI departs from isolated, siloed security tools. By orchestrating signals through the **CyberGuard Brain Coordinator**, the platform correlates indicators of compromise (IoCs) across communication channels, financial transaction networks, and socket-level telemetry.

```
                           ┌───────────────────────────┐
                           │    CYBERGUARD AI BRAIN    │
                           │  Cross-Threat Correlation │
                           └─────────────┬─────────────┘
                                         │
                 ┌───────────────────────┼───────────────────────┐
                 │                       │                       │
                 ▼                       ▼                       ▼
        ┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
        │   PhishShield   │     │   UPI Shield    │     │   NetSentinel   │
        │ URL/Text Urgency│     │ VPA / PIN Trap  │     │ C2 / Sockets    │
        └────────┬────────┘     └────────┬────────┘     └────────┬────────┘
                 │                       │                       │
                 └───────────────────────┼───────────────────────┘
                                         │
                                         ▼
                           ┌───────────────────────────┐
                           │   Risk & Policy Engine    │
                           │ 0-100 Score + Policy Rule │
                           │  SAFE | WARN | BLOCK |    │
                           │          ISOLATE          │
                           └───────────────────────────┘
```

---

## 🛡️ Core Defense Engines

### 1. Central CyberGuard Brain (`core/brain.py`)
- Coordinates multi-vector inspection across all specialized engines.
- **Cross-Threat Correlation**: Correlates brand impersonation across SMS lures and UPI handles, links target domains to active DNS tunneling, and detects unified killchains.
- Generates chronological attack sequence flows.
- Synthesizes tactical AI security diagnoses explaining attack mechanisms.

### 2. PhishShield Engine (`core/phish_shield.py`)
- **Shannon Entropy Analysis**: Detects algorithmically generated domain names (DGA).
- **High-Abuse TLD Profiling**: Monitors high-risk extensions (`.xyz`, `.top`, `.tk`, `.icu`, `.buzz`).
- **Brand Typosquatting & Impersonation**: Flags mimicry of major institutions (SBI, HDFC, ICICI, Paytm, etc.).
- **Social Engineering Urgency Lures**: Identifies psychological coercion patterns (electricity disconnection threats, KYC freeze warnings, prize baits).

### 3. UPI Shield Engine (`core/upi_shield.py`)
- **NPCI Handle Validation**: Verifies authorized PSP handles (`@okhdfcbank`, `@okaxis`, `@oksbi`, `@paytm`, `@ybl`).
- **Deceptive VPA Prefixes**: Identifies unauthorized merchant impersonation (`billdesk`, `customercare`, `refund`, `kyc`).
- **Reverse Collect PIN Trap Protection**: Enforces the golden rule of UPI: *"You NEVER enter your UPI PIN to receive money."* Flags fraudulent collect prompts attempting to drain funds.
- **QR Intent Parser**: Analyzes `upi://pay` URI parameters for pre-locked high debits or tampered payees.

### 4. NetSentinel Engine (`core/net_sentinel.py`)
- **Backdoor & Trojan Port Monitoring**: Detects connections to high-risk listening ports (ports 4444 Metasploit, 1337 backdoor, 31337 trojan, 6667 IRC botnet, 9001/9050 Tor).
- **C2 Periodic Beaconing Heartbeat Detector**: Analyzes inter-packet arrival times (jitter standard deviation `< 0.35s` indicates automated command-and-control polling).
- **DNS Tunneling Exfiltration**: Identifies encoded data payloads and high label entropy in DNS queries.

### 5. Risk & Response Policy Engine (`core/risk_engine.py`)
- Computes weighted composite risk (0–100) and applies correlation boosts (+10 to +18 points).
- **Enforced Policy Framework**:
  - `0 – 34`: **`SAFE`** (Allow event; standard logging)
  - `35 – 64`: **`WARN`** (Display advisory alert; prompt secondary MFA)
  - `65 – 84`: **`BLOCK`** (Block outbound request; reject UPI collect request)
  - `85 – 100`: **`ISOLATE`** (Quarantine network interface, terminate sockets, sinkhole domain, blacklist VPA)

---

## ⚡ Attack Scenario Simulations

The platform includes four preloaded real-world attack chains:
1. **Electricity Bill Power-Cut Trap**: Urgent power disconnection SMS &bull; Deceptive billdesk VPA &bull; Port 4444 Metasploit backdoor (`ISOLATE`).
2. **SBI KYC Suspension Scam**: PAN card expiry lure &bull; Typosquatted bank domain &bull; Fake support VPA &bull; Port 1337 backdoor (`ISOLATE`).
3. **Crypto Airdrop QR Trojan**: 1.5 ETH prize claim &bull; Malicious QR code &bull; Reverse PIN collect &bull; DNS tunneling exfiltration (`HIGH`).
4. **Legitimate Corporate Activity**: Routine Google Workspace webmail &bull; Verified coffee payment &bull; Standard HTTPS socket (`SAFE`).

---

## 🚀 Quickstart & Installation

### Prerequisites
- Python 3.10 or higher
- Git

### Installation
```bash
# Clone the repository
git clone https://github.com/shivaji-bhushan/CyberGuard-AI.git
cd CyberGuard-AI

# Install dependencies
pip install -r requirements.txt
```

### Running the Platform
```bash
# Run backend server (Port 5050)
python app.py
```
Or on Windows, simply double-click:
```bat
start_cyberguard.bat
```

Open your browser at: **`http://127.0.0.1:5050`**

---

## 🧪 Automated Test Suite

Run the full integration test suite covering all defense engines, risk calculations, and REST endpoints:
```bash
python test_cyberguard.py
```
Output:
```
.........
----------------------------------------------------------------------
Ran 9 tests in 0.088s

OK
```

---

## 📡 REST API Reference

| Endpoint | Method | Description |
|---|---|---|
| `GET /api/status` | `GET` | Platform health and active defense engines |
| `POST /api/scan/unified` | `POST` | Multi-vector evaluation with cross-threat correlation |
| `POST /api/scan/phish` | `POST` | Specialist URL & text urgency analysis |
| `POST /api/scan/upi` | `POST` | Specialist UPI VPA & QR analysis |
| `POST /api/scan/network` | `POST` | Specialist socket & C2 beacon analysis |
| `POST /api/simulate` | `POST` | Preloaded attack chain scenario runner |
| `GET /api/incidents` | `GET` | Audit log stream of recent security assessments |

---

## 📄 License
MIT License &copy; 2026 CyberGuard AI. Built with precision and care.
