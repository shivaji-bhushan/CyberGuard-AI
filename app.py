"""
CyberGuard AI — Unified Cyber Defense Platform
Backend Flask Service (Port 5050)
"One AI Brain. Multiple Specialized Defenses."
"""

import os
import sys
import time
from flask import Flask, render_template, request, jsonify

# Ensure core package is resolvable
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.brain import brain_instance
from core.phish_shield import analyze_phishing_event
from core.upi_shield import analyze_upi_event
from core.net_sentinel import analyze_network_event

app = Flask(__name__, template_folder="templates", static_folder="static")

# In-memory incident log store (keeps last 50 incidents)
INCIDENT_LOGS = []


def _record_incident(result: dict):
    entry = {
        "incident_id": result.get("incident_id"),
        "timestamp": result.get("timestamp"),
        "title": result.get("incident_title", "Security Assessment"),
        "composite_score": result.get("risk", {}).get("composite_score", 0),
        "threat_level": result.get("risk", {}).get("threat_level", "LOW"),
        "decision": result.get("risk", {}).get("decision", "SAFE"),
        "correlations_count": len(result.get("correlations", [])),
        "modules_active": list(result.get("modules", {}).keys())
    }
    INCIDENT_LOGS.insert(0, entry)
    if len(INCIDENT_LOGS) > 50:
        INCIDENT_LOGS.pop()


# Preloaded Simulation Scenarios
SIMULATION_SCENARIOS = {
    "electricity_scam": {
        "title": "Electricity Bill Urgent Cutoff Scam",
        "description": "Multi-vector attack targeting urgent utility payment with reverse PIN trap and RAT backdoor.",
        "phish": {
            "url": "http://power-bill-update.xyz/pay-online",
            "text": "Dear customer your electricity power will be disconnected tonight 9:30 PM due to unpaid bill. Call 9876543210 or pay immediately at http://power-bill-update.xyz"
        },
        "upi": {
            "vpa": "mahadiscom.billdesk@paytm",
            "amount": 1480.0,
            "context": "URGENT: Enter your UPI PIN to verify transaction and receive electricity subsidy refund",
            "qr_payload": "upi://pay?pa=mahadiscom.billdesk@paytm&pn=MahaDiscom&am=1480.00&cu=INR"
        },
        "network": {
            "ip": "185.220.101.5",
            "port": 4444,
            "protocol": "TCP",
            "beacon_intervals": [5.01, 4.99, 5.02, 5.00, 4.98, 5.01],
            "dns_query": "c2.power-bill-update.xyz"
        }
    },
    "bank_kyc_trap": {
        "title": "SBI Account Suspension & KYC Fraud Trap",
        "description": "Brand impersonation across phishing landing page, fake official VPA, and C2 exfiltration.",
        "phish": {
            "url": "http://sbi-kyc-verify.top/netbanking-login",
            "text": "URGENT: Your SBI NetBanking account is BLOCKED due to expired PAN KYC. Update immediately to prevent permanent deactivation: http://sbi-kyc-verify.top"
        },
        "upi": {
            "vpa": "sbi.fraudulent.collect@okaxis",
            "amount": 500.0,
            "context": "Enter your 6-digit UPI PIN to claim ₹500 KYC verification cash bonus",
            "qr_payload": "upi://pay?pa=sbi.fraudulent.collect@okaxis&pn=SBI_KYC_Refund&am=500.00&cu=INR"
        },
        "network": {
            "ip": "45.142.122.99",
            "port": 1337,
            "protocol": "TCP",
            "beacon_intervals": [10.02, 9.98, 10.01, 10.00, 9.99],
            "dns_query": "tunnel.sbi-kyc-verify.top"
        }
    },
    "crypto_drain": {
        "title": "Crypto Airdrop QR Trojan & DNS Exfiltration",
        "description": "High-value bait lure with DNS tunneling payload and reverse collect drain.",
        "phish": {
            "url": "http://binance-airdrop-claim.live/connect-wallet",
            "text": "CONGRATULATIONS: You won 1.50 ETH ($4,200). Claim within 10 minutes at http://binance-airdrop-claim.live or forfeits."
        },
        "upi": {
            "vpa": "crypto.liquidity.pool@ybl",
            "amount": 25000.0,
            "context": "Scan QR & enter secret UPI PIN to release token liquidity into your bank account",
            "qr_payload": "upi://pay?pa=crypto.liquidity.pool@ybl&pn=BinancePool&am=25000.00&cu=INR"
        },
        "network": {
            "ip": "193.36.119.12",
            "port": 31337,
            "protocol": "UDP",
            "beacon_intervals": [3.01, 2.99, 3.00, 3.02, 2.98],
            "dns_query": "7a8b9c1d2e3f405162738495a6b7c8d9e0f1.exfil.darknet.cc"
        }
    },
    "safe_baseline": {
        "title": "Legitimate Enterprise Workday Session (Safe Baseline)",
        "description": "Standard corporate web mail, verified merchant UPI coffee payment, and standard TLS web socket.",
        "phish": {
            "url": "https://mail.google.com/mail/u/0/#inbox",
            "text": "Hi Shiva, the project meeting is confirmed for 3:00 PM in Conference Room B."
        },
        "upi": {
            "vpa": "starbucks.coffee@icici",
            "amount": 340.0,
            "context": "Payment for Cafe Latte and Croissant",
            "qr_payload": "upi://pay?pa=starbucks.coffee@icici&pn=Starbucks&am=340.00&cu=INR"
        },
        "network": {
            "ip": "142.250.190.46",
            "port": 443,
            "protocol": "TCP",
            "beacon_intervals": [1.2, 8.4, 0.4, 15.6, 3.1],
            "dns_query": "google.com"
        }
    }
}


@app.route("/")
def index():
    """Renders the dark cyber defense command center."""
    return render_template("index.html")


@app.route("/api/status", methods=["GET"])
def system_status():
    """Returns platform diagnostic health status."""
    return jsonify({
        "status": "ONLINE",
        "platform": "CyberGuard AI Unified Defense Platform",
        "brain_version": brain_instance.version,
        "active_engines": brain_instance.subsystems,
        "incident_count": len(INCIDENT_LOGS),
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
    })


@app.route("/api/scan/phish", methods=["POST"])
def scan_phish():
    """Direct PhishShield analysis endpoint."""
    data = request.get_json() or {}
    url = data.get("url", "").strip()
    text = data.get("text", "").strip()
    result = analyze_phishing_event(url=url, text=text)
    return jsonify(result)


@app.route("/api/scan/upi", methods=["POST"])
def scan_upi():
    """Direct UPI Shield analysis endpoint."""
    data = request.get_json() or {}
    vpa = data.get("vpa", "").strip()
    amount = float(data.get("amount", 0.0) or 0.0)
    context_text = data.get("context", "").strip()
    qr_payload = data.get("qr_payload", "").strip()
    result = analyze_upi_event(vpa=vpa, amount=amount, context_text=context_text, qr_payload=qr_payload)
    return jsonify(result)


@app.route("/api/scan/network", methods=["POST"])
def scan_network():
    """Direct NetSentinel analysis endpoint."""
    data = request.get_json() or {}
    ip = data.get("ip", "").strip()
    port = int(data.get("port", 0) or 0)
    protocol = data.get("protocol", "TCP")
    beacon_raw = data.get("beacon_intervals", [])
    if isinstance(beacon_raw, str):
        beacon_intervals = [float(x.strip()) for x in beacon_raw.split(",") if x.strip()]
    else:
        beacon_intervals = [float(x) for x in beacon_raw]
    dns_query = data.get("dns_query", "").strip()

    result = analyze_network_event(
        ip=ip,
        port=port,
        protocol=protocol,
        beacon_intervals=beacon_intervals,
        dns_query=dns_query
    )
    return jsonify(result)


@app.route("/api/scan/unified", methods=["POST"])
def scan_unified():
    """Central unified multi-vector scan evaluated by CyberGuard Brain."""
    data = request.get_json() or {}
    phish_in = data.get("phish")
    upi_in = data.get("upi")
    net_in = data.get("network")
    title = data.get("title", "Live Manual Multi-Vector Assessment")

    result = brain_instance.analyze_event(
        phish_input=phish_in,
        upi_input=upi_in,
        net_input=net_in,
        incident_title=title
    )
    _record_incident(result)
    return jsonify(result)


@app.route("/api/simulate", methods=["POST"])
def simulate_attack():
    """Triggers preloaded real-world attack scenarios."""
    data = request.get_json() or {}
    scenario_key = data.get("scenario", "electricity_scam")
    scenario = SIMULATION_SCENARIOS.get(scenario_key)

    if not scenario:
        return jsonify({"error": f"Unknown scenario: {scenario_key}"}), 400

    result = brain_instance.analyze_event(
        phish_input=scenario["phish"],
        upi_input=scenario["upi"],
        net_input=scenario["network"],
        incident_title=scenario["title"]
    )
    result["scenario_info"] = {
        "key": scenario_key,
        "name": scenario["title"],
        "description": scenario["description"]
    }
    _record_incident(result)
    return jsonify(result)


@app.route("/api/incidents", methods=["GET"])
def get_incidents():
    """Returns recent incident history logs."""
    return jsonify({
        "total": len(INCIDENT_LOGS),
        "incidents": INCIDENT_LOGS
    })


if __name__ == "__main__":
    port = int(os.environ.get("CYBERGUARD_PORT", 5050))
    print(f"\n=======================================================")
    print(f"  CYBERGUARD AI — Unified Cyber Defense Platform")
    print(f"  One AI Brain. Multiple Specialized Defenses.")
    print(f"  Listening on http://127.0.0.1:{port}")
    print(f"=======================================================\n")
    app.run(host="0.0.0.0", port=port, debug=True)
