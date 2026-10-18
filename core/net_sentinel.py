"""
CyberGuard AI — NetSentinel Engine
Analyzes network traffic anomalies, port scans, suspicious outbound sockets,
Command-and-Control (C2) beaconing patterns, and DNS tunneling exfiltration.
"""

import math
import re

# Threat signature databases
HIGH_RISK_PORTS = {
    4444: "Metasploit Default Listener",
    1337: "Common Hacker Backdoor Port",
    31337: "Elite Backdoor / Trojan",
    6667: "IRC Botnet C2 Channel",
    8888: "Suspicious Alternate Proxy / Web Backdoor",
    9001: "Tor Relay / C2 Traffic",
    9050: "Tor SOCKS Proxy",
    5555: "Android ADB Debug Exploit Port",
    445: "SMB Worm / EternalBlue Propagation",
    3389: "Exposed Remote Desktop (RDP Brute-force)"
}

SUSPICIOUS_SUBNETS = [
    "185.220.", "194.26.", "45.154.", "91.240.", "193.106.", "103.151."
]

def calculate_entropy(text: str) -> float:
    """Calculates Shannon entropy for string randomness."""
    if not text:
        return 0.0
    freq = {}
    for char in text:
        freq[char] = freq.get(char, 0) + 1
    entropy = 0.0
    for count in freq.values():
        p = count / len(text)
        entropy -= p * math.log2(p)
    return round(entropy, 2)

def analyze_connection(dest_ip: str, dest_port: int, protocol: str = "TCP", packet_size: int = 128, frequency_sec: float = None) -> dict:
    """
    Evaluates a single network socket connection for malicious indicators.
    """
    flags = []
    risk_score = 0
    threat_type = "Benign Connection"

    dest_ip = dest_ip.strip()
    dest_port = int(dest_port)
    protocol = protocol.upper()

    # 1. High Risk Port Check
    if dest_port in HIGH_RISK_PORTS:
        risk_score += 45
        service_threat = HIGH_RISK_PORTS[dest_port]
        threat_type = f"Backdoor / Exploitation Port ({service_threat})"
        flags.append(f"Connection to high-risk port {dest_port}: {service_threat}")

    # 2. Known Malicious / Bulletproof Hosting Subnets
    if any(dest_ip.startswith(subnet) for subnet in SUSPICIOUS_SUBNETS):
        risk_score += 40
        threat_type = "Known Bulletproof Host / C2 Server"
        flags.append(f"Destination IP {dest_ip} matches known bulletproof hosting subnet")

    # 3. C2 Beaconing Heartbeat Check
    if frequency_sec is not None and frequency_sec > 0:
        # Periodic keep-alive pings between 5s and 120s with tiny packet sizes
        if 5 <= frequency_sec <= 60 and packet_size <= 256:
            risk_score += 35
            threat_type = "Periodic C2 Beaconing Keep-Alive"
            flags.append(f"Fixed-interval beaconing detected (every {frequency_sec}s, payload {packet_size}B)")

    # 4. Outbound plain HTTP on unusual port
    if dest_port not in [80, 443, 8080, 8443] and protocol in ["HTTP", "TCP"] and dest_port < 1024:
        risk_score += 20
        flags.append(f"Privileged port access attempt: {dest_port}/{protocol}")

    risk_score = min(100, max(5, risk_score))
    threat_level = "CRITICAL" if risk_score >= 70 else ("HIGH" if risk_score >= 45 else ("MEDIUM" if risk_score >= 25 else "LOW"))

    return {
        "dest_ip": dest_ip,
        "dest_port": dest_port,
        "protocol": protocol,
        "is_suspicious": risk_score >= 45,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "threat_type": threat_type,
        "flags": flags if flags else ["Normal outbound network telemetry"],
        "explanation": f"Connection to {dest_ip}:{dest_port} shows active signatures of {threat_type}." if risk_score >= 45 else "Socket profile conforms to benign cloud/web services.",
        "recommendation": f"BLOCK IP {dest_ip} & TERMINATE SOCKET immediately." if risk_score >= 45 else "Allow connection."
    }

def analyze_dns_query(query_domain: str) -> dict:
    """
    Detects DNS tunneling, data exfiltration, and DGA queries.
    """
    flags = []
    risk_score = 0
    query = query_domain.strip().lower()

    subdomain = query.split(".")[0] if "." in query else query
    entropy = calculate_entropy(subdomain)

    # 1. High length and high entropy indicate encoded data exfiltration
    if len(subdomain) > 28 and entropy > 3.6:
        risk_score += 55
        flags.append(f"DNS Tunneling / Data Exfiltration Signature (Length: {len(subdomain)}, Entropy: {entropy})")

    # 2. Number of labels
    labels = query.split(".")
    if len(labels) >= 5:
        risk_score += 25
        flags.append(f"Excessive DNS domain depth ({len(labels)} labels)")

    # 3. Base64 / Hex characters density in label
    hex_ratio = len(re.findall(r"[0-9a-fA-F]", subdomain)) / max(1, len(subdomain))
    if hex_ratio > 0.85 and len(subdomain) > 16:
        risk_score += 35
        flags.append(f"Hex-encoded data payload in DNS subdomain ({int(hex_ratio*100)}% hex density)")

    risk_score = min(100, max(5, risk_score))
    threat_level = "CRITICAL" if risk_score >= 70 else ("HIGH" if risk_score >= 45 else ("MEDIUM" if risk_score >= 25 else "LOW"))

    return {
        "query_domain": query,
        "is_suspicious": risk_score >= 45,
        "risk_score": risk_score,
        "threat_level": threat_level,
        "entropy": entropy,
        "flags": flags if flags else ["Benign DNS lookup"],
        "explanation": "DNS tunneling detected: Subdomain carries algorithmically encoded exfiltration payload." if risk_score >= 45 else "Normal DNS resolution query.",
        "recommendation": "SINKHOLE DNS & ISOLATE CLIENT ENDPOINT." if risk_score >= 45 else "Query benign."
    }

def analyze_network_logs(log_text: str) -> dict:
    """
    Parses firewall, NetFlow, or connection logs for port scans and abnormal bursts.
    """
    lines = [line.strip() for line in log_text.splitlines() if line.strip()]
    flags = []
    anomaly_score = 0
    scanned_ports = set()
    targeted_ips = set()

    for line in lines:
        # Extract IP and Port pairs
        match = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})[:\s]+(\d{1,5})", line)
        if match:
            ip, port = match.group(1), int(match.group(2))
            targeted_ips.add(ip)
            scanned_ports.add(port)

            if port in HIGH_RISK_PORTS:
                anomaly_score += 20
                flags.append(f"Probe targeting vulnerable port {port} ({HIGH_RISK_PORTS[port]})")

    # Port Scan Detection: Multiple distinct ports scanned on few IPs
    if len(scanned_ports) >= 5:
        anomaly_score += 45
        flags.append(f"Active Port Scan / Reconnaissance: {len(scanned_ports)} distinct ports targeted")

    total_risk = min(100, max(10, anomaly_score))
    threat_level = "CRITICAL" if total_risk >= 70 else ("HIGH" if total_risk >= 45 else ("MEDIUM" if total_risk >= 25 else "LOW"))

    return {
        "log_entries_count": len(lines),
        "unique_ips": len(targeted_ips),
        "unique_ports": len(scanned_ports),
        "is_suspicious": total_risk >= 45,
        "risk_score": total_risk,
        "threat_level": threat_level,
        "flags": flags if flags else ["Uniform traffic flow without reconnaissance signatures"],
        "explanation": f"Network reconnaissance activity detected across {len(scanned_ports)} ports." if total_risk >= 45 else "Normal connection telemetry.",
        "recommendation": "ENABLE IDS/IPS AUTO-BLOCK on source IP." if total_risk >= 45 else "Standard monitoring."
    }

def scan_network_payload(payload: dict) -> dict:
    """Main dispatch function for NetSentinel module."""
    if "dest_ip" in payload and "dest_port" in payload:
        return analyze_connection(
            dest_ip=payload["dest_ip"],
            dest_port=payload["dest_port"],
            protocol=payload.get("protocol", "TCP"),
            packet_size=payload.get("packet_size", 128),
            frequency_sec=payload.get("frequency_sec")
        )
    elif "dns_query" in payload and payload["dns_query"]:
        return analyze_dns_query(payload["dns_query"])
    elif "log_text" in payload and payload["log_text"]:
        return analyze_network_logs(payload["log_text"])
    else:
        return {
            "error": "No connection details, DNS query, or log text provided for NetSentinel",
            "is_suspicious": False,
            "risk_score": 0
        }


def analyze_beacon_intervals(intervals: list) -> dict:
    """
    Analyzes successive network transmission intervals to detect automated C2 heartbeats.
    Low variance / standard deviation indicates non-human periodic polling.
    """
    if not intervals or len(intervals) < 3:
        return {"is_c2_beacon": False, "confidence": 0.0, "mean_interval": 0, "std_dev": 0}

    mean_val = sum(intervals) / len(intervals)
    variance = sum((x - mean_val) ** 2 for x in intervals) / len(intervals)
    std_dev = math.sqrt(variance)

    # If std_dev is very low (jitter < 0.25 sec) and mean interval is between 2s and 120s
    is_beacon = std_dev < 0.35 and 2.0 <= mean_val <= 120.0
    confidence = round(max(0.0, min(1.0, 1.0 - (std_dev / 2.0))), 2)

    return {
        "is_c2_beacon": is_beacon,
        "confidence": confidence,
        "mean_interval": round(mean_val, 2),
        "std_dev": round(std_dev, 3),
        "explanation": f"Automated fixed C2 heartbeat detected: Mean {mean_val:.2f}s with minimal jitter ({std_dev:.3f}s)." if is_beacon else "Randomized human interval telemetry."
    }


def analyze_network_event(
    ip: str = "",
    port: int = 0,
    protocol: str = "TCP",
    beacon_intervals: list = None,
    dns_query: str = ""
) -> dict:
    """
    Unified entrypoint for NetSentinel analyzing socket, beacon jitter, and DNS tunneling.
    """
    socket_res = analyze_connection(ip, port, protocol) if (ip or port) else None
    beacon_res = analyze_beacon_intervals(beacon_intervals) if beacon_intervals else None
    dns_res = analyze_dns_query(dns_query) if dns_query else None

    scores = []
    if socket_res:
        socket_res["ip"] = ip
        socket_res["is_risky_port"] = port in HIGH_RISK_PORTS
        scores.append(socket_res.get("risk_score", 0))

    if beacon_res and beacon_res.get("is_c2_beacon"):
        scores.append(75)

    if dns_res:
        scores.append(dns_res.get("risk_score", 0))

    final_score = max(scores) if scores else 0
    if final_score >= 65:
        verdict = "CRITICAL C2 INTRUSION"
        threat_level = "CRITICAL" if final_score >= 80 else "HIGH"
    elif final_score >= 35:
        verdict = "SUSPICIOUS TRAFFIC"
        threat_level = "MEDIUM"
    else:
        verdict = "SAFE"
        threat_level = "LOW"

    return {
        "risk_score": final_score,
        "verdict": verdict,
        "threat_level": threat_level,
        "details": {
            "socket_analysis": socket_res or {"ip": "", "flags": [], "is_risky_port": False},
            "beacon_analysis": beacon_res or {"is_c2_beacon": False},
            "dns_analysis": dns_res or {"dns_query": "", "flags": []}
        }
    }

analyze_dns_tunneling = analyze_dns_query

