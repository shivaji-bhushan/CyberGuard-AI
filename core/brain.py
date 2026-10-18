"""
CyberGuard AI — Central AI Brain Coordinator & Cross-Threat Correlation Engine
"One AI Brain. Multiple Specialized Defenses."

Orchestrates PhishShield, UPI Shield, and NetSentinel, detects cross-threat
correlation anchors (e.g., matching brand entities, shared IPs/domains,
coordinated SMS->UPI->C2 attack stages), builds visual graph models,
and applies unified policy actions.
"""

import time
import uuid
from typing import Dict, Any, List

from .phish_shield import analyze_phishing_event
from .upi_shield import analyze_upi_event
from .net_sentinel import analyze_network_event
from .risk_engine import calculate_composite_risk


class CyberGuardBrain:
    def __init__(self):
        self.version = "2.4.0"
        self.status = "ONLINE"
        self.subsystems = ["PhishShield", "UPI Shield", "NetSentinel", "RiskPolicyEngine"]

    def analyze_event(
        self,
        phish_input: Dict[str, Any] = None,
        upi_input: Dict[str, Any] = None,
        net_input: Dict[str, Any] = None,
        incident_title: str = "Live Unified Security Telemetry"
    ) -> Dict[str, Any]:
        """
        Executes unified cross-vector inspection across all three defense engines.
        Correlates indicators of compromise (IoCs) and synthesizes threat graph.
        """
        incident_id = f"CG-{int(time.time())}-{str(uuid.uuid4())[:4].upper()}"
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        modules_results = {}

        # 1. Run PhishShield if phish telemetry provided
        if phish_input and (phish_input.get("url") or phish_input.get("text")):
            modules_results["phish_shield"] = analyze_phishing_event(
                url=phish_input.get("url", ""),
                text=phish_input.get("text", "")
            )

        # 2. Run UPI Shield if UPI telemetry provided
        if upi_input and (upi_input.get("vpa") or upi_input.get("context") or upi_input.get("qr_payload")):
            modules_results["upi_shield"] = analyze_upi_event(
                vpa=upi_input.get("vpa", ""),
                amount=float(upi_input.get("amount", 0.0) or 0.0),
                context_text=upi_input.get("context", ""),
                qr_payload=upi_input.get("qr_payload", "")
            )

        # 3. Run NetSentinel if network telemetry provided
        if net_input and (net_input.get("ip") or net_input.get("dns_query") or net_input.get("beacon_intervals")):
            modules_results["net_sentinel"] = analyze_network_event(
                ip=net_input.get("ip", ""),
                port=int(net_input.get("port", 0) or 0),
                protocol=net_input.get("protocol", "TCP"),
                beacon_intervals=net_input.get("beacon_intervals", []),
                dns_query=net_input.get("dns_query", "")
            )

        # 4. Cross-Threat Evidence Correlation
        correlation_matches = self._correlate_threats(modules_results, phish_input, upi_input, net_input)

        # 5. Risk & Policy synthesis
        risk_evaluation = calculate_composite_risk(modules_results, correlation_matches)

        # 6. Build interactive threat graph
        threat_graph = self._build_threat_graph(modules_results, correlation_matches, risk_evaluation)

        # 7. Synthesize executive summary & AI diagnosis
        ai_diagnosis = self._generate_ai_diagnosis(modules_results, correlation_matches, risk_evaluation)

        return {
            "incident_id": incident_id,
            "incident_title": incident_title,
            "timestamp": timestamp,
            "brain_version": self.version,
            "modules": modules_results,
            "correlations": correlation_matches,
            "threat_graph": threat_graph,
            "risk": risk_evaluation,
            "ai_diagnosis": ai_diagnosis
        }

    def _correlate_threats(
        self,
        modules: Dict[str, Any],
        phish_in: Dict[str, Any],
        upi_in: Dict[str, Any],
        net_in: Dict[str, Any]
    ) -> List[Dict[str, Any]]:
        """
        Detects correlation patterns linking social engineering, financial deception, and C2/network anomalies.
        """
        matches = []
        p_res = modules.get("phish_shield")
        u_res = modules.get("upi_shield")
        n_res = modules.get("net_sentinel")

        # Correlation 1: Brand / Entity Alignment (Phish + UPI)
        # e.g., SMS claims 'SBI KYC' and UPI VPA is 'sbi.alert@okaxis' or Electricity scam
        if p_res and u_res:
            p_brands = p_res.get("details", {}).get("url_analysis", {}).get("detected_brands", [])
            u_brands = u_res.get("details", {}).get("vpa_analysis", {}).get("detected_brands", [])
            shared_brands = set(p_brands).intersection(set(u_brands))
            if shared_brands:
                matches.append({
                    "type": "BRAND_IMPERSONATION_LINK",
                    "confidence": "HIGH",
                    "details": f"Coordinated brand spoofing detected across Phishing lure and UPI VPA for: {', '.join(shared_brands).upper()}.",
                    "entities": list(shared_brands),
                    "vector_pair": ["phish_shield", "upi_shield"]
                })

            # Check if SMS text keywords match UPI reverse collect or alert
            text_flags = p_res.get("details", {}).get("text_analysis", {}).get("flags", [])
            p_has_finance = any("payment" in f.lower() or "bank" in f.lower() or "lottery" in f.lower() for f in text_flags)
            u_has_collect = u_res.get("details", {}).get("context_analysis", {}).get("is_reverse_collect_trap", False)
            if p_has_finance and u_has_collect:
                matches.append({
                    "type": "SOCIAL_ENGINEERING_FINANCIAL_TRAP",
                    "confidence": "VERY_HIGH",
                    "details": "Urgent SMS social-engineering hook directly leads to fraudulent UPI reverse-collect PIN trap.",
                    "entities": ["SMS Phish Trap", "Reverse Collect PIN"],
                    "vector_pair": ["phish_shield", "upi_shield"]
                })

        # Correlation 2: Domain & Network Infrastructure Alignment (Phish + Net)
        # e.g., URL hostname appears in DNS tunnel or NetSentinel IP matches phishing target host
        if p_res and n_res:
            url_host = p_res.get("details", {}).get("url_analysis", {}).get("hostname", "")
            dns_q = n_res.get("details", {}).get("dns_analysis", {}).get("dns_query", "")
            net_ip = n_res.get("details", {}).get("socket_analysis", {}).get("ip", "")

            if url_host and dns_q and (url_host in dns_q or dns_q in url_host):
                matches.append({
                    "type": "C2_INFRASTRUCTURE_LINK",
                    "confidence": "CRITICAL",
                    "details": f"DNS telemetry query '{dns_q}' directly correlates with phishing campaign domain '{url_host}'.",
                    "entities": [url_host, dns_q],
                    "vector_pair": ["phish_shield", "net_sentinel"]
                })

            if n_res.get("details", {}).get("beacon_analysis", {}).get("is_c2_beacon", False) and p_res.get("risk_score", 0) >= 60:
                matches.append({
                    "type": "MALWARE_DROPPER_C2_SYNDICATE",
                    "confidence": "HIGH",
                    "details": "High-risk credential harvesting URL paired with active C2 heartbeat beaconing on target machine.",
                    "entities": [net_ip or "C2 Node"],
                    "vector_pair": ["phish_shield", "net_sentinel"]
                })

        # Correlation 3: Multi-Stage Attack Chain (All 3 vectors active)
        if len(modules) >= 3:
            high_count = sum(1 for m in modules.values() if m.get("risk_score", 0) >= 60)
            if high_count >= 2:
                matches.append({
                    "type": "UNIFIED_KILLCHAIN_CONVERGENCE",
                    "confidence": "CRITICAL",
                    "details": "Synchronized attack progression identified: Phishing entry vector -> Financial exfiltration attempt -> Active C2 command tunnel.",
                    "entities": ["Full Killchain (Phish->UPI->C2)"],
                    "vector_pair": ["phish_shield", "upi_shield", "net_sentinel"]
                })

        return matches

    def _build_threat_graph(
        self,
        modules: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        risk: Dict[str, Any]
    ) -> Dict[str, Any]:
        """
        Creates graph visualization data nodes and edges representing the unified attack surface.
        """
        nodes = []
        links = []

        # Central Brain Node
        nodes.append({
            "id": "BRAIN",
            "name": "CyberGuard Brain",
            "category": "core",
            "val": 35,
            "status": risk.get("decision", "SAFE"),
            "risk": risk.get("composite_score", 0),
            "threat_level": risk.get("threat_level", "LOW")
        })

        # Add module nodes
        if "phish_shield" in modules:
            p_score = modules["phish_shield"].get("risk_score", 0)
            nodes.append({
                "id": "PHISH",
                "name": "PhishShield",
                "category": "vector",
                "val": 24,
                "status": "DANGER" if p_score >= 65 else ("WARN" if p_score >= 35 else "SAFE"),
                "risk": p_score,
                "detail": f"{modules['phish_shield'].get('verdict')} ({p_score}/100)"
            })
            links.append({"source": "PHISH", "target": "BRAIN", "type": "telemetry", "label": "Feed Risk"})

            flags = modules["phish_shield"].get("details", {}).get("url_analysis", {}).get("flags", [])
            for i, f in enumerate(flags[:2]):
                art_id = f"PHISH_FLAG_{i}"
                nodes.append({
                    "id": art_id,
                    "name": f[:26] + "..." if len(f) > 26 else f,
                    "category": "indicator",
                    "val": 14,
                    "status": "WARN",
                    "risk": p_score
                })
                links.append({"source": art_id, "target": "PHISH", "type": "ioc", "label": "Detected"})

        if "upi_shield" in modules:
            u_score = modules["upi_shield"].get("risk_score", 0)
            nodes.append({
                "id": "UPI",
                "name": "UPI Shield",
                "category": "vector",
                "val": 24,
                "status": "DANGER" if u_score >= 65 else ("WARN" if u_score >= 35 else "SAFE"),
                "risk": u_score,
                "detail": f"{modules['upi_shield'].get('verdict')} ({u_score}/100)"
            })
            links.append({"source": "UPI", "target": "BRAIN", "type": "telemetry", "label": "Feed Risk"})

            u_flags = modules["upi_shield"].get("details", {}).get("context_analysis", {}).get("flags", [])
            for i, f in enumerate(u_flags[:2]):
                art_id = f"UPI_FLAG_{i}"
                nodes.append({
                    "id": art_id,
                    "name": f[:26] + "..." if len(f) > 26 else f,
                    "category": "indicator",
                    "val": 14,
                    "status": "WARN",
                    "risk": u_score
                })
                links.append({"source": art_id, "target": "UPI", "type": "ioc", "label": "Flagged"})

        if "net_sentinel" in modules:
            n_score = modules["net_sentinel"].get("risk_score", 0)
            nodes.append({
                "id": "NET",
                "name": "NetSentinel",
                "category": "vector",
                "val": 24,
                "status": "DANGER" if n_score >= 65 else ("WARN" if n_score >= 35 else "SAFE"),
                "risk": n_score,
                "detail": f"{modules['net_sentinel'].get('verdict')} ({n_score}/100)"
            })
            links.append({"source": "NET", "target": "BRAIN", "type": "telemetry", "label": "Feed Risk"})

            n_flags = modules["net_sentinel"].get("details", {}).get("socket_analysis", {}).get("flags", [])
            for i, f in enumerate(n_flags[:2]):
                art_id = f"NET_FLAG_{i}"
                nodes.append({
                    "id": art_id,
                    "name": f[:26] + "..." if len(f) > 26 else f,
                    "category": "indicator",
                    "val": 14,
                    "status": "WARN",
                    "risk": n_score
                })
                links.append({"source": art_id, "target": "NET", "type": "ioc", "label": "Flagged"})

        # Correlation link edges between vectors
        for corr in correlations:
            pair = corr.get("vector_pair", [])
            if len(pair) == 2:
                src_map = {"phish_shield": "PHISH", "upi_shield": "UPI", "net_sentinel": "NET"}
                s = src_map.get(pair[0])
                t = src_map.get(pair[1])
                if s and t:
                    links.append({
                        "source": s,
                        "target": t,
                        "type": "correlation",
                        "label": corr.get("type", "CORRELATED")
                    })

        return {"nodes": nodes, "links": links}

    def _generate_ai_diagnosis(
        self,
        modules: Dict[str, Any],
        correlations: List[Dict[str, Any]],
        risk: Dict[str, Any]
    ) -> str:
        """
        Produces human-readable, actionable security intelligence analysis.
        """
        score = risk.get("composite_score", 0)
        decision = risk.get("decision", "SAFE")
        corr_count = len(correlations)

        if decision == "ISOLATE":
            return (
                f"CRITICAL MULTI-VECTOR BREACH IN PROGRESS (Risk Score: {score}/100). "
                f"CyberGuard Brain identified {corr_count} cross-threat correlation links confirming "
                f"a synchronized attack syndicate targeting credentials, financial traps, and active C2 sockets. "
                f"Immediate system isolation protocol engaged."
            )
        elif decision == "BLOCK":
            return (
                f"HIGH SEVERITY INTRUSION DETECTED (Risk Score: {score}/100). "
                f"Active defensive countermeasures triggered to block high-risk phishing payloads or fraudulent payment VPAs. "
                f"Perimeter firewall and gateway enforcement active."
            )
        elif decision == "WARN":
            return (
                f"SUSPICIOUS ACTIVITY LOGGED (Risk Score: {score}/100). "
                f"Telemetry reveals anomalous behavioral patterns or potential phishing lure traits. "
                f"Secondary identity challenge and advisory telemetry dispatched."
            )
        else:
            return (
                f"EVENT ASSESSED AS BENIGN (Risk Score: {score}/100). "
                f"All indicators adhere to verified baselines. Zero active IoC correlations identified."
            )


# Global singleton instance
brain_instance = CyberGuardBrain()
