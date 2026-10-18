"""
CyberGuard AI — Comprehensive Automated Test Suite
Validates PhishShield, UPI Shield, NetSentinel, Risk Engine, Brain correlation,
and Flask API endpoints.
"""

import unittest
import json
from core.phish_shield import analyze_phishing_event, calculate_shannon_entropy, detect_brand_typosquatting
from core.upi_shield import analyze_upi_event, parse_upi_qr_string, detect_reverse_collect_trap
from core.net_sentinel import analyze_network_event, analyze_beacon_intervals, analyze_dns_tunneling
from core.risk_engine import calculate_composite_risk
from core.brain import CyberGuardBrain
from app import app


class TestPhishShield(unittest.TestCase):
    def test_phishing_url_detection(self):
        # Fake SBI bank phishing link
        res = analyze_phishing_event(
            url="http://sbi-kyc-verify.top/netbanking-login",
            text="URGENT: Your SBI account is blocked. Update PAN KYC now."
        )
        self.assertGreaterEqual(res["risk_score"], 65)
        self.assertIn("PHISHING", res["verdict"])
        self.assertTrue(any("sbi" in b.lower() for b in res["details"]["url_analysis"]["detected_brands"]))

    def test_safe_url(self):
        res = analyze_phishing_event(
            url="https://mail.google.com/mail/u/0/#inbox",
            text="Meeting agenda for tomorrow at 10 AM."
        )
        self.assertLess(res["risk_score"], 35)
        self.assertEqual(res["verdict"], "SAFE")


class TestUPIShield(unittest.TestCase):
    def test_reverse_collect_trap(self):
        # Scam scenario: "Enter UPI PIN to receive money"
        res = analyze_upi_event(
            vpa="mahadiscom.billdesk@paytm",
            amount=1480.0,
            context_text="Enter secret UPI PIN to receive electricity refund voucher."
        )
        self.assertGreaterEqual(res["risk_score"], 60)
        self.assertTrue(res["details"]["context_analysis"]["is_reverse_collect_trap"])

    def test_legitimate_merchant(self):
        res = analyze_upi_event(
            vpa="starbucks.coffee@icici",
            amount=350.0,
            context_text="Payment for Latte"
        )
        self.assertLess(res["risk_score"], 35)
        self.assertEqual(res["verdict"], "SAFE")


class TestNetSentinel(unittest.TestCase):
    def test_c2_backdoor_detection(self):
        # Port 4444 + regular 5.0 second beaconing + suspicious DNS tunneling
        res = analyze_network_event(
            ip="185.220.101.5",
            port=4444,
            protocol="TCP",
            beacon_intervals=[5.01, 4.99, 5.02, 5.00, 4.98],
            dns_query="c2.power-bill-update.xyz"
        )
        self.assertGreaterEqual(res["risk_score"], 70)
        self.assertTrue(res["details"]["beacon_analysis"]["is_c2_beacon"])
        self.assertTrue(res["details"]["socket_analysis"]["is_risky_port"])


class TestRiskEngineAndBrain(unittest.TestCase):
    def setUp(self):
        self.brain = CyberGuardBrain()

    def test_cross_threat_correlation_boost(self):
        # Scenario where SMS and UPI share 'sbi' entity
        result = self.brain.analyze_event(
            phish_input={
                "url": "http://sbi-kyc-verify.top/login",
                "text": "SBI Alert: Complete KYC immediately or account suspended."
            },
            upi_input={
                "vpa": "sbi.fraudulent.collect@okaxis",
                "amount": 500.0,
                "context": "Enter UPI PIN to verify and receive refund."
            },
            net_input={
                "ip": "45.142.122.99",
                "port": 1337,
                "protocol": "TCP",
                "beacon_intervals": [10.0, 10.0, 9.9, 10.1],
                "dns_query": "tunnel.sbi-kyc-verify.top"
            }
        )
        self.assertGreaterEqual(len(result["correlations"]), 1)
        self.assertGreaterEqual(result["risk"]["correlation_boost"], 10)
        self.assertEqual(result["risk"]["decision"], "ISOLATE")
        self.assertIn("threat_graph", result)
        self.assertGreater(len(result["threat_graph"]["nodes"]), 3)


class TestFlaskEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_status_endpoint(self):
        res = self.client.get("/api/status")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertEqual(data["status"], "ONLINE")

    def test_simulation_endpoint(self):
        res = self.client.post("/api/simulate", json={"scenario": "electricity_scam"})
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("incident_id", data)
        self.assertIn(data["risk"]["decision"], ["BLOCK", "ISOLATE"])

    def test_incidents_endpoint(self):
        res = self.client.get("/api/incidents")
        self.assertEqual(res.status_code, 200)
        data = json.loads(res.data)
        self.assertIn("incidents", data)


if __name__ == "__main__":
    unittest.main()
