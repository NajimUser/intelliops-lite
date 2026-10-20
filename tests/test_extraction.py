import unittest
from src.extraction import masquer_secrets, normaliser_log, normaliser_scan, normaliser_pipeline

class TestExtraction(unittest.TestCase):
    def test_masquer_secrets(self):
        self.assertEqual(masquer_secrets("user=bob password=abc123"), "user=bob password=[SECRET]")
        self.assertEqual(masquer_secrets("api_key:key123;autre=val"), "api_key:[SECRET];autre=val")

    def test_normaliser_log(self):
        ligne = "2026-10-05 10:02:11 ERROR backend OOMKilled restarts=14 password=abc123"
        evt = normaliser_log(ligne, 42)
        self.assertEqual(evt.id, "EVT-00042")
        self.assertEqual(evt.timestamp, "2026-10-05T10:02:11Z")
        self.assertEqual(evt.severity, "HIGH")
        self.assertNotIn("abc123", evt.message)

    def test_normaliser_scan(self):
        rapport = {"cve": "CVE-2026-1234", "package": "openssl", "severity": "critical", "date": "2026-10-05T10:00:00Z"}
        evt = normaliser_scan(rapport, 1)
        self.assertEqual(evt.event_type, "VULNERABILITY")
        self.assertEqual(evt.severity, "CRITICAL")

    def test_normaliser_pipeline(self):
        rapport = {"job": "build", "status": "failed", "date": "2026-10-05T10:00:00Z"}
        evt = normaliser_pipeline(rapport, 2)
        self.assertEqual(evt.event_type, "PIPELINE_FAILURE")
        self.assertEqual(evt.severity, "HIGH")

if __name__ == "__main__":
    unittest.main()