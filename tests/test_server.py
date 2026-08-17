import sys, unittest
from pathlib import Path
sys.path.insert(0,str(Path(__file__).resolve().parents[1]))
from server import analyze, password_hash, password_valid

class SecurityTests(unittest.TestCase):
    def test_password_hashing(self):
        stored=password_hash("CorrectHorseBatteryStaple!")
        self.assertTrue(password_valid("CorrectHorseBatteryStaple!",stored))
        self.assertFalse(password_valid("wrong",stored))
        self.assertNotIn("CorrectHorseBatteryStaple!",stored)

    def test_phishing_report_is_high_risk(self):
        score,severity,analysis,indicators=analyze({"title":"Urgent password warning","incident_type":"phishing","description":"Verify your account immediately","suspicious_content":"Click here https://bit.ly/fake-login"})
        self.assertGreaterEqual(score,50)
        self.assertIn(severity,("high","critical"))
        self.assertTrue(indicators)
        self.assertIn("analyst",analysis["method"])

    def test_benign_report_remains_low(self):
        score,severity,_,_=analyze({"title":"Question","incident_type":"other","description":"I received an expected class announcement","suspicious_content":""})
        self.assertLess(score,25)
        self.assertEqual(severity,"low")

if __name__=="__main__": unittest.main()
