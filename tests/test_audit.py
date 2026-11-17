import os, sys, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scanner"))
from audit import scan

class T(unittest.TestCase):
    def test_detects_secret_and_missing_gitignore(self):
        with tempfile.TemporaryDirectory() as d:
            with open(os.path.join(d, "a.py"), "w") as f:
                f.write('password = "supersecret123"\n')
            titles = {x["title"] for x in scan(d)}
            self.assertIn("Hardcoded secret", titles)
            self.assertIn("Missing .gitignore", titles)

if __name__ == "__main__":
    unittest.main()
