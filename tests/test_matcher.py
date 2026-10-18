import os
import shutil
import tempfile
import time
import unittest

from config.matcher import DomainMatcher

class TestDomainMatcher(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.test_dir, "whitelist.yaml")

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_exact_and_wildcard_matching(self):
        content = """
whitelist:
  - "*-dot-asia-southeast1.notebooks.googleusercontent.com"
  - "cloudresourcemanager.googleapis.com"
  - "compute.googleapis.com"
  - "fonts.gstatic.com"
  - "accounts.google.com"
  - "analytics.google.com"
  - "cloud.google.com"
  - "cloudconsole-pa.clients6.google.com"
  - "cloudusersettings-pa.clients6.google.com"
  - "console.cloud.google.com"
  - "notebooks.clients6.google.com"
  - "www.gstatic.com"

settings:
  default_action: "block"
"""
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write(content)

        matcher = DomainMatcher(self.config_path)

        # Exact matches
        self.assertTrue(matcher.is_allowed("cloud.google.com"))
        self.assertTrue(matcher.is_allowed("cloud.google.com:443"))
        self.assertTrue(matcher.is_allowed("CLOUD.GOOGLE.COM:443"))
        self.assertTrue(matcher.is_allowed("accounts.google.com"))
        self.assertTrue(matcher.is_allowed("www.gstatic.com:443"))

        # Wildcard pattern matches
        self.assertTrue(matcher.is_allowed("my-notebook-dot-asia-southeast1.notebooks.googleusercontent.com"))
        self.assertTrue(matcher.is_allowed("test-dot-asia-southeast1.notebooks.googleusercontent.com:443"))

        # Blocked destinations
        self.assertFalse(matcher.is_allowed("example.com"))
        self.assertFalse(matcher.is_allowed("evil.com:443"))
        self.assertFalse(matcher.is_allowed("malicious.googleusercontent.com"))
        self.assertFalse(matcher.is_allowed("other-notebook.googleusercontent.com"))

    def test_hot_reload(self):
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("whitelist:\n  - cloud.google.com\n")

        matcher = DomainMatcher(self.config_path, check_interval_seconds=0.0)
        self.assertTrue(matcher.is_allowed("cloud.google.com"))
        self.assertFalse(matcher.is_allowed("added-later.com"))

        time.sleep(0.05)
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("whitelist:\n  - cloud.google.com\n  - added-later.com\n")

        self.assertTrue(matcher.is_allowed("added-later.com"))

    def test_resilience_to_malformed_config(self):
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("whitelist:\n  - cloud.google.com\n")

        matcher = DomainMatcher(self.config_path, check_interval_seconds=0.0)
        self.assertTrue(matcher.is_allowed("cloud.google.com"))

        time.sleep(0.05)
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("whitelist: [unclosed malformed")

        # Retains existing valid rules
        self.assertTrue(matcher.is_allowed("cloud.google.com"))
        self.assertFalse(matcher.is_allowed("evil.com"))

if __name__ == "__main__":
    unittest.main()
