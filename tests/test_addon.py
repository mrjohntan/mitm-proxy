import json
import os
import shutil
import tempfile
import unittest
from unittest.mock import MagicMock

from config.addon import EgressWhitelistAddon


class TestEgressWhitelistAddon(unittest.TestCase):
    def setUp(self):
        self.test_dir = tempfile.mkdtemp()
        self.config_path = os.path.join(self.test_dir, "whitelist.yaml")
        with open(self.config_path, "w", encoding="utf-8") as f:
            f.write("""
whitelist:
  - "cloud.google.com"
  - "*.googleusercontent.com"
settings:
  default_action: "block"
""")
        self.addon = EgressWhitelistAddon(config_path=self.config_path)

    def tearDown(self):
        shutil.rmtree(self.test_dir)

    def test_http_connect_allowed(self):
        flow = MagicMock()
        flow.request.host = "cloud.google.com"
        flow.request.port = 443
        flow.response = None

        self.addon.http_connect(flow)
        self.assertIsNone(flow.response)

    def test_http_connect_blocked(self):
        flow = MagicMock()
        flow.request.host = "unapproved.example.com"
        flow.request.port = 443
        flow.response = None

        self.addon.http_connect(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.response.headers.get("X-Egress-Policy"), "Blocked")

        payload = json.loads(flow.response.content.decode("utf-8"))
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["code"], 403)
        self.assertIn("unapproved.example.com", payload["message"])

    def test_tls_clienthello_passthrough_when_allowed(self):
        self.addon.matcher.tls_passthrough = True
        data = MagicMock()
        data.context.client.sni = "cloud.google.com"
        data.context.server.address = ("cloud.google.com", 443)
        data.ignore_connection = False

        self.addon.tls_clienthello(data)
        self.assertTrue(data.ignore_connection)

    def test_tls_clienthello_no_passthrough_when_blocked(self):
        data = MagicMock()
        data.context.client.sni = "forbidden.com"
        data.context.server.address = ("forbidden.com", 443)
        data.ignore_connection = False

        self.addon.tls_clienthello(data)
        self.assertFalse(data.ignore_connection)

    def test_plain_http_request_blocked(self):
        flow = MagicMock()
        flow.request.method = "GET"
        flow.request.pretty_host = "evil.com"
        flow.request.path = "/data"
        flow.response = None

        self.addon.request(flow)
        self.assertIsNotNone(flow.response)
        self.assertEqual(flow.response.status_code, 403)

    def test_plain_http_request_allowed(self):
        flow = MagicMock()
        flow.request.method = "GET"
        flow.request.pretty_host = "cloud.google.com"
        flow.request.path = "/index.html"
        flow.response = None

        self.addon.request(flow)
        self.assertIsNone(flow.response)


if __name__ == "__main__":
    unittest.main()
