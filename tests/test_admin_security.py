import base64
import unittest

from admin_panel.security import basic_auth_matches
from admin_panel.app import is_loopback_host


class BasicAuthTests(unittest.TestCase):
    def header(self, value: str) -> str:
        return "Basic " + base64.b64encode(value.encode("utf-8")).decode("ascii")

    def test_disabled_auth_accepts_request(self):
        # With allow_anonymous=True, empty credentials should pass
        self.assertTrue(basic_auth_matches("", "", "", allow_anonymous=True))
        # Without allow_anonymous, empty credentials should be rejected
        self.assertFalse(basic_auth_matches("", "", ""))

    def test_valid_credentials_are_accepted(self):
        self.assertTrue(basic_auth_matches(self.header("alex:secret"), "alex", "secret"))

    def test_invalid_and_malformed_credentials_are_rejected(self):
        self.assertFalse(basic_auth_matches(self.header("alex:wrong"), "alex", "secret"))
        self.assertFalse(basic_auth_matches("Basic not-base64", "alex", "secret"))
        self.assertFalse(basic_auth_matches("", "alex", "secret"))

    def test_only_loopback_bindings_are_safe_without_auth(self):
        self.assertTrue(is_loopback_host("127.0.0.1"))
        self.assertTrue(is_loopback_host("::1"))
        self.assertTrue(is_loopback_host("localhost"))
        self.assertFalse(is_loopback_host("0.0.0.0"))
        self.assertFalse(is_loopback_host("192.168.1.20"))


if __name__ == "__main__":
    unittest.main()
