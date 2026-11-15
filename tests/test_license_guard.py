import base64
import importlib.util
import json
import os
import time
import unittest
from unittest.mock import patch

from utils.license_guard import PRODUCT_NAME, verify_license_key


HAS_CRYPTOGRAPHY = importlib.util.find_spec("cryptography") is not None


@unittest.skipUnless(HAS_CRYPTOGRAPHY, "cryptography package is required for license verification")
class LicenseGuardTests(unittest.TestCase):
    def test_verifies_signed_product_license_and_rejects_expired_license(self):
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

        def signed_token(payload):
            payload_bytes = json.dumps(payload, separators=(",", ":")).encode("utf-8")
            signature = private_key.sign(payload_bytes)
            encode = lambda value: base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")
            return f"{encode(payload_bytes)}.{encode(signature)}"

        active = signed_token({
            "product": PRODUCT_NAME,
            "tier": "PRO",
            "email": "qa@example.test",
            "issued_at": int(time.time()),
            "expires_at": int(time.time()) + 3600,
        })
        expired = signed_token({
            "product": PRODUCT_NAME,
            "tier": "PRO",
            "expires_at": int(time.time()) - 1,
        })
        with patch.dict(os.environ, {"PROTOSEC_LICENSE_PUBLIC_KEY_HEX": public_key.hex()}):
            self.assertTrue(verify_license_key(active)[0])
            self.assertFalse(verify_license_key(expired)[0])
            self.assertFalse(verify_license_key(active + "tampered")[0])

    def test_reports_unconfigured_offline_key(self):
        with patch.dict(os.environ, {"PROTOSEC_LICENSE_PUBLIC_KEY_HEX": ""}):
            active, message = verify_license_key("not-a-license")
        self.assertFalse(active)
        self.assertIn("not configured", message)


if __name__ == "__main__":
    unittest.main()
