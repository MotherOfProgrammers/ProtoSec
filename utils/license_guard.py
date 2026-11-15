import base64
import json
import os
import sys
import tempfile
import time
from pathlib import Path

PRODUCT_NAME = "ProtoSec"
LICENSE_FILE = Path.home() / ".protosec-license"
PUBLIC_KEY_ENV = "PROTOSEC_LICENSE_PUBLIC_KEY_HEX"
MAX_TOKEN_LENGTH = 8192


def _public_key_hex() -> str:
    packaged_key = getattr(sys, "_MEIPASS", None)
    if packaged_key:
        key_file = Path(packaged_key) / "license_public_key.hex"
        if key_file.is_file():
            return key_file.read_text(encoding="ascii").strip()
    return os.environ.get(PUBLIC_KEY_ENV, "").strip()


def _decode_urlsafe(value: str) -> bytes:
    if not value or len(value) > MAX_TOKEN_LENGTH:
        raise ValueError("Invalid license token size.")
    padded = value + "=" * (-len(value) % 4)
    return base64.b64decode(padded, altchars=b"-_", validate=True)


def verify_license_key(token: str) -> tuple[bool, str]:
    try:
        public_key_hex = _public_key_hex()
    except OSError as exc:
        return False, f"Unable to read the configured license public key: {exc}"
    if not public_key_hex:
        return False, "Offline licensing is not configured in this build."
    try:
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if not isinstance(token, str) or len(token) > MAX_TOKEN_LENGTH:
            raise ValueError("Invalid license token size.")
        parts = token.strip().split(".")
        if len(parts) != 2:
            raise ValueError("Expected payload.signature license format.")

        payload_bytes = _decode_urlsafe(parts[0])
        signature = _decode_urlsafe(parts[1])
        if len(signature) != 64:
            raise ValueError("Invalid signature size.")

        public_key = Ed25519PublicKey.from_public_bytes(bytes.fromhex(public_key_hex))
        public_key.verify(signature, payload_bytes)
        payload = json.loads(payload_bytes.decode("utf-8"))
        if not isinstance(payload, dict):
            raise ValueError("License payload must be a JSON object.")
        if payload.get("product") != PRODUCT_NAME or payload.get("tier") != "PRO":
            raise ValueError("License is not a ProtoSec Pro license.")

        issued_at = payload.get("issued_at")
        if issued_at is not None and (not isinstance(issued_at, int) or issued_at > int(time.time()) + 300):
            raise ValueError("License issue date is invalid.")
        expires_at = payload.get("expires_at")
        if expires_at is not None:
            if not isinstance(expires_at, int):
                raise ValueError("License expiration is invalid.")
            if expires_at <= int(time.time()):
                raise ValueError("License has expired.")

        licensee = payload.get("email")
        return True, f"Licensed to {licensee}" if isinstance(licensee, str) and licensee else "ProtoSec Pro license active."
    except ImportError:
        return False, "The cryptography package is required to verify licenses."
    except (ValueError, UnicodeDecodeError, json.JSONDecodeError):
        return False, "Invalid license key or unsupported license format."
    except InvalidSignature:
        return False, "License signature is invalid or has been tampered with."


def is_pro_unlocked() -> tuple[bool, str]:
    if not LICENSE_FILE.exists():
        return False, "Free edition"
    try:
        return verify_license_key(LICENSE_FILE.read_text(encoding="utf-8"))
    except OSError as exc:
        return False, f"Unable to read the saved license: {exc}"


def save_license_key(token: str) -> tuple[bool, str]:
    valid, message = verify_license_key(token)
    if not valid:
        return False, message

    temporary_path = None
    try:
        LICENSE_FILE.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=LICENSE_FILE.parent,
            prefix=".protosec-license-",
            delete=False,
        ) as handle:
            handle.write(token.strip())
            handle.write("\n")
            temporary_path = Path(handle.name)
        if os.name != "nt":
            temporary_path.chmod(0o600)
        os.replace(temporary_path, LICENSE_FILE)
        return True, message
    except OSError as exc:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)
        return False, f"Unable to save the license: {exc}"
