"""Unit tests for PKI, X25519+HKDF, AES-256-GCM framing, PBKDF2, and TOTP MFA."""

from __future__ import annotations

import base64
import os
from pathlib import Path

import pytest

from aegisvault.crypto_engine import (
    ECDHEKeyExchange,
    PKIManager,
    ReplayAttackError,
    TamperDetectedError,
    TunnelCipher,
    generate_totp,
    hash_password,
    verify_password,
    verify_totp,
)


def test_pki_generation_and_ssl_contexts(tmp_path: Path) -> None:
    pki = PKIManager(tmp_path / "certs")
    bundle = pki.ensure_pki()
    assert bundle.ca_cert.exists()
    assert bundle.server_cert.exists()
    assert bundle.client_cert.exists()
    assert len(pki.get_cert_fingerprint(bundle.server_cert)) == 64

    srv_ctx = pki.build_server_ssl_context(require_client_cert=True)
    cli_ctx = pki.build_client_ssl_context(use_client_cert=True)
    assert srv_ctx is not None and cli_ctx is not None


def test_ecdhe_aes_gcm_roundtrip_tamper_and_replay() -> None:
    client_kex = ECDHEKeyExchange()
    server_kex = ECDHEKeyExchange()
    salt = os.urandom(16)

    c_key, c_prefix = client_kex.derive_session_material(server_kex.public_b64(), salt)
    s_key, s_prefix = server_kex.derive_session_material(client_kex.public_b64(), salt)
    assert c_key == s_key
    assert c_prefix == s_prefix

    c_cipher = TunnelCipher(c_key, c_prefix, session_id="TUN-TEST01")
    s_cipher = TunnelCipher(s_key, s_prefix, session_id="TUN-TEST01")

    frame = c_cipher.encrypt_frame({"command": "ping", "seq_check": True}, direction="c2s")
    decrypted = s_cipher.decrypt_frame(frame, expected_direction="c2s")
    assert decrypted["command"] == "ping"

    # Replay detection on duplicate frame
    with pytest.raises(ReplayAttackError):
        s_cipher.decrypt_frame(frame, expected_direction="c2s")

    # Tamper detection on flipped bit
    frame2 = c_cipher.encrypt_frame({"command": "relay", "msg": "confidential"}, direction="c2s")
    raw = bytearray(base64.b64decode(frame2["ciphertext"]))
    raw[0] ^= 0x01
    frame2["ciphertext"] = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(TamperDetectedError):
        s_cipher.decrypt_frame(frame2, expected_direction="c2s")


def test_password_hashing_and_totp() -> None:
    hashed = hash_password("StrongPass#2026!")
    assert verify_password("StrongPass#2026!", hashed)
    assert not verify_password("WrongPass!", hashed)

    secret = "JBSWY3DPEHPK3PXP"
    code = generate_totp(secret, for_time=1700000000)
    assert len(code) == 6 and code.isdigit()
    assert verify_totp(secret, code, for_time=1700000000)
    assert not verify_totp(secret, "000000", for_time=1700000000)
