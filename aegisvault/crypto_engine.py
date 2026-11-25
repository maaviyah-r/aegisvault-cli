"""Cryptographic engine: X.509 mTLS PKI, X25519+HKDF key agreement, AES-256-GCM framing, PBKDF2, and TOTP MFA."""

from __future__ import annotations

import base64
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import ssl
import struct
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from cryptography import x509
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class CryptoSecurityError(Exception):
    """Base error for cryptographic failures."""


class TamperDetectedError(CryptoSecurityError):
    """Raised when AES-GCM authentication tag verification fails (MITM/corruption)."""


class ReplayAttackError(CryptoSecurityError):
    """Raised when a duplicate or out-of-window sequence number is received."""


@dataclass(frozen=True)
class PKIBundle:
    ca_cert: Path
    ca_key: Path
    server_cert: Path
    server_key: Path
    client_cert: Path
    client_key: Path


class PKIManager:
    """Manages local ECDSA P-256 Root CA and mTLS certificates for Vault Server & Edge Gateway."""

    def __init__(self, certs_dir: Path) -> None:
        self.certs_dir = certs_dir
        self.certs_dir.mkdir(parents=True, exist_ok=True)

    def ensure_pki(self, force: bool = False) -> PKIBundle:
        bundle = PKIBundle(
            ca_cert=self.certs_dir / "ca.crt",
            ca_key=self.certs_dir / "ca.key",
            server_cert=self.certs_dir / "vault.crt",
            server_key=self.certs_dir / "vault.key",
            client_cert=self.certs_dir / "gateway.crt",
            client_key=self.certs_dir / "gateway.key",
        )
        if not force and all(p.exists() for p in (
            bundle.ca_cert, bundle.ca_key,
            bundle.server_cert, bundle.server_key,
            bundle.client_cert, bundle.client_key,
        )):
            return bundle

        now = datetime.datetime.now(datetime.timezone.utc)

        # 1. Root CA (ECDSA P-256)
        ca_key = ec.generate_private_key(ec.SECP256R1())
        ca_subject = x509.Name([
            x509.NameAttribute(NameOID.COUNTRY_NAME, "PK"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisVault Security Authority"),
            x509.NameAttribute(NameOID.COMMON_NAME, "AegisVault Local Root CA"),
        ])
        ca_cert = (
            x509.CertificateBuilder()
            .subject_name(ca_subject)
            .issuer_name(ca_subject)
            .public_key(ca_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True,
                    content_commitment=False,
                    key_encipherment=False,
                    data_encipherment=False,
                    key_agreement=False,
                    key_cert_sign=True,
                    crl_sign=True,
                    encipher_only=False,
                    decipher_only=False,
                ),
                critical=True,
            )
            .sign(ca_key, hashes.SHA256())
        )
        self._write_cert_and_key(bundle.ca_cert, bundle.ca_key, ca_cert, ca_key)

        # 2. Vault Server Certificate
        server_key = ec.generate_private_key(ec.SECP256R1())
        server_san = x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("aegisvault-server"),
            x509.DNSName("vault.aegis.local"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ])
        server_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisVault"),
                x509.NameAttribute(NameOID.COMMON_NAME, "aegisvault-server"),
            ]))
            .issuer_name(ca_subject)
            .public_key(server_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(server_san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        self._write_cert_and_key(bundle.server_cert, bundle.server_key, server_cert, server_key)

        # 3. Gateway Client Certificate (for mTLS)
        client_key = ec.generate_private_key(ec.SECP256R1())
        client_san = x509.SubjectAlternativeName([
            x509.DNSName("localhost"),
            x509.DNSName("aegisvault-gateway"),
            x509.DNSName("gateway.aegis.local"),
            x509.IPAddress(ipaddress.IPv4Address("127.0.0.1")),
        ])
        client_cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "AegisVault"),
                x509.NameAttribute(NameOID.COMMON_NAME, "aegisvault-gateway"),
            ]))
            .issuer_name(ca_subject)
            .public_key(client_key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=365))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(client_san, critical=False)
            .add_extension(
                x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )
        self._write_cert_and_key(bundle.client_cert, bundle.client_key, client_cert, client_key)
        return bundle

    @staticmethod
    def _write_cert_and_key(cert_path: Path, key_path: Path, cert: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> None:
        cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        key_path.write_bytes(
            key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    def build_server_ssl_context(self, require_client_cert: bool = True) -> ssl.SSLContext:
        bundle = self.ensure_pki()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_cert_chain(certfile=str(bundle.server_cert), keyfile=str(bundle.server_key))
        ctx.load_verify_locations(cafile=str(bundle.ca_cert))
        ctx.verify_mode = ssl.CERT_REQUIRED if require_client_cert else ssl.CERT_OPTIONAL
        return ctx

    def build_client_ssl_context(self, use_client_cert: bool = True) -> ssl.SSLContext:
        bundle = self.ensure_pki()
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        ctx.load_verify_locations(cafile=str(bundle.ca_cert))
        if use_client_cert:
            ctx.load_cert_chain(certfile=str(bundle.client_cert), keyfile=str(bundle.client_key))
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        return ctx

    def get_cert_fingerprint(self, cert_path: Path) -> str:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex()


class ECDHEKeyExchange:
    """Ephemeral X25519 key exchange + HKDF-SHA256 for perfect forward secrecy inside the mini-VPN tunnel."""

    def __init__(self) -> None:
        self._private_key = x25519.X25519PrivateKey.generate()
        self.public_bytes = self._private_key.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )

    def public_b64(self) -> str:
        return base64.b64encode(self.public_bytes).decode("ascii")

    def derive_session_material(self, peer_public_b64: str, salt: bytes) -> tuple[bytes, bytes]:
        """Derive a 32-byte AES-256 key and a 4-byte nonce prefix using HKDF-SHA256."""
        peer_bytes = base64.b64decode(peer_public_b64.encode("ascii"))
        peer_key = x25519.X25519PublicKey.from_public_bytes(peer_bytes)
        shared_secret = self._private_key.exchange(peer_key)
        derived = HKDF(
            algorithm=hashes.SHA256(),
            length=36,
            salt=salt,
            info=b"aegisvault-mini-vpn-aes256gcm-v1",
        ).derive(shared_secret)
        return derived[:32], derived[32:36]


class TunnelCipher:
    """AES-256-GCM authenticated tunnel framing with monotonic sequence numbers and replay window defense."""

    def __init__(self, key: bytes, nonce_prefix: bytes, session_id: str, replay_window: int = 64) -> None:
        if len(key) != 32:
            raise ValueError("AES-256-GCM requires a 32-byte key.")
        if len(nonce_prefix) != 4:
            raise ValueError("Nonce prefix must be 4 bytes.")
        self._aesgcm = AESGCM(key)
        self._nonce_prefix = nonce_prefix
        self.session_id = session_id
        self._send_seq = 0
        self._max_recv_seq = 0
        self._seen_seqs: set[int] = set()
        self._replay_window = replay_window

    def encrypt_frame(self, payload: dict[str, Any], direction: str = "c2s") -> dict[str, Any]:
        self._send_seq += 1
        seq = self._send_seq
        nonce = self._nonce_prefix + struct.pack(">Q", seq)
        aad = f"{self.session_id}|{direction}|{seq}".encode("utf-8")
        plaintext = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        ciphertext = self._aesgcm.encrypt(nonce, plaintext, aad)
        return {
            "session_id": self.session_id,
            "direction": direction,
            "seq": seq,
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        }

    def decrypt_frame(self, frame: dict[str, Any], expected_direction: str) -> dict[str, Any]:
        try:
            seq = int(frame["seq"])
            direction = str(frame["direction"])
            nonce = base64.b64decode(frame["nonce"])
            ciphertext = base64.b64decode(frame["ciphertext"])
        except (KeyError, ValueError, TypeError) as exc:
            raise TamperDetectedError(f"Malformed encrypted frame: {exc}") from exc

        if direction != expected_direction:
            raise TamperDetectedError(f"Unexpected frame direction: {direction}")

        # Sliding-window replay protection
        if seq <= 0:
            raise ReplayAttackError("Invalid non-positive sequence number.")
        if seq in self._seen_seqs:
            raise ReplayAttackError(f"Duplicate sequence number detected (seq={seq}).")
        if self._max_recv_seq > self._replay_window and seq <= (self._max_recv_seq - self._replay_window):
            raise ReplayAttackError(f"Stale sequence number outside replay window (seq={seq}).")

        aad = f"{self.session_id}|{direction}|{seq}".encode("utf-8")
        try:
            plaintext = self._aesgcm.decrypt(nonce, ciphertext, aad)
        except InvalidTag as exc:
            raise TamperDetectedError("AES-256-GCM authentication tag verification failed (possible MITM tampering).") from exc

        # Record accepted sequence number after cryptographic verification
        self._seen_seqs.add(seq)
        if seq > self._max_recv_seq:
            self._max_recv_seq = seq
            cutoff = self._max_recv_seq - self._replay_window
            if cutoff > 0:
                self._seen_seqs = {s for s in self._seen_seqs if s > cutoff}

        return json.loads(plaintext.decode("utf-8"))


def hash_password(password: str, salt: bytes | None = None, iterations: int = 200_000) -> str:
    """Hash a password with PBKDF2-HMAC-SHA256 and per-user salt."""
    salt_bytes = salt if salt is not None else os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt_bytes, iterations)
    return f"pbkdf2_sha256${iterations}${base64.b64encode(salt_bytes).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password: str, encoded_hash: str) -> bool:
    """Verify a password against a stored PBKDF2-HMAC-SHA256 hash using constant-time comparison."""
    try:
        algo, iters_str, salt_b64, dk_b64 = encoded_hash.split("$", 3)
        if algo != "pbkdf2_sha256":
            return False
        iterations = int(iters_str)
        salt = base64.b64decode(salt_b64)
        expected = base64.b64decode(dk_b64)
    except (ValueError, TypeError):
        return False
    actual = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, iterations)
    return hmac.compare_digest(actual, expected)


def generate_totp(secret_b32: str, for_time: float | None = None, step: int = 30, digits: int = 6) -> str:
    """Generate RFC 6238 TOTP code using HMAC-SHA1."""
    now = int(time.time() if for_time is None else for_time)
    counter = now // step
    key = base64.b32decode(secret_b32.upper().encode("ascii"), casefold=True)
    msg = struct.pack(">Q", counter)
    digest = hmac.new(key, msg, hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(code_int % (10 ** digits)).zfill(digits)


def verify_totp(secret_b32: str, code: str, window: int = 1, for_time: float | None = None) -> bool:
    """Verify a 6-digit TOTP code allowing +/- window steps for minor clock skew."""
    now = time.time() if for_time is None else for_time
    clean = str(code).strip()
    for delta in range(-window, window + 1):
        expected = generate_totp(secret_b32, for_time=now + (delta * 30))
        if hmac.compare_digest(clean, expected):
            return True
    return False
