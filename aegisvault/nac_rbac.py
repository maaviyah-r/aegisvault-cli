"""Network Access Control (NAC) device admission and Role-Based Access Control (RBAC) with PBKDF2 + TOTP MFA."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .crypto_engine import generate_totp, hash_password, verify_password, verify_totp
from .siem_logger import SIEMLogger


@dataclass(frozen=True)
class NACDecision:
    admitted: bool
    device_id: str
    assigned_vlan: str
    posture_score: int
    reason: str


class NACEngine:
    """Validates endpoint identity, MAC binding, antivirus/firewall posture, and VLAN segmentation."""

    def __init__(self, registry_path: Path, siem: SIEMLogger | None = None) -> None:
        self.registry_path = registry_path
        self.siem = siem
        data = json.loads(registry_path.read_text(encoding="utf-8"))
        self.min_posture_score: int = int(data.get("minimum_posture_score", 80))
        self.quarantine_vlan: str = str(data.get("quarantine_vlan", "VLAN-99-QUARANTINE"))
        self.devices: dict[str, dict[str, Any]] = dict(data.get("devices", {}))

    def evaluate_device(
        self,
        device_id: str,
        mac_address: str,
        source_ip: str = "127.0.0.1",
        posture_override: int | None = None,
    ) -> NACDecision:
        device = self.devices.get(device_id)
        if not device:
            decision = NACDecision(
                admitted=False,
                device_id=device_id,
                assigned_vlan=self.quarantine_vlan,
                posture_score=0,
                reason=f"Unknown/unregistered device '{device_id}' assigned to {self.quarantine_vlan}.",
            )
            self._log_nac(decision, source_ip, "HIGH")
            return decision

        expected_mac = str(device.get("mac_address", "")).upper()
        if mac_address.upper() != expected_mac:
            decision = NACDecision(
                admitted=False,
                device_id=device_id,
                assigned_vlan=self.quarantine_vlan,
                posture_score=int(device.get("posture_score", 0)),
                reason=f"MAC spoofing suspected for '{device_id}': expected {expected_mac}, got {mac_address.upper()}.",
            )
            self._log_nac(decision, source_ip, "CRITICAL")
            return decision

        posture = int(posture_override if posture_override is not None else device.get("posture_score", 0))
        av_ok = bool(device.get("antivirus_active", False))
        fw_ok = bool(device.get("firewall_enabled", False))
        status = str(device.get("status", "QUARANTINED")).upper()

        if status != "APPROVED" or posture < self.min_posture_score or not (av_ok and fw_ok):
            decision = NACDecision(
                admitted=False,
                device_id=device_id,
                assigned_vlan=self.quarantine_vlan,
                posture_score=posture,
                reason=(
                    f"Device '{device_id}' failed posture compliance "
                    f"(status={status}, score={posture}/{self.min_posture_score}, av={av_ok}, fw={fw_ok})."
                ),
            )
            self._log_nac(decision, source_ip, "HIGH")
            return decision

        vlan = str(device.get("assigned_vlan", "VLAN-20-CORP"))
        decision = NACDecision(
            admitted=True,
            device_id=device_id,
            assigned_vlan=vlan,
            posture_score=posture,
            reason=f"Device '{device_id}' admitted to {vlan} (posture={posture}).",
        )
        self._log_nac(decision, source_ip, "INFO")
        return decision

    def register_device(
        self,
        device_id: str,
        hostname: str,
        mac_address: str,
        assigned_vlan: str = "VLAN-20-CORP",
        posture_score: int = 90,
        os_version: str = "Windows-11-Pro",
    ) -> dict[str, Any]:
        entry = {
            "hostname": hostname,
            "mac_address": mac_address.upper(),
            "assigned_vlan": assigned_vlan,
            "os_version": os_version,
            "posture_score": posture_score,
            "antivirus_active": True,
            "firewall_enabled": True,
            "status": "APPROVED" if posture_score >= self.min_posture_score else "QUARANTINED",
        }
        self.devices[device_id] = entry
        if self.siem:
            self.siem.log("NAC", "device_registered", "INFO", actor="admin", action="ALLOW", details={"device_id": device_id, **entry})
        return entry

    def quarantine_device(self, device_id: str, reason: str = "Administrative quarantine") -> bool:
        if device_id not in self.devices:
            return False
        self.devices[device_id]["status"] = "QUARANTINED"
        self.devices[device_id]["assigned_vlan"] = self.quarantine_vlan
        if self.siem:
            self.siem.log("NAC", "device_quarantined", "HIGH", actor="admin", action="QUARANTINE", details={"device_id": device_id, "reason": reason})
        return True

    def _log_nac(self, decision: NACDecision, source_ip: str, severity: str) -> None:
        if self.siem:
            self.siem.log(
                category="NAC",
                event_type="device_admission",
                severity=severity,
                source_ip=source_ip,
                actor=decision.device_id,
                action="ALLOW" if decision.admitted else "QUARANTINE",
                details={
                    "device_id": decision.device_id,
                    "assigned_vlan": decision.assigned_vlan,
                    "posture_score": decision.posture_score,
                    "reason": decision.reason,
                },
            )


@dataclass(frozen=True)
class AuthResult:
    authenticated: bool
    username: str
    role: str | None
    token: str | None
    mfa_verified: bool
    reason: str


class RBACEngine:
    """Authenticates users (PBKDF2-SHA256 + optional RFC 6238 TOTP MFA) and enforces 6-role RBAC permissions."""

    DEFAULT_ACCOUNTS: list[tuple[str, str, str, str]] = [
        # (username, password, role, base32_totp_secret)
        ("secadmin", "AegisSec#2026!", "security_admin", "JBSWY3DPEHPK3PXP"),
        ("netadmin", "AegisNet#2026!", "network_admin", "KRSXG5CTMVRXEZLU"),
        ("sysadmin", "AegisSys#2026!", "system_admin", "MFRGGZDFMZTWQ2LK"),
        ("analyst", "AegisSoc#2026!", "security_analyst", "NBSWY3DPO5XXE3DE"),
        ("manager", "AegisMgr#2026!", "it_manager", "ONXW2ZJANFXGOIDL"),
        ("alice", "AegisUser#2026!", "end_user", "ORSXG5BAMV4GC3LQ"),
    ]

    def __init__(
        self,
        rbac_policy_path: Path,
        users_db_path: Path | None = None,
        siem: SIEMLogger | None = None,
        token_ttl_seconds: int = 3600,
    ) -> None:
        self.rbac_policy_path = rbac_policy_path
        self.users_db_path = users_db_path
        self.siem = siem
        self.token_ttl_seconds = token_ttl_seconds
        self._signing_secret = hashlib.sha256(
            os.environ.get("AEGISVAULT_TOKEN_SECRET", "aegisvault-local-hmac-key-2026").encode("utf-8")
        ).digest()

        policy_data = json.loads(rbac_policy_path.read_text(encoding="utf-8"))
        self.roles: dict[str, dict[str, Any]] = dict(policy_data.get("roles", {}))
        self.users: dict[str, dict[str, Any]] = {}
        self._load_or_seed_users()

    def _load_or_seed_users(self) -> None:
        if self.users_db_path and self.users_db_path.exists():
            self.users = json.loads(self.users_db_path.read_text(encoding="utf-8"))
            return
        for username, password, role, totp_secret in self.DEFAULT_ACCOUNTS:
            self.users[username] = {
                "username": username,
                "role": role,
                "password_hash": hash_password(password),
                "totp_secret": totp_secret,
                "mfa_required": role in ("security_admin", "network_admin", "system_admin"),
                "active": True,
            }
        if self.users_db_path:
            self.users_db_path.parent.mkdir(parents=True, exist_ok=True)
            self.users_db_path.write_text(json.dumps(self.users, indent=2), encoding="utf-8")

    def get_current_totp(self, username: str) -> str:
        """Helper for local CLI demo & tests to compute a user's current 6-digit TOTP MFA code."""
        user = self.users.get(username)
        if not user:
            raise KeyError(f"Unknown user: {username}")
        return generate_totp(user["totp_secret"])

    def authenticate(
        self,
        username: str,
        password: str,
        totp_code: str | None = None,
        source_ip: str = "127.0.0.1",
        enforce_mfa: bool = False,
    ) -> AuthResult:
        user = self.users.get(username)
        if not user or not user.get("active", True):
            self._log_auth(username, source_ip, False, False, "Unknown or disabled account")
            return AuthResult(False, username, None, None, False, "Invalid credentials.")

        if not verify_password(password, user["password_hash"]):
            self._log_auth(username, source_ip, False, False, "Password mismatch")
            return AuthResult(False, username, None, None, False, "Invalid credentials.")

        mfa_verified = False
        if totp_code is not None:
            if not verify_totp(user["totp_secret"], totp_code):
                self._log_auth(username, source_ip, False, False, "Invalid TOTP MFA code")
                return AuthResult(False, username, None, None, False, "Invalid MFA code.")
            mfa_verified = True
        elif enforce_mfa and user.get("mfa_required", False):
            self._log_auth(username, source_ip, False, False, "Missing mandatory MFA code")
            return AuthResult(False, username, None, None, False, "MFA code required for privileged role.")

        role = str(user["role"])
        token = self._issue_token(username, role, mfa_verified)
        self._log_auth(username, source_ip, True, mfa_verified, f"Authenticated as {role}")
        return AuthResult(True, username, role, token, mfa_verified, "Authentication successful.")

    def _issue_token(self, username: str, role: str, mfa_verified: bool) -> str:
        payload = {
            "sub": username,
            "role": role,
            "mfa": mfa_verified,
            "iat": int(time.time()),
            "exp": int(time.time()) + self.token_ttl_seconds,
        }
        payload_b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii")
        sig = hmac.new(self._signing_secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        return f"{payload_b64}.{sig}"

    def verify_token(self, token: str) -> dict[str, Any] | None:
        try:
            payload_b64, sig = token.split(".", 1)
        except ValueError:
            return None
        expected_sig = hmac.new(self._signing_secret, payload_b64.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        try:
            payload = json.loads(base64.urlsafe_b64decode(payload_b64.encode("ascii")).decode("utf-8"))
        except (ValueError, json.JSONDecodeError):
            return None
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload

    def authorize(self, token: str, permission: str, source_ip: str = "127.0.0.1") -> tuple[bool, str]:
        claims = self.verify_token(token)
        if not claims:
            if self.siem:
                self.siem.log("RBAC", "authorization_check", "HIGH", source_ip, "anonymous", "DENY", {"permission": permission, "reason": "Invalid or expired token"})
            return False, "Invalid or expired session token."

        role = str(claims.get("role", ""))
        username = str(claims.get("sub", "unknown"))
        role_perms = set(self.roles.get(role, {}).get("permissions", []))
        allowed = permission in role_perms
        if self.siem:
            self.siem.log(
                category="RBAC",
                event_type="authorization_check",
                severity="INFO" if allowed else "MEDIUM",
                source_ip=source_ip,
                actor=username,
                action="ALLOW" if allowed else "DENY",
                details={"role": role, "permission": permission},
            )
        if not allowed:
            return False, f"Role '{role}' is not authorized for '{permission}'."
        return True, f"Authorized ({role} -> {permission})."

    def _log_auth(self, username: str, source_ip: str, ok: bool, mfa: bool, reason: str) -> None:
        if self.siem:
            self.siem.log(
                category="AUTH",
                event_type="user_login",
                severity="INFO" if ok else "MEDIUM",
                source_ip=source_ip,
                actor=username,
                action="ALLOW" if ok else "DENY",
                details={"mfa_verified": mfa, "reason": reason},
            )
