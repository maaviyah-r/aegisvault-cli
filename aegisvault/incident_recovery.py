"""Incident Response handler and AES-256-GCM Encrypted Backup & Disaster Recovery manager."""

from __future__ import annotations

import base64
import datetime
import hashlib
import json
import os
import uuid
from pathlib import Path
from typing import Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .siem_logger import SIEMLogger


class IncidentResponseManager:
    """Manages security incident lifecycle (OPEN -> CONTAINED -> RESOLVED) for SOC operations."""

    def __init__(self, store_path: Path, siem: SIEMLogger | None = None) -> None:
        self.store_path = store_path
        self.store_path.parent.mkdir(parents=True, exist_ok=True)
        self.siem = siem
        self.incidents: list[dict[str, Any]] = self._load()

    def _load(self) -> list[dict[str, Any]]:
        if not self.store_path.exists():
            return []
        try:
            return json.loads(self.store_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return []

    def _save(self) -> None:
        self.store_path.write_text(json.dumps(self.incidents, indent=2), encoding="utf-8")

    def create_incident(
        self,
        title: str,
        severity: str,
        source_ip: str,
        category: str,
        containment_action: str,
    ) -> dict[str, Any]:
        inc = {
            "incident_id": f"INC-{uuid.uuid4().hex[:8].upper()}",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "title": title,
            "severity": severity.upper(),
            "source_ip": source_ip,
            "category": category.upper(),
            "status": "CONTAINED" if containment_action else "OPEN",
            "containment_action": containment_action,
            "resolved_at": None,
        }
        self.incidents.append(inc)
        self._save()
        if self.siem:
            self.siem.log("INCIDENT", "incident_created", severity, source_ip=source_ip, actor="soc-ir", action="CONTAIN", details=inc)
        return inc

    def resolve_incident(self, incident_id: str, notes: str = "Mitigated and verified.") -> bool:
        for inc in self.incidents:
            if inc["incident_id"] == incident_id:
                inc["status"] = "RESOLVED"
                inc["resolution_notes"] = notes
                inc["resolved_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
                self._save()
                if self.siem:
                    self.siem.log("INCIDENT", "incident_resolved", "INFO", actor="soc-ir", action="RESOLVE", details={"incident_id": incident_id, "notes": notes})
                return True
        return False


class BackupRecoveryManager:
    """Creates AES-256-GCM encrypted vault/config snapshots with SHA-256 integrity verification."""

    def __init__(self, backups_dir: Path, siem: SIEMLogger | None = None, passphrase: str | None = None) -> None:
        self.backups_dir = backups_dir
        self.backups_dir.mkdir(parents=True, exist_ok=True)
        self.siem = siem
        secret = passphrase or os.environ.get("AEGISVAULT_BACKUP_KEY", "AegisVault-DR-MasterKey-2026!")
        self._key = hashlib.sha256(secret.encode("utf-8")).digest()

    def create_backup(self, state_payload: dict[str, Any], label: str = "vault-snapshot") -> dict[str, Any]:
        ts = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        backup_id = f"{label}-{ts}-{uuid.uuid4().hex[:6]}"
        plaintext = json.dumps(state_payload, sort_keys=True, indent=2).encode("utf-8")
        plaintext_sha256 = hashlib.sha256(plaintext).hexdigest()

        nonce = os.urandom(12)
        aesgcm = AESGCM(self._key)
        aad = backup_id.encode("utf-8")
        ciphertext = aesgcm.encrypt(nonce, plaintext, aad)
        ciphertext_sha256 = hashlib.sha256(ciphertext).hexdigest()

        envelope = {
            "backup_id": backup_id,
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "algorithm": "AES-256-GCM",
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "ciphertext_sha256": ciphertext_sha256,
            "plaintext_sha256": plaintext_sha256,
            "size_bytes": len(ciphertext),
        }
        out_path = self.backups_dir / f"{backup_id}.enc.json"
        out_path.write_text(json.dumps(envelope, indent=2), encoding="utf-8")

        meta = {
            "backup_id": backup_id,
            "path": str(out_path),
            "created_at": envelope["created_at"],
            "algorithm": envelope["algorithm"],
            "ciphertext_sha256": ciphertext_sha256,
            "size_bytes": len(ciphertext),
        }
        if self.siem:
            self.siem.log("BACKUP", "backup_created", "INFO", actor="sysadmin", action="ALLOW", details=meta)
        return meta

    def verify_and_restore(self, backup_path: Path) -> tuple[bool, dict[str, Any] | str]:
        if not backup_path.exists():
            return False, f"Backup file not found: {backup_path}"
        try:
            envelope = json.loads(backup_path.read_text(encoding="utf-8"))
            backup_id = str(envelope["backup_id"])
            nonce = base64.b64decode(envelope["nonce"])
            ciphertext = base64.b64decode(envelope["ciphertext"])
            expected_ct_hash = str(envelope["ciphertext_sha256"])
            expected_pt_hash = str(envelope["plaintext_sha256"])
        except Exception as exc:
            return False, f"Invalid backup envelope: {exc}"

        if hashlib.sha256(ciphertext).hexdigest() != expected_ct_hash:
            if self.siem:
                self.siem.log("BACKUP", "backup_integrity_failed", "CRITICAL", actor="sysadmin", action="DENY", details={"backup_id": backup_id})
            return False, "Backup ciphertext SHA-256 integrity check failed (file tampered)."

        try:
            plaintext = AESGCM(self._key).decrypt(nonce, ciphertext, backup_id.encode("utf-8"))
        except Exception:
            return False, "AES-256-GCM decryption failed (wrong key or tampered data)."

        if hashlib.sha256(plaintext).hexdigest() != expected_pt_hash:
            return False, "Decrypted plaintext SHA-256 mismatch."

        restored = json.loads(plaintext.decode("utf-8"))
        if self.siem:
            self.siem.log("BACKUP", "backup_restored", "INFO", actor="sysadmin", action="ALLOW", details={"backup_id": backup_id})
        return True, restored

    def list_backups(self) -> list[dict[str, Any]]:
        results: list[dict[str, Any]] = []
        for fp in sorted(self.backups_dir.glob("*.enc.json")):
            try:
                env = json.loads(fp.read_text(encoding="utf-8"))
                results.append({
                    "backup_id": env.get("backup_id", fp.stem),
                    "created_at": env.get("created_at"),
                    "size_bytes": env.get("size_bytes", fp.stat().st_size),
                    "ciphertext_sha256": env.get("ciphertext_sha256"),
                    "path": str(fp),
                })
            except Exception:
                continue
        return results
