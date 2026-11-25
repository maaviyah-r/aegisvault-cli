"""Unit tests for tamper-evident SIEM hash chain, 10 reports, incidents, and encrypted backup/restore."""

from __future__ import annotations

import json
from pathlib import Path

from aegisvault.incident_recovery import BackupRecoveryManager, IncidentResponseManager
from aegisvault.siem_logger import SIEMLogger


def test_siem_hash_chain_and_tamper_detection(tmp_path: Path) -> None:
    log_path = tmp_path / "siem.jsonl"
    siem = SIEMLogger(log_path)
    siem.log("AUTH", "user_login", "INFO", actor="secadmin", action="ALLOW")
    siem.log("IPS", "active_ip_ban", "CRITICAL", source_ip="198.51.100.5", action="BLOCK")

    ok, count, _ = siem.verify_chain()
    assert ok and count == 2

    reports = siem.generate_security_reports()
    assert len(reports) == 10

    # Tamper with line 1 and verify detection
    lines = log_path.read_text(encoding="utf-8").splitlines()
    tampered = json.loads(lines[0])
    tampered["actor"] = "attacker"
    lines[0] = json.dumps(tampered)
    log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

    ok_after, _, msg = siem.verify_chain()
    assert not ok_after
    assert "Tampering detected" in msg


def test_incidents_and_encrypted_backup_restore(tmp_path: Path) -> None:
    siem = SIEMLogger(tmp_path / "siem.jsonl")
    ir = IncidentResponseManager(tmp_path / "incidents.json", siem=siem)
    inc = ir.create_incident("DDoS Mitigated", "CRITICAL", "198.51.100.9", "IPS", "Banned IP")
    assert inc["status"] == "CONTAINED"
    assert ir.resolve_incident(inc["incident_id"])

    bak = BackupRecoveryManager(tmp_path / "backups", siem=siem)
    payload = {"vault_secrets": {"db_key": "super-secret"}, "policy": "v1"}
    meta = bak.create_backup(payload)
    backup_file = Path(meta["path"])
    assert backup_file.exists()

    ok, restored = bak.verify_and_restore(backup_file)
    assert ok and isinstance(restored, dict)
    assert restored["vault_secrets"]["db_key"] == "super-secret"

    # Tamper with ciphertext and verify rejection
    env = json.loads(backup_file.read_text(encoding="utf-8"))
    env["ciphertext"] = "AAAA" + env["ciphertext"][4:]
    backup_file.write_text(json.dumps(env), encoding="utf-8")
    ok_bad, _ = bak.verify_and_restore(backup_file)
    assert not ok_bad
