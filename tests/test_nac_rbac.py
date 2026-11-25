"""Unit tests for NAC device admission/quarantine and 6-role RBAC + MFA."""

from __future__ import annotations

from pathlib import Path

from aegisvault.config import CONFIG_DIR
from aegisvault.nac_rbac import NACEngine, RBACEngine
from aegisvault.siem_logger import SIEMLogger


def test_nac_admission_and_quarantine(tmp_path: Path) -> None:
    siem = SIEMLogger(tmp_path / "siem.jsonl")
    nac = NACEngine(CONFIG_DIR / "nac_registry.json", siem=siem)

    ok = nac.evaluate_device("ws-admin-01", "02:42:AC:10:00:10")
    assert ok.admitted
    assert ok.assigned_vlan == "VLAN-10-ADMIN"

    spoof = nac.evaluate_device("ws-admin-01", "DE:AD:BE:EF:00:01")
    assert not spoof.admitted
    assert spoof.assigned_vlan == "VLAN-99-QUARANTINE"

    unpatched = nac.evaluate_device("ws-unpatched-99", "02:42:AC:99:00:99")
    assert not unpatched.admitted
    assert unpatched.assigned_vlan == "VLAN-99-QUARANTINE"

    rogue = nac.evaluate_device("rogue-laptop-007", "AA:BB:CC:DD:EE:FF")
    assert not rogue.admitted
    assert rogue.assigned_vlan == "VLAN-99-QUARANTINE"


def test_rbac_mfa_and_least_privilege(tmp_path: Path) -> None:
    siem = SIEMLogger(tmp_path / "siem.jsonl")
    rbac = RBACEngine(CONFIG_DIR / "rbac_policy.json", users_db_path=tmp_path / "users.json", siem=siem)

    # Privileged user with MFA enforced fails without TOTP
    no_mfa = rbac.authenticate("secadmin", "AegisSec#2026!", enforce_mfa=True)
    assert not no_mfa.authenticated

    # Succeeds with valid TOTP
    code = rbac.get_current_totp("secadmin")
    ok_admin = rbac.authenticate("secadmin", "AegisSec#2026!", totp_code=code, enforce_mfa=True)
    assert ok_admin.authenticated and ok_admin.mfa_verified and ok_admin.token
    assert rbac.authorize(ok_admin.token, "ips:manage")[0]

    # End user has vault:read but NOT vault:write or ips:manage
    ok_user = rbac.authenticate("alice", "AegisUser#2026!")
    assert ok_user.authenticated and ok_user.token
    assert rbac.authorize(ok_user.token, "vault:read")[0]
    assert not rbac.authorize(ok_user.token, "vault:write")[0]
    assert not rbac.authorize(ok_user.token, "ips:manage")[0]
