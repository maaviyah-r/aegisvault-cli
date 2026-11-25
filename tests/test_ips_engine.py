"""Unit tests for Stateful Firewall ACLs and Active IPS threat prevention."""

from __future__ import annotations

from pathlib import Path

from aegisvault.config import CONFIG_DIR
from aegisvault.ips_engine import ActiveIPSEngine
from aegisvault.siem_logger import SIEMLogger


def test_firewall_rules_and_quarantine(tmp_path: Path) -> None:
    siem = SIEMLogger(tmp_path / "siem.jsonl")
    ips = ActiveIPSEngine(CONFIG_DIR / "security_policy.json", siem=siem)

    assert len(ips.firewall_rules) >= 15
    assert ips.evaluate_firewall("VLAN-30-DMZ", "VLAN-40-VAULT", "TLS-VPN", 8443).allowed
    assert not ips.evaluate_firewall("VLAN-20-CORP", "VLAN-40-VAULT", "TCP", 23).allowed
    assert not ips.evaluate_firewall("VLAN-99-QUARANTINE", "VLAN-40-VAULT", "TCP", 8443).allowed
    assert not ips.evaluate_firewall("VLAN-20-CORP", "VLAN-40-VAULT", "TCP", 9999).allowed


def test_ips_rate_limit_bruteforce_portscan_and_dpi(tmp_path: Path) -> None:
    siem = SIEMLogger(tmp_path / "siem.jsonl")
    ips = ActiveIPSEngine(CONFIG_DIR / "security_policy.json", siem=siem)

    # DDoS flood ban
    for i in range(26):
        verdict = ips.check_rate_limit("198.51.100.10", now=1000.0 + i * 0.01)
    assert not verdict.allowed and verdict.threat_type == "DDOS_FLOOD"
    assert ips.is_banned("198.51.100.10")[0]

    # Manual unban
    assert ips.unban_ip("198.51.100.10")
    assert not ips.is_banned("198.51.100.10")[0]

    # Brute force lockout
    for _ in range(4):
        bf = ips.record_auth_failure("198.51.100.11", "secadmin", now=2000.0)
    assert not bf.allowed and bf.threat_type == "BRUTE_FORCE"

    # Port scan detection
    for p in (22, 80, 443, 3306, 8080):
        ps = ips.record_port_probe("198.51.100.12", p)
    assert not ps.allowed and ps.threat_type == "PORT_SCAN"

    # DPI payload inspection
    assert ips.inspect_payload("Normal encrypted heartbeat payload", source_ip="10.10.20.1").allowed
    sqli = ips.inspect_payload("SELECT * FROM vault WHERE id=1 OR 1=1;--", source_ip="198.51.100.13")
    assert not sqli.allowed and sqli.threat_type == "SQL_INJECTION"
    cmdi = ips.inspect_payload("ping; rm -rf /", source_ip="198.51.100.14")
    assert not cmdi.allowed and cmdi.threat_type == "COMMAND_INJECTION"
