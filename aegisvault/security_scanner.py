"""Localhost Vulnerability Assessment, Configuration Audit, and Active Attack Simulation Suite."""

from __future__ import annotations

import asyncio
import base64
import socket
import time
from typing import Any

from .config import AegisConfig, DEFAULT_CONFIG
from .vpn_tunnel import AegisGatewayClient, AegisVaultServer


def run_vulnerability_scan(host: str = "127.0.0.1", ports: list[int] | None = None, config: AegisConfig = DEFAULT_CONFIG) -> dict[str, Any]:
    """Scan local service ports and audit TLS, NAC, RBAC, and IPS configuration posture."""
    target_ports = ports or [21, 22, 23, 80, 443, 8443, 8444, 11434]
    open_ports: list[int] = []
    for port in target_ports:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((host, port)) == 0:
                open_ports.append(port)

    findings: list[dict[str, Any]] = []
    insecure_open = [p for p in open_ports if p in (21, 23, 80)]
    if insecure_open:
        findings.append({
            "id": "VULN-01",
            "severity": "HIGH",
            "title": f"Insecure Cleartext Ports Open: {insecure_open}",
            "status": "OPEN",
            "recommendation": "Disable FTP/Telnet/HTTP and enforce Firewall Rule NSR-02.",
        })
    else:
        findings.append({
            "id": "VULN-01",
            "severity": "INFO",
            "title": "No Cleartext Legacy Ports (21/23/80) Exposed on Localhost",
            "status": "PASS",
            "recommendation": "Maintain default-deny policy NSR-15.",
        })

    certs_ready = all((config.certs_dir / name).exists() for name in ("ca.crt", "vault.crt", "gateway.crt"))
    findings.append({
        "id": "VULN-02",
        "severity": "INFO" if certs_ready else "MEDIUM",
        "title": "Mutual TLS (ECDSA P-256) PKI Certificates Provisioned",
        "status": "PASS" if certs_ready else "WARN",
        "recommendation": "Rotate CA & node certificates annually and keep private keys protected.",
    })

    policy_exists = config.policy_path.exists() and config.nac_registry_path.exists() and config.rbac_policy_path.exists()
    findings.append({
        "id": "VULN-03",
        "severity": "INFO" if policy_exists else "CRITICAL",
        "title": "Security Policy, NAC Registry & 6-Role RBAC Baseline Loaded",
        "status": "PASS" if policy_exists else "FAIL",
        "recommendation": "Audit policy files via SHA-256 backup manifests.",
    })

    ollama_open = 11434 in open_ports
    findings.append({
        "id": "VULN-04",
        "severity": "INFO",
        "title": f"Local Ollama AI Binding (127.0.0.1:11434) Status: {'ONLINE' if ollama_open else 'OFFLINE (Fallback Ready)'}",
        "status": "PASS",
        "recommendation": "Keep Ollama bound strictly to 127.0.0.1 (NSR-11) to prevent log exfiltration.",
    })

    return {
        "target_host": host,
        "ports_scanned": target_ports,
        "open_ports": open_ports,
        "findings": findings,
    }


async def run_full_localhost_simulation(config: AegisConfig = DEFAULT_CONFIG, port: int = 0) -> dict[str, Any]:
    """Run an end-to-end localhost dual-node security & attack simulation and collect real metrics."""
    server = AegisVaultServer(config=config, require_client_cert=True)
    host, actual_port = await server.start(host="127.0.0.1", port=port)

    results: dict[str, Any] = {
        "host": host,
        "port": actual_port,
        "scenarios": [],
        "latency_ms": [],
    }

    try:
        # Scenario 1: Legitimate mTLS + NAC + RBAC + TOTP MFA + AES-256-GCM Tunnel + Latency Benchmark
        totp = server.rbac.get_current_totp("secadmin")
        client = AegisGatewayClient(config=config)
        t0 = time.perf_counter()
        hs = await client.connect(
            username="secadmin",
            password="AegisSec#2026!",
            totp_code=totp,
            enforce_mfa=True,
            device_id="ws-admin-01",
            mac_address="02:42:AC:10:00:10",
            host=host,
            port=actual_port,
            simulated_source_ip="10.10.10.10",
        )
        handshake_ms = round((time.perf_counter() - t0) * 1000, 2)
        assert hs.get("ok"), f"Legitimate handshake failed: {hs}"

        for i in range(10):
            ts = time.perf_counter()
            pong = await client.send_command("ping")
            assert pong.get("ok")
            results["latency_ms"].append(round((time.perf_counter() - ts) * 1000, 3))

        put_res = await client.send_command("vault_put", key="db_master_secret", value="AES256-Protected-Campus-Key")
        get_res = await client.send_command("vault_get", key="db_master_secret")
        relay_res = await client.send_command("relay", message="Encrypted telemetry packet via AegisVault Mini-VPN")
        backup_res = await client.send_command("backup_create")
        await client.close()

        results["handshake_ms"] = handshake_ms
        results["avg_tunnel_rtt_ms"] = round(sum(results["latency_ms"]) / len(results["latency_ms"]), 3)
        results["scenarios"].append({
            "name": "Legitimate mTLS + MFA + AES-256-GCM Tunnel",
            "expected": "ALLOW",
            "actual": "ALLOW" if (put_res.get("ok") and get_res.get("value") == "AES256-Protected-Campus-Key" and relay_res.get("ok")) else "FAIL",
            "passed": bool(put_res.get("ok") and get_res.get("value") == "AES256-Protected-Campus-Key" and backup_res.get("ok")),
            "detail": f"Handshake={handshake_ms}ms, Avg RTT={results['avg_tunnel_rtt_ms']}ms, Backup={backup_res.get('backup', {}).get('backup_id')}",
        })

        # Scenario 2: NAC Quarantine (Unpatched / Rogue MAC Device)
        c_nac = AegisGatewayClient(config=config)
        nac_reply = await c_nac.connect(
            username="alice",
            password="AegisUser#2026!",
            device_id="ws-unpatched-99",
            mac_address="02:42:AC:99:00:99",
            host=host,
            port=actual_port,
            simulated_source_ip="10.10.99.99",
        )
        results["scenarios"].append({
            "name": "NAC Non-Compliant Endpoint Quarantine",
            "expected": "QUARANTINE",
            "actual": nac_reply.get("code"),
            "passed": nac_reply.get("code") == "NAC_QUARANTINED",
            "detail": nac_reply.get("error"),
        })

        # Scenario 3: RBAC Privilege Escalation Attempt (end_user tries vault_put)
        c_rbac = AegisGatewayClient(config=config)
        hs_user = await c_rbac.connect(
            username="alice",
            password="AegisUser#2026!",
            device_id="ws-corp-01",
            mac_address="02:42:AC:20:00:25",
            host=host,
            port=actual_port,
            simulated_source_ip="10.10.20.25",
        )
        esc_res = await c_rbac.send_command("vault_put", key="rogue", value="unauthorized")
        await c_rbac.close()
        results["scenarios"].append({
            "name": "RBAC Privilege Escalation Prevention",
            "expected": "RBAC_DENIED",
            "actual": esc_res.get("code"),
            "passed": bool(hs_user.get("ok") and esc_res.get("code") == "RBAC_DENIED"),
            "detail": esc_res.get("error"),
        })

        # Scenario 4: Credential Brute-Force Attack -> Active IPS Lockout
        bf_code = None
        for _ in range(4):
            c_bf = AegisGatewayClient(config=config)
            r = await c_bf.connect(
                username="secadmin",
                password="WrongPassword!",
                device_id="gw-edge-01",
                mac_address="02:42:AC:14:00:02",
                host=host,
                port=actual_port,
                simulated_source_ip="192.168.50.101",
            )
            bf_code = r.get("code")
        results["scenarios"].append({
            "name": "Credential Brute-Force Active IPS Lockout",
            "expected": "IPS_LOCKOUT",
            "actual": bf_code,
            "passed": bf_code == "IPS_LOCKOUT",
            "detail": "4 failed logins triggered NSR-08 active IP ban on 192.168.50.101",
        })

        # Scenario 5: Deep Payload Inspection (SQL Injection inside encrypted tunnel)
        c_dpi = AegisGatewayClient(config=config)
        await c_dpi.connect(
            username="secadmin",
            password="AegisSec#2026!",
            device_id="gw-edge-01",
            mac_address="02:42:AC:14:00:02",
            host=host,
            port=actual_port,
            simulated_source_ip="192.168.50.102",
        )
        dpi_res = await c_dpi.send_command("relay", message="admin' UNION SELECT password FROM users; DROP TABLE secrets;--")
        await c_dpi.close()
        results["scenarios"].append({
            "name": "Active IPS Deep Payload Inspection (SQLi)",
            "expected": "IPS_DPI_BLOCK",
            "actual": dpi_res.get("code"),
            "passed": dpi_res.get("code") == "IPS_DPI_BLOCK",
            "detail": dpi_res.get("error"),
        })

        # Scenario 6: MITM AES-256-GCM Ciphertext Tampering Detection
        c_mitm = AegisGatewayClient(config=config)
        await c_mitm.connect(
            username="analyst",
            password="AegisSoc#2026!",
            device_id="ws-analyst-01",
            mac_address="02:42:AC:20:00:15",
            host=host,
            port=actual_port,
            simulated_source_ip="192.168.50.103",
        )
        assert c_mitm.cipher is not None
        frame = c_mitm.cipher.encrypt_frame({"command": "ping"}, direction="c2s")
        raw_ct = bytearray(base64.b64decode(frame["ciphertext"]))
        raw_ct[0] ^= 0xFF  # Flip bits to simulate MITM tampering
        frame["ciphertext"] = base64.b64encode(bytes(raw_ct)).decode("ascii")
        tamper_res = await c_mitm.send_raw_frame(frame)
        await c_mitm.close()
        results["scenarios"].append({
            "name": "MITM AES-256-GCM Tamper Detection & Ban",
            "expected": "TAMPER_DETECTED",
            "actual": tamper_res.get("code"),
            "passed": tamper_res.get("code") == "TAMPER_DETECTED",
            "detail": tamper_res.get("error"),
        })

        # Scenario 7: Replay Attack Detection
        c_rep = AegisGatewayClient(config=config)
        await c_rep.connect(
            username="analyst",
            password="AegisSoc#2026!",
            device_id="ws-analyst-01",
            mac_address="02:42:AC:20:00:15",
            host=host,
            port=actual_port,
            simulated_source_ip="192.168.50.104",
        )
        assert c_rep.cipher is not None
        legit_frame = c_rep.cipher.encrypt_frame({"command": "ping"}, direction="c2s")
        first_reply = await c_rep.send_raw_frame(legit_frame)
        replay_reply = await c_rep.send_raw_frame(legit_frame)  # Send exact same frame again!
        await c_rep.close()
        results["scenarios"].append({
            "name": "VPN Tunnel Replay Attack Defense",
            "expected": "REPLAY_DETECTED",
            "actual": replay_reply.get("code"),
            "passed": bool("ciphertext" in first_reply and replay_reply.get("code") == "REPLAY_DETECTED"),
            "detail": replay_reply.get("error"),
        })

        # Scenario 8: DoS / DDoS Flood Rate-Limiting & Active Ban
        c_dos = AegisGatewayClient(config=config)
        await c_dos.connect(
            username="analyst",
            password="AegisSoc#2026!",
            device_id="ws-analyst-01",
            mac_address="02:42:AC:20:00:15",
            host=host,
            port=actual_port,
            simulated_source_ip="192.168.50.105",
        )
        dos_code = None
        for _ in range(28):
            r = await c_dos.send_command("ping")
            if not r.get("ok"):
                dos_code = r.get("code")
                break
        await c_dos.close()
        results["scenarios"].append({
            "name": "DoS/DDoS Flood Rate-Limiting & Active Ban",
            "expected": "IPS_RATE_LIMIT",
            "actual": dos_code,
            "passed": dos_code == "IPS_RATE_LIMIT",
            "detail": "Rate limiter halted flood at >25 reqs/10s and banned 192.168.50.105",
        })

        # Scenario 9: Firewall Cleartext Protocol & Quarantine Escape Denial
        fw_telnet = server.ips.evaluate_firewall("VLAN-20-CORP", "VLAN-40-VAULT", "TCP", 23, source_ip="10.10.20.99")
        fw_escape = server.ips.evaluate_firewall("VLAN-99-QUARANTINE", "VLAN-40-VAULT", "TCP", 8443, source_ip="10.10.99.99")
        results["scenarios"].append({
            "name": "Firewall Cleartext (Telnet) & Quarantine Isolation",
            "expected": "DENY",
            "actual": "DENY" if (not fw_telnet.allowed and not fw_escape.allowed) else "ALLOW",
            "passed": (not fw_telnet.allowed and not fw_escape.allowed),
            "detail": f"Telnet={fw_telnet.rule_id}, QuarantineEscape={fw_escape.rule_id}",
        })

        # Scenario 10: Local Ollama (qwen2.5) AI Threat Audit + SIEM Integrity + Backup Restore
        audit = server.auditor.audit_siem(server.siem)
        chain_ok, chain_cnt, chain_msg = server.siem.verify_chain()
        backups = server.backups.list_backups()
        restore_ok, _ = server.backups.verify_and_restore(
            config.backups_dir / f"{backups[-1]['backup_id']}.enc.json"
        ) if backups else (False, "no backup")

        results["ai_audit"] = audit
        results["siem_summary"] = server.siem.summarize()
        results["ips_stats"] = server.ips.get_stats()
        results["vuln_scan"] = run_vulnerability_scan(host="127.0.0.1", config=config)
        results["reports"] = server.siem.generate_security_reports(
            ips_stats=results["ips_stats"],
            vuln_findings=results["vuln_scan"]["findings"],
            incidents=server.incidents.incidents,
            backups=backups,
        )
        results["scenarios"].append({
            "name": "SIEM Hash-Chain + Ollama AI Audit + Encrypted Backup Restore",
            "expected": "PASS",
            "actual": "PASS" if (chain_ok and restore_ok and audit.get("overall_risk")) else "FAIL",
            "passed": bool(chain_ok and restore_ok and audit.get("overall_risk")),
            "detail": f"SIEM={chain_cnt} records intact | Audit engine={audit.get('engine')} | Backup restore={restore_ok}",
        })

    finally:
        await server.stop()

    results["all_passed"] = all(s["passed"] for s in results["scenarios"])
    return results
