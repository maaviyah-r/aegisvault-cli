"""AegisVault CLI - Rich command-line interface for localhost & dual-container security operations."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from . import __version__
from .ai_auditor import OllamaThreatAuditor
from .config import DEFAULT_CONFIG
from .crypto_engine import PKIManager
from .incident_recovery import BackupRecoveryManager
from .ips_engine import ActiveIPSEngine
from .nac_rbac import NACEngine, RBACEngine
from .security_scanner import run_full_localhost_simulation, run_vulnerability_scan
from .siem_logger import SIEMLogger
from .vpn_tunnel import AegisGatewayClient, AegisVaultServer

console = Console()


def cmd_init(_args: argparse.Namespace) -> int:
    DEFAULT_CONFIG.ensure_runtime_dirs()
    pki = PKIManager(DEFAULT_CONFIG.certs_dir)
    bundle = pki.ensure_pki(force=bool(_args.force))
    siem = SIEMLogger(DEFAULT_CONFIG.logs_dir / "siem_events.jsonl")
    RBACEngine(DEFAULT_CONFIG.rbac_policy_path, users_db_path=DEFAULT_CONFIG.data_dir / "users.json", siem=siem)
    console.print(Panel.fit(
        f"[bold green]AegisVault CLI v{__version__} Initialized[/bold green]\n"
        f"CA Certificate     : {bundle.ca_cert}\n"
        f"Vault Server Cert  : {bundle.server_cert}\n"
        f"Gateway Client Cert: {bundle.client_cert}\n"
        f"Server Fingerprint : {pki.get_cert_fingerprint(bundle.server_cert)[:32]}...\n"
        f"Runtime Directory  : {DEFAULT_CONFIG.runtime_dir}",
        title="PKI & Runtime Bootstrap",
    ))
    return 0


def cmd_server(args: argparse.Namespace) -> int:
    async def _run() -> None:
        server = AegisVaultServer(config=DEFAULT_CONFIG, require_client_cert=not args.no_mtls)
        host, port = await server.start(host=args.host, port=args.port)
        console.print(Panel.fit(
            f"[bold cyan]AegisVault Core Server Listening[/bold cyan]\n"
            f"Endpoint  : [bold]{host}:{port}[/bold] (TLS + X25519 + AES-256-GCM)\n"
            f"mTLS Mode : {'REQUIRED' if not args.no_mtls else 'OPTIONAL'}\n"
            f"Ollama AI : {DEFAULT_CONFIG.ollama_url} (model={DEFAULT_CONFIG.ollama_model})\n"
            f"Press Ctrl+C to stop gracefully.",
            title="Vault Server Node",
        ))
        try:
            await server.serve_forever()
        except asyncio.CancelledError:
            pass
        finally:
            await server.stop()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[yellow]Vault Server stopped cleanly.[/yellow]")
    return 0


def cmd_client(args: argparse.Namespace) -> int:
    async def _run() -> int:
        client = AegisGatewayClient(config=DEFAULT_CONFIG)
        rbac = RBACEngine(DEFAULT_CONFIG.rbac_policy_path, users_db_path=DEFAULT_CONFIG.data_dir / "users.json")
        totp = args.totp
        if args.auto_mfa:
            totp = rbac.get_current_totp(args.user)

        hs = await client.connect(
            username=args.user,
            password=args.password,
            device_id=args.device,
            mac_address=args.mac,
            totp_code=totp,
            host=args.host,
            port=args.port,
        )
        if not hs.get("ok"):
            console.print(f"[bold red]Connection Rejected ({hs.get('code')}):[/bold red] {hs.get('error')}")
            return 1

        console.print(
            f"[green]Tunnel Established[/green] | Session={hs['session_id']} | "
            f"Role={hs['role']} | VLAN={hs['assigned_vlan']} | MFA={hs['mfa_verified']}"
        )

        kwargs: dict[str, object] = {}
        if args.key:
            kwargs["key"] = args.key
        if args.value:
            kwargs["value"] = args.value
        if args.message:
            kwargs["message"] = args.message
        if args.target_ip:
            kwargs["target_ip"] = args.target_ip

        resp = await client.send_command(args.action, **kwargs)
        await client.close()
        console.print_json(json.dumps(resp, indent=2, default=str))
        return 0 if resp.get("ok") else 1

    return asyncio.run(_run())


def cmd_demo(args: argparse.Namespace) -> int:
    console.print(Panel.fit(
        "[bold cyan]AegisVault CLI — Full Localhost Dual-Node Security Demonstration[/bold cyan]\n"
        "Running Vault Core + Edge Gateway on 127.0.0.1 with mTLS, AES-256-GCM, NAC/RBAC, Active IPS & Ollama qwen2.5 Audit...",
        title="Localhost E2E Demo",
    ))
    results = asyncio.run(run_full_localhost_simulation(config=DEFAULT_CONFIG, port=args.port))

    table = Table(title="End-to-End Security Verification Scenarios (localhost)")
    table.add_column("#", justify="right", style="cyan")
    table.add_column("Security Scenario", style="bold")
    table.add_column("Expected", style="magenta")
    table.add_column("Observed", style="green")
    table.add_column("Result")
    table.add_column("Details")

    for idx, sc in enumerate(results["scenarios"], start=1):
        badge = "[bold green]PASS[/bold green]" if sc["passed"] else "[bold red]FAIL[/bold red]"
        table.add_row(str(idx), sc["name"], str(sc["expected"]), str(sc["actual"]), badge, str(sc["detail"]))

    console.print(table)
    audit = results["ai_audit"]
    console.print(Panel(
        audit["analysis"],
        title=f"AI Threat Audit ({audit['engine']} | Risk={audit['overall_risk']})",
        border_style="cyan",
    ))

    if args.save_json:
        out_path = Path(args.save_json)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(json.dumps(results, indent=2, default=str), encoding="utf-8")
        console.print(f"[green]Saved complete simulation telemetry to {out_path}[/green]")

    return 0 if results["all_passed"] else 1


def cmd_nac(args: argparse.Namespace) -> int:
    nac = NACEngine(DEFAULT_CONFIG.nac_registry_path)
    if args.check_device:
        dec = nac.evaluate_device(args.check_device, args.mac or "")
        color = "green" if dec.admitted else "red"
        console.print(f"[{color}]{dec.reason}[/{color}] -> VLAN={dec.assigned_vlan}")
        return 0 if dec.admitted else 1

    table = Table(title="NAC Endpoint Registry & Posture Compliance")
    table.add_column("Device ID", style="cyan")
    table.add_column("Hostname")
    table.add_column("MAC Address")
    table.add_column("VLAN", style="magenta")
    table.add_column("Posture", justify="right")
    table.add_column("Status")
    for dev_id, info in nac.devices.items():
        st = f"[green]{info['status']}[/green]" if info["status"] == "APPROVED" else f"[red]{info['status']}[/red]"
        table.add_row(dev_id, info["hostname"], info["mac_address"], info["assigned_vlan"], str(info["posture_score"]), st)
    console.print(table)
    return 0


def cmd_rbac(args: argparse.Namespace) -> int:
    rbac = RBACEngine(DEFAULT_CONFIG.rbac_policy_path, users_db_path=DEFAULT_CONFIG.data_dir / "users.json")
    if args.totp_user:
        console.print(f"Current RFC 6238 TOTP for [bold]{args.totp_user}[/bold]: [bold green]{rbac.get_current_totp(args.totp_user)}[/bold green]")
        return 0

    table = Table(title="RBAC Roles & Least-Privilege Permissions Matrix")
    table.add_column("Role", style="cyan bold")
    table.add_column("Description")
    table.add_column("Permissions", style="green")
    for role, meta in rbac.roles.items():
        table.add_row(role, meta["description"], ", ".join(meta["permissions"]))
    console.print(table)
    return 0


def cmd_firewall(_args: argparse.Namespace) -> int:
    ips = ActiveIPSEngine(DEFAULT_CONFIG.policy_path)
    table = Table(title=f"Network Security Policy Rules (v{ips.policy_version} — {len(ips.firewall_rules)} Rules)")
    table.add_column("Rule ID", style="cyan bold")
    table.add_column("Name")
    table.add_column("Source -> Dest")
    table.add_column("Proto/Port")
    table.add_column("Action", style="magenta")
    for r in ips.firewall_rules:
        table.add_row(r["rule_id"], r["name"], f"{r['zone_src']} -> {r['zone_dst']}", f"{r['protocol']}/{r['port']}", r["action"])
    console.print(table)
    return 0


def cmd_siem(args: argparse.Namespace) -> int:
    siem = SIEMLogger(DEFAULT_CONFIG.logs_dir / "siem_events.jsonl")
    ok, count, msg = siem.verify_chain()
    summary = siem.summarize()
    color = "green" if ok else "red"
    console.print(Panel.fit(
        f"[{color}]{msg}[/{color}]\n"
        f"Total Events : {summary['total_events']}\n"
        f"By Category  : {summary['by_category']}\n"
        f"By Severity  : {summary['by_severity']}\n"
        f"By Action    : {summary['by_action']}",
        title="SIEM Hash-Chain & Telemetry Summary",
    ))
    if args.tail:
        for ev in siem.read_events(limit=args.tail):
            console.print(f"{ev['timestamp']} [{ev['severity']}] {ev['category']}/{ev['event_type']} {ev['source_ip']} -> {ev['action']}")
    return 0 if ok else 1


def cmd_audit(args: argparse.Namespace) -> int:
    siem = SIEMLogger(DEFAULT_CONFIG.logs_dir / "siem_events.jsonl")
    auditor = OllamaThreatAuditor(
        ollama_url=args.ollama_url or DEFAULT_CONFIG.ollama_url,
        model=args.model or DEFAULT_CONFIG.ollama_model,
    )
    res = auditor.audit_siem(siem, force_heuristic=args.offline)
    console.print(Panel(res["analysis"], title=f"Ollama Threat Audit ({res['engine']} | Risk={res['overall_risk']})", border_style="cyan"))
    return 0


def cmd_scan(args: argparse.Namespace) -> int:
    report = run_vulnerability_scan(host=args.host, config=DEFAULT_CONFIG)
    table = Table(title=f"Localhost Vulnerability & Config Assessment ({report['target_host']})")
    table.add_column("ID", style="cyan")
    table.add_column("Severity")
    table.add_column("Finding")
    table.add_column("Status")
    table.add_column("Recommendation")
    for f in report["findings"]:
        table.add_row(f["id"], f["severity"], f["title"], f["status"], f["recommendation"])
    console.print(table)
    console.print(f"Open scanned ports: {report['open_ports']}")
    return 0


def cmd_backup(args: argparse.Namespace) -> int:
    siem = SIEMLogger(DEFAULT_CONFIG.logs_dir / "siem_events.jsonl")
    mgr = BackupRecoveryManager(DEFAULT_CONFIG.backups_dir, siem=siem)
    if args.create:
        vault_file = DEFAULT_CONFIG.data_dir / "vault_store.json"
        secrets = json.loads(vault_file.read_text(encoding="utf-8")) if vault_file.exists() else {}
        meta = mgr.create_backup({"vault_secrets": secrets, "policy_version": "1.0.0"})
        console.print(f"[green]Encrypted AES-256-GCM backup created:[/green] {meta['path']}")
        return 0
    if args.verify:
        ok, res = mgr.verify_and_restore(Path(args.verify))
        if ok:
            console.print(f"[green]Backup integrity verified & decrypted cleanly![/green] Keys: {list(res.keys())}")
            return 0
        console.print(f"[red]Backup verification failed:[/red] {res}")
        return 1

    table = Table(title="Encrypted Vault Backups (AES-256-GCM)")
    table.add_column("Backup ID", style="cyan")
    table.add_column("Created At")
    table.add_column("Size (B)", justify="right")
    table.add_column("SHA-256 Prefix")
    for b in mgr.list_backups():
        table.add_row(b["backup_id"], str(b["created_at"]), str(b["size_bytes"]), str(b["ciphertext_sha256"])[:24] + "...")
    console.print(table)
    return 0


def cmd_reports(args: argparse.Namespace) -> int:
    siem = SIEMLogger(DEFAULT_CONFIG.logs_dir / "siem_events.jsonl")
    ips = ActiveIPSEngine(DEFAULT_CONFIG.policy_path)
    backups = BackupRecoveryManager(DEFAULT_CONFIG.backups_dir).list_backups()
    vuln = run_vulnerability_scan(config=DEFAULT_CONFIG)
    reports = siem.generate_security_reports(ips_stats=ips.get_stats(), vuln_findings=vuln["findings"], backups=backups)
    out = Path(args.output or (DEFAULT_CONFIG.reports_dir / "security_reports.json"))
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(reports, indent=2, default=str), encoding="utf-8")
    console.print(f"[green]Exported all 10 required security reports to {out}[/green]")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="aegisvault",
        description="AegisVault CLI — Dual-container & localhost network security suite (TLS/AES-GCM mini-VPN, NAC/RBAC, Active IPS, Ollama qwen2.5 AI Auditing).",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    p_init = sub.add_parser("init", help="Bootstrap local mTLS PKI certificates and runtime folders")
    p_init.add_argument("--force", action="store_true", help="Regenerate all certificates")
    p_init.set_defaults(func=cmd_init)

    p_srv = sub.add_parser("server", help="Start Vault Core Server on localhost (or container)")
    p_srv.add_argument("--host", default=DEFAULT_CONFIG.vault_host)
    p_srv.add_argument("--port", type=int, default=DEFAULT_CONFIG.vault_port)
    p_srv.add_argument("--no-mtls", action="store_true", help="Make client mTLS certificate optional")
    p_srv.set_defaults(func=cmd_server)

    p_cli = sub.add_parser("client", help="Connect Edge Gateway Client over TLS/AES-256-GCM tunnel")
    p_cli.add_argument("action", choices=["ping", "relay", "vault_put", "vault_get", "vault_list", "vault_delete", "ips_status", "ips_unban", "siem_summary", "ai_audit", "backup_create", "reports_export"])
    p_cli.add_argument("--host", default=DEFAULT_CONFIG.vault_host)
    p_cli.add_argument("--port", type=int, default=DEFAULT_CONFIG.vault_port)
    p_cli.add_argument("--user", default="secadmin")
    p_cli.add_argument("--password", default="AegisSec#2026!")
    p_cli.add_argument("--device", default="ws-admin-01")
    p_cli.add_argument("--mac", default="02:42:AC:10:00:10")
    p_cli.add_argument("--totp", default=None)
    p_cli.add_argument("--auto-mfa", action="store_true")
    p_cli.add_argument("--key", default=None)
    p_cli.add_argument("--value", default=None)
    p_cli.add_argument("--message", default=None)
    p_cli.add_argument("--target-ip", default=None)
    p_cli.set_defaults(func=cmd_client)

    p_demo = sub.add_parser("demo", help="Run full localhost dual-node security & attack simulation demo")
    p_demo.add_argument("--port", type=int, default=0, help="Port to bind Vault server (0=auto free localhost port)")
    p_demo.add_argument("--save-json", default=None, help="Optional path to export full simulation telemetry JSON")
    p_demo.set_defaults(func=cmd_demo)

    p_nac = sub.add_parser("nac", help="Inspect NAC endpoint registry or test admission")
    p_nac.add_argument("--check-device", default=None)
    p_nac.add_argument("--mac", default=None)
    p_nac.set_defaults(func=cmd_nac)

    p_rbac = sub.add_parser("rbac", help="Display RBAC role-permission matrix or generate user TOTP")
    p_rbac.add_argument("--totp-user", default=None)
    p_rbac.set_defaults(func=cmd_rbac)

    p_fw = sub.add_parser("firewall", help="Display all Network Security Policy firewall ACL rules")
    p_fw.set_defaults(func=cmd_firewall)

    p_siem = sub.add_parser("siem", help="Verify SIEM SHA-256 hash chain and inspect recent events")
    p_siem.add_argument("--tail", type=int, default=0)
    p_siem.set_defaults(func=cmd_siem)

    p_aud = sub.add_parser("audit", help="Run local Ollama (qwen2.5) AI Threat Audit on SIEM logs")
    p_aud.add_argument("--model", default=DEFAULT_CONFIG.ollama_model)
    p_aud.add_argument("--ollama-url", default=DEFAULT_CONFIG.ollama_url)
    p_aud.add_argument("--offline", action="store_true", help="Force local heuristic fallback")
    p_aud.set_defaults(func=cmd_audit)

    p_scan = sub.add_parser("scan", help="Run localhost port scan and security configuration audit")
    p_scan.add_argument("--host", default="127.0.0.1")
    p_scan.set_defaults(func=cmd_scan)

    p_bak = sub.add_parser("backup", help="Manage AES-256-GCM encrypted vault backups")
    p_bak.add_argument("--create", action="store_true")
    p_bak.add_argument("--verify", default=None)
    p_bak.set_defaults(func=cmd_backup)

    p_rep = sub.add_parser("reports", help="Export all 10 CCP security reports as JSON")
    p_rep.add_argument("--output", default=None)
    p_rep.set_defaults(func=cmd_reports)

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
