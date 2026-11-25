"""Dual-node asyncio mTLS + X25519/HKDF + AES-256-GCM Mini-VPN Tunnel Server (Vault) & Client (Gateway)."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import struct
import time
import uuid
from pathlib import Path
from typing import Any

from .ai_auditor import OllamaThreatAuditor
from .config import AegisConfig, DEFAULT_CONFIG
from .crypto_engine import (
    ECDHEKeyExchange,
    PKIManager,
    ReplayAttackError,
    TamperDetectedError,
    TunnelCipher,
)
from .incident_recovery import BackupRecoveryManager, IncidentResponseManager
from .ips_engine import ActiveIPSEngine
from .nac_rbac import NACEngine, RBACEngine
from .siem_logger import SIEMLogger

MAX_FRAME_WIRE_BYTES = 262_144  # 256 KB hard wire cap


async def _write_json_frame(writer: asyncio.StreamWriter, obj: dict[str, Any]) -> int:
    data = json.dumps(obj, separators=(",", ":")).encode("utf-8")
    header = struct.pack(">I", len(data))
    writer.write(header + data)
    await writer.drain()
    return len(data)


async def _read_json_frame(reader: asyncio.StreamReader) -> dict[str, Any]:
    header = await reader.readexactly(4)
    (length,) = struct.unpack(">I", header)
    if length <= 0 or length > MAX_FRAME_WIRE_BYTES:
        raise ValueError(f"Frame size {length} outside permitted bounds.")
    raw = await reader.readexactly(length)
    return json.loads(raw.decode("utf-8"))


class AegisVaultServer:
    """Vault Core Node (Container 1 / localhost:8443): mTLS + AES-GCM VPN + NAC/RBAC + Active IPS + SIEM + Ollama Audit."""

    def __init__(self, config: AegisConfig = DEFAULT_CONFIG, require_client_cert: bool = True) -> None:
        self.config = config
        self.config.ensure_runtime_dirs()
        self.require_client_cert = require_client_cert

        self.pki = PKIManager(self.config.certs_dir)
        self.pki.ensure_pki()
        self.siem = SIEMLogger(self.config.logs_dir / "siem_events.jsonl")
        self.nac = NACEngine(self.config.nac_registry_path, siem=self.siem)
        self.rbac = RBACEngine(
            self.config.rbac_policy_path,
            users_db_path=self.config.data_dir / "users.json",
            siem=self.siem,
        )
        self.ips = ActiveIPSEngine(self.config.policy_path, siem=self.siem)
        self.auditor = OllamaThreatAuditor(
            ollama_url=self.config.ollama_url,
            model=self.config.ollama_model,
            timeout=self.config.ollama_timeout,
        )
        self.incidents = IncidentResponseManager(self.config.data_dir / "incidents.json", siem=self.siem)
        self.backups = BackupRecoveryManager(self.config.backups_dir, siem=self.siem)

        self.vault_store_path = self.config.data_dir / "vault_store.json"
        self.vault_secrets: dict[str, dict[str, Any]] = self._load_vault_store()

        self._server: asyncio.AbstractServer | None = None
        self.started_at: float = time.time()
        self.active_sessions: dict[str, dict[str, Any]] = {}
        self.bound_port: int = self.config.vault_port

    def _load_vault_store(self) -> dict[str, dict[str, Any]]:
        if not self.vault_store_path.exists():
            return {}
        try:
            return json.loads(self.vault_store_path.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            return {}

    def _save_vault_store(self) -> None:
        self.vault_store_path.write_text(json.dumps(self.vault_secrets, indent=2), encoding="utf-8")

    async def start(self, host: str | None = None, port: int | None = None) -> tuple[str, int]:
        bind_host = host or self.config.vault_host
        bind_port = self.config.vault_port if port is None else port
        ssl_ctx = self.pki.build_server_ssl_context(require_client_cert=self.require_client_cert)
        self._server = await asyncio.start_server(self._handle_client, bind_host, bind_port, ssl=ssl_ctx)
        sockets = self._server.sockets
        if sockets:
            self.bound_port = int(sockets[0].getsockname()[1])
        self.started_at = time.time()
        self.siem.log(
            category="VPN",
            event_type="vault_server_started",
            severity="INFO",
            source_ip=bind_host,
            actor="aegisvault-server",
            action="ALLOW",
            details={"host": bind_host, "port": self.bound_port, "mtls_required": self.require_client_cert},
        )
        return bind_host, self.bound_port

    async def stop(self) -> None:
        if self._server is not None:
            self._server.close()
            await self._server.wait_closed()
            self._server = None
            self.siem.log("VPN", "vault_server_stopped", "INFO", actor="aegisvault-server", action="ALLOW")

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        assert self._server is not None
        async with self._server:
            await self._server.serve_forever()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        peer_ip = str(peer[0]) if peer else "127.0.0.1"
        session_id = ""

        try:
            hello = await asyncio.wait_for(_read_json_frame(reader), timeout=10.0)
            # Support simulated client source_ip for multi-source localhost testing while defaulting to peer_ip
            effective_ip = str(hello.get("simulated_source_ip") or peer_ip)

            # 1. IPS Ban & Rate Limit Check
            rate_verdict = self.ips.check_rate_limit(effective_ip)
            if not rate_verdict.allowed:
                self.incidents.create_incident(
                    title=f"IPS Blocked Connection ({rate_verdict.threat_type})",
                    severity=rate_verdict.severity,
                    source_ip=effective_ip,
                    category="IPS",
                    containment_action="Dropped connection and enforced active IP ban",
                )
                await _write_json_frame(writer, {"ok": False, "code": "IPS_BLOCKED", "error": rate_verdict.reason})
                return

            if hello.get("type") != "handshake":
                await _write_json_frame(writer, {"ok": False, "code": "BAD_HANDSHAKE", "error": "Expected handshake frame."})
                return

            # 2. NAC Device Admission Check
            device_id = str(hello.get("device_id", ""))
            mac_address = str(hello.get("mac_address", ""))
            nac_decision = self.nac.evaluate_device(device_id, mac_address, source_ip=effective_ip)
            if not nac_decision.admitted:
                self.incidents.create_incident(
                    title=f"NAC Device Quarantined: {device_id}",
                    severity="HIGH",
                    source_ip=effective_ip,
                    category="NAC",
                    containment_action=f"Assigned {device_id} to {nac_decision.assigned_vlan}",
                )
                await _write_json_frame(writer, {
                    "ok": False,
                    "code": "NAC_QUARANTINED",
                    "assigned_vlan": nac_decision.assigned_vlan,
                    "error": nac_decision.reason,
                })
                return

            # 3. Firewall Zone Policy Check
            fw_verdict = self.ips.evaluate_firewall(
                src_zone=nac_decision.assigned_vlan,
                dst_zone="VLAN-40-VAULT",
                protocol="TLS-VPN",
                port=8443,
                source_ip=effective_ip,
            )
            if not fw_verdict.allowed:
                await _write_json_frame(writer, {"ok": False, "code": "FIREWALL_DENY", "error": fw_verdict.reason})
                return

            # 4. RBAC Authentication (+ TOTP MFA)
            username = str(hello.get("username", ""))
            password = str(hello.get("password", ""))
            totp_code = hello.get("totp_code")
            enforce_mfa = bool(hello.get("enforce_mfa", False))
            auth = self.rbac.authenticate(username, password, totp_code=totp_code, source_ip=effective_ip, enforce_mfa=enforce_mfa)
            if not auth.authenticated or not auth.token:
                bf_verdict = self.ips.record_auth_failure(effective_ip, username)
                if not bf_verdict.allowed:
                    self.incidents.create_incident(
                        title=f"Brute-Force Attack Mitigated ({username})",
                        severity="CRITICAL",
                        source_ip=effective_ip,
                        category="AUTH",
                        containment_action="Active IPS lockout and IP ban applied",
                    )
                await _write_json_frame(writer, {
                    "ok": False,
                    "code": "IPS_LOCKOUT" if not bf_verdict.allowed else "AUTH_FAILED",
                    "error": bf_verdict.reason if not bf_verdict.allowed else auth.reason,
                })
                return

            # 5. Ephemeral X25519 ECDHE + HKDF-SHA256 -> AES-256-GCM Session Tunnel
            client_pub_b64 = str(hello.get("client_pub_b64", ""))
            salt = os.urandom(16)
            ecdhe = ECDHEKeyExchange()
            session_key, nonce_prefix = ecdhe.derive_session_material(client_pub_b64, salt)
            session_id = f"TUN-{uuid.uuid4().hex[:12].upper()}"
            cipher = TunnelCipher(
                key=session_key,
                nonce_prefix=nonce_prefix,
                session_id=session_id,
                replay_window=self.ips.thresholds.get("replay_window_size", 64),
            )

            self.active_sessions[session_id] = {
                "session_id": session_id,
                "username": auth.username,
                "role": auth.role,
                "device_id": device_id,
                "vlan": nac_decision.assigned_vlan,
                "source_ip": effective_ip,
                "established_at": time.time(),
            }
            self.siem.log(
                category="VPN",
                event_type="tunnel_established",
                severity="INFO",
                source_ip=effective_ip,
                actor=auth.username,
                action="ALLOW",
                details={
                    "session_id": session_id,
                    "device_id": device_id,
                    "vlan": nac_decision.assigned_vlan,
                    "role": auth.role,
                    "cipher": "TLS+X25519+AES-256-GCM",
                },
            )

            await _write_json_frame(writer, {
                "ok": True,
                "type": "handshake_ok",
                "session_id": session_id,
                "role": auth.role,
                "assigned_vlan": nac_decision.assigned_vlan,
                "mfa_verified": auth.mfa_verified,
                "server_pub_b64": ecdhe.public_b64(),
                "salt_b64": base64.b64encode(salt).decode("ascii"),
                "token": auth.token,
            })

            # 6. Encrypted Tunnel Command Loop
            while True:
                try:
                    enc_frame = await asyncio.wait_for(_read_json_frame(reader), timeout=60.0)
                except (asyncio.IncompleteReadError, asyncio.TimeoutError):
                    break

                # Per-request IPS Rate Limit
                rl = self.ips.check_rate_limit(effective_ip)
                if not rl.allowed:
                    self.incidents.create_incident(
                        title="In-Tunnel DDoS Flood Mitigated",
                        severity="CRITICAL",
                        source_ip=effective_ip,
                        category="IPS",
                        containment_action="Terminated tunnel session and banned IP",
                    )
                    resp = cipher.encrypt_frame({"ok": False, "code": "IPS_RATE_LIMIT", "error": rl.reason}, direction="s2c")
                    await _write_json_frame(writer, resp)
                    break

                # AES-256-GCM Decrypt + Replay Protection
                try:
                    cmd_payload = cipher.decrypt_frame(enc_frame, expected_direction="c2s")
                except ReplayAttackError as exc:
                    self.ips.record_crypto_violation(effective_ip, "REPLAY_ATTACK", str(exc))
                    self.incidents.create_incident(
                        title="VPN Tunnel Replay Attack Blocked",
                        severity="CRITICAL",
                        source_ip=effective_ip,
                        category="CRYPTO",
                        containment_action="Dropped replayed frame, killed session, banned source IP",
                    )
                    await _write_json_frame(writer, {"ok": False, "code": "REPLAY_DETECTED", "error": str(exc)})
                    break
                except TamperDetectedError as exc:
                    self.ips.record_crypto_violation(effective_ip, "MITM_TAMPER", str(exc))
                    self.incidents.create_incident(
                        title="AES-GCM Tag Tampering / MITM Detected",
                        severity="CRITICAL",
                        source_ip=effective_ip,
                        category="CRYPTO",
                        containment_action="Dropped tampered frame, killed session, banned source IP",
                    )
                    await _write_json_frame(writer, {"ok": False, "code": "TAMPER_DETECTED", "error": str(exc)})
                    break

                # Deep Payload Inspection (DPI)
                dpi = self.ips.inspect_payload(json.dumps(cmd_payload), source_ip=effective_ip, actor=auth.username)
                if not dpi.allowed:
                    self.incidents.create_incident(
                        title=f"DPI Blocked Malicious Payload ({dpi.threat_type})",
                        severity="CRITICAL",
                        source_ip=effective_ip,
                        category="IPS",
                        containment_action=f"Dropped frame ({dpi.rule_id}) and banned source IP",
                    )
                    resp = cipher.encrypt_frame({"ok": False, "code": "IPS_DPI_BLOCK", "threat_type": dpi.threat_type, "error": dpi.reason}, direction="s2c")
                    await _write_json_frame(writer, resp)
                    break

                result = self._dispatch_command(cmd_payload, auth.token, effective_ip, auth.username)
                enc_resp = cipher.encrypt_frame(result, direction="s2c")
                sent_bytes = await _write_json_frame(writer, enc_resp)
                self.siem.log(
                    category="TRAFFIC",
                    event_type="encrypted_tunnel_rpc",
                    severity="INFO",
                    source_ip=effective_ip,
                    actor=auth.username,
                    action="ALLOW" if result.get("ok") else "DENY",
                    details={"command": cmd_payload.get("command"), "bytes": sent_bytes, "session_id": session_id},
                )
                if cmd_payload.get("command") == "close":
                    break

        except Exception as exc:
            self.siem.log("VPN", "connection_error", "MEDIUM", source_ip=peer_ip, action="DENY", details={"error": str(exc)})
        finally:
            if session_id:
                self.active_sessions.pop(session_id, None)
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

    def _dispatch_command(self, payload: dict[str, Any], token: str, source_ip: str, username: str) -> dict[str, Any]:
        cmd = str(payload.get("command", "")).lower()

        perm_map = {
            "ping": "tunnel:connect",
            "relay": "tunnel:connect",
            "close": "tunnel:connect",
            "vault_get": "vault:read",
            "vault_list": "vault:read",
            "vault_put": "vault:write",
            "vault_delete": "vault:delete",
            "ips_status": "ips:view",
            "ips_unban": "ips:manage",
            "siem_summary": "siem:view",
            "ai_audit": "audit:run",
            "backup_create": "backup:create",
            "reports_export": "report:generate",
        }
        required_perm = perm_map.get(cmd)
        if not required_perm:
            return {"ok": False, "code": "UNKNOWN_COMMAND", "error": f"Unknown tunnel command: {cmd}"}

        allowed, reason = self.rbac.authorize(token, required_perm, source_ip=source_ip)
        if not allowed:
            return {"ok": False, "code": "RBAC_DENIED", "error": reason}

        if cmd == "ping":
            return {"ok": True, "pong": True, "uptime_seconds": round(time.time() - self.started_at, 2), "active_sessions": len(self.active_sessions)}

        if cmd == "relay":
            msg = str(payload.get("message", ""))
            return {"ok": True, "relayed": True, "echo": msg, "bytes": len(msg.encode("utf-8")), "cipher": "AES-256-GCM"}

        if cmd == "close":
            return {"ok": True, "message": "Tunnel closed gracefully."}

        if cmd == "vault_put":
            key = str(payload.get("key", "")).strip()
            value = str(payload.get("value", ""))
            if not key:
                return {"ok": False, "error": "Secret key is required."}
            self.vault_secrets[key] = {"value": value, "updated_by": username, "updated_at": time.time()}
            self._save_vault_store()
            return {"ok": True, "stored_key": key}

        if cmd == "vault_get":
            key = str(payload.get("key", "")).strip()
            item = self.vault_secrets.get(key)
            if not item:
                return {"ok": False, "error": f"Secret '{key}' not found."}
            return {"ok": True, "key": key, "value": item["value"], "updated_by": item["updated_by"]}

        if cmd == "vault_list":
            return {"ok": True, "keys": sorted(self.vault_secrets.keys())}

        if cmd == "vault_delete":
            key = str(payload.get("key", "")).strip()
            if key in self.vault_secrets:
                del self.vault_secrets[key]
                self._save_vault_store()
                return {"ok": True, "deleted_key": key}
            return {"ok": False, "error": f"Secret '{key}' not found."}

        if cmd == "ips_status":
            return {"ok": True, "stats": self.ips.get_stats(), "banned": self.ips.list_banned()}

        if cmd == "ips_unban":
            target = str(payload.get("target_ip", ""))
            unbanned = self.ips.unban_ip(target, actor=username)
            return {"ok": unbanned, "target_ip": target}

        if cmd == "siem_summary":
            return {"ok": True, "summary": self.siem.summarize()}

        if cmd == "ai_audit":
            force_h = bool(payload.get("force_heuristic", False))
            audit = self.auditor.audit_siem(self.siem, force_heuristic=force_h)
            return {"ok": True, "audit": audit}

        if cmd == "backup_create":
            state = {
                "vault_secrets": self.vault_secrets,
                "incidents": self.incidents.incidents,
                "nac_devices": self.nac.devices,
            }
            meta = self.backups.create_backup(state)
            return {"ok": True, "backup": meta}

        if cmd == "reports_export":
            reports = self.siem.generate_security_reports(
                ips_stats=self.ips.get_stats(),
                incidents=self.incidents.incidents,
                backups=self.backups.list_backups(),
            )
            return {"ok": True, "reports": reports}

        return {"ok": False, "error": "Unhandled command"}


class AegisGatewayClient:
    """Edge Gateway Node (Container 2 / localhost client): establishes mTLS + X25519 + AES-256-GCM tunnel."""

    def __init__(self, config: AegisConfig = DEFAULT_CONFIG, use_client_cert: bool = True) -> None:
        self.config = config
        self.config.ensure_runtime_dirs()
        self.pki = PKIManager(self.config.certs_dir)
        self.pki.ensure_pki()
        self.use_client_cert = use_client_cert

        self._reader: asyncio.StreamReader | None = None
        self._writer: asyncio.StreamWriter | None = None
        self.cipher: TunnelCipher | None = None
        self.session_info: dict[str, Any] = {}

    async def connect(
        self,
        username: str,
        password: str,
        device_id: str = "gw-edge-01",
        mac_address: str = "02:42:AC:14:00:02",
        totp_code: str | None = None,
        host: str | None = None,
        port: int | None = None,
        simulated_source_ip: str | None = None,
        enforce_mfa: bool = False,
    ) -> dict[str, Any]:
        target_host = host or self.config.vault_host
        target_port = self.config.vault_port if port is None else port
        ssl_ctx = self.pki.build_client_ssl_context(use_client_cert=self.use_client_cert)
        server_hostname = target_host if target_host not in ("127.0.0.1", "0.0.0.0") else "localhost"

        self._reader, self._writer = await asyncio.open_connection(
            target_host,
            target_port,
            ssl=ssl_ctx,
            server_hostname=server_hostname,
        )
        ecdhe = ECDHEKeyExchange()
        hello: dict[str, Any] = {
            "type": "handshake",
            "device_id": device_id,
            "mac_address": mac_address,
            "username": username,
            "password": password,
            "totp_code": totp_code,
            "enforce_mfa": enforce_mfa,
            "client_pub_b64": ecdhe.public_b64(),
        }
        if simulated_source_ip:
            hello["simulated_source_ip"] = simulated_source_ip

        await _write_json_frame(self._writer, hello)
        reply = await _read_json_frame(self._reader)
        if not reply.get("ok"):
            await self.close()
            return reply

        salt = base64.b64decode(reply["salt_b64"])
        session_key, nonce_prefix = ecdhe.derive_session_material(reply["server_pub_b64"], salt)
        self.cipher = TunnelCipher(session_key, nonce_prefix, session_id=reply["session_id"])
        self.session_info = reply
        return reply

    async def send_command(self, command: str, **kwargs: Any) -> dict[str, Any]:
        if not self._writer or not self._reader or not self.cipher:
            raise RuntimeError("Tunnel is not connected.")
        payload = {"command": command, **kwargs}
        enc = self.cipher.encrypt_frame(payload, direction="c2s")
        await _write_json_frame(self._writer, enc)
        raw_resp = await _read_json_frame(self._reader)
        if "ciphertext" in raw_resp:
            return self.cipher.decrypt_frame(raw_resp, expected_direction="s2c")
        return raw_resp

    async def send_raw_frame(self, frame: dict[str, Any]) -> dict[str, Any]:
        """Low-level hook used by security testing / attack simulations (MITM tamper & replay)."""
        if not self._writer or not self._reader:
            raise RuntimeError("Tunnel is not connected.")
        await _write_json_frame(self._writer, frame)
        return await _read_json_frame(self._reader)

    async def close(self) -> None:
        if self._writer:
            self._writer.close()
            try:
                await self._writer.wait_closed()
            except Exception:
                pass
            self._writer = None
            self._reader = None
            self.cipher = None
