"""Local Ollama (qwen2.5) AI Threat Auditing engine with deterministic heuristic fallback."""

from __future__ import annotations

import datetime
import json
import urllib.error
import urllib.request
from typing import Any

from .siem_logger import SIEMLogger


class OllamaThreatAuditor:
    """Audits local SIEM telemetry using local Ollama (`qwen2.5`) without sending logs off-host."""

    def __init__(
        self,
        ollama_url: str = "http://127.0.0.1:11434",
        model: str = "qwen2.5",
        timeout: float = 25.0,
    ) -> None:
        self.ollama_url = ollama_url.rstrip("/")
        self.model = model
        self.timeout = timeout

    def check_health(self) -> dict[str, Any]:
        """Probe local Ollama daemon and check whether the target model is installed."""
        try:
            req = urllib.request.Request(f"{self.ollama_url}/api/tags", method="GET")
            with urllib.request.urlopen(req, timeout=3.0) as resp:
                data = json.loads(resp.read().decode("utf-8"))
            models = [m.get("name", "") for m in data.get("models", [])]
            has_model = any(m == self.model or m.startswith(f"{self.model}:") for m in models)
            return {
                "reachable": True,
                "url": self.ollama_url,
                "target_model": self.model,
                "model_installed": has_model,
                "installed_models": models,
            }
        except Exception as exc:
            return {
                "reachable": False,
                "url": self.ollama_url,
                "target_model": self.model,
                "model_installed": False,
                "installed_models": [],
                "error": str(exc),
            }

    def audit_siem(self, siem: SIEMLogger, max_events: int = 50, force_heuristic: bool = False) -> dict[str, Any]:
        """Run an AI threat audit on recent SIEM events using Ollama qwen2.5 (or deterministic fallback)."""
        summary = siem.summarize()
        recent_events = siem.read_events(limit=max_events)
        critical_or_blocked = [
            {
                "timestamp": e.get("timestamp"),
                "category": e.get("category"),
                "event_type": e.get("event_type"),
                "severity": e.get("severity"),
                "source_ip": e.get("source_ip"),
                "actor": e.get("actor"),
                "action": e.get("action"),
                "details": e.get("details"),
            }
            for e in recent_events
            if e.get("severity") in ("CRITICAL", "HIGH", "MEDIUM") or e.get("action") in ("BLOCK", "DENY", "QUARANTINE")
        ]

        if not force_heuristic:
            health = self.check_health()
            if health["reachable"] and health["model_installed"]:
                try:
                    ai_text = self._query_ollama(summary, critical_or_blocked)
                    return {
                        "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                        "engine": f"ollama:{self.model}",
                        "ollama_status": "online",
                        "siem_events_analyzed": len(recent_events),
                        "chain_intact": summary["chain_intact"],
                        "overall_risk": self._calculate_risk_rating(summary, critical_or_blocked),
                        "analysis": ai_text,
                        "flagged_events_count": len(critical_or_blocked),
                    }
                except Exception as exc:
                    fallback_note = f"Ollama query failed ({exc}); used deterministic local fallback."
            else:
                reason = health.get("error", f"Model '{self.model}' not pulled in Ollama")
                fallback_note = f"Ollama ({self.ollama_url}, model={self.model}) unavailable: {reason}"
        else:
            fallback_note = "Heuristic audit explicitly requested."

        return self._heuristic_audit(summary, critical_or_blocked, len(recent_events), fallback_note)

    def _query_ollama(self, summary: dict[str, Any], flagged_events: list[dict[str, Any]]) -> str:
        prompt = (
            "You are a senior Network Security SOC Analyst auditing logs from AegisVault CLI "
            "(TLS/AES-256-GCM mini-VPN, NAC/RBAC, Active IPS, and SHA-256 chained SIEM).\n"
            "Analyze the telemetry below and produce a concise, structured threat audit covering:\n"
            "1. Executive Risk Rating & Justification\n"
            "2. Observed Attack Vectors (mapped to MITRE ATT&CK techniques where applicable)\n"
            "3. Effectiveness of Active Defenses (IPS, NAC, RBAC, AES-GCM)\n"
            "4. Top 4 Prioritized Remediation Recommendations.\n\n"
            f"SIEM SUMMARY:\n{json.dumps(summary, indent=2)}\n\n"
            f"FLAGGED SECURITY EVENTS (most recent {len(flagged_events)}):\n"
            f"{json.dumps(flagged_events[-20:], indent=2)}\n"
        )
        body = json.dumps({
            "model": self.model,
            "prompt": prompt,
            "stream": False,
            "options": {"temperature": 0.2},
        }).encode("utf-8")
        req = urllib.request.Request(
            f"{self.ollama_url}/api/generate",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=self.timeout) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
        return str(payload.get("response", "")).strip()

    @staticmethod
    def _calculate_risk_rating(summary: dict[str, Any], flagged: list[dict[str, Any]]) -> str:
        if not summary.get("chain_intact", True):
            return "CRITICAL"
        crit = sum(1 for e in flagged if e.get("severity") == "CRITICAL")
        high = sum(1 for e in flagged if e.get("severity") == "HIGH")
        if crit >= 3:
            return "CRITICAL"
        if crit >= 1 or high >= 3:
            return "HIGH"
        if flagged:
            return "MEDIUM"
        return "LOW"

    def _heuristic_audit(
        self,
        summary: dict[str, Any],
        flagged: list[dict[str, Any]],
        total_analyzed: int,
        note: str,
    ) -> dict[str, Any]:
        risk = self._calculate_risk_rating(summary, flagged)
        threats_seen: set[str] = set()
        for ev in flagged:
            tt = ev.get("details", {}).get("threat_type") or ev.get("event_type")
            if tt:
                threats_seen.add(str(tt))

        mitre_map = {
            "DDOS_FLOOD": "T1498 (Network Denial of Service)",
            "BRUTE_FORCE": "T1110 (Brute Force Credential Stuffing)",
            "PORT_SCAN": "T1046 (Network Service Discovery)",
            "SQL_INJECTION": "T1190 (Exploit Public-Facing Application)",
            "COMMAND_INJECTION": "T1059 (Command and Scripting Interpreter)",
            "MITM_TAMPER": "T1557 (Adversary-in-the-Middle)",
            "REPLAY_ATTACK": "T1550 (Use Alternate Authentication Material / Replay)",
            "device_admission": "T1200 (Hardware Additions / Rogue Endpoint NAC Violation)",
        }
        mapped_ttps = [mitre_map[t] for t in sorted(threats_seen) if t in mitre_map]

        lines = [
            f"Overall Risk Rating: {risk}",
            f"SIEM Integrity: {'INTACT (SHA-256 hash chain verified)' if summary['chain_intact'] else 'COMPROMISED'}",
            f"Events Analyzed: {total_analyzed} total | {len(flagged)} security-relevant alerts/blocks",
            "",
            "Observed Threat Vectors & MITRE ATT&CK Mapping:",
        ]
        if mapped_ttps:
            for item in mapped_ttps:
                lines.append(f"  - {item}")
        else:
            lines.append("  - No active attack signatures observed in the analyzed window.")

        lines.extend([
            "",
            "Defense Effectiveness:",
            f"  - Total Blocked/Denied/Quarantined Actions: {summary['by_action'].get('BLOCK', 0) + summary['by_action'].get('DENY', 0) + summary['by_action'].get('QUARANTINE', 0)}",
            "  - Cryptographic Transport: TLS + X25519/HKDF + AES-256-GCM authenticated framing active.",
            "",
            "Prioritized Recommendations:",
            "  1. Review actively quarantined IPs and rogue NAC devices before lifting any bans.",
            "  2. Enforce mandatory RFC 6238 TOTP MFA across all privileged admin and analyst accounts.",
            "  3. Rotate ECDSA mTLS certificates and create a fresh AES-256-GCM encrypted backup snapshot.",
            f"  4. Start local Ollama (`ollama serve` & `ollama pull {self.model}`) to enable live LLM natural-language reasoning.",
        ])

        return {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "engine": f"local-heuristic-fallback (target ollama:{self.model})",
            "ollama_status": "offline",
            "ollama_note": note,
            "siem_events_analyzed": total_analyzed,
            "chain_intact": summary["chain_intact"],
            "overall_risk": risk,
            "mitre_techniques": mapped_ttps,
            "analysis": "\n".join(lines),
            "flagged_events_count": len(flagged),
        }
