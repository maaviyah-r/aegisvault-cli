"""Unit tests for Ollama (qwen2.5) AI Threat Auditor with offline fallback & mocked live LLM."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import patch

from aegisvault.ai_auditor import OllamaThreatAuditor
from aegisvault.siem_logger import SIEMLogger


def test_ai_auditor_offline_fallback(tmp_path: Path) -> None:
    siem = SIEMLogger(tmp_path / "siem.jsonl")
    siem.log("IPS", "active_ip_ban", "CRITICAL", source_ip="192.168.50.10", action="BLOCK", details={"threat_type": "DDOS_FLOOD"})
    siem.log("IPS", "active_ip_ban", "CRITICAL", source_ip="192.168.50.11", action="BLOCK", details={"threat_type": "MITM_TAMPER"})

    auditor = OllamaThreatAuditor(ollama_url="http://127.0.0.1:19999", model="qwen2.5")
    result = auditor.audit_siem(siem)
    assert result["ollama_status"] == "offline"
    assert result["overall_risk"] in ("HIGH", "CRITICAL")
    assert any("T1498" in t for t in result["mitre_techniques"])
    assert any("T1557" in t for t in result["mitre_techniques"])


def test_ai_auditor_mocked_qwen25_live(tmp_path: Path) -> None:
    siem = SIEMLogger(tmp_path / "siem.jsonl")
    siem.log("AUTH", "user_login", "MEDIUM", source_ip="10.10.20.1", actor="alice", action="DENY")

    auditor = OllamaThreatAuditor(ollama_url="http://127.0.0.1:11434", model="qwen2.5")
    with patch.object(auditor, "check_health", return_value={"reachable": True, "model_installed": True}), \
         patch.object(auditor, "_query_ollama", return_value="1. Risk Rating: MEDIUM\n2. Single failed login observed."):
        res = auditor.audit_siem(siem)
        assert res["engine"] == "ollama:qwen2.5"
        assert res["ollama_status"] == "online"
        assert "Risk Rating: MEDIUM" in res["analysis"]
