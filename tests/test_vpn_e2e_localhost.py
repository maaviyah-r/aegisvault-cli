"""End-to-end live localhost dual-node mTLS + AES-256-GCM integration test suite."""

from __future__ import annotations

import asyncio
from pathlib import Path

from aegisvault.config import AegisConfig
from aegisvault.security_scanner import run_full_localhost_simulation


def test_full_localhost_dual_node_security_suite(tmp_path: Path) -> None:
    cfg = AegisConfig(
        runtime_dir=tmp_path / "runtime",
        certs_dir=tmp_path / "runtime" / "certs",
        logs_dir=tmp_path / "runtime" / "logs",
        backups_dir=tmp_path / "runtime" / "backups",
        reports_dir=tmp_path / "runtime" / "reports",
        data_dir=tmp_path / "runtime" / "data",
    )
    results = asyncio.run(run_full_localhost_simulation(config=cfg, port=0))

    assert len(results["scenarios"]) == 10
    for sc in results["scenarios"]:
        assert sc["passed"], f"Scenario failed: {sc['name']} -> {sc}"

    assert results["all_passed"] is True
    assert results["siem_summary"]["chain_intact"] is True
    assert len(results["reports"]) == 10
    assert results["avg_tunnel_rtt_ms"] >= 0
