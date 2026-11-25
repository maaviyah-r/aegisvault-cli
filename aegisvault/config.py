"""Centralized configuration for AegisVault CLI (localhost & dual-container modes)."""

from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
RUNTIME_DIR = Path(os.environ.get("AEGISVAULT_RUNTIME_DIR", str(BASE_DIR / "runtime")))
CERTS_DIR = RUNTIME_DIR / "certs"
LOGS_DIR = RUNTIME_DIR / "logs"
BACKUPS_DIR = RUNTIME_DIR / "backups"
REPORTS_DIR = RUNTIME_DIR / "reports"
DATA_DIR = RUNTIME_DIR / "data"


@dataclass(frozen=True)
class AegisConfig:
    """Runtime settings with localhost-first defaults and Docker env overrides."""

    vault_host: str = os.environ.get("AEGISVAULT_VAULT_HOST", "127.0.0.1")
    vault_port: int = int(os.environ.get("AEGISVAULT_VAULT_PORT", "8443"))
    gateway_bind_host: str = os.environ.get("AEGISVAULT_GATEWAY_HOST", "127.0.0.1")
    gateway_port: int = int(os.environ.get("AEGISVAULT_GATEWAY_PORT", "8444"))
    ollama_url: str = os.environ.get("AEGISVAULT_OLLAMA_URL", "http://127.0.0.1:11434")
    ollama_model: str = os.environ.get("AEGISVAULT_OLLAMA_MODEL", "qwen2.5")
    ollama_timeout: float = float(os.environ.get("AEGISVAULT_OLLAMA_TIMEOUT", "25.0"))
    policy_path: Path = CONFIG_DIR / "security_policy.json"
    nac_registry_path: Path = CONFIG_DIR / "nac_registry.json"
    rbac_policy_path: Path = CONFIG_DIR / "rbac_policy.json"
    runtime_dir: Path = RUNTIME_DIR
    certs_dir: Path = CERTS_DIR
    logs_dir: Path = LOGS_DIR
    backups_dir: Path = BACKUPS_DIR
    reports_dir: Path = REPORTS_DIR
    data_dir: Path = DATA_DIR

    def ensure_runtime_dirs(self) -> None:
        for path in (
            self.runtime_dir,
            self.certs_dir,
            self.logs_dir,
            self.backups_dir,
            self.reports_dir,
            self.data_dir,
        ):
            path.mkdir(parents=True, exist_ok=True)


DEFAULT_CONFIG = AegisConfig()
