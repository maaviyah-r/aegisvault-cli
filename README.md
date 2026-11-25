# AegisVault CLI

Dual-container & localhost CLI network security suite featuring **mutual TLS + X25519/HKDF + AES-256-GCM mini-VPN tunneling**, **NAC/RBAC access control with TOTP MFA**, **Active IPS defense & stateful firewall ACLs**, **tamper-evident SHA-256 SIEM logging**, **encrypted backup/disaster recovery**, and **local Ollama (`qwen2.5`) AI threat auditing**.

---

## Key Capabilities

- **TLS / AES-256-GCM Mini-VPN Tunnel**: Local ECDSA P-256 Root CA + mTLS node certificates, ephemeral X25519 ECDHE key agreement + HKDF-SHA256 session keys, AES-256-GCM authenticated framing, and sliding-window replay defense.
- **NAC & 6-Role RBAC + MFA**: Endpoint MAC/posture admission (auto-quarantine to `VLAN-99-QUARANTINE`), PBKDF2-HMAC-SHA256 credential hashing, RFC 6238 TOTP MFA, HMAC-SHA256 signed session tokens, and least-privilege role enforcement (`security_admin`, `network_admin`, `system_admin`, `security_analyst`, `it_manager`, `end_user`).
- **Active IPS & Firewall Policy Engine**: 16 explicit Network Security Rules (`NSR-01`–`NSR-16`), DoS/DDoS sliding-window rate limiting, brute-force lockout, port-scan blocking, Deep Payload Inspection (SQLi, Command Injection, Path Traversal, XSS, Reverse Shells), and MITM/replay active banning.
- **Tamper-Evident SIEM & 10 Security Reports**: Append-only JSONL log with SHA-256 hash chaining (`verify_chain`) and automated export of all 10 organizational security reports.
- **Local Ollama (`qwen2.5`) AI Threat Auditing**: Strictly bound to `127.0.0.1:11434` so logs never leave the host, with automatic deterministic fallback when Ollama is offline.
- **Encrypted Backup & Disaster Recovery**: AES-256-GCM encrypted snapshots with SHA-256 integrity verification prior to restore.

---

## Quick Start (100% Local on `localhost`)

```powershell
# 1. Create and activate virtual environment
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt

# 2. Bootstrap local PKI certificates & runtime folders
python -m aegisvault init

# 3. Run the full end-to-end localhost dual-node demo & attack simulation
python -m aegisvault demo
```

### Running Vault Server & Edge Gateway in Two Local Terminals

Terminal 1 (Vault Core Node on `127.0.0.1:8443`):
```powershell
python -m aegisvault server --host 127.0.0.1 --port 8443
```

Terminal 2 (Edge Gateway Client connecting over mTLS + AES-256-GCM):
```powershell
python -m aegisvault client ping --auto-mfa
python -m aegisvault client vault_put --key api_token --value "secret-2026" --auto-mfa
python -m aegisvault client vault_get --key api_token --auto-mfa
python -m aegisvault client ips_status --auto-mfa
python -m aegisvault client ai_audit --auto-mfa
```

### Other CLI Commands
```powershell
python -m aegisvault nac               # View NAC registry & posture scores
python -m aegisvault rbac              # View 6-role RBAC permission matrix
python -m aegisvault firewall          # View all 16 Network Security Rules
python -m aegisvault siem --tail 10    # Verify SHA-256 SIEM chain & view events
python -m aegisvault audit             # Run Ollama qwen2.5 threat audit
python -m aegisvault scan              # Run localhost port & config vulnerability scan
python -m aegisvault backup --create   # Create AES-256-GCM encrypted backup
python -m aegisvault reports           # Export all 10 security reports to JSON
```

---

## Dual-Container Mode (Docker Compose)

```bash
docker compose up --build -d
docker compose run --rm aegisvault-gateway client ping --host aegisvault-server --port 8443 --auto-mfa
```

---

## Running Automated Tests

```powershell
pytest -v
```
