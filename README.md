# OpenClaw Linux Security Hardening Script

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2FDebian%2FRHEL-orange.svg)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## Overview

This script focuses on addressing **security risks specific to OpenClaw deployment**, not generic system hardening.

## Author Information

| Item | Information |
|------|-------------|
| **Author** | Alex |
| **Email** | unix_sec@163.com |
| **Version** | 1.2.0 |

## v1.2 New Features (Environment Adaptability)

| Feature | Description |
|---------|-------------|
| **Environment Pre-check** | Auto-detect systemd/firewall/AppArmor/SELinux/Python3 availability at startup |
| **Smart Skip** | Gracefully skip hardening items when components are missing, with reasons and alternatives |
| **Graceful Degradation** | State management falls back to text file when Python3 is unavailable |
| **Environment Report** | Main menu shows detection results, indicating which items may be limited |
| **Crash Prevention** | Removed `set -e` to prevent detection command failures from crashing the script |

## v1.1 Features

| Feature | Description |
|---------|-------------|
| **Idempotent Execution** | Can be run repeatedly, skips completed items |
| **Individual Rollback** | Support rollback of specific hardening items |
| **Complete Logging** | All operations have detailed logs |
| **Debug Mode** | Support debugging individual items |
| **State Management** | JSON state file tracks hardening status |

## OpenClaw Security Risk Analysis

Based on OpenClaw **source code audit** + **internet security research** (ClawHavoc attack, TIP hijacking, 1800+ exposed instances), 10 risk categories identified:

| ID | Risk | Source | Description | Severity |
|----|------|--------|-------------|----------|
| R1 | Gateway Exposure | Research | 1800+ instances leaking API keys | **Critical** |
| R2 | Prompt/Command Injection | Code+Research | Agent shell access + TIP hijacking | **Critical** |
| R3 | MCP Tool Poisoning | ClawHavoc | 341 malicious skills stealing creds | **Critical** |
| R4 | SSRF Attacks | Code | Agent accessing internal resources | High |
| R5 | Credential Leakage | Research | Token/API Key/chat history exposed | **Critical** |
| R6 | Privilege Escalation | Code | Elevated tools + env var injection | High |
| R7 | File System Traversal | Code | Path traversal/symlink attacks | High |
| R8 | Resource Exhaustion | General | Fork bombs/memory exhaustion | Medium |
| R9 | Supply Chain Attack | ClawHavoc | Malicious ClawHub skill packages | **Critical** |
| R10 | Log/Data Leakage | Code | Sensitive info written to logs | Medium |

> References: [ClawHavoc](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) | [OpenClaw Security Model](https://venturebeat.com/security/openclaw-agentic-ai-security-risk-ciso-guide) | [TIP Hijacking](https://www.secrss.com/articles/83397)

## Hardening Items (12 items)

| # | Item | Risks | Linux Measure |
|---|------|-------|---------------|
| 1 | Gateway Bind Hardening | R1 | Loopback enforcement + periodic check |
| 2 | Service Account Isolation | R5 | nologin + no sudo |
| 3 | File Permission Hardening | R5/R7 | 640/700 + symlink protection |
| 4 | Credential Security | R5 | Token + env var filtering |
| 5 | systemd Process Sandbox | R2/R6/R8 | seccomp + capabilities + cgroup |
| 6 | Firewall Port Restriction | R1 | UFW/firewalld/iptables |
| 7 | Network Outbound Whitelist | R4 | iptables outbound rules |
| 8 | AppArmor/SELinux | R7/R6 | Mandatory Access Control |
| 9 | Bash Tool Restrictions | R2/R6 | Command blacklist + restricted shell |
| 10 | Resource Limits | R8 | PAM limits |
| 11 | **MCP/Skill Protection** | R9/R3 | Skill audit + integrity check |
| 12 | **Log Audit & Redaction** | R10/R5 | auditd + logrotate + redaction |

## Hardening Details

### [5] systemd Process Sandbox

Service isolation through systemd process sandboxing:

```ini
[Service]
# Prevent privilege escalation
NoNewPrivileges=true

# System directories read-only
ProtectSystem=strict

# User home directories read-only
ProtectHome=read-only

# Isolated temp directory
PrivateTmp=true

# System call filtering (block dangerous operations)
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @clock @module

# Capability restrictions
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# Memory protection
MemoryDenyWriteExecute=true
```

### [8] AppArmor/SELinux Access Control

Restrict OpenClaw process to specific directories only:

```
# AppArmor config summary
profile openclaw {
  # Allow access
  /opt/openclaw/** r,           # Code directory (read-only)
  /var/lib/openclaw/** rw,      # State directory (read-write)
  /tmp/openclaw-workspace/** rw, # Workspace (read-write)
  
  # Deny access
  deny /etc/passwd w,
  deny /etc/shadow rw,
  deny /etc/sudoers rw,
  deny /root/** rw,
  deny /home/*/.ssh/** rw,
}
```

### [7] Network Outbound Whitelist (SSRF Protection)

Restrict OpenClaw to only connect to specified AI APIs:

```bash
# Config: /etc/openclaw/outbound-whitelist.conf
api.openai.com
api.anthropic.com
api.deepseek.com
generativelanguage.googleapis.com
```

The script automatically resolves these domain IPs and configures firewall rules.

### [10] cgroup Resource Limits

Prevent malicious prompts from exhausting resources:

```ini
# CPU limit (50% single core)
CPUQuota=50%

# Memory limit (max 2GB)
MemoryMax=2G

# Task limit (prevent fork bombs)
TasksMax=100

# File descriptor limit
LimitNOFILE=4096
```

### [9] Bash Tool Command Restrictions

Prevent AI Agent from executing dangerous commands:

```bash
# Blocked commands
BLOCKED_COMMANDS=(
    "useradd" "userdel" "passwd"      # User management
    "chmod" "chown"                    # Permission changes
    "systemctl" "service"              # Service control
    "iptables" "ufw"                   # Firewall
    "mount" "dd" "mkfs"                # Disk operations
    "apt" "yum" "dnf"                  # Package management
    "sudo" "su"                        # Privilege escalation
)

# Allowed paths
ALLOWED_PATHS=(
    "/home"
    "/tmp/openclaw-workspace"
)
```

## Quick Start

```bash
# 1. Add execute permission
chmod +x linux-security-hardening.sh

# 2. Dry run (recommended first)
sudo ./linux-security-hardening.sh --dry-run

# 3. Interactive mode
sudo ./linux-security-hardening.sh

# 4. One-click full hardening
sudo ./linux-security-hardening.sh --all

# 5. Check hardening status
sudo ./linux-security-hardening.sh --status

# 6. Rollback specific item
sudo ./linux-security-hardening.sh --rollback 5

# 7. Debug specific item
sudo ./linux-security-hardening.sh --debug 3
```

## Command Line Arguments

| Argument | Description | Example |
|----------|-------------|---------|
| `--help` | Show help | `./script.sh --help` |
| `--dry-run` | Dry run mode | `./script.sh --dry-run` |
| `--status` | Show status | `./script.sh --status` |
| `--rollback N` | Rollback item N | `./script.sh --rollback 5` |
| `--debug N` | Debug item N | `./script.sh --debug 3` |
| `--apply N` | Apply item N | `./script.sh --apply 1` |
| `--all` | Apply all items | `./script.sh --all` |

## Interactive Menu

| Option | Function |
|--------|----------|
| 1 | Interactive item selection |
| 2 | One-click full hardening |
| 3 | View hardening status |
| 4 | Rollback specific item |
| 5 | Debug specific item |
| 6 | View logs |
| 7 | Rollback all |

## Idempotency

The script supports idempotent execution, safe to run repeatedly:

- **Service account**: Skips if already exists
- **Config files**: Preserves existing files
- **Firewall rules**: Checks before adding
- **State file**: JSON format tracking each item

State file: `/var/lib/openclaw-hardening/hardening-state.json`

## Logging

All operations are logged:

- **Log directory**: `/var/log/openclaw-hardening/`
- **Format**: `[timestamp] [level] [function] message`
- **Levels**: INFO, WARN, ERROR, DEBUG, ACTION

```bash
# View recent logs
tail -f /var/log/openclaw-hardening/hardening-*.log

# View logs for specific item
grep "item=5" /var/log/openclaw-hardening/hardening-*.log
```

## Debug Mode

Debug mode allows testing individual items:

```bash
# Enter debug mode
sudo ./linux-security-hardening.sh --debug 5

# Debug menu options:
# [1] Apply
# [2] Rollback
# [3] Dry-run apply
# [4] Dry-run rollback
# [5] View logs
```

## Configuration

### AI API Whitelist

Edit `AI_API_DOMAINS` array at script top:

```bash
AI_API_DOMAINS=(
    "api.openai.com"
    "api.anthropic.com"
    "api.deepseek.com"
    "generativelanguage.googleapis.com"
    # Add your AI APIs
)
```

### Allowed Agent Directories

Edit `ALLOWED_WORK_DIRS` array:

```bash
ALLOWED_WORK_DIRS=(
    "/home"
    "/tmp/openclaw-workspace"
    "$OPENCLAW_STATE_DIR"
    # Add project directories
)
```

## Security Checklist

| Check | Command | Expected |
|-------|---------|----------|
| Service account unprivileged | `groups openclaw` | No sudo/wheel |
| Secrets directory permissions | `stat -c "%a" /etc/openclaw/secrets` | 750 |
| Gateway port local only | `ss -tlnp \| grep 18789` | 127.0.0.1 |
| Process sandbox enabled | `grep NoNewPrivileges /etc/systemd/system/openclaw.service` | true |
| AppArmor config exists | `ls /etc/apparmor.d/openclaw` | exists |
| Audit rules configured | `ls /etc/audit/rules.d/openclaw.rules` | exists |
| Resource limits configured | `ls /etc/systemd/system/openclaw.service.d/` | exists |

## Changelog

### v1.2.0 (2026-02-09)
- Added: Environment adaptability detection framework, auto-detect all dependencies at startup
- Added: Environment pre-check report shown in main menu with component availability status
- Added: Pre-requisite checks for every apply/rollback function, smart skip when components missing
- Added: Python3 fallback - state management degrades to text file when Python3 unavailable
- Added: `generate_token()` multi-fallback (urandom → openssl → sha256)
- Improved: `do_apply_1` detects ss/netstat fallback, skips timer on non-systemd systems
- Improved: `do_apply_2` checks useradd availability, nologin shell path auto-adaptation
- Improved: `do_apply_5` checks systemd + service account existence
- Improved: `do_apply_6` full firewall chain check (command + service status + rule persistence)
- Improved: `do_apply_7` dig + firewall dual check, individual domain resolve failures handled
- Improved: `do_apply_8` AppArmor/SELinux deep check (enabled state + parser tools)
- Improved: `do_apply_10` PAM limits directory existence check
- Improved: `do_apply_12` auditd/redaction/logrotate three-stage independent degradation
- Fixed: Removed `set -e` to prevent detection failures from crashing the script
- Fixed: auditd detection operator precedence bug

### v1.1.0 (2026-02-06)
- Redesigned: Focus on OpenClaw deployment risks
- Removed: Generic CIS hardening (SSH, password policy, etc.)
- Added: Network outbound whitelist (SSRF protection)
- Added: cgroup resource limits
- Added: Bash Tool command restrictions

### v1.0.0 (2026-02-05)
- Initial release

## License

Apache License 2.0

---

**Author**: Alex | **Email**: unix_sec@163.com
