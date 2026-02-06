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
| **Version** | 1.1.0 |

## v1.1 New Features

| Feature | Description |
|---------|-------------|
| **Idempotent Execution** | Can be run repeatedly, skips completed items |
| **Individual Rollback** | Support rollback of specific hardening items |
| **Complete Logging** | All operations have detailed logs |
| **Debug Mode** | Support debugging individual items |
| **State Management** | JSON state file tracks hardening status |

## OpenClaw Deployment Security Risks

When deploying OpenClaw on Linux, you face these specific security risks:

| Risk | Description | Severity | Hardening Item |
|------|-------------|----------|----------------|
| **Service runs with high privileges** | Service runs as root or privileged user | High | 1, 4 |
| **Config/Secret leakage** | config.yaml, Token exposed | High | 2, 3 |
| **Gateway port exposure** | Port 18789 accessible externally | High | 5 |
| **Agent file traversal** | AI Agent accesses /etc, /root, etc. | High | 6 |
| **No operation audit** | Agent operations not logged | Medium | 7 |
| **SSRF attacks** | Agent accesses internal network resources | High | 8 |
| **Resource exhaustion** | Malicious prompts exhaust CPU/memory | Medium | 9 |
| **Bash command injection** | Agent executes dangerous system commands | High | 10 |

## Hardening Items

| # | Item | Target Risk | Linux-Specific Measure |
|---|------|-------------|------------------------|
| 1 | Create service account | High privileges | nologin account, no sudo |
| 2 | Configure file permissions | Config leakage | 640/750 permissions |
| 3 | Generate secure config | Secret leakage | Token generation, env isolation |
| 4 | Install systemd service | High privileges | **Process sandbox** (see below) |
| 5 | Configure firewall | Port exposure | UFW/firewalld/iptables |
| 6 | Configure AppArmor/SELinux | File traversal | **Mandatory Access Control** |
| 7 | Enable audit policy | No audit | **auditd** |
| 8 | Network outbound whitelist | SSRF | **iptables outbound rules** |
| 9 | Resource limits | Exhaustion | **cgroup** |
| 10 | Bash Tool restrictions | Injection | **Command/path whitelist** |

## Linux-Specific Hardening Details

### [4] systemd Process Sandbox

Linux systemd provides rich process sandboxing capabilities not available in Windows service management:

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

**Windows comparison:** Windows services require AppLocker + NTFS ACL + service account permissions combined to achieve similar isolation.

### [6] AppArmor/SELinux Access Control

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

**Windows comparison:** Windows uses AppLocker for similar functionality, but focuses mainly on executable control rather than fine-grained directory access.

### [8] Network Outbound Whitelist (SSRF Protection)

Restrict OpenClaw to only connect to specified AI APIs:

```bash
# Config: /etc/openclaw/outbound-whitelist.conf
api.openai.com
api.anthropic.com
api.deepseek.com
generativelanguage.googleapis.com
```

The script automatically resolves these domain IPs and configures firewall rules.

### [9] cgroup Resource Limits

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

**Windows comparison:** Windows requires Job Objects or WSL2 for similar resource isolation.

### [10] Bash Tool Command Restrictions

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
