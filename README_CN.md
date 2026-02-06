# OpenClaw Linux 安全加固脚本

[![Platform](https://img.shields.io/badge/Platform-Ubuntu%2FDebian%2FRHEL-orange.svg)](https://ubuntu.com/)
[![License](https://img.shields.io/badge/License-Apache%202.0-green.svg)](LICENSE)

## 概述

本脚本专注于解决 **OpenClaw 部署带来的特定安全风险**，而非通用的系统加固。

## 作者信息

| 项目 | 信息 |
|------|------|
| **作者** | Alex |
| **邮箱** | unix_sec@163.com |
| **版本** | 1.1.0 |

## v1.1 新增功能

| 功能 | 说明 |
|------|------|
| **幂等执行** | 可重复运行，自动跳过已完成项 |
| **单独回退** | 支持回退指定的加固项 |
| **完整日志** | 所有操作均有详细日志记录 |
| **调试模式** | 支持单独调试指定功能项 |
| **状态管理** | JSON 状态文件记录加固状态 |

## OpenClaw 部署安全风险分析

在 Linux 环境部署 OpenClaw 时，面临以下特定安全风险：

| 风险 | 说明 | 危害等级 | 加固项 |
|------|------|----------|--------|
| **服务高权限运行** | 服务以 root 或高权限用户运行 | 高 | 1, 4 |
| **配置/密钥泄露** | config.yaml、Token 被读取 | 高 | 2, 3 |
| **Gateway 端口暴露** | 18789 端口对外开放 | 高 | 5 |
| **Agent 文件越界** | AI Agent 访问 /etc、/root 等敏感目录 | 高 | 6 |
| **操作无审计** | Agent 操作无记录，难以追溯 | 中 | 7 |
| **SSRF 攻击** | 通过 Agent 访问内网资源 | 高 | 8 |
| **资源耗尽** | 恶意 prompt 导致 CPU/内存耗尽 | 中 | 9 |
| **Bash 命令注入** | Agent 执行危险系统命令 | 高 | 10 |

## 加固项列表

| # | 加固项 | 针对风险 | Linux 特有措施 |
|---|--------|----------|----------------|
| 1 | 创建专用服务账户 | 高权限运行 | nologin 账户、无 sudo |
| 2 | 配置文件系统权限 | 配置泄露 | 640/750 权限 |
| 3 | 生成安全配置 | 密钥泄露 | Token 生成、环境变量隔离 |
| 4 | 安装 systemd 服务 | 高权限运行 | **进程沙箱** (见下文) |
| 5 | 配置防火墙 | 端口暴露 | UFW/firewalld/iptables |
| 6 | 配置 AppArmor/SELinux | 文件越界 | **强制访问控制** |
| 7 | 启用审计策略 | 无审计 | **auditd** |
| 8 | 网络出站白名单 | SSRF | **iptables 出站限制** |
| 9 | 资源限制 | 资源耗尽 | **cgroup** |
| 10 | Bash Tool 限制 | 命令注入 | **命令/路径白名单** |

## Linux 特有加固详解

### [4] systemd 进程沙箱

Linux 的 systemd 提供了丰富的进程沙箱功能，这是 Windows 服务管理所不具备的：

```ini
[Service]
# 禁止获取新特权 (防止提权攻击)
NoNewPrivileges=true

# 系统目录只读 (防止系统被篡改)
ProtectSystem=strict

# 用户主目录只读 (防止数据泄露)
ProtectHome=read-only

# 隔离临时目录
PrivateTmp=true

# 系统调用过滤 (阻止危险操作)
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @clock @module

# 能力限制 (只保留必要能力)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE

# 内存保护
MemoryDenyWriteExecute=true
```

**与 Windows 对比：** Windows 服务需要依赖 AppLocker + NTFS ACL + 服务账户权限组合实现类似效果，配置更复杂。

### [6] AppArmor/SELinux 访问控制

限制 OpenClaw 进程只能访问特定目录：

```
# AppArmor 配置摘要
profile openclaw {
  # 允许访问
  /opt/openclaw/** r,           # 代码目录 (只读)
  /var/lib/openclaw/** rw,      # 状态目录 (读写)
  /tmp/openclaw-workspace/** rw, # 工作目录 (读写)
  
  # 禁止访问
  deny /etc/passwd w,
  deny /etc/shadow rw,
  deny /etc/sudoers rw,
  deny /root/** rw,
  deny /home/*/.ssh/** rw,
}
```

**与 Windows 对比：** Windows 使用 AppLocker 实现类似功能，但主要针对可执行文件控制，对目录访问的精细控制不如 AppArmor。

### [8] 网络出站白名单 (SSRF 防护)

限制 OpenClaw 只能连接到指定的 AI API：

```bash
# 配置文件: /etc/openclaw/outbound-whitelist.conf
api.openai.com
api.anthropic.com
api.deepseek.com
generativelanguage.googleapis.com
```

脚本会自动解析这些域名的 IP 并配置防火墙规则。

**与 Windows 对比：** Windows 可通过 Windows Firewall 实现，但配置出站规则需要更多步骤。

### [9] cgroup 资源限制

防止恶意 prompt 导致资源耗尽：

```ini
# CPU 限制 (50% 单核)
CPUQuota=50%

# 内存限制 (最大 2GB)
MemoryMax=2G

# 任务数限制 (防止 fork 炸弹)
TasksMax=100

# 文件描述符限制
LimitNOFILE=4096
```

**与 Windows 对比：** Windows 需要使用 Job Objects 或 WSL2 才能实现类似的资源隔离。

### [10] Bash Tool 命令限制

防止 AI Agent 执行危险命令：

```bash
# 禁止执行的命令
BLOCKED_COMMANDS=(
    "useradd" "userdel" "passwd"      # 用户管理
    "chmod" "chown"                    # 权限修改
    "systemctl" "service"              # 服务控制
    "iptables" "ufw"                   # 防火墙
    "mount" "dd" "mkfs"                # 磁盘操作
    "apt" "yum" "dnf"                  # 包管理
    "sudo" "su"                        # 提权
)

# 允许访问的目录
ALLOWED_PATHS=(
    "/home"
    "/tmp/openclaw-workspace"
)
```

## 快速开始

```bash
# 1. 添加执行权限
chmod +x linux-security-hardening.sh

# 2. 模拟运行 (推荐先执行)
sudo ./linux-security-hardening.sh --dry-run

# 3. 交互式运行
sudo ./linux-security-hardening.sh

# 4. 一键完整加固
sudo ./linux-security-hardening.sh --all

# 5. 查看加固状态
sudo ./linux-security-hardening.sh --status

# 6. 回退指定加固项
sudo ./linux-security-hardening.sh --rollback 5

# 7. 调试指定加固项
sudo ./linux-security-hardening.sh --debug 3
```

## 命令行参数

| 参数 | 说明 | 示例 |
|------|------|------|
| `--help` | 显示帮助信息 | `./script.sh --help` |
| `--dry-run` | 模拟运行 | `./script.sh --dry-run` |
| `--status` | 查看加固状态 | `./script.sh --status` |
| `--rollback N` | 回退加固项 N | `./script.sh --rollback 5` |
| `--debug N` | 调试加固项 N | `./script.sh --debug 3` |
| `--apply N` | 应用加固项 N | `./script.sh --apply 1` |
| `--all` | 一键应用所有 | `./script.sh --all` |

## 交互式菜单

| 选项 | 功能 |
|------|------|
| 1 | 交互式选择加固项 |
| 2 | 一键完整加固 |
| 3 | 查看加固状态 |
| 4 | 回退指定加固项 |
| 5 | 调试指定加固项 |
| 6 | 查看日志 |
| 7 | 全部回退 |

## 幂等性说明

脚本支持幂等执行，可以安全地重复运行：

- **服务账户**: 已存在则跳过创建
- **配置文件**: 已存在则保留原文件
- **防火墙规则**: 先检查再添加，避免重复
- **状态文件**: JSON 格式记录每项加固状态

状态文件位置: `/var/lib/openclaw-hardening/hardening-state.json`

## 日志说明

所有操作均记录到日志文件：

- **日志目录**: `/var/log/openclaw-hardening/`
- **日志格式**: `[时间] [级别] [函数] 消息`
- **日志级别**: INFO, WARN, ERROR, DEBUG, ACTION

```bash
# 查看最近日志
tail -f /var/log/openclaw-hardening/hardening-*.log

# 查看特定加固项日志
grep "item=5" /var/log/openclaw-hardening/hardening-*.log
```

## 调试模式

调试模式支持对单个加固项进行测试：

```bash
# 进入调试模式
sudo ./linux-security-hardening.sh --debug 5

# 调试菜单选项:
# [1] 执行加固
# [2] 执行回退
# [3] 模拟执行加固
# [4] 模拟执行回退
# [5] 查看日志
```

## 配置说明

### AI API 白名单

修改脚本头部的 `AI_API_DOMAINS` 数组：

```bash
AI_API_DOMAINS=(
    "api.openai.com"
    "api.anthropic.com"
    "api.deepseek.com"
    "generativelanguage.googleapis.com"
    # 添加你使用的 AI API
)
```

### 允许 Agent 访问的目录

修改 `ALLOWED_WORK_DIRS` 数组：

```bash
ALLOWED_WORK_DIRS=(
    "/home"
    "/tmp/openclaw-workspace"
    "$OPENCLAW_STATE_DIR"
    # 添加项目目录
)
```

## 安全检查清单

| 检查项 | 命令 | 期望值 |
|--------|------|--------|
| 服务账户无特权 | `groups openclaw` | 不含 sudo/wheel |
| 密钥目录权限 | `stat -c "%a" /etc/openclaw/secrets` | 750 |
| Gateway 端口本地 | `ss -tlnp \| grep 18789` | 127.0.0.1 |
| 进程沙箱启用 | `grep NoNewPrivileges /etc/systemd/system/openclaw.service` | true |
| AppArmor 配置 | `ls /etc/apparmor.d/openclaw` | 存在 |
| 审计规则配置 | `ls /etc/audit/rules.d/openclaw.rules` | 存在 |
| 资源限制配置 | `ls /etc/systemd/system/openclaw.service.d/` | 存在 |

## 更新日志

### v1.1.0 (2026-02-06)
- 重新设计: 专注于 OpenClaw 部署风险
- 移除: 通用 CIS 加固项 (SSH、密码策略等)
- 新增: 网络出站白名单 (SSRF 防护)
- 新增: cgroup 资源限制
- 新增: Bash Tool 命令限制

### v1.0.0 (2026-02-05)
- 初始版本

## 许可证

Apache License 2.0

---

**作者**: Alex | **邮箱**: unix_sec@163.com
