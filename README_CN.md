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
| **版本** | 1.2.0 |

## v1.2 新增功能 (环境适配性)

| 功能 | 说明 |
|------|------|
| **环境预检** | 启动时自动检测 systemd/防火墙/AppArmor/SELinux/Python3 等组件可用性 |
| **智能跳过** | 缺失组件时优雅跳过对应加固项，给出原因和替代建议 |
| **优雅降级** | Python3 不可用时状态管理自动降级为文本文件方式 |
| **环境报告** | 主菜单显示环境检测结果，标注哪些加固项可能受限 |
| **安全防护** | 去除 `set -e`，避免检测命令失败导致脚本退出崩溃 |

## v1.1 功能

| 功能 | 说明 |
|------|------|
| **幂等执行** | 可重复运行，自动跳过已完成项 |
| **单独回退** | 支持回退指定的加固项 |
| **完整日志** | 所有操作均有详细日志记录 |
| **调试模式** | 支持单独调试指定功能项 |
| **状态管理** | JSON 状态文件记录加固状态 |

## OpenClaw 安全风险分析

基于 OpenClaw **源码审计** + **互联网安全研究**（ClawHavoc 攻击、TIP 劫持漏洞、1800+ 暴露实例等），识别出 10 类安全风险：

| 编号 | 风险 | 来源 | 说明 | 等级 |
|------|------|------|------|------|
| R1 | Gateway 暴露 | 安全研究 | 1800+ 实例暴露 API Key | **严重** |
| R2 | 提示注入/命令注入 | 源码+研究 | Agent Shell 访问 + TIP 劫持 | **严重** |
| R3 | MCP 工具投毒 | ClawHavoc | 341 恶意 Skill 窃取凭证 | **严重** |
| R4 | SSRF 攻击 | 源码 | Agent 访问内网资源 | 高 |
| R5 | 凭证泄露 | 安全研究 | Token/API Key/聊天记录 | **严重** |
| R6 | 权限提升 | 源码 | elevated 工具+环境变量注入 | 高 |
| R7 | 文件系统越界 | 源码 | 路径遍历/符号链接攻击 | 高 |
| R8 | 资源耗尽 | 通用 | Fork 炸弹/内存耗尽 | 中 |
| R9 | 供应链攻击 | ClawHavoc | ClawHub 恶意技能包 | **严重** |
| R10 | 日志/数据泄露 | 源码 | 敏感信息写入日志 | 中 |

> 参考: [ClawHavoc 攻击](https://thehackernews.com/2026/02/researchers-find-341-malicious-clawhub.html) | [OpenClaw 安全模型缺陷](https://venturebeat.com/security/openclaw-agentic-ai-security-risk-ciso-guide) | [TIP 劫持漏洞](https://www.secrss.com/articles/83397)

## 加固项列表 (12 项)

| # | 加固项 | 覆盖风险 | Linux 措施 |
|---|--------|----------|------------|
| 1 | Gateway 绑定加固 | R1 | loopback 强制 + 定时检查 |
| 2 | 服务账户隔离 | R5 | nologin + 无 sudo |
| 3 | 文件权限加固 | R5/R7 | 640/700 + 符号链接保护 |
| 4 | 凭证安全管理 | R5 | Token + 环境变量过滤 |
| 5 | systemd 进程沙箱 | R2/R6/R8 | seccomp + 能力限制 + cgroup |
| 6 | 防火墙端口限制 | R1 | UFW/firewalld/iptables |
| 7 | 网络出站白名单 | R4 | iptables 出站规则 |
| 8 | AppArmor/SELinux | R7/R6 | 强制访问控制 |
| 9 | Bash Tool 限制 | R2/R6 | 命令黑名单 + 受限 Shell |
| 10 | 资源限制 | R8 | PAM limits |
| 11 | **MCP/Skill 防护** | R9/R3 | Skill 审计 + 完整性检查 |
| 12 | **日志审计与脱敏** | R10/R5 | auditd + logrotate + 脱敏 |

## 加固详解

### [5] systemd 进程沙箱

通过 systemd 的进程沙箱功能实现服务隔离：

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

### [8] AppArmor/SELinux 访问控制

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

### [7] 网络出站白名单 (SSRF 防护)

限制 OpenClaw 只能连接到指定的 AI API：

```bash
# 配置文件: /etc/openclaw/outbound-whitelist.conf
api.openai.com
api.anthropic.com
api.deepseek.com
generativelanguage.googleapis.com
```

脚本会自动解析这些域名的 IP 并配置防火墙规则。

### [10] cgroup 资源限制

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

### [9] Bash Tool 命令限制

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

### v1.2.0 (2026-02-09)
- 新增: 环境适配性检测框架，启动时自动检测所有依赖组件
- 新增: 环境预检报告，主菜单展示组件可用性状态
- 新增: 每个加固项/回退项增加前置依赖检查，缺失组件时智能跳过
- 新增: Python3 不可用时状态管理自动降级为文本文件
- 新增: `generate_token()` 多方案备选 (urandom → openssl → sha256)
- 优化: `do_apply_1` 检测 ss/netstat 互备，非 systemd 跳过定时器
- 优化: `do_apply_2` 检测 useradd、nologin shell 路径自适应
- 优化: `do_apply_5` 检测 systemd + 服务账户是否存在
- 优化: `do_apply_6` 防火墙全链路检查 (命令 + 服务状态 + 规则持久化)
- 优化: `do_apply_7` dig + 防火墙双重检查，域名解析失败单独跳过
- 优化: `do_apply_8` AppArmor/SELinux 深度检查 (启用状态 + parser 工具)
- 优化: `do_apply_10` PAM limits 目录存在性检查
- 优化: `do_apply_12` auditd/脱敏/logrotate 三段独立降级
- 修复: 去除 `set -e`，避免检测命令失败导致脚本退出
- 修复: auditd 检测逻辑运算符优先级问题

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
