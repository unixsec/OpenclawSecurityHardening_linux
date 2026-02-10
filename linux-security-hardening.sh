#!/bin/bash
# ============================================================================
# OpenClaw Linux 安全加固脚本
# 版本: 1.3
# 作者: Alex
# 邮箱: unix_sec@163.com
# 许可证: Apache License 2.0
# 适用: Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / RHEL 8+
#
# 安全风险覆盖:
#   基于 OpenClaw 源码分析 + 互联网安全研究 (ClawHavoc, TIP劫持等)
#
#   [R1] Gateway 暴露风险     - 1800+ 实例暴露 API Key
#   [R2] 提示注入/命令注入    - Agent Shell 访问 + 提示词劫持
#   [R3] MCP 工具投毒         - ClawHavoc: 341 恶意 Skill
#   [R4] SSRF 攻击           - Agent 访问内网资源
#   [R5] 凭证泄露            - Token/API Key/聊天记录泄露
#   [R6] 权限提升            - elevated 工具 + 环境变量注入
#   [R7] 文件系统越界         - 路径遍历/符号链接攻击
#   [R8] 资源耗尽            - Fork 炸弹/内存耗尽
#   [R9] 供应链攻击          - ClawHub 恶意技能包
#   [R10] 日志/数据泄露       - 敏感信息写入日志
#
# 使用方法:
#   sudo ./linux-security-hardening.sh              # 交互式菜单
#   sudo ./linux-security-hardening.sh --dry-run    # 模拟运行
#   sudo ./linux-security-hardening.sh --rollback 5 # 回退加固项 5
#   sudo ./linux-security-hardening.sh --debug 3    # 调试加固项 3
#   sudo ./linux-security-hardening.sh --status     # 查看状态
#   sudo ./linux-security-hardening.sh --all        # 一键加固
# ============================================================================

# 不使用 set -e，避免环境检测命令失败导致脚本退出
set +e

# ============================================================================
# 配置变量
# ============================================================================
OPENCLAW_DIR="/opt/openclaw"
OPENCLAW_STATE_DIR="/var/lib/openclaw"
OPENCLAW_LOGS_DIR="/var/log/openclaw"
OPENCLAW_SECRETS_DIR="/etc/openclaw/secrets"
OPENCLAW_CONFIG_DIR="/etc/openclaw"
SERVICE_ACCOUNT="openclaw"
GATEWAY_PORT="18789"
NODE_PATH="/usr/bin/node"

LOG_DIR="/var/log/openclaw-hardening"
LOG_FILE="$LOG_DIR/hardening-$(date +%Y%m%d).log"
STATE_DIR="/var/lib/openclaw-hardening"
STATE_FILE="$STATE_DIR/hardening-state.json"

# ============================================================================
# 环境能力标记 (检测后填充，加固项据此决定是否跳过)
# ============================================================================
HAS_SYSTEMD=0
HAS_FIREWALL=0     # FIREWALL 变量存具体类型
HAS_MAC=0           # MAC_SYSTEM 变量存具体类型
HAS_PYTHON3=0
HAS_AUDITD=0
HAS_DIG=0
HAS_USERADD=0
HAS_PKG_MANAGER=0
HAS_SED=0
HAS_LOGROTATE=0

# AI API 出站白名单
AI_API_DOMAINS=(
    "api.openai.com"
    "api.anthropic.com"
    "api.deepseek.com"
    "generativelanguage.googleapis.com"
)

# Agent 工作目录白名单
ALLOWED_WORK_DIRS=(
    "/home"
    "/tmp/openclaw-workspace"
    "$OPENCLAW_STATE_DIR"
)

# 颜色
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
WHITE='\033[0;97m'
RESET='\033[0m'
DIM='\033[2m'

# 运行模式
DRY_RUN=0
DEBUG_MODE=0
DEBUG_ITEM=0
ROLLBACK_MODE=0
ROLLBACK_ITEM=0

# 加固项定义 (12 项)
declare -A ITEM_NAMES=(
    [1]="[R1] Gateway 绑定加固 (防暴露)"
    [2]="[R5] 服务账户隔离 (最小权限)"
    [3]="[R5][R7] 文件权限加固 (防泄露/越界)"
    [4]="[R5] 凭证安全管理 (Token/密钥)"
    [5]="[R2][R6][R8] systemd 进程沙箱"
    [6]="[R1] 防火墙端口限制"
    [7]="[R4] 网络出站白名单 (防 SSRF)"
    [8]="[R7][R6] AppArmor/SELinux 访问控制"
    [9]="[R2][R6] Bash Tool 命令限制 (防注入)"
    [10]="[R8] 资源限制 (防耗尽)"
    [11]="[R9][R3] MCP/Skill 供应链防护"
    [12]="[R10][R5] 日志审计与脱敏"
)

# 阶段标记: PRE=部署前, POST=部署后
declare -A ITEM_PHASE=(
    [1]="POST"     # Gateway 绑定 — 需要已安装的 config.yaml
    [2]="PRE"      # 服务账户 — 部署前创建
    [3]="PRE"      # 文件权限 — 部署前准备目录结构
    [4]="POST"     # 凭证管理 — 为已安装服务生成 Token/配置
    [5]="POST"     # systemd 沙箱 — 需要已安装的二进制文件
    [6]="PRE"      # 防火墙 — 部署前锁定端口
    [7]="PRE"      # 出站白名单 — 部署前限制网络
    [8]="POST"     # AppArmor/SELinux — 需要已安装的路径
    [9]="POST"     # Bash Tool 限制 — 为运行中服务配置
    [10]="PRE"     # 资源限制 — 部署前设置
    [11]="POST"    # MCP/Skill 防护 — 为运行中服务配置
    [12]="POST"    # 日志审计 — 监控运行中服务
)

declare -A PHASE_LABEL=(
    [PRE]="部署前"
    [POST]="部署后"
)

# 阶段顺序 (部署前项优先)
PRE_ITEMS=(2 3 6 7 10)
POST_ITEMS=(1 4 5 8 9 11 12)

declare -A ITEM_RISKS=(
    [1]="1800+ 实例暴露 API Key，攻击者可获取完整访问权限"
    [2]="服务以 root 运行可导致整个系统被控制"
    [3]="配置/密钥文件权限过宽导致凭证泄露"
    [4]="Gateway Token/API Key 明文存储或泄露"
    [5]="Agent 可提权执行系统命令、加载内核模块"
    [6]="Gateway 端口对外暴露导致未授权访问"
    [7]="Agent 被利用进行 SSRF 攻击内网资源"
    [8]="Agent 通过路径遍历/符号链接访问敏感文件"
    [9]="提示注入导致 Agent 执行 rm -rf / 等危险命令"
    [10]="恶意 prompt 导致 fork 炸弹或内存耗尽"
    [11]="ClawHavoc: 341 恶意 Skill 窃取凭证和数据"
    [12]="API Key/聊天记录写入日志导致信息泄露"
)

# ============================================================================
# 日志与状态管理
# ============================================================================

init_logging() {
    mkdir -p "$LOG_DIR" "$STATE_DIR" 2>/dev/null || true
    touch "$LOG_FILE" 2>/dev/null || true
    [ ! -f "$STATE_FILE" ] && echo '{"items":{}}' > "$STATE_FILE" 2>/dev/null || true
}

log() {
    local level=$1 message=$2
    local ts=$(date '+%Y-%m-%d %H:%M:%S')
    local caller="${FUNCNAME[2]:-main}"
    echo "[$ts] [$level] [$caller] $message" >> "$LOG_FILE" 2>/dev/null || true
    if [ "$DEBUG_MODE" -eq 1 ]; then
        case $level in
            INFO)  echo -e "${DIM}[$ts] [INFO] $message${RESET}" ;;
            WARN)  echo -e "${YELLOW}[$ts] [WARN] $message${RESET}" ;;
            ERROR) echo -e "${RED}[$ts] [ERROR] $message${RESET}" ;;
            DEBUG) echo -e "${CYAN}[$ts] [DEBUG] $message${RESET}" ;;
        esac
    fi
}
log_info()  { log "INFO" "$1"; }
log_warn()  { log "WARN" "$1"; }
log_error() { log "ERROR" "$1"; }
log_debug() { log "DEBUG" "$1"; }
log_action() { log "ACTION" "item=$2 action=$1 status=$3 detail=\"$4\""; }

get_item_state() {
    local item=$1
    if [ "$HAS_PYTHON3" -eq 1 ] && [ -f "$STATE_FILE" ]; then
        python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('items',{}).get('$item',{}).get('status','none'))" 2>/dev/null || echo "none"
    elif [ -f "$STATE_FILE" ]; then
        # 降级: 用 grep 简单匹配
        grep -oP "\"$item\":\s*\{[^}]*\"status\":\s*\"\\K[^\"]*" "$STATE_FILE" 2>/dev/null || echo "none"
    else
        echo "none"
    fi
}

set_item_state() {
    local item=$1 status=$2
    if [ "$HAS_PYTHON3" -eq 1 ]; then
        python3 -c "
import json
with open('$STATE_FILE','r') as f: d=json.load(f)
d.setdefault('items',{})['$item']={'status':'$status','timestamp':'$(date +%Y-%m-%dT%H:%M:%S)'}
with open('$STATE_FILE','w') as f: json.dump(d,f,indent=2)
" 2>/dev/null || log_warn "状态写入失败: item=$item status=$status"
    else
        # 降级: 简单文本记录
        echo "$item=$status $(date +%Y-%m-%dT%H:%M:%S)" >> "${STATE_DIR}/state-fallback.txt" 2>/dev/null || true
        log_warn "Python3 不可用, 使用降级状态记录"
    fi
}

clear_item_state() {
    local item=$1
    if [ "$HAS_PYTHON3" -eq 1 ] && [ -f "$STATE_FILE" ]; then
        python3 -c "
import json
with open('$STATE_FILE','r') as f: d=json.load(f)
d.get('items',{}).pop('$item',None)
with open('$STATE_FILE','w') as f: json.dump(d,f,indent=2)
" 2>/dev/null || true
    elif [ -f "${STATE_DIR}/state-fallback.txt" ]; then
        # 降级
        if [ "$HAS_SED" -eq 1 ]; then
            sed -i "/^${item}=/d" "${STATE_DIR}/state-fallback.txt" 2>/dev/null || true
        fi
    fi
}

# ============================================================================
# 系统检测与环境预检
# ============================================================================

detect_all() {
    # 发行版
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID; DISTRO_VERSION=$VERSION_ID; DISTRO_NAME=$NAME
    else
        DISTRO="unknown"; DISTRO_NAME="Unknown"; DISTRO_VERSION=""
    fi
    
    # systemd
    if command -v systemctl &>/dev/null && systemctl --version &>/dev/null; then
        HAS_SYSTEMD=1
    fi
    
    # 防火墙
    FIREWALL="none"
    if command -v ufw &>/dev/null; then
        FIREWALL="ufw"; HAS_FIREWALL=1
    elif command -v firewall-cmd &>/dev/null; then
        FIREWALL="firewalld"; HAS_FIREWALL=1
    elif command -v iptables &>/dev/null; then
        FIREWALL="iptables"; HAS_FIREWALL=1
    fi
    
    # 强制访问控制
    MAC_SYSTEM="none"
    if command -v aa-status &>/dev/null; then
        MAC_SYSTEM="apparmor"; HAS_MAC=1
    elif command -v getenforce &>/dev/null; then
        MAC_SYSTEM="selinux"; HAS_MAC=1
    fi
    
    # 包管理器
    PKG_MANAGER="unknown"
    if command -v apt-get &>/dev/null; then
        PKG_MANAGER="apt"; HAS_PKG_MANAGER=1
    elif command -v dnf &>/dev/null; then
        PKG_MANAGER="dnf"; HAS_PKG_MANAGER=1
    elif command -v yum &>/dev/null; then
        PKG_MANAGER="yum"; HAS_PKG_MANAGER=1
    fi
    
    # 其他工具
    command -v python3 &>/dev/null && HAS_PYTHON3=1
    { command -v auditd &>/dev/null || command -v auditctl &>/dev/null; } && HAS_AUDITD=1
    command -v dig &>/dev/null && HAS_DIG=1
    command -v useradd &>/dev/null && HAS_USERADD=1
    command -v sed &>/dev/null && HAS_SED=1
    command -v logrotate &>/dev/null && HAS_LOGROTATE=1
    
    log_info "环境检测: distro=$DISTRO $DISTRO_VERSION, systemd=$HAS_SYSTEMD, firewall=$FIREWALL, mac=$MAC_SYSTEM, pkg=$PKG_MANAGER, python3=$HAS_PYTHON3, auditd=$HAS_AUDITD, dig=$HAS_DIG"
}

# 环境预检报告 (在菜单中显示)
show_env_summary() {
    echo -e "${WHITE}环境检测:${RESET}"
    [ "$HAS_SYSTEMD" -eq 1 ]     && echo -e "  ${GREEN}✓${RESET} systemd"          || echo -e "  ${RED}✗${RESET} systemd (加固项 1,5 受限)"
    [ "$HAS_FIREWALL" -eq 1 ]    && echo -e "  ${GREEN}✓${RESET} 防火墙: $FIREWALL" || echo -e "  ${RED}✗${RESET} 防火墙 (加固项 6,7 跳过)"
    [ "$HAS_MAC" -eq 1 ]         && echo -e "  ${GREEN}✓${RESET} MAC: $MAC_SYSTEM"  || echo -e "  ${YELLOW}✗${RESET} AppArmor/SELinux (加固项 8 跳过)"
    [ "$HAS_PYTHON3" -eq 1 ]     && echo -e "  ${GREEN}✓${RESET} Python3"           || echo -e "  ${YELLOW}✗${RESET} Python3 (状态管理降级)"
    [ "$HAS_USERADD" -eq 1 ]     && echo -e "  ${GREEN}✓${RESET} useradd"           || echo -e "  ${RED}✗${RESET} useradd (加固项 2 跳过)"
    echo ""
}

# 带依赖检查的跳过提示
skip_item() {
    local reason=$1
    echo -e "  ${YELLOW}[跳过] $reason${RESET}"
    log_warn "跳过: $reason"
}

install_package() {
    local pkg=$1
    if [ "$HAS_PKG_MANAGER" -eq 0 ]; then
        log_warn "无包管理器，无法安装 $pkg"
        return 1
    fi
    log_info "安装: $pkg"
    case $PKG_MANAGER in
        apt) apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        yum) yum install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        dnf) dnf install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        *) return 1 ;;
    esac
}

generate_token() {
    if [ -r /dev/urandom ]; then
        < /dev/urandom tr -dc 'A-Za-z0-9' | head -c 32
    elif command -v openssl &>/dev/null; then
        openssl rand -base64 24 | tr -dc 'A-Za-z0-9' | head -c 32
    else
        # 最后手段
        date +%s%N | sha256sum | head -c 32
    fi
}

# ============================================================================
# [1] Gateway 绑定加固 — 防止 1800+ 暴露事件
# ============================================================================

do_apply_1() {
    log_info "加固 Gateway 绑定配置"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将强制 Gateway 绑定到 loopback${RESET}"
        return
    fi
    
    mkdir -p "$OPENCLAW_CONFIG_DIR" 2>/dev/null || { skip_item "无法创建配置目录 $OPENCLAW_CONFIG_DIR"; return; }
    
    # 检查并修复 Gateway 绑定
    if [ -f "$OPENCLAW_CONFIG_DIR/config.yaml" ]; then
        if grep -q 'bind:.*loopback' "$OPENCLAW_CONFIG_DIR/config.yaml" 2>/dev/null; then
            echo -e "  ${YELLOW}[幂等] Gateway 已绑定到 loopback${RESET}"
        else
            if [ "$HAS_SED" -eq 1 ]; then
                sed -i 's/bind:.*/bind: loopback/' "$OPENCLAW_CONFIG_DIR/config.yaml"
                log_info "已修复 Gateway 绑定为 loopback"
                echo "  已修复 Gateway 绑定为 loopback"
            else
                log_warn "sed 不可用，无法自动修复绑定，请手动编辑 config.yaml"
                echo -e "  ${YELLOW}[警告] sed 不可用，请手动修改 bind: loopback${RESET}"
            fi
        fi
    fi
    
    # 创建绑定检查脚本 (使用 ss 或 netstat)
    local NET_CMD="ss -tlnp"
    command -v ss &>/dev/null || { command -v netstat &>/dev/null && NET_CMD="netstat -tlnp"; } || { log_warn "ss/netstat 均不可用，跳过创建检查脚本"; }
    
    cat > "$OPENCLAW_CONFIG_DIR/check-gateway-bind.sh" << SCRIPT
#!/bin/bash
# 检查 Gateway 是否暴露
EXPOSED=\$($NET_CMD 2>/dev/null | grep ":$GATEWAY_PORT " | grep -v "127.0.0.1" | grep -v "::1")
if [ -n "\$EXPOSED" ]; then
    echo "[CRITICAL] Gateway 端口 $GATEWAY_PORT 对外暴露!"
    echo "\$EXPOSED"
    command -v logger &>/dev/null && logger -p auth.crit "OpenClaw Gateway exposed on non-loopback address"
    exit 1
else
    echo "[OK] Gateway 仅绑定到本地回环"
    exit 0
fi
SCRIPT
    chmod 750 "$OPENCLAW_CONFIG_DIR/check-gateway-bind.sh"

    # 创建 systemd timer 定期检查 (仅 systemd 环境)
    if [ "$HAS_SYSTEMD" -eq 1 ]; then
        cat > /etc/systemd/system/openclaw-bind-check.service << EOF
[Unit]
Description=OpenClaw Gateway Bind Check

[Service]
Type=oneshot
ExecStart=$OPENCLAW_CONFIG_DIR/check-gateway-bind.sh
EOF
        cat > /etc/systemd/system/openclaw-bind-check.timer << EOF
[Unit]
Description=Periodic OpenClaw Gateway Bind Check

[Timer]
OnBootSec=60
OnUnitActiveSec=300

[Install]
WantedBy=timers.target
EOF
        systemctl daemon-reload
        systemctl enable --now openclaw-bind-check.timer 2>/dev/null || true
    else
        echo -e "  ${YELLOW}[提示] 非 systemd 系统，跳过定时检查任务 (可手动执行 check-gateway-bind.sh)${RESET}"
        log_warn "非 systemd 环境，跳过定时检查"
    fi
    
    log_action "apply" "1" "success" "Gateway 绑定加固完成"
    echo -e "  ${GREEN}[完成] Gateway 绑定加固 + 定期检查${RESET}"
}

do_rollback_1() {
    log_info "回退: Gateway 绑定加固"
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$OPENCLAW_CONFIG_DIR/check-gateway-bind.sh"
        if [ "$HAS_SYSTEMD" -eq 1 ]; then
            systemctl disable --now openclaw-bind-check.timer 2>/dev/null || true
            rm -f /etc/systemd/system/openclaw-bind-check.{service,timer}
            systemctl daemon-reload 2>/dev/null || true
        fi
    fi
    log_action "rollback" "1" "success" "Gateway 绑定加固已回退"
    echo -e "  ${GREEN}[完成] 已回退${RESET}"
}

# ============================================================================
# [2] 服务账户隔离
# ============================================================================

do_apply_2() {
    log_info "创建服务账户: $SERVICE_ACCOUNT"
    
    # 环境检查: useradd
    if [ "$HAS_USERADD" -eq 0 ]; then
        skip_item "useradd 不可用，无法创建服务账户 (容器环境或最小化安装?)"
        return
    fi
    
    if id "$SERVICE_ACCOUNT" &>/dev/null; then
        echo -e "  ${YELLOW}[幂等] 服务账户已存在${RESET}"
    elif [ "$DRY_RUN" -eq 0 ]; then
        local nologin_shell="/usr/sbin/nologin"
        [ ! -f "$nologin_shell" ] && nologin_shell="/sbin/nologin"
        [ ! -f "$nologin_shell" ] && nologin_shell="/bin/false"
        
        useradd -r -s "$nologin_shell" -d "$OPENCLAW_STATE_DIR" \
                -c "OpenClaw Service Account" "$SERVICE_ACCOUNT" 2>/dev/null
        if [ $? -ne 0 ]; then
            log_error "创建服务账户失败"
            echo -e "  ${RED}[失败] 创建账户失败${RESET}"
            return
        fi
        echo "  账户 $SERVICE_ACCOUNT 已创建 (shell: $nologin_shell)"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将创建账户 $SERVICE_ACCOUNT${RESET}"
        return
    fi
    
    [ "$DRY_RUN" -eq 0 ] && {
        command -v passwd &>/dev/null && passwd -l "$SERVICE_ACCOUNT" &>/dev/null || true
        command -v gpasswd &>/dev/null && {
            gpasswd -d "$SERVICE_ACCOUNT" sudo &>/dev/null || true
            gpasswd -d "$SERVICE_ACCOUNT" wheel &>/dev/null || true
        }
    }
    
    log_action "apply" "2" "success" "服务账户已配置"
    echo -e "  ${GREEN}[完成] 服务账户已创建且无特权${RESET}"
}

do_rollback_2() {
    if [ "$DRY_RUN" -eq 0 ] && id "$SERVICE_ACCOUNT" &>/dev/null; then
        if command -v userdel &>/dev/null; then
            userdel "$SERVICE_ACCOUNT" 2>/dev/null || true
            echo -e "  ${GREEN}[完成] 账户已删除${RESET}"
        else
            skip_item "userdel 不可用，无法删除账户"
        fi
    elif ! id "$SERVICE_ACCOUNT" &>/dev/null; then
        echo -e "  ${YELLOW}[跳过] 账户不存在${RESET}"
    fi
    log_action "rollback" "2" "success" ""
}

# ============================================================================
# [3] 文件权限加固 — 防凭证泄露/路径遍历
# ============================================================================

do_apply_3() {
    log_info "配置文件权限"
    if [ "$DRY_RUN" -eq 1 ]; then echo -e "  ${CYAN}[DRY-RUN]${RESET}"; return; fi
    
    mkdir -p "$OPENCLAW_DIR" "$OPENCLAW_STATE_DIR" "$OPENCLAW_LOGS_DIR" \
             "$OPENCLAW_SECRETS_DIR" "$OPENCLAW_CONFIG_DIR" "/tmp/openclaw-workspace"
    
    # 代码目录 (只读)
    chown -R root:"$SERVICE_ACCOUNT" "$OPENCLAW_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_DIR"
    find "$OPENCLAW_DIR" -type f -exec chmod 640 {} \; 2>/dev/null || true
    
    # 密钥目录 (严格)
    chown -R root:"$SERVICE_ACCOUNT" "$OPENCLAW_SECRETS_DIR" 2>/dev/null || true
    chmod 700 "$OPENCLAW_SECRETS_DIR"
    find "$OPENCLAW_SECRETS_DIR" -type f -exec chmod 600 {} \; 2>/dev/null || true
    
    # 配置目录
    chown -R root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_CONFIG_DIR"
    
    # 状态目录 (可写)
    chown -R "$SERVICE_ACCOUNT":"$SERVICE_ACCOUNT" "$OPENCLAW_STATE_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_STATE_DIR"
    
    # 日志目录
    chown -R "$SERVICE_ACCOUNT":"$SERVICE_ACCOUNT" "$OPENCLAW_LOGS_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_LOGS_DIR"
    
    # 工作空间
    chown -R "$SERVICE_ACCOUNT":"$SERVICE_ACCOUNT" "/tmp/openclaw-workspace" 2>/dev/null || true
    chmod 750 "/tmp/openclaw-workspace"
    
    # 防止符号链接攻击 (OpenClaw 源码使用 O_NOFOLLOW 但需系统级加固)
    echo 1 > /proc/sys/fs/protected_symlinks 2>/dev/null || true
    echo 1 > /proc/sys/fs/protected_hardlinks 2>/dev/null || true
    
    log_action "apply" "3" "success" "文件权限配置完成"
    echo -e "  ${GREEN}[完成] 文件权限 + 符号链接保护${RESET}"
}

do_rollback_3() {
    [ "$DRY_RUN" -eq 0 ] && {
        chmod 755 "$OPENCLAW_DIR" "$OPENCLAW_STATE_DIR" "$OPENCLAW_LOGS_DIR" "$OPENCLAW_CONFIG_DIR" 2>/dev/null || true
        chmod 755 "$OPENCLAW_SECRETS_DIR" 2>/dev/null || true
    }
    log_action "rollback" "3" "success" ""
    echo -e "  ${GREEN}[完成] 权限已重置${RESET}"
}

# ============================================================================
# [4] 凭证安全管理 — 防 Token/API Key 泄露
# ============================================================================

do_apply_4() {
    log_info "配置凭证安全"
    if [ "$DRY_RUN" -eq 1 ]; then echo -e "  ${CYAN}[DRY-RUN]${RESET}"; return; fi
    
    mkdir -p "$OPENCLAW_SECRETS_DIR" "$OPENCLAW_CONFIG_DIR"
    
    # 生成 Gateway Token (幂等)
    if [ ! -f "$OPENCLAW_SECRETS_DIR/gateway-token" ]; then
        generate_token > "$OPENCLAW_SECRETS_DIR/gateway-token"
        chmod 600 "$OPENCLAW_SECRETS_DIR/gateway-token"
        chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_SECRETS_DIR/gateway-token" 2>/dev/null || true
        echo "  Gateway Token 已生成"
    else
        echo -e "  ${YELLOW}[幂等] Token 已存在${RESET}"
    fi
    
    # 安全配置文件 (幂等)
    if [ ! -f "$OPENCLAW_CONFIG_DIR/config.yaml" ]; then
        cat > "$OPENCLAW_CONFIG_DIR/config.yaml" << EOF
# OpenClaw 安全配置 - $(date '+%Y-%m-%d %H:%M:%S')
gateway:
  bind: loopback
  port: $GATEWAY_PORT
  auth:
    mode: token
  controlUi:
    enabled: true
    allowInsecureAuth: false
    dangerouslyDisableDeviceAuth: false
logging:
  redactSensitive: tools
tools:
  elevated:
    enabled: false
  bash:
    allowedPaths:
$(for dir in "${ALLOWED_WORK_DIRS[@]}"; do echo "      - $dir"; done)
browser:
  enabled: false
EOF
        chmod 640 "$OPENCLAW_CONFIG_DIR/config.yaml"
        chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR/config.yaml" 2>/dev/null || true
    else
        echo -e "  ${YELLOW}[幂等] 配置已存在${RESET}"
    fi
    
    # 环境变量文件 (防止环境变量注入攻击)
    cat > "$OPENCLAW_CONFIG_DIR/environment" << EOF
OPENCLAW_STATE_DIR=$OPENCLAW_STATE_DIR
OPENCLAW_GATEWAY_TOKEN_FILE=$OPENCLAW_SECRETS_DIR/gateway-token
NODE_ENV=production
# 阻止代码生成攻击 (源码 bash-tools.exec.ts 过滤的危险变量)
NODE_OPTIONS=--disallow-code-generation-from-strings
EOF
    chmod 640 "$OPENCLAW_CONFIG_DIR/environment"
    chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR/environment" 2>/dev/null || true
    
    # 创建 .openclaw 目录权限检查
    if [ -d "$HOME/.openclaw" ]; then
        chmod 700 "$HOME/.openclaw"
        [ -f "$HOME/.openclaw/device-auth.json" ] && chmod 600 "$HOME/.openclaw/device-auth.json"
        log_info "已加固 ~/.openclaw 目录权限"
    fi
    
    log_action "apply" "4" "success" "凭证安全配置完成"
    echo -e "  ${GREEN}[完成] Token + 配置 + 环境变量保护${RESET}"
}

do_rollback_4() {
    [ "$DRY_RUN" -eq 0 ] && {
        rm -f "$OPENCLAW_SECRETS_DIR/gateway-token"
        rm -f "$OPENCLAW_CONFIG_DIR/config.yaml"
        rm -f "$OPENCLAW_CONFIG_DIR/environment"
    }
    log_action "rollback" "4" "success" ""
    echo -e "  ${GREEN}[完成] 凭证配置已删除${RESET}"
}

# ============================================================================
# [5] systemd 进程沙箱 — 防提权/命令执行/资源耗尽
# ============================================================================

do_apply_5() {
    log_info "安装 systemd 进程沙箱"
    
    # 环境检查: systemd
    if [ "$HAS_SYSTEMD" -eq 0 ]; then
        skip_item "非 systemd 系统 (可能是容器/旧 init 系统)，无法创建服务沙箱。建议手动配置进程隔离。"
        return
    fi
    if [ "$DRY_RUN" -eq 1 ]; then echo -e "  ${CYAN}[DRY-RUN] 将创建 systemd 沙箱服务${RESET}"; return; fi
    
    # 检查服务账户是否存在 (依赖加固项 2)
    if ! id "$SERVICE_ACCOUNT" &>/dev/null; then
        log_warn "服务账户 $SERVICE_ACCOUNT 不存在，服务将以 nobody 运行"
        echo -e "  ${YELLOW}[警告] 服务账户不存在，建议先执行加固项 2${RESET}"
    fi
    
    [ -f /etc/systemd/system/openclaw.service ] && echo -e "  ${YELLOW}[幂等] 服务已存在，更新配置${RESET}"
    
    cat > /etc/systemd/system/openclaw.service << EOF
[Unit]
Description=OpenClaw AI Gateway Service
After=network.target

[Service]
Type=simple
User=$SERVICE_ACCOUNT
Group=$SERVICE_ACCOUNT
WorkingDirectory=$OPENCLAW_DIR
EnvironmentFile=$OPENCLAW_CONFIG_DIR/environment
ExecStart=$NODE_PATH $OPENCLAW_DIR/dist/entry.js start
Restart=always
RestartSec=5
StandardOutput=append:$OPENCLAW_LOGS_DIR/stdout.log
StandardError=append:$OPENCLAW_LOGS_DIR/stderr.log

# ===== 进程沙箱 (防 R2 提权 + R6 命令执行) =====
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true

ReadWritePaths=$OPENCLAW_STATE_DIR $OPENCLAW_LOGS_DIR /tmp/openclaw-workspace
ReadOnlyPaths=$OPENCLAW_DIR $OPENCLAW_CONFIG_DIR $OPENCLAW_SECRETS_DIR

# 内核保护 (防加载内核模块/修改参数)
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true

# 设备/命名空间隔离
PrivateDevices=true
ProtectHostname=true
ProtectClock=true

# 网络限制
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX

# 系统调用过滤 (阻止 mount/reboot/模块加载等)
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @clock @module @raw-io @obsolete

# 能力限制 (仅保留绑定端口)
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=

# 内存保护 (防 RCE 利用)
MemoryDenyWriteExecute=true
RestrictNamespaces=true
LockPersonality=true
RestrictRealtime=true
RestrictSUIDSGID=true

# ===== 资源限制 (防 R8 耗尽) =====
CPUQuota=80%
MemoryMax=2G
MemoryHigh=1536M
TasksMax=128
LimitNOFILE=4096
LimitNPROC=64
LimitCORE=0
OOMScoreAdjust=300

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openclaw 2>/dev/null || true
    
    log_action "apply" "5" "success" "systemd 进程沙箱安装完成"
    echo -e "  ${GREEN}[完成] 进程沙箱 + 系统调用过滤 + 资源限制${RESET}"
}

do_rollback_5() {
    if [ "$HAS_SYSTEMD" -eq 0 ]; then
        echo -e "  ${YELLOW}[跳过] 非 systemd 系统${RESET}"
        log_action "rollback" "5" "skipped" "非 systemd"
        return
    fi
    [ "$DRY_RUN" -eq 0 ] && {
        systemctl stop openclaw 2>/dev/null || true
        systemctl disable openclaw 2>/dev/null || true
        rm -f /etc/systemd/system/openclaw.service
        rm -rf /etc/systemd/system/openclaw.service.d
        systemctl daemon-reload 2>/dev/null || true
    }
    log_action "rollback" "5" "success" ""
    echo -e "  ${GREEN}[完成] 服务已删除${RESET}"
}

# ============================================================================
# [6] 防火墙端口限制 — 防 Gateway 暴露
# ============================================================================

do_apply_6() {
    log_info "配置防火墙 ($FIREWALL)"
    
    # 环境检查: 防火墙
    if [ "$HAS_FIREWALL" -eq 0 ]; then
        skip_item "未检测到防火墙 (ufw/firewalld/iptables)，请先安装防火墙或手动限制端口 $GATEWAY_PORT"
        return
    fi
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将使用 $FIREWALL 限制端口 $GATEWAY_PORT${RESET}"
        return
    fi
    
    case $FIREWALL in
        ufw)
            # 检查 ufw 服务是否正常
            if ! ufw status &>/dev/null; then
                skip_item "ufw 命令存在但服务异常，跳过"
                return
            fi
            ufw deny in on any to any port "$GATEWAY_PORT" proto tcp \
                comment "OpenClaw - Block External" 2>/dev/null || true
            ufw allow in on lo to any port "$GATEWAY_PORT" proto tcp \
                comment "OpenClaw - Allow Local" 2>/dev/null || true
            ufw --force enable 2>/dev/null || true
            ;;
        firewalld)
            # 检查 firewalld 服务状态
            if ! systemctl is-active firewalld &>/dev/null; then
                systemctl start firewalld 2>/dev/null || { skip_item "firewalld 服务启动失败"; return; }
            fi
            systemctl enable firewalld 2>/dev/null || true
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=$GATEWAY_PORT protocol=tcp reject" 2>/dev/null || true
            firewall-cmd --permanent --zone=trusted --add-interface=lo 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
            ;;
        iptables)
            iptables -C INPUT -p tcp --dport "$GATEWAY_PORT" -j DROP 2>/dev/null || \
                iptables -A INPUT -p tcp --dport "$GATEWAY_PORT" -j DROP 2>/dev/null || { skip_item "iptables 规则添加失败"; return; }
            iptables -C INPUT -i lo -p tcp --dport "$GATEWAY_PORT" -j ACCEPT 2>/dev/null || \
                iptables -I INPUT -i lo -p tcp --dport "$GATEWAY_PORT" -j ACCEPT 2>/dev/null || true
            # 持久化 (可能不存在目录)
            if [ -d /etc/iptables ]; then
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            elif command -v netfilter-persistent &>/dev/null; then
                netfilter-persistent save 2>/dev/null || true
            else
                log_warn "iptables 规则无法持久化 (重启后丢失)，建议安装 iptables-persistent"
                echo -e "  ${YELLOW}[警告] 规则未持久化，重启后丢失${RESET}"
            fi
            ;;
    esac
    
    log_action "apply" "6" "success" "防火墙配置完成 ($FIREWALL)"
    echo -e "  ${GREEN}[完成] 端口 $GATEWAY_PORT 已限制为本地访问 ($FIREWALL)${RESET}"
}

do_rollback_6() {
    if [ "$HAS_FIREWALL" -eq 0 ]; then
        echo -e "  ${YELLOW}[跳过] 无防火墙${RESET}"
        log_action "rollback" "6" "skipped" "无防火墙"
        return
    fi
    [ "$DRY_RUN" -eq 0 ] && {
        case $FIREWALL in
            ufw) ufw delete deny "$GATEWAY_PORT/tcp" 2>/dev/null || true ;;
            firewalld) firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 port port=$GATEWAY_PORT protocol=tcp reject" 2>/dev/null; firewall-cmd --reload 2>/dev/null || true ;;
            iptables) iptables -D INPUT -p tcp --dport "$GATEWAY_PORT" -j DROP 2>/dev/null || true ;;
        esac
    }
    log_action "rollback" "6" "success" ""
    echo -e "  ${GREEN}[完成] 防火墙规则已删除${RESET}"
}

# ============================================================================
# [7] 网络出站白名单 — 防 SSRF (源码有 fetchWithSsrFGuard 但需网络层加固)
# ============================================================================

do_apply_7() {
    log_info "配置网络出站白名单"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] AI API 白名单:${RESET}"
        for d in "${AI_API_DOMAINS[@]}"; do echo "    - $d"; done
        [ "$HAS_FIREWALL" -eq 0 ] && echo -e "  ${YELLOW}[提示] 无防火墙，将仅生成白名单配置文件${RESET}"
        [ "$HAS_DIG" -eq 0 ] && echo -e "  ${YELLOW}[提示] dig 不可用，无法解析域名 IP，将跳过防火墙规则${RESET}"
        return
    fi
    
    mkdir -p "$OPENCLAW_CONFIG_DIR"
    
    # 保存白名单配置文件 (不依赖防火墙，始终生成)
    cat > "$OPENCLAW_CONFIG_DIR/outbound-whitelist.conf" << EOF
# OpenClaw 出站白名单 - $(date '+%Y-%m-%d %H:%M:%S')
# 用于 SSRF 防护 (源码 src/infra/net/ssrf.ts 提供应用层防护)
# 此处提供网络层加固
$(for d in "${AI_API_DOMAINS[@]}"; do echo "$d"; done)
EOF
    chmod 640 "$OPENCLAW_CONFIG_DIR/outbound-whitelist.conf"
    echo -e "  ${GREEN}[完成] 白名单配置文件已生成${RESET}"
    
    # 防火墙出站规则 (需要防火墙 + dig)
    if [ "$HAS_FIREWALL" -eq 0 ]; then
        echo -e "  ${YELLOW}[提示] 无防火墙，跳过出站防火墙规则 (已生成白名单配置文件供应用层参考)${RESET}"
        log_warn "无防火墙，仅生成白名单配置文件"
    elif [ "$HAS_DIG" -eq 0 ]; then
        echo -e "  ${YELLOW}[提示] dig 不可用，无法解析域名 IP，跳过防火墙规则${RESET}"
        echo -e "  ${YELLOW}        安装 dig: apt install dnsutils / yum install bind-utils${RESET}"
        log_warn "dig 不可用，跳过出站规则 (白名单配置文件已生成)"
    elif [ "$FIREWALL" = "iptables" ] || [ "$FIREWALL" = "ufw" ]; then
        local resolved=0
        for domain in "${AI_API_DOMAINS[@]}"; do
            log_debug "解析: $domain"
            ips=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | head -5)
            if [ -z "$ips" ]; then
                log_warn "域名 $domain 解析失败，跳过"
                echo -e "  ${YELLOW}[警告] $domain 解析失败${RESET}"
                continue
            fi
            for ip in $ips; do
                if [ "$FIREWALL" = "ufw" ]; then
                    ufw allow out to "$ip" port 443 proto tcp comment "AI: $domain" 2>/dev/null || true
                else
                    iptables -C OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT 2>/dev/null || \
                        iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT 2>/dev/null || true
                fi
                ((resolved++))
            done
        done
        echo -e "  ${GREEN}[完成] $resolved 条出站规则已添加${RESET}"
    else
        echo -e "  ${YELLOW}[提示] firewalld 出站规则需手动配置，已生成白名单配置文件${RESET}"
    fi
    
    log_action "apply" "7" "success" "出站白名单配置完成"
}

do_rollback_7() {
    [ "$DRY_RUN" -eq 0 ] && rm -f "$OPENCLAW_CONFIG_DIR/outbound-whitelist.conf"
    log_action "rollback" "7" "success" ""
    echo -e "  ${GREEN}[完成] 白名单已删除 (防火墙规则需手动清理)${RESET}"
}

# ============================================================================
# [8] AppArmor/SELinux — 防文件越界/路径遍历
# ============================================================================

do_apply_8() {
    log_info "配置 MAC ($MAC_SYSTEM)"
    
    # 环境检查: MAC 系统
    if [ "$HAS_MAC" -eq 0 ]; then
        skip_item "未检测到 AppArmor 或 SELinux。如需强制访问控制，请先安装: apt install apparmor / yum install selinux-policy"
        return
    fi
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置 $MAC_SYSTEM 策略${RESET}"
        return
    fi
    
    case $MAC_SYSTEM in
        apparmor)
            # 检查 AppArmor 是否实际启用
            if ! aa-status &>/dev/null; then
                skip_item "AppArmor 已安装但未启用。请执行: systemctl enable --now apparmor"
                return
            fi
            # 检查 apparmor_parser
            if ! command -v apparmor_parser &>/dev/null; then
                skip_item "apparmor_parser 不可用，无法加载策略"
                return
            fi
            cat > /etc/apparmor.d/openclaw << 'EOF'
#include <tunables/global>

profile openclaw /usr/bin/node {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Node.js
  /usr/bin/node ix,
  /usr/local/bin/node ix,

  # OpenClaw 代码 (只读)
  /opt/openclaw/** r,
  /opt/openclaw/dist/** ix,

  # 配置和密钥 (只读)
  /etc/openclaw/** r,

  # 状态和日志 (读写)
  /var/lib/openclaw/** rw,
  /var/log/openclaw/** rw,

  # Agent 工作空间 (受限读写)
  /tmp/openclaw-workspace/** rw,
  /home/** rw,
  /tmp/** rw,

  # 网络
  network inet stream,
  network inet6 stream,
  network unix stream,

  # ===== 禁止: 防止 Agent 越界访问 =====
  deny /etc/passwd w,
  deny /etc/shadow rw,
  deny /etc/sudoers rw,
  deny /etc/pam.d/** w,
  deny /etc/ssh/** w,
  deny /root/.ssh/** rw,
  deny /home/*/.ssh/** rw,
  deny /boot/** rw,
  deny /sys/** w,
  deny /proc/sys/** w,
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_rawio,
  deny capability net_admin,
  deny capability sys_module,
}
EOF
            apparmor_parser -r /etc/apparmor.d/openclaw 2>/dev/null || true
            ;;
        selinux)
            local sestate
            sestate=$(getenforce 2>/dev/null)
            if [ "$sestate" = "Disabled" ]; then
                skip_item "SELinux 已安装但处于 Disabled 状态，无法配置。请修改 /etc/selinux/config 后重启。"
                return
            fi
            if ! command -v semanage &>/dev/null; then
                skip_item "semanage 不可用，请安装: yum install policycoreutils-python-utils"
                return
            fi
            semanage fcontext -a -t bin_t "$OPENCLAW_DIR/dist(/.*)?" 2>/dev/null || true
            semanage fcontext -a -t var_lib_t "$OPENCLAW_STATE_DIR(/.*)?" 2>/dev/null || true
            command -v restorecon &>/dev/null && restorecon -Rv "$OPENCLAW_DIR" "$OPENCLAW_STATE_DIR" 2>/dev/null || true
            ;;
    esac
    
    log_action "apply" "8" "success" "MAC 配置完成"
    echo -e "  ${GREEN}[完成] 强制访问控制已配置${RESET}"
}

do_rollback_8() {
    if [ "$HAS_MAC" -eq 0 ]; then
        echo -e "  ${YELLOW}[跳过] 无 MAC 系统${RESET}"
        log_action "rollback" "8" "skipped" "无 MAC"
        return
    fi
    [ "$DRY_RUN" -eq 0 ] && {
        if [ "$MAC_SYSTEM" = "apparmor" ]; then
            rm -f /etc/apparmor.d/openclaw
            command -v apparmor_parser &>/dev/null && apparmor_parser -R openclaw 2>/dev/null || true
        elif [ "$MAC_SYSTEM" = "selinux" ]; then
            command -v semanage &>/dev/null && {
                semanage fcontext -d "$OPENCLAW_DIR/dist(/.*)?" 2>/dev/null || true
                semanage fcontext -d "$OPENCLAW_STATE_DIR(/.*)?" 2>/dev/null || true
            }
        fi
    }
    log_action "rollback" "8" "success" ""
    echo -e "  ${GREEN}[完成] MAC 策略已删除${RESET}"
}

# ============================================================================
# [9] Bash Tool 命令限制 — 防提示注入/命令注入
# ============================================================================

do_apply_9() {
    log_info "配置 Bash Tool 安全限制"
    if [ "$DRY_RUN" -eq 1 ]; then echo -e "  ${CYAN}[DRY-RUN]${RESET}"; return; fi
    
    mkdir -p "$OPENCLAW_CONFIG_DIR"
    
    # 命令限制配置 (基于源码 bash-tools.exec.ts 的 allowlist 机制)
    cat > "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf" << 'EOF'
# OpenClaw Bash Tool 安全限制
# 基于源码 src/agents/bash-tools.exec.ts 的安全机制扩展

# ===== 阻止的命令 (覆盖提示注入常见攻击) =====
BLOCKED_COMMANDS=(
    # 用户/权限管理
    "useradd" "userdel" "usermod" "passwd" "chpasswd"
    "groupadd" "groupdel" "groupmod"
    "chmod" "chown" "chgrp" "setfacl"
    "visudo"
    
    # 系统控制
    "reboot" "shutdown" "poweroff" "init" "systemctl"
    "service" "update-rc.d"
    
    # 网络配置
    "iptables" "ip6tables" "ufw" "firewall-cmd"
    "ifconfig" "ip" "route" "netplan"
    
    # 磁盘操作
    "mount" "umount" "fdisk" "mkfs" "dd" "parted"
    
    # 包管理
    "apt" "apt-get" "dpkg" "yum" "dnf" "rpm" "snap"
    
    # 提权工具
    "sudo" "su" "pkexec" "doas"
    
    # 定时任务
    "crontab" "at"
    
    # 危险网络工具 (防 SSRF/数据外泄)
    "nc" "netcat" "ncat" "socat"
    
    # 编译工具 (防恶意代码编译执行)
    "gcc" "g++" "make" "cc" "as" "ld"
    
    # 容器逃逸相关
    "docker" "podman" "nsenter" "unshare" "chroot"
)

# ===== 危险环境变量 (与源码 DANGEROUS_HOST_ENV_VARS 对齐) =====
BLOCKED_ENV_VARS=(
    "LD_PRELOAD"
    "LD_LIBRARY_PATH"
    "DYLD_INSERT_LIBRARIES"
    "DYLD_LIBRARY_PATH"
    "NODE_OPTIONS"
    "PYTHONPATH"
    "PERL5LIB"
    "RUBYLIB"
)

# ===== 目录限制 =====
ALLOWED_PATHS=("/home" "/tmp/openclaw-workspace" "/var/lib/openclaw")
BLOCKED_PATHS=("/etc" "/root" "/boot" "/sys" "/proc" "/dev" "/usr/sbin" "/sbin")

MAX_EXEC_TIME=60
MAX_OUTPUT_SIZE=1048576
ALLOW_BACKGROUND=false
EOF

    chmod 640 "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf"
    chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf" 2>/dev/null || true
    
    # 受限 shell 包装器
    cat > "$OPENCLAW_DIR/restricted-bash.sh" << 'WRAPPER'
#!/bin/bash
# OpenClaw 受限 Bash 执行器
TIMEOUT=60
enable -n source
enable -n eval
export PATH="/usr/bin:/bin"
# 清理危险环境变量
unset LD_PRELOAD LD_LIBRARY_PATH DYLD_INSERT_LIBRARIES NODE_OPTIONS
timeout $TIMEOUT bash -r -c "$@"
WRAPPER
    chmod 750 "$OPENCLAW_DIR/restricted-bash.sh" 2>/dev/null || true
    chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_DIR/restricted-bash.sh" 2>/dev/null || true
    
    log_action "apply" "9" "success" "Bash Tool 限制配置完成"
    echo -e "  ${GREEN}[完成] 命令黑名单 + 环境变量过滤 + 受限 Shell${RESET}"
}

do_rollback_9() {
    [ "$DRY_RUN" -eq 0 ] && {
        rm -f "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf"
        rm -f "$OPENCLAW_DIR/restricted-bash.sh"
    }
    log_action "rollback" "9" "success" ""
    echo -e "  ${GREEN}[完成] Bash 限制已删除${RESET}"
}

# ============================================================================
# [10] 资源限制 — 防 Fork 炸弹/内存耗尽
# ============================================================================

do_apply_10() {
    log_info "配置独立资源限制"
    if [ "$DRY_RUN" -eq 1 ]; then echo -e "  ${CYAN}[DRY-RUN] 将配置 PAM limits${RESET}"; return; fi
    
    # 环境检查: PAM limits 目录
    if [ ! -d /etc/security/limits.d ]; then
        # 尝试创建或跳过
        if [ -d /etc/security ]; then
            mkdir -p /etc/security/limits.d 2>/dev/null || { skip_item "/etc/security/limits.d 不存在且无法创建 (可能是容器环境)"; return; }
        else
            skip_item "/etc/security 目录不存在 (可能是容器或非标准 PAM 环境)，跳过资源限制"
            return
        fi
    fi
    
    # 检查服务账户
    if ! id "$SERVICE_ACCOUNT" &>/dev/null; then
        log_warn "服务账户 $SERVICE_ACCOUNT 不存在，limits 将在创建账户后生效"
        echo -e "  ${YELLOW}[警告] 服务账户不存在，建议先执行加固项 2${RESET}"
    fi
    
    # PAM limits (即使不通过 systemd 启动也生效)
    cat > /etc/security/limits.d/openclaw.conf << EOF
# OpenClaw 资源限制 - 防止 R8 资源耗尽
$SERVICE_ACCOUNT  hard  nproc     64
$SERVICE_ACCOUNT  hard  nofile    4096
$SERVICE_ACCOUNT  hard  core      0
$SERVICE_ACCOUNT  hard  memlock   1048576
$SERVICE_ACCOUNT  hard  as        2097152
EOF

    log_action "apply" "10" "success" "资源限制配置完成"
    echo -e "  ${GREEN}[完成] PAM limits 资源限制${RESET}"
}

do_rollback_10() {
    [ "$DRY_RUN" -eq 0 ] && rm -f /etc/security/limits.d/openclaw.conf
    log_action "rollback" "10" "success" ""
    echo -e "  ${GREEN}[完成] 资源限制已删除${RESET}"
}

# ============================================================================
# [11] MCP/Skill 供应链防护 — 防 ClawHavoc (341 恶意 Skill)
# ============================================================================

do_apply_11() {
    log_info "配置 MCP/Skill 供应链防护"
    if [ "$DRY_RUN" -eq 1 ]; then echo -e "  ${CYAN}[DRY-RUN]${RESET}"; return; fi
    
    mkdir -p "$OPENCLAW_CONFIG_DIR"
    
    # 创建 Skill 安全策略配置
    cat > "$OPENCLAW_CONFIG_DIR/skill-security.conf" << 'EOF'
# OpenClaw Skill/MCP 供应链安全策略
# 背景: ClawHavoc 攻击 - 341 恶意 Skill 在 ClawHub 分发 AMOS 木马

# ===== Skill 安装策略 =====
# 仅允许已签名的 Skill
REQUIRE_SIGNED_SKILLS=true

# 禁止 Skill 安装执行系统命令
SKILL_SANDBOX=true

# 禁止 Skill 访问以下路径
SKILL_BLOCKED_PATHS=(
    "$HOME/.ssh"
    "$HOME/.aws"
    "$HOME/.config"
    "$HOME/.gnupg"
    "/etc/openclaw/secrets"
)

# ===== MCP 服务器策略 =====
# 仅允许白名单内的 MCP 服务器
MCP_WHITELIST_ONLY=true

# 允许的 MCP 服务器列表
MCP_ALLOWED_SERVERS=(
    # 添加信任的 MCP 服务器
)

# MCP 工具描述审计
MCP_AUDIT_TOOL_DESCRIPTIONS=true

# 阻止 MCP 工具描述中的隐藏指令
MCP_BLOCK_HIDDEN_INSTRUCTIONS=true

# ===== 完整性检查 =====
# Skill 安装前计算 SHA256 校验
SKILL_INTEGRITY_CHECK=true
EOF
    
    chmod 640 "$OPENCLAW_CONFIG_DIR/skill-security.conf"
    chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR/skill-security.conf" 2>/dev/null || true
    
    # 创建 Skill 完整性检查脚本
    cat > "$OPENCLAW_CONFIG_DIR/verify-skill.sh" << 'SCRIPT'
#!/bin/bash
# 验证 Skill 完整性
SKILL_PATH=$1

if [ -z "$SKILL_PATH" ]; then
    echo "用法: verify-skill.sh <skill-path>"
    exit 1
fi

echo "===== Skill 安全检查 ====="
echo "路径: $SKILL_PATH"

# 1. 检查可疑的安装命令
echo ""
echo "[1] 检查可疑安装命令..."
SUSPICIOUS=$(grep -rn 'curl.*|.*sh\|wget.*|.*bash\|pip install\|npm install -g\|brew install' "$SKILL_PATH" 2>/dev/null)
if [ -n "$SUSPICIOUS" ]; then
    echo "  [!] 发现可疑安装命令:"
    echo "$SUSPICIOUS"
else
    echo "  [OK] 未发现可疑安装命令"
fi

# 2. 检查隐藏指令
echo ""
echo "[2] 检查 MCP 工具描述中的隐藏指令..."
HIDDEN=$(grep -rn 'ignore previous\|ignore above\|system prompt\|<script\|<!--.*-->' "$SKILL_PATH" 2>/dev/null)
if [ -n "$HIDDEN" ]; then
    echo "  [!] 发现可疑隐藏指令:"
    echo "$HIDDEN"
else
    echo "  [OK] 未发现隐藏指令"
fi

# 3. 检查敏感路径访问
echo ""
echo "[3] 检查敏感路径访问..."
SENSITIVE=$(grep -rn '\.ssh\|\.aws\|\.gnupg\|/etc/shadow\|/etc/passwd' "$SKILL_PATH" 2>/dev/null)
if [ -n "$SENSITIVE" ]; then
    echo "  [!] 发现访问敏感路径:"
    echo "$SENSITIVE"
else
    echo "  [OK] 未发现敏感路径访问"
fi

# 4. 计算完整性哈希
echo ""
echo "[4] Skill 文件哈希:"
find "$SKILL_PATH" -type f -exec sha256sum {} \; 2>/dev/null | head -20
SCRIPT
    
    chmod 750 "$OPENCLAW_CONFIG_DIR/verify-skill.sh"
    
    log_action "apply" "11" "success" "供应链防护配置完成"
    echo -e "  ${GREEN}[完成] Skill 安全策略 + 完整性检查工具${RESET}"
}

do_rollback_11() {
    [ "$DRY_RUN" -eq 0 ] && {
        rm -f "$OPENCLAW_CONFIG_DIR/skill-security.conf"
        rm -f "$OPENCLAW_CONFIG_DIR/verify-skill.sh"
    }
    log_action "rollback" "11" "success" ""
    echo -e "  ${GREEN}[完成] 供应链防护已删除${RESET}"
}

# ============================================================================
# [12] 日志审计与脱敏 — 防日志泄露 API Key/聊天记录
# ============================================================================

do_apply_12() {
    log_info "配置日志审计与脱敏"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置 auditd 规则 + 日志脱敏 + logrotate${RESET}"
        [ "$HAS_AUDITD" -eq 0 ] && echo -e "  ${YELLOW}[提示] auditd 未安装，审计规则部分将跳过${RESET}"
        [ "$HAS_LOGROTATE" -eq 0 ] && echo -e "  ${YELLOW}[提示] logrotate 未安装，日志轮转部分将跳过${RESET}"
        return
    fi
    
    local auditd_done=0
    local logrotate_done=0
    
    # ===== auditd 部分 =====
    if [ "$HAS_AUDITD" -eq 1 ] || command -v auditctl &>/dev/null; then
        mkdir -p /etc/audit/rules.d 2>/dev/null
        
        cat > /etc/audit/rules.d/openclaw.rules << EOF
# OpenClaw 审计规则 - $(date '+%Y-%m-%d %H:%M:%S')
-D
-b 8192
-f 1

# 监控配置/密钥访问
-w $OPENCLAW_CONFIG_DIR -p wa -k openclaw_config
-w $OPENCLAW_SECRETS_DIR -p rwa -k openclaw_secrets

# 监控代码执行
-w $OPENCLAW_DIR -p x -k openclaw_exec

# 监控 Agent 工作目录
-w /tmp/openclaw-workspace -p rwxa -k agent_workspace

# 监控敏感文件 (防止 Agent 读取)
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p rwa -k identity
-w /etc/sudoers -p wa -k sudoers
-w /etc/ssh -p wa -k ssh_config
EOF
        
        if [ "$HAS_SYSTEMD" -eq 1 ]; then
            systemctl restart auditd 2>/dev/null || true
            systemctl enable auditd 2>/dev/null || true
        else
            # 非 systemd: 尝试 service 命令
            command -v service &>/dev/null && service auditd restart 2>/dev/null || true
        fi
        auditd_done=1
        echo -e "  ${GREEN}[完成] auditd 审计规则${RESET}"
    else
        echo -e "  ${YELLOW}[跳过] auditd 未安装 (安装: apt install auditd / yum install audit)${RESET}"
        log_warn "auditd 未安装，跳过审计规则"
        # 尝试安装
        if [ "$HAS_PKG_MANAGER" -eq 1 ]; then
            echo -e "  ${CYAN}  尝试安装 auditd...${RESET}"
            if install_package "auditd" 2>/dev/null || install_package "audit" 2>/dev/null; then
                echo -e "  ${GREEN}  auditd 安装成功，请重新执行此加固项${RESET}"
            else
                echo -e "  ${YELLOW}  auditd 安装失败${RESET}"
            fi
        fi
    fi
    
    # ===== 日志脱敏配置 (不依赖 auditd，始终生成) =====
    mkdir -p "$OPENCLAW_CONFIG_DIR" 2>/dev/null
    cat > "$OPENCLAW_CONFIG_DIR/log-redaction.conf" << 'EOF'
# 日志脱敏规则
# 匹配这些模式的内容将在日志中被替换为 [REDACTED]

# API Key 模式
REDACT_PATTERNS=(
    'sk-[a-zA-Z0-9]{20,}'          # OpenAI API Key
    'sk-ant-[a-zA-Z0-9-]{20,}'     # Anthropic API Key
    'AIza[a-zA-Z0-9_-]{35}'        # Google API Key
    'Bearer [a-zA-Z0-9._-]{20,}'   # Bearer Token
    'token=[a-zA-Z0-9]{20,}'       # Generic Token
    'password[=:][^ ]{5,}'         # Password 参数
    'secret[=:][^ ]{5,}'           # Secret 参数
)

# 日志轮转配置
LOG_MAX_SIZE=100M
LOG_RETENTION_DAYS=30
LOG_COMPRESS=true
EOF
    
    chmod 640 "$OPENCLAW_CONFIG_DIR/log-redaction.conf"
    echo -e "  ${GREEN}[完成] 日志脱敏配置${RESET}"
    
    # ===== logrotate 部分 =====
    if [ "$HAS_LOGROTATE" -eq 1 ] && [ -d /etc/logrotate.d ]; then
        cat > /etc/logrotate.d/openclaw << EOF
$OPENCLAW_LOGS_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 640 $SERVICE_ACCOUNT $SERVICE_ACCOUNT
    postrotate
        [ "$HAS_SYSTEMD" -eq 1 ] && systemctl reload openclaw 2>/dev/null || true
    endscript
}
EOF
        logrotate_done=1
        echo -e "  ${GREEN}[完成] logrotate 配置${RESET}"
    else
        echo -e "  ${YELLOW}[跳过] logrotate 未安装或 /etc/logrotate.d 不存在${RESET}"
        log_warn "logrotate 不可用，跳过日志轮转配置"
    fi
    
    # 汇总
    local summary=""
    [ "$auditd_done" -eq 1 ] && summary="auditd"
    [ -n "$summary" ] && summary="$summary + "
    summary="${summary}脱敏"
    [ "$logrotate_done" -eq 1 ] && summary="$summary + logrotate"
    
    log_action "apply" "12" "success" "日志审计与脱敏配置完成 ($summary)"
    echo -e "  ${GREEN}[完成] $summary${RESET}"
}

do_rollback_12() {
    [ "$DRY_RUN" -eq 0 ] && {
        [ -f /etc/audit/rules.d/openclaw.rules ] && rm -f /etc/audit/rules.d/openclaw.rules
        rm -f "$OPENCLAW_CONFIG_DIR/log-redaction.conf"
        [ -f /etc/logrotate.d/openclaw ] && rm -f /etc/logrotate.d/openclaw
        if [ "$HAS_SYSTEMD" -eq 1 ]; then
            systemctl restart auditd 2>/dev/null || true
        elif command -v service &>/dev/null; then
            service auditd restart 2>/dev/null || true
        fi
    }
    log_action "rollback" "12" "success" ""
    echo -e "  ${GREEN}[完成] 审计/脱敏已删除${RESET}"
}

# ============================================================================
# 报告总结
# ============================================================================

# 全局计数器 (每次批量操作前重置)
REPORT_SUCCESS=0
REPORT_SKIPPED=0
REPORT_FAILED=0
declare -a REPORT_ITEMS_OK=()
declare -a REPORT_ITEMS_SKIP=()
declare -a REPORT_ITEMS_FAIL=()

reset_report() {
    REPORT_SUCCESS=0; REPORT_SKIPPED=0; REPORT_FAILED=0
    REPORT_ITEMS_OK=(); REPORT_ITEMS_SKIP=(); REPORT_ITEMS_FAIL=()
}

print_report() {
    local action=${1:-"加固"}
    local total=$((REPORT_SUCCESS + REPORT_SKIPPED + REPORT_FAILED))
    
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════╗${RESET}"
    echo -e "${CYAN}║              ${action}执行报告                              ║${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${RESET}  执行时间: $(date '+%Y-%m-%d %H:%M:%S')"
    echo -e "${CYAN}║${RESET}  运行模式: $([ "$DRY_RUN" -eq 1 ] && echo '模拟运行' || echo '实际执行')"
    echo -e "${CYAN}║${RESET}  总计: ${WHITE}$total${RESET} 项"
    echo -e "${CYAN}║${RESET}  ${GREEN}成功: $REPORT_SUCCESS${RESET}  ${YELLOW}跳过: $REPORT_SKIPPED${RESET}  ${RED}失败: $REPORT_FAILED${RESET}"
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${RESET}"
    
    if [ ${#REPORT_ITEMS_OK[@]} -gt 0 ]; then
        echo -e "${CYAN}║${RESET} ${GREEN}成功项:${RESET}"
        for desc in "${REPORT_ITEMS_OK[@]}"; do
            echo -e "${CYAN}║${RESET}   ${GREEN}✓${RESET} $desc"
        done
    fi
    if [ ${#REPORT_ITEMS_SKIP[@]} -gt 0 ]; then
        echo -e "${CYAN}║${RESET} ${YELLOW}跳过项:${RESET}"
        for desc in "${REPORT_ITEMS_SKIP[@]}"; do
            echo -e "${CYAN}║${RESET}   ${YELLOW}○${RESET} $desc"
        done
    fi
    if [ ${#REPORT_ITEMS_FAIL[@]} -gt 0 ]; then
        echo -e "${CYAN}║${RESET} ${RED}失败项:${RESET}"
        for desc in "${REPORT_ITEMS_FAIL[@]}"; do
            echo -e "${CYAN}║${RESET}   ${RED}✗${RESET} $desc"
        done
    fi
    
    echo -e "${CYAN}╠══════════════════════════════════════════════════════╣${RESET}"
    echo -e "${CYAN}║${RESET}  日志: $LOG_FILE"
    echo -e "${CYAN}║${RESET}  状态: $STATE_FILE"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════╝${RESET}"
    
    log_info "报告: $action 总计=$total 成功=$REPORT_SUCCESS 跳过=$REPORT_SKIPPED 失败=$REPORT_FAILED"
}

# ============================================================================
# 加固/回退调度 (带结果追踪)
# ============================================================================

apply_item() {
    local item=$1
    local before_state=$(get_item_state "$item")
    log_info "执行加固项 $item: ${ITEM_NAMES[$item]}"
    
    # 捕获输出判断是否跳过
    local output
    output=$("do_apply_$item" 2>&1)
    local rc=$?
    echo "$output"
    
    if echo "$output" | grep -q '\[跳过\]'; then
        ((REPORT_SKIPPED++))
        REPORT_ITEMS_SKIP+=("[$item] ${ITEM_NAMES[$item]}")
    elif [ $rc -ne 0 ] || echo "$output" | grep -q '\[失败\]'; then
        ((REPORT_FAILED++))
        REPORT_ITEMS_FAIL+=("[$item] ${ITEM_NAMES[$item]}")
    else
        ((REPORT_SUCCESS++))
        REPORT_ITEMS_OK+=("[$item] ${ITEM_NAMES[$item]}")
        [ "$DRY_RUN" -eq 0 ] && set_item_state "$item" "applied"
    fi
}

rollback_item() {
    local item=$1
    echo -e "  ${YELLOW}回退加固项 $item: ${ITEM_NAMES[$item]}${RESET}"
    
    local output
    output=$("do_rollback_$item" 2>&1)
    local rc=$?
    echo "$output"
    
    if echo "$output" | grep -q '\[跳过\]'; then
        ((REPORT_SKIPPED++))
        REPORT_ITEMS_SKIP+=("[$item] ${ITEM_NAMES[$item]}")
    elif [ $rc -ne 0 ]; then
        ((REPORT_FAILED++))
        REPORT_ITEMS_FAIL+=("[$item] ${ITEM_NAMES[$item]}")
    else
        ((REPORT_SUCCESS++))
        REPORT_ITEMS_OK+=("[$item] ${ITEM_NAMES[$item]}")
        [ "$DRY_RUN" -eq 0 ] && clear_item_state "$item"
    fi
}

# ============================================================================
# 调试模式
# ============================================================================

debug_item() {
    local item=$1
    echo ""
    echo -e "${CYAN}调试 - 加固项 $item: ${ITEM_NAMES[$item]}${RESET}"
    echo -e "${DIM}风险: ${ITEM_RISKS[$item]}${RESET}"
    echo ""
    echo "  状态: $(get_item_state $item)"
    echo ""
    echo "  [1] 执行  [2] 回退  [3] 模拟执行  [4] 模拟回退  [5] 日志  [0] 返回"
    read -p "  选择: " c
    case $c in
        1) DEBUG_MODE=1; DRY_RUN=0; apply_item "$item" ;;
        2) DEBUG_MODE=1; DRY_RUN=0; rollback_item "$item" ;;
        3) DEBUG_MODE=1; DRY_RUN=1; apply_item "$item" ;;
        4) DEBUG_MODE=1; DRY_RUN=1; rollback_item "$item" ;;
        5) grep -E "item=$item" "$LOG_FILE" 2>/dev/null | tail -20 ;;
        0) return ;;
    esac
    read -p "  按 Enter 继续..."
    debug_item "$item"
}

# ============================================================================
# 菜单
# ============================================================================

print_header() {
    clear
    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${CYAN}    OpenClaw Linux 安全加固脚本 v1.3${RESET}"
    echo -e "${CYAN}    覆盖 10 类安全风险 / 12 项加固措施${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    [ "$DRY_RUN" -eq 1 ] && echo -e "${YELLOW}                [模拟运行]${RESET}"
    echo ""
}

show_status() {
    echo ""
    echo -e "${CYAN}======== 加固状态 ========${RESET}"
    echo -e "${WHITE}  ── 部署前 (安装 OpenClaw 之前执行) ──${RESET}"
    for i in "${PRE_ITEMS[@]}"; do
        local st=$(get_item_state "$i")
        [ "$st" = "applied" ] && echo -e "  ${GREEN}[√]${RESET} [$i] ${ITEM_NAMES[$i]}" || echo -e "  [ ] [$i] ${ITEM_NAMES[$i]}"
    done
    echo -e "${WHITE}  ── 部署后 (安装 OpenClaw 之后执行) ──${RESET}"
    for i in "${POST_ITEMS[@]}"; do
        local st=$(get_item_state "$i")
        [ "$st" = "applied" ] && echo -e "  ${GREEN}[√]${RESET} [$i] ${ITEM_NAMES[$i]}" || echo -e "  [ ] [$i] ${ITEM_NAMES[$i]}"
    done
    echo ""
}

main_menu() {
    print_header
    show_env_summary
    echo -e "${WHITE}安全风险覆盖:${RESET}"
    echo -e "  R1 Gateway暴露  R2 提示注入  R3 MCP投毒  R4 SSRF"
    echo -e "  R5 凭证泄露    R6 权限提升  R7 文件越界  R8 资源耗尽"
    echo -e "  R9 供应链攻击  R10 日志泄露"
    echo ""
    echo -e "  ${WHITE}── 加固 ──${RESET}                    ${WHITE}── 管理 ──${RESET}"
    echo -e "  ${CYAN}[1]${RESET} 交互式选择          ${CYAN}[7]${RESET} 调试模式"
    echo -e "  ${CYAN}[2]${RESET} 一键完整加固        ${CYAN}[8]${RESET} 查看日志"
    echo -e "  ${CYAN}[3]${RESET} ${YELLOW}部署前加固${RESET} (${#PRE_ITEMS[@]}项)     ${CYAN}[9]${RESET} 查看状态"
    echo -e "  ${CYAN}[4]${RESET} ${YELLOW}部署后加固${RESET} (${#POST_ITEMS[@]}项)"
    echo -e "  ${WHITE}── 回退 ──${RESET}                    ${CYAN}[0]${RESET} 退出"
    echo -e "  ${CYAN}[5]${RESET} 回退指定项"
    echo -e "  ${CYAN}[6]${RESET} 一键全部回退"
    echo -e "  ${CYAN}[R]${RESET} 回退部署前加固"
    echo -e "  ${CYAN}[T]${RESET} 回退部署后加固"
    echo ""
    read -p "选项: " c
    case "${c^^}" in
        1) interactive_select ;;
        2) one_click "ALL" ;;
        3) one_click "PRE" ;;
        4) one_click "POST" ;;
        5) rollback_menu ;;
        6) rollback_all ;;
        7) debug_menu ;;
        8) view_logs ;;
        9) show_status; read -p "Enter..."; main_menu ;;
        R) rollback_phase "PRE" ;;
        T) rollback_phase "POST" ;;
        0) exit_s ;;
        *) main_menu ;;
    esac
}

interactive_select() {
    declare -A SEL; for i in {1..12}; do SEL[$i]=0; done
    while true; do
        print_header
        echo -e "${WHITE}  ── 部署前 (安装 OpenClaw 之前) ──${RESET}"
        for i in "${PRE_ITEMS[@]}"; do
            local st=$(get_item_state "$i"); local si=""; [ "$st" = "applied" ] && si="${GREEN}[已加固]${RESET} "
            [ "${SEL[$i]}" -eq 1 ] && echo -e "  ${GREEN}[√]${RESET} [$i] $si${ITEM_NAMES[$i]}" || echo -e "  [ ] [$i] $si${ITEM_NAMES[$i]}"
        done
        echo -e "${WHITE}  ── 部署后 (安装 OpenClaw 之后) ──${RESET}"
        for i in "${POST_ITEMS[@]}"; do
            local st=$(get_item_state "$i"); local si=""; [ "$st" = "applied" ] && si="${GREEN}[已加固]${RESET} "
            [ "${SEL[$i]}" -eq 1 ] && echo -e "  ${GREEN}[√]${RESET} [$i] $si${ITEM_NAMES[$i]}" || echo -e "  [ ] [$i] $si${ITEM_NAMES[$i]}"
        done
        echo ""
        echo -e "  ${CYAN}[A]${RESET} 全选  ${CYAN}[P]${RESET} 选部署前  ${CYAN}[D]${RESET} 选部署后  ${CYAN}[N]${RESET} 清空  ${CYAN}[E]${RESET} 执行  ${CYAN}[B]${RESET} 返回"
        read -p "输入: " inp
        case "${inp^^}" in
            A) for i in {1..12}; do SEL[$i]=1; done ;;
            P) for i in "${PRE_ITEMS[@]}"; do SEL[$i]=1; done ;;
            D) for i in "${POST_ITEMS[@]}"; do SEL[$i]=1; done ;;
            N) for i in {1..12}; do SEL[$i]=0; done ;;
            B) main_menu; return ;;
            E)
                local cnt=0; for i in {1..12}; do [ "${SEL[$i]}" -eq 1 ] && ((cnt++)); done
                [ $cnt -eq 0 ] && { echo "请选择"; sleep 1; continue; }
                reset_report
                for i in {1..12}; do [ "${SEL[$i]}" -eq 1 ] && { echo ""; echo -e "${CYAN}[$i] ${ITEM_NAMES[$i]}${RESET}"; apply_item "$i"; }; done
                print_report "加固"
                read -p "Enter..."; main_menu; return ;;
            *)
                for ((j=0; j<${#inp}; j++)); do
                    c="${inp:$j:1}"
                    if [[ "$c" =~ ^[1-9]$ ]]; then
                        if [ "$c" = "1" ] && [ $((j+1)) -lt ${#inp} ]; then
                            n="${inp:$((j+1)):1}"
                            if [[ "$n" =~ ^[0-2]$ ]]; then SEL["1$n"]=$((1-SEL["1$n"])); ((j++)); continue; fi
                        fi
                        SEL[$c]=$((1-SEL[$c]))
                    fi
                done ;;
        esac
    done
}

one_click() {
    local phase=${1:-ALL}
    local items=() label=""
    case $phase in
        PRE)  items=("${PRE_ITEMS[@]}");  label="部署前加固 (${#PRE_ITEMS[@]}项: 服务账户/权限/防火墙/网络/资源限制)" ;;
        POST) items=("${POST_ITEMS[@]}"); label="部署后加固 (${#POST_ITEMS[@]}项: Gateway/凭证/沙箱/MAC/命令限制/供应链/日志)" ;;
        ALL)  items=(${PRE_ITEMS[@]} ${POST_ITEMS[@]}); label="完整加固 (12项, 先执行部署前 → 再执行部署后)" ;;
    esac
    local total=${#items[@]}
    
    print_header
    echo -e "${WHITE}$label${RESET}"
    echo ""
    for i in "${items[@]}"; do
        echo -e "  [$i] [${YELLOW}${PHASE_LABEL[${ITEM_PHASE[$i]}]}${RESET}] ${ITEM_NAMES[$i]}"
    done
    echo ""
    read -p "确认执行? [Y/N]: " c
    [[ ! "${c^^}" =~ ^Y ]] && { main_menu; return; }
    
    reset_report
    local n=0
    for i in "${items[@]}"; do
        ((n++))
        echo ""
        echo -e "${CYAN}[$n/$total] [${PHASE_LABEL[${ITEM_PHASE[$i]}]}] ${ITEM_NAMES[$i]}${RESET}"
        apply_item "$i"
    done
    print_report "加固"
    read -p "Enter..."; main_menu
}

rollback_menu() {
    print_header; show_status; echo -e "  ${CYAN}[B]${RESET} 返回"
    read -p "回退编号 (1-12): " it
    [ "$it" = "B" ] || [ "$it" = "b" ] && { main_menu; return; }
    if [[ "$it" =~ ^[0-9]+$ ]] && [ "$it" -ge 1 ] && [ "$it" -le 12 ]; then
        read -p "确认? [Y/N]: " c
        if [[ "${c^^}" =~ ^Y ]]; then
            reset_report
            rollback_item "$it"
            print_report "回退"
        fi
    fi
    read -p "Enter..."; rollback_menu
}

rollback_phase() {
    local phase=$1
    local items=() label=""
    case $phase in
        PRE)  label="部署前加固项"; for i in "${PRE_ITEMS[@]}"; do items+=("$i"); done ;;
        POST) label="部署后加固项"; for i in "${POST_ITEMS[@]}"; do items+=("$i"); done ;;
        ALL)  label="全部加固项"; items=(12 11 10 9 8 7 6 5 4 3 2 1) ;;
    esac
    
    # 统计已加固项
    local applied_count=0
    for i in "${items[@]}"; do
        [ "$(get_item_state $i)" = "applied" ] && ((applied_count++))
    done
    
    if [ $applied_count -eq 0 ]; then
        echo -e "${YELLOW}没有已加固的${label}需要回退${RESET}"
        read -p "Enter..."; main_menu; return
    fi
    
    print_header
    echo -e "${WHITE}一键回退: $label (已加固 $applied_count 项)${RESET}"
    echo ""
    for i in "${items[@]}"; do
        local st=$(get_item_state "$i")
        [ "$st" = "applied" ] && echo -e "  ${GREEN}[√]${RESET} [$i] ${ITEM_NAMES[$i]}" || echo -e "  ${YELLOW}[−]${RESET} [$i] ${ITEM_NAMES[$i]} (未加固, 跳过)"
    done
    echo ""
    
    if [ "$phase" = "ALL" ]; then
        read -p "输入 CONFIRM 确认全部回退: " c
        [ "$c" != "CONFIRM" ] && { main_menu; return; }
    else
        read -p "确认回退 $label? [Y/N]: " c
        [[ ! "${c^^}" =~ ^Y ]] && { main_menu; return; }
    fi
    
    reset_report
    # 按倒序回退（后部署的先回退）
    local rev_items=()
    for ((idx=${#items[@]}-1; idx>=0; idx--)); do
        rev_items+=("${items[$idx]}")
    done
    
    for i in "${rev_items[@]}"; do
        if [ "$(get_item_state $i)" = "applied" ]; then
            echo ""
            echo -e "${YELLOW}回退 [$i] ${ITEM_NAMES[$i]}${RESET}"
            rollback_item "$i"
        else
            ((REPORT_SKIPPED++))
            REPORT_ITEMS_SKIP+=("[$i] ${ITEM_NAMES[$i]} (未加固)")
        fi
    done
    print_report "回退"
    read -p "Enter..."; main_menu
}

rollback_all() {
    rollback_phase "ALL"
}

debug_menu() {
    print_header
    echo -e "${WHITE}  ── 部署前 ──${RESET}"
    for i in "${PRE_ITEMS[@]}"; do echo "  [$i] [$(get_item_state $i)] ${ITEM_NAMES[$i]}"; done
    echo -e "${WHITE}  ── 部署后 ──${RESET}"
    for i in "${POST_ITEMS[@]}"; do echo "  [$i] [$(get_item_state $i)] ${ITEM_NAMES[$i]}"; done
    echo -e "\n  ${CYAN}[B]${RESET} 返回"; read -p "编号: " it
    [ "$it" = "B" ] || [ "$it" = "b" ] && { main_menu; return; }
    [[ "$it" =~ ^[0-9]+$ ]] && [ "$it" -ge 1 ] && [ "$it" -le 12 ] && debug_item "$it"
    debug_menu
}

view_logs() {
    echo "日志: $LOG_FILE"; echo "---"; tail -30 "$LOG_FILE" 2>/dev/null || echo "(无)"; echo "---"
    read -p "Enter..."; main_menu
}

exit_s() { log_info "退出"; echo "日志: $LOG_FILE"; exit 0; }

show_help() {
    echo "OpenClaw Linux 安全加固脚本 v1.3"
    echo "用法: $0 [选项]"
    echo ""
    echo "  加固:"
    echo "  --apply N        应用加固项 N"
    echo "  --all            一键全部加固 (部署前+部署后)"
    echo "  --pre            仅执行部署前加固 (${#PRE_ITEMS[@]}项)"
    echo "  --post           仅执行部署后加固 (${#POST_ITEMS[@]}项)"
    echo ""
    echo "  回退:"
    echo "  --rollback N     回退加固项 N"
    echo "  --rollback-all   一键回退全部加固项"
    echo "  --rollback-pre   一键回退部署前加固项"
    echo "  --rollback-post  一键回退部署后加固项"
    echo ""
    echo "  其他:"
    echo "  --help           帮助"
    echo "  --dry-run        模拟运行"
    echo "  --status         查看状态"
    echo "  --debug N        调试加固项 N"
}

# ============================================================================
# 主程序
# ============================================================================

main() {
    init_logging
    detect_all
    
    local apply_items=()
    local rollback_phase_arg=""
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h) show_help; exit 0 ;;
            --dry-run) DRY_RUN=1; shift ;;
            --status) show_status; exit 0 ;;
            --rollback) ROLLBACK_MODE=1; ROLLBACK_ITEM=$2; shift 2 ;;
            --rollback-all)  rollback_phase_arg="ALL"; shift ;;
            --rollback-pre)  rollback_phase_arg="PRE"; shift ;;
            --rollback-post) rollback_phase_arg="POST"; shift ;;
            --debug) DEBUG_MODE=1; DEBUG_ITEM=$2; shift 2 ;;
            --apply) apply_items+=("$2"); shift 2 ;;
            --pre) apply_items=(${PRE_ITEMS[@]}); shift ;;
            --post) apply_items=(${POST_ITEMS[@]}); shift ;;
            --all) apply_items=(${PRE_ITEMS[@]} ${POST_ITEMS[@]}); shift ;;
            *) shift ;;
        esac
    done
    
    [ "$EUID" -ne 0 ] && [ "$DRY_RUN" -eq 0 ] && { echo "请使用 root 运行"; exit 1; }
    
    # 单项回退 (命令行)
    if [ "$ROLLBACK_MODE" -eq 1 ]; then
        reset_report
        rollback_item "$ROLLBACK_ITEM"
        print_report "回退"
        exit 0
    fi
    
    # 批量回退 (命令行)
    if [ -n "$rollback_phase_arg" ]; then
        local rb_items=()
        case $rollback_phase_arg in
            PRE)  rb_items=("${PRE_ITEMS[@]}") ;;
            POST) rb_items=("${POST_ITEMS[@]}") ;;
            ALL)  rb_items=(12 11 10 9 8 7 6 5 4 3 2 1) ;;
        esac
        reset_report
        for i in "${rb_items[@]}"; do
            if [ "$(get_item_state $i)" = "applied" ]; then
                echo -e "${YELLOW}回退 [$i] ${ITEM_NAMES[$i]}${RESET}"
                rollback_item "$i"
            else
                ((REPORT_SKIPPED++))
                REPORT_ITEMS_SKIP+=("[$i] ${ITEM_NAMES[$i]} (未加固)")
            fi
        done
        print_report "回退"
        exit 0
    fi
    
    [ "$DEBUG_MODE" -eq 1 ] && [ "$DEBUG_ITEM" -gt 0 ] 2>/dev/null && { debug_item "$DEBUG_ITEM"; exit 0; }
    
    # 批量加固 (命令行)
    if [ ${#apply_items[@]} -gt 0 ]; then
        reset_report
        for i in "${apply_items[@]}"; do
            echo -e "${CYAN}[$i] ${ITEM_NAMES[$i]}${RESET}"
            apply_item "$i"
        done
        print_report "加固"
        exit 0
    fi
    
    main_menu
}

main "$@"
