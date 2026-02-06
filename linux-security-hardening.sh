#!/bin/bash
# ============================================================================
# OpenClaw Linux 安全加固脚本
# 版本: 1.1
# 作者: Alex
# 邮箱: unix_sec@163.com
# 许可证: Apache License 2.0
# 适用: Ubuntu 20.04+ / Debian 11+ / CentOS 8+ / RHEL 8+
#
# 功能特性:
#   - 幂等执行: 可重复运行，自动跳过已完成的加固项
#   - 单独回退: 支持回退指定的加固项
#   - 完整日志: 所有操作均有详细日志记录
#   - 调试模式: 支持单独调试指定功能项
#
# 使用方法:
#   ./linux-security-hardening.sh              # 交互式菜单
#   ./linux-security-hardening.sh --dry-run    # 模拟运行
#   ./linux-security-hardening.sh --rollback 5 # 回退加固项 5
#   ./linux-security-hardening.sh --debug 3    # 调试加固项 3
#   ./linux-security-hardening.sh --status     # 查看加固状态
#   ./linux-security-hardening.sh --help       # 帮助信息
# ============================================================================

set -e

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

# 日志配置
LOG_DIR="/var/log/openclaw-hardening"
LOG_FILE="$LOG_DIR/hardening-$(date +%Y%m%d).log"
ROLLBACK_LOG="$LOG_DIR/rollback-$(date +%Y%m%d).log"

# 状态文件 (用于幂等性检查)
STATE_DIR="/var/lib/openclaw-hardening"
STATE_FILE="$STATE_DIR/hardening-state.json"

# AI API 出站白名单
AI_API_DOMAINS=(
    "api.openai.com"
    "api.anthropic.com"
    "api.deepseek.com"
    "generativelanguage.googleapis.com"
)

# 允许 Agent 访问的目录
ALLOWED_WORK_DIRS=(
    "/home"
    "/tmp/openclaw-workspace"
    "$OPENCLAW_STATE_DIR"
)

# 颜色代码
RED='\033[0;91m'
GREEN='\033[0;92m'
YELLOW='\033[0;93m'
CYAN='\033[0;96m'
WHITE='\033[0;97m'
RESET='\033[0m'
BOLD='\033[1m'
DIM='\033[2m'

# 运行模式
DRY_RUN=0
DEBUG_MODE=0
DEBUG_ITEM=0
ROLLBACK_MODE=0
ROLLBACK_ITEM=0

# 加固项名称
declare -A ITEM_NAMES=(
    [1]="创建专用服务账户"
    [2]="配置文件系统权限"
    [3]="生成安全配置和 Token"
    [4]="安装 systemd 服务 (进程沙箱)"
    [5]="配置防火墙 (端口限制)"
    [6]="配置 AppArmor/SELinux (访问控制)"
    [7]="启用审计策略 (操作审计)"
    [8]="配置网络出站白名单 (SSRF 防护)"
    [9]="配置资源限制 (防资源耗尽)"
    [10]="配置 Bash Tool 安全限制"
)

# ============================================================================
# 日志函数
# ============================================================================

init_logging() {
    mkdir -p "$LOG_DIR" "$STATE_DIR"
    touch "$LOG_FILE"
    chmod 640 "$LOG_FILE"
    
    # 初始化状态文件
    if [ ! -f "$STATE_FILE" ]; then
        echo '{"items":{}}' > "$STATE_FILE"
    fi
}

log() {
    local level=$1
    local message=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    local caller="${FUNCNAME[2]:-main}"
    
    echo "[$timestamp] [$level] [$caller] $message" >> "$LOG_FILE"
    
    # 调试模式下输出到终端
    if [ "$DEBUG_MODE" -eq 1 ]; then
        case $level in
            INFO)  echo -e "${DIM}[$timestamp] [INFO] $message${RESET}" ;;
            WARN)  echo -e "${YELLOW}[$timestamp] [WARN] $message${RESET}" ;;
            ERROR) echo -e "${RED}[$timestamp] [ERROR] $message${RESET}" ;;
            DEBUG) echo -e "${CYAN}[$timestamp] [DEBUG] $message${RESET}" ;;
        esac
    fi
}

log_info()  { log "INFO" "$1"; }
log_warn()  { log "WARN" "$1"; }
log_error() { log "ERROR" "$1"; }
log_debug() { log "DEBUG" "$1"; }

log_action() {
    local action=$1
    local item=$2
    local status=$3
    local detail=$4
    
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    echo "[$timestamp] [ACTION] item=$item action=$action status=$status detail=\"$detail\"" >> "$LOG_FILE"
}

# ============================================================================
# 状态管理 (幂等性支持)
# ============================================================================

get_item_state() {
    local item=$1
    if [ -f "$STATE_FILE" ]; then
        python3 -c "import json; d=json.load(open('$STATE_FILE')); print(d.get('items',{}).get('$item',{}).get('status','none'))" 2>/dev/null || echo "none"
    else
        echo "none"
    fi
}

set_item_state() {
    local item=$1
    local status=$2
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')
    
    if [ -f "$STATE_FILE" ]; then
        python3 -c "
import json
with open('$STATE_FILE', 'r') as f:
    d = json.load(f)
if 'items' not in d:
    d['items'] = {}
d['items']['$item'] = {'status': '$status', 'timestamp': '$timestamp'}
with open('$STATE_FILE', 'w') as f:
    json.dump(d, f, indent=2)
" 2>/dev/null
    fi
}

clear_item_state() {
    local item=$1
    
    if [ -f "$STATE_FILE" ]; then
        python3 -c "
import json
with open('$STATE_FILE', 'r') as f:
    d = json.load(f)
if 'items' in d and '$item' in d['items']:
    del d['items']['$item']
with open('$STATE_FILE', 'w') as f:
    json.dump(d, f, indent=2)
" 2>/dev/null
    fi
}

is_item_applied() {
    local item=$1
    local state=$(get_item_state "$item")
    [ "$state" = "applied" ]
}

# ============================================================================
# 系统检测
# ============================================================================

detect_distro() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        DISTRO=$ID
        DISTRO_VERSION=$VERSION_ID
        DISTRO_NAME=$NAME
    elif [ -f /etc/redhat-release ]; then
        DISTRO="rhel"
        DISTRO_NAME="Red Hat Enterprise Linux"
    else
        DISTRO="unknown"
        DISTRO_NAME="Unknown"
    fi
    log_info "检测到发行版: $DISTRO $DISTRO_VERSION"
}

detect_firewall() {
    if command -v ufw &> /dev/null; then
        FIREWALL="ufw"
    elif command -v firewall-cmd &> /dev/null; then
        FIREWALL="firewalld"
    elif command -v iptables &> /dev/null; then
        FIREWALL="iptables"
    else
        FIREWALL="none"
    fi
    log_info "检测到防火墙: $FIREWALL"
}

detect_mac() {
    if command -v aa-status &> /dev/null; then
        MAC_SYSTEM="apparmor"
    elif command -v getenforce &> /dev/null; then
        MAC_SYSTEM="selinux"
    else
        MAC_SYSTEM="none"
    fi
    log_info "检测到 MAC: $MAC_SYSTEM"
}

detect_package_manager() {
    if command -v apt-get &> /dev/null; then
        PKG_MANAGER="apt"
    elif command -v dnf &> /dev/null; then
        PKG_MANAGER="dnf"
    elif command -v yum &> /dev/null; then
        PKG_MANAGER="yum"
    else
        PKG_MANAGER="unknown"
    fi
}

install_package() {
    local pkg=$1
    log_info "安装软件包: $pkg"
    case $PKG_MANAGER in
        apt) apt-get install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        yum) yum install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
        dnf) dnf install -y "$pkg" >> "$LOG_FILE" 2>&1 ;;
    esac
}

generate_token() {
    < /dev/urandom tr -dc 'A-Za-z0-9' | head -c 32
}

# ============================================================================
# 加固项实现 (带幂等性检查)
# ============================================================================

# [1] 创建服务账户
do_apply_1() {
    log_info "开始执行: 创建服务账户"
    
    # 幂等性检查
    if id "$SERVICE_ACCOUNT" &>/dev/null; then
        log_info "服务账户已存在，检查配置..."
        echo -e "  ${YELLOW}[幂等] 服务账户已存在${RESET}"
    else
        if [ "$DRY_RUN" -eq 0 ]; then
            useradd -r -s /usr/sbin/nologin -d "$OPENCLAW_STATE_DIR" \
                    -c "OpenClaw Service Account" "$SERVICE_ACCOUNT"
            log_info "服务账户已创建: $SERVICE_ACCOUNT"
            echo "  账户 $SERVICE_ACCOUNT 已创建"
        else
            echo -e "  ${CYAN}[DRY-RUN] 将创建账户 $SERVICE_ACCOUNT${RESET}"
        fi
    fi
    
    if [ "$DRY_RUN" -eq 0 ]; then
        # 确保账户锁定且无特权
        passwd -l "$SERVICE_ACCOUNT" &>/dev/null || true
        gpasswd -d "$SERVICE_ACCOUNT" sudo &>/dev/null || true
        gpasswd -d "$SERVICE_ACCOUNT" wheel &>/dev/null || true
        log_info "服务账户已锁定并移除特权组"
    fi
    
    log_action "apply" "1" "success" "服务账户配置完成"
    echo -e "  ${GREEN}[完成] 服务账户已配置${RESET}"
}

do_rollback_1() {
    log_info "开始回退: 删除服务账户"
    echo "  回退加固项 1: 删除服务账户..."
    
    if id "$SERVICE_ACCOUNT" &>/dev/null; then
        if [ "$DRY_RUN" -eq 0 ]; then
            userdel -r "$SERVICE_ACCOUNT" 2>/dev/null || userdel "$SERVICE_ACCOUNT"
            log_info "服务账户已删除: $SERVICE_ACCOUNT"
            echo -e "  ${GREEN}[完成] 账户已删除${RESET}"
        else
            echo -e "  ${CYAN}[DRY-RUN] 将删除账户 $SERVICE_ACCOUNT${RESET}"
        fi
    else
        echo -e "  ${YELLOW}[跳过] 账户不存在${RESET}"
    fi
    
    log_action "rollback" "1" "success" "服务账户已删除"
}

# [2] 配置文件权限
do_apply_2() {
    log_info "开始执行: 配置文件权限"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置目录权限${RESET}"
        return
    fi
    
    # 创建目录
    mkdir -p "$OPENCLAW_DIR" "$OPENCLAW_STATE_DIR" "$OPENCLAW_LOGS_DIR" \
             "$OPENCLAW_SECRETS_DIR" "$OPENCLAW_CONFIG_DIR" \
             "/tmp/openclaw-workspace"
    
    # 配置权限 (幂等操作)
    chown -R root:"$SERVICE_ACCOUNT" "$OPENCLAW_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_DIR"
    
    chown -R "$SERVICE_ACCOUNT":"$SERVICE_ACCOUNT" "$OPENCLAW_STATE_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_STATE_DIR"
    
    chown -R root:"$SERVICE_ACCOUNT" "$OPENCLAW_SECRETS_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_SECRETS_DIR"
    
    chown -R "$SERVICE_ACCOUNT":"$SERVICE_ACCOUNT" "$OPENCLAW_LOGS_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_LOGS_DIR"
    
    chown -R root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR" 2>/dev/null || true
    chmod 750 "$OPENCLAW_CONFIG_DIR"
    
    chown -R "$SERVICE_ACCOUNT":"$SERVICE_ACCOUNT" "/tmp/openclaw-workspace" 2>/dev/null || true
    chmod 750 "/tmp/openclaw-workspace"
    
    log_action "apply" "2" "success" "文件权限配置完成"
    echo -e "  ${GREEN}[完成] 文件权限已配置${RESET}"
}

do_rollback_2() {
    log_info "开始回退: 重置文件权限"
    echo "  回退加固项 2: 重置文件权限..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        # 重置为默认权限
        chmod 755 "$OPENCLAW_DIR" 2>/dev/null || true
        chmod 755 "$OPENCLAW_STATE_DIR" 2>/dev/null || true
        chmod 755 "$OPENCLAW_LOGS_DIR" 2>/dev/null || true
        chmod 755 "$OPENCLAW_CONFIG_DIR" 2>/dev/null || true
        log_info "目录权限已重置"
        echo -e "  ${GREEN}[完成] 权限已重置${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将重置目录权限${RESET}"
    fi
    
    log_action "rollback" "2" "success" "文件权限已重置"
}

# [3] 生成安全配置
do_apply_3() {
    log_info "开始执行: 生成安全配置"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将生成安全配置文件${RESET}"
        return
    fi
    
    mkdir -p "$OPENCLAW_SECRETS_DIR" "$OPENCLAW_CONFIG_DIR"
    
    # 生成 Token (幂等: 仅在不存在时生成)
    if [ ! -f "$OPENCLAW_SECRETS_DIR/gateway-token" ]; then
        local token=$(generate_token)
        echo "$token" > "$OPENCLAW_SECRETS_DIR/gateway-token"
        chmod 640 "$OPENCLAW_SECRETS_DIR/gateway-token"
        chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_SECRETS_DIR/gateway-token" 2>/dev/null || true
        log_info "Gateway Token 已生成"
        echo "  Gateway Token 已生成"
    else
        log_info "Gateway Token 已存在，跳过生成"
        echo -e "  ${YELLOW}[幂等] Token 已存在${RESET}"
    fi
    
    # 生成配置文件 (幂等: 仅在不存在时生成)
    if [ ! -f "$OPENCLAW_CONFIG_DIR/config.yaml" ]; then
        cat > "$OPENCLAW_CONFIG_DIR/config.yaml" << EOF
# OpenClaw 安全配置
# 生成时间: $(date '+%Y-%m-%d %H:%M:%S')

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
        log_info "配置文件已生成"
    else
        log_info "配置文件已存在，跳过生成"
        echo -e "  ${YELLOW}[幂等] 配置文件已存在${RESET}"
    fi
    
    # 环境变量文件
    cat > "$OPENCLAW_CONFIG_DIR/environment" << EOF
OPENCLAW_STATE_DIR=$OPENCLAW_STATE_DIR
OPENCLAW_GATEWAY_TOKEN_FILE=$OPENCLAW_SECRETS_DIR/gateway-token
NODE_ENV=production
NODE_OPTIONS=--disallow-code-generation-from-strings
EOF
    chmod 640 "$OPENCLAW_CONFIG_DIR/environment"
    chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR/environment" 2>/dev/null || true
    
    log_action "apply" "3" "success" "安全配置生成完成"
    echo -e "  ${GREEN}[完成] 安全配置已生成${RESET}"
}

do_rollback_3() {
    log_info "开始回退: 删除安全配置"
    echo "  回退加固项 3: 删除安全配置..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$OPENCLAW_SECRETS_DIR/gateway-token"
        rm -f "$OPENCLAW_CONFIG_DIR/config.yaml"
        rm -f "$OPENCLAW_CONFIG_DIR/environment"
        log_info "安全配置已删除"
        echo -e "  ${GREEN}[完成] 配置已删除${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除安全配置${RESET}"
    fi
    
    log_action "rollback" "3" "success" "安全配置已删除"
}

# [4] 安装 systemd 服务
do_apply_4() {
    log_info "开始执行: 安装 systemd 服务"
    
    if ! command -v systemctl &>/dev/null; then
        log_warn "非 systemd 系统，跳过"
        echo -e "  ${YELLOW}[跳过] 非 systemd 系统${RESET}"
        return
    fi
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将安装 systemd 服务${RESET}"
        return
    fi
    
    # 检查是否已存在
    if [ -f /etc/systemd/system/openclaw.service ]; then
        log_info "服务单元已存在，更新配置"
        echo -e "  ${YELLOW}[幂等] 服务已存在，更新配置${RESET}"
    fi
    
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

# 进程沙箱
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=read-only
PrivateTmp=true
ReadWritePaths=$OPENCLAW_STATE_DIR $OPENCLAW_LOGS_DIR /tmp/openclaw-workspace
ReadOnlyPaths=$OPENCLAW_DIR $OPENCLAW_CONFIG_DIR $OPENCLAW_SECRETS_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectControlGroups=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
PrivateDevices=true
PrivateUsers=true
ProtectHostname=true
ProtectClock=true
RestrictRealtime=true
RestrictSUIDSGID=true
LockPersonality=true
SystemCallFilter=@system-service
SystemCallFilter=~@mount @reboot @swap @clock @module @raw-io
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=
MemoryDenyWriteExecute=true
RestrictNamespaces=true

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable openclaw 2>/dev/null || true
    
    log_action "apply" "4" "success" "systemd 服务安装完成"
    echo -e "  ${GREEN}[完成] systemd 服务已安装${RESET}"
}

do_rollback_4() {
    log_info "开始回退: 删除 systemd 服务"
    echo "  回退加固项 4: 删除 systemd 服务..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        systemctl stop openclaw 2>/dev/null || true
        systemctl disable openclaw 2>/dev/null || true
        rm -f /etc/systemd/system/openclaw.service
        rm -rf /etc/systemd/system/openclaw.service.d
        systemctl daemon-reload
        log_info "systemd 服务已删除"
        echo -e "  ${GREEN}[完成] 服务已删除${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除 systemd 服务${RESET}"
    fi
    
    log_action "rollback" "4" "success" "systemd 服务已删除"
}

# [5] 配置防火墙
do_apply_5() {
    log_info "开始执行: 配置防火墙 ($FIREWALL)"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置防火墙规则${RESET}"
        return
    fi
    
    case $FIREWALL in
        ufw)
            # 幂等: ufw 规则重复添加不会报错
            ufw deny in on any to any port "$GATEWAY_PORT" proto tcp \
                comment "OpenClaw Gateway - Block External" 2>/dev/null || true
            ufw allow in on lo to any port "$GATEWAY_PORT" proto tcp \
                comment "OpenClaw Gateway - Allow Local" 2>/dev/null || true
            ufw --force enable 2>/dev/null || true
            log_info "UFW 规则已配置"
            ;;
        firewalld)
            systemctl start firewalld 2>/dev/null || true
            systemctl enable firewalld 2>/dev/null || true
            firewall-cmd --permanent --add-rich-rule="rule family=ipv4 port port=$GATEWAY_PORT protocol=tcp reject" 2>/dev/null || true
            firewall-cmd --permanent --zone=trusted --add-interface=lo 2>/dev/null || true
            firewall-cmd --reload 2>/dev/null || true
            log_info "firewalld 规则已配置"
            ;;
        iptables)
            # 幂等: 先检查规则是否存在
            if ! iptables -C INPUT -p tcp --dport "$GATEWAY_PORT" -j DROP 2>/dev/null; then
                iptables -A INPUT -p tcp --dport "$GATEWAY_PORT" -j DROP
            fi
            if ! iptables -C INPUT -i lo -p tcp --dport "$GATEWAY_PORT" -j ACCEPT 2>/dev/null; then
                iptables -I INPUT -i lo -p tcp --dport "$GATEWAY_PORT" -j ACCEPT
            fi
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            log_info "iptables 规则已配置"
            ;;
        *)
            log_warn "未检测到防火墙"
            echo -e "  ${YELLOW}[跳过] 未检测到防火墙${RESET}"
            return
            ;;
    esac
    
    log_action "apply" "5" "success" "防火墙配置完成"
    echo -e "  ${GREEN}[完成] 防火墙已配置${RESET}"
}

do_rollback_5() {
    log_info "开始回退: 删除防火墙规则"
    echo "  回退加固项 5: 删除防火墙规则..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        case $FIREWALL in
            ufw)
                ufw delete deny "$GATEWAY_PORT/tcp" 2>/dev/null || true
                ufw delete allow in on lo to any port "$GATEWAY_PORT" 2>/dev/null || true
                ;;
            firewalld)
                firewall-cmd --permanent --remove-rich-rule="rule family=ipv4 port port=$GATEWAY_PORT protocol=tcp reject" 2>/dev/null || true
                firewall-cmd --reload 2>/dev/null || true
                ;;
            iptables)
                iptables -D INPUT -p tcp --dport "$GATEWAY_PORT" -j DROP 2>/dev/null || true
                iptables -D INPUT -i lo -p tcp --dport "$GATEWAY_PORT" -j ACCEPT 2>/dev/null || true
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                ;;
        esac
        log_info "防火墙规则已删除"
        echo -e "  ${GREEN}[完成] 防火墙规则已删除${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除防火墙规则${RESET}"
    fi
    
    log_action "rollback" "5" "success" "防火墙规则已删除"
}

# [6] 配置 AppArmor/SELinux
do_apply_6() {
    log_info "开始执行: 配置 MAC ($MAC_SYSTEM)"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置 MAC${RESET}"
        return
    fi
    
    case $MAC_SYSTEM in
        apparmor)
            cat > /etc/apparmor.d/openclaw << 'EOF'
#include <tunables/global>

profile openclaw /usr/bin/node {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  /usr/bin/node ix,
  /usr/local/bin/node ix,
  /opt/openclaw/** r,
  /opt/openclaw/dist/** ix,
  /etc/openclaw/** r,
  /var/lib/openclaw/** rw,
  /var/log/openclaw/** rw,
  /tmp/openclaw-workspace/** rw,
  /tmp/** rw,
  /var/tmp/** rw,

  network inet stream,
  network inet6 stream,
  network unix stream,

  deny /etc/passwd w,
  deny /etc/shadow rw,
  deny /etc/sudoers rw,
  deny /etc/ssh/** w,
  deny /root/** rw,
  deny /home/*/.ssh/** rw,
  deny /boot/** rw,
  deny capability sys_admin,
  deny capability sys_ptrace,
  deny capability sys_rawio,
  deny capability net_admin,
  deny capability sys_module,
}
EOF
            apparmor_parser -r /etc/apparmor.d/openclaw 2>/dev/null || true
            log_info "AppArmor 配置已应用"
            ;;
        selinux)
            if [ "$(getenforce)" != "Disabled" ]; then
                semanage fcontext -a -t bin_t "$OPENCLAW_DIR/dist(/.*)?" 2>/dev/null || true
                semanage fcontext -a -t var_lib_t "$OPENCLAW_STATE_DIR(/.*)?" 2>/dev/null || true
                restorecon -Rv "$OPENCLAW_DIR" "$OPENCLAW_STATE_DIR" 2>/dev/null || true
                setsebool -P httpd_can_network_connect 1 2>/dev/null || true
                log_info "SELinux 上下文已配置"
            fi
            ;;
        *)
            log_warn "未检测到 MAC 系统"
            echo -e "  ${YELLOW}[跳过] 未检测到 MAC 系统${RESET}"
            return
            ;;
    esac
    
    log_action "apply" "6" "success" "MAC 配置完成"
    echo -e "  ${GREEN}[完成] MAC 已配置${RESET}"
}

do_rollback_6() {
    log_info "开始回退: 删除 MAC 配置"
    echo "  回退加固项 6: 删除 MAC 配置..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        case $MAC_SYSTEM in
            apparmor)
                rm -f /etc/apparmor.d/openclaw
                apparmor_parser -R openclaw 2>/dev/null || true
                ;;
            selinux)
                semanage fcontext -d "$OPENCLAW_DIR/dist(/.*)?" 2>/dev/null || true
                semanage fcontext -d "$OPENCLAW_STATE_DIR(/.*)?" 2>/dev/null || true
                ;;
        esac
        log_info "MAC 配置已删除"
        echo -e "  ${GREEN}[完成] MAC 配置已删除${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除 MAC 配置${RESET}"
    fi
    
    log_action "rollback" "6" "success" "MAC 配置已删除"
}

# [7] 审计策略
do_apply_7() {
    log_info "开始执行: 配置审计策略"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置 auditd${RESET}"
        return
    fi
    
    # 安装 auditd
    if ! command -v auditd &>/dev/null; then
        log_info "安装 auditd..."
        install_package "auditd" || install_package "audit"
    fi
    
    mkdir -p /etc/audit/rules.d
    
    cat > /etc/audit/rules.d/openclaw.rules << EOF
# OpenClaw 审计规则 - 生成于 $(date '+%Y-%m-%d %H:%M:%S')
-D
-b 8192
-f 1

-w $OPENCLAW_CONFIG_DIR -p wa -k openclaw_config
-w $OPENCLAW_SECRETS_DIR -p rwa -k openclaw_secrets
-w $OPENCLAW_DIR -p x -k openclaw_exec
-w $OPENCLAW_STATE_DIR -p wa -k openclaw_state
-w /tmp/openclaw-workspace -p rwxa -k agent_workspace
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p rwa -k identity
-w /etc/sudoers -p wa -k sudoers
EOF

    systemctl restart auditd 2>/dev/null || true
    systemctl enable auditd 2>/dev/null || true
    
    log_action "apply" "7" "success" "审计策略配置完成"
    echo -e "  ${GREEN}[完成] 审计策略已配置${RESET}"
}

do_rollback_7() {
    log_info "开始回退: 删除审计规则"
    echo "  回退加固项 7: 删除审计规则..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f /etc/audit/rules.d/openclaw.rules
        systemctl restart auditd 2>/dev/null || true
        log_info "审计规则已删除"
        echo -e "  ${GREEN}[完成] 审计规则已删除${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除审计规则${RESET}"
    fi
    
    log_action "rollback" "7" "success" "审计规则已删除"
}

# [8] 网络出站白名单
do_apply_8() {
    log_info "开始执行: 配置网络出站白名单"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置出站白名单${RESET}"
        for domain in "${AI_API_DOMAINS[@]}"; do
            echo "    - $domain"
        done
        return
    fi
    
    # 保存白名单配置
    mkdir -p "$OPENCLAW_CONFIG_DIR"
    cat > "$OPENCLAW_CONFIG_DIR/outbound-whitelist.conf" << EOF
# OpenClaw 网络出站白名单 - 生成于 $(date '+%Y-%m-%d %H:%M:%S')
$(for domain in "${AI_API_DOMAINS[@]}"; do echo "$domain"; done)
EOF
    chmod 640 "$OPENCLAW_CONFIG_DIR/outbound-whitelist.conf"
    
    # 配置防火墙出站规则
    case $FIREWALL in
        ufw)
            ufw allow out 53/udp comment "DNS" 2>/dev/null || true
            ufw allow out 53/tcp comment "DNS" 2>/dev/null || true
            for domain in "${AI_API_DOMAINS[@]}"; do
                log_debug "解析域名: $domain"
                ips=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | head -5)
                for ip in $ips; do
                    ufw allow out to "$ip" port 443 proto tcp \
                        comment "AI API: $domain" 2>/dev/null || true
                done
            done
            ;;
        iptables)
            # 幂等检查
            if ! iptables -C OUTPUT -p udp --dport 53 -j ACCEPT 2>/dev/null; then
                iptables -A OUTPUT -p udp --dport 53 -j ACCEPT
                iptables -A OUTPUT -p tcp --dport 53 -j ACCEPT
                iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
                iptables -A OUTPUT -o lo -j ACCEPT
            fi
            for domain in "${AI_API_DOMAINS[@]}"; do
                ips=$(dig +short "$domain" 2>/dev/null | grep -E '^[0-9]+\.' | head -5)
                for ip in $ips; do
                    if ! iptables -C OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT 2>/dev/null; then
                        iptables -A OUTPUT -p tcp -d "$ip" --dport 443 -j ACCEPT
                    fi
                done
            done
            iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
            ;;
    esac
    
    log_action "apply" "8" "success" "网络出站白名单配置完成"
    echo -e "  ${GREEN}[完成] 网络出站白名单已配置${RESET}"
}

do_rollback_8() {
    log_info "开始回退: 删除出站白名单"
    echo "  回退加固项 8: 删除出站白名单..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$OPENCLAW_CONFIG_DIR/outbound-whitelist.conf"
        # 注意: 不删除防火墙规则以避免影响其他服务
        log_info "出站白名单配置已删除"
        echo -e "  ${GREEN}[完成] 配置已删除${RESET}"
        echo -e "  ${YELLOW}[注意] 防火墙规则需手动清理${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除出站白名单配置${RESET}"
    fi
    
    log_action "rollback" "8" "success" "出站白名单配置已删除"
}

# [9] 资源限制
do_apply_9() {
    log_info "开始执行: 配置资源限制"
    
    if ! command -v systemctl &>/dev/null; then
        log_warn "非 systemd 系统，跳过"
        echo -e "  ${YELLOW}[跳过] 非 systemd 系统${RESET}"
        return
    fi
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置资源限制${RESET}"
        return
    fi
    
    mkdir -p /etc/systemd/system/openclaw.service.d
    
    cat > /etc/systemd/system/openclaw.service.d/resource-limits.conf << EOF
# OpenClaw 资源限制 - 生成于 $(date '+%Y-%m-%d %H:%M:%S')
[Service]
CPUQuota=50%
MemoryMax=2G
MemoryHigh=1536M
TasksMax=100
LimitNOFILE=4096
LimitNPROC=64
LimitCORE=0
IOWeight=50
OOMScoreAdjust=500
EOF

    systemctl daemon-reload
    
    log_action "apply" "9" "success" "资源限制配置完成"
    echo -e "  ${GREEN}[完成] 资源限制已配置${RESET}"
}

do_rollback_9() {
    log_info "开始回退: 删除资源限制"
    echo "  回退加固项 9: 删除资源限制..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f /etc/systemd/system/openclaw.service.d/resource-limits.conf
        rmdir /etc/systemd/system/openclaw.service.d 2>/dev/null || true
        systemctl daemon-reload
        log_info "资源限制已删除"
        echo -e "  ${GREEN}[完成] 资源限制已删除${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除资源限制${RESET}"
    fi
    
    log_action "rollback" "9" "success" "资源限制已删除"
}

# [10] Bash Tool 限制
do_apply_10() {
    log_info "开始执行: 配置 Bash Tool 限制"
    
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "  ${CYAN}[DRY-RUN] 将配置 Bash Tool 限制${RESET}"
        return
    fi
    
    mkdir -p "$OPENCLAW_CONFIG_DIR"
    
    cat > "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf" << 'EOF'
# OpenClaw Bash Tool 安全限制配置

BLOCKED_COMMANDS=(
    "useradd" "userdel" "usermod" "passwd" "chpasswd"
    "groupadd" "groupdel" "groupmod"
    "chmod" "chown" "chgrp" "setfacl"
    "reboot" "shutdown" "poweroff" "init" "systemctl"
    "service" "update-rc.d"
    "iptables" "ip6tables" "ufw" "firewall-cmd"
    "ifconfig" "ip" "route"
    "mount" "umount" "fdisk" "mkfs" "dd"
    "apt" "apt-get" "dpkg" "yum" "dnf" "rpm"
    "sudo" "su" "pkexec" "doas"
    "crontab" "at"
)

ALLOWED_PATHS=(
    "/home"
    "/tmp/openclaw-workspace"
    "/var/lib/openclaw"
)

BLOCKED_PATHS=(
    "/etc"
    "/root"
    "/boot"
    "/sys"
    "/proc"
    "/dev"
    "/usr/sbin"
    "/sbin"
)

MAX_EXEC_TIME=60
MAX_OUTPUT_SIZE=1048576
ALLOW_BACKGROUND=false
EOF

    chmod 640 "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf"
    chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf" 2>/dev/null || true
    
    # 创建受限 shell 包装器
    cat > "$OPENCLAW_DIR/restricted-bash.sh" << 'EOF'
#!/bin/bash
TIMEOUT=60
enable -n source
enable -n eval
export PATH="/usr/bin:/bin"
timeout $TIMEOUT bash -r -c "$@"
EOF
    chmod 750 "$OPENCLAW_DIR/restricted-bash.sh" 2>/dev/null || true
    chown root:"$SERVICE_ACCOUNT" "$OPENCLAW_DIR/restricted-bash.sh" 2>/dev/null || true
    
    log_action "apply" "10" "success" "Bash Tool 限制配置完成"
    echo -e "  ${GREEN}[完成] Bash Tool 限制已配置${RESET}"
}

do_rollback_10() {
    log_info "开始回退: 删除 Bash Tool 限制"
    echo "  回退加固项 10: 删除 Bash Tool 限制..."
    
    if [ "$DRY_RUN" -eq 0 ]; then
        rm -f "$OPENCLAW_CONFIG_DIR/bash-restrictions.conf"
        rm -f "$OPENCLAW_DIR/restricted-bash.sh"
        log_info "Bash Tool 限制已删除"
        echo -e "  ${GREEN}[完成] 限制配置已删除${RESET}"
    else
        echo -e "  ${CYAN}[DRY-RUN] 将删除 Bash Tool 限制${RESET}"
    fi
    
    log_action "rollback" "10" "success" "Bash Tool 限制已删除"
}

# ============================================================================
# 执行加固/回退
# ============================================================================

apply_item() {
    local item=$1
    local name=${ITEM_NAMES[$item]}
    
    log_info "执行加固项 $item: $name"
    
    # 调用对应的加固函数
    "do_apply_$item"
    
    # 更新状态
    if [ "$DRY_RUN" -eq 0 ]; then
        set_item_state "$item" "applied"
    fi
}

rollback_item() {
    local item=$1
    local name=${ITEM_NAMES[$item]}
    
    log_info "回退加固项 $item: $name"
    echo ""
    echo -e "${YELLOW}回退加固项 $item: $name${RESET}"
    
    # 调用对应的回退函数
    "do_rollback_$item"
    
    # 更新状态
    if [ "$DRY_RUN" -eq 0 ]; then
        clear_item_state "$item"
    fi
}

# ============================================================================
# 调试模式
# ============================================================================

debug_item() {
    local item=$1
    local name=${ITEM_NAMES[$item]}
    
    echo ""
    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${CYAN}调试模式 - 加固项 $item: $name${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    echo ""
    
    # 显示当前状态
    local state=$(get_item_state "$item")
    echo -e "当前状态: ${YELLOW}$state${RESET}"
    echo ""
    
    echo "可用操作:"
    echo "  [1] 执行加固 (apply)"
    echo "  [2] 执行回退 (rollback)"
    echo "  [3] 模拟执行加固 (dry-run apply)"
    echo "  [4] 模拟执行回退 (dry-run rollback)"
    echo "  [5] 查看日志"
    echo "  [0] 退出调试"
    echo ""
    
    read -p "请选择: " choice
    
    case $choice in
        1)
            DEBUG_MODE=1
            DRY_RUN=0
            echo ""
            apply_item "$item"
            ;;
        2)
            DEBUG_MODE=1
            DRY_RUN=0
            echo ""
            rollback_item "$item"
            ;;
        3)
            DEBUG_MODE=1
            DRY_RUN=1
            echo ""
            apply_item "$item"
            ;;
        4)
            DEBUG_MODE=1
            DRY_RUN=1
            echo ""
            rollback_item "$item"
            ;;
        5)
            echo ""
            echo "最近日志 (包含项目 $item):"
            grep -E "(item=$item|加固项 $item)" "$LOG_FILE" 2>/dev/null | tail -20
            ;;
        0)
            return
            ;;
    esac
    
    echo ""
    read -p "按 Enter 继续..."
    debug_item "$item"
}

# ============================================================================
# 状态查看
# ============================================================================

show_status() {
    echo ""
    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${CYAN}OpenClaw 安全加固状态${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    echo ""
    
    for i in {1..10}; do
        local name=${ITEM_NAMES[$i]}
        local state=$(get_item_state "$i")
        
        case $state in
            applied)
                echo -e "  [${GREEN}√${RESET}] [$i] $name"
                ;;
            *)
                echo -e "  [ ] [$i] $name"
                ;;
        esac
    done
    
    echo ""
    echo "日志文件: $LOG_FILE"
    echo "状态文件: $STATE_FILE"
    echo ""
}

# ============================================================================
# 主菜单
# ============================================================================

print_header() {
    clear
    echo -e "${CYAN}============================================================${RESET}"
    echo -e "${CYAN}      OpenClaw Linux 安全加固脚本 v1.1${RESET}"
    echo -e "${CYAN}============================================================${RESET}"
    if [ "$DRY_RUN" -eq 1 ]; then
        echo -e "${YELLOW}                [模拟运行模式]${RESET}"
    fi
    if [ "$DEBUG_MODE" -eq 1 ]; then
        echo -e "${CYAN}                [调试模式]${RESET}"
    fi
    echo ""
}

main_menu() {
    print_header
    
    echo -e "${WHITE}功能特性:${RESET}"
    echo "  - 幂等执行: 可安全重复运行"
    echo "  - 单独回退: 支持回退指定加固项"
    echo "  - 完整日志: 所有操作均有记录"
    echo "  - 调试模式: 支持单项调试"
    echo ""
    
    echo -e "${WHITE}请选择操作:${RESET}"
    echo ""
    echo -e "  ${CYAN}[1]${RESET} 交互式选择加固项"
    echo -e "  ${CYAN}[2]${RESET} 一键完整加固"
    echo -e "  ${CYAN}[3]${RESET} 查看加固状态"
    echo -e "  ${CYAN}[4]${RESET} 回退指定加固项"
    echo -e "  ${CYAN}[5]${RESET} 调试指定加固项"
    echo -e "  ${CYAN}[6]${RESET} 查看日志"
    echo -e "  ${CYAN}[7]${RESET} 全部回退"
    echo -e "  ${CYAN}[0]${RESET} 退出"
    echo ""
    read -p "请输入选项 [0-7]: " choice

    case $choice in
        1) interactive_select ;;
        2) one_click_all ;;
        3) show_status; read -p "按 Enter 返回..."; main_menu ;;
        4) rollback_menu ;;
        5) debug_menu ;;
        6) view_logs ;;
        7) rollback_all ;;
        0) exit_script ;;
        *) main_menu ;;
    esac
}

interactive_select() {
    # 选择状态
    declare -A SELECTED
    for i in {1..10}; do SELECTED[$i]=0; done
    
    while true; do
        print_header
        echo -e "${WHITE}输入数字切换选中状态 (支持多选如 '1234')${RESET}"
        echo ""
        
        for i in {1..10}; do
            local name=${ITEM_NAMES[$i]}
            local state=$(get_item_state "$i")
            local sel=${SELECTED[$i]}
            
            local status_icon=""
            [ "$state" = "applied" ] && status_icon="${GREEN}[已加固]${RESET} "
            
            if [ "$sel" -eq 1 ]; then
                echo -e "  ${GREEN}[√]${RESET} [$i] $status_icon$name"
            else
                echo -e "  [ ] [$i] $status_icon$name"
            fi
        done
        
        echo ""
        echo -e "  ${CYAN}[A]${RESET} 全选  ${CYAN}[N]${RESET} 清空  ${CYAN}[E]${RESET} 执行  ${CYAN}[B]${RESET} 返回"
        echo ""
        read -p "请输入: " input
        
        case "${input^^}" in
            A) for i in {1..10}; do SELECTED[$i]=1; done ;;
            N) for i in {1..10}; do SELECTED[$i]=0; done ;;
            B) main_menu; return ;;
            E)
                # 执行选中项
                local count=0
                for i in {1..10}; do [ "${SELECTED[$i]}" -eq 1 ] && ((count++)); done
                
                if [ $count -eq 0 ]; then
                    echo -e "${YELLOW}请至少选择一个加固项${RESET}"
                    sleep 1
                    continue
                fi
                
                echo ""
                log_info "开始执行 $count 个加固项"
                
                for i in {1..10}; do
                    if [ "${SELECTED[$i]}" -eq 1 ]; then
                        echo ""
                        echo -e "${CYAN}执行加固项 $i: ${ITEM_NAMES[$i]}${RESET}"
                        apply_item "$i"
                    fi
                done
                
                echo ""
                echo -e "${GREEN}完成！执行了 $count 个加固项${RESET}"
                log_info "加固完成，共 $count 项"
                read -p "按 Enter 返回..."
                main_menu
                return
                ;;
            *)
                # 处理数字输入
                for ((j=0; j<${#input}; j++)); do
                    char="${input:$j:1}"
                    if [[ "$char" =~ ^[0-9]$ ]]; then
                        if [ "$char" = "1" ] && [ $((j+1)) -lt ${#input} ]; then
                            next="${input:$((j+1)):1}"
                            if [ "$next" = "0" ]; then
                                SELECTED[10]=$((1 - SELECTED[10]))
                                ((j++))
                                continue
                            fi
                        fi
                        if [ "$char" -ge 1 ] && [ "$char" -le 9 ]; then
                            SELECTED[$char]=$((1 - SELECTED[$char]))
                        fi
                    fi
                done
                ;;
        esac
    done
}

one_click_all() {
    print_header
    echo -e "${CYAN}一键完整加固 - 执行所有 10 个加固项${RESET}"
    echo ""
    
    read -p "确认执行? [Y/N]: " confirm
    if [[ ! "${confirm^^}" =~ ^Y ]]; then
        main_menu
        return
    fi
    
    log_info "开始一键完整加固"
    
    for i in {1..10}; do
        echo ""
        echo -e "${CYAN}[$i/10] ${ITEM_NAMES[$i]}${RESET}"
        apply_item "$i"
    done
    
    echo ""
    echo -e "${GREEN}============================================================${RESET}"
    echo -e "${GREEN}一键完整加固完成！${RESET}"
    echo -e "${GREEN}============================================================${RESET}"
    log_info "一键完整加固完成"
    
    read -p "按 Enter 返回..."
    main_menu
}

rollback_menu() {
    print_header
    echo -e "${YELLOW}选择要回退的加固项:${RESET}"
    echo ""
    
    for i in {1..10}; do
        local name=${ITEM_NAMES[$i]}
        local state=$(get_item_state "$i")
        
        if [ "$state" = "applied" ]; then
            echo -e "  ${GREEN}[√]${RESET} [$i] $name"
        else
            echo -e "  ${DIM}[ ] [$i] $name (未加固)${RESET}"
        fi
    done
    
    echo ""
    echo -e "  ${CYAN}[B]${RESET} 返回主菜单"
    echo ""
    read -p "输入要回退的加固项编号 (1-10): " item
    
    if [ "$item" = "B" ] || [ "$item" = "b" ]; then
        main_menu
        return
    fi
    
    if [[ "$item" =~ ^[0-9]+$ ]] && [ "$item" -ge 1 ] && [ "$item" -le 10 ]; then
        echo ""
        read -p "确认回退加固项 $item? [Y/N]: " confirm
        if [[ "${confirm^^}" =~ ^Y ]]; then
            rollback_item "$item"
        fi
    else
        echo -e "${RED}无效的加固项编号${RESET}"
    fi
    
    read -p "按 Enter 继续..."
    rollback_menu
}

rollback_all() {
    print_header
    echo -e "${RED}警告: 将回退所有已应用的加固项${RESET}"
    echo ""
    
    read -p "确认全部回退? 输入 CONFIRM: " confirm
    if [ "$confirm" != "CONFIRM" ]; then
        main_menu
        return
    fi
    
    log_info "开始全部回退"
    
    # 倒序回退
    for i in 10 9 8 7 6 5 4 3 2 1; do
        local state=$(get_item_state "$i")
        if [ "$state" = "applied" ]; then
            rollback_item "$i"
        fi
    done
    
    echo ""
    echo -e "${GREEN}全部回退完成${RESET}"
    log_info "全部回退完成"
    
    read -p "按 Enter 返回..."
    main_menu
}

debug_menu() {
    print_header
    echo -e "${CYAN}调试模式 - 选择要调试的加固项:${RESET}"
    echo ""
    
    for i in {1..10}; do
        local name=${ITEM_NAMES[$i]}
        local state=$(get_item_state "$i")
        echo "  [$i] [$state] $name"
    done
    
    echo ""
    echo -e "  ${CYAN}[B]${RESET} 返回主菜单"
    echo ""
    read -p "输入加固项编号 (1-10): " item
    
    if [ "$item" = "B" ] || [ "$item" = "b" ]; then
        main_menu
        return
    fi
    
    if [[ "$item" =~ ^[0-9]+$ ]] && [ "$item" -ge 1 ] && [ "$item" -le 10 ]; then
        debug_item "$item"
    fi
    
    debug_menu
}

view_logs() {
    print_header
    echo -e "${CYAN}日志查看${RESET}"
    echo ""
    echo "日志文件: $LOG_FILE"
    echo ""
    echo "最近 30 条日志:"
    echo -e "${DIM}----------------------------------------${RESET}"
    tail -30 "$LOG_FILE" 2>/dev/null || echo "(无日志)"
    echo -e "${DIM}----------------------------------------${RESET}"
    echo ""
    read -p "按 Enter 返回..."
    main_menu
}

exit_script() {
    log_info "脚本退出"
    echo ""
    echo "感谢使用 OpenClaw 安全加固脚本！"
    echo "日志文件: $LOG_FILE"
    exit 0
}

# ============================================================================
# 帮助信息
# ============================================================================

show_help() {
    echo "OpenClaw Linux 安全加固脚本 v1.1"
    echo ""
    echo "用法: $0 [选项]"
    echo ""
    echo "选项:"
    echo "  --help, -h         显示帮助信息"
    echo "  --dry-run          模拟运行，不实际执行"
    echo "  --status           查看加固状态"
    echo "  --rollback <N>     回退指定加固项 (1-10)"
    echo "  --debug <N>        调试指定加固项 (1-10)"
    echo "  --apply <N>        应用指定加固项 (1-10)"
    echo "  --all              一键应用所有加固项"
    echo ""
    echo "示例:"
    echo "  $0                     # 交互式菜单"
    echo "  $0 --dry-run           # 模拟运行"
    echo "  $0 --status            # 查看状态"
    echo "  $0 --rollback 5        # 回退加固项 5"
    echo "  $0 --debug 3           # 调试加固项 3"
    echo "  $0 --apply 1 --apply 2 # 应用加固项 1 和 2"
    echo ""
}

# ============================================================================
# 主程序
# ============================================================================

main() {
    # 初始化
    init_logging
    
    # 检测系统
    detect_distro
    detect_firewall
    detect_mac
    detect_package_manager
    
    # 解析参数
    local apply_items=()
    
    while [[ $# -gt 0 ]]; do
        case $1 in
            --help|-h)
                show_help
                exit 0
                ;;
            --dry-run)
                DRY_RUN=1
                shift
                ;;
            --status)
                show_status
                exit 0
                ;;
            --rollback)
                ROLLBACK_MODE=1
                ROLLBACK_ITEM=$2
                shift 2
                ;;
            --debug)
                DEBUG_MODE=1
                DEBUG_ITEM=$2
                shift 2
                ;;
            --apply)
                apply_items+=("$2")
                shift 2
                ;;
            --all)
                apply_items=(1 2 3 4 5 6 7 8 9 10)
                shift
                ;;
            *)
                shift
                ;;
        esac
    done
    
    # 检查 root
    if [ "$EUID" -ne 0 ] && [ "$DRY_RUN" -eq 0 ]; then
        echo -e "${RED}[错误] 请使用 root 权限运行！${RESET}"
        echo "使用方法: sudo $0"
        exit 1
    fi
    
    log_info "脚本启动"
    
    # 命令行模式
    if [ "$ROLLBACK_MODE" -eq 1 ]; then
        if [[ "$ROLLBACK_ITEM" =~ ^[0-9]+$ ]] && [ "$ROLLBACK_ITEM" -ge 1 ] && [ "$ROLLBACK_ITEM" -le 10 ]; then
            rollback_item "$ROLLBACK_ITEM"
        else
            echo -e "${RED}无效的加固项编号: $ROLLBACK_ITEM${RESET}"
            exit 1
        fi
        exit 0
    fi
    
    if [ "$DEBUG_MODE" -eq 1 ] && [ "$DEBUG_ITEM" -gt 0 ]; then
        if [[ "$DEBUG_ITEM" =~ ^[0-9]+$ ]] && [ "$DEBUG_ITEM" -ge 1 ] && [ "$DEBUG_ITEM" -le 10 ]; then
            debug_item "$DEBUG_ITEM"
        else
            echo -e "${RED}无效的加固项编号: $DEBUG_ITEM${RESET}"
            exit 1
        fi
        exit 0
    fi
    
    if [ ${#apply_items[@]} -gt 0 ]; then
        for item in "${apply_items[@]}"; do
            if [[ "$item" =~ ^[0-9]+$ ]] && [ "$item" -ge 1 ] && [ "$item" -le 10 ]; then
                echo ""
                echo -e "${CYAN}应用加固项 $item: ${ITEM_NAMES[$item]}${RESET}"
                apply_item "$item"
            fi
        done
        exit 0
    fi
    
    # 交互式菜单
    main_menu
}

main "$@"
