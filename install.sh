#!/bin/bash

# ==============================================================================
# VPS 定制初始化脚本 (适用于 Debian & Ubuntu LTS)
# 版本: 8.0.0 (精简定制版)
# ------------------------------------------------------------------------------
# 修改内容:
# - [修改] 软件包: 增加 htop, iperf3, mtr, iftop, rsyslog, nano; 移除 vim 优化
# - [移除] 彻底移除 Swap 自动配置
# - [移除] 彻底移除 Fail2ban 配置
# - [保留] BBR 深度优化, SSH 安全配置, 主机名/时区/DNS/NTP 配置
# ==============================================================================
set -euo pipefail

# --- 默认配置 ---
TIMEZONE=$(timedatectl show --property=Timezone --value 2>/dev/null || echo "UTC")
# [修改] 更新后的软件包列表
INSTALL_PACKAGES="curl sudo wget htop unzip iptables nano iperf3 mtr iftop rsyslog"
PRIMARY_DNS_V4="1.1.1.1"
SECONDARY_DNS_V4="8.8.8.8"
PRIMARY_DNS_V6="2606:4700:4700::1111"
SECONDARY_DNS_V6="2001:4860:4860::8888"
NEW_HOSTNAME=""
BBR_MODE="default"

# --- SSH 相关配置 ---
NEW_SSH_PORT=""
NEW_SSH_PASSWORD=""

# --- 颜色和全局变量 ---
readonly GREEN='\033[0;32m' RED='\033[0;31m' YELLOW='\033[1;33m'
readonly BLUE='\033[0;34m' CYAN='\033[0;36m' NC='\033[0m'

non_interactive=false
spinner_pid=0
LOG_FILE=""
VERIFICATION_PASSED=0
VERIFICATION_FAILED=0
VERIFICATION_WARNINGS=0

# ==============================================================================
# --- 核心辅助函数 ---
# ==============================================================================

log() {
    echo -e "$1"
}

handle_error() {
    local exit_code=$? line_number=$1
    command -v tput >/dev/null 2>&1 && tput cnorm 2>/dev/null || true
    local error_message="\n${RED}[ERROR] 脚本在第 ${line_number} 行失败 (退出码: ${exit_code})${NC}"
    echo -e "$error_message"
    [[ -n "$LOG_FILE" ]] && echo "[ERROR] Script failed at line ${line_number} (exit code: ${exit_code})" >> "$LOG_FILE"
    [[ $spinner_pid -ne 0 ]] && kill "$spinner_pid" 2>/dev/null
    exit "$exit_code"
}

start_spinner() {
    if ! command -v tput >/dev/null 2>&1 || [[ ! -t 1 ]]; then
        echo -e "${CYAN}${1:-}${NC}"
        return
    fi
    echo -n -e "${CYAN}${1:-}${NC}"
    ( while :; do for c in '/' '-' '\' '|'; do echo -ne "\b$c"; sleep 0.1; done; done ) &
    spinner_pid=$!
    tput civis 2>/dev/null || true
}

stop_spinner() {
    if [[ $spinner_pid -ne 0 ]]; then
        kill "$spinner_pid" 2>/dev/null
        wait "$spinner_pid" 2>/dev/null || true
        spinner_pid=0
    fi
    if command -v tput >/dev/null 2>&1 && [[ -t 1 ]]; then
        tput cnorm 2>/dev/null || true
        echo -e "\b${GREEN}✔${NC}"
    else
        echo -e "${GREEN}✔${NC}"
    fi
}

get_public_ipv4() {
    local ip
    for cmd in "curl -s -4 --max-time 5" "wget -qO- -4 --timeout=5"; do
        for url in "https://api.ipify.org" "https://ip.sb"; do
            ip=$($cmd "$url" 2>/dev/null) && [[ "$ip" =~ ^[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}$ ]] && echo "$ip" && return
        done
    done
}

has_ipv6() {
    if ip -6 route show default 2>/dev/null | grep -q 'default' || ip -6 addr show 2>/dev/null | grep -q 'inet6.*scope global'; then
        return 0
    fi
    if command -v ping &>/dev/null; then
        ping -6 -c 1 -W 3 dns.google >/dev/null 2>&1 && return 0
    fi
    if command -v curl &>/dev/null; then
        curl -6 -s --head --max-time 5 "https://[2606:4700:4700::1111]/" >/dev/null 2>&1 && return 0
    fi
    return 1
}

is_container() {
    case "$(systemd-detect-virt --container 2>/dev/null)" in
        docker|lxc|openvz|containerd|podman) return 0 ;;
    esac
    [[ -f /.dockerenv ]] || [[ -f /run/.containerenv ]] ||
    grep -q 'container=lxc\|container=docker' /proc/1/environ 2>/dev/null
}

compare_version() {
    printf '%s\n' "$@" | sort -V | head -n1
}

is_kernel_version_ge() {
    local required="$1" current
    current=$(uname -r | grep -oP '^\d+\.\d+' || echo "0.0")
    [[ "$(compare_version "$current" "$required")" = "$required" ]]
}

verify_privileges() {
    local checks=0
    [[ $EUID -eq 0 ]] && ((checks++))
    [[ -w /etc/passwd ]] && ((checks++))
    [[ $EUID -eq 0 ]] || groups | grep -qE '\b(sudo|wheel|admin)\b' && ((checks++))
    if [[ $checks -lt 2 ]]; then
        log "${RED}[ERROR] 权限不足，需要root权限或完整sudo权限${NC}"
        return 1
    fi
    return 0
}

# ==============================================================================
# --- 验证函数 ---
# ==============================================================================

record_verification() {
    local component="$1" status="$2" message="$3"
    case "$status" in
        "PASS") log "    ${GREEN}✓${NC} ${component}: ${message}"; ((VERIFICATION_PASSED++)) ;;
        "WARN") log "    ${YELLOW}⚠${NC} ${component}: ${message}"; ((VERIFICATION_WARNINGS++)) ;;
        "FAIL") log "    ${RED}✗${NC} ${component}: ${message}"; ((VERIFICATION_FAILED++)) ;;
    esac
}

verify_config() {
    local component="$1" expected="$2" actual="$3"
    if [[ "$actual" = "$expected" ]]; then
        record_verification "$component" "PASS" "已设置为 '${actual}'"
    else
        record_verification "$component" "FAIL" "期望 '${expected}'，实际 '${actual}'"
    fi
}

verify_bbr() {
    local current_cc=$(sysctl -n net.ipv4.tcp_congestion_control 2>/dev/null || echo "N/A")
    local current_qdisc=$(sysctl -n net.core.default_qdisc 2>/dev/null || echo "N/A")
    if [[ "$BBR_MODE" = "none" ]]; then
        [[ "$current_cc" != "bbr" ]] && record_verification "BBR" "PASS" "已禁用" || record_verification "BBR" "WARN" "可能需要重启生效 (当前: ${current_cc})"
    elif [[ "$current_cc" = "bbr" && "$current_qdisc" = "fq" ]]; then
        record_verification "BBR" "PASS" "已启用 (${BBR_MODE}模式)"
    else
        record_verification "BBR" "FAIL" "配置异常: ${current_cc}/${current_qdisc}"
    fi
}

verify_dns() {
    local status="FAIL" message="" dns_servers=""
    if (systemctl is-active --quiet cloud-init 2>/dev/null || [[ -d /etc/cloud ]]); then
        status="WARN"
        message="云环境可能覆盖; "
    fi
    if (systemctl is-active --quiet systemd-resolved 2>/dev/null); then
        local conf_file="/etc/systemd/resolved.conf.d/99-custom-dns.conf"
        if [[ -f "$conf_file" ]]; then
            dns_servers=$(grep -E "^\s*DNS=" "$conf_file" | sed -e 's/DNS=//' -e 's/^\s*//' -e 's/\s*$//')
        fi
        message+="systemd-resolved: "
    else
        local conf_file="/etc/resolv.conf"
        if [[ -f "$conf_file" ]]; then
            dns_servers=$(grep -E "^\s*nameserver" "$conf_file" | awk '{print $2}' | paste -sd ' ' -)
        fi
        message+="resolv.conf: "
    fi
    if [[ -n "$dns_servers" ]]; then
        [[ "$status" != "WARN" ]] && status="PASS"
        message+="${dns_servers}"
    else
        status="FAIL"
        message+="配置缺失"
    fi
    record_verification "DNS" "$status" "$message"
}

verify_time_sync() {
    if (timedatectl status 2>/dev/null | grep -q 'NTP service: active'); then
        record_verification "时间同步" "PASS" "systemd-timesyncd (NTP) 已激活"
    elif (systemctl is-active --quiet systemd-timesyncd 2>/dev/null); then
        record_verification "时间同步" "PASS" "systemd-timesyncd 服务运行中"
    elif (systemctl is-active --quiet chrony 2>/dev/null || systemctl is-active --quiet ntp 2>/dev/null); then
        record_verification "时间同步" "WARN" "正在使用第三方NTP (chrony/ntp)"
    else
        record_verification "时间同步" "FAIL" "NTP服务未运行"
    fi
}

run_verification() {
    log "\n${YELLOW}=============== 配置验证 ===============${NC}"
    VERIFICATION_PASSED=0 VERIFICATION_FAILED=0 VERIFICATION_WARNINGS=0
    set +e
    [[ -n "$NEW_HOSTNAME" ]] && verify_config "主机名" "$NEW_HOSTNAME" "$(hostname)"
    verify_config "时区" "$TIMEZONE" "$(timedatectl show --property=Timezone --value 2>/dev/null || echo 'N/A')"
    verify_time_sync
    verify_bbr
    verify_dns
    local installed=0 total=0
    for pkg in $INSTALL_PACKAGES; do ((total++)); dpkg -l "$pkg" >/dev/null 2>&1 && ((installed++)); done
    [[ $installed -eq $total ]] && record_verification "软件包" "PASS" "全部已安装 ($installed/$total)" || record_verification "软件包" "FAIL" "部分缺失 ($installed/$total)"
    if [[ -n "$NEW_SSH_PORT" ]]; then
        local current_port=$(grep -oP '^\s*Port\s+\K\d+' /etc/ssh/sshd_config | tail -n1)
        [[ -z "$current_port" ]] && current_port="22"
        verify_config "SSH端口" "$NEW_SSH_PORT" "$current_port"
    fi
    set -e
    log "\n${BLUE}验证结果: ${GREEN}通过 ${VERIFICATION_PASSED}${NC}, ${YELLOW}警告 ${VERIFICATION_WARNINGS}${NC}, ${RED}失败 ${VERIFICATION_FAILED}${NC}"
}

# ==============================================================================
# --- 参数解析 ---
# ==============================================================================

usage() {
    cat << EOF
${YELLOW}用法: $0 [选项]${NC}
${BLUE}核心选项:${NC}
  --hostname <name>      设置主机名
  --timezone <tz>        设置时区
  --ip-dns <'主 备'>      设置IPv4 DNS
  --ip6-dns <'主 备'>     设置IPv6 DNS
${BLUE}BBR选项:${NC}
  --bbr                  启用默认BBR (默认)
  --bbr-optimized        启用优化BBR (高配置)
  --no-bbr               禁用BBR
${BLUE}SSH选项:${NC}
  --ssh-port <port>      设置SSH端口
  --ssh-password <pass> 设置root密码
${BLUE}其他:${NC}
  -h, --help             显示帮助
  --non-interactive      非交互模式
${GREEN}示例: $0 --bbr-optimized --ssh-port 2222${NC}
EOF
    exit 0
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage ;;
            --hostname) NEW_HOSTNAME="$2"; shift 2 ;;
            --timezone) TIMEZONE="$2"; shift 2 ;;
            --ip-dns) read -r PRIMARY_DNS_V4 SECONDARY_DNS_V4 <<< "$2"; shift 2 ;;
            --ip6-dns) read -r PRIMARY_DNS_V6 SECONDARY_DNS_V6 <<< "$2"; shift 2 ;;
            --bbr) BBR_MODE="default"; shift ;;
            --bbr-optimized) BBR_MODE="optimized"; shift ;;
            --no-bbr) BBR_MODE="none"; shift ;;
            --ssh-port) NEW_SSH_PORT="$2"; shift 2 ;;
            --ssh-password) NEW_SSH_PASSWORD="$2"; shift 2 ;;
            --non-interactive) non_interactive=true; shift ;;
            *) echo -e "${RED}未知选项: $1${NC}"; usage ;;
        esac
    done
}

# ==============================================================================
# --- 功能函数 ---
# ==============================================================================

pre_flight_checks() {
    log "${BLUE}[INFO] 系统预检查...${NC}"
    verify_privileges || exit 1
    if is_container; then
        log "${YELLOW}[WARN] 容器环境，某些功能可能受限${NC}"
        [[ "$non_interactive" = false ]] && { read -p "继续? [y/N] " -r < /dev/tty; [[ ! "$REPLY" =~ ^[Yy]$ ]] && exit 0; }
    fi
    [[ ! -f /etc/os-release ]] && { log "${RED}错误: 系统信息缺失${NC}"; exit 1; }
    source /etc/os-release
    local supported=false
    [[ "$ID" = "debian" && "$VERSION_ID" =~ ^(10|11|12|13)$ ]] && supported=true
    [[ "$ID" = "ubuntu" && "$VERSION_ID" =~ ^(20\.04|22\.04|24\.04)$ ]] && supported=true
    if [[ "$supported" = "false" ]]; then
        log "${YELLOW}[WARN] 系统: ${PRETTY_NAME} (建议使用Debian 10-13或Ubuntu 20.04-24.04)${NC}"
        [[ "$non_interactive" = false ]] && { read -p "继续? [y/N] " -r < /dev/tty; [[ ! "$REPLY" =~ ^[Yy]$ ]] && exit 0; }
    fi
    log "${GREEN}✅ 系统: ${PRETTY_NAME}${NC}"
}

install_packages() {
    log "\n${YELLOW}=============== 1. 软件包安装 ===============${NC}"
    log "${BLUE}即将安装: ${INSTALL_PACKAGES}${NC}"
    start_spinner "更新软件包列表... "
    DEBIAN_FRONTEND=noninteractive apt-get update -qq >> "$LOG_FILE" 2>&1
    stop_spinner
    start_spinner "安装软件包... "
    DEBIAN_FRONTEND=noninteractive apt-get install -y $INSTALL_PACKAGES >> "$LOG_FILE" 2>&1
    stop_spinner
    # [移除] Vim 优化配置已删除
    log "${GREEN}✅ 软件包安装完成${NC}"
}

configure_hostname() {
    log "\n${YELLOW}=============== 2. 主机名配置 ===============${NC}"
    local current_hostname=$(hostname)
    log "${BLUE}当前主机名: ${current_hostname}${NC}"
    local final_hostname="$current_hostname"
    if [[ -n "$NEW_HOSTNAME" ]]; then
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
            hostnamectl set-hostname "$NEW_HOSTNAME" >> "$LOG_FILE" 2>&1
            final_hostname="$NEW_HOSTNAME"
            log "${GREEN}✅ 主机名设为: ${NEW_HOSTNAME}${NC}"
        else
            log "${RED}[ERROR] 主机名格式错误${NC}"
            NEW_HOSTNAME=""
        fi
    elif [[ "$non_interactive" = true ]]; then
        local auto_ip
        auto_ip=$(get_public_ipv4)
        if [[ -n "$auto_ip" ]]; then 
            final_hostname=$(echo "$auto_ip" | tr '.' '-')
            hostnamectl set-hostname "$final_hostname" >> "$LOG_FILE" 2>&1
            NEW_HOSTNAME="$final_hostname"
            log "${GREEN}✅ 自动设置主机名: ${final_hostname}${NC}"
        else
            log "${YELLOW}[WARN] 无法自动获取公网IP，跳过自动设置主机名。${NC}"
        fi
    elif [[ "$non_interactive" = false ]]; then
        read -p "修改主机名? [y/N] " -r < /dev/tty
        if [[ "$REPLY" =~ ^[Yy]$ ]]; then
            read -p "输入新主机名: " new_name < /dev/tty
            if [[ -n "$new_name" && "$new_name" =~ ^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$ ]]; then
                hostnamectl set-hostname "$new_name" >> "$LOG_FILE" 2>&1
                final_hostname="$new_name"
                NEW_HOSTNAME="$new_name"
            fi
        fi
    fi
    if [[ "$final_hostname" != "$current_hostname" ]]; then
        if grep -q "^127\.0\.1\.1" /etc/hosts; then
            sed -i "s/^127\.0\.1\.1.*/127.0.1.1\t${final_hostname}/" /etc/hosts
        else
            echo -e "127.0.1.1\t${final_hostname}" >> /etc/hosts
        fi
    fi
}

configure_timezone() {
    log "\n${YELLOW}=============== 3. 时区配置 ===============${NC}"
    timedatectl set-timezone "$TIMEZONE" >> "$LOG_FILE" 2>&1
    log "${GREEN}✅ 时区: ${TIMEZONE}${NC}"
}

configure_time_sync() {
    log "\n${YELLOW}=============== 4. 时间同步配置 ===============${NC}"
    if (systemctl is-active --quiet chrony 2>/dev/null || \
       systemctl is-active --quiet ntp 2>/dev/null || \
       systemctl is-active --quiet ntpd 2>/dev/null); then
        log "${YELLOW}[WARN] 检测到已有的NTP服务 (chrony/ntp) 正在运行，跳过。${NC}"
        return
    fi
    if ! command -v timedatectl >/dev/null 2>&1; then
        log "${RED}[ERROR] 未找到 timedatectl 命令, 无法配置 systemd-timesyncd。${NC}"
        return
    fi
    local timesyncd_enabled=false
    if systemctl cat systemd-timesyncd >/dev/null 2>&1; then
        start_spinner "启用 systemd-timesyncd (NTP)... "
        systemctl unmask systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        if timedatectl set-ntp true >> "$LOG_FILE" 2>&1; then
            timesyncd_enabled=true
        else
            systemctl enable --now systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        fi
        stop_spinner
    fi
    if [ "$timesyncd_enabled" = false ] && ! (systemctl is-active --quiet systemd-timesyncd 2>/dev/null); then
        log "${YELLOW}[WARN] systemd-timesyncd 未运行，尝试安装...${NC}"
        start_spinner "安装 systemd-timesyncd... "
        DEBIAN_FRONTEND=noninteractive apt-get update -qq >> "$LOG_FILE" 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get install -y systemd-timesyncd >> "$LOG_FILE" 2>&1
        stop_spinner
        start_spinner "再次尝试启用 systemd-timesyncd... "
        systemctl unmask systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        if timedatectl set-ntp true >> "$LOG_FILE" 2>&1; then
             : 
        else
            systemctl enable --now systemd-timesyncd >> "$LOG_FILE" 2>&1 || true
        fi
        stop_spinner
    fi
    if (timedatectl status 2>/dev/null | grep -q 'NTP service: active'); then
        log "${GREEN}✅ systemd-timesyncd (NTP) 已启用并激活。${NC}"
    elif (systemctl is-active --quiet systemd-timesyncd 2>/dev/null); then
        log "${GREEN}✅ systemd-timesyncd (NTP) 服务正在运行。${NC}"
    else
        log "${RED}[ERROR] 尝试启用 'systemd-timesyncd' 失败！${NC}"
    fi
}

configure_bbr() {
    log "\n${YELLOW}=============== 5. BBR配置 (优化版) ===============${NC}"
    local config_file="/etc/sysctl.d/99-bbr.conf"
    if [[ "$BBR_MODE" = "none" ]]; then
        log "${BLUE}[INFO] 跳过BBR配置${NC}"
        rm -f "$config_file"
        sysctl -p >> "$LOG_FILE" 2>&1 || true
        return
    fi
    if ! is_kernel_version_ge "4.9"; then
        log "${RED}[ERROR] 内核版本过低 ($(uname -r))，需要4.9+${NC}"
        return 1
    fi
    local mem_mb=$(free -m | awk '/^Mem:/{print $2}')
    case "$BBR_MODE" in
        "optimized")
            log "${BLUE}配置优化BBR (高性能参数)...${NC}"
            if [[ $mem_mb -lt 1024 ]]; then log "${YELLOW}[WARN] 内存较低，建议使用默认BBR模式${NC}"; fi
            local rmem_wmem somaxconn
            if [[ $mem_mb -ge 4096 ]]; then rmem_wmem=67108864; somaxconn=65535
            elif [[ $mem_mb -ge 1024 ]]; then rmem_wmem=33554432; somaxconn=32768
            else rmem_wmem=16777216; somaxconn=16384; fi
            cat > "$config_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
net.core.rmem_max = ${rmem_wmem}
net.core.wmem_max = ${rmem_wmem}
net.ipv4.tcp_rmem = 4096 87380 ${rmem_wmem}
net.ipv4.tcp_wmem = 4096 65536 ${rmem_wmem}
net.core.somaxconn = ${somaxconn}
net.ipv4.tcp_max_syn_backlog = ${somaxconn}
net.core.netdev_max_backlog = ${somaxconn}
net.ipv4.tcp_fin_timeout = 30
net.ipv4.tcp_tw_reuse = 1
net.ipv4.tcp_slow_start_after_idle = 0
net.ipv4.ip_local_port_range = 10000 65535
net.ipv4.tcp_keepalive_time = 600
net.ipv4.tcp_keepalive_intvl = 15
net.ipv4.tcp_keepalive_probes = 5
net.ipv4.tcp_notsent_lowat = 16384
net.ipv4.tcp_mtu_probing = 1
EOF
            ;;
        *)
            log "${BLUE}配置标准BBR...${NC}"
            cat > "$config_file" << EOF
net.core.default_qdisc = fq
net.ipv4.tcp_congestion_control = bbr
EOF
            ;;
    esac
    sysctl -p "$config_file" >> "$LOG_FILE" 2>&1
    log "${GREEN}✅ BBR配置完成${NC}"
}

# [移除] configure_swap 函数已删除

configure_dns() {
    log "\n${YELLOW}=============== 6. DNS配置 ===============${NC}"
    if (systemctl is-active --quiet cloud-init 2>/dev/null || [[ -d /etc/cloud ]]); then
        log "${YELLOW}[WARN] 云环境检测，DNS可能被覆盖${NC}"
    fi
    if (systemctl is-active --quiet systemd-resolved 2>/dev/null); then
        log "${BLUE}配置systemd-resolved...${NC}"
        mkdir -p /etc/systemd/resolved.conf.d
        cat > /etc/systemd/resolved.conf.d/99-custom-dns.conf << EOF
[Resolve]
DNS=${PRIMARY_DNS_V4} ${SECONDARY_DNS_V4}$(has_ipv6 && echo " ${PRIMARY_DNS_V6} ${SECONDARY_DNS_V6}")
FallbackDNS=1.0.0.1 8.8.4.4
EOF
        systemctl restart systemd-resolved >> "$LOG_FILE" 2>&1 || log "${YELLOW}[WARN] systemd-resolved 重启失败${NC}"
    else
        log "${BLUE}配置resolv.conf...${NC}"
        chattr -i /etc/resolv.conf 2>/dev/null || true
        cat > /etc/resolv.conf << EOF
nameserver ${PRIMARY_DNS_V4}
nameserver ${SECONDARY_DNS_V4}
$(has_ipv6 && echo "nameserver ${PRIMARY_DNS_V6}")
$(has_ipv6 && echo "nameserver ${SECONDARY_DNS_V6}")
EOF
    fi
    log "${GREEN}✅ DNS配置完成${NC}"
}

configure_ssh() {
    log "\n${YELLOW}=============== 7. SSH配置 ===============${NC}"
    [[ -z "$NEW_SSH_PORT" ]] && [[ "$non_interactive" = false ]] && { read -p "SSH端口 (留空跳过): " -r NEW_SSH_PORT < /dev/tty; }
    if [[ -z "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = false ]]; then
        read -s -p "root密码 (输入时不可见, 留空跳过): " NEW_SSH_PASSWORD < /dev/tty
        echo
    fi
    if [[ -n "$NEW_SSH_PASSWORD" ]] && [[ "$non_interactive" = true ]]; then
        log "${RED}[SECURITY WARNING] 使用 --ssh-password 参数会将密码记录在shell历史中，存在安全风险！${NC}"
    fi
    local ssh_changed=false
    if [[ -n "$NEW_SSH_PORT" && "$NEW_SSH_PORT" =~ ^[0-9]+$ && "$NEW_SSH_PORT" -gt 0 && "$NEW_SSH_PORT" -lt 65536 ]]; then
        cp /etc/ssh/sshd_config "/etc/ssh/sshd_config.backup.$(date +%Y%m%d)"
        sed -i '/^[#\s]*Port\s\+/d' /etc/ssh/sshd_config
        echo "Port ${NEW_SSH_PORT}" >> /etc/ssh/sshd_config
        ssh_changed=true
        log "${GREEN}✅ SSH端口设为: ${NEW_SSH_PORT}${NC}"
    fi
    if [[ -n "$NEW_SSH_PASSWORD" ]]; then
        echo "root:${NEW_SSH_PASSWORD}" | chpasswd >> "$LOG_FILE" 2>&1
        log "${GREEN}✅ root密码已设置${NC}"
    fi
    if [[ "$ssh_changed" = true ]]; then
        if sshd -t 2>>"$LOG_FILE"; then
            systemctl restart sshd >> "$LOG_FILE" 2>&1
            log "${YELLOW}[WARN] SSH端口已更改，请用新端口重连！${NC}"
        else
            log "${RED}[ERROR] SSH配置错误，已恢复备份${NC}"
            cp "/etc/ssh/sshd_config.backup.$(date +%Y%m%d)" /etc/ssh/sshd_config
            systemctl restart sshd >> "$LOG_FILE" 2>&1 || true
        fi
    fi
}

# [移除] configure_fail2ban 函数已删除

system_update() {
    log "\n${YELLOW}=============== 8. 系统更新 ===============${NC}"
    start_spinner "系统升级... "
    DEBIAN_FRONTEND=noninteractive apt-get full-upgrade -y -o Dpkg::Options::="--force-confold" >> "$LOG_FILE" 2>&1
    stop_spinner
    start_spinner "清理缓存... "
    apt-get autoremove --purge -y >> "$LOG_FILE" 2>&1
    apt-get clean >> "$LOG_FILE" 2>&1
    stop_spinner
    log "${GREEN}✅ 系统更新完成${NC}"
}

# ==============================================================================
# --- 主函数 ---
# ==============================================================================
main() {
    trap 'handle_error ${LINENO}' ERR
    [[ $EUID -ne 0 ]] && { echo -e "${RED}需要root权限${NC}"; exit 1; }
    
    parse_args "$@"

    {
        echo -e "${CYAN}==================== VPS 定制初始化 ====================${NC}"
        echo -e "主机名: ${NEW_HOSTNAME:-自动/交互}"
        echo -e "时区: ${TIMEZONE}"
        echo -e "软件包: ${INSTALL_PACKAGES}"
        echo -e "BBR: ${BBR_MODE}"
        echo -e "DNS: ${PRIMARY_DNS_V4}, ${SECONDARY_DNS_V4}"
        [[ -n "$NEW_SSH_PORT" ]] && echo -e "SSH端口: ${NEW_SSH_PORT}"
        echo -e "${CYAN}=======================================================${NC}"
    } >&2

    if [[ "$non_interactive" = false ]]; then
        read -p "开始配置? [Y/n] " -r < /dev/tty
        [[ "$REPLY" =~ ^[Nn]$ ]] && exit 0
    fi
    
    LOG_FILE="/var/log/vps-init-$(date +%Y%m%d-%H%M%S).log"
    echo "VPS Init Log - $(date)" > "$LOG_FILE"
    
    log "\n${BLUE}开始执行配置...${NC}"
    SECONDS=0
    
    pre_flight_checks
    install_packages
    configure_hostname
    configure_timezone
    configure_time_sync
    configure_bbr
    # [移除] configure_swap
    configure_dns
    
    if [[ -n "$NEW_SSH_PORT" || -n "$NEW_SSH_PASSWORD" ]]; then
        if ! dpkg -l openssh-server >/dev/null 2>&1; then
            start_spinner "安装openssh-server... "
            DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server >> "$LOG_FILE" 2>&1
            stop_spinner
        fi
    fi
    
    configure_ssh
    # [移除] configure_fail2ban
    system_update
    
    run_verification
    
    log "\n${YELLOW}==================== 完成 ====================${NC}"
    log "${GREEN}🎉 VPS初始化完成！${NC}"
    log "执行时间: ${SECONDS}秒"
    log "日志文件: ${LOG_FILE}"
    
    if [[ -n "$NEW_SSH_PORT" ]]; then
        log "\n${RED}⚠️  SSH端口已改为 ${NEW_SSH_PORT}，请用新端口重连！${NC}"
    fi
    
    if is_container; then
        log "\n${BLUE}容器环境，配置已生效${NC}"
    else
        log "\n${BLUE}建议重启以确保所有配置生效${NC}"
        if [[ "$non_interactive" = false ]]; then
            read -p "立即重启? [Y/n] " -r < /dev/tty
            [[ ! "$REPLY" =~ ^[Nn]$ ]] && { log "${BLUE}重启中...${NC}"; sleep 2; reboot; }
        fi
    fi
    
    [[ $VERIFICATION_FAILED -eq 0 ]] && exit 0 || exit 1
}

main "$@"
