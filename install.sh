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
        if [[ "$NEW_HOSTNAME" =~ ^[a-zA-Z0-9]([a-zA-Z
