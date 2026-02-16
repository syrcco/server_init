#!/usr/bin/env bash
set -euo pipefail

# =============================================================================
#  VPS 一键初始化脚本（合并 init_my_server.sh + init.sh + firewall.sh）
#
#  用法：
#    bash init_server.sh [--dd] [--user USERNAME] [--help]
#
#  模式：
#    --dd       只运行 DD 重装脚本（bin456789/reinstall）
#    --user     指定新建的普通用户名（默认 syrcco）
#    默认       依次执行：装包 → 调优 → Docker → SSH 加固 → 用户 → 防火墙 → 自动更新
#
#  所有配置项均可通过环境变量覆盖，见下方「配置区」。
# =============================================================================

# ========================= 配置区（环境变量可覆盖） =========================

NEW_USER="${NEW_USER:-syrcco}"
TIMEZONE="${TIMEZONE:-Asia/Shanghai}"

# SSH
SSH_PORTS="${SSH_PORTS:-}"                           # 留空则自动检测 sshd 端口

# DD 重装参数
DD_OS_1="${DD_OS_1:-debian}"
DD_OS_2="${DD_OS_2:-12}"
DD_SSH_PORT="${DD_SSH_PORT:-31415}"
DD_SSH_KEY="${DD_SSH_KEY:-ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGE3rQl0o4KRV3UggBH7VlCmQDS8xT/eRUwBFKOyO/f/}"

# 防火墙
EXTRA_INPUT_TCP_PORTS="${EXTRA_INPUT_TCP_PORTS:-}"   # 额外开放的主机入站 TCP 端口，空格分隔
UFW_RESET="${UFW_RESET:-1}"                          # 1=清空 ufw 规则后重建；0=仅追加

# ========================= 内部变量 =========================

DD_ONLY=0
INIT_ARGS=()

# ========================= 工具函数 =========================

log()  { printf '\033[1;32m[+] %s\033[0m\n' "$*"; }
warn() { printf '\033[1;33m[!] %s\033[0m\n' "$*" >&2; }
die()  { printf '\033[1;31m[×] %s\033[0m\n' "$*" >&2; exit 1; }

need_root() {
  [[ "${EUID:-0}" -eq 0 ]] || die "请用 root 执行（sudo -i 后再跑）。"
}

fetch() {
  local url="$1" out="$2"
  if command -v curl >/dev/null 2>&1; then
    curl -fsSLo "$out" "$url"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "$out" "$url"
  else
    die "需要 curl 或 wget"
  fi
}

has_tty() {
  # 检测是否有可用的交互终端
  [[ -t 0 ]] && return 0
  [[ -e /dev/tty ]] && return 0
  return 1
}

detect_sshd_ports() {
  # 优先使用用户通过环境变量指定的端口
  if [[ -n "${SSH_PORTS}" ]]; then
    echo "${SSH_PORTS}"
    return 0
  fi
  # 自动检测（尝试常见路径，某些系统 sshd 不在 PATH 中）
  local sshd_bin=""
  if command -v sshd >/dev/null 2>&1; then
    sshd_bin="sshd"
  elif [[ -x /usr/sbin/sshd ]]; then
    sshd_bin="/usr/sbin/sshd"
  fi
  if [[ -n "${sshd_bin}" ]]; then
    local ports
    ports="$("${sshd_bin}" -T 2>/dev/null | awk '/^port /{print $2}' | xargs || true)"
    if [[ -n "$ports" ]]; then
      echo "$ports"
      return 0
    fi
  fi
  echo "22"
}

# ========================= 参数解析 =========================

usage() {
  cat <<'EOF'
用法：
  bash init_server.sh [--dd] [--user USERNAME] [--help]

模式：
  --dd        只运行 DD 重装脚本（bin456789/reinstall）
  --user NAME 指定新建的普通用户名（默认 syrcco）
  默认        依次执行：装包 → 调优 → Docker → SSH 加固 → 用户 → 防火墙 → 自动更新

环境变量：
  SSH_PORTS              手动指定 SSH 端口（留空自动检测）
  EXTRA_INPUT_TCP_PORTS  额外开放的主机入站 TCP 端口（空格分隔）
  UFW_RESET              1=清空 ufw 规则后重建（默认）；0=仅追加
  DD_OS_1 / DD_OS_2      DD 重装的目标系统（默认 debian 12）
  DD_SSH_PORT            DD 重装后的 SSH 端口（默认 31415）
  DD_SSH_KEY             DD 重装后注入的 SSH 公钥

注意：使用管道 curl | bash 时，请务必使用 -- 分隔参数。
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --dd)
      DD_ONLY=1
      shift
      ;;
    --user)
      [[ -n "${2:-}" ]] || die "--user 需要一个参数"
      NEW_USER="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      INIT_ARGS+=("$1")
      shift
      ;;
  esac
done

# ========================= DD 重装模式 =========================

run_dd_mode() {
  log "进入 DD 重装模式..."
  local tmp
  tmp="$(mktemp /tmp/reinstall.XXXXXX.sh)"
  fetch "https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh" "$tmp"
  exec bash "$tmp" "${DD_OS_1}" "${DD_OS_2}" \
    --ssh-port "${DD_SSH_PORT}" --ssh-key "${DD_SSH_KEY}"
}

# ========================= 模块函数 =========================

# ---------- 1. 基础工具包 ----------
install_packages() {
  log "安装基础工具包..."
  apt-get update
  apt-get install -y \
    ca-certificates wget curl gnupg \
    git vim tmux bash-completion \
    htop ncdu lsof rsync jq \
    dnsutils mtr \
    zip unzip tree chrony sudo
}

# ---------- 2. 时区 & 时间同步 ----------
configure_time() {
  log "配置时区: ${TIMEZONE}"
  timedatectl set-timezone "${TIMEZONE}"
  systemctl enable --now chrony
  chronyc makestep || true
}

# ---------- 3. 内核调优 ----------
configure_sysctl() {
  log "写入内核调优参数..."

  cat > /etc/sysctl.d/99-vps-tuning.conf <<'EOF'
# --- 文件描述符 ---
fs.file-max                     = 6815744

# --- TCP 连接队列 ---
net.ipv4.tcp_max_syn_backlog    = 8192
net.core.somaxconn              = 8192

# --- TCP 优化 ---
net.ipv4.tcp_tw_reuse           = 1
net.core.default_qdisc          = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_no_metrics_save    = 1
net.ipv4.tcp_ecn                = 0
net.ipv4.tcp_frto               = 0
net.ipv4.tcp_rfc1337            = 1
net.ipv4.tcp_sack               = 1
net.ipv4.tcp_window_scaling     = 1
net.ipv4.tcp_adv_win_scale      = 2
net.ipv4.tcp_moderate_rcvbuf    = 1
net.ipv4.tcp_fin_timeout        = 30
net.ipv4.tcp_timestamps         = 1

# tcp_abort_on_overflow: 队列满时 RST 而非静默丢包
# 高并发突发场景可能导致连接风暴，按需开启（0=关闭 1=开启）
net.ipv4.tcp_abort_on_overflow  = 0

# tcp_mtu_probing: 某些路径存在 PMTUD 黑洞时设为 1 可自动探测
# 0=关闭 1=默认开启 2=仅在检测到黑洞时启用
net.ipv4.tcp_mtu_probing        = 1

# --- TCP 缓冲区 ---
net.ipv4.tcp_rmem               = 4096 87380 67108864
net.ipv4.tcp_wmem               = 4096 65536 67108864
net.core.rmem_max               = 67108864
net.core.wmem_max               = 67108864
net.ipv4.udp_rmem_min           = 8192
net.ipv4.udp_wmem_min           = 8192

# --- 端口范围 ---
net.ipv4.ip_local_port_range    = 1024 65535

# --- 反向路径过滤 ---
# 1=严格模式（单网卡 VPS 推荐），2=松散模式（多网卡/隧道/策略路由时用 2）
net.ipv4.conf.all.rp_filter     = 1
net.ipv4.conf.default.rp_filter = 1

# --- IP 转发（Docker 需要） ---
net.ipv4.ip_forward             = 1
EOF

  # 禁用 IPv6（注意：某些软件依赖 IPv6 回环，如有问题请删除此文件）
  cat > /etc/sysctl.d/98-disable-ipv6.conf <<'EOF'
net.ipv6.conf.all.disable_ipv6     = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6      = 1
EOF

  sysctl --system >/dev/null
  log "内核参数已生效"
}

# ---------- 4. Docker ----------
install_docker() {
  log "配置 Docker daemon..."
  mkdir -p /etc/docker
  cat > /etc/docker/daemon.json <<'EOF'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF

  if command -v docker >/dev/null 2>&1; then
    log "Docker 已安装，跳过安装步骤"
  else
    log "安装 Docker..."
    # 注意：通过管道执行远程脚本存在供应链风险，这是 Docker 官方推荐的安装方式
    curl -fsSL https://get.docker.com | sh
  fi

  systemctl enable --now docker
  docker --version
  # docker compose (plugin) 在某些安装方式下可能不存在，不应阻断脚本
  docker compose version || warn "docker compose plugin 未安装，如需使用请另行安装"
}

# ---------- 5. SSH 加固（仅修改配置，不重启） ----------
harden_ssh() {
  # 安全检查：只有 root 存在有效公钥时才禁用密码登录，防止锁死
  if [[ -s /root/.ssh/authorized_keys ]]; then
    log "SSH 加固：检测到 root 公钥，禁用密码登录"
    # 使用 sshd_config.d 而非 sed 主文件（Debian 12 的 Include 在主文件顶部，first-match-wins）
    # 00- 前缀确保在 sshd_config.d 内优先级最高
    mkdir -p /etc/ssh/sshd_config.d
    cat > /etc/ssh/sshd_config.d/00-hardening.conf <<'EOF'
PasswordAuthentication no
PubkeyAuthentication yes
KbdInteractiveAuthentication no
EOF
  else
    warn "未检测到 /root/.ssh/authorized_keys，跳过禁用密码登录"
    warn "请先配置 SSH 公钥，再手动禁用密码登录："
    warn "  echo 'PasswordAuthentication no' > /etc/ssh/sshd_config.d/00-hardening.conf"
    warn "  systemctl restart ssh"
  fi
}

# ---------- 6. 创建普通用户（幂等） ----------
create_user() {
  log "创建用户: ${NEW_USER}"

  if id "${NEW_USER}" &>/dev/null; then
    log "用户 ${NEW_USER} 已存在，跳过创建"
  else
    useradd -m -s /bin/bash "${NEW_USER}"
    log "用户 ${NEW_USER} 创建成功"
  fi

  # sudo 配置（幂等：覆盖写入）
  mkdir -p /etc/sudoers.d
  chmod 755 /etc/sudoers.d
  cat > "/etc/sudoers.d/${NEW_USER}" <<EOF
${NEW_USER} ALL=(ALL) NOPASSWD:ALL
EOF
  chmod 440 "/etc/sudoers.d/${NEW_USER}"

  # 复制 SSH 公钥
  mkdir -p "/home/${NEW_USER}/.ssh"
  if [[ -f /root/.ssh/authorized_keys ]]; then
    cp /root/.ssh/authorized_keys "/home/${NEW_USER}/.ssh/authorized_keys"
    chmod 600 "/home/${NEW_USER}/.ssh/authorized_keys"
  else
    warn "/root/.ssh/authorized_keys 不存在，请手动为 ${NEW_USER} 配置 SSH 公钥"
  fi
  chmod 700 "/home/${NEW_USER}/.ssh"
  chown -R "${NEW_USER}:${NEW_USER}" "/home/${NEW_USER}/.ssh"
}

# ---------- 7. 交互确认禁用 root 登录 ----------
confirm_disable_root() {
  echo ""
  echo "========================================="
  echo "  重要：请在新终端测试 ${NEW_USER} 登录"
  echo ""
  echo "  测试步骤："
  echo "  1. 打开新终端"
  echo "  2. 用 ${NEW_USER} 用户 SSH 登录"
  echo "  3. 测试 sudo 权限: sudo whoami"
  echo "========================================="
  echo ""

  local hardening_conf="/etc/ssh/sshd_config.d/00-hardening.conf"

  if has_tty; then
    local confirm=""
    read -rp "确认新用户登录成功后，输入 yes 继续禁用 root 登录 [yes/no]: " confirm < /dev/tty || true

    if [[ "${confirm}" == "yes" ]]; then
      # 追加 PermitRootLogin 到 sshd_config.d（如果 harden_ssh 已创建该文件则追加，否则新建）
      mkdir -p /etc/ssh/sshd_config.d
      if [[ -f "${hardening_conf}" ]]; then
        if ! grep -q '^PermitRootLogin' "${hardening_conf}"; then
          echo "PermitRootLogin no" >> "${hardening_conf}"
        fi
      else
        echo "PermitRootLogin no" > "${hardening_conf}"
      fi
      log "Root SSH 登录已配置为禁用（重启 SSH 后生效）"
    else
      warn "Root SSH 登录未禁用！"
      warn "建议测试成功后手动执行："
      warn "  echo 'PermitRootLogin no' >> ${hardening_conf}"
      warn "  systemctl restart ssh"
    fi
  else
    warn "未检测到交互终端（TTY），跳过禁用 root 登录的交互确认"
    warn "请稍后手动验证 ${NEW_USER} 可登录后，执行："
    warn "  echo 'PermitRootLogin no' >> ${hardening_conf}"
    warn "  systemctl restart ssh"
  fi
}

# ---------- 8. 统一重启 SSH（只调用一次） ----------
restart_ssh() {
  log "重启 SSH 服务..."
  systemctl restart ssh
}

# ---------- 9. 防火墙（UFW） ----------
setup_firewall() {
  log "安装 UFW..."
  apt-get install -y ufw

  local ssh_ports
  ssh_ports="$(detect_sshd_ports)"
  log "SSH 端口: ${ssh_ports}"

  local input_ports="80 443 ${ssh_ports} ${EXTRA_INPUT_TCP_PORTS}"

  # 禁用 → 重置（可选）→ 配置 → 启用
  log "禁用 ufw（应用新规则前）"
  ufw --force disable || true

  if [[ "${UFW_RESET}" == "1" ]]; then
    log "重置 ufw 规则"
    ufw --force reset
  fi

  log "默认策略：拒绝入站 / 允许出站"
  ufw default deny incoming
  ufw default allow outgoing

  log "放行主机入站 TCP 端口: ${input_ports}"
  for p in ${input_ports}; do
    [[ -n "$p" ]] || continue
    if [[ " ${ssh_ports} " == *" ${p} "* ]]; then
      ufw limit "${p}/tcp" comment "limit ssh tcp ${p}" >/dev/null
    else
      ufw allow "${p}/tcp" comment "allow tcp ${p}" >/dev/null
    fi
  done

  # Docker 需要 FORWARD 策略为 ACCEPT
  log "设置转发策略: ACCEPT（Docker 需要）"
  sed -i 's/^DEFAULT_FORWARD_POLICY=.*/DEFAULT_FORWARD_POLICY="ACCEPT"/' /etc/default/ufw

  log "启用 ufw"
  ufw --force enable >/dev/null

  # DOCKER-USER 策略说明：
  # Docker 发布端口（-p / ports）会直接操作 iptables nat/filter 链，绕过 UFW 的 INPUT 规则。
  # 因此 ufw allow/deny 无法控制 Docker 已发布的端口。
  # 本脚本不注入 DOCKER-USER 限制规则，Docker 端口暴露由 docker-compose ports 自行控制：
  #   - 需要公网暴露：ports: "8080:80"
  #   - 仅本机访问：  ports: "127.0.0.1:8080:80"
  #   - 不暴露：      不写 ports（仅容器网络内部可达）
  log "DOCKER-USER 策略: 透传（不注入限制规则）"
  log "注意: UFW 无法拦截 Docker 已发布的端口，请通过 docker-compose ports 绑定地址控制暴露范围"

  # 如果 Docker 已安装，重启以确保 iptables 链状态正确
  if command -v systemctl >/dev/null 2>&1; then
    if systemctl list-unit-files 2>/dev/null | grep -q '^docker\.service'; then
      log "重启 Docker（确保 iptables 链状态一致）"
      systemctl restart docker || warn "Docker 重启失败，请自行确认"
    fi
  fi

  ufw status verbose || true
}

# ---------- 10. 自动安全更新 ----------
setup_auto_update() {
  log "配置自动安全更新（unattended-upgrades）..."
  export DEBIAN_FRONTEND=noninteractive

  apt-get install -y unattended-upgrades

  cat > /etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

  cat > /etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,suite=stable-security,label=Debian-Security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF

  systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

  # dry-run 测试，失败不阻断脚本
  unattended-upgrade --dry-run --debug || true
}

# ---------- 11. 最终状态汇总 ----------
final_check() {
  echo ""
  echo "========================================="
  log "初始化完成！状态汇总："
  echo "========================================="
  echo ""

  echo "--- 内核参数 ---"
  sysctl net.ipv4.ip_forward \
         net.ipv4.tcp_congestion_control \
         net.core.default_qdisc \
         2>/dev/null || true

  echo ""
  echo "--- 时间 ---"
  timedatectl 2>/dev/null | grep -E "Time zone|Local time" || true

  echo ""
  echo "--- Docker ---"
  docker --version 2>/dev/null || warn "Docker 未安装"
  docker compose version 2>/dev/null || true

  echo ""
  echo "--- UFW ---"
  ufw status numbered 2>/dev/null || true

  echo ""
  echo "--- 用户 ---"
  echo "普通用户: ${NEW_USER}"
  echo "sudo 权限: $(sudo -l -U "${NEW_USER}" 2>/dev/null | tail -1 || echo '未知')"

  echo ""
  echo "========================================="
  log "关键提示："
  echo "  - UFW 管主机自身的入站端口: ufw allow <port>/tcp"
  echo "  - UFW 无法拦截 Docker 已发布的端口"
  echo "  - Docker 端口暴露由 docker-compose ports 控制："
  echo "    公网暴露: ports: \"8080:80\""
  echo "    仅本机:   ports: \"127.0.0.1:8080:80\""
  echo "========================================="
}

# ========================= 主入口 =========================

main() {
  need_root

  # DD 模式：互斥执行，exec 替换进程
  if [[ "${DD_ONLY}" -eq 1 ]]; then
    run_dd_mode
    # exec 不会返回，以下不会执行
  fi

  log "进入标准初始化模式..."
  echo ""

  install_packages
  configure_time
  configure_sysctl
  install_docker
  harden_ssh
  create_user
  confirm_disable_root
  restart_ssh
  setup_firewall
  setup_auto_update
  final_check
}

main
