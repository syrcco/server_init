( curl -fsSLo reinstall.sh https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh || wget -O reinstall.sh https://raw.githubusercontent.com/bin456789/reinstall/main/reinstall.sh ) && bash reinstall.sh debian 12 --ssh-port 31415 --ssh-key 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIGE3rQl0o4KRV3UggBH7VlCmQDS8xT/eRUwBFKOyO/f/'

NEW_USER="syrcco"

# 解析命令行参数
while [[ $# -gt 0 ]]; do
    case $1 in
        --user)
            NEW_USER="$2"
            shift 2
            ;;
        -h|--help)
            echo "用法: bash script.sh [--user username]"
            echo "示例: bash script.sh --user myuser"
            exit 0
            ;;
        *)
            echo "未知参数: $1"
            echo "用法: bash script.sh [--user username]"
            exit 1
            ;;
    esac
done


set -e

apt update && apt install -y \
	ca-certificates wget curl gnupg \
	git vim tmux bash-completion \
	htop ncdu lsof rsync jq \
	dnsutils mtr \
	zip unzip tree chrony
	
timedatectl set-timezone Asia/Shanghai 
systemctl enable --now chrony 
chronyc makestep


cat > /etc/sysctl.d/99-vps-tuning.conf <<'EOF'
fs.file-max                     = 6815744
net.ipv4.tcp_max_syn_backlog    = 8192
net.core.somaxconn              = 8192
net.ipv4.tcp_tw_reuse           = 1
net.ipv4.tcp_abort_on_overflow  = 1
net.core.default_qdisc          = fq
net.ipv4.tcp_congestion_control = bbr
net.ipv4.tcp_no_metrics_save    = 1
net.ipv4.tcp_ecn                = 0
net.ipv4.tcp_frto               = 0
net.ipv4.tcp_mtu_probing         = 0
net.ipv4.tcp_rfc1337            = 1
net.ipv4.tcp_sack               = 1
net.ipv4.tcp_fack               = 1
net.ipv4.tcp_window_scaling     = 1
net.ipv4.tcp_adv_win_scale      = 2
net.ipv4.tcp_moderate_rcvbuf    = 1
net.ipv4.tcp_fin_timeout        = 30
net.ipv4.tcp_rmem               = 4096 87380 67108864
net.ipv4.tcp_wmem               = 4096 65536 67108864
net.core.rmem_max               = 67108864
net.core.wmem_max               = 67108864
net.ipv4.udp_rmem_min           = 8192
net.ipv4.udp_wmem_min           = 8192
net.ipv4.ip_local_port_range    = 1024 65535
net.ipv4.tcp_timestamps         = 1
net.ipv4.conf.all.rp_filter     = 0
net.ipv4.conf.default.rp_filter = 0
net.ipv4.ip_forward             = 1
EOF

cat > /etc/sysctl.d/98-disable-ipv6.conf <<EOF
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
net.ipv6.conf.lo.disable_ipv6 = 1
EOF

systemctl restart systemd-sysctl.service



mkdir -p /etc/docker
cat > /etc/docker/daemon.json <<EOF
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "3"
  }
}
EOF

curl -fsSL https://get.docker.com | sh
systemctl enable --now docker

docker --version
docker compose version

sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication no/g' /etc/ssh/sshd_config

# === 创建普通用户 ===
apt-get install -y sudo
mkdir -p /etc/sudoers.d
chmod 755 /etc/sudoers.d

useradd -m -s /bin/bash "$NEW_USER"

cat > /etc/sudoers.d/"$NEW_USER" <<EOF
$NEW_USER ALL=(ALL) NOPASSWD:ALL
EOF
chmod 440 /etc/sudoers.d/"$NEW_USER"

mkdir -p /home/"$NEW_USER"/.ssh
cp /root/.ssh/authorized_keys /home/"$NEW_USER"/.ssh/authorized_keys
chmod 700 /home/"$NEW_USER"/.ssh
chmod 600 /home/"$NEW_USER"/.ssh/authorized_keys
chown -R "$NEW_USER":"$NEW_USER" /home/"$NEW_USER"/.ssh

echo "========================================="
echo "⚠️  重要：请在新终端测试 $NEW_USER@$ 登录"

echo "测试步骤："
echo "1. 打开新终端"
echo "3. 测试 sudo 权限: sudo whoami"
echo ""
read -p "确认新用户登录成功后，输入 yes 继续禁用 root 登录 [yes/no]: " confirm

if [[ "$confirm" == "yes" ]]; then
    sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config
    systemctl restart ssh
    echo ""
    echo "✅ Root SSH 登录已禁用"
    echo "========================================="
    echo "配置完成！请使用 $NEW_USER 用户登录"
    echo "========================================="
else
    echo ""
    echo "⚠️  警告：Root SSH 登录未禁用！"
    echo "========================================="
    echo "出于安全考虑，建议测试成功后手动执行："
    echo "sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin no/g' /etc/ssh/sshd_config"
    echo "systemctl restart ssh"
    echo "========================================="
fi


systemctl restart ssh

# ===== 自动安全更新（Debian 12 / bookworm）=====
export DEBIAN_FRONTEND=noninteractive

apt-get update
apt-get install -y unattended-upgrades

# 1) APT 周期任务：只更新列表 + 运行 unattended-upgrades（不预下载全部可升级包）
cat >/etc/apt/apt.conf.d/20auto-upgrades <<'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Unattended-Upgrade "1";
APT::Periodic::AutocleanInterval "7";
EOF

# 2) unattended-upgrades：只允许安全更新；禁用自动重启
cat >/etc/apt/apt.conf.d/50unattended-upgrades <<'EOF'
Unattended-Upgrade::Origins-Pattern {
        // 兼容两种常见写法：bookworm-security / stable-security
        "origin=Debian,codename=${distro_codename}-security,label=Debian-Security";
        "origin=Debian,suite=stable-security,label=Debian-Security";
};

Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Remove-New-Unused-Dependencies "true";

Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Automatic-Reboot-WithUsers "false";
EOF

# 3) 启用定时器（Debian 12 通常默认已启用；这里做兜底）
systemctl enable --now apt-daily.timer apt-daily-upgrade.timer

# 4) dry-run 测试：建议不要让“测试”把整套初始化脚本打断
unattended-upgrade --dry-run --debug || true

sysctl --system
timedatectl
docker --version
docker compose version
