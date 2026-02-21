#!/usr/bin/env bash
# =============================================================================
# aichan-setup.sh — 爱衣运维用户初始化脚本
# =============================================================================

set -euo pipefail

# ── 配置 ──────────────────────────────────────────────────────────────────────
AICHAN_USER="aichan"
AICHAN_PUBKEY="ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAuENAZICEyge+7bdaTkHy323S3InBOe1eQpo3ifZjNg aichan@openclaw"
SUDOERS_FILE="/etc/sudoers.d/aichan"
DEFAULT_LEVEL="L1"
WRAPPER_DIR="/srv/aichan/bin"

# ── 颜色输出 ──────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; BLUE='\033[0;34m'; NC='\033[0m'
info()    { echo -e "${BLUE}[INFO]${NC} $*"; }
success() { echo -e "${GREEN}[OK]${NC} $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC} $*"; }
error()   { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ── 参数解析 ──────────────────────────────────────────────────────────────────
LEVEL="$DEFAULT_LEVEL"
REMOVE=false
FORCE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --level|-l)
            # 问题4修复：检查第二个参数存在
            if [[ $# -lt 2 ]]; then
                error "--level 需要指定权限级别参数（L1/L2/L3/L4）"
            fi
            LEVEL="${2^^}"  # 转大写
            shift 2
            ;;
        --remove|-r)
            REMOVE=true
            shift
            ;;
        --force|-f)
            FORCE=true
            shift
            ;;
        --help|-h)
            cat <<'HELPEOF'
用法：
  bash aichan-setup.sh              # 默认 L1 权限
  bash aichan-setup.sh --level L2   # 指定权限级别
  bash aichan-setup.sh --level L3   # 再次运行可升降级
  bash aichan-setup.sh --remove --force  # 删除 aichan 用户（需要 --force）

权限级别：
  L1 — 只读：SSH 登录，读文件，查进程/日志，无 sudo
  L2 — 读写：L1 + sudo 写文件(aichan-sync/aichan-write) + docker 只读
  L3 — 服务管理：L2 + sudo docker 管理 + sudo aichan-systemctl + 可删除文件(aichan-rm)
  L4 — root 等效：sudo ALL NOPASSWD（需主人明确指定）

在目标服务器以 root 运行：
  curl -sL https://raw.githubusercontent.com/你的仓库/aichan-setup.sh | bash -s -- --level L2
HELPEOF
            exit 0
            ;;
        *)
            error "未知参数: $1，使用 --help 查看用法"
            ;;
    esac
done

# ── 检查 root ─────────────────────────────────────────────────────────────────
[[ $EUID -eq 0 ]] || error "请以 root 身份运行此脚本"

# ── 删除用户 ──────────────────────────────────────────────────────────────────
if $REMOVE; then
    if ! $FORCE; then
        warn "⚠️  危险操作：即将删除用户 $AICHAN_USER 及其所有数据！"
        warn "如果确认要删除，请使用 --force 标志重新运行："
        warn "  bash aichan-setup.sh --remove --force"
        exit 1
    fi
    warn "正在删除用户 $AICHAN_USER ..."
    /usr/sbin/userdel -r "$AICHAN_USER" 2>/dev/null || true
    rm -f "$SUDOERS_FILE"
    success "用户 $AICHAN_USER 已删除"
    exit 0
fi

# ── 验证权限级别 ───────────────────────────────────────────────────────────────
[[ "$LEVEL" =~ ^L[1-4]$ ]] || error "无效的权限级别: $LEVEL（有效值：L1 L2 L3 L4）"

# ── 创建或更新用户 ────────────────────────────────────────────────────────────
if id "$AICHAN_USER" &>/dev/null; then
    info "用户 $AICHAN_USER 已存在，更新配置..."
else
    info "创建用户 $AICHAN_USER ..."
    /usr/sbin/useradd -m -s /bin/bash -c "Ai-chan operator" "$AICHAN_USER"
    /usr/bin/passwd -l "$AICHAN_USER"  # 锁定密码，只允许密钥登录
    success "用户 $AICHAN_USER 创建完成"
fi

# ── 注入公钥（幂等追加） ───────────────────────────────────────────────────────
info "配置 SSH 公钥..."
AICHAN_HOME=$(getent passwd "$AICHAN_USER" | cut -d: -f6)
mkdir -p "$AICHAN_HOME/.ssh"
if grep -qF "$AICHAN_PUBKEY" "$AICHAN_HOME/.ssh/authorized_keys" 2>/dev/null; then
    info "公钥已存在，跳过追加"
else
    echo "$AICHAN_PUBKEY" >> "$AICHAN_HOME/.ssh/authorized_keys"
    success "公钥已追加"
fi
chmod 700 "$AICHAN_HOME/.ssh"
chmod 600 "$AICHAN_HOME/.ssh/authorized_keys"
chown -R "$AICHAN_USER:$AICHAN_USER" "$AICHAN_HOME/.ssh"

# ── 部署包装脚本 ──────────────────────────────────────────────────────────────
info "部署包装脚本到 $WRAPPER_DIR ..."
mkdir -p "$WRAPPER_DIR"

# aichan-sync — rsync 白名单
cat > "$WRAPPER_DIR/aichan-sync" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-sync — rsync 白名单包装脚本
# 用法：sudo aichan-sync <rsync参数...> <src> <dest>
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 2 ]]; then
    echo "用法：sudo aichan-sync <rsync参数...> <src> <dest>" >&2
    exit 1
fi

DEST="${@: -1}"  # 最后一个参数为目标路径
# 规范化路径
DEST_REAL=$(realpath -m "$DEST" 2>/dev/null || echo "$DEST")

allowed=false
for prefix in "${ALLOWED_PREFIXES[@]}"; do
    if [[ "$DEST_REAL" == "$prefix"* || "$DEST_REAL" == "${prefix%/}" ]]; then
        allowed=true
        break
    fi
done

if ! $allowed; then
    echo "[aichan-sync] 拒绝：目标路径不在白名单内: $DEST" >&2
    echo "[aichan-sync] 允许的目标前缀：${ALLOWED_PREFIXES[*]}" >&2
    exit 1
fi

exec /usr/bin/rsync "$@"
WRAPPER_EOF

# aichan-write — tee 白名单
cat > "$WRAPPER_DIR/aichan-write" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-write — tee 白名单包装脚本
# 用法：echo "内容" | sudo aichan-write /path/to/file
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 1 ]]; then
    echo "用法：echo '内容' | sudo aichan-write /path/to/file" >&2
    exit 1
fi

TARGET="$1"
# 规范化路径（目录可能还不存在，使用父目录判断）
TARGET_REAL=$(realpath -m "$TARGET" 2>/dev/null || echo "$TARGET")

allowed=false
for prefix in "${ALLOWED_PREFIXES[@]}"; do
    if [[ "$TARGET_REAL" == "$prefix"* || "$TARGET_REAL" == "${prefix%/}" ]]; then
        allowed=true
        break
    fi
done

if ! $allowed; then
    echo "[aichan-write] 拒绝：目标路径不在白名单内: $TARGET" >&2
    echo "[aichan-write] 允许的目标前缀：${ALLOWED_PREFIXES[*]}" >&2
    exit 1
fi

exec /usr/bin/tee "$TARGET"
WRAPPER_EOF

# 问题1修复：新增 aichan-cp 包装脚本（白名单限制目标路径）
cat > "$WRAPPER_DIR/aichan-cp" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-cp — cp 白名单包装脚本
# 用法：sudo aichan-cp [选项] <src> <dest>
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 2 ]]; then
    echo "用法：sudo aichan-cp [选项] <src> <dest>" >&2
    exit 1
fi

DEST="${@: -1}"  # 最后一个参数为目标路径
DEST_REAL=$(realpath -m "$DEST" 2>/dev/null || echo "$DEST")

allowed=false
for prefix in "${ALLOWED_PREFIXES[@]}"; do
    if [[ "$DEST_REAL" == "$prefix"* || "$DEST_REAL" == "${prefix%/}" ]]; then
        allowed=true
        break
    fi
done

if ! $allowed; then
    echo "[aichan-cp] 拒绝：目标路径不在白名单内: $DEST" >&2
    echo "[aichan-cp] 允许的目标前缀：${ALLOWED_PREFIXES[*]}" >&2
    exit 1
fi

exec /bin/cp "$@"
WRAPPER_EOF

# 问题1修复：新增 aichan-mkdir 包装脚本（白名单限制路径）
cat > "$WRAPPER_DIR/aichan-mkdir" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-mkdir — mkdir 白名单包装脚本
# 用法：sudo aichan-mkdir [选项] <dir...>
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 1 ]]; then
    echo "用法：sudo aichan-mkdir [选项] <dir...>" >&2
    exit 1
fi

# 检查所有非选项参数（即路径）
for arg in "$@"; do
    [[ "$arg" == -* ]] && continue
    TARGET_REAL=$(realpath -m "$arg" 2>/dev/null || echo "$arg")
    allowed=false
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        if [[ "$TARGET_REAL" == "$prefix"* || "$TARGET_REAL" == "${prefix%/}" ]]; then
            allowed=true
            break
        fi
    done
    if ! $allowed; then
        echo "[aichan-mkdir] 拒绝：路径不在白名单内: $arg" >&2
        echo "[aichan-mkdir] 允许的前缀：${ALLOWED_PREFIXES[*]}" >&2
        exit 1
    fi
done

exec /bin/mkdir "$@"
WRAPPER_EOF

# 问题1修复：新增 aichan-chmod 包装脚本（白名单限制路径）
cat > "$WRAPPER_DIR/aichan-chmod" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-chmod — chmod 白名单包装脚本
# 用法：sudo aichan-chmod <mode> <file...>
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 2 ]]; then
    echo "用法：sudo aichan-chmod <mode> <file...>" >&2
    exit 1
fi

# 第一个非选项参数是 mode，其余是路径
found_mode=false
for arg in "$@"; do
    if [[ "$arg" == -* ]]; then continue; fi
    if ! $found_mode; then
        found_mode=true
        continue  # 跳过 mode 参数
    fi
    TARGET_REAL=$(realpath -m "$arg" 2>/dev/null || echo "$arg")
    allowed=false
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        if [[ "$TARGET_REAL" == "$prefix"* || "$TARGET_REAL" == "${prefix%/}" ]]; then
            allowed=true
            break
        fi
    done
    if ! $allowed; then
        echo "[aichan-chmod] 拒绝：路径不在白名单内: $arg" >&2
        echo "[aichan-chmod] 允许的前缀：${ALLOWED_PREFIXES[*]}" >&2
        exit 1
    fi
done

exec /bin/chmod "$@"
WRAPPER_EOF

# 问题1修复：新增 aichan-chown 包装脚本（白名单限制路径）
cat > "$WRAPPER_DIR/aichan-chown" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-chown — chown 白名单包装脚本
# 用法：sudo aichan-chown <owner>[:<group>] <file...>
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 2 ]]; then
    echo "用法：sudo aichan-chown <owner>[:<group>] <file...>" >&2
    exit 1
fi

# 第一个非选项参数是 owner:group，其余是路径
found_owner=false
for arg in "$@"; do
    if [[ "$arg" == -* ]]; then continue; fi
    if ! $found_owner; then
        found_owner=true
        continue  # 跳过 owner 参数
    fi
    TARGET_REAL=$(realpath -m "$arg" 2>/dev/null || echo "$arg")
    allowed=false
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        if [[ "$TARGET_REAL" == "$prefix"* || "$TARGET_REAL" == "${prefix%/}" ]]; then
            allowed=true
            break
        fi
    done
    if ! $allowed; then
        echo "[aichan-chown] 拒绝：路径不在白名单内: $arg" >&2
        echo "[aichan-chown] 允许的前缀：${ALLOWED_PREFIXES[*]}" >&2
        exit 1
    fi
done

exec /bin/chown "$@"
WRAPPER_EOF

# 问题1修复：新增 aichan-mv 包装脚本（白名单限制源和目标路径，L3 用）
cat > "$WRAPPER_DIR/aichan-mv" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-mv — mv 白名单包装脚本（L3）
# 用法：sudo aichan-mv [选项] <src> <dest>
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 2 ]]; then
    echo "用法：sudo aichan-mv [选项] <src> <dest>" >&2
    exit 1
fi

# 检查所有非选项参数（源和目标都需在白名单内）
for arg in "$@"; do
    [[ "$arg" == -* ]] && continue
    TARGET_REAL=$(realpath -m "$arg" 2>/dev/null || echo "$arg")
    allowed=false
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        if [[ "$TARGET_REAL" == "$prefix"* || "$TARGET_REAL" == "${prefix%/}" ]]; then
            allowed=true
            break
        fi
    done
    if ! $allowed; then
        echo "[aichan-mv] 拒绝：路径不在白名单内: $arg" >&2
        echo "[aichan-mv] 允许的前缀：${ALLOWED_PREFIXES[*]}" >&2
        exit 1
    fi
done

exec /bin/mv "$@"
WRAPPER_EOF

# 问题3修复：aichan-rm — 去掉 BLOCKED_PREFIXES，只保留白名单 + 根目录防护
cat > "$WRAPPER_DIR/aichan-rm" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-rm — rm 白名单包装脚本（仅 L3）
# 用法：sudo aichan-rm [选项] /path/to/file
# 安全策略：只允许操作白名单路径；根目录单独防护防止误传 /
set -euo pipefail

ALLOWED_PREFIXES=("/opt/" "/srv/" "/root/" "/home/")

if [[ $# -lt 1 ]]; then
    echo "用法：sudo aichan-rm [选项] /path/to/file" >&2
    exit 1
fi

# 提取所有非选项参数作为路径列表
PATHS=()
for arg in "$@"; do
    if [[ "$arg" != -* ]]; then
        PATHS+=("$arg")
    fi
done

if [[ ${#PATHS[@]} -eq 0 ]]; then
    echo "[aichan-rm] 错误：未指定目标路径" >&2
    exit 1
fi

for target in "${PATHS[@]}"; do
    target_real=$(realpath -m "$target" 2>/dev/null || echo "$target")

    # 防止操作根目录
    if [[ "$target_real" == "/" ]]; then
        echo "[aichan-rm] 拒绝：禁止操作根目录" >&2
        exit 1
    fi

    # 验证在白名单内
    allowed=false
    for prefix in "${ALLOWED_PREFIXES[@]}"; do
        if [[ "$target_real" == "$prefix"* ]]; then
            allowed=true
            break
        fi
    done

    if ! $allowed; then
        echo "[aichan-rm] 拒绝：目标路径不在白名单内: $target" >&2
        echo "[aichan-rm] 允许的目标前缀：${ALLOWED_PREFIXES[*]}" >&2
        exit 1
    fi
done

exec /bin/rm "$@"
WRAPPER_EOF

# 问题2修复：aichan-systemctl — 删除 READONLY_VERBS，注释说明实际逻辑
cat > "$WRAPPER_DIR/aichan-systemctl" <<'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-systemctl — systemctl 黑名单包装脚本
# 用法：sudo aichan-systemctl <systemctl参数...>
#
# 安全策略：只拦截"破坏性操作 + 关键服务"的组合，其余操作全部放行。
# 关键服务列表保护 SSH/网络不被意外停用。
set -euo pipefail

# 禁止 stop/disable 的关键系统服务
BLACKLISTED_SERVICES=("ssh" "sshd" "networking" "network-manager" "systemd-networkd" "systemd-resolved" "dbus")

# 破坏性操作（针对黑名单服务禁止，其余服务放行）
DESTRUCTIVE_VERBS=("stop" "disable" "kill" "mask" "halt" "poweroff" "reboot")

if [[ $# -lt 1 ]]; then
    echo "用法：sudo aichan-systemctl <systemctl参数...>" >&2
    exit 1
fi

# 提取 verb（跳过以 - 开头的选项）
VERB=""
for arg in "$@"; do
    if [[ "$arg" != -* ]]; then
        VERB="$arg"
        break
    fi
done

# 检查是否为破坏性操作
is_destructive=false
for v in "${DESTRUCTIVE_VERBS[@]}"; do
    if [[ "$VERB" == "$v" ]]; then
        is_destructive=true
        break
    fi
done

if $is_destructive; then
    # 提取目标服务名（第一个非选项、非verb参数）
    found_verb=false
    for arg in "$@"; do
        if [[ "$arg" == -* ]]; then
            continue
        fi
        if ! $found_verb; then
            found_verb=true
            continue  # 跳过 verb 本身
        fi
        # 这是服务名
        SERVICE="$arg"
        # 去除 .service 后缀进行比较
        SERVICE_BASE="${SERVICE%.service}"
        for blocked in "${BLACKLISTED_SERVICES[@]}"; do
            if [[ "$SERVICE_BASE" == "$blocked" ]]; then
                echo "[aichan-systemctl] 拒绝：禁止对关键系统服务执行 $VERB 操作: $SERVICE" >&2
                echo "[aichan-systemctl] 受保护的服务：${BLACKLISTED_SERVICES[*]}" >&2
                exit 1
            fi
        done
        break
    done
fi

exec /bin/systemctl "$@"
WRAPPER_EOF

# aichan-ufw — ufw 白名单包装脚本（仅允许安全子命令）
cat > "$WRAPPER_DIR/aichan-ufw" << 'WRAPPER_EOF'
#!/usr/bin/env bash
# aichan-ufw — ufw 安全包装脚本
# 允许：status/allow/limit/delete/reload/enable
# 禁止：reset/default（防止破坏基础策略）
set -euo pipefail

ALLOWED_CMDS=("status" "allow" "limit" "delete" "reload" "enable" "disable" "show")
BLOCKED_CMDS=("reset" "default")

if [[ $# -lt 1 ]]; then
    echo "用法：sudo aichan-ufw <ufw参数...>" >&2
    exit 1
fi

# 提取第一个非选项参数作为子命令
CMD=""
for arg in "$@"; do
    if [[ "$arg" != -* ]]; then
        CMD="$arg"
        break
    fi
done

# 检查是否为禁止命令
for blocked in "${BLOCKED_CMDS[@]}"; do
    if [[ "$CMD" == "$blocked" ]]; then
        echo "[aichan-ufw] 拒绝：禁止执行 ufw $CMD（危险操作，请联系主人）" >&2
        exit 1
    fi
done

# 检查是否在允许列表
allowed=false
for ok in "${ALLOWED_CMDS[@]}"; do
    if [[ "$CMD" == "$ok" ]]; then
        allowed=true
        break
    fi
done

if ! $allowed; then
    echo "[aichan-ufw] 拒绝：不支持的子命令: $CMD" >&2
    echo "[aichan-ufw] 允许的子命令：${ALLOWED_CMDS[*]}" >&2
    exit 1
fi

exec /usr/sbin/ufw "$@"
WRAPPER_EOF

chmod +x "$WRAPPER_DIR/aichan-sync" \
         "$WRAPPER_DIR/aichan-write" \
         "$WRAPPER_DIR/aichan-cp" \
         "$WRAPPER_DIR/aichan-mkdir" \
         "$WRAPPER_DIR/aichan-chmod" \
         "$WRAPPER_DIR/aichan-chown" \
         "$WRAPPER_DIR/aichan-mv" \
         "$WRAPPER_DIR/aichan-rm" \
         "$WRAPPER_DIR/aichan-systemctl" \
         "$WRAPPER_DIR/aichan-ufw"

success "包装脚本部署完成"

# ── 配置 sudoers ──────────────────────────────────────────────────────────────
info "配置权限级别 $LEVEL ..."
rm -f "$SUDOERS_FILE"

case "$LEVEL" in
    L1)
        # 只读，无 sudo
        info "L1：只读模式，无 sudo 权限"
        ;;

    L2)
        # 读写：文件操作（通过包装脚本）+ docker 只读
        cat > "$SUDOERS_FILE" <<EOF
# aichan L2 - 读写权限
Defaults:aichan !requiretty, !use_pty

# 文件操作（通过白名单包装脚本）
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-sync
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-sync *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-write
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-write *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-cp
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-cp *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-mkdir
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-mkdir *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chmod
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chmod *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chown
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chown *

# Docker 只读
aichan ALL=(root) NOPASSWD: /usr/bin/docker ps
aichan ALL=(root) NOPASSWD: /usr/bin/docker ps *
aichan ALL=(root) NOPASSWD: /usr/bin/docker logs
aichan ALL=(root) NOPASSWD: /usr/bin/docker logs *
aichan ALL=(root) NOPASSWD: /usr/bin/docker inspect
aichan ALL=(root) NOPASSWD: /usr/bin/docker inspect *
aichan ALL=(root) NOPASSWD: /usr/bin/docker stats
aichan ALL=(root) NOPASSWD: /usr/bin/docker stats *
aichan ALL=(root) NOPASSWD: /usr/bin/docker images
aichan ALL=(root) NOPASSWD: /usr/bin/docker images *
EOF
        ;;

    L3)
        # 服务管理：L2 + docker 管理 + aichan-systemctl + aichan-rm + apt
        cat > "$SUDOERS_FILE" <<EOF
# aichan L3 - 服务管理权限
Defaults:aichan !requiretty, !use_pty

# 文件操作（通过白名单包装脚本）
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-sync
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-sync *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-write
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-write *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-cp
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-cp *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-mkdir
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-mkdir *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chmod
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chmod *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chown
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-chown *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-mv
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-mv *
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-rm
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-rm *

# Docker 完整管理
aichan ALL=(root) NOPASSWD: /usr/bin/docker ps
aichan ALL=(root) NOPASSWD: /usr/bin/docker ps *
aichan ALL=(root) NOPASSWD: /usr/bin/docker logs
aichan ALL=(root) NOPASSWD: /usr/bin/docker logs *
aichan ALL=(root) NOPASSWD: /usr/bin/docker inspect
aichan ALL=(root) NOPASSWD: /usr/bin/docker inspect *
aichan ALL=(root) NOPASSWD: /usr/bin/docker stats
aichan ALL=(root) NOPASSWD: /usr/bin/docker stats *
aichan ALL=(root) NOPASSWD: /usr/bin/docker images
aichan ALL=(root) NOPASSWD: /usr/bin/docker images *
aichan ALL=(root) NOPASSWD: /usr/bin/docker start
aichan ALL=(root) NOPASSWD: /usr/bin/docker start *
aichan ALL=(root) NOPASSWD: /usr/bin/docker stop
aichan ALL=(root) NOPASSWD: /usr/bin/docker stop *
aichan ALL=(root) NOPASSWD: /usr/bin/docker restart
aichan ALL=(root) NOPASSWD: /usr/bin/docker restart *
aichan ALL=(root) NOPASSWD: /usr/bin/docker pull
aichan ALL=(root) NOPASSWD: /usr/bin/docker pull *
aichan ALL=(root) NOPASSWD: /usr/bin/docker exec
aichan ALL=(root) NOPASSWD: /usr/bin/docker exec *
aichan ALL=(root) NOPASSWD: /usr/local/bin/docker-compose
aichan ALL=(root) NOPASSWD: /usr/local/bin/docker-compose *
aichan ALL=(root) NOPASSWD: /usr/bin/docker compose
aichan ALL=(root) NOPASSWD: /usr/bin/docker compose *

# systemctl 服务管理（通过黑名单包装脚本）
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-systemctl
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-systemctl *

# ufw 防火墙管理（通过白名单包装脚本，禁止 reset/default）
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-ufw
aichan ALL=(root) NOPASSWD: $WRAPPER_DIR/aichan-ufw *

# 软件包管理
aichan ALL=(root) NOPASSWD: /usr/bin/apt install
aichan ALL=(root) NOPASSWD: /usr/bin/apt install *
aichan ALL=(root) NOPASSWD: /usr/bin/apt remove
aichan ALL=(root) NOPASSWD: /usr/bin/apt remove *
aichan ALL=(root) NOPASSWD: /usr/bin/apt update
aichan ALL=(root) NOPASSWD: /usr/bin/apt update *
aichan ALL=(root) NOPASSWD: /usr/bin/apt list
aichan ALL=(root) NOPASSWD: /usr/bin/apt list *
aichan ALL=(root) NOPASSWD: /usr/bin/apt show
aichan ALL=(root) NOPASSWD: /usr/bin/apt show *
EOF
        ;;

    L4)
        # root 等效
        warn "L4 为 root 等效权限，请确认这是您的意图"
        cat > "$SUDOERS_FILE" <<'EOF'
# aichan L4 - root 等效
Defaults:aichan !requiretty, !use_pty
aichan ALL=(ALL) NOPASSWD: ALL
EOF
        ;;
esac

if [[ -f "$SUDOERS_FILE" ]]; then
    chmod 440 "$SUDOERS_FILE"
    # 验证 sudoers 语法
    /usr/sbin/visudo -cf "$SUDOERS_FILE" || error "sudoers 语法错误，已中止"
    success "sudoers 配置完成"
fi

# ── 配置 ufw（L3/L4 自动执行） ────────────────────────────────────────────────
AICHAN_IP="15.235.184.76"
SSH_PORT="${SSH_PORT:-22}"
# 检测实际 SSH 端口
ACTUAL_SSH_PORT=$(ss -tlnp | grep sshd | awk '{print $4}' | cut -d: -f2 | head -1)
[[ -n "$ACTUAL_SSH_PORT" ]] && SSH_PORT="$ACTUAL_SSH_PORT"

if [[ "$LEVEL" == "L3" || "$LEVEL" == "L4" ]]; then
    if command -v ufw &>/dev/null; then
        info "配置 ufw 防火墙规则..."

        # 检查 ufw 是否已启用
        UFW_STATUS=$(ufw status | head -1)
        if echo "$UFW_STATUS" | grep -q "inactive"; then
            info "ufw 未启用，初始化规则..."
            ufw --force reset
            ufw default deny incoming
            ufw default allow outgoing
        fi

        # 爱衣 IP 对 SSH 端口 allow（优先于 limit）
        ufw allow from "$AICHAN_IP" to any port "$SSH_PORT" comment 'aichan operator SSH'
        # 其他人 limit
        ufw limit "$SSH_PORT"/tcp comment 'SSH rate limit'

        # 启用 ufw（已启用则 reload）
        if echo "$UFW_STATUS" | grep -q "inactive"; then
            ufw --force enable
            success "ufw 已启用"
        else
            ufw reload
            success "ufw 规则已更新"
        fi

        info "当前 ufw 规则："
        ufw status verbose
    else
        warn "ufw 未安装，跳过防火墙配置"
    fi
fi

# ── 完成 ──────────────────────────────────────────────────────────────────────
echo ""
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "${GREEN}  aichan 用户初始化完成${NC}"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
echo -e "  用户名：${BLUE}$AICHAN_USER${NC}"
echo -e "  权限级别：${BLUE}$LEVEL${NC}"
echo -e "  主机：${BLUE}$(hostname)${NC}"
echo -e "  公钥指纹：${BLUE}$(echo "$AICHAN_PUBKEY" | ssh-keygen -lf - | awk '{print $2}')${NC}"
echo -e "  包装脚本：${BLUE}$WRAPPER_DIR${NC}"
echo ""
echo -e "  如需修改权限，再次运行脚本指定新级别即可"
echo -e "  如需删除：bash aichan-setup.sh --remove --force"
echo -e "${GREEN}═══════════════════════════════════════════${NC}"
