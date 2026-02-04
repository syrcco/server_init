#!/usr/bin/env bash
set -euo pipefail

# ===========================================================================
# Stage 0: Plan (constants)
# ===========================================================================
NETWORK_NAME="proxy"

SS_PORT="59876"
APPLE_PORT_START="10001"

APPLE_DOMAINS=(
  "swdist.apple.com"
  "swcdn.apple.com"
  "updates.cdn-apple.com"
  "mensura.cdn-apple.com"
  "osxapps.itunes.apple.com"
  "aod.itunes.apple.com"
)

CADDY_DIR="/opt/caddy"
XRAY_DIR="/opt/xray"

# Need root for /opt and docker network creation
if [[ "${EUID}" -ne 0 ]]; then
  if command -v sudo >/dev/null 2>&1; then
    script_path="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
    exec sudo -E bash "${script_path}" "$@"
  else
    echo "ERROR: please run as root (or install sudo)." >&2
    exit 1
  fi
fi

echo "================ Stage 0: Plan ================"
echo "Directories:"
echo "  Caddy: ${CADDY_DIR}"
echo "  Xray : ${XRAY_DIR}"
echo
echo "External Docker network:"
echo "  ${NETWORK_NAME}"
echo
echo "Ports:"
echo "  Public: 80/tcp   -> Caddy HTTP (redirect later)"
echo "  Public: 443/tcp  -> Caddy L4 (SNI router later)"
echo "  Public: ${SS_PORT}/tcp,udp -> Xray SS2022 later"
echo
echo "Apple SNI -> Xray port mapping (planned):"
p="${APPLE_PORT_START}"
for d in "${APPLE_DOMAINS[@]}"; do
  echo "  ${d} -> ${p}"
  p=$((p + 1))
done
echo "==============================================="

# ===========================================================================
# Stage 1: Prereq checks
# ===========================================================================
echo
echo "================ Stage 1: Checks ================"

if ! command -v docker >/dev/null 2>&1; then
  echo "ERROR: Docker is not installed. Install Docker first, then rerun." >&2
  exit 1
fi

# Basic sanity (does not require daemon running, but usually does)
if ! docker version >/dev/null 2>&1; then
  echo "ERROR: Docker is installed but not usable (daemon not running or permission issue)." >&2
  exit 1
fi

if ! docker compose version >/dev/null 2>&1; then
  echo "ERROR: docker compose plugin not found. Install docker-compose-plugin, then rerun." >&2
  exit 1
fi

echo "[OK] Docker present"
echo "[OK] docker compose present"

# Create independent stack directories (no binding between stacks)
if mkdir -p "${CADDY_DIR}" "${XRAY_DIR}" 2>/dev/null; then
  chmod 755 "${CADDY_DIR}" "${XRAY_DIR}"
  echo "[OK] Created/ensured directories"
else
  echo "ERROR: Failed to create directories in /opt (permission issue?)" >&2
  exit 1
fi

# Ensure external network exists
if docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
  echo "[OK] Docker network '${NETWORK_NAME}' already exists"
else
  docker network create "${NETWORK_NAME}" >/dev/null 2>&1
  echo "[OK] Created Docker network '${NETWORK_NAME}'"
fi




# ===========================================================================
# Stage 2: Prepare Xray stack (image + compose skeleton)
# ===========================================================================

echo
echo "================ Stage 2: Xray skeleton ================"

# Version pin (will also be used by Stage 2 key generation)
XRAY_VERSION="${XRAY_VERSION:-26.1.23}"
XRAY_IMAGE="ghcr.io/xtls/xray-core:${XRAY_VERSION}"

echo "[*] Pulling Xray image: ${XRAY_IMAGE}"
docker pull "${XRAY_IMAGE}" >/dev/null
echo "[OK] Pulled ${XRAY_IMAGE}"

# Prepare independent Xray directory layout under /opt/xray
mkdir -p "${XRAY_DIR}/config" "${XRAY_DIR}/secrets"
chmod 755 "${XRAY_DIR}" "${XRAY_DIR}/config" "${XRAY_DIR}/secrets"

# Minimal placeholder config (valid JSON; no inbounds yet)
# Stage 2/4 will overwrite this with real inbounds after generating secrets.
cat > "${XRAY_DIR}/config/config.json" <<'EOF'
{
  "log": { "loglevel": "warning" },
  "inbounds": [],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF
chmod 644 "${XRAY_DIR}/config/config.json"
echo "[OK] Wrote placeholder Xray config: ${XRAY_DIR}/config/config.json"

# Xray compose (independent project in /opt/xray; joins external network "proxy")
# Note: We DO NOT start it yet. Stage 4 will add final config + ports and then start.
cat > "${XRAY_DIR}/docker-compose.yml" <<EOF
services:
  xray:
    image: ${XRAY_IMAGE}
    container_name: xray
    restart: unless-stopped
    networks:
      - ${NETWORK_NAME}
    volumes:
      - ${XRAY_DIR}/config/config.json:/etc/xray/config.json:ro
    command: ["run","-c","/etc/xray/config.json"]
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"


networks:
  ${NETWORK_NAME}:
    external: true
EOF

chmod 644 "${XRAY_DIR}/docker-compose.yml"
echo "[OK] Wrote Xray compose: ${XRAY_DIR}/docker-compose.yml"


# ===========================================================================
# Stage 3: Generate secrets (idempotent)
# ===========================================================================

echo
echo "================ Stage 3: Generate secrets ================"

XRAY_VERSION="${XRAY_VERSION:-26.1.23}"
XRAY_IMAGE="ghcr.io/xtls/xray-core:${XRAY_VERSION}"

SECRETS_FILE="${XRAY_DIR}/secrets/secrets.env"

# Ensure secrets directory exists (Stage 3 should have created it, but make sure)
mkdir -p "${XRAY_DIR}/secrets"
chmod 700 "${XRAY_DIR}/secrets"

if [[ -f "${SECRETS_FILE}" ]]; then
  echo "[OK] Secrets already exist, reusing: ${SECRETS_FILE}"
  echo "     (Delete this file if you want to regenerate.)"
else
  echo "[*] Generating new secrets..."

  # UUID
  if command -v uuidgen >/dev/null 2>&1; then
    XRAY_UUID="$(uuidgen)"
  else
    XRAY_UUID="$(cat /proc/sys/kernel/random/uuid)"
  fi

  # REALITY keypair via xray image
  out="$(docker run --rm "${XRAY_IMAGE}" x25519 2>&1)"
  
  REALITY_PRIVATE_KEY="$(echo "${out}" | grep -i "PrivateKey" | awk -F': ' '{print $2}' | tr -d ' \r\n ')"
  REALITY_PUBLIC_KEY="$(echo "${out}" | grep -Ei "PublicKey|Password" | awk -F': ' '{print $2}' | tr -d ' \r\n ')"

  if [[ -z "${REALITY_PRIVATE_KEY}" || -z "${REALITY_PUBLIC_KEY}" ]]; then
    echo "ERROR: failed to generate REALITY keypair from image '${XRAY_IMAGE}'" >&2
    echo "DEBUG OUTPUT:" >&2
    echo "${out}" >&2
    exit 1
  fi

  # Random helpers (prefer host openssl; fallback to alpine+openssl)
  rand_hex() {
    local nbytes="$1"
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -hex "${nbytes}"
    else
      docker run --rm alpine:3.20 sh -c "apk add --no-cache openssl >/dev/null && openssl rand -hex ${nbytes}"
    fi
  }

  rand_b64_bytes() {
    local nbytes="$1"
    if command -v openssl >/dev/null 2>&1; then
      openssl rand -base64 "${nbytes}" | tr -d '\n'
    else
      docker run --rm alpine:3.20 sh -c "apk add --no-cache openssl >/dev/null && openssl rand -base64 ${nbytes} | tr -d '\n'"
    fi
  }

  # shortIds: 8-byte hex each (16 chars)
  REALITY_SHORTID_1="$(rand_hex 8)"
  REALITY_SHORTID_2="$(rand_hex 8)"

  # SS2022: choose method + key length
  SS_METHOD="2022-blake3-aes-128-gcm"
  SS_PASSWORD="$(rand_b64_bytes 16)"

  # Write secrets (quoted for safe 'source')
  umask 077
  cat > "${SECRETS_FILE}" <<EOF
XRAY_UUID="${XRAY_UUID}"
REALITY_PRIVATE_KEY="${REALITY_PRIVATE_KEY}"
REALITY_PUBLIC_KEY="${REALITY_PUBLIC_KEY}"
REALITY_SHORTID_1="${REALITY_SHORTID_1}"
REALITY_SHORTID_2="${REALITY_SHORTID_2}"
SS_METHOD="${SS_METHOD}"
SS_PASSWORD="${SS_PASSWORD}"
EOF
  chmod 600 "${SECRETS_FILE}"

  echo "[OK] Secrets generated: ${SECRETS_FILE}"
fi

# Load secrets into current shell for the next stages (Stage 4 will need them)
# shellcheck disable=SC1090
source "${SECRETS_FILE}"

# Print a short summary (no private key)
echo
echo "---- Xray secrets summary ----"
echo "✓ XRAY_UUID generated"
echo "✓ REALITY keypair generated"
echo "✓ REALITY ShortIDs generated"
echo "✓ SS2022 password generated"
echo
echo "All secrets saved to: ${SECRETS_FILE}"
echo "To view: cat ${SECRETS_FILE}"
echo "------------------------------"


# =========================
# Stage 4: Write final Xray config + expose SS port + start service
# =========================

echo
echo "================ Stage 4: Xray config + start ================"

# Re-derive image tag consistently
XRAY_VERSION="${XRAY_VERSION:-26.1.23}"
XRAY_IMAGE="ghcr.io/xtls/xray-core:${XRAY_VERSION}"

XRAY_CONFIG_FILE="${XRAY_DIR}/config/config.json"

# Sanity: required secrets must exist (Stage 2 should have sourced them)
: "${XRAY_UUID:?missing XRAY_UUID}"
: "${REALITY_PRIVATE_KEY:?missing REALITY_PRIVATE_KEY}"
: "${REALITY_PUBLIC_KEY:?missing REALITY_PUBLIC_KEY}"
: "${REALITY_SHORTID_1:?missing REALITY_SHORTID_1}"
: "${REALITY_SHORTID_2:?missing REALITY_SHORTID_2}"
: "${SS_METHOD:?missing SS_METHOD}"
: "${SS_PASSWORD:?missing SS_PASSWORD}"

# Build inbounds JSON into a temp file to avoid trailing-comma issues
tmp_inbounds="$(mktemp)"

port="${APPLE_PORT_START}"
for domain in "${APPLE_DOMAINS[@]}"; do
  cat >> "${tmp_inbounds}" <<EOF
    {
      "listen": "0.0.0.0",
      "port": ${port},
      "protocol": "vless",
      "settings": {
        "clients": [
          {
            "id": "${XRAY_UUID}",
            "flow": "xtls-rprx-vision",
            "email": "default@user"
          }
        ],
        "decryption": "none"
      },
      "streamSettings": {
        "network": "tcp",
        "security": "reality",
        "sockopt": {
          "acceptProxyProtocol": true
        },
        "realitySettings": {
          "show": false,
          "dest": "${domain}:443",
          "xver": 0,
          "serverNames": ["${domain}"],
          "privateKey": "${REALITY_PRIVATE_KEY}",
          "shortIds": ["${REALITY_SHORTID_1}", "${REALITY_SHORTID_2}"]
        }
      }
    },

EOF
  port=$((port + 1))
done

# SS2022 inbound (public, host-mapped)
cat >> "${tmp_inbounds}" <<EOF
    {
      "listen": "0.0.0.0",
      "port": ${SS_PORT},
      "protocol": "shadowsocks",
      "settings": {
        "method": "${SS_METHOD}",
        "password": "${SS_PASSWORD}",
        "network": "tcp,udp"
      }
    }
EOF

# Write final config
cat > "${XRAY_CONFIG_FILE}" <<EOF
{
  "log": { "loglevel": "warning" },
  "inbounds": [
$(cat "${tmp_inbounds}")
  ],
  "outbounds": [
    { "protocol": "freedom", "tag": "direct" },
    { "protocol": "blackhole", "tag": "block" }
  ]
}
EOF

rm -f "${tmp_inbounds}"
chmod 644 "${XRAY_CONFIG_FILE}"

echo "[OK] Wrote Xray config: ${XRAY_CONFIG_FILE}"

# Rewrite Xray compose with SS port mapping only (REALITY ports stay internal on the docker network)
cat > "${XRAY_DIR}/docker-compose.yml" <<EOF
services:
  xray:
    image: ${XRAY_IMAGE}
    container_name: xray
    restart: unless-stopped
    networks:
      - ${NETWORK_NAME}
    ports:
      - "${SS_PORT}:${SS_PORT}/tcp"
      - "${SS_PORT}:${SS_PORT}/udp"
    volumes:
      - ./config/config.json:/etc/xray/config.json:ro
    command: ["run","-c","/etc/xray/config.json"]
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"


networks:
  ${NETWORK_NAME}:
    external: true
EOF

chmod 644 "${XRAY_DIR}/docker-compose.yml"
echo "[OK] Updated Xray compose: ${XRAY_DIR}/docker-compose.yml"

# Validate config using the container
echo "[*] Validating Xray config (xray run -test)..."
( cd "${XRAY_DIR}" && COMPOSE_PROJECT_NAME="xray" docker compose run --rm xray run -test -c /etc/xray/config.json ) >/dev/null
echo "[OK] Xray config validation passed"

# Start/update service
echo "[*] Starting Xray..."
( cd "${XRAY_DIR}" && COMPOSE_PROJECT_NAME="xray" docker compose up -d --remove-orphans ) >/dev/null

echo "[OK] Xray is up. Status:"
( cd "${XRAY_DIR}" && COMPOSE_PROJECT_NAME="xray" docker compose ps )

echo
echo "---- Connection info (for next stage / client config) ----"
echo "VLESS UUID:           ${XRAY_UUID}"
echo "REALITY Public Key:   ${REALITY_PUBLIC_KEY}"
echo "REALITY ShortIDs:     ${REALITY_SHORTID_1}, ${REALITY_SHORTID_2}"
echo
echo "Apple SNI -> Xray internal port mapping:"
p="${APPLE_PORT_START}"
for d in "${APPLE_DOMAINS[@]}"; do
  echo "  ${d} -> ${p}"
  p=$((p + 1))
done
echo
echo "SS2022:"
echo "  Port:   ${SS_PORT} (TCP+UDP)"
echo "  Method: ${SS_METHOD}"
echo "  PSK:    ${SS_PASSWORD}"
echo "----------------------------------------------------------"


# =========================
# Stage 5: Caddy (layer4 SNI router on :443 + HTTP app on :80/:8443)
# =========================

echo
echo "================ Stage 5: build + config + start ================"

CADDY_VERSION="${CADDY_VERSION:-2.10.2}"

echo "[*] Pulling Caddy base images..."
docker pull "caddy:${CADDY_VERSION}" >/dev/null
docker pull "caddy:2-builder" >/dev/null
echo "[OK] Pulled caddy:${CADDY_VERSION} and caddy:2-builder"

# Prepare Caddy stack directory layout
mkdir -p "${CADDY_DIR}"
chmod 755 "${CADDY_DIR}"

# Dockerfile: always use caddy:2-builder; build pinned version with caddy-l4
cat > "${CADDY_DIR}/Dockerfile" <<EOF
FROM caddy:2-builder AS builder
RUN xcaddy build "v${CADDY_VERSION}" \\
    --with github.com/mholt/caddy-l4

FROM caddy:${CADDY_VERSION}
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
EOF
chmod 644 "${CADDY_DIR}/Dockerfile"
echo "[OK] Wrote ${CADDY_DIR}/Dockerfile"

# Caddyfile: must start with a proper heredoc (no bash command group!)
CADDYFILE="${CADDY_DIR}/Caddyfile"

cat > "${CADDYFILE}" <<EOF
{
  # :443 is owned by layer4; HTTP app uses :80 and internal HTTPS on :8443
  http_port 80
  https_port 8443

  # Internal HTTPS listener (layer4 default route -> :8443) must parse PROXY header first
  servers :8443 {
    listener_wrappers {
      proxy_protocol
      tls
    }
  }

  layer4 {
    :443 {
EOF

# Add SNI routes to Xray internal ports
p="${APPLE_PORT_START}"
for d in "${APPLE_DOMAINS[@]}"; do
  cat >> "${CADDYFILE}" <<EOF
      @sni_${p} tls sni ${d}
      route @sni_${p} {
        proxy {
          upstream xray:${p}
          proxy_protocol v2
        }
      }

EOF
  p=$((p + 1))
done

# Close layer4 + add HTTP app blocks
cat >> "${CADDYFILE}" <<'EOF'
      # Default: everything else goes to the internal HTTPS site on :8443
      route {
        proxy {
          upstream caddy:8443
          proxy_protocol
        }
      }
    }
  }
}

# HTTP -> HTTPS redirect (future web services)
:80 {
  redir https://{host}{uri} 308
}

# Placeholder HTTPS site (self-signed/internal CA for now; replace later)
:8443 {
    # 这里的 tls 必须与你的测试域名匹配
    tls internal 

    handle host temp.guuax.com {
		respond "proxy stack OK (temp.guuax.com handled via :8443)" 200
	}

    handle {
        abort
    }
}
EOF

chmod 644 "${CADDYFILE}"
echo "[OK] Wrote ${CADDYFILE}"

# docker-compose.yml (independent project under /opt/caddy)
cat > "${CADDY_DIR}/docker-compose.yml" <<EOF
services:
  caddy:
    build:
      context: .
    image: local/caddy-l4:${CADDY_VERSION}
    container_name: caddy
    restart: unless-stopped
    networks:
      - ${NETWORK_NAME}
    ports:
      - "80:80/tcp"
      - "443:443/tcp"
    volumes:
      - caddy_data:/data
      - caddy_config:/config
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"


volumes:
  caddy_data:
  caddy_config:

networks:
  ${NETWORK_NAME}:
    external: true
EOF

chmod 644 "${CADDY_DIR}/docker-compose.yml"
echo "[OK] Wrote ${CADDY_DIR}/docker-compose.yml"

# Build, validate, start (independent)
echo "[*] Building Caddy image (with caddy-l4)..."
( cd "${CADDY_DIR}" && COMPOSE_PROJECT_NAME="caddy" docker compose build --pull ) >/dev/null
echo "[OK] Build complete"

echo "[*] Validating Caddyfile..."
( cd "${CADDY_DIR}" && COMPOSE_PROJECT_NAME="caddy" docker compose run --rm caddy validate --config /etc/caddy/Caddyfile ) >/dev/null
echo "[OK] Caddyfile validation passed"

echo "[*] Starting Caddy..."
( cd "${CADDY_DIR}" && COMPOSE_PROJECT_NAME="caddy" docker compose up -d --remove-orphans ) >/dev/null

echo "[OK] Caddy is up. Status:"
( cd "${CADDY_DIR}" && COMPOSE_PROJECT_NAME="caddy" docker compose ps )


# =========================
# Stage 6: Post-deploy verification + UFW allow SS port
# =========================

echo
echo "================ Stage 6: Verify + firewall ================"

# --- UFW: allow SS port (tcp+udp) if ufw active ---
if command -v ufw >/dev/null 2>&1; then
  if ufw status | grep -qi "Status: active"; then
    echo "[*] UFW active: allowing SS port ${SS_PORT}/tcp and ${SS_PORT}/udp"
    ufw allow "${SS_PORT}/tcp" >/dev/null || true
    ufw allow "${SS_PORT}/udp" >/dev/null || true
    echo "[OK] UFW rules ensured for ${SS_PORT}/tcp,udp"
  else
    echo "[*] UFW installed but not active; skipping UFW rules"
  fi
else
  echo "[*] UFW not installed; skipping firewall changes"
fi

echo
echo "---- Docker compose status ----"
( cd "${XRAY_DIR}" && COMPOSE_PROJECT_NAME="xray" docker compose ps ) || true
( cd "${CADDY_DIR}" && COMPOSE_PROJECT_NAME="caddy" docker compose ps ) || true

echo
echo "---- Listening ports (expected: 80/tcp, 443/tcp, ${SS_PORT}/tcp+udp) ----"
if command -v ss >/dev/null 2>&1; then
  ss -lntup | grep -E ":(80|443|${SS_PORT})\b" || true
else
  echo "[*] ss not found; skipping port listing"
fi

echo
echo "---- Basic HTTP/HTTPS checks (local) ----"
if command -v curl >/dev/null 2>&1; then
  echo "[*] HTTP redirect check: http://127.0.0.1/"
  curl -sS -I http://127.0.0.1/ | sed -n '1,5p' || true

  echo
  echo "[*] HTTPS placeholder check via :443 default route (SNI temp.guuax.com):"
  echo "    (using --resolve to point temp.guuax.com -> 127.0.0.1; -k because tls internal)"
  curl -sS -k --resolve temp.guuax.com:443:127.0.0.1 https://temp.guuax.com/ | head -n 2 || true
else
  echo "[*] curl not found; skipping HTTP/HTTPS checks"
fi

echo
echo "---- Quick connection info reminder ----"
echo "SS2022: ${SS_PORT}/tcp+udp, method=${SS_METHOD}"
echo "VLESS+REALITY: connect to :443 with SNI set to one of the Apple domains; routes to internal ports starting at ${APPLE_PORT_START}"





