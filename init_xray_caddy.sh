#!/usr/bin/env bash
set -euo pipefail

STACK_DIR="${STACK_DIR:-/opt/proxy-stack}"
NETWORK_NAME="proxy"

# Fixed ports per your plan
SS_PORT="59876"
APPLE_PORT_START="10001"
APPLE_PORT_END="10006"

APPLE_DOMAINS=(
  "swdist.apple.com"
  "swcdn.apple.com"
  "updates.cdn-apple.com"
  "mensura.cdn-apple.com"
  "osxapps.itunes.apple.com"
  "aod.itunes.apple.com"
)

CADDY_VERSION="${CADDY_VERSION:-2.10.2}"
XRAY_VERSION="${XRAY_VERSION:-26.1.23}"

need_root() {
  if [[ "${EUID}" -ne 0 ]]; then
    if command -v sudo >/dev/null 2>&1; then
      exec sudo -E bash "$0" "$@"
    else
      echo "ERROR: please run as root (or install sudo)."
      exit 1
    fi
  fi
}

install_docker_if_needed() {
  if ! command -v docker >/dev/null 2>&1; then
    echo "[*] Docker not found, installing..."
    curl -fsSL https://get.docker.com | sh
  fi

  # Ensure docker compose plugin exists
  if ! docker compose version >/dev/null 2>&1; then
    echo "[*] docker compose plugin not found, installing..."
    if command -v apt-get >/dev/null 2>&1; then
      apt-get update -y
      apt-get install -y docker-compose-plugin
    else
      echo "ERROR: cannot install docker compose plugin automatically on this OS."
      exit 1
    fi
  fi
}

ensure_network() {
  if ! docker network inspect "${NETWORK_NAME}" >/dev/null 2>&1; then
    echo "[*] Creating docker network: ${NETWORK_NAME}"
    docker network create "${NETWORK_NAME}" >/dev/null
  else
    echo "[*] Docker network '${NETWORK_NAME}' already exists"
  fi
}

ufw_allow_ss() {
  if command -v ufw >/dev/null 2>&1; then
    # only touch SS port rules; do not change default policy
    if ufw status | grep -qi "Status: active"; then
      echo "[*] UFW active: allowing ${SS_PORT}/tcp and ${SS_PORT}/udp"
      ufw allow "${SS_PORT}/tcp" >/dev/null || true
      ufw allow "${SS_PORT}/udp" >/dev/null || true
    else
      echo "[*] UFW installed but not active; skipping UFW rules"
    fi
  else
    echo "[*] UFW not installed; skipping firewall changes"
  fi
}

rand_hex() {
  local nbytes="${1}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex "${nbytes}"
  else
    docker run --rm alpine:3.20 sh -c "apk add --no-cache openssl >/dev/null && openssl rand -hex ${nbytes}"
  fi
}

rand_b64_bytes() {
  local nbytes="${1}"
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 "${nbytes}" | tr -d '\n'
  else
    docker run --rm alpine:3.20 sh -c "apk add --no-cache openssl >/dev/null && openssl rand -base64 ${nbytes} | tr -d '\n'"
  fi
}

gen_uuid() {
  if command -v uuidgen >/dev/null 2>&1; then
    uuidgen
  else
    cat /proc/sys/kernel/random/uuid
  fi
}

pull_images() {
  echo "[*] Pulling base images..."
  docker pull "caddy:${CADDY_VERSION}" >/dev/null
  docker pull "caddy:${CADDY_VERSION}-builder" >/dev/null || docker pull "caddy:2-builder" >/dev/null
  docker pull "ghcr.io/xtls/xray-core:${XRAY_VERSION}" >/dev/null
}

gen_reality_keypair() {
  # Output: "private|public"
  local out
  out="$(docker run --rm "ghcr.io/xtls/xray-core:${XRAY_VERSION}" xray x25519)"
  local priv pub
  priv="$(echo "${out}" | awk -F': ' '/Private key/ {print $2}' | tr -d '\r')"
  pub="$(echo "${out}"  | awk -F': ' '/Public key/  {print $2}' | tr -d '\r')"
  if [[ -z "${priv}" || -z "${pub}" ]]; then
    echo "ERROR: failed to generate REALITY keypair"
    echo "${out}"
    exit 1
  fi
  echo "${priv}|${pub}"
}

write_files() {
  mkdir -p "${STACK_DIR}/caddy" "${STACK_DIR}/xray"
  chmod 700 "${STACK_DIR}" "${STACK_DIR}/caddy" "${STACK_DIR}/xray"

  # ---------- secrets (idempotent) ----------
  local secrets_file="${STACK_DIR}/xray/secrets.env"
  if [[ -f "${secrets_file}" ]]; then
    echo "[*] Reusing existing secrets: ${secrets_file}"
    # shellcheck disable=SC1090
    source "${secrets_file}"
  else
    echo "[*] Generating secrets..."
    umask 077

    XRAY_UUID="$(gen_uuid)"
    IFS='|' read -r REALITY_PRIVATE_KEY REALITY_PUBLIC_KEY < <(gen_reality_keypair)

    # shortIds: 8-byte hex (16 chars) each
    REALITY_SHORTID_1="$(rand_hex 8)"
    REALITY_SHORTID_2="$(rand_hex 8)"

    # SS2022: base64 key; 32-byte key works across methods per Xray docs
    SS_METHOD="2022-blake3-aes-128-gcm"
    SS_PASSWORD="$(rand_b64_bytes 32)"

    cat > "${secrets_file}" <<EOF
XRAY_UUID=${XRAY_UUID}
REALITY_PRIVATE_KEY=${REALITY_PRIVATE_KEY}
REALITY_PUBLIC_KEY=${REALITY_PUBLIC_KEY}
REALITY_SHORTID_1=${REALITY_SHORTID_1}
REALITY_SHORTID_2=${REALITY_SHORTID_2}
SS_METHOD=${SS_METHOD}
SS_PASSWORD=${SS_PASSWORD}
EOF
    chmod 600 "${secrets_file}"
  fi

  # ---------- Xray config ----------
  echo "[*] Writing Xray config..."
  local xray_config="${STACK_DIR}/xray/config.json"
  local tmp_inbounds
  tmp_inbounds="$(mktemp)"

  # Build VLESS+REALITY inbounds 10001-10006 mapped to Apple domains
  local port="${APPLE_PORT_START}"
  local idx=0
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
    idx=$((idx + 1))
  done

  # Add SS2022 inbound (host-mapped)
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

  # Write full config
  cat > "${xray_config}" <<EOF
{
  "log": {
    "loglevel": "warning"
  },
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
  chmod 600 "${xray_config}"

  # ---------- Xray Dockerfile ----------
  cat > "${STACK_DIR}/xray/Dockerfile" <<EOF
FROM ghcr.io/xtls/xray-core:${XRAY_VERSION}
# distroless-style image; keep it minimal
WORKDIR /etc/xray
COPY config.json /etc/xray/config.json
USER 65532:65532
ENTRYPOINT ["xray","run","-c","/etc/xray/config.json"]
EOF

  # ---------- Xray compose ----------
  cat > "${STACK_DIR}/xray/docker-compose.yml" <<EOF
services:
  xray:
    build:
      context: .
    image: local/xray:${XRAY_VERSION}
    container_name: xray
    restart: unless-stopped
    networks:
      - ${NETWORK_NAME}
    ports:
      - "${SS_PORT}:${SS_PORT}/tcp"
      - "${SS_PORT}:${SS_PORT}/udp"
    volumes:
      - ./config.json:/etc/xray/config.json:ro
    security_opt:
      - no-new-privileges:true
    cap_drop:
      - ALL
    logging:
      driver: json-file
      options:
        max-size: "10m"
        max-file: "3"
    healthcheck:
      test: ["CMD","xray","run","-test","-c","/etc/xray/config.json"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  ${NETWORK_NAME}:
    external: true
EOF

  # ---------- Caddy Dockerfile (build with caddy-l4 only) ----------
  echo "[*] Writing Caddy Dockerfile + Caddyfile..."
  cat > "${STACK_DIR}/caddy/Dockerfile" <<EOF
FROM caddy:${CADDY_VERSION}-builder AS builder
RUN xcaddy build \\
    --with github.com/mholt/caddy-l4

FROM caddy:${CADDY_VERSION}
COPY --from=builder /usr/bin/caddy /usr/bin/caddy
COPY Caddyfile /etc/caddy/Caddyfile
EOF

  # ---------- Caddyfile ----------
  # Design:
  # - HTTP app listens on :80 (redirect) and :8443 (HTTPS site)
  # - L4 app listens on :443 and SNI-routes Apple domains to xray ports, else to 127.0.0.1:8443
  # - Proxy Protocol v2 is added for BOTH paths
  # - :8443 server enables proxy_protocol listener wrapper, so Caddy sees real client IP
  local caddyfile="${STACK_DIR}/caddy/Caddyfile"

  {
    # Avoid binding HTTPS app to :443; :443 is owned by layer4
    http_port 80
    https_port 8443

    # Enable proxy_protocol parsing on the internal HTTPS listener (layer4 -> :8443)
    servers :8443 {
      listener_wrappers {
        proxy_protocol
        tls
      }
    }

    # L4 TCP router on :443
    layer4 {
      :443 {
EOF

  port="${APPLE_PORT_START}"
  for domain in "${APPLE_DOMAINS[@]}"; do
    cat >> "${caddyfile}" <<EOF
        @sni_${port} tls sni ${domain}
        route @sni_${port} {
          proxy {
            upstream xray:${port}
            proxy_protocol v2
          }
        }

EOF
    port=$((port + 1))
  done

  cat >> "${caddyfile}" <<'EOF'
        # Default: everything else goes to the internal HTTPS site (Caddy HTTP app on :8443)
        route {
          proxy {
            upstream 127.0.0.1:8443
            proxy_protocol v2
          }
        }
      }
    }
  }

# HTTP -> HTTPS redirect (future web services)
:80 {
  redir https://{host}{uri} 308
}

# Placeholder HTTPS site (self-signed for now; later replace with real domain configs / reverse_proxy)
# You can delete/modify this freely later.
temp.guuax.com {
  tls internal
  respond "proxy stack OK (replace this site block later)" 200
}
EOF

  # ---------- Caddy compose ----------
  cat > "${STACK_DIR}/caddy/docker-compose.yml" <<EOF
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
    healthcheck:
      test: ["CMD","caddy","validate","--config","/etc/caddy/Caddyfile"]
      interval: 30s
      timeout: 10s
      retries: 3

volumes:
  caddy_data:
  caddy_config:

networks:
  ${NETWORK_NAME}:
    external: true
EOF

  echo "[*] Files written under: ${STACK_DIR}"
}

compose_up() {
  echo "[*] Validating configs (xray -test, caddy validate)..."
  # Validate Xray config using a one-off container (Xray supports -test)
  ( cd "${STACK_DIR}/xray" && docker compose run --rm xray xray run -test -c /etc/xray/config.json ) >/dev/null

  # Build & validate Caddy
  ( cd "${STACK_DIR}/caddy" && docker compose build --pull ) >/dev/null
  ( cd "${STACK_DIR}/caddy" && docker compose run --rm caddy caddy validate --config /etc/caddy/Caddyfile ) >/dev/null

  echo "[*] Starting stack..."
  export COMPOSE_PROJECT_NAME="proxy-stack"
  docker compose -f "${STACK_DIR}/xray/docker-compose.yml" -f "${STACK_DIR}/caddy/docker-compose.yml" up -d --remove-orphans

  echo "[*] Done. Current status:"
  docker compose -f "${STACK_DIR}/xray/docker-compose.yml" -f "${STACK_DIR}/caddy/docker-compose.yml" ps
}

print_summary() {
  echo
  echo "================= GENERATED CONNECTION INFO ================="
  echo "VLESS UUID:            ${XRAY_UUID}"
  echo "REALITY Public Key:    ${REALITY_PUBLIC_KEY}"
  echo "REALITY ShortIDs:      ${REALITY_SHORTID_1}, ${REALITY_SHORTID_2}"
  echo
  echo "Apple SNI -> Xray Port mapping:"
  local p="${APPLE_PORT_START}"
  for d in "${APPLE_DOMAINS[@]}"; do
    echo "  ${d}  ->  ${p}"
    p=$((p + 1))
  done
  echo
  echo "SS2022:"
  echo "  Port:   ${SS_PORT} (TCP+UDP)"
  echo "  Method: ${SS_METHOD}"
  echo "  PSK:    ${SS_PASSWORD}"
  echo
  echo "Secrets saved at: ${STACK_DIR}/xray/secrets.env"
  echo "============================================================="
  echo
  echo "Notes:"
  echo "- Reality/VLESS is reached via :443 with SNI set to one of the Apple domains above."
  echo "- All other :443 SNI goes to Caddy site on :8443 (behind L4)."
  echo "- SS2022 is directly on host :${SS_PORT} (ufw allow added if ufw is active)."
}

main() {
  need_root "$@"
  install_docker_if_needed
  pull_images
  ensure_network
  ufw_allow_ss
  write_files
  compose_up
  print_summary
}

main "$@"
