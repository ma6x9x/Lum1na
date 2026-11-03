#!/bin/bash
# Lum1na-Mind Mac serve — bind 0.0.0.0, print the Phone URL, advertise Bonjour.
#
# Phone: Lum1na-Debugger → Mind → gear → Discover, or paste the Phone URL.
# 192.168.1.1 is usually the Wi-Fi gateway, not this Mac.
#
# Prefers an already-running ollama on *:11434. mlx_lm.server is used when
# installed and LUMIND_ENGINE=mlx. Port 8080 is skipped when something else
# (often Ghidra) already owns it.
set -euo pipefail

PORT="${LUMIND_PORT:-}"
ENGINE="${LUMIND_ENGINE:-auto}"
MODEL="${LUMIND_MODEL:-}"
LAN_IP="$(ipconfig getifaddr en0 2>/dev/null || true)"
if [[ -z "${LAN_IP}" ]]; then
  LAN_IP="$(ipconfig getifaddr en1 2>/dev/null || true)"
fi
if [[ -z "${LAN_IP}" ]]; then
  echo "No LAN IPv4 on en0/en1. Join Wi-Fi/Ethernet on this Mac, then re-run."
  exit 1
fi

listening_on() {
  local p="$1"
  lsof -nP -iTCP:"${p}" -sTCP:LISTEN 2>/dev/null | awk 'NR>1 {print $1, $9}'
}

ollama_all_ifaces() {
  lsof -nP -iTCP:11434 -sTCP:LISTEN 2>/dev/null | grep -E '\*:11434|0\.0\.0\.0:11434' >/dev/null
}

print_phone() {
  local port="$1"
  echo
  echo "========== PHONE =========="
  echo "  Phone URL : http://${LAN_IP}:${port}/v1"
  echo "  Bonjour   : Lum1na-Mind  _lumina-mind._tcp  port ${port}"
  echo "  Same Wi-Fi as the phone. Allow Local Network on first connect."
  echo "  Mind → gear → Test Connection. Pick a model name from GET /models."
  echo "  Do not use http://192.168.1.1:… — that is usually the router."
  echo "==========================="
  echo
}

advertise() {
  local port="$1"
  echo "Advertising Bonjour _lumina-mind._tcp local ${port} (ctrl-c to stop)"
  exec dns-sd -R "Lum1na-Mind" _lumina-mind._tcp local "${port}"
}

pick_mlx_port() {
  if [[ -n "${PORT}" ]]; then
    echo "${PORT}"
    return
  fi
  if [[ -z "$(listening_on 8080)" ]]; then
    echo 8080
    return
  fi
  echo "Port 8080 is already in use:" >&2
  listening_on 8080 >&2
  echo "Using 8081 for mlx_lm.server. Set LUMIND_PORT to override." >&2
  echo 8081
}

echo "Mac LAN IPv4: ${LAN_IP}"

# --- already-running ollama on all interfaces (this lab Mac) ---
if [[ "${ENGINE}" == "auto" || "${ENGINE}" == "ollama" ]]; then
  if ollama_all_ifaces; then
    echo "ollama already listening on *:11434 (phone-reachable)."
    if command -v ollama >/dev/null 2>&1; then
      echo "Models on this Mac:"
      ollama list || true
    fi
    echo "From this Mac: curl -s http://127.0.0.1:11434/v1/models"
    echo "Phone model field must match one of those names (llama3.1:8b, glm-5.3-flash:cloud, …)."
    echo "glm-edge-1.5b is the in-app default; pull it or change the phone model."
    print_phone 11434
    advertise 11434
  fi
fi

# --- start mlx_lm.server ---
if [[ "${ENGINE}" == "mlx" || "${ENGINE}" == "auto" ]]; then
  if python3 -c "import mlx_lm" >/dev/null 2>&1; then
    MLX_PORT="$(pick_mlx_port)"
    MLX_MODEL="${MODEL:-glm-4-9b-chat}"
    print_phone "${MLX_PORT}"
    dns-sd -R "Lum1na-Mind" _lumina-mind._tcp local "${MLX_PORT}" >/tmp/lumina-mind-bonjour.log 2>&1 &
    DNS_PID=$!
    trap 'kill ${DNS_PID} 2>/dev/null || true' EXIT
    echo "Starting mlx_lm.server host=0.0.0.0 port=${MLX_PORT} model=${MLX_MODEL}"
    exec python3 -m mlx_lm.server --model "${MLX_MODEL}" --host 0.0.0.0 --port "${MLX_PORT}"
  elif [[ "${ENGINE}" == "mlx" ]]; then
    echo "mlx_lm is not installed. pip install mlx-lm  (Apple Silicon Mac)"
    exit 1
  fi
fi

# --- start ollama bound on all interfaces ---
if ! command -v ollama >/dev/null 2>&1; then
  echo "Neither mlx_lm nor ollama is available."
  echo "  pip install mlx-lm"
  echo "  or install ollama and run: OLLAMA_HOST=0.0.0.0:11434 ollama serve"
  exit 1
fi

if [[ -n "$(listening_on 11434)" ]]; then
  echo "Something is on 11434 but not *:all-ifaces. Phone cannot reach 127.0.0.1 on the Mac."
  listening_on 11434
  echo "Quit that ollama, then re-run this script so it binds 0.0.0.0."
  echo "  OLLAMA_HOST=0.0.0.0:11434 ollama serve"
  exit 1
fi

export OLLAMA_HOST="0.0.0.0:11434"
print_phone 11434
dns-sd -R "Lum1na-Mind" _lumina-mind._tcp local 11434 >/tmp/lumina-mind-bonjour.log 2>&1 &
DNS_PID=$!
trap 'kill ${DNS_PID} 2>/dev/null || true' EXIT
echo "Starting ollama with OLLAMA_HOST=${OLLAMA_HOST}"
exec ollama serve
