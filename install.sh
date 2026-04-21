#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# install.sh — Универсальный установщик
#
# Режимы:
#   VPS режим   — Asterisk + PJSIP + Exolve (для исходящих звонков)
#   Прокси режим — Kamailio + WireGuard + rtpengine (центральный SIP прокси)
#
# Использование:
#   bash install.sh                    — меню выбора режима
#   bash install.sh vps wizard         — настройка VPS
#   bash install.sh vps apply          — установка VPS
#   bash install.sh proxy wizard       — настройка прокси
#   bash install.sh proxy apply        — установка прокси
#   bash install.sh proxy add-vps      — добавить VPS к прокси
#   bash install.sh proxy remove-vps   — удалить VPS из прокси
#   bash install.sh proxy list         — показать конфиг прокси
# =============================================================================

# ─── Общие настройки ────────────────────────────────────────────────────────
LOCKFILE="/var/run/install_sh.lock"
DRY_RUN="${DRY_RUN:-0}"
APT_UPDATED=0

# ─── VPS настройки ──────────────────────────────────────────────────────────
ASTERISK_VER="${ASTERISK_VER:-21}"
ASTERISK_TARBALL_URL="${ASTERISK_TARBALL_URL:-}"
ALLOW_UPGRADE="${ALLOW_UPGRADE:-0}"
VPS_CONFIG_FILE="${VPS_CONFIG_FILE:-/etc/asterisk/install.env}"
SERVER_IP="${SERVER_IP:-}"
DEFAULT_MAX_CONTACTS="${DEFAULT_MAX_CONTACTS:-1}"
DEFAULT_REMOVE_EXISTING="${DEFAULT_REMOVE_EXISTING:-yes}"
PUBLIC_IPS="${PUBLIC_IPS:-}"
USERS="${USERS:-1001}"
TRUNKS="${TRUNKS:-exolve}"
EXOLVE_NAME="${EXOLVE_NAME:-exolve}"
EXOLVE_PROXY="${EXOLVE_PROXY:-80.75.130.99}"
EXOLVE_PORT="${EXOLVE_PORT:-5060}"
EXOLVE_MATCHES="${EXOLVE_MATCHES:-}"
OUTCID="${OUTCID:-}"
ACTIVE_TRUNK="${ACTIVE_TRUNK:-}"
ENABLE_UFW="${ENABLE_UFW:-1}"
SSH_PORT="${SSH_PORT:-22}"
TRUSTED_SIP_SOURCES="${TRUSTED_SIP_SOURCES:-}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-1}"
ENABLE_RECORDING="${ENABLE_RECORDING:-1}"
RECORDING_DAYS="${RECORDING_DAYS:-7}"
ENABLE_BALANCE_CHECK="${ENABLE_BALANCE_CHECK:-0}"
BALANCE_CHECK_INTERVAL="${BALANCE_CHECK_INTERVAL:-5}"
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"
PROXY_WG_IP="${PROXY_WG_IP:-}"

# ─── Прокси настройки ───────────────────────────────────────────────────────
PROXY_CONFIG_FILE="/etc/kamailio/proxy.env"
PROXY_IP="${PROXY_IP:-}"
VPS_NODES="${VPS_NODES:-}"
PROXY_USERS="${PROXY_USERS:-}"
WG_INTERFACE="${WG_INTERFACE:-wg0}"
WG_PROXY_IP="${WG_PROXY_IP:-10.10.0.1}"
WG_SUBNET="${WG_SUBNET:-10.10.0}"
WG_PORT="${WG_PORT:-51820}"

# ─── Globals ────────────────────────────────────────────────────────────────
NEED_DIALPLAN_RELOAD=0
NEED_PJSIP_RELOAD=0
NEED_SYSTEMD_DAEMON_RELOAD=0
NEED_ASTERISK_RESTART=0
NEED_SAVE_CONFIG=0
CHANGES=()

# =============================================================================
# Общие хелперы
# =============================================================================
ts(){ date +%Y%m%d_%H%M%S; }
log(){ echo "[*] $*"; }
warn(){ echo "[!] $*" >&2; }
die(){ echo "[X] $*" >&2; exit 1; }
is_true(){ case "${1:-0}" in 1|true|TRUE|yes|YES|y|Y) return 0;; *) return 1;; esac }
run_cmd(){ if is_true "$DRY_RUN"; then log "DRY_RUN: $*"; return 0; fi; eval "$@"; }
need_root(){ [[ "$(id -u)" -eq 0 ]] || die "Run as root."; }

detect_os(){
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release"
  . /etc/os-release
  case "${ID:-}" in debian|ubuntu) :;; *) die "Unsupported OS: ${ID:-unknown}";; esac
  command -v apt-get >/dev/null 2>&1 || die "apt-get not found"
}

normalize_list(){ echo "$*" | tr ',' ' ' | awk '{$1=$1; print}'; }
upper_sanitize(){ echo "$1" | tr '[:lower:]' '[:upper:]' | sed -E 's/[^A-Z0-9]+/_/g'; }
get_var(){ local name="$1"; eval "printf '%s' \"\${${name}:-}\""; }
set_var(){ local name="$1" value="$2"; export "${name}=${value}"; }

list_contains(){
  local item="$1"; shift
  local x
  for x in $(normalize_list "$*"); do [[ "$x" == "$item" ]] && return 0; done
  return 1
}

backup_file(){
  local f="$1"; [[ -f "$f" ]] || return 0
  run_cmd "cp -a \"${f}\" \"${f}.bak_$(ts)\""
}

is_ipv4(){
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.; local -a o; read -r -a o <<<"$ip"
  local x; for x in "${o[@]}"; do [[ "$x" -ge 0 && "$x" -le 255 ]] || return 1; done
  return 0
}

gen_password(){
  openssl rand -base64 24 | tr -d '\n' | tr '/+=' 'xyz' | cut -c1-28 2>/dev/null \
  || tr -dc 'A-Za-z0-9' </dev/urandom | head -c 28
}

use_yandex_mirror(){
  sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.yandex.ru/ubuntu|g' /etc/apt/sources.list 2>/dev/null || true
  sed -i 's|http://security.ubuntu.com/ubuntu|http://mirror.yandex.ru/ubuntu|g' /etc/apt/sources.list 2>/dev/null || true
  if [ -f /etc/apt/sources.list.d/ubuntu.sources ]; then
    sed -i 's|http://archive.ubuntu.com/ubuntu|http://mirror.yandex.ru/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
    sed -i 's|http://security.ubuntu.com/ubuntu|http://mirror.yandex.ru/ubuntu|g' /etc/apt/sources.list.d/ubuntu.sources 2>/dev/null || true
  fi
}

ensure_packages(){
  local pkgs=("$@") missing=() p
  for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  [[ "${#missing[@]}" -eq 0 ]] && { log "Packages OK: ${pkgs[*]}"; return 0; }
  log "Installing: ${missing[*]}"
  if is_true "$DRY_RUN"; then return 0; fi
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    use_yandex_mirror
    apt-get update -q
    APT_UPDATED=1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

prompt_var(){
  local var="$1" prompt="$2" def="${3:-}"
  local cur; cur="$(get_var "$var" 2>/dev/null || echo "${def}")"
  [[ -n "$cur" ]] && def="$cur"
  local input=""
  if [[ -n "$def" ]]; then read -rp "${prompt} [${def}]: " input; input="${input:-$def}"
  else read -rp "${prompt}: " input; fi
  export "${var}=${input}"
}

acquire_lock(){
  exec 9>"$LOCKFILE"
  flock -n 9 || { echo "[X] Скрипт уже запущен."; exit 1; }
}

# =============================================================================
# ██╗   ██╗██████╗ ███████╗    ███╗   ███╗ ██████╗ ██████╗ ███████╗
# ██║   ██║██╔══██╗██╔════╝    ████╗ ████║██╔═══██╗██╔══██╗██╔════╝
# ██║   ██║██████╔╝███████╗    ██╔████╔██║██║   ██║██║  ██║█████╗
# ╚██╗ ██╔╝██╔═══╝ ╚════██║    ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝
#  ╚████╔╝ ██║     ███████║    ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
#   ╚═══╝  ╚═╝     ╚══════╝    ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
# =============================================================================

# ─── VPS: загрузка конфига ──────────────────────────────────────────────────
vps_load_config(){
  [[ -f "$VPS_CONFIG_FILE" ]] || return 0
  . "$VPS_CONFIG_FILE" 2>/dev/null || true
}

vps_env_escape(){ local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf "%s" "$s"; }
vps_env_append(){ local -n _b="$1"; local k="$2" v="$3" line; printf -v line '%s="%s"\n' "$k" "$(vps_env_escape "$v")"; _b+="$line"; }

vps_save_config(){
  mkdir -p "$(dirname "$VPS_CONFIG_FILE")"
  [[ -f "$VPS_CONFIG_FILE" ]] || printf "# install.sh config\n" > "$VPS_CONFIG_FILE"
  local trunk_list user_list
  trunk_list="$(normalize_list "$TRUNKS")"; user_list="$(normalize_list "$USERS")"
  local block=""
  block+="# Managed config"$'\n'
  vps_env_append block SERVER_IP "$SERVER_IP"
  vps_env_append block PUBLIC_IPS "$PUBLIC_IPS"
  vps_env_append block USERS "$USERS"
  vps_env_append block TRUNKS "$TRUNKS"
  vps_env_append block OUTCID "$OUTCID"
  vps_env_append block ACTIVE_TRUNK "$ACTIVE_TRUNK"
  vps_env_append block ENABLE_UFW "$ENABLE_UFW"
  vps_env_append block SSH_PORT "$SSH_PORT"
  vps_env_append block ENABLE_FAIL2BAN "$ENABLE_FAIL2BAN"
  vps_env_append block ENABLE_RECORDING "$ENABLE_RECORDING"
  vps_env_append block RECORDING_DAYS "$RECORDING_DAYS"
  vps_env_append block DEFAULT_MAX_CONTACTS "$DEFAULT_MAX_CONTACTS"
  vps_env_append block DEFAULT_REMOVE_EXISTING "$DEFAULT_REMOVE_EXISTING"
  vps_env_append block EXOLVE_NAME "$EXOLVE_NAME"
  vps_env_append block EXOLVE_PROXY "$EXOLVE_PROXY"
  vps_env_append block EXOLVE_PORT "$EXOLVE_PORT"
  vps_env_append block EXOLVE_MATCHES "$EXOLVE_MATCHES"
  vps_env_append block PROXY_WG_IP "$PROXY_WG_IP"
  block+=$'\n'
  local t
  for t in $trunk_list; do
    local up; up="$(upper_sanitize "$t")"
    vps_env_append block "TRUNK_${up}_PROXY"   "$(get_var "TRUNK_${up}_PROXY")"
    vps_env_append block "TRUNK_${up}_PORT"    "$(get_var "TRUNK_${up}_PORT")"
    vps_env_append block "TRUNK_${up}_MATCHES" "$(get_var "TRUNK_${up}_MATCHES")"
    vps_env_append block "TRUNK_${up}_OUTCID"  "$(get_var "TRUNK_${up}_OUTCID")"
    vps_env_append block "TRUNK_${up}_CONTEXT" "$(get_var "TRUNK_${up}_CONTEXT")"
    vps_env_append block "TRUNK_${up}_BIND_IP" "$(get_var "TRUNK_${up}_BIND_IP")"
    block+=$'\n'
  done
  local u
  for u in $user_list; do
    vps_env_append block "USER_${u}_PASS"            "$(get_var "USER_${u}_PASS")"
    vps_env_append block "USER_${u}_TRUNK"           "$(get_var "USER_${u}_TRUNK")"
    vps_env_append block "USER_${u}_OUTCID"          "$(get_var "USER_${u}_OUTCID")"
    vps_env_append block "USER_${u}_MAX_CONTACTS"    "$(get_var "USER_${u}_MAX_CONTACTS")"
    vps_env_append block "USER_${u}_REMOVE_EXISTING" "$(get_var "USER_${u}_REMOVE_EXISTING")"
    block+=$'\n'
  done
  # Записать через managed block
  local begin="# BEGIN MANAGED: INSTALL_SH_CONFIG"
  local end="# END MANAGED: INSTALL_SH_CONFIG"
  local new_block="${begin}"$'\n'"${block}"$'\n'"${end}"$'\n'
  local current; current="$(cat "$VPS_CONFIG_FILE")"
  local updated=""
  if [[ "$current" == *"$begin"* ]]; then
    updated="$(printf "%s" "$current" | awk -v begin="$begin" -v end="$end" -v nb="$new_block" \
      'BEGIN{inblk=0} { if($0==begin){printf "%s",nb;inblk=1;next} if($0==end){inblk=0;next} if(!inblk)print }')"
  else
    updated="$current"$'\n'"$new_block"
  fi
  printf "%s" "$updated" > "$VPS_CONFIG_FILE"
  chmod 600 "$VPS_CONFIG_FILE"
}

# ─── VPS: установка Asterisk ─────────────────────────────────────────────────
vps_ensure_asterisk(){
  if dpkg -s asterisk >/dev/null 2>&1; then
    log "Asterisk уже установлен: $(asterisk -V 2>/dev/null | awk '{print $2}' || true)"
    # Проверить что chan_sip отключён
    local chan_sip="/usr/lib/x86_64-linux-gnu/asterisk/modules/chan_sip.so"
    [[ -f "$chan_sip" ]] && mv "$chan_sip" "${chan_sip}.disabled" && log "chan_sip.so отключён" || true
    return 0
  fi
  log "Устанавливаю Asterisk (apt)..."
  is_true "$DRY_RUN" && return 0
  use_yandex_mirror
  if [[ "$APT_UPDATED" -eq 0 ]]; then apt-get update -q; APT_UPDATED=1; fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y asterisk asterisk-modules asterisk-config
  # Убрать noload для pjsip
  local mc="/etc/asterisk/modules.conf"
  [[ -f "$mc" ]] && sed -i '/noload.*chan_pjsip/d;/noload.*res_pjsip/d' "$mc" || true
  # Отключить chan_sip физически
  local chan_sip="/usr/lib/x86_64-linux-gnu/asterisk/modules/chan_sip.so"
  [[ -f "$chan_sip" ]] && mv "$chan_sip" "${chan_sip}.disabled" && log "chan_sip.so отключён" || true
  CHANGES+=("Installed Asterisk + disabled chan_sip")
  NEED_ASTERISK_RESTART=1
  log "Asterisk установлен: $(asterisk -V 2>/dev/null || true)"
}

# ─── VPS: пользователи и директории ──────────────────────────────────────────
vps_ensure_user_dirs(){
  id asterisk >/dev/null 2>&1 || run_cmd "adduser --system --group --home /var/lib/asterisk --no-create-home asterisk"
  run_cmd "mkdir -p /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk /etc/asterisk"
  for d in /var/lib/asterisk /var/log/asterisk /var/spool/asterisk /var/run/asterisk /etc/asterisk; do
    [[ -e "$d" ]] && chown asterisk:asterisk "$d" || true
  done
}

# ─── VPS: systemd ────────────────────────────────────────────────────────────
vps_ensure_systemd(){
  local unit=/etc/systemd/system/asterisk.service
  cat > "$unit" << 'EOF'
[Unit]
Description=Asterisk PBX
After=network.target
[Service]
Type=simple
User=asterisk
Group=asterisk
RuntimeDirectory=asterisk
RuntimeDirectoryMode=0755
ExecStart=/usr/sbin/asterisk -f -U asterisk -G asterisk
ExecReload=/usr/sbin/asterisk -rx "core reload"
Restart=always
RestartSec=3
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
EOF
  systemctl daemon-reload
  systemctl enable asterisk >/dev/null 2>&1 || true
  NEED_ASTERISK_RESTART=1
}

# ─── VPS: UFW ────────────────────────────────────────────────────────────────
vps_ensure_ufw(){
  is_true "$ENABLE_UFW" || return 0
  ensure_packages ufw
  is_true "$DRY_RUN" && return 0
  ufw --force enable >/dev/null || true
  ufw allow "${SSH_PORT}/tcp" >/dev/null
  ufw allow 5060/udp          >/dev/null
  ufw allow 5061/udp          >/dev/null
  ufw allow 10000:20000/udp   >/dev/null
  # Разрешить WireGuard порт если прокси настроен
  [[ -n "$PROXY_WG_IP" ]] && ufw allow 51820/udp >/dev/null || true
  log "UFW настроен"
}

# ─── VPS: конфиги Asterisk ───────────────────────────────────────────────────
vps_detect_ip(){
  [[ -n "${SERVER_IP:-}" ]] && return 0
  SERVER_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
  [[ -n "$SERVER_IP" ]] || die "SERVER_IP не определён"
}

vps_normalize_public_ips(){
  [[ -z "${PUBLIC_IPS:-}" ]] && PUBLIC_IPS="$SERVER_IP"
  PUBLIC_IPS="$(normalize_list "$PUBLIC_IPS")"
  list_contains "$SERVER_IP" "$PUBLIC_IPS" || PUBLIC_IPS="$(normalize_list "$SERVER_IP $PUBLIC_IPS")"
}

vps_ensure_asterisk_configs(){
  local pjsip=/etc/asterisk/pjsip.conf
  local trunks_file=/etc/asterisk/pjsip_trunks.conf
  local users_file=/etc/asterisk/pjsip_users.conf
  local exts=/etc/asterisk/extensions.conf
  local tactive=/etc/asterisk/trunk_active.conf

  for f in "$pjsip" "$trunks_file" "$users_file" "$exts" "$tactive"; do
    [[ -f "$f" ]] || touch "$f"
    chown asterisk:asterisk "$f"
  done

  vps_normalize_public_ips

  # pjsip.conf транспорты
  local trans=""
  trans+="[transport-udp-public]"$'\n'
  trans+="type=transport"$'\n'"protocol=udp"$'\n'"bind=0.0.0.0:5060"$'\n'
  trans+="external_signaling_address=${SERVER_IP}"$'\n'"external_media_address=${SERVER_IP}"$'\n'
  trans+="local_net=10.0.0.0/8"$'\n'"local_net=172.16.0.0/12"$'\n'"local_net=192.168.0.0/16"$'\n\n'
  local idx=0
  for ip in $PUBLIC_IPS; do
    idx=$((idx+1))
    local tname="transport-udp-trunk"; [[ $idx -gt 1 ]] && tname="transport-udp-trunk${idx}"
    trans+="[${tname}]"$'\n'"type=transport"$'\n'"protocol=udp"$'\n'"bind=${ip}:5061"$'\n'
    trans+="external_signaling_address=${ip}"$'\n'"external_media_address=${ip}"$'\n'
    trans+="local_net=10.0.0.0/8"$'\n'"local_net=172.16.0.0/12"$'\n'"local_net=192.168.0.0/16"$'\n\n'
  done

  vps_apply_block "$pjsip" "TRANSPORTS" "$trans" ";"
  vps_apply_block "$pjsip" "INCLUDES" \
    $'#include "pjsip_trunks.conf"\n#include "pjsip_users.conf"' ";"

  # Транки
  local trunk_list; trunk_list="$(normalize_list "$TRUNKS")"
  for t in $trunk_list; do
    local up; up="$(upper_sanitize "$t")"
    local proxy; proxy="$(get_var "TRUNK_${up}_PROXY")"
    local port; port="$(get_var "TRUNK_${up}_PORT")"; [[ -n "$port" ]] || port="5060"
    local matches; matches="$(get_var "TRUNK_${up}_MATCHES")"
    local outcid; outcid="$(get_var "TRUNK_${up}_OUTCID")"
    local ctx; ctx="$(get_var "TRUNK_${up}_CONTEXT")"; [[ -n "$ctx" ]] || ctx="from-${t}"
    local bind_ip; bind_ip="$(get_var "TRUNK_${up}_BIND_IP")"; [[ -n "$bind_ip" ]] || bind_ip="$SERVER_IP"
    [[ -n "$proxy" ]] || die "Missing TRUNK_${up}_PROXY"

    local inf_block=""
    if is_ipv4 "$proxy"; then
      inf_block="[${t}-identify]"$'\n'"type=identify"$'\n'"endpoint=${t}"$'\n'"match=${proxy}/32"$'\n'
    elif [[ -n "$matches" ]]; then
      local m; for m in $(normalize_list "$matches"); do inf_block+="match=${m}"$'\n'; done
      inf_block="[${t}-identify]"$'\n'"type=identify"$'\n'"endpoint=${t}"$'\n'"${inf_block}"
    fi

    local from_user=""; [[ -n "$outcid" ]] && from_user="from_user=${outcid}"
    local tb
    tb="[${t}]"$'\n'"type=endpoint"$'\n'"transport=transport-udp-trunk"$'\n'"context=${ctx}"$'\n'
    tb+="disallow=all"$'\n'"allow=ulaw"$'\n'"allow=alaw"$'\n'"aors=${t}"$'\n'
    tb+="outbound_proxy=sip:${proxy}:${port}\\;lr"$'\n'"from_domain=${proxy}"$'\n'"${from_user}"$'\n'
    tb+="send_pai=yes"$'\n'"trust_id_outbound=yes"$'\n'"direct_media=no"$'\n'
    tb+="rtp_symmetric=yes"$'\n'"force_rport=yes"$'\n'"rewrite_contact=yes"$'\n\n'
    tb+="[${t}]"$'\n'"type=aor"$'\n'"contact=sip:${proxy}:${port}"$'\n'"qualify_frequency=60"$'\n\n'
    tb+="${inf_block}"

    vps_apply_block "$trunks_file" "TRUNK_${t}" "$tb" ";"
  done

  # Юзеры
  local user_list; user_list="$(normalize_list "$USERS")"
  for u in $user_list; do
    [[ "$u" =~ ^[0-9]+$ ]] || die "User must be numeric: $u"
    local pass; pass="$(get_var "USER_${u}_PASS")"
    [[ -n "$pass" ]] || { pass="$(gen_password)"; set_var "USER_${u}_PASS" "$pass"; NEED_SAVE_CONFIG=1; }
    local maxc; maxc="$(get_var "USER_${u}_MAX_CONTACTS")"; [[ -n "$maxc" ]] || maxc="$DEFAULT_MAX_CONTACTS"
    local rem; rem="$(get_var "USER_${u}_REMOVE_EXISTING")"; [[ -n "$rem" ]] || rem="$DEFAULT_REMOVE_EXISTING"

    local ub
    ub="[${u}]"$'\n'"type=endpoint"$'\n'"transport=transport-udp-public"$'\n'"context=from-internal-${u}"$'\n'
    ub+="disallow=all"$'\n'"allow=ulaw"$'\n'"allow=alaw"$'\n'"auth=${u}"$'\n'"aors=${u}"$'\n'
    ub+="rtp_symmetric=yes"$'\n'"force_rport=yes"$'\n'"rewrite_contact=yes"$'\n'"direct_media=no"$'\n\n'
    ub+="[${u}]"$'\n'"type=auth"$'\n'"auth_type=userpass"$'\n'"username=${u}"$'\n'"password=${pass}"$'\n\n'
    ub+="[${u}]"$'\n'"type=aor"$'\n'"max_contacts=${maxc}"$'\n'"remove_existing=${rem}"$'\n'"qualify_frequency=0"$'\n'

    vps_apply_block "$users_file" "USER_${u}" "$ub" ";"
  done

  # Диалплан
  local first_user; first_user="$(echo "$user_list" | awk '{print $1}')"
  local first_trunk; first_trunk="$(echo "$trunk_list" | awk '{print $1}')"
  local first_trunk_up; first_trunk_up="$(upper_sanitize "$first_trunk")"
  local first_ctx; first_ctx="$(get_var "TRUNK_${first_trunk_up}_CONTEXT")"; [[ -n "$first_ctx" ]] || first_ctx="from-${first_trunk}"

  local internal_dials=""
  for u in $user_list; do
    internal_dials+="exten => ${u},1,Dial(PJSIP/${u},30)"$'\n'" same => n,Hangup()"$'\n'
  done

  local per_user=""
  for u in $user_list; do
    local utrunk; utrunk="$(get_var "USER_${u}_TRUNK")"; [[ -n "$utrunk" ]] || utrunk="active"
    local dial_target outcid_set
    if [[ "$utrunk" == "active" ]]; then
      dial_target='PJSIP/${EXTEN}@${TRUNK}'
      outcid_set=" same => n,Set(CALLERID(all)=\${OUTCID})"$'\n'
    else
      dial_target="PJSIP/\${EXTEN}@${utrunk}"
      outcid_set=""
    fi
    local rec=""
    is_true "$ENABLE_RECORDING" && rec=" same => n,MixMonitor(/var/spool/asterisk/monitor/\${STRFTIME(\${EPOCH},,\%Y\%m\%d-\%H\%M\%S)}-\${EXTEN}-out-${u}.wav,b,/usr/bin/lame -b 64 \${MONITOR_FILENAME} \${MONITOR_FILENAME:0:-4}.mp3 && rm -f \${MONITOR_FILENAME})"$'\n'
    per_user+=$'\n'"[from-internal-${u}]"$'\n'"${internal_dials}"$'\n'
    per_user+="exten => _7XXXXXXXXXX,1,NoOp(Outgoing for ${u})"$'\n'"${outcid_set}${rec}"
    per_user+=" same => n,Dial(${dial_target},60)"$'\n'" same => n,Hangup()"$'\n'
  done

  local incoming=""
  for t in $trunk_list; do
    local up ctx; up="$(upper_sanitize "$t")"; ctx="$(get_var "TRUNK_${up}_CONTEXT")"; [[ -n "$ctx" ]] || ctx="from-${t}"
    local rec=""
    is_true "$ENABLE_RECORDING" && rec=" same => n,MixMonitor(/var/spool/asterisk/monitor/\${STRFTIME(\${EPOCH},,\%Y\%m\%d-\%H\%M\%S)}-\${EXTEN}-in.wav,b,/usr/bin/lame -b 64 \${MONITOR_FILENAME} \${MONITOR_FILENAME:0:-4}.mp3 && rm -f \${MONITOR_FILENAME})"$'\n'
    incoming+=$'\n'"[${ctx}]"$'\n'"exten => _X.,1,NoOp(Incoming ${t})"$'\n'"${rec}"
    incoming+=" same => n,Dial(PJSIP/${first_user},60)"$'\n'" same => n,Hangup()"$'\n'
  done

  local dp
  dp="#include \"trunk_active.conf\""$'\n'"[from-internal]"$'\n'"include => from-internal-${first_user}"$'\n'
  dp+="${per_user}"$'\n'"${incoming}"

  vps_apply_block "$exts" "DIALPLAN_GENERATED" "$dp" ";"

  # trunk_active.conf
  if ! grep -q '^\[globals\]' "$tactive" 2>/dev/null; then
    printf "[globals]\n" > "$tactive"
  fi
  local desired="${ACTIVE_TRUNK:-$first_trunk}"
  vps_apply_block "$tactive" "TRUNK_GLOBALS" \
    "[globals]"$'\n'"TRUNK=${desired}"$'\n'"OUTCID=${OUTCID}" ";"

  chown asterisk:asterisk "$pjsip" "$trunks_file" "$users_file" "$exts" "$tactive"

  # proxy-in endpoint если задан PROXY_WG_IP
  [[ -n "${PROXY_WG_IP:-}" ]] && vps_ensure_proxy_endpoint || true

  NEED_PJSIP_RELOAD=1; NEED_DIALPLAN_RELOAD=1
}

vps_apply_block(){
  local file="$1" marker="$2" content="$3" cpfx="${4:-;}"
  local begin="${cpfx} BEGIN MANAGED: ${marker}"
  local end="${cpfx} END MANAGED: ${marker}"
  local new_block="${begin}"$'\n'"${content}"$'\n'"${end}"$'\n'
  local current=""; [[ -f "$file" ]] && current="$(cat "$file")"
  local updated=""
  if [[ "$current" == *"$begin"* ]]; then
    updated="$(printf "%s" "$current" | awk -v b="$begin" -v e="$end" -v nb="$new_block" \
      'BEGIN{inblk=0}{if($0==b){printf "%s",nb;inblk=1;next}if($0==e){inblk=0;next}if(!inblk)print}')"
  else
    updated="${current}"$'\n'"${new_block}"
  fi
  printf "%s" "$updated" > "$file"
}

vps_ensure_proxy_endpoint(){
  local users_file="/etc/asterisk/pjsip_users.conf"
  local exts_file="/etc/asterisk/extensions.conf"
  local trunk; trunk="$(normalize_list "$TRUNKS" | awk '{print $1}')"

  # proxy-in endpoint
  if ! grep -q "^\[proxy-in\]" "$users_file" 2>/dev/null; then
    cat >> "$users_file" << EOF

; ===== KAMAILIO PROXY =====
[proxy-in]
type=endpoint
transport=transport-udp-public
context=from-proxy
disallow=all
allow=ulaw
allow=alaw
aors=proxy-in
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
identify_by=ip

[proxy-in]
type=aor
contact=sip:${PROXY_WG_IP}:5060
qualify_frequency=0

[proxy-in-identify]
type=identify
endpoint=proxy-in
match=${PROXY_WG_IP}
EOF
    CHANGES+=("Added proxy-in endpoint for ${PROXY_WG_IP}")
    NEED_PJSIP_RELOAD=1
  fi

  # from-proxy диалплан
  if ! grep -q "^\[from-proxy\]" "$exts_file" 2>/dev/null; then
    cat >> "$exts_file" << EOF

[from-proxy]
exten => _7XXXXXXXXXX,1,NoOp(Kamailio proxy: \${EXTEN})
 same => n,Dial(PJSIP/\${EXTEN}@${trunk},60)
 same => n,Hangup()
exten => _8XXXXXXXXXX,1,Goto(from-proxy,7\${EXTEN:1},1)
exten => _+7XXXXXXXXXX,1,Goto(from-proxy,7\${EXTEN:2},1)
exten => _9XXXXXXXXX,1,Goto(from-proxy,7\${EXTEN},1)
EOF
    CHANGES+=("Added from-proxy dialplan")
    NEED_DIALPLAN_RELOAD=1
  fi
}

# ─── VPS: fail2ban ───────────────────────────────────────────────────────────
vps_ensure_fail2ban(){
  is_true "$ENABLE_FAIL2BAN" || return 0
  ensure_packages fail2ban
  cat > /etc/fail2ban/jail.d/asterisk-pbx.conf << 'EOF'
[asterisk]
enabled  = true
port     = 5060
protocol = udp
filter   = asterisk
logpath  = /var/log/asterisk/messages.log
maxretry = 5
findtime = 300
bantime  = 86400
EOF
  systemctl enable --now fail2ban >/dev/null 2>&1 || true
  systemctl restart fail2ban >/dev/null 2>&1 || true
}

# ─── VPS: запись ─────────────────────────────────────────────────────────────
vps_ensure_recording(){
  is_true "$ENABLE_RECORDING" || return 0
  ensure_packages lame
  mkdir -p /var/spool/asterisk/monitor
  chown asterisk:asterisk /var/spool/asterisk/monitor
  cat > /etc/cron.d/asterisk-recording-cleanup << EOF
0 3 * * * root find /var/spool/asterisk/monitor -name '*.mp3' -mtime +${RECORDING_DAYS} -delete 2>/dev/null
EOF
}

# ─── VPS: перезапуск/reload ──────────────────────────────────────────────────
vps_reload(){
  [[ "$NEED_SYSTEMD_DAEMON_RELOAD" -eq 1 ]] && systemctl daemon-reload || true
  if [[ "$NEED_ASTERISK_RESTART" -eq 1 || "$NEED_PJSIP_RELOAD" -eq 1 ]]; then
    log "Перезапускаю Asterisk..."
    systemctl restart asterisk
    return 0
  fi
  systemctl is-active --quiet asterisk || systemctl start asterisk
  [[ "$NEED_DIALPLAN_RELOAD" -eq 1 ]] && asterisk -rx "dialplan reload" >/dev/null 2>&1 || true
}

vps_health(){
  log "Проверка..."
  local i=0
  while ! systemctl is-active --quiet asterisk && (( i < 10 )); do sleep 1; i=$((i+1)); done
  if systemctl is-active --quiet asterisk; then
    log "Asterisk активен: $(asterisk -V 2>/dev/null || true)"
    asterisk -rx "pjsip show transports" 2>/dev/null || true
  else
    warn "Asterisk не запустился. journalctl -u asterisk -n 50 --no-pager"
  fi
}

# ─── VPS: wizard ─────────────────────────────────────────────────────────────
vps_cmd_wizard(){
  need_root; detect_os; vps_load_config
  echo; echo "=== VPS Мастер ==="
  prompt_var SERVER_IP "IP этого сервера" "${SERVER_IP:-}"
  vps_detect_ip; vps_normalize_public_ips
  prompt_var OUTCID "OUTCID (11 цифр)" "${OUTCID:-}"
  prompt_var TRUNKS "Транки" "${TRUNKS:-exolve}"
  TRUNKS="$(normalize_list "$TRUNKS")"
  local t
  for t in $TRUNKS; do
    local up; up="$(upper_sanitize "$t")"
    [[ -n "$(get_var "TRUNK_${up}_PROXY")"   ]] || set_var "TRUNK_${up}_PROXY"   "80.75.130.99"
    [[ -n "$(get_var "TRUNK_${up}_PORT")"    ]] || set_var "TRUNK_${up}_PORT"    "5060"
    [[ -n "$(get_var "TRUNK_${up}_MATCHES")" ]] || set_var "TRUNK_${up}_MATCHES" "80.75.130.101"
    [[ -n "$(get_var "TRUNK_${up}_OUTCID")"  ]] || set_var "TRUNK_${up}_OUTCID"  "$OUTCID"
    [[ -n "$(get_var "TRUNK_${up}_CONTEXT")" ]] || set_var "TRUNK_${up}_CONTEXT" "from-${t}"
    [[ -n "$(get_var "TRUNK_${up}_BIND_IP")" ]] || set_var "TRUNK_${up}_BIND_IP" "$SERVER_IP"
  done
  prompt_var USERS "SIP пользователи" "${USERS:-1001}"
  USERS="$(normalize_list "$USERS")"
  local u
  for u in $USERS; do
    local pv="USER_${u}_PASS"; local cp; cp="$(get_var "$pv")"
    if [[ -z "$cp" ]]; then cp="$(gen_password)"; set_var "$pv" "$cp"; echo "  ${u}: пароль → ${cp}"; fi
    [[ -n "$(get_var "USER_${u}_TRUNK")" ]] || set_var "USER_${u}_TRUNK" "active"
  done
  prompt_var SSH_PORT "SSH порт" "${SSH_PORT:-22}"
  prompt_var PROXY_WG_IP "WireGuard IP прокси (оставьте пустым если прокси нет)" "${PROXY_WG_IP:-}"
  NEED_SAVE_CONFIG=1; vps_save_config
  echo; echo "Готово! Запустите: bash install.sh vps apply"
}

# ─── VPS: list ───────────────────────────────────────────────────────────────
vps_cmd_list(){
  need_root; vps_load_config
  echo "SERVER_IP: ${SERVER_IP:-}"
  echo "USERS: ${USERS:-}  TRUNKS: ${TRUNKS:-}"
  echo "PROXY_WG_IP: ${PROXY_WG_IP:-не задан}"
  local u
  for u in $(normalize_list "${USERS:-}"); do
    echo "  SIP: Server=${SERVER_IP:-?} User=${u} Pass=$(get_var "USER_${u}_PASS")"
  done
}

# ─── VPS: меню ───────────────────────────────────────────────────────────────
vps_cmd_menu(){
  need_root; detect_os
  while true; do
    echo; echo "======= VPS Меню ======="
    echo "1) Мастер (wizard)"
    echo "2) Применить (apply)"
    echo "3) Показать (list)"
    echo "4) Сменить пароль юзера"
    echo "0) Назад"
    echo "========================"
    read -rp "Выберите: " c
    case "${c:-}" in
      1) vps_cmd_wizard ;;
      2) vps_main_apply ;;
      3) vps_cmd_list ;;
      4) read -rp "Extension: " ext; vps_set_pass "$ext" ;;
      0) break ;;
    esac
  done
}

vps_set_pass(){
  local ext="$1"; vps_load_config
  local pass; read -rp "Новый пароль для ${ext}: " pass
  set_var "USER_${ext}_PASS" "$pass"; NEED_SAVE_CONFIG=1; vps_save_config
  echo "Готово. Запустите: bash install.sh vps apply"
}

# ─── VPS: apply ──────────────────────────────────────────────────────────────
vps_main_apply(){
  need_root; detect_os; vps_load_config
  vps_detect_ip; vps_normalize_public_ips
  # Валидация
  [[ -n "${TRUNKS:-}" ]] || die "TRUNKS не задан"
  [[ -n "${USERS:-}"  ]] || die "USERS не задан"
  local u
  for u in $(normalize_list "$USERS"); do
    [[ "$u" =~ ^[0-9]+$ ]] || die "User must be numeric: $u"
    local pass; pass="$(get_var "USER_${u}_PASS")"
    if [[ -z "$pass" ]]; then pass="$(gen_password)"; set_var "USER_${u}_PASS" "$pass"; NEED_SAVE_CONFIG=1; fi
    [[ -n "$(get_var "USER_${u}_TRUNK")" ]] || set_var "USER_${u}_TRUNK" "active"
  done

  vps_ensure_asterisk
  vps_ensure_user_dirs
  vps_ensure_systemd
  vps_ensure_ufw
  vps_ensure_asterisk_configs
  vps_ensure_fail2ban
  vps_ensure_recording

  [[ "$NEED_SAVE_CONFIG" -eq 1 ]] && vps_save_config || true
  vps_reload
  vps_health

  echo
  echo "============================================================"
  echo "VPS ГОТОВ"
  echo "SERVER_IP: ${SERVER_IP}"
  for u in $(normalize_list "$USERS"); do
    echo "  SIP: Server=${SERVER_IP} User=${u} Pass=$(get_var "USER_${u}_PASS")"
  done
  [[ -n "${PROXY_WG_IP:-}" ]] && echo "Kamailio прокси: ${PROXY_WG_IP}" || true
  echo "============================================================"
}

# =============================================================================
# ██████╗ ██████╗  ██████╗ ██╗  ██╗██╗   ██╗    ███╗   ███╗ ██████╗ ██████╗ ███████╗
# ██╔══██╗██╔══██╗██╔═══██╗╚██╗██╔╝╚██╗ ██╔╝    ████╗ ████║██╔═══██╗██╔══██╗██╔════╝
# ██████╔╝██████╔╝██║   ██║ ╚███╔╝  ╚████╔╝     ██╔████╔██║██║   ██║██║  ██║█████╗
# ██╔═══╝ ██╔══██╗██║   ██║ ██╔██╗   ╚██╔╝      ██║╚██╔╝██║██║   ██║██║  ██║██╔══╝
# ██║     ██║  ██║╚██████╔╝██╔╝ ██╗   ██║       ██║ ╚═╝ ██║╚██████╔╝██████╔╝███████╗
# ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝       ╚═╝     ╚═╝ ╚═════╝ ╚═════╝ ╚══════╝
# =============================================================================

proxy_load_config(){
  [[ -f "$PROXY_CONFIG_FILE" ]] && . "$PROXY_CONFIG_FILE" || true
}

proxy_save_config(){
  mkdir -p "$(dirname "$PROXY_CONFIG_FILE")"
  cat > "$PROXY_CONFIG_FILE" << EOF
PROXY_IP="${PROXY_IP}"
SSH_PORT="${SSH_PORT}"
ENABLE_UFW="${ENABLE_UFW}"
VPS_NODES="${VPS_NODES}"
PROXY_USERS="${PROXY_USERS}"
WG_INTERFACE="${WG_INTERFACE}"
WG_PROXY_IP="${WG_PROXY_IP}"
WG_SUBNET="${WG_SUBNET}"
WG_PORT="${WG_PORT}"
EOF
  chmod 600 "$PROXY_CONFIG_FILE"
}

proxy_ensure_packages(){
  ensure_packages kamailio kamailio-sqlite-modules sqlite3
  ensure_packages rtpengine 2>/dev/null || ensure_packages ngcp-rtpengine-daemon 2>/dev/null || warn "rtpengine не найден"
  ensure_packages wireguard
}

proxy_ensure_ufw(){
  is_true "$ENABLE_UFW" || return 0
  ensure_packages ufw
  ufw --force enable >/dev/null || true
  ufw allow "${SSH_PORT}/tcp" >/dev/null
  ufw allow 5060/udp          >/dev/null
  ufw allow 10000:20000/udp   >/dev/null
  ufw allow "${WG_PORT}/udp"  >/dev/null
}

proxy_setup_wireguard(){
  mkdir -p /etc/wireguard; chmod 700 /etc/wireguard
  if [[ ! -f /etc/wireguard/proxy_private.key ]]; then
    wg genkey | tee /etc/wireguard/proxy_private.key | wg pubkey > /etc/wireguard/proxy_public.key
    chmod 600 /etc/wireguard/proxy_private.key
    log "WireGuard ключи сгенерированы: $(cat /etc/wireguard/proxy_public.key)"
  fi
  local priv; priv="$(cat /etc/wireguard/proxy_private.key)"
  local peers="" idx=1 entry vps_ip
  for entry in ${VPS_NODES:-}; do
    vps_ip="$(echo "$entry" | cut -d: -f1)"
    local wg_vps_ip="${WG_SUBNET}.$((idx+1))"
    local kf="/etc/wireguard/vps_${vps_ip//./_}_public.key"
    if [[ -f "$kf" ]]; then
      peers+=$'\n'"[Peer]"$'\n'"# VPS ${vps_ip}"$'\n'"PublicKey = $(cat "$kf")"$'\n'
      peers+="AllowedIPs = ${wg_vps_ip}/32"$'\n'"Endpoint = ${vps_ip}:${WG_PORT}"$'\n'"PersistentKeepalive = 25"$'\n'
    fi
    idx=$((idx+1))
  done
  cat > "/etc/wireguard/${WG_INTERFACE}.conf" << EOF
[Interface]
Address = ${WG_PROXY_IP}/24
PrivateKey = ${priv}
ListenPort = ${WG_PORT}
${peers}
EOF
  chmod 600 "/etc/wireguard/${WG_INTERFACE}.conf"
  systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
  systemctl restart "wg-quick@${WG_INTERFACE}" 2>/dev/null || wg-quick up "${WG_INTERFACE}" 2>/dev/null || true
  log "WireGuard: ${WG_PROXY_IP}"
}

proxy_create_databases(){
  mkdir -p /etc/kamailio
  # dispatcher.db
  rm -f /etc/kamailio/dispatcher.db
  sqlite3 /etc/kamailio/dispatcher.db "CREATE TABLE version (table_name VARCHAR(32) NOT NULL, table_version INT DEFAULT 0 NOT NULL, CONSTRAINT ver_table_name_idx UNIQUE (table_name));"
  sqlite3 /etc/kamailio/dispatcher.db "INSERT INTO version VALUES ('dispatcher', 4);"
  sqlite3 /etc/kamailio/dispatcher.db "CREATE TABLE dispatcher (id INTEGER PRIMARY KEY AUTOINCREMENT, setid INTEGER NOT NULL DEFAULT 0, destination VARCHAR(192) NOT NULL DEFAULT '', flags INTEGER NOT NULL DEFAULT 0, priority INTEGER NOT NULL DEFAULT 0, attrs VARCHAR(128) NOT NULL DEFAULT '', description VARCHAR(64) NOT NULL DEFAULT '');"
  local idx=1 entry vps_ip
  for entry in ${VPS_NODES:-}; do
    vps_ip="$(echo "$entry" | cut -d: -f1)"
    local wg_vps_ip="${WG_SUBNET}.$((idx+1))"
    sqlite3 /etc/kamailio/dispatcher.db "INSERT INTO dispatcher (setid, destination, flags, priority, description) VALUES (1, 'sip:${wg_vps_ip}:5060', 0, 0, 'VPS ${vps_ip}');"
    log "  VPS: ${vps_ip} → WG ${wg_vps_ip}"
    idx=$((idx+1))
  done
  # users.db
  rm -f /etc/kamailio/users.db
  sqlite3 /etc/kamailio/users.db "CREATE TABLE version (table_name VARCHAR(32) NOT NULL, table_version INT DEFAULT 0 NOT NULL, CONSTRAINT ver_table_name_idx UNIQUE (table_name));"
  sqlite3 /etc/kamailio/users.db "INSERT INTO version VALUES ('subscriber', 7);"
  sqlite3 /etc/kamailio/users.db "CREATE TABLE subscriber (id INTEGER PRIMARY KEY AUTOINCREMENT, username VARCHAR(64) NOT NULL DEFAULT '', domain VARCHAR(64) NOT NULL DEFAULT '', password VARCHAR(64) NOT NULL DEFAULT '', email_address VARCHAR(64) NOT NULL DEFAULT '', ha1 VARCHAR(64) NOT NULL DEFAULT '', ha1b VARCHAR(64) NOT NULL DEFAULT '', rpid VARCHAR(64) DEFAULT NULL, CONSTRAINT subscriber_account_idx UNIQUE (username, domain));"
  local uentry ext pass ha1
  for uentry in ${PROXY_USERS:-}; do
    ext="${uentry%%:*}"; pass="${uentry##*:}"
    ha1="$(echo -n "${ext}:${PROXY_IP}:${pass}" | md5sum | cut -d' ' -f1)"
    sqlite3 /etc/kamailio/users.db "INSERT INTO subscriber (username, domain, password, email_address, ha1, ha1b) VALUES ('${ext}', '${PROXY_IP}', '${pass}', '', '${ha1}', '');"
    log "  Юзер: ${ext}"
  done
  chown -R kamailio:kamailio /etc/kamailio/ 2>/dev/null || true
}

proxy_generate_cfg(){
  cat > /etc/kamailio/kamailio.cfg << EOF
#!KAMAILIO
debug=2
log_stderror=no
log_facility=LOG_LOCAL0
fork=yes
children=4
port=5060
listen=udp:${PROXY_IP}:5060
listen=udp:${WG_PROXY_IP}:5060

mpath="/usr/lib/x86_64-linux-gnu/kamailio/modules/"

loadmodule "kex.so"
loadmodule "corex.so"
loadmodule "tm.so"
loadmodule "tmx.so"
loadmodule "sl.so"
loadmodule "rr.so"
loadmodule "pv.so"
loadmodule "maxfwd.so"
loadmodule "usrloc.so"
loadmodule "registrar.so"
loadmodule "textops.so"
loadmodule "siputils.so"
loadmodule "xlog.so"
loadmodule "sanity.so"
loadmodule "ctl.so"
loadmodule "auth.so"
loadmodule "auth_db.so"
loadmodule "dispatcher.so"
loadmodule "db_sqlite.so"
loadmodule "rtpengine.so"

modparam("tm", "failure_reply_mode", 3)
modparam("tm", "fr_timer", 30000)
modparam("tm", "fr_inv_timer", 120000)
modparam("rr", "enable_full_lr", 0)
modparam("rr", "append_fromtag", 0)
modparam("registrar", "method_filtering", 1)
modparam("registrar", "max_expires", 3600)
modparam("registrar", "gruu_enabled", 0)
modparam("usrloc", "db_mode", 0)
modparam("auth_db", "db_url", "sqlite:///etc/kamailio/users.db")
modparam("auth_db", "calculate_ha1", 0)
modparam("auth_db", "password_column", "ha1")
modparam("auth_db", "load_credentials", "")
modparam("auth_db", "use_domain", 0)
modparam("dispatcher", "db_url", "sqlite:///etc/kamailio/dispatcher.db")
modparam("dispatcher", "ds_ping_interval", 10)
modparam("dispatcher", "ds_ping_method", "OPTIONS")
modparam("dispatcher", "ds_probing_mode", 1)
modparam("dispatcher", "ds_ping_from", "sip:ping@${WG_PROXY_IP}")
modparam("rtpengine", "rtpengine_sock", "udp:127.0.0.1:2223")

request_route {
  if (!mf_process_maxfwd_header(10)) { sl_send_reply("483","Too Many Hops"); exit; }
  if (is_method("REGISTER")) { route(REGISTRAR); exit; }
  if (is_method("INVITE|SUBSCRIBE")) { record_route(); }
  if (loose_route()) {
    if (is_method("INVITE")) { rtpengine_manage("replace-origin replace-session-connection"); }
    route(RELAY); exit;
  }
  if (is_method("INVITE")) {
    if (!auth_check("\$fd","subscriber","1")) { auth_challenge("\$fd","0"); exit; }
    consume_credentials();
    force_send_socket(udp:${WG_PROXY_IP}:5060);
    if (!ds_select_dst(1,4)) { sl_send_reply("503","Service Unavailable"); exit; }
    rtpengine_manage("replace-origin replace-session-connection");
    route(RELAY); exit;
  }
  route(RELAY);
}
route[REGISTRAR] {
  if (!auth_check("\$fd","subscriber","1")) { auth_challenge("\$fd","0"); exit; }
  consume_credentials();
  if (!save("location")) { sl_reply_error(); }
  exit;
}
route[RELAY] {
  if (!t_relay()) { sl_reply_error(); }
  exit;
}
onreply_route {
  if (is_method("INVITE") && has_body("application/sdp")) {
    rtpengine_manage("replace-origin replace-session-connection");
  }
}
failure_route[MANAGE_FAILURE] {
  if (t_is_canceled()) { exit; }
  if (t_check_status("503")) { if (ds_next_dst()) { route(RELAY); exit; } }
}
EOF
  chown kamailio:kamailio /etc/kamailio/kamailio.cfg 2>/dev/null || true
}

proxy_start(){
  systemctl stop asterisk 2>/dev/null || true
  systemctl disable asterisk 2>/dev/null || true
  systemctl enable rtpengine 2>/dev/null || systemctl enable rtpengine-daemon 2>/dev/null || true
  systemctl restart rtpengine 2>/dev/null || systemctl restart rtpengine-daemon 2>/dev/null || true
  systemctl enable kamailio
  systemctl restart kamailio
  sleep 3
  systemctl is-active --quiet kamailio && log "Kamailio запущен!" || warn "Kamailio не запустился"
}

# ─── Прокси: wizard ──────────────────────────────────────────────────────────
proxy_cmd_wizard(){
  need_root; proxy_load_config
  echo; echo "=== Прокси Мастер ==="
  [[ -z "$PROXY_IP" ]] && PROXY_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/{for(i=1;i<=NF;i++) if($i=="src"){print $(i+1);exit}}' || true)"
  prompt_var PROXY_IP "IP этого сервера" "$PROXY_IP"
  prompt_var SSH_PORT "SSH порт" "${SSH_PORT:-22}"
  echo; echo "VPS серверы. Формат: IP:SIP_НОМЕР:SIP_ПАРОЛЬ (через пробел)"
  read -rp "VPS [${VPS_NODES:-}]: " input; [[ -n "$input" ]] && VPS_NODES="$input"
  echo; echo "SIP юзеры. Формат: НОМЕР:ПАРОЛЬ (через пробел)"
  read -rp "Юзеры [${PROXY_USERS:-}]: " input; [[ -n "$input" ]] && PROXY_USERS="$input"
  proxy_save_config
  echo; echo "Готово! Запустите: bash install.sh proxy apply"
}

# ─── Прокси: add-vps ─────────────────────────────────────────────────────────
proxy_cmd_add_vps(){
  need_root; proxy_load_config
  echo; local vps_ip ext pass
  read -rp "IP VPS: " vps_ip
  read -rp "SIP номер: " ext
  read -rp "SIP пароль: " pass
  [[ -n "$vps_ip" && -n "$ext" && -n "$pass" ]] || die "Все поля обязательны"
  VPS_NODES="$(echo "${VPS_NODES:-} ${vps_ip}:${ext}:${pass}" | xargs)"
  echo "${PROXY_USERS:-}" | grep -q "${ext}:" || PROXY_USERS="$(echo "${PROXY_USERS:-} ${ext}:${pass}" | xargs)"
  proxy_save_config
  echo; echo "WireGuard публичный ключ прокси:"
  [[ -f /etc/wireguard/proxy_public.key ]] && cat /etc/wireguard/proxy_public.key || echo "(запустите apply сначала)"
  echo
  echo "Теперь на VPS ${vps_ip} выполните:"
  local idx=1 e; for e in ${VPS_NODES:-}; do
    [[ "$(echo "$e" | cut -d: -f1)" == "$vps_ip" ]] && break; idx=$((idx+1))
  done
  local wg_vps_ip="${WG_SUBNET}.$((idx+1))"
  echo "  bash install.sh vps-setup-proxy \\"
  echo "    --proxy-ip ${PROXY_IP} \\"
  echo "    --proxy-pubkey <КЛЮЧ_ВЫШЕ> \\"
  echo "    --wg-vps-ip ${wg_vps_ip}"
  echo
  read -rp "Публичный ключ VPS (или Enter чтобы пропустить): " pubkey
  if [[ -n "$pubkey" ]]; then
    echo "$pubkey" > "/etc/wireguard/vps_${vps_ip//./_}_public.key"
    proxy_main_apply
  else
    echo "Позже: bash install.sh proxy add-vps-key ${vps_ip} <КЛЮЧ>"
  fi
}

# ─── Прокси: add-vps-key ─────────────────────────────────────────────────────
proxy_cmd_add_vps_key(){
  need_root; proxy_load_config
  local vps_ip="${1:-}" pubkey="${2:-}"
  [[ -n "$vps_ip" && -n "$pubkey" ]] || die "Использование: bash install.sh proxy add-vps-key <IP> <PUBKEY>"
  mkdir -p /etc/wireguard
  echo "$pubkey" > "/etc/wireguard/vps_${vps_ip//./_}_public.key"
  log "Ключ сохранён для ${vps_ip}"
  proxy_setup_wireguard
  log "WireGuard обновлён"
}

# ─── Прокси: remove-vps ──────────────────────────────────────────────────────
proxy_cmd_remove_vps(){
  need_root; proxy_load_config
  echo; echo "Текущие VPS:"
  local idx=0 entry
  for entry in ${VPS_NODES:-}; do
    idx=$((idx+1))
    echo "  ${idx}) $(echo "$entry" | cut -d: -f1)  SIP: $(echo "$entry" | cut -d: -f2)"
  done
  [[ "$idx" -eq 0 ]] && { echo "Нет VPS."; return 0; }
  read -rp "IP для удаления: " del_ip; [[ -n "$del_ip" ]] || return 0
  local new_nodes="" del_ext=""
  for entry in ${VPS_NODES:-}; do
    local ip; ip="$(echo "$entry" | cut -d: -f1)"
    [[ "$ip" == "$del_ip" ]] && { del_ext="$(echo "$entry" | cut -d: -f2)"; continue; }
    new_nodes="$(echo "${new_nodes} ${entry}" | xargs)"
  done
  VPS_NODES="${new_nodes:-}"
  local new_users=""
  for entry in ${PROXY_USERS:-}; do
    [[ "$(echo "$entry" | cut -d: -f1)" == "$del_ext" ]] && continue
    new_users="$(echo "${new_users} ${entry}" | xargs)"
  done
  PROXY_USERS="${new_users:-}"
  rm -f "/etc/wireguard/vps_${del_ip//./_}_public.key"
  proxy_save_config
  proxy_main_apply
  echo "✓ Удалён: ${del_ip}"
}

# ─── Прокси: list ────────────────────────────────────────────────────────────
proxy_cmd_list(){
  need_root; proxy_load_config
  echo; echo "PROXY_IP: ${PROXY_IP:-}"
  echo "WireGuard: ${WG_PROXY_IP} порт ${WG_PORT}"
  [[ -f /etc/wireguard/proxy_public.key ]] && echo "Публичный ключ: $(cat /etc/wireguard/proxy_public.key)"
  echo; echo "VPS:"
  local idx=1 entry
  for entry in ${VPS_NODES:-}; do
    local ip ext kf wg_ip
    ip="$(echo "$entry" | cut -d: -f1)"; ext="$(echo "$entry" | cut -d: -f2)"
    wg_ip="${WG_SUBNET}.$((idx+1))"
    kf="/etc/wireguard/vps_${ip//./_}_public.key"
    local ks="⚠ ключ не загружен"; [[ -f "$kf" ]] && ks="✓"
    echo "  ${idx}) ${ip} → ${wg_ip}  SIP: ${ext}  [${ks}]"
    idx=$((idx+1))
  done
  echo; echo "SIP юзеры (Server=${PROXY_IP:-?}):"
  for entry in ${PROXY_USERS:-}; do
    echo "  User: $(echo "$entry" | cut -d: -f1)  Pass: $(echo "$entry" | cut -d: -f2)"
  done
  echo; echo "Статус:"
  systemctl is-active --quiet kamailio && echo "  Kamailio: ✓" || echo "  Kamailio: ✗"
  systemctl is-active "wg-quick@${WG_INTERFACE}" 2>/dev/null && echo "  WireGuard: ✓" || echo "  WireGuard: ✗"
}

# ─── Прокси: меню ────────────────────────────────────────────────────────────
proxy_cmd_menu(){
  need_root
  while true; do
    echo; echo "======= Прокси Меню ======="
    echo "1) Показать конфиг и статус"
    echo "2) Добавить VPS"
    echo "3) Удалить VPS"
    echo "4) Применить изменения"
    echo "5) Мастер настройки"
    echo "6) Добавить WireGuard ключ VPS"
    echo "0) Назад"
    echo "==========================="
    read -rp "Выберите: " c
    case "${c:-}" in
      1) proxy_cmd_list ;;
      2) proxy_cmd_add_vps ;;
      3) proxy_cmd_remove_vps ;;
      4) proxy_main_apply ;;
      5) proxy_cmd_wizard ;;
      6) read -rp "IP VPS: " vi; read -rp "Публичный ключ: " pk; proxy_cmd_add_vps_key "$vi" "$pk" ;;
      0) break ;;
    esac
  done
}

# ─── Прокси: apply ───────────────────────────────────────────────────────────
proxy_main_apply(){
  need_root; detect_os; proxy_load_config
  [[ -n "$PROXY_IP" ]]    || die "PROXY_IP не задан"
  [[ -n "$VPS_NODES" ]]   || die "VPS_NODES не заданы"
  [[ -n "$PROXY_USERS" ]] || die "PROXY_USERS не заданы"
  log "=== Установка Kamailio прокси ==="
  use_yandex_mirror
  proxy_ensure_packages
  proxy_ensure_ufw
  proxy_setup_wireguard
  proxy_create_databases
  proxy_generate_cfg
  proxy_start
  proxy_save_config
  echo
  echo "============================================================"
  echo "ПРОКСИ ГОТОВ: ${PROXY_IP}:5060"
  echo
  for entry in ${PROXY_USERS:-}; do
    echo "  Server: ${PROXY_IP}  User: $(echo "$entry"|cut -d: -f1)  Pass: $(echo "$entry"|cut -d: -f2)"
  done
  echo "WireGuard публичный ключ:"
  [[ -f /etc/wireguard/proxy_public.key ]] && echo "  $(cat /etc/wireguard/proxy_public.key)"
  echo "============================================================"
}

# =============================================================================
# VPS → настройка под прокси (выполняется на VPS)
# =============================================================================
vps_setup_proxy(){
  need_root; detect_os
  local proxy_ip="" proxy_pubkey="" wg_vps_ip="" wg_proxy_ip="10.10.0.1" wg_port="51820"
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --proxy-ip)     proxy_ip="$2";     shift 2 ;;
      --proxy-pubkey) proxy_pubkey="$2"; shift 2 ;;
      --wg-vps-ip)    wg_vps_ip="$2";   shift 2 ;;
      --wg-proxy-ip)  wg_proxy_ip="$2"; shift 2 ;;
      --wg-port)      wg_port="$2";     shift 2 ;;
      *) die "Неизвестный параметр: $1" ;;
    esac
  done
  if [[ -z "$proxy_ip" ]]; then
    echo "=== Настройка VPS для Kamailio прокси ==="; echo
    read -rp "IP прокси: " proxy_ip
    read -rp "Публичный ключ прокси: " proxy_pubkey
    read -rp "WireGuard IP для этого VPS (напр: 10.10.0.2): " wg_vps_ip
    read -rp "WireGuard IP прокси [10.10.0.1]: " inp; [[ -n "$inp" ]] && wg_proxy_ip="$inp"
  fi
  [[ -n "$proxy_ip" && -n "$proxy_pubkey" && -n "$wg_vps_ip" ]] || die "Не все параметры заданы"

  # WireGuard
  log "Устанавливаю WireGuard..."
  ensure_packages wireguard
  mkdir -p /etc/wireguard; chmod 700 /etc/wireguard
  if [[ ! -f /etc/wireguard/vps_private.key ]]; then
    wg genkey | tee /etc/wireguard/vps_private.key | wg pubkey > /etc/wireguard/vps_public.key
    chmod 600 /etc/wireguard/vps_private.key
  fi
  local vps_priv; vps_priv="$(cat /etc/wireguard/vps_private.key)"
  local vps_pubkey; vps_pubkey="$(cat /etc/wireguard/vps_public.key)"
  cat > /etc/wireguard/wg0.conf << EOF
[Interface]
Address = ${wg_vps_ip}/24
PrivateKey = ${vps_priv}
ListenPort = ${wg_port}

[Peer]
PublicKey = ${proxy_pubkey}
AllowedIPs = ${wg_proxy_ip}/32
Endpoint = ${proxy_ip}:${wg_port}
PersistentKeepalive = 25
EOF
  chmod 600 /etc/wireguard/wg0.conf
  systemctl enable wg-quick@wg0 >/dev/null 2>&1 || true
  systemctl restart wg-quick@wg0 2>/dev/null || wg-quick up wg0 2>/dev/null || true
  sleep 2; ip addr show wg0 >/dev/null 2>&1 && log "WireGuard запущен: ${wg_vps_ip}" || warn "WireGuard не запустился"

  # Определить имя транка
  local trunk="exolve"
  [[ -f /etc/asterisk/install.env ]] && trunk="$(grep '^TRUNKS=' /etc/asterisk/install.env | cut -d'"' -f2 | awk '{print $1}')" || true

  # Отключить chan_sip
  local cs="/usr/lib/x86_64-linux-gnu/asterisk/modules/chan_sip.so"
  [[ -f "$cs" ]] && mv "$cs" "${cs}.disabled" && log "chan_sip.so отключён" || true

  # proxy-in endpoint
  local users_file="/etc/asterisk/pjsip_users.conf"
  if ! grep -q "^\[proxy-in\]" "$users_file" 2>/dev/null; then
    cat >> "$users_file" << EOF

; ===== KAMAILIO PROXY =====
[proxy-in]
type=endpoint
transport=transport-udp-public
context=from-proxy
disallow=all
allow=ulaw
allow=alaw
aors=proxy-in
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
identify_by=ip

[proxy-in]
type=aor
contact=sip:${wg_proxy_ip}:5060
qualify_frequency=0

[proxy-in-identify]
type=identify
endpoint=proxy-in
match=${wg_proxy_ip}
EOF
  fi

  # from-proxy диалплан
  local exts_file="/etc/asterisk/extensions.conf"
  if ! grep -q "^\[from-proxy\]" "$exts_file" 2>/dev/null; then
    cat >> "$exts_file" << EOF

[from-proxy]
exten => _7XXXXXXXXXX,1,NoOp(Kamailio: \${EXTEN})
 same => n,Dial(PJSIP/\${EXTEN}@${trunk},60)
 same => n,Hangup()
exten => _8XXXXXXXXXX,1,Goto(from-proxy,7\${EXTEN:1},1)
exten => _+7XXXXXXXXXX,1,Goto(from-proxy,7\${EXTEN:2},1)
exten => _9XXXXXXXXX,1,Goto(from-proxy,7\${EXTEN},1)
EOF
  fi

  # Перезагрузить Asterisk
  if systemctl is-active --quiet asterisk; then
    asterisk -rx "module reload res_pjsip" 2>/dev/null || true
    asterisk -rx "dialplan reload" 2>/dev/null || true
  else
    systemctl restart asterisk
  fi
  sleep 2

  echo
  echo "============================================================"
  echo "✓ VPS НАСТРОЕН ПОД ПРОКСИ"
  echo "WireGuard IP: ${wg_vps_ip}"
  echo "Публичный ключ VPS: ${vps_pubkey}"
  echo
  echo "На прокси-сервере выполните:"
  echo "  bash install.sh proxy add-vps-key $(hostname -I | awk '{print $1}') ${vps_pubkey}"
  echo "============================================================"
}

# =============================================================================
# Главное меню
# =============================================================================
main_menu(){
  need_root
  while true; do
    echo
    echo "╔══════════════════════════════════════╗"
    echo "║     Универсальный установщик SIP     ║"
    echo "╠══════════════════════════════════════╣"
    echo "║  1) VPS режим (Asterisk + Exolve)    ║"
    echo "║  2) Прокси режим (Kamailio)          ║"
    echo "║  3) Настроить VPS под прокси         ║"
    echo "║  0) Выход                            ║"
    echo "╚══════════════════════════════════════╝"
    read -rp "Выберите: " c
    case "${c:-}" in
      1) vps_cmd_menu ;;
      2) proxy_cmd_menu ;;
      3) vps_setup_proxy ;;
      0) break ;;
    esac
  done
}

# =============================================================================
# Entry point
# =============================================================================
acquire_lock

case "${1:-menu}" in
  menu|"") main_menu ;;

  # VPS режим
  vps)
    case "${2:-menu}" in
      menu)    vps_cmd_menu ;;
      wizard)  need_root; detect_os; vps_cmd_wizard ;;
      apply)   need_root; detect_os; vps_load_config; vps_main_apply ;;
      list)    vps_cmd_list ;;
      *)
        echo "Использование: bash install.sh vps [menu|wizard|apply|list]"
        exit 1 ;;
    esac ;;

  # Прокси режим
  proxy)
    case "${2:-menu}" in
      menu)        proxy_cmd_menu ;;
      wizard)      need_root; detect_os; proxy_cmd_wizard ;;
      apply)       need_root; detect_os; proxy_main_apply ;;
      list)        proxy_cmd_list ;;
      add-vps)     proxy_cmd_add_vps ;;
      remove-vps)  proxy_cmd_remove_vps ;;
      add-vps-key) proxy_cmd_add_vps_key "${3:-}" "${4:-}" ;;
      *)
        echo "Использование: bash install.sh proxy [menu|wizard|apply|list|add-vps|remove-vps|add-vps-key]"
        exit 1 ;;
    esac ;;

  # Настройка VPS под прокси
  vps-setup-proxy)
    shift
    vps_setup_proxy "$@" ;;

  *)
    echo "Использование: bash install.sh [menu|vps|proxy|vps-setup-proxy]"
    exit 1 ;;
esac
