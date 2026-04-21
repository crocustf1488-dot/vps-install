#!/usr/bin/env bash
set -euo pipefail
# =============================================================================
# install.sh — idempotent Asterisk/PJSIP installer + RU menu + users/trunks manager
# Config: /etc/asterisk/install.env (managed block)
# =============================================================================
ASTERISK_VER="${ASTERISK_VER:-21}"
ASTERISK_TARBALL_URL="${ASTERISK_TARBALL_URL:-}"
ALLOW_UPGRADE="${ALLOW_UPGRADE:-0}"
CONFIG_FILE="${CONFIG_FILE:-/etc/asterisk/install.env}"
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
OUTCID="${OUTCID:-79587108569}"
ACTIVE_TRUNK="${ACTIVE_TRUNK:-}"
ENABLE_UFW="${ENABLE_UFW:-1}"
SSH_PORT="${SSH_PORT:-22}"
TRUSTED_SIP_SOURCES="${TRUSTED_SIP_SOURCES:-}"
ENABLE_FAIL2BAN="${ENABLE_FAIL2BAN:-1}"
ENABLE_RECORDING="${ENABLE_RECORDING:-1}"
RECORDING_DAYS="${RECORDING_DAYS:-7}"
ENABLE_BALANCE_CHECK="${ENABLE_BALANCE_CHECK:-1}"
BALANCE_CHECK_INTERVAL="${BALANCE_CHECK_INTERVAL:-5}"
TG_TOKEN="${TG_TOKEN:-}"
TG_CHAT_ID="${TG_CHAT_ID:-}"
DRY_RUN="${DRY_RUN:-0}"
# Если задан — автоматически настроит proxy-in endpoint для Kamailio прокси
PROXY_WG_IP="${PROXY_WG_IP:-}"
# =============================================================================
# Lock
# =============================================================================
LOCKFILE="/var/run/install_sh.lock"
acquire_lock(){
  exec 9>"$LOCKFILE"
  if ! flock -n 9; then
    echo "[X] Скрипт уже запущен (lock: $LOCKFILE). Дождитесь завершения." >&2
    exit 1
  fi
}
# =============================================================================
# Globals
# =============================================================================
NEED_DIALPLAN_RELOAD=0
NEED_PJSIP_RELOAD=0
NEED_SYSTEMD_DAEMON_RELOAD=0
NEED_ASTERISK_RESTART=0
NEED_SAVE_CONFIG=0
APT_UPDATED=0
CHANGES=()
# =============================================================================
# Helpers
# =============================================================================
ts(){ date +%Y%m%d_%H%M%S; }
log(){ echo "[*] $*"; }
warn(){ echo "[!] $*" >&2; }
die(){ echo "[X] $*" >&2; exit 1; }
is_true(){
  case "${1:-0}" in 1|true|TRUE|yes|YES|y|Y) return 0 ;; *) return 1 ;; esac
}
run_cmd(){
  if is_true "$DRY_RUN"; then log "DRY_RUN: $*"; return 0; fi
  eval "$@"
}
need_root(){ [[ "$(id -u)" -eq 0 ]] || die "Run as root."; }
detect_os(){
  [[ -r /etc/os-release ]] || die "Cannot read /etc/os-release"
  . /etc/os-release
  case "${ID:-}" in debian|ubuntu) : ;; *) die "Unsupported OS: ${ID:-unknown}";; esac
  command -v apt-get >/dev/null 2>&1 || die "apt-get not found"
  command -v systemctl >/dev/null 2>&1 || die "systemctl not found"
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
  local b="${f}.bak_$(ts)"
  run_cmd "cp -a \"${f}\" \"${b}\""
  log "Backup: ${b}"
}
is_ipv4(){
  local ip="$1"
  [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
  local IFS=.; local -a o; read -r -a o <<<"$ip"
  local x; for x in "${o[@]}"; do [[ "$x" -ge 0 && "$x" -le 255 ]] || return 1; done
  return 0
}
is_cidr(){
  local v="$1"
  [[ "$v" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}/[0-9]{1,2}$ ]] || return 1
  local ip="${v%/*}" mask="${v#*/}"
  is_ipv4 "$ip" || return 1
  [[ "$mask" -ge 0 && "$mask" -le 32 ]] || return 1
  return 0
}
validate_trusted_sources(){
  [[ -z "${TRUSTED_SIP_SOURCES:-}" ]] && return 0
  local src
  for src in $(normalize_list "$TRUSTED_SIP_SOURCES"); do
    [[ "$src" =~ ^[0-9]+$ ]] && die "TRUSTED_SIP_SOURCES содержит '${src}'. Нужны IP/CIDR, не порт."
    is_ipv4 "$src" || is_cidr "$src" || die "TRUSTED_SIP_SOURCES: некорректное '${src}'."
  done
}
gen_password(){
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 24 | tr -d '\n' | tr '/+=' 'xyz' | cut -c1-28; return 0
  fi
  tr -dc 'A-Za-z0-9_@#%+=-' </dev/urandom 2>/dev/null | head -c 28 || true
}
detect_ip(){
  if [[ -z "${SERVER_IP}" ]]; then
    SERVER_IP="$(ip route get 1.1.1.1 2>/dev/null | awk '/src/ {for(i=1;i<=NF;i++) if($i=="src"){print $(i+1); exit}}' || true)"
    [[ -n "$SERVER_IP" ]] && warn "SERVER_IP autodetected as '${SERVER_IP}'."
  fi
  [[ -n "${SERVER_IP}" ]] || die "SERVER_IP is empty."
  log "Using SERVER_IP=${SERVER_IP}"
}
# =============================================================================
# Multi-Public-IP helpers
# =============================================================================
normalize_public_ips(){
  if [[ -z "${PUBLIC_IPS:-}" ]]; then PUBLIC_IPS="$SERVER_IP"
  else PUBLIC_IPS="$(normalize_list "$PUBLIC_IPS")"; fi
  local first; first="$(echo "$PUBLIC_IPS" | awk '{print $1}')"
  if [[ "$first" != "$SERVER_IP" ]]; then
    if list_contains "$SERVER_IP" "$PUBLIC_IPS"; then
      local rebuilt="" ip; rebuilt+="$SERVER_IP"
      for ip in $PUBLIC_IPS; do [[ "$ip" == "$SERVER_IP" ]] && continue; rebuilt+=" $ip"; done
      PUBLIC_IPS="$(normalize_list "$rebuilt")"
    else PUBLIC_IPS="$(normalize_list "$SERVER_IP $PUBLIC_IPS")"; fi
  fi
  set_var PUBLIC_IPS "$PUBLIC_IPS"
}
validate_public_ips(){
  normalize_public_ips
  local ip
  for ip in $PUBLIC_IPS; do is_ipv4 "$ip" || die "PUBLIC_IPS: некорректный IP '${ip}'"; done
}
# =============================================================================
# Safe env writer
# =============================================================================
env_escape(){
  local s="$1"; s="${s//\\/\\\\}"; s="${s//\"/\\\"}"; printf "%s" "$s"
}
env_append(){
  local -n _b="$1"; local k="$2" v="$3" line
  printf -v line '%s="%s"\n' "$k" "$(env_escape "$v")"; _b+="$line"
}
config_lint(){
  local f="$1"; [[ -f "$f" ]] || return 0
  awk '
    /^[[:space:]]*$/ {next} /^[[:space:]]*#/ {next}
    /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/ {next}
    {bad=1; printf("BAD_LINE:%d:%s\n", NR, $0) > "/dev/stderr"} END{exit bad}
  ' "$f"
}
config_autofix_quote_spaces(){
  local f="$1"; [[ -f "$f" ]] || return 0
  local tmp; tmp="$(mktemp)"
  awk '
    function esc(s){ gsub(/\\/,"\\\\",s); gsub(/"/,"\\\"",s); return s }
    { line=$0
      if (line ~ /^[[:space:]]*($|#)/) { print line; next }
      if (line !~ /^[[:space:]]*[A-Za-z_][A-Za-z0-9_]*=/) { print "# REMOVED_INVALID_LINE: " line; next }
      key=line; sub(/=.*/,"",key); val=substr(line, length(key)+2)
      if (val ~ /^"/ || val ~ /^\047/) { print line; next }
      if (val ~ /[[:space:]]/) { print key "=\"" esc(val) "\""; next }
      print line }
  ' "$f" >"$tmp"
  if ! cmp -s "$tmp" "$f"; then
    if is_true "$DRY_RUN"; then log "DRY_RUN: would auto-fix quoting in $f"; rm -f "$tmp"; return 0; fi
    backup_file "$f"; mv "$tmp" "$f"; log "Auto-fixed quoting in: $f"; return 0
  fi
  rm -f "$tmp"; return 0
}
ensure_config_exists(){
  run_cmd "mkdir -p \"$(dirname "$CONFIG_FILE")\""
  [[ -f "$CONFIG_FILE" ]] || { is_true "$DRY_RUN" || printf "%s\n" "# install.sh config" >"$CONFIG_FILE"; }
}
load_config_file(){
  [[ -f "$CONFIG_FILE" ]] || return 0
  if ! config_lint "$CONFIG_FILE"; then
    warn "Config has invalid lines: $CONFIG_FILE"; warn "Attempting auto-fix..."
    config_autofix_quote_spaces "$CONFIG_FILE"
    config_lint "$CONFIG_FILE" || die "Config still invalid. Fix manually: $CONFIG_FILE"
  fi
  config_autofix_quote_spaces "$CONFIG_FILE"
  . "$CONFIG_FILE"
}
# =============================================================================
# File apply helpers
# =============================================================================
file_apply_if_changed(){
  local file="$1" content="$2" mode="${3:-0644}" owner="${4:-root:root}" reason="${5:-}"
  local tmp; tmp="$(mktemp)"; printf "%s" "$content" >"$tmp"
  local changed=0
  if [[ -f "$file" ]]; then cmp -s "$tmp" "$file" || changed=1; else changed=1; fi
  if [[ "$changed" -eq 1 ]]; then
    [[ -n "$reason" ]] && CHANGES+=("$reason") || CHANGES+=("Updated: $file")
    if is_true "$DRY_RUN"; then log "DRY_RUN: would update file $file"; rm -f "$tmp"; return 0; fi
    backup_file "$file"
    install -m "$mode" -o "${owner%%:*}" -g "${owner##*:}" "$tmp" "$file"
    rm -f "$tmp"; log "Updated: $file"; return 0
  fi
  rm -f "$tmp"; log "No change: $file"; return 1
}
apply_managed_block(){
  local file="$1" marker_name="$2" block_content="$3" comment_prefix="${4:-;}"
  local begin="${comment_prefix} BEGIN MANAGED: ${marker_name}"
  local end="${comment_prefix} END MANAGED: ${marker_name}"
  local new_block="${begin}"$'\n'"${block_content}"$'\n'"${end}"$'\n'
  local current=""; [[ -f "$file" ]] && current="$(cat "$file")"
  local updated=""
  if [[ "$current" == *"$begin"* && "$current" == *"$end"* ]]; then
    updated="$(printf "%s" "$current" | awk -v begin="$begin" -v end="$end" -v nb="$new_block" '
      BEGIN{inblk=0}
      { if ($0==begin){printf "%s", nb; inblk=1; next}
        if ($0==end){inblk=0; next}
        if (!inblk) print $0 }')"
    [[ "$updated" == *$'\n' ]] || updated+=$'\n'
  else
    updated="$current"
    [[ -n "$updated" && "$updated" != *$'\n' ]] && updated+=$'\n'
    updated+=$'\n'"$new_block"
  fi
  local tmp; tmp="$(mktemp)"; printf "%s" "$updated" >"$tmp"
  local changed=0
  if [[ -f "$file" ]]; then cmp -s "$tmp" "$file" || changed=1; else changed=1; fi
  if [[ "$changed" -eq 1 ]]; then
    if is_true "$DRY_RUN"; then log "DRY_RUN: would update managed block '${marker_name}' in $file"; rm -f "$tmp"; return 0; fi
    backup_file "$file"; install -m 0644 -o root -g root "$tmp" "$file"
    rm -f "$tmp"; log "Updated managed block '${marker_name}' in $file"; return 0
  fi
  rm -f "$tmp"; log "No change for managed block '${marker_name}' in $file"; return 1
}
ensure_owner_mode(){
  local path="$1" owner="$2" mode="$3"; [[ -e "$path" ]] || return 0
  local u="${owner%%:*}" g="${owner##*:}"
  local cur_u cur_g cur_mode
  cur_u="$(stat -c '%U' "$path" 2>/dev/null || echo "")"
  cur_g="$(stat -c '%G' "$path" 2>/dev/null || echo "")"
  cur_mode="$(stat -c '%a' "$path" 2>/dev/null || echo "")"
  local want_mode="${mode#0}"
  if [[ "$cur_u" != "$u" || "$cur_g" != "$g" ]]; then
    is_true "$DRY_RUN" && log "DRY_RUN: would chown ${owner} ${path}" || chown "${owner}" "$path"
  fi
  if [[ "$cur_mode" != "$want_mode" ]]; then
    is_true "$DRY_RUN" && log "DRY_RUN: would chmod ${mode} ${path}" || chmod "${mode}" "$path"
  fi
}
# =============================================================================
# Legacy migration
# =============================================================================
migrate_legacy_exolve(){
  if [[ -z "${TRUNKS:-}" && -n "${EXOLVE_NAME:-}" ]]; then TRUNKS="${EXOLVE_NAME}"; NEED_SAVE_CONFIG=1; fi
  local trunk_list t up proxy_var proxy
  trunk_list="$(normalize_list "${TRUNKS:-}")"; [[ -n "$trunk_list" ]] || return 0
  for t in $trunk_list; do
    local up proxy
    up="$(upper_sanitize "$t")"; proxy_var="TRUNK_${up}_PROXY"; proxy="$(get_var "$proxy_var")"
    if [[ -z "$proxy" ]]; then
      if [[ -n "${EXOLVE_PROXY:-}" && ( "$t" == "exolve" || "$t" == "${EXOLVE_NAME:-}" ) ]]; then
        set_var "TRUNK_${up}_PROXY"   "${EXOLVE_PROXY}"
        set_var "TRUNK_${up}_PORT"    "${EXOLVE_PORT:-5060}"
        set_var "TRUNK_${up}_MATCHES" "${EXOLVE_MATCHES:-}"
        set_var "TRUNK_${up}_OUTCID"  "${OUTCID:-}"
        set_var "TRUNK_${up}_CONTEXT" "from-exolve"
        set_var "TRUNK_${up}_BIND_IP" "${SERVER_IP}"
        CHANGES+=("Migrated legacy EXOLVE_* -> TRUNK_${up}_*"); NEED_SAVE_CONFIG=1
      fi
    fi
  done
}
# =============================================================================
# Packages / Asterisk — APT INSTALL (быстро, ~1-2 мин вместо 15)
# =============================================================================
ensure_packages(){
  local pkgs=("$@") missing=() p
  for p in "${pkgs[@]}"; do dpkg -s "$p" >/dev/null 2>&1 || missing+=("$p"); done
  [[ "${#missing[@]}" -eq 0 ]] && { log "Packages: OK"; return 0; }
  log "Installing packages: ${missing[*]}"
  if is_true "$DRY_RUN"; then log "DRY_RUN: would apt-get install -y ${missing[*]}"; return 0; fi
  if [[ "$APT_UPDATED" -eq 0 ]]; then
    apt-get update -q
    APT_UPDATED=1
  fi
  DEBIAN_FRONTEND=noninteractive apt-get install -y "${missing[@]}"
}

ensure_asterisk_installed(){
  # ── Быстрая установка через apt ──────────────────────────────────────────
  # Намного быстрее чем сборка из исходников (1-2 мин vs 15 мин).
  # Устанавливает Asterisk из официальных репозиториев Ubuntu/Debian.
  # Для PJSIP нужен пакет asterisk-modules (входит в зависимости).
  # ─────────────────────────────────────────────────────────────────────────
  if dpkg -s asterisk >/dev/null 2>&1; then
    local cur_v
    cur_v="$(asterisk -V 2>/dev/null | awk '{print $2}' | head -n1 || true)"
    log "Asterisk уже установлен: ${cur_v}"
    return 0
  fi

  log "Устанавливаю Asterisk через apt (быстро)..."
  is_true "$DRY_RUN" && { log "DRY_RUN: would apt-get install asterisk"; return 0; }

  if [[ "$APT_UPDATED" -eq 0 ]]; then
    apt-get update -q
    APT_UPDATED=1
  fi

  DEBIAN_FRONTEND=noninteractive apt-get install -y \
    asterisk \
    asterisk-modules \
    asterisk-config

  # Убедиться что chan_pjsip и res_pjsip загружаются
  local modules_conf="/etc/asterisk/modules.conf"
  if [[ -f "$modules_conf" ]]; then
    # Убираем noload для pjsip если он там есть
    sed -i '/noload.*chan_pjsip/d'   "$modules_conf" 2>/dev/null || true
    sed -i '/noload.*res_pjsip/d'    "$modules_conf" 2>/dev/null || true
    sed -i '/noload.*res_pjsip_/d'   "$modules_conf" 2>/dev/null || true
  fi

  # ── Отключить chan_sip — ОБЯЗАТЕЛЬНО для работы PJSIP ──────────────────────
  # chan_sip перехватывает UDP пакеты и мешает res_pjsip обрабатывать входящие.
  # Физическое удаление .so файла — единственный надёжный способ.
  local chan_sip_so="/usr/lib/x86_64-linux-gnu/asterisk/modules/chan_sip.so"
  if [[ -f "$chan_sip_so" ]]; then
    mv "$chan_sip_so" "${chan_sip_so}.disabled"
    log "chan_sip.so отключён (переименован в .disabled)"
  fi

  CHANGES+=("Installed Asterisk via apt")
  CHANGES+=("Disabled chan_sip.so")
  NEED_ASTERISK_RESTART=1
  log "Asterisk установлен через apt: $(asterisk -V 2>/dev/null || true)"
}

asterisk_installed_version(){
  command -v asterisk >/dev/null 2>&1 || { echo ""; return 0; }
  asterisk -V 2>/dev/null | awk '{print $2}' | head -n1 || true
}
# =============================================================================
# System user/dirs, systemd, firewall, fail2ban
# =============================================================================
ensure_user_and_dirs(){
  if ! id asterisk >/dev/null 2>&1; then
    log "Creating user/group 'asterisk'..."
    run_cmd "adduser --system --group --home /var/lib/asterisk --no-create-home asterisk"
    CHANGES+=("Created user: asterisk")
  fi
  run_cmd "mkdir -p /var/lib/asterisk /var/log/asterisk /var/log/asterisk/cdr-csv /var/spool/asterisk /var/run/asterisk /etc/asterisk"
  ensure_owner_mode /var/lib/asterisk         asterisk:asterisk 0755
  ensure_owner_mode /var/log/asterisk         asterisk:asterisk 0755
  ensure_owner_mode /var/log/asterisk/cdr-csv asterisk:asterisk 0750
  ensure_owner_mode /var/spool/asterisk       asterisk:asterisk 0755
  ensure_owner_mode /var/run/asterisk         asterisk:asterisk 0755
  ensure_owner_mode /etc/asterisk             asterisk:asterisk 0755
}
ensure_systemd_unit(){
  local unit=/etc/systemd/system/asterisk.service
  local content
  content="$(cat <<'EOF'
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
NoNewPrivileges=true
PrivateTmp=true
[Install]
WantedBy=multi-user.target
EOF
)"
  if file_apply_if_changed "$unit" "$content" 0644 root:root "Updated systemd unit: asterisk.service"; then
    NEED_SYSTEMD_DAEMON_RELOAD=1; NEED_ASTERISK_RESTART=1
  fi
  [[ "$NEED_SYSTEMD_DAEMON_RELOAD" -eq 1 ]] && run_cmd "systemctl daemon-reload"
  run_cmd "systemctl enable asterisk >/dev/null 2>&1 || true"
}
ufw_rule_has(){ ufw status 2>/dev/null | grep -Eq "$1"; }
ensure_ufw_rules(){
  is_true "$ENABLE_UFW" || { log "Skipping UFW (ENABLE_UFW=0)"; return 0; }
  validate_trusted_sources; ensure_packages ufw
  is_true "$DRY_RUN" && log "DRY_RUN: would enable ufw" || ufw --force enable >/dev/null || true
  if ! ufw_rule_has "${SSH_PORT}/tcp"; then
    log "UFW: allow ${SSH_PORT}/tcp"
    run_cmd "ufw allow ${SSH_PORT}/tcp >/dev/null"; CHANGES+=("UFW allow ${SSH_PORT}/tcp")
  fi
  if ! ufw_rule_has "5061/udp"; then
    log "UFW: allow 5061/udp (trunk transport)"
    run_cmd "ufw allow 5061/udp >/dev/null"; CHANGES+=("UFW allow 5061/udp (trunk)")
  fi
  if ! ufw_rule_has "10000:20000/udp"; then
    log "UFW: allow 10000-20000/udp (RTP)"
    run_cmd "ufw allow 10000:20000/udp >/dev/null"; CHANGES+=("UFW allow 10000-20000/udp")
  fi
  if [[ -n "${TRUSTED_SIP_SOURCES:-}" ]]; then
    local src
    for src in $(normalize_list "$TRUSTED_SIP_SOURCES"); do
      if ufw status 2>/dev/null | grep -qE "5060/udp.*${src}"; then
        log "UFW: SIP rule exists for ${src}"
      else
        log "UFW: allow 5060/udp from ${src}"
        run_cmd "ufw allow from ${src} to any port 5060 proto udp >/dev/null"
        CHANGES+=("UFW allow 5060/udp from ${src}")
      fi
    done
  else
    if ! ufw_rule_has "5060/udp"; then
      log "UFW: allow 5060/udp"
      run_cmd "ufw allow 5060/udp >/dev/null"; CHANGES+=("UFW allow 5060/udp (any)")
    fi
  fi
}
ensure_fail2ban(){
  is_true "$ENABLE_FAIL2BAN" || { log "Skipping fail2ban (ENABLE_FAIL2BAN=0)"; return 0; }
  ensure_packages fail2ban
  local jail_file="/etc/fail2ban/jail.d/asterisk-pbx.conf"
  local jail_content="[asterisk]
enabled  = true
port     = 5060
protocol = udp
filter   = asterisk
logpath  = /var/log/asterisk/messages.log
maxretry = 5
findtime = 300
bantime  = 86400
backend  = auto
[asterisk-tcp]
enabled  = true
port     = 5060
protocol = tcp
filter   = asterisk
logpath  = /var/log/asterisk/messages.log
maxretry = 5
findtime = 300
bantime  = 86400
backend  = auto"
  if [[ ! -f "$jail_file" ]] || ! grep -q "asterisk-pbx\|asterisk-tcp" "$jail_file" 2>/dev/null; then
    echo "$jail_content" > "$jail_file"
    CHANGES+=("Fail2ban asterisk jail configured")
  fi
  local ast_log="/etc/asterisk/logger.conf"
  if [[ -f "$ast_log" ]] && ! grep -q "^messages" "$ast_log"; then
    echo "messages => notice,warning,error" >> "$ast_log"
    NEED_ASTERISK_RESTART=1
    CHANGES+=("Asterisk logger: messages enabled")
  fi
  run_cmd "systemctl enable --now fail2ban >/dev/null 2>&1 || true"
  run_cmd "systemctl restart fail2ban >/dev/null 2>&1 || true"
  CHANGES+=("Fail2ban installed/enabled")
}
# =============================================================================
# Recording
# =============================================================================
ensure_recording(){
  is_true "$ENABLE_RECORDING" || { log "Skipping recording (ENABLE_RECORDING=0)"; return 0; }
  log "Setting up call recording..."
  ensure_packages lame
  run_cmd "mkdir -p /var/spool/asterisk/monitor"
  ensure_owner_mode /var/spool/asterisk/monitor asterisk:asterisk 0755
  local cron_file=/etc/cron.d/asterisk-recording-cleanup
  local cron_content
  cron_content="# Delete recordings older than ${RECORDING_DAYS} days
0 3 * * * root find /var/spool/asterisk/monitor -name '*.mp3' -mtime +${RECORDING_DAYS} -delete 2>/dev/null; find /var/spool/asterisk/monitor -name '*.wav' -mtime +${RECORDING_DAYS} -delete 2>/dev/null
"
  if file_apply_if_changed "$cron_file" "$cron_content" 0644 root:root "Updated recording cron"; then
    CHANGES+=("Recording cleanup: keep ${RECORDING_DAYS} days")
  fi
  CHANGES+=("Recording enabled: /var/spool/asterisk/monitor/")
}
# =============================================================================
# Balance check
# =============================================================================
ensure_balance_check(){
  is_true "$ENABLE_BALANCE_CHECK" || { log "Skipping balance check (ENABLE_BALANCE_CHECK=0)"; return 0; }
  [[ -n "$TG_TOKEN" && -n "$TG_CHAT_ID" ]] || { log "Skipping balance check (TG_TOKEN/TG_CHAT_ID not set)"; return 0; }
  local script_file=/usr/local/bin/asterisk-balance-check.sh
  local cron_file=/etc/cron.d/asterisk-balance-check
  local trunk; trunk="$(normalize_list "$TRUNKS" | awk '{print $1}')"
  local up; up="$(upper_sanitize "$trunk")"
  local proxy; proxy="$(get_var "TRUNK_${up}_PROXY")"
  local interval="${BALANCE_CHECK_INTERVAL:-5}"
  if [[ ! -f "$script_file" ]] || ! grep -q "auto-generated-balance-check" "$script_file" 2>/dev/null; then
    cat > "$script_file" <<SCRIPT
#!/usr/bin/env bash
# auto-generated-balance-check
TG_TOKEN="${TG_TOKEN}"
TG_CHAT_ID="${TG_CHAT_ID}"
PROXY="${proxy}"
LABEL="\$(grep ^SERVER_LABEL= /etc/asterisk/install.env 2>/dev/null | cut -d= -f2 || hostname)"
LOG=/var/log/asterisk/balance-check.log
ALERT_FILE=/tmp/balance-alert-sent
if tail -n 200 /var/log/asterisk/messages.log 2>/dev/null | grep -qiE "403.*\${PROXY}|503.*\${PROXY}|\${PROXY}.*403|\${PROXY}.*503"; then
  if [[ ! -f "\${ALERT_FILE}" ]] || [[ -n "\$(find "\${ALERT_FILE}" -mmin +60 2>/dev/null)" ]]; then
    MSG="\$(printf '\xf0\x9f\x92\xb3') <b>Возможно кончился баланс!</b>%0ASервер: <b>\${LABEL}</b>%0AПрокси: <code>\${PROXY}</code>"
    curl -s -X POST "https://api.telegram.org/bot\${TG_TOKEN}/sendMessage" \
      -d "chat_id=\${TG_CHAT_ID}&text=\${MSG}&parse_mode=HTML" >/dev/null 2>&1
    touch "\${ALERT_FILE}"
    echo "\$(date): Sent balance alert" >> "\${LOG}"
  fi
else
  rm -f "\${ALERT_FILE}"
fi
SCRIPT
    chmod 0755 "$script_file"
    CHANGES+=("Balance check script: $script_file")
  fi
  local cron_content="*/${interval} * * * * root bash ${script_file} 2>/dev/null
"
  if file_apply_if_changed "$cron_file" "$cron_content" 0644 root:root "Updated balance check cron"; then
    CHANGES+=("Balance check cron: every ${interval} min")
  fi
}
# =============================================================================
# Asterisk configs
# =============================================================================
infer_matches(){
  local proxy="$1" matches="$2"
  [[ -n "$matches" ]] && { echo "$matches"; return 0; }
  is_ipv4 "$proxy" && { echo "${proxy}/32"; return 0; }
  echo ""
}
ensure_trunk_active_conf(){
  local f=/etc/asterisk/trunk_active.conf
  [[ -f "$f" ]] || { run_cmd "touch \"$f\""; CHANGES+=("Created: $f"); }
  if ! grep -q '^\[globals\]' "$f" 2>/dev/null; then
    if is_true "$DRY_RUN"; then log "DRY_RUN: would prepend [globals] to $f"
    else
      backup_file "$f"
      { printf "%s\n" "[globals]"; cat "$f"; } >"${f}.tmp"; mv "${f}.tmp" "$f"
    fi
    CHANGES+=("Fixed: [globals] in trunk_active.conf")
  fi
  local desired="$ACTIVE_TRUNK"
  [[ -z "$desired" ]] && desired="$(awk -F= '/^TRUNK=/{print $2; exit}' "$f" 2>/dev/null || true)"
  [[ -z "$desired" ]] && desired="$(normalize_list "$TRUNKS" | awk '{print $1}')"
  local block
  block="$(cat <<EOF
[globals]
TRUNK=${desired}
OUTCID=${OUTCID}
EOF
)"
  apply_managed_block "$f" "TRUNK_GLOBALS" "$block" ";" && NEED_DIALPLAN_RELOAD=1 || true
  ensure_owner_mode "$f" asterisk:asterisk 0644
}
ensure_asterisk_configs(){
  local pjsip=/etc/asterisk/pjsip.conf
  local trunks_file=/etc/asterisk/pjsip_trunks.conf
  local users_file=/etc/asterisk/pjsip_users.conf
  local exts=/etc/asterisk/extensions.conf
  [[ -f "$pjsip" ]]       || { run_cmd "touch \"$pjsip\"";       CHANGES+=("Created: $pjsip"); }
  [[ -f "$trunks_file" ]] || { run_cmd "touch \"$trunks_file\""; CHANGES+=("Created: $trunks_file"); }
  [[ -f "$users_file" ]]  || { run_cmd "touch \"$users_file\"";  CHANGES+=("Created: $users_file"); }
  [[ -f "$exts" ]]        || { run_cmd "touch \"$exts\"";        CHANGES+=("Created: $exts"); }
  validate_public_ips
  local transports_block=""
  transports_block+="[transport-udp-public]"$'\n'
  transports_block+="type=transport"$'\n'
  transports_block+="protocol=udp"$'\n'
  transports_block+="bind=0.0.0.0:5060"$'\n'
  transports_block+="external_signaling_address=${SERVER_IP}"$'\n'
  transports_block+="external_media_address=${SERVER_IP}"$'\n'
  transports_block+="local_net=10.0.0.0/8"$'\n'
  transports_block+="local_net=172.16.0.0/12"$'\n'
  transports_block+="local_net=192.168.0.0/16"$'\n'
  transports_block+=$'\n'
  local idx=0 ip tname
  for ip in $PUBLIC_IPS; do
    idx=$((idx+1))
    if [[ "$idx" -eq 1 ]]; then tname="transport-udp-trunk"
    else tname="transport-udp-trunk${idx}"; fi
    transports_block+="[${tname}]"$'\n'
    transports_block+="type=transport"$'\n'
    transports_block+="protocol=udp"$'\n'
    transports_block+="bind=${ip}:5061"$'\n'
    transports_block+="external_signaling_address=${ip}"$'\n'
    transports_block+="external_media_address=${ip}"$'\n'
    transports_block+="local_net=10.0.0.0/8"$'\n'
    transports_block+="local_net=172.16.0.0/12"$'\n'
    transports_block+="local_net=192.168.0.0/16"$'\n'
    transports_block+=$'\n'
  done
  if apply_managed_block "$pjsip" "TRANSPORTS" "$transports_block" ";"; then
    NEED_PJSIP_RELOAD=1; NEED_ASTERISK_RESTART=1
  fi
  local include_block
  include_block="$(cat <<'EOF'
; Installer keeps trunks/users in separate files:
#include "pjsip_trunks.conf"
#include "pjsip_users.conf"
EOF
)"
  apply_managed_block "$pjsip" "INCLUDES" "$include_block" ";" && NEED_PJSIP_RELOAD=1 || true
  ensure_owner_mode "$pjsip" asterisk:asterisk 0644
  local trunk_list user_list
  trunk_list="$(normalize_list "$TRUNKS")"
  user_list="$(normalize_list "$USERS")"
  local t
  for t in $trunk_list; do
    local up proxy port matches outcid context bind_ip trunk_transport
    up="$(upper_sanitize "$t")"
    proxy="$(get_var "TRUNK_${up}_PROXY")"
    port="$(get_var "TRUNK_${up}_PORT")"; [[ -n "$port" ]] || port="5060"
    matches="$(get_var "TRUNK_${up}_MATCHES")"
    outcid="$(get_var "TRUNK_${up}_OUTCID")"
    context="$(get_var "TRUNK_${up}_CONTEXT")"; [[ -n "$context" ]] || context="from-${t}"
    bind_ip="$(get_var "TRUNK_${up}_BIND_IP")"; [[ -n "$bind_ip" ]] || bind_ip="$SERVER_IP"
    is_ipv4 "$bind_ip" || die "TRUNK_${up}_BIND_IP must be IPv4 (got: '$bind_ip')"
    list_contains "$bind_ip" "$PUBLIC_IPS" || die "TRUNK_${up}_BIND_IP='$bind_ip' not in PUBLIC_IPS='$PUBLIC_IPS'"
    [[ -n "$proxy" ]] || die "Missing TRUNK_${up}_PROXY for trunk '${t}'"
    trunk_transport="transport-udp-trunk"
    local cidx=0 cur_ip
    for cur_ip in $PUBLIC_IPS; do
      cidx=$((cidx+1))
      if [[ "$cur_ip" == "$bind_ip" ]]; then
        if [[ "$cidx" -eq 1 ]]; then trunk_transport="transport-udp-trunk"
        else trunk_transport="transport-udp-trunk${cidx}"; fi
        break
      fi
    done
    local from_user_line=""
    [[ -n "$outcid" ]] && from_user_line="from_user=${outcid}"
    local inf identify_block
    inf="$(infer_matches "$proxy" "$matches")"; identify_block=""
    if [[ -n "$inf" ]]; then
      local mlines="" m
      for m in $(normalize_list "$inf"); do mlines+="match=${m}"$'\n'; done
      identify_block="$(cat <<EOF
[${t}-identify]
type=identify
endpoint=${t}
${mlines%$'\n'}
EOF
)"
    fi
    local trunk_block
    trunk_block="$(cat <<EOF
; ===== TRUNK: ${t} =====
[${t}]
type=endpoint
transport=${trunk_transport}
context=${context}
disallow=all
allow=ulaw
allow=alaw
aors=${t}
outbound_proxy=sip:${proxy}:${port}\;lr
from_domain=${proxy}
${from_user_line}
send_pai=yes
trust_id_outbound=yes
direct_media=no
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
[${t}]
type=aor
contact=sip:${proxy}:${port}
qualify_frequency=60
${identify_block}
EOF
)"
    apply_managed_block "$trunks_file" "TRUNK_${t}" "$trunk_block" ";" && NEED_PJSIP_RELOAD=1 || true
  done
  ensure_owner_mode "$trunks_file" asterisk:asterisk 0644
  local u
  for u in $user_list; do
    [[ "$u" =~ ^[0-9]+$ ]] || die "User '${u}' must be numeric extension"
    local pass; pass="$(get_var "USER_${u}_PASS")"
    [[ -n "$pass" ]] || die "Missing USER_${u}_PASS for user '${u}'"
    local maxc remove_existing
    maxc="$(get_var "USER_${u}_MAX_CONTACTS")"; [[ -n "$maxc" ]] || maxc="$DEFAULT_MAX_CONTACTS"
    [[ "$maxc" =~ ^[0-9]+$ ]] || die "USER_${u}_MAX_CONTACTS must be numeric"
    remove_existing="$(get_var "USER_${u}_REMOVE_EXISTING")"; [[ -n "$remove_existing" ]] || remove_existing="$DEFAULT_REMOVE_EXISTING"
    local user_block
    user_block="$(cat <<EOF
; ===== LOCAL SIP USER ${u} =====
[${u}]
type=endpoint
transport=transport-udp-public
context=from-internal-${u}
disallow=all
allow=ulaw
allow=alaw
auth=${u}
aors=${u}
rtp_symmetric=yes
force_rport=yes
rewrite_contact=yes
direct_media=no
[${u}]
type=auth
auth_type=userpass
username=${u}
password=${pass}
[${u}]
type=aor
max_contacts=${maxc}
remove_existing=${remove_existing}
qualify_frequency=0
EOF
)"
    apply_managed_block "$users_file" "USER_${u}" "$user_block" ";" && NEED_PJSIP_RELOAD=1 || true
  done
  ensure_owner_mode "$users_file" asterisk:asterisk 0644
  local internal_dials=""
  for u in $user_list; do
    internal_dials+="exten => ${u},1,Dial(PJSIP/${u},30)"$'\n'
    internal_dials+=" same => n,Hangup()"$'\n'
  done
  local per_user_contexts=""
  for u in $user_list; do
    local trunk outcid
    trunk="$(get_var "USER_${u}_TRUNK")"; [[ -n "$trunk" ]] || trunk="active"
    outcid="$(get_var "USER_${u}_OUTCID")"
    local dial_target="" noop_trunk="" cid_set=""
    if [[ -n "$outcid" ]]; then cid_set=" same => n,Set(CALLERID(all)=${outcid})"$'\n'; fi
    if [[ "$trunk" == "active" ]]; then
      noop_trunk='${TRUNK}'; dial_target='PJSIP/${EXTEN}@${TRUNK}'
      [[ -z "$outcid" ]] && cid_set=" same => n,Set(CALLERID(all)=\${OUTCID})"$'\n'
    else
      noop_trunk="$trunk"; dial_target="PJSIP/\${EXTEN}@${trunk}"
      if [[ -z "$outcid" ]]; then
        local up_t trunk_outcid; up_t="$(upper_sanitize "$trunk")"
        trunk_outcid="$(get_var "TRUNK_${up_t}_OUTCID")"
        [[ -n "$trunk_outcid" ]] && cid_set=" same => n,Set(CALLERID(all)=${trunk_outcid})"$'\n'
      fi
    fi
    per_user_contexts+=$'\n'"[from-internal-${u}]"$'\n'
    per_user_contexts+=$internal_dials$'\n'
    per_user_contexts+="exten => _7XXXXXXXXXX,1,NoOp(Outgoing via ${noop_trunk} for ${u})"$'\n'
    per_user_contexts+="${cid_set}"
    if is_true "$ENABLE_RECORDING"; then
      per_user_contexts+=" same => n,MixMonitor(/var/spool/asterisk/monitor/\${STRFTIME(\${EPOCH},,\%Y\%m\%d-\%H\%M\%S)}-\${EXTEN}-out-${u}.wav,b,/usr/bin/lame -b 64 \${MONITOR_FILENAME} \${MONITOR_FILENAME:0:-4}.mp3 && rm -f \${MONITOR_FILENAME})"$'\n'
    fi
    per_user_contexts+=" same => n,Dial(${dial_target},60)"$'\n'
    per_user_contexts+=" same => n,Hangup()"$'\n'
  done
  local incoming_ctxs="" first_user
  first_user="$(echo "$user_list" | awk '{print $1}')"
  for t in $trunk_list; do
    local up ctx; up="$(upper_sanitize "$t")"
    ctx="$(get_var "TRUNK_${up}_CONTEXT")"; [[ -n "$ctx" ]] || ctx="from-${t}"
    incoming_ctxs+=$'\n'"[${ctx}]"$'\n'
    incoming_ctxs+="exten => _X.,1,NoOp(Incoming from trunk ${t})"$'\n'
    if is_true "$ENABLE_RECORDING"; then
      incoming_ctxs+=" same => n,MixMonitor(/var/spool/asterisk/monitor/\${STRFTIME(\${EPOCH},,\%Y\%m\%d-\%H\%M\%S)}-\${EXTEN}-in.wav,b,/usr/bin/lame -b 64 \${MONITOR_FILENAME} \${MONITOR_FILENAME:0:-4}.mp3 && rm -f \${MONITOR_FILENAME})"$'\n'
    fi
    incoming_ctxs+=" same => n,Dial(PJSIP/${first_user},60)"$'\n'
    incoming_ctxs+=" same => n,Hangup()"$'\n'
  done
  local dialplan_block
  dialplan_block="$(cat <<EOF
#include "trunk_active.conf"
; Generated by install.sh
[from-internal]
include => from-internal-${first_user}
${per_user_contexts}
${incoming_ctxs}
EOF
)"
  apply_managed_block "$exts" "DIALPLAN_GENERATED" "$dialplan_block" ";" && NEED_DIALPLAN_RELOAD=1 || true
  ensure_owner_mode "$exts" asterisk:asterisk 0644
  ensure_trunk_active_conf
}
# =============================================================================
# Tools
# =============================================================================
ensure_tools(){
  local settrunk=/usr/local/bin/settrunk
  local content
  content="$(cat <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
if [[ $# -ne 1 ]]; then echo "Usage: settrunk <TRUNK_NAME>"; exit 1; fi
NEW="$1"; FILE="/etc/asterisk/trunk_active.conf"
command -v asterisk >/dev/null 2>&1 || { echo "Error: asterisk CLI not found"; exit 3; }
if ! asterisk -rx "pjsip show endpoint ${NEW}" >/dev/null 2>&1; then
  echo "Error: endpoint '${NEW}' not found in PJSIP"; exit 2
fi
[[ -f "$FILE" ]] || echo "[globals]" > "$FILE"
if ! grep -q '^\[globals\]' "$FILE"; then
  tmp="$(mktemp)"; { echo "[globals]"; cat "$FILE"; } >"$tmp"; mv "$tmp" "$FILE"
fi
if grep -q '^TRUNK=' "$FILE"; then sed -i "s/^TRUNK=.*/TRUNK=${NEW}/" "$FILE"
else echo "TRUNK=${NEW}" >> "$FILE"; fi
asterisk -rx "dialplan reload" >/dev/null 2>&1 || true
echo "Active trunk set to: ${NEW}"
EOF
)"
  file_apply_if_changed "$settrunk" "$content" 0755 root:root "Updated tool: settrunk" || true
}
# =============================================================================
# Config persistence
# =============================================================================
save_config_file(){
  ensure_config_exists; normalize_public_ips
  local user_list trunk_list
  user_list="$(normalize_list "$USERS")"; trunk_list="$(normalize_list "$TRUNKS")"
  local block=""
  block+="# Managed config for install.sh"$'\n'
  env_append block SERVER_IP            "$SERVER_IP"
  env_append block PUBLIC_IPS           "$PUBLIC_IPS"
  env_append block USERS                "$USERS"
  env_append block TRUNKS               "$TRUNKS"
  env_append block ACTIVE_TRUNK         "$ACTIVE_TRUNK"
  block+=$'\n'
  env_append block ENABLE_UFW           "$ENABLE_UFW"
  env_append block SSH_PORT             "$SSH_PORT"
  env_append block TRUSTED_SIP_SOURCES  "$TRUSTED_SIP_SOURCES"
  block+=$'\n'
  env_append block ASTERISK_VER         "$ASTERISK_VER"
  env_append block ASTERISK_TARBALL_URL "$ASTERISK_TARBALL_URL"
  env_append block ALLOW_UPGRADE        "$ALLOW_UPGRADE"
  env_append block ENABLE_FAIL2BAN      "$ENABLE_FAIL2BAN"
  env_append block ENABLE_BALANCE_CHECK "$ENABLE_BALANCE_CHECK"
  env_append block BALANCE_CHECK_INTERVAL "$BALANCE_CHECK_INTERVAL"
  env_append block TG_TOKEN             "$TG_TOKEN"
  env_append block TG_CHAT_ID           "$TG_CHAT_ID"
  env_append block ENABLE_RECORDING    "$ENABLE_RECORDING"
  env_append block RECORDING_DAYS      "$RECORDING_DAYS"
  block+=$'\n'
  env_append block DEFAULT_MAX_CONTACTS    "$DEFAULT_MAX_CONTACTS"
  env_append block DEFAULT_REMOVE_EXISTING "$DEFAULT_REMOVE_EXISTING"
  block+=$'\n'
  env_append block OUTCID       "$OUTCID"
  env_append block EXOLVE_NAME  "$EXOLVE_NAME"
  env_append block EXOLVE_PROXY "$EXOLVE_PROXY"
  env_append block EXOLVE_PORT  "$EXOLVE_PORT"
  env_append block EXOLVE_MATCHES "$EXOLVE_MATCHES"
  block+=$'\n'
  local t
  for t in $trunk_list; do
    local up; up="$(upper_sanitize "$t")"
    local proxy port matches outcid context bind_ip
    proxy="$(get_var "TRUNK_${up}_PROXY")"
    port="$(get_var "TRUNK_${up}_PORT")"; [[ -n "$port" ]] || port="5060"
    matches="$(get_var "TRUNK_${up}_MATCHES")"
    outcid="$(get_var "TRUNK_${up}_OUTCID")"
    context="$(get_var "TRUNK_${up}_CONTEXT")"; [[ -n "$context" ]] || context="from-${t}"
    bind_ip="$(get_var "TRUNK_${up}_BIND_IP")"; [[ -n "$bind_ip" ]] || bind_ip="$SERVER_IP"
    env_append block "TRUNK_${up}_PROXY"   "$proxy"
    env_append block "TRUNK_${up}_PORT"    "$port"
    env_append block "TRUNK_${up}_MATCHES" "$matches"
    env_append block "TRUNK_${up}_OUTCID"  "$outcid"
    env_append block "TRUNK_${up}_CONTEXT" "$context"
    env_append block "TRUNK_${up}_BIND_IP" "$bind_ip"
    block+=$'\n'
  done
  local u
  for u in $user_list; do
    local pass trunk outcid maxc rem
    pass="$(get_var "USER_${u}_PASS")"
    trunk="$(get_var "USER_${u}_TRUNK")"
    outcid="$(get_var "USER_${u}_OUTCID")"
    maxc="$(get_var "USER_${u}_MAX_CONTACTS")"
    rem="$(get_var "USER_${u}_REMOVE_EXISTING")"
    env_append block "USER_${u}_PASS"            "$pass"
    env_append block "USER_${u}_TRUNK"           "$trunk"
    env_append block "USER_${u}_OUTCID"          "$outcid"
    env_append block "USER_${u}_MAX_CONTACTS"    "$maxc"
    env_append block "USER_${u}_REMOVE_EXISTING" "$rem"
    block+=$'\n'
  done
  apply_managed_block "$CONFIG_FILE" "INSTALL_SH_CONFIG" "$block" "#"
  if is_true "$DRY_RUN"; then log "DRY_RUN: would chmod 600 ${CONFIG_FILE}"
  else chmod 600 "$CONFIG_FILE" || true; chown root:root "$CONFIG_FILE" || true; fi
}
# =============================================================================
# Reload/restart + checks
# =============================================================================
asterisk_is_active(){ systemctl is-active --quiet asterisk 2>/dev/null; }
reload_or_restart_if_needed(){
  [[ "$NEED_SYSTEMD_DAEMON_RELOAD" -eq 1 ]] && run_cmd "systemctl daemon-reload"
  if [[ "$NEED_ASTERISK_RESTART" -eq 1 || "$NEED_PJSIP_RELOAD" -eq 1 ]]; then
    log "Asterisk: restarting..."; run_cmd "systemctl restart asterisk"; return 0
  fi
  if asterisk_is_active; then
    if [[ "$NEED_DIALPLAN_RELOAD" -eq 1 ]]; then
      log "Asterisk: dialplan reload"
      run_cmd "asterisk -rx \"dialplan reload\" >/dev/null 2>&1 || true"
    fi
  else
    if [[ "$NEED_DIALPLAN_RELOAD" -eq 1 ]]; then log "Asterisk not active; starting."; run_cmd "systemctl start asterisk"
    else warn "Asterisk not active."; fi
  fi
}
health_checks(){
  log "Health checks..."
  if command -v asterisk >/dev/null 2>&1; then log "Asterisk version: $(asterisk -V 2>/dev/null || true)"; fi
  local i=0
  while ! asterisk_is_active && (( i < 10 )); do sleep 1; i=$((i+1)); done
  if asterisk_is_active; then
    log "Asterisk is active."
    run_cmd "asterisk -rx \"pjsip show transports\" || true"
  else
    warn "Asterisk is not active. Check: journalctl -u asterisk -n 200 --no-pager"
  fi
}
print_summary(){
  local users trunks
  users="$(normalize_list "$USERS")"; trunks="$(normalize_list "$TRUNKS")"
  normalize_public_ips
  echo
  echo "============================================================"
  echo "INSTALL/UPDATE COMPLETE"
  echo "SERVER_IP: ${SERVER_IP}"
  local u
  for u in $users; do
    echo "  SIP: Server=${SERVER_IP}  User=${u}  Pass=$(get_var "USER_${u}_PASS")"
  done
  echo "Транки: ${trunks}"
  if [[ "${#CHANGES[@]}" -eq 0 ]]; then echo "Changes: none."; else
    echo "Changes:"; local c; for c in "${CHANGES[@]}"; do echo "  - ${c}"; done; fi
  echo "============================================================"
}
validate_inputs(){
  detect_ip; validate_public_ips; validate_trusted_sources
  [[ "$SSH_PORT" =~ ^[0-9]+$ ]] || die "SSH_PORT must be numeric."
  [[ -n "${DEFAULT_MAX_CONTACTS:-}" ]]    || { set_var DEFAULT_MAX_CONTACTS "1";   NEED_SAVE_CONFIG=1; }
  [[ "${DEFAULT_MAX_CONTACTS}" =~ ^[0-9]+$ ]] || die "DEFAULT_MAX_CONTACTS must be numeric"
  [[ -n "${DEFAULT_REMOVE_EXISTING:-}" ]] || { set_var DEFAULT_REMOVE_EXISTING "yes"; NEED_SAVE_CONFIG=1; }
  local trunk_list user_list
  trunk_list="$(normalize_list "$TRUNKS")"; user_list="$(normalize_list "$USERS")"
  [[ -n "$trunk_list" ]] || die "TRUNKS is empty"
  [[ -n "$user_list"  ]] || die "USERS is empty"
  local u
  for u in $user_list; do
    [[ "$u" =~ ^[0-9]+$ ]] || die "User '${u}' must be numeric extension"
    local pass_var="USER_${u}_PASS"; local pass; pass="$(get_var "$pass_var")"
    if [[ -z "$pass" ]]; then
      pass="$(gen_password)"; set_var "$pass_var" "$pass"; CHANGES+=("Generated ${pass_var}"); NEED_SAVE_CONFIG=1
    fi
    local tvar="USER_${u}_TRUNK"
    [[ -n "$(get_var "$tvar")" ]] || { set_var "$tvar" "active"; NEED_SAVE_CONFIG=1; }
    local mx; mx="$(get_var "USER_${u}_MAX_CONTACTS")"
    [[ -z "$mx" || "$mx" =~ ^[0-9]+$ ]] || die "USER_${u}_MAX_CONTACTS must be numeric"
  done
  local t
  for t in $trunk_list; do
    local up; up="$(upper_sanitize "$t")"
    local proxy; proxy="$(get_var "TRUNK_${up}_PROXY")"
    [[ -n "$proxy" ]] || die "Missing TRUNK_${up}_PROXY for trunk '${t}'"
    local bind_ip; bind_ip="$(get_var "TRUNK_${up}_BIND_IP")"
    [[ -n "$bind_ip" ]] || { set_var "TRUNK_${up}_BIND_IP" "$SERVER_IP"; bind_ip="$SERVER_IP"; NEED_SAVE_CONFIG=1; }
    is_ipv4 "$bind_ip" || die "TRUNK_${up}_BIND_IP must be IPv4"
    list_contains "$bind_ip" "$PUBLIC_IPS" || die "TRUNK_${up}_BIND_IP='$bind_ip' not in PUBLIC_IPS"
  done
}
# =============================================================================
# Настройка proxy-in endpoint для Kamailio прокси (если PROXY_WG_IP задан)
# =============================================================================
ensure_proxy_config(){
  [[ -n "${PROXY_WG_IP:-}" ]] || return 0
  log "Настраиваю proxy-in endpoint для Kamailio прокси (${PROXY_WG_IP})..."

  local users_file="/etc/asterisk/pjsip_users.conf"
  local exts_file="/etc/asterisk/extensions.conf"

  # Добавить proxy-in endpoint если нет
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
  else
    log "proxy-in endpoint уже существует"
  fi

  # Добавить from-proxy диалплан если нет
  if ! grep -q "^\[from-proxy\]" "$exts_file" 2>/dev/null; then
    local trunk; trunk="$(normalize_list "$TRUNKS" | awk '{print $1}')"
    cat >> "$exts_file" << EOF

[from-proxy]
exten => _7XXXXXXXXXX,1,NoOp(Kamailio proxy: \${EXTEN})
 same => n,Dial(PJSIP/\${EXTEN}@${trunk},60)
 same => n,Hangup()
exten => _8XXXXXXXXXX,1,Goto(from-proxy,7\${EXTEN:1},1)
exten => _+7XXXXXXXXXX,1,Goto(from-proxy,7\${EXTEN:2},1)
exten => _9XXXXXXXXX,1,Goto(from-proxy,7\${EXTEN},1)
EOF
    CHANGES+=("Added from-proxy dialplan context")
    NEED_DIALPLAN_RELOAD=1
  else
    log "from-proxy диалплан уже существует"
  fi

  ensure_owner_mode "$users_file" asterisk:asterisk 0644
  ensure_owner_mode "$exts_file"  asterisk:asterisk 0644
}

main_apply(){
  need_root; detect_os; load_config_file; migrate_legacy_exolve; validate_inputs
  ensure_asterisk_installed; ensure_user_and_dirs; ensure_systemd_unit
  ensure_ufw_rules; ensure_asterisk_configs; ensure_tools; ensure_fail2ban; ensure_recording; ensure_balance_check
  ensure_proxy_config
  if [[ "$NEED_SAVE_CONFIG" -eq 1 || ! -f "$CONFIG_FILE" ]]; then save_config_file; fi
  reload_or_restart_if_needed; health_checks; print_summary
}
choose_editor(){ [[ -n "${EDITOR:-}" ]] && { echo "$EDITOR"; return; }; command -v nano >/dev/null 2>&1 && { echo nano; return; }; echo vi; }
cmd_edit(){
  need_root; detect_os; ensure_config_exists
  local ed; ed="$(choose_editor)"; run_cmd "$ed "$CONFIG_FILE""
  log "После редактирования: bash install.sh apply"
}
prompt_var(){
  local var="$1" prompt="$2" def="${3:-}"
  local cur; cur="$(get_var "$var")"; [[ -n "$cur" ]] && def="$cur"
  local input=""
  if [[ -n "$def" ]]; then read -rp "${prompt} [${def}]: " input; input="${input:-$def}"
  else read -rp "${prompt}: " input; fi
  set_var "$var" "$input"
}
cmd_wizard(){
  need_root; detect_os; load_config_file
  echo; echo "=== install.sh мастер ==="
  prompt_var SERVER_IP "SERVER_IP (публичный IP этого VPS)" "$SERVER_IP"
  detect_ip; set_var PUBLIC_IPS "$SERVER_IP"; normalize_public_ips
  prompt_var OUTCID "OUTCID (номер, 11 цифр без +)" "$OUTCID"
  prompt_var TRUNKS "Транки (через пробел, напр: exolve)" "$TRUNKS"
  TRUNKS="$(normalize_list "$TRUNKS")"; [[ -n "$TRUNKS" ]] || die "TRUNKS не может быть пустым"
  set_var TRUNKS "$TRUNKS"
  local t
  for t in $TRUNKS; do
    local up; up="$(upper_sanitize "$t")"
    local cur
    cur="$(get_var "TRUNK_${up}_PROXY")";   [[ -n "$cur" ]] || set_var "TRUNK_${up}_PROXY"   "80.75.130.99"
    cur="$(get_var "TRUNK_${up}_PORT")";    [[ -n "$cur" ]] || set_var "TRUNK_${up}_PORT"    "5060"
    cur="$(get_var "TRUNK_${up}_MATCHES")"; [[ -n "$cur" ]] || set_var "TRUNK_${up}_MATCHES" "80.75.130.101"
    cur="$(get_var "TRUNK_${up}_OUTCID")";  [[ -n "$cur" ]] || set_var "TRUNK_${up}_OUTCID"  "$OUTCID"
    cur="$(get_var "TRUNK_${up}_CONTEXT")"; [[ -n "$cur" ]] || set_var "TRUNK_${up}_CONTEXT" "from-${t}"
    cur="$(get_var "TRUNK_${up}_BIND_IP")"; [[ -n "$cur" ]] || set_var "TRUNK_${up}_BIND_IP" "$SERVER_IP"
  done
  prompt_var USERS "SIP пользователи (через пробел, напр: 1001)" "$USERS"
  USERS="$(normalize_list "$USERS")"; [[ -n "$USERS" ]] || die "USERS не может быть пустым"
  set_var USERS "$USERS"
  local u
  for u in $USERS; do
    [[ "$u" =~ ^[0-9]+$ ]] || die "Пользователь '${u}' должен быть числом"
    local pass_var="USER_${u}_PASS"
    local cur_pass; cur_pass="$(get_var "$pass_var")"
    if [[ -z "$cur_pass" ]]; then
      cur_pass="$(gen_password)"; set_var "$pass_var" "$cur_pass"
      echo "  ${u}: пароль сгенерирован → ${cur_pass}"
    else
      prompt_var "$pass_var" "  ${u}: пароль (Enter = оставить)" "$cur_pass"
    fi
    [[ -n "$(get_var "USER_${u}_TRUNK")" ]] || set_var "USER_${u}_TRUNK" "active"
    [[ -n "$(get_var "USER_${u}_OUTCID")" ]] || set_var "USER_${u}_OUTCID" "$OUTCID"
  done
  prompt_var SSH_PORT "SSH порт (для UFW)" "$SSH_PORT"
  set_var ENABLE_UFW "1"; set_var TRUSTED_SIP_SOURCES ""; set_var ALLOW_UPGRADE "0"
  set_var ENABLE_FAIL2BAN "1"; set_var DEFAULT_MAX_CONTACTS "1"; set_var DEFAULT_REMOVE_EXISTING "yes"
  [[ -n "$(get_var ENABLE_RECORDING)" ]] || set_var ENABLE_RECORDING "1"
  [[ -n "$(get_var RECORDING_DAYS)" ]] || set_var RECORDING_DAYS "7"
  NEED_SAVE_CONFIG=1; save_config_file
  echo; echo "Готово! Запускайте: bash install.sh apply"
}
cmd_list(){
  need_root; detect_os; load_config_file; normalize_public_ips
  local trunk_list user_list
  trunk_list="$(normalize_list "${TRUNKS:-}")"; user_list="$(normalize_list "${USERS:-}")"
  echo "SERVER_IP: ${SERVER_IP:-}  PUBLIC_IPS: ${PUBLIC_IPS:-}"
  echo; echo "Транки: ${trunk_list:-(пусто)}"
  local t
  for t in $trunk_list; do
    local up; up="$(upper_sanitize "$t")"
    echo "  - ${t}: proxy=$(get_var "TRUNK_${up}_PROXY") port=$(get_var "TRUNK_${up}_PORT") outcid=$(get_var "TRUNK_${up}_OUTCID")"
  done
  echo; echo "Пользователи: ${user_list:-(пусто)}"
  local u
  for u in $user_list; do
    echo "  - ${u}: trunk=$(get_var "USER_${u}_TRUNK") outcid=$(get_var "USER_${u}_OUTCID") pass=(скрыт)"
  done
}
cmd_trunk_add(){
  need_root; detect_os; load_config_file; detect_ip; normalize_public_ips; validate_public_ips
  local name="${1:-}"
  [[ -n "$name" ]] || die "Использование: bash install.sh trunk add <name>"
  local up; up="$(upper_sanitize "$name")"
  local proxy port matches outcid
  proxy="$(get_var "TRUNK_${up}_PROXY")";   [[ -n "$proxy"   ]] || proxy="80.75.130.99"
  port="$(get_var "TRUNK_${up}_PORT")";     [[ -n "$port"    ]] || port="5060"
  matches="$(get_var "TRUNK_${up}_MATCHES")"; [[ -n "$matches" ]] || matches="80.75.130.101"
  outcid="$(get_var "TRUNK_${up}_OUTCID")"; [[ -n "$outcid"  ]] || outcid="$OUTCID"
  echo; echo "Добавление/обновление транка: ${name}"
  prompt_var "TRUNK_${up}_PROXY"   "  proxy"            "$proxy"
  prompt_var "TRUNK_${up}_PORT"    "  port"             "$port"
  prompt_var "TRUNK_${up}_MATCHES" "  identify matches" "$matches"
  prompt_var "TRUNK_${up}_OUTCID"  "  OUTCID (опц.)"    "$outcid"
  local cur_ctx; cur_ctx="$(get_var "TRUNK_${up}_CONTEXT")"
  [[ -n "$cur_ctx" ]] || set_var "TRUNK_${up}_CONTEXT" "from-${name}"
  local cur_bind; cur_bind="$(get_var "TRUNK_${up}_BIND_IP")"
  [[ -n "$cur_bind" ]] || set_var "TRUNK_${up}_BIND_IP" "$SERVER_IP"
  TRUNKS="$(normalize_list "${TRUNKS:-}")"
  if ! list_contains "$name" "$TRUNKS"; then
    TRUNKS="$(normalize_list "$TRUNKS $name")"; set_var TRUNKS "$TRUNKS"
  fi
  NEED_SAVE_CONFIG=1; save_config_file
  echo; echo "Транк '${name}' сохранён. Дальше: bash install.sh apply"
}
cmd_user_add(){
  need_root; detect_os; load_config_file
  local ext="${1:-}"
  [[ -n "$ext" ]] || die "Использование: bash install.sh user add <ext>"
  [[ "$ext" =~ ^[0-9]+$ ]] || die "extension должен быть числом"
  local pass; pass="$(get_var "USER_${ext}_PASS")"
  echo; echo "Добавление/обновление SIP-пользователя: ${ext}"
  if [[ -z "$pass" ]]; then
    pass="$(gen_password)"; set_var "USER_${ext}_PASS" "$pass"
    echo "  Пароль сгенерирован → ${pass}"
  else
    prompt_var "USER_${ext}_PASS" "  Пароль (Enter = оставить)" "$pass"
  fi
  [[ -n "$(get_var "USER_${ext}_TRUNK")"           ]] || set_var "USER_${ext}_TRUNK"           "active"
  [[ -n "$(get_var "USER_${ext}_OUTCID")"          ]] || set_var "USER_${ext}_OUTCID"          "$OUTCID"
  [[ -n "$(get_var "USER_${ext}_MAX_CONTACTS")"    ]] || set_var "USER_${ext}_MAX_CONTACTS"    "$DEFAULT_MAX_CONTACTS"
  [[ -n "$(get_var "USER_${ext}_REMOVE_EXISTING")" ]] || set_var "USER_${ext}_REMOVE_EXISTING" "$DEFAULT_REMOVE_EXISTING"
  USERS="$(normalize_list "${USERS:-}")"
  if ! list_contains "$ext" "$USERS"; then
    USERS="$(normalize_list "$USERS $ext")"; set_var USERS "$USERS"
  fi
  NEED_SAVE_CONFIG=1; save_config_file
  echo; echo "Пользователь '${ext}' сохранён."
  echo "MicroSIP: Server=${SERVER_IP:-<SERVER_IP>} User=${ext} Pass=$(get_var "USER_${ext}_PASS")"
  echo; echo "Дальше: bash install.sh apply"
}
cmd_user_set_pass(){
  need_root; detect_os; load_config_file
  local ext="${1:-}"
  [[ -n "$ext" ]] || die "Использование: bash install.sh user set-pass <ext>"
  [[ "$ext" =~ ^[0-9]+$ ]] || die "extension должен быть числом"
  local pass=""; read -rp "Новый пароль для ${ext}: " pass
  [[ -n "$pass" ]] || die "Пароль не может быть пустым"
  set_var "USER_${ext}_PASS" "$pass"; NEED_SAVE_CONFIG=1
  save_config_file; echo "Готово. Дальше: bash install.sh apply"
}
cmd_user_set_trunk(){
  need_root; detect_os; load_config_file
  local ext="${1:-}" tr="${2:-}"
  [[ -n "$ext" && -n "$tr" ]] || die "Использование: bash install.sh user set-trunk <ext> <trunk>"
  set_var "USER_${ext}_TRUNK" "$tr"; NEED_SAVE_CONFIG=1
  save_config_file; echo "Готово. Дальше: bash install.sh apply"
}
cmd_menu(){
  need_root; detect_os
  while true; do
    echo
    echo "================ install.sh меню ================"
    echo "1) Мастер (wizard)"
    echo "2) Применить (apply)"
    echo "3) Открыть конфиг в редакторе (edit)"
    echo "4) Показать список (list)"
    echo "5) Добавить/обновить транк"
    echo "6) Добавить/обновить SIP-пользователя"
    echo "7) Назначить транк пользователю"
    echo "8) Сменить пароль пользователю"
    echo "0) Выход"
    echo "================================================="
    read -rp "Выберите пункт: " choice
    case "${choice:-}" in
      1) cmd_wizard ;;
      2) main_apply ;;
      3) cmd_edit ;;
      4) cmd_list ;;
      5) read -rp "Имя транка: " name; cmd_trunk_add "${name:-}" ;;
      6) read -rp "Extension: " ext; cmd_user_add "${ext:-}" ;;
      7) read -rp "Extension: " ext; read -rp "Транк: " tr; cmd_user_set_trunk "${ext:-}" "${tr:-}" ;;
      8) read -rp "Extension: " ext; cmd_user_set_pass "${ext:-}" ;;
      0) break ;;
      *) echo "Неизвестный пункт." ;;
    esac
  done
}
cmd_recording(){
  need_root; detect_os; load_config_file
  local subcmd="${1:-}"
  case "$subcmd" in
    on)  set_var ENABLE_RECORDING "1"; set_var RECORDING_DAYS "${2:-7}"; NEED_SAVE_CONFIG=1; save_config_file; echo "Запись включена." ;;
    off) set_var ENABLE_RECORDING "0"; NEED_SAVE_CONFIG=1; save_config_file; echo "Запись выключена." ;;
    *)   echo "Использование: bash install.sh recording on [days] | off"; exit 1 ;;
  esac
}
usage(){
  cat <<EOF
Использование:
  bash install.sh menu
  bash install.sh wizard
  bash install.sh edit
  bash install.sh list
  bash install.sh apply
  bash install.sh trunk add <name>
  bash install.sh user add <ext>
  bash install.sh user set-trunk <ext> <trunk>
  bash install.sh user set-pass <ext>
  bash install.sh recording on [days]
  bash install.sh recording off
EOF
}
# =============================================================================
# Entry point
# =============================================================================
acquire_lock
case "${1:-apply}" in
  menu)      cmd_menu ;;
  wizard)    cmd_wizard ;;
  edit)      cmd_edit ;;
  list)      cmd_list ;;
  apply|"")  main_apply ;;
  trunk)
    [[ "${2:-}" == "add" ]] || { usage; exit 1; }
    cmd_trunk_add "${3:-}"
    ;;
  user)
    case "${2:-}" in
      add)       cmd_user_add "${3:-}" ;;
      set-trunk) cmd_user_set_trunk "${3:-}" "${4:-}" ;;
      set-pass)  cmd_user_set_pass "${3:-}" ;;
      *)         usage; exit 1 ;;
    esac
    ;;
  recording) cmd_recording "${2:-}" "${3:-}" ;;
  *) usage; exit 1 ;;
esac
