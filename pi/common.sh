# Shared helpers for the Pi scripts. Sourced, not run directly.
#
# Every script runs in one of two modes:
#   --check  (default) prints what it WOULD do and changes nothing. Safe to run any time.
#   --apply  actually makes the changes. Needs sudo.

MODE="check"
for arg in "$@"; do
  case "$arg" in
    --apply) MODE="apply" ;;
    --check) MODE="check" ;;
  esac
done

if [ -t 1 ]; then
  BOLD=$'\e[1m'; DIM=$'\e[2m'; RED=$'\e[31m'; GREEN=$'\e[32m'; YELLOW=$'\e[33m'; RESET=$'\e[0m'
else
  BOLD=""; DIM=""; RED=""; GREEN=""; YELLOW=""; RESET=""
fi

step()  { printf '\n%s== %s ==%s\n' "$BOLD" "$*" "$RESET"; }
info()  { printf '   %s\n' "$*"; }
ok()    { printf '   %s✓ %s%s\n' "$GREEN" "$*" "$RESET"; }
warn()  { printf '   %s! %s%s\n' "$YELLOW" "$*" "$RESET"; }
fail()  { printf '\n%s✗ %s%s\n' "$RED" "$*" "$RESET" >&2; exit 1; }

# Run a command, or just show it in check mode.
run() {
  if [ "$MODE" = "apply" ]; then
    printf '   %s$ %s%s\n' "$DIM" "$*" "$RESET"
    "$@"
  else
    printf '   %swould run:%s %s\n' "$YELLOW" "$RESET" "$*"
  fi
}

# Write a file from stdin, or show what it would contain in check mode.
# Keeps a one-time backup of any file it replaces (<file>.qs-backup).
write_file() {
  local path="$1" mode="${2:-0644}" content
  content="$(cat)"
  if [ "$MODE" = "apply" ]; then
    mkdir -p "$(dirname "$path")"
    if [ -f "$path" ] && [ ! -f "$path.qs-backup" ]; then
      cp -p "$path" "$path.qs-backup"
      info "backed up existing $path to $path.qs-backup"
    fi
    printf '%s\n' "$content" > "$path"
    chmod "$mode" "$path"
    ok "wrote $path"
  else
    printf '   %swould write %s:%s\n' "$YELLOW" "$path" "$RESET"
    printf '%s\n' "$content" | sed 's/^/      | /'
  fi
}

require_root_for_apply() {
  if [ "$MODE" = "apply" ] && [ "$(id -u)" -ne 0 ]; then
    fail "Run with sudo to apply changes:  sudo $0 --apply"
  fi
}

# The person who ran sudo (the account that must keep SSH access).
admin_user() {
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    printf '%s' "$SUDO_USER"
  else
    id -un
  fi
}

mode_banner() {
  if [ "$MODE" = "apply" ]; then
    printf '%sMode: APPLY. Changes will be made.%s\n' "$BOLD" "$RESET"
  else
    printf '%sMode: CHECK. Nothing will be changed.%s Add --apply to make the changes.\n' "$BOLD" "$RESET"
  fi
}

# Logs that are root-only by default. The Splunk forwarder gets read-only access to just these
# files through a file ACL, re-applied by the qs-crowdsec-log-acl timer (every 10 minutes) so
# files recreated by log rotation get it too. 03, 04 and 05 all write the same service from
# here, so re-running any of them never drops a log another one added.
# (The unit keeps its original name, from when it only covered CrowdSec.)
QS_ACL_DIRS="/var/log/pihole"
QS_ACL_LOGS="/var/log/crowdsec.log /var/log/crowdsec-firewall-bouncer.log /var/log/caddy/access.log /var/log/pihole/pihole.log"

write_log_acl_service() {
  local fwd_user="$1"
  write_file /etc/systemd/system/qs-crowdsec-log-acl.service 0644 <<EOF
# Written by Quiet Signal lab kit: let the Splunk forwarder ($fwd_user) read CrowdSec, Caddy and Pi-hole logs.
[Unit]
Description=Quiet Signal: read-only log access for the Splunk forwarder (CrowdSec, Caddy, Pi-hole)

[Service]
Type=oneshot
ExecStart=/bin/sh -c 'for d in $QS_ACL_DIRS; do [ -d "\$\$d" ] && setfacl -m u:$fwd_user:rx "\$\$d"; done; for f in $QS_ACL_LOGS; do [ -f "\$\$f" ] && setfacl -m u:$fwd_user:r "\$\$f"; done; exit 0'
EOF
}
