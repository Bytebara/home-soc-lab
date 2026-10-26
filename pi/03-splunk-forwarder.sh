#!/usr/bin/env bash
# 03-splunk-forwarder.sh: install the Splunk Universal Forwarder on the Pi (Phase 4).
#
#   ./03-splunk-forwarder.sh <forwarder-file> <ubuntu-pc-ip>              show the plan (safe)
#   sudo ./03-splunk-forwarder.sh <forwarder-file> <ubuntu-pc-ip> --apply install it
#
#   <forwarder-file>  the Linux ARMv8 (64-bit) Universal Forwarder you downloaded from
#                     splunk.com (.deb or .tgz). Copy it to the Pi with scp first.
#   <ubuntu-pc-ip>    the fixed local IP of the Ubuntu PC running Splunk, e.g. 192.168.1.20
#
# Set up Splunk on the Ubuntu PC first (splunk/install-server.sh), so it's ready to receive.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/common.sh
source "$HERE/common.sh"

PKG="${1:-}"
SERVER="${2:-}"
[ -n "$PKG" ] && [ -n "$SERVER" ] && [ "${PKG#--}" = "$PKG" ] && [ "${SERVER#--}" = "$SERVER" ] || fail "Usage: sudo $0 <forwarder .deb or .tgz> <ubuntu-pc-ip> [--apply]"

mode_banner
require_root_for_apply

SPLUNK_HOME="/opt/splunkforwarder"
APP_SRC="$HERE/../splunk/forwarder-app/qs_pilab_forwarder"
FWD_USER="splunkfwd"

# ---------------------------------------------------------------- 0. checks
step "0. Checking the Pi and your inputs"
[ -f "$PKG" ] || fail "Can't find $PKG. Copy it to the Pi first, e.g.  scp splunkforwarder-*.deb <user>@<pi>.local:~"
case "$PKG" in
  *.deb|*.tgz) ok "forwarder package: $(basename "$PKG")" ;;
  *) fail "Expected a .deb or .tgz file from splunk.com, got $PKG" ;;
esac
case "$PKG" in
  *armv8*|*arm64*|*aarch64*) ok "it's the 64-bit ARM build" ;;
  *) warn "the file name doesn't say armv8/arm64. On splunk.com choose Linux, then ARMv8 (64-bit)." ;;
esac
case "$SERVER" in
  10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) ok "Splunk server: $SERVER (home network)" ;;
  *) fail "$SERVER isn't a home-network address. Logs should only go to your own Ubuntu PC." ;;
esac
[ "$(uname -m)" = "aarch64" ] || fail "This needs 64-bit Raspberry Pi OS (uname -m shows $(uname -m))."

PAGE="$(getconf PAGESIZE)"
if [ "$PAGE" != "4096" ]; then
  warn "This Pi uses ${PAGE}-byte memory pages (the Pi 5 default). Some ARM programs,"
  warn "possibly including the Splunk forwarder, crash with that. If the forwarder fails to start:"
  info "  1. sudo nano /boot/firmware/config.txt"
  info "  2. add a line at the end:  kernel=kernel8.img"
  info "  3. sudo reboot, then run this script again"
fi

if command -v nc >/dev/null 2>&1; then
  if nc -z -w 3 "$SERVER" 9997 2>/dev/null; then
    ok "Splunk on $SERVER is listening on port 9997"
  else
    warn "can't reach $SERVER:9997 yet. Run install-server.sh on the Ubuntu PC first, and check its firewall."
  fi
fi

# ---------------------------------------------------------------- 1. install
step "1. Installing the forwarder"
if [ -x "$SPLUNK_HOME/bin/splunk" ]; then
  ok "already installed in $SPLUNK_HOME"
else
  if ! id "$FWD_USER" >/dev/null 2>&1; then
    run useradd --system --home-dir "$SPLUNK_HOME" --shell /usr/sbin/nologin "$FWD_USER"
  fi
  case "$PKG" in
    *.deb) run dpkg -i "$PKG" ;;
    *.tgz) run tar -xzf "$PKG" -C /opt ;;
  esac
fi

# ---------------------------------------------------------------- 2. permissions
step "2. Letting the forwarder read logs (least privilege)"
info "The forwarder runs as its own user '$FWD_USER', not root."
info "Joining the 'adm' group lets it read system logs, nothing more."
run usermod -aG adm "$FWD_USER"

# ---------------------------------------------------------------- 3. config
step "3. Adding the Quiet Signal inputs and pointing it at $SERVER"
[ -d "$APP_SRC" ] || fail "Can't find $APP_SRC. Run this from inside the unzipped kit."
run mkdir -p "$SPLUNK_HOME/etc/apps/qs_pilab_forwarder/default"
run cp "$APP_SRC/default/inputs.conf" "$APP_SRC/default/app.conf" "$SPLUNK_HOME/etc/apps/qs_pilab_forwarder/default/"
sed "s/SPLUNK_SERVER/$SERVER/" "$APP_SRC/default/outputs.conf.template" \
  | write_file "$SPLUNK_HOME/etc/apps/qs_pilab_forwarder/default/outputs.conf" 0644

# ---------------------------------------------------------------- 4. admin login
step "4. Local admin account for the forwarder"
info "The forwarder needs its own admin login (only used on the Pi). Save it in your password manager."
SEED="$SPLUNK_HOME/etc/system/local/user-seed.conf"
if [ "$MODE" = "apply" ]; then
  if [ -f "$SPLUNK_HOME/etc/passwd" ]; then
    ok "admin account already set up"
  else
    read -r -p "   Forwarder admin username: " FWD_ADMIN
    read -r -s -p "   Forwarder admin password (8+ characters): " FWD_PASS; echo
    [ "${#FWD_PASS}" -ge 8 ] || fail "Password must be at least 8 characters."
    mkdir -p "$(dirname "$SEED")"
    umask 077
    printf '[user_info]\nUSERNAME = %s\nPASSWORD = %s\n' "$FWD_ADMIN" "$FWD_PASS" > "$SEED"
    unset FWD_PASS
    ok "seed file written; Splunk deletes it after first start"
  fi
else
  info "would ask for a username and password and pass them to Splunk via a one-time seed file"
fi

# ---------------------------------------------------------------- 5. start
step "5. Starting the forwarder and enabling it at boot"
run chown -R "$FWD_USER:$FWD_USER" "$SPLUNK_HOME"
if [ "$MODE" = "apply" ] && systemctl cat SplunkForwarder.service >/dev/null 2>&1; then
  ok "already set to start at boot"
else
  run "$SPLUNK_HOME/bin/splunk" enable boot-start -systemd-managed 1 -user "$FWD_USER" --accept-license --answer-yes --no-prompt
fi
run systemctl start SplunkForwarder

# ---------------------------------------------------------------- 6. CrowdSec log access
step "6. Read-only access to CrowdSec's private logs"
info "CrowdSec keeps its logs readable by root only. Grant the forwarder read access to just"
info "those files (a file ACL), and re-apply it every 10 minutes with a systemd timer so"
info "new files created by log rotation get it too."
run env DEBIAN_FRONTEND=noninteractive apt-get -y install acl
write_log_acl_service "$FWD_USER"
write_file /etc/systemd/system/qs-crowdsec-log-acl.timer 0644 <<'EOF'
# Re-applies the access every 10 minutes, because CrowdSec creates new root-only files when it rotates logs.
[Unit]
Description=Quiet Signal: keep CrowdSec logs readable by the Splunk forwarder

[Timer]
OnBootSec=2min
OnUnitActiveSec=10min

[Install]
WantedBy=timers.target
EOF
run systemctl daemon-reload
run systemctl enable --now qs-crowdsec-log-acl.timer
for f in /var/log/crowdsec.log /var/log/crowdsec-firewall-bouncer.log; do
  if [ -f "$f" ] || [ "$MODE" != "apply" ]; then run setfacl -m "u:$FWD_USER:r" "$f"; fi
done
run systemctl restart SplunkForwarder

# ---------------------------------------------------------------- 7. verify
step "7. Checking it can read the logs"
for f in /var/log/auth.log /var/log/syslog /var/log/ufw.log /var/log/crowdsec.log /var/log/crowdsec-firewall-bouncer.log; do
  if [ ! -e "$f" ]; then
    info "$f doesn't exist yet (fine; it's picked up when it appears)"
  elif [ "$MODE" = "apply" ]; then
    if sudo -u "$FWD_USER" test -r "$f"; then ok "can read $f"; else warn "can't read $f. Fix:  sudo setfacl -m u:$FWD_USER:r $f"; fi
  else
    info "would check $FWD_USER can read $f"
  fi
done

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "Forwarder installed."
  cat <<EOF

Check it on the Ubuntu PC in Splunk Search:
   index=pilab | stats count by sourcetype

Forwarder status on the Pi:
   sudo systemctl status SplunkForwarder
   sudo -u $FWD_USER $SPLUNK_HOME/bin/splunk list forward-server
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s %s %s --apply\n' "$0" "$PKG" "$SERVER"
fi
