#!/usr/bin/env bash
# install-server.sh: set up Splunk Enterprise on the Ubuntu PC (Phase 4).
#
#   ./install-server.sh <splunk-enterprise.deb> <pi-ip>              show the plan (safe)
#   sudo ./install-server.sh <splunk-enterprise.deb> <pi-ip> --apply set it up
#
#   <splunk-enterprise.deb>  Splunk Enterprise for Linux (.deb) from splunk.com.
#                            It starts as a 60-day trial; switch to the Free license later.
#                            If Splunk is already installed, pass "installed" instead.
#   <pi-ip>                  the Pi's fixed local IP, e.g. 192.168.1.30, or "later" if the
#                            Pi isn't set up yet (the script then prints the firewall
#                            command to run once you know the Pi's address)
#
# Installs Splunk (if needed), adds the Quiet Signal Lab app (index, receiver on port 9997,
# field extractions, saved searches, dashboard) and opens port 9997 to the Pi only.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/../pi/common.sh
source "$HERE/../pi/common.sh"

PKG="${1:-}"
PI_IP="${2:-}"
[ -n "$PKG" ] && [ -n "$PI_IP" ] && [ "${PKG#--}" = "$PKG" ] && [ "${PI_IP#--}" = "$PI_IP" ] || fail "Usage: sudo $0 <splunk .deb | installed> <pi-ip | later> [--apply]"

mode_banner
require_root_for_apply

SPLUNK_HOME="/opt/splunk"
APP_SRC="$HERE/server-app/quiet_signal_lab"

# ---------------------------------------------------------------- 0. checks
step "0. Checking this PC"
case "$PI_IP" in
  later) info "Pi address: not set yet. Port 9997 stays closed until you add the Pi's address." ;;
  10.*|172.1[6-9].*|172.2[0-9].*|172.3[01].*|192.168.*) ok "Pi address: $PI_IP (home network)" ;;
  *) fail "$PI_IP isn't a home-network address." ;;
esac
MEM_GB="$(awk '/MemTotal/ {printf "%d", $2/1024/1024}' /proc/meminfo)"
CORES="$(nproc)"
info "RAM: ${MEM_GB} GB, CPU cores: $CORES"
[ "$MEM_GB" -ge 7 ] || warn "Splunk will be slow with under 8 GB of RAM. It should still work for a small lab."
DISK_GB="$(df -BG --output=avail /opt 2>/dev/null | tail -1 | tr -dc '0-9')"
if [ -n "$DISK_GB" ]; then
  info "free space for /opt: ${DISK_GB} GB"
  if [ "$DISK_GB" -lt 20 ]; then warn "less than 20 GB free; Splunk needs room for its data"; fi
fi

# ---------------------------------------------------------------- 1. install
step "1. Splunk Enterprise"
if [ -x "$SPLUNK_HOME/bin/splunk" ]; then
  ok "already installed in $SPLUNK_HOME"
elif [ "$PKG" = "installed" ]; then
  fail "You said Splunk is installed, but $SPLUNK_HOME/bin/splunk doesn't exist."
else
  [ -f "$PKG" ] || fail "Can't find $PKG"
  case "$PKG" in *.deb) ok "package: $(basename "$PKG")" ;; *) fail "Expected the .deb file for Linux from splunk.com" ;; esac
  run dpkg -i "$PKG"
fi
SPLUNK_OWNER="$(stat -c %U "$SPLUNK_HOME" 2>/dev/null || echo splunk)"

# The admin login is created on first start from a one-time seed file. Checked on every run,
# so an install that was never started (no etc/passwd yet) still gets an admin.
SEED="$SPLUNK_HOME/etc/system/local/user-seed.conf"
if [ -f "$SPLUNK_HOME/etc/passwd" ]; then
  ok "Splunk admin account already exists"
elif [ "$MODE" = "apply" ]; then
  if [ -f "$SEED" ]; then
    ok "admin login already seeded; it's created when Splunk starts"
  else
    info "Create the Splunk admin login (this is what you'll use in the web page). Save it in your password manager."
    read -r -p "   Splunk admin username: " ADMIN
    read -r -s -p "   Splunk admin password (8+ characters): " PASS; echo
    [ "${#PASS}" -ge 8 ] || fail "Password must be at least 8 characters."
    mkdir -p "$SPLUNK_HOME/etc/system/local"
    ( umask 077; printf '[user_info]\nUSERNAME = %s\nPASSWORD = %s\n' "$ADMIN" "$PASS" > "$SEED" )
    unset PASS
    chown "$SPLUNK_OWNER:$SPLUNK_OWNER" "$SEED"
    ok "admin login seeded; Splunk reads it on first start, then deletes it"
  fi
else
  info "no admin account yet: would ask for an admin username and password and seed them for first start"
fi

# ---------------------------------------------------------------- 2. app
step "2. Adding the Quiet Signal Lab app"
[ -d "$APP_SRC" ] || fail "Can't find $APP_SRC. Run this from inside the unzipped kit."
APP_DST="$SPLUNK_HOME/etc/apps/quiet_signal_lab"
# Replace only the kit's own files (default/). Changes you make in Splunk's web page are
# stored in local/ and metadata/local.meta, and are kept across updates.
run mkdir -p "$APP_DST/metadata"
run rm -rf "$APP_DST/default"
run cp -r "$APP_SRC/default" "$APP_DST/"
run cp "$APP_SRC/metadata/default.meta" "$APP_DST/metadata/default.meta"
if [ -d "$APP_DST/local" ] || [ -f "$APP_DST/metadata/local.meta" ]; then
  ok "kept your own changes made in Splunk (local settings)"
fi
run chown -R "$SPLUNK_OWNER:$SPLUNK_OWNER" "$APP_DST"

# ---------------------------------------------------------------- 3. start
step "3. Starting Splunk and enabling it at boot"
# Note: 'cmd | grep -q' is avoided in these scripts. With pipefail, grep -q can exit early,
# the producer gets SIGPIPE, and a match is wrongly reported as "not found".
if [ "$MODE" = "apply" ] && ! systemctl cat Splunkd.service >/dev/null 2>&1; then
  run "$SPLUNK_HOME/bin/splunk" enable boot-start -systemd-managed 1 -user "$SPLUNK_OWNER" --accept-license --answer-yes --no-prompt
fi
[ "$MODE" = "apply" ] || info "would enable Splunk to start at boot (first time only)"
run systemctl restart Splunkd

# ---------------------------------------------------------------- 4. firewall
step "4. Firewall: port 9997 open to the Pi only"
# ufw only reports its status to root, so check mode without sudo can't tell.
UFW_STATE="missing"
if command -v ufw >/dev/null 2>&1; then
  if [ "$(id -u)" -ne 0 ]; then
    UFW_STATE="unknown"
  elif grep -q "Status: active" <<<"$(ufw status 2>/dev/null)"; then
    UFW_STATE="active"
  else
    UFW_STATE="inactive"
  fi
fi
ufw_advice() {
  warn "ufw isn't active on this PC. Recommended:"
  info "  sudo ufw default deny incoming"
  [ "$PI_IP" = "later" ] || info "  sudo ufw allow from $PI_IP to any port 9997 proto tcp"
  info "  sudo ufw allow from <your-home-network>/24 to any port 22 proto tcp   (if you SSH in)"
  info "  sudo ufw enable"
}
if [ "$UFW_STATE" = "unknown" ]; then
  info "Can't check the firewall without sudo (ufw only answers root). The --apply run checks it."
fi
if [ "$PI_IP" = "later" ]; then
  info "Skipped for now. Once the Pi has its fixed address, run on this PC:"
  info "  sudo ufw allow from <pi-ip> to any port 9997 proto tcp comment 'Splunk forwarder from Pi'"
  case "$UFW_STATE" in missing|inactive) ufw_advice ;; esac
elif [ "$UFW_STATE" = "active" ]; then
  run ufw allow from "$PI_IP" to any port 9997 proto tcp comment 'Splunk forwarder from Pi'
  info "The Splunk web page (port 8000) stays reachable only from this PC unless you allow more."
elif [ "$UFW_STATE" = "unknown" ]; then
  info "would run (if ufw is active): ufw allow from $PI_IP to any port 9997 proto tcp comment 'Splunk forwarder from Pi'"
else
  ufw_advice
fi

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "Splunk is ready to receive logs from the Pi."
  cat <<EOF

Next:
  1. Open http://localhost:8000 on this PC and log in.
  2. Open the "Quiet Signal Lab" app. The dashboard is "Pi lab overview".
  3. On the Pi, run pi/03-splunk-forwarder.sh with this PC's IP.
  4. Check data is arriving:  index=pilab | stats count by sourcetype
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s %s %s --apply\n' "$0" "$PKG" "$PI_IP"
fi
