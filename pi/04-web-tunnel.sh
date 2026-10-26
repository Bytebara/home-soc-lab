#!/usr/bin/env bash
# 04-web-tunnel.sh: put your website on the Pi and publish it through Cloudflare Tunnel (Phase 5).
#
#   ./04-web-tunnel.sh <site-folder> <your-domain>               show the plan (safe)
#   sudo ./04-web-tunnel.sh <site-folder> <your-domain> --apply  do it
#
#   <site-folder>  the built website copied from your computer, e.g. ~/site
#                  (build it with SITE_BASE=/ so links work at your domain's root)
#   <your-domain>  the domain you added to Cloudflare, e.g. quietsignal.dev
#
# What it does:
#   1. Installs Caddy (Debian's package, kept patched by automatic updates) and serves the
#      site on 127.0.0.1:8081 only, with security headers. (Port 8080 belongs to CrowdSec.)
#   2. Installs cloudflared from Cloudflare's official package repository and connects it
#      using the tunnel token from your Cloudflare dashboard (asked for, never shown).
#   3. Turns on the web access log in the Splunk forwarder and keeps it readable.
#
# Nothing is opened on your router or the Pi's firewall: the tunnel connects outward.

set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=SCRIPTDIR/common.sh
source "$HERE/common.sh"

SITE_SRC="${1:-}"
DOMAIN="${2:-}"
[ -n "$SITE_SRC" ] && [ -n "$DOMAIN" ] && [ "${SITE_SRC#--}" = "$SITE_SRC" ] && [ "${DOMAIN#--}" = "$DOMAIN" ] \
  || fail "Usage: sudo $0 <site-folder> <your-domain> [--apply]"

mode_banner
require_root_for_apply

WEB_ROOT="/var/www/quiet-signal"
WEB_PORT=8081   # 8080 is used by CrowdSec's local API
FWD_HOME="/opt/splunkforwarder"
FWD_USER="splunkfwd"
FWD_LOCAL="$FWD_HOME/etc/apps/qs_pilab_forwarder/local"

# ---------------------------------------------------------------- 0. checks
step "0. Checking your inputs"
SITE_SRC="${SITE_SRC%/}"
[ -f "$SITE_SRC/index.html" ] || fail "No index.html in $SITE_SRC. Copy the built site (the dist folder) to the Pi first."
ok "site folder: $SITE_SRC ($(find "$SITE_SRC" -type f | wc -l) files)"
if grep -q 'href="/quiet-signal/' "$SITE_SRC/index.html"; then
  fail "This build's links start with /quiet-signal/ (the GitHub Pages address).
   Rebuild for your domain on your computer:
     \$env:SITE_URL=\"https://$DOMAIN\"; \$env:SITE_BASE=\"/\"; npm run build"
fi
ok "links are built for the domain's root"
case "$DOMAIN" in
  *.*) ;;
  *) fail "$DOMAIN doesn't look like a domain (e.g. quietsignal.dev)" ;;
esac
if ! printf '%s' "$DOMAIN" | grep -Eq '^[A-Za-z0-9.-]+$'; then
  fail "$DOMAIN contains characters a domain can't have"
fi
ok "domain: $DOMAIN"
if [ -x "$FWD_HOME/bin/splunk" ]; then ok "Splunk forwarder found"; else warn "Splunk forwarder not found; web logs won't reach Splunk until 03-splunk-forwarder.sh is run"; fi

# ---------------------------------------------------------------- 1. Caddy
step "1. Caddy web server (local only, port $WEB_PORT on 127.0.0.1)"
grep -q "^http://:$WEB_PORT {" "$HERE/Caddyfile.template" || fail "Caddyfile.template doesn't use port $WEB_PORT. The kit files don't match; re-unzip the kit."
command -v ss >/dev/null 2>&1 || fail "The 'ss' tool is missing, so the port can't be checked. Install it with: sudo apt-get install iproute2"
LISTENER="$(ss -Hltnp "sport = :$WEB_PORT" 2>/dev/null || true)"
if [ -z "$LISTENER" ]; then
  ok "port $WEB_PORT is free for Caddy"
elif grep -q '"caddy"' <<<"$LISTENER"; then
  ok "port $WEB_PORT is already Caddy's"
elif [ "$(id -u)" -ne 0 ]; then
  warn "something is listening on port $WEB_PORT (run with sudo to see which program)"
else
  fail "Port $WEB_PORT is already in use by another program:
   $LISTENER
   Caddy can't share it. Tell Claude which program it is."
fi
run env DEBIAN_FRONTEND=noninteractive apt-get -y install caddy
run mkdir -p "$WEB_ROOT" /var/log/caddy
if [ "$MODE" = "apply" ]; then
  chown caddy:caddy /var/log/caddy
  chmod 755 /var/log/caddy
fi
info "Copying the site into $WEB_ROOT (old files there are replaced)."
run rm -rf "${WEB_ROOT:?}/"*
run cp -r "$SITE_SRC/." "$WEB_ROOT/"
run chown -R root:root "$WEB_ROOT"
run chmod -R a+rX "$WEB_ROOT"
write_file /etc/caddy/Caddyfile 0644 < "$HERE/Caddyfile.template"
if [ "$MODE" = "apply" ]; then
  if caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1; then
    ok "Caddy configuration is valid"
  else
    caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile || true
    fail "Caddy rejected the configuration (details above). Nothing was reloaded."
  fi
  systemctl enable caddy >/dev/null 2>&1 || true
  if ! systemctl restart caddy; then
    journalctl -u caddy -n 15 --no-pager | sed 's/^/      /'
    fail "Caddy didn't start (its log is above)."
  fi
  sleep 2
  if curl -fsS -o /dev/null http://127.0.0.1:$WEB_PORT/; then
    ok "site answers on http://127.0.0.1:$WEB_PORT"
  else
    fail "Caddy is running but the site didn't answer. See: sudo journalctl -u caddy -n 30"
  fi
else
  info "would check the configuration with 'caddy validate', restart Caddy, and test http://127.0.0.1:$WEB_PORT"
fi

# ---------------------------------------------------------------- 2. cloudflared
step "2. Cloudflare Tunnel connector (cloudflared)"
if command -v cloudflared >/dev/null 2>&1; then
  ok "cloudflared already installed ($(cloudflared --version 2>/dev/null | head -1))"
else
  info "Adding Cloudflare's official package repository, signed with their key."
  run mkdir -p --mode=0755 /usr/share/keyrings
  if [ "$MODE" = "apply" ]; then
    curl -fsSL https://pkg.cloudflare.com/cloudflare-main.gpg -o /usr/share/keyrings/cloudflare-main.gpg
    ok "saved Cloudflare's signing key"
  else
    info "would download https://pkg.cloudflare.com/cloudflare-main.gpg to /usr/share/keyrings/"
  fi
  write_file /etc/apt/sources.list.d/cloudflared.list 0644 <<'EOF'
deb [signed-by=/usr/share/keyrings/cloudflare-main.gpg] https://pkg.cloudflare.com/cloudflared any main
EOF
  run apt-get update
  run env DEBIAN_FRONTEND=noninteractive apt-get -y install cloudflared
fi

if [ "$MODE" = "apply" ]; then
  if systemctl cat cloudflared.service >/dev/null 2>&1; then
    ok "tunnel service already installed"
  else
    info "Paste the tunnel TOKEN from your Cloudflare dashboard (the long text after"
    info "'service install' in the command it shows). It's hidden as you paste. Treat it"
    info "like a password: anyone with it can run your tunnel. Never post it anywhere."
    read -r -s -p "   Tunnel token: " TOKEN; echo
    TOKEN="$(printf '%s' "$TOKEN" | sed 's/^.*service install[[:space:]]*//; s/[[:space:]]//g')"
    [ "${#TOKEN}" -ge 100 ] || fail "That doesn't look like a tunnel token (too short). Copy only the token part."
    cloudflared service install "$TOKEN" >/dev/null
    unset TOKEN
    ok "tunnel service installed"
  fi
  sleep 5
  if systemctl is-active --quiet cloudflared; then
    ok "cloudflared is running"
  else
    fail "cloudflared isn't running. See: sudo journalctl -u cloudflared -n 30"
  fi
else
  info "would ask for your tunnel token (hidden) and run 'cloudflared service install'"
fi

# ---------------------------------------------------------------- 3. Splunk
step "3. Sending web logs to Splunk"
write_file "$FWD_LOCAL/inputs.conf" 0644 <<'EOF'
# Written by Quiet Signal lab kit (04-web-tunnel.sh): turn on the Caddy access log input.
[monitor:///var/log/caddy/access.log]
disabled = false
EOF
info "Keeping Caddy's log readable by the forwarder (read-only), including after log rotation."
write_log_acl_service "$FWD_USER"
run systemctl daemon-reload
if [ -x "$FWD_HOME/bin/splunk" ]; then
  run chown -R "$FWD_USER:$FWD_USER" "$FWD_LOCAL"
  if [ "$MODE" = "apply" ]; then
    curl -fsS -o /dev/null http://127.0.0.1:$WEB_PORT/ || true   # make sure the log file exists
    sleep 1
  fi
  run systemctl start qs-crowdsec-log-acl.service
  run systemctl restart SplunkForwarder
fi

step "Done"
if [ "$MODE" = "apply" ]; then
  ok "The site is served locally and the tunnel is connected."
  cat <<EOF

Last step, in the Cloudflare dashboard (Networking > Tunnels > your tunnel > Routes):
  Add route > Published application
    Subdomain: (leave empty)     Domain: $DOMAIN
    Service URL: http://127.0.0.1:$WEB_PORT
  Optional second route with Subdomain "www" and the same Service URL.

Then open https://$DOMAIN in your browser.

In Splunk:  index=pilab sourcetype=caddy:access | table _time client_ip request.uri status
EOF
else
  printf '\nNothing was changed. When the plan looks right:  sudo %s %s %s --apply\n' "$0" "$SITE_SRC" "$DOMAIN"
fi
