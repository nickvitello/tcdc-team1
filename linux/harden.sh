#!/usr/bin/env bash
# Local audit, private baseline, and drift watcher. No automatic SSH/firewall/account edits.
# Usage: sudo bash harden.sh <boxname> [--rebaseline]
set -euo pipefail
umask 077
BOX="${1:-$(hostname)}"
[[ "$BOX" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || { echo 'Invalid box name'; exit 2; }
REBASELINE=0
[ $# -eq 0 ] || shift
while [ $# -gt 0 ]; do
  case "$1" in --rebaseline) REBASELINE=1;; *) echo "Unknown option: $1"; exit 2;; esac
  shift
done
[ "$(id -u)" -eq 0 ] || { echo 'Run as root'; exit 2; }
command -v python3 >/dev/null || { echo 'python3 is required'; exit 2; }
SELFDIR="$(cd "$(dirname "$0")" && pwd)"
for module in baseline.py watch-agent.sh; do
  [ -s "$SELFDIR/$module" ] || { echo "Missing module $module; nothing installed"; exit 2; }
done
BK=/root/tcdc-baseline
[ ! -L "$BK" ] || { echo 'Refusing symlink baseline directory'; exit 2; }
mkdir -p "$BK"; chmod 700 "$BK"
TS="$(date +%Y%m%d-%H%M%S)-$$"
LOG="$BK/harden-$TS.log"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }
log "=== audit/install box=$BOX ==="
FIRST=0
if [ ! -e "$BK/integrity.json" ]; then
  if [ -e "$BK/baseline.sha256" ] && [ "$REBASELINE" -eq 0 ]; then
    log 'OLD baseline: accepted evidence preserved. Review changes, then use --rebaseline. Nothing installed.'
    exit 2
  fi
  FIRST=1
elif [ "$REBASELINE" -eq 0 ]; then
  python3 "$SELFDIR/baseline.py" validate "$BK/integrity.json" || exit 2
  python3 "$SELFDIR/baseline.py" capture "$BK/forensic-$TS.json"
  python3 "$SELFDIR/baseline.py" check "$BK/integrity.json" | tee -a "$LOG" || {
    rc=${PIPESTATUS[0]}; [ "$rc" -eq 1 ] || exit 2;
    log 'Pre-existing drift retained; normal rerun does not accept it.'
  }
fi
if [ "$REBASELINE" -eq 1 ]; then
  archive="$BK/accepted-$TS"; mkdir -m700 "$archive"
  for f in integrity.json baseline.sha256 inventory.base enabled-services.txt .timers.base; do
    [ ! -e "$BK/$f" ] || cp -a "$BK/$f" "$archive/"
  done
  log "Previous accepted evidence archived: $archive"
fi
log 'Accounts (review identities, not just counts; retain packet users and blackteam/whiteteam):'
getent passwd | awk -F: '$3==0 || ($3>=1000 && $7!~/(nologin|false|sync)$/){print "  " $1 " uid=" $3 " gid=" $4 " shell=" $7}' | tee -a "$LOG"
{ getent group sudo || true; getent group wheel || true; } | tee -a "$LOG"
log 'SSH configuration is NOT modified. Preserve staff and scored login methods.'
log 'Keys, sudoers, cron, SSH configuration, units, symlinks, and watcher files are monitored.'

install -d -m755 /usr/local/lib/tcdc
install -m700 "$SELFDIR/baseline.py" /usr/local/lib/tcdc/baseline.py
install -m700 "$SELFDIR/watch-agent.sh" /usr/local/sbin/tcdc-watch
printf '[Unit]\nDescription=TCDC local drift watch\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/tcdc-watch %s\n' "$BOX" > /etc/systemd/system/tcdc-watch.service
printf '[Unit]\nDescription=TCDC drift watch 60s\n[Timer]\nOnBootSec=30\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/tcdc-watch.timer
# Install the enablement symlink before capture; do not run the watcher until capture completes.
systemctl daemon-reload
systemctl enable tcdc-watch.timer
if [ "$FIRST" -eq 1 ] || [ "$REBASELINE" -eq 1 ]; then
  python3 /usr/local/lib/tcdc/baseline.py capture "$BK/integrity.json"
  log 'Accepted baseline captured after watcher installation; review initial state for pre-existing compromise.'
fi
systemctl restart tcdc-watch.timer
systemctl is-active --quiet tcdc-watch.timer
log 'Timer active. Rerun drift checks manually with: sudo /usr/local/sbin/tcdc-watch'
log "Review $LOG and $BK/drift.log. No passwords or firewall/SSH policies changed."
