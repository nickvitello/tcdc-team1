#!/usr/bin/env bash
# TCDC Team 1 — Linux hardening. Idempotent. Safe to re-run.
# Usage: sudo bash harden.sh <boxname> [--rebaseline]
# Does NOT change passwords itself (that goes through the vault so the
# /team/passwords dashboard stays in sync). Does NOT delete protected users (R8).
#
# BASELINE LIFECYCLE (review #11): the FIRST run captures the accepted baseline.
# Re-runs do NOT overwrite it (so a later compromise can't silently become the new
# "clean" reference). They take a timestamped forensic snapshot instead. To
# deliberately accept current state as the new baseline, pass --rebaseline.
set -uo pipefail
BOX="${1:-unknown}"
REBASELINE=0; [ "${2:-}" = "--rebaseline" ] && REBASELINE=1
TS="$(date +%Y%m%d-%H%M%S)"
BK="/root/tcdc-baseline"
LOG="$BK/harden-$TS.log"
mkdir -p "$BK"
log(){ echo "[$(date +%H:%M:%S)] $*" | tee -a "$LOG"; }

PROTECTED_USERS="blackteam whiteteam root"

log "=== TCDC harden start box=$BOX (protected: $PROTECTED_USERS) ==="

# hash set written to $1; inventory (path list) written to $2
build_baseline(){
  local HASHES="$1" INV="$2"
  : > "$HASHES"
  for f in /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/crontab \
           /etc/ssh/sshd_config /root/.ssh/authorized_keys; do
    [ -e "$f" ] && sha256sum "$f" >> "$HASHES" 2>/dev/null
  done
  # hash every file under sudoers.d, cron dirs, systemd unit dirs (review #8)
  find /etc/sudoers.d /etc/cron.d /etc/cron.hourly /etc/cron.daily \
       /etc/cron.weekly /etc/cron.monthly /var/spool/cron \
       /etc/systemd/system /lib/systemd/system -type f 2>/dev/null \
    | xargs -r sha256sum >> "$HASHES" 2>/dev/null
  getent passwd | awk -F: '$3>=0{print $1":"$6}' | while IFS=: read -r u home; do
    ak="$home/.ssh/authorized_keys"; [ -f "$ak" ] && sha256sum "$ak" >> "$HASHES" 2>/dev/null
  done
  # path INVENTORY so NEW files/symlinks (not just changed ones) are detectable
  # (review #12: include -type l so a symlinked persistence file is recorded).
  find /etc/sudoers.d /etc/cron.d /etc/cron.hourly /etc/cron.daily \
       /etc/cron.weekly /etc/cron.monthly /var/spool/cron /etc/systemd/system \
       \( -type f -o -type l \) 2>/dev/null | sort -u > "$INV"
}

# record our own watcher units in the inventory so the watch-agent does not flag them as
# NEW persistence (review #4: explicit baseline of OUR artifacts, not a name-substring skip)
bless_own_units(){
  local INV="$1"
  [ -s "$INV" ] || return 0
  for u in /etc/systemd/system/tcdc-watch.service /etc/systemd/system/tcdc-watch.timer; do
    grep -qxF "$u" "$INV" 2>/dev/null || echo "$u" >> "$INV"
  done
  sort -u "$INV" -o "$INV" 2>/dev/null || true
}

# 1. Baseline snapshot (drift detection source of truth)
if [ -s "$BK/baseline.sha256" ] && [ "$REBASELINE" -eq 0 ]; then
  log "[1] baseline EXISTS -> keeping accepted baseline (re-run with --rebaseline to replace)"
  log "    forensic snapshot only -> $BK/forensic-$TS.sha256"
  build_baseline "$BK/forensic-$TS.sha256" "$BK/forensic-$TS.inv"
  # review #5: an OLD-format baseline (pre-inventory) leaves the watcher blind to new files.
  # Build the inventory now so detection works, but mark it clearly as an UPGRADE snapshot the
  # operator must review (a pre-existing planted file would otherwise be silently accepted).
  if [ ! -f "$BK/inventory.base" ]; then
    log "[1!] OLD-FORMAT baseline (no inventory.base). Building inventory as UPGRADE snapshot."
    log "     REVIEW these paths - they are now accepted as baseline:"
    build_baseline "$BK/.upgrade-$TS.sha256" "$BK/inventory.base"
    bless_own_units "$BK/inventory.base"
    sed 's/^/       /' "$BK/inventory.base" | tee -a "$LOG"
    rm -f "$BK/.upgrade-$TS.sha256"
  fi
else
  log "[1] capturing accepted baseline -> $BK/baseline.sha256 (+ inventory)"
  build_baseline "$BK/baseline.sha256" "$BK/inventory.base"
  cp -a /etc/passwd /etc/shadow /etc/sudoers "$BK/" 2>/dev/null
  log "    baselined $(wc -l < "$BK/baseline.sha256") files, $(wc -l < "$BK/inventory.base") inventory paths"
fi

# 2. authorized_keys audit (backup, do NOT auto-delete — review first)
# R8: blackteam/whiteteam (and root) keys are PROTECTED. We never clear them and we flag them
# so an operator following the clear-hint below can't accidentally cut competition-staff access.
log "[2] authorized_keys audit"
getent passwd | awk -F: '$3>=0{print $1":"$6}' | while IFS=: read -r u home; do
  ak="$home/.ssh/authorized_keys"
  if [ -f "$ak" ] && [ -s "$ak" ]; then
    cp -a "$ak" "$BK/authkeys.$u.$TS" 2>/dev/null
    case " $PROTECTED_USERS " in
      *" $u "*) log "    $u: $(grep -c . "$ak") key(s)  (PROTECTED - R8: DO NOT CLEAR; backup: $BK/authkeys.$u.$TS)" ;;
      *)        log "    $u: $(grep -c . "$ak") key(s)  (backup: $BK/authkeys.$u.$TS)" ;;
    esac
  fi
done
log "    -> clear ONLY non-protected users after review: > ~USER/.ssh/authorized_keys"
log "    -> NEVER clear: $PROTECTED_USERS (R8)"

# 3. Privilege audit (report)
log "[3] privilege audit"
log "    sudo: $(getent group sudo | cut -d: -f4)   wheel: $(getent group wheel | cut -d: -f4)"
grep -rEh '^[^#].*ALL' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/^/      sudoers: /' | tee -a "$LOG"
awk -F: '$3==0 && $1!="root"{print "    !! EXTRA UID0 (backdoor?): "$1}' /etc/passwd | tee -a "$LOG"

# 4. Listeners + enabled services inventory (report)
log "[4] listening sockets"
(ss -tulpnH 2>/dev/null || netstat -tulpn 2>/dev/null) | sed 's/^/      /' | tee -a "$LOG" | head -40
# only (re)write the accepted enabled-services list on first/baseline run
if [ ! -s "$BK/enabled-services.txt" ] || [ "$REBASELINE" -eq 1 ]; then
  systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null \
    | awk '{print $1}' > "$BK/enabled-services.txt"
fi
log "    enabled -> $BK/enabled-services.txt ($(wc -l < "$BK/enabled-services.txt" 2>/dev/null))"

# 5. sshd hardening (conservative — keep scored SSH login working)
log "[5] sshd hardening"
SSHD=/etc/ssh/sshd_config
if [ -f "$SSHD" ]; then
  cp -a "$SSHD" "$BK/sshd_config.$TS"
  # review #9: decide BEFORE editing whether sshd_config was CLEAN vs the accepted baseline.
  # If it already drifted (someone changed e.g. AuthorizedKeysFile), re-blessing it after our
  # edit would silently accept that unrelated drift. Only re-bless when it was clean (so we
  # don't flag our OWN hardening) or when --rebaseline is explicit.
  SSHD_PRECLEAN=0
  if grep -q " $SSHD\$" "$BK/baseline.sha256" 2>/dev/null; then
    _want="$(grep " $SSHD\$" "$BK/baseline.sha256" | tail -1 | awk '{print $1}')"
    _have="$(sha256sum "$SSHD" 2>/dev/null | awk '{print $1}')"
    [ -n "$_want" ] && [ "$_want" = "$_have" ] && SSHD_PRECLEAN=1
  else
    SSHD_PRECLEAN=1   # no baseline entry yet (first run): our post-edit state is the baseline
  fi
  set_sshd(){ grep -qiE "^\s*$1\b" "$SSHD" && sed -i "s|^\s*$1.*|$1 $2|I" "$SSHD" || echo "$1 $2" >> "$SSHD"; }
  # R8 / access-safety: do NOT auto-change PermitRootLogin. If blackteam/whiteteam or a scored
  # check logs in as root by PASSWORD, forcing prohibit-password silently cuts them off. REPORT
  # the current value only; harden root login by hand after confirming nobody relies on it.
  _rl="$(grep -iE '^\s*PermitRootLogin' "$SSHD" 2>/dev/null | tail -1 | awk '{print $2}')"
  log "    PermitRootLogin currently: ${_rl:-(unset = default 'prohibit-password' on modern sshd)} - NOT changed (review manually)"
  set_sshd X11Forwarding no
  set_sshd PermitEmptyPasswords no
  set_sshd MaxAuthTries 4
  if sshd -t 2>>"$LOG"; then
    if systemctl reload ssh 2>/dev/null || systemctl reload sshd 2>/dev/null; then
      log "    sshd reloaded OK"
    else
      log "    !! sshd reload FAILED (both ssh and sshd units) — config valid but not applied; check manually"
    fi
    if [ "$SSHD_PRECLEAN" -eq 1 ] || [ "$REBASELINE" -eq 1 ]; then
      # re-baseline ONLY the file we just changed, so the watcher never flags our own hardening
      if grep -q " $SSHD\$" "$BK/baseline.sha256" 2>/dev/null; then
        grep -v " $SSHD\$" "$BK/baseline.sha256" > "$BK/.b.tmp" 2>/dev/null && mv "$BK/.b.tmp" "$BK/baseline.sha256"
      fi
      sha256sum "$SSHD" >> "$BK/baseline.sha256"
    else
      log "    !! sshd_config had PRE-EXISTING drift vs baseline - NOT re-blessing. Watcher will keep"
      log "       flagging $SSHD until you review it and re-run with --rebaseline to accept."
    fi
  else
    log "    !! sshd -t FAILED, reverting"; cp -a "$BK/sshd_config.$TS" "$SSHD"
  fi
fi

# 6. Install drift watch-agent (systemd timer every 60s)
log "[6] install watch-agent"
SELFDIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd)"
if [ -f "$SELFDIR/watch-agent.sh" ]; then
  install -m750 "$SELFDIR/watch-agent.sh" /usr/local/sbin/tcdc-watch
else
  curl -fsSL "https://raw.githubusercontent.com/nickvitello/tcdc-team1/main/linux/watch-agent.sh" \
    -o /usr/local/sbin/tcdc-watch 2>/dev/null && chmod 750 /usr/local/sbin/tcdc-watch
fi
if [ -x /usr/local/sbin/tcdc-watch ]; then
  printf '[Unit]\nDescription=TCDC drift watch\n[Service]\nType=oneshot\nExecStart=/usr/local/sbin/tcdc-watch %s\n' "$BOX" > /etc/systemd/system/tcdc-watch.service
  printf '[Unit]\nDescription=TCDC drift watch 60s\n[Timer]\nOnBootSec=30\nOnUnitActiveSec=60\n[Install]\nWantedBy=timers.target\n' > /etc/systemd/system/tcdc-watch.timer
  systemctl daemon-reload 2>/dev/null
  systemctl enable --now tcdc-watch.timer 2>/dev/null && log "    watch timer active (60s)"
  # our units live under /etc/systemd/system (inventoried). Record them in the accepted
  # inventory so the watcher treats them as known, not as NEW persistence (review #4).
  bless_own_units "$BK/inventory.base"
else
  log "    !! watch-agent not installed (no internet?) — copy manually"
fi

log "=== harden done. Baseline+backups in $BK ==="
log "NEXT (via vault): rotate default passwords, mirror to /team/passwords"
echo; echo ">>> Review $LOG . Rogue keys BACKED UP not deleted — clear yourself after check."
