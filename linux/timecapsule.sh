#!/usr/bin/env bash
# timecapsule.sh - capture a Linux box's security-relevant state, then diff any two captures.
#
#   sudo bash timecapsule.sh snap <label>      e.g. snap start, snap hardened, snap 1130
#   sudo bash timecapsule.sh list
#   sudo bash timecapsule.sh diff <A> <B>      labels or folder names, e.g. diff start hardened
#   sudo bash timecapsule.sh diff <A> now      compare a capture against the live system
#   sudo bash timecapsule.sh restore <A> <path> [path...]   put files/dirs back as they were in A
#
# A capture is a folder of plain text files (users, sudo, keys, listeners, services,
# cron, setuid files, packages, SHA-256 of key directories) plus a config backup
# tarball you can restore from. snap/list/diff are read-only on the system.
# restore is the only command that writes, and it saves the current version first.
#
# Captures live in /root/timecapsule (root only). Red team can delete /root, so
# copy the folder to the jumpbox (still competition infrastructure, so R23 is fine).
# Do NOT copy it off to a personal laptop: R23 bans exfiltrating box data.
set -uo pipefail

STORE="${TIMECAPSULE_DIR:-/root/timecapsule}"
BACKUP_PATHS="/etc /var/www /srv /var/lib/bind /var/cache/bind /var/ftp /root/.ssh"
HASH_PATHS="/etc /var/www /srv /var/ftp /usr/local /usr/bin /usr/sbin /usr/lib/systemd/system /root/.ssh /var/spool/cron"
# PAM modules: a backdoored pam_unix.so here logs every password typed at login
HASH_PATHS="$HASH_PATHS $(ls -d /usr/lib/*/security /lib/*/security 2>/dev/null | xargs -r readlink -f | sort -u | tr '\n' ' ')"

die(){ echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

# ------------------------------------------------------------------ snap
snap(){
  local label="${1:-}"
  [[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || die "label must be letters/digits/._- (got '${label}')"
  local ts dir
  ts="$(date +%H%M%S)"
  dir="$STORE/$(date +%Y%m%d)-$ts-$label"
  mkdir -p "$dir" && chmod 700 "$STORE" "$dir"
  echo "[timecapsule] capturing '$label' -> $dir"
  cd "$dir" || die "cannot enter $dir"

  # meta
  { hostname; date; uname -a; uptime; } > meta.txt 2>&1

  # accounts and privilege
  getent passwd | sort > passwd.txt
  getent group  | sort > group.txt
  awk -F: '$3==0{print}' /etc/passwd > uid0.txt
  # shadow: which accounts changed password, without copying the hashes themselves
  getent shadow | awk -F: '{print $1}' | while read -r u; do
    h="$(getent shadow "$u" | cut -d: -f2)"
    printf '%s %s\n' "$u" "$(printf '%s' "$h" | sha256sum | cut -c1-16)"
  done | sort > shadow-fingerprints.txt
  { echo "### /etc/sudoers"; cat /etc/sudoers
    for f in /etc/sudoers.d/*; do [ -f "$f" ] && { echo "### $f"; cat "$f"; }; done
  } > sudoers.txt 2>/dev/null

  # ssh
  getent passwd | awk -F: '{print $1":"$6}' | while IFS=: read -r u home; do
    for ak in "$home/.ssh/authorized_keys" "$home/.ssh/authorized_keys2"; do
      [ -f "$ak" ] && { echo "### $u $ak"; cat "$ak"; }
    done
  done > authorized_keys.txt 2>/dev/null
  (sshd -T 2>/dev/null | sort) > sshd-effective.txt

  # network
  # drop pid=/fd= so a service restart alone doesn't show up as a change
  (ss -tulpnH 2>/dev/null || netstat -tulpn 2>/dev/null) \
    | sed -E 's/,?pid=[0-9]+//g; s/,?fd=[0-9]+//g; s/[[:space:]]+/ /g' | sort > listeners.txt
  ss -tupnH state established 2>/dev/null | sed -E 's/[[:space:]]+/ /g' | sort > connections.txt
  ip -br addr > ip-addr.txt 2>&1; ip route > ip-route.txt 2>&1
  { iptables-save 2>/dev/null; nft list ruleset 2>/dev/null; ufw status verbose 2>/dev/null; } > firewall.txt
  cat /etc/hosts /etc/resolv.conf > hosts-resolv.txt 2>/dev/null

  # processes (args only, no PIDs/times, so diffs show real changes)
  # skip kernel threads ([kworker/...]) and this script itself: pure noise in a diff
  ps -eo user=,args= | awk '$2 !~ /^\[/' | grep -v 'timecapsule' | sort -u > processes.txt

  # services and scheduled jobs
  systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | sort > services-enabled.txt
  systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | sort > services-running.txt
  systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $(NF-1), $NF}' | sort > timers.txt
  # full unit text for everything admins (or attackers) put in /etc/systemd, incl. override .d files
  for u in $(find /etc/systemd/system -name '*.service' -o -name '*.timer' 2>/dev/null | xargs -r -n1 basename | sort -u); do
    echo "### $u"; systemctl cat "$u" 2>/dev/null
  done > units-custom.txt
  { for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
      [ -f "$f" ] && { echo "### $f"; cat "$f"; }
    done; } > cron.txt 2>/dev/null

  # classic persistence spots
  { echo "### /etc/ld.so.preload"; cat /etc/ld.so.preload 2>/dev/null
    echo "### /etc/rc.local";      cat /etc/rc.local 2>/dev/null
    echo "### pam_exec / odd modules in /etc/pam.d"; grep -rn 'pam_exec\|\.so' /etc/pam.d 2>/dev/null | grep -v '^#' | sort
  } > persistence-spots.txt
  find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort > setuid.txt
  (getcap -r / 2>/dev/null | sort) > capabilities.txt

  # packages
  dpkg-query -W -f='${Package} ${Version}\n' 2>/dev/null | sort > packages.txt

  # file fingerprints (what files exist + their content hash)
  for p in $HASH_PATHS; do
    [ -e "$p" ] && find "$p" -xdev -type f -size -50M 2>/dev/null
  done | grep -v '^/etc/.*-$' | sort -u \
    | xargs -r -d '\n' sha256sum 2>/dev/null | awk '{print $2, $1}' | sort > hashes.txt

  # restorable config backup
  local existing=""
  for p in $BACKUP_PATHS; do [ -e "$p" ] && existing="$existing $p"; done
  # shellcheck disable=SC2086
  tar czf backup.tgz --ignore-failed-read $existing 2>/dev/null
  chmod 600 backup.tgz

  echo "[timecapsule] done: $(ls | wc -l) files, $(wc -l < hashes.txt) hashed, backup $(du -h backup.tgz | cut -f1)"
  echo "[timecapsule] copy it somewhere safe:  scp -r $dir <you>@<jumpbox>:timecapsule/"
}

# ------------------------------------------------------------------ helpers
resolve(){
  # accept a full folder name or just its label; newest match wins
  local want="$1" m
  [ -d "$STORE/$want" ] && { echo "$STORE/$want"; return; }
  m="$(ls -1d "$STORE"/*-"$want" 2>/dev/null | sort | tail -1)"
  [ -n "$m" ] || die "no capture named '$want' (try: timecapsule.sh list)"
  echo "$m"
}

list(){
  [ -d "$STORE" ] || die "no captures yet"
  ls -1 "$STORE"
}

# ------------------------------------------------------------------ diff
diff_caps(){
  local A B
  A="$(resolve "$1")" || exit 1
  B="$(resolve "$2")" || exit 1
  echo "=== timecapsule diff"
  echo "    A: $(basename "$A")"
  echo "    B: $(basename "$B")"

  # file fingerprints: added / removed / changed, summarised by path
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"; trap - RETURN' RETURN
  awk '{print $1}' "$A/hashes.txt" > "$tmp/a"; awk '{print $1}' "$B/hashes.txt" > "$tmp/b"
  local added removed changed
  added="$(comm -13 "$tmp/a" "$tmp/b")"
  removed="$(comm -23 "$tmp/a" "$tmp/b")"
  changed="$(join "$A/hashes.txt" "$B/hashes.txt" | awk '$2!=$3{print $1}')"
  echo; echo "### FILES"
  [ -n "$added" ]   && echo "$added"   | sed 's/^/  + new      /'
  [ -n "$removed" ] && echo "$removed" | sed 's/^/  - removed  /'
  [ -n "$changed" ] && echo "$changed" | sed 's/^/  ~ changed  /'
  [ -z "$added$removed$changed" ] && echo "  (no file changes)"

  # everything else: a unified diff per section that differs
  local f any=0
  for f in uid0 passwd group shadow-fingerprints sudoers authorized_keys sshd-effective \
           listeners firewall services-enabled services-running timers units-custom cron \
           persistence-spots setuid capabilities processes packages hosts-resolv; do
    [ -f "$A/$f.txt" ] && [ -f "$B/$f.txt" ] || continue
    if ! cmp -s "$A/$f.txt" "$B/$f.txt"; then
      any=1
      echo; echo "### ${f^^}"
      diff -u "$A/$f.txt" "$B/$f.txt" | tail -n +3 | grep '^[+-]' | sed 's/^/  /'
    fi
  done
  [ "$any" -eq 0 ] && { echo; echo "(no other changes)"; }
  echo
  echo "restore a file from A:  tar xzf $A/backup.tgz -C / <path-without-leading-slash>"
}

# ------------------------------------------------------------------ restore
restore(){
  local src="$1"; shift
  [ $# -ge 1 ] || die "usage: timecapsule.sh restore <label> <path> [path...]"
  local A; A="$(resolve "$src")" || exit 1
  [ -f "$A/backup.tgz" ] || die "capture $(basename "$A") has no backup.tgz"

  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"; trap - RETURN' RETURN
  tar tzf "$A/backup.tgz" 2>/dev/null | sed 's#/$##' > "$tmp/members"

  local p rel ts saved
  ts="$(date +%Y%m%d-%H%M%S)"
  saved="$STORE/pre-restore-$ts.tgz"
  # validate everything first: restore all or nothing
  for p in "$@"; do
    [[ "$p" == /* ]] || die "use absolute paths: $p"
    rel="${p#/}"; rel="${rel%/}"
    awk -v r="$rel" '$0==r || index($0, r"/")==1 {f=1} END{exit !f}' "$tmp/members" \
      || die "$p is not in capture $(basename "$A") (backed-up roots: $BACKUP_PATHS)"
  done

  # 1. save what is there NOW, so a restore can itself be undone
  local now_rel=()
  for p in "$@"; do rel="${p#/}"; rel="${rel%/}"; [ -e "/$rel" ] && now_rel+=("$rel"); done
  if [ ${#now_rel[@]} -gt 0 ]; then
    tar czf "$saved" -C / "${now_rel[@]}" 2>/dev/null && chmod 600 "$saved"
    echo "[timecapsule] current version saved -> $saved"
  fi

  # 2. put the captured version back (owners and permissions as captured)
  for p in "$@"; do
    rel="${p#/}"; rel="${rel%/}"
    if tar xzpf "$A/backup.tgz" -C / --same-owner "$rel" 2>"$tmp/err"; then
      echo "[timecapsule] restored /$rel from $(basename "$A")"
    else
      echo "[timecapsule] !! FAILED /$rel: $(head -c 200 "$tmp/err")"
    fi
    # 3. a restore puts files BACK but never deletes. Show what exists now that the
    #    capture did not have (a dropped webshell in /var/www, a new cron file...)
    if [ -d "/$rel" ]; then
      find "/$rel" -type f 2>/dev/null | sed 's#^/##' | sort > "$tmp/live"
      awk -v r="$rel" 'index($0, r"/")==1' "$tmp/members" | sort > "$tmp/had"
      comm -23 "$tmp/live" "$tmp/had" > "$tmp/extra"
      if [ -s "$tmp/extra" ]; then
        echo "[timecapsule] !! files in /$rel that were NOT in the capture (review, then remove by hand):"
        sed 's#^#      /#' "$tmp/extra" | head -50
        [ "$(wc -l < "$tmp/extra")" -gt 50 ] && echo "      ... $(wc -l < "$tmp/extra") total"
      fi
    fi
  done
  echo "[timecapsule] NEXT: syntax-check and reload the service (apachectl configtest / named-checkconf / sshd -t),"
  echo "              then watch the scoreboard. Undo this restore with:"
  [ ${#now_rel[@]} -gt 0 ] && echo "              tar xzpf $saved -C /"
}

case "${1:-}" in
  snap) snap "${2:-}" ;;
  list) list ;;
  diff)
    [ $# -eq 3 ] || die "usage: timecapsule.sh diff <A> <B|now>"
    if [ "$3" = "now" ]; then
      snap auto >/dev/null || die "could not capture current state"
      diff_caps "$2" auto
    else
      diff_caps "$2" "$3"
    fi ;;
  restore) shift; [ $# -ge 2 ] || die "usage: timecapsule.sh restore <label> <path> [path...]"; restore "$@" ;;
  *) sed -n '2,19p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
