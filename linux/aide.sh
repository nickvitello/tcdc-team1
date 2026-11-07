#!/usr/bin/env bash
# aide.sh - AIDE file-integrity checks with a TCDC-safe config. Run as root on a Linux box,
# or from the jumpbox for every box at once:  ./fleet.sh aide <action>
#
#   install   apt install aide, then DISABLE its daily timer (no scheduled job left behind)
#   init      build the baseline database (do it right after hardening)
#   check     compare the box against the baseline; prints only what changed
#   accept    after reviewing a check, make the current state the new baseline
#
# Uses its own config and database in /root/aide. Never touches /etc/aide or the
# default database. Read-only on the system apart from /root/aide.
# Rules: scans run at lowest CPU/disk priority (uptime); Wazuh's /var/ossec is
# excluded entirely (R7); nothing here changes accounts or services (R8).
set -uo pipefail

DIR=/root/aide
CONF=$DIR/aide.conf
DB=$DIR/aide.db
NEW=$DIR/aide.db.new

die(){ echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
gentle(){ nice -n 19 ionice -c3 "$@"; }

write_conf(){
  mkdir -p "$DIR" && chmod 700 "$DIR"
  cat > "$CONF" <<'EOF'
# TCDC AIDE config (written by aide.sh; edit aide.sh, not this file)
database_in=file:/root/aide/aide.db
database_out=file:/root/aide/aide.db.new
database_new=file:/root/aide/aide.db.new
gzip_dbout=no
report_url=stdout
report_summarize_changes=yes
report_grouped=yes
report_detailed_init=no
warn_dead_symlinks=no

# FULL: owner, group, permissions, size, mtime, ctime, type, link target, SHA-256
FULL = p+u+g+s+m+c+ftype+l+sha256

# config, accounts, sudo, cron, ssh, pam, systemd units, profile scripts
/etc FULL
# binaries and admin tools (a replaced sshd/ls/ps shows up here)
/usr/bin FULL
/usr/sbin FULL
/usr/local FULL
# systemd units shipped by packages, and PAM modules (password-stealing backdoors)
/usr/lib/systemd/system FULL
/usr/lib/[^/]+/security FULL
# per-user cron, the scored web/FTP content
/var/spool/cron FULL
/var/www FULL
/srv FULL
/var/ftp FULL
# login keys and shell startup files (root and every user)
/root/\.ssh FULL
/root/\.(bashrc|profile|bash_profile) FULL
/home/[^/]+/\.ssh FULL
/home/[^/]+/\.(bashrc|profile|bash_profile|bash_logout) FULL

# --- excluded ---
# organizer tooling: not ours to watch or touch (R7)
!/var/ossec
# our own tool data
!/root/aide
!/root/timecapsule
!/root/tcdc-baseline
# churn that is not an attack
!/etc/mtab$
!/etc/adjtime$
!/etc/.*-$
!/etc/.*\.swp$
EOF
  chmod 600 "$CONF"
}

need_aide(){ command -v aide >/dev/null 2>&1 || die "aide not installed: run 'aide.sh install' (needs apt access)"; }

case "${1:-}" in
  install)
    if ! command -v aide >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q aide >/dev/null \
        || die "apt install failed (no internet on this box?)"
    fi
    # the package enables a daily check timer; we want no scheduled jobs on the box
    systemctl disable --now dailyaidecheck.timer >/dev/null 2>&1 || true
    echo "[aide] installed $(aide --version 2>&1 | head -1); daily timer: $(systemctl is-enabled dailyaidecheck.timer 2>/dev/null || echo none)"
    ;;
  init)
    need_aide; write_conf
    echo "[aide] building baseline (low priority, can take a few minutes)..."
    gentle aide --config="$CONF" --init >/dev/null 2>"$DIR/init.err"
    rc=$?
    [ -s "$NEW" ] || die "init failed (rc=$rc): $(head -c 300 "$DIR/init.err")"
    mv -f "$NEW" "$DB" && chmod 600 "$DB"
    echo "[aide] baseline saved: $DB ($(du -h "$DB" | cut -f1))"
    ;;
  check)
    need_aide; write_conf
    [ -s "$DB" ] || die "no baseline yet: run 'aide.sh init' first"
    gentle aide --config="$CONF" --check
    rc=$?
    # AIDE exit codes: 0 = no changes; 1-7 = bitmask of added/removed/changed; 14+ = error
    if   [ $rc -eq 0 ];  then echo "[aide] no changes since baseline"
    elif [ $rc -lt 14 ]; then echo "[aide] CHANGES FOUND (exit $rc): review above; restore with timecapsule or fix by hand"; exit 1
    else echo "[aide] ERROR (exit $rc)"; exit $rc; fi
    ;;
  accept)
    need_aide; write_conf
    [ -s "$DB" ] || die "no baseline yet: run 'aide.sh init' first"
    echo "[aide] making the CURRENT state the new baseline (only after reviewing 'check')"
    gentle aide --config="$CONF" --update >/dev/null 2>"$DIR/update.err"
    [ -s "$NEW" ] || die "update failed: $(head -c 300 "$DIR/update.err")"
    cp -f "$DB" "$DIR/aide.db.prev" && mv -f "$NEW" "$DB" && chmod 600 "$DB" "$DIR/aide.db.prev"
    echo "[aide] baseline updated (previous kept as aide.db.prev)"
    ;;
  *) sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
