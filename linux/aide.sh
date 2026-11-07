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
# TCDC AIDE config (Optimized Middle-Ground Edition)
database_in=file:/root/aide/aide.db
database_out=file:/root/aide/aide.db.new
database_new=file:/root/aide/aide.db.new
gzip_dbout=no
report_url=stdout
report_summarize_changes=yes
report_grouped=yes
report_detailed_init=no
warn_dead_symlinks=no

# FULL: Comprehensive attributes + crypto signature for high-risk targets
FULL = p+u+g+s+m+c+ftype+l+sha256

# 1. CORE OPERATING SYSTEM ATTACK SURFACE
/etc FULL
/boot FULL

# 2. GLOBAL EXECUTABLES & BINARIES (Catches persistence tools/backdoors)
/bin FULL
/sbin FULL
/usr/bin FULL
/usr/sbin FULL
/usr/local FULL

# 3. KERNEL EXTENSIONS & SYSTEM RUNTIMES (Catches persistence modules)
/lib FULL
/lib64 FULL
/usr/lib/systemd/system FULL
/usr/lib/[^/]+/security FULL

# 4. ENTIRE USER PROFILE INTERFACES (Watches all home directories & root space)
/root FULL
/home FULL

# 5. WEBSERVICES & VARIABLE RESOURCE ARTIFACTS
/var/spool/cron FULL
/var/www FULL
/srv FULL
/var/ftp FULL

# --- EXCLUSIONS (Keeps initialization fast) ---
!/root/aide
!/root/timecapsule
!/root/tcdc-baseline
!/var/ossec
!/var/log
!/var/cache
!/etc/\.git
!/etc/\.etckeeper$
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
    echo "[aide] installed $(aide --version 2>&1 | head -1); daily timer: $(systemctl is-enabled dailyaidecheck.timer 2>/dev/null; true)"
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
