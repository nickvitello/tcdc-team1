#!/usr/bin/env bash
# fleet.sh - run timecapsule (and any premade tool) on every Linux box from the JUMPBOX.
# Nothing is installed on the boxes: the script is streamed over SSH, run once, and deleted.
#
#   TEAM=5 ./fleet.sh snap <label>                 snapshot every box
#   TEAM=5 ./fleet.sh diff <A> <B|now>             diff on every box (now = live state)
#   TEAM=5 ./fleet.sh list                         snapshots on every box
#   TEAM=5 ./fleet.sh pull                         copy every box's snapshots + AIDE db to ./capsules/
#   TEAM=5 ./fleet.sh restore <box> <label> <path> [path...]   roll files back on ONE box
#   TEAM=5 ./fleet.sh restore-copy <box> <label> <path> [path...]   same, but from the copy
#                                                  pulled to the jumpbox (if the box's own snapshots are gone)
#   TEAM=5 ./fleet.sh aide <install|init|check|accept>   AIDE file integrity (see aide.sh)
#   TEAM=5 ./fleet.sh etckeeper <install|list|commit <label>|diff <label>>   git history of /etc
#   TEAM=5 ./fleet.sh etckeeper restore <box> <label> <path> [path...]       roll /etc files back on ONE box
#   TEAM=5 ./fleet.sh wazuh-agent <check|status|remove|install <mgr-ip> <enroll-pw>>   full agent (wazuh-agents.md)
#   TEAM=5 ./fleet.sh run "<command>"              run a command as root on every box
#                                                  e.g. "debsums -c", "lynis audit system --quick"
# Options (environment variables):
#   BOXES=ns1,ipcam        only these boxes          ADMIN_USER=kennedy   log in as someone else
#   FLEET_PASS=...         skip the password prompt (else asked once, hidden)
#   FLEET_HOSTS="name=user@host:port ..."   replace the built-in box list entirely
#
# Run this on the jumpbox, not a personal laptop: pull/diff bring box data back, and
# R23 forbids taking box data off competition infrastructure. The jumpbox is inside it.
set -uo pipefail

HERE="$(cd "$(dirname "$0")" && pwd)"
TC="$HERE/timecapsule.sh"
AIDE_SH="$HERE/aide.sh"
ETCK_SH="$HERE/etckeeper.sh"
WAGENT_SH="$HERE/wazuh-agent.sh"
ADMIN_USER="${ADMIN_USER:-washington}"
OUT="$HERE/capsules"

die(){ echo "ERROR: $*" >&2; exit 1; }
[ -f "$TC" ] || die "timecapsule.sh must sit next to fleet.sh"

# ------------------------------------------------------------------ box list
declare -a NAMES=() TARGETS=()
if [ -n "${FLEET_HOSTS:-}" ]; then
  for e in $FLEET_HOSTS; do NAMES+=("${e%%=*}"); TARGETS+=("${e#*=}"); done
else
  [[ "${TEAM:-}" =~ ^[0-9]+$ ]] || die "set TEAM=<your team number>, e.g. TEAM=5 ./fleet.sh snap start"
  N=$((100 + TEAM))
  NAMES=(ns1 ftp-archive artifactorium ssh-workstation ipcam)
  TARGETS=("$ADMIN_USER@10.$N.10.53:22" "$ADMIN_USER@10.$N.10.21:22" "$ADMIN_USER@10.$N.10.80:22"
           "$ADMIN_USER@10.$N.10.22:22" "$ADMIN_USER@10.150.0.$TEAM:22")
fi
if [ -n "${BOXES:-}" ]; then
  declare -a n2=() t2=()
  for i in "${!NAMES[@]}"; do
    [[ ",$BOXES," == *",${NAMES[$i]},"* ]] && { n2+=("${NAMES[$i]}"); t2+=("${TARGETS[$i]}"); }
  done
  [ ${#n2[@]} -gt 0 ] || die "BOXES=$BOXES matched nothing (known: ${NAMES[*]})"
  NAMES=("${n2[@]}"); TARGETS=("${t2[@]}")
fi

# ------------------------------------------------------------------ ssh plumbing
if [ -z "${FLEET_PASS:-}" ]; then
  read -rsp "Password for $ADMIN_USER (ssh + sudo): " FLEET_PASS; echo
fi
mkdir -p "$HOME/.ssh" && chmod 700 "$HOME/.ssh"
SSH_OPTS=(-o StrictHostKeyChecking=accept-new -o ConnectTimeout=6
          -o ControlMaster=auto -o "ControlPath=$HOME/.ssh/fleet-%r@%h:%p" -o ControlPersist=15m)
if command -v sshpass >/dev/null 2>&1; then
  export SSHPASS="$FLEET_PASS"; SSH=(sshpass -e ssh)
else
  SSH=(ssh)   # you'll type the password once per box; the connection is then reused 15 min
fi

host_of(){ local t="${1#*@}"; echo "${t%:*}"; }
user_of(){ echo "${1%@*}"; }
port_of(){ echo "${1##*:}"; }
sshx(){  # sshx <target> <remote command string>   (stdin passes through)
  local t="$1"; shift
  "${SSH[@]}" "${SSH_OPTS[@]}" -p "$(port_of "$t")" "$(user_of "$t")@$(host_of "$t")" "$@"
}

declare -A NOPASS=()
needs_pw(){  # 0 = sudo wants a password, 1 = passwordless sudo
  local t="$1"
  if [ -z "${NOPASS[$t]:-}" ]; then
    if sshx "$t" 'sudo -n true' </dev/null >/dev/null 2>&1; then NOPASS[$t]=1; else NOPASS[$t]=0; fi
  fi
  [ "${NOPASS[$t]}" = 0 ]
}
# pw_line must only be called AFTER needs_pw ran in this (parent) shell: inside a pipe it
# runs in a subshell, where a fresh check would be repeated every time and never cached.
pw_line(){ [ "${NOPASS[$1]:-0}" = 0 ] && printf '%s\n' "$FLEET_PASS"; true; }

# run timecapsule on a box: script streamed in after the sudo password, CRs stripped
# (a Windows checkout would otherwise break bash), saved to a temp file, run, deleted
tc_remote(){ local t="$1"; shift; script_remote "$t" "$TC" "$@"; }
script_remote(){
  local t="$1" script="$2"; shift 2
  local args; args="$(printf '%q ' "$@")"
  needs_pw "$t"
  { pw_line "$t"; tr -d '\r' < "$script"; } \
    | sshx "$t" "sudo -S -p '' bash -c 'f=\$(mktemp); cat > \"\$f\"; bash \"\$f\" \"\$@\"; rc=\$?; rm -f \"\$f\"; exit \$rc' tc $args"
}
root_remote(){  # run an arbitrary command as root
  local t="$1" cmd="$2"
  needs_pw "$t"
  pw_line "$t" | sshx "$t" "sudo -S -p '' bash -c $(printf '%q' "$cmd")"
}

each(){  # each <function> [args...] - run on every selected box, never stop on one failure
  local fn="$1"; shift; local i rc fails=0
  for i in "${!NAMES[@]}"; do
    echo; echo "=================== ${NAMES[$i]}  ($(host_of "${TARGETS[$i]}"))"
    if ! sshx "${TARGETS[$i]}" true </dev/null 2>/tmp/fleet.err.$$; then
      echo "!! cannot reach/log in: $(tr -d '\r' < /tmp/fleet.err.$$ | tail -1)"; fails=$((fails+1)); continue
    fi
    "$fn" "${TARGETS[$i]}" "${NAMES[$i]}" "$@"; rc=$?
    [ $rc -ne 0 ] && { echo "!! exit code $rc on ${NAMES[$i]}"; fails=$((fails+1)); }
  done
  rm -f /tmp/fleet.err.$$
  echo; echo "=================== done: ${#NAMES[@]} box(es), $fails problem(s)"
}

# ------------------------------------------------------------------ commands
do_snap(){ tc_remote "$1" snap "$3"; }
do_list(){ tc_remote "$1" list; }
do_diff(){ tc_remote "$1" diff "$3" "$4"; }
do_run(){  root_remote "$1" "$3"; }
do_aide(){ script_remote "$1" "$AIDE_SH" "$3"; }
do_etck(){ local t="$1"; shift 2; script_remote "$t" "$ETCK_SH" "$@"; }
do_wagent(){ local t="$1"; shift 2; script_remote "$t" "$WAGENT_SH" "$@"; }
do_pull(){
  local t="$1" name="$2" f
  mkdir -p "$OUT" && chmod 700 "$OUT"
  f="$OUT/$name-$(date +%H%M%S).tgz"
  needs_pw "$t"
  # timecapsule snapshots plus AIDE's database, so an attacker who edits them on
  # the box can't hide changes from a comparison against these copies
  if pw_line "$t" | sshx "$t" "sudo -S -p '' tar czf - -C /root --ignore-failed-read timecapsule aide 2>/dev/null" > "$f" && [ -s "$f" ]; then
    chmod 600 "$f"; echo "saved $f ($(du -h "$f" | cut -f1))"
  else
    rm -f "$f"; echo "!! nothing pulled (no snapshots yet, or tar failed)"; return 1
  fi
}

cmd="${1:-}"; shift || true
case "$cmd" in
  snap)    [ $# -eq 1 ] || die "usage: fleet.sh snap <label>";        each do_snap "$1" ;;
  list)    each do_list ;;
  diff)    [ $# -eq 2 ] || die "usage: fleet.sh diff <A> <B|now>";    each do_diff "$1" "$2" ;;
  run)     [ $# -eq 1 ] || die 'usage: fleet.sh run "<command>"';     each do_run "$1" ;;
  aide)    [[ "${1:-}" =~ ^(install|init|check|accept)$ ]] || die "usage: fleet.sh aide <install|init|check|accept>"
           [ -f "$AIDE_SH" ] || die "aide.sh must sit next to fleet.sh"
           each do_aide "$1" ;;
  wazuh-agent)
    [ -f "$WAGENT_SH" ] || die "wazuh-agent.sh must sit next to fleet.sh"
    case "${1:-}" in
      check|status|remove) each do_wagent "$1" ;;
      install)
        [ $# -eq 3 ] || die "usage: fleet.sh wazuh-agent install <manager-ip> <enrollment-password>"
        echo "Installs OUR Wazuh agent on: ${NAMES[*]} (refuses on any box that already has an agent)."
        read -rp "Black Team OK'd this and you ran 'check'? Type yes: " ok; [ "$ok" = "yes" ] || die "aborted"
        each do_wagent install "$2" "$3" ;;
      *) die "usage: fleet.sh wazuh-agent <check|status|remove|install <manager-ip> <enrollment-password>>" ;;
    esac ;;
  etckeeper)
    [ -f "$ETCK_SH" ] || die "etckeeper.sh must sit next to fleet.sh"
    case "${1:-}" in
      install|list)  each do_etck "$1" ;;
      commit|diff)   [ $# -eq 2 ] || die "usage: fleet.sh etckeeper $1 <label>"; each do_etck "$1" "$2" ;;
      restore)
        [ $# -ge 4 ] || die "usage: fleet.sh etckeeper restore <box> <label> <path> [path...]"
        box="$2"; idx=""; for i in "${!NAMES[@]}"; do [ "${NAMES[$i]}" = "$box" ] && idx=$i; done
        [ -n "$idx" ] || die "unknown box '$box' (known: ${NAMES[*]})"
        echo "etckeeper restore on $box from '$3': ${*:4}"
        read -rp "Type yes to proceed: " ok; [ "$ok" = "yes" ] || die "aborted"
        script_remote "${TARGETS[$idx]}" "$ETCK_SH" restore "$3" "${@:4}" ;;
      *) die "usage: fleet.sh etckeeper <install|list|commit <label>|diff <label>|restore <box> <label> <path>...>" ;;
    esac ;;
  pull)    each do_pull ;;
  restore-copy)
    [ $# -ge 3 ] || die "usage: fleet.sh restore-copy <box> <label> <path> [path...]"
    box="$1"; label="$2"; shift 2
    idx=""; for i in "${!NAMES[@]}"; do [ "${NAMES[$i]}" = "$box" ] && idx=$i; done
    [ -n "$idx" ] || die "unknown box '$box' (known: ${NAMES[*]})"
    [[ "$label" =~ ^[A-Za-z0-9._-]+$ ]] || die "bad label '$label'"
    rels=()
    for p in "$@"; do
      [[ "$p" == /?* ]] || die "use absolute paths: $p"
      case "$p" in
        /|/etc|/etc/|/etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/passwd-|/etc/shadow-|/etc/group-|/etc/gshadow-|/etc/audit|/etc/audit/*|/etc/cloud|/etc/cloud/*)
          die "refusing to restore $p: it would revert accounts or touch organizer tooling (R7/R8)" ;;
      esac
      r="${p#/}"; rels+=("${r%/}")
    done
    # newest pulled copy of this box that contains the label
    src=""; snapdir=""
    for f in $(ls -1t "$OUT/$box"-*.tgz 2>/dev/null); do
      d="$(tar tzf "$f" 2>/dev/null | grep -E "^timecapsule/[0-9]+-[0-9]+-$label/backup.tgz$" | sort | tail -1)"
      [ -n "$d" ] && { src="$f"; snapdir="$d"; break; }
    done
    [ -n "$src" ] || die "no pulled copy of $box contains a snapshot '$label' (run ./fleet.sh pull while the box still has it)"
    work="$(mktemp -d)"; trap 'rm -rf "$work"' EXIT
    tar xzf "$src" -C "$work" "$snapdir" || die "cannot read $src"
    bk="$work/$snapdir"
    for r in "${rels[@]}"; do
      tar tzf "$bk" | sed 's#/$##' | grep -qxF -e "$r" -e "$r/" || tar tzf "$bk" | grep -q "^$r/" \
        || die "/$r is not in that snapshot's backup"
    done
    echo "restore-copy on $box from the jumpbox copy $(basename "$src") ($snapdir): ${rels[*]/#//}"
    read -rp "Type yes to proceed: " ok; [ "$ok" = "yes" ] || die "aborted"
    t="${TARGETS[$idx]}"; ts="$(date +%Y%m%d-%H%M%S)"; q="$(printf '%q ' "${rels[@]}")"
    needs_pw "$t"
    # save the box's current version first (undo), then extract the jumpbox copy over it
    { pw_line "$t"; cat "$bk"; } | sshx "$t" "sudo -S -p '' bash -c 'mkdir -p /root/timecapsule && tar czf /root/timecapsule/pre-restore-copy-$ts.tgz -C / --ignore-failed-read $q 2>/dev/null; tar xzpf - -C / --same-owner $q && echo restored'" \
      && echo "undo: tar xzpf /root/timecapsule/pre-restore-copy-$ts.tgz -C /   (on $box)" \
      && echo "NEXT: syntax-check and reload the service; files added since '$label' are NOT deleted (check ./fleet.sh diff)"
    ;;
  restore)
    [ $# -ge 3 ] || die "usage: fleet.sh restore <box> <label> <path> [path...]"
    box="$1"; shift
    idx=""; for i in "${!NAMES[@]}"; do [ "${NAMES[$i]}" = "$box" ] && idx=$i; done
    [ -n "$idx" ] || die "unknown box '$box' (known: ${NAMES[*]})"
    echo "Restore on $box from '$1': ${*:2}"
    read -rp "Type yes to proceed: " ok; [ "$ok" = "yes" ] || die "aborted"
    tc_remote "${TARGETS[$idx]}" restore "$@" ;;
  *) sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
