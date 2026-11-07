#!/usr/bin/env bash
# etckeeper.sh - git history of /etc, as a second restore path independent of timecapsule.
# Run as root on a box, or for every box from the jumpbox:  ./fleet.sh etckeeper <action>
#
#   install            apt install etckeeper (it commits /etc once on install), then turn
#                      OFF its daily autocommit timer/cron: no scheduled jobs on the box
#   commit <label>     commit /etc now and tag it, e.g. commit hardened
#   diff <label>       what changed in /etc since <label> (new, edited and deleted files)
#   list               tags and recent commits
#   restore <label> <path> [path...]   put files back as they were at <label>
#                      (paths under /etc; the current version is committed first)
#
# Everything stays in /etc/.git on the box (root-only, mode 700). Read-only apart from
# that, except restore. Same guards as timecapsule: never restores account files
# (blackteam/whiteteam passwords, R8) or organizer tooling config (R7).
set -uo pipefail
die(){ echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"
G(){ git -C /etc "$@"; }
need(){ command -v etckeeper >/dev/null 2>&1 && [ -d /etc/.git ] || die "etckeeper not set up: run 'etckeeper.sh install' (needs apt access)"; }
label_ok(){ [[ "$1" =~ ^[A-Za-z0-9._-]+$ ]] || die "label must be letters/digits/._- (got '$1')"; }

case "${1:-}" in
  install)
    if ! command -v etckeeper >/dev/null 2>&1; then
      DEBIAN_FRONTEND=noninteractive apt-get install -y -q etckeeper >/dev/null \
        || die "apt install failed (no internet on this box?)"
    fi
    [ -d /etc/.git ] || etckeeper init >/dev/null
    # no scheduled jobs: stop the daily timer, and tell the daily cron script to skip
    systemctl disable --now etckeeper.timer >/dev/null 2>&1 || true
    C=/etc/etckeeper/etckeeper.conf
    if [ -f "$C" ] && ! grep -q '^AVOID_DAILY_AUTOCOMMITS=1' "$C"; then
      sed -i 's/^#\?AVOID_DAILY_AUTOCOMMITS=.*/AVOID_DAILY_AUTOCOMMITS=1/' "$C"
      grep -q '^AVOID_DAILY_AUTOCOMMITS=1' "$C" || echo 'AVOID_DAILY_AUTOCOMMITS=1' >> "$C"
    fi
    G rev-parse -q --verify HEAD >/dev/null || etckeeper commit "etckeeper.sh install" >/dev/null
    echo "[etckeeper] ready: $(G rev-list --count HEAD) commit(s); daily timer: $(systemctl is-enabled etckeeper.timer 2>/dev/null; true); daily autocommit: off"
    ;;
  commit)
    need; [ -n "${2:-}" ] || die "usage: etckeeper.sh commit <label>"; label_ok "$2"
    G tag -l "$2" | grep -qx "$2" && die "label '$2' already exists (pick a new one, e.g. $2-2)"
    if [ -n "$(G status --porcelain)" ]; then
      etckeeper commit "tcdc: $2" >/dev/null || die "commit failed"
    fi
    G tag "$2" && echo "[etckeeper] /etc saved as '$2' ($(G rev-parse --short HEAD))"
    ;;
  diff)
    need; [ -n "${2:-}" ] || die "usage: etckeeper.sh diff <label>"; label_ok "$2"
    G rev-parse -q --verify "refs/tags/$2" >/dev/null || die "no label '$2' (try: etckeeper.sh list)"
    echo "=== /etc changes since '$2' (A=new  M=edited  D=deleted, includes uncommitted)"
    G add -A -N . 2>/dev/null          # make brand-new files visible to diff (stages nothing)
    out="$(G diff --name-status "$2" -- . ':!.etckeeper')"
    if [ -z "$out" ]; then echo "(no changes)"; exit 0; fi
    echo "$out" | sed 's/^/  /'
    echo; echo "=== details"
    G --no-pager diff "$2" -- . ':!.etckeeper' ':!shadow' ':!shadow-' ':!gshadow' ':!gshadow-' | head -300
    echo "(password hashes in shadow/gshadow are not shown)"
    exit 1
    ;;
  list)
    need
    echo "=== labels"; G tag -l --sort=creatordate --format='  %(refname:short)  %(creatordate:short) %(creatordate:format:%H:%M)'
    echo "=== recent commits"; G --no-pager log --format='  %h %ad %s' --date=format:'%m-%d %H:%M' -10
    ;;
  restore)
    need; shift
    [ $# -ge 2 ] || die "usage: etckeeper.sh restore <label> <path> [path...]"
    label="$1"; shift; label_ok "$label"
    G rev-parse -q --verify "refs/tags/$label" >/dev/null || die "no label '$label' (try: etckeeper.sh list)"
    rels=()
    for p in "$@"; do
      [[ "$p" == /etc/?* ]] || die "only paths under /etc can be restored: $p"
      rel="${p#/etc/}"; rel="${rel%/}"
      case "/etc/$rel" in
        /etc/passwd|/etc/shadow|/etc/group|/etc/gshadow|/etc/passwd-|/etc/shadow-|/etc/group-|/etc/gshadow-|/etc/audit|/etc/audit/*|/etc/cloud|/etc/cloud/*)
          die "refusing to restore /etc/$rel: it would revert accounts or touch organizer tooling (R7/R8)" ;;
      esac
      G cat-file -e "$label:$rel" 2>/dev/null || die "/etc/$rel did not exist at '$label'"
      rels+=("$rel")
    done
    # 1. keep the current state, so this restore can itself be undone
    if [ -n "$(G status --porcelain)" ]; then etckeeper commit "tcdc: before restore from $label" >/dev/null; fi
    before="$(G rev-parse --short HEAD)"
    # 2. put the files back, then let etckeeper re-apply recorded owners/permissions
    G checkout "$label" -- "${rels[@]}" || die "checkout failed"
    etckeeper init >/dev/null 2>&1
    for r in "${rels[@]}"; do echo "[etckeeper] restored /etc/$r from '$label'"; done
    # 3. like timecapsule: a restore never deletes. Show files added since the label.
    for r in "${rels[@]}"; do
      if [ -d "/etc/$r" ]; then
        extra="$(G ls-files --others --exclude-standard -- "$r"; comm -13 <(G ls-tree -r --name-only "$label" -- "$r" | sort) <(G ls-files -- "$r" | sort))"
        [ -n "$extra" ] && { echo "[etckeeper] !! in /etc/$r but not at '$label' (review, remove by hand):"; echo "$extra" | sort -u | sed 's#^#      /etc/#'; }
      fi
    done
    echo "[etckeeper] NEXT: syntax-check and reload the service, then watch the scoreboard."
    echo "            Undo this restore with: git -C /etc checkout $before -- <path> && etckeeper init"
    ;;
  *) sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
