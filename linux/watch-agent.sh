#!/usr/bin/env bash
# Reports locally; no webhook/export. Timer runs as root once per minute.
set -uo pipefail
umask 077
BOX="${1:-$(hostname)}"
BK=/root/tcdc-baseline
[ -d "$BK" ] || { echo 'MONITOR ERROR: baseline directory missing'; exit 2; }
OUT="$BK/drift.log"
alert(){ printf '[%s] %s DRIFT: %s\n' "$(date '+%F %T')" "$BOX" "$*" >> "$OUT"; }
result=$(python3 /usr/local/lib/tcdc/baseline.py check "$BK/integrity.json" 2>&1)
rc=$?
if [ "$rc" -ne 0 ]; then
  while IFS= read -r line; do alert "$line"; done <<< "$result"
fi
# Nonzero status makes missing/corrupt baseline or a failed collection visible to systemd.
[ "$rc" -le 1 ] || exit 2
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd |
  while IFS= read -r user; do alert "Review extra UID0 account: $user"; done
exit 0
