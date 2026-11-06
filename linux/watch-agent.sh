#!/usr/bin/env bash
# TCDC drift watch-agent. Run by systemd timer every 60s. Compares live state to baseline.
# Reports drift to local log + optional Discord webhook (set TCDC_WEBHOOK env in the unit).
set -uo pipefail
BOX="${1:-unknown}"
BK="/root/tcdc-baseline"
OUT="$BK/drift.log"
WEBHOOK="${TCDC_WEBHOOK:-}"
[ -f "$BK/baseline.sha256" ] || { echo "no baseline, run harden.sh first"; exit 0; }
alert(){
  local m="[$(date '+%F %T')] $BOX DRIFT: $*"
  echo "$m" >> "$OUT"
  [ -n "$WEBHOOK" ] && curl -fsS -m5 -H 'Content-Type: application/json' \
    -d "{\"content\":\"$(echo "$m" | sed 's/"/\\"/g')\"}" "$WEBHOOK" >/dev/null 2>&1 || true
}

# 1. file hash drift vs baseline
while read -r want path; do
  [ -e "$path" ] || { alert "file GONE $path"; continue; }
  have="$(sha256sum "$path" 2>/dev/null | awk '{print $1}')"
  [ "$have" = "$want" ] || alert "file CHANGED $path"
done < "$BK/baseline.sha256"

# 2. new enabled services since baseline (Metasploit/Sliver persistence)
if [ -f "$BK/enabled-services.txt" ]; then
  systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' \
    | grep -vxF -f "$BK/enabled-services.txt" 2>/dev/null \
    | while read -r s; do [ -n "$s" ] && alert "NEW enabled service: $s"; done
fi

# 3. new systemd timers (common C2 persistence)
systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $NF}' | grep -v '^$' \
  | grep -v 'tcdc-watch' > "$BK/.timers.now" 2>/dev/null
[ -f "$BK/.timers.base" ] || cp "$BK/.timers.now" "$BK/.timers.base" 2>/dev/null
grep -vxF -f "$BK/.timers.base" "$BK/.timers.now" 2>/dev/null \
  | while read -r t; do [ -n "$t" ] && alert "NEW timer: $t"; done

# 4. extra UID0 accounts (backdoor)
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd \
  | while read -r u; do [ -n "$u" ] && alert "EXTRA UID0 account: $u"; done

# 5. new authorized_keys not present at baseline
getent passwd | awk -F: '$3>=0{print $6}' | sort -u | while read -r home; do
  ak="$home/.ssh/authorized_keys"
  if [ -f "$ak" ]; then
    h="$(sha256sum "$ak" | awk '{print $1}')"
    grep -q "$h" "$BK/baseline.sha256" 2>/dev/null || alert "authorized_keys changed/new: $ak"
  fi
done

# 6. suspicious outbound-ish listeners on odd high ports (meterpreter/sliver beacons often bind/connect 4444/8080/443-alt)
(ss -tlpnH 2>/dev/null || netstat -tlpn 2>/dev/null) \
  | grep -E ':(4444|5555|8081|9001|1337|31337)\b' \
  | while read -r l; do alert "suspicious listener: $l"; done

exit 0
