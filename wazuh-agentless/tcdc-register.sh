#!/bin/bash
# Runs INSIDE the manager container (baked in by Dockerfile.manager).
# Usage:  echo '<password>' | tcdc-register.sh <user@host>
# Adds or REPLACES the stored password for one host, then tests the login.
# The password arrives on stdin so it never appears in a process list.
set -uo pipefail
H="${1:?usage: echo PASSWORD | tcdc-register.sh user@host}"
[[ "$H" =~ ^[a-z_][a-z0-9_.-]*@[0-9A-Za-z.-]+$ ]] || { echo "bad user@host: $H"; exit 2; }
IFS= read -r PW || true
PW="${PW%$'\r'}"                                   # PowerShell pipes add a CR
[ -n "$PW" ] || { echo "empty password"; exit 2; }
case "$PW" in *'|'*) echo "password may not contain |"; exit 2;; esac

cd /var/ossec/agentless || exit 1
# drop any existing entry for exactly this user@host (so password rotation works)
if [ -s .passlist ]; then
  base64 -d .passlist | awk -F'|' -v h="$H" '$1 != h' > .passlist.tmp
  base64 .passlist.tmp > .passlist; rm -f .passlist.tmp
fi
./register_host.sh add "$H" "$PW" "" >/dev/null || { echo "register failed"; exit 1; }
chown root:wazuh .passlist && chmod 640 .passlist

# login test with the same script Wazuh uses. The remote command prints a marker,
# then ends its own shell so nothing lands in .bash_history.
T=$(printf '%s\n' 'echo TCDC_LOGIN_OK' 'kill -KILL "$PPID"' | base64 -w0)
cd /var/ossec
if timeout 60 agentless/ssh_generic_diff "$H" echo "$T" '|' base64 -d '|' bash 2>&1 \
     | tr -d '\r' | grep -q 'TCDC_LOGIN_OK'; then
  echo "OK    $H  (password stored, login works)"
else
  echo "FAIL  $H  (password stored, but login test failed: wrong password, VPN down, or box unreachable)"
  exit 1
fi
