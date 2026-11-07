#!/usr/bin/env bash
# Run from a reviewed checkout or fetch this file and modules at the same immutable revision.
set -euo pipefail
umask 077
BOX="${1:-$(hostname)}"
[ $# -eq 0 ] || shift
REF="${TCDC_REF:-}"
[[ "$REF" =~ ^[0-9a-fA-F]{40}$ ]] || { echo 'Set TCDC_REF to a reviewed 40-character commit SHA before downloading'; exit 2; }
RAW="https://raw.githubusercontent.com/nickvitello/tcdc-team1/$REF/linux"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
for f in harden.sh watch-agent.sh baseline.py; do
  curl --connect-timeout 10 --max-time 60 -fsSL "$RAW/$f" -o "$TMP/$f"
  [ -s "$TMP/$f" ] || { echo "Empty module: $f"; exit 2; }
done
sudo bash "$TMP/harden.sh" "$BOX" "$@"
