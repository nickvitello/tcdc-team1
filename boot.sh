#!/usr/bin/env bash
# TCDC Team 1 Linux bootstrap.
# Usage: curl -sSL https://raw.githubusercontent.com/GH_USER/tcdc-team1/main/boot.sh | sudo bash -s <boxname>
set -uo pipefail
BOX="${1:-$(hostname)}"
RAW="https://raw.githubusercontent.com/GH_USER/tcdc-team1/main/linux"
TMP="$(mktemp -d)"; trap 'rm -rf "$TMP"' EXIT
echo "[boot] box=$BOX  fetching modules..."
for f in harden.sh watch-agent.sh; do
  if curl -fsSL "$RAW/$f" -o "$TMP/$f"; then echo "[boot] got $f";
  else echo "[boot] !! FAILED to fetch $f (no egress? stage via jumpbox)"; exit 1; fi
done
chmod +x "$TMP"/*.sh
sudo bash "$TMP/harden.sh" "$BOX"
