#!/usr/bin/env bash
# wazuh-agent.sh - install/remove OUR full Wazuh agent on a Linux box, with guards.
# Run from the jumpbox for every box:  ./fleet.sh wazuh-agent <action> [args]
#
#   check                               is ANY Wazuh agent here? ours, someone else's, or none
#   install <manager-ip> <enroll-pw>    install ours (refuses if any agent already exists: R7)
#   status                              is ours running?
#   remove                              remove ours (refuses to touch an agent that isn't ours)
#
# READ wazuh-agentless/wazuh-agents.md FIRST. Only with Black Team's OK.
set -uo pipefail
VERSION="4.14.10-1"
MARK=/var/ossec/.tcdc-ours
die(){ echo "ERROR: $*" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || die "run as root (sudo)"

# Anything that looks like a Wazuh/OSSEC agent install, ours or not.
existing(){
  [ -d /var/ossec ] && return 0
  dpkg -l 2>/dev/null | grep -qE '^ii +(wazuh-agent|ossec-hids-agent) ' && return 0
  systemctl list-unit-files 2>/dev/null | grep -qE '^(wazuh-agent|ossec)\.service' && return 0
  return 1
}
who_owns(){
  if ! existing; then echo none
  elif [ -f "$MARK" ]; then echo ours
  else echo other; fi
}

case "${1:-}" in
  check)
    case "$(who_owns)" in
      none)  echo "[wazuh-agent] NONE: no Wazuh agent on this box" ;;
      ours)  echo "[wazuh-agent] OURS: our agent ($(cat "$MARK" 2>/dev/null)), service $(systemctl is-active wazuh-agent 2>/dev/null)" ;;
      other) echo "[wazuh-agent] OTHER: a Wazuh agent that is NOT ours is installed. It is almost certainly the organizers'."
             echo "             Do not install, stop, edit or remove anything (R7, R15)."; exit 2 ;;
    esac ;;
  install)
    [ $# -eq 3 ] || die "usage: wazuh-agent.sh install <manager-ip> <enrollment-password>"
    MGR="$2"; PW="$3"
    [[ "$MGR" =~ ^[0-9A-Za-z.-]+$ ]] || die "bad manager address: $MGR"
    [[ "$PW" =~ ^[A-Za-z0-9]+$ ]] || die "enrollment password must be letters/digits"
    if existing; then
      die "a Wazuh agent ($(who_owns)) is already installed here: refusing (R7). Run 'check'."
    fi
    command -v curl >/dev/null && command -v gpg >/dev/null || die "needs curl and gpg"
    # reach the manager's enrollment port before changing anything
    timeout 5 bash -c "exec 3<>/dev/tcp/$MGR/1515" 2>/dev/null || die "cannot reach $MGR:1515 from this box: no agent installed"
    KEY=/usr/share/keyrings/wazuh-tcdc.gpg; LIST=/etc/apt/sources.list.d/wazuh-tcdc.list
    curl -fsS https://packages.wazuh.com/key/GPG-KEY-WAZUH | gpg --no-default-keyring --keyring "gnupg-ring:$KEY" --import >/dev/null 2>&1 \
      || die "cannot download the Wazuh signing key (no internet on this box?)"
    chmod 644 "$KEY"
    echo "deb [signed-by=$KEY] https://packages.wazuh.com/4.x/apt/ stable main" > "$LIST"
    apt-get update -q -o Dir::Etc::sourcelist="$LIST" -o Dir::Etc::sourceparts=- >/dev/null 2>&1 \
      || { rm -f "$LIST" "$KEY"; die "apt update for the Wazuh repo failed"; }
    # agent name ends in -tcdc so nobody mistakes it for an organizer agent (R15)
    if ! WAZUH_MANAGER="$MGR" WAZUH_REGISTRATION_PASSWORD="$PW" WAZUH_AGENT_NAME="$(hostname)-tcdc" \
         DEBIAN_FRONTEND=noninteractive apt-get install -y -q "wazuh-agent=$VERSION" >/dev/null; then
      rm -f "$LIST" "$KEY"; die "install failed"
    fi
    echo "installed $(date '+%F %T') manager=$MGR" > "$MARK"
    # no repo left behind: a later 'apt upgrade' must not silently change the agent
    rm -f "$LIST" "$KEY"
    systemctl daemon-reload; systemctl enable --now wazuh-agent >/dev/null 2>&1
    sleep 5
    echo "[wazuh-agent] installed ours ($VERSION) -> $MGR; service: $(systemctl is-active wazuh-agent)"
    ;;
  status)
    echo "[wazuh-agent] $(who_owns); service: $(systemctl is-active wazuh-agent 2>/dev/null || true)" ;;
  remove)
    case "$(who_owns)" in
      none)  echo "[wazuh-agent] nothing to remove" ;;
      other) die "the installed agent is NOT ours (no $MARK): refusing to remove it (R7)" ;;
      ours)
        systemctl disable --now wazuh-agent >/dev/null 2>&1
        DEBIAN_FRONTEND=noninteractive apt-get purge -y -q wazuh-agent >/dev/null 2>&1
        [ -f "$MARK" ] && rm -rf /var/ossec        # only ever our own install
        rm -f /etc/apt/sources.list.d/wazuh-tcdc.list /usr/share/keyrings/wazuh-tcdc.gpg
        echo "[wazuh-agent] ours removed" ;;
    esac ;;
  *) sed -n '2,12p' "$0" | sed 's/^# \{0,1\}//'; exit 1 ;;
esac
