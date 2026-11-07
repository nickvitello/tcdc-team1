# Read-only state checks, run on each Linux box by Wazuh's agentless ssh_generic_diff.
# Wazuh logs in as YOUR account (no sudo, no su), runs this, stores the output, and
# raises an alert when it differs from the previous run.
#
# How it gets there: setup.ps1 base64-encodes this file into wazuh_manager.conf as
#   echo <base64> | base64 -d | bash
# (Wazuh mangles any argument word containing ; $ " or quotes, so the encoding keeps
# every word plain). Nothing is written to the box.
#
# Keep output STABLE between runs: no timestamps, PIDs, uptimes or counters,
# or every run will alert.
export LC_ALL=C
echo ==USERS==; cat /etc/passwd /etc/group
echo ==UID0==; awk -F: '$3==0' /etc/passwd
echo ==LISTENERS==; ss -tulnH | awk '{print $1, $5}' | sort -u
echo ==SERVICES==; systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | sort
echo ==TIMERS==; systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $NF}' | sort
echo ==CRON==; cat /etc/crontab /etc/cron.d/* 2>/dev/null
echo ==SUDOERS.D==; ls -l --time-style=+%F_%T /etc/sudoers.d 2>&1
echo ==PRELOAD==; cat /etc/ld.so.preload 2>/dev/null
echo ==SUID==; find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort
echo ==PROCESSES==; ps --ppid 2 -p 2 --deselect -o user=,comm= | sort -u
echo ==END==
# End our own login shell with SIGKILL so it never writes this command into the
# account's .bash_history (bash saves history only on a normal exit). Affects
# nothing but this one SSH session, which is closing anyway.
kill -KILL "$PPID"
