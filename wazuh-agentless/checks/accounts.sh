# Accounts and access. Diffed every DiffSeconds (default 5 min).
# Root-only sections (sudoers, password changes, everyone's SSH keys, sshd) are
# skipped automatically when not running as root.
export LC_ALL=C
echo ==USERS==; cat /etc/passwd
echo ==GROUPS==; cat /etc/group
echo ==UID0==; awk -F: '$3==0' /etc/passwd
echo ==SUDOERS==
if [ -r /etc/sudoers ]; then grep -hvE '^[[:space:]]*(#|$)' /etc/sudoers /etc/sudoers.d/* 2>/dev/null | sort; else ls -l --time-style=+%F_%T /etc/sudoers.d 2>&1; fi
echo ==PASSWORD-CHANGES==
if [ -r /etc/shadow ]; then while IFS=: read -r u h _; do printf '%s %s\n' "$u" "$(printf '%s' "$h" | sha256sum | cut -c1-12)"; done < /etc/shadow; fi
echo ==SSH-KEYS==
if [ "$(id -u)" = 0 ]; then
  for h in $(awk -F: '{print $6}' /etc/passwd | sort -u); do
    for f in "$h/.ssh/authorized_keys" "$h/.ssh/authorized_keys2"; do [ -f "$f" ] && { echo "## $f"; cat "$f"; }; done
  done
else cat ~/.ssh/authorized_keys 2>/dev/null; fi
echo ==SSHD==; sshd -T 2>/dev/null | grep -iE '^(port|permitrootlogin|passwordauthentication|pubkeyauthentication|authorizedkeysfile|permitemptypasswords|allowusers|allowgroups) ' | sort
echo ==END==
