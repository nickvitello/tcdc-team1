# Who is on the box and what was just dropped on it. Diffed every ActivitySeconds
# (default 2 min). Expect some noise here: your own team's logins show up too.
export LC_ALL=C
echo ==LOGGED-IN==; who | awk '{print $1, $5}' | sort -u
echo ==TMP-EXECUTABLES==; find /tmp /var/tmp /dev/shm -xdev -path '*/systemd-private-*' -prune -o -type f -perm /111 -print 2>/dev/null | sort
echo ==WEB-SCRIPTS==; find /var/www /srv -xdev -type f \( -name '*.php*' -o -name '*.phtml' -o -name '*.jsp' -o -name '*.asp*' -o -name '*.cgi' -o -name '*.pl' -o -name '*.py' -o -name '*.sh' \) 2>/dev/null | sort
echo ==PROCESSES==; ps --ppid 2 -p 2 --deselect -o user=,comm= | sort -u
echo ==END==
