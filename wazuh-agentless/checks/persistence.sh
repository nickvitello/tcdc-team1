# Places attackers hide persistence. Diffed every DiffSeconds (default 5 min).
export LC_ALL=C
echo ==CRON==
cat /etc/crontab /etc/cron.d/* 2>/dev/null
ls /etc/cron.hourly /etc/cron.daily /etc/cron.weekly /etc/cron.monthly 2>/dev/null
for f in /var/spool/cron/crontabs/*; do [ -r "$f" ] && { echo "## $f"; grep -v '^#' "$f"; }; done
echo ==TIMERS==; systemctl list-timers --all --no-legend 2>/dev/null | awk '{print $NF}' | sort
echo ==SERVICES-ENABLED==; systemctl list-unit-files --type=service --state=enabled --no-legend 2>/dev/null | awk '{print $1}' | sort
echo ==UNIT-FILES==; find /etc/systemd/system -type f 2>/dev/null | sort | xargs -r sha256sum 2>/dev/null | awk '{print $2, substr($1,1,12)}'
echo ==PRELOAD==; cat /etc/ld.so.preload 2>/dev/null
echo ==PAM==; grep -rhE 'pam_exec|pam_script' /etc/pam.d 2>/dev/null | sort; sha256sum /usr/lib/*/security/*.so 2>/dev/null | awk '{print $2, substr($1,1,12)}'
echo ==STARTUP==; cat /etc/rc.local 2>/dev/null; ls -l --time-style=+%F_%T /etc/profile.d 2>/dev/null | tail -n +2
echo ==SUID==; find / -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null | sort
echo ==CAPABILITIES==; getcap -r /usr /opt 2>/dev/null | sort
echo ==KERNEL-MODULES==; awk '{print $1}' /proc/modules | sort
echo ==APT-SOURCES==; cat /etc/apt/sources.list /etc/apt/sources.list.d/* 2>/dev/null | grep -vE '^[[:space:]]*(#|$)' | sort
echo ==END==
