# Is each service up? Diffed every FastSeconds (default 1 min): a second uptime
# alarm next to Watchtower and the scoreboard. Only lists services that exist.
export LC_ALL=C
echo ==SERVICES==
systemctl list-units --type=service --all --no-legend --plain 2>/dev/null \
  | awk '$1 ~ /^(apache2|nginx|httpd|lighttpd|bind9|named|unbound|dnsmasq|vsftpd|proftpd|pure-ftpd|ssh|sshd|mosquitto|mysql|mariadb|postgresql|php[0-9.]*-fpm|cron|rsyslog|ufw)\.service$/ {print $1, $3, $4}' | sort
echo ==LOCAL-PORTS==
for p in 21 22 53 80 443 1883; do (exec 3<>"/dev/tcp/127.0.0.1/$p") 2>/dev/null && echo "tcp/$p open" || echo "tcp/$p closed"; done
echo ==END==
