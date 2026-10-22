"""Where PHP stacks keep things, across distributions, panels and one-click stacks.

Covered layouts: Debian/Ubuntu, RHEL/CentOS/Rocky/Alma/Amazon (incl. Remi/SCL), Alpine,
openSUSE, Arch; BT Panel (宝塔) / aaPanel, 1Panel, cPanel (EA-PHP), Plesk, CyberPanel /
OpenLiteSpeed, HestiaCP / VestaCP, ISPConfig, DirectAdmin, Virtualmin, LNMP.org, OneinStack,
Bitnami, XAMPP. Missing paths are simply skipped, so over-listing is harmless.
"""

WEB_USER_NAMES = ("www-data", "apache", "nginx", "www", "http", "httpd", "wwwrun",
                  "lighttpd", "php-fpm", "caddy", "litespeed", "nobody-www", "lsadm")
MYSQL_USER_NAMES = ("mysql", "mariadb")
# Web users inside official/common container images (Debian www-data, Alpine www-data).
CONTAINER_WEB_UIDS = (33, 82)
# 1Panel and BT Docker PHP images remap www-data to uid 1000. On the host uid 1000 is
# usually the first login user, so it only counts for processes inside containers.
CONTAINERIZED_WEB_UIDS = (33, 82, 1000)

WEBROOT_CANDIDATES = (
    "/var/www", "/srv/www", "/srv/http", "/usr/share/nginx", "/usr/local/nginx/html",
    "/usr/local/apache2/htdocs", "/usr/local/apache/htdocs", "/www/wwwroot", "/home/wwwroot",
    "/data/wwwroot", "/data/www", "/opt/lampp/htdocs", "/usr/local/www", "/var/lib/nginx/html",
    "/usr/share/webapps", "/usr/share/phpmyadmin", "/usr/share/phpMyAdmin",
    "/www/server/phpmyadmin", "/var/lib/phpmyadmin", "/usr/local/lsws/Example/html",
    "/www/dk_project/wwwroot", "/app",
)
WEBROOT_GLOBS = (
    "/home/*/public_html", "/home/*/www", "/home/*/domains/*/public_html", "/home/*/web",
    "/home/*/web/*/public_html", "/home/*/web/*/private", "/var/www/clients/*/*/web",
    "/var/www/vhosts/*/httpdocs", "/opt/bitnami/apps/*/htdocs", "/opt/bitnami/*/htdocs",
    "/usr/local/lsws/*/html",
)
NGINX_CONF_GLOBS = (
    "/etc/nginx/*.conf", "/etc/nginx/*/*.conf", "/etc/nginx/sites-enabled/*",
    "/etc/nginx/sites-available/*", "/etc/nginx/http.d/*.conf",
    "/usr/local/nginx/conf/*.conf", "/usr/local/nginx/conf/*/*.conf",
    "/www/server/nginx/conf/*.conf", "/www/server/panel/vhost/nginx/*.conf",
    "/usr/local/openresty/nginx/conf/*.conf", "/usr/local/openresty/nginx/conf/*/*.conf",
)
APACHE_CONF_GLOBS = (
    "/etc/apache2/*.conf", "/etc/apache2/*/*.conf", "/etc/apache2/sites-enabled/*",
    "/etc/apache2/envvars", "/etc/apache2/vhosts.d/*.conf", "/etc/httpd/conf/*.conf",
    "/etc/httpd/conf.d/*.conf", "/etc/httpd/conf/extra/*.conf",
    "/usr/local/apache/conf/*.conf", "/usr/local/apache/conf/*/*.conf",
    "/www/server/apache/conf/*.conf", "/www/server/panel/vhost/apache/*.conf",
    "/usr/local/lsws/conf/vhosts/*/*.conf", "/usr/local/lsws/conf/*.conf",
)
FPM_CONF_GLOBS = (
    "/etc/php/*/fpm/pool.d/*.conf", "/etc/php/*/fpm/php-fpm.conf", "/etc/php-fpm.d/*.conf",
    "/etc/php-fpm.conf", "/etc/php/php-fpm.conf", "/etc/php/php-fpm.d/*.conf",
    "/etc/php[0-9]*/php-fpm.conf", "/etc/php[0-9]*/php-fpm.d/*.conf",
    "/etc/php[0-9]*/fpm/php-fpm.conf", "/etc/php[0-9]*/fpm/php-fpm.d/*.conf",
    "/usr/local/etc/php-fpm.conf", "/usr/local/etc/php-fpm.d/*.conf",
    "/usr/local/php*/etc/php-fpm.conf", "/usr/local/php*/etc/php-fpm.d/*.conf",
    "/www/server/php/*/etc/php-fpm.conf", "/etc/opt/remi/php*/php-fpm.d/*.conf",
    "/opt/remi/php*/root/etc/php-fpm.d/*.conf", "/opt/cpanel/ea-php*/root/etc/php-fpm.d/*.conf",
    "/opt/plesk/php/*/etc/php-fpm.d/*.conf", "/www/dk_project/runtime/run/php/*/conf/php-fpm.conf",
)
PHP_INI_GLOBS = (
    "/etc/php.ini", "/etc/php.d/*.ini", "/etc/php/php.ini", "/etc/php/conf.d/*.ini",
    "/etc/php/*/*/php.ini", "/etc/php/*/*/conf.d/*.ini", "/etc/php[0-9]*/php.ini",
    "/etc/php[0-9]*/conf.d/*.ini", "/etc/php[0-9]*/*/php.ini", "/etc/php5/*/php.ini",
    "/usr/local/etc/php/php.ini", "/usr/local/etc/php/conf.d/*.ini", "/usr/local/lib/php.ini",
    "/usr/local/php*/etc/php.ini", "/usr/local/php*/lib/php.ini", "/www/server/php/*/etc/php.ini",
    "/etc/opt/remi/php*/php.ini", "/etc/opt/remi/php*/php.d/*.ini",
    "/opt/remi/php*/root/etc/php.ini", "/opt/cpanel/ea-php*/root/etc/php.ini",
    "/opt/alt/php*/etc/php.ini", "/usr/local/lsws/lsphp*/etc/php/*/litespeed/php.ini",
    "/opt/plesk/php/*/etc/php.ini", "/opt/bitnami/php/etc/php.ini",
    "/var/www/vhosts/system/*/etc/php.ini", "/usr/local/lsws/lsphp*/etc/php.ini",
    "/home/*/etc/php*/php.ini", "/www/dk_project/runtime/run/php/*/conf/php.ini",
)
LOG_DIRS = (
    "/var/log/nginx", "/var/log/apache2", "/var/log/httpd", "/var/log/lighttpd", "/var/log/php",
    "/var/log/php-fpm", "/var/log/caddy", "/var/log/litespeed", "/var/log/modsecurity",
    "/var/log/suricata", "/usr/local/nginx/logs", "/usr/local/apache/logs",
    "/usr/local/apache/domlogs", "/usr/local/apache2/logs", "/usr/local/openresty/nginx/logs",
    "/usr/local/lsws/logs", "/www/wwwlogs", "/www/server/nginx/logs", "/www/server/apache/logs",
    "/home/wwwlogs", "/data/wwwlogs", "/var/log/httpd/domains", "/opt/bitnami/apache2/logs",
    "/opt/bitnami/nginx/logs", "/opt/bitnami/php/logs", "/var/log/virtualmin",
    "/var/log/ispconfig/httpd",
)
LOG_GLOBS = (
    "/var/log/php*.log*", "/var/log/php*-fpm*", "/var/log/php[0-9]*", "/var/log/modsec_audit.log*",
    "/var/log/syslog*", "/var/log/messages*", "/www/server/php/*/var/log",
    "/usr/local/php*/var/log", "/var/opt/remi/php*/log/php-fpm", "/var/www/vhosts/system/*/logs",
    "/home/*/logs", "/opt/cpanel/ea-php*/root/usr/var/log/php-fpm", "/var/log/plesk-php*-fpm",
    "/www/dk_project/runtime/run/php/*/log", "/home/*/public_html/error_log",
    "/home/*/public_html/*/error_log",
)
SESSION_DIR_CANDIDATES = (
    "/var/lib/php/sessions", "/var/lib/php/session", "/var/lib/php5", "/var/lib/php", "/tmp",
    "/tmp/sessions", "/var/tmp", "/var/cpanel/php/sessions", "/www/server/php/tmp",
    "/www/php_session", "/var/lib/lsphp/session",
)
SESSION_DIR_GLOBS = (
    "/var/opt/remi/php*/lib/php/session", "/opt/remi/php*/root/var/lib/php/session",
    "/opt/alt/php*/var/lib/php/session", "/usr/local/php*/var/session", "/var/lib/php*/sessions",
    "/var/lib/php[0-9]*", "/home/*/tmp", "/var/www/clients/client*/web*/tmp",
)
# Applications that keep native PHP session files themselves (relative to a web root,
# also one and two levels below it): ThinkPHP, DedeCMS, OpenCart, Magento.
APP_SESSION_DIRS = ("runtime/session", "data/sessions_*", "storage/session", "var/session")

# 1Panel: BASE_DIR comes from 1pctl (default /opt); paths below are relative to
# <BASE_DIR>/1panel and cover the v1 (OpenResty app) and v2 (www/, runtime/) layouts.
ONEPANEL_CTL = ("/usr/local/bin/1pctl", "/usr/bin/1pctl")
ONEPANEL_WEBROOTS = ("www", "apps/openresty/*/www")
ONEPANEL_APP_WEBROOTS = ("wordpress", "discuz", "typecho", "emlog", "kodbox", "nextcloud",
                         "joomla", "drupal", "maccms", "dzzoffice")
ONEPANEL_LOGS = ("www/sites/*/log", "apps/openresty/*/log", "apps/openresty/*/www/sites/*/log",
                 "runtime/php/*/log", "apps/php*/*/log")
ONEPANEL_INI = ("runtime/php/*/conf/php.ini", "runtime/php/*/conf/conf.d/*.ini",
                "apps/php*/*/conf/php.ini")
ONEPANEL_NGINX = ("www/conf.d/*.conf", "apps/openresty/*/conf/nginx.conf",
                  "apps/openresty/*/conf/conf.d/*.conf")
ONEPANEL_FPM = ("runtime/php/*/conf/php-fpm.conf", "apps/php*/*/conf/php-fpm.conf")
# Directories that legitimately hold generated PHP (compiled templates / caches); used
# only for context in reports - signatures still run on them.
GENERATED_PHP_DIRS = (
    "/storage/framework/views/", "/bootstrap/cache/", "/runtime/", "/var/cache/",
    "/templates_c/", "/data/template/", "/tmp/twig/", "/generated/code/", "/cache/",
)
