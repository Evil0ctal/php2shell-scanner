# php2shell-scanner

[English](README.md) | **简体中文**

针对 PHP `session.upload_progress` 远程代码执行漏洞 **CVE-2026-109618 / CVE-2026-109619**
（又称 “php2shell”）的**漏洞检测**与**入侵取证**工具。

作者：**[Evil0ctal](https://github.com/Evil0ctal)** ·
仓库：<https://github.com/Evil0ctal/php2shell-scanner> · 许可证：[MIT](LICENSE)

> [!WARNING]
> **法律声明：** 本工具仅用于对你拥有或已获得明确授权的系统进行漏洞检测和入侵取证，
> 不得用于任何非法用途。使用者须自行遵守所在地法律法规，作者不对任何滥用行为承担责任。

## 一个工具，完整闭环

| 步骤 | 命令 | 回答的问题 |
|---|---|---|
| 1. 检测 | `php2shell-scanner scan <网址 / 域名 / IP:端口>` | *这台服务器有没有漏洞？* 远程、**非破坏性**检测 |
| 2. 取证 | `sudo php2shell-scanner forensics`（在服务器上运行） | *是否已经被入侵？* 即使 PHP / phpMyAdmin 已卸载也能查 |
| 3. 报告 | 自动生成 | 终端摘要、可下载分享的 **Markdown 报告**，以及可选的 JSON |

- **零依赖**：只用 Python 3.6.1+ 标准库，可打包成单个 `.pyz` 文件。
- **安全设计**：远程扫描绝不进行利用；取证模式严格只读（以 `O_NOATIME` 打开文件、不修改
  任何内容、不执行发现的任何文件）。
- **贴近实战**：覆盖 WordPress、Laravel、ThinkPHP、Drupal、Joomla、Magento 等 PHP 应用；
  宝塔、1Panel、cPanel、Plesk 等面板；Docker/Podman 中运行的 PHP；Ubuntu、Debian、
  RHEL/Rocky/Alma、Amazon Linux、Alpine、openSUSE、Arch 等发行版。

## 快速开始

从 [Releases](https://github.com/Evil0ctal/php2shell-scanner/releases) 下载单文件版本
（无需安装，只要 Python 3.6.1+）：

```bash
curl -fLO https://github.com/Evil0ctal/php2shell-scanner/releases/latest/download/php2shell-scanner.pyz
curl -fLO https://github.com/Evil0ctal/php2shell-scanner/releases/latest/download/php2shell-scanner.pyz.sha256
sha256sum -c php2shell-scanner.pyz.sha256
sudo python3 php2shell-scanner.pyz forensics          # 或：python3 php2shell-scanner.pyz scan <目标>
```

也可以从源码构建：

```bash
git clone https://github.com/Evil0ctal/php2shell-scanner && cd php2shell-scanner
./build_pyz.sh                              # 生成 dist/php2shell-scanner.pyz（单文件）

python3 dist/php2shell-scanner.pyz          # 交互式菜单：远程扫描或本机取证
```

```bash
# 1) 远程、非破坏性的漏洞检测
python3 php2shell-scanner.pyz scan example.com
python3 php2shell-scanner.pyz scan https://shop.example.com:8443 --path /login.php
python3 php2shell-scanner.pyz scan -f targets.txt --threads 8 --json scan.json

# 2) 在服务器上：是否已被入侵？（需要 root 才能读取证据）
scp dist/php2shell-scanner.pyz root@server:/root/
sudo python3 /root/php2shell-scanner.pyz forensics --since 2026-09-01

# 离线扫描可疑磁盘挂载出来的快照（结果最可信）
python3 php2shell-scanner.pyz forensics --root /mnt/suspect-disk
```

不打包也可以，在仓库目录执行 `python3 php2shell-scanner.py <命令>`。服务器上没有 `python3`？
宝塔 / aaPanel 自带一个（`/www/server/panel/pyenv/bin/python3`，也可用 `btpython`）；
RHEL/Alma/Rocky 8 可用 `/usr/libexec/platform-python`；CentOS 7 需先 `yum install python3`。

## 远程扫描（`scan`）

综合多种**相互独立**的方法交叉验证，单一弱信号绝不会把目标判为“有漏洞”：

| # | 方法 | 信号 |
|---|---|---|
| 1 | 多页面、多轮重复的版本指纹（`--rounds`） | `X-Powered-By` / `Server` / `X-PHP-Version`；版本不一致说明负载均衡后有多台后端；识别发行版后缀（`-1ubuntu2.14`、`~deb12u1`、`.el8`），提示可能已回移植补丁 |
| 2 | 暴露的 `phpinfo()`（11 个常见路径） | 权威版本号和 SAPI，以及 `session.upload_progress.enabled`、`use_only_cookies`、`use_strict_mode`、`file_uploads` |
| 3 | 版本线索 | `composer.json` 中的 PHP 约束、PHP < 5.5 的彩蛋 GUID、PHP Cookie/应用特征（WordPress、Laravel、ThinkPHP、Discuz! 等） |
| 4 | 可达性检测 | 一个对照 multipart POST，加上一个附带 `PHP_SESSION_UPLOAD_PROGRESS` 字段的相同请求，**不带任何 session ID**，PHP 不会写入任何上传进度；用来判断边缘 WAF 是否拦截了漏洞功能 |
| 5 | 被动异常检测 | 64 位以上的超长 `PHPSESSID`（CVE-2026-109618 的堆内存泄漏症状）、CDN/边缘识别、SAPI 推断 |

**绝不会发送：** session ID（Cookie 或表单字段）、构造的恶意文件名、大包/拖延/分块请求，
以及任何会写入 session、打崩 worker 或执行代码的内容。`--passive` 只发送 GET/HEAD 请求。
请求的 User-Agent 为 `php2shell-scanner/<版本>`，表明身份。每个目标约 20–30 个请求；
跳转最多跟随一次且只在同一主机内；每个请求最长 3 × `--timeout`，每个目标最长 `--budget` 秒，
恶意或极慢的服务器无法拖住扫描。

| 结果 | 含义 | 退出码 |
|---|---|---|
| **VULNERABLE** | 观察到受影响版本（来自 phpinfo，或不带发行版后缀的响应头） | 3 |
| **LIKELY VULNERABLE** | 发行版构建中的受影响上游版本、EOL 分支，或出现泄漏症状 | 2 |
| **UNKNOWN** / **UNREACHABLE** | 检测到 PHP 但版本被隐藏 / 目标无响应 | 1 |
| **NOT VULNERABLE** / **NO PHP DETECTED** | 只观察到已修复版本 / 未发现 PHP | 0 |

缓解措施（关闭 upload_progress、边缘 WAF）会和结果一起报告，但不会掩盖结果，
因为 var_destroy UAF 和 OOM 利用链不依赖 upload_progress。远程检测看不到回移植补丁、
被隐藏的版本或 CDN 背后的源站，请用 `php -v` 确认，并在服务器上运行 `forensics`。

| 参数 | 含义 |
|---|---|
| `TARGET ...`、`-f FILE` | 网址、域名、`ip:端口[/路径]`；未写协议时先试 https 再试 http |
| `--path /x.php` | 额外要做指纹识别的 PHP 页面（可重复） |
| `--passive` | 只发 GET/HEAD，跳过可达性检测 |
| `--rounds N`、`--threads N`、`--delay 秒`、`--timeout 秒`、`--budget 秒` | 节奏、并发与时间上限 |
| `--strict-tls` | 证书不可信时不再继续（默认：继续并在报告中注明） |
| `--json FILE`、`--markdown FILE`、`--no-markdown` | 报告（默认生成 Markdown） |
| `--yes` | 非交互式确认已获授权（否则会提示确认） |

## 入侵取证（`forensics`）

卸载 PHP 能堵住漏洞，但清除不了攻击者留下的东西。取证扫描专门查找这些痕迹，
可在实机上运行，也可用 `--root` 扫描挂载的磁盘镜像。

| 检查项 | 查找什么 |
|---|---|
| `sessions` | PHP session 文件中的 PHP 代码、序列化 gadget、公开利用工具生成的 session ID、残留的 `upload_progress_` 条目、膨胀的 session（主机**和容器**内） |
| `logs` | 包含 `sess_*` 的 LFI 请求、phpMyAdmin CVE-2018-12613、请求体中的 `PHP_SESSION_UPLOAD_PROGRESS` 和构造的文件名（WAF/ModSecurity 日志）、webshell 流量和管理工具 UA、phpMyAdmin 爆破、被下载的 `.env`/备份文件、OOM 和 `Session object destruction failed` 错误、worker 崩溃、Docker/Kubernetes 容器日志、轮转的 `.gz/.bz2/.xz` 日志、journald |
| `webroot` | webshell（请求参数进入 eval/exec、冰蝎、哥斯拉、蚁剑、中国菜刀、混淆、反弹 shell）、上传目录和图片中的 PHP、隐藏及双扩展名 PHP、`include` `.ico` 文件或十六进制编码路径、`auto_prepend_file`、恶意 `.htaccess`、MySQL 写出的 PHP、SUID 文件、`.git` 中的 PHP |
| `apps` | WordPress、Laravel、ThinkPHP、Drupal、Joomla、Magento 2、Nextcloud、MediaWiki、Discuz!、Typecho、PrestaShop、OpenCart、phpBB、DedeCMS、帝国CMS：应用和版本清单、WordPress mu-plugins、Laravel `APP_DEBUG` / 公开的 `.env`、有漏洞的 ThinkPHP |
| `persistence` | cron（含 Web 用户和容器内的 crontab）、systemd、rc/profile 文件、`ld.so.preload` |
| `accounts` / `auth` | 额外的 UID 0 账户；Web 用户的 shell/sudo/用户组/SSH 公钥；以 Web 用户身份的 SSH 登录、Web 用户 sudo/su、爆破后成功登录、新建账户、特权组变更 |
| `processes` / `network` | Web 用户运行的 shell/netcat、从 `/tmp` 或 memfd 运行的程序、伪装的 `[kworker]`、挖矿程序、反弹/正向 shell、对外暴露的 PHP-FPM |
| `tmp` | 临时目录、Web 用户家目录、X11/ICE socket 目录和容器临时目录中的投放程序、脚本、保存的 `id` 输出、SUID 文件 |
| `database` | MySQL UDF 后门、指向 PHP 的 `general_log_file`、`INTO OUTFILE` 痕迹、`.mysql_history`、phpMyAdmin 安装及版本 |
| `php` | PHP 二进制（不执行即可读出版本）、软件包（dpkg / apk / pacman / rpm）、运行中的 PHP、php.ini 后门 |
| `integrity` | 用 `dpkg --verify` / `rpm -V` 校验 ps、ls、sshd、libc 等（是否被替换） |
| `baseline` | 防火墙（ufw / firewalld / nftables / iptables）、对外暴露的 Redis/MySQL/Docker API/面板端口、SSH 配置、fail2ban、自动更新、SELinux/AppArmor |

**运行环境：** 内置以下环境的目录知识：Debian/Ubuntu、RHEL/CentOS/Rocky/Alma/Amazon（含 Remi/SCL）、
Alpine、openSUSE、Arch；宝塔/aaPanel、1Panel、cPanel（EA-PHP）、Plesk、CyberPanel/OpenLiteSpeed、
HestiaCP/VestaCP、ISPConfig、DirectAdmin、Virtualmin、LNMP.org、OneinStack、Bitnami、XAMPP。
1Panel 无论装在哪里都能找到（从 `1pctl` 读取 `BASE_DIR`，支持 v1 和 v2 目录布局、PHP 运行环境
和应用商店站点），宝塔的 Docker 项目（`/www/dk_project`）同样支持。**Docker 和 Podman** 容器通过
磁盘上的元数据发现（离线同样可用）：会扫描每个容器的可写层、绑定挂载、数据卷和 json-file 日志，
因此从宿主机就能发现投放在 1Panel PHP 容器里的 webshell。还会通过内核挂载表处理 Docker 29 的
containerd 镜像存储；正确识别容器内的进程（1Panel/宝塔以 uid 1000 运行 PHP）；搜索 php-fpm/httpd
的 systemd `PrivateTmp` 目录；并像扫描 PHP 自身的 session 一样扫描应用自管的 session 目录
（ThinkPHP `runtime/session`、DedeCMS、OpenCart、Magento）。

### 如何阅读结果

每条发现都有严重程度（`CRITICAL … INFO`）和类型：**compromise**（攻击者已获得代码执行或持久化）、
**attempt**（利用流量或利用过程的某一阶段）、**exposure**（有漏洞或危险的配置）、
**hardening**（安全基线问题，单独展示，不影响结论）。

| 结论 | 条件 | 退出码 |
|---|---|---|
| **COMPROMISED**（已被入侵） | 存在 CRITICAL 级别的 compromise | 3 |
| **LIKELY COMPROMISED**（很可能已被入侵） | HIGH 级别的 compromise，或 CRITICAL 级别的 attempt | 2 |
| **SUSPICIOUS** / **EXPOSED**（可疑 / 存在暴露面） | MEDIUM 及以上的 compromise/attempt / 只有 MEDIUM 及以上的 exposure | 1 |
| **NO INDICATORS FOUND**（未发现迹象） | 以上都不满足 | 0 |
| *结果不完整* | 有检查失败且未发现任何迹象 | 70 |

互联网上的通用扫描噪音（例如探测 `/?cmd=id`、`../../etc/passwd`）只记为 LOW，不影响结论；
php2shell 专属的证据保持原有权重。

默认生成 **Markdown 报告**（`php2shell-forensics-<主机>-<时间>.md`，权限 0600），包含结论、
后续步骤、汇总表以及每条发现的证据（属主、mtime/ctime、首次/最后出现时间、来源 IP）。
不可信内容都会转义，文件名或日志行无法注入 Markdown、HTML 或终端控制序列。

| 参数 | 含义 |
|---|---|
| `--root DIR` | 扫描挂载的磁盘镜像（会关闭实时的进程/网络/软件包检查） |
| `--since DATE` | `YYYY-MM-DD` 或 `30d`：标记在此之后变动的文件、公钥、systemd 单元、sudoers |
| `--webroot / --log / --session-dir` | 额外的扫描位置（可重复） |
| `--checks a,b` / `--skip a,b` | 选择检查项（`--list-checks`） |
| `--markdown FILE` / `--no-markdown`、`--json FILE` | 报告 |
| `--no-exec` | 不调用任何外部程序（dpkg、rpm、iptables、journalctl、php -v） |
| `--min-severity`、`--max-per-rule`、`--max-file-size`、`--max-files` | 输出与限制 |

### 对生产服务器的影响

取证模式本身就是按“在线上生产机运行”设计的：

- **只读**：不连接 MySQL、Redis 等任何服务，不加锁，不读取数据库表文件，不修改也不执行发现的任何文件；
  唯一的写入是它自己的报告文件。
- **默认低优先级**：自动降到 CPU nice 19 和最低的磁盘 IO 优先级；读完大文件后通知内核释放对应的页缓存，
  扫描几 GB 日志也不会把数据库和 Web 服务正在用的缓存挤掉。需要全速运行时加 `--no-throttle`。
- **资源有上限**：单线程（最多占一个 CPU 核），流式读取并限制读取量，内存只在几十 MB 级别。
- **实测**：在一台运行 MySQL、Redis、nginx 的宝塔生产服务器（4 核 8 GB）上，只占一个核，
  内存峰值 50 MB，没有产生 IO 压力，MySQL 未受影响）。完整扫描它的 272 个日志文件和网站目录
  用时 29 秒，从磁盘读取约 60 MB。

### “我已经卸载了 PHP 和 phpMyAdmin，安全了吗？”

不一定。session 文件、网站目录和日志通常还在，它们就是证据，扫描前不要删除。
webshell 落地后的第一件事通常是建立持久化：计划任务、SSH 公钥、后台程序，这些在没有 PHP 后照样工作。
MySQL 也还在，如果 phpMyAdmin 曾经可访问，请更换数据库密码。结论为 **COMPROMISED / LIKELY
COMPROMISED** 时：隔离主机，清理前先做磁盘镜像，从干净的机器上更换所有凭据，然后重建系统。

### 局限性

- 访问日志不记录 POST 正文；除非 WAF 或 `$request_body` 日志记录了请求体，否则只能依据副作用判断。
- 只能找到日志保留期内的证据；“未发现迹象”不能证明主机是干净的。
- 内核级或 `ld.so.preload` rootkit 可以欺骗实时检查，此时请对磁盘镜像使用 `--root`。
- 发行版软件包可能已回移植修复补丁，版本检查会注明这一点。
- 文件访问时间会被保留，但在实机上列出目录仍可能更新目录本身的访问时间。

## 已测试环境

取证模式在 Docker 中的每个发行版上运行过（`tests/e2e/distros.sh`），都布置了一个 webshell，
全部判定为 **COMPROMISED**，且没有检查报错。

| 发行版 | Python | | 发行版 | Python |
|---|---|---|---|---|
| Ubuntu 20.04 | 3.8.10 | | Amazon Linux 2023 | 3.9.25 |
| Ubuntu 24.04 | 3.12.3 | | Alpine 3.20 | 3.12.13 |
| Debian 12 | 3.11.2 | | openSUSE Leap 15.6 | 3.6.15 |
| Rocky Linux 9 | 3.9.18 | | Arch Linux | 3.14.8 |
| AlmaLinux 8（platform-python） | 3.6.8 | | macOS（单元测试、`--root` 模式） | 3.10 |

远程扫描已针对真实的 `php:7.4`、`php:8.2.34`、`php:8.3` 和 `wordpress` 容器验证
（`tests/e2e/remote_real.sh`）；取证扫描已在真实的 nginx + php-fpm + phpMyAdmin + WordPress
环境中做过误报测试（`tests/e2e/false_positive_lamp.sh`）。

## 开发

```bash
python3 -m pytest tests -q                   # 单元测试 + 离线端到端测试
bash tests/e2e/run.sh                        # Docker：干净主机 vs 布置了入侵痕迹的主机
bash tests/e2e/false_positive_lamp.sh        # Docker：真实的 nginx + php-fpm + phpMyAdmin + WordPress
bash tests/e2e/remote_real.sh                # Docker：远程扫描真实的 PHP 7.4 / 8.2 / 8.3 环境
bash tests/e2e/distros.sh                    # Docker：在 9 个 Linux 发行版上运行取证
./build_pyz.sh                               # 生成 dist/php2shell-scanner.pyz
```

## 作者与许可证

作者 **[Evil0ctal](https://github.com/Evil0ctal)**，以 [MIT 许可证](LICENSE)发布。
欢迎在 <https://github.com/Evil0ctal/php2shell-scanner> 提交 Issue 和 Pull Request。
