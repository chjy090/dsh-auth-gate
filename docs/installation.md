# dsh-pairing-gate 安装与配置操作手册

> **v0.7.2 改名**：本插件原名 `dsh-auth-gate`，因 npm 上该包名已被 [TecFancy/dsh-auth-gate](https://github.com/TecFancy/dsh-auth-gate) 占用，改为 `dsh-pairing-gate`；仓库为 <https://github.com/chjy090/dsh-pairing-gate>，旧仓库链接会 301 跳转。本地/生产**目录名仍为 `dsh-auth-gate`**，状态目录 `$DSH_HOME/auth-gate` 不变，state/账号/设备无需迁移。

本文是 `dsh-pairing-gate` 的**可照做安装手册**，覆盖：前置要求、安装进 dsh、配置项、两种首次初始化方式、设备配对与登录、frp/Caddy 网络拓扑、日常运维、故障排查、安全模型和安装后自检。

- 适用版本：`dsh-pairing-gate` **v0.7.3**（`package.json`）；v0.7.3 新增 `clientDeviceId` 重复配对去重并把 `maxDevices` 默认值调到 100，`state.json` 向后兼容（旧设备无 `clientDeviceId` 视为无）。v0.7.2 仅改包名/仓库名（原名 `dsh-auth-gate`），功能、配置与 `state.json` 格式与 v0.7.1 一致；旧名安装的迁移步骤见 2.7.1。
- 验证基线：dsh **0.2.1-rc.2**、Node.js **v22.23.2**、pnpm **12.15.0**、npm **10.9.8**（2026-10 的实际部署）。
- 读者：拥有 dsh 服务器 root 权限、准备把认证网关放到公网入口的管理员。
- 协议：单用户自用。**设备配对就是第二因素**：配对时需要 TOTP，配对成功后该设备登录只需用户名 + 密码。

> **先读安全红线**：不要把 `listenHost` 或 frpc 的 `local_ip` 配成 `127.0.0.1`；不要把 dsh 的 `3080` 直接暴露到公网；不要把 `admin.key`、TOTP secret、`setup.token`、`deviceToken` 贴到聊天、工单或日志。详见第 9 节。

> 下文命令默认已按第 0 节导出 `DSH_HOME`、`PLUGIN_DIR`、`GATE_URL`、`STATE_DIR` 等变量；如果单独跳到某一节执行，请先补上这些 `export`。

---

## 0. 最短路径（熟悉 Linux 的人先看这里）

```bash
# 变量按实际环境替换；下面以本机部署为例
export DSH_HOME=/opt/deepseekharness/config/dsh
export PLUGIN_DIR=/opt/ai_code/mobile-apk/dsh-auth-gate
export GATE_HOST=172.16.180.14
export GATE_PORT=3443
export GATE_URL="https://${GATE_HOST}:${GATE_PORT}"
export STATE_DIR="$DSH_HOME/auth-gate"

# 1) 插件依赖
cd "$PLUGIN_DIR"
sudo npm install --no-audit --no-fund

# 2) 以 link 方式安装（会自动加 dependency + bundle，并调用 pnpm）
sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" \
  dsh plugin --profile web add link:"$PLUGIN_DIR"

# 3) 重启 dsh（安装/升级/改 TLS 证书才需要；只改网络设置不需要）
sudo systemctl restart dsh
sudo journalctl -u dsh -n 200 --no-pager | grep -E 'auth-gate|setup required|admin key'

# adminKey（A/B 初始化与后续配对都要用）
ADMIN=$(sudo cat "$STATE_DIR/admin.key")

# 4) 首次初始化（全新实例，二选一）
#    A. 从日志取一次性链接，在最终要登录的浏览器里打开
sudo journalctl -u dsh -n 200 --no-pager | grep 'setup required'
#    B. adminKey + curl（自动化/应急；不会自动配对浏览器）
ADMIN=$(sudo cat "$STATE_DIR/admin.key")
curl -sk -X POST "$GATE_URL/__admin/api/bootstrap" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<至少10位的强密码>"}'

# 5) 生成设备配对码，先配对再登录
curl -sk -X POST "$GATE_URL/__admin/api/qr" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"platform":"web"}'
```

---

## 1. 前置要求

### 1.1 软件版本

| 组件 | 要求 | 本机基线 | 检查命令 |
|---|---|---|---|
| dsh | 能加载 profile bundle / Cordis 插件；本手册以 `0.2.1-rc.2` 验证 | `0.2.1-rc.2` | `dsh --version` |
| Node.js | **22.x**（dsh 自身运行在 Node 22） | `v22.23.2` | `node --version` |
| pnpm | `dsh plugin` 内部会调用；必须在 PATH 中 | `12.15.0` | `pnpm --version` |
| npm | 用于安装插件自身的 `qrcode` 依赖 | `10.9.8` | `npm --version` |
| OpenSSL | 生成/检查证书、计算指纹（1.1.1+，推荐 3.x） | 系统自带 | `openssl version` |
| curl / jq | 自检与 API 操作；`jq` 可选但强烈建议 | 系统自带 | `curl --version`、`jq --version` |
| systemd | 本手册以 `dsh.service` 管理 dsh | 已启用 | `systemctl is-active dsh` |

说明：

- 插件 `package.json` 没有声明 `engines.dsh` 或 `engines.node`，因此版本不匹配时不会在安装阶段硬拒绝；**升级 dsh 大版本前先在隔离 profile/stateDir 验证**，不要直接在生产上试。
- `dsh plugin` 找不到 pnpm 时会以 127 退出并提示 `pnpm was not found`。本机 pnpm 在 `/opt/deepseekharness/npm-global/bin/pnpm`，需要把它放进 PATH。
- 不需要全局安装 `qrcode`；它由插件目录内的 `npm install` 安装（当前锁文件为 `qrcode@1.5.4`）。

### 1.2 端口与网络

| 端口 | 用途 | 暴露范围 |
|---|---|---|
| `3443/tcp` | dsh-pairing-gate 自己的 HTTPS 监听 | 只给需要访问的网段 / frpc 所在主机；**不要用 loopback 监听** |
| `3080/tcp` | dsh 原生 HTTPS 监听（网关的上游） | **只对内网开放**，绝不能直接暴露公网 |
| `23443/tcp`（示例） | frps 为网关开放的 TCP `remotePort`（TLS 直通） | 公网只开放这一个 |
| `18080/tcp`（示例） | frps 为 Caddy 回源开放的 TCP `remotePort` | 只让 Caddy 所在主机访问 |
| `8443/tcp`（示例） | Caddy 对公网提供 HTTPS | 公网入口 |

检查：

```bash
sudo ss -ltnp | grep -E ':3443|:3080|:23443|:18080|:8443'
sudo firewall-cmd --list-all          # firewalld
# 或：sudo ufw status numbered         # ufw
```

dsh 当前（本机示例）监听 `172.16.180.14:3080`，网关监听 `172.16.180.14:3443`。**网关必须监听一个具体的内网网卡地址**，不能是 `0.0.0.0`、`::`、`127.0.0.1`、`::1`。

### 1.3 TLS 证书

生产必须给网关配置 TLS；否则：

- 浏览器到网关是明文 HTTP；
- 网关 cookie 不带 `Secure`；
- 配对二维码的 `fp=` 为空，DSH Mobile 会拒绝配对。

需要准备：

1. PEM 格式的证书文件（`tlsCert`）和私钥文件（`tlsKey`）；
2. 私钥权限 `0600`，属主为运行 dsh 的用户（本机为 root）；
3. 证书 SAN 覆盖浏览器实际访问的主机/IP（局域网 IP、域名；本机健康检查再加 `127.0.0.1` 和 `localhost`）；
4. 如果 TLS 在 Caddy/nginx 等反向代理处终止，还需把**代理证书**的 SHA-256 DER 指纹填入 `publicFingerprint`（见第 6 节）。

本机现有证书：

```bash
sudo ls -l /opt/deepseekharness/config/tls/dsh.crt.pem \
             /opt/deepseekharness/config/tls/dsh.key.pem
# 本机基线：crt 644 root:root；key 600 root:root

# 查看 SAN
openssl x509 -in /opt/deepseekharness/config/tls/dsh.crt.pem \
  -noout -subject -issuer -dates -ext subjectAltName

# 查看证书 DER SHA-256（即二维码里的 fp；不含冒号，小写）
openssl x509 -in /opt/deepseekharness/config/tls/dsh.crt.pem \
  -outform DER | openssl dgst -sha256 -r | awk '{print $1}'
```

本机证书 SAN 为 `IP:172.16.180.14, IP:127.0.0.1, DNS:localhost`，可作为自签/内网证书的参考。

### 1.4 目录、用户与权限

| 路径 | 说明 | 权限 |
|---|---|---|
| `$DSH_HOME` | dsh 的数据根；本机 `/opt/deepseekharness/config/dsh` | 由 dsh 管理 |
| `$DSH_HOME/profiles/web` | `web` profile；安装插件、改配置的位置 | 属主 root |
| `$PLUGIN_DIR` | 插件源码目录；本机 `/opt/ai_code/mobile-apk/dsh-auth-gate` | 可读、可执行 |
| `$DSH_HOME/auth-gate`（默认 `stateDir`） | `state.json`、`admin.key`、`setup.token`、`network.json` | 目录 `0700`，文件 `0600` |

确认 DSH_HOME 和服务用户：

```bash
sudo systemctl cat dsh | grep -E '^Environment=(DSH_HOME|HOME)='
sudo systemctl show dsh -p User -p Group
```

`dsh plugin` 不会自动读取 systemd 的 `DSH_HOME`，**必须在执行命令前显式导出**，否则会把插件装到 `/root/.dsh/profiles/web` 而不是生产 profile。这是最常见的安装事故之一。

### 1.5 获取仓库

方式 A：独立 clone 到固定目录（推荐生产）：

```bash
# 仓库：https://github.com/chjy090/dsh-pairing-gate（原名 dsh-auth-gate，旧链接 301）
sudo git clone https://github.com/chjy090/dsh-pairing-gate.git /opt/dsh-auth-gate
export PLUGIN_DIR=/opt/dsh-auth-gate
test -f "$PLUGIN_DIR/package.json" && echo "plugin dir ok"
```

方式 B：直接 link 本地已有源码（本机 monorepo 方式）：

```bash
export PLUGIN_DIR=/opt/ai_code/mobile-apk/dsh-auth-gate
test -f "$PLUGIN_DIR/package.json" && echo "plugin dir ok"
```

说明：

- `link:` 必须写**绝对路径**；源码目录被移动/删除后，profile 的链接会失效，需要重新 `add` 或修正 `package.json`。
- 不需要 `npm publish`，也不要把插件装成全局包；它作为 profile 的 bundle 依赖存在。
- 插件目录里的 `node_modules` 是插件运行所需依赖（`qrcode`），升级源码后如依赖变化需重新 `npm install`。

### 1.6 安装前检查清单

```bash
set -e
dsh --version
node --version
pnpm --version
sudo systemctl is-active dsh
sudo test -r /opt/deepseekharness/config/tls/dsh.crt.pem
sudo test -r /opt/deepseekharness/config/tls/dsh.key.pem
sudo journalctl -u dsh -n 50 --no-pager | grep -E 'dsh web|listening' || true
sudo ss -ltnp | grep -E ':3080|:3443' || true
```

确认 `3443` 没有被其它进程占用；确认 `3080` 由 dsh 占用；确认 TLS 文件可读。

---

## 2. 安装到 dsh

### 2.1 安装插件自身依赖

在插件目录执行（用运行 dsh 的同一用户；本机服务 `User=root`）：

```bash
cd "$PLUGIN_DIR"
sudo npm install --no-audit --no-fund
```

验证：

```bash
node -e "console.log('qrcode', require('qrcode/package.json').version)"   # 期望 1.5.4
node --check lib/index.js
node --check lib/gateway.js
```

这一步只安装插件的 npm 依赖，不会把插件装进 dsh。`npm ci` 也可以（有 `package-lock.json` 时更适合可重复安装）。

### 2.2 配置（可选：使用默认值可跳过）

插件包自带 `cordis.patch.yml`，通过 `package.json` 的 `dsh.bundle.patch` 声明。`dsh plugin add` 成功后，它作为 profile 的一个 bundle 层被自动加载，**默认配置就是插件目录里的这份文件**（`listenHost: 172.16.180.14`、`listenPort: 3443`、TLS 路径等）。因此：

- 只想快速装起来：先不改配置，装完在管理页「设置」tab 改网络参数即可；
- 需要改 `upstream`、TLS 路径、`stateDir`、限流/过期等**非网络字段**：必须改 profile 配置（或在插件包自己的 `cordis.patch.yml` 上改，但升级会覆盖，不推荐）。

修改 profile 配置的位置是：

```text
$DSH_HOME/profiles/web/cordis.patch.yml
```

注意 `cordis.yml` 是组合后的空入口，**不要改它**；按文件头部注释改 `cordis.patch.yml`。

#### 2.2.1 正确覆盖方式（id-targeted patch）

插件已经由 bundle 插入了一个 `id: auth-gate` 的条目，profile 里要覆盖它，应使用**按 id 的配置补丁**，而不是再写一个 `insert:`：

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
# 注意：config 是整体替换，不是深合并！
- id: auth-gate
  config:
    listenHost: 172.16.180.14
    listenPort: 3443
    upstream: https://172.16.180.14:3080
    upstreamInsecureTls: true
    publicUrl: https://172.16.180.14:3443
    tlsCert: /opt/deepseekharness/config/tls/dsh.crt.pem
    tlsKey: /opt/deepseekharness/config/tls/dsh.key.pem
    adminKeyFile: $DSH_HOME/auth-gate/admin.key
    stateDir: $DSH_HOME/auth-gate
    sessionTtlHours: 48            # 空闲窗口（小时）
    sessionAbsoluteTtlDays: 30     # 绝对上限（天，自会话创建起算；0 = 无上限）
    deviceTtlDays: 90              # 设备滑动窗口（天）
    deviceAbsoluteTtlDays: 365     # 设备绝对上限（天，自配对起算；0 = 无上限）
    maxDevices: 100
    pairTicketTtlSeconds: 120
    loginLock:
      maxFailures: 5
      windowMinutes: 15
      lockMinutes: 15
```

**关键**：Cordis 的 patch 对 `config` 是**整体替换**，不是逐字段合并。如果你只写 `config: { listenPort: 3444 }`，其他字段会退回 `lib/config.js` 的内置默认值（包括 `listenHost: 127.0.0.1`、`tlsCert: null`），很可能导致监听 loopback 或 TLS 丢失。要么写完整配置，要么只通过 `network.json`/管理页改那四个网络字段。

#### 2.2.2 手动安装（不用 `dsh plugin add`）才用 insert

只有在你**没有**用 `dsh plugin add`、需要手工把插件加进 profile 时，才在 profile patch 里追加：

```yaml
- insert:
    - id: auth-gate
      name: 'dsh-pairing-gate'
      config:
        # 同上，完整配置
```

已经通过 bundle 自动插入后，**不要**再写这段 `insert`，否则会出现两个同 id 条目，配置归属不明确。需要覆盖时用 2.2.1。

#### 2.2.3 网络字段的另一种覆盖：network.json

如果只想改 `listenHost` / `listenPort` / `publicUrl` / `publicFingerprint`，更推荐用管理页「设置」或 `POST /__admin/api/network`；它们会写入 `$STATE_DIR/network.json`，优先级高于 bundle config，且不需要改 profile 文件。详见 3.4。

### 2.3 安装进 web profile

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export PLUGIN_DIR=/opt/ai_code/mobile-apk/dsh-auth-gate

sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" \
  dsh plugin --profile web add link:"$PLUGIN_DIR"
```

如果当前就是 root 且 `dsh` 已在 PATH：

```bash
DSH_HOME="$DSH_HOME" dsh plugin --profile web add link:"$PLUGIN_DIR"
```

如果 `dsh` 不在 PATH（`sudo` 的 secure_path 常见情况），用绝对路径：

```bash
sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" \
  /opt/deepseekharness/npm-global/bin/dsh plugin --profile web add link:"$PLUGIN_DIR"
```

这条命令实际发生的事：

1. `dsh plugin` 把参数转发给 profile 目录里的 pnpm，执行类似 `pnpm add link:/opt/.../dsh-auth-gate` 的操作（路径仍是目录名 `dsh-auth-gate`）；
2. pnpm 在 `$DSH_HOME/profiles/web/package.json` 的 `dependencies` 中写入 `"dsh-pairing-gate": "link:/opt/.../dsh-auth-gate"`（键取包名，路径是目录），并在 `node_modules` 下建立同名符号链接；
3. pnpm 成功后，dsh 读取该包的 `package.json`，发现 `dsh.bundle.patch = ./cordis.patch.yml`，自动把 `dsh-pairing-gate` 追加到 `dsh.profile.bundles`；
4. 因此**不需要手工编辑 `dsh.profile.bundles`**；下次启动 dsh 时，插件自带的 `cordis.patch.yml` 会作为 bundle 层生效。

可能看到的输出/告警：

- 兼容性不匹配：`dsh: to accept the risk, run: dsh plugin --profile web allow-version ...`。不要在生产上随意接受风险；先隔离验证。
- `dsh: pnpm was not found`：把 pnpm 放入 PATH。
- 如果包没有声明 `dsh.bundle`，会提示 `installed as a plain dependency, not a profile layer`；本插件声明了，不应出现。

验证安装结果：

```bash
jq '{dep:.dependencies["dsh-pairing-gate"],
     inBundles:(.dsh.profile.bundles | index("dsh-pairing-gate") != null)}' \
  "$DSH_HOME/profiles/web/package.json"

readlink -f "$DSH_HOME/profiles/web/node_modules/dsh-pairing-gate"
# 期望输出 $PLUGIN_DIR（符号链接名取包名，指向目录 dsh-auth-gate）
```

如果 `inBundles` 为 `false`，检查是否装到了错误的 `DSH_HOME`（例如 `/root/.dsh`），或 `package.json` 的 `dsh.bundle` 是否被破坏。

### 2.4 重启 dsh 并确认监听

```bash
sudo systemctl restart dsh
sudo systemctl is-active dsh
sudo journalctl -u dsh -n 200 --no-pager | grep -E 'auth-gate|setup required|admin key'
```

正常应看到：

```text
auth-gate: listening on https://172.16.180.14:3443 (172.16.180.14:3443), upstream https://172.16.180.14:3080
```

如果存在 `network.json` 覆盖，行尾还会带：

```text
 [network.json override]
```

首次启动（未初始化）还会看到：

```text
auth-gate: generated admin key ********************************************************<后8位> (stored 0600 at /opt/deepseekharness/config/dsh/auth-gate/admin.key; read it from that file, not the log)
auth-gate: setup required — open https://172.16.180.14:3443/__admin#setup=<64位hex>（也可从 /opt/deepseekharness/config/dsh/auth-gate/setup.token 读取）
```

说明：

- 管理密钥日志只打印掩码和后 8 位，**不打印完整密钥**；从 `admin.key` 文件读取。
- `setup required` 只在未初始化时出现；已初始化的生产实例升级后不会出现。
- 插件启动失败不会把 dsh 拖垮：日志会是 `auth-gate: failed to start: ...`，dsh 自身继续运行，但网关不可用。没有 `listening` 行就要排障。

跟随日志：

```bash
sudo journalctl -u dsh -f | grep --line-buffered auth-gate
```

### 2.5 防火墙

只放行实际需要的入口。**3080 只对内网开放**。

直接暴露网关 3443（没有 frp/Caddy）时：

```bash
# firewalld
sudo firewall-cmd --permanent --add-port=3443/tcp
sudo firewall-cmd --reload
sudo firewall-cmd --list-all

# 或 ufw
sudo ufw allow 3443/tcp
sudo ufw status numbered
```

限制 dsh 3080 只给内网（firewalld 示例）：

```bash
# 如果 3080 目前在 public ports 中，先移除
sudo firewall-cmd --permanent --remove-port=3080/tcp || true

# 只允许内网网段（按实际网段替换 172.16.180.0/24）
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="172.16.180.0/24" port port="3080" protocol="tcp" accept'
sudo firewall-cmd --reload
sudo firewall-cmd --list-all
```

如果走 frp/Caddy：

- **不要把 3443 直接暴露公网**；frpc 与网关同机/同内网即可；
- 公网只开 frps 的 `remote_port`（直通模式）或 Caddy 的 `8443`（TLS 终止模式）；
- 3080 继续只对内网开放。

> 本机现状可参考：`3443/tcp` 在 public zone；`3080` 只有 `source 172.16.180.0/24` 的 rich rule。是否收紧 3443 取决于你是否还用 frp/Caddy；无论哪种，3080 都不要出现在 public ports 中。

### 2.6 升级（link 安装）

`link:` 安装指向源码目录，**升级不需要重新 `dsh plugin add`**：

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export PLUGIN_DIR=/opt/ai_code/mobile-apk/dsh-auth-gate
export STATE_DIR="$DSH_HOME/auth-gate"

# 1) 备份状态（强烈建议；见 7.3）
sudo systemctl stop dsh
sudo tar -C "$(dirname "${STATE_DIR:?}")" -czpf /root/auth-gate-backup-$(date +%F-%H%M).tgz "$(basename "${STATE_DIR:?}")"
sudo systemctl start dsh

# 2) 更新源码（二选一）
cd "$PLUGIN_DIR"
sudo git pull --ff-only
# 或者用 rsync/scp 把新版本覆盖到 $PLUGIN_DIR

# 3) 依赖有变化时重装（无变化也可执行，幂等）
sudo npm install --no-audit --no-fund

# 4) 重启 dsh 让服务端与 client bundle 重新组合
sudo systemctl restart dsh

# 5) 确认版本和监听
node -p "require('$PLUGIN_DIR/package.json').version"
sudo journalctl -u dsh -n 100 --no-pager | grep -E 'auth-gate|failed to start'
```

注意：

- **不要**在升级后重新执行 `dsh plugin add`；link 依赖没有变，重新 add 只会多一次 pnpm 操作，没有收益。
- **例外（v0.7.1 → v0.7.2 改名）**：包名从 `dsh-auth-gate` 变为 `dsh-pairing-gate`，profile 里记录的仍是旧名，只 `git pull` + 重启会因 bundle 名 `dsh-pairing-gate` 无法解析而加载失败。**必须先按 2.7.1 执行 `remove dsh-auth-gate` → `add link:$PLUGIN_DIR`**，再重启；state 与账号不受影响。
- 客户端面板（侧边栏「认证管理」）在 dsh 启动时组合，**必须重启 dsh**，并在浏览器硬刷新（Ctrl/Cmd+Shift+R）丢弃旧 bundle 缓存。
- 证书文件替换也必须重启 dsh；`network.json` 中的 `publicFingerprint` 不会自动跟着证书变。
- 如果新版本要求新的 dsh/Node 版本，先用隔离 `DSH_HOME` + 独立 `stateDir` 验证，再动生产。
- 升级前保留 `state.json`/`admin.key`/`network.json` 的备份；不要只备份源码。

### 2.7 卸载

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export STATE_DIR="$DSH_HOME/auth-gate"

# 1) 从 profile 移除（自动移除 dependency 与 bundles 条目，并调用 pnpm）
#    旧名安装的用户第一次迁移时用 dsh-auth-gate，见 2.7.1
sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" \
  dsh plugin --profile web remove dsh-pairing-gate

# 2) 重启 dsh；侧边栏入口与网关监听随之消失
sudo systemctl restart dsh

# 3) 确认已移除
jq '{dep:.dependencies["dsh-pairing-gate"],
     inBundles:(.dsh.profile.bundles | index("dsh-pairing-gate") != null)}' \
  "$DSH_HOME/profiles/web/package.json"
```

清理项：

- 如果 profile 的 `cordis.patch.yml` 里还有 `- id: auth-gate` 覆盖段，删掉它；否则重启时 loader 会提示找不到目标（通常只是 warning，不影响其它插件）。
- 防火墙：撤销 3443 的放行；如果不再使用 frp/Caddy，撤销对应 `remote_port`/域名配置。
- **状态目录**：`$STATE_DIR`（默认 `$DSH_HOME/auth-gate`）保留，便于以后重装恢复账号、设备、审计和网络设置。确认不再需要时才删除：

  ```bash
  sudo rm -rf "${STATE_DIR:?}"   # 确认路径；会丢失用户、TOTP、设备、会话、审计、network.json
  ```

  删除前务必确认已备份；删除 `network.json` 也会让运行时网络覆盖失效（回退 bundle config，需重启）。
- dsh 的 3080 不受插件卸载影响；继续保持只对内网开放。

### 2.7.1 从旧名 `dsh-auth-gate` 迁移（v0.7.2）

v0.7.2 只改包名与仓库名，**本地目录名、配置项与状态目录都没有变**，所以迁移不影响账号、TOTP、已配对设备、会话、审计与 `network.json`：

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export PLUGIN_DIR=/opt/ai_code/mobile-apk/dsh-auth-gate   # 目录名不变

# 1) 移除旧包名（自动移除 dependency 与 bundles 条目）
sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" \
  dsh plugin --profile web remove dsh-auth-gate

# 2) 用新包名重新 link 同一目录；也可以 npm 安装 dsh-pairing-gate
sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" \
  dsh plugin --profile web add link:"$PLUGIN_DIR"

# 3) 重启，让服务端插件与 client bundle 按新包名重新组合
sudo systemctl restart dsh
```

迁移后核对：

```bash
jq '{dep:.dependencies["dsh-pairing-gate"],
     inBundles:(.dsh.profile.bundles | index("dsh-pairing-gate") != null),
     old:(.dependencies["dsh-auth-gate"] // "absent")}' \
  "$DSH_HOME/profiles/web/package.json"
# 期望 dep 为 link:...、inBundles 为 true、old 为 absent
```

- 若 profile 的 `cordis.patch.yml` 里有 `- id: auth-gate` 覆盖段，把 `name:` 改成 `dsh-pairing-gate`（或删掉 `name` 只保留 `id`）。
- 状态目录仍是 `$DSH_HOME/auth-gate`（`state.json` / `admin.key` / `network.json`），不需要搬移或重建。
- 回滚到 v0.7.1 时反向操作：`remove dsh-pairing-gate` → `add link:$PLUGIN_DIR`（旧版本 package.json 的 name 是 `dsh-auth-gate`）。

### 2.8 安装完成的判定标准

满足以下全部条件才算安装成功：

1. `systemctl is-active dsh` 为 `active`；
2. 日志出现 `auth-gate: listening on https://...`，且没有 `failed to start`；
3. `ss -ltnp` 显示网关监听在**具体 LAN 地址**，不是 `127.0.0.1`/`0.0.0.0`；
4. `GET /__auth/login` 返回 200；
5. `GET /__admin/api/setup/status` 返回合法 JSON；
6. 未初始化时能拿到 `setup required` 链接；已初始化时 `configured:true` 且无 setup 链接；
7. `admin.key`/`state.json` 权限为 `0600`，状态目录 `0700`；
8. 3080 没有暴露到公网。

自检命令见第 10 节。

---

## 3. 配置项参考

### 3.1 配置来源与优先级

从低到高：

1. `lib/config.js` 的 `CONFIG_DEFAULTS`（内置默认值）；
2. 插件包 `cordis.patch.yml`（bundle 层，随插件包提供）；
3. profile `$DSH_HOME/profiles/web/cordis.patch.yml` 中按 `id: auth-gate` 的覆盖（`config` **整体替换**）；
4. 运行时 `$STATE_DIR/network.json`（只覆盖 `listenHost`、`listenPort`、`publicUrl`、`publicFingerprint` 四个字段）；
5. `lib/standalone.js` 的 `AUTH_GATE_*` 环境变量——**只对独立运行入口有效**，不是 dsh 插件配置。

对于四个网络字段：`network.json` > bundle/profile config > 默认值。其它字段（TLS、upstream、stateDir、TTL、限流）始终来自 bundle/profile config，`network.json` 不能改。

### 3.2 字段逐项说明

| 字段 | 类型 / 默认 | 校验与范围 | 说明 |
|---|---|---|---|
| `listenHost` | 字符串，默认 `127.0.0.1` | 必须是具体网卡地址；禁止通配（`0.0.0.0`、`::`、`::0`、`0::0`、`00::`、`::ffff:0.0.0.0` 等）；管理页/`network.json` **禁止 loopback**（`127.0.0.0/8`、`::1`、`::ffff:127.0.0.1`） | 网关实际绑定的本机 LAN 地址。生产必须写 LAN 地址（如 `172.16.180.14`）。bundle config 写 loopback 时启动会 WARN 并禁用本机 loopback 管理通道；`network.json`/API 直接 400。默认值只是开发默认，正式部署必须覆盖。 |
| `listenPort` | 整数，默认 `3443` | 1–65535；管理页/`network.json` 还要求不等于 `upstream` 端口 | 网关 HTTPS 端口。改端口要同步防火墙和 frpc 的 `local_port`/`localPort`。bundle config 与 3080 相同时会监听冲突。 |
| `upstream` | 字符串，默认 `http://127.0.0.1:3080` | 必须是绝对 `http(s)` URL，且是 dsh 根 URL（不能带路径、不能带用户名密码） | dsh 的真实地址。生产用 `https://172.16.180.14:3080`，必须与 dsh 监听的 authority 一致；写 `127.0.0.1` 会破坏 dsh 的 Host/Origin fence。 |
| `upstreamInsecureTls` | 布尔，默认 `false` | 布尔或 `"true"/"false"/"1"/"0"` | 上游 dsh 使用自签证书时设 `true`。如果 dsh 换成受信证书，改回 `false`。 |
| `publicUrl` | 字符串，默认由 `listenHost`/`listenPort` 和 TLS 推导 | 管理页/`network.json` 要求纯 origin：`http(s)://host[:port]`；不能带凭据、非根路径、查询、片段；尾部 `/` 会被归一化；配了 TLS 必须 `https:`，没配 TLS 必须 `http:` | **配对二维码、配对链接、首次初始化链接、设备 origin** 的基地址。frp 场景填中转后的公网 IP/域名；不要填监听地址以外的路径。bundle config 中多余路径会被 `URL.origin` 静默归一化（不报错）；管理页/`network.json` 对非根路径/查询/片段直接 400，建议始终写纯 origin。 |
| `publicFingerprint` | 字符串，默认 `""` | 空串；或 64 位十六进制 SHA-256（大小写自动归一）；`"auto"` 仅 `POST /__admin/api/network` 可用，不能出现在配置文件/`network.json` | 二维码 `fp=` 使用的外部证书指纹。留空 = 网关自身 TLS 证书；TLS 在 Caddy/nginx 终止时填代理证书指纹。**证书续期后必须重新读取**。 |
| `tlsCert` / `tlsKey` | 路径，默认 `null` | 必须同时配置或同时留空；必须是 PEM；进程可读 | 网关自己的 HTTPS 证书/私钥。只配一个会启动失败；读取失败/非 PEM 会 `failed to start`。改证书需重启 dsh。 |
| `adminKeyFile` | 路径，默认 `<stateDir>/admin.key` | 支持 `~`、`$HOME`、`$DSH_HOME` 展开；文件内容必须是 64 位小写 hex（32 字节） | 管理密钥文件。首次启动自动生成（0600）；已存在但内容非法时**拒绝启动**。不要把它放进 Web 根目录。 |
| `stateDir` | 路径，默认 `$DSH_HOME/auth-gate`（无 `DSH_HOME` 时 `~/.dsh/auth-gate`） | 持久化目录；只允许一个网关进程使用 | 保存 `state.json`、`admin.key`、`setup.token`、`network.json`。目录 0700；备份/迁移见 7.3。 |
| `sessionTtlHours` | 整数，默认 `48` | 1–720（30 天） | 会话**空闲窗口**（小时）。每个已认证 HTTP 请求在“距上次刷新 ≥ min(1h, 窗口/2)”或“剩余有效期 < 窗口/2”时滑动续期并重发 cookie。改小更安全；改大方便但增加 cookie 泄露窗口。 |
| `sessionAbsoluteTtlDays` | 整数，默认 `30` | 0–3650；0 = 无绝对上限 | 会话**绝对上限**（天，自 `createdAt` 起算）。即使持续活跃，到点后会话也立即失效。 |
| `deviceTtlDays` | 整数，默认 `90` | 1–3650 | 已配对设备的**滑动窗口**；每次 `renew` 成功或密码登录成功推进到 `min(now + 窗口, 配对时间 + 绝对上限)`，设备 cookie 按新的剩余时长重发。 |
| `deviceAbsoluteTtlDays` | 整数，默认 `365` | 0–3650；0 = 无绝对上限 | 设备**绝对上限**（天，自配对创建起算）；到点后设备记录被 prune（同时删除其全部 session），必须重新配对。 |
| `maxDevices` | 整数，默认 `100` | 1–100 | 活跃设备上限；达到上限时**新**设备配对返回 `device_limit`，先吊销旧设备；带未过期 `clientDeviceId` 的重复配对是原地替换，不受此限制。 |
| `pairTicketTtlSeconds` | 整数，默认 `120` | 1–3600 | 一次性配对票据有效期；二维码过期需重新生成。 |
| `loginLock.maxFailures` | 整数，默认 `5` | 1–100 | 同一 IP + 用户名在窗口内允许的失败次数。 |
| `loginLock.windowMinutes` | 整数，默认 `15` | 1–1440 | 失败计数窗口。 |
| `loginLock.lockMinutes` | 整数，默认 `15` | 1–1440 | 达到失败次数后的锁定时间；返回 429 `rate_limited`。 |

补充：

- 数值字段也接受数字字符串（如 `"3443"`），但 YAML 里建议直接写数字。
- `publicUrl` 改变会让所有已配对设备的 origin 失效（登录/续期返回 `origin_changed`），需要重新配对；已有登录会话不受影响，直到过期。
- `publicFingerprint` 改变只影响之后生成的二维码，不会让已配对设备失效（App 只在配对时 pinning）。
- `tlsCert`/`tlsKey` 不支持热加载；换证书必须重启 dsh。
- 内置默认 `listenHost: 127.0.0.1` 只适合本地开发；如果你的 profile 覆盖 `config` 时漏写 `listenHost`，会退回 loopback 并触发 WARN/禁用本机管理通道。

### 3.3 完整配置示例

```yaml
# $DSH_HOME/profiles/web/cordis.patch.yml
# 覆盖插件 bundle 的默认配置。config 整体替换，不要只写单个字段。
- id: auth-gate
  name: 'dsh-pairing-gate'      # 可选：断言目标条目名，写错会跳过该 patch
  config:
    # --- 监听与上游 ---
    listenHost: 172.16.180.14   # 必须是本机 LAN 地址；禁止 127.0.0.1 / 0.0.0.0
    listenPort: 3443
    upstream: https://172.16.180.14:3080
    upstreamInsecureTls: true   # dsh 自签证书；换成受信证书后改 false

    # --- 对外地址与 TLS ---
    publicUrl: https://172.16.180.14:3443
    # 可选：TLS 在 Caddy/nginx 处终止时填代理证书 DER SHA-256（64 位 hex）
    # 留空表示使用网关自己的证书；"auto" 只能用于 POST /__admin/api/network
    # publicFingerprint: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    tlsCert: /opt/deepseekharness/config/tls/dsh.crt.pem
    tlsKey: /opt/deepseekharness/config/tls/dsh.key.pem

    # --- 状态与密钥 ---
    adminKeyFile: $DSH_HOME/auth-gate/admin.key
    stateDir: $DSH_HOME/auth-gate

    # --- 生命周期与限流 ---
    sessionTtlHours: 48            # 空闲窗口（小时）
    sessionAbsoluteTtlDays: 30     # 绝对上限（天，自会话创建起算；0 = 无上限）
    deviceTtlDays: 90              # 设备滑动窗口（天）
    deviceAbsoluteTtlDays: 365     # 设备绝对上限（天，自配对起算；0 = 无上限）
    maxDevices: 100
    pairTicketTtlSeconds: 120
    loginLock:
      maxFailures: 5
      windowMinutes: 15
      lockMinutes: 15
```

如果使用插件自带的 `cordis.patch.yml`（不覆盖），字段与本例相同，只是 `publicFingerprint` 默认没有写（等价于空）。

### 3.4 `network.json` 运行时覆盖

路径：`$STATE_DIR/network.json`（默认 `$DSH_HOME/auth-gate/network.json`）。

用途：管理页「设置」tab 或 `POST /__admin/api/network` 保存的网络参数，重启后仍生效。文件是原子写、`0600`。

格式：

```json
{
  "listenHost": "172.16.180.14",
  "listenPort": 3443,
  "publicUrl": "https://auth.example.com:8443",
  "publicFingerprint": "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
  "updatedAt": 1790000000000
}
```

> 上面的指纹是**纯占位值**，不是任何真实证书的指纹；实际值请用 3.5.2 的命令读取。

规则：

- 只识别 `listenHost`、`listenPort`、`publicUrl`、`publicFingerprint` 四个字段；其余字段忽略。`updatedAt` 只是记录时间，无校验意义。
- `publicFingerprint` 为空时**不会写入文件**（缺省与空串同义，均表示使用网关自身证书）；旧的三字段文件仍兼容。
- 启动时如果文件存在，这四项覆盖 bundle config；日志行尾出现 `[network.json override]`，管理 API 的 `network.source` 为 `override`。
- 文件缺失：使用 bundle config，`source=config`。
- 文件损坏/字段非法（loopback、通配地址、端口等于上游、`publicUrl` 带非根路径、协议与 TLS 状态不符、指纹不是 64 hex 或写了 `auto`）：**不会静默忽略**。启动日志会打印 `network override ... is not valid JSON` 或 `is invalid (...)`，并明确提示：

  ```text
  auth-gate: network override /.../network.json is not valid JSON (...). The runtime network override is IGNORED for this start; continuing with the bundle config.
  auth-gate: to fix, correct the JSON/values in /.../network.json or run `rm -f '/.../network.json'` and restart dsh. ...
  ```

  此时网关**回退到 bundle config 继续启动**（UI 显示 `source=config`），不会绑定到意外地址。修复文件或删除后重启即可。
- **不要在网关运行时只删文件**：内存里的值仍然生效，且下次重启会回到 bundle config，造成“运行值与重启值不一致”。删除后必须重启。
- 手写文件时注意：JSON 里不能写 `$DSH_HOME` 变量；路径只出现在 `stateDir`/`adminKeyFile` 等配置字段，不在此文件。
- 写入方式优先级：管理页/API > 手写。运行中手写会被下一次 API 保存覆盖；手写后重启才生效。

推荐用 API 修改：

```bash
ADMIN=$(sudo cat "$STATE_DIR/admin.key")
BASE="$GATE_URL"

# 查看当前生效值、来源、规则提示
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/network" | jq

# 只改 publicUrl（adminKey 通道免 TOTP；之后的新二维码使用新地址）
curl -sk -X POST "$BASE/__admin/api/network" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicUrl":"https://auth.example.com:8443"}' | jq

# 设置固定指纹（64 位 hex；留空表示用网关自身证书）
curl -sk -X POST "$BASE/__admin/api/network" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicFingerprint":"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}' | jq

# 从当前 publicUrl 自动读取代理证书指纹（TLS 5 秒超时；失败 400 且不落盘）
curl -sk -X POST "$BASE/__admin/api/network" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicFingerprint":"auto"}' | jq
```

通过**登录会话**调用 `POST /__admin/api/network` 时必须带 6 位动态验证码：

```json
{"listenPort": 3443, "totp": "<6位动态验证码>"}
```

错误：缺失 403 `totp_required`，错误 403 `totp_invalid`，失败 5 次锁 5 分钟；adminKey 通道免 TOTP/CSRF。

### 3.5 TLS 证书、SAN 与指纹

#### 3.5.1 SAN 要求

浏览器按 URL 主机名校验证书，所以证书 SAN 必须包含：

- 浏览器实际访问的局域网 IP（如 `172.16.180.14`）；
- 如果通过域名直连，域名（如 `auth.example.com`）；
- 本机健康检查/本机浏览器访问时，`127.0.0.1` 和 `localhost`；
- 如果经 frp TCP 直通、且浏览器直接用中转 IP 访问，中转 IP 也应加入 SAN（否则浏览器告警；App 有指纹 pinning，可不受 SAN 限制）。

注意：

- `127.0.0.1` / `localhost` 只应出现在**证书 SAN**里，方便本机 `curl`/浏览器访问；**不要**把 `listenHost` 配成 `127.0.0.1`。loopback 监听会触发 v0.6.1 的 P0 防护：禁用本机 loopback 管理通道并 WARN，而且 `network.json` 会直接拒绝。
- 网关的 `listenHost` 是绑定地址，`publicUrl` 是二维码/跳转地址，两者可以不同（frp/Caddy 场景很常见），但证书要覆盖用户实际访问的那个主机。
- 证书更换后二维码 `fp` 会变化：**新设备**必须用新二维码配对；已配对设备不受影响（pinning 只在配对时校验）。

检查 SAN：

```bash
openssl x509 -in /opt/deepseekharness/config/tls/dsh.crt.pem \
  -noout -subject -dates -ext subjectAltName
```

#### 3.5.2 指纹

```bash
# 网关自身证书的 SHA-256 DER（小写 hex，无冒号）
openssl x509 -in /opt/deepseekharness/config/tls/dsh.crt.pem \
  -outform DER | openssl dgst -sha256 -r | awk '{print $1}'

# 从任意 HTTPS 入口读取 leaf 证书指纹（Caddy/nginx/网关都适用）
openssl s_client -connect auth.example.com:8443 -servername auth.example.com </dev/null 2>/dev/null \
  | openssl x509 -outform DER | openssl dgst -sha256 -r | awk '{print $1}'
```

这个值就是二维码里的 `fp=`，也是 App 做 fail-closed pinning 的依据。`publicFingerprint` 为空时，网关用自己的证书指纹；非空时用该外部指纹。

#### 3.5.3 生成自签证书（插件独立仓库没有脚本时）

> 本 monorepo 根目录有 `scripts/gen-tls-certs.sh`（相对插件目录是 `../scripts/gen-tls-certs.sh`；**不在插件包内**，独立发布插件时不存在）。它默认输出 `<repo>/server-tls`，生成 CA、`server.crt`/`server.key`，SAN 为 `--ip` 指定地址 + `127.0.0.1` + `localhost`，并输出指纹。用法：
>
> ```bash
> cd /opt/ai_code/mobile-apk
> sudo ./scripts/gen-tls-certs.sh --out /opt/deepseekharness/config/tls --ip 172.16.180.14
> # 产物是 server.crt / server.key；可直接把 tlsCert/tlsKey 指过去，
> # 或复制成 dsh 现有文件名（注意不要覆盖正在使用的证书，先备份）。
> ```
>
> 不要把该脚本当成插件自带功能；插件目录里没有 `scripts/`。

没有脚本时，用下面的 openssl 等价命令生成一张带 SAN 的自签证书（已在临时目录验证语法）：

```bash
sudo install -d -m 755 /opt/deepseekharness/config/tls
cd /opt/deepseekharness/config/tls

sudo openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
  -keyout dsh.key.pem -out dsh.crt.pem \
  -subj "/CN=172.16.180.14" \
  -addext "subjectAltName=IP:172.16.180.14,IP:127.0.0.1,DNS:localhost" \
  -addext "basicConstraints=critical,CA:FALSE" \
  -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
  -addext "extendedKeyUsage=serverAuth"

sudo chmod 600 dsh.key.pem
sudo chmod 644 dsh.crt.pem
sudo chown root:root dsh.key.pem dsh.crt.pem

# 自检
openssl x509 -in dsh.crt.pem -noout -subject -ext subjectAltName
openssl verify -CAfile dsh.crt.pem dsh.crt.pem
```

要点：

- 自签证书浏览器会告警，需要手动接受例外；DSH Mobile 不依赖系统信任，而是比对二维码 `fp`，因此自签证书可以正常配对。
- 如果通过公网域名 + Caddy 终止 TLS，公网用户看到的是 Caddy 的受信证书；网关自身证书只在 Caddy→网关的回源段使用，Caddy 需要 `tls_insecure_skip_verify`（或把网关自签 CA 加入信任）。
- 生产公网强烈建议用 ACME/Let's Encrypt 或 Caddy 自动 HTTPS，不要长期让公网用户手动接受自签例外。

证书轮换流程：

```bash
cd /opt/deepseekharness/config/tls
sudo systemctl stop dsh
# 备份旧证书，替换 tlsCert/tlsKey 指向的文件
sudo cp -a dsh.crt.pem dsh.crt.pem.bak
sudo cp -a dsh.key.pem dsh.key.pem.bak
# 写入新证书/私钥（保持 600/644）
sudo systemctl start dsh
# 检查日志和指纹
sudo journalctl -u dsh -n 100 --no-pager | grep auth-gate
# 如果 TLS 在代理处终止：重新读取 publicFingerprint
# 重新生成配对二维码；旧二维码的 fp 已失效
```

### 3.6 常见错误配置

| 配置 | 后果 | 正确做法 |
|---|---|---|
| `listenHost: 0.0.0.0` / `::` | 启动失败（`config: listenHost must be ... not a wildcard`），或绑定后被二次校验拒绝 | 写具体 LAN 地址 |
| `listenHost: 127.0.0.1` | bundle config 可启动但 WARN 并禁用 loopback 管理通道；`network.json`/API 400；frp 场景会让公网访客被当成 loopback | 写 LAN 地址；frpc `localIP` 同地址 |
| `listenPort` 等于 `upstream` 端口 | 端口冲突，监听失败；API 返回 400 `invalid_listen_port` | 换端口 |
| `publicUrl` 带非根路径/查询/片段 | bundle config 静默归一化为 origin；API/`network.json` 400；尾部 `/` 可接受并归一化 | 写纯 origin，如 `https://auth.example.com:8443` |
| TLS 已配置但 `publicUrl: http://...` | 启动失败：`publicUrl must be https when TLS is configured` | 改成 https，或去掉 TLS（不推荐） |
| 只配 `tlsCert` 或只配 `tlsKey` | 启动失败：`tlsCert and tlsKey must be configured together` | 两个都配或都留空 |
| `admin.key` 被手工改成非 64 位小写 hex | 启动失败：`does not contain 32 bytes of hex; refusing to start` | 用 `openssl rand -hex 32` 重新生成，保持 0600 |
| `upstream` 写成 `http://127.0.0.1:3080` 而 dsh 监听 LAN | 上游 Host/Origin fence 不匹配，401/502 | 写 dsh 实际监听的 authority |
| `stateDir` 指向临时目录 | 重启后账号/设备丢失 | 放持久化目录并备份 |
| profile patch 只写 `config: {listenPort: 3444}` | 其他字段退回默认值（包括 loopback/TLS 丢失） | 写完整 config，或用 `network.json` 只覆盖网络字段 |

---

## 4. 首次初始化

前提：dsh 已重启，日志出现 `auth-gate: listening on ...`；`state.json` 里还没有用户（`GET /__admin/api/setup/status` 返回 `configured:false`）。

两条路径二选一：

- **A. WebUI 向导（推荐）**：浏览器完成建管理员 + 绑定 TOTP + 自动配对当前浏览器；
- **B. adminKey CLI（自动化/应急）**：curl 建用户，拿 TOTP secret/QR；不会自动配对浏览器，需要再生成配对码。

### 4.1 路径 A：WebUI 向导（推荐）

#### 4.1.1 取一次性初始化链接

```bash
# 从启动日志取完整链接（唯一一条会打印完整 setup token 的日志）
sudo journalctl -u dsh -n 200 --no-pager | grep 'setup required'

# 或者从 0600 文件读取 token，再拼链接（默认路径即 $DSH_HOME/auth-gate/setup.token）
sudo cat "$STATE_DIR/setup.token"
# 输出是 64 位 hex；在浏览器打开：
#   $GATE_URL/__admin#setup=<64位hex>
```

链接形如：

```text
https://172.16.180.14:3443/__admin#setup=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
```

token 位于 URL **fragment**（`#setup=`），不会发给服务器，也不会进访问日志。若只打开 `https://.../__admin` 而不带 token，页面会提示粘贴完整链接或 token。

> 能读到 journald 或 `setup.token` 的人，可以在初始化完成前抢先创建管理员。请按 root 级秘密保护；初始化成功后确认 `setup.token` 已删除。

#### 4.1.2 打开向导并创建管理员

在**最终要用来登录的那台浏览器**里打开完整链接：

1. 自签证书会告警：确认访问的是自己的地址后接受例外；
2. 填写用户名：`^[A-Za-z0-9._-]{1,64}$`（字母/数字/`.`/`_`/`-`，1–64 位）；
3. 填写密码：至少 10 位、最多 200 位，两次一致；
4. 点击继续。页面调用 `POST /__admin/api/setup/begin`，服务端校验 token 后返回**一次性 TOTP 二维码 + Base32 密钥**。

此时**还没有创建用户**；草稿只在内存里，刷新/放弃不会留下半初始化状态。

#### 4.1.3 绑定 TOTP

1. 用认证器（Aegis、1Password、Google Authenticator 等）扫描二维码，或手输 Base32 密钥；
2. 输入当前 6 位动态验证码；
3. 点击确认。页面调用 `POST /__admin/api/setup/confirm`，服务端原子完成：

   - 创建用户；
   - 标记 TOTP 已确认；
   - 创建名为「初始化浏览器」的 `web` 设备；
   - 下发 `dsh_gate_device` cookie（默认 90 天）；
   - 删除 `setup.token`。

4. 页面提示成功后跳转 `/__auth/login`，当前浏览器已完成配对，**只需用户名 + 密码**登录，不再需要扫码/TOTP。

#### 4.1.4 登录

在登录页输入用户名和密码；成功后得到 `dsh_gate_session`（v0.7.0 起：空闲窗口默认 48 小时、绝对上限 30 天，活跃请求会滑动续期；v0.7.1 起所有带 cookie 的响应为 `cache-control: private, no-store` + `vary: cookie`），打开 `/__admin` 管理页即可。

#### 4.1.5 令牌生命周期

- 未初始化时首次启动生成 `$STATE_DIR/setup.token`（32 字节随机数 hex，64 位，0600）；之后每次重启复用同一 token，直到初始化完成。
- 初始化成功后删除文件并清空内存；即使进程在删除前崩溃，只要 `state.json` 已配置，下次启动会删除残留文件且不再打印初始化链接。
- token 是**一次性**的：初始化完成后，`setup/begin`、`setup/confirm`、`setup/token` 一律 `409 already_configured`；旧的 token 立即失效。
- 链接丢了/需要轮换：用 adminKey 调 `POST /__admin/api/setup/token`（仅在未初始化时可用）：

  ```bash
  ADMIN=$(sudo cat "$STATE_DIR/admin.key")
  curl -sk -X POST "$GATE_URL/__admin/api/setup/token" \
    -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' -d '{}'
  # 返回 setupUrl（唯一会回显完整 token 的 API）；旧 token 与进行中的草稿立即作废
  ```

- 如果 `state.json` 已有用户，即使 `setup.token` 残留，重启后也不会出现向导（store 会删除残留）。
- 如果确实要重新初始化：先备份，再停止 dsh、清空 `$STATE_DIR`（会丢失账号、TOTP、设备、会话、审计），再启动。不要只删 `setup.token`。

#### 4.1.6 向导的限流与错误

- `setup/begin`、`setup/confirm` 各按 IP 限 **10 次 / 5 分钟**；超出 429 `rate_limited`。
- 浏览器带 `Origin` 时必须与当前网关 authority 同源；缺失 `Origin` 的 curl 兼容放行。
- 错误：`setup_token_invalid`（403，token 错/过期）、`totp_invalid`（403，动态码错）、`weak_password`（400）、`invalid_username`（400）、`already_configured`（409）。
- 审计记录 `setup_begin` / `setup_confirm` / `setup_token_rotated`（成功）或 `admin_denied`（失败）；不写密码、token、TOTP secret。

### 4.2 路径 B：adminKey CLI（自动化/应急）

适用：无浏览器、批量/自动化、向导不可用；或已有管理员但需要脚本化操作。

> 这条路径**不会自动配对当前浏览器**。建完用户后，登录仍会返回 `device_required`，必须先完成一次设备配对（见 4.2.4 和第 5 节）。

#### 4.2.1 读取管理密钥

首次启动自动生成：

```bash
sudo ls -l "$STATE_DIR/admin.key"       # 期望 -rw-------（0600）
ADMIN=$(sudo cat "$STATE_DIR/admin.key")
# 不要 echo $ADMIN；不要写进脚本参数/提交到 git
```

管理密钥是 **32 字节随机数的 64 位 hex**，等价于 bearer 根凭据。日志只打印掩码和后 8 位，完整值只在文件里。

#### 4.2.2 创建管理员

在**未初始化**状态下执行（已初始化会 409）。把响应直接写到 0600 临时文件，避免 secret 进终端/历史：

```bash
ADMIN=$(sudo cat "$STATE_DIR/admin.key")
umask 077
curl -sk -X POST "$GATE_URL/__admin/api/bootstrap" \
  -H "x-auth-gate-admin-key: $ADMIN" \
  -H 'content-type: application/json' \
  -d '{"username":"admin","password":"<至少10位的强密码>"}' \
  > /tmp/auth-gate-bootstrap.json

# 只看字段是否存在/二维码大小，不打印 secret
jq '{ok,username,hasOtpauth:(.otpauthUri!=null),hasSecret:(.secretB32!=null),qrSvgLength:(.qrSvg|length)}' \
  /tmp/auth-gate-bootstrap.json
```

响应（示例字段；实际内容在文件中）：

```json
{
  "ok": true,
  "username": "admin",
  "otpauthUri": "otpauth://totp/...",
  "secretB32": "BASE32SECRET...",
  "qrSvg": "<svg ...>...</svg>"
}
```

说明：

- 用户名规则同上；密码至少 10 位；弱密码 400 `weak_password`。
- `secretB32`、`otpauthUri`、`qrSvg` **只在此次响应出现**，服务端不落盘、不写日志；请立即保存/扫码。
- bootstrap 成功后删除 `setup.token`；该路径不会创建设备。
- `bootstrap` **只能成功一次**：成功后再次调用会 409 `already_configured`。如果 secret 没保存，不要重跑 bootstrap，改用 4.2.3 的 `resetTotp`。
- 如果密码里有引号/反斜杠，直接拼 JSON 会坏；用 `jq` 生成 body 更稳：

  ```bash
  read -rsp '密码（≥10 位）: ' GATE_PASSWORD; echo
  jq -n --arg u 'admin' --arg p "$GATE_PASSWORD" '{username:$u,password:$p}' \
    | curl -sk -X POST "$GATE_URL/__admin/api/bootstrap" \
        -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
        --data-binary @- > /tmp/auth-gate-bootstrap.json
  unset GATE_PASSWORD
  ```

- 更安全的做法是把密码写入 0600 临时文件，用 `--data-binary @file`，完成后 `shred -u`；避免密码出现在 shell 历史和 `ps`。

#### 4.2.3 生成 TOTP 二维码

> 若 4.2.2 已成功建号，**不要再次 bootstrap**（会 409）。直接用 4.2.2 保存的响应；如果当时没保存，走下面的 `resetTotp` 分支。

```bash
# 情形一：4.2.2 的响应已保存
jq -r '.otpauthUri' /tmp/auth-gate-bootstrap.json
jq -r '.qrSvg' /tmp/auth-gate-bootstrap.json > /tmp/auth-gate-totp.svg

# 情形二：已经建号但没保存 secret —— 用 adminKey 重置 TOTP 生成新的
#（会撤销全部设备/会话，之后要重新配对）
ADMIN=$(sudo cat "$STATE_DIR/admin.key")
curl -sk -X POST "$GATE_URL/__admin/api/user" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"resetTotp":true}' > /tmp/auth-gate-totp.json
jq -r '.otpauthUri' /tmp/auth-gate-totp.json
jq -r '.qrSvg' /tmp/auth-gate-totp.json > /tmp/auth-gate-totp.svg
```

打开二维码的方式（任选）：

- 在服务器有桌面的情况下：浏览器打开 `file:///tmp/auth-gate-totp.svg`；
- 把 SVG 复制到自己电脑：`scp user@server:/tmp/auth-gate-totp.svg .`，用浏览器打开；
- 认证器支持手输：类型 TOTP、算法 SHA1、6 位、30 秒，密钥填 `secretB32`（从对应 JSON 的 `.secretB32` 读取，不要 echo 到终端）；
- 已能登录管理页时，也可以在「账号 → 重置 TOTP」里直接看到新二维码（效果等同 `resetTotp`，同样会撤销全部设备/会话）；
- 如果 secret 再次丢失：重复 `resetTotp` 分支（会撤销全部设备/会话，需要重新配对）。

完成后删除临时文件：

```bash
shred -u /tmp/auth-gate-bootstrap.json /tmp/auth-gate-totp.json /tmp/auth-gate-totp.svg 2>/dev/null \
  || rm -f /tmp/auth-gate-bootstrap.json /tmp/auth-gate-totp.json /tmp/auth-gate-totp.svg
```

#### 4.2.4 生成设备配对码

```bash
ADMIN=$(sudo cat "$STATE_DIR/admin.key")
curl -sk -X POST "$GATE_URL/__admin/api/qr" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"platform":"web"}'
```

响应：

```json
{
  "url": "https://172.16.180.14:3443/__auth/pair#v=1&t=<ticket>&fp=<证书指纹>&n=<主机名>",
  "expiresAt": 1790000000000,
  "qrSvg": "<svg ...>"
}
```

- 浏览器配对：把 `url` 复制到**目标浏览器**打开；
- 手机 App 配对：把 `qrSvg` 渲染成二维码给 DSH Mobile 扫描（`platform` 只影响页面提示，票据逻辑相同）；
- 票据默认 **120 秒**、一次性；过期/用掉后重新生成；
- adminKey 通道免 TOTP；登录会话通道生成配对码必须带 6 位 TOTP（见第 5 节）。

#### 4.2.5 已初始化实例怎么办

- `POST /__admin/api/bootstrap` 在已初始化时返回 409 `already_configured`；不要试图重新 bootstrap。
- 忘记密码：用 adminKey 改密（会撤销全部设备/会话，需要重新配对）：

  ```bash
  curl -sk -X POST "$GATE_URL/__admin/api/user" \
    -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
    -d '{"password":"<新的至少10位密码>"}'
  ```

- TOTP 丢失：重置 TOTP（返回新 `secretB32`/`otpauthUri`/`qrSvg`；撤销全部设备/会话）：

  ```bash
  curl -sk -X POST "$GATE_URL/__admin/api/user" \
    -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
    -d '{"resetTotp":true}'
  ```

### 4.3 两条初始化路径对比

| 项目 | A. WebUI 向导 | B. adminKey CLI |
|---|---|---|
| 适用 | 首次部署、人工操作（推荐） | 自动化、无浏览器、应急 |
| 创建用户 | 向导 `setup/begin`+`confirm` | `POST /__admin/api/bootstrap` |
| TOTP | 页面显示二维码，输入动态码确认 | 响应返回 secret/QR，但**不校验** TOTP |
| 自动配对当前浏览器 | 是（创建 `web` 设备 + device cookie） | 否 |
| 初始化后登录 | 用户名 + 密码 | 需先生成/兑换配对码，再用户名 + 密码 |
| 凭据 | setup token（一次性，日志/文件） | adminKey（0600 文件） |
| 初始化后 | setup API 409 | bootstrap 409；用 `/user`、`/qr` 管理 |

---

## 5. 设备配对与登录

### 5.1 准备

- 已完成初始化（`configured:true`）；
- 有有效管理能力：登录会话、或 `x-auth-gate-admin-key`；
- `publicUrl` 与证书指纹正确（frp/Caddy 场景先设好 `publicFingerprint`）；
- 设备数量未达 `maxDevices`（默认 100）；已有同 `clientDeviceId` 的未过期设备时，重复配对走原地替换，不占新名额。

### 5.2 浏览器配对

1. 登录管理页 `$GATE_URL/__admin`，或打开 dsh 侧边栏「认证管理」面板；
2. 进入「配对」；
3. 选择平台「浏览器」；
4. 会话通道需输入认证器当前的 **6 位动态验证码**（adminKey 通道可留空）；
5. 点击「生成配对二维码」；
6. 点「复制配对链接」，在**目标浏览器**打开该链接；
7. 页面 `/__auth/pair` 读取 URL fragment 中的票据，调用 `POST /__auth/pair/redeem`，成功后写入 `dsh_gate_device` cookie（默认 90 天）；
8. 打开 `$GATE_URL`，用用户名 + 密码登录。

注意：同一条链接在哪个浏览器打开，就配对哪个浏览器；换浏览器/清 cookie 都算新设备，需要重新配对。票据 120 秒内有效且只能用一次。

### 5.3 手机 App 配对

1. 管理页「配对」选择「安卓」，输入 TOTP（会话通道）生成二维码；
2. 用 DSH Mobile 扫码；
3. App 先比对二维码里的 `fp` 与它实际看到的证书 SHA-256（fail-closed），不一致会拒绝连接；
4. App 调 `POST /__auth/pair/redeem`，拿到 `deviceToken` 并保存设备 cookie；建议在 body 里带稳定的 `clientDeviceId`（安装 ID），重装后再次扫码不会产生重复设备记录（见 5.3.1）；
5. 在 App 里用用户名 + 密码登录；
6. 会话过期时 App 用 `POST /__auth/renew`（JSON body 的 `deviceToken`，**不需要密码**）换新会话。

`fp` 不匹配的典型原因：TLS 在 Caddy 处终止但没设 `publicFingerprint`，或代理证书续期后没重新读取。见第 6、8 节。

### 5.3.1 同一设备重复配对：`clientDeviceId`（v0.7.3）

`POST /__auth/pair/redeem` 的 JSON body 新增可选 `clientDeviceId`（客户端生成的稳定安装 ID，合法格式 `^[A-Za-z0-9._-]{8,64}$`）。浏览器配对不传该字段，行为完全不变。

- **缺失**：保持现行「每次兑现票据都新建一条设备记录」。
- **非法**（非字符串、长度不在 8–64、含非法字符）：**400 `invalid_client_device_id`**，审计 `pair_redeem`（detail `invalid_client_device_id`），票据**不消耗**，可用合法值重试；store 层收到非法值同样返回 `invalid_client_device_id`，不会静默当成缺失而新建。
- **合法且存在未过期（`expiresAt > now`）的同 ID 设备**：原地复用同一 `device.id`，更新 `name`/`platform`/`origin`/`lastSeenAt`，生成新 `deviceToken`（旧 tokenHash 立即失效，旧 token 的 `/__auth/renew` → 401），**删除该设备全部旧 session**，**清空全部其它待用配对票据**（重新配对 = 完整凭据重置，与吊销设备同级联；替换前签发的其它票据 redeem 均返回 `invalid_ticket`），`createdAt = now`（重新配对 = 重新验证，绝对上限窗口重置），`expiresAt = min(now + deviceTtlDays, createdAt + deviceAbsoluteTtlDays)`；不新增设备、不占新名额、不触发 `device_limit`，响应带 `replaced: true` 并回显 `clientDeviceId`。
- **合法但没有匹配设备**：按现行逻辑新建（含 `maxDevices` 检查），响应 `replaced: false`；回显 `clientDeviceId`。
- 并发同 ID 的 redeem 由 store 锁串行；最终只保留一条设备记录，只有最后一次轮换出的 token 有效。
- `clientDeviceId` 只是去重提示，不是认证因子，必须使用安装级高熵随机值（App 使用 UUID）；它仅保存在内部 `state.json`（可选字段，旧设备无该字段视为无），管理 API/审计/日志不展示。

```bash
# 第一次：新建（replaced=false）
curl -k -X POST -H 'content-type: application/json' \
  -d '{"ticket":"t_xxx","clientDeviceId":"android-install-9f2c1a7b","deviceName":"Pixel 8","platform":"android"}' \
  "$GATE_URL/__auth/pair/redeem"

# 旧 token 失效后，用同一 ID 重新扫码：原地替换（replaced=true，deviceId 不变，设备总数不变）
curl -k -X POST -H 'content-type: application/json' \
  -d '{"ticket":"t_yyy","clientDeviceId":"android-install-9f2c1a7b","deviceName":"Pixel 8","platform":"android"}' \
  "$GATE_URL/__auth/pair/redeem"
# → {"deviceToken":"dt_…","deviceId":"d_…","replaced":true,"clientDeviceId":"android-install-9f2c1a7b",...}
```

### 5.4 登录、会话、续期、登出

- 未登录访问页面：HTML 请求 302 到 `/__auth/login?next=...`；非 HTML/API 请求 401 JSON `authentication_required`。
- 登录：`POST /__auth/login`，JSON `{username,password}`，需要 CSRF 头/cookie；成功 200 + `dsh_gate_session`（空闲窗口默认 48 小时、绝对上限 30 天）并返回 `expiresAt`/`deviceExpiresAt`。登录成功也会滑动设备有效期并重发 `dsh_gate_device`。
- 无设备 cookie：401 `device_required`；设备 origin 与当前 `publicUrl` 不一致：401 `origin_changed`；用户名/密码错：401 `invalid_credentials`；连续失败触发 429。
- `GET /__auth/whoami`：无会话返回 200 `{"authenticated":false}`；有会话返回用户/设备/过期时间。
- `POST /__auth/logout`：删除当前会话，设备保留。
- `POST /__auth/renew`：只接受 JSON body 的 `deviceToken`，不接受 cookie 回退；成功换新会话，同时滑动设备有效期、重发设备 cookie，并在响应中返回 `deviceExpiresAt`（毫秒时间戳）。
- 会话滑动：每个**已认证的 HTTP 请求**（反代、管理页/API、whoami；不含 WebSocket upgrade，WS 只更新 `lastSeenAt`）在到期前按配置刷新 `expiresAt` 并重发 `dsh_gate_session`（同一 token，新的 `Max-Age`）。刷新只在需要时发生（每次请求最多一次落盘），SSE/流式响应与静态资源不会造成写放大。
- 绝对上限：`now > expiresAt`（空闲）或 `now > createdAt + sessionAbsoluteTtlDays`（绝对）都视为无效；旧版本创建的会话在下一次刷新时补写 `absoluteExpiresAt`。
- 设备 cookie：`dsh_gate_device`；会话 cookie：`dsh_gate_session`；CSRF cookie：`dsh_gate_csrf`；都 `HttpOnly`、`SameSite=Lax`，TLS 下 `Secure`。
- 网关不把 dsh 的 `dsh-auth-*` cookie 暴露给浏览器：上游注入、响应剥离。

### 5.5 v0.4+ 的 TOTP 语义（重要）

| 操作 | 是否需要 TOTP | 说明 |
|---|---|---|
| 设备配对（生成二维码/链接） | **是**（登录会话通道）；adminKey/loopback 免 | TOTP 只在这里证明“持有认证器” |
| 登录（已配对设备） | **否** | 用户名 + 密码即可；设备 cookie 就是第二因素 |
| 续期 `renew` | **否** | 只凭 `deviceToken`；等价于长期 bearer |
| 改密码 / 重置 TOTP | 需要**当前密码**（会话通道）；adminKey 免 | 成功后撤销全部设备 + 会话，需重新配对 |
| 修改网络设置（会话通道） | **是**（6 位 TOTP） | adminKey/loopback 免 |

因此：

- TOTP 泄露但设备未配对：不能直接登录，但可能被用来生成新配对码（还需要有效管理会话或 adminKey）；
- 密码泄露 + 已配对设备：可以直接登录；
- 设备 cookie/`deviceToken` 泄露：等同于账号凭据（可免密 renew），应立即吊销设备；
- 改密码/重置 TOTP 是整信任面重置，所有手机/浏览器都要重新扫码。

### 5.6 配对票据、限流与错误

- 票据 TTL 默认 `120` 秒（`pairTicketTtlSeconds`），服务端只存 SHA-256，票据只在 URL fragment，不进日志；
- 票据一次性：成功兑换后失效；重复兑换返回 401 `invalid_ticket`；过期返回 401 `expired_ticket`；
- 设备达到上限：新设备 401 `device_limit`，先吊销旧设备；带未过期 `clientDeviceId` 的重复配对原地替换，不受上限影响；
- 配对/续期按 IP 限 30 次/分钟；QR 签发按 IP 限 10 次/分钟；会话通道的配对 TOTP 失败 5 次锁 5 分钟；超出 429 `rate_limited`（带 `Retry-After`）；
- 登录失败：同一 IP + 用户名窗口内 5 次失败锁 15 分钟（可配）；成功一次清零；
- 错误响应统一 JSON `{error:"..."}`；页面/审计不含密码、TOTP、票据、deviceToken。

### 5.7 `publicUrl`/origin 变更的影响

设备在配对时把 `origin`（即当时的 `publicUrl`）写入 `state.json`。之后：

- 只改 `publicUrl`：**新二维码**使用新地址；已配对设备从旧 origin 登录/续期返回 `origin_changed`，必须重新配对；已有登录会话仍有效到过期。
- 只改端口、同 host：浏览器 cookie 仍会携带；但设备记录的 origin 变了（如果 publicUrl 也变），仍可能要求重新配对。
- 换域名/host：cookie 按 host 隔离，通常需要重新登录；设备 origin 也可能不匹配。
- 改 `publicFingerprint`：只影响之后生成的二维码；已配对设备不需要重配。
- 改监听地址/端口：立即重建监听；现有 HTTP/WebSocket 连接会断开，页面需刷新/重连；frpc `local_port` 要同步改；`publicUrl` 不会自动跟着变。

---

## 6. 网络设置、frp 与 Caddy

### 6.1 在管理页修改网络设置

服务端 `/__admin` 与原生侧边栏「认证管理 → 设置」都支持：

1. 登录管理页/打开面板；
2. 进入「设置」；
3. 查看只读信息：TLS 是否启用、生效来源（`override`/`config`）、当前监听、`publicUrl`、实际用于二维码的指纹；
4. 修改 `listenHost`、`listenPort`、`publicUrl`、`publicFingerprint`；
5. 会话通道需输入 6 位 TOTP + 内联二次确认；adminKey/loopback 免 TOTP；
6. 保存。监听变化会**先绑定新地址、成功持久化后再关闭旧监听**；失败自动回滚，返回 400 `rebind_failed`（`reason=address_in_use|address_not_available|permission_denied|listen_failed|persist_failed`）；
7. 保存成功后连接可能短暂中断，刷新页面/使用新地址访问；`publicUrl` 变化后新二维码使用新地址。

`POST /__admin/api/network` 成功响应：

```json
{"ok":true,"network":{"listenHost":"...","listenPort":3443,"publicUrl":"...","tlsConfigured":true,"source":"override","publicFingerprint":"...","effectiveFingerprint":"...","fingerprintHint":"..."},"rebound":true}
```

`GET /__admin/api/network` 返回 `{network:{...}, rules:{...}}`。

### 6.2 `publicUrl` 怎么填

| 场景 | `listenHost`/`listenPort` | `publicUrl` | 指纹 |
|---|---|---|---|
| 局域网直连 | `172.16.180.14:3443` | `https://172.16.180.14:3443` | 空（网关自身证书） |
| frp TCP 直通 | `172.16.180.14:3443` | `https://203.0.113.10:23443` | 空（App 用网关证书 fp pinning） |
| frp + Caddy 终止 TLS | `172.16.180.14:3443` | `https://auth.example.com:8443` | Caddy 证书 SHA-256（`publicFingerprint`） |

`publicUrl` 只用于生成二维码/链接/初始化链接和设备 origin，**不会**改变实际监听地址；建议写纯 origin（尾部 `/` 会被归一化，非根路径会被管理 API 拒绝）。

### 6.3 方案一：frp TCP 直通（推荐，简单）

拓扑：

```text
公网用户 ──HTTPS──> frps:23443 ──TCP──> frpc ──> 网关 172.16.180.14:3443（TLS 由网关终止）
```

`frpc.toml`（frpc 与网关同机/同内网；以 frp v0.52+ 的 TOML 格式为例；旧版 ini 写 `local_ip`/`local_port`，字段名以你的 frp 版本为准）：

```toml
serverAddr = "203.0.113.10"
serverPort = 7000
auth.method = "token"
auth.token = "<FRP_TOKEN>"

[[proxies]]
name = "dsh-auth-gate"
type = "tcp"
localIP = "172.16.180.14"   # 必须是网关绑定的同一 LAN 地址，不能是 127.0.0.1
localPort = 3443
remotePort = 23443
```

frps 侧：

- 放行 `23443/tcp`（只这一个公网入口）；
- `3443` 和 `3080` 保持私有；
- 如需限制 frps 监听，按 frp 版本配置 `proxyBindAddr`/防火墙，只让公网访问 `remotePort`。

然后：

1. 管理页把 `publicUrl` 改成 `https://203.0.113.10:23443`；
2. 生成新的配对码；
3. 浏览器直接访问中转 IP 时，若证书 SAN 不含该 IP 会告警：可临时接受例外，或重签含该 IP/域名的证书；
4. App 按二维码 `fp` pinning，即使 SAN 不含中转 IP 也能配对。

注意：frpc 所在主机的地址会成为网关看到的所有外部访客源 IP，按 IP 的限流会被共享；登录仍需要已配对设备 + 密码。

### 6.4 方案二：frp + Caddy 终止 TLS（v0.6.2）

拓扑：

```text
浏览器/App ──HTTPS(auth.example.com:8443, Caddy 受信证书)──> VPS Caddy
    └──HTTPS 回源──> frps 127.0.0.1:18080 ──> frpc ──> 网关 172.16.180.14:3443（自签）
```

`frpc.toml`：

```toml
serverAddr = "203.0.113.10"
serverPort = 7000
auth.method = "token"
auth.token = "<FRP_TOKEN>"

[[proxies]]
name = "dsh-auth-gate-caddy"
type = "tcp"
localIP = "172.16.180.14"   # 不能写 127.0.0.1
localPort = 3443
remotePort = 18080
```

frps 侧：让 `18080` 只对 Caddy 可见（例如 `proxyBindAddr = "127.0.0.1"`，视 frp 版本；或用防火墙只放行 Caddy 主机）。

`Caddyfile`（VPS）：

```caddyfile
auth.example.com:8443 {
    tls admin@example.com

    reverse_proxy 127.0.0.1:18080 {
        # 关键：保留浏览器原始 Host（含端口）。Caddy 默认可能把 Host
        # 改成上游 127.0.0.1:18080，导致网关的 Origin/Host 同源校验拒绝
        # 带 Origin 的模块/样式/接口请求（表现为 403 forbidden_origin、
        # 登录后黑屏、MIME application/json）。
        header_up Host {http.request.hostport}

        # 回源到网关自签 HTTPS；生产不建议明文 HTTP 回源
        transport http {
            tls
            tls_insecure_skip_verify
        }
    }
}
```

然后：

1. 管理页把 `publicUrl` 设为 `https://auth.example.com:8443`；
2. 点「从对外地址自动读取」或 `POST {"publicFingerprint":"auto"}`，保存 Caddy 证书指纹；
3. 之后生成的二维码 `fp=` 是 Caddy 证书指纹，App 可正常配对；浏览器看到有效证书无告警；
4. **证书续期后必须重新读取指纹**，否则新二维码仍是旧指纹，App fail-closed 拒绝。

关于 `header_up Host`：

- 网关的 `sameBrowserOrigin()` 要求请求 `Origin` 的 host 与 `Host` 头完全一致（协议也要匹配）；反代若改写 Host，浏览器发 `Origin: https://auth.example.com:8443`，上游却是 `Host: 127.0.0.1:18080`，请求被 403 `forbidden_origin`；
- 带 `Origin` 的请求包括登录 POST、部分模块/静态资源请求；表现可能是登录页能开，但登录后黑屏、控制台报 `MIME type application/json` 或 403；
- WebSocket 握手同样校验 Origin/Host；
- 原则：让网关收到的 `Host` 与浏览器访问的 authority **完全一致**。端口不是 443 时用 `{http.request.hostport}`；如果站点在 443 且实际 Host 不带端口，用 `{http.request.host}`（以实测为准），或者用 Caddy 的 `header_up Host {http.request.host}` 并确认 8443 场景下端口不丢。
- 不要用 `X-Forwarded-Host` 试图绕过：网关只看 `Host` 头；也不要用明文 HTTP 回源。

### 6.5 `publicFingerprint` 设置与续期

- 留空：二维码 `fp=` = 网关自身 TLS 证书指纹；适合直连/ frp TCP 直通。
- 64 位 hex：二维码 `fp=` = 外部（代理）证书指纹；适合 Caddy/nginx 终止 TLS。
- `"auto"`：仅 `POST /__admin/api/network` 可用；服务端用 `node:tls` 连接**当前提交/已保存的 `publicUrl`** 的 host:port（默认 443），5 秒超时，`rejectUnauthorized:false`，不发 HTTP 请求，读取 leaf 证书 DER 算 SHA-256；失败 400 `fingerprint_fetch_failed`（`reason=not_https|timeout|connection_refused|dns_failed|unreachable|certificate_failed|...`），不落盘、不改状态。
- `publicFingerprint` 变更只影响之后生成的二维码；已配对设备不需要重配（pinning 只发生在配对时）。
- 代理证书续期后：重新点「从对外地址自动读取」或 POST `auto`；旧二维码配对会失败；已配对设备继续可用。
- 校验：

  ```bash
  # 二维码实际使用的指纹（公开管理 API，需 adminKey）
  curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$GATE_URL/__admin/api/network" \
    | jq '.network | {publicFingerprint, effectiveFingerprint, fingerprintHint}'

  # 代理证书指纹（应与保存值一致）
  openssl s_client -connect auth.example.com:8443 -servername auth.example.com </dev/null 2>/dev/null \
    | openssl x509 -outform DER | openssl dgst -sha256 -r | awk '{print $1}'
  ```

### 6.6 安全红线（必须遵守）

1. **`listenHost` 不能是 loopback**（`127.0.0.1`、`::1`、`::ffff:127.0.0.1`）。loopback 监听会让本机 frp/反代转发来的公网访客看起来像本机管理员；v0.6.1 会禁用 loopback 管理通道并 WARN，`network.json`/API 直接拒绝。
2. **frpc 的 `localIP` 必须是网关绑定的同一 LAN 地址，不能是 `127.0.0.1`**。否则 frp 回源破坏信任模型：所有公网访客都是 loopback 对端，可能免 TOTP/会话访问管理 API。
3. **3080 只对内网开放**：dsh 原生的 3080 直连会绕过网关；用防火墙 rich rule/安全组限制到内网网段，绝不放到公网。
4. **公网只暴露认证网关**（直连 3443，或 frps 的 remote_port / Caddy 的 8443）；3443 在 frp/Caddy 模式下只给 frpc/Caddy 访问。
5. **回源不要用明文 HTTP**（Caddy/nginx 终止 TLS 时）；`transport http { tls }` + `tls_insecure_skip_verify`（或信任网关 CA）。
6. **不要用 `0.0.0.0`/`::`** 监听；网关会拒绝通配地址。
7. 前置代理会让源 IP 变成代理地址，按 IP 的登录/配对限流共享；接受这个取舍，或只让可信代理回源。

### 6.7 修改后的影响与回滚

| 修改 | 立即影响 | 设备/二维码 | 回滚 |
|---|---|---|---|
| `publicUrl` | 不断连；新二维码/链接使用新地址 | 已配对设备登录/续期返回 `origin_changed`，需重配；已有会话有效 | 改回旧值或删 `network.json` + 重启 |
| `publicFingerprint` | 不断连；新二维码 `fp` 变化 | 已配对设备不受影响；旧二维码失效 | 重新读取/清空 |
| `listenHost`/`listenPort` | 重建监听，现有连接断开；需刷新/重连 | `publicUrl` 不变则二维码不变；frpc `local_port` 要同步 | 保存旧值或删 `network.json` + 重启；失败自动回滚 |
| 两者同时改 | 先存 `publicUrl` 再改监听，避免二维码短暂指向旧入口 | 改完重新生成二维码 | 逐项恢复 |

回滚到 bundle config：

```bash
export STATE_DIR=/opt/deepseekharness/config/dsh/auth-gate   # 按实际替换
sudo systemctl stop dsh
sudo rm -f "${STATE_DIR:?}/network.json"    # 确认路径！会丢失运行时网络覆盖
sudo systemctl start dsh
sudo journalctl -u dsh -n 100 --no-pager | grep auth-gate
```

**不要**在网关运行时只删 `network.json`；内存值仍生效，且重启后行为变化。TLS 证书本身不会热加载，换证书仍需重启。

---

## 7. 日常运维

### 7.1 管理页功能

服务端管理页：`$GATE_URL/__admin`（未登录 HTML 302 到登录页；登录后 200）。
原生侧边栏：dsh 左侧「全局面板 → 认证管理」，同源时可用；从 3080 直连只显示说明卡（设计行为）。

| 区块 | 功能 | 安全要求 |
|---|---|---|
| 账号 | 修改密码（当前密码 + 新密码 ≥10 位 + 确认）；重置 TOTP（内联确认，新 QR/secret 只显示一次） | 会话通道必须当前密码；成功后撤销全部设备 + 会话，需要重新配对 |
| 配对 | 平台（安卓/浏览器）、6 位 TOTP（会话通道）、生成/重新生成二维码、倒计时、复制链接 | 会话通道必须 TOTP；adminKey 免 |
| 设备 | 名称/ID、平台、在线（最近 120 秒）、当前设备、创建/最近活跃/到期、吊销 | 吊销立即失效该设备会话与续期 |
| 会话 | 设备、创建/最近活跃/到期、当前会话标记；不显示 token | 最多 100 条 |
| 设置 | TLS 状态、来源、监听、`publicUrl`、`publicFingerprint`、自动读取指纹、保存 | 会话通道必须 TOTP；改监听会短暂断连 |
| 审计 | 最近 100 条：时间/类型/IP/设备/详情，倒序 | 不含密码/TOTP/票据/token |

`/__admin?embed=1` 是给 dsh Web GUI 的同源 iframe 模式；`frame-ancestors 'self'`，其他页面保持 `DENY`。

### 7.2 adminKey 应急命令

```bash
ADMIN=$(sudo cat "$STATE_DIR/admin.key")
BASE="$GATE_URL"

# 状态（用户、TOTP 是否配置、设备、会话摘要、网络）
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/state" | jq

# 会话摘要
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/sessions" | jq

# 生成配对码（platform: android|web；adminKey 免 TOTP）
curl -sk -X POST "$BASE/__admin/api/qr" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"platform":"android"}' | jq

# 吊销设备（同时撤销其会话）
curl -sk -X POST "$BASE/__admin/api/devices/revoke" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"deviceId":"d_xxx"}' | jq

# 改密码（撤销全部设备/会话；至少 10 位）
curl -sk -X POST "$BASE/__admin/api/user" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"password":"<新的至少10位密码>"}' | jq

# 重置 TOTP（返回新 secret/otpauthUri/qrSvg；撤销全部设备/会话）
curl -sk -X POST "$BASE/__admin/api/user" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"resetTotp":true}' | jq

# 网络设置
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/network" | jq
curl -sk -X POST "$BASE/__admin/api/network" \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicUrl":"https://auth.example.com:8443"}' | jq

# 审计（最近 100 条）
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/audit" | jq
```

adminKey 通道免 TOTP/CSRF，但它是 bearer 根凭据；不要写进 URL、日志、shell 历史或截图。`bootstrap` 只在未初始化时可用；已初始化用 `/user`/`/qr`。

### 7.3 状态目录备份与恢复

`$STATE_DIR` 内容：

| 文件 | 内容 | 权限 |
|---|---|---|
| `state.json` | 用户、密码哈希、TOTP secret、设备、票据、会话、审计 | 0600 |
| `admin.key` | 64 位 hex 管理密钥 | 0600 |
| `network.json` | 运行时网络覆盖（可选） | 0600 |
| `setup.token` | 未初始化时的一次性初始化 token（初始化后没有） | 0600 |

备份（建议停服务保证一致；网关状态是原子写，但停机最稳）：

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export STATE_DIR="$DSH_HOME/auth-gate"   # 若自定义 stateDir，改成实际路径

sudo systemctl stop dsh
sudo tar -C "$(dirname "${STATE_DIR:?}")" -czpf "/root/auth-gate-$(date +%F-%H%M).tgz" "$(basename "${STATE_DIR:?}")"
sudo systemctl start dsh

# 检查备份内容与权限
sudo tar -tzf /root/auth-gate-*.tgz | head
```

恢复：

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export STATE_DIR="$DSH_HOME/auth-gate"   # 若自定义 stateDir，改成实际路径

sudo systemctl stop dsh
sudo cp -a "${STATE_DIR:?}" "${STATE_DIR:?}.before-restore.$(date +%s)" 2>/dev/null || true
sudo tar -C "$(dirname "${STATE_DIR:?}")" -xzpf /root/auth-gate-YYYY-MM-DD-HHMM.tgz
sudo chown -R root:root "${STATE_DIR:?}"
sudo chmod 700 "${STATE_DIR:?}"
sudo find "${STATE_DIR:?}" -type f -exec chmod 600 {} +
sudo systemctl start dsh
sudo journalctl -u dsh -n 100 --no-pager | grep auth-gate
stat -c '%a %U:%G %n' "$STATE_DIR" "$STATE_DIR"/*
```

注意：

- 备份包含 TOTP secret、密码哈希、会话/设备 token 哈希；按 root 级秘密保管，跨机传输要加密；
- 恢复后如 `network.json` 与当前网卡/域名不匹配，可能绑定失败或回退；必要时删除/修正 `network.json` 并重启；
- 不要在网关运行时覆盖 `state.json`；同一 `stateDir` 只允许一个网关进程；
- 跨版本恢复前先看 release notes；`state.json` 有版本字段（当前 `version: 1`），不兼容时网关会拒绝启动而不是重置；
- 生产重置：先备份，再停止 dsh、移走/清空 `$STATE_DIR`，启动后走首次初始化；这会丢失账号、TOTP、设备、审计。

### 7.4 日志与审计

```bash
# 启动/监听/初始化/网络覆盖
sudo journalctl -u dsh -n 200 --no-pager | grep -E 'auth-gate|admin key|setup required|network.json'

# 实时
sudo journalctl -u dsh -f | grep --line-buffered -E 'auth-gate|failed to start'

# 本次启动
sudo journalctl -u dsh -b --no-pager | grep auth-gate
```

日志中可能出现的关键行：

- `auth-gate: listening on ...`：成功监听；
- `auth-gate: failed to start: ...`：启动失败（dsh 继续运行，网关不可用）；
- `auth-gate: setup required — open ...`：未初始化，唯一带完整 setup token 的日志；
- `auth-gate: generated admin key ****...<后8位>`：首次生成 admin key，只有掩码；
- `auth-gate: listener is bound to loopback — ... DISABLED`：监听 loopback 的 WARN；
- `auth-gate: network override ... IGNORED ...`：`network.json` 损坏回退；
- `auth-gate: network rebind complete — ...`：热重建成功。

审计：管理页「审计」或 `GET /__admin/api/audit`，最近 100 条；`state.json` 保留最近 500 条。审计只记粗粒度原因/IP/设备，不写密码、TOTP secret、票据、deviceToken。`setup required` 日志是唯一带完整初始化 token 的例外，初始化后不再出现；请限制 journald 读取权限。

### 7.5 证书、adminKey、账号轮换

| 操作 | 步骤 | 影响 |
|---|---|---|
| 换 TLS 证书 | 备份旧证书 → 替换 `tlsCert`/`tlsKey` 文件 → `systemctl restart dsh` → 检查日志/指纹 → 重新生成二维码 | 新设备需新二维码；已配对设备不受影响；若走 Caddy，重新读取 `publicFingerprint` |
| 轮换 adminKey | 停 dsh → `openssl rand -hex 32 > "${STATE_DIR:?}/admin.key"` → `chmod 600` → 启动 | 旧 key 立即失效；不影响用户/设备/TOTP/会话 |
| 改密码 | 管理页/`POST /__admin/api/user` | 撤销全部设备 + 会话；所有设备重新配对 |
| 重置 TOTP | 管理页/`POST /__admin/api/user {"resetTotp":true}` | 同上；新 secret/QR 只显示一次 |
| 吊销单台设备 | 管理页/`POST /__admin/api/devices/revoke` | **级联**：设备记录、该设备全部 session、全部待用配对票据一次原子删除；旧 deviceToken 的 renew、所有 session cookie 与设备 cookie 下一次请求立即失效（401/403）；不影响其他设备 |

adminKey 文件丢失但有 root：停止 dsh，写入新的 64 位 hex 到 `admin.key`（0600），启动；不需要清空 `state.json`。如果连 `state.json` 也丢失，只能重新初始化（全部设备/账号丢失）。

### 7.6 监控建议

- `systemctl is-active dsh`、`ss -ltnp | grep 3443`；
- `curl -sk -o /dev/null -w '%{http_code}' "$GATE_URL/__auth/login"` 期望 200；
- 关注日志 `failed to start`、`upstream ... request failed`、`502`；
- 证书到期（`openssl x509 -enddate`）、设备到期、`admin.key`/`state.json` 权限；
- 磁盘空间（`state.json` 增长、审计 500 条上限）；
- 3080 不得出现在公网防火墙规则中。

---

## 8. 故障排查

### 8.1 快速定位

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export GATE_URL=https://172.16.180.14:3443
export STATE_DIR="$DSH_HOME/auth-gate"

sudo systemctl status dsh --no-pager
sudo journalctl -u dsh -n 200 --no-pager | grep -E 'auth-gate|failed to start|setup required|network'
sudo ss -ltnp | grep -E ':3443|:3080'
curl -sk -o /dev/null -w 'login=%{http_code}\n' "$GATE_URL/__auth/login"
curl -sk "$GATE_URL/__admin/api/setup/status"; echo
curl -sk "$GATE_URL/__auth/whoami"; echo
curl -sk -o /dev/null -w 'root=%{http_code}\n' "$GATE_URL/"
curl -sk -o /dev/null -w 'root_html=%{http_code} %{redirect_url}\n' -H 'Accept: text/html' "$GATE_URL/"
```

### 8.2 现象 → 原因 → 修法

| 现象 | 原因 | 修法 |
|---|---|---|
| 登录返回 401 `not_configured` | `state.json` 还没有用户（全新实例），不是默认账号问题 | 走第 4 节 WebUI 向导或 adminKey bootstrap；不要猜默认密码 |
| 登录返回 401 `device_required` | 当前浏览器/App 没有有效设备 cookie；设备被吊销/过期；cookie 被清；`renew` 没带 `deviceToken` | 在管理页生成配对码，用目标设备打开链接/扫码；`renew` 只在 JSON body 传 `deviceToken` |
| 登录/续期返回 401 `origin_changed` | 设备配对时的 `publicUrl` 与当前 `publicUrl` 不一致（改了域名/端口/中转地址） | 重新生成配对码并配对；旧设备可在管理页吊销；确认新 `publicUrl` 是最终入口 |
| 登录返回 401 `invalid_credentials` | 用户名或密码错（已配对设备上不再校验 TOTP） | 核对用户名/密码；忘记密码用 adminKey `POST /__admin/api/user` 重置（会撤销全部设备/会话） |
| 登录返回 429 `rate_limited` | 同一 IP+用户名 15 分钟内失败 5 次（可配）；或配对/续期/QR/会话 TOTP 的独立限流 | 看 `Retry-After` 等待；不要反复试；必要时改密码/用 adminKey；重启会清内存计数但会中断服务 |
| 403 `forbidden_origin` | 反向代理改写了 `Host`，浏览器 `Origin` 与上游 `Host` 不一致；或访问协议/Host 与网关不一致 | Caddy 加 `header_up Host {http.request.hostport}`（443 站点按实际用 `{http.request.host}`）；确保 Host/Origin 完全一致；WebSocket 同样 |
| 登录页能打开，登录后黑屏；Console 报 `MIME type application/json` 或资源 403 | 同 `Host` 问题：模块/静态资源请求带 Origin，被网关 403 JSON，浏览器拒绝把 JSON 当 JS/CSS | 修代理 Host 保留；检查 `curl -H 'Origin: https://auth.example.com:8443'` 的响应；硬刷新；确保没有从 3080 访问 |
| DSH Mobile 扫码后拒绝配对 / “指纹不匹配” | 二维码 `fp` 与 App 实际看到的证书不一致：TLS 在 Caddy 终止但没设 `publicFingerprint`；代理证书续期后没重读；二维码是旧的 | 设 `publicUrl` 为公网入口；点「从对外地址自动读取」/POST `auto`；重新生成二维码；续期后重复此操作 |
| 启动日志 `network override ... IGNORED` / `source=config` | `network.json` 损坏或字段非法（loopback/通配/端口等于 upstream/`publicUrl` 带路径/协议不符/指纹非 64 hex 或 `auto`） | 按日志修 JSON 或 `sudo rm -f "${STATE_DIR:?}/network.json"`，重启 dsh；删除前确认路径；不要在运行时只删 |
| 修改网络设置返回 400 `rebind_failed`（`address_in_use` 等） | 新端口被占用/地址不可用/权限不足；或 `network.json` 持久化失败 | `ss -ltnp` 查占用；换端口；检查状态目录写权限/磁盘；旧监听未受影响，修正后重试；`persist_failed` 查 stateDir 权限 |
| `GET /__admin/api/admin-key` 403 / 不可用 | 该端点只对 loopback 管理通道开放；网关监听 loopback 时整条通道被 v0.6.1 禁用；从 LAN/公网访问不是 loopback | 直接读 `$STATE_DIR/admin.key`（0600）并用 `x-auth-gate-admin-key` 头；不要把该端点当常规取 key 方式 |
| 启动只有 `auth-gate: failed to start: ...` | 端口占用、证书读不到/非 PEM、`listenHost` 通配、`publicUrl` 与 TLS 不匹配、state 损坏、`admin.key` 非法 | 看具体错误；插件故意不把异常抛进 Cordis，dsh 仍可用；逐项修配置/权限/端口后重启 |
| 反代 502 `upstream_auth_failed` | 网关换不到 dsh launch token（dsh 重启/token 失效）；上游 TLS 校验/`upstreamInsecureTls` 配错；`upstream` authority 不对 | 检查 dsh 日志、`upstream` 是否为 dsh 实际监听地址、`upstreamInsecureTls` 是否为 true；重启 dsh 后 `authenticatedUrl()` 会重取 |
| 上游 401 后仍 502 | dsh 的 Host/Origin fence 与 `upstream` authority 不一致（常见写 `127.0.0.1` 但 dsh 监听 LAN） | `upstream` 改成 dsh 实际监听 authority；不要用 localhost 代理 LAN 监听 |
| 初始化向导 409 `already_configured` | 已有用户，setup 写接口永久关闭 | 用密码登录或 adminKey 管理；确需重来只能停机备份/清空 `$STATE_DIR`（丢失全部数据） |
| 初始化 token 无效/过期 | token 一次性；轮换后旧 token 失效；初始化已完成 | 用 adminKey `POST /__admin/api/setup/token` 取新链接（仅未初始化）；已初始化则走登录 |
| 二维码兑换 401 `invalid_ticket` / `expired_ticket` | 票据一次性/超过 120 秒/已被使用/服务端重启丢失 | 重新生成；确保手机/服务器时间同步；不要重复打开旧链接 |
| 配对 401 `device_limit` | 活跃设备达到 `maxDevices`（默认 100）；注意带同一 `clientDeviceId` 的替换不受限 | 管理页吊销不用/过期设备；或提高 `maxDevices`（需重启/配置） |
| 403 `csrf_invalid` | 会话/loopback 通道 POST 缺少 `x-auth-gate-csrf` 或与 `dsh_gate_csrf` cookie 不一致 | 用管理页操作；脚本用 adminKey（免 CSRF）；不要手写无 CSRF 的会话 POST |
| 403 `totp_required` / `totp_invalid` | 会话通道生成配对码/改网络设置必须带 6 位 TOTP；手机/服务器时间偏差超过 ±1 窗口 | 输入当前验证码；同步时间（NTP）；或用 adminKey 通道 |
| 403 `invalid_current_password` | 会话通道改密码/重置 TOTP 必须当前密码 | 输入当前密码；忘记则用 adminKey 重置 |
| 状态文件损坏/网关拒绝启动 | `state.json` 非法 JSON/版本不支持；不会静默重置 | 停 dsh，恢复备份；不要直接覆盖/删除；无备份只能重新初始化（丢失账号/设备/审计） |
| `dsh plugin` 报 EACCES / 装错位置 | 用非 root 操作 root 的 profile；或未导出 `DSH_HOME` 导致装到 `/root/.dsh` | 用 `sudo env DSH_HOME=... PATH=... dsh ...`；核对 `$DSH_HOME/profiles/web/package.json`；装错则重新 add |
| 侧边栏没有「认证管理」 | 插件未加载/未重启/浏览器缓存；profile 没有 bundle 条目；client bundle 错误 | 检查 profile dependency/bundles、日志；重启 dsh；硬刷新；用 `?authgate-debug=1` 看面板调试卡 |

### 8.3 日志/端口/HTTPS 分类

| 检查 | 期望 | 异常处理 |
|---|---|---|
| `journalctl -u dsh \| grep 'auth-gate: listening'` | 有且地址为 LAN | 没有→看 failed to start；地址 loopback→改 `listenHost` |
| `ss -ltnp \| grep 3443` | 监听在 LAN 地址 | 无→启动失败；0.0.0.0→配置错误 |
| `curl -k https://.../__auth/login` | 200 | 连接拒绝→监听/防火墙；证书错误→SAN/证书链 |
| `curl -k https://.../__admin/api/setup/status` | 200 JSON | 404/403→插件未加载或路径错 |
| `curl -k -H admin .../__admin/api/state` | 200 | 403→key 错/监听 loopback/未带 header |
| `openssl s_client -connect ...:3443` | 有证书 | 失败→TLS 配置/端口 |

---

## 9. 安全模型

### 9.1 信任边界

```text
公网 ──> 认证网关（设备 cookie + 用户名密码）──> dsh（launch token / 内部会话）
              │
              └─ /__admin：会话 / adminKey / loopback（受 v0.6.1 限制）
```

- 未认证的浏览器**看不到 dsh 的 launch token，也拿不到 dsh 的会话 cookie**；网关在服务端用 `connection.authenticatedUrl()` 换 dsh cookie，注入上游请求并从响应剥离。
- 网关是 dsh 前面的第二道门，不是 dsh 自身鉴权的替代；能直连 3080 的人仍可看到 dsh 自己的入口，所以 3080 必须只对内网开放。
- 反代在改写 Origin 前先校验入站 Origin 必须等于网关自身 authority；WebSocket 同样，防止同站跨源页面借会话 cookie 让 dsh 误判同源。

### 9.2 设备绑定 = 第二因素

- 配对时必须验证 6 位 TOTP（登录会话通道；adminKey 通道由 bearer 凭据证明身份）；
- 配对成功后，设备 cookie/`deviceToken` 就是第二因素；登录只需密码；
- 这是刻意的产品取舍：方便，但**密码 + 已配对设备 = 可登录**；设备丢失/被他人拿到风险高，必须给设备设锁屏，丢失立即吊销。

### 9.3 `deviceToken` / 设备 cookie 等同账号凭据

- `POST /__auth/renew` **只接受 JSON body 的 `deviceToken`，不需要密码**，可直接换出新 session；
- 因此 `deviceToken`/`dsh_gate_device` 泄露 = 设备有效期内的持久访问（滑动 90 天、绝对上限 365 天，可反复 renew）；密码已知时还可直接登录；
- 泄露处置：立即在管理页吊销该设备；怀疑密码同时泄露时改密（会撤销全部设备/会话）；不要发到聊天/日志/工单；
- 网关不校验设备指纹；清 cookie、换浏览器、换设备都视为新设备，需重新配对。

### 9.4 会话即管理能力

- 任一有效 `dsh_gate_session` 可查看设备/会话/审计、吊销设备；
- 生成配对码还需 6 位 TOTP；改密/重置 TOTP 还需当前密码；网络设置需 TOTP；
- 会话 cookie 泄露应按管理凭据泄露处理：吊销设备/改密，必要时轮换 adminKey；
- CSRF：登录与管理页写操作要求 `x-auth-gate-csrf` + `dsh_gate_csrf` 双提交；adminKey 是 header bearer，免 CSRF（不会被跨站页面自动携带）。

### 9.5 秘密保管

| 秘密 | 位置 | 保管要求 |
|---|---|---|
| 管理员密码 | 仅内存/哈希在 `state.json`（scrypt） | 不要复用；至少 10 位；密码管理器 |
| TOTP secret | `state.json`（Base32） | 等同第二因素；不截图/不发聊天；重置会撤销全部设备 |
| `admin.key` | `$STATE_DIR/admin.key`（0600，64 hex） | root 级 bearer；不写 URL/日志；轮换后旧值立即失效 |
| `setup.token` | `$STATE_DIR/setup.token`（0600，仅未初始化） | 能读它可在初始化前抢先建管理员；初始化后确认删除 |
| `deviceToken` / 设备 cookie | App/浏览器本地 | 等同账号凭据；泄露立即吊销设备 |
| session cookie | 浏览器 | 等同管理能力；不要暴露给第三方页面/日志 |
| `state.json` / 备份 | `$STATE_DIR` | 含 TOTP/密码哈希/token 哈希；加密备份，限制权限 |

日志脱敏：密码、TOTP secret、票据、设备/会话 token、launch token 都不打印；adminKey 只打印掩码 + 路径；唯一例外是未初始化时的那条 `setup required` 完整初始化链接，初始化后不再出现。请限制 journald 读取权限（`journalctl` 组/root）。

### 9.6 TLS 与指纹 pinning

- 生产必须 TLS；HSTS 由网关设置（`Strict-Transport-Security`）；
- App 对网关 origin 做 **fail-closed** 证书指纹 pinning：二维码 `fp=` 与它看到的 leaf 证书 SHA-256 必须一致，否则拒绝；这比系统 CA 校验更严格，因此代理终止 TLS 时必须设 `publicFingerprint`；
- 浏览器仍按系统 CA/SAN 校验；自签证书需要例外或把 CA 装入系统；
- 证书续期/更换后：新二维码必须重生成；代理场景重新读取 `publicFingerprint`；已配对设备不需要重配（pinning 只在配对时）；
- `upstreamInsecureTls: true` 只用于本机/内网自签 dsh；dsh 换受信证书后改回 false。

### 9.7 限流、审计与已知限制

- 登录锁定（IP+用户名）、配对/续期 30/min、QR 10/min、会话 TOTP/当前密码 5 次/5 分钟、setup 10/5 分钟；429 带 `Retry-After`；
- 审计最近 500 条（API/页面 100 条），只记粗粒度原因/IP/设备；
- 单用户、无 WebAuthn、无设备指纹；设备 cookie 清掉即新设备；
- 密码 scrypt（N=16384, r=8, p=1）；票据/设备/会话 token 32 字节随机 base64url，只存 SHA-256；比较常数时间；
- 网关限流按 IP；frp/Caddy 会让源 IP 变成代理地址，限流共享（登录仍需设备+密码，管理写仍受 TOTP/当前密码/CSRF 保护）；
- 同一 `stateDir` 只允许一个网关进程；状态文件互斥是进程内的；
- 公网部署只暴露网关；不要直接把 3080 放公网，也不要把网关监听 loopback 后交给本机反代。

---

## 10. 测试与安装后自检

### 10.1 安装后自检命令

```bash
export DSH_HOME=/opt/deepseekharness/config/dsh
export GATE_URL=https://172.16.180.14:3443
export STATE_DIR="$DSH_HOME/auth-gate"
export ADMIN=$(sudo cat "$STATE_DIR/admin.key")

# 1) 服务与端口
sudo systemctl is-active dsh
sudo ss -ltnp | grep -E ':3443|:3080'

# 2) 页面/接口状态码
curl -sk -o /dev/null -w 'login=%{http_code}\n' "$GATE_URL/__auth/login"                    # 200
curl -sk -o /dev/null -w 'root=%{http_code}\n' "$GATE_URL/"                                  # 401（curl 默认 Accept */*）
curl -sk -o /dev/null -w 'root_html=%{http_code} %{redirect_url}\n' -H 'Accept: text/html' "$GATE_URL/"  # 302 -> login
curl -sk "$GATE_URL/__auth/whoami"; echo                                                     # {"authenticated":false}
curl -sk "$GATE_URL/__admin/api/setup/status"; echo                                          # configured true/false

# 3) 管理 API（adminKey）
curl -sk -o /dev/null -w 'network_no_key=%{http_code}\n' "$GATE_URL/__admin/api/network"     # 403
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$GATE_URL/__admin/api/network" \
  | jq '.network | {listenHost,listenPort,publicUrl,tlsConfigured,source,publicFingerprint,effectiveFingerprint}'
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$GATE_URL/__admin/api/state" \
  | jq '{configured,user,devices:(.devices|length),sessions,network:(.network|{source,listenHost,listenPort,publicUrl})}'

# 4) 文件权限
stat -c '%a %U:%G %n' "$STATE_DIR" "$STATE_DIR"/*

# 5) 启动日志
sudo journalctl -u dsh -n 200 --no-pager | grep -E 'auth-gate|failed to start|setup required'

# 6) TLS 证书 SAN / 指纹
openssl x509 -in /opt/deepseekharness/config/tls/dsh.crt.pem -noout -subject -ext subjectAltName
openssl x509 -in /opt/deepseekharness/config/tls/dsh.crt.pem -outform DER \
  | openssl dgst -sha256 -r | awk '{print $1}'

# 7) 3080 暴露检查（应只看到内网规则/无 public port）
sudo firewall-cmd --list-all | sed -n '1,40p'
```

> `curl -k` 仅用于自签/内网证书；如果网关或代理使用受信证书，请去掉 `-k`，让 curl 真正校验证书链。

期望：

- `login=200`；`root=401`；`root_html=302`；`whoami` 为 `{"authenticated":false}`（无 cookie）；
- `setup/status` 是合法 JSON，`configured` 与实例状态一致；
- `network_no_key=403`；带 key 的 `network`/`state` 200；
- 状态目录 `700`，文件 `600`；
- 日志有 `listening on https://<LAN>:<port>`，无 `failed to start`；
- `firewall-cmd --list-all` 中 3080 不在 public `ports`，只有内网 rich rule。

### 10.2 登录与配对的手工验收

在浏览器中：

1. 打开 `$GATE_URL`，应 302 到登录页；输入用户名 + 密码（已配对浏览器）登录；
2. 打开 `/__admin`，检查账号/配对/设备/会话/设置/审计区块；
3. 生成「浏览器」配对码，在另一个浏览器打开链接，确认设备列表新增；登录成功；
4. 手机 App 扫码，确认 `fp` 匹配、配对成功、登录成功、renew 可用；
5. 在管理页吊销一台设备，确认其会话/续期立即失效；
6. 修改密码或重置 TOTP，确认全部设备/会话被撤销、需要重新配对；
7. 设置 tab 保存一次 `publicUrl`（会话通道需 TOTP），确认二维码使用新地址；改监听端口时确认连接短暂中断、旧端口关闭/新端口可用（如果具备条件）；
8. 从 3080 打开的 dsh 页面里点侧边栏「认证管理」，应看到「不是认证网关」说明卡，而不是登录页/管理页；
9. 通过 frp/Caddy 访问时，确认页面不黑屏、Console 无 403/MIME 错误；对比二维码 `fp` 与代理证书指纹；
10. 硬刷新后侧边栏「认证管理」正常。

### 10.3 开发/回归测试（可选，在插件目录）

```bash
cd "$PLUGIN_DIR"

# 单测（v0.7.3 基线 167/167）
npm test

# 独立网关 E2E（1~2 分钟；会启动临时 dsh/网关，使用独立 DSH_HOME/stateDir）
bash tests/e2e-standalone.sh
```

E2E 说明：

- 默认会尝试从 journal 取 launch URL；取不到时用临时 `DSH_HOME` 在 `127.0.0.1:3099` 启动临时 dsh，网关测试端口为 `3456`/`3458`/`3459`，不影响生产的 3080/3443；
- 需要本机有非 loopback IP（默认取 `hostname -I` 第一个非 127 地址，可用 `E2E_SOURCE_IP` 覆盖）；
- `E2E_KEEP=1` 保留 `.test-tmp/`、`.test-dsh-home/` 便于排障，但临时 dsh 日志含 launch token，排查完立即删除；
- 该脚本会修改测试目录、启动临时进程，生产环境按变更窗口执行；本文档未在生产上执行它。

### 10.4 本文档的验证状态

已实测（2026-10，生产实例只读检查）：

- `npm test` → **167/167 pass**（v0.7.3；含 `tests/client-device-id.test.js` 9 项与 P2 加固新增的 4 项：非法 `clientDeviceId` 不降级、替换清空待用票据、重复非空 `clientDeviceId` 拒绝启动、`maxDevices` 1/100 边界）；`bash tests/e2e-standalone.sh` → **E2E PASSED（29 步 / 39 PASS）**（本轮已实际运行：第 26 步注入时钟的滑动/绝对上限 + v0.7.1 P2-1/P2-3 场景；第 27 步真实网关的 cookie 缓存头与 public asset 不重发 cookie；第 28 步同一 `clientDeviceId` 重配 → 设备记录数不变、旧 token 401、新 token 200、非法 ID 400 且审计为 `pair_redeem`、管理 API 不暴露 ID；第 29 步并发旧 token renew 与同 ID 重配交错后旧 session 为 0）；
- `GET /__auth/whoami` → `{"authenticated":false}`；
- `GET /__admin/api/setup/status` → `{"configured":true,"hasToken":false,...}`；
- `GET /`（默认 Accept）→ 401；`Accept: text/html` → 302；
- `GET /__auth/login` → 200；
- 无 key 的 `GET /__admin/api/network` → 403；带 adminKey → 200，返回 `{network:{...},rules:{...}}`；
- `GET /__admin/api/state`（adminKey）→ 200；
- `GET /__admin/api/admin-key`（adminKey，从 LAN）→ 403；
- openssl 自签证书命令在临时目录生成/校验通过；
- 生产日志存在 `auth-gate: listening on https://172.16.180.14:3443 (...)`。

未实测（不要当成已执行）：

- `dsh plugin add/remove`（生产已安装；未重新执行以免改变 profile）；
- `systemctl restart dsh`（会影响正在使用的生产会话；文档编写期间未重启）；
- 首次初始化向导 / `bootstrap` / `/__admin/api/qr`（生产已初始化，执行会改变账号/审计）；
- frp/Caddy 拓扑与证书续期（本机没有可复现的公网 VPS/Caddy 链路）；
- 真实浏览器中的配对、侧边栏面板、黑屏修复与移动端扫码（需真机/浏览器人工验收）；
- 生产实例上的 v0.7.0/v0.7.1 行为（滑动刷新/双 cookie/吊销级联、P2-1 响应头、P2-3 读路径绝对上限）未验证：本轮未重启生产 dsh；`renew`/登录的成功路径、旧会话迁移与旧设备清理需重启后按 §10.1 抽查。

### 10.5 版本要点

- v0.4.0：TOTP 从登录移到配对；登录只看已配对设备 + 用户名密码；
- v0.5.0：WebUI 首次初始化向导（setup.token，一次链接；自动配对当前浏览器）；
- v0.6.0：管理页网络设置；`publicUrl` 影响二维码；监听热重建；设备 origin 变化返回 `origin_changed`；
- v0.7.3：`maxDevices` 默认 8 → 100；`POST /__auth/pair/redeem` 接受可选 `clientDeviceId`（8–64 位 `[A-Za-z0-9._-]`），同一未过期 ID 原地复用设备：轮换 token、删除旧 session、重置绝对上限窗口、不占新名额；缺失仍每次新建，非法 400 `invalid_client_device_id`；
- v0.7.1：P2 安全修复（无新功能）——带会话/设备 cookie 的响应统一 `private, no-store` + `Vary: cookie`，public asset 不刷新会话/不重发 cookie；`extendDevice`/设备读取不再返回 `tokenHash`；设备绝对上限在**所有读路径**生效，越限设备及其全部 session 立即删除（旧 state / 调低 `deviceAbsoluteTtlDays` 无需等到下一次 renew/登录）；单测 147→151、e2e 26→27 步；
- v0.7.0：设备/会话改为「滑动窗口 + 绝对上限」（48h/30d 会话、90d/365d 设备，均可在配置里关掉绝对上限）；`renew`/登录重发设备 cookie 并返回 `deviceExpiresAt`；会话刷新重发 `dsh_gate_session`；吊销设备级联删除其全部 session 与待用 ticket，过期 prune 同时删 session；
- v0.6.1：安全修复（P0）：拒绝 loopback 监听、loopback 管理通道在监听 loopback 时禁用、热重建先绑新后关旧、`network.json` 损坏回退；
- v0.6.2：`publicFingerprint`（外部/代理证书指纹），frp + Caddy TLS 终止场景；`auto` 自动读取；证书续期需重读。

---

## 11. 附录

### 11.1 变量与占位符

| 占位符 | 含义 | 示例 |
|---|---|---|
| `$DSH_HOME` | dsh 数据根 | `/opt/deepseekharness/config/dsh` |
| `$PLUGIN_DIR` | 插件源码目录 | `/opt/ai_code/mobile-apk/dsh-auth-gate` |
| `$STATE_DIR` | 网关状态目录 | `$DSH_HOME/auth-gate` |
| `$GATE_URL` | 网关外部地址（publicUrl） | `https://172.16.180.14:3443` |
| `172.16.180.14` | 本机内网地址（示意） | 按实际替换 |
| `203.0.113.10` | 公网中转 IP（TEST-NET-3，占位） | 按实际替换 |
| `auth.example.com` | 公网域名（占位） | 按实际替换 |
| `<64位hex>` | 64 位小写十六进制 | `openssl rand -hex 32` / 证书指纹 |
| `<至少10位的强密码>` | 管理员密码 | 用密码管理器生成，≥10 位 |
| `<FRP_TOKEN>` | frp 认证 token | 不要用示例值 |

### 11.2 文件与路径速查

```text
$DSH_HOME/profiles/web/package.json          # dependencies + dsh.profile.bundles
$DSH_HOME/profiles/web/cordis.patch.yml      # profile 覆盖配置
$PLUGIN_DIR/package.json                     # dsh.bundle.patch / dsh.client
$PLUGIN_DIR/cordis.patch.yml                 # 插件默认配置
$STATE_DIR/state.json                        # 用户/设备/会话/审计（0600）
$STATE_DIR/admin.key                         # 管理密钥（0600）
$STATE_DIR/setup.token                       # 未初始化时的一次性 token（0600）
$STATE_DIR/network.json                      # 运行时网络覆盖（0600）
/opt/deepseekharness/config/tls/dsh.crt.pem  # 本机 TLS 证书（示例）
/opt/deepseekharness/config/tls/dsh.key.pem  # 本机 TLS 私钥（示例，0600）
```

### 11.3 错误码速查

| 错误码 | HTTP | 场景 |
|---|---|---|
| `not_configured` | 401 | 未初始化时登录 |
| `device_required` | 401 | 无/过期/吊销设备；renew 缺 deviceToken |
| `origin_changed` | 401 | 设备 origin 与当前 publicUrl 不符 |
| `invalid_credentials` | 401 | 用户名/密码错 |
| `rate_limited` | 429 | 登录/配对/QR/会话 TOTP 限流 |
| `authentication_required` | 401 | 未登录访问非 HTML 受保护路径 |
| `forbidden_origin` | 403 | Origin 与 Host 不一致（代理改写 Host） |
| `csrf_invalid` | 403 | 会话/loopback POST 缺 CSRF |
| `totp_required` / `totp_invalid` | 403 | 会话通道配对/网络设置 TOTP |
| `invalid_current_password` | 403 | 会话通道改密/重置 TOTP |
| `invalid_ticket` / `expired_ticket` | 401 | 配对票据非法/过期 |
| `device_limit` | 401 | 活跃设备达到上限（带同 `clientDeviceId` 的替换不受限） |
| `invalid_client_device_id` | 400 | `clientDeviceId` 格式非法（缺失则按新建处理） |
| `already_configured` | 409 | 初始化后调 setup/bootstrap |
| `invalid_listen_host` | 400 | 通配/loopback/非 IP/带括号 |
| `invalid_listen_port` | 400 | 端口越界/等于上游端口 |
| `invalid_public_url` | 400 | 非根路径/查询/凭据/协议与 TLS 不符 |
| `invalid_public_fingerprint` | 400 | 非空、非 64 hex、或配置里写 auto |
| `rebind_failed` | 400 | 热重建绑定/持久化失败 |
| `fingerprint_fetch_failed` | 400 | `auto` 探测失败，未落盘 |
| `no_changes` | 400 | 网络设置没提交任何字段 |
| `network_persist_failed` | 500 | 网络设置持久化失败（非预期） |
| `weak_password` / `invalid_username` | 400 | 密码/用户名不符合规则 |
| `no_user` | 400/409 | 未初始化时改密/生成 QR |

### 11.4 常用命令速查

```bash
# 安装
cd "$PLUGIN_DIR" && sudo npm install --no-audit --no-fund
sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" dsh plugin --profile web add link:"$PLUGIN_DIR"
sudo systemctl restart dsh

# 日志
sudo journalctl -u dsh -n 200 --no-pager | grep -E 'auth-gate|setup required|admin key'
sudo journalctl -u dsh -f | grep --line-buffered auth-gate

# 初始化
sudo journalctl -u dsh -n 200 --no-pager | grep 'setup required'
sudo cat "$STATE_DIR/setup.token"
ADMIN=$(sudo cat "$STATE_DIR/admin.key")

# 健康检查
curl -sk -o /dev/null -w '%{http_code}\n' "$GATE_URL/__auth/login"
curl -sk "$GATE_URL/__auth/whoami"
curl -sk "$GATE_URL/__admin/api/setup/status"
curl -sk -H "x-auth-gate-admin-key: $ADMIN" "$GATE_URL/__admin/api/network" | jq

# 备份（若自定义 stateDir，改成实际路径）
sudo systemctl stop dsh
sudo tar -C "$(dirname "${STATE_DIR:?}")" -czpf "/root/auth-gate-$(date +%F-%H%M).tgz" "$(basename "${STATE_DIR:?}")"
sudo systemctl start dsh

# 卸载
sudo env DSH_HOME="$DSH_HOME" PATH="$PATH" dsh plugin --profile web remove dsh-pairing-gate
sudo systemctl restart dsh
```

### 11.5 相关文档

- 插件仓库：<https://github.com/chjy090/dsh-pairing-gate>（旧链接 301）；版本与发行说明见 [Releases](https://github.com/chjy090/dsh-pairing-gate/releases)
- 插件 README（功能、API、设计细节、变更记录）：[`../README.md`](../README.md)
- README 的「安装」章节摘要：[`../README.md`](../README.md)
- 网络设置/ frp 细节：README 的「网络设置 / frp 内网穿透」章节
- 移动端扫码/指纹语义：见 DSH Mobile 仓库/文档（插件侧只定义 `#v=1&t=<ticket>&fp=<sha256>&n=<hostname>`）

---

**最后提醒**：生产变更前先备份 `$STATE_DIR`；任何时候不要删除 `state.json` 来“修复”登录问题；不要把 `admin.key`、TOTP secret、`setup.token`、`deviceToken` 发到聊天或日志。遇到 `forbidden_origin`/黑屏，优先检查反向代理是否保留了浏览器原始 `Host`。
