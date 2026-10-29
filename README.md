# dsh-pairing-gate

> **包名说明**：npm 包名为 `dsh-pairing-gate`（本地目录名仍为 `dsh-auth-gate`）。原名 `dsh-auth-gate` 已被 [TecFancy/dsh-auth-gate](https://github.com/TecFancy/dsh-auth-gate) 占用，两者功能不同：本插件是**扫码设备配对 + 公网反代 + 管理面板/初始化向导**，后者是密码/共享令牌登录 + 用户管理 CLI。旧仓库链接会 301 跳转到 <https://github.com/chjy090/dsh-pairing-gate>；改名版本的迁移步骤见「从旧名 `dsh-auth-gate` 迁移」与「版本与更新」。

DeepSeek Harness（dsh）的前台认证网关插件：**TOTP 授权的扫码设备配对 + 用户名密码登录**，认证通过后把请求反代到 dsh（含 WebSocket）。

> **路径约定**：下文所有 `$DSH_HOME/auth-gate/...` 都是 dsh 状态目录下的路径；**未设置 `DSH_HOME` 时 `stateDir` 回退到 `~/.dsh/auth-gate`**（没有 `DSH_HOME` 也能直接启动，`admin.key`/`state.json`/`setup.token`/`network.json` 都在该目录）。

## 快速开始

仓库默认配置是**可移植的本机 HTTP 默认值**，新机器装完即可启动，不依赖 TLS 证书或本机部署地址。

1. **安装**（`$PLUGIN_DIR` 是插件目录；`dsh plugin add` 会自动注入 `auth-gate`，不要重复写 `insert:`），然后重启 dsh：

   ```bash
   cd $PLUGIN_DIR && npm install --no-audit --no-fund   # 首次安装 qrcode 依赖
   dsh plugin --profile web add link:$PLUGIN_DIR        # 也可以是一个 git URL
   systemctl restart dsh
   ```

2. **首次初始化**：启动日志会打印一次性链接（未初始化时才有，`journalctl -u dsh -n 200 --no-pager | grep 'setup required'`）

   ```text
   auth-gate: setup required — open http://127.0.0.1:3443/__admin#setup=<token>
   ```

   也可以从 `$DSH_HOME/auth-gate/setup.token` 读取 token（未设置 `DSH_HOME` 时默认在 `~/.dsh/auth-gate/setup.token`）。在**本机浏览器**打开该链接（`http://127.0.0.1:3443/__admin#setup=<token>`），按向导创建管理员并绑定 TOTP，完成后当前浏览器即被配对。

3. **默认只在本机明文 HTTP 上监听**：`127.0.0.1:3443`，反代本机 dsh `http://127.0.0.1:3080`。适合本机试用，**不要**直接暴露到公网。

4. **跨机 / 公网 / App 配对需要 TLS**（App 扫码只接受 https 配对 URL）。**两种拓扑下网关自身都必须配置 `tlsCert`/`tlsKey`**——配置校验是「配了 TLS ⇒ `publicUrl` 必须 `https:`；没配 TLS ⇒ `publicUrl` 必须 `http:`」（`lib/config.js`）：
   - 网关自己终止 TLS：把 `listenHost` 改为本机 LAN 地址，配置 `tlsCert`/`tlsKey`（自签即可），并设置 `publicUrl: https://<实际访问的主机>[:端口]`；
   - 或在前面用 Caddy/Nginx 终止**对外** TLS：网关仍要配置 `tlsCert`/`tlsKey`（自签即可），代理以 **HTTPS 回源**到网关（`tls_insecure_skip_verify` 或信任网关 CA）；`publicUrl` 写代理对外的 https 地址，代理证书与网关证书不同时再把代理证书指纹填进 `publicFingerprint`；
   - **不支持**「代理终止 TLS + 明文 HTTP 回源 + 网关不配证书」：这样网关的 `publicUrl` 只能是 http，App 无法用 HTTPS + 指纹配对。

5. **改配置的位置**是 profile `cordis.patch.yml` 里按 `id: auth-gate` 的 override。Cordis 对 `config` 是**整体替换**，必须写全所有字段（可复制 [`config.example.json`](config.example.json) 修改）；不要直接改插件包内的 `cordis.patch.yml`，升级会覆盖。

> ⚠️ **默认配置只适合本机试用**。生产 / 跨机访问 / App 扫码配对**必须先改配置**：在 profile 的 `- id: auth-gate` override 里配置 LAN `listenHost`、`tlsCert`/`tlsKey` 与 `https://` 的 `publicUrl`（用 Caddy/Nginx 终止对外 TLS 时，网关自身仍要证书、代理须 HTTPS 回源）。详见上方「快速开始」第 3–5 条与 [`docs/installation.md`](docs/installation.md) §2.2.2。

## 配套仓库

| 仓库 | 说明 |
| --- | --- |
| [dsh-pairing-gate](https://github.com/chjy090/dsh-pairing-gate) | 本插件：dsh 服务端设备配对网关（扫码配对 / 会话 / TOTP / 反代） |
| [DSH-Mobile](https://github.com/chjy090/DSH-Mobile) | Android 客户端：扫码配对、设备令牌自动续期；APK 与更新见 [Releases](https://github.com/chjy090/DSH-Mobile/releases) |

目标部署是「单人自用」的**设备绑定即第二因素**认证模型：

1. 新设备先在管理页输入 **6 位 TOTP** 生成一次性配对二维码，扫码/打开链接完成绑定（`dsh_gate_device` cookie，默认 90 天）；
2. 之后这台设备只需 **用户名 + 密码** 登录，不再填写 TOTP；
3. 改密码 / 重置 TOTP 仍要求**当前密码**（凭证变更的二次确认），重置/改密会撤销全部设备与会话，所有设备重新配对。

全新部署的首次初始化可以完全在浏览器完成：网关启动日志给出一次性初始化链接，打开后按向导创建管理员、绑定 TOTP，并**自动把当前浏览器配对为可信设备**，随后直接用户名 + 密码登录。adminKey/curl 仅保留为自动化或应急通道（见「首次初始化」）。

管理页（服务端 `/__admin` 与原生侧边栏「设置」tab）可以修改**监听地址/端口**、**对外访问地址 `publicUrl`** 与**对外证书指纹 `publicFingerprint`**。`publicUrl` 用于生成配对二维码/链接，可以填 frp 中转后的公网 IP/域名；改监听地址会**即时重建监听**（无需重启 dsh），失败自动回滚；`publicFingerprint` 留空时使用网关自身证书，前置代理终止 TLS 时填代理证书指纹（App 按二维码里的 `fp=` 做 fail-closed pinning）。详见「网络设置 / frp 内网穿透」。

**滑动会话与绝对上限**：设备令牌与登录会话都采用「滑动窗口 + 绝对上限」。App 每次 `POST /__auth/renew` 成功或密码登录成功，都会把设备有效期推进到 `min(now + deviceTtlDays, 配对时间 + deviceAbsoluteTtlDays)` 并重发设备 cookie；Web 会话每次已认证的 HTTP 请求在满足刷新条件时把 `expiresAt` 推进到 `min(now + sessionTtlHours, 创建时间 + sessionAbsoluteTtlDays)`，并重发 `dsh_gate_session`（同一 token，新的 `Max-Age`）。默认 `sessionTtlHours: 48`（空闲窗口）、`sessionAbsoluteTtlDays: 30`、`deviceTtlDays: 90`、`deviceAbsoluteTtlDays: 365`（0 = 无绝对上限）。**吊销设备会级联删除该设备的全部会话并清空待用配对票据**，旧 deviceToken、所有 session cookie 与设备 cookie 在下一次 HTTP 请求立即失效（已建立的 WebSocket 隧道不会因此立即断开，需等连接自然关闭）。设备绝对上限在**所有读路径**立即生效（命中 `createdAt + deviceAbsoluteTtlDays <= now` 即删除设备及其全部 session），旧 `state.json` 设备或调低 `deviceAbsoluteTtlDays` 后也不会活到下一次 renew/登录；设备读取与 `extendDevice` 不返回 `tokenHash`。

**同一设备重复配对去重**：`POST /__auth/pair/redeem` 接受可选的 `clientDeviceId`（客户端生成的稳定安装 ID）。同一 ID 且旧记录未过期时原地复用 `device.id`、轮换 `deviceToken`（旧 token 立即失效）、删除该设备全部旧会话、把 `createdAt` 重置为本次配对时间（绝对上限重新起算）、清空全部其它待用配对票据，不新增设备也不触发 `device_limit`；响应带 `replaced` 并回显 `clientDeviceId`。浏览器配对不传该字段，行为不变。详见「配对与登录」第 6 条。

> **loopback 安全提示**：管理页/`network.json` 的监听地址**禁止 loopback**（`127.0.0.0/8`、`::1`）；当网关实际绑定 loopback 时（例如默认的本机试用配置），会**自动禁用「本机 loopback 即管理员」通道**（仅保留 adminKey 与会话），并在启动日志打印 WARN。这堵住了「网关监听 127.0.0.1 + frp/本机反代转发」时公网访客被当成本机管理员、直接读取 `/__admin/api/admin-key` 的路径。生产用 frp 时，frpc 的 `local_ip` 必须填网关绑定的同一 LAN 地址。详见「数据与安全」。

未认证的浏览器看不到 dsh 的 launch token，也拿不到 dsh 的会话 cookie。

```
手机 / 浏览器 ──HTTP/HTTPS(:3443)──> dsh-pairing-gate（本插件自带监听）
    │                             ├─ /__auth/*   登录页、CSRF、配对兑换、续期、登出
    │                             ├─ /__admin*   登录会话 / adminKey（loopback 监听时本机自动通道禁用）管理页与 API
    │                             └─ 其它路径 → 校验网关会话 → 反代 dsh（Host/Origin 改写、注入 dsh cookie、WS 隧道）
    └──扫码──> https://<publicUrl>/__auth/pair#v=1&t=<一次性票据>&fp=<证书 SHA256>
                                  dsh（默认 http://127.0.0.1:3080；生产按实际监听配置）
```

> 网关是 dsh 前面的**第二道门**，不是 dsh 自身的替代鉴权。网关默认 `upstream: http://127.0.0.1:3080`（本机部署即 dsh 自身）；能直连 dsh 3080 的人仍可看到 dsh 自己的登录入口，生产环境建议用防火墙把 3080 限制为 loopback/可信网段（本轮不改防火墙）。

## 功能

- 前台监听默认 `127.0.0.1:3443`（明文 HTTP、无 TLS），适合本机首装/试用；生产建议使用 LAN 地址 + TLS 1.2+/HSTS。
- 登录两要素：**已配对设备 cookie**（配对时由 6 位 TOTP 授权）+ 用户名密码（scrypt）。正常登录不填 TOTP；未配对设备固定返回 `device_required`。
- 扫码配对：管理页（登录会话通道）必须输入认证器当前的 **6 位 TOTP**；校验只验证、不消耗登录重放计数器，所以同一 30 秒窗口可连续生成多个二维码，实际签发仍按 IP 限 10 次/分钟。一次性票据默认 120 秒、服务端只存 SHA-256；二维码只把票据放在 **URL fragment**，不会发给服务器或日志。
- 设备管理：默认最多 100 台、默认 90 天；每台设备可单独吊销，吊销立即失效其会话；同一客户端可用 `clientDeviceId` 重复配对，仍只占一条记录。
- **WebUI 管理页**：登录后打开 `/__admin` 即可管理账号、生成配对二维码/链接、查看设备与会话、吊销设备、重置 TOTP、修改网络设置、查看审计（详见「WebUI 管理页」）。
- **网络设置**：管理页可修改监听地址/端口、对外地址 `publicUrl` 与对外证书指纹 `publicFingerprint`。`publicUrl` 立刻用于新的配对二维码/链接（frp 场景填中转公网 IP/域名）；`publicFingerprint` 留空表示使用网关自身 TLS 证书，填 64 位 SHA-256（或 POST `"auto"` 自动读取 publicUrl 的证书）后二维码 `fp=` 改用公网实际证书，App 可按代理证书 pinning；监听地址/端口采用**先绑新、后关旧**的热重建（先绑定成功再持久化，失败时旧监听全程可用）；管理页/`network.json` 只接受本机 LAN 地址（拒绝 loopback 与通配地址，loopback 仅用于 bundle 默认的本机首装）；覆盖值持久化到 `$DSH_HOME/auth-gate/network.json`（0600），重启后仍生效。
- **原生侧边栏管理面板**：dsh 左侧栏「全局面板」的「认证管理」入口改为 **React + dsh 设计系统** 原生面板（不再用 iframe）：顶部状态、配对二维码/倒计时/复制、改密、重置 TOTP、设备/会话表格、最近 100 条审计；20 秒轮询（页面隐藏时暂停）、CSRF 双提交、429 倒计时、未登录/会话失效跳转登录。从 3080 直连时只显示跳转 3443 的说明卡，不发 API 请求。
- 反代：HTTP(S) 与 WebSocket；Host/Origin 改写、入站 Cookie 删除、注入 dsh 会话 cookie、上游 `Set-Cookie` 剥离、上游 401 自动刷新 cookie 重试一次、Location 改写。
- 会话：空闲窗口 48 小时 + 绝对上限 30 天（滑动续期）；服务端只存 token 的 SHA-256；登出、吊销设备会撤销对应会话（吊销设备级联撤销该设备全部会话）；**改密/重置 TOTP 会撤销全部会话与全部已配对设备**（需重新扫码）。
- 限流：同一 IP+用户名 15 分钟内 5 次失败锁 15 分钟；配对/续期按 IP 30 次/分钟；QR 签发按 IP 10 次/分钟；会话通道的 `currentPassword`（改密/重置 TOTP）与配对 TOTP 校验各自按 IP 计数，5 次失败锁 5 分钟（成功一次即清零）。
- 审计：最近 500 条（管理 API 返回最近 100 条），只记录粗粒度原因，不写密码/TOTP/票据/设备 token。
- 状态文件 `0600`、原子写、互斥；损坏时拒绝启动而不是静默重置；管理密钥独立 `0600` 文件，首启生成，日志只输出掩码与文件路径（不打印完整密钥）。
- 中文登录页/管理页，服务端渲染，无外部静态资源。

## 包结构

```
dsh-auth-gate/              # 本地目录名保持不变；npm 包名为 dsh-pairing-gate
├── package.json
├── cordis.patch.yml      # 可移植默认配置（insert 行）
├── config.example.json   # 与默认值一致的可复制配置模板
├── lib/
│   ├── index.js          # Cordis 入口
│   ├── standalone.js     # 不依赖 dsh 的独立入口（开发/测试）
│   ├── gateway.js        # HTTPS/HTTP 服务、路由、反代、WS、热重建监听
│   ├── config.js         # 配置校验与 TLS 读取（network.json 覆盖 bundle config）
│   ├── network.js        # 网络覆盖校验、network.json 原子读写、热重建校验
│   ├── dsh-session.js    # authenticatedUrl → Set-Cookie 缓存/401 刷新
│   ├── store.js          # state.json、adminKey、设备/票据/会话/审计
│   ├── password.js       # scrypt
│   ├── totp.js / base32.js
│   ├── qr.js             # SVG/PNG、证书指纹、配对 URL
│   ├── ratelimit.js
│   ├── pages.js          # 服务端渲染中文页（/__admin 直连兜底，保留 ?embed=1 兼容）
│   └── client.js         # dsh Web GUI client half（原生 React 管理面板，无 iframe）
├── locales/zh.json
├── tests/                # node:test 单测 + e2e-standalone.sh
└── README.md
```

> 详细的安装与配置步骤见 [docs/installation.md](docs/installation.md)（前置要求、配置项、WebUI/adminKey 初始化、frp/Caddy、排障与安全模型）。

## 安装（详细步骤）

前提：默认配置反代 `http://127.0.0.1:3080`，不要求 dsh 已启用 TLS；网关自身默认监听 `127.0.0.1:3443` 明文 HTTP。如果现有 dsh 以原生 HTTPS（自签证书）运行，在 profile override 中把 `upstream` 改为 `https://<实际地址>:3080`，并按需设置 `upstreamInsecureTls: true`。

> 说明：下文的 `$PLUGIN_DIR` 表示插件目录（monorepo 中为 `<仓库根>/dsh-auth-gate`，独立 clone 的仓库中为仓库根目录）。**目录名保持 `dsh-auth-gate` 不变，只是包名改为 `dsh-pairing-gate`**，以兼容已有的 profile link 与脚本。

1. 在插件目录安装依赖（`qrcode`）：

   ```bash
   cd $PLUGIN_DIR
   npm install --no-audit --no-fund
   ```

2. 以 link 方式安装到 `web` profile：

   ```bash
   dsh plugin --profile web add link:$PLUGIN_DIR
   ```

3. **配置覆盖（生产/自定义时）**：`dsh plugin add` 已通过插件的 bundle patch 自动注入 `auth-gate`（默认配置见 `cordis.patch.yml`），**不要**再追加同 id 的 `- insert:`（会产生重复条目）。需要改监听地址/端口/上游/TLS 时，在 `$DSH_HOME/profiles/web/cordis.patch.yml` 里用 **id-targeted 覆盖**（不加 `insert:`）。注意 Cordis 对 `config` 是**整体替换**，以下字段必须写全（可复制 [`config.example.json`](config.example.json) 后修改）：

   ```yaml
   - id: auth-gate
     name: 'dsh-pairing-gate'
     config:
       # 整体替换，不是深合并：不要只写要改的字段。
       listenHost: 192.0.2.10            # 示例：本机 LAN 地址（生产必须替换）
       listenPort: 3443
       upstream: http://127.0.0.1:3080   # dsh 为自签 HTTPS 时改 https://... 并设 upstreamInsecureTls: true
       upstreamInsecureTls: false
       publicUrl: https://192.0.2.10:3443
       tlsCert: /etc/dsh/tls/dsh.crt.pem
       tlsKey: /etc/dsh/tls/dsh.key.pem
       stateDir: $DSH_HOME/auth-gate
       adminKeyFile: $DSH_HOME/auth-gate/admin.key
       sessionTtlHours: 48
       sessionAbsoluteTtlDays: 30
       deviceTtlDays: 90
       deviceAbsoluteTtlDays: 365
       maxDevices: 100
       pairTicketTtlSeconds: 120
       loginLock:
         maxFailures: 5
         windowMinutes: 15
         lockMinutes: 15
   ```

   > 只写 `config: { listenPort: 3444 }` 会让其它字段退回 `lib/config.js` 内置默认值（loopback、无 TLS），生产上会导致监听地址/证书意外变化。更多字段说明见 [docs/installation.md](docs/installation.md)。

4. 重启 dsh 让插件生效：

   ```bash
   systemctl restart dsh
   journalctl -u dsh -n 100 --no-pager | grep -E 'auth-gate|admin key'
   ```

   首次启动会生成 **64 位十六进制管理密钥** 并写入 `$DSH_HOME/auth-gate/admin.key`（0600；未设置 `DSH_HOME` 时为 `~/.dsh/auth-gate/admin.key`）；日志只打印掩码和路径，**不打印完整密钥**。请从该文件读取并保存到密码管理器；后续启动不再生成。

5. 防火墙：默认 loopback 监听不需要放行 3443；改为 LAN/TLS 生产入口后再放行（例如 `firewall-cmd --add-port=3443/tcp`），并尽量把 dsh 的 3080 限制为 loopback/可信网段。本轮未修改防火墙。

6. 查看启动日志里的初始化链接（未初始化时才会有）：`journalctl -u dsh -n 100 --no-pager | grep 'setup required'`，然后按下一节的 WebUI 向导完成首次初始化。已初始化的生产实例升级后不会出现该链接。

> 可直接在管理页修改 `listenHost`/端口与 `publicUrl`（即时生效、无需重启）；bundle config 只是可移植的首次部署默认值（loopback 明文 HTTP），生产入口必须通过 profile override 或 `network.json` 配置 LAN/TLS。换端口后记得同步防火墙与 frp 的 `local_port`。同一页面还可设置 `publicFingerprint`（详见「网络设置 / frp 内网穿透」）。

### 卸载

```bash
dsh plugin --profile web remove dsh-pairing-gate
# 从旧名升级的用户第一次迁移时先 remove dsh-auth-gate，见下一节
# 需要保留账号/设备时不要删除 $DSH_HOME/auth-gate；否则 rm -rf "$DSH_HOME/auth-gate"
systemctl restart dsh
```

### 从旧名 `dsh-auth-gate` 迁移

包名已改为 [dsh-pairing-gate](https://github.com/chjy090/dsh-pairing-gate)（本地目录名仍是 `dsh-auth-gate`）。已以旧名安装的用户按下面三步迁移，**`state.json`、账号、TOTP、已配对设备、会话与 `network.json` 都不受影响**：

```bash
# 1) 移除旧名（会同时移除 dependency 与 bundles 条目）
dsh plugin --profile web remove dsh-auth-gate

# 2) 用新包名重新 link（目录路径不变）；或安装 npm 包 dsh-pairing-gate
dsh plugin --profile web add link:/opt/ai_code/mobile-apk/dsh-auth-gate

# 3) 重启，让服务端插件与 client bundle 按新包名重新组合
systemctl restart dsh
```

迁移后 `$DSH_HOME/profiles/web/package.json` 的 dependency 键与 `dsh.profile.bundles` 都应为 `dsh-pairing-gate`（见 [docs/installation.md](docs/installation.md) 2.7.1）。若 profile 的 `cordis.patch.yml` 里还留着 `- id: auth-gate` 覆盖段，把其中的 `name:` 也改成 `dsh-pairing-gate`。

## 首次初始化（WebUI 向导）

全新部署（`stateDir` 里还没有用户）**不需要 SSH 或 curl**：启动网关后，从服务器日志取出一次性初始化链接，在浏览器里按向导完成「创建管理员 + 绑定 TOTP + 自动配对当前浏览器」，随后即可用用户名 + 密码登录。

网关首次启动（未初始化）会生成一次性初始化令牌 `$DSH_HOME/auth-gate/setup.token`（32 字节随机数，hex，0600），并打印**唯一一条**带完整令牌的日志：

```text
auth-gate: setup required — open <publicUrl>/__admin#setup=<64位hex>（默认本机 http://127.0.0.1:3443；也可从 $DSH_HOME/auth-gate/setup.token 读取）
```

### 步骤

1. **取初始化链接**（任选其一）：
   ```bash
   journalctl -u dsh -n 200 --no-pager | grep 'setup required'
   # 或：sudo cat "$DSH_HOME/auth-gate/setup.token" 后拼成 <publicUrl>/__admin#setup=<token>
   ```
   令牌只出现在这一行启动日志和 0600 文件中；日志/文件均按敏感信息保护（能读到的人可在初始化完成前抢先创建管理员）。
2. 在**最终要登录的那台浏览器**里打开完整链接。令牌位于 URL fragment（`#setup=`），不会发给服务器，也不会进访问日志。若只打开发送 `https://…/__admin`，页面会提示粘贴完整链接或令牌。
3. **创建管理员**：填写用户名（字母/数字/`.`/`_`/`-`，1–64 位）和至少 10 位密码，确认两次。页面调用 `POST /__admin/api/setup/begin`，校验令牌后返回**一次性 TOTP 二维码**与 Base32 密钥（只在本次响应/页面显示，服务器不落盘、不写日志，此刻还未创建用户，刷新不会留下半初始化状态）。
4. **绑定 TOTP**：用认证器（Aegis/1Password/Google Authenticator 等）扫码或手输密钥，输入当前 6 位动态验证码。页面调用 `POST /__admin/api/setup/confirm`，服务端原子完成：创建用户 → 标记 TOTP 已确认 → 创建名为「初始化浏览器」的 `web` 设备 → 下发 `dsh_gate_device` cookie（90 天）→ 删除 `setup.token`。
5. 自动跳转 `/__auth/login`，**只需用户名 + 密码**登录；当前浏览器已配对，不再需要扫码。

> 已初始化的实例升级后不会出现向导：`/__admin` 仍按原逻辑 302 到登录页。要看到向导必须全新部署（空 stateDir），或先完整卸载/清空 `$DSH_HOME/auth-gate`（会丢失账号与全部已配对设备，谨慎操作）。

### 令牌生命周期、重置与关闭

- **生成/复用**：未初始化时首次启动生成；之后每次重启复用同一令牌，直到初始化完成。
- **删除**：初始化成功后立即删除 `setup.token` 并清空内存值；即使进程在删除前崩溃，只要 `state.json` 已配置，下次启动也会删除残留文件且不再打印初始化链接。
- **轮换/找回**：用管理密钥调用（返回的 `setupUrl` 是唯一会回显完整令牌的 API，且仅在未初始化时可用；旧令牌与内存中的待确认草稿立即作废）：
  ```bash
  ADMIN=$(cat "$DSH_HOME/auth-gate/admin.key")
  curl -k -X POST https://192.0.2.10:3443/__admin/api/setup/token \
    -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' -d '{}'
  ```
- **关闭**：初始化完成后所有 setup 写接口（`begin/confirm/token`）一律 `409 already_configured`；`/__admin` 恢复原鉴权（未登录 HTML → 302 登录页）。
- **公开面**：未初始化时只有 `/__admin`（向导页）与 `/__admin/api/setup/status|begin|confirm` 公开；`user/qr/devices/state/audit` 等仍按原鉴权返回 401/403。
- **限流/来源**：`begin`、`confirm` 各按 IP 限 10 次 / 5 分钟（429 `rate_limited`）；浏览器带 `Origin` 时必须与当前网关 authority 同源，缺 `Origin` 的 curl 兼容放行。
- **审计**：成功写操作记 `admin_change`，detail 为 `setup_begin` / `setup_confirm` / `setup_token_rotated`；失败记 `admin_denied`（`setup_token_invalid` / `setup_totp_invalid` / `setup_*_rate_limited` / `*_bad_origin`）。审计、页面、日志均不含密码、令牌或 TOTP secret。
- **页面安全**：服务端渲染 + CSP nonce，`X-Frame-Options: DENY`、`frame-ancestors 'none'`、`Cache-Control: no-store`；不依赖 client bundle。

### 自动化 / 应急通道（adminKey，可选）

已有自动化脚本仍可用 adminKey 直接 bootstrap；它只创建用户、**不会自动配对浏览器**，需要再生成配对二维码并 redeem：

```bash
ADMIN=$(cat "$DSH_HOME/auth-gate/admin.key")
curl -k -X POST https://192.0.2.10:3443/__admin/api/bootstrap \
  -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"username":"admin","password":"至少十位的密码"}'
```

响应包含 `secretB32`、`otpauthUri`、`qrSvg`（TOTP secret 仅此一次）。随后可用 `POST /__admin/api/qr` 生成配对二维码，在浏览器打开链接或手机扫码完成设备绑定。管理密钥请从 `admin.key` 读取，避免写进 shell 历史。

> 不要使用默认口令：插件没有默认账号/密码；未初始化时密码登录返回 `not_configured`（此时请走 WebUI 向导）。

## WebUI 管理页

登录成功后直接打开：

```
https://192.0.2.10:3443/__admin
```

未登录的 HTML 访问会 `302` 到 `/__auth/login?next=/__admin`，登录后自动回到管理页（不是 403 死页）。

### 原生侧边栏管理面板

`dsh-pairing-gate` 同时是一个 dsh **client 插件**：`package.json` 通过 `exports["./client"]` 暴露 `lib/client.js`，并声明

```json
"dsh": {
  "client": {
    "platform": "web",
    "inject": ["@deepseek-ai/dsh-client-ui-layout", "@deepseek-ai/dsh-client-ui-sidebar"]
  }
}
```

dsh 启动时扫描 loader 条目，把 client bundle 组合进 `/plugins/...` 的启动清单。浏览器里它注册两个 slot：

- `sidebar.panellist`：左侧栏「全局面板」列表里的盾牌图标「认证管理」（与「插件」「定时任务」同一区域；窄栏显示图标 + tooltip，宽栏显示文字）。
- `main`（keyed slot，key = `auth-gate`）：点开面板后主内容区渲染原生 `AuthGatePage`。**不再加载 iframe**。

面板功能（对照 `/__admin` 服务端页）：

- **顶部状态**：用户名（或「本机通道」）、TOTP 绑定状态、当前访问 origin、刷新按钮、网关管理页外链。
- **配对**：平台（安卓 / 浏览器）、会话通道需输入 **6 位动态验证码**、生成/重新生成、QR（服务端 `qrSvg`，注入前校验）、有效期倒计时、复制链接。
- **账号**：修改密码（当前密码 + 新密码 + 确认）、重置 TOTP（内联二次确认）；成功后展示新 TOTP QR/secret **仅一次**，并提示重新登录。
- **设备**：名称/ID、平台标签、在线、当前设备、创建/最近活跃/到期、吊销（二次确认后 POST 并刷新）。
- **会话**：设备、创建/最近活跃/到期、当前会话标记。
- **设置**：只读展示 TLS 状态、生效来源（运行时覆盖/插件配置）、当前监听、publicUrl 与**二维码当前生效指纹**；修改监听地址、端口、对外访问地址（publicUrl）与对外证书指纹（`publicFingerprint`，含「从对外地址自动读取」按钮），会话通道需 6 位动态验证码 + 内联二次确认；保存成功 toast，监听重建时提示连接会短暂中断并需刷新；未设置指纹但对外主机与监听地址不同时显示 `fingerprintHint` 风险提示。
- **审计**：最近 100 条（时间/类型/IP/设备/详情），倒序，滚动容器 + 手动刷新。

渲染与交互：

- `lib/client.js` 是手写 dsh ModuleLoader 懒 CJS 包，只 `require("react")` 与
  `@deepseek-ai/dsh-client-ui-primitives`（dsh Web shell 的内置模块表项，官方 sidebar 也用它）；
  全部用 `React.createElement`，不使用 JSX。
- 实际使用 `Button`、`Input`、`SegmentedControl`、`SegmentedTabs`、`Tag`、`writeClipboard` 和若干 `Icon*`；
  若 primitives 不可用会退化为本地极简控件，侧边栏条目不会整体消失。
- 整个面板包在 `PanelErrorBoundary` 中：渲染异常不再把 React 树卸载成空白，而是显示
  「认证管理渲染失败」卡（`error.message` + 栈前 1500 字符）并打印 `[auth-gate] render failed`。
  每个 primitives 组件（含图标）单独 guard，单个设计系统组件抛错只退化该控件。
- 调试：地址加 `?authgate-debug=1`（或 hash `#authgate-debug`）会显示固定调试卡，含 `location.href/port`、
  `React.version`、primitives 是否加载 + 导出 key（最多 40 个）+ real/fallback 绑定，以及当前 phase/tab/渲染分支。
  正常访问不渲染调试卡。
- 布局/表格/卡片用 dsh 主题 token（`--dsw-alias-*`、`--dsw-font-*`、`--dsw-radius-*`、`--dsw-shadow-*`）自绘，
  不硬编码主题色，亮/暗主题跟随 dsh。
- 唯一 `dangerouslySetInnerHTML` 是服务端二维码 SVG；注入前校验 `<svg…</svg>` 信封并拒绝 `<script>`、
  `<foreignObject>`、`on*=`、`javascript:`。其余字符串全部走 React 文本（自动转义）。
- 密码只存在于组件 state 与请求 body，不写 console/localStorage；TOTP secret 只在一次性结果屏显示。

请求、CSRF 与降级：

- 挂载时**先请求公开的 `GET /__admin/api/setup/status`**：`configured:false` 时只渲染「网关尚未初始化」卡片（提示打开 `<gatewayOrigin>/__admin`，初始化链接在启动日志/`setup.token`），**不再请求 CSRF/whoami/state，也不显示登录 CTA**；`configured:true` 后才继续 `GET /__auth/csrf` → `GET /__auth/whoami`。所有请求 `credentials:"same-origin"`、`cache:"no-store"`，POST 带 `x-auth-gate-csrf`。`csrf_invalid` 只刷新一次 token 并重试一次。
- 未登录：先探测一次 `/__admin/api/state`；浏览器面板没有 adminKey，因此 loopback 监听时固定 403（显示「未登录 + 去登录」），
  `next` 为当前 `pathname+search`，整页跳 `/__auth/login`，**不循环重试**。网关监听 loopback 时本机自动管理通道禁用，面板固定显示「未登录 + 去登录」。
- 会话失效：401 或 403 `forbidden`/`not_configured` → 停止轮询并显示「会话已失效 + 重新登录」；
  403 `invalid_current_password` 只在表单内提示，不误判掉线。
- 429：读取 `retry-after` 显示剩余秒数并禁用操作；到期自动恢复。
- 20 秒轮询 `/__admin/api/state`；`document.visibilityState !== "visible"` 时暂停，回到可见立即补一次；
  卸载时清理 interval、倒计时、toast 与 `visibilitychange` 监听。
- 挂载时先探测同源 `GET /__admin/api/setup/status`：只要返回合法 JSON，就认为当前文档由网关提供，**不再硬性要求 `location.port === "3443"`**（因此 frp 中转域名/其他端口也能使用原生面板）；典型 3080 直连探测失败 → 只显示说明卡和「打开认证网关管理页」按钮，不发管理 API 请求。

兼容与生效：

- `/__admin`（含 `?embed=1`、nonce 内联脚本、`frame-ancestors 'self'`）**保留不动**，作为浏览器直连/旧版本兜底；
  未初始化时该路径改为公开的 WebUI 初始化向导（`DENY` 不可 frame），初始化完成后恢复 302/登录页行为；原生侧边栏不再使用它。
- **卸载/恢复**：卸载插件（或让 profile 不加载 `auth-gate` 行）并重启 dsh 后，侧边栏条目随 client bundle 一起消失，
  管理页仍可通过 `https://<host>:3443/__admin` 直接访问。
- **生效方式**：client half 在 dsh 启动时组合，新增/修改后需要重启 dsh（`systemctl restart dsh`）并硬刷新浏览器以丢弃旧 bundle 缓存；**不需要重新 `dsh plugin add`**。

> 仍建议把 3443 作为唯一入口：从 3080 直达 dsh 会绕过网关的登录与设备校验。

### 三种鉴权通道

| 通道 | 判定 | POST CSRF | 会话通道的二次验证 |
|---|---|---|---|
| `session`（WebUI 主路径） | 有效 `dsh_gate_session` cookie（设备已配对且会话未过期） | 必须（`x-auth-gate-csrf` 头 + `dsh_gate_csrf` cookie 双提交） | 生成配对码 / 修改网络设置：**6 位 TOTP**；改密/重置 TOTP：**当前密码** |
| `loopback` | TCP 对端是 `127.0.0.1/::1`，且 Host 属于本部署的 authority（防 DNS rebinding）。**仅当网关监听地址不是 loopback 时启用**；监听 loopback 时整条通道禁用 | 必须 | 可省略 |
| `key` | 请求头 `x-auth-gate-admin-key: <adminKey>`（bearer 凭据） | 免（header 凭据不会被跨站页面自动携带） | 可省略 |

三条通道任一满足即通过；三条都无法满足时才 403。**会话通道只解锁 `/__admin*`**：`/__auth/*` 与反代路径的鉴权规则完全没有放宽，反代和 WebSocket 仍然只认有效会话。未初始化是唯一例外：`/__admin`（向导页）与 `/__admin/api/setup/status|begin|confirm` 公开，其余管理 API 仍按上表鉴权；初始化完成后例外全部关闭。

### 服务端管理页功能（/__admin 直连）

- **账号**：修改密码（当前密码 + 新密码两次，至少 10 位）。改密会撤销**全部会话与全部已配对设备**；页面与响应都会提示「所有设备需重新扫码」。
- **配对**：选择「安卓设备 / 浏览器设备」并输入认证器当前的 **6 位动态验证码**（仅会话通道需要）后生成一次性配对二维码（SVG 内嵌，倒计时显示剩余秒数，过期提示重新生成）。动态验证码只用于这次配对授权，不会写进配对链接、页面 URL 或日志；页面不会把它回填到 HTML。同一 30 秒窗口可连续生成多个二维码（不消耗登录重放计数器）。二维码下方提供「复制配对链接」；**同一条链接在浏览器打开即可完成浏览器设备配对**。`platform` 只影响页面提示，ticket 逻辑不变（fragment、一次性、TTL）。
- **已配对设备**：平台标签（安卓 / 浏览器 / iOS）、设备名、状态（在线/离线 + 当前设备）、创建时间、最近活跃、到期时间；可单台吊销，吊销后该设备的会话与续期立即失效。在线 = 最近 120 秒内有设备或会话请求。
- **会话**：最多 100 条，显示设备、创建时间、最近活跃、到期时间、是否为当前会话；不展示 token。
- **TOTP**：顶部显示 TOTP 状态（**已配置 / 未配置**）。该徽标只反映账号是否已保存认证器密钥（`totpConfigured`，不回显 secret），不代表当前请求证明过持有认证器；任何通道配对成功都不会改变它，「重置 TOTP」后需按新二维码重新配置。「重置 TOTP」需要当前密码（会话通道），成功后直接显示新的绑定二维码 / Base32 secret / `otpauth://` URI，并按现有逻辑撤销全部设备与会话。
- **网络设置**：只读展示 TLS 状态、生效来源（override/config）、当前监听与 publicUrl；表单修改监听地址、监听端口和对外访问地址（publicUrl），会话通道需 6 位 TOTP + 内联二次确认；监听变更提示连接会短暂中断。字段/错误码与原生面板一致，`?embed=1` 下同样可用。
- **审计**：最近 100 条表格（时间、类型、IP、设备、详情），全部 HTML 转义；改密、TOTP 重置、设备吊销、生成配对码、网络设置变更都会写审计。

### CSRF、当前密码与限流

- 管理页所有写操作都走 `fetch` + `x-auth-gate-csrf` 头，并与 `dsh_gate_csrf` cookie 双提交；GET 页面/API 不要求 CSRF。
- 会话通道改密、重置 TOTP 必须再次输入**当前密码**；会话通道**生成配对码**必须输入**6 位 TOTP**。仅拿到会话 cookie（例如被劫持的浏览器）不足以轮换凭据，也不足以另配一台 90 天设备再续出新会话。adminKey 通道由 bearer 凭据证明身份，允许省略这两类校验（loopback 通道在网关监听 loopback 时禁用）。
- 会话通道的 `currentPassword` 与配对 TOTP 校验各自按 IP 计数：5 分钟内失败 5 次返回 429 `rate_limited` 并锁定 5 分钟，成功一次清零；QR 实际签发按 IP 限制 10 次/分钟。
- 配对 TOTP 校验**只验证不消费**登录重放计数器：同一 30 秒窗口可反复生成二维码，但真实签发仍受 10 次/分钟限制，且失败会进入独立的 TOTP 限流。
- 改密/重置 TOTP 是整信任面的重置：服务端清空全部设备与 session，返回 `{devicesRevoked, sessionsRevoked, rePairRequired:true}`。所有手机/浏览器必须重新扫码配对后再登录。当前管理页会显示提示并在改密后引导回登录页。

> **认证模型与风险**：TOTP 只在**设备配对**时验证，设备绑定成功后该设备上「密码正确即可登录」。因此：
> - **密码泄露 + 已配对设备** = 可直接登录（设备丢失或被他人拿到时尤其危险）。请给设备本身设置锁屏，设备丢失/转手时立即在管理页吊销该设备；怀疑密码泄露时改密（会撤销全部设备与会话，强制重新配对）。
> - **TOTP 泄露但设备未配对** = 仍不能登录，只可能被用来生成新的配对二维码（还需要一个有效管理会话或 adminKey）。发现 TOTP 异常时应重置 TOTP 并吊销设备。
> - **会话 cookie 泄露** ≈ 管理能力泄露（可看设备/会话/审计、吊销设备；生成配对码另需 TOTP，改密/重置 TOTP 另需当前密码）。设备吊销时也会清空所有待用配对票据。
> - **有效 session + 任一 TOTP 码** = 生成配对二维码 → 任意设备打开链接 / 扫码 `redeem` 得到 `deviceToken` → `POST /__auth/renew`（**只凭 body 里的 deviceToken，不需要密码**）换出新 session = **设备有效期内（默认滑动 90 天、绝对上限 365 天）的持久访问**。因此 session cookie 与 `deviceToken` 都视同账号凭据：泄露立即在管理台吊销该设备、必要时改密；不要把 TOTP 码、配对链接或 deviceToken 发到聊天或日志。
> - 已知取舍：配对后的第二个因素从「每次登录的 TOTP」变成「设备 cookie 本身」。网关不额外校验设备指纹；清 cookie、换浏览器都视为新设备，必须重新配对。

### adminKey 应急

忘记密码、TOTP 丢失或无法登录时，从服务器读取 `$DSH_HOME/auth-gate/admin.key`（0600），用命令行直接管理：

```bash
ADMIN=$(cat "$DSH_HOME/auth-gate/admin.key")
BASE=https://192.0.2.10:3443
curl -k -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/state"
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"resetTotp":true}' "$BASE/__admin/api/user"
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"password":"新的至少十位密码"}' "$BASE/__admin/api/user"
```

adminKey 是 bearer 凭据：不要写进 URL、日志或 shell 历史；轮换方式见「日常运维」。`/__admin/api/admin-key` 不再向 loopback 访客返回密钥（监听 loopback 时整条 loopback 通道禁用），请直接从 `$DSH_HOME/auth-gate/admin.key` 读取。

## 网络设置 / frp 内网穿透

`/__admin` 页面与原生侧边栏「认证管理 → 设置」tab 都可以修改：

- **监听地址/端口**（`listenHost` / `listenPort`）：网关实际绑定的本机网卡地址与端口；保存后**立即重建监听**，无需重启 dsh。
- **对外访问地址**（`publicUrl`）：只用于生成配对二维码/链接（以及 `setup.token` 链接等），必须是纯 origin；frp 场景填中转后的公网 IP/域名。二维码**不会**使用监听地址。
- **对外证书指纹**（`publicFingerprint`）：配对二维码 `fp=` 使用的证书 DER SHA-256。留空（默认）＝网关自身 TLS 证书；TLS 在 frp/反向代理（Caddy、nginx 等）处终止时填代理证书指纹，否则 App 会按网关自签证书 pinning 并拒绝连接。输入 64 位十六进制（大小写自动归一），或点「从对外地址自动读取」由服务端探测当前 `publicUrl` 的证书。**证书续期后必须重新读取/更新**。

### 优先级与持久化

配置优先级：`$DSH_HOME/auth-gate/network.json` > 插件 bundle config（`cordis.patch.yml`）> 内置默认值。

运行时覆盖保存在 `$DSH_HOME/auth-gate/network.json`（0600，原子写）：

```json
{
  "listenHost": "172.16.180.14",
  "listenPort": 3443,
  "publicUrl": "https://de12.de5.net:8443",
  "publicFingerprint": "70a78d74d75fc65a17685b11408b5337cb3f5c32f91346e8705043251a45aaac",
  "updatedAt": 1790000000000
}
```

`publicFingerprint` 为空时**不写入文件**（缺省与空串同义，均表示使用网关自身证书），因此旧的三字段 `network.json` 仍然兼容。

- 启动时若文件存在，覆盖 bundle config 中的这几个值（其它配置如 TLS/upstream/stateDir 不变），日志会标注 `[network.json override]`。
- 删除该文件并重启 dsh 即可回退到 bundle config；**不要**在网关运行时只删文件，否则内存值与重启后不一致。
- 文件损坏或写入非法值（如 loopback/通配监听地址、与 dsh 上游端口相同、`publicUrl` 带路径、协议与 TLS 状态不符、`publicFingerprint` 不是 64 位 hex 或是 `auto`）时，**不会静默失败**：启动日志会打印醒目错误与恢复指引（`rm -f $DSH_HOME/auth-gate/network.json` 后重启），并回退到 bundle config 继续启动（UI 显示 `source=config`）。修复/删除该文件前，运行时覆盖一直被忽略。
- 校验规则：监听地址必须是本机 LAN 网卡的具体 IPv4/IPv6 字面量；**禁止 loopback（`127.0.0.0/8`、`::1`、`::ffff:127.0.0.1`）**，返回 400 `listen_host_loopback_not_allowed`；禁止所有通配写法（`0.0.0.0`、`::`、`::0`、`0::0`、`00::`、`::ffff:0.0.0.0` 等，`server.address()` 也会二次校验），返回 400 `invalid_listen_host`；端口 1–65535 且不能等于 dsh 上游端口（当前 3080）；`publicUrl` 只能是 `http(s)://host[:port]`，不能带路径/查询/片段/凭据；TLS 已配置时必须 `https:`，未配置时必须 `http:`；`publicFingerprint` 只能是空串或 64 位十六进制 SHA-256（`auto` 仅 POST 时可用，且不会被持久化）。
- **为什么禁止 loopback**：网关的「loopback 即本机管理员」信任模型只能区分 TCP 对端地址。若网关监听 `127.0.0.1` 而 frpc（或本机 nginx）从 loopback 转发，所有公网访客在网关看来都是 `127.0.0.1`；frp TCP 访客还能自带 `Host: 127.0.0.1:3443`，从而免 TOTP/会话读取管理 API。网关的双重防护：① 网络设置/`network.json` 拒绝 loopback；② 即使有人手工把 bundle config 改成 loopback，启动后也会**自动禁用 loopback 管理通道**并打印 WARN，只保留 adminKey 与会话，`/__admin/api/admin-key` 不再对 loopback 返回密钥。

### 管理 API

```bash
ADMIN=$(cat "$DSH_HOME/auth-gate/admin.key")
BASE=https://203.0.113.10:23443

# 当前生效值 + TLS 状态 + 来源（config / override）+ 校验规则说明（不需要 TOTP）
curl -k -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/network"

# 只改 publicUrl（adminKey 通道免 TOTP；会立即用于之后生成的二维码/链接）
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicUrl":"https://203.0.113.10:23443"}' "$BASE/__admin/api/network"

# 设置固定的对外证书指纹（64 位 SHA-256；大小写自动归一；留空表示用网关自身证书）
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicFingerprint":"70a78d74d75fc65a17685b11408b5337cb3f5c32f91346e8705043251a45aaac"}' "$BASE/__admin/api/network"

# 自动读取当前已保存 publicUrl 的证书指纹（TLS 连接 5s 超时；失败 400 且不落盘）
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicFingerprint":"auto"}' "$BASE/__admin/api/network"

# 改监听端口（响应 {ok:true,network:{...},rebound:true}；旧端口连接会断开）
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"listenPort":3443}' "$BASE/__admin/api/network"
```

- 通过**登录会话**（WebUI）调用 `POST /__admin/api/network` 时必须带 6 位动态验证码（`totp`）：缺失 403 `totp_required`、错误 403 `totp_invalid`，失败 5 次锁 5 分钟（独立于配对 TOTP 的计数器）。adminKey 通道免 TOTP/CSRF；`loopback` 通道仅在网关监听非 loopback 地址时存在。
- 字段错误：400 `invalid_listen_host` / `invalid_listen_port` / `invalid_public_url` / `invalid_public_fingerprint`，响应带 `field` 与粗粒度 `reason`；重建失败 400 `rebind_failed`（`reason=address_in_use|address_not_available|permission_denied|listen_failed` 等），网关已回滚到旧地址；`"auto"` 探测失败 400 `fingerprint_fetch_failed`（`reason=not_https|timeout|connection_refused|dns_failed|unreachable|certificate_failed|…`），**不修改任何状态**。
- 自动探测只连接**当前提交/已保存的 `publicUrl`** 的主机与端口（默认 443），使用 `node:tls`，5 秒超时，`rejectUnauthorized:false`（自签代理也合法），读取 leaf 证书 DER 后算 SHA-256；不发送任何 HTTP 请求。调用方无法指定探测目标，因此不会变成任意地址的 SSRF/TLS 扫描器。
- 成功写审计 `admin_change` / `detail=network_update; listen=…; public=…; public_fp=<前 8 位或 self>; rebound=…; via=…`，不记录 TOTP；探测失败写 `admin_denied / fingerprint_fetch_failed`。
- `GET /__admin/api/network` 返回 `network:{listenHost,listenPort,publicUrl,tlsConfigured,source,publicFingerprint,effectiveFingerprint,fingerprintHint}`：`publicFingerprint` 是保存值（hex 或空），`effectiveFingerprint` 是实际用于 QR 的指纹（空覆盖时等于网关自身证书），`fingerprintHint` 是给 UI 的提示文案。`GET /__admin/api/state` 也带同一个 `network` 视图。

### 两种典型 frp 用法

#### ① TCP 转发（推荐；App 靠二维码里的证书指纹 pinning）

`frpc.ini` 示例（frpc 与网关同机）：

```ini
[dsh-gate]
type = tcp
local_ip = 172.16.180.14
local_port = 3443
remote_port = 23443
```

然后在管理页把 `publicUrl` 改成 `https://203.0.113.10:23443`（frps 公网 IP / 域名 + remote_port）。之后生成的配对二维码形如
`https://203.0.113.10:23443/__auth/pair#v=1&t=…&fp=…`，App 会先比对 `fp`（证书 DER SHA-256）再连接，因此**即使证书 SAN 不含中转 IP，App 仍可正常连接**。

- 浏览器直接访问 `https://203.0.113.10:23443` 时会因证书 SAN 不含该 IP 而告警：可手动接受例外（仅建议临时使用），或重签一张包含该 IP/域名的证书。
- **监听地址与 `local_ip` 都必须是同一个 LAN 网卡地址（如 `172.16.180.14`），绝不能写 `127.0.0.1`。** 网关的 `loopback` 管理通道按 TCP 对端地址判定：若 frpc 从 loopback 转发，所有公网访客都会被当成“本机管理员”，`/__admin` 及管理 API 将可被未登录访问。管理页/`network.json` 直接拒绝 loopback 监听；若通过 bundle config 手工设成 loopback，网关会禁用本机自动管理通道并 WARN，但仍建议立即改成 LAN 地址，因为 loopback 监听本身无法区分本机用户与代理转发。
- frpc 所在主机的地址会成为所有外部访客在网关侧看到的来源 IP，按 IP 的限流（登录/配对/QR）会被共享；登录本身仍需要已配对设备 + 密码，会话通道仍受 CSRF/TOTP/当前密码保护。
- 防火墙只需在 frps 放行 `remote_port`；网关的 3443 与 dsh 的 3080 保持私有。

#### ② frp HTTPS 自定义域名

**可用做法（TLS 直通）**：仍用 `type = tcp`，把域名 DNS 指向 frps（或 frps 的公网 IP），`remote_port` 映射到网关 3443，`publicUrl` 填 `https://dsh.example.com:23443`（若能把 remote_port 映射为 443，则可省略端口）。**证书 SAN 必须包含 `dsh.example.com`**，由网关自己终止 TLS；这样浏览器和 App 都正常。证书更换后二维码 `fp` 会变化，已配对 App 需要重新扫码。

**不支持的做法（frps 终止 TLS + 明文回源）**：`type = https` + `custom_domains` + `vhostHTTPSPort` 会在 frps 用 frps 的证书终止 TLS，再以明文 HTTP 转发给网关。当前版本的配置校验要求「网关没配 TLS ⇒ `publicUrl` 必须 http；配了 TLS ⇒ 必须 https」，而二维码又直接使用 `publicUrl`；同时前置代理会破坏 loopback 管理信任模型并让源 IP 全部变成代理地址。因此**不要**用 frps 终止 TLS + 明文回源的组合；请使用上面的 TLS 直通（TCP）方式，或下面的「反向代理终止 TLS + HTTPS 回源」（注意「HTTPS 回源」不等于网关可以不要证书：下面方案里网关仍配置自签 `tlsCert`/`tlsKey`，否则 https 的 `publicUrl` 会被配置校验直接拒绝）。

#### ③ frp + TLS 终止反向代理（Caddy / nginx）

典型拓扑：本机网关 `https://172.16.180.14:3443`（自签证书）→ frpc `localPort=3443 → remotePort=18080` → VPS frps 只监听 `127.0.0.1:18080` → VPS 上的 Caddy 用 **Let's Encrypt 有效证书**提供 `https://de12.de5.net:8443`，再以 HTTPS 反代到 `https://127.0.0.1:18080`（`tls_insecure_skip_verify`，因为回源的是网关自签证书）。公网用户看到的是 **Caddy 的证书**，网关自己的证书从不出现在公网，因此：

1. 管理页把 `publicUrl` 设为 `https://de12.de5.net:8443`；
2. 在「对外证书指纹」点 **「从对外地址自动读取」**（或 `POST {"publicFingerprint":"auto"}`）——服务端会连接 `de12.de5.net:8443`，读取 Caddy 的 leaf 证书并保存其 SHA-256（例：`70a78d74d75fc65a17685b11408b5337cb3f5c32f91346e8705043251a45aaac`，Certbot/ACME 证书）；
3. 之后生成的配对二维码为 `https://de12.de5.net:8443/__auth/pair#v=1&t=…&fp=<Caddy 证书 SHA-256>`：浏览器拿到有效证书可无告警，App 按 `publicFingerprint` pinning 也能正常配对；若留空，二维码仍带网关自签指纹，App 会 **fail-closed 拒绝**。

Caddy 片段示例（VPS）：

```caddyfile
de12.de5.net:8443 {
    tls admin@example.com
    reverse_proxy 127.0.0.1:18080 {
        # 关键：保留浏览器原始 Host（含 :8443 端口）。Caddy 默认会把 Host
        # 改成上游 127.0.0.1:18080，导致 auth-gate 的 Origin 同源校验拒绝
        # 带 Origin 头的 CSS/JS/模块请求（表现为登录后黑屏、MIME application/json）。
        header_up Host {http.request.hostport}
        transport http {
            tls
            tls_insecure_skip_verify
        }
    }
}
```

注意事项：

- **续期**：Let's Encrypt/Certbot 自动续期会换证书，`publicFingerprint` 不会自动更新；续期后必须重新点「从对外地址自动读取」（或填入新指纹），再重新生成配对二维码。旧二维码在续期后配对会失败。
- **安全边界**：`publicFingerprint` 只有管理员可设置（会话通道还需 6 位 TOTP；adminKey/本机通道免）。`"auto"` 只探测**当前提交/已保存的 `publicUrl`** 的主机端口，5 秒超时，不发送 HTTP 请求，不能用于扫描任意地址；探测失败返回 400 `fingerprint_fetch_failed` 且不落盘。
- `publicUrl` 变更**不会**自动改变 `publicFingerprint`（避免猜错证书把 App 锁死）：换到新的公网入口后请显式重新读取；`GET /__admin/api/network` 的 `fingerprintHint` 会在「对外主机与监听地址不同且未设置指纹」时提示这一风险。
- 前置代理会让网关看到的来源 IP 全部变成 frpc/代理地址，按 IP 的登录/配对限流会被共享；登录仍需已配对设备 + 密码，管理写操作仍受 CSRF/TOTP/当前密码保护。回源必须是 **HTTPS**（不要用明文 HTTP 回源），且 frpc 的 `local_ip` 必须保持网关的 LAN 地址，不能用 `127.0.0.1`。

### 修改后的影响（重要）

- **只改 `publicUrl`**：立即生效、不断开连接；之后新生成的二维码/链接使用新地址。已配对设备的记录里保存的是**配对时的 origin**：从旧 origin 登录/续期会返回 `origin_changed`（需重新扫码配对），不会静默继续使用已弃用的域名。已有登录会话仍有效到过期；浏览器 cookie 不区分端口但按 host 隔离：换域名/host 后通常需要重新登录，仅换端口时同 host 的 cookie 仍会携带（设备 origin 变了仍需重新配对）。**不会**自动改动 `publicFingerprint`：若新入口由另一张证书提供，需要显式重新读取，否则新二维码指纹错误、App 拒绝配对（服务端不会替管理员猜测）。
- **只改 `publicFingerprint`**：立即生效、不断开连接；只影响之后生成的配对二维码/链接。已按旧指纹配对成功的设备不需要重新配对（pinning 只在配对时校验），但用旧二维码重配的新设备会失败。
- **只改监听地址/端口**：立即重建监听；所有现有 HTTP/WebSocket 连接会断开，页面需刷新/重连（UI 会提示）。若 frp 的 `local_port` 指向旧端口，需要同步改 frpc 配置；`publicUrl` 不会自动跟着变，若外部入口也变了请一并修改。
- **两者都改**：先保存 publicUrl 再改监听（或一次提交），避免二维码短暂指向旧入口；改完重新生成一次配对二维码。
- 成功的网络修改会持久化，重启 dsh 后仍生效；TLS 证书本身不会热加载，换证书仍需重启。

## 配对与登录

1. 管理页点「生成配对二维码」（或 `POST /__admin/api/qr`；**会话通道需在 body 带 `totp`（6 位动态验证码）**，adminKey 免）。返回的 `url` 形如
   `https://192.0.2.10:3443/__auth/pair#v=1&t=<ticket>&fp=<证书DER SHA256>&n=<主机名>`。
   票据只存在 fragment，服务端日志不会出现；TOTP/当前密码都不会进入 URL，也不会写入审计。
2. 手机 App（[DSH Mobile](https://github.com/chjy090/DSH-Mobile)）扫码后比对 `fp` 与证书 SHA-256，然后 `POST /__auth/pair/redeem`
   换取 `deviceToken`，同时拿到 `HttpOnly; Secure; SameSite=Lax` 的设备 cookie（初始 `min(now+90 天, now+365 天)`，之后随 renew/登录滑动，绝对上限从配对时起算）。App 建议在 body 里带稳定的 `clientDeviceId`（见第 6 条），这样重装/重新扫码不会堆出重复设备记录。
3. 打开网关地址：没有会话时 302 到 `/__auth/login?next=…`；输入**用户名 + 密码**（已配对设备无需 TOTP）。
   没有设备 cookie 时登录固定返回 `device_required`（先扫码配对）。
4. 登录成功得到 48 小时空闲窗口的会话（绝对上限 30 天）；活跃使用会滑动续期并重发 cookie；`/__auth/whoami` 可查看当前用户/设备；`/__auth/logout` 注销会话（设备保留）。
5. App 侧会话过期时用设备 token `POST /__auth/renew`（**只接受 JSON body 的 `deviceToken`**）换新会话，无需重新扫码；
   成功时设备有效期同时滑动，响应带 `deviceExpiresAt` 并重发设备 cookie（`Max-Age` 为新的剩余时长）。
   为防 CSRF/免密续期被跨站利用，不再接受“无 body 时回退 `dsh_gate_device` cookie”的旧路径。
6. **同一设备重复配对**：`POST /__auth/pair/redeem` 的 JSON body 可带可选 `clientDeviceId`（合法格式 `^[A-Za-z0-9._-]{8,64}$`，例如 App 首次启动生成的安装 ID；浏览器配对不传，行为不变）。若该字段合法、且存在**未过期**（`expiresAt > now`）的同 ID 设备：
   - **原地复用同一 `device.id`**，更新 `name`/`platform`/`origin`/`lastSeenAt`；
   - **轮换 `deviceToken`**：旧 `tokenHash` 立即失效，旧 token 的 `/__auth/renew` 返回 401；
   - **删除该设备全部旧 session**：旧 `dsh_gate_session` 立即未认证；
   - **清空全部其它待用配对票据**：重新配对 = 完整凭据重置，与吊销设备同级联；替换前签发的其它票据 redeem 均返回 `invalid_ticket`（当前这张已消费）；
   - `createdAt = now`（重新配对 = 重新验证，**绝对上限窗口重新起算**），`expiresAt = min(now + deviceTtlDays, createdAt + deviceAbsoluteTtlDays)`；
   - 不新增设备、不占新名额、**不触发 `device_limit`**；即使已达到 `maxDevices`（默认 100），已有 ID 仍可替换成功；新 ID 才按上限检查；
   - 响应 200 增加 `replaced: true` 并回显 `clientDeviceId`；新建时 `replaced: false`（不传 ID 时也不回显）。
   缺失该字段保持「每次新建」；提供但格式非法（非字符串、长度不在 8–64、含非法字符）返回 **400 `invalid_client_device_id`**，审计 `pair_redeem`（detail `invalid_client_device_id`），且**不消耗票据**（store 层同样拒绝非法值，不会静默降级为新建）。并发同 ID 的 redeem 由 store 锁串行，最终只有一条设备记录。`clientDeviceId` 只是去重提示，不是认证因子，必须使用安装级高熵随机值（App 使用 UUID）；它仅存内部 `state.json`，管理 API/审计/日志不展示。登录/renew 的设备 token 校验、滑动续期与会话创建在 store 锁内一次完成（`authenticateDeviceToken`）：即使替换与在途的旧 token 请求并发，旧 token 也只会得到 401，或它刚创建的会话被替换删除，不会在替换后留下存活会话。

> **Caveat**：上述「立即失效」针对后续 HTTP 请求与 `/__auth/renew`；已建立的 WebSocket 隧道不会因 session 删除而立即断开，需等连接自然关闭。并发下的 token 轮换保证已由原子校验保证，不会在替换后留下存活会话。

```bash
# 同一 App 安装 ID 重新配对：第一次 replaced=false，第二次 replaced=true（设备数不变）
curl -k -X POST -H 'content-type: application/json' \
  -d '{"ticket":"t_xxx","clientDeviceId":"android-install-9f2c1a7b","deviceName":"Pixel 8","platform":"android"}' \
  "$BASE/__auth/pair/redeem"
# → {"deviceToken":"dt_…","deviceId":"d_…","replaced":false,...}
# 旧 deviceToken 立即 401，新 deviceToken 可正常 POST /__auth/renew
```

### 日常运维

```bash
ADMIN=$(cat "$DSH_HOME/auth-gate/admin.key")
BASE=https://192.0.2.10:3443

# 状态：用户、TOTP 是否已确认、设备列表（devices[].online / lastActiveAt）、会话摘要
#   sessions 仍为数量（兼容旧客户端）；sessionCount + sessionList 是详细摘要，
#   sessionList[] = {deviceId, createdAt, lastSeenAt, expiresAt, current}
curl -k -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/state"

# 会话摘要（WebUI 轮询用；不含 token）
curl -k -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/sessions"

# 生成配对二维码（2 分钟有效，票据一次性；platform 可选 android/web，仅影响页面提示）
# 使用登录会话通道（而非 adminKey）调用时必须同时传 6 位动态验证码：{"platform":"android","totp":"123456"}
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"platform":"android"}' "$BASE/__admin/api/qr"

# 吊销设备（同时撤销其会话）
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"deviceId":"d_xxx"}' "$BASE/__admin/api/devices/revoke"

# 修改密码（会注销全部会话 + 撤销全部已配对设备，需要重新扫码；至少 10 位）
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"password":"新的至少十位密码"}' "$BASE/__admin/api/user"

# 重置 TOTP（返回新 secretB32/otpauthUri/qrSvg；旧验证码立即失效，会话与全部设备均被撤销）
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"resetTotp":true}' "$BASE/__admin/api/user"

# 网络设置：查看 / 修改 publicUrl / 热重建监听端口（adminKey 免 TOTP）
curl -k -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/network"
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicUrl":"https://203.0.113.10:23443"}' "$BASE/__admin/api/network"
# 对外证书指纹（frp 后由 Caddy 等终止 TLS 时）：固定值或 "auto" 自动探测
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicFingerprint":"70a78d74d75fc65a17685b11408b5337cb3f5c32f91346e8705043251a45aaac"}' "$BASE/__admin/api/network"
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"publicFingerprint":"auto"}' "$BASE/__admin/api/network"
curl -k -X POST -H "x-auth-gate-admin-key: $ADMIN" -H 'content-type: application/json' \
  -d '{"listenPort":3443}' "$BASE/__admin/api/network"

# 审计（最近 100 条）
curl -k -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/audit"

# adminKey 只从 $DSH_HOME/auth-gate/admin.key（0600）读取
# /__admin/api/admin-key 不再向 loopback 访客返回密钥（监听 loopback 时整条通道禁用）
```

管理密钥轮换：停止网关/dsh 后，把新生成的 32 字节 hex 写入 `$DSH_HOME/auth-gate/admin.key`（`chmod 600`），再启动。轮换不影响用户、设备、TOTP 或已有会话；旧密钥立即失效。

> 凭据轮换：`POST /__admin/api/user` 改密或重置 TOTP 后会返回 `{devicesRevoked, sessionsRevoked, rePairRequired:true}`，
> 服务端已清空所有设备与 session。所有手机必须重新扫码配对（`/__admin/api/qr`）后再登录。
> 通过**登录会话**通道调用 `/__admin/api/user` 时 body 必须带 `currentPassword`；调用 `/__admin/api/qr` 时
> body 必须带 `totp`（缺失 403 `totp_required`、错误 403 `totp_invalid`，独立计数 5 次失败后 429 `rate_limited`）。
> adminKey 通道可省略这两类校验（loopback 通道在 loopback 监听时已禁用）。上面的 `curl` 示例使用 adminKey，因此无需 TOTP/当前密码。

## 数据与安全

- `state.json`（`$DSH_HOME/auth-gate/state.json`，0600）：
  - `user`：用户名、`scrypt$16384$8$1$…` 密码哈希、TOTP Base32 密钥（配对的二次因素）、`lastTotpCounter`（历史字段；登录与配对均不消费）。
  - `devices`：`tokenHash`（SHA-256）、名称、平台、origin、创建/最后使用/到期时间。
  - `tickets`：`ticketHash`、创建/到期；过期后保留 10 分钟以便返回 `expired_ticket`。
  - `sessions`：`tokenHash`、deviceId、创建/最后使用/最后刷新（`lastRefreshedAt`）/空闲到期（`expiresAt`）/绝对上限（`absoluteExpiresAt`，旧版本记录可能缺失，下次刷新补齐；最多 100 条）。
  - `audit`：最近 500 条。
- `admin.key`（0600）：32 字节随机 hex；不写入 `state.json`，不在 API 响应之外持久化；也不写入日志（日志只有掩码）。
- `network.json`（0600，原子写）：运行时网络覆盖 `{listenHost, listenPort, publicUrl, publicFingerprint?, updatedAt}`（`publicFingerprint` 为空时省略）；启动时优先于 bundle config。删除并重启即回退；损坏/非法值会让网关忽略该文件、打印恢复指引（`rm -f` 后重启）并在 bundle config 上继续启动，不会静默绑定到意外地址。
- `setup.token`（0600）：仅在未初始化时存在的一次性 WebUI 初始化令牌；初始化成功后删除。**唯一一条未初始化启动日志会带完整初始化链接**（这是全系统唯一在日志中出现完整 setup token 的地方）；能读 journald/该文件的主体会获得管理员创建能力，请按 root 级秘密保护，并在初始化后确认文件已删除。
- 浏览器只持有 `dsh_gate_session` / `dsh_gate_device` / `dsh_gate_csrf` 三个 cookie；dsh 的 `dsh-auth-*` cookie 仅存在网关进程内，请求上游时注入、响应时剥离（HTTP 与 WebSocket 握手都剥离）。
- 反代在把 Origin 改写成 dsh authority 之前，先校验入站 Origin 必须等于网关自身 authority；WebSocket 同样校验。这样同站跨源的恶意页面不能借会话 cookie 让 dsh 误判为同源。
- loopback 管理资格还要求 Host 属于 `publicUrl` / 监听地址 / localhost 的 authority，避免 DNS rebinding 页面从 loopback 读取管理 API；且网关自身监听 loopback 时整条通道禁用。
- 管理页的会话通道只影响 `/__admin*`：有效的 `dsh_gate_session` 可以直接打开管理页；该通道的 POST 必须通过 CSRF 双提交，**生成配对码必须校验 6 位 TOTP**，**改密/重置 TOTP 必须校验当前密码**。`/__auth/*` 与反代/WebSocket 的规则没有变化。
- **session 即管理能力**：持有任一有效 session 即可查看设备/会话/审计、吊销设备；生成配对码还需 TOTP，改密/重置 TOTP 还需当前密码。设备 token 或 session 泄露应按管理凭据泄露处理（立即吊销设备/改密），不要把 session cookie 暴露给第三方页面或日志。
- **吊销级联**：删除设备时在同一次原子状态写入中删除设备记录、该设备的**全部** session（可能同时有多个浏览器/App 会话）并清空全部待用配对票据；设备因过期被 prune 时同样删除其全部 session。因此旧 deviceToken 的 `renew`、该设备所有 `dsh_gate_session` cookie 以及 `dsh_gate_device` cookie 都会在下一次请求失效（401 / 管理 API 403）。
- **缓存隔离**：任何附带 `Set-Cookie` 的响应（含反代响应）都带 `cache-control: private, no-store` 与 `vary: cookie`；public asset 请求不刷新会话、不重发 cookie。前置共享缓存即使忽略 `Vary`，也会因 `private, no-store` 不缓存这些响应。
- **deviceToken / 设备 cookie 视同账号凭据**：登录只校验设备 cookie + 用户名密码；更关键的是 `POST /__auth/renew` **只需要 JSON body 里的 `deviceToken`，不需要密码**，可直接换出新 session。所以 `deviceToken`/`dsh_gate_device` 泄露 = 设备有效期内的持久访问（默认滑动 90 天、绝对上限 365 天，每次 renew 重新计时；可反复 renew），密码已知时还可直接登录。泄露立即在管理台吊销该设备；怀疑密码同时泄露时改密（会撤销全部设备与会话）。不要发到聊天或日志。网关不校验设备指纹，清 cookie/换浏览器等于新设备，需重新配对。
- 密码：scrypt（N=16384, r=8, p=1，16 字节 salt，32 字节 key），`timingSafeEqual`；最小 10 位。
- 所有票据/设备/会话 token 都是 32 字节随机数的 base64url，只存 SHA-256；比较使用常数时间比较。
- CSRF：登录与所有 loopback/会话管理写操作都要求 `x-auth-gate-csrf` 请求头与 `dsh_gate_csrf` cookie 一致（loopback 通道仅在监听非 loopback 地址时存在）；adminKey 是请求头 bearer 凭据，免 CSRF。登录页与管理页 CSP 都使用 per-response nonce，无内联事件处理器、无外部 CDN。
- 续期：`/__auth/renew` 只接受 JSON body 的 `deviceToken`，不接受 cookie 回退；该 token 属于长期 bearer，等价于第二因素，勿写日志。
- TOTP：登录不校验 TOTP；配对时验证当前 6 位码（±1 窗口），**只验证不写 `lastTotpCounter`**，因此同窗口可连续出码；`consumeTotpCounter` 仍保留在存储层但登录/配对均不调用。TOTP 失败由独立的按 IP 计数器限流。
- 开放重定向：反代只把指向 upstream authority 的 http(s) Location 改写为同源相对路径；`//evil.example`、外域、`javascript:` 等一律改为 `/`。
- 日志：脱敏，不打印密码、TOTP secret、票据、设备/会话 token、launch token；管理员密钥只打印掩码与路径，从不打印完整值。**唯一例外**：未初始化时的那一条 `setup required` 启动日志会打印完整初始化链接（含 setup token），初始化后不再出现；请限制 journald 读取权限。
- 上游 TLS：`upstreamInsecureTls: true` 只适用于本机/内网自签 dsh；如果 dsh 换成正受信证书，应改为 `false`。
- **admin.key 文件权限 = 管理权**：完整密钥只在 `$DSH_HOME/auth-gate/admin.key`（0600；未设置 `DSH_HOME` 时 `~/.dsh/auth-gate/admin.key`）；systemd journal 中只有掩码，能读 journal 不再等于能管理网关。仍请把该文件当作 root 级秘密。
- 换证书/改 `publicUrl` 后，App 内保存的旧指纹或旧设备 origin 会不匹配：需要重新扫码配对（`state.json` 里已有设备可先吊销）。前置代理证书续期后必须重新读取 `publicFingerprint`，否则二维码仍带旧指纹、App 会拒绝配对。
- 前置反向代理（对外 TLS 在代理终止、HTTPS 回源到网关）是受支持的场景，但必须：① 设置 `publicFingerprint` 为代理证书指纹；② 保持网关监听 LAN 地址、frpc `local_ip` 同地址（全程不要出现 loopback 回源）；③ 只通过 adminKey/会话管理网关，并接受源 IP 变成代理地址、按 IP 限流共享；④ 代理必须 **HTTPS 回源**，且网关自身 TLS 不能省（自签即可）。明文 HTTP 回源不是「关掉网关 TLS 就行」的替代方案：配置校验要求「配了 `tlsCert`/`tlsKey` ⇒ `publicUrl` 必须 https；没配 TLS ⇒ `publicUrl` 必须 http」，明文回源时 `publicUrl` 只能是 http，App 无法用 HTTPS + 指纹配对，因此**不支持**。

## 独立运行（开发/测试）

`lib/standalone.js` 不依赖 dsh，读取 `AUTH_GATE_*` 环境变量，并用 `DSH_TOKEN_URL`（journal 里带 launch token 的 URL）或 `DSH_TOKEN`（裸 token）兑换 dsh 会话 cookie。

```bash
# 必须是本机 LAN 地址（不要用 127.0.0.1/::1：网关会拒绝并禁用本机自动管理通道）
export AUTH_GATE_LISTEN_HOST=192.0.2.10
export AUTH_GATE_LISTEN_PORT=3456
export AUTH_GATE_UPSTREAM=https://192.0.2.10:3080
export AUTH_GATE_UPSTREAM_INSECURE_TLS=true
export AUTH_GATE_PUBLIC_URL=https://192.0.2.10:3456
export AUTH_GATE_TLS_CERT=/path/to/dsh.crt.pem
export AUTH_GATE_TLS_KEY=/path/to/dsh.key.pem
export AUTH_GATE_STATE_DIR=$PWD/.test-state
export DSH_TOKEN_URL='https://192.0.2.10:3080/?token=...'   # 不要回显/提交

node lib/standalone.js
```

| 环境变量 | 说明 |
|---|---|
| `AUTH_GATE_LISTEN_HOST` / `AUTH_GATE_HOST` | 监听地址（必须具体地址，禁止 `0.0.0.0`/`::`） |
| `AUTH_GATE_LISTEN_PORT` / `AUTH_GATE_PORT` | 监听端口，默认 3443 |
| `AUTH_GATE_UPSTREAM` | dsh 根 URL（当前 `https://192.0.2.10:3080`） |
| `AUTH_GATE_UPSTREAM_INSECURE_TLS` | `true/false`；自签证书用 `true` |
| `AUTH_GATE_PUBLIC_URL` | 二维码/登录跳转使用的外部 origin |
| `AUTH_GATE_PUBLIC_FINGERPRINT` | 可选：二维码 `fp=` 使用的对外证书 SHA-256 hex；留空用网关自身证书（`auto` 仅 API POST 可用） |
| `AUTH_GATE_TLS_CERT` / `AUTH_GATE_TLS_KEY` | 同时提供则启用 HTTPS；只给一个会启动失败 |
| `AUTH_GATE_STATE_DIR` | 状态目录，默认 `$DSH_HOME/auth-gate` |
| `AUTH_GATE_ADMIN_KEY_FILE` | 管理密钥文件，默认 `<stateDir>/admin.key` |
| `AUTH_GATE_SESSION_TTL_HOURS` | 会话空闲窗口（小时），默认 48 |
| `AUTH_GATE_SESSION_ABSOLUTE_TTL_DAYS` | 会话绝对上限（天，自创建起算），默认 30；0 = 无上限 |
| `AUTH_GATE_DEVICE_TTL_DAYS` | 设备滑动空闲窗口（天），默认 90 |
| `AUTH_GATE_DEVICE_ABSOLUTE_TTL_DAYS` | 设备绝对上限（天，自配对起算），默认 365；0 = 无上限 |
| `AUTH_GATE_MAX_DEVICES` | 设备上限，默认 100（范围 1–100） |
| `AUTH_GATE_PAIR_TICKET_TTL_SECONDS` | 配对票据 TTL，默认 120 |
| `AUTH_GATE_LOGIN_MAX_FAILURES` / `..._WINDOW_MINUTES` / `..._LOCK_MINUTES` | 登录锁定参数 |
| `DSH_TOKEN_URL` / `DSH_TOKEN` | 兑换 dsh cookie 的 launch URL / 裸 token |

`SIGINT`/`SIGTERM` 会优雅关闭（关闭监听、销毁 socket、落盘状态）。

## 版本与更新

- **所有版本变更与发行说明统一发布在 GitHub Releases**：<https://github.com/chjy090/dsh-pairing-gate/releases>。各版本之间的差异、升级与回滚说明以 Releases 中的 release notes 为准。
- **升级（link 安装）**：更新源码（`git pull` 或替换插件目录）→ `systemctl restart dsh`，无需重新 `dsh plugin add`。账号、TOTP、已配对设备、`state.json` 与 `network.json` 都会保留，无需迁移（**v0.7.4 例外，见下**）。**例外：v0.7.1 → v0.7.2 是改名版本**，profile 里仍记着旧包名 `dsh-auth-gate`，只 `git pull` + 重启会因新 bundle 名 `dsh-pairing-gate` 无法解析而加载失败；必须按「从旧名 `dsh-auth-gate` 迁移」先 `remove` 旧名再 `add link:`，然后重启。
- **⚠️ v0.7.3 → v0.7.4 是破坏性默认值变更**：v0.7.4 起插件包自带的 `cordis.patch.yml` 改为可移植默认值（`listenHost: 127.0.0.1`、`listenPort: 3443`、`upstream: http://127.0.0.1:3080`、不配置 TLS/publicUrl）。已有部署如果依赖旧的 bundle 默认值，**必须先**在 profile `$DSH_HOME/profiles/web/cordis.patch.yml` 加 `- id: auth-gate` 的 override 并写全生产配置（`listenHost`/`upstream`/`upstreamInsecureTls`/`tlsCert`/`tlsKey`/`publicUrl` 等，模板见 installation §2.2.2），重启后才不会掉线。否则：`network.json` 里的 https `publicUrl` 会因「未配置 TLS」被判无效并回退到 bundle 默认值，网关落到 `127.0.0.1:3443` 纯 HTTP、上游 `127.0.0.1:3080` 不可达，外部 3443/公网入口失效。改完 override 后重启，确认 journal 出现 `listening on https://<你的对外地址>` 且 `curl -k https://<LAN>:3443/__auth/login` 为 200。
- **升级前建议备份**：`tar -czf ~/auth-gate-$(date +%F).tgz -C "$DSH_HOME" auth-gate`（含账号与设备，权限 0600）。
- **回滚方式**：把源码切到目标 Release 对应的 tag/commit（或解压旧版本备份）→ `systemctl restart dsh`。旧版本会忽略新版本写入的多余 state 字段；仍建议回滚前备份 `$DSH_HOME/auth-gate`。
- **查看当前版本**：`node -e "console.log(require('./package.json').version)"`。

## 测试

```bash
cd $PLUGIN_DIR
npm test                       # node:test：password/base32/totp/ratelimit/store/sliding/qr/fingerprint/config/first-run-smoke/network/proxy/dsh-session/pages/gateway-401/admin-session/setup/client-render/device-token-atomic
bash tests/e2e-standalone.sh   # 真实 TLS 网关全流程（1~2 分钟，含 WebUI 会话通道 + 初始化向导 + 网络设置/热重建 + 对外证书指纹 + 滑动续期/吊销级联）
```

当前基线（v0.7.5）：`npm test` **171/171 pass**；`bash tests/e2e-standalone.sh` → **E2E PASSED（29 步 / 39 PASS）**。v0.7.5 只整理文档/README（版本历史迁到 GitHub Releases、补充生产前置条件提示），没有改运行逻辑或测试。首装冒烟测试用临时 `stateDir` + 默认配置启动 standalone：登录页 200、`/__admin` 可访问、未认证 `GET /__admin/api/admin-key` 返回 403 且不回显密钥（loopback 管理通道禁用）、setup 链接与 0600 `setup.token`、SIGTERM 干净退出且无临时文件/进程。

E2E 行为：

- 优先使用调用者提供的 `DSH_TOKEN_URL`（配合 `E2E_UPSTREAM`）；否则尝试 `E2E_USE_JOURNAL=1` 从 `journalctl -u dsh` 取启动 URL；
- 若 journal 里没有（当前机器就是这种情况：启动行已被日志滚动掉，且不允许重启生产 dsh），脚本会以**独立 `DSH_HOME`** 在 `127.0.0.1:3099` 启动一个临时 dsh web 实例（同样使用 dsh 原生 HTTPS + 同一张证书），再把网关反代到它。生产 dsh（3080）完全不受影响。
- 主网关固定监听 `127.0.0.1:3456`（避开 dsh 的 3080 与旧代理的 3443，状态目录 `.test-state`，结束删除）；该实例用于验证「loopback 监听自动禁用本机管理通道」。网络设置/初始化向导实例监听本机 LAN 地址的 3458，热重建在同一 LAN 地址的 3458↔3459 之间进行（network API 拒绝 loopback）。
- 会话通道的 E2E 请求通过 `curl --interface <本机非 loopback IP>` 模拟 LAN 客户端（默认取 `hostname -I` 的第一个非 127 地址，可用 `E2E_SOURCE_IP` 覆盖）；主网关监听 loopback 时本机自动通道已禁用，会话仍必须完整通过 CSRF/TOTP/currentPassword。不需要改防火墙或额外监听端口。
- 默认会在结束时删除带 launch token 的临时 dsh 日志。`E2E_KEEP=1` 会保留 `.test-tmp/` 与 `.test-dsh-home/` 便于排障，但**其中的 dsh 日志含 launch token**，排查完请立即删除。

覆盖（29 步）：302 登录跳转 / 401 JSON；CSRF 与安全头；admin bootstrap；QR 指纹与 fragment 票据；配对、单次票据、过期票据；无设备 `device_required`；已配对设备 + 密码登录（无 TOTP）与 cookie 标志；device token renew（仅 body，拒绝空 body/cookie 回退）；反代 `/` 含 `__DSH_BOOT__`；上游 Set-Cookie 剥离；WebSocket `/api/remote.mux` 401/101；登录会话访问 `/__admin` 200 与匿名 302、无 CSRF 403；会话通道生成 QR 缺/错 TOTP 403、正确 200、同一 TOTP 窗口可重复；改密/重置 TOTP 强制 currentPassword 并清空设备/会话；登出；5 次错误密码 429；吊销设备；开放重定向防护；审计/日志不含秘密；文件 0600。**初始化向导（第 19/20 步）**：全新 `stateDir` 上向导页、CSP/no-store、status 不回显 token、错 token 403、adminKey 轮换 token、begin/confirm 全流程、`setup.token` 删除、初始化后写接口 409。**网络设置（第 21~25 步）**：`GET /__admin/api/network`、session 改 publicUrl 缺/错 TOTP 403、非法 origin 400、正确 TOTP 200 + `network.json` 0600、QR 使用新 origin、adminKey 热重建（先绑新后关旧）、通配/loopback 地址与上游端口冲突均 400、损坏 `network.json` 回退 bundle config、`publicFingerprint` 固定值/`auto` 探测/失败 400 `fingerprint_fetch_failed`/审计只留前 8 位。**安全加固（第 26/27 步）**：注入时钟下 `private, no-store` + `Vary: cookie`、public asset 不刷新会话、越过绝对上限的设备失效；真实网关登录页/登录/renew 响应头契约。**配对去重（第 28/29 步）**：同一 `clientDeviceId` 重配设备数不变、旧 token 401、新 token 200、非法 ID 400 且不新增设备；并发旧 token renew 与重配交错后旧 session 为 0。

## 故障排查

| 现象 | 排查 |
|---|---|
| dsh 启动日志只有 `auth-gate: failed to start: …` | 看错误：端口占用、证书读取失败、`listenHost` 是通配地址、`publicUrl` 与 TLS 不匹配、state 损坏后拒绝启动。插件故意不把异常抛进 Cordis boot，dsh 本身继续可用。若错误提到 `network override`，网关会**回退到 bundle config 继续启动**，按日志里的 `rm -f …/network.json` 处理后重启即可。 |
| 登录一直 `device_required` | 该浏览器还没有设备 cookie：先在管理页生成二维码并用 DSH Mobile 扫码；或检查 `publicUrl` 是否与访问 authority 一致（设备绑定 origin）。 |
| `/__admin` 显示初始化向导而不是登录页 | 这是未初始化（`configured:false`）的正常行为：从启动日志或 `auth-gate/setup.token` 取 `#setup=<token>` 链接完成向导；初始化后页面自动恢复 302/登录。 |
| 初始化链接丢失 / 令牌过期 | 用 adminKey 调 `POST /__admin/api/setup/token` 取新 `setupUrl`（旧令牌与进行中的草稿立即失效）；详见「首次初始化」。 |
| setup 接口返回 409 `already_configured` | 已经初始化，写接口永久关闭；请走密码登录或 adminKey 管理。若确需重新初始化，只能停机备份/清空 `$DSH_HOME/auth-gate`（丢失账号、设备与审计），不要只删 `setup.token`。 |
| `setup.token` 仍存在但 `/__admin` 不是向导 | `state.json` 已配置；重启后 store 会自动删除残留文件。确认 `/__admin/api/state` 的 `configured`，并检查是否误删/覆盖了 state。 |
| `/__admin` 302 到登录页 | 当前浏览器没有有效网关会话。先用已配对设备完成用户名+密码登录（不再需要 TOTP）；登录后会自动回到 `/__admin`。若账号不可用，改用 adminKey 应急（读 `$DSH_HOME/auth-gate/admin.key`）。未初始化时不会 302，而是直接显示向导。 |
| 左侧栏没有「认证管理」条目 | 确认 profile 的 `dsh-pairing-gate` 行已加载（旧名安装时为 `dsh-auth-gate`）、`package.json` 含 `exports["./client"]` 和 `dsh.client`，重启 dsh 后看启动日志有无 client bundle/组合错误；浏览器硬刷新。 |
| 「认证管理」面板空白/一直加载 | 面板有错误边界，真崩溃会显示「认证管理渲染失败」卡（`error.message` + 栈前 1500 字符）并在 Console 打印 `[auth-gate]` 日志，不再是整块空白。排查顺序：① 地址栏加 `?authgate-debug=1`（或 hash `#authgate-debug`）刷新，看顶部调试卡的 `location.href/port`、`React.version`、primitives 是否加载及 real/fallback 绑定、当前渲染分支；② F12 → Console 过滤 `[auth-gate]`，复制 `render failed` / `primitive failed` 行与栈；③ 立即兜底：点错误卡「打开独立管理页 /__admin」，或直接访问 `https://<网关地址>/__admin`（同源会话可直接用）；④ 面板会探测同源 `GET /__admin/api/setup/status` 来判断是否由网关提供（不再只看 3443），探测失败才会显示「不是认证网关」说明卡，3080 直连显示说明卡是设计行为；仍空白则硬刷新并检查 dsh 启动日志里的 client bundle 错误。 |
| Console 报 `GET …/manifest.webmanifest 401 (Unauthorized)` / favicon 401 | 网关对 `manifest.webmanifest`、favicon、apple-touch-icon 与 `/assets/*` 的 **GET/HEAD** 放行，浏览器不带登录态也能取到这些静态 dist 文件（数据/API 路由仍 401/302）。若重启后仍报 401：确认加载的是当前版本（`node -e "console.log(require('./package.json').version)"`）、请求方法确为 GET/HEAD、且路径未被改写；`/api/*`、`/plugins/*`、`/__admin*` 返回 401 属预期。 |
| 从 3080 打开只看到提示 | 这是预期的优雅降级，不是故障；按提示改从 `https://<host>:3443` 访问。 |
| `admin` 页/API 403 | 没有有效会话 cookie，也没有 `x-auth-gate-admin-key`（监听 loopback 时本机自动通道已禁用；非 loopback 监听时 loopback 对端也不再是常规来源）。用浏览器登录后访问 `/__admin`，或 curl 加 `x-auth-gate-admin-key`。会话通道的 POST 还要求 CSRF 头 + cookie。 |
| 会话通道生成配对码返回 403 `totp_required` / `totp_invalid` | 通过登录会话生成配对码时必须输入认证器当前的 6 位动态验证码；检查手机/服务器时间是否同步（±1 窗口）。也可以改用 adminKey 通道（loopback 通道在 loopback 监听时已禁用）。 |
| 会话通道配对 TOTP 返回 429 `rate_limited` | 同一 IP 5 分钟内失败 5 次会锁 5 分钟；等待锁过期或改用 adminKey。 |
| 会话通道改密/重置 TOTP 返回 403 `invalid_current_password` | 凭证变更必须输入当前密码（防会话被劫持后直接轮换凭据）；也可以改用 adminKey 通道。 |
| QR 签发返回 429 `rate_limited` | 同一 IP 1 分钟内最多签发 10 次；等待窗口重置。 |
| 反代 502 `upstream_auth_failed` | 网关无法用 launch token 换到 dsh cookie：dsh 重启后 token 会变，插件的 `authenticatedUrl()` 每次重取即可；standalone 需要更新 `DSH_TOKEN_URL`。也可能是上游 TLS 校验/`upstreamInsecureTls` 配错。 |
| 上游 401 后仍 502 | 检查 dsh 的 Host/Origin fence：`upstream` 必须使用 dsh 监听地址的 authority（当前 `192.0.2.10:3080`），不能写 `127.0.0.1`，否则 dsh 签发的 cookie authority 不匹配。 |
| 登录 429 | 同一 IP+用户名 15 分钟内失败 5 次会锁 15 分钟；等待或重启网关（内存计数）。 |
| 二维码 `fp` 为空 | 未配置 `tlsCert/tlsKey`，网关以明文 HTTP 运行（日志有警告）。生产必须配 TLS，App 会拒绝空指纹。 |
| 状态文件损坏 | 网关拒绝启动，不会静默重置。先把 `state.json` 备份移走再重新初始化；不要直接覆盖。 |

## 已知限制 / 未验证项

- **client bundle 的验证范围**：通过 `node --check` 与 Node VM 渲染 harness 覆盖；面板由 `PanelErrorBoundary` 兜底（真崩溃显示「认证管理渲染失败」卡），primitives 的真实像素布局仍需真机验收（见下方「真浏览器交互未自动化验证」）。
- **未在生产重启/真机验证**：本轮只改文档与版本号，未重启生产 dsh、未改 App；初始化向导三步交互、设置表单/toast、真实 frp 链路、浏览器对自签证书 SAN 的告警，以及监听切换瞬间的并发请求/SSE/WebSocket 重连行为仍需在真实环境验收。
- **认证语义变更**：登录不再要求 TOTP；已配对设备上「密码正确即可登录」。这是刻意的产品取舍，风险与吊销建议见上方「认证模型与风险」。设备丢失、密码泄露、设备 cookie 泄露都应按凭据泄露处理（吊销设备/改密）。
- **Android App（不在本包范围）**：App 端扫码/`fp` pin/`renew`/登出的行为需真机联调。
- 单用户、无 WebAuthn；WebUI 管理页为服务端渲染 + 原生 JS，在线状态是按 120 秒活跃窗口计算的近似值。
- **真浏览器交互未自动化验证**：E2E 用 curl 覆盖服务端页面/API/CSRF/currentPassword，VM harness 覆盖原生面板的树/文案/请求/轮询/清理；但真实浏览器中的 primitives 布局、SegmentedTabs 键盘导航、剪贴板权限弹窗、QR 扫码和亮/暗主题显示仍需人工点一遍。服务端 `/__admin` 的 `confirm()` 弹窗等也仍属人工验收范围。
- WebSocket 上游 401 不会像 HTTP 那样自动刷新 cookie 重试一次（HTTP 请求会先刷新，通常足够）；如需更强保证，重连即可。
- 大于 8MB 或未声明 `Content-Length`（chunked）的请求体走流式转发，不做缓冲；如果恰好在这类请求上遇到 dsh cookie 401，会返回 502 而不会重放（普通页面/API 请求仍会自动刷新并重试一次）。
- 同一个 `stateDir` 只应由一个网关进程使用；状态文件的互斥锁是进程内的。
- 公网部署（Tailscale/Caddy/防火墙）不在本轮；网关不应直接暴露到公网。
- 管理 API 的 loopback 信任模型不适合放在反向代理之后（见「数据与安全」）。

## License

MIT（与仓库其他部分一致；见仓库根 `LICENSE`）。
