# dsh-pairing-gate

> **改名说明（v0.7.2）**：原名为 `dsh-auth-gate`，因 npm 上该包名已被 [TecFancy/dsh-auth-gate](https://github.com/TecFancy/dsh-auth-gate) 占用而改名；两者功能不同：本插件是**扫码设备配对 + 公网反代 + 管理面板/初始化向导**，后者是密码/共享令牌登录 + 用户管理 CLI。旧仓库链接会 301 跳转到 <https://github.com/chjy090/dsh-pairing-gate>。

DeepSeek Harness（dsh）的前台认证网关插件：**TOTP 授权的扫码设备配对 + 用户名密码登录**，认证通过后把请求反代到 dsh（含 WebSocket）。

## 配套仓库

| 仓库 | 说明 |
| --- | --- |
| [dsh-pairing-gate](https://github.com/chjy090/dsh-pairing-gate) | 本插件：dsh 服务端设备配对网关（扫码配对 / 会话 / TOTP / 反代） |
| [DSH-Mobile](https://github.com/chjy090/DSH-Mobile) | Android 客户端：扫码配对、设备令牌自动续期；APK 与更新见 [Releases](https://github.com/chjy090/DSH-Mobile/releases) |

目标部署是「单人自用」。v0.4.0 起认证模型是**设备绑定即第二因素**：

1. 新设备先在管理页输入 **6 位 TOTP** 生成一次性配对二维码，扫码/打开链接完成绑定（`dsh_gate_device` cookie，默认 90 天）；
2. 之后这台设备只需 **用户名 + 密码** 登录，不再填写 TOTP；
3. 改密码 / 重置 TOTP 仍要求**当前密码**（凭证变更的二次确认），重置/改密会撤销全部设备与会话，所有设备重新配对。

v0.5.0 起，全新部署的首次初始化可以完全在浏览器完成：网关启动日志给出一次性初始化链接，打开后按向导创建管理员、绑定 TOTP，并**自动把当前浏览器配对为可信设备**，随后直接用户名 + 密码登录。adminKey/curl 仅保留为自动化或应急通道。

v0.6.0 起，管理页（服务端 `/__admin` 与原生侧边栏「设置」tab）可以修改**监听地址/端口**与**对外访问地址 `publicUrl`**。后者用于生成配对二维码/链接，因此可以填 frp 中转后的公网 IP/域名；改监听地址会**即时重建监听**（无需重启 dsh），失败自动回滚。详见「网络设置 / frp 内网穿透」。

v0.7.0 起，**设备令牌与登录会话都改为「滑动窗口 + 绝对上限」**：App 每次 `POST /__auth/renew` 成功或密码登录成功，都会把设备有效期推进到 `min(now + deviceTtlDays, 配对时间 + deviceAbsoluteTtlDays)`，并重发设备 cookie；Web 会话每次已认证的 HTTP 请求在满足刷新条件时把 `expiresAt` 推进到 `min(now + sessionTtlHours, 创建时间 + sessionAbsoluteTtlDays)`，并重发 `dsh_gate_session`（同一 token，新的 `Max-Age`）。默认 `sessionTtlHours: 48`（空闲窗口）、`sessionAbsoluteTtlDays: 30`、`deviceTtlDays: 90`、`deviceAbsoluteTtlDays: 365`（0 = 无绝对上限）。**吊销设备会级联删除该设备的全部会话并清空待用配对票据**，旧 deviceToken、所有 session cookie 与设备 cookie 在下一次请求立即失效。
v0.7.1 是 v0.7.0 的 P2 安全修复（无新功能、配置/state 格式不变）：① 带会话/设备 cookie 的响应统一 `cache-control: private, no-store` + `vary: cookie`，并且 public asset 请求不再刷新会话、不再附带 `Set-Cookie`（防止前置共享缓存缓存并回放他人会话）；② `extendDevice` 及设备读取结果不再返回 `tokenHash`；③ 设备绝对上限改为**所有读路径**立即生效（`findDeviceByToken`/`findDeviceById` 命中 `createdAt + deviceAbsoluteTtlDays <= now` 即删除设备及其全部 session），旧 `state.json` 设备或调低 `deviceAbsoluteTtlDays` 后不再能活到下一次 renew/登录。

v0.6.2 起，网络设置新增**对外证书指纹 `publicFingerprint`**：当 TLS 由 frp 后面的反向代理（如 Caddy）终止时，浏览器看到的是代理证书，而 App 会按二维码里的 `fp=` 做 fail-closed pinning。此时把代理证书的 SHA-256 DER 填进该字段（或点「从对外地址自动读取」），二维码就按公网实际证书 pinning，App 可正常配对；留空仍使用网关自身证书。

> **v0.6.1 安全修复（P0）**：监听地址**禁止 loopback**（`127.0.0.0/8`、`::1`），并且当网关实际绑定 loopback 时自动禁用「本机 loopback 即管理员」通道（仅保留 adminKey 与会话）。这堵住了「网关监听 127.0.0.1 + frp/本机反代转发」时公网访客被当成本机管理员、直接读取 `/__admin/api/admin-key` 的路径。frpc 的 `local_ip` 必须填网关绑定的同一 LAN 地址。

未认证的浏览器看不到 dsh 的 launch token，也拿不到 dsh 的会话 cookie。

```
手机 / 浏览器 ──HTTPS(:3443)──> dsh-pairing-gate（本插件自带监听）
    │                             ├─ /__auth/*   登录页、CSRF、配对兑换、续期、登出
    │                             ├─ /__admin*   登录会话 / adminKey（loopback 监听时本机自动通道禁用）管理页与 API
    │                             └─ 其它路径 → 校验网关会话 → 反代 dsh（Host/Origin 改写、注入 dsh cookie、WS 隧道）
    └──扫码──> https://<host>:3443/__auth/pair#v=1&t=<一次性票据>&fp=<证书 SHA256>
                                  dsh 192.0.2.10:3080（原生 HTTPS，自签证书）
```

> 网关是 dsh 前面的**第二道门**，不是 dsh 自身的替代鉴权。dsh 目前监听 `192.0.2.10:3080`，能直连该地址的人仍可看到 dsh 自己的登录入口；生产环境建议用防火墙把 3080 限制为 loopback/可信网段（本轮不改防火墙）。

## 功能

- 前台 HTTPS 监听（默认 `192.0.2.10:3443`），TLS 1.2+，HSTS。
- 登录两要素：**已配对设备 cookie**（配对时由 6 位 TOTP 授权）+ 用户名密码（scrypt）。正常登录不填 TOTP；未配对设备固定返回 `device_required`。
- 扫码配对：管理页（登录会话通道）必须输入认证器当前的 **6 位 TOTP**；校验只验证、不消耗登录重放计数器，所以同一 30 秒窗口可连续生成多个二维码，实际签发仍按 IP 限 10 次/分钟。一次性票据默认 120 秒、服务端只存 SHA-256；二维码只把票据放在 **URL fragment**，不会发给服务器或日志。
- 设备管理：最多 8 台、默认 90 天；每台设备可单独吊销，吊销立即失效其会话。
- **WebUI 管理页**：登录后打开 `/__admin` 即可管理账号、生成配对二维码/链接、查看设备与会话、吊销设备、重置 TOTP、修改网络设置、查看审计（详见「WebUI 管理页」）。
- **网络设置（v0.6.0 / v0.6.1 / v0.6.2）**：管理页可修改监听地址/端口、对外地址 `publicUrl` 与对外证书指纹 `publicFingerprint`。`publicUrl` 立刻用于新的配对二维码/链接（frp 场景填中转公网 IP/域名）；`publicFingerprint` 留空表示使用网关自身 TLS 证书，填 64 位 SHA-256（或 POST `"auto"` 自动读取 publicUrl 的证书）后二维码 `fp=` 改用公网实际证书，App 可按代理证书 pinning；监听地址/端口采用**先绑新、后关旧**的热重建（先绑定成功再持久化，失败时旧监听全程可用）；监听地址必须是本机 LAN 地址，拒绝 loopback 与通配地址；覆盖值持久化到 `$DSH_HOME/auth-gate/network.json`（0600），重启后仍生效。
- **原生侧边栏管理面板（v0.3.0）**：dsh 左侧栏「全局面板」的「认证管理」入口改为 **React + dsh 设计系统** 原生面板（不再用 iframe）：顶部状态、配对二维码/倒计时/复制、改密、重置 TOTP、设备/会话表格、最近 100 条审计；20 秒轮询（页面隐藏时暂停）、CSRF 双提交、429 倒计时、未登录/会话失效跳转登录。从 3080 直连时只显示跳转 3443 的说明卡，不发 API 请求。
- 反代：HTTP(S) 与 WebSocket；Host/Origin 改写、入站 Cookie 删除、注入 dsh 会话 cookie、上游 `Set-Cookie` 剥离、上游 401 自动刷新 cookie 重试一次、Location 改写。
- 会话：空闲窗口 48 小时 + 绝对上限 30 天（v0.7.0 起滑动续期）；服务端只存 token 的 SHA-256；登出、吊销设备会撤销对应会话（吊销设备级联撤销该设备全部会话）；**改密/重置 TOTP 会撤销全部会话与全部已配对设备**（需重新扫码）。
- 限流：同一 IP+用户名 15 分钟内 5 次失败锁 15 分钟；配对/续期按 IP 30 次/分钟；QR 签发按 IP 10 次/分钟；会话通道的 `currentPassword`（改密/重置 TOTP）与配对 TOTP 校验各自按 IP 计数，5 次失败锁 5 分钟（成功一次即清零）。
- 审计：最近 500 条（管理 API 返回最近 100 条），只记录粗粒度原因，不写密码/TOTP/票据/设备 token。
- 状态文件 `0600`、原子写、互斥；损坏时拒绝启动而不是静默重置；管理密钥独立 `0600` 文件，首启生成，日志只输出掩码与文件路径（不打印完整密钥）。
- 中文登录页/管理页，服务端渲染，无外部静态资源。

## 包结构

```
dsh-auth-gate/              # 本地目录名保持不变；npm 包名为 dsh-pairing-gate
├── package.json
├── cordis.patch.yml      # 插件默认配置（insert 行）
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

## 安装（需要用户自行执行；本轮未安装、未重启 dsh）

前提：dsh 已经用 `--tls-cert/--tls-key` 原生 HTTPS 运行，证书路径与默认配置一致。

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

3. **配置覆盖（可选）**：`dsh plugin add` 已通过插件的 bundle patch 自动注入 `auth-gate`（默认配置见 `cordis.patch.yml`），**不要**再追加同 id 的 `- insert:`（会产生重复条目）。需要改监听地址/端口/上游/TLS 时，在 `$DSH_HOME/profiles/web/cordis.patch.yml` 里用 **id-targeted 覆盖**（不加 `insert:`）：

   ```yaml
   - id: auth-gate
     name: 'dsh-pairing-gate'
     config:
       listenHost: 192.0.2.10
       listenPort: 3443
       # …只写需要覆盖的字段，其余沿用 bundle 默认…
   ```



   > 插件包内的 `cordis.patch.yml` 由 `dsh.bundle.patch` 自动提供默认值；上面只需写覆盖字段即可。完整配置项说明见 [docs/installation.md](docs/installation.md)。

4. 重启 dsh 让插件生效：

   ```bash
   systemctl restart dsh
   journalctl -u dsh -n 100 --no-pager | grep -E 'auth-gate|admin key'
   ```

   首次启动会生成 **64 位十六进制管理密钥** 并写入 `$DSH_HOME/auth-gate/admin.key`（0600）；日志只打印掩码和路径，**不打印完整密钥**。请从该文件读取并保存到密码管理器；后续启动不再生成。

5. 防火墙放行 3443（例如 `firewall-cmd --add-port=3443/tcp`；本轮未修改防火墙），并尽量把 dsh 的 3080 限制为 loopback/可信网段。
6. 查看启动日志里的初始化链接（未初始化时才会有）：`journalctl -u dsh -n 100 --no-pager | grep 'setup required'`，然后按下一节的 WebUI 向导完成首次初始化。已初始化的生产实例升级后不会出现该链接。

> v0.6.0 起可直接在管理页修改 `listenHost`/端口与 `publicUrl`（即时生效、无需重启）；bundle config 仍是首次部署的默认值。换端口后记得同步防火墙与 frp 的 `local_port`。v0.6.2 起同一页面还可设置 `publicFingerprint`（详见「网络设置 / frp 内网穿透」）。

### 卸载

```bash
dsh plugin --profile web remove dsh-pairing-gate
# 从旧名升级的用户第一次迁移时先 remove dsh-auth-gate，见下一节
# 需要保留账号/设备时不要删除 $DSH_HOME/auth-gate；否则 rm -rf "$DSH_HOME/auth-gate"
systemctl restart dsh
```

### 从旧名 `dsh-auth-gate` 迁移

v0.7.2 只改包名（仓库改为 [dsh-pairing-gate](https://github.com/chjy090/dsh-pairing-gate)，本地目录名仍是 `dsh-auth-gate`）。已以旧名安装的用户按下面三步迁移，**`state.json`、账号、TOTP、已配对设备、会话与 `network.json` 都不受影响**：

```bash
# 1) 移除旧名（会同时移除 dependency 与 bundles 条目）
dsh plugin --profile web remove dsh-auth-gate

# 2) 用新包名重新 link（目录路径不变）；或安装 npm 包 dsh-pairing-gate
dsh plugin --profile web add link:/opt/ai_code/mobile-apk/dsh-auth-gate

# 3) 重启，让服务端插件与 client bundle 按新包名重新组合
systemctl restart dsh
```

迁移后 `$DSH_HOME/profiles/web/package.json` 的 dependency 键与 `dsh.profile.bundles` 都应为 `dsh-pairing-gate`（见 [docs/installation.md](docs/installation.md) 2.7.1）。若 profile 的 `cordis.patch.yml` 里还留着 `- id: auth-gate` 覆盖段，把其中的 `name:` 也改成 `dsh-pairing-gate`。

## 首次初始化（WebUI 向导，v0.5.0）

全新部署（`stateDir` 里还没有用户）**不需要 SSH 或 curl**：启动网关后，从服务器日志取出一次性初始化链接，在浏览器里按向导完成「创建管理员 + 绑定 TOTP + 自动配对当前浏览器」，随后即可用用户名 + 密码登录。

网关首次启动（未初始化）会生成一次性初始化令牌 `$DSH_HOME/auth-gate/setup.token`（32 字节随机数，hex，0600），并打印**唯一一条**带完整令牌的日志：

```text
auth-gate: setup required — open https://192.0.2.10:3443/__admin#setup=<64位hex>（也可从 $DSH_HOME/auth-gate/setup.token 读取）
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

> 生产实例已经初始化，升级到 v0.5.0 后不会出现向导：`/__admin` 仍按原逻辑 302 到登录页。要看到向导必须全新部署（空 stateDir），或先完整卸载/清空 `$DSH_HOME/auth-gate`（会丢失账号与全部已配对设备，谨慎操作）。

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

### 原生侧边栏管理面板（v0.3.0）

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
- **设置**（v0.6.0，v0.6.2 起含证书指纹）：只读展示 TLS 状态、生效来源（运行时覆盖/插件配置）、当前监听、publicUrl 与**二维码当前生效指纹**；修改监听地址、端口、对外访问地址（publicUrl）与对外证书指纹（`publicFingerprint`，含「从对外地址自动读取」按钮），会话通道需 6 位动态验证码 + 内联二次确认；保存成功 toast，监听重建时提示连接会短暂中断并需刷新；未设置指纹但对外主机与监听地址不同时显示 `fingerprintHint` 风险提示。
- **审计**：最近 100 条（时间/类型/IP/设备/详情），倒序，滚动容器 + 手动刷新。

渲染与交互：

- `lib/client.js` 是手写 dsh ModuleLoader 懒 CJS 包，只 `require("react")` 与
  `@deepseek-ai/dsh-client-ui-primitives`（dsh Web shell 的内置模块表项，官方 sidebar 也用它）；
  全部用 `React.createElement`，不使用 JSX。
- 实际使用 `Button`、`Input`、`SegmentedControl`、`SegmentedTabs`、`Tag`、`writeClipboard` 和若干 `Icon*`；
  若 primitives 不可用会退化为本地极简控件，侧边栏条目不会整体消失。
- v0.4.2 起整个面板包在 `PanelErrorBoundary` 中：渲染异常不再把 React 树卸载成空白，而是显示
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
  `next` 为当前 `pathname+search`，整页跳 `/__auth/login`，**不循环重试**。旧版本依赖本机 loopback 通道显示「本机通道」的行为在 v0.6.1 已随 P0 修复移除。
- 会话失效：401 或 403 `forbidden`/`not_configured` → 停止轮询并显示「会话已失效 + 重新登录」；
  403 `invalid_current_password` 只在表单内提示，不误判掉线。
- 429：读取 `retry-after` 显示剩余秒数并禁用操作；到期自动恢复。
- 20 秒轮询 `/__admin/api/state`；`document.visibilityState !== "visible"` 时暂停，回到可见立即补一次；
  卸载时清理 interval、倒计时、toast 与 `visibilitychange` 监听。
- 挂载时先探测同源 `GET /__admin/api/setup/status`：只要返回合法 JSON，就认为当前文档由网关提供，**不再硬性要求 `location.port === "3443"`**（因此 frp 中转域名/其他端口也能使用原生面板）；典型 3080 直连探测失败 → 只显示说明卡和「打开认证网关管理页」按钮，不发管理 API 请求。

兼容与生效：

- `/__admin`（含 `?embed=1`、nonce 内联脚本、`frame-ancestors 'self'`）**保留不动**，作为浏览器直连/旧版本兜底；
  未初始化时该路径改为公开的 WebUI 初始化向导（`DENY` 不可 frame），初始化完成后恢复 302/登录页行为；v0.3.0 的侧边栏不再使用它。
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

> **认证模型与风险（v0.4.0 语义，v0.4.1 文案修正）**：TOTP 只在**设备配对**时验证，设备绑定成功后该设备上「密码正确即可登录」。因此：
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

adminKey 是 bearer 凭据：不要写进 URL、日志或 shell 历史；轮换方式见「日常运维」。v0.6.1 起 `/__admin/api/admin-key` 不再向 loopback 访客返回密钥（监听 loopback 时整条 loopback 通道禁用），请直接从 `$DSH_HOME/auth-gate/admin.key` 读取。

## 网络设置 / frp 内网穿透

v0.6.0 起，`/__admin` 页面与原生侧边栏「认证管理 → 设置」tab 都可以修改：

- **监听地址/端口**（`listenHost` / `listenPort`）：网关实际绑定的本机网卡地址与端口；保存后**立即重建监听**，无需重启 dsh。
- **对外访问地址**（`publicUrl`）：只用于生成配对二维码/链接（以及 `setup.token` 链接等），必须是纯 origin；frp 场景填中转后的公网 IP/域名。二维码**不会**使用监听地址。
- **对外证书指纹**（`publicFingerprint`，v0.6.2）：配对二维码 `fp=` 使用的证书 DER SHA-256。留空（默认）＝网关自身 TLS 证书；TLS 在 frp/反向代理（Caddy、nginx 等）处终止时填代理证书指纹，否则 App 会按网关自签证书 pinning 并拒绝连接。输入 64 位十六进制（大小写自动归一），或点「从对外地址自动读取」由服务端探测当前 `publicUrl` 的证书。**证书续期后必须重新读取/更新**。

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
- **为什么禁止 loopback**：网关的「loopback 即本机管理员」信任模型只能区分 TCP 对端地址。若网关监听 `127.0.0.1` 而 frpc（或本机 nginx）从 loopback 转发，所有公网访客在网关看来都是 `127.0.0.1`；frp TCP 访客还能自带 `Host: 127.0.0.1:3443`，从而免 TOTP/会话读取管理 API（v0.6.0 的 P0）。v0.6.1 双重修复：① 网络设置/`network.json` 拒绝 loopback；② 即使有人手工把 bundle config 改成 loopback，启动后也会**自动禁用 loopback 管理通道**并打印 WARN，只保留 adminKey 与会话，`/__admin/api/admin-key` 不再对 loopback 返回密钥。

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

- 通过**登录会话**（WebUI）调用 `POST /__admin/api/network` 时必须带 6 位动态验证码（`totp`）：缺失 403 `totp_required`、错误 403 `totp_invalid`，失败 5 次锁 5 分钟（独立于配对 TOTP 的计数器）。adminKey 通道免 TOTP/CSRF；`loopback` 通道在 v0.6.1 起仅在网关监听非 loopback 地址时存在。
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
- **监听地址与 `local_ip` 都必须是同一个 LAN 网卡地址（如 `172.16.180.14`），绝不能写 `127.0.0.1`。** 网关的 `loopback` 管理通道按 TCP 对端地址判定：若 frpc 从 loopback 转发，所有公网访客都会被当成“本机管理员”，`/__admin` 及管理 API 将可被未登录访问。v0.6.1 起管理页/`network.json` 直接拒绝 loopback 监听；若通过 bundle config 手工设成 loopback，网关会禁用本机自动管理通道并 WARN，但仍建议立即改成 LAN 地址，因为 loopback 监听本身无法区分本机用户与代理转发。
- frpc 所在主机的地址会成为所有外部访客在网关侧看到的来源 IP，按 IP 的限流（登录/配对/QR）会被共享；登录本身仍需要已配对设备 + 密码，会话通道仍受 CSRF/TOTP/当前密码保护。
- 防火墙只需在 frps 放行 `remote_port`；网关的 3443 与 dsh 的 3080 保持私有。

#### ② frp HTTPS 自定义域名

**可用做法（TLS 直通）**：仍用 `type = tcp`，把域名 DNS 指向 frps（或 frps 的公网 IP），`remote_port` 映射到网关 3443，`publicUrl` 填 `https://dsh.example.com:23443`（若能把 remote_port 映射为 443，则可省略端口）。**证书 SAN 必须包含 `dsh.example.com`**，由网关自己终止 TLS；这样浏览器和 App 都正常。证书更换后二维码 `fp` 会变化，已配对 App 需要重新扫码。

**不支持的做法（frps 终止 TLS + 明文回源）**：`type = https` + `custom_domains` + `vhostHTTPSPort` 会在 frps 用 frps 的证书终止 TLS，再以明文 HTTP 转发给网关。当前版本的配置校验要求「网关没配 TLS ⇒ `publicUrl` 必须 http；配了 TLS ⇒ 必须 https」，而二维码又直接使用 `publicUrl`；同时前置代理会破坏 loopback 管理信任模型并让源 IP 全部变成代理地址。因此**不要**用 frps 终止 TLS + 明文回源的组合；请使用上面的 TLS 直通（TCP）方式，或下面的「反向代理终止 TLS + HTTPS 回源」。

#### ③ frp + TLS 终止反向代理（Caddy / nginx，v0.6.2）

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
2. 手机 App（[DSH Mobile](https://github.com/chjy090/DSH-Mobile)，当前 v0.4.5）扫码后比对 `fp` 与证书 SHA-256，然后 `POST /__auth/pair/redeem`
   换取 `deviceToken`，同时拿到 `HttpOnly; Secure; SameSite=Lax` 的设备 cookie（初始 `min(now+90 天, now+365 天)`，之后随 renew/登录滑动，绝对上限从配对时起算）。
3. 打开网关地址：没有会话时 302 到 `/__auth/login?next=…`；输入**用户名 + 密码**（已配对设备无需 TOTP）。
   没有设备 cookie 时登录固定返回 `device_required`（先扫码配对）。
4. 登录成功得到 48 小时空闲窗口的会话（绝对上限 30 天）；活跃使用会滑动续期并重发 cookie；`/__auth/whoami` 可查看当前用户/设备；`/__auth/logout` 注销会话（设备保留）。
5. App 侧会话过期时用设备 token `POST /__auth/renew`（**只接受 JSON body 的 `deviceToken`**）换新会话，无需重新扫码；
   成功时设备有效期同时滑动，响应带 `deviceExpiresAt` 并重发设备 cookie（`Max-Age` 为新的剩余时长）。
   为防 CSRF/免密续期被跨站利用，不再接受“无 body 时回退 `dsh_gate_device` cookie”的旧路径。

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

# adminKey 只从 $DSH_HOME/auth-gate/admin.key（0600）读取；v0.6.1 起
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
  - `user`：用户名、`scrypt$16384$8$1$…` 密码哈希、TOTP Base32 密钥（配对的二次因素）、`lastTotpCounter`（历史字段；v0.4.0 登录与配对均不消费）。
  - `devices`：`tokenHash`（SHA-256）、名称、平台、origin、创建/最后使用/到期时间。
  - `tickets`：`ticketHash`、创建/到期；过期后保留 10 分钟以便返回 `expired_ticket`。
  - `sessions`：`tokenHash`、deviceId、创建/最后使用/最后刷新（`lastRefreshedAt`）/空闲到期（`expiresAt`）/绝对上限（`absoluteExpiresAt`，旧版本记录可能缺失，下次刷新补齐；最多 100 条）。
  - `audit`：最近 500 条。
- `admin.key`（0600）：32 字节随机 hex；不写入 `state.json`，不在 API 响应之外持久化；也不写入日志（日志只有掩码）。
- `network.json`（0600，原子写）：运行时网络覆盖 `{listenHost, listenPort, publicUrl, publicFingerprint?, updatedAt}`（`publicFingerprint` 为空时省略）；启动时优先于 bundle config。删除并重启即回退；损坏/非法值会让网关忽略该文件、打印恢复指引（`rm -f` 后重启）并在 bundle config 上继续启动，不会静默绑定到意外地址。
- `setup.token`（0600）：仅在未初始化时存在的一次性 WebUI 初始化令牌；初始化成功后删除。**唯一一条未初始化启动日志会带完整初始化链接**（这是全系统唯一在日志中出现完整 setup token 的地方）；能读 journald/该文件的主体会获得管理员创建能力，请按 root 级秘密保护，并在初始化后确认文件已删除。
- 浏览器只持有 `dsh_gate_session` / `dsh_gate_device` / `dsh_gate_csrf` 三个 cookie；dsh 的 `dsh-auth-*` cookie 仅存在网关进程内，请求上游时注入、响应时剥离（HTTP 与 WebSocket 握手都剥离）。
- 反代在把 Origin 改写成 dsh authority 之前，先校验入站 Origin 必须等于网关自身 authority；WebSocket 同样校验。这样同站跨源的恶意页面不能借会话 cookie 让 dsh 误判为同源。
- loopback 管理资格还要求 Host 属于 `publicUrl` / 监听地址 / localhost 的 authority，避免 DNS rebinding 页面从 loopback 读取管理 API；且网关自身监听 loopback 时整条通道禁用（v0.6.1）。
- 管理页的会话通道只影响 `/__admin*`：有效的 `dsh_gate_session` 可以直接打开管理页；该通道的 POST 必须通过 CSRF 双提交，**生成配对码必须校验 6 位 TOTP**，**改密/重置 TOTP 必须校验当前密码**。`/__auth/*` 与反代/WebSocket 的规则没有变化。
- **session 即管理能力**：持有任一有效 session 即可查看设备/会话/审计、吊销设备；生成配对码还需 TOTP，改密/重置 TOTP 还需当前密码。设备 token 或 session 泄露应按管理凭据泄露处理（立即吊销设备/改密），不要把 session cookie 暴露给第三方页面或日志。
- **吊销级联（v0.7.0）**：删除设备时在同一次原子状态写入中删除设备记录、该设备的**全部** session（可能同时有多个浏览器/App 会话）并清空全部待用配对票据；设备因过期被 prune 时同样删除其全部 session。因此旧 deviceToken 的 `renew`、该设备所有 `dsh_gate_session` cookie 以及 `dsh_gate_device` cookie 都会在下一次请求失效（401 / 管理 API 403）。
- **缓存隔离（v0.7.1）**：任何附带 `Set-Cookie` 的响应（含反代响应）都带 `cache-control: private, no-store` 与 `vary: cookie`；public asset 请求不刷新会话、不重发 cookie。前置共享缓存即使忽略 `Vary`，也会因 `private, no-store` 不缓存这些响应。
- **deviceToken / 设备 cookie 视同账号凭据**：v0.4.0 登录只校验设备 cookie + 用户名密码；更关键的是 `POST /__auth/renew` **只需要 JSON body 里的 `deviceToken`，不需要密码**，可直接换出新 session。所以 `deviceToken`/`dsh_gate_device` 泄露 = 设备有效期内的持久访问（默认滑动 90 天、绝对上限 365 天，每次 renew 重新计时；可反复 renew），密码已知时还可直接登录。泄露立即在管理台吊销该设备；怀疑密码同时泄露时改密（会撤销全部设备与会话）。不要发到聊天或日志。网关不校验设备指纹，清 cookie/换浏览器等于新设备，需重新配对。
- 密码：scrypt（N=16384, r=8, p=1，16 字节 salt，32 字节 key），`timingSafeEqual`；最小 10 位。
- 所有票据/设备/会话 token 都是 32 字节随机数的 base64url，只存 SHA-256；比较使用常数时间比较。
- CSRF：登录与所有 loopback/会话管理写操作都要求 `x-auth-gate-csrf` 请求头与 `dsh_gate_csrf` cookie 一致（loopback 通道仅在监听非 loopback 地址时存在）；adminKey 是请求头 bearer 凭据，免 CSRF。登录页与管理页 CSP 都使用 per-response nonce，无内联事件处理器、无外部 CDN。
- 续期：`/__auth/renew` 只接受 JSON body 的 `deviceToken`，不接受 cookie 回退；该 token 属于长期 bearer，等价于第二因素，勿写日志。
- TOTP：登录不校验 TOTP；配对时验证当前 6 位码（±1 窗口），**只验证不写 `lastTotpCounter`**，因此同窗口可连续出码；`consumeTotpCounter` 仍保留在存储层但登录/配对均不调用。TOTP 失败由独立的按 IP 计数器限流。
- 开放重定向：反代只把指向 upstream authority 的 http(s) Location 改写为同源相对路径；`//evil.example`、外域、`javascript:` 等一律改为 `/`。
- 日志：脱敏，不打印密码、TOTP secret、票据、设备/会话 token、launch token；管理员密钥只打印掩码与路径，从不打印完整值。**唯一例外**：未初始化时的那一条 `setup required` 启动日志会打印完整初始化链接（含 setup token），初始化后不再出现；请限制 journald 读取权限。
- 上游 TLS：`upstreamInsecureTls: true` 只适用于本机/内网自签 dsh；如果 dsh 换成正受信证书，应改为 `false`。
- **admin.key 文件权限 = 管理权**：完整密钥只在 `$DSH_HOME/auth-gate/admin.key`（0600）；systemd journal 中只有掩码，能读 journal 不再等于能管理网关。仍请把该文件当作 root 级秘密。
- 换证书/改 `publicUrl` 后，App 内保存的旧指纹或旧设备 origin 会不匹配：需要重新扫码配对（`state.json` 里已有设备可先吊销）。前置代理证书续期后必须重新读取 `publicFingerprint`，否则二维码仍带旧指纹、App 会拒绝配对。
- 前置反向代理（TLS 在代理终止、HTTPS 回源到网关）是 v0.6.2 支持的场景，但必须：① 设置 `publicFingerprint` 为代理证书指纹；② 保持网关监听 LAN 地址、frpc `local_ip` 同地址（全程不要出现 loopback 回源）；③ 只通过 adminKey/会话管理网关，并接受源 IP 变成代理地址、按 IP 限流共享。若代理以明文 HTTP 回源，则需关闭网关自身 TLS（`tlsCert/tlsKey: null`），此时 `publicUrl` 只能是 http，App 也无法用 HTTPS+指纹配对，因此不推荐。

## 独立运行（开发/测试）

`lib/standalone.js` 不依赖 dsh，读取 `AUTH_GATE_*` 环境变量，并用 `DSH_TOKEN_URL`（journal 里带 launch token 的 URL）或 `DSH_TOKEN`（裸 token）兑换 dsh 会话 cookie。

```bash
# 必须是本机 LAN 地址（不要用 127.0.0.1/::1：v0.6.1 会拒绝并禁用本机自动管理通道）
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
| `AUTH_GATE_PUBLIC_FINGERPRINT` | 可选（v0.6.2）：二维码 `fp=` 使用的对外证书 SHA-256 hex；留空用网关自身证书（`auto` 仅 API POST 可用） |
| `AUTH_GATE_TLS_CERT` / `AUTH_GATE_TLS_KEY` | 同时提供则启用 HTTPS；只给一个会启动失败 |
| `AUTH_GATE_STATE_DIR` | 状态目录，默认 `$DSH_HOME/auth-gate` |
| `AUTH_GATE_ADMIN_KEY_FILE` | 管理密钥文件，默认 `<stateDir>/admin.key` |
| `AUTH_GATE_SESSION_TTL_HOURS` | 会话空闲窗口（小时），默认 48 |
| `AUTH_GATE_SESSION_ABSOLUTE_TTL_DAYS` | 会话绝对上限（天，自创建起算），默认 30；0 = 无上限 |
| `AUTH_GATE_DEVICE_TTL_DAYS` | 设备滑动空闲窗口（天），默认 90 |
| `AUTH_GATE_DEVICE_ABSOLUTE_TTL_DAYS` | 设备绝对上限（天，自配对起算），默认 365；0 = 无上限 |
| `AUTH_GATE_MAX_DEVICES` | 设备上限，默认 8 |
| `AUTH_GATE_PAIR_TICKET_TTL_SECONDS` | 配对票据 TTL，默认 120 |
| `AUTH_GATE_LOGIN_MAX_FAILURES` / `..._WINDOW_MINUTES` / `..._LOCK_MINUTES` | 登录锁定参数 |
| `DSH_TOKEN_URL` / `DSH_TOKEN` | 兑换 dsh cookie 的 launch URL / 裸 token |

`SIGINT`/`SIGTERM` 会优雅关闭（关闭监听、销毁 socket、落盘状态）。

## 版本与更新

- **所有版本变更与发行说明统一发布在 GitHub Releases**：<https://github.com/chjy090/dsh-pairing-gate/releases>。
- **升级（link 安装）**：更新源码（`git pull` 或替换插件目录）→ `systemctl restart dsh`，无需重新 `dsh plugin add`。账号、TOTP、已配对设备、`state.json` 与 `network.json` 都会保留，无需迁移。**例外：v0.7.1 → v0.7.2 是改名版本**，profile 里仍记着旧包名 `dsh-auth-gate`，只 `git pull` + 重启会因新 bundle 名 `dsh-pairing-gate` 无法解析而加载失败；必须按「从旧名 `dsh-auth-gate` 迁移」先 `remove` 旧名再 `add link:`，然后重启。
- **升级前建议备份**：`tar -czf ~/auth-gate-$(date +%F).tgz -C "$DSH_HOME" auth-gate`（含账号与设备，权限 0600）。
- **回滚方式**：把源码切到目标 Release 对应的 tag/commit（或解压旧版本备份）→ `systemctl restart dsh`。旧版本会忽略新版本写入的多余 state 字段；仍建议回滚前备份 `$DSH_HOME/auth-gate`。
- **查看当前版本**：`node -e "console.log(require('./package.json').version)"`。

## 测试

```bash
cd $PLUGIN_DIR
npm test                       # node:test：password/base32/totp/ratelimit/store/sliding/qr/fingerprint/config/network/proxy/dsh-session/pages/gateway-401/admin-session/setup/client-render
bash tests/e2e-standalone.sh   # 真实 TLS 网关全流程（1~2 分钟，含 WebUI 会话通道 + 初始化向导 + 网络设置/热重建 + 对外证书指纹 + 滑动续期/吊销级联）
```

当前基线（v0.7.2，功能与 v0.7.1 相同，仅改名）：`npm test` **151/151 pass**；`bash tests/e2e-standalone.sh` → **E2E PASSED（27 步 / 37 PASS）**。第 21 步在 LAN 地址 + 独立 `stateDir` 的已初始化实例上验证 session+TOTP 改 publicUrl、QR 使用中转 origin、invalid 400、adminKey 恢复；第 22 步验证 LAN 地址上 3458→3459→3458 热重建（先绑新后关旧、旧端口关闭/新端口 200/network.json 持久化）；第 23 步验证通配地址（含 `::0`/`0::0`/`00::`/`::ffff:0.0.0.0`）、loopback（`127.0.0.1`/`::1`）、上游端口、http/https 不匹配均 400 且不持久化/不改监听，并验证「绑定成功但 network.json 持久化失败」时关闭新监听、旧端口继续 200；第 24 步验证损坏 `network.json` 启动回退到 bundle config；v0.7.1 新增/改动：第 3/11/19 步的 `no-store` 断言兼容 `private, no-store`；第 26 步新增注入时钟的 P2-1（cookie 响应头 + asset 不刷新）与 P2-3（旧设备越过绝对上限后 token/session 失效）场景；第 27 步对真实网关断言登录页/登录/renew 响应带 `private, no-store` + `Vary: cookie`，带会话 cookie 的 public asset 不返回 `Set-Cookie` 且不被要求登录。第 25 步验证 `publicFingerprint`：空值回退网关证书、固定值（大写归一）驱动 QR `fp=`、`"auto"` 对 setup 实例自身 TLS 握手读出证书指纹并落盘、探测失败（关闭端口）400 `fingerprint_fetch_failed` 且不落盘、session 写入仍须 TOTP、审计只留前 8 位。主网关仍监听 loopback，用于验证 P0 修复（无凭据读 state/admin-key 均 403，启动 WARN）。

E2E 行为：

- 优先使用调用者提供的 `DSH_TOKEN_URL`（配合 `E2E_UPSTREAM`）；否则尝试 `E2E_USE_JOURNAL=1` 从 `journalctl -u dsh` 取启动 URL；
- 若 journal 里没有（当前机器就是这种情况：启动行已被日志滚动掉，且不允许重启生产 dsh），脚本会以**独立 `DSH_HOME`** 在 `127.0.0.1:3099` 启动一个临时 dsh web 实例（同样使用 dsh 原生 HTTPS + 同一张证书），再把网关反代到它。生产 dsh（3080）完全不受影响。
- 主网关固定监听 `127.0.0.1:3456`（避开 dsh 的 3080 与旧代理的 3443，状态目录 `.test-state`，结束删除）；该实例用于验证 v0.6.1 的「loopback 监听自动禁用本机管理通道」。网络设置/初始化向导实例监听本机 LAN 地址的 3458，热重建在同一 LAN 地址的 3458↔3459 之间进行（network API 拒绝 loopback）。
- 会话通道的 E2E 请求通过 `curl --interface <本机非 loopback IP>` 模拟 LAN 客户端（默认取 `hostname -I` 的第一个非 127 地址，可用 `E2E_SOURCE_IP` 覆盖）；v0.6.1 起主网关监听 loopback 时本机自动通道已禁用，会话仍必须完整通过 CSRF/TOTP/currentPassword。不需要改防火墙或额外监听端口。
- 默认会在结束时删除带 launch token 的临时 dsh 日志。`E2E_KEEP=1` 会保留 `.test-tmp/` 与 `.test-dsh-home/` 便于排障，但**其中的 dsh 日志含 launch token**，排查完请立即删除。

覆盖（27 步）：302 登录跳转 / 401 JSON；CSRF 与安全头；admin bootstrap；QR 指纹与 fragment 票据；配对、单次票据、过期票据；无设备 `device_required`；**已配对设备 + 密码登录（无 TOTP）与 cookie 标志**；device token renew（仅 body，拒绝空 body/cookie 回退）；反代 `/` 含 `__DSH_BOOT__`；上游 Set-Cookie 剥离；WebSocket `/api/remote.mux` 401/101；**登录会话访问 `/__admin` 200（账号/配对/设备/会话/审计区块、配对区 6 位动态验证码输入框、无 pair-current-password）、无会话 302**；会话 POST 无 CSRF 403；**会话通道生成 QR 缺 TOTP 403 `totp_required`、错 TOTP 403 `totp_invalid`、正确 200、同一 TOTP 窗口连续两次 200**，随后配对浏览器设备、吊销后 token renew 401；登出；5 次错误密码 429；吊销设备；**会话通道改密/重置 TOTP 强制 currentPassword，成功后设备/会话清空；改密后新密码直接登录（无 TOTP），新 session 用新 TOTP 签发 QR，旧 TOTP secret 与缺失码 403**；开放重定向防护；审计与日志不含秘密；文件 0600；**第 19/20 步（v0.5.0）**：全新 `stateDir` 实例上未初始化 `/__admin` 200 向导（DENY/no-store/CSP nonce）、status 不回显 token、错 token 403、adminKey 轮换 token 且旧 token 403、begin 返回 QR/secret、错 TOTP 403 且仍未初始化、正确 confirm 200 + `dsh_gate_device` cookie + 用户/TOTP 已确认 + web 设备 + `setup.token` 删除；初始化后 begin/confirm/token-rotate 409、密码登录 200、会话 `/__admin` 200、匿名 302、审计含 setup 事件且无秘密；**第 21~23 步（v0.6.0）**：`GET /__admin/api/network` 初始 config/规则、服务端页与 `?embed=1` 含网络设置区块、session 改 publicUrl 缺/错 TOTP 403 + 非法 origin 400 不落盘、正确 TOTP 200 + 源码 `network.json` 0600 + `POST /qr` 的 URL 使用 `https://relay.example:8443`、adminKey 恢复；adminKey 热重建 3458→3459→3458（响应 `rebound:true`、旧端口关闭、新端口 `/__auth/login` 200、新端口会话 `/__admin` 200、network.json 持久化、无需重启）；通配监听地址/等上游端口/http 与 TLS 不匹配均 400、network.json 与监听不变、审计含 `network_update`、`network_invalid_*` 且不含 TOTP secret；**第 24 步（v0.6.1）**：损坏 `network.json` 的 standalone 继续启动、日志含 `IGNORED`/`rm -f`/`not valid JSON`、网络 API 返回 `source=config` 且监听 bundle 端口；**第 25 步（v0.6.2）**：`GET network` 返回空 `publicFingerprint` 且 `effectiveFingerprint` 等于网关证书、服务端页/`?embed=1` 含新输入框与自动读取按钮、非法指纹 400（带 `field`）、session 写指纹无 TOTP 403、固定值（大写输入归一）写入 `network.json` 并驱动 QR `fp=`、`"auto"` 对该测试实例 TLS 握手读出证书指纹并落盘/驱动 QR、关闭端口探测失败 400 `fingerprint_fetch_failed` 且不改 publicUrl/指纹、清空后 QR 回退网关证书、审计含 `public_fp=<前8位>` 与失败记录且不含完整指纹、TOTP secret 不落盘；第 2/23 步另覆盖 loopback 监听 403 + admin-key 不泄露、`127.0.0.1`/`::1` 与 IPv6 通配 400、持久化失败先绑后关回滚。 **第 26/27 步（v0.7.1）**：注入时钟下已认证 API/HTML 刷新响应为 `private, no-store` + `Vary: cookie`、public asset 即使刷新到期也不改会话且无 `Set-Cookie`、旧设备越过绝对上限后 session 未认证/renew 401 且设备被删除；真实网关上登录页（CSRF cookie）/登录/renew 响应头满足同一契约，带有效会话 cookie 的 public asset 不要求登录且不返回 `Set-Cookie`。

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
| 「认证管理」面板空白/一直加载 | v0.4.2 起面板有错误边界，真崩溃会显示「认证管理渲染失败」卡（`error.message` + 栈前 1500 字符）并在 Console 打印 `[auth-gate]` 日志，不再是整块空白。排查顺序：① 地址栏加 `?authgate-debug=1`（或 hash `#authgate-debug`）刷新，看顶部调试卡的 `location.href/port`、`React.version`、primitives 是否加载及 real/fallback 绑定、当前渲染分支；② F12 → Console 过滤 `[auth-gate]`，复制 `render failed` / `primitive failed` 行与栈；③ 立即兜底：点错误卡「打开独立管理页 /__admin」，或直接访问 `https://<网关地址>/__admin`（同源会话可直接用）；④ v0.6.0 起面板会探测同源 `GET /__admin/api/setup/status` 来判断是否由网关提供（不再只看 3443），探测失败才会显示「不是认证网关」说明卡，3080 直连显示说明卡是设计行为；仍空白则硬刷新并检查 dsh 启动日志里的 client bundle 错误。 |
| Console 报 `GET …/manifest.webmanifest 401 (Unauthorized)` / favicon 401 | v0.4.3 起网关对 `manifest.webmanifest`、favicon、apple-touch-icon 与 `/assets/*` 的 **GET/HEAD** 放行，浏览器不带登录态也能取到这些静态 dist 文件（数据/API 路由仍 401/302）。若重启后仍报 401：确认加载的是 0.4.3+（`node -e "console.log(require('./package.json').version)"`）、请求方法确为 GET/HEAD、且路径未被改写；`/api/*`、`/plugins/*`、`/__admin*` 返回 401 属预期。 |
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

- **生产 dsh 未重启**：本轮没有重启生产 dsh。v0.4.0 的 client bundle 只在隔离 `DSH_HOME` 的临时 dsh（`127.0.0.1:3097`，明文网关 3457）验证了页面 200、boot manifest、bundle/combo 200 与 `node --check`，并用 Node VM 渲染 harness 覆盖面板逻辑；**没有在真实浏览器里点开侧边栏面板**，primitives 的真实像素布局、剪贴板权限、QR 扫码和亮/暗主题观感需生产生效后肉眼确认一次。v0.4.1 只改了 `lib/client.js` 的 TOTP 徽标取值与文案，已 `node --check` 且服务端单测覆盖 `totpConfigured`。v0.4.2 定位到 3443 面板空白的真实根因（`totpBound` 未定义，见 `tests/client-render.test.js` 的 ready 分支回归），新增错误边界/调试卡/primitives fallback，并以 fake React + VM harness 覆盖；但**仍未在真实浏览器里点开面板验证**，重启生效后请按「故障排查」用 `?authgate-debug=1` 与 Console 确认一次。v0.4.3 只放行浏览器公开静态资源（manifest/favicon/touch icons 与 `/assets/*` 的 GET/HEAD，其余仍要求会话），已单测覆盖；**生产 dsh 仍未重启**，因此「Console 不再出现 manifest 401」尚未在真实浏览器验证，重启后刷新 3443 页面确认一次，并顺带确认 `/api/*`、`/plugins/*`、`/__admin*` 仍返回 401/302。
- **v0.5.0 生产生效前的预检**：在隔离 `DSH_HOME`（复制生产 profile，临时 dsh `127.0.0.1:3097` + 明文网关 `127.0.0.1:3457`）验证了：全新独立 stateDir 下网关启动打印初始化链接、`GET /__admin` 200 向导页、公开 status、adminKey 轮换 token、begin/confirm 完整完成、`setup.token` 删除；已初始化后匿名（非 loopback 源）`/__admin` 仍 302、有会话 200、密码登录 200；boot manifest 含 `dsh-auth-gate/client.js`（rev `e2163007a545`），单文件 bundle 200 / 93 780 B、含 `loadSetupStatus`、`node --check` 通过。清理后 3097/3457 均已关闭、隔离目录删除；生产 dsh 未重启（PID 未变）。**尚未在生产 3443 上验证**：生产已初始化，升级后不会出现向导；真实浏览器里的向导三步交互（扫码/TOTP/跳转）只在 VM/curl 层覆盖，生效后如要演练需另起全新 stateDir 实例。
- **v0.6.0 网络设置预检（隔离，未触碰生产）**：复制生产 profile 到 `/opt/ai_code/preflight-dsh`，临时 dsh 监听 `127.0.0.1:3097`（明文），网关 `127.0.0.1:3457`（`tlsCert/Key:null`、`publicUrl:http://127.0.0.1:3457`、独立 stateDir）。验证：boot manifest 含 `dsh-auth-gate/client.js`（rev `f2e78d364815`），下载的单文件 bundle 200 / 108 833 B、`node --check` 通过；用该下载 bundle 跑 VM harness 11/11（含「设置」tab 渲染与**非 3443 origin 探测**）；服务端 `/__admin`（及 `?embed=1`）含网络设置区块；adminKey bootstrap 后 `GET/POST /__admin/api/network` 正常；热重建 3457→3460→3457 成功（旧端口关闭、新端口 `/__auth/login` 200、新端口会话管理页 200、`network.json` 0600，dsh PID 未变，无重启）。清理后 3097/3457/3460 关闭、隔离目录删除；生产 dsh PID 2425514 未变、生产 3080/3443 未重启、生产 `$DSH_HOME/auth-gate/network.json` 仍不存在。**未验证**：真实浏览器中的设置表单/确认/toast、真实 frp 链路、浏览器对证书 SAN 的告警，以及监听切换瞬间的并发请求/SSE/WebSocket 重连行为。
- **认证语义变更**：登录不再要求 TOTP；已配对设备上「密码正确即可登录」。这是刻意的产品取舍，风险与吊销建议见上方「认证模型与风险」。设备丢失、密码泄露、设备 cookie 泄露都应按凭据泄露处理（吊销设备/改密）。
- **Android App v0.4.0** 不在本包范围；App 端扫码/`fp` pin/`renew`/登出的行为需真机联调。
- 单用户、无 WebAuthn；WebUI 管理页为服务端渲染 + 原生 JS，在线状态是按 120 秒活跃窗口计算的近似值。
- **真浏览器交互未自动化验证**：E2E 用 curl 覆盖服务端页面/API/CSRF/currentPassword，VM harness 覆盖原生面板的树/文案/请求/轮询/清理；但真实浏览器中的 primitives 布局、SegmentedTabs 键盘导航、剪贴板权限弹窗、QR 扫码和亮/暗主题显示仍需人工点一遍。服务端 `/__admin` 的 `confirm()` 弹窗等也仍属人工验收范围。
- WebSocket 上游 401 不会像 HTTP 那样自动刷新 cookie 重试一次（HTTP 请求会先刷新，通常足够）；如需更强保证，重连即可。
- 大于 8MB 或未声明 `Content-Length`（chunked）的请求体走流式转发，不做缓冲；如果恰好在这类请求上遇到 dsh cookie 401，会返回 502 而不会重放（普通页面/API 请求仍会自动刷新并重试一次）。
- 同一个 `stateDir` 只应由一个网关进程使用；状态文件的互斥锁是进程内的。
- 公网部署（Tailscale/Caddy/防火墙）不在本轮；网关不应直接暴露到公网。
- 管理 API 的 loopback 信任模型不适合放在反向代理之后（见「数据与安全」）。

## License

MIT（与仓库其他部分一致；见仓库根 `LICENSE`）。
