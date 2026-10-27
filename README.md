# dsh-auth-gate

DeepSeek Harness（dsh）的前台认证网关插件：**TOTP 授权的扫码设备配对 + 用户名密码登录**，认证通过后把请求反代到 dsh（含 WebSocket）。

目标部署是「单人自用」。v0.4.0 起认证模型是**设备绑定即第二因素**：

1. 新设备先在管理页输入 **6 位 TOTP** 生成一次性配对二维码，扫码/打开链接完成绑定（`dsh_gate_device` cookie，默认 90 天）；
2. 之后这台设备只需 **用户名 + 密码** 登录，不再填写 TOTP；
3. 改密码 / 重置 TOTP 仍要求**当前密码**（凭证变更的二次确认），重置/改密会撤销全部设备与会话，所有设备重新配对。

v0.5.0 起，全新部署的首次初始化可以完全在浏览器完成：网关启动日志给出一次性初始化链接，打开后按向导创建管理员、绑定 TOTP，并**自动把当前浏览器配对为可信设备**，随后直接用户名 + 密码登录。adminKey/curl 仅保留为自动化或应急通道。

未认证的浏览器看不到 dsh 的 launch token，也拿不到 dsh 的会话 cookie。

```
手机 / 浏览器 ──HTTPS(:3443)──> dsh-auth-gate（本插件自带监听）
    │                             ├─ /__auth/*   登录页、CSRF、配对兑换、续期、登出
    │                             ├─ /__admin*   登录会话 / 本机 / adminKey 管理页与 API
    │                             └─ 其它路径 → 校验网关会话 → 反代 dsh（Host/Origin 改写、注入 dsh cookie、WS 隧道）
    └──扫码──> https://<host>:3443/__auth/pair#v=1&t=<一次性票据>&fp=<证书 SHA256>
                                  dsh 192.0.2.10:3080（原生 HTTPS，自签证书）
```

> 网关是 dsh 前面的**第二道门**，不是 dsh 自身的替代鉴权。dsh 目前监听 `192.0.2.10:3080`，能直连该地址的人仍可看到 dsh 自己的登录入口；生产环境建议用防火墙把 3080 限制为 loopback/可信网段。

## 功能

- 前台 HTTPS 监听（默认 `192.0.2.10:3443`），TLS 1.2+，HSTS。
- 登录两要素：**已配对设备 cookie**（配对时由 6 位 TOTP 授权）+ 用户名密码（scrypt）。正常登录不填 TOTP；未配对设备固定返回 `device_required`。
- 扫码配对：管理页（登录会话通道）必须输入认证器当前的 **6 位 TOTP**；校验只验证、不消耗登录重放计数器，所以同一 30 秒窗口可连续生成多个二维码，实际签发仍按 IP 限 10 次/分钟。一次性票据默认 120 秒、服务端只存 SHA-256；二维码只把票据放在 **URL fragment**，不会发给服务器或日志。
- 设备管理：最多 8 台、默认 90 天；每台设备可单独吊销，吊销立即失效其会话。
- **WebUI 管理页**：登录后打开 `/__admin` 即可管理账号、生成配对二维码/链接、查看设备与会话、吊销设备、重置 TOTP、查看审计（详见「WebUI 管理页」）。
- **原生侧边栏管理面板（v0.3.0）**：dsh 左侧栏「全局面板」的「认证管理」入口改为 **React + dsh 设计系统** 原生面板（不再用 iframe）：顶部状态、配对二维码/倒计时/复制、改密、重置 TOTP、设备/会话表格、最近 100 条审计；20 秒轮询（页面隐藏时暂停）、CSRF 双提交、429 倒计时、未登录/会话失效跳转登录。从 3080 直连时只显示跳转 3443 的说明卡，不发 API 请求。
- 反代：HTTP(S) 与 WebSocket；Host/Origin 改写、入站 Cookie 删除、注入 dsh 会话 cookie、上游 `Set-Cookie` 剥离、上游 401 自动刷新 cookie 重试一次、Location 改写。
- 会话：8 小时；服务端只存 token 的 SHA-256；登出、吊销设备会撤销对应会话；**改密/重置 TOTP 会撤销全部会话与全部已配对设备**（需重新扫码）。
- 限流：同一 IP+用户名 15 分钟内 5 次失败锁 15 分钟；配对/续期按 IP 30 次/分钟；QR 签发按 IP 10 次/分钟；会话通道的 `currentPassword`（改密/重置 TOTP）与配对 TOTP 校验各自按 IP 计数，5 次失败锁 5 分钟（成功一次即清零）。
- 审计：最近 500 条（管理 API 返回最近 100 条），只记录粗粒度原因，不写密码/TOTP/票据/设备 token。
- 状态文件 `0600`、原子写、互斥；损坏时拒绝启动而不是静默重置；管理密钥独立 `0600` 文件，首启生成，日志只输出掩码与文件路径（不打印完整密钥）。
- 中文登录页/管理页，服务端渲染，无外部静态资源。

## 包结构

```
dsh-auth-gate/            # 本仓库根目录
├── package.json
├── cordis.patch.yml      # 插件默认配置（insert 行）
├── lib/
│   ├── index.js          # Cordis 入口
│   ├── standalone.js     # 不依赖 dsh 的独立入口（开发/测试）
│   ├── gateway.js        # HTTPS/HTTP 服务、路由、反代、WS
│   ├── config.js         # 配置校验与 TLS 读取
│   ├── dsh-session.js    # authenticatedUrl → Set-Cookie 缓存/401 刷新
│   ├── store.js          # state.json、adminKey、设备/票据/会话/审计
│   ├── password.js       # scrypt
│   ├── totp.js / base32.js
│   ├── qr.js             # SVG/PNG、证书指纹、配对 URL
│   ├── ratelimit.js
│   ├── pages.js          # 服务端渲染中文页（/__admin 直连兜底，保留 ?embed=1 兼容）
│   └── client.js         # dsh Web GUI client half（原生 React 管理面板，无 iframe）
├── locales/zh.json
├── .gitignore
├── README.md
└── LICENSE
```

## 获取源码

本仓库是 dsh-auth-gate 的独立发布仓库（源码 + README + LICENSE）。先克隆到本地并安装运行时依赖：

```bash
git clone https://github.com/chjy090/dsh-auth-gate.git ~/dsh-auth-gate
cd ~/dsh-auth-gate
npm install --no-audit --no-fund
export PLUGIN_DIR="$HOME/dsh-auth-gate"
```

## 安装

前提：dsh 已经用 `--tls-cert/--tls-key` 原生 HTTPS 运行，证书路径与默认配置一致。

> 说明：下文的 `$PLUGIN_DIR` 表示本仓库根目录（若在 monorepo 中则为 `<仓库根>/dsh-auth-gate`）。

1. 在插件目录安装依赖（`qrcode`）：

   ```bash
   cd $PLUGIN_DIR
   npm install --no-audit --no-fund
   ```

2. 以 link 方式安装到 `web` profile：

   ```bash
   dsh plugin --profile web add link:$PLUGIN_DIR
   ```

3. 在 `$DSH_HOME/profiles/web/cordis.patch.yml` 中追加（或合并）插件配置：

   ```yaml
   - insert:
       - id: auth-gate
         name: 'dsh-auth-gate'
         config:
           listenHost: 192.0.2.10
           listenPort: 3443
           upstream: https://192.0.2.10:3080
           upstreamInsecureTls: true
           publicUrl: https://192.0.2.10:3443
           tlsCert: /path/to/dsh.crt.pem
           tlsKey: /path/to/dsh.key.pem
           adminKeyFile: $DSH_HOME/auth-gate/admin.key
           stateDir: $DSH_HOME/auth-gate
           sessionTtlHours: 8
           deviceTtlDays: 90
           maxDevices: 8
           pairTicketTtlSeconds: 120
           loginLock:
             maxFailures: 5
             windowMinutes: 15
             lockMinutes: 15
   ```

   也可以直接使用包内的 `cordis.patch.yml` 作为默认值；插件已通过 `dsh.bundle.patch` 声明它。

4. 重启 dsh 让插件生效：

   ```bash
   systemctl restart dsh
   journalctl -u dsh -n 100 --no-pager | grep -E 'auth-gate|admin key'
   ```

   首次启动会生成 **64 位十六进制管理密钥** 并写入 `$DSH_HOME/auth-gate/admin.key`（0600）；日志只打印掩码和路径，**不打印完整密钥**。请从该文件读取并保存到密码管理器；后续启动不再生成。

5. 防火墙放行 3443（例如 `firewall-cmd --add-port=3443/tcp`），并尽量把 dsh 的 3080 限制为 loopback/可信网段。
6. 查看启动日志里的初始化链接（未初始化时才会有）：`journalctl -u dsh -n 100 --no-pager | grep 'setup required'`，然后按下一节的 WebUI 向导完成首次初始化。已初始化的实例升级后不会出现该链接。

> 换 `listenHost`/端口后记得同步 `publicUrl`、`tlsCert`/`tlsKey` 与防火墙。

### 卸载

```bash
dsh plugin --profile web remove dsh-auth-gate
# 需要保留账号/设备时不要删除 $DSH_HOME/auth-gate；否则 rm -rf "$DSH_HOME/auth-gate"
systemctl restart dsh
```

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

> 已初始化的实例升级到 v0.5.0 后不会出现向导：`/__admin` 仍按原逻辑 302 到登录页。要看到向导必须全新部署（空 stateDir），或先完整卸载/清空 `$DSH_HOME/auth-gate`（会丢失账号与全部已配对设备，谨慎操作）。

### 令牌生命周期、重置与关闭

- **生成/复用**：未初始化时首次启动生成；之后每次重启复用同一令牌，直到初始化完成。
- **删除**：初始化成功后立即删除 `setup.token` 并清空内存值；即使进程在删除前崩溃，只要 `state.json` 已配置，下次启动也会删除残留文件且不再打印初始化链接。
- **轮换/找回**：用管理密钥或 loopback 调用（返回的 `setupUrl` 是唯一会回显完整令牌的 API，且仅在未初始化时可用；旧令牌与内存中的待确认草稿立即作废）：
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

`dsh-auth-gate` 同时是一个 dsh **client 插件**：`package.json` 通过 `exports["./client"]` 暴露 `lib/client.js`，并声明

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
- 未登录：先探测一次 `/__admin/api/state`；200 表示本机 loopback/管理密钥通道（显示「本机通道」，配对/改密的二次验证可留空），
  403 则显示「未登录 + 去登录」，`next` 为当前 `pathname+search`，整页跳 `/__auth/login`，**不循环重试**。
- 会话失效：401 或 403 `forbidden`/`not_configured` → 停止轮询并显示「会话已失效 + 重新登录」；
  403 `invalid_current_password` 只在表单内提示，不误判掉线。
- 429：读取 `retry-after` 显示剩余秒数并禁用操作；到期自动恢复。
- 20 秒轮询 `/__admin/api/state`；`document.visibilityState !== "visible"` 时暂停，回到可见立即补一次；
  卸载时清理 interval、倒计时、toast 与 `visibilitychange` 监听。
- `location.port !== "3443"`（典型是 3080 直连）→ 只显示说明卡和「打开认证网关管理页」按钮，
  **不发任何 API 请求**。

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
| `session`（WebUI 主路径） | 有效 `dsh_gate_session` cookie（设备已配对且会话未过期） | 必须（`x-auth-gate-csrf` 头 + `dsh_gate_csrf` cookie 双提交） | 生成配对码：**6 位 TOTP**；改密/重置 TOTP：**当前密码** |
| `loopback` | TCP 对端是 `127.0.0.1/::1`，且 Host 属于本部署的 authority（防 DNS rebinding） | 必须 | 可省略 |
| `key` | 请求头 `x-auth-gate-admin-key: <adminKey>`（bearer 凭据） | 免（header 凭据不会被跨站页面自动携带） | 可省略 |

三条通道任一满足即通过；三条都无法满足时才 403。**会话通道只解锁 `/__admin*`**：`/__auth/*` 与反代路径的鉴权规则完全没有放宽，反代和 WebSocket 仍然只认有效会话。未初始化是唯一例外：`/__admin`（向导页）与 `/__admin/api/setup/status|begin|confirm` 公开，其余管理 API 仍按上表鉴权；初始化完成后例外全部关闭。

### 服务端管理页功能（/__admin 直连）

- **账号**：修改密码（当前密码 + 新密码两次，至少 10 位）。改密会撤销**全部会话与全部已配对设备**；页面与响应都会提示「所有设备需重新扫码」。
- **配对**：选择「安卓设备 / 浏览器设备」并输入认证器当前的 **6 位动态验证码**（仅会话通道需要）后生成一次性配对二维码（SVG 内嵌，倒计时显示剩余秒数，过期提示重新生成）。动态验证码只用于这次配对授权，不会写进配对链接、页面 URL 或日志；页面不会把它回填到 HTML。同一 30 秒窗口可连续生成多个二维码（不消耗登录重放计数器）。二维码下方提供「复制配对链接」；**同一条链接在浏览器打开即可完成浏览器设备配对**。`platform` 只影响页面提示，ticket 逻辑不变（fragment、一次性、TTL）。
- **已配对设备**：平台标签（安卓 / 浏览器 / iOS）、设备名、状态（在线/离线 + 当前设备）、创建时间、最近活跃、到期时间；可单台吊销，吊销后该设备的会话与续期立即失效。在线 = 最近 120 秒内有设备或会话请求。
- **会话**：最多 100 条，显示设备、创建时间、最近活跃、到期时间、是否为当前会话；不展示 token。
- **TOTP**：顶部显示 TOTP 状态（**已配置 / 未配置**）。该徽标只反映账号是否已保存认证器密钥（`totpConfigured`，不回显 secret），不代表当前请求证明过持有认证器；任何通道配对成功都不会改变它，「重置 TOTP」后需按新二维码重新配置。「重置 TOTP」需要当前密码（会话通道），成功后直接显示新的绑定二维码 / Base32 secret / `otpauth://` URI，并按现有逻辑撤销全部设备与会话。
- **审计**：最近 100 条表格（时间、类型、IP、设备、详情），全部 HTML 转义；改密、TOTP 重置、设备吊销、生成配对码都会写审计。

### CSRF、当前密码与限流

- 管理页所有写操作都走 `fetch` + `x-auth-gate-csrf` 头，并与 `dsh_gate_csrf` cookie 双提交；GET 页面/API 不要求 CSRF。
- 会话通道改密、重置 TOTP 必须再次输入**当前密码**；会话通道**生成配对码**必须输入**6 位 TOTP**。仅拿到会话 cookie（例如被劫持的浏览器）不足以轮换凭据，也不足以另配一台 90 天设备再续出新会话。loopback/adminKey 通道可由网络位置/bearer 凭据证明身份，允许省略这两类校验。
- 会话通道的 `currentPassword` 与配对 TOTP 校验各自按 IP 计数：5 分钟内失败 5 次返回 429 `rate_limited` 并锁定 5 分钟，成功一次清零；QR 实际签发按 IP 限制 10 次/分钟。
- 配对 TOTP 校验**只验证不消费**登录重放计数器：同一 30 秒窗口可反复生成二维码，但真实签发仍受 10 次/分钟限制，且失败会进入独立的 TOTP 限流。
- 改密/重置 TOTP 是整信任面的重置：服务端清空全部设备与 session，返回 `{devicesRevoked, sessionsRevoked, rePairRequired:true}`。所有手机/浏览器必须重新扫码配对后再登录。当前管理页会显示提示并在改密后引导回登录页。

> **认证模型与风险（v0.4.0 语义，v0.4.1 文案修正）**：TOTP 只在**设备配对**时验证，设备绑定成功后该设备上「密码正确即可登录」。因此：
> - **密码泄露 + 已配对设备** = 可直接登录（设备丢失或被他人拿到时尤其危险）。请给设备本身设置锁屏，设备丢失/转手时立即在管理页吊销该设备；怀疑密码泄露时改密（会撤销全部设备与会话，强制重新配对）。
> - **TOTP 泄露但设备未配对** = 仍不能登录，只可能被用来生成新的配对二维码（还需要一个有效管理会话或 loopback/adminKey）。发现 TOTP 异常时应重置 TOTP 并吊销设备。
> - **会话 cookie 泄露** ≈ 管理能力泄露（可看设备/会话/审计、吊销设备；生成配对码另需 TOTP，改密/重置 TOTP 另需当前密码）。设备吊销时也会清空所有待用配对票据。
> - **有效 session + 任一 TOTP 码** = 生成配对二维码 → 任意设备打开链接 / 扫码 `redeem` 得到 `deviceToken` → `POST /__auth/renew`（**只凭 body 里的 deviceToken，不需要密码**）换出新 session = **最长 90 天的持久访问**。因此 session cookie 与 `deviceToken` 都视同账号凭据：泄露立即在管理台吊销该设备、必要时改密；不要把 TOTP 码、配对链接或 deviceToken 发到聊天或日志。
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

adminKey 是 bearer 凭据：不要写进 URL、日志或 shell 历史；轮换方式见「日常运维」。若本机可访问，也可用 `curl -k "$BASE/__admin/api/admin-key"`（仅 loopback）取回。

## 配对与登录

1. 管理页点「生成配对二维码」（或 `POST /__admin/api/qr`；**会话通道需在 body 带 `totp`（6 位动态验证码）**，adminKey/loopback 免）。返回的 `url` 形如
   `https://192.0.2.10:3443/__auth/pair#v=1&t=<ticket>&fp=<证书DER SHA256>&n=<主机名>`。
   票据只存在 fragment，服务端日志不会出现；TOTP/当前密码都不会进入 URL，也不会写入审计。
2. 手机 App（DSH Mobile v0.4.0）扫码后比对 `fp` 与证书 SHA-256，然后 `POST /__auth/pair/redeem`
   换取 `deviceToken`，同时拿到 `HttpOnly; Secure; SameSite=Lax` 的设备 cookie（90 天）。
3. 打开网关地址：没有会话时 302 到 `/__auth/login?next=…`；输入**用户名 + 密码**（已配对设备无需 TOTP）。
   没有设备 cookie 时登录固定返回 `device_required`（先扫码配对）。
4. 登录成功得到 8 小时会话；`/__auth/whoami` 可查看当前用户/设备；`/__auth/logout` 注销会话（设备保留）。
5. App 侧会话过期时用设备 token `POST /__auth/renew`（**只接受 JSON body 的 `deviceToken`**）换新会话，无需重新扫码。
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

# 审计（最近 100 条）
curl -k -H "x-auth-gate-admin-key: $ADMIN" "$BASE/__admin/api/audit"

# 取回 adminKey（仅 loopback）
curl -k "$BASE/__admin/api/admin-key"
```

管理密钥轮换：停止网关/dsh 后，把新生成的 32 字节 hex 写入 `$DSH_HOME/auth-gate/admin.key`（`chmod 600`），再启动。轮换不影响用户、设备、TOTP 或已有会话；旧密钥立即失效。

> 凭据轮换：`POST /__admin/api/user` 改密或重置 TOTP 后会返回 `{devicesRevoked, sessionsRevoked, rePairRequired:true}`，
> 服务端已清空所有设备与 session。所有手机必须重新扫码配对（`/__admin/api/qr`）后再登录。
> 通过**登录会话**通道调用 `/__admin/api/user` 时 body 必须带 `currentPassword`；调用 `/__admin/api/qr` 时
> body 必须带 `totp`（缺失 403 `totp_required`、错误 403 `totp_invalid`，独立计数 5 次失败后 429 `rate_limited`）。
> loopback/adminKey 通道可省略这两类校验。上面的 `curl` 示例使用 adminKey，因此无需 TOTP/当前密码。

## 数据与安全

- `state.json`（`$DSH_HOME/auth-gate/state.json`，0600）：
  - `user`：用户名、`scrypt$16384$8$1$…` 密码哈希、TOTP Base32 密钥（配对的二次因素）、`lastTotpCounter`（历史字段；v0.4.0 登录与配对均不消费）。
  - `devices`：`tokenHash`（SHA-256）、名称、平台、origin、创建/最后使用/到期时间。
  - `tickets`：`ticketHash`、创建/到期；过期后保留 10 分钟以便返回 `expired_ticket`。
  - `sessions`：`tokenHash`、deviceId、创建/最后使用/到期（最多 100 条）。
  - `audit`：最近 500 条。
- `admin.key`（0600）：32 字节随机 hex；不写入 `state.json`，不在 API 响应之外持久化；也不写入日志（日志只有掩码）。
- `setup.token`（0600）：仅在未初始化时存在的一次性 WebUI 初始化令牌；初始化成功后删除。**唯一一条未初始化启动日志会带完整初始化链接**（这是全系统唯一在日志中出现完整 setup token 的地方）；能读 journald/该文件的主体会获得管理员创建能力，请按 root 级秘密保护，并在初始化后确认文件已删除。
- 浏览器只持有 `dsh_gate_session` / `dsh_gate_device` / `dsh_gate_csrf` 三个 cookie；dsh 的 `dsh-auth-*` cookie 仅存在网关进程内，请求上游时注入、响应时剥离（HTTP 与 WebSocket 握手都剥离）。
- 反代在把 Origin 改写成 dsh authority 之前，先校验入站 Origin 必须等于网关自身 authority；WebSocket 同样校验。这样同站跨源的恶意页面不能借会话 cookie 让 dsh 误判为同源。
- loopback 管理资格还要求 Host 属于 `publicUrl` / 监听地址 / localhost 的 authority，避免 DNS rebinding 页面从 loopback 读取管理 API。
- 管理页的会话通道只影响 `/__admin*`：有效的 `dsh_gate_session` 可以直接打开管理页；该通道的 POST 必须通过 CSRF 双提交，**生成配对码必须校验 6 位 TOTP**，**改密/重置 TOTP 必须校验当前密码**。`/__auth/*` 与反代/WebSocket 的规则没有变化。
- **session 即管理能力**：持有任一有效 session 即可查看设备/会话/审计、吊销设备；生成配对码还需 TOTP，改密/重置 TOTP 还需当前密码。设备 token 或 session 泄露应按管理凭据泄露处理（立即吊销设备/改密），不要把 session cookie 暴露给第三方页面或日志。
- 设备吊销时同步清空全部待用配对票据，避免吊销前签发的 ticket 在吊销后仍可兑换成新设备。
- **deviceToken / 设备 cookie 视同账号凭据**：v0.4.0 登录只校验设备 cookie + 用户名密码；更关键的是 `POST /__auth/renew` **只需要 JSON body 里的 `deviceToken`，不需要密码**，可直接换出新 session。所以 `deviceToken`/`dsh_gate_device` 泄露 = 最长 90 天的持久访问（可反复 renew），密码已知时还可直接登录。泄露立即在管理台吊销该设备；怀疑密码同时泄露时改密（会撤销全部设备与会话）。不要发到聊天或日志。网关不校验设备指纹，清 cookie/换浏览器等于新设备，需重新配对。
- 密码：scrypt（N=16384, r=8, p=1，16 字节 salt，32 字节 key），`timingSafeEqual`；最小 10 位。
- 所有票据/设备/会话 token 都是 32 字节随机数的 base64url，只存 SHA-256；比较使用常数时间比较。
- CSRF：登录与所有 loopback/会话管理写操作都要求 `x-auth-gate-csrf` 请求头与 `dsh_gate_csrf` cookie 一致；adminKey 是请求头 bearer 凭据，免 CSRF。登录页与管理页 CSP 都使用 per-response nonce，无内联事件处理器、无外部 CDN。
- 续期：`/__auth/renew` 只接受 JSON body 的 `deviceToken`，不接受 cookie 回退；该 token 属于长期 bearer，等价于第二因素，勿写日志。
- TOTP：登录不校验 TOTP；配对时验证当前 6 位码（±1 窗口），**只验证不写 `lastTotpCounter`**，因此同窗口可连续出码；`consumeTotpCounter` 仍保留在存储层但登录/配对均不调用。TOTP 失败由独立的按 IP 计数器限流。
- 开放重定向：反代只把指向 upstream authority 的 http(s) Location 改写为同源相对路径；`//evil.example`、外域、`javascript:` 等一律改为 `/`。
- 日志：脱敏，不打印密码、TOTP secret、票据、设备/会话 token、launch token；管理员密钥只打印掩码与路径，从不打印完整值。**唯一例外**：未初始化时的那一条 `setup required` 启动日志会打印完整初始化链接（含 setup token），初始化后不再出现；请限制 journald 读取权限。
- 上游 TLS：`upstreamInsecureTls: true` 只适用于本机/内网自签 dsh；如果 dsh 换成正受信证书，应改为 `false`。
- **admin.key 文件权限 = 管理权**：完整密钥只在 `$DSH_HOME/auth-gate/admin.key`（0600）；systemd journal 中只有掩码，能读 journal 不再等于能管理网关。仍请把该文件当作 root 级秘密。
- 换证书/改 `publicUrl` 后，App 内保存的旧指纹或旧设备 origin 会不匹配：需要重新扫码配对（`state.json` 里已有设备可先吊销）。
- 不要把本网关放到另一个反向代理后面：管理端的「loopback 即管理员」判断会把代理对端当成 127.0.0.1。若必须前置代理，请只使用 adminKey 头并限制网络。

## 独立运行（开发/测试）

`lib/standalone.js` 不依赖 dsh，读取 `AUTH_GATE_*` 环境变量，并用 `DSH_TOKEN_URL`（journal 里带 launch token 的 URL）或 `DSH_TOKEN`（裸 token）兑换 dsh 会话 cookie。

```bash
export AUTH_GATE_LISTEN_HOST=127.0.0.1
export AUTH_GATE_LISTEN_PORT=3456
export AUTH_GATE_UPSTREAM=https://192.0.2.10:3080
export AUTH_GATE_UPSTREAM_INSECURE_TLS=true
export AUTH_GATE_PUBLIC_URL=https://127.0.0.1:3456
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
| `AUTH_GATE_UPSTREAM` | dsh 根 URL（例如 `https://192.0.2.10:3080`） |
| `AUTH_GATE_UPSTREAM_INSECURE_TLS` | `true/false`；自签证书用 `true` |
| `AUTH_GATE_PUBLIC_URL` | 二维码/登录跳转使用的外部 origin |
| `AUTH_GATE_TLS_CERT` / `AUTH_GATE_TLS_KEY` | 同时提供则启用 HTTPS；只给一个会启动失败 |
| `AUTH_GATE_STATE_DIR` | 状态目录，默认 `$DSH_HOME/auth-gate` |
| `AUTH_GATE_ADMIN_KEY_FILE` | 管理密钥文件，默认 `<stateDir>/admin.key` |
| `AUTH_GATE_SESSION_TTL_HOURS` | 会话时长，默认 8 |
| `AUTH_GATE_DEVICE_TTL_DAYS` | 设备有效期，默认 90 |
| `AUTH_GATE_MAX_DEVICES` | 设备上限，默认 8 |
| `AUTH_GATE_PAIR_TICKET_TTL_SECONDS` | 配对票据 TTL，默认 120 |
| `AUTH_GATE_LOGIN_MAX_FAILURES` / `..._WINDOW_MINUTES` / `..._LOCK_MINUTES` | 登录锁定参数 |
| `DSH_TOKEN_URL` / `DSH_TOKEN` | 兑换 dsh cookie 的 launch URL / 裸 token |

`SIGINT`/`SIGTERM` 会优雅关闭（关闭监听、销毁 socket、落盘状态）。

## 开发与测试

本发布仓库只包含运行时源码，不包含测试代码（`tests/` 与 e2e 脚本仅在 DSH-Mobile monorepo 的
`dsh-auth-gate/tests/` 中维护）；如需回归测试，请在 monorepo 检出后运行 `npm test` 与
`bash tests/e2e-standalone.sh`。

## 版本记录

- **v0.5.0**：WebUI 首次初始化向导（`setup.token`、`/__admin` 向导页、`setup/status|begin|confirm|token`、自动配对当前浏览器）、侧边栏未初始化卡片。
- **v0.4.3**：放行 `manifest.webmanifest`、favicon、apple-touch-icon 与 `/assets/*` 的 GET/HEAD 静态资源，避免未登录浏览器 Console 401。
- **v0.4.2**：原生侧边栏面板增加错误边界、primitives fallback、`?authgate-debug=1` 调试卡与渲染回归测试。
- **v0.4.0**：TOTP 从登录移到配对环节；已配对设备登录仅需用户名 + 密码。

## 故障排查

| 现象 | 排查 |
|---|---|
| dsh 启动日志只有 `auth-gate: failed to start: …` | 看错误：端口占用、证书读取失败、`listenHost` 是通配地址、`publicUrl` 与 TLS 不匹配、state 损坏后拒绝启动。插件故意不把异常抛进 Cordis boot，dsh 本身继续可用。 |
| 登录一直 `device_required` | 该浏览器还没有设备 cookie：先在管理页生成二维码并用 DSH Mobile 扫码；或检查 `publicUrl` 是否与访问 authority 一致（设备绑定 origin）。 |
| `/__admin` 显示初始化向导而不是登录页 | 这是未初始化（`configured:false`）的正常行为：从启动日志或 `auth-gate/setup.token` 取 `#setup=<token>` 链接完成向导；初始化后页面自动恢复 302/登录。 |
| 初始化链接丢失 / 令牌过期 | 用 adminKey 或 loopback 调 `POST /__admin/api/setup/token` 取新 `setupUrl`（旧令牌与进行中的草稿立即失效）；详见「首次初始化」。 |
| setup 接口返回 409 `already_configured` | 已经初始化，写接口永久关闭；请走密码登录或 adminKey 管理。若确需重新初始化，只能停机备份/清空 `$DSH_HOME/auth-gate`（丢失账号、设备与审计），不要只删 `setup.token`。 |
| `setup.token` 仍存在但 `/__admin` 不是向导 | `state.json` 已配置；重启后 store 会自动删除残留文件。确认 `/__admin/api/state` 的 `configured`，并检查是否误删/覆盖了 state。 |
| `/__admin` 302 到登录页 | 当前浏览器没有有效网关会话。先用已配对设备完成用户名+密码登录（不再需要 TOTP）；登录后会自动回到 `/__admin`。若账号不可用，改用 loopback/adminKey 应急。未初始化时不会 302，而是直接显示向导。 |
| 左侧栏没有「认证管理」条目 | 确认 profile 的 `dsh-auth-gate` 行已加载、`package.json` 含 `exports["./client"]` 和 `dsh.client`，重启 dsh 后看启动日志有无 client bundle/组合错误；浏览器硬刷新。 |
| 「认证管理」面板空白/一直加载 | v0.4.2 起面板有错误边界，真崩溃会显示「认证管理渲染失败」卡（`error.message` + 栈前 1500 字符）并在 Console 打印 `[auth-gate]` 日志，不再是整块空白。排查顺序：① 地址栏加 `?authgate-debug=1`（或 hash `#authgate-debug`）刷新，看顶部调试卡的 `location.href/port`、`React.version`、primitives 是否加载及 real/fallback 绑定、当前渲染分支；② F12 → Console 过滤 `[auth-gate]`，复制 `render failed` / `primitive failed` 行与栈；③ 立即兜底：点错误卡「打开独立管理页 /__admin」，或直接访问 `https://<host>:3443/__admin`（同源会话可直接用）；④ 面板只在 `location.port === "3443"` 时工作，3080 显示说明卡是设计行为；仍空白则硬刷新并检查 dsh 启动日志里的 client bundle 错误。 |
| Console 报 `GET …/manifest.webmanifest 401 (Unauthorized)` / favicon 401 | v0.4.3 起网关对 `manifest.webmanifest`、favicon、apple-touch-icon 与 `/assets/*` 的 **GET/HEAD** 放行，浏览器不带登录态也能取到这些静态 dist 文件（数据/API 路由仍 401/302）。若重启后仍报 401：确认加载的是 0.4.3+（`node -e "console.log(require('./package.json').version)"`）、请求方法确为 GET/HEAD、且路径未被改写；`/api/*`、`/plugins/*`、`/__admin*` 返回 401 属预期。 |
| 从 3080 打开只看到提示 | 这是预期的优雅降级，不是故障；按提示改从 `https://<host>:3443` 访问。 |
| `admin` 页/API 403 | 三种通道都不满足：没有会话 cookie、不是 loopback、也没有 `x-auth-gate-admin-key`。用浏览器登录后访问 `/__admin`，或 curl 加 `x-auth-gate-admin-key`。会话通道的 POST 还要求 CSRF 头 + cookie。 |
| 会话通道生成配对码返回 403 `totp_required` / `totp_invalid` | 通过登录会话生成配对码时必须输入认证器当前的 6 位动态验证码；检查手机/服务器时间是否同步（±1 窗口）。也可以改用 loopback/adminKey 通道。 |
| 会话通道配对 TOTP 返回 429 `rate_limited` | 同一 IP 5 分钟内失败 5 次会锁 5 分钟；等待锁过期或改用 loopback/adminKey。 |
| 会话通道改密/重置 TOTP 返回 403 `invalid_current_password` | 凭证变更必须输入当前密码（防会话被劫持后直接轮换凭据）；也可以改用 loopback/adminKey 通道。 |
| QR 签发返回 429 `rate_limited` | 同一 IP 1 分钟内最多签发 10 次；等待窗口重置。 |
| 反代 502 `upstream_auth_failed` | 网关无法用 launch token 换到 dsh cookie：dsh 重启后 token 会变，插件的 `authenticatedUrl()` 每次重取即可；standalone 需要更新 `DSH_TOKEN_URL`。也可能是上游 TLS 校验/`upstreamInsecureTls` 配错。 |
| 上游 401 后仍 502 | 检查 dsh 的 Host/Origin fence：`upstream` 必须使用 dsh 监听地址的 authority（例如 `192.0.2.10:3080`），不能写 `127.0.0.1`，否则 dsh 签发的 cookie authority 不匹配。 |
| 登录 429 | 同一 IP+用户名 15 分钟内失败 5 次会锁 15 分钟；等待或重启网关（内存计数）。 |
| 二维码 `fp` 为空 | 未配置 `tlsCert/tlsKey`，网关以明文 HTTP 运行（日志有警告）。生产必须配 TLS，App 会拒绝空指纹。 |
| 状态文件损坏 | 网关拒绝启动，不会静默重置。先把 `state.json` 备份移走再重新初始化；不要直接覆盖。 |

## 已知限制

- **认证语义**：登录不要求 TOTP；已配对设备上「密码正确即可登录」。这是刻意的产品取舍，风险与吊销建议见「认证模型与风险」。
- **Android App（DSH Mobile）不在本包范围**：App 端扫码、证书指纹 pin、`renew` 与登出的行为需真机联调。
- 单用户、无 WebAuthn；WebUI 管理页为服务端渲染 + 原生 JS，在线状态是按 120 秒活跃窗口计算的近似值。
- 真实浏览器中的 primitives 布局、SegmentedTabs 键盘导航、剪贴板权限弹窗、QR 扫码和亮/暗主题显示，建议部署后人工确认一次。
- WebSocket 上游 401 不会像 HTTP 那样自动刷新 cookie 重试一次（HTTP 请求会先刷新，通常足够）；如需更强保证，重连即可。
- 大于 8MB 或未声明 `Content-Length`（chunked）的请求体走流式转发，不做缓冲；如果恰好在这类请求上遇到 dsh cookie 401，会返回 502 而不会重放。
- 同一个 `stateDir` 只应由一个网关进程使用；状态文件的互斥锁是进程内的。
- 网关不应直接暴露到公网；如需公网访问，建议前置 Tailscale/Caddy/防火墙，仅暴露 3443。
- 管理 API 的 loopback 信任模型不适合放在反向代理之后（见「数据与安全」）。

## License

[MIT](LICENSE) © 2026 chjy090
