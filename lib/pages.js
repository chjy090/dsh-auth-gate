/**
 * Server-rendered HTML for the login, pairing and admin pages.
 *
 * Pages are self-contained (no external assets) so the gate works on an
 * isolated LAN. Inline scripts carry a per-response CSP nonce. All dynamic
 * values are HTML-escaped; JSON handed to scripts is escaped for `</script>`.
 */

import { readFileSync } from 'node:fs';

const zh = JSON.parse(readFileSync(new URL('../locales/zh.json', import.meta.url), 'utf8'));

/**
 * Look up a UI string.
 * @param {string} key
 * @param {Record<string,string>} [values]
 * @returns {string}
 */
export function t(key, values = {}) {
  let text = zh[key] ?? key;
  for (const [name, value] of Object.entries(values)) text = text.replaceAll(`{${name}}`, String(value));
  return text;
}

export function escapeHtml(value) {
  return String(value).replace(/[&<>"']/gu, (char) => {
    switch (char) {
      case '&':
        return '&amp;';
      case '<':
        return '&lt;';
      case '>':
        return '&gt;';
      case '"':
        return '&quot;';
      default:
        return '&#39;';
    }
  });
}

/** JSON safe to embed in an inline script. */
function jsonForScript(value) {
  return JSON.stringify(value)
    .replaceAll('<', '\\u003c')
    .replaceAll('>', '\\u003e')
    .replaceAll('&', '\\u0026')
    .replaceAll('\u2028', '\\u2028')
    .replaceAll('\u2029', '\\u2029');
}

function formatTime(value) {
  if (!Number.isFinite(value) || value <= 0) return '—';
  try {
    return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short' }).format(new Date(value));
  } catch {
    return new Date(value).toISOString();
  }
}

const PAGE_CSS = `
:root{color-scheme:light dark;--bg:#f5f6f8;--card:#fff;--text:#1c1f23;--muted:#666;--accent:#2f6fed;--danger:#c62828;--border:#d9dce1}
@media (prefers-color-scheme:dark){:root{--bg:#14161a;--card:#1d2026;--text:#e8eaed;--muted:#9aa0a6;--accent:#8ab4f8;--danger:#f28b82;--border:#353a42}}
*{box-sizing:border-box}
body{margin:0;min-height:100vh;display:flex;justify-content:center;align-items:flex-start;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,"Noto Sans SC",sans-serif;padding:24px 12px}
.card{width:100%;max-width:560px;background:var(--card);border:1px solid var(--border);border-radius:14px;padding:24px;box-shadow:0 6px 24px rgba(0,0,0,.06)}
h1{font-size:20px;margin:0 0 4px}
h2{font-size:16px;margin:24px 0 8px}
.sub{color:var(--muted);margin:0 0 20px}
label{display:block;margin:14px 0 6px;font-weight:600;font-size:14px}
input{width:100%;padding:11px 12px;border:1px solid var(--border);border-radius:9px;background:transparent;color:inherit;font-size:16px}
input:focus{outline:2px solid var(--accent);outline-offset:1px}
button{margin-top:16px;width:100%;padding:12px;border:0;border-radius:9px;background:var(--accent);color:#fff;font-size:16px;font-weight:600;cursor:pointer}
button:disabled{opacity:.55;cursor:default}
button.secondary{background:transparent;color:var(--accent);border:1px solid var(--accent);width:auto;padding:8px 12px;font-size:14px;margin:0}
button.inline{width:auto;margin-top:0;padding:10px 18px;font-size:15px}
button.danger{background:transparent;color:var(--danger);border:1px solid var(--danger);width:auto;padding:6px 10px;font-size:13px;margin:0}
.hint{color:var(--muted);font-size:13px;margin:16px 0 0}
.msg{margin-top:14px;min-height:1.2em;font-size:14px}
.msg.error{color:var(--danger)}
.msg.ok{color:#2e7d32}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
pre{overflow:auto;background:rgba(127,127,127,.12);padding:10px;border-radius:8px;white-space:pre-wrap;word-break:break-all}
.qr{display:flex;justify-content:center;margin:16px 0}
.qr svg{width:240px;height:240px;background:#fff;padding:8px;border-radius:8px}
table{width:100%;border-collapse:collapse;margin-top:10px;font-size:13px}
th,td{text-align:left;padding:7px 6px;border-bottom:1px solid var(--border);vertical-align:top}
th{color:var(--muted);font-weight:600}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
.kv{display:grid;grid-template-columns:max-content 1fr;gap:6px 14px;margin-top:10px;font-size:14px}
.kv dt{color:var(--muted)}
.kv dd{margin:0;word-break:break-all}
hr{border:0;border-top:1px solid var(--border);margin:22px 0}
.card.admin{max-width:980px}
.topbar{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:10px;margin:16px 0 4px;padding:14px;border:1px solid var(--border);border-radius:10px;background:rgba(127,127,127,.06)}
.topbar div{font-size:13px;color:var(--muted)}
.topbar strong{display:block;margin-top:2px;color:var(--text);font-size:15px;font-weight:600;word-break:break-all}
section.block{border-top:1px solid var(--border);margin-top:22px;padding-top:18px}
section.block h2{margin-top:0}
.form-grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:0 14px}
.form-grid .wide{grid-column:1/-1}
select{width:100%;padding:11px 12px;border:1px solid var(--border);border-radius:9px;background:var(--card);color:inherit;font-size:15px}
.table-wrap{width:100%;overflow-x:auto}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:12px;line-height:1.5;border:1px solid var(--border);color:var(--muted);white-space:nowrap;margin:0 4px 4px 0}
.badge.platform{border-color:var(--accent);color:var(--accent)}
.badge.online{border-color:#2e7d32;color:#2e7d32}
.badge.offline{border-color:var(--border);color:var(--muted)}
.badge.current{border-color:var(--accent);color:var(--accent)}
.hint.warn{color:#9a6700}
@media (prefers-color-scheme:dark){
.badge.online{border-color:#81c995;color:#81c995}
.hint.warn{color:#e3b341}
.msg.ok{color:#81c995}
}
.qr-meta{margin:4px 0 10px;font-size:14px}
.qr-meta.expired{color:var(--danger);font-weight:600}
.totp-box{margin-top:14px}
.pair-url{max-height:140px}
.empty{color:var(--muted);font-size:14px;padding:10px 0}
.steps{display:flex;gap:8px;list-style:none;margin:0 0 20px;padding:0}
.steps li{flex:1;padding:8px 10px;border:1px solid var(--border);border-radius:9px;color:var(--muted);font-size:13px;text-align:center}
.steps li.active{border-color:var(--accent);color:var(--accent);font-weight:600}
.steps li.done{border-color:#2e7d32;color:#2e7d32}
[hidden]{display:none!important}
.wizard-actions{display:flex;gap:10px;align-items:center;margin-top:12px}
.wizard-actions button{margin-top:0}
@media (max-width:640px){body{padding:12px 8px}.card{padding:16px}.card.admin{max-width:100%}}
/* Embedded mode (?embed=1): the dsh sidebar page owns the outer frame, so drop
   the standalone title/description chrome and let the admin body fill the pane. */
body.embed{padding:0;align-items:stretch;min-height:100vh}
body.embed .card.admin{max-width:none;border:0;border-radius:0;box-shadow:none;padding:14px 16px;min-height:100vh}
body.embed h1,body.embed .card.admin > .sub{display:none}
body.embed .topbar{margin:0 0 2px;padding:8px 10px;gap:6px 10px}
body.embed .topbar strong{font-size:13px}
body.embed section.block{margin-top:16px;padding-top:14px}
body.embed .msg{margin-top:8px}
@media (max-width:640px){body.embed .card.admin{padding:10px 12px}}
`;

function shell({ title, body, script, nonce, embed = false }) {
  return `<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>${escapeHtml(title)} · DSH</title>
<style>${PAGE_CSS}</style>
</head>
<body${embed ? ' class="embed"' : ''}>
${body}
${script === undefined ? '' : `<script nonce="${escapeHtml(nonce)}">${script}</script>`}
</body>
</html>`;
}

/**
 * @param {{csrf:string,next:string,configured:boolean,nonce:string,loopback:boolean}} input
 */
export function loginPage(input) {
  const { csrf, next, configured, nonce, loopback } = input;
  const errorMessages = Object.fromEntries(
    ['invalid_credentials', 'device_required', 'origin_changed', 'rate_limited', 'csrf_invalid', 'not_configured', 'network'].map((code) => [
      code,
      t(`login.error.${code}`)
    ])
  );
  const body = `<main class="card">
<h1>${escapeHtml(t('login.title'))}</h1>
<p class="sub">${escapeHtml(t('login.subtitle'))}</p>
${
    configured
      ? `<form id="login-form" autocomplete="on" novalidate>
<label for="username">${escapeHtml(t('login.username'))}</label>
<input id="username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" required>
<label for="password">${escapeHtml(t('login.password'))}</label>
<input id="password" name="password" type="password" autocomplete="current-password" required>
<button id="submit" type="submit">${escapeHtml(t('login.submit'))}</button>
<div id="msg" class="msg" role="alert" aria-live="polite"></div>
</form>
<p class="hint">${escapeHtml(t('login.device_hint'))}</p>`
      : `<p class="msg error">${escapeHtml(t('login.not_configured'))}</p>`
  }
${loopback ? `<p class="hint">${escapeHtml(t('login.admin_hint'))}</p>` : ''}
</main>`;
  const script = configured
    ? `(function(){
'use strict';
var CSRF=${jsonForScript(csrf)};
var NEXT=${jsonForScript(next)};
var MESSAGES=${jsonForScript(errorMessages)};
var form=document.getElementById('login-form');
var submit=document.getElementById('submit');
var msg=document.getElementById('msg');
form.addEventListener('submit',async function(event){
  event.preventDefault();
  msg.className='msg';msg.textContent='';
  submit.disabled=true;
  try{
    var response=await fetch('/__auth/login',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json','x-auth-gate-csrf':CSRF},body:JSON.stringify({username:document.getElementById('username').value,password:document.getElementById('password').value})});
    var data={};try{data=await response.json();}catch(e){}
    if(response.ok){
      msg.className='msg ok';msg.textContent='OK';
      location.replace(NEXT||'/');
      return;
    }
    var code=data.error||('http_'+response.status);
    msg.className='msg error';
    msg.textContent=MESSAGES[code]||('登录失败（'+code+'）');
    if(response.status===429||code==='csrf_invalid'){setTimeout(function(){location.reload();},2500);}
  }catch(error){
    msg.className='msg error';msg.textContent=MESSAGES.network;
  }finally{
    submit.disabled=false;
  }
});
})();`
    : '';
  return shell({ title: t('login.title'), body, script, nonce });
}

/**
 * @param {{nonce:string}} input
 */
export function pairPage(input) {
  const body = `<main class="card">
<h1>${escapeHtml(t('pair.title'))}</h1>
<p class="sub">${escapeHtml(t('pair.subtitle'))}</p>
<form id="pair-form">
<label for="device-name">${escapeHtml(t('pair.device_name'))}</label>
<input id="device-name" type="text" maxlength="64" autocomplete="off">
<button id="pair-submit" type="submit">${escapeHtml(t('pair.confirm'))}</button>
<div id="pair-msg" class="msg" role="alert" aria-live="polite"></div>
</form>
<p class="hint">${escapeHtml(t('pair.scan_hint'))}</p>
<p class="hint">${escapeHtml(t('pair.hint'))}</p>
</main>`;
  const script = `(function(){
'use strict';
var MESSAGES={
  missing_ticket:${jsonForScript(t('pair.error.missing_ticket'))},
  invalid_ticket:${jsonForScript(t('pair.error.invalid_ticket'))},
  expired_ticket:${jsonForScript(t('pair.error.expired_ticket'))},
  device_limit:${jsonForScript(t('pair.error.device_limit'))},
  rate_limited:${jsonForScript(t('pair.error.rate_limited'))},
  network:${jsonForScript(t('pair.error.network'))}
};
var hash=location.hash.startsWith('#')?location.hash.slice(1):location.hash;
var params=new URLSearchParams(hash);
var ticket=params.get('t')||'';
var fingerprint=params.get('fp')||'';
var version=params.get('v')||'';
if(location.hash){history.replaceState(null,'',location.pathname+location.search);}
var nameInput=document.getElementById('device-name');
var ua=navigator.userAgent||'';
nameInput.value=(/Android/i.test(ua)?'Android':(/iPhone|iPad/i.test(ua)?'iOS':'浏览器'))+' 设备';
var msg=document.getElementById('pair-msg');
var submit=document.getElementById('pair-submit');
if(!ticket){msg.className='msg error';msg.textContent=MESSAGES.missing_ticket;submit.disabled=true;return;}
document.getElementById('pair-form').addEventListener('submit',async function(event){
  event.preventDefault();
  msg.className='msg';msg.textContent='';
  submit.disabled=true;
  try{
    var response=await fetch('/__auth/pair/redeem',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({ticket:ticket,deviceName:nameInput.value,platform:/Android/i.test(ua)?'android':(/iPhone|iPad/i.test(ua)?'ios':'web'),fingerprint:fingerprint,version:version})});
    var data={};try{data=await response.json();}catch(e){}
    if(response.ok){
      msg.className='msg ok';
      msg.textContent=${jsonForScript(t('pair.success'))}+'（'+data.deviceId+'）';
      submit.textContent=${jsonForScript(t('pair.success'))};
      var link=document.createElement('p');
      link.className='hint';
      link.innerHTML='<a href="/__auth/login">继续登录</a>';
      document.getElementById('pair-form').appendChild(link);
      return;
    }
    var code=data.error||'network';
    msg.className='msg error';
    msg.textContent=MESSAGES[code]||(code+'');
  }catch(error){
    msg.className='msg error';msg.textContent=MESSAGES.network;
  }finally{
    submit.disabled=false;
  }
});
})();`;
  return shell({ title: t('pair.title'), body, script, nonce: input.nonce });
}

/**
 * First-run WebUI wizard (served at `/__admin` while the gate has no user).
 *
 * The setup token is read from `location.hash` only — fragments never reach
 * the server or its logs. When the page is opened without a fragment the user
 * can paste the full link or the bare token. No secret is rendered by the
 * server; the TOTP secret/QR arrive from `POST /__admin/api/setup/begin` and
 * are displayed once, in step 2.
 * @param {{nonce:string}} input
 * @returns {string}
 */
export function setupPage(input) {
  const errorMessages = Object.fromEntries(
    [
      'setup_token_invalid',
      'totp_invalid',
      'invalid_username',
      'weak_password',
      'rate_limited',
      'already_configured',
      'forbidden_origin',
      'device_limit',
      'network'
    ].map((code) => [code, t(`setup.error.${code}`)])
  );
  const body = `<main class="card">
<h1>${escapeHtml(t('setup.title'))}</h1>
<p class="sub">${escapeHtml(t('setup.subtitle'))}</p>
<ol class="steps" id="setup-steps">
<li class="active" id="setup-tab-1">1. ${escapeHtml(t('setup.step1'))}</li>
<li id="setup-tab-2">2. ${escapeHtml(t('setup.step2'))}</li>
<li id="setup-tab-3">3. ${escapeHtml(t('setup.step3'))}</li>
</ol>
<section id="setup-panel-1">
<div id="setup-token-row" hidden>
<label for="setup-token">${escapeHtml(t('setup.token_label'))}</label>
<input id="setup-token" type="text" autocomplete="off" autocapitalize="none" spellcheck="false" placeholder="${escapeHtml(t('setup.token_placeholder'))}">
<p class="hint">${escapeHtml(t('setup.token_hint'))}</p>
</div>
<p class="hint" id="setup-token-ok" hidden>${escapeHtml(t('setup.token_from_link'))}</p>
<form id="setup-form" novalidate>
<label for="setup-username">${escapeHtml(t('setup.username'))}</label>
<input id="setup-username" name="username" type="text" autocomplete="username" autocapitalize="none" spellcheck="false" maxlength="64" required>
<label for="setup-password">${escapeHtml(t('setup.password'))}</label>
<input id="setup-password" name="password" type="password" autocomplete="new-password" minlength="10" maxlength="200" required>
<label for="setup-password2">${escapeHtml(t('setup.password_confirm'))}</label>
<input id="setup-password2" type="password" autocomplete="new-password" minlength="10" maxlength="200" required>
<button id="setup-begin" type="submit">${escapeHtml(t('setup.continue'))}</button>
<div id="setup-begin-msg" class="msg" role="alert" aria-live="polite"></div>
</form>
<p class="hint">${escapeHtml(t('setup.security_hint'))}</p>
</section>
<section id="setup-panel-2" hidden>
<h2>${escapeHtml(t('setup.scan_title'))}</h2>
<p class="hint">${escapeHtml(t('setup.scan_hint'))}</p>
<div id="setup-qr" class="qr"></div>
<label>${escapeHtml(t('setup.secret_label'))}</label>
<pre id="setup-secret"></pre>
<form id="setup-confirm-form" novalidate>
<label for="setup-totp">${escapeHtml(t('setup.totp_label'))}</label>
<input id="setup-totp" name="totp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000" required>
<button id="setup-confirm" type="submit">${escapeHtml(t('setup.confirm'))}</button>
<div id="setup-confirm-msg" class="msg" role="alert" aria-live="polite"></div>
</form>
<div class="wizard-actions"><button id="setup-back" class="secondary" type="button">${escapeHtml(t('setup.back'))}</button></div>
</section>
<section id="setup-panel-3" hidden>
<h2>${escapeHtml(t('setup.success_title'))}</h2>
<p>${escapeHtml(t('setup.success_hint'))}</p>
<p class="hint">${escapeHtml(t('setup.redirecting'))}</p>
</section>
</main>`;
  const script = `(function(){
'use strict';
var MESSAGES=${jsonForScript(errorMessages)};
var GENERIC=${jsonForScript(t('setup.error.generic'))};
var TOKEN_MISSING=${jsonForScript(t('setup.token_missing'))};
var TOKEN_INVALID=${jsonForScript(t('setup.token_invalid'))};
var PASSWORD_MISMATCH=${jsonForScript(t('setup.password_mismatch'))};
var PASSWORD_SHORT=${jsonForScript(t('setup.password_short'))};
var USERNAME_INVALID=${jsonForScript(t('setup.username_invalid'))};
var TOTP_INVALID_FORMAT=${jsonForScript(t('setup.error.totp_invalid'))};
var TOKEN='';
var hash=typeof location.hash==='string'?location.hash:'';
var match=/^#setup=([0-9a-fA-F]{64})$/.exec(hash);
if(match){TOKEN=match[1].toLowerCase();}
var tab1=document.getElementById('setup-tab-1');
var tab2=document.getElementById('setup-tab-2');
var tab3=document.getElementById('setup-tab-3');
var panel1=document.getElementById('setup-panel-1');
var panel2=document.getElementById('setup-panel-2');
var panel3=document.getElementById('setup-panel-3');
var tokenRow=document.getElementById('setup-token-row');
var tokenOk=document.getElementById('setup-token-ok');
var tokenInput=document.getElementById('setup-token');
var usernameInput=document.getElementById('setup-username');
var passwordInput=document.getElementById('setup-password');
var password2Input=document.getElementById('setup-password2');
var beginButton=document.getElementById('setup-begin');
var beginMsg=document.getElementById('setup-begin-msg');
var confirmForm=document.getElementById('setup-confirm-form');
var confirmButton=document.getElementById('setup-confirm');
var confirmMsg=document.getElementById('setup-confirm-msg');
var totpInput=document.getElementById('setup-totp');
var qrBox=document.getElementById('setup-qr');
var secretBox=document.getElementById('setup-secret');
if(TOKEN){tokenRow.hidden=true;tokenOk.hidden=false;}else{tokenRow.hidden=false;}
function setStep(step){
  tab1.className=step===1?'active':(step>1?'done':'');
  tab2.className=step===2?'active':(step>2?'done':'');
  tab3.className=step===3?'active':'';
  panel1.hidden=step!==1;
  panel2.hidden=step!==2;
  panel3.hidden=step!==3;
}
function show(element,text,isError){
  element.className=isError?'msg error':'msg';
  element.textContent=text;
}
function readToken(){
  var raw=TOKEN;
  if(!raw){
    raw=String(tokenInput.value||'').trim();
    var at=raw.indexOf('#setup=');
    if(at>=0)raw=raw.slice(at+7);
    var amp=raw.indexOf('&');
    if(amp>=0)raw=raw.slice(0,amp);
    raw=raw.trim().toLowerCase();
    if(raw.length>0&&/^[0-9a-f]{64}$/.test(raw))TOKEN=raw;
  }
  return /^[0-9a-f]{64}$/.test(raw)?raw:'';
}
function mapError(code){
  if(code==='setup_token_invalid')return MESSAGES.setup_token_invalid;
  if(code==='totp_invalid')return MESSAGES.totp_invalid;
  if(code==='invalid_username')return MESSAGES.invalid_username;
  if(code==='weak_password')return MESSAGES.weak_password;
  if(code==='rate_limited')return MESSAGES.rate_limited;
  if(code==='already_configured')return MESSAGES.already_configured;
  if(code==='forbidden_origin')return MESSAGES.forbidden_origin;
  if(code==='device_limit')return MESSAGES.device_limit;
  if(code==='network')return MESSAGES.network;
  return GENERIC;
}
function allowTokenReentry(){
  TOKEN='';
  tokenRow.hidden=false;
  tokenOk.hidden=true;
  tokenInput.value='';
  tokenInput.focus();
}
document.getElementById('setup-form').addEventListener('submit',async function(event){
  event.preventDefault();
  show(beginMsg,'',false);
  var token=readToken();
  if(!token){
    var rawInput=String(tokenInput.value||'').trim();
    show(beginMsg,(TOKEN||rawInput)===''?TOKEN_MISSING:TOKEN_INVALID,true);
    return;
  }
  var username=String(usernameInput.value||'').trim();
  var password=passwordInput.value||'';
  if(!/^[A-Za-z0-9._-]{1,64}$/.test(username)){show(beginMsg,USERNAME_INVALID,true);return;}
  if(password.length<10){show(beginMsg,PASSWORD_SHORT,true);return;}
  if(password!==password2Input.value){show(beginMsg,PASSWORD_MISMATCH,true);return;}
  beginButton.disabled=true;
  try{
    var response=await fetch('/__admin/api/setup/begin',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({token:token,username:username,password:password})});
    var data={};try{data=await response.json();}catch(e){}
    if(!response.ok){
      if(data.error==='setup_token_invalid')allowTokenReentry();
      show(beginMsg,mapError(data.error||('http_'+response.status)),true);
      return;
    }
    var svg=typeof data.qrSvg==='string'?data.qrSvg.trim():'';
    if(svg.indexOf('<svg')!==0||svg.length<64||svg.toLowerCase().indexOf('<script')>=0){show(beginMsg,GENERIC,true);return;}
    qrBox.innerHTML=svg;
    secretBox.textContent=typeof data.secretB32==='string'?data.secretB32:'';
    passwordInput.value='';password2Input.value='';
    setStep(2);
    if(typeof history.replaceState==='function')history.replaceState(null,'',location.pathname+location.search);
    totpInput.focus();
  }catch(error){
    show(beginMsg,mapError('network'),true);
  }finally{
    beginButton.disabled=false;
  }
});
confirmForm.addEventListener('submit',async function(event){
  event.preventDefault();
  show(confirmMsg,'',false);
  var token=readToken();
  if(!token){show(confirmMsg,TOKEN_INVALID,true);return;}
  var code=String(totpInput.value||'').replace(/[\\s-]/g,'');
  if(!/^[0-9]{6}$/.test(code)){show(confirmMsg,TOTP_INVALID_FORMAT,true);return;}
  confirmButton.disabled=true;
  try{
    var response=await fetch('/__admin/api/setup/confirm',{method:'POST',credentials:'same-origin',headers:{'content-type':'application/json'},body:JSON.stringify({token:token,totp:code})});
    var data={};try{data=await response.json();}catch(e){}
    if(!response.ok){
      if(data.error==='setup_token_invalid'){
        allowTokenReentry();
        setStep(1);
        show(beginMsg,MESSAGES.setup_token_invalid,true);
        return;
      }
      show(confirmMsg,mapError(data.error||('http_'+response.status)),true);
      return;
    }
    totpInput.value='';
    setStep(3);
    setTimeout(function(){location.replace('/__auth/login');},1200);
  }catch(error){
    show(confirmMsg,mapError('network'),true);
  }finally{
    confirmButton.disabled=false;
  }
});
document.getElementById('setup-back').addEventListener('click',function(){
  show(confirmMsg,'',false);
  setStep(1);
});
setStep(1);
})();`;
  return shell({ title: t('setup.title'), body, script, nonce: input.nonce });
}

const PLATFORM_LABELS = Object.freeze({
  android: '安卓',
  ios: 'iOS',
  web: '浏览器',
  browser: '浏览器'
});

/**
 * Human label for a device platform. Unknown values are shown as-is (escaped
 * by the caller), never interpreted as HTML.
 * @param {unknown} value
 * @returns {string}
 */
function platformLabel(value) {
  if (typeof value !== 'string' || value.length === 0) return '未知';
  return PLATFORM_LABELS[value.toLowerCase()] ?? value;
}

/**
 * @param {Array<object>} devices
 * @param {string|null} currentDeviceId
 * @returns {string}
 */
function devicesTableHtml(devices, currentDeviceId) {
  if (devices.length === 0) {
    return `<p class="empty">${escapeHtml('暂无设备。点击下方「生成配对二维码」，用 DSH Mobile 扫码或复制链接在浏览器中配对。')}</p>`;
  }
  return `<div class="table-wrap"><table>
<thead><tr>
<th>平台</th><th>名称</th><th>状态</th><th>创建时间</th><th>最近活跃</th><th>到期时间</th><th>操作</th>
</tr></thead>
<tbody>${devices
    .map(
      (device) => `<tr>
<td><span class="badge platform">${escapeHtml(platformLabel(device.platform))}</span></td>
<td>${escapeHtml(device.name)}<br><code>${escapeHtml(device.id)}</code></td>
<td><span class="badge ${device.online === true ? 'online' : 'offline'}">${device.online === true ? '在线' : '离线'}</span>${
        device.id === currentDeviceId ? '<span class="badge current">当前</span>' : ''
      }</td>
<td>${escapeHtml(formatTime(device.createdAt))}</td>
<td>${escapeHtml(formatTime(device.lastActiveAt ?? device.lastSeenAt))}</td>
<td>${escapeHtml(formatTime(device.expiresAt))}</td>
<td><button class="danger revoke" type="button" data-device-id="${escapeHtml(device.id)}">吊销</button></td>
</tr>`
    )
    .join('')}</tbody></table></div>`;
}

/**
 * @param {Array<object>} sessions
 * @param {Array<object>} devices
 * @returns {string}
 */
function sessionsTableHtml(sessions, devices) {
  if (sessions.length === 0) {
    return `<p class="empty">${escapeHtml('当前没有有效会话。')}</p>`;
  }
  const names = new Map(devices.map((device) => [device.id, device.name]));
  return `<div class="table-wrap"><table>
<thead><tr>
<th>设备</th><th>创建时间</th><th>最近活跃</th><th>到期时间</th><th>状态</th>
</tr></thead>
<tbody>${sessions
    .map(
      (session) => `<tr>
<td>${escapeHtml(names.get(session.deviceId) ?? session.deviceId)}<br><code>${escapeHtml(session.deviceId)}</code></td>
<td>${escapeHtml(formatTime(session.createdAt))}</td>
<td>${escapeHtml(formatTime(session.lastSeenAt))}</td>
<td>${escapeHtml(formatTime(session.expiresAt))}</td>
<td>${session.current === true ? '<span class="badge current">当前会话</span>' : '<span class="badge">有效</span>'}</td>
</tr>`
    )
    .join('')}</tbody></table></div>`;
}

/**
 * @param {Array<object>} entries
 * @returns {string}
 */
function auditTableHtml(entries) {
  if (entries.length === 0) {
    return `<p class="empty">${escapeHtml(t('admin.no_audit'))}</p>`;
  }
  return `<div class="table-wrap"><table>
<thead><tr><th>时间</th><th>类型</th><th>IP</th><th>设备</th><th>详情</th></tr></thead>
<tbody>${entries
    .map(
      (entry) => `<tr>
<td>${escapeHtml(formatTime(entry.at))}</td>
<td>${escapeHtml(entry.type)}</td>
<td>${escapeHtml(entry.ip)}</td>
<td>${escapeHtml(entry.deviceId)}</td>
<td>${escapeHtml(entry.detail)}</td>
</tr>`
    )
    .join('')}</tbody></table></div>`;
}

/**
 * WebUI management page. The page is server-rendered so the first paint works
 * without JavaScript; the inline script (CSP nonce) only adds actions, QR
 * countdown and a 20-second online-status refresh.
 *
 * All server-provided values are HTML-escaped. Dynamic data rendered by the
 * script uses `textContent`; the only `innerHTML` use is the trusted QR SVG
 * returned by this gateway.
 *
 * @param {{
 *   nonce:string,
 *   csrf:string,
 *   state:{configured:boolean,user:null|{username:string,totpConfigured:boolean,totpConfirmed:boolean},devices:Array<object>,sessionList?:Array<object>,instanceId?:string},
 *   audit?:Array<object>,
 *   serverTime?:number,
 *   channel?:'loopback'|'key'|'session',
 *   requiresCurrentPassword?:boolean,
 *   requiresPairingTotp?:boolean,
 *   pairTicketTtlSeconds?:number,
 *   adminKeyRevealed?:boolean,
 *   network?:{listenHost:string,listenPort:number,publicUrl:string,tlsConfigured:boolean,source:'config'|'override',publicFingerprint?:string,effectiveFingerprint?:string,fingerprintHint?:string},
 *   embed?:boolean
 * }} input
 */
export function adminPage(input) {
  const { state, csrf, nonce } = input;
  const configured = state.configured === true;
  const devices = Array.isArray(state.devices) ? state.devices : [];
  const sessions = Array.isArray(state.sessionList) ? state.sessionList : [];
  const audit = Array.isArray(input.audit) ? input.audit : [];
  const channel = input.channel ?? 'loopback';
  const requiresCurrentPassword = input.requiresCurrentPassword === true;
  const requiresPairingTotp = input.requiresPairingTotp === true;
  const serverTime = Number.isFinite(input.serverTime) ? input.serverTime : Date.now();
  const currentSession = sessions.find((session) => session.current === true) ?? null;
  const currentDeviceId = typeof currentSession?.deviceId === 'string' ? currentSession.deviceId : null;
  const channelLabel = channel === 'session' ? '登录会话' : channel === 'key' ? '管理密钥' : '本机 loopback';
  // Embedded in the dsh sidebar: drop the standalone shell chrome but keep the
  // same server-rendered admin body, CSRF token and nonce-scoped script.
  const embed = input.embed === true;
  const network = input.network ?? {
    listenHost: '',
    listenPort: '',
    publicUrl: '',
    tlsConfigured: false,
    source: 'config',
    publicFingerprint: '',
    effectiveFingerprint: '',
    fingerprintHint: ''
  };
  const networkSourceLabel = network.source === 'override' ? '运行时覆盖（network.json）' : '插件配置（cordis.patch.yml）';
  const networkProtocolHint = network.tlsConfigured ? '必须使用 https' : '必须使用 http';

  const bootstrapSection = configured
    ? ''
    : `<section class="block">
<h2>${escapeHtml(t('admin.bootstrap_title'))}</h2>
<p class="hint">${escapeHtml(t('admin.bootstrap_hint'))}</p>
<form id="bootstrap-form" novalidate>
<div class="form-grid">
<div><label for="bootstrap-username">${escapeHtml(t('admin.username'))}</label>
<input id="bootstrap-username" name="username" autocomplete="username" autocapitalize="none" maxlength="64" required></div>
<div><label for="bootstrap-password">${escapeHtml(t('admin.password'))}</label>
<input id="bootstrap-password" name="password" type="password" autocomplete="new-password" minlength="10" maxlength="200" required></div>
<div><label for="bootstrap-password2">${escapeHtml(t('admin.password_confirm'))}</label>
<input id="bootstrap-password2" type="password" autocomplete="new-password" minlength="10" maxlength="200" required></div>
</div>
<button id="bootstrap-submit" type="submit" class="inline">${escapeHtml(t('admin.create'))}</button>
</form>
<div id="bootstrap-result"></div>
</section>`;

  const accountSection = configured
    ? `<section id="section-account" class="block">
<h2>${escapeHtml(t('admin.user'))}与密码</h2>
<p class="hint">${escapeHtml(
      requiresCurrentPassword
        ? '通过登录会话访问时，修改密码或重置 TOTP 必须输入当前密码。'
        : '本机/管理密钥通道可不填当前密码；管理密钥等同于 bearer 凭据，请妥善保管。'
    )}</p>
<form id="password-form" novalidate>
<div class="form-grid">
<div><label for="current-password">当前密码${requiresCurrentPassword ? '（必填）' : '（可留空）'}</label>
<input id="current-password" type="password" autocomplete="current-password" maxlength="512"${requiresCurrentPassword ? ' required' : ''}></div>
<div><label for="new-password">${escapeHtml(t('admin.new_password'))}</label>
<input id="new-password" type="password" autocomplete="new-password" minlength="10" maxlength="200"></div>
<div><label for="new-password2">${escapeHtml(t('admin.password_confirm'))}</label>
<input id="new-password2" type="password" autocomplete="new-password" minlength="10" maxlength="200"></div>
</div>
<div class="row">
<button id="password-submit" type="submit" class="inline">${escapeHtml(t('admin.change_password'))}</button>
<button id="reset-totp" class="secondary" type="button">${escapeHtml(t('admin.reset_totp'))}</button>
</div>
<p class="hint warn">修改密码或重置 TOTP 后，全部已配对设备与会话会被立即撤销，所有设备需重新扫码后再登录。</p>
<div id="totp-result"></div>
</form>
</section>`
    : '';

  const pairSection = configured
    ? `<section id="section-pair" class="block">
<h2>配对</h2>
<p class="hint">生成一次性配对验证码。二维码供 DSH Mobile 扫码；同一条配对链接在浏览器打开即可完成浏览器设备配对。票据仅存在于 URL fragment，有效期 ${escapeHtml(
        String(input.pairTicketTtlSeconds ?? 120)
      )} 秒左右。</p>
<p class="hint">${
        requiresPairingTotp
          ? '通过登录会话生成配对码时必须输入认证器 App 当前的 6 位动态验证码；它只用于本次校验，不会写入配对链接或日志。设备配对本身即第二因素，配对后登录只需用户名 + 密码。'
          : '本机 / 管理密钥通道可不填动态验证码；管理密钥等同 bearer 凭据，请妥善保管。'
      }</p>
<div class="form-grid">
<div class="wide"><label for="pair-totp">6 位动态验证码${requiresPairingTotp ? '（生成配对码必填）' : '（仅登录会话通道需要）'}</label>
<input id="pair-totp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000"${requiresPairingTotp ? ' required' : ''}></div>
</div>
<div class="row">
<div style="flex:1;min-width:200px"><label for="qr-platform" style="margin-top:0">设备类型</label>
<select id="qr-platform">
<option value="android">安卓设备（DSH Mobile）</option>
<option value="web">浏览器设备</option>
</select></div>
<button id="qr-button" class="secondary" type="button">生成配对二维码</button>
</div>
<div id="qr-result"></div>
</section>`
    : '';

  const networkSection = configured && input.network !== undefined
    ? `<section id="section-network" class="block">
<h2>网络设置</h2>
<p class="hint">修改网关的监听地址/端口，以及生成配对二维码/链接时使用的对外访问地址（publicUrl）。frp 内网穿透时，publicUrl 填中转的公网 IP 或域名（可带端口），而监听地址必须填网关本机实际绑定的 LAN 网卡地址（frpc 的 <code>local_ip</code> 也必须是同一地址）——二维码只使用 publicUrl，不使用监听地址。禁止监听 <code>127.0.0.1</code> / <code>::1</code>：loopback 监听加上本机 frp/反代会让公网访客被当成本机管理员。</p>
<div class="topbar">
<div>TLS 状态<strong>${network.tlsConfigured ? '已配置（HTTPS）' : '未配置（HTTP）'}</strong></div>
<div>当前来源<strong>${escapeHtml(networkSourceLabel)}</strong></div>
<div>当前监听<strong><code>${escapeHtml(`${network.listenHost}:${network.listenPort}`)}</code></strong></div>
<div>对外访问地址<strong><code>${escapeHtml(String(network.publicUrl))}</code></strong></div>
</div>
<form id="network-form" novalidate>
<div class="form-grid">
<div><label for="network-listen-host">监听地址</label>
<input id="network-listen-host" type="text" autocomplete="off" spellcheck="false" value="${escapeHtml(String(network.listenHost))}" placeholder="172.16.180.14"></div>
<div><label for="network-listen-port">监听端口</label>
<input id="network-listen-port" type="number" min="1" max="65535" inputmode="numeric" value="${escapeHtml(String(network.listenPort))}" placeholder="3443"></div>
<div class="wide"><label for="network-public-url">对外访问地址（publicUrl）</label>
<input id="network-public-url" type="text" autocomplete="off" spellcheck="false" value="${escapeHtml(String(network.publicUrl))}" placeholder="https://example.com:3443"></div>
<div class="wide"><label for="network-public-fingerprint">对外证书指纹（可选）</label>
<div class="row">
<input id="network-public-fingerprint" type="text" autocomplete="off" spellcheck="false" style="flex:1;min-width:240px" value="${escapeHtml(
      String(network.publicFingerprint ?? '')
    )}" placeholder="留空 = 使用网关自身证书；经 frp/Caddy 终止 TLS 时填 64 位 SHA-256">
<button id="network-fingerprint-auto" class="secondary" type="button">从对外地址自动读取</button>
</div>
<p class="hint">用于配对二维码里的 <code>fp=</code>：留空表示使用网关自身 TLS 证书；当 TLS 在 frp/反向代理（如 Caddy）处终止时，填代理证书的 SHA-256 DER 指纹（64 位十六进制，大小写自动归一）。点「从对外地址自动读取」会用当前已保存的 publicUrl 建立 TLS 连接并读取对端证书——证书续期后需重新读取，否则 App 会因指纹不匹配拒绝配对。</p>
</div>
<div class="wide"><p class="hint">二维码当前生效指纹 <code id="network-effective-fingerprint">${escapeHtml(
      String(network.effectiveFingerprint ?? '')
    )}</code> ${escapeHtml(String(network.fingerprintHint ?? ''))}</p></div>
<div class="wide"><label for="network-totp">6 位动态验证码${requiresPairingTotp ? '（会话通道必填）' : '（管理密钥通道可留空）'}</label>
<input id="network-totp" type="text" inputmode="numeric" pattern="[0-9]{6}" maxlength="6" autocomplete="one-time-code" placeholder="000000"${requiresPairingTotp ? ' required' : ''}></div>
</div>
<p class="hint">用于生成配对二维码/链接；frp 中转时填中转公网 IP/域名。地址必须是 <code>http(s)://host[:port]</code> 形式的纯 origin，不能带路径、查询、片段或凭据；TLS ${network.tlsConfigured ? '已配置，' : '未配置，'}${networkProtocolHint}。监听地址必须是本机 LAN 网卡的具体 IPv4/IPv6 字面量（禁止 <code>127.0.0.1</code>/<code>::1</code> 与 <code>0.0.0.0</code>/<code>::</code>）；端口 1–65535，且不能等于 dsh 上游端口。</p>
<p class="hint warn">修改监听地址/端口会关闭旧监听并用新地址立即重建，当前连接会短暂中断；保存成功后请稍后刷新页面，或使用新的地址重新访问。只改 publicUrl 不会断开连接。</p>
<div class="row"><button id="network-submit" type="submit" class="inline">保存网络设置</button></div>
<div id="network-result"></div>
</form>
</section>`
    : '';

  const devicesSection = configured
    ? `<section id="section-devices" class="block">
<h2>${escapeHtml(t('admin.devices'))}</h2>
<p class="hint">在线 = 最近 120 秒内有请求；「当前」= 本次管理会话所在的设备。吊销后该设备的会话立即失效。</p>
<div id="devices-table">${devicesTableHtml(devices, currentDeviceId)}</div>
</section>`
    : '';

  const sessionsSection = configured
    ? `<section id="section-sessions" class="block">
<h2>会话</h2>
<p class="hint">当前网关会话（按最近活跃排序，最多 100 条，不展示 token）。</p>
<div id="sessions-table">${sessionsTableHtml(sessions, devices)}</div>
</section>`
    : '';

  const auditSection = configured
    ? `<section id="section-audit" class="block">
<h2>${escapeHtml(t('admin.audit'))}（当前 ${audit.length} 条）</h2>
<button id="audit-button" class="secondary" type="button">${escapeHtml(t('common.refresh'))}</button>
<div id="audit-table">${auditTableHtml(audit)}</div>
</section>`
    : '';

  const body = `<main class="card admin">
<h1>${escapeHtml(t('admin.title'))}</h1>
<p class="sub">WebUI 管理页 · 登录后访问 · 功能：账号、配对、设备、会话、审计</p>
<div class="topbar">
<div>登录用户<strong>${escapeHtml(state.user?.username ?? (configured ? '—' : '未初始化'))}</strong></div>
<div>TOTP 状态<strong>${state.user?.totpConfigured === true ? '已配置' : '未配置'}</strong></div>
<div>访问通道<strong>${escapeHtml(channelLabel)}</strong></div>
<div>实例 ID<strong><code>${escapeHtml(state.instanceId ?? '—')}</code></strong></div>
<div>服务器时间<strong>${escapeHtml(formatTime(serverTime))}</strong></div>
</div>
<div id="admin-msg" class="msg" role="alert" aria-live="polite"></div>
${bootstrapSection}
${accountSection}
${pairSection}
${networkSection}
${devicesSection}
${sessionsSection}
${auditSection}
</main>`;

  const messages = {
    invalid_current_password: '当前密码不正确。',
    totp_required: '请输入 6 位动态验证码。',
    totp_invalid: '动态验证码不正确或已过期。',
    csrf_invalid: t('admin.csrf_error'),
    weak_password: t('admin.error.weak_password'),
    no_user: t('admin.error.no_user'),
    device_not_found: t('admin.error.device_not_found'),
    forbidden: '没有权限执行该操作。',
    loopback_only: '该接口仅限本机（loopback）访问；若网关监听 loopback，本机自动管理通道会被禁用。',
    already_configured: t('admin.error.already_configured'),
    invalid_username: t('admin.error.invalid_username'),
    bad_request: '请求格式不正确。',
    rate_limited: t('admin.error.rate_limited'),
    invalid_listen_host: t('admin.network.error.invalid_listen_host'),
    listen_host_loopback_not_allowed: t('admin.network.error.listen_host_loopback_not_allowed'),
    invalid_listen_port: t('admin.network.error.invalid_listen_port'),
    invalid_public_url: t('admin.network.error.invalid_public_url'),
    invalid_public_fingerprint: t('admin.network.error.invalid_public_fingerprint'),
    fingerprint_fetch_failed: t('admin.network.error.fingerprint_fetch_failed'),
    rebind_failed: t('admin.network.error.rebind_failed'),
    network_persist_failed: t('admin.network.error.network_persist_failed'),
    no_changes: t('admin.network.error.no_changes'),
    origin_changed: t('admin.network.error.origin_changed'),
    generic: t('admin.error.generic')
  };

  const script = `(function(){
'use strict';
var CSRF=${jsonForScript(csrf)};
var CONFIG=${jsonForScript({ configured, requiresCurrentPassword, requiresPairingTotp, channel })};
var MESSAGES=${jsonForScript(messages)};
var PLATFORM=${jsonForScript(PLATFORM_LABELS)};
var message=document.getElementById('admin-msg');
var polling=CONFIG.configured;
function show(text,ok){
  if(!message)return;
  message.className='msg '+(ok?'ok':'error');
  message.textContent=text;
}
function api(path,method,body){
  var options={method:method||'GET',credentials:'same-origin',headers:{}};
  if(method==='POST'){options.headers['x-auth-gate-csrf']=CSRF;}
  if(body!==undefined){options.headers['content-type']='application/json';options.body=JSON.stringify(body);}
  return fetch(path,options).then(function(response){
    return response.json().catch(function(){return {};}).then(function(data){
      if(!response.ok){
        var code=data.error||('http_'+response.status);
        var error=new Error(MESSAGES[code]||('操作失败（'+code+'）'));
        error.code=code;
        throw error;
      }
      return data;
    });
  });
}
function formatTime(value){
  if(typeof value!=='number'||!isFinite(value)||value<=0)return '—';
  try{return new Date(value).toLocaleString('zh-CN');}catch(e){return new Date(value).toISOString();}
}
function platformLabel(value){
  if(typeof value!=='string'||value.length===0)return '未知';
  return PLATFORM[value.toLowerCase()]||value;
}
function appendCell(row,value,className){
  var cell=document.createElement('td');
  cell.textContent=value===undefined||value===null?'':String(value);
  if(className)cell.className=className;
  row.appendChild(cell);
  return cell;
}
function tableShell(headers){
  var wrap=document.createElement('div');wrap.className='table-wrap';
  var table=document.createElement('table');
  var thead=document.createElement('thead');var headRow=document.createElement('tr');
  headers.forEach(function(label){var th=document.createElement('th');th.textContent=label;headRow.appendChild(th);});
  thead.appendChild(headRow);table.appendChild(thead);
  var body=document.createElement('tbody');table.appendChild(body);wrap.appendChild(table);
  return {wrap:wrap,body:body};
}
function emptyHint(text){
  var p=document.createElement('p');p.className='empty';p.textContent=text;return p;
}
function currentDeviceId(data){
  var current=null;
  ((data&&data.sessionList)||[]).forEach(function(session){if(session.current)current=session.deviceId;});
  return current;
}
function renderDevices(data){
  var host=document.getElementById('devices-table');
  if(!host)return;
  host.textContent='';
  var devices=(data&&data.devices)||[];
  if(devices.length===0){host.appendChild(emptyHint('暂无设备。点击下方「生成配对二维码」，用 DSH Mobile 扫码或复制链接在浏览器中配对。'));return;}
  var current=currentDeviceId(data);
  var parts=tableShell(['平台','名称','状态','创建时间','最近活跃','到期时间','操作']);
  devices.forEach(function(device){
    var row=document.createElement('tr');
    var platformCell=document.createElement('td');
    var platformBadge=document.createElement('span');platformBadge.className='badge platform';platformBadge.textContent=platformLabel(device.platform);
    platformCell.appendChild(platformBadge);row.appendChild(platformCell);
    var nameCell=document.createElement('td');
    nameCell.appendChild(document.createTextNode(device.name||''));
    nameCell.appendChild(document.createElement('br'));
    var idCode=document.createElement('code');idCode.textContent=device.id||'';nameCell.appendChild(idCode);
    row.appendChild(nameCell);
    var statusCell=document.createElement('td');
    var onlineBadge=document.createElement('span');onlineBadge.className='badge '+(device.online===true?'online':'offline');onlineBadge.textContent=device.online===true?'在线':'离线';
    statusCell.appendChild(onlineBadge);
    if(current===device.id){var currentBadge=document.createElement('span');currentBadge.className='badge current';currentBadge.textContent='当前';statusCell.appendChild(currentBadge);}
    row.appendChild(statusCell);
    appendCell(row,formatTime(device.createdAt));
    appendCell(row,formatTime(typeof device.lastActiveAt==='number'?device.lastActiveAt:device.lastSeenAt));
    appendCell(row,formatTime(device.expiresAt));
    var actionCell=document.createElement('td');
    var button=document.createElement('button');button.type='button';button.className='danger revoke';button.setAttribute('data-device-id',device.id);button.textContent='吊销';
    actionCell.appendChild(button);row.appendChild(actionCell);
    parts.body.appendChild(row);
  });
  host.appendChild(parts.wrap);
}
function renderSessions(data){
  var host=document.getElementById('sessions-table');
  if(!host)return;
  host.textContent='';
  var sessions=(data&&data.sessionList)||[];
  if(sessions.length===0){host.appendChild(emptyHint('当前没有有效会话。'));return;}
  var names={};
  ((data&&data.devices)||[]).forEach(function(device){names[device.id]=device.name;});
  var parts=tableShell(['设备','创建时间','最近活跃','到期时间','状态']);
  sessions.forEach(function(session){
    var row=document.createElement('tr');
    var deviceCell=document.createElement('td');
    deviceCell.appendChild(document.createTextNode(names[session.deviceId]||session.deviceId));
    deviceCell.appendChild(document.createElement('br'));
    var idCode=document.createElement('code');idCode.textContent=session.deviceId||'';deviceCell.appendChild(idCode);
    row.appendChild(deviceCell);
    appendCell(row,formatTime(session.createdAt));
    appendCell(row,formatTime(session.lastSeenAt));
    appendCell(row,formatTime(session.expiresAt));
    var stateCell=document.createElement('td');
    var badge=document.createElement('span');badge.className='badge'+(session.current===true?' current':'');
    badge.textContent=session.current===true?'当前会话':'有效';stateCell.appendChild(badge);
    row.appendChild(stateCell);
    parts.body.appendChild(row);
  });
  host.appendChild(parts.wrap);
}
function refreshState(){
  if(!polling)return;
  api('/__admin/api/state','GET').then(function(data){
    renderDevices(data);renderSessions(data);
  }).catch(function(error){
    if(error&&(error.code==='forbidden'||error.code==='loopback_only')){
      polling=false;
      show('会话已失效，请重新登录后访问管理页。',false);
    }
  });
}
function renderAudit(entries){
  var host=document.getElementById('audit-table');
  if(!host)return;
  host.textContent='';
  if(!entries||entries.length===0){host.appendChild(emptyHint(${jsonForScript(t('admin.no_audit'))}));return;}
  var parts=tableShell(['时间','类型','IP','设备','详情']);
  entries.forEach(function(entry){
    var row=document.createElement('tr');
    appendCell(row,formatTime(entry.at));
    appendCell(row,entry.type);
    appendCell(row,entry.ip);
    appendCell(row,entry.deviceId);
    appendCell(row,entry.detail);
    parts.body.appendChild(row);
  });
  host.appendChild(parts.wrap);
}
function renderTotp(target,data){
  if(!target)return;
  target.textContent='';
  var box=document.createElement('div');box.className='totp-box';
  if(data&&data.qrSvg){var qr=document.createElement('div');qr.className='qr';qr.innerHTML=data.qrSvg;box.appendChild(qr);}
  if(data&&data.secretB32){var secret=document.createElement('pre');secret.textContent=${jsonForScript('密钥（Base32）')}+': '+data.secretB32;box.appendChild(secret);}
  if(data&&data.otpauthUri){var uri=document.createElement('pre');uri.textContent='otpauth URI: '+data.otpauthUri;box.appendChild(uri);}
  target.appendChild(box);
}
function copyText(text){
  function fallback(){
    var area=document.createElement('textarea');
    area.value=text;
    area.setAttribute('readonly','');
    area.style.position='fixed';area.style.opacity='0';
    document.body.appendChild(area);area.select();
    var ok=false;
    try{ok=document.execCommand('copy');}catch(e){ok=false;}
    area.remove();
    if(ok)show('配对链接已复制。',true);
    else prompt('复制配对链接（Ctrl/Cmd+C）',text);
  }
  if(navigator.clipboard&&navigator.clipboard.writeText){
    navigator.clipboard.writeText(text).then(function(){show('配对链接已复制。',true);},fallback);
  }else{
    fallback();
  }
}
var qrTimer=null;
function renderQr(data){
  var target=document.getElementById('qr-result');
  if(!target)return;
  target.textContent='';
  var qr=document.createElement('div');qr.className='qr';qr.innerHTML=data.qrSvg||'';target.appendChild(qr);
  var meta=document.createElement('p');meta.className='qr-meta';target.appendChild(meta);
  var actions=document.createElement('div');actions.className='row';
  var copyButton=document.createElement('button');copyButton.type='button';copyButton.className='secondary';copyButton.textContent='复制配对链接';
  copyButton.addEventListener('click',function(){copyText(data.url);});actions.appendChild(copyButton);
  target.appendChild(actions);
  var url=document.createElement('pre');url.className='pair-url';url.textContent=data.url;target.appendChild(url);
  var hint=document.createElement('p');hint.className='hint';hint.textContent='同一条链接在浏览器中打开即可配对浏览器设备；二维码用于 DSH Mobile 扫码。';
  target.appendChild(hint);
  function tick(){
    var left=Math.ceil((data.expiresAt-Date.now())/1000);
    if(left>0){meta.className='qr-meta';meta.textContent='剩余 '+left+' 秒';return;}
    meta.className='qr-meta expired';meta.textContent='已过期，请重新生成。';
    if(qrTimer!==null){clearInterval(qrTimer);qrTimer=null;}
  }
  tick();
  if(qrTimer!==null){clearInterval(qrTimer);qrTimer=null;}
  qrTimer=setInterval(tick,1000);
}
var bootstrap=document.getElementById('bootstrap-form');
if(bootstrap){
  bootstrap.addEventListener('submit',function(event){
    event.preventDefault();
    var passwordInput=document.getElementById('bootstrap-password');
    var confirmInput=document.getElementById('bootstrap-password2');
    if(!passwordInput||!confirmInput)return;
    if(passwordInput.value!==confirmInput.value){show('两次输入的密码不一致。',false);return;}
    var submit=document.getElementById('bootstrap-submit');
    if(submit)submit.disabled=true;
    api('/__admin/api/bootstrap','POST',{
      username:document.getElementById('bootstrap-username').value,
      password:passwordInput.value
    }).then(function(data){
      show(${jsonForScript(t('admin.bootstrap_success'))},true);
      renderTotp(document.getElementById('bootstrap-result'),data);
    }).catch(function(error){show(error.message,false);}).then(function(){if(submit)submit.disabled=false;});
  });
}
var passwordForm=document.getElementById('password-form');
if(passwordForm){
  passwordForm.addEventListener('submit',function(event){
    event.preventDefault();
    var current=document.getElementById('current-password');
    var first=document.getElementById('new-password');
    var second=document.getElementById('new-password2');
    var submit=document.getElementById('password-submit');
    if(!first||!second)return;
    if(CONFIG.requiresCurrentPassword&&(!current||current.value.length===0)){show('请输入当前密码。',false);return;}
    if(first.value.length<10){show('新密码至少需要 10 位。',false);return;}
    if(first.value!==second.value){show('两次输入的新密码不一致。',false);return;}
    if(!confirm('确认修改密码？修改后将撤销全部会话与已配对设备，所有设备需重新扫码。'))return;
    var payload={password:first.value};
    if(current&&current.value.length>0)payload.currentPassword=current.value;
    if(submit)submit.disabled=true;
    api('/__admin/api/user','POST',payload).then(function(data){
      passwordForm.reset();polling=false;
      show('密码已修改：撤销 '+data.devicesRevoked+' 台设备、'+data.sessionsRevoked+' 个会话；所有设备需重新扫码。',true);
      if(CONFIG.requiresCurrentPassword){setTimeout(function(){location.replace('/__auth/login');},8000);}
    }).catch(function(error){show(error.message,false);}).then(function(){if(submit)submit.disabled=false;});
  });
}
var resetTotp=document.getElementById('reset-totp');
if(resetTotp){
  resetTotp.addEventListener('click',function(){
    if(!confirm('确认重置 TOTP？旧验证码会立即失效，全部会话与已配对设备会被撤销，所有设备需重新扫码。'))return;
    var current=document.getElementById('current-password');
    if(CONFIG.requiresCurrentPassword&&(!current||current.value.length===0)){show('请输入当前密码后再重置 TOTP。',false);return;}
    var payload={resetTotp:true};
    if(current&&current.value.length>0)payload.currentPassword=current.value;
    resetTotp.disabled=true;
    api('/__admin/api/user','POST',payload).then(function(data){
      renderTotp(document.getElementById('totp-result'),data);polling=false;
      show('TOTP 已重置：新密钥只显示这一次；全部设备与会话已撤销，所有设备需重新扫码。',true);
    }).catch(function(error){show(error.message,false);resetTotp.disabled=false;});
  });
}
var qrButton=document.getElementById('qr-button');
if(qrButton){
  qrButton.addEventListener('click',function(){
    var platformSelect=document.getElementById('qr-platform');
    var pairTotp=document.getElementById('pair-totp');
    if(CONFIG.requiresPairingTotp&&(!pairTotp||pairTotp.value.length!==6)){show('请输入 6 位动态验证码后再生成配对码。',false);return;}
    var payload={platform:platformSelect?platformSelect.value:'android'};
    if(pairTotp&&pairTotp.value.length>0)payload.totp=pairTotp.value;
    qrButton.disabled=true;
    api('/__admin/api/qr','POST',payload).then(function(data){
      renderQr(data);
      if(pairTotp)pairTotp.value='';
      qrButton.textContent='重新生成配对二维码';
      show('配对二维码已生成，请在有效期内完成扫码或打开链接。',true);
    }).catch(function(error){show(error.message,false);}).then(function(){qrButton.disabled=false;});
  });
}
var devicesHost=document.getElementById('devices-table');
if(devicesHost){
  devicesHost.addEventListener('click',function(event){
    var target=event.target;
    while(target&&target!==devicesHost&&!(target.tagName==='BUTTON'&&target.classList.contains('revoke'))){target=target.parentElement;}
    if(!target||target===devicesHost)return;
    if(!confirm('确认吊销该设备？该设备的所有会话将立即失效。'))return;
    target.disabled=true;
    api('/__admin/api/devices/revoke','POST',{deviceId:target.getAttribute('data-device-id')}).then(function(){
      show('设备已吊销，其会话与续期已立即失效。',true);
      refreshState();
    }).catch(function(error){show(error.message,false);target.disabled=false;});
  });
}
var auditButton=document.getElementById('audit-button');
if(auditButton){
  auditButton.addEventListener('click',function(){
    api('/__admin/api/audit','GET').then(function(data){
      renderAudit(data.audit||[]);
      show('审计日志已刷新。',true);
    }).catch(function(error){show(error.message,false);});
  });
}
var networkForm=document.getElementById('network-form');
if(networkForm){
  networkForm.addEventListener('submit',function(event){
    event.preventDefault();
    var hostInput=document.getElementById('network-listen-host');
    var portInput=document.getElementById('network-listen-port');
    var urlInput=document.getElementById('network-public-url');
    var fpInput=document.getElementById('network-public-fingerprint');
    var totpInput=document.getElementById('network-totp');
    var submit=document.getElementById('network-submit');
    var host=hostInput?hostInput.value.trim():'';
    var port=portInput?portInput.value.trim():'';
    var url=urlInput?urlInput.value.trim():'';
    var publicFingerprint=fpInput?fpInput.value.trim():'';
    var totp=totpInput?totpInput.value.trim():'';
    if(!host||!port||!url){show('监听地址、监听端口和对外访问地址均不能为空。',false);return;}
    if(CONFIG.requiresPairingTotp&&totp.length!==6){show('请输入 6 位动态验证码后再修改网络设置。',false);return;}
    if(!confirm('确认保存网络设置？修改监听地址/端口会立即关闭旧监听并重新绑定，当前连接会短暂中断。'))return;
    var payload={listenHost:host,listenPort:Number(port),publicUrl:url,publicFingerprint:publicFingerprint};
    if(totp.length>0)payload.totp=totp;
    if(submit)submit.disabled=true;
    api('/__admin/api/network','POST',payload).then(function(data){
      if(totpInput)totpInput.value='';
      var rebound=data&&data.rebound===true;
      show(rebound
        ? '网络设置已保存：监听地址/端口已重建，当前连接可能已断开；请稍后刷新页面或使用新地址重新访问。'
        : '网络设置已保存：下次生成配对二维码/链接将使用新的对外访问地址与指纹。',true);
      if(data&&data.network){
        var parts=document.getElementById('section-network');
        if(parts){var codes=parts.querySelectorAll('.topbar code');if(codes.length>=2){codes[0].textContent=data.network.listenHost+':'+data.network.listenPort;codes[1].textContent=data.network.publicUrl;}}
        if(fpInput)fpInput.value=String(data.network.publicFingerprint||'');
        var effective=document.getElementById('network-effective-fingerprint');
        if(effective)effective.textContent=String(data.network.effectiveFingerprint||'');
      }
      if(rebound){polling=false;}
    }).catch(function(error){show(error.message,false);}).then(function(){if(submit)submit.disabled=false;});
  });
}
var networkFingerprintAuto=document.getElementById('network-fingerprint-auto');
if(networkFingerprintAuto){
  networkFingerprintAuto.addEventListener('click',function(){
    var totpInput=document.getElementById('network-totp');
    var totp=totpInput?totpInput.value.trim():'';
    if(CONFIG.requiresPairingTotp&&totp.length!==6){show('请输入 6 位动态验证码后再读取对外证书指纹。',false);return;}
    if(!confirm('从当前已保存的对外访问地址建立 TLS 连接并读取证书指纹？读取结果会立即保存并用于之后生成的配对二维码。'))return;
    var payload={publicFingerprint:'auto'};
    if(totp.length>0)payload.totp=totp;
    networkFingerprintAuto.disabled=true;
    api('/__admin/api/network','POST',payload).then(function(data){
      if(totpInput)totpInput.value='';
      var fpInput=document.getElementById('network-public-fingerprint');
      var effective=document.getElementById('network-effective-fingerprint');
      var saved=data&&data.network?String(data.network.publicFingerprint||''):'';
      var actual=data&&data.network?String(data.network.effectiveFingerprint||''):'';
      if(fpInput)fpInput.value=saved;
      if(effective)effective.textContent=actual;
      show(saved
        ? '已读取并保存对外证书指纹：'+saved+'（实际生效：'+actual+'）。'
        : '读取完成，实际生效指纹：'+actual+'。',true);
    }).catch(function(error){show(error.message,false);}).then(function(){networkFingerprintAuto.disabled=false;});
  });
}
if(CONFIG.configured){setInterval(refreshState,20000);}
})();`;

  return shell({ title: t('admin.title'), body, script, nonce, embed });
}

/** Minimal plain-text page used for 403/404/502 responses. */
export function plainPage(title, message) {
  return `<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><title>${escapeHtml(
    title
  )}</title><style>${PAGE_CSS}</style></head><body><main class="card"><h1>${escapeHtml(title)}</h1><p class="sub">${escapeHtml(
    message
  )}</p></main></body></html>`;
}
