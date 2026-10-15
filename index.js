#!/usr/bin/env node
/**
 * TitanxBot — single-account auto-trader for Titan Exchange testnet (testnet.titanx.cc, Canton devnet).
 *
 * Files:
 *   account.json   -> INPUT only, never written by index.js:
 *                       { loginMode: "google"|"evm", twoCaptchaKey, referralCode, evmPrivateKey, proxy }
 *   config.json    -> behavior only (markets, size, timing, dryRun). Lihat "_keterangan" di dalamnya.
 *   session.json   -> AUTO-GENERATED: Auth0 tokens + cookies, API session key (ed25519), bot state.
 *   chrome-profile/-> AUTO, Chrome profile khusus `node index.js login` (bukan Chrome harian kamu).
 *   logs/          -> AUTO, log file.
 *
 * Commands:
 *   node index.js login            one-time Google login: Chrome kebuka, kamu klik Google sekali, selesai.
 *   node index.js login --manual   sama, tapi kamu buka URL sendiri lalu paste URL hasil redirect.
 *   node index.js                  jalan terus: session -> onboarding -> faucet -> loop trade.
 *   node index.js once             satu siklus lalu keluar.
 *   node index.js status           print dashboard sekali (akun / posisi / market / points) lalu keluar.
 *   node index.js selftest         cek offline canonical + signature (tanpa network).
 *
 * Transport:
 *   Cloudflare WAF on testnet-api.titanx.cc blocks Node/curl TLS fingerprints ("Sorry, you have been
 *   blocked"). `impit` impersonates Chrome TLS/H2 and passes without any cookie. The WebSocket upgrade is
 *   blocked the same way, so everything below is REST polling.
 *
 * Auth (reverse-engineered from the web bundles, testnet build 2026-10):
 *   1) Identity
 *      google -> Auth0 tenant auth.titanx.cc, client zqRjNoHqTNx0PTVMbFL9bghbJUMqRvrF, audience
 *                https://api.titanx.cc, code + PKCE. The web app keeps tokens in memory only and never
 *                asks for a refresh token, so `login` runs its OWN PKCE flow with `offline_access`.
 *                Renewal order: refresh_token -> Auth0 silent auth (prompt=none) with the SSO cookies
 *                captured during login -> ask for `login` again.
 *                Observed 2026-10-09: this tenant does NOT grant refresh tokens (offline_access ignored),
 *                and its Auth0 cookie is a 3-day ROLLING idle session. So the bot replays silent auth
 *                every auth0KeepAliveH hours to keep it alive; a missed 3-day window = run `login` again.
 *                response_mode must be `query` — `fragment` fails after Google with Auth0's "Oops" page.
 *      evm    -> personal_sign over the "Daml-Perp-Session-Auth v=2" text with account.evmPrivateKey.
 *                Fully headless forever, but it is a DIFFERENT Titan account than the Google one.
 *   2) API session: the bot generates its own ed25519 key and calls POST /v1/auth/session (unsigned,
 *      no captcha) -> { sessionId, accountId, party, expiresAt } valid 7 days. The browser's key is a
 *      non-extractable WebCrypto key, so the bot never reuses the web session — it mints its own.
 *   3) Every private call carries X-Session-Id + X-Request-Ts/Nonce/Sig: ed25519 over the
 *      "Daml-Perp-Request v=2" canonical (origin = API base, NOT the site origin). State-changing calls
 *      also carry X-Session-Sig over an action canonical (Daml-Perp-Order v=1, ...), with the same
 *      nonce/ts echoed in the JSON body.
 *
 * Onboarding (once per account, skipped automatically when already done in the browser):
 *   a) party bind: GET /v1/parties/suggest -> POST /v1/deposits/intent with X-Turnstile-Token
 *      (the ONLY captcha in the app; solved through 2captcha) -> poll until state "bound".
 *   b) referral bind: testnet is invite-only and the web's "Use Titan's" fallback code is empty on
 *      testnet, so an unbound account needs account.referralCode.
 *   c) faucet: POST /v1/me/faucet {} (no captcha). Server answers with a cooldown (Retry-After) or
 *      "balance_sufficient"; the web only offers it under 2000 USDCx.
 *
 * UI: pinned ANSI dashboard (header + akun, posisi, market, trade bot, aktivitas) redrawn in place,
 *   data refreshed every dashboardRefreshSec. Falls back to plain line logs when stdout is not a TTY
 *   (pm2 / nohup / docker) or config.dashboard is false.
 *
 * Points: live /v1/me/points shows rules `first_trade_bonus_v1` (250) and `weekly_trades_streak_v3`
 *   (server-side, not described in the web bundle — rewards trading across the week's days). The UI also
 *   mentions a weekly fee-share pool.
 *
 * Volume engine (see "volume engine" section): 1-3 concurrent positions in different markets, maker-first
 *   (post-only at the touch, re-quoted, taker IOC fallback) because fees — not speed — are what drain the
 *   account toward the faucet floor. Sizes, holds, delays, sides, sessions, breaks and a daily rest are all
 *   drawn from wide, heavy-tailed distributions re-rolled per session. Signed mutations go through one
 *   queue (serial) so action nonces stay ordered; leftovers from a crash are cancelled/flattened on start.
 */
'use strict';

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const readline = require('readline/promises');
const { AsyncLocalStorage } = require('async_hooks');
const { spawn } = require('child_process');
const { Impit } = require('impit');

const DIR = __dirname;
const ACCOUNT_FILE = path.join(DIR, 'account.json');
const ACCOUNTS_FILE = path.join(DIR, 'accounts.json'); // multi-account registry (array); absent = single account.json
const PROXY_FILE = path.join(DIR, 'proxy.txt'); // one proxy per line; account i uses line i (WAJIB di mode multi)
const CONFIG_FILE = process.env.TITANX_CONFIG ? path.resolve(process.env.TITANX_CONFIG) : path.join(DIR, 'config.json');
// Per-account state paths. Re-pointed by useAccount() so one process (login loop) or many (workers) can each
// own an isolated session/lock/profile under accounts/<label>/. Legacy single account keeps the DIR root.

const SITE = 'https://testnet.titanx.cc';
const API = 'https://testnet-api.titanx.cc';
const AUTH0_DOMAIN = 'auth.titanx.cc';
const AUTH0_CLIENT_ID = 'zqRjNoHqTNx0PTVMbFL9bghbJUMqRvrF';
const AUTH0_AUDIENCE = 'https://api.titanx.cc';
const AUTH0_SCOPE = 'openid profile email offline_access';
const TURNSTILE_SITEKEY = '0x4AAAAAAFLFXY8lYzgalHMX';
const SESSION_TTL_MS = 7 * 24 * 3600 * 1000; // Pn in session bundle
const EMPTY_SHA256 = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';
// Reasons the engine gives when a reduce-only close finds nothing left to close.
const CLOSED_REASONS = new Set(['reduce_only_no_position', 'no_opposing_position', 'no_position', 'reduce_only_exhausted', 'reduce_only_voided']);

const DEFAULT_CONFIG = {
  dryRun: false,
  markets: { 'BTC-USDCX': 5, 'SOL-USDCX': 3, 'ETH-USDCX': 3, 'CC-USDCX': 1 },
  leverage: [5, 20],
  marginUsePct: [15, 45],
  maxNotionalUsd: 120000,
  bookSharePct: 25,
  maxConcurrent: [2, 3],
  makerChance: 0.7,
  makerWaitSec: [3, 25],
  makerChaseMax: 2,
  holdSec: [3, 600],
  holdMedianSec: 25,
  delaySec: [1, 120],
  delayMedianSec: 6,
  sessionMin: [40, 180],
  breakMin: [1, 8],
  dailyRestHours: [0.5, 2],
  restWindowLocal: [2, 8],
  scaleInChance: 0.25,
  partialExitChance: 0.3,
  roundSizeChance: 0.35,
  equityFloorUsd: 200,
  maxFeesPerDayUsd: 0,
  slippagePct: 1,
  maxTradesPerDay: 0,
  minAvailableUsd: 30,
  autoFaucet: true,
  faucetBelowUsd: 2000,
  closeOnExit: true,
  maxBatchStaleSec: 3600,
  sessionRenewBeforeH: 24,
  auth0KeepAliveH: 12,
  sessionMaxNotional: '1000000',
  requestTimeoutMs: 15000,
  turnstileSolverUrl: '', // kosong = pakai 2captcha; isi URL solver lokal (mis. http://127.0.0.1:8000) = pakai Turnstile-Solver
  solverConcurrency: 0, // maks solve bareng ke solver lokal. 0 = auto (baca thread × page_count dari config.json solver)
  transientRetryMax: 3,
  transientBackoffMs: 2000,
  proxyRotate: true,
  proxyRotateAfter: 2,
  partyQueueWaitMin: 60,
  partyQueueRetrySec: 60,
  positionPollTimeoutSec: 30,
  closeRetryMax: 5,
  forbiddenPauseMin: 15,
  chromePath: '',
  auth0Connection: '',
  logFile: 'logs/titanxbot.log',
  dashboard: true,
  dashboardRefreshSec: 15,
  tradeHistory: false,
};

// ── per-account context (single-process multi-account) ──────────────────────────────────────────
// Every account runs inside als.run(C, …); all per-account state lives in C. Facades below forward
// bare `store`/`view`/`cfg`/… to the active C, so existing call sites need no change. cx() falls back
// to ROOT when no account scope is active (module init, selftest, single-account path).
const als = new AsyncLocalStorage();
function makeCtx(meta) {
  return {
    acct: meta || null,
    cfg: { ...DEFAULT_CONFIG },
    account: {},
    store: { auth0: null, session: null, state: {} },
    view: {
      account: null, accountAt: 0, mids: {}, stats: {}, statsAt: 0, points: null, pointsAt: 0, referral: null,
      volume: 0, volumeWindow: '7d', fees: 0, realizedPnl: 0, serverStatsAt: 0,
      phase: { text: 'mulai', kind: 'work', until: 0 },
    },
    plan: { sessionEndsAt: 0, breakUntil: 0, nextOpenAt: 0, intensity: 1, target: 1, sideBias: 0, weights: null, block: null, resting: null },
    slots: new Map(),
    recovering: new Set(),
    proxyPool: [],
    cur: null, impit: null, proxyIdx: 0, proxyFails: 0,
    sessionFile: path.join(DIR, 'session.json'),
    lockFile: path.join(DIR, 'session.lock'),
    profileDir: path.join(DIR, 'chrome-profile'),
    logPath: null, lastPoints: 0, forbiddenUntil: 0,
  };
}
const ROOT = makeCtx({ index: 0, label: '(utama)', stateDir: DIR, proxy: '', overrides: {}, legacy: true });
const cx = () => als.getStore() || ROOT;
const facade = (name) => new Proxy({}, {
  get: (_, k) => cx()[name][k],
  set: (_, k, v) => (cx()[name][k] = v, true),
  has: (_, k) => k in cx()[name],
  deleteProperty: (_, k) => delete cx()[name][k],
  ownKeys: () => Reflect.ownKeys(cx()[name]),
  getOwnPropertyDescriptor: (_, k) => Reflect.getOwnPropertyDescriptor(cx()[name], k),
});
const collFacade = (name) => new Proxy({}, {
  get: (_, k) => { const c = cx()[name]; const v = c[k]; return typeof v === 'function' ? v.bind(c) : v; },
});
// (facade bindings for store/view/cfg/… are wired in Task 2; nothing uses them yet)
const cfg = facade('cfg');
const account = facade('account');
const store = facade('store');
let skewMs = 0;
let lastNonce = 0;
let stopping = false;
// Cloudflare WAF (error 1020) blocks every POST to the API that lacks a cf_clearance cookie (2026-10-13). The
// cookie is issued for the whole zone (.titanx.cc, so it also covers testnet-api.titanx.cc) by solving the
// managed challenge in a real browser — the local Turnstile-Solver /clearance endpoint (camoufox). Verified NOT
// bound to the egress IP, so ONE clearance is shared by every account/proxy; refresh only on a fresh CF block.
let cfClearance = null;          // { cookie: 'cf_clearance=...', ua } attached to every API request
let cfClearanceAt = 0;           // ms when obtained; doubles as a generation counter for concurrent refresh
let cfClearanceInflight = null;  // single in-flight solve so N concurrent accounts don't all solve at once
// The local Turnstile-Solver has a fixed browser-page pool (config.json thread × page_count); asking for more
// solves at once than it has pages gets a 429 "Server penuh". This process-wide gate caps concurrent solver calls
// (Turnstile + clearance share the pool) to that capacity, so a high onboard/fleet concurrency still only asks the
// solver for as many solves as it can run. Shared across all account contexts (one process).
let solverGate = null;           // async semaphore, lazily sized to the solver's capacity
let solverCap = 0;               // cached capacity (thread × page_count), or an explicit cfg.solverConcurrency
let dash = false; // pinned dashboard active (run/once on a TTY)
let logSink = null; // when set (e.g. onboard.js), per-account log() lines go here instead of the console
const acct = facade('acct'); // per-account meta; set via cx().acct in useAccount()
const proxyPool = facade('proxyPool'); // rotation candidates (proxy.txt + whatever this account currently uses)

// ---------------------------------------------------------------------------------------------
// small utils

class FatalError extends Error { }
class NeedLoginError extends Error { }

function fail(msg) {
  log(msg, 'err');
  releaseLock();
  process.exit(1);
}

// One safe line: a pinned dashboard draws each log as a single box row, so newlines/tabs/control chars
// (e.g. a multi-line Node warning on stderr) would desync the frame height and stack boxes. Flatten them.
const oneLine = (s) => String(s).replace(/[\r\n\t]+/g, ' ').replace(/[\x00-\x08\x0b\x0c\x0e-\x1f]/g, '').slice(0, 500);

function log(msg, kind = 'info') {
  msg = oneLine(msg);
  const icon = { info: '·', ok: '✓', warn: '!', err: '✗', trade: '$' }[kind] || '·';
  const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
  if (cx().logPath) {
    try { fs.appendFileSync(cx().logPath, `${new Date().toISOString()} ${kind.toUpperCase().padEnd(5)} ${msg}\n`); } catch { }
  }
  if (fleetDash) {
    // Fleet mode: never print straight to the terminal (the pinned fleet frame owns it). Tag the line with
    // this account's label and show it in the shared activity box.
    fleetLog.push({ t, kind, label: cx().acct?.label || '-', msg: `${icon} ${msg}` });
    if (fleetLog.length > 150) fleetLog.shift();
    scheduleFleetRender();
    return;
  }
  if (dash) {
    // Never print straight to the terminal while the frame is pinned; the activity box shows it.
    LOG_LINES.push({ t, kind, msg: `${icon} ${msg}` });
    if (LOG_LINES.length > 200) LOG_LINES.shift();
    scheduleRender();
    return;
  }
  if (logSink) { try { logSink({ t, kind, label: cx().acct?.label || '-', msg: `${icon} ${msg}` }); return; } catch { } }
  (kind === 'err' || kind === 'warn' ? console.error : console.log)(`[${t}] ${icon} ${msg}`);
}

function sleep(ms) {
  // Wakes up early on Ctrl+C so a long hold/delay does not block shutdown.
  return new Promise((resolve) => {
    const end = Date.now() + ms;
    const tick = () => (stopping || Date.now() >= end ? resolve() : setTimeout(tick, Math.max(0, Math.min(250, end - Date.now()))));
    tick();
  });
}

// Polling pauses must NOT be cut short by Ctrl+C (closeOnExit still polls positions while stopping).
const wait = (ms) => new Promise((r) => setTimeout(r, Math.max(0, ms || 0)));
const num = (x) => { const n = Number(x); return Number.isFinite(n) ? n : 0; };
const pick = (arr) => arr[Math.floor(Math.random() * arr.length)];
const short = (s) => (s ? `${String(s).slice(0, 10)}…` : '-');
const utcDay = () => new Date().toISOString().slice(0, 10);

function fmtDur(ms) {
  // s = detik, m = menit, j = jam, h = hari
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 90) return `${s}s`;
  const m = Math.floor(s / 60);
  if (m < 90) return `${m}m`;
  const h = Math.floor(m / 60);
  if (h < 48) return `${h}j ${m % 60}m`;
  return `${Math.floor(h / 24)}h ${h % 24}j`;
}

function readJson(file, optional) {
  try {
    return JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (e) {
    if (optional && e.code === 'ENOENT') return null;
    throw new FatalError(`${path.basename(file)}: ${e.code === 'ENOENT' ? 'file tidak ada' : e.message}`);
  }
}

function jwtPayload(token) {
  try { return JSON.parse(Buffer.from(token.split('.')[1], 'base64url').toString('utf8')); } catch { return {}; }
}

// ---------------------------------------------------------------------------------------------
// files, lock, account roster

/** Non-empty, non-comment lines of a text file (proxy.txt). */
function readLines(file, optional) {
  let txt;
  try { txt = fs.readFileSync(file, 'utf8'); }
  catch (e) {
    if (optional && e.code === 'ENOENT') return [];
    throw new FatalError(`${path.basename(file)}: ${e.code === 'ENOENT' ? 'file tidak ada' : e.message}`);
  }
  return txt.split(/\r?\n/).map((l) => l.trim()).filter((l) => l && !l.startsWith('#'));
}

/** Point the per-account state files (session/lock/profile) at one account's dir and remember the context. */
function useAccount(ctx) {
  cx().acct = ctx;
  cx().sessionFile = path.join(ctx.stateDir, 'session.json');
  cx().lockFile = path.join(ctx.stateDir, 'session.lock');
  cx().profileDir = path.join(ctx.stateDir, 'chrome-profile');
  fs.mkdirSync(ctx.stateDir, { recursive: true });
}

/**
 * The account roster.
 *   accounts.json present (array)  -> one context per entry; proxy.txt is MANDATORY and paired by line index;
 *                                     each account gets an isolated state dir accounts/<label>/.
 *   accounts.json absent           -> a single legacy account from account.json at the DIR root (proxy optional).
 * Entry fields (label, loginMode, twoCaptchaKey, referralCode, evmPrivateKey, proxy) override account.json.
 */
/** accounts/<label>/ folders that already hold a session.json, sorted — the "copy folder & run" source. */
function listAccountDirs() {
  try {
    return fs.readdirSync(path.join(DIR, 'accounts'), { withFileTypes: true })
      .filter((d) => d.isDirectory() && fs.existsSync(path.join(DIR, 'accounts', d.name, 'session.json')))
      .map((d) => d.name).sort();
  } catch { return []; }
}

const sessionProxy = (stateDir) => readJson(path.join(stateDir, 'session.json'), true)?.session?.proxy || '';

function loadAccounts() {
  const list = readJson(ACCOUNTS_FILE, true);
  const proxies = readLines(PROXY_FILE, true);

  // 1) accounts.json present -> authoritative roster. Order fixes the default proxy pairing (account i <->
  //    proxy line i); entries may override fields. Per-account proxy = entry.proxy -> proxy stamped in the
  //    account's own session (set at login, updated by auto-rotate, so a rotated proxy survives restarts and
  //    copies) -> proxy.txt line i (first run of an account that has no session yet).
  if (Array.isArray(list) && list.length) {
    const seen = new Set();
    return list.map((a, i) => {
      const label = String(a.label || i + 1).trim().replace(/[^\w.-]+/g, '_');
      if (!label) throw new FatalError(`accounts.json: akun ke-${i + 1} label kosong.`);
      if (seen.has(label)) throw new FatalError(`accounts.json: label "${label}" dobel — tiap akun harus beda label.`);
      seen.add(label);
      const stateDir = path.join(DIR, 'accounts', label);
      const proxy = a.proxy || sessionProxy(stateDir) || proxies[i];
      if (!proxy) throw new FatalError(`akun "${label}" belum punya proxy — isi proxy.txt baris ${i + 1} (atau "proxy" di accounts.json).`);
      return { index: i, label, stateDir, proxy, overrides: a, legacy: false };
    });
  }

  // 2) No accounts.json, but accounts/<label>/session.json folders exist -> derive the roster straight from the
  //    folders. This is the "login on the laptop, copy the accounts/ folder to the VPS, just run" path:
  //    label = folder name, proxy = the one stamped in that session (fallback: proxy.txt by sorted order).
  const dirs = listAccountDirs();
  if (dirs.length) {
    return dirs.map((label, i) => {
      const stateDir = path.join(DIR, 'accounts', label);
      return { index: i, label, stateDir, proxy: sessionProxy(stateDir) || proxies[i] || '', overrides: {}, legacy: false };
    });
  }

  // 3) Nothing multi-account -> single legacy account at the DIR root (account.json enforced later by loadAll).
  const base = readJson(ACCOUNT_FILE, true) || {};
  return [{ index: 0, label: '(utama)', stateDir: DIR, proxy: base.proxy || '', overrides: {}, legacy: true }];
}

/**
 * How a stored session relates to the account label that owns its folder:
 *   'ok'       -> session.label matches this account; use it.
 *   'none'     -> no session, or an UNLABELED one (not claimed by any account) -> mint/login fresh.
 *   'mismatch' -> session.label is a DIFFERENT account (wrong folder / swapped file) -> refuse, re-login.
 * Legacy single-account sessions (DIR root, no accounts.json) are never label-checked.
 */
function sessionMatch(session, label) {
  if (!session || session.label == null) return 'none';
  return session.label === label ? 'ok' : 'mismatch';
}

// ---------------------------------------------------------------------------------------------
// proxy — per-account, with auto-rotate on repeated proxy/connect failures

function applyProxy(url) {
  const opts = { browser: 'chrome', followRedirects: false, timeout: cfg.requestTimeoutMs };
  if (url) opts.proxyUrl = url;
  cx().impit = new Impit(opts);
}

/** Build the rotation pool (proxy.txt ∪ current), point at `current`, and reset the failure counter. */
function initProxy(current) {
  cx().proxyPool = readLines(PROXY_FILE, true);
  if (current && !proxyPool.includes(current)) proxyPool.unshift(current);
  cx().proxyIdx = Math.max(0, proxyPool.indexOf(current));
  cx().proxyFails = 0;
  applyProxy(current);
}

/** Switch this account to a proxy and persist it into its session.json (so a copied folder stays correct). */
function setProxy(url) {
  if (acct) acct.proxy = url;
  if (store.session) { store.session.proxy = url || null; try { saveStore(); } catch { } }
  applyProxy(url);
}

function rotateProxy(why) {
  if (!cfg.proxyRotate) return false;
  if (proxyPool.length <= 1) { log(`proxy error (${why}) — tidak ada proxy lain di proxy.txt untuk rotate`, 'warn'); cx().proxyFails = 0; return false; }
  cx().proxyIdx = (cx().proxyIdx + 1) % proxyPool.length;
  const next = proxyPool[cx().proxyIdx];
  log(`rotate proxy (${why}) → ${maskProxy(next)} [${cx().proxyIdx + 1}/${proxyPool.length}]`, 'warn');
  setProxy(next);
  cx().proxyFails = 0;
  return true;
}

/** Count a proxy-level failure; once past the threshold, rotate to the next proxy (applied on the next call). */
function noteProxyError(why) {
  if (!cfg.proxyRotate) return false;
  return (++cx().proxyFails >= Math.max(1, cfg.proxyRotateAfter)) ? rotateProxy(why) : false;
}

const noteProxyOk = () => { cx().proxyFails = 0; };

function loadAll() {
  const c = readJson(CONFIG_FILE, true) || {};
  for (const [k, v] of Object.entries(c)) if (!k.startsWith('_')) cfg[k] = v;
  if (!acct) useAccount({ index: 0, label: '(utama)', stateDir: DIR, proxy: '', overrides: {}, legacy: true });
  // Single (legacy) mode: account.json IS the account -> required. Multi mode: it's just shared defaults for
  // accounts.json entries -> optional (handy on a VPS where you copy only accounts/ + accounts.json + proxy.txt).
  const base = readJson(ACCOUNT_FILE, !acct.legacy) || {};
  cx().account = { ...base, ...(acct.overrides || {}) }; // accounts.json entry overrides account.json defaults
  account.loginMode = String(account.loginMode || 'google').toLowerCase();
  if (!['google', 'evm'].includes(account.loginMode)) throw new FatalError('loginMode harus "google" atau "evm"');
  // Each account reads its OWN session file; reset so account B never inherits account A's session in a loop.
  const s = readJson(cx().sessionFile, true);
  cx().store = s ? { auth0: s.auth0 ?? null, session: s.session ?? null, state: s.state ?? {} } : { auth0: null, session: null, state: {} };
  if (cfg.logFile) {
    // Labelled accounts get their own logs/<label>.log; the legacy single account keeps config.logFile.
    cx().logPath = acct.legacy ? path.resolve(DIR, cfg.logFile) : path.resolve(DIR, 'logs', `${acct.label}.log`);
    fs.mkdirSync(path.dirname(cx().logPath), { recursive: true });
  }
  const proxyUrl = acct.proxy || account.proxy || '';
  // Backfill: stamp the proxy into sessions minted before proxy-stamping existed, so a copied accounts/ folder
  // stays self-contained. Then build the rotation pool (proxy.txt) pointed at this account's current proxy.
  if (!acct.legacy && store.session && !store.session.proxy && proxyUrl) { store.session.proxy = proxyUrl; try { saveStore(); } catch { } }
  initProxy(proxyUrl);
}

function saveStore() {
  const tmp = `${cx().sessionFile}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(store, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, cx().sessionFile);
}

function pidAlive(pid) {
  try { process.kill(pid, 0); return true; } catch (e) { return e.code === 'EPERM'; }
}

function acquireLock() {
  // One session key = one process. Two processes would race nonces and both trade the same account.
  let pid = 0;
  try { pid = Number(fs.readFileSync(cx().lockFile, 'utf8')); } catch { }
  if (pid && pid !== process.pid && pidAlive(pid)) fail(`Bot lain masih jalan (pid ${pid}). Matikan dulu, atau hapus session.lock kalau yakin tidak ada.`);
  fs.writeFileSync(cx().lockFile, String(process.pid));
}

function releaseLock() {
  try { if (Number(fs.readFileSync(cx().lockFile, 'utf8')) === process.pid) fs.unlinkSync(cx().lockFile); } catch { }
}

// ---------------------------------------------------------------------------------------------
// canonical strings — 1:1 copies of session-*.js helpers (U, W, G, cn, Bt, Ut, Kt, ...)

function U(k, v) { return `${k}:`.padEnd(14, ' ') + String(v); }

function W(dec) {
  // Decimal -> "<int>.<10 digits>", e.g. "0.00013" -> "0.0001300000", "-0.5" -> "-0.5000000000".
  const t = String(dec).trim();
  const m = /^(-?)(\d*)(?:\.(\d*))?$/.exec(t);
  if (!m || (m[2] === '' && (m[3] === undefined || m[3] === ''))) throw new Error(`invalid decimal "${dec}"`);
  const [, sign, int, frac = ''] = m;
  if (frac.length > 10) throw new Error(`decimal "${dec}" has more than 10 fractional digits`);
  const i = int.replace(/^0+(?=\d)/, '') || '0';
  const f = frac.padEnd(10, '0');
  return `${i === '0' && /^0*$/.test(f) ? '' : sign}${i}.${f}`;
}

function G(date) {
  // ISO timestamp with trailing zero milliseconds trimmed: ".370Z" -> ".37Z", ".000Z" -> "Z".
  return date.toISOString().replace(/\.(\d{3})Z$/, (_, ms) => { const t = ms.replace(/0+$/, ''); return t ? `.${t}Z` : 'Z'; });
}

function buildQuery(q) {
  if (!q) return '';
  return Object.entries(q)
    .filter(([, v]) => v !== undefined && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(String(v))}`)
    .join('&');
}

function canonQuery(qs) {
  const t = qs.startsWith('?') ? qs.slice(1) : qs;
  if (t === '') return '';
  const segs = t.split('&').filter((s) => s.length > 0);
  const key = (s) => { const i = s.indexOf('='); return Buffer.from(i === -1 ? s : s.slice(0, i), 'utf8'); };
  return segs.map((s) => ({ s, k: key(s) })).sort((a, b) => Buffer.compare(a.k, b.k)).map((x) => x.s).join('&');
}

const sha256hex = (s) => crypto.createHash('sha256').update(s, 'utf8').digest('hex');

function requestCanon(e) {
  return ['Daml-Perp-Request v=2', `aud: ${e.aud}`, `origin: ${e.origin}`, `session: ${e.sessionId}`, `conn: ${e.conn}`,
    `method: ${e.method}`, `path: ${e.path}`, `query: ${e.query}`, `body: ${e.bodySha256}`, `ts: ${e.ts}`, `nonce: ${e.nonce}`,
    `expires: ${e.expires}`].join('\n');
}

function sessionAuthCanon(e) {
  if (!/^[0-9a-f]{64}$/i.test(e.sessionPubKeyHex)) throw new Error('sessionPubKeyHex must be 64 hex chars (32 bytes)');
  return ['Daml-Perp-Session-Auth v=2', U('scheme', e.scheme), U('credential', e.credential), U('sessionPubKey', e.sessionPubKeyHex),
    U('expiry', G(e.expiry)), U('maxNotional', W(e.maxNotional)), U('userNonce', e.userNonce), U('label', e.label ?? '')].join('\n');
}

const attached = (p, t) => [U(`${p}Trigger`, W(t?.trigger ?? '0')), U(`${p}Limit`, W(t?.limit ?? '0')), U(`${p}Size`, W(t?.size ?? '0'))];

function orderCanon(e) {
  return ['Daml-Perp-Order v=1', U('sessionId', e.sessionId), U('market', e.market),
    U('side', e.side), U('type', e.type), U('size', W(e.size)), U('price', W(e.price)), U('tif', e.tif ?? ''),
    U('reduceOnly', e.reduceOnly === true ? 'true' : 'false'), ...attached('tp', e.tp), ...attached('sl', e.sl),
    U('clientOrderId', e.clientOrderId ?? ''), U('nonce', e.nonce), U('ts', G(e.ts))].join('\n');
}

const cancelCanon = (e) => ['Daml-Perp-Cancel v=1', U('sessionId', e.sessionId), U('orderId', e.orderId), U('nonce', e.nonce), U('ts', G(e.ts))].join('\n');
const leverageCanon = (e) => ['Daml-Perp-Leverage v=1', U('sessionId', e.sessionId), U('market', e.market), U('leverage', e.leverage), U('nonce', e.nonce), U('ts', G(e.ts))].join('\n');
const depositIntentCanon = (e) => ['Daml-Perp-Deposit-Intent v=1', U('sessionId', e.sessionId), U('hint', e.hint ?? ''), U('nonce', e.nonce), U('ts', G(e.ts))].join('\n');
const referralBindCanon = (e) => ['Daml-Perp-Referral-Bind v=1', U('sessionId', e.sessionId), U('code', e.code), U('nonce', e.nonce), U('ts', G(e.ts))].join('\n');
const revokeCanon = (e) => ['Daml-Perp-Session-Revoke v=1', U('sessionId', e.sessionId), U('target', e.target), U('nonce', e.nonce), U('ts', G(e.ts))].join('\n');

// ---------------------------------------------------------------------------------------------
// signing

function activate(s) {
  cx().cur = { sessionId: s.sessionId, key: crypto.createPrivateKey({ key: Buffer.from(s.privateKey, 'base64'), format: 'der', type: 'pkcs8' }) };
}

function edSign(text, S = cx().cur) {
  return crypto.sign(null, Buffer.from(text, 'utf8'), S.key).toString('hex');
}

function nextNonce() {
  // Web: X(sess, kind) = max(nonces[kind] + 1, Date.now()). One global counter is strictly increasing
  // for every kind, so it satisfies any per-kind replay check.
  lastNonce = Math.max(lastNonce + 1, Date.now());
  return lastNonce;
}

const serverNow = () => new Date(Date.now() + skewMs);

function requestSig(method, p, qs, bodyStr, S = cx().cur) {
  if (!S) throw new Error('signed request tanpa session aktif');
  const ts = G(serverNow());
  const nonce = String(nextNonce());
  const canon = requestCanon({
    aud: 'rest', origin: API, sessionId: S.sessionId, conn: '', method, path: p, query: canonQuery(qs),
    bodySha256: bodyStr === undefined || bodyStr.length === 0 ? EMPTY_SHA256 : sha256hex(bodyStr), ts, nonce, expires: '',
  });
  return { 'X-Session-Id': S.sessionId, 'X-Request-Ts': ts, 'X-Request-Nonce': nonce, 'X-Request-Sig': edSign(canon, S) };
}

function action(canonFn, fields, S = cx().cur) {
  // Per-action signature (the `$` helper). Returns the nonce/ts that must be echoed in the body/query.
  if (!S) throw new Error('signed action tanpa session aktif');
  const nonce = nextNonce();
  const tsDate = serverNow();
  const canon = canonFn({ sessionId: S.sessionId, ...fields, nonce, ts: tsDate });
  return { nonce, ts: G(tsDate), headers: { 'X-Session-Id': S.sessionId, 'X-Session-Sig': edSign(canon, S) } };
}

// ---------------------------------------------------------------------------------------------
// HTTP

class ApiError extends Error {
  constructor(status, p, body, { retryAfter, text, message } = {}) {
    const code = body?.error?.code;
    super(message || body?.error?.details?.message || body?.error?.message || code || body?.reason || `HTTP ${status} ${text ? text.slice(0, 120) : ''}`.trim());
    this.status = status;
    this.path = p;
    this.code = code;
    this.reason = body?.error?.details?.reason ?? body?.reason;
    this.retryAfter = retryAfter;
    this.body = body;
  }
  get transient() { return this.status === 0 || this.status === 429 || this.status >= 500 || this.code === 'read_model_stale'; }
  get deadSession() {
    return (this.status === 401 && this.code !== 'request_stale') || ['session_expired', 'engine_session_rejected'].includes(this.code);
  }
}

// The server's message can be as bare as "request refused"; the real cause sits in status/code/details.reason.
const errText = (e) => (e instanceof ApiError && e.status
  ? `${e.message} [HTTP ${e.status}${e.code ? ` ${e.code}` : ''}${e.reason && e.reason !== e.code ? `/${e.reason}` : ''} ${e.path}]`
  : e.message);

function noteForbidden(method, p) {
  // 403 forbidden on an order = the server refuses this account's trading (web: "This account can't do this
  // right now"). Retrying every loop only hammers it: pause orders + recovery for this account, then retry.
  const first = !(cx().forbiddenUntil > Date.now());
  cx().forbiddenUntil = Date.now() + Math.max(1, cfg.forbiddenPauseMin) * 60e3;
  if (first) log(`server menolak ${method} ${p} akun ini (403 forbidden) — order & recovery dijeda ${cfg.forbiddenPauseMin} menit. Kalau di web juga ditolak, akunnya diblokir server`, 'err');
}

function learnSkew(res, t0, t1) {
  // Same as client g(): server Date vs local midpoint, ignored under 5s or over 2 days.
  const d = res.headers.get('date');
  if (!d) return;
  const r = Date.parse(d) - (t0 + t1) / 2;
  if (!Number.isFinite(r) || Math.abs(r) > 1728e5) return;
  skewMs = Math.abs(r) < 5e3 ? 0 : Math.round(r);
}

async function rawFetch(url, init) {
  const t0 = Date.now();
  try {
    const res = await cx().impit.fetch(url, init);
    learnSkew(res, t0, Date.now());
    return res;
  } catch (e) {
    const err = new ApiError(0, url, null, { message: `network: ${e.message}` });
    err.code = 'network';
    err.connectFailed = /Connect|Proxy|InvalidURL/i.test(e?.constructor?.name || '');
    // Proxy-ish failures (connect, read timeout, stream decode, reset, DNS...) -> candidates for rotation.
    // Flaky/slow proxies surface as "reading response stream ... Body TimedOut" from impit (reqwest).
    err.proxyish = err.connectFailed
      || /timed?\s*out|timeout|reading response|response stream|connection (reset|closed|refused|aborted)|broken pipe|\beof\b|handshake|\bproxy\b|\bdns\b|unreachable|decode|incomplete/i.test(e?.message || '');
    throw err;
  }
}

async function api(method, p, { query, body, signed = false, headers = {}, timeoutMs, retry, as } = {}) {
  const qs = buildQuery(query);
  const url = `${API}${p}${qs ? `?${qs}` : ''}`;
  const bodyStr = body === undefined ? undefined : JSON.stringify(body);
  // Mutations are never resent after the request may have reached the server (order could fill twice);
  // 429 / connect failures are safe because nothing was processed.
  const retryable = retry ?? method === 'GET';
  let clearedRetry = false; // allow exactly one cf_clearance-refresh retry per call (any method)
  for (let attempt = 0; ; attempt++) {
    const h = {
      accept: 'application/json', origin: SITE, referer: `${SITE}/`,
      'sec-fetch-site': 'same-site', 'sec-fetch-mode': 'cors', 'sec-fetch-dest': 'empty',
      ...(bodyStr !== undefined ? { 'content-type': 'application/json' } : {}),
      ...headers,
    };
    // Attach the shared cf_clearance cookie (+ the UA that solved it) so the CF WAF lets this through. `gen`
    // snapshots the clearance generation: if this attempt is CF-blocked we refresh only when nobody else already did.
    const gen = cfClearanceAt;
    if (cfClearance) {
      h.cookie = h.cookie ? `${h.cookie}; ${cfClearance.cookie}` : cfClearance.cookie;
      if (cfClearance.ua) h['user-agent'] = cfClearance.ua;
    }
    if (signed) Object.assign(h, requestSig(method, p, method === 'GET' ? qs : '', bodyStr, as));
    let res;
    try {
      res = await rawFetch(url, { method, headers: h, ...(bodyStr !== undefined ? { body: bodyStr } : {}), timeout: timeoutMs ?? cfg.requestTimeoutMs });
    } catch (e) {
      // Retry in-call only when safe: GETs (idempotent) or a pure connect failure (nothing reached the server).
      // A read/body timeout on a mutation is NOT retried — the order may have been placed — but it still counts
      // toward rotating away from a slow proxy.
      if ((retryable || e.connectFailed) && attempt < cfg.transientRetryMax) { await sleep(cfg.transientBackoffMs * 2 ** attempt); continue; }
      if (e.proxyish) noteProxyError('timeout/connect'); // count; rotate to another proxy for the next call
      throw e;
    }
    const text = await res.text();
    let data = null;
    try { data = text ? JSON.parse(text) : null; } catch { }
    if (res.ok) {
      noteProxyOk(); // a clean response means the current proxy works — reset the failure streak
      if (data === null && text) throw new ApiError(res.status, p, null, { message: `respons bukan JSON: ${text.slice(0, 120)}` });
      return data;
    }
    const ra = res.headers.get('retry-after');
    const retryAfter = ra !== null && /^\d+$/.test(ra.trim()) ? Number(ra.trim()) : undefined;
    const err = new ApiError(res.status, p, data, { retryAfter, text });
    if (res.status === 403 && !data) {
      // CF WAF (error 1020): an edge block, served as HTML, before the request reached the app — so retrying is
      // safe even for a mutation (nothing was processed). A cf_clearance cookie clears it; fetch one from the
      // local solver and retry once. If this attempt already carried the current clearance, that clearance is
      // stale -> force a new solve; if another account refreshed it meanwhile (gen changed), just reuse theirs.
      err.message = 'diblok Cloudflare WAF (403) — perlu cf_clearance';
      if (!clearedRetry && solverBase()) {
        clearedRetry = true;
        const c = (cfClearanceAt !== gen && cfClearance)
          ? cfClearance
          : await ensureClearance(true).catch((e) => { log(`ambil cf_clearance gagal: ${e.message}`, 'warn'); return null; });
        if (c) { log('ulangi request dengan cf_clearance', 'ok'); continue; }
      }
      noteProxyError('cloudflare 403');
    }
    if (res.status === 403 && err.code === 'forbidden' && method !== 'GET' && /^\/v1\/(orders|me\/leverage)/.test(p)) noteForbidden(method, p);
    const shortWait = retryAfter === undefined || retryAfter <= 60;
    const canRetry = (res.status === 429 && shortWait) || (retryable && err.transient && shortWait);
    if (canRetry && attempt < cfg.transientRetryMax) {
      await sleep(retryAfter !== undefined ? retryAfter * 1000 : cfg.transientBackoffMs * 2 ** attempt);
      continue;
    }
    throw err;
  }
}

// ---------------------------------------------------------------------------------------------
// Titan endpoints

const pub = {
  markets: async () => (await api('GET', '/v1/markets')).markets || [],
  status: () => api('GET', '/v1/exchange/status'),
  orderbook: (m, depth = 5) => api('GET', `/v1/markets/${encodeURIComponent(m)}/orderbook`, { query: { depth } }),
  suggestHandle: () => api('GET', '/v1/parties/suggest'),
  referralCode: (c) => api('GET', `/v1/referral/codes/${encodeURIComponent(c)}`),
};

const me = {
  // /v1/me and /v1/me/referral are GETs that the web signs with a Cancel canonical (orderId ME/REFERRAL).
  identity() {
    const a = action(cancelCanon, { orderId: 'ME' });
    return api('GET', '/v1/me', { query: { nonce: a.nonce, ts: a.ts }, headers: a.headers, signed: true });
  },
  referral() {
    const a = action(cancelCanon, { orderId: 'REFERRAL' });
    return api('GET', '/v1/me/referral', { query: { nonce: a.nonce, ts: a.ts }, headers: a.headers, signed: true });
  },
  account: () => api('GET', '/v1/me/account', { signed: true }),
  async balance() {
    try { return await api('GET', '/v1/me/balance', { signed: true }); } catch (e) { if (e.status === 404) return null; throw e; }
  },
  sizing: (market, price) => api('GET', '/v1/me/sizing', { query: { market, price }, signed: true }),
  positions: async () => (await api('GET', '/v1/me/positions', { signed: true }))?.items || [],
  openOrders: async (market) => (await api('GET', '/v1/me/orders', { query: { market, limit: 100 }, signed: true, retry: false }))?.items || [],
  points: () => api('GET', '/v1/me/points', { signed: true }),
  volume: () => api('GET', '/v1/me/volume', { signed: true }), // server-truth volume (same as web /rewards), window 7d
  portfolio: () => api('GET', '/v1/me/portfolio', { signed: true }), // server-truth cumFees/cumRealizedPnl/funding time-series
  depositIntent: () => api('GET', '/v1/deposits/intent', { signed: true }),
  faucet: () => api('POST', '/v1/me/faucet', { body: {}, signed: true, timeoutMs: 35000, retry: false }),
};

// Concurrent slots share one queue for signed mutations, and the action nonce is drawn inside it, so
// nonces always reach the server in increasing order. Reads (GET) run freely, as in the web app.
let mutationChain = Promise.resolve();
function serial(fn) {
  const run = mutationChain.then(fn, fn);
  mutationChain = run.catch(() => { });
  return run;
}

function placeOrder(o) {
  if (cfg.dryRun) { log(`[dryRun] order ${JSON.stringify(o)}`); return Promise.resolve({ ok: true, fills: 0, dry: true }); }
  return serial(async () => {
    const a = action(orderCanon, o);
    try {
      return await api('POST', '/v1/orders', { body: { ...o, nonce: a.nonce, ts: a.ts }, headers: a.headers, signed: true, timeoutMs: 15000, retry: false });
    } catch (e) {
      // A refused order comes back as HTTP 400 (post-only cross, position cap, ...). Nothing was placed, so
      // return it as a normal rejection instead of killing the slot (web: FC/WC on status 400).
      if (!(e instanceof ApiError) || e.status !== 400) throw e;
      const reason = e.reason || (/post-only[^]*cross/i.test(e.message) ? 'post_only_would_cross' : e.code || 'rejected');
      return { ok: false, reason, message: errText(e) };
    }
  });
}

function cancelOrder(orderId) {
  return serial(() => {
    const a = action(cancelCanon, { orderId });
    return api('DELETE', `/v1/orders/${encodeURIComponent(orderId)}`, { body: { nonce: a.nonce, ts: a.ts }, headers: a.headers, signed: true, retry: false });
  });
}

function setLeverage(market, leverage) {
  return serial(() => {
    const a = action(leverageCanon, { market, leverage });
    return api('PUT', `/v1/me/leverage/${encodeURIComponent(market)}`, {
      body: { market, leverage, nonce: a.nonce, ts: a.ts }, headers: a.headers, signed: true, retry: false,
    });
  });
}

async function postDepositIntent(hint, turnstileToken) {
  const a = action(depositIntentCanon, { hint });
  return api('POST', '/v1/deposits/intent', {
    body: { nonce: a.nonce, ts: a.ts, ...(hint ? { hint } : {}) },
    headers: { ...a.headers, Prefer: 'respond-async', ...(turnstileToken ? { 'X-Turnstile-Token': turnstileToken } : {}) },
    signed: true, timeoutMs: 65000, retry: false,
  });
}

async function postReferralBind(code) {
  const a = action(referralBindCanon, { code });
  return api('POST', '/v1/me/referral/bind', { body: { code, nonce: a.nonce, ts: a.ts }, headers: a.headers, signed: true, retry: false });
}

async function revokeSession(old) {
  // DELETE /v1/auth/keys/{sid}, signed with the OLD key. Best effort: the old key expires anyway.
  const S = { sessionId: old.sessionId, key: crypto.createPrivateKey({ key: Buffer.from(old.privateKey, 'base64'), format: 'der', type: 'pkcs8' }) };
  const a = action(revokeCanon, { target: old.sessionId }, S);
  await api('DELETE', `/v1/auth/keys/${old.sessionId}`, { body: { nonce: a.nonce, ts: a.ts }, headers: a.headers, signed: true, retry: false, as: S });
}

// ---------------------------------------------------------------------------------------------
// numbers / grids — copies of index-*.js mC, hC, nw

function trimDec(s) { return s.includes('.') ? s.replace(/0+$/, '').replace(/\.$/, '') : s; }
function floorTo(x, d) { const n = 10 ** d; return Math.floor(x * n + 1e-9) / n; }
const fmtSize = (x, d) => trimDec(floorTo(x, d).toFixed(d));

function sizeFor(usd, px, szDec, minNotional) {
  if (!(usd > 0) || !(px > 0)) return 0;
  const a = floorTo(usd / px, szDec);
  if (!(minNotional > 0) || usd < minNotional || a * px >= minNotional) return a;
  const n = 10 ** szDec;
  return Math.ceil((minNotional / px) * n - 1e-9) / n;
}

function slipCap(best, side, tol, szDec) {
  // Market order = limit IOC at best * (1 ± tol), max 5 significant figures and max (6 - szDec) decimals.
  if (!(best > 0) || !(tol >= 0)) return null;
  const i = side === 'buy' ? best * (1 + tol) : best * (1 - tol);
  if (!(i > 0)) return null;
  const s = Math.max(0, Math.min(Math.max(0, 6 - szDec), 4 - Math.floor(Math.log10(i))));
  const c = 10 ** s;
  const l = side === 'buy' ? Math.floor(i * c) / c : Math.ceil(i * c) / c;
  return l > 0 ? l.toFixed(s) : null;
}

// ---------------------------------------------------------------------------------------------
// Auth0 (google mode)

const b64url = (buf) => Buffer.from(buf).toString('base64url');

function pkce() {
  const verifier = b64url(crypto.randomBytes(32));
  return { verifier, challenge: b64url(crypto.createHash('sha256').update(verifier).digest()) };
}

function authorizeUrl({ challenge, state, nonce, prompt, responseMode }) {
  const q = new URLSearchParams({
    client_id: AUTH0_CLIENT_ID, redirect_uri: SITE, audience: AUTH0_AUDIENCE, scope: AUTH0_SCOPE,
    response_type: 'code', response_mode: responseMode, state, nonce, code_challenge: challenge, code_challenge_method: 'S256',
  });
  if (prompt) q.set('prompt', prompt);
  if (cfg.auth0Connection) q.set('connection', cfg.auth0Connection);
  return `https://${AUTH0_DOMAIN}/authorize?${q}`;
}

function paramsFromUrl(u) {
  const p = new URLSearchParams(u.search);
  for (const [k, v] of new URLSearchParams(u.hash.replace(/^#/, ''))) p.set(k, v);
  return p;
}

async function auth0Token(params) {
  const res = await rawFetch(`https://${AUTH0_DOMAIN}/oauth/token`, {
    method: 'POST',
    headers: { 'content-type': 'application/x-www-form-urlencoded', accept: 'application/json', origin: SITE, referer: `${SITE}/` },
    body: new URLSearchParams({ client_id: AUTH0_CLIENT_ID, ...params }).toString(),
  });
  const text = await res.text();
  let data = null;
  try { data = JSON.parse(text); } catch { }
  if (!res.ok || !data?.access_token) {
    const e = new Error(`Auth0 /oauth/token ${res.status}: ${data?.error_description || data?.error || text.slice(0, 160)}`);
    e.oauth = data?.error;
    throw e;
  }
  return data;
}

function saveTokens(tok) {
  // Refresh tokens rotate: the new one is persisted before anything else touches it.
  store.auth0 = {
    ...store.auth0,
    accessToken: tok.access_token,
    accessTokenExp: Date.now() + num(tok.expires_in || 86400) * 1000,
    ...(tok.refresh_token ? { refreshToken: tok.refresh_token } : {}),
    updatedAt: new Date().toISOString(),
  };
  saveStore();
}

function setCookieList(res) {
  const h = res.headers;
  if (typeof h.getSetCookie === 'function') return h.getSetCookie();
  const raw = h.get('set-cookie');
  return raw ? raw.split(/,(?=\s*[^;,=\s]+=)/) : [];
}

function mergeCookies(cookies, res) {
  for (const line of setCookieList(res)) {
    const [pair, ...attrs] = line.split(';');
    const eq = pair.indexOf('=');
    if (eq < 1) continue;
    const name = pair.slice(0, eq).trim();
    const value = pair.slice(eq + 1).trim();
    let expires = null;
    for (const a of attrs) {
      const [k, v] = a.split('=').map((x) => x && x.trim());
      if (/^max-age$/i.test(k)) expires = Date.now() + num(v) * 1000;
      else if (/^expires$/i.test(k) && expires === null) expires = Date.parse(v) || null;
    }
    const i = cookies.findIndex((c) => c.name === name);
    if (expires !== null && expires <= Date.now()) { if (i >= 0) cookies.splice(i, 1); continue; }
    const c = { name, value, expires };
    if (i >= 0) cookies[i] = c; else cookies.push(c);
  }
}

async function silentAuth() {
  // Auth0 prompt=none with the SSO cookies from `login`: works while the Auth0 login session is alive.
  const cookies = (store.auth0?.cookies || []).filter((c) => !c.expires || c.expires > Date.now());
  if (!cookies.length) throw new Error('tidak ada cookie Auth0 tersimpan');
  const { verifier, challenge } = pkce();
  const state = b64url(crypto.randomBytes(16));
  let url = authorizeUrl({ challenge, state, nonce: b64url(crypto.randomBytes(16)), prompt: 'none', responseMode: 'query' });
  for (let hop = 0; hop < 6; hop++) {
    const res = await rawFetch(url, {
      headers: {
        cookie: cookies.map((c) => `${c.name}=${c.value}`).join('; '),
        accept: 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8', referer: `${SITE}/`,
        'sec-fetch-site': 'cross-site', 'sec-fetch-mode': 'navigate', 'sec-fetch-dest': 'document',
      },
    });
    mergeCookies(cookies, res);
    const loc = res.headers.get('location');
    if (!loc) throw new Error(`HTTP ${res.status} tanpa redirect`);
    const next = new URL(loc, url);
    if (next.origin === SITE) {
      const p = paramsFromUrl(next);
      if (p.get('error')) throw new Error(`${p.get('error')} ${p.get('error_description') || ''}`.trim());
      if (p.get('state') !== state) throw new Error('state mismatch');
      store.auth0.cookies = cookies;
      saveStore();
      return auth0Token({ grant_type: 'authorization_code', code: p.get('code'), code_verifier: verifier, redirect_uri: SITE });
    }
    if (next.hostname !== AUTH0_DOMAIN) throw new Error(`redirect tak terduga ke ${next.origin}`);
    url = next.toString();
  }
  throw new Error('kebanyakan redirect');
}

async function getAccessToken() {
  const a = store.auth0;
  if (!a) throw new NeedLoginError('belum pernah login Google');
  if (a.accessToken && num(a.accessTokenExp) - Date.now() > 5 * 60e3) return a.accessToken;
  if (a.refreshToken) {
    try {
      const tok = await auth0Token({ grant_type: 'refresh_token', refresh_token: a.refreshToken });
      saveTokens(tok);
      return tok.access_token;
    } catch (e) {
      if (e.oauth !== 'invalid_grant') throw e;
      store.auth0.refreshToken = null;
      saveStore();
      log('refresh token Auth0 ditolak (invalid_grant), coba silent auth', 'warn');
    }
  }
  if (a.cookies?.length) {
    try {
      const tok = await silentAuth();
      saveTokens(tok);
      log('access token baru via Auth0 silent auth', 'ok');
      return tok.access_token;
    } catch (e) {
      log(`silent auth gagal: ${e.message}`, 'warn');
    }
  }
  throw new NeedLoginError('token Auth0 habis dan tidak bisa diperbarui otomatis');
}

async function auth0KeepAlive() {
  // Rolls the Auth0 SSO cookie (3-day idle lifetime) so silent auth still works when the 7-day API
  // session needs renewing. Also leaves a fresh access token behind.
  if (account.loginMode !== 'google' || !store.auth0?.cookies?.length || store.auth0.refreshToken) return;
  if (Date.now() < num(store.auth0.keepAliveAt) + cfg.auth0KeepAliveH * 3600e3) return;
  try {
    saveTokens(await silentAuth());
    store.auth0.keepAliveAt = Date.now();
    saveStore();
    const exp = store.auth0.cookies.find((c) => c.name === 'auth0')?.expires;
    log(`login Auth0 diperpanjang${exp ? ` (cookie s/d ${new Date(exp).toISOString().slice(0, 16)}Z)` : ''}`, 'ok');
  } catch (e) {
    store.auth0.keepAliveAt = Date.now() - cfg.auth0KeepAliveH * 3600e3 + 3600e3; // retry in 1h
    saveStore();
    const left = store.session ? Date.parse(store.session.expiresAt) - Date.now() : 0;
    log(`perpanjang login Auth0 gagal (${e.message}). Bot tetap jalan ${fmtDur(left)} lagi (sisa session API); sebelum itu jalankan: node index.js login`, 'warn');
  }
}

function findChrome() {
  if (cfg.chromePath) return fs.existsSync(cfg.chromePath) ? cfg.chromePath : null;
  const env = process.env;
  const candidates = {
    darwin: [
      '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
      '/Applications/Brave Browser.app/Contents/MacOS/Brave Browser',
      '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge',
      '/Applications/Chromium.app/Contents/MacOS/Chromium',
    ],
    win32: [
      `${env.PROGRAMFILES}\\Google\\Chrome\\Application\\chrome.exe`,
      `${env['PROGRAMFILES(X86)']}\\Google\\Chrome\\Application\\chrome.exe`,
      `${env.LOCALAPPDATA}\\Google\\Chrome\\Application\\chrome.exe`,
      `${env.PROGRAMFILES}\\BraveSoftware\\Brave-Browser\\Application\\brave.exe`,
      `${env['PROGRAMFILES(X86)']}\\Microsoft\\Edge\\Application\\msedge.exe`,
    ],
    linux: ['/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/brave-browser'],
  }[process.platform] || [];
  return candidates.find((p) => p && fs.existsSync(p)) || null;
}

async function cdpCall(port, method, timeoutMs = 10000) {
  const { webSocketDebuggerUrl } = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json();
  return new Promise((resolve, reject) => {
    const ws = new WebSocket(webSocketDebuggerUrl);
    const timer = setTimeout(() => { try { ws.close(); } catch { } reject(new Error('CDP timeout')); }, timeoutMs);
    ws.onopen = () => ws.send(JSON.stringify({ id: 1, method }));
    ws.onmessage = (ev) => {
      const m = JSON.parse(String(ev.data));
      if (m.id !== 1) return;
      clearTimeout(timer);
      try { ws.close(); } catch { }
      if (m.error) reject(new Error(m.error.message)); else resolve(m.result);
    };
    ws.onerror = () => { clearTimeout(timer); reject(new Error('CDP websocket error')); };
  });
}

async function chromeLogin(url) {
  // Plain Chrome with a dedicated profile — no automation flags, so Google treats it as a normal browser.
  // The debug port is only polled over HTTP for the tab URL; nothing attaches to the page during login.
  const bin = findChrome();
  if (!bin) throw new FatalError('Chrome/Brave/Edge tidak ketemu. Isi config.chromePath, atau pakai: node index.js login --manual');
  const port = 9300 + Math.floor(Math.random() * 600);
  fs.mkdirSync(cx().profileDir, { recursive: true });
  const child = spawn(bin, [
    `--user-data-dir=${cx().profileDir}`, `--remote-debugging-port=${port}`, '--no-first-run', '--no-default-browser-check', '--new-window', url,
  ], { stdio: 'ignore' });
  let exited = false;
  child.on('exit', () => { exited = true; });
  child.on('error', (e) => { exited = true; log(`gagal buka Chrome: ${e.message}`, 'err'); });
  log('Chrome kebuka. Login pakai akun Google kamu di jendela itu (cuma sekali). Nunggu maks 10 menit...');
  const deadline = Date.now() + 10 * 60e3;
  let redirect = null;
  const seenErrors = new Set();
  while (!redirect && Date.now() < deadline) {
    if (exited) throw new FatalError('Chrome ditutup sebelum login selesai.');
    try {
      const list = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json();
      for (const t of list) {
        if (typeof t.url !== 'string') continue;
        if (t.url.startsWith(SITE) && /[?&#](code|error)=/.test(t.url)) { redirect = t.url; break; }
        // Auth0's own error page (errors it cannot send back to the site): show the real reason.
        if (t.url.startsWith(`https://${AUTH0_DOMAIN}/`) && /\/error\b|[?&]error=/.test(t.url) && !seenErrors.has(t.url)) {
          seenErrors.add(t.url);
          const p = new URL(t.url).searchParams;
          log(`Auth0 error: ${p.get('error') || '?'} — ${p.get('error_description') || t.url}. Coba login lagi di jendela itu, atau Ctrl+C.`, 'err');
        }
      }
    } catch { }
    if (!redirect) await wait(100);
  }
  if (!redirect) { child.kill(); throw new FatalError('Timeout 10 menit nunggu login.'); }
  let cookies = [];
  try {
    const r = await cdpCall(port, 'Storage.getCookies');
    cookies = (r.cookies || [])
      .filter((c) => c.domain.replace(/^\./, '') === AUTH0_DOMAIN)
      .map((c) => ({ name: c.name, value: c.value, expires: c.expires > 0 ? Math.round(c.expires * 1000) : null }));
  } catch (e) {
    log(`ambil cookie Auth0 gagal (${e.message}) — lanjut tanpa fallback silent-auth`, 'warn');
  }
  cdpCall(port, 'Browser.close', 3000).catch(() => { });
  setTimeout(() => { if (!exited) child.kill(); }, 4000).unref();
  return { redirect, cookies };
}

async function cmdLogin(manual) {
  if (account.loginMode !== 'google') throw new FatalError('`login` cuma untuk loginMode "google". Mode evm langsung jalan tanpa login.');
  const { verifier, challenge } = pkce();
  const state = b64url(crypto.randomBytes(24));
  // response_mode=query, same as the web's loginWithRedirect. (fragment is rejected by this tenant only at
  // the very end, after Google, as the generic Auth0 "Oops" page.) The web app cannot redeem our code: it
  // lacks our code_verifier, and its own state check fails first.
  const url = authorizeUrl({ challenge, state, nonce: b64url(crypto.randomBytes(24)), responseMode: 'query' });
  let redirect;
  let cookies = [];
  if (manual) {
    console.log(`\n1) Buka URL ini di browser (yang sudah login Google kamu juga boleh):\n\n${url}\n`);
    console.log('2) Login pakai Google. Setelah selesai kamu dilempar ke testnet.titanx.cc/?code=...&state=...');
    console.log('3) LANGSUNG copy URL lengkap dari address bar (harus ada "code=") lalu paste di sini.');
    console.log('   Kalau "code=" keburu hilang dari address bar, buka History browser (Cmd/Ctrl+Y) dan copy dari situ.\n');
    const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
    redirect = (await rl.question('URL: ')).trim();
    rl.close();
  } else {
    ({ redirect, cookies } = await chromeLogin(url));
  }
  let u;
  try { u = new URL(redirect); } catch { throw new FatalError('URL tidak valid.'); }
  const p = paramsFromUrl(u);
  if (p.get('error')) throw new FatalError(`Auth0: ${p.get('error')} ${p.get('error_description') || ''}`);
  if (!p.get('code')) throw new FatalError('URL tidak mengandung code=.');
  if (p.get('state') !== state) throw new FatalError('state tidak cocok — pakai URL dari login yang barusan, bukan yang lama.');
  const tok = await auth0Token({ grant_type: 'authorization_code', code: p.get('code'), code_verifier: verifier, redirect_uri: SITE });
  store.auth0 = { refreshToken: null, cookies: cookies.length ? cookies : store.auth0?.cookies || [], keepAliveAt: Date.now() };
  saveTokens(tok);
  const claims = jwtPayload(tok.access_token);
  log(`login OK: ${claims.sub || '?'} (aud ${[].concat(claims.aud || []).join(',')})`, 'ok');
  if (tok.refresh_token) log('refresh token: ADA → bot bisa perpanjang login sendiri tanpa kamu', 'ok');
  else log(`refresh token: tidak diberi Auth0 (normal untuk tenant ini) → bot perpanjang login lewat silent-auth cookie tiap ${cfg.auth0KeepAliveH} jam. Selama bot jalan minimal sekali per 3 hari, tidak perlu login lagi.`, 'ok');
  // A fresh Google login always gets a fresh API session.
  await mintSession('login baru');
  await showStatus();
}

// ---------------------------------------------------------------------------------------------
// API session

async function mintSession(reason) {
  const old = store.session;
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const pubHex = Buffer.from(publicKey.export({ format: 'jwk' }).x, 'base64url').toString('hex');
  const expiry = new Date(serverNow().getTime() + SESSION_TTL_MS);
  const maxNotional = W(String(cfg.sessionMaxNotional));
  let body;
  if (account.loginMode === 'evm') {
    const w = evmWallet();
    const message = sessionAuthCanon({
      scheme: 'evm', credential: w.address.toLowerCase(), sessionPubKeyHex: pubHex, expiry, maxNotional, userNonce: Date.now() * 1e6, label: '',
    });
    body = { scheme: 'evm', message, signature: (await w.signMessage(message)).replace(/^0x/, '') };
  } else {
    body = { scheme: 'jwt', token: await getAccessToken(), sessionPubKey: pubHex, expiry: G(expiry), maxNotional };
  }
  const res = await api('POST', '/v1/auth/session', { body, retry: false });
  if (!res?.sessionId) throw new Error(`/v1/auth/session: respons aneh ${JSON.stringify(res).slice(0, 200)}`);
  store.session = {
    sessionId: res.sessionId,
    accountId: res.accountId ?? null,
    party: res.party ?? null,
    // Which accounts.json account owns this session. The matching key for multi-account: a session is only
    // used under the label it was minted for; a different/absent label means "login this account again".
    label: acct && !acct.legacy ? acct.label : null,
    // Proxy this account used at login. Stamped so a copied accounts/ folder is self-contained: the roster
    // can be rebuilt from the folders alone (no accounts.json / proxy.txt needed) with each proxy preserved.
    proxy: (acct && acct.proxy) || account.proxy || null,
    expiresAt: res.expiresAt || expiry.toISOString(),
    maxNotional: res.maxNotional ?? maxNotional,
    method: account.loginMode,
    publicKeyHex: pubHex,
    privateKey: privateKey.export({ format: 'der', type: 'pkcs8' }).toString('base64'),
    createdAt: new Date().toISOString(),
  };
  store.state.renewTryAt = 0;
  saveStore();
  activate(store.session);
  log(`session API baru ${short(res.sessionId)}${store.session.label ? ` · akun ${store.session.label}` : ''} · party ${handleOf(res.party)} s/d ${store.session.expiresAt} (${reason})`, 'ok');
  if (old?.sessionId && old.sessionId !== res.sessionId && Date.parse(old.expiresAt) > Date.now()) {
    revokeSession(old).catch((e) => log(`revoke session lama: ${e.message}`, 'warn'));
  }
}

function evmWallet() {
  const pk = String(account.evmPrivateKey || '').trim();
  if (!/^(0x)?[0-9a-fA-F]{64}$/.test(pk)) throw new FatalError('account.json: evmPrivateKey kosong/tidak valid (64 hex)');
  const { Wallet } = require('ethers');
  return new Wallet(pk.startsWith('0x') ? pk : `0x${pk}`);
}

async function ensureSession() {
  const s = store.session;
  const left = s ? Date.parse(s.expiresAt) - Date.now() : -1;
  if (s && left > 0 && cx().cur?.sessionId !== s.sessionId) activate(s);
  if (s && left > cfg.sessionRenewBeforeH * 3600e3) return;
  // Renewal: don't hammer Auth0 every loop when it keeps failing; old session is still usable meanwhile.
  if (s && left > 5 * 60e3 && Date.now() < num(store.state.renewTryAt)) return;
  store.state.renewTryAt = Date.now() + 30 * 60e3;
  try {
    await mintSession(s ? `perpanjang, sisa ${fmtDur(left)}` : 'pertama kali');
  } catch (e) {
    if (s && left > 5 * 60e3) { log(`perpanjang session gagal (${e.message}); session lama masih ${fmtDur(left)}`, 'warn'); return; }
    throw e;
  }
}

function dropSession(why) {
  if (!store.session) return; // another slot already dropped it
  log(`session API ditolak server (${why}) → bikin baru`, 'warn');
  store.session = null;
  cx().cur = null;
  store.state.renewTryAt = 0;
  saveStore();
}

// ---------------------------------------------------------------------------------------------
// onboarding

/** Local Turnstile-Solver base URL (shared by Turnstile tokens and cf_clearance), or '' if none configured. */
function solverBase() {
  return String(account.turnstileSolverUrl || cfg.turnstileSolverUrl || process.env.TITANX_SOLVER_URL || '').trim().replace(/\/$/, '');
}

/** How many solves the local solver can run at once. Explicit cfg.solverConcurrency wins; otherwise read the
 *  solver's own config.json (Turnstile-Solver-main/config.json): pool size = thread × page_count. Cached. */
function solverCapacity() {
  if (solverCap) return solverCap;
  const override = Math.floor(Number(cfg.solverConcurrency) || 0);
  if (override > 0) { solverCap = override; return solverCap; }
  try {
    const sc = readJson(path.join(DIR, 'Turnstile-Solver-main', 'config.json'), true);
    const n = (Math.floor(Number(sc?.thread)) || 0) * (Math.floor(Number(sc?.page_count)) || 0);
    if (n > 0) { solverCap = n; return solverCap; }
  } catch { }
  solverCap = 4; // safe default when the solver config can't be read (e.g. remote solver)
  return solverCap;
}

/** Minimal async semaphore: run(fn) waits until fewer than `n` tasks are in flight, so solver calls never exceed
 *  the solver's page pool. The slot is held for the WHOLE solve (start + poll) = exactly one occupied page. */
function makeGate(n) {
  let active = 0; const q = [];
  const pump = () => { while (active < n && q.length) { active++; q.shift()(); } };
  return {
    async run(fn) {
      await new Promise((res) => { q.push(res); pump(); });
      try { return await fn(); } finally { active--; pump(); }
    },
  };
}
function solverGateGet() {
  if (!solverGate) { const n = solverCapacity(); solverGate = makeGate(n); log(`solver lokal: maks ${n} solve bareng (thread × page_count)`, 'info'); }
  return solverGate;
}

/** POST a solver job (/turnstile or /clearance) and return its task id. A 429 "Server penuh" (pool momentarily
 *  full) is waited out and retried rather than surfaced as a hard error. */
async function solverStart(url, what) {
  for (let i = 0; i < 30; i++) {
    let mk;
    try { mk = await fetch(url).then((r) => r.json()); }
    catch (e) { throw new Error(`solver lokal /${what} tidak terjangkau (${e.message}) — jalankan api_server.py dulu`); }
    const id = mk.task_id || mk.id;
    if (id) return id;
    if (/penuh|full|coba lagi/i.test(`${mk.error || ''} ${mk.message || ''}`)) { await wait(2000); continue; } // pool full -> wait
    throw new Error(`solver lokal /${what}: ${JSON.stringify(mk).slice(0, 160)}`);
  }
  throw new Error(`solver lokal /${what}: pool penuh terus (30x) — kurangi concurrency atau naikkan thread/page_count solver`);
}

/** Poll /result until the job finishes. Returns { httpStatus, j }. */
async function solverPoll(base, id, timeoutMs) {
  const deadline = Date.now() + timeoutMs;
  await wait(2000);
  while (Date.now() < deadline) {
    const res = await fetch(`${base}/result?id=${encodeURIComponent(id)}`);
    if (res.status === 202) { await wait(2000); continue; } // masih diproses
    return { httpStatus: res.status, j: await res.json().catch(() => ({})) };
  }
  throw new Error(`solver lokal timeout ${Math.round(timeoutMs / 1000)}s`);
}

/** Local self-hosted Turnstile solver: GET /turnstile -> poll /result. Gated to the solver's pool capacity. */
async function solveTurnstileLocal(base, quiet = false) {
  return solverGateGet().run(async () => {
    if (!quiet) log(`solve Turnstile via solver lokal ${base}...`);
    const q = `url=${encodeURIComponent(`${SITE}/`)}&sitekey=${encodeURIComponent(TURNSTILE_SITEKEY)}`;
    const id = await solverStart(`${base}/turnstile?${q}`, 'turnstile');
    const { httpStatus, j } = await solverPoll(base, id, 300e3);
    if (httpStatus === 200 && j.status === 'success' && j.value) { if (!quiet) log('Turnstile beres (solver lokal)', 'ok'); return j.value; }
    throw new Error(`solver lokal result: HTTP ${httpStatus} ${j.status || ''} ${j.value || j.error || ''}`.trim());
  });
}

/** Turnstile-Solver /clearance (camoufox): GET /clearance -> poll /result -> { cookie:'cf_clearance=…', ua }. Gated. */
async function getClearanceLocal(base) {
  return solverGateGet().run(async () => {
    const id = await solverStart(`${base}/clearance?url=${encodeURIComponent(`${SITE}/`)}&timeout=70`, 'clearance');
    const { httpStatus, j } = await solverPoll(base, id, 120e3);
    if (httpStatus === 200 && j.status === 'success') {
      const cookie = j.cookies && /cf_clearance=/.test(j.cookies) ? String(j.cookies).match(/cf_clearance=[^;]+/)[0]
        : (j.cf_clearance ? `cf_clearance=${j.cf_clearance}` : '');
      if (!cookie) throw new Error('solver lokal /clearance: cf_clearance kosong');
      return { cookie, ua: String(j.user_agent || '') };
    }
    throw new Error(`solver lokal /clearance result: HTTP ${httpStatus} ${j.status || ''} ${j.value || j.message || j.error || ''}`.trim());
  });
}

/** Cache a fresh-enough cf_clearance (shared by every account; not IP-bound). Returns it, or null if no solver is
 *  configured. Concurrent callers coalesce onto one solve. force=true always re-solves. */
async function ensureClearance(force = false) {
  const base = solverBase();
  if (!base) return null; // no local solver -> cannot auto-bypass the WAF
  if (!force && cfClearance && Date.now() - cfClearanceAt < 20 * 60e3) return cfClearance;
  if (cfClearanceInflight) return cfClearanceInflight;
  cfClearanceInflight = (async () => {
    log(`ambil cf_clearance (bypass Cloudflare WAF) via solver lokal ${base}...`);
    // The solver round-robins its browser contexts (each on a proxy from its own pool); some proxies can't pass
    // the CF managed challenge -> "clearance_fail". The cookie is NOT IP-bound, so just retry: another context /
    // proxy gets it. Up to 5 tries with a short gap.
    let lastErr = null;
    for (let i = 1; i <= 5; i++) {
      try {
        const c = await getClearanceLocal(base);
        cfClearance = c; cfClearanceAt = Date.now();
        log('cf_clearance didapat (dipakai semua akun)', 'ok');
        return c;
      } catch (e) {
        lastErr = e;
        log(`cf_clearance percobaan ${i}/5 gagal: ${e.message}`, 'warn');
        if (i < 5) await wait(3000);
      }
    }
    throw lastErr || new Error('cf_clearance gagal (5x)');
  })();
  try { return await cfClearanceInflight; } finally { cfClearanceInflight = null; }
}

async function solveTurnstile(quiet = false) {
  const solverUrl = solverBase();
  if (solverUrl) return solveTurnstileLocal(solverUrl, quiet);
  const key = String(account.twoCaptchaKey || '').trim();
  if (!key) throw new FatalError('account.json: twoCaptchaKey kosong. Dibutuhkan sekali untuk bind party (Turnstile).');
  const call = async (method, body) => {
    const r = await fetch(`https://api.2captcha.com/${method}`, {
      method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ clientKey: key, ...body }),
    });
    return r.json();
  };
  if (!quiet) log('solve Cloudflare Turnstile via 2captcha...');
  const c = await call('createTask', { task: { type: 'TurnstileTaskProxyless', websiteURL: `${SITE}/`, websiteKey: TURNSTILE_SITEKEY } });
  if (c.errorId) {
    const m = `2captcha createTask: ${c.errorCode} ${c.errorDescription || ''}`.trim();
    // a wrong/blocked key never fixes itself; ERROR_ZERO_BALANCE does once topped up -> stays retryable
    if (/^ERROR_(KEY_DOES_NOT_EXIST|WRONG_USER_KEY|IP_NOT_ALLOWED|IP_BANNED)$/.test(c.errorCode)) throw new FatalError(`${m} — cek twoCaptchaKey`);
    throw new Error(m);
  }
  const deadline = Date.now() + 180e3;
  await wait(8000);
  while (Date.now() < deadline) {
    const r = await call('getTaskResult', { taskId: c.taskId });
    if (r.errorId) throw new Error(`2captcha: ${r.errorCode} ${r.errorDescription || ''}`);
    if (r.status === 'ready' && r.solution?.token) { if (!quiet) log('Turnstile beres', 'ok'); return r.solution.token; }
    await wait(5000);
  }
  throw new Error('2captcha timeout 180s');
}

function setParty(party) {
  store.session.party = party;
  saveStore();
  log(`party Canton terikat: ${party}`, 'ok');
}

/** Normalize a Canton handle exactly like the web (onboarding-*.js): lowercase, [a-z0-9_], max 16; else null. */
function normHandle(h) {
  const s = String(h || '').toLowerCase().replace(/[^a-z0-9_]/g, '').slice(0, 16);
  return /^[a-z0-9_]{3,16}$/.test(s) ? s : null;
}

class PartyIntentError extends Error {
  constructor(code, message) { super(message); this.name = 'PartyIntentError'; this.code = code || null; }
}
class CaptchaFailedError extends Error {
  constructor() { super('Turnstile ditolak server 2x berturut-turut'); this.name = 'CaptchaFailedError'; }
}

/**
 * The web's captcha wrapper (session-*.js zt): fresh Turnstile per try; a 403 captcha_required/failed retries once.
 * `ready` = a token solved ahead of time (used for the first try only), so a bind can fire the instant a slot opens.
 */
async function withCaptcha(fn, ready = null) {
  for (let t = 0; ; t++) {
    try {
      return await fn(t === 0 && ready ? ready : await solveTurnstile());
    } catch (e) {
      if (!(e instanceof ApiError && e.status === 403 && /captcha_(required|failed)/.test(`${e.reason} ${e.code}`))) throw e;
      if (t >= 1) throw new CaptchaFailedError();
      log(`captcha ditolak server (${e.reason || e.code || '403'}) — solve ulang sekali`, 'warn');
    }
  }
}

// Party allocation poller — mirrors the web (index-*.js jx): states none/queued/allocating/bound/failed, the
// server may swap the handle (st.hint), poll every pollAfterMs (1-30 s), read errors back off up to 5 times.
// A queued intent is worked by the server whether we watch or not (a later --resume finds it bound) and polling is a
// free GET, so there is no fixed deadline: give up only when the queue position has not moved for 20 minutes
// (testnet 2026-10-11: ~4300 queued, eta 40 min — the old fixed 20 min gave up halfway).
async function waitParty(st, onHint) {
  const STALL_MS = 20 * 60e3;
  let stallAt = Date.now() + STALL_MS;
  let lastPlace = null;
  let lastLog = 0;
  for (; ;) {
    const h = normHandle(st?.hint);
    if (h && onHint) onHint(h);
    const state = st?.state ?? (st?.party ? 'bound' : undefined);
    if (state === 'bound' && st.party) return setParty(st.party);
    if (state === 'failed' || state === 'none') {
      throw new PartyIntentError(st.error?.code, `bind party ${state}: ${st.error?.code || ''} ${st.error?.message || ''}`.trim());
    }
    if (state === 'queued' && st.position !== lastPlace) {
      lastPlace = st.position;
      stallAt = Date.now() + STALL_MS;
      if (Date.now() - lastLog >= 60e3) { // the queue moves every few seconds — one line a minute is enough
        lastLog = Date.now();
        log(`antri bikin party Canton: #${num(st.position) + 1}${st.queueLength ? `/${st.queueLength}` : ''}${st.etaSeconds ? `, eta ${fmtDur(st.etaSeconds * 1000)}` : ''}`);
      }
    }
    if (Date.now() > stallAt) {
      throw new PartyIntentError('queue_stalled', `bind party: antrian tidak bergerak 20 menit${lastPlace !== null ? ` (posisi #${num(lastPlace) + 1})` : ''} — server tetap memproses, coba lagi nanti`);
    }
    const base = Math.min(30000, Math.max(1000, num(st?.pollAfterMs) || 2000));
    for (let errs = 0; ;) {
      await wait(errs === 0 ? base : Math.min(30000, base * 2 ** errs));
      try { st = await me.depositIntent(); break; } catch (e) {
        if ((e instanceof ApiError && e.status > 0 && e.status < 500 && e.status !== 429) || ++errs >= 5) throw e;
      }
    }
  }
}

async function bindParty(opts = {}) {
  const { queueOnly = false } = opts; // queueOnly: submit the intent, return as soon as it is queued (skip the 8h waitParty) — used by antri.js
  // Already bound in the browser earlier? GET /v1/deposits/intent tells us without a captcha.
  try {
    const st = await me.depositIntent();
    if (st?.party && (st.state === 'bound' || !st.state)) return setParty(st.party);
    if (st?.state === 'queued' || st?.state === 'allocating') { if (queueOnly) { log('sudah di antrian party ✓'); return { queued: true }; } return waitParty(st); }
  } catch (e) {
    if (e.status !== 404) log(`cek status party: ${e.message}`, 'warn');
  }
  if (cfg.dryRun) { log('[dryRun] party belum terikat — skip bind (butuh captcha)', 'warn'); return; }
  // Same loop as the web's auto-bind (index-*.js Ax): 3 attempts; a full queue (503 queue_full, "Lots of sign-ups
  // right now") waits without spending one; a taken handle (party_taken / conflict) asks for a fresh suggestion; a
  // captcha refused twice stops. The web gives up on a full queue after 5 tries (~5 min); live testnet (2026-10-10)
  // stayed full longer than that, so a bot keeps waiting up to partyQueueWaitMin (0 = no limit; each try costs one
  // Turnstile solve).
  let hint = null;
  let lastErr = null;
  let busyUntil = 0;
  let busyNoted = 0;
  let busyTries = 0;
  let ipCapRotations = 0;
  // While the queue is full a Turnstile token is solved AHEAD of time, so when a slot frees up the bind goes out in
  // well under a second instead of after a ~10 s solve (slots are taken by whoever is first). Same cost: one solve
  // per real attempt. Tokens live ~300 s; older than 240 s is not used.
  let prefetch = null;
  const startPrefetch = () => { prefetch = solveTurnstile(true).then((t) => ({ t, at: Date.now() }), () => null); };
  const takeReady = async () => {
    if (!prefetch) return null;
    const r = await prefetch;
    prefetch = null;
    return r && Date.now() - r.at < 240e3 ? r.t : null;
  };
  for (let attempt = 1; attempt <= 3;) {
    try {
      if (!hint) {
        hint = normHandle((await pub.suggestHandle())?.handle);
        if (!hint) throw new Error('saran handle dari server tidak valid');
      }
      if (!busyUntil) log(`bind party Canton (handle "${hint}", percobaan ${attempt}/3)...`); // quiet while queue-retrying
      const st = await withCaptcha((token) => postDepositIntent(hint, token), await takeReady());
      if (queueOnly) {
        if (st?.party && (st.state === 'bound' || !st.state)) return setParty(st.party);
        log('masuk antrian party ✓ (server lanjut memproses — selesaikan nanti: node onboard.js --resume)');
        return { queued: true };
      }
      return await waitParty(st, (h) => { if (h !== hint) { log(`server memakai handle "${h}"`); hint = h; } });
    } catch (e) {
      if (e instanceof FatalError || stopping) throw e;
      // already queued server-side: a fresh POST would burn a captcha and could lose the queue spot
      if (e instanceof PartyIntentError && e.code === 'queue_stalled') throw e;
      // Anti-sybil gate (new 2026-10-13): TitanX refuses a wallet with no on-chain history. A fresh random wallet
      // can NEVER pass this — stop immediately instead of retrying 3× (each burns a Turnstile solve) and then
      // forever via runUntilDone. Only a different wallet (with ≥1 tx on a supported chain) fixes it.
      if (/never sent a transaction|at least one transaction on a supported chain/i.test(e.message || '')) {
        throw new FatalError('wallet belum punya transaksi on-chain — TitanX wajibkan wallet dengan ≥1 tx di supported chain (anti-sybil). Wallet random baru tidak bisa; pakai wallet yang sudah ada riwayat transaksi.');
      }
      lastErr = e;
      // Per-IP daily cap on party allocations: THIS proxy is maxed for today. A fresh IP clears it (the wallet/
      // account is unchanged — only the request IP matters). Rotate and retry, bounded so we don't spin forever.
      if (/daily maximum of party allocations|already started the daily/i.test(e.message || '')) {
        if (ipCapRotations < Math.min(proxyPool.length, 40) && rotateProxy('IP kena cap party harian')) {
          ipCapRotations++;
          continue; // retry WITHOUT burning one of the 3 tries — just from a fresh IP
        }
        throw new PartyIntentError('party_ip_capped', 'proxy kena cap party harian & tidak ada IP segar lain — tunggu reset harian atau tambah proxy.txt');
      }
      if (e instanceof ApiError && e.status === 503 && e.code === 'queue_full') {
        if (!busyUntil) { const m = num(cfg.partyQueueWaitMin); busyUntil = m > 0 ? Date.now() + m * 60e3 : Infinity; }
        if (Date.now() < busyUntil) {
          // The server checks the captcha BEFORE the queue (POST without a token = 403 captcha_required), but
          // GET /v1/deposits/intent reports the global queueLength without one (pinned at 5000 = full on testnet
          // 2026-10-10). Poll that cheaply and jump in as soon as it drops; otherwise make a real attempt (1 captcha)
          // every partyQueueRetrySec — freed slots go to whoever retries first, and the web retries every Retry-After.
          const pace = Math.max(5, num(cfg.partyQueueRetrySec) || 5) * 1000; // konstan (biar cepet); abaikan Retry-After saat antrian penuh
          startPrefetch(); // next token solves while we wait
          const full = num((await me.depositIntent().catch(() => null))?.queueLength);
          const since = Date.now();
          busyTries++;
          if (Date.now() - busyNoted > 5 * 60e3) {
            busyNoted = Date.now();
            log(`antrian bikin party penuh${full ? ` (${full} antri)` : ''} — "ramai yang daftar"; sudah coba ${busyTries}x, coba lagi tiap ${fmtDur(pace)}, ${Number.isFinite(busyUntil) ? `sabar s/d ${fmtDur(busyUntil - Date.now())}` : 'sabar sampai dapat slot'}`, 'warn');
          }
          for (; ;) {
            await sleep(Math.min(20e3, pace));
            if (stopping || Date.now() >= busyUntil || !full) break;
            if (Date.now() - since >= pace) break;
            const q = num((await me.depositIntent().catch(() => null))?.queueLength);
            if (!q || q < full) { log(`antrian turun (${q || '?'} antri) — coba bind lagi`); break; }
          }
          continue;
        }
      }
      const taken = (e instanceof PartyIntentError && e.code === 'party_taken')
        || (e instanceof ApiError && (e.code === 'conflict' || /hint/.test(e.reason || '')));
      if (taken) { log(`handle "${hint}" sudah dipakai — minta saran baru`, 'warn'); hint = null; }
      else log(`bind party percobaan ${attempt}/3 gagal: ${e.message}`, 'warn');
      if (attempt < 3) await sleep(5000); // jeda antar-attempt bind party: konstan 5 dtk (biar cepet)
      attempt++;
    }
  }
  throw new Error(`bind party gagal 3x${lastErr ? `: ${lastErr.message}` : ''}`);
}

// Server reason codes from the web (use-onboard-gate-*.js Ul) -> what the user should do about them.
const REFERRAL_ERRORS = {
  referral_code_unknown: 'kode invite tidak dikenal server',
  referral_code_inactive: 'kode invite belum aktif (pemiliknya belum pernah deposit/faucet)',
  referral_self: 'tidak bisa pakai kode milik sendiri',
  referral_cycle: 'kode itu milik akun yang kamu referensikan sendiri (siklus)',
  referral_code_invalid: 'format kode invite salah',
};

async function bindReferral() {
  const code = String(account.referralCode || '').trim().toLowerCase();
  if (!code) {
    throw new FatalError('Akun ini belum punya referrer dan testnet Titan invite-only. Isi "referralCode" (kode invite) di account.json lalu jalankan lagi.');
  }
  if (!/^[a-z0-9_-]{3,32}$/.test(code)) throw new FatalError(`referralCode "${code}" formatnya salah (3-32 huruf/angka/_/-)`);
  // Like the web: an "unseen" code only warns ("You can still apply it"); the bind call is the authority.
  const v = await pub.referralCode(code).catch(() => null);
  if (v && !v.valid) log(`kode invite "${code}" belum terlihat valid di server — tetap dicoba`, 'warn');
  if (cfg.dryRun) { log(`[dryRun] skip bind referral ${code}`); return; }
  try {
    const r = await postReferralBind(code);
    log(`referral terpasang: ${r?.codeUsed || code}`, 'ok');
  } catch (e) {
    const why = [e.code, e.reason].find((k) => k && (k === 'referral_already_bound' || REFERRAL_ERRORS[k]));
    if (why === 'referral_already_bound') return;
    if (why) throw new FatalError(`referral "${code}" ditolak: ${REFERRAL_ERRORS[why]} (${why})`);
    throw e;
  }
}

async function ensureOnboarded() {
  // Returns true once party + referral are bound. Safe to call repeatedly: every step checks first.
  if (!store.session.party) await bindParty();
  if (!store.session.party) { log('party belum terikat — referral/faucet/trade menunggu bind selesai', 'warn'); return false; }
  const ref = await me.referral();
  view.referral = ref?.referrer ?? null;
  if (ref?.referrer?.bound !== true) await bindReferral();
  else log(`referral OK (${ref.referrer.codeUsed || 'bound'})`);
  return true; // bindReferral throws when it cannot bind
}

// ---------------------------------------------------------------------------------------------
// account / faucet

async function getAccount() {
  // An account that was never funded answers 404 / unknown_user here: treat as empty, not as a crash.
  const soft = (e) => { if (e.deadSession || !(e.status >= 400 && e.status < 500)) throw e; return null; };
  const a = await me.account().catch(soft);
  if (a) { view.account = a; view.accountAt = Date.now(); }
  const b = a ? null : await me.balance().catch(soft);
  const value = num(a?.accountValue ?? a?.balance ?? b?.accountBase ?? b?.balance);
  const available = num(a?.available ?? a?.availableToTrade ?? a?.withdrawable ?? value);
  return { value, available, raw: a ?? b };
}

/**
 * Auto-claim: the web only offers the faucet under 2,000 USDCx, but the server itself accepted a claim
 * at 9,877 (2026-10-09, +10,000). Watch the value about once a minute — from the dashboard/scheduler
 * data when it is fresh, so no extra request — and claim as soon as it drops below faucetBelowUsd.
 * A 5xx/timeout on the claim is an UNKNOWN outcome (that 2026-10-09 claim answered 503 and still paid
 * out), so it gets the same settle wait as a success instead of a quick retry.
 * Two timers: faucetCheckAt = when to look again, faucetCooldownUntil = server-imposed wait (Retry-After,
 * pending settlement, disabled). The second one is shown on the dashboard.
 */
async function maybeFaucet() {
  if (!cfg.autoFaucet) return;
  const st = store.state;
  const now = Date.now();
  if (now < num(st.faucetCooldownUntil) || now < num(st.faucetCheckAt)) return;
  st.faucetCheckAt = now + 60e3;
  const value = view.account && now - view.accountAt < 30e3 ? num(view.account.accountValue) : (await getAccount()).value;
  if (value >= cfg.faucetBelowUsd) return;
  if (cfg.dryRun) { log(`[dryRun] nilai akun ${money(value)} < ${money(cfg.faucetBelowUsd, 0)} → akan auto-klaim faucet`); return; }
  setPhase('klaim faucet');
  const cooldown = (sec, why, kind = 'warn') => {
    st.faucetCooldownUntil = Date.now() + sec * 1000;
    saveStore();
    log(`faucet: ${why} — coba lagi ${fmtDur(sec * 1000)}`, kind);
  };
  try {
    const r = await me.faucet();
    log(`faucet +${r?.amount} USDCx (nilai akun sebelum: ${money(r?.accountValue ?? value)}) — masuk di batch settlement berikut`, 'ok');
    // never claim twice while the first top-up is still settling
    st.faucetCooldownUntil = Date.now() + 10 * 60e3;
    saveStore();
    refreshSoon();
  } catch (e) {
    if (e.deadSession) throw e;
    if (e.code === 'rate_limited' || e.status === 429) cooldown(e.retryAfter ?? 3600, 'cooldown dari server');
    else if (e.code === 'conflict' || e.reason === 'balance_sufficient') cooldown(5 * 60, 'server bilang saldo masih cukup / top-up sebelumnya belum settle', 'info');
    else if (e.code === 'forbidden') cooldown(6 * 3600, 'dimatikan untuk akun ini (forbidden)');
    else if (e.code === 'engine_unavailable' || e.status >= 500 || e.status === 0) {
      cooldown(10 * 60, `hasil tidak pasti (${e.reason || e.code || e.status}) — bisa saja sudah masuk, cek saldo dulu`, 'info');
      refreshSoon();
    }
    else cooldown(10 * 60, `gagal: ${e.message}`);
  }
}

async function logPoints() {
  try {
    const p = await me.points();
    view.points = p;
    view.pointsAt = Date.now();
    const rules = (p?.byRule || []).map((r) => `${String(r.rule).replace(/_v\d+$/, '')} ${num(r.points)}`).join(', ');
    const ep = p?.currentEpoch;
    log(`points ${num(p?.total)} (${rules || '-'}) | rank ${p?.rank ?? '-'}/${p?.rankedParties ?? '-'}${ep ? ` | minggu #${ep.index}: proyeksi ${ep.projectedPoints ?? '-'} s/d ${ep.endsAt}` : ''}`);
  } catch (e) {
    log(`points: ${e.status === 503 ? 'program points sedang tidak tersedia' : e.message}`, 'warn');
  }
  // Server-truth airdrop stats — fetched here in the ENGINE (always runs, pm2 included), not only in the
  // dashboard refresh, so VOL/fee/PnL are populated even headless.
  await refreshServerStats();
}

/** Pull volume (web /rewards) + portfolio (cumFees/cumRealizedPnl) straight from the server into `view`. */
async function refreshServerStats() {
  const v = await me.volume().catch(() => null);
  if (v) { view.volume = num(v.total); view.volumeWindow = v.window || '7d'; }
  const pf = await me.portfolio().catch(() => null);
  const last = pf?.items?.[pf.items.length - 1];
  if (last) { view.fees = num(last.cumFees); view.realizedPnl = num(last.cumRealizedPnl); view.serverStatsAt = Date.now(); }
}

// ---------------------------------------------------------------------------------------------
// trading

let marketCache = { at: 0, byName: {} };

async function getMarkets() {
  if (Date.now() - marketCache.at < 10 * 60e3) return marketCache.byName;
  const byName = {};
  for (const m of await pub.markets()) byName[m.market] = { ...m, szDecimals: num(m.szDecimals), minNotional: num(m.minNotional), maxLeverage: num(m.maxLeverage), maxPositionNotional: num(m.maxPositionNotional) };
  marketCache = { at: Date.now(), byName };
  return byName;
}

async function findPosition(market) {
  const ps = await me.positions();
  return ps.find((p) => p.market === market && num(p.size) !== 0) || null;
}

async function waitForPosition(market, timeoutSec) {
  // Positions come from a read model that trails the engine by a batch or two.
  const end = Date.now() + timeoutSec * 1000;
  for (; ;) {
    const p = await findPosition(market);
    if (p || Date.now() > end) return p;
    await wait(1500);
  }
}

async function waitForFlat(market, timeoutSec) {
  const end = Date.now() + timeoutSec * 1000;
  for (; ;) {
    if (!(await findPosition(market))) return true;
    if (Date.now() > end) return false;
    await wait(1500);
  }
}

function dayStats() {
  const day = utcDay();
  const st = store.state;
  if (st.dayStats?.date !== day) st.dayStats = { date: day, volumeUsd: 0, feesUsd: 0, makerUsd: 0, roundTrips: 0, pnlUsd: 0 };
  return st.dayStats;
}

function addVolume(usd, fee, makerUsd = 0) {
  const s = (store.state.stats ||= { roundTrips: 0, volumeUsd: 0, feesUsd: 0, pnlUsd: 0, makerUsd: 0, since: new Date().toISOString() });
  for (const o of [s, dayStats()]) {
    o.volumeUsd = +(num(o.volumeUsd) + usd).toFixed(2);
    o.feesUsd = +(num(o.feesUsd) + num(fee)).toFixed(4);
    o.makerUsd = +(num(o.makerUsd) + makerUsd).toFixed(2);
  }
  saveStore();
}

function recordTrade(tr) {
  // History (last 50 round trips, for the single-account trade table) is OPTIONAL — off by default to keep
  // RAM and session.json lean on a VPS. Stats (volume/fee/pnl/roundTrips) are always kept.
  if (cfg.tradeHistory) {
    const h = (store.state.history ||= []);
    h.push(tr);
    if (h.length > 50) h.splice(0, h.length - 50);
  } else if (store.state.history) {
    delete store.state.history;
  }
  for (const o of [store.state.stats, dayStats()]) {
    if (!o) continue;
    o.roundTrips = num(o.roundTrips) + 1;
    o.pnlUsd = +(num(o.pnlUsd) + num(tr.pnl)).toFixed(4);
  }
  saveStore();
}

async function engineHealthy() {
  try {
    const s = await pub.status();
    // batchStaleSeconds is on-chain settlement lag (observed 200s+ during normal trading), not matching lag.
    if (s?.publishing === false || num(s?.batchStaleSeconds) > cfg.maxBatchStaleSec) {
      log(`engine exchange macet (publishing=${s?.publishing}, batch stale ${s?.batchStaleSeconds}s) — pause`, 'warn');
      return false;
    }
    return true;
  } catch (e) {
    log(`exchange status: ${e.message}`, 'warn');
    return false;
  }
}

// ---------------------------------------------------------------------------------------------
// volume engine
//
// Up to N concurrent "slots", one bot position per market. A slot: pick market/side/size -> entry
// (maker-first, sometimes in 2-3 clips) -> hold -> exit (sometimes partial first) -> flat check.
// Everything a person would vary is drawn from wide, heavy-tailed distributions and re-rolled per
// session, so there is no fixed size, period, side ratio or rhythm to fingerprint.
// Maker-first matters for volume: maker fee 1.5 bps vs taker 4.5 bps, and the fee drain toward the
// faucet floor is what really caps volume, not speed.

const slots = collFacade('slots'); // live slots (id -> slot); persisted copy in store.state.slots for crash recovery
const recovering = collFacade('recovering');
const plan = facade('plan');
let slotSeq = 0;
let healthCache = { at: 0, ok: true };
const ZERO = () => ({ size: 0, notional: 0, fee: 0, makerNotional: 0 });
const addFills = (acc, f) => { for (const k of Object.keys(acc)) acc[k] += num(f?.[k]); return acc; };

// ---- randomness

function gauss() {
  let u = 0;
  let v = 0;
  while (!u) u = Math.random();
  while (!v) v = Math.random();
  return Math.sqrt(-2 * Math.log(u)) * Math.cos(2 * Math.PI * v);
}
const asRange = (x) => (Array.isArray(x) ? x : [x, x]);
const clamp = (x, r) => Math.min(asRange(r)[1], Math.max(asRange(r)[0], x));
const chance = (p) => Math.random() < p;
/** Uniform in log space: as many $2k trades as $20k ones, like real order flow. */
function logUniform(r) {
  const [a, b] = asRange(r);
  if (!(a > 0) || !(b > 0)) return a + Math.random() * (b - a);
  return Math.exp(Math.log(a) + Math.random() * (Math.log(b) - Math.log(a)));
}
/** Log-normal around a median, clipped: mostly short, sometimes long — how people actually wait. */
const heavyTail = (median, range, sigma = 0.9) => clamp(median * Math.exp(sigma * gauss()), range);
const randInt = (r) => { const [a, b] = asRange(r); return Math.round(a + Math.random() * (b - a)); };

function weightedPick(weights) {
  const entries = Object.entries(weights).filter(([, w]) => w > 0);
  let r = Math.random() * entries.reduce((s, [, w]) => s + w, 0);
  for (const [k, w] of entries) if ((r -= w) <= 0) return k;
  return entries.length ? entries[entries.length - 1][0] : null;
}

function marketWeights() {
  // config.markets: array (equal weights) or { "BTC-USDCX": 5, ... }
  const m = cfg.markets;
  return Array.isArray(m) ? Object.fromEntries(m.map((k) => [k, 1])) : { ...m };
}

/** People type round amounts a lot: $5,000, $12k, $25,000 ... the rest is jittered. */
function humanizeUsd(usd) {
  if (!chance(cfg.roundSizeChance)) return usd * (0.93 + Math.random() * 0.14);
  const mag = 10 ** Math.floor(Math.log10(usd));
  const r = usd / mag;
  const steps = [1, 1.2, 1.5, 2, 2.5, 3, 4, 5, 6, 7.5, 8, 10];
  return steps.reduce((b, s) => (Math.abs(s - r) < Math.abs(b - r) ? s : b), 1) * mag;
}

/** ...or a round coin amount (0.05 BTC, 3 SOL). Never below one size tick. */
function humanizeSize(size, szDec) {
  if (!(size > 0) || !chance(cfg.roundSizeChance / 2)) return size;
  const d = Math.max(0, Math.min(szDec, 1 - Math.floor(Math.log10(size))));
  return floorTo(size, d) || size;
}

// ---- market helpers

function tickDecimals(px, szDec) {
  // price grid of the exchange: <= 5 significant figures and <= (6 - szDecimals) decimals
  return Math.max(0, Math.min(6 - szDec, 4 - Math.floor(Math.log10(px))));
}

async function book(market, depth = 5) {
  const ob = await pub.orderbook(market, depth);
  const lv = (xs) => (xs || []).map((l) => ({ px: num(l.price), sz: num(l.size) })).filter((l) => l.px > 0);
  const bids = lv(ob?.bids);
  const asks = lv(ob?.asks);
  return { bids, asks, bid: bids[0]?.px || 0, ask: asks[0]?.px || 0 };
}

const liquidityUsd = (levels, ref, bps) => levels.filter((l) => Math.abs(l.px - ref) / ref <= bps / 1e4).reduce((s, l) => s + l.px * l.sz, 0);

function makerPrice(side, b, mk) {
  // Join the touch most of the time; step one tick inside when the spread leaves room.
  if (!(b.bid > 0 && b.ask > b.bid)) return null;
  const d = tickDecimals(side === 'buy' ? b.bid : b.ask, mk.szDecimals);
  const tick = 10 ** -d;
  const improve = Math.round((b.ask - b.bid) / tick) >= 2 && chance(0.35) ? tick : 0;
  const px = side === 'buy' ? b.bid + improve : b.ask - improve;
  if (side === 'buy' ? px >= b.ask : px <= b.bid) return null;
  return trimDec(px.toFixed(d));
}

function walkedAway(side, px, b, mk) {
  const tick = 10 ** -tickDecimals(px, mk.szDecimals);
  return side === 'buy' ? b.bid - px > 2 * tick : px - b.ask > 2 * tick;
}

async function chooseSide(market) {
  // Session bias + 12-minute drift, followed 60% / faded 40% — never a plain coin flip.
  let drift = 0;
  try {
    const c = await api('GET', `/v1/markets/${encodeURIComponent(market)}/candles`, { query: { interval: '1m', limit: 12 }, retry: false });
    const xs = (c?.items || []).slice().sort((a, b) => Date.parse(a.openTs) - Date.parse(b.openTs));
    if (xs.length >= 2) drift = Math.sign(num(xs[xs.length - 1].close) - num(xs[0].open));
  } catch { }
  const p = clamp(0.5 + plan.sideBias + (chance(0.6) ? 1 : -1) * drift * (0.08 + Math.random() * 0.12), [0.15, 0.85]);
  return chance(p) ? 'buy' : 'sell';
}

function desiredLeverage(mk) {
  // re-rolled per market per day, mostly on the values people click (3/5/10/20x)
  const st = store.state;
  const day = utcDay();
  if (st.levPlan?.date !== day) st.levPlan = { date: day, m: {} };
  if (!st.levPlan.m[mk.market]) {
    const [a, b] = asRange(cfg.leverage);
    const common = [2, 3, 5, 10, 15, 20].filter((x) => x >= a && x <= b && x <= mk.maxLeverage);
    const v = common.length && chance(0.75) ? pick(common) : randInt([a, b]);
    st.levPlan.m[mk.market] = Math.max(1, Math.min(v, mk.maxLeverage));
    saveStore();
  }
  return st.levPlan.m[mk.market];
}

async function planSize(mk, side, b) {
  const touch = side === 'buy' ? b.ask : b.bid;
  if (!(touch > 0)) return null;
  const lev = desiredLeverage(mk);
  let sz = await me.sizing(mk.market, String(touch)).catch(() => null);
  if (sz && num(sz.leverage) !== lev && !cfg.dryRun) {
    const r = await setLeverage(mk.market, lev);
    if (r?.ok === false) log(`set leverage ${mk.market} ${lev}x ditolak: ${r.reason}`, 'warn');
    sz = (await me.sizing(mk.market, String(touch)).catch(() => null)) || sz;
  }
  const free = num(sz?.availableToTrade) || (await getAccount()).available;
  const usedLev = num(sz?.leverage) || lev;
  const depthCap = liquidityUsd(side === 'buy' ? b.asks : b.bids, touch, 5) * (cfg.bookSharePct / 100);
  let usd = free * (logUniform(cfg.marginUsePct) / 100) * usedLev;
  usd = humanizeUsd(Math.min(usd, cfg.maxNotionalUsd, depthCap || usd));
  let size = humanizeSize(floorTo(usd / touch, mk.szDecimals), mk.szDecimals);
  const max = num(side === 'buy' ? sz?.maxBuySize : sz?.maxSellSize);
  if (max > 0 && size > max * 0.95) size = floorTo(max * (0.55 + Math.random() * 0.35), mk.szDecimals);
  // Per-market position cap (markets[].maxPositionNotional, web QS): valued at max(mark, order price), and a
  // taker IOC can price slippagePct past the touch, so stay a few % under it. The web applies it on top of /v1/me/sizing.
  const capUsd = mk.maxPositionNotional > 0 ? (mk.maxPositionNotional * 0.97) / (1 + cfg.slippagePct / 100) : Infinity;
  if (size * touch > capUsd) size = floorTo((capUsd / touch) * (0.8 + Math.random() * 0.2), mk.szDecimals);
  const min = mk.minNotional * 1.1;
  if (size * touch < min) size = Math.ceil((min / touch) * 10 ** mk.szDecimals) / 10 ** mk.szDecimals;
  if ((max > 0 && size > max) || size * touch > capUsd) return null;
  return { size, touch, lev: usedLev, usd: size * touch };
}

// ---- order plumbing

async function openOrderIds(market) {
  return new Set((await me.openOrders(market)).map((o) => o.orderId));
}

/** Fills of one order (from /v1/me/fills); waits for `min` fills to show up in the read model. */
async function orderFills(market, orderId, min = 0) {
  let f = [];
  for (let i = 0; i < (min > 0 ? 10 : 3); i++) {
    const r = await api('GET', '/v1/me/fills', { query: { market, limit: 100 }, signed: true, retry: false }).catch(() => null);
    f = (r?.items || []).filter((x) => x.orderId === orderId);
    if (min > 0 ? f.length >= min : f.length > 0 || i >= 1) break;
    await wait(700);
  }
  const acc = ZERO();
  for (const x of f) {
    const n = num(x.fillSize) * num(x.fillPrice);
    acc.size += num(x.fillSize);
    acc.notional += n;
    acc.fee += num(x.fee);
    if (x.liquidity === 'maker') acc.makerNotional += n;
  }
  return acc;
}

function trackOrder(slot, id, on) {
  const s = store.state.slots?.[slot.id];
  if (!s) return;
  s.orders = (s.orders || []).filter((x) => x !== id);
  if (on) s.orders.push(id);
  saveStore();
}

const posSize = async (market) => Math.abs(num((await findPosition(market).catch(() => null))?.size));

/**
 * Fill `size` on one side. maker: post-only at/inside the touch, re-quoted when the market walks away,
 * until a random patience runs out; the rest goes taker IOC when `takerRest` (exits always do).
 * Filled amount = max(fills read model, position change), so a lagging fills feed never makes the
 * bot quote the same size twice.
 */
async function execute(slot, mk, { side, size, reduceOnly = false, maker = false, takerRest = true }) {
  const market = mk.market;
  const acc = ZERO();
  const tick = 10 ** -mk.szDecimals;
  const left = () => floorTo(size - acc.size, mk.szDecimals);
  const tradable = (q, px) => q >= tick - 1e-12 && (reduceOnly || q * px >= mk.minNotional * 1.02);
  const leg = reduceOnly ? 'exit' : 'entry';
  const ro = reduceOnly ? { reduceOnly: true } : {};
  const base = await posSize(market);
  const syncWithPosition = async (px) => {
    const now = await posSize(market);
    const moved = reduceOnly ? base - now : now - base;
    if (moved > acc.size + tick / 2) { acc.notional += (moved - acc.size) * px; acc.size = moved; }
  };

  if (maker && !stopping) {
    const deadline = Date.now() + logUniform(cfg.makerWaitSec) * 1000;
    for (let q = 0; q <= cfg.makerChaseMax && !stopping && Date.now() < deadline; q++) {
      const px = makerPrice(side, await book(market), mk);
      if (!px || !tradable(left(), num(px))) break;
      slot.phase = `${leg} maker`;
      slot.until = deadline;
      const res = await placeOrder({ market, side, type: 'limit', size: fmtSize(left(), mk.szDecimals), price: px, tif: 'alo', ...ro });
      if (res?.dry) return acc;
      if (!res?.ok) {
        if (res?.reason === 'post_only_would_cross') continue;
        if (CLOSED_REASONS.has(res?.reason)) return acc;
        log(`${market} ${leg} maker ditolak: ${res?.message || res?.reason}`, 'warn');
        break;
      }
      const id = res.orderId;
      trackOrder(slot, id, true);
      const requoteAfter = Date.now() + (4 + Math.random() * 12) * 1000;
      for (; ;) {
        await wait(1100 + Math.random() * 1700);
        if (stopping || Date.now() > deadline) break;
        if (!(await openOrderIds(market).catch(() => new Set([id]))).has(id)) break; // filled
        if (Date.now() > requoteAfter && walkedAway(side, num(px), await book(market), mk)) break;
      }
      await cancelOrder(id).catch(() => null); // harmless when it already filled
      trackOrder(slot, id, false);
      addFills(acc, await orderFills(market, id));
      await syncWithPosition(num(px));
      if (!tradable(left(), num(px))) break;
    }
  }

  if (takerRest && left() > 0) {
    const b = await book(market);
    const best = side === 'buy' ? b.ask : b.bid;
    const cap = slipCap(best, side, cfg.slippagePct / 100, mk.szDecimals);
    if (cap && tradable(left(), best)) {
      slot.phase = `${leg} taker`;
      slot.until = 0;
      const res = await placeOrder({ market, side, type: 'limit', size: fmtSize(left(), mk.szDecimals), price: cap, tif: 'ioc', ...ro });
      if (res?.ok && num(res.fills) > 0) addFills(acc, await orderFills(market, res.orderId, num(res.fills)));
      else if (res && !res.ok && !CLOSED_REASONS.has(res.reason)) log(`${market} ${leg} taker ditolak: ${res.message || res.reason}`, 'warn');
    }
  }
  return acc;
}

/** Reduce-only taker until the position is gone (the guarantee behind every exit and recovery). */
async function flatten(slot, mk) {
  const acc = ZERO();
  if (cfg.dryRun) return acc; // dry run never touches a real position
  for (let i = 1; i <= cfg.closeRetryMax; i++) {
    const pos = await findPosition(mk.market);
    if (!pos) return acc;
    const side = num(pos.size) > 0 ? 'sell' : 'buy';
    const b = await book(mk.market);
    const cap = slipCap(side === 'buy' ? b.ask : b.bid, side, cfg.slippagePct / 100, mk.szDecimals);
    if (cap) {
      if (slot) { slot.phase = 'tutup taker'; slot.until = 0; }
      const res = await placeOrder({ market: mk.market, side, type: 'limit', size: trimDec(String(pos.size).replace('-', '')), price: cap, tif: 'ioc', reduceOnly: true });
      if (res?.ok && num(res.fills) > 0) {
        addFills(acc, await orderFills(mk.market, res.orderId, num(res.fills)));
        if (await waitForFlat(mk.market, cfg.positionPollTimeoutSec)) return acc;
        continue;
      }
      if (res && !res.ok && CLOSED_REASONS.has(res.reason)) return acc;
    }
    await wait(2500);
  }
  throw new Error(`posisi ${mk.market} belum flat setelah ${cfg.closeRetryMax}x`);
}

async function exitLeg(slot, mk, portion, maker) {
  const pos = await findPosition(mk.market);
  if (!pos) return ZERO();
  const total = Math.abs(num(pos.size));
  const size = portion >= 1 ? total : floorTo(total * portion, mk.szDecimals);
  if (!(size > 0)) return ZERO();
  return execute(slot, mk, { side: num(pos.size) > 0 ? 'sell' : 'buy', size, reduceOnly: true, maker, takerRest: portion >= 1 });
}

function persistSlot(slot, stage) {
  const all = (store.state.slots ||= {});
  all[slot.id] = { ...(all[slot.id] || { orders: [] }), market: slot.market, side: slot.side, stage, startedAt: new Date(slot.startedAt).toISOString() };
  saveStore();
}

async function runSlot(slot) {
  const mk = (await getMarkets())[slot.market];
  const entry = ZERO();
  const exit = ZERO();
  let opened = 0;
  try {
    slot.phase = 'analisa';
    slot.side = await chooseSide(slot.market);
    const p = await planSize(mk, slot.side, await book(slot.market, 20));
    if (!p) { log(`${slot.market}: margin tidak cukup untuk ukuran minimum`, 'warn'); return; }
    const label = `${slot.market} ${sideLabel(slot.side === 'buy')}`;
    if (cfg.dryRun) {
      log(`[dryRun] ${label} ${fmtSize(p.size, mk.szDecimals)} (~$${money(p.usd, 0)}, ${p.lev}x) — tidak dikirim`);
      return;
    }
    if (stopping) return; // Ctrl+C while planning: never open on the way out
    persistSlot(slot, 'entry');
    const clips = chance(cfg.scaleInChance) ? (chance(0.7) ? 2 : 3) : 1;
    const weights = Array.from({ length: clips }, () => 0.5 + Math.random());
    const wsum = weights.reduce((a, c) => a + c, 0);
    for (let i = 0; i < clips && !stopping; i++) {
      const part = i === clips - 1 ? floorTo(p.size - entry.size, mk.szDecimals) : floorTo((p.size * weights[i]) / wsum, mk.szDecimals);
      if (part * p.touch < mk.minNotional * 1.05) continue;
      addFills(entry, await execute(slot, mk, { side: slot.side, size: part, maker: chance(cfg.makerChance), takerRest: chance(0.75) }));
      if (i < clips - 1) { slot.phase = 'jeda clip'; slot.until = 0; await sleep(heavyTail(7, [2, 40]) * 1000); }
    }
    const pos = await waitForPosition(slot.market, entry.size > 0 ? cfg.positionPollTimeoutSec : 4);
    if (!pos) return; // nothing filled (maker never touched, taker skipped)
    opened = Date.now();
    persistSlot(slot, 'hold');
    const style = entry.notional && entry.makerNotional / entry.notional >= 0.5 ? 'maker' : 'taker';
    log(`BUKA ${label} ${trimDec(String(pos.size).replace('-', ''))} (~$${money(entry.notional || p.usd, 0)}, ${p.lev}x, ${style}) | fee ${entry.fee.toFixed(4)}`, 'trade');
    refreshSoon();

    let hold = (heavyTail(cfg.holdMedianSec, cfg.holdSec) * 1000) / Math.sqrt(plan.intensity);
    if (chance(cfg.partialExitChance)) {
      const first = hold * (0.3 + Math.random() * 0.4);
      slot.phase = 'tahan';
      slot.until = Date.now() + first;
      await sleep(first);
      if (!stopping) addFills(exit, await exitLeg(slot, mk, 0.3 + Math.random() * 0.4, chance(cfg.makerChance)));
      hold -= first;
    }
    slot.phase = 'tahan';
    slot.until = Date.now() + hold;
    await sleep(hold);
    if (stopping && !cfg.closeOnExit) return;
    persistSlot(slot, 'exit');
    addFills(exit, await exitLeg(slot, mk, 1, !stopping && chance(cfg.makerChance)));
    addFills(exit, await flatten(slot, mk));
  } catch (e) {
    if (e instanceof ApiError && e.deadSession) dropSession(e.code || e.status);
    log(`slot ${slot.market} error: ${errText(e)} — posisinya dibereskan otomatis`, 'err');
  } finally {
    slots.delete(slot.id);
    if (entry.size > 0) {
      const dir = slot.side === 'buy' ? 1 : -1;
      const pnl = exit.size > 0 ? dir * (exit.notional / exit.size - entry.notional / entry.size) * Math.min(exit.size, entry.size) : 0;
      const fee = entry.fee + exit.fee;
      const ex = (x) => (x.notional && x.makerNotional / x.notional >= 0.5 ? 'M' : 'T');
      addVolume(entry.notional + exit.notional, fee, entry.makerNotional + exit.makerNotional);
      if (exit.size > 0) {
        recordTrade({
          at: new Date().toISOString(), market: slot.market, side: slot.side, size: fmtSize(entry.size, mk.szDecimals), notional: entry.notional,
          holdMs: opened ? Date.now() - opened : 0, pnl, fee, exec: `${ex(entry)}→${ex(exit)}`,
        });
        log(`TUTUP ${slot.market} ${sideLabel(slot.side === 'buy')} | vol $${money(entry.notional + exit.notional, 0)} | PnL ${signedAuto(pnl)} | fee ${fee.toFixed(4)} | ${ex(entry)}→${ex(exit)}`, 'trade');
      }
    }
    // keep the persisted record only while something may still be open; recovery flattens it later
    const rec = store.state.slots?.[slot.id];
    if (rec) {
      const open = await findPosition(slot.market).catch(() => true);
      if (!open && !(rec.orders || []).length) { delete store.state.slots[slot.id]; saveStore(); }
    }
    refreshSoon();
  }
}

async function recoverSlot(id, s) {
  // A slot from a crash / forced exit: cancel its resting orders, flatten its position, forget it.
  recovering.add(id);
  try {
    for (const oid of s.orders || []) await cancelOrder(oid).catch(() => null);
    const mk = (await getMarkets())[s.market];
    if (!mk) throw new Error(`market ${s.market} tidak ada`);
    const pos = await waitForPosition(s.market, s.stage === 'entry' || s.legacy ? cfg.positionPollTimeoutSec : 6);
    if (pos) {
      log(`pulihkan: tutup posisi bot ${s.market} sisa sesi sebelumnya (${pos.size})`, 'warn');
      const f = await flatten(null, mk);
      addVolume(f.notional, f.fee, f.makerNotional);
    }
    delete store.state.slots[id];
    saveStore();
  } catch (e) {
    if (e instanceof ApiError && e.deadSession) dropSession(e.code || e.status);
    log(`pulihkan ${s.market}: ${errText(e)} — dicoba lagi`, 'warn');
  } finally {
    recovering.delete(id);
  }
}

function migrateLegacyOpenTrade() {
  // pre-engine versions tracked a single `openTrade`
  const t = store.state.openTrade;
  if (!t) return;
  (store.state.slots ||= {})[`legacy-${Date.parse(t.openedAt) || Date.now()}`] = { market: t.market, side: t.side, stage: 'hold', orders: [], legacy: true, startedAt: t.openedAt };
  delete store.state.openTrade;
  saveStore();
}

function restWindow(now) {
  // one long rest per local day, random start inside restWindowLocal, random length
  const [h0, h1] = asRange(cfg.dailyRestHours);
  if (!(h1 > 0)) return null;
  const d = new Date(now);
  const key = d.toDateString();
  const st = store.state;
  if (st.rest?.key !== key) {
    const dur = (h0 + Math.random() * (h1 - h0)) * 3600e3;
    const [w0, w1] = asRange(cfg.restWindowLocal);
    const day0 = new Date(d.getFullYear(), d.getMonth(), d.getDate()).getTime();
    const room = Math.max(0, (w1 - w0) * 3600e3 - dur);
    const start = day0 + w0 * 3600e3 + Math.random() * room;
    st.rest = { key, start, end: start + dur };
    saveStore();
  }
  return now >= st.rest.start && now < st.rest.end ? st.rest : null;
}

function newSession(now) {
  plan.sessionEndsAt = now + logUniform(cfg.sessionMin) * 60e3;
  plan.intensity = 0.6 + Math.random() * 0.8;
  plan.target = Math.max(1, randInt(cfg.maxConcurrent));
  plan.sideBias = (Math.random() - 0.5) * 0.3;
  plan.weights = Object.fromEntries(Object.entries(marketWeights()).map(([m, w]) => [m, w * logUniform([0.5, 2])]));
  plan.nextOpenAt = Math.max(plan.nextOpenAt, now + heavyTail(5, [1, 45]) * 1000);
  log(`sesi baru ${fmtDur(plan.sessionEndsAt - now)} · intensitas ${plan.intensity.toFixed(2)} · maks ${plan.target} posisi`);
}

function updatePlan(now) {
  if (!plan.sessionEndsAt && !plan.breakUntil) return newSession(now);
  if (plan.sessionEndsAt && now >= plan.sessionEndsAt) {
    plan.sessionEndsAt = 0;
    const [a, b] = asRange(cfg.breakMin);
    if (b > 0) {
      plan.breakUntil = now + logUniform([Math.max(a, 0.1), b]) * 60e3;
      log(`istirahat sebentar ${fmtDur(plan.breakUntil - now)}`);
    } else newSession(now);
  } else if (plan.breakUntil && now >= plan.breakUntil) {
    plan.breakUntil = 0;
    newSession(now);
  }
}

async function openBlocker(now) {
  // Reasons not to OPEN a new position right now (open ones always finish).
  if (now - healthCache.at > 60e3) healthCache = { at: now, ok: await engineHealthy() };
  if (!healthCache.ok) return 'engine exchange macet';
  const d = dayStats();
  if (cfg.maxTradesPerDay > 0 && d.roundTrips >= cfg.maxTradesPerDay) return `batas ${cfg.maxTradesPerDay} trade/hari`;
  if (cfg.maxFeesPerDayUsd > 0 && d.feesUsd >= cfg.maxFeesPerDayUsd) return `batas fee harian $${cfg.maxFeesPerDayUsd}`;
  const a = now - view.accountAt < 20e3 && view.account ? { value: num(view.account.accountValue), available: num(view.account.available) } : await getAccount();
  if (a.value < cfg.equityFloorUsd) {
    const cd = num(store.state.faucetCooldownUntil) - now;
    return `nilai akun ${money(a.value)} < ${money(cfg.equityFloorUsd, 0)} — nunggu faucet${cd > 0 ? ` (${fmtDur(cd)})` : ''}`;
  }
  if (a.available < cfg.minAvailableUsd) return `margin bebas ${money(a.available)} < ${cfg.minAvailableUsd}`;
  return null;
}

async function pickMarket() {
  const markets = await getMarkets();
  const positions = await me.positions();
  const busy = new Set([
    ...positions.filter((p) => num(p.size) !== 0).map((p) => p.market), // manual positions are never touched
    ...[...slots.values()].map((s) => s.market),
    ...Object.values(store.state.slots || {}).map((s) => s.market),
  ]);
  const w = {};
  for (const [m, x] of Object.entries(plan.weights || marketWeights())) if (markets[m] && !busy.has(m)) w[m] = x;
  return weightedPick(w);
}

function enginePhase(now) {
  let head;
  if (stopping) head = 'berhenti — menutup posisi bot';
  else if (recovering.size) head = `memulihkan ${recovering.size} posisi lama`;
  else if (plan.resting) head = `☾ istirahat harian · ${fmtDur(plan.resting.end - now)}`;
  else if (plan.breakUntil > now) head = `istirahat · ${fmtDur(plan.breakUntil - now)}`;
  else if (plan.block) head = `pause: ${plan.block}`;
  else {
    head = `aktif ${slots.size}/${plan.target}`;
    if (plan.sessionEndsAt) head += ` · sesi ${fmtDur(plan.sessionEndsAt - now)}`;
    if (slots.size < plan.target && plan.nextOpenAt > now) head += ` · buka lagi ${fmtDur(plan.nextOpenAt - now)}`;
  }
  const parts = [...slots.values()].map((s) => `${s.market.split('-')[0]} ${s.side ? sideLabel(s.side === 'buy') : ''} ${s.phase}${s.until > now ? ` ${fmtDur(s.until - now)}` : ''}`);
  return [head, ...parts].join('  │  ');
}

/** One scheduler step: recover leftovers, update sessions/rest, maybe start a slot. Returns { task } when it starts one. */
async function schedulerTick(once = false) {
  const now = Date.now();
  const fb = cx().forbiddenUntil - now;
  if (fb > 0) { plan.block = `server menolak order akun ini (403 forbidden) — coba lagi ${fmtDur(fb)}`; return null; }
  // leftovers are only cleaned up live; a dry run just keeps away from those markets
  if (!cfg.dryRun) for (const [id, s] of Object.entries(store.state.slots || {})) if (!slots.has(id) && !recovering.has(id)) recoverSlot(id, s);
  if (stopping || recovering.size) return null;
  if (!once) {
    updatePlan(now);
    plan.resting = restWindow(now);
    if (plan.resting || plan.breakUntil > now) return null;
  }
  plan.block = await openBlocker(now);
  if (plan.block) return null;
  if (slots.size >= (once ? 1 : plan.target) || (!once && now < plan.nextOpenAt)) return null;
  const market = await pickMarket();
  if (!market) { plan.block = 'semua market sedang terisi'; return null; }
  const slot = { id: `s${now.toString(36)}${slotSeq++}`, market, side: null, phase: 'mulai', until: 0, startedAt: now };
  slots.set(slot.id, slot);
  plan.nextOpenAt = now + (heavyTail(cfg.delayMedianSec, cfg.delaySec) * 1000) / plan.intensity;
  slot.task = runSlot(slot);
  return { task: slot.task };
}

// ---------------------------------------------------------------------------------------------
// dashboard — pinned ANSI frame redrawn in place (same idea as ModuloBot), no dependencies

const C = { reset: '\x1b[0m', bold: '\x1b[1m', red: '\x1b[31m', green: '\x1b[32m', yellow: '\x1b[33m', cyan: '\x1b[36m', gray: '\x1b[90m' };
const KIND_COLOR = { ok: C.green, err: C.red, warn: C.yellow, trade: C.cyan, work: C.cyan, info: '' };
const BX = { tl: '┌', tr: '┐', bl: '└', br: '┘', h: '─', v: '│', lt: '├', rt: '┤', tt: '┬', bt: '┴', x: '┼' };
const LOG_LINES = [];
const view = facade('view');
let lastRenderLines = 0;
let renderTimer = null;
let refreshing = false;

const stripAnsi = (s) => String(s ?? '').replace(/\x1b\[[0-9;]*m/g, '');
const vlen = (s) => stripAnsi(s).length;
const paint = (color, s) => (color ? `${color}${s}${C.reset}` : String(s));

/** Truncate on visible length, then pad. Colour codes never count as width. */
function cell(s, n, align = 'left') {
  const raw = stripAnsi(s);
  const t = raw.length > n ? `${raw.slice(0, Math.max(0, n - 1))}…` : raw;
  return align === 'right' ? t.padStart(n) : t.padEnd(n);
}

/** Pad a coloured string to visible width n (drops the colours only when it has to truncate). */
function fit(s, n) {
  const l = vlen(s);
  return l > n ? cell(s, n) : s + ' '.repeat(n - l);
}

const money = (x, d = 2) => num(x).toLocaleString('en-US', { minimumFractionDigits: d, maximumFractionDigits: d });
const signed = (x, d = 2) => `${num(x) > 0 ? '+' : ''}${money(x, d)}`;
const signedAuto = (x) => signed(x, Math.abs(num(x)) < 1 ? 4 : 2);
const tone = (x) => (num(x) > 0 ? C.green : num(x) < 0 ? C.red : '');
const handleOf = (party) => (party ? String(party).split('::')[0] : '-');
const sideLabel = (buy) => (buy ? 'LONG' : 'SHORT');

function price(x) {
  const n = num(x);
  if (!n) return '-';
  return n.toLocaleString('en-US', { maximumFractionDigits: n >= 1000 ? 1 : n >= 10 ? 2 : n >= 1 ? 4 : 5 });
}

function compact(x) {
  const n = num(x);
  if (n >= 1e9) return `${(n / 1e9).toFixed(2)}B`;
  if (n >= 1e6) return `${(n / 1e6).toFixed(2)}M`;
  if (n >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
  return n.toFixed(0);
}

/** A column of width w costs w + 3 ('│' + ' ' + w + ' '), plus one closing '│'. */
const lineWidth = (cols) => 1 + cols.reduce((s, c) => s + c.w + 3, 0);

/**
 * `prio` = keep-order when the terminal is narrow (1 is never dropped). Every table is stretched to
 * the full width so all boxes line up; leftover width goes to the `flex` column (or the last one).
 */
function layout(defs, avail) {
  let cols = defs.map((c) => ({ prio: 1, ...c, w: c.min }));
  while (lineWidth(cols) > avail) {
    const worst = cols.reduce((w, c) => (c.prio > 1 && (!w || c.prio > w.prio) ? c : w), null);
    if (!worst) break;
    cols = cols.filter((c) => c !== worst);
  }
  let slack = avail - lineWidth(cols);
  for (const c of [...cols].sort((a, b) => a.prio - b.prio)) {
    if (slack <= 0) break;
    const add = Math.min((c.ideal ?? c.min) - c.w, slack);
    if (add > 0) { c.w += add; slack -= add; }
  }
  if (slack > 0) {
    // spread the rest evenly so wide terminals get balanced tables, remainder to the flex column
    const per = Math.floor(slack / cols.length);
    for (const c of cols) c.w += per;
    (cols.find((c) => c.flex) || cols[cols.length - 1]).w += slack - per * cols.length;
  }
  return cols;
}

function boxTop(W, left, right = '') {
  // ┌─ left ──────────── right ─┐   (right is dropped, then left truncated, when the line is too narrow)
  let l = ` ${left} `;
  let r = vlen(right) ? ` ${right} ` : '';
  if (vlen(l) + vlen(r) > W - 4) r = '';
  if (vlen(l) > W - 4) l = cell(l, W - 4);
  const fill = Math.max(0, W - 4 - vlen(l) - vlen(r));
  return `${C.gray}${BX.tl}${BX.h}${C.reset}${C.bold}${l}${C.reset}${C.gray}${BX.h.repeat(fill)}${C.reset}${r}${C.gray}${BX.h}${BX.tr}${C.reset}`;
}
const boxLine = (W, s) => `${C.gray}${BX.v}${C.reset} ${fit(s, W - 4)} ${C.gray}${BX.v}${C.reset}`;
const boxRule = (W, l, r) => `${C.gray}${l}${BX.h.repeat(W - 2)}${r}${C.reset}`;
const colRule = (cols, l, m, r) => `${C.gray}${l}${cols.map((c) => BX.h.repeat(c.w + 2)).join(m)}${r}${C.reset}`;

function colRow(cols, cells) {
  const body = cols.map((c, i) => ` ${paint(cells[i].color, cell(cells[i].text, c.w, c.align))} `).join(`${C.gray}${BX.v}${C.reset}`);
  return `${C.gray}${BX.v}${C.reset}${body}${C.gray}${BX.v}${C.reset}`;
}

function tableBox(W, title, right, defs, rows, maxRows, empty) {
  const cols = layout(defs, W);
  const out = [boxTop(W, title, right), colRow(cols, cols.map((c) => ({ text: c.label, color: C.gray }))), colRule(cols, BX.lt, BX.x, BX.rt)];
  const shown = rows.length > maxRows ? rows.slice(0, Math.max(0, maxRows - 1)) : rows;
  for (const r of shown) out.push(colRow(cols, cols.map((c) => ({ text: c.get(r), color: c.color ? c.color(r) : c.dim ? C.gray : '' }))));
  const note = !rows.length ? empty : shown.length < rows.length ? `+${rows.length - shown.length} lagi` : null;
  const wide = cols.reduce((best, c, i) => (c.w > cols[best].w ? i : best), 0);
  if (note) out.push(colRow(cols, cols.map((c, i) => ({ text: i === wide ? note : '', color: C.gray }))));
  out.push(colRule(cols, BX.bl, BX.bt, BX.br));
  return out;
}

const openPositions = () => (view.account?.positions || []).filter((p) => num(p.size) !== 0);
const liveSlot = (market) => [...slots.values()].find((x) => x.market === market);
const isBotPos = (market) => !!liveSlot(market) || Object.values(store.state.slots || {}).some((x) => x.market === market);

const POS_COLS = [
  { label: 'MARKET', min: 9, ideal: 10, get: (p) => p.market },
  { label: 'SISI', min: 5, ideal: 5, get: (p) => sideLabel(num(p.size) > 0), color: (p) => (num(p.size) > 0 ? C.green : C.red) },
  { label: 'SIZE', min: 7, ideal: 10, align: 'right', get: (p) => trimDec(String(p.size).replace('-', '')) },
  { label: 'ENTRY', min: 8, ideal: 10, align: 'right', prio: 2, get: (p) => price(p.entryPrice) },
  { label: 'MARK', min: 8, ideal: 10, align: 'right', prio: 2, get: (p) => price(p.markPrice) },
  { label: 'uPnL', min: 8, ideal: 10, align: 'right', get: (p) => signedAuto(p.unrealizedPnl), color: (p) => tone(p.unrealizedPnl) },
  { label: 'ROE', min: 7, ideal: 8, align: 'right', prio: 3, get: (p) => `${signed(num(p.returnOnEquity) * 100, 1)}%`, color: (p) => tone(p.returnOnEquity) },
  { label: 'LEV', min: 3, ideal: 4, align: 'right', prio: 3, get: (p) => `${p.leverage}x` },
  { label: 'LIKUIDASI', min: 9, ideal: 10, align: 'right', prio: 4, get: (p) => price(p.liquidationPrice) },
  {
    label: 'PEMILIK', min: 7, ideal: 14, flex: true, prio: 2,
    get: (p) => { const s = liveSlot(p.market); return s ? `bot · ${s.phase}` : isBotPos(p.market) ? 'bot (pulih)' : 'manual'; },
    color: (p) => (isBotPos(p.market) ? C.cyan : C.gray),
  },
];

function marketRows() {
  return Object.keys(view.mids || {}).sort().map((m) => {
    const st = view.stats[m];
    const last = num(st?.lastPrice) || num(view.mids[m]);
    const prev = num(st?.prevPrice24h);
    const pos = openPositions().find((p) => p.market === m);
    const status = pos ? (isBotPos(m) ? 'posisi bot' : 'posisi manual') : liveSlot(m) ? 'order bot' : num(marketWeights()[m]) > 0 ? 'siap' : 'off';
    return { m, mid: view.mids[m], chg: prev ? ((last - prev) / prev) * 100 : null, vol: st?.volume24hQuote, trades: st?.trades24h, status };
  });
}

const MARKET_COLS = [
  { label: 'MARKET', min: 9, ideal: 10, get: (r) => r.m },
  { label: 'HARGA', min: 9, ideal: 11, align: 'right', get: (r) => price(r.mid) },
  { label: '24J', min: 7, ideal: 8, align: 'right', get: (r) => (r.chg === null ? '-' : `${signed(r.chg)}%`), color: (r) => tone(r.chg) },
  { label: 'VOL 24J', min: 8, ideal: 9, align: 'right', prio: 3, get: (r) => (r.vol ? `$${compact(r.vol)}` : '-') },
  { label: 'TRADES', min: 6, ideal: 7, align: 'right', prio: 4, get: (r) => (r.trades ? compact(r.trades) : '-') },
  {
    label: 'STATUS', min: 7, ideal: 13, flex: true, prio: 2, get: (r) => r.status,
    color: (r) => ({ siap: C.green, 'posisi bot': C.cyan, 'order bot': C.cyan, 'posisi manual': C.yellow }[r.status] || C.gray),
  },
];

const TRADE_COLS = [
  { label: 'WAKTU', min: 5, ideal: 5, prio: 2, get: (t) => new Date(t.at).toLocaleTimeString('en-GB', { hour12: false }).slice(0, 5) },
  { label: 'MARKET', min: 9, ideal: 10, flex: true, get: (t) => t.market },
  { label: 'SISI', min: 5, ideal: 5, get: (t) => sideLabel(t.side === 'buy'), color: (t) => (t.side === 'buy' ? C.green : C.red) },
  { label: 'SIZE', min: 7, ideal: 10, align: 'right', prio: 3, get: (t) => t.size },
  { label: 'NOTIONAL', min: 8, ideal: 9, align: 'right', prio: 2, get: (t) => money(t.notional) },
  { label: 'HOLD', min: 4, ideal: 5, align: 'right', prio: 3, get: (t) => fmtDur(t.holdMs) },
  { label: 'EKS', min: 3, ideal: 4, prio: 3, get: (t) => t.exec || '-' },
  { label: 'PnL', min: 8, ideal: 9, align: 'right', get: (t) => signedAuto(t.pnl), color: (t) => tone(t.pnl) },
  { label: 'FEE', min: 6, ideal: 7, align: 'right', prio: 2, get: (t) => money(t.fee, 4) },
];

function headerBox(W, now) {
  const a = view.account || {};
  const s = store.session;
  const st = store.state;
  const ph = view.phase;
  const p = view.points;
  const upnl = openPositions().reduce((sum, x) => sum + num(x.unrealizedPnl), 0);
  const RULE_NAMES = { first_trade_bonus: 'bonus', weekly_trades_streak: 'streak' };
  const rules = (p?.byRule || []).map((r) => {
    const k = String(r.rule).replace(/_v\d+$/, '');
    return `${RULE_NAMES[k] || k.replace(/_/g, ' ')} ${money(r.points, 0)}`;
  }).join(' · ');

  const sessLeft = s ? Date.parse(s.expiresAt) - now : 0;
  const sessCell = !s ? paint(C.red, 'belum ada') : paint(sessLeft <= 0 ? C.red : sessLeft < cfg.sessionRenewBeforeH * 3600e3 ? C.yellow : '', sessLeft > 0 ? `${fmtDur(sessLeft)} lagi` : 'habis');
  let loginCell = '-';
  if (account.loginMode === 'evm') loginCell = 'wallet EVM';
  else if (store.auth0?.refreshToken) loginCell = 'refresh token';
  else {
    const exp = store.auth0?.cookies?.find((c) => c.name === 'auth0')?.expires;
    if (exp) loginCell = paint(exp - now <= 0 ? C.red : exp - now < 24 * 3600e3 ? C.yellow : '', exp > now ? `cookie ${fmtDur(exp - now)}` : 'cookie habis → login');
  }
  const value = num(a.accountValue);
  const cdLeft = num(st.faucetCooldownUntil) - now;
  const faucetCell = !cfg.autoFaucet ? paint(C.gray, 'auto-klaim off')
    : cdLeft > 0 ? paint(C.yellow, `cooldown ${fmtDur(cdLeft)}`)
      : !a.accountValue ? '-'
        : value >= cfg.faucetBelowUsd ? paint(C.gray, `auto · klaim < ${compact(cfg.faucetBelowUsd)}`) : paint(C.green, 'auto · klaim sekarang');
  const items = [
    ['Nilai akun', a.accountValue ? `${money(a.accountValue)} USDCx` : '-'],
    ['Margin bebas', a.available ? money(a.available) : '-'],
    ['uPnL', paint(tone(upnl), signedAuto(upnl))],
    ['Margin pakai', a.marginUsed ? money(a.marginUsed) : '-'],
    ['Points', p ? `${money(p.total, 0)}${p.rank ? paint(C.gray, ` #${money(p.rank, 0)}/${money(p.rankedParties, 0)}`) : ''}` : '-'],
    ['Rincian', rules || '-'],
    [`Vol ${view.volumeWindow || '7d'}`, view.volume ? `$${compact(view.volume)}` : '-'], // server (web /rewards)
    ['Fee total', view.fees ? money(view.fees) : '-'],                                     // server (portfolio cumFees)
    ['PnL real', view.serverStatsAt ? paint(tone(view.realizedPnl), signedAuto(view.realizedPnl)) : '-'], // server
    ['Faucet', faucetCell],
    ['Session API', sessCell],
    ['Login', loginCell],
    ['Party', handleOf(s?.party)],
    ['Referral', view.referral?.codeUsed || (view.referral?.bound ? 'terikat' : '-')],
  ];

  const mkts = Object.entries(marketWeights()).filter(([, w]) => w > 0).map(([m]) => m.split('-')[0]).join('/');
  const mode = [cfg.dryRun ? paint(C.yellow, 'DRY RUN') : 'live', account.loginMode, `lev ${asRange(cfg.leverage).join('–')}x`, `margin ${asRange(cfg.marginUsePct).join('–')}%`, mkts].join(' · ');
  const age = view.accountAt ? `data ${fmtDur(now - view.accountAt)} lalu · ` : '';
  // ph.fn = live engine status (sessions, pauses, every slot's step); plain text otherwise
  const phText = ph.fn ? ph.fn(now) : ph.text;
  const phKind = ph.fn ? (stopping || plan.block ? 'warn' : slots.size ? 'trade' : 'info') : ph.kind;
  const eta = !ph.fn && ph.until > now ? paint(C.gray, ` · ${fmtDur(ph.until - now)}`) : '';
  const out = [
    boxTop(W, `TitanxBot-Sipal ${paint(C.gray, mode)}`, paint(C.gray, `${age}${new Date(now).toLocaleTimeString('en-GB', { hour12: false })}`)),
    boxLine(W, `${paint(KIND_COLOR[phKind] || C.gray, '●')} ${phText}${eta}`),
    boxRule(W, BX.lt, BX.rt),
  ];
  const inner = W - 4;
  // 3-4 columns only when each label+value cell gets >= 34 chars; 2 narrow columns beat 1 tall one
  const n = inner >= 4 * 36 ? 4 : inner >= 3 * 36 ? 3 : inner >= 54 ? 2 : 1;
  const cw = Math.floor((inner - (n - 1) * 2) / n);
  for (let i = 0; i < items.length; i += n) {
    out.push(boxLine(W, items.slice(i, i + n).map(([k, v]) => fit(`${paint(C.gray, k.padEnd(13))}${v}`, cw)).join('  ')));
  }
  out.push(boxRule(W, BX.bl, BX.br));
  return out;
}

function activityBox(W, rows) {
  const out = [boxTop(W, 'Aktivitas', paint(C.gray, cfg.logFile || ''))];
  const lines = LOG_LINES.slice(-rows);
  for (let i = 0; i < rows; i++) {
    const l = lines[i];
    out.push(boxLine(W, l ? `${paint(C.gray, l.t)}  ${paint(KIND_COLOR[l.kind], cell(l.msg, W - 14))}` : ''));
  }
  out.push(boxRule(W, BX.bl, BX.br));
  return out;
}

function frame(oneShot = false) {
  const now = Date.now();
  const W = Math.max(60, process.stdout.columns || 100);
  const H = oneShot ? Infinity : Math.max(16, (process.stdout.rows || 30) - 1);
  const out = headerBox(W, now);
  const pos = openPositions();
  out.push(...tableBox(W, 'Posisi', paint(C.gray, `${pos.length} terbuka`), POS_COLS, pos, 6, 'tidak ada posisi'));

  // Height budget: header + positions always; activity keeps >= 3 lines; trades before market table.
  const ACT_MIN = oneShot ? 0 : 5;
  const hist = (store.state.history || []).slice().reverse();
  const tradeMin = 4 + Math.min(3, Math.max(1, hist.length));
  let room = H - out.length;
  const mrows = marketRows();
  if (mrows.length) {
    const mkt = tableBox(W, 'Market', paint(C.gray, view.statsAt ? `24j · ${fmtDur(now - view.statsAt)} lalu` : ''), MARKET_COLS, mrows, mrows.length, '-');
    if (room - mkt.length >= ACT_MIN + tradeMin) { out.push(...mkt); room -= mkt.length; }
  }
  if (room >= ACT_MIN + tradeMin) {
    // server-truth totals (volume = web /rewards, fee/PnL = portfolio)
    const right = `vol $${compact(view.volume)} (${view.volumeWindow || '7d'}) · fee ${money(view.fees, 2)} · PnL real ${paint(tone(view.realizedPnl), signedAuto(view.realizedPnl))}`;
    const want = 4 + Math.min(10, Math.max(1, hist.length));
    const lines = oneShot ? want : Math.min(want, Math.max(tradeMin, room - ACT_MIN - 3));
    const t = tableBox(W, 'Trade bot terakhir', paint(C.gray, right), TRADE_COLS, hist, lines - 4, 'belum ada trade');
    out.push(...t);
    room -= t.length;
  }
  if (!oneShot) out.push(...activityBox(W, Math.max(3, room - 2)));
  return oneShot ? out : out.slice(0, H);
}

function render() {
  if (renderTimer) { clearTimeout(renderTimer); renderTimer = null; }
  if (!dash) return;
  if (process.stdout.writableLength > 131072) return; // slow pipe: skip rather than buffer frames in RAM
  const out = frame();
  process.stdout.write(`${lastRenderLines ? `\x1b[${lastRenderLines}A` : ''}${out.map((r) => `\x1b[2K${r}`).join('\n')}\n\x1b[0J`);
  lastRenderLines = out.length;
}

function scheduleRender() {
  if (dash && !renderTimer) renderTimer = setTimeout(render, 300);
}

function setPhase(text, kind = 'work', until = 0) {
  view.phase = { text, kind, until };
  scheduleRender();
}

async function refreshView(force = false, light = false) {
  // Read-only GETs (request signature only, no action nonce), so it can run beside the trade loop.
  if (refreshing || !cx().cur) return;
  refreshing = true;
  try {
    const now = Date.now();
    const acct = await api('GET', '/v1/me/account', { signed: true, retry: false }).catch(() => null);
    if (acct) { view.account = acct; view.accountAt = now; }
    // Fleet workers (and the many-account one-shot `status`) only feed the parent's NILAI/uPnL/POS columns:
    // there is no market table, and VOL/POIN/RANK are refreshed by the engine's logPoints() every 10 min.
    // Stop here. With hundreds of accounts, mids + per-market stats + points + portfolio + referral below are
    // hundreds of duplicate fetches of identical exchange data every cycle — the account GET is all we need.
    if (light) return;
    const mids = await api('GET', '/v1/exchange/mids', { retry: false }).catch(() => null);
    if (mids?.mids) view.mids = mids.mids;
    if (force || now - view.statsAt > 60e3) {
      view.statsAt = now;
      await Promise.all(Object.keys(view.mids).map((m) => api('GET', `/v1/markets/${encodeURIComponent(m)}/stats`, { retry: false })
        .then((x) => { view.stats[m] = x; }).catch(() => { })));
    }
    if (force || now - view.pointsAt > 5 * 60e3) {
      view.pointsAt = now;
      view.points = (await api('GET', '/v1/me/points', { signed: true, retry: false }).catch(() => null)) || view.points;
      await refreshServerStats(); // volume + portfolio (fee/pnl) from the server
    }
    if (force && !view.referral) view.referral = (await me.referral().catch(() => null))?.referrer ?? null;
  } finally {
    refreshing = false;
    scheduleRender();
  }
}

function refreshSoon() {
  if (dash) refreshView().catch(() => { });
}

function startDashboard() {
  dash = true;
  process.stdout.write('\x1b[?25l\x1b[2J\x1b[H'); // hide cursor, start from a clean screen
  process.on('exit', () => { render(); process.stdout.write('\x1b[?25h'); });
  // a resize changes both column layout and box heights -> full repaint
  process.stdout.on('resize', () => { lastRenderLines = 0; process.stdout.write('\x1b[2J\x1b[H'); render(); });
  setInterval(render, 1000).unref(); // countdowns
  setInterval(() => refreshView().catch(() => { }), Math.max(5, cfg.dashboardRefreshSec) * 1000).unref();
  render();
}

// ---------------------------------------------------------------------------------------------
// multi-account: worker (one account per child) <-> parent orchestrator + fleet dashboard

/** Compact, stable one-liner for the fleet STATUS column (no per-second countdowns the parent can't refresh). */
function shortPhase(now) {
  if (stopping) return 'berhenti';
  if (recovering.size) return `pulih ${recovering.size} posisi`;
  if (plan.resting) return `istirahat ${fmtDur(plan.resting.end - now)}`;
  if (plan.breakUntil > now) return `jeda ${fmtDur(plan.breakUntil - now)}`;
  if (plan.block) return `pause: ${plan.block}`;
  const mk = [...slots.values()].map((s) => s.market.split('-')[0]);
  if (mk.length) return `trading ${mk.join('·')}`;
  if (plan.nextOpenAt > now) return `nunggu buka ${fmtDur(plan.nextOpenAt - now)}`;
  return `aktif ${slots.size}/${plan.target}`;
}

// ---- parent side -------------------------------------------------------------------------------
const fleet = new Map(); // index -> { ctx, child, status, alive, restartAt, fails }
const fleetLog = []; // merged activity across accounts: { t, kind, label, msg }
let fleetDash = false;
let FLEET_LOG = null; // orchestrator-level fleet log path
let fleetRenderLines = 0;
let fleetTimer = null;
let fleetOnce = false;
let fleetLaunched = false; // all workers spawned — guards maybeExit() from firing mid-stagger

function plog(msg, kind = 'info', label = 'fleet') {
  msg = oneLine(msg);
  const t = new Date().toLocaleTimeString('en-GB', { hour12: false });
  if (FLEET_LOG) { try { fs.appendFileSync(FLEET_LOG,`${new Date().toISOString()} ${kind.toUpperCase().padEnd(5)} [${label}] ${msg}\n`); } catch { } }
  fleetLog.push({ t, kind, label, msg });
  if (fleetLog.length > 150) fleetLog.shift();
  if (fleetDash) scheduleFleetRender();
  else (kind === 'err' || kind === 'warn' ? console.error : console.log)(`[${t}] ${label}: ${msg}`);
}

const maskProxy = (p) => (p ? String(p).replace(/\/\/[^@/]*@/, '//***@') : '-');

const FLEET_COLS = [
  { label: 'AKUN', min: 6, ideal: 12, get: (r) => r.label, color: (r) => (r.down ? C.red : '') },
  { label: 'NILAI', min: 8, ideal: 11, align: 'right', get: (r) => (r.dataAt ? money(r.value) : '-') },
  { label: 'uPnL', min: 7, ideal: 9, align: 'right', get: (r) => (r.dataAt ? signedAuto(r.upnl) : '-'), color: (r) => tone(r.upnl) },
  { label: 'POS', min: 3, ideal: 4, align: 'right', get: (r) => (r.dataAt ? String(r.pos) : '-') },
  { label: 'VOL', min: 6, ideal: 9, align: 'right', prio: 2, get: (r) => (r.dataAt && r.vol ? `$${compact(r.vol)}` : '-') },
  { label: 'POIN', min: 5, ideal: 7, align: 'right', prio: 3, get: (r) => (r.points == null ? '-' : money(r.points, 0)) },
  { label: 'RANK', min: 7, ideal: 8, align: 'right', prio: 4, get: (r) => (r.rank ? `#${compact(r.rank)}` : '-') },
  {
    label: 'SESI', min: 6, ideal: 8, align: 'right', prio: 3,
    get: (r) => (!r.hasSession ? '-' : r.sessionLeft <= 0 ? 'habis' : fmtDur(r.sessionLeft)),
    color: (r) => (!r.hasSession ? '' : r.sessionLeft <= 0 ? C.red : r.sessionLeft < cfg.sessionRenewBeforeH * 3600e3 ? C.yellow : ''),
  },
  {
    label: 'FAUCET', min: 6, ideal: 8, prio: 3,
    get: (r) => (!r.at ? '-' : r.faucetOff ? 'off' : r.faucetUntil - Date.now() > 0 ? `cd ${fmtDur(r.faucetUntil - Date.now())}` : 'siap'),
    color: (r) => (!r.at || r.faucetOff ? C.gray : r.faucetUntil - Date.now() > 0 ? C.yellow : C.green),
  },
  { label: 'STATUS', min: 8, ideal: 26, flex: true, prio: 2, get: (r) => r.status, color: (r) => (r.down ? C.red : r.stopping ? C.yellow : r.pos ? C.cyan : C.gray) },
];

function fleetRows() {
  const now = Date.now();
  return [...fleet.values()].sort((a, b) => a.ctx.index - b.ctx.index).map((f) => {
    const C = f.C;
    if (!C) return { label: f.ctx.label, at: 0, dataAt: 0, value: 0, upnl: 0, pos: 0, hasSession: false, sessionLeft: 0, faucetOff: true, faucetUntil: 0, vol: 0, points: null, rank: null, status: f.restartAt ? `mati — restart ${fmtDur(f.restartAt - now)}` : 'menyiapkan...', down: !f.alive, stopping };
    return als.run(C, () => {
      const a = view.account || {}; const st = store.state || {}; const s = store.session;
      return {
        label: f.ctx.label, at: now, dataAt: view.accountAt,
        value: num(a.accountValue), upnl: openPositions().reduce((x, p) => x + num(p.unrealizedPnl), 0), pos: openPositions().length,
        hasSession: !!s, sessionLeft: s ? Date.parse(s.expiresAt) - now : 0,
        faucetOff: !cfg.autoFaucet, faucetUntil: num(st.faucetCooldownUntil),
        vol: num(view.volume), points: view.points ? num(view.points.total) : null, rank: view.points ? num(view.points.rank) : null,
        status: f.alive ? shortPhase(now) : (f.restartAt ? `mati — restart ${fmtDur(f.restartAt - now)}` : 'mati'),
        down: !f.alive, stopping,
      };
    });
  });
}

function fleetFrame() {
  const now = Date.now();
  const W = Math.max(60, process.stdout.columns || 100);
  const H = Math.max(16, (process.stdout.rows || 30) - 1);
  const rows = fleetRows();
  const n = fleet.size;
  const nAlive = [...fleet.values()].filter((f) => f.alive).length;
  const tot = rows.reduce((o, r) => { o.value += r.value; o.upnl += r.upnl; o.pos += r.pos; o.vol += r.vol; return o; }, { value: 0, upnl: 0, pos: 0, vol: 0 });
  const volWin = [...fleet.values()].map((f) => f.C && als.run(f.C, () => view.volumeWindow)).find(Boolean) || '7d';
  const freshest = rows.reduce((m, r) => Math.max(m, r.dataAt), 0);

  const mode = [cfg.dryRun ? paint(C.yellow, 'DRY RUN') : 'live', `lev ${asRange(cfg.leverage).join('–')}x`, `margin ${asRange(cfg.marginUsePct).join('–')}%`].join(' · ');
  const age = freshest ? `data ${fmtDur(now - freshest)} lalu · ` : '';
  const out = [
    boxTop(W, `TitanxBot · ${n} akun · ${paint(C.gray, mode)}`, paint(C.gray, `${age}${new Date(now).toLocaleTimeString('en-GB', { hour12: false })}`)),
    boxLine(W, `${paint(nAlive === n ? C.green : C.yellow, '●')} ${nAlive}/${n} jalan · nilai ${money(tot.value)} · uPnL ${paint(tone(tot.upnl), signedAuto(tot.upnl))} · vol $${compact(tot.vol)} (${volWin})`),
    boxRule(W, BX.bl, BX.br),
  ];
  // accounts table takes what it needs; activity keeps the rest (>= 4 lines)
  const actMin = 6;
  const maxAcct = Math.max(3, H - out.length - actMin - 3);
  out.push(...tableBox(W, 'Akun', paint(C.gray, `${tot.pos} posisi terbuka`), FLEET_COLS, rows, maxAcct, 'tidak ada akun'));
  const actRows = Math.max(3, H - out.length - 2);
  out.push(boxTop(W, 'Aktivitas', paint(C.gray, 'logs/')));
  const lines = fleetLog.slice(-actRows);
  for (let i = 0; i < actRows; i++) {
    const l = lines[i];
    out.push(boxLine(W, l ? `${paint(C.gray, l.t)} ${paint(C.cyan, cell(l.label, 8))} ${paint(KIND_COLOR[l.kind] || '', cell(oneLine(l.msg), Math.max(10, W - 26)))}` : ''));
  }
  out.push(boxRule(W, BX.bl, BX.br));
  return out.slice(0, H);
}

function fleetRenderNow() {
  if (fleetTimer) { clearTimeout(fleetTimer); fleetTimer = null; }
  if (!fleetDash) return;
  // Backpressure guard: if the terminal/SSH link hasn't drained the last paint, skip this one instead of
  // queueing more frames in memory. A slow pipe is the usual reason a pinned dashboard's RAM balloons.
  if (process.stdout.writableLength > 131072) return;
  const out = fleetFrame();
  process.stdout.write(`${fleetRenderLines ? `\x1b[${fleetRenderLines}A` : ''}${out.map((r) => `\x1b[2K${r}`).join('\n')}\n\x1b[0J`);
  fleetRenderLines = out.length;
}

// Coalesce bursts into at most one paint per ~300ms; the 1s interval covers anything skipped.
function scheduleFleetRender() { if (fleetDash && !fleetTimer) fleetTimer = setTimeout(fleetRenderNow, 300); }

// One global ticker: refresh each live account's account-only view (value/uPnL/pos), staggered so hundreds of
// accounts don't hit /v1/me/account at the same instant. Points/vol come from each engine's logPoints.
let fleetRefreshBusy = false;
async function fleetRefreshTick() {
  if (fleetRefreshBusy) return;
  fleetRefreshBusy = true;
  try {
    const live = [...fleet.values()].filter((f) => f.alive && f.C);
    const gap = Math.max(10, Math.floor((Math.max(5, cfg.dashboardRefreshSec) * 1000) / Math.max(1, live.length)));
    for (const f of live) {
      if (stopping) break;
      await als.run(f.C, () => refreshView(false, true).catch(() => { }));
      await wait(gap);
    }
  } finally { fleetRefreshBusy = false; }
}

function maybeExit() {
  if (fleetLaunched && (stopping || fleetOnce) && [...fleet.values()].every((f) => !f.alive)) {
    if (fleetDash) { fleetRenderNow(); process.stdout.write('\x1b[?25h'); }
    process.exit(0);
  }
}

function runOrchestrator(contexts, oneShot) {
  fleetOnce = oneShot;
  if (cfg.logFile) { FLEET_LOG = path.resolve(DIR, cfg.logFile); fs.mkdirSync(path.dirname(FLEET_LOG), { recursive: true }); }
  for (const meta of contexts) fleet.set(meta.index, { ctx: meta, C: null, alive: false, restartAt: 0, fails: 0 });

  // pm2 stop / systemd / kill send SIGTERM -> ask every account to stop cleanly (close bot positions first).
  process.on('SIGTERM', () => { stopping = true; });
  process.on('SIGINT', () => {
    if (stopping) { plog('paksa keluar — mematikan semua akun', 'warn'); if (fleetDash) process.stdout.write('\x1b[?25h'); process.exit(130); }
    stopping = true;
    plog('Ctrl+C — semua akun menutup posisi lalu berhenti (Ctrl+C lagi = paksa)', 'warn');
  });

  const tty = cfg.dashboard && process.stdout.isTTY;
  if (tty) {
    fleetDash = true;
    process.stdout.write('\x1b[?25l\x1b[2J\x1b[H');
    process.on('exit', () => { try { fleetRenderNow(); process.stdout.write('\x1b[?25h'); } catch { } for (const f of fleet.values()) { try { if (f.C) als.run(f.C, releaseLock); } catch { } } });
    process.stdout.on('resize', () => { fleetRenderLines = 0; process.stdout.write('\x1b[2J\x1b[H'); fleetRenderNow(); });
    setInterval(fleetRenderNow, 1000).unref(); // countdowns
    setInterval(fleetRefreshTick, Math.max(5, cfg.dashboardRefreshSec) * 1000).unref(); // light account-only refresh
    fleetRenderNow();
  }
  plog(`TitanxBot fleet · ${contexts.length} akun${oneShot ? ' · once' : ''}`, 'ok');

  const run = async (f) => {
    const C = makeCtx(f.ctx);
    f.C = C; f.alive = true; f.restartAt = 0;
    await als.run(C, async () => {
      try { useAccount(f.ctx); loadAll(); acquireLock(); assertSessionLabel(); }
      catch (e) {
        if (e instanceof NeedLoginError) plog(`perlu login — jalankan: node index.js login --account ${f.ctx.label}`, 'err', f.ctx.label);
        else plog(`setup gagal (${e.message})`, 'err', f.ctx.label);
        return;
      }
      while (!stopping) {
        try { await runAccountEngine(oneShot ? 'once' : 'run'); break; }
        catch (e) {
          if (e instanceof NeedLoginError) { plog(`perlu login — jalankan: node index.js login --account ${f.ctx.label}`, 'err', f.ctx.label); break; }
          if (e instanceof FatalError) { plog(`fatal (${e.message}) — akun ini berhenti`, 'err', f.ctx.label); break; }
          f.fails = (f.fails || 0) + 1;
          const back = Math.min(60000, 5000 * f.fails);
          f.restartAt = Date.now() + back;
          plog(`error (${e.message}) — restart ${fmtDur(back)}`, 'err', f.ctx.label);
          await wait(back);
        }
      }
      try { releaseLock(); } catch { }
    });
    f.alive = false; f.C = null;
    plog('selesai', 'ok', f.ctx.label);
    maybeExit();
  };

  (async () => {
    const jobs = [];
    for (const f of fleet.values()) { if (stopping) break; jobs.push(run(f)); await wait(oneShot ? 400 : 1500); }
    fleetLaunched = true;
    maybeExit();
    await Promise.allSettled(jobs);
    maybeExit();
  })();
  return new Promise(() => { }); // lives until maybeExit()/SIGINT calls process.exit
}

/** One-shot multi-account snapshot (read-only; no lock, no session mint — safe while the fleet runs). */
async function cmdFleetStatus(contexts) {
  for (const ctx of contexts) {
    useAccount(ctx); loadAll();
    const pad = ctx.label.padEnd(10);
    try {
      const m = sessionMatch(store.session, ctx.label);
      if (m === 'mismatch') { console.log(`${pad} MISMATCH — session milik akun "${store.session.label}", login ulang`); continue; }
      if (m === 'none' || Date.parse(store.session.expiresAt) <= Date.now()) { console.log(`${pad} belum login / session habis`); continue; }
      activate(store.session);
      await refreshView(true, true); // account only — this print shows no market/points data
      const a = view.account || {};
      const up = openPositions().reduce((x, p) => x + num(p.unrealizedPnl), 0);
      console.log(`${pad} nilai ${money(num(a.accountValue)).padStart(11)}  uPnL ${signedAuto(up).padStart(9)}  pos ${openPositions().length}  session ${fmtDur(Date.parse(store.session.expiresAt) - Date.now())}  faucet ${num(store.state.faucetCooldownUntil) - Date.now() > 0 ? `cd ${fmtDur(num(store.state.faucetCooldownUntil) - Date.now())}` : 'siap'}`);
    } catch (e) { console.log(`${pad} ERROR ${e.message}`); }
  }
}

async function cmdLoginAll(contexts, manual) {
  for (let i = 0; i < contexts.length; i++) {
    const ctx = contexts[i];
    useAccount(ctx); loadAll();
    console.log(`\n=== Login akun ${ctx.label} (${i + 1}/${contexts.length}) · proxy ${maskProxy(ctx.proxy)} ===`);
    if (account.loginMode !== 'google') { console.log(`mode ${account.loginMode} (evm) — tidak perlu login, langsung jalan.`); continue; }
    try { await cmdLogin(manual); } // sequential: one Chrome window at a time, never parallel
    catch (e) { console.error(`akun ${ctx.label} GAGAL login: ${e.message}`); }
  }
  console.log('\nSemua akun selesai diproses. Jalankan: node index.js');
}

// ---------------------------------------------------------------------------------------------
// status / main

async function showStatus() {
  const s = store.session;
  log(`mode ${account.loginMode} | session ${short(s?.sessionId)} s/d ${s?.expiresAt || '-'} | party ${s?.party || '-'}`);
  try {
    const who = await me.identity();
    log(`user ${who?.user ?? '-'} | username ${who?.username || '-'} | #${who?.userNumber ?? '-'} | onboarded ${who?.onboardedAt || '-'}`);
  } catch (e) { log(`/v1/me: ${e.message}`, 'warn'); }
  try {
    const a = await getAccount();
    log(`nilai akun ${a.value.toFixed(2)} USDCx | margin bebas ${a.available.toFixed(2)} | raw ${JSON.stringify(a.raw).slice(0, 300)}`);
  } catch (e) { log(`akun: ${e.message}`, 'warn'); }
  try {
    const ps = await me.positions();
    if (!ps.length) log('posisi: kosong');
    for (const p of ps) log(`posisi ${p.market} size ${p.size} entry ${p.entryPrice} mark ${p.markPrice} uPnL ${p.unrealizedPnl} lev ${p.leverage}x`);
  } catch (e) { log(`posisi: ${e.message}`, 'warn'); }
  try {
    const r = await me.referral();
    log(`referral: referrer ${r?.referrer?.bound ? `terikat (${r.referrer.codeUsed || '?'})` : 'BELUM'} | kode kamu ${r?.code || '-'} | referee ${r?.refereeCount ?? 0}`);
  } catch (e) { log(`referral: ${e.message}`, 'warn'); }
  await logPoints();
  const stt = store.state.stats;
  if (stt) log(`statistik bot sejak ${stt.since}: ${stt.roundTrips} round trip, volume ~${stt.volumeUsd} USDCx, fee ${stt.feesUsd}`);
}

async function withSessionRetry(fn) {
  try {
    return await fn();
  } catch (e) {
    if (!(e instanceof ApiError && e.deadSession)) throw e;
    dropSession(e.code || e.status);
    await ensureSession();
    return fn();
  }
}

async function shutdown() {
  // Slots see `stopping`: holds end early and exits go taker (closeOnExit). Give them time to finish.
  const live = [...slots.values()].map((x) => x.task).filter(Boolean);
  if (live.length) {
    log(`menunggu ${live.length} posisi bot ditutup...`);
    await Promise.race([Promise.allSettled(live), wait(120e3)]);
  }
  const left = Object.values(store.state.slots || {}).map((x) => x.market);
  if (left.length) log(`posisi/order bot ${left.join(', ')} belum beres — dibereskan otomatis saat bot jalan lagi`, 'warn');
  releaseLock();
  process.exit(0);
}

function selftest() {
  const eq = (a, b, what) => { if (a !== b) throw new Error(`${what}: ${JSON.stringify(a)} !== ${JSON.stringify(b)}`); };
  eq(W('0.00013'), '0.0001300000', 'W');
  eq(W('82510'), '82510.0000000000', 'W');
  eq(W('-0.5'), '-0.5000000000', 'W');
  eq(W('-0'), '0.0000000000', 'W');
  eq(G(new Date('2026-10-09T04:30:35.370Z')), '2026-10-09T04:30:35.37Z', 'G');
  eq(G(new Date('2026-10-09T04:30:35.000Z')), '2026-10-09T04:30:35Z', 'G');
  eq(canonQuery('ts=2026&nonce=1&market=BTC'), 'market=BTC&nonce=1&ts=2026', 'cn');
  eq(slipCap(82510, 'buy', 0.01, 5), '83335', 'nw BTC');
  eq(slipCap(2492.65, 'sell', 0.01, 4), '2467.8', 'nw ETH');
  eq(slipCap(0.11815, 'buy', 0.01, 0), '0.11933', 'nw CC');
  eq(fmtSize(sizeFor(25, 82510, 5, 10), 5), '0.0003', 'hC');
  eq(fmtSize(sizeFor(10, 82510, 5, 10), 5), '0.00013', 'hC bump');
  const canon = orderCanon({ sessionId: 'SESSION_ID', market: 'BTC-USDCX', side: 'buy', type: 'limit', size: '0.00013', price: '83337', tif: 'ioc', nonce: 1791520235370, ts: new Date('2026-10-09T04:30:35.370Z') });
  eq(canon.split('\n')[7], 'tif:          ioc', 'order tif line');
  eq(canon.split('\n')[15], 'clientOrderId:', 'order clientOrderId line');
  eq(canon.split('\n')[16], 'nonce:        1791520235370', 'order nonce line');
  eq(canon.split('\n')[17], 'ts:           2026-10-09T04:30:35.37Z', 'order ts line');
  eq(canon.split('\n').length, 18, 'order lines');
  const { privateKey, publicKey } = crypto.generateKeyPairSync('ed25519');
  const S = { sessionId: 's', key: privateKey };
  const sig = edSign(canon, S);
  eq(sig.length, 128, 'sig hex length');
  eq(crypto.verify(null, Buffer.from(canon), publicKey, Buffer.from(sig, 'hex')), true, 'sig verify');
  // multi-account: proxy creds must never leak into the dashboard/logs
  eq(maskProxy('http://user:pass@1.2.3.4:3129'), 'http://***@1.2.3.4:3129', 'maskProxy');
  eq(maskProxy(''), '-', 'maskProxy empty');
  // multi-account: session<->label matching
  eq(sessionMatch({ label: 'adityo' }, 'adityo'), 'ok', 'match ok');
  eq(sessionMatch({ label: 'pubiji' }, 'adityo'), 'mismatch', 'match mismatch');
  eq(sessionMatch({}, 'adityo'), 'none', 'match unlabeled');
  eq(sessionMatch(null, 'adityo'), 'none', 'match no session');
  // single-process multi-account: facades must route to the active context, with zero bleed
  const A = makeCtx({ index: 1, label: 'A' }); const B = makeCtx({ index: 2, label: 'B' });
  als.run(A, () => { store.session = { label: 'A' }; view.volume = 111; slots.set('m', 1); plan.target = 3; });
  als.run(B, () => { store.session = { label: 'B' }; view.volume = 222; plan.target = 9; });
  eq(A.store.session.label, 'A', 'ctx A store');
  eq(B.store.session.label, 'B', 'ctx B store');
  eq(als.run(A, () => view.volume), 111, 'ctx A view');
  eq(als.run(B, () => view.volume), 222, 'ctx B view');
  eq(als.run(A, () => slots.size), 1, 'ctx A slots');
  eq(als.run(B, () => slots.size), 0, 'ctx B slots (no bleed)');
  eq(als.run(A, () => plan.target), 3, 'ctx A plan');
  eq(als.run(B, () => plan.target), 9, 'ctx B plan');
  eq(ROOT.view.volume, 0, 'ROOT untouched');
  log('selftest OK: W/G/cn/nw/hC/orderCanon/ed25519/maskProxy/sessionMatch/ctx cocok dengan bundle web', 'ok');
}

// Multi-account: a session is only usable under the label it was minted for.
function assertSessionLabel() {
  if (acct && !acct.legacy) {
    const m = sessionMatch(store.session, acct.label);
    if (m === 'mismatch') throw new NeedLoginError(`session folder "${acct.label}" ternyata milik akun "${store.session.label}" — login ulang: node index.js login --account ${acct.label}`);
    if (m === 'none' && store.session) { log('session lama tanpa label / bukan milik akun ini — bikin session baru', 'warn'); store.session = null; }
  }
}

async function main() {
  const cmd = process.argv[2] || 'run';
  if (cmd === 'selftest') return selftest();

  // ---- account routing -------------------------------------------------------------------------
  // Resolve the roster: >1 account -> run them ALL in THIS process (one als context each) via runOrchestrator;
  // exactly 1 (legacy / --account / single-entry roster) -> run inline in the ROOT context below.
  const contexts = loadAccounts();
  const flagIdx = process.argv.indexOf('--account');
  const only = flagIdx >= 0 ? String(process.argv[flagIdx + 1] || '').trim() : '';
  const picked = only ? contexts.filter((c) => c.label === only || String(c.index + 1) === only) : contexts;
  if (only && !picked.length) throw new FatalError(`--account "${only}" tidak ketemu (pakai label atau urutan di accounts.json).`);
  if (cmd === 'login') return cmdLoginAll(picked, process.argv.includes('--manual'));
  if (cmd === 'status' && picked.length > 1) return cmdFleetStatus(picked);
  if ((cmd === 'run' || cmd === 'once') && picked.length > 1) return runOrchestrator(picked, cmd === 'once');
  useAccount(picked[0]); // single account (legacy / --account / 1-entry roster): run in THIS process (ROOT)

  loadAll();
  acquireLock();
  if (cmd === 'login') return cmdLogin(process.argv.includes('--manual')); // single-account login (legacy path)

  assertSessionLabel();

  process.on('SIGINT', () => {
    if (stopping) {
      const left = Object.values(store.state.slots || {}).map((x) => x.market);
      if (left.length) log(`paksa keluar: posisi/order bot ${left.join(', ')} masih ada — dibereskan otomatis saat bot dijalankan lagi`, 'warn');
      releaseLock();
      process.exit(130);
    }
    stopping = true;
    setPhase('berhenti — menyelesaikan langkah ini', 'warn');
    log('Ctrl+C — berhenti setelah langkah ini (Ctrl+C lagi = paksa keluar)', 'warn');
  });

  const tty = cfg.dashboard && process.stdout.isTTY;
  if (cmd === 'status') {
    await ensureSession();
    if (!tty) return withSessionRetry(showStatus);
    await refreshView(true);
    migrateLegacyOpenTrade();
    const left = Object.values(store.state.slots || {}).map((x) => x.market);
    if (left.length) setPhase(`posisi bot ${left.join(', ')} masih ada — dibereskan otomatis saat bot jalan lagi`, 'warn');
    else setPhase('snapshot (bot tidak sedang jalan)', 'info');
    process.stdout.write(`${frame(true).join('\n')}\n`);
    return;
  }
  if (tty) startDashboard();
  await runAccountEngine(cmd);
}

async function runAccountEngine(cmd) {
  setPhase('menyiapkan session');
  // Cloudflare WAF (error 1020) blocks every API POST without a cf_clearance cookie. Fetch one up-front (zone-wide,
  // shared by all accounts) so order/faucet/leverage/session POSTs go through. Non-fatal: api() also fetches it
  // lazily on a 403, so a transient solver hiccup here doesn't stop the bot.
  if (solverBase()) await ensureClearance(false).catch((e) => log(`cf_clearance belum didapat (${e.message}) — tiap request akan coba sendiri saat butuh`, 'warn'));
  else log('turnstileSolverUrl kosong di config.json: POST ke API diblok Cloudflare WAF (403). Isi turnstileSolverUrl + jalankan Turnstile-Solver-main/api_server.py.', 'warn');
  await ensureSession();

  migrateLegacyOpenTrade();
  log(`TitanxBot jalan | mode ${account.loginMode}${cfg.dryRun ? ' | DRY RUN' : ''} | volume engine | lev ${asRange(cfg.leverage).join('-')}x | margin ${asRange(cfg.marginUsePct).join('-')}% | maks ${asRange(cfg.maxConcurrent).join('-')} posisi`);

  // The loop only schedules: each position runs as its own task (runSlot) next to it.
  let onboarded = false;
  let loopErrors = 0; // consecutive failing cycles — drives the escalating backoff below
  while (!stopping) {
    try {
      await ensureSession();
      await auth0KeepAlive();
      if (!onboarded) {
        setPhase('cek onboarding');
        onboarded = await withSessionRetry(ensureOnboarded);
        refreshSoon();
        if (!onboarded && !cfg.dryRun) throw new Error('onboarding belum selesai, dicoba lagi siklus berikut');
      }
      await withSessionRetry(maybeFaucet);
      if (Date.now() - cx().lastPoints > 10 * 60e3) { cx().lastPoints = Date.now(); await withSessionRetry(logPoints); }
      view.phase = { fn: enginePhase };
      const started = await withSessionRetry(() => schedulerTick(cmd === 'once'));
      if (cmd === 'once') {
        if (started) { await started.task; break; }
        if (plan.block && !recovering.size && !Object.keys(store.state.slots || {}).length) { log(`once: tidak buka posisi (${plan.block})`, 'warn'); break; }
      }
      loopErrors = 0; // a clean cycle resets the backoff
    } catch (e) {
      if (e instanceof FatalError || e instanceof NeedLoginError) throw e;
      log(`loop error: ${e.message}`, 'err');
      setPhase(`error: ${e.message}`, 'err');
      // Escalating backoff: during an outage (e.g. all proxies timing out) idle longer and longer (up to 60s)
      // instead of spinning every 5s — keeps retrying forever, but stays light on the VPS.
      loopErrors++;
      if (e instanceof ApiError && e.status === 429) await sleep(Math.min(300, e.retryAfter ?? 30) * 1000);
      else await sleep(Math.min(60000, 5000 * loopErrors));
    }
    await sleep(600 + Math.random() * 900);
  }
  await shutdown();
}

if (require.main !== module) {
  // Test hooks only (node -e "require('./index.js')..."); the bot itself always runs through main().
  module.exports = { W, G, canonQuery, orderCanon, requestCanon, slipCap, sizeFor, api, action, activate, setImpit: (o) => { cx().impit = new Impit(o); }, _fleet: { fleet, fleetLog, fleetFrame, cfg: () => cfg, setDash: (v) => { fleetDash = v; } }, _proxy: { initProxy, noteProxyError, rotateProxy, state: () => ({ idx: cx().proxyIdx, fails: cx().proxyFails, cur: proxyPool[cx().proxyIdx], poolLen: proxyPool.length }) },
    // onboard.js drives the same engine primitives for brand-new accounts (one account per process).
    _onboard: {
      DIR, ACCOUNTS_FILE, ACCOUNT_FILE, PROXY_FILE, FatalError, NeedLoginError, ApiError,
      readJson, readLines, loadAccounts, useAccount, loadAll, acquireLock, releaseLock, ensureSession, bindParty,
      bindReferral, ensureOnboarded, getAccount, me, pub, log, postDepositIntent, fmtDur, money, num, maskProxy, normHandle, sessionAuthCanon, ensureClearance, solverBase,
      sessionProxy, cfg: () => cfg, store: () => store, account: () => account, acct: () => acct,
      als, makeCtx, setLogSink: (fn) => { logSink = fn; },
      solverCapacity, solveTurnstileLocal, // test hooks: solver throttle
      setTransport: (t) => { cx().impit = t; }, // tests: swap the HTTP client for a mock server
    } };
} else main()
  .then(() => { releaseLock(); process.exit(0); })
  .catch((e) => {
    if (e instanceof NeedLoginError) {
      log(`${e.message}. Jalankan: node index.js login`, 'err');
      releaseLock();
      process.exit(2);
    }
    log(e instanceof FatalError || e instanceof ApiError ? e.message : e.stack || e.message, 'err');
    releaseLock();
    process.exit(1);
  });
