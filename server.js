#!/usr/bin/env node
/**
 * Personal Finance Tracker - Single-file Node.js + Express + MongoDB
 * - Authentication via Node 'crypto' (pbkdf2)
 * - CRUD transactions (income/expense)
 * - Analytics (totals, category, monthly) via MongoDB aggregation
 * - Single HTML page served from Express
 * - No external libs besides express and mongodb
 */

const express = require('express');
const crypto = require('crypto');
const { MongoClient, ObjectId } = require('mongodb');
const { promisify } = require('util');

// ---------------------- Config ----------------------
const PORT = process.env.PORT || 3000;
const MONGO_URL = process.env.MONGO_URL || 'mongodb://127.0.0.1:27017';
const DB_NAME = process.env.DB_NAME || 'personal_finance_tracker';

const COOKIE_NAME = 'sid';
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days
const PBKDF2_ITERATIONS = 120000; // good baseline
const PBKDF2_KEYLEN = 64;
const PBKDF2_DIGEST = 'sha512';

const pbkdf2 = promisify(crypto.pbkdf2);

// ---------------------- Simple In-Memory Session Store ----------------------
const sessions = new Map(); // token -> { userId, username, expiresAt }
function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, {
    userId: user._id.toString(),
    username: user.username,
    expiresAt: Date.now() + SESSION_TTL_MS,
  });
  return token;
}
function getSession(token) {
  const s = sessions.get(token);
  if (!s) return null;
  if (s.expiresAt < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return s;
}
function destroySession(token) {
  sessions.delete(token);
}
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of sessions.entries()) {
    if (v.expiresAt < now) sessions.delete(k);
  }
}, 60_000).unref();

// ---------------------- Helpers ----------------------
class HttpError extends Error {
  constructor(status, message) {
    super(message);
    this.status = status;
  }
}

const asyncHandler = (fn) => (req, res, next) =>
  Promise.resolve(fn(req, res, next)).catch(next);

function parseCookies(req) {
  const header = req.headers.cookie;
  const out = {};
  if (!header) return out;
  const parts = header.split(';');
  for (const part of parts) {
    const [k, ...v] = part.split('=');
    if (!k) continue;
    out[k.trim()] = decodeURIComponent((v.join('=') || '').trim());
  }
  return out;
}

function setSessionCookie(res, token) {
  const maxAge = Math.floor(SESSION_TTL_MS / 1000);
  const secure = process.env.NODE_ENV === 'production' ? 'Secure; ' : '';
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=${encodeURIComponent(token)}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${maxAge}; ${secure}`.trim()
  );
}

function clearSessionCookie(res) {
  const secure = process.env.NODE_ENV === 'production' ? 'Secure; ' : '';
  res.setHeader(
    'Set-Cookie',
    `${COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; ${secure}`.trim()
  );
}

function ensureAuth(req, res, next) {
  if (!req.user) return next(new HttpError(401, 'Unauthorized'));
  next();
}

// Password hashing
async function hashPassword(password, salt = null) {
  const useSalt = salt || crypto.randomBytes(16).toString('base64');
  const derived = await pbkdf2(
    Buffer.from(password, 'utf8'),
    Buffer.from(useSalt, 'base64'),
    PBKDF2_ITERATIONS,
    PBKDF2_KEYLEN,
    PBKDF2_DIGEST
  );
  return {
    salt: useSalt,
    hash: derived.toString('base64'),
    iterations: PBKDF2_ITERATIONS,
    algo: `pbkdf2-${PBKDF2_DIGEST}`,
  };
}

async function verifyPassword(password, passwordRecord) {
  const { salt, hash, iterations, algo } = passwordRecord || {};
  if (!salt || !hash || !iterations || !algo) return false;
  const digest = algo.split('-')[1] || PBKDF2_DIGEST;
  const derived = await pbkdf2(
    Buffer.from(password, 'utf8'),
    Buffer.from(salt, 'base64'),
    iterations,
    PBKDF2_KEYLEN,
    digest
  );
  const a = Buffer.from(hash, 'base64');
  const b = Buffer.from(derived);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}

// Basic validators
function validateUsername(u) {
  if (typeof u !== 'string') return false;
  const s = u.trim();
  return /^[a-zA-Z0-9_.-]{3,32}$/.test(s);
}
function validatePassword(p) {
  return typeof p === 'string' && p.length >= 6 && p.length <= 200;
}
function sanitizeCategory(c) {
  if (typeof c !== 'string') return null;
  const s = c.trim();
  if (!s || s.length > 50) return null;
  return s;
}
function validateType(t) {
  return t === 'income' || t === 'expense';
}
function parseDate(d) {
  if (!d) return new Date();
  const dt = new Date(d);
  if (isNaN(dt.getTime())) return null;
  return dt;
}
function parseAmount(a) {
  const n = Number(a);
  if (!isFinite(n)) return null;
  return Math.round(n * 100) / 100;
}

// ---------------------- HTML UI ----------------------
const html = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width,initial-scale=1"/>
  <title>Personal Finance Tracker</title>
  <style>
    :root { 
      --bg:#0b1020;
      --bg-soft:#0d1326;
      --panel:#0f172a;
      --panel-2:#111827;
      --muted:#94a3b8; 
      --fg:#e5e7eb; 
      --accent:#22c55e; 
      --danger:#ef4444; 
      --warn:#f59e0b; 
      --blue:#3b82f6; 
      --purple:#8b5cf6;
      --gradient: linear-gradient(135deg, #3b82f6 0%, #22c55e 100%);
      --ring: rgba(59,130,246,.2);
      --border: rgba(148,163,184,.12);
      --shadow: 0 10px 30px rgba(0,0,0,.35);
      --glass: rgba(17,24,39,.55);
    }
    [data-theme="light"] {
      --bg:#f4f6fb;
      --bg-soft:#eef2ff;
      --panel:#ffffff;
      --panel-2:#ffffff;
      --muted:#64748b;
      --fg:#0f172a;
      --accent:#16a34a;
      --danger:#dc2626;
      --warn:#d97706;
      --blue:#2563eb;
      --purple:#7c3aed;
      --gradient: linear-gradient(135deg, #2563eb 0%, #16a34a 100%);
      --ring: rgba(37,99,235,.15);
      --border: rgba(15,23,42,.08);
      --shadow: 0 10px 25px rgba(2,6,23,.10);
      --glass: rgba(255,255,255,.7);
    }
    * { box-sizing: border-box; }
    html, body { height: 100%; }
    body { 
      margin:0; 
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Inter, sans-serif; 
      background: radial-gradient(1200px 600px at -10% -10%, rgba(59,130,246,.15), transparent 60%), 
                  radial-gradient(900px 500px at 110% 10%, rgba(34,197,94,.12), transparent 50%),
                  radial-gradient(900px 600px at 60% 120%, rgba(139,92,246,.1), transparent 60%),
                  var(--bg);
      color: var(--fg);
      line-height: 1.5;
      position: relative;
    }
    .noise {
      pointer-events:none;
      position: fixed; inset: 0; opacity:.04; z-index:0;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' opacity='0.5' viewBox='0 0 100 100'%3E%3Cfilter id='n'%3E%3CfeTurbulence type='fractalNoise' baseFrequency='0.75' numOctaves='2' stitchTiles='stitch'/%3E%3CfeColorMatrix type='saturate' values='0'/%3E%3C/filter%3E%3Crect width='100%' height='100%' filter='url(%23n)'/%3E%3C/svg%3E");
      background-size: cover;
    }

    header { 
      padding: 14px 20px; 
      background: linear-gradient(to bottom, rgba(0,0,0,.25), transparent), var(--panel-2);
      border-bottom: 1px solid var(--border); 
      box-shadow: var(--shadow);
      position: sticky; top: 0; z-index: 5;
      backdrop-filter: blur(10px);
    }
    .header-content {
      max-width: 1200px;
      margin: 0 auto;
      display: flex; 
      justify-content: space-between; 
      align-items: center;
      gap: 12px;
    }
    .brand {
      display:flex; align-items:center; gap:12px;
    }
    header h1 { 
      margin: 0; 
      font-size: 22px; 
      font-weight: 700;
      letter-spacing: .3px;
      background: var(--gradient);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .header-actions { display:flex; gap: 10px; align-items:center; }
    select.slim {
      appearance: none;
      padding: 8px 30px 8px 12px;
      background: var(--bg);
      border: 1px solid var(--border);
      color: var(--fg);
      border-radius: 10px;
      font: inherit;
      position: relative;
    }
    .header-actions .user { 
      display: flex; 
      gap: 10px; 
      align-items: center;
      background: rgba(255,255,255,0.05);
      padding: 8px 12px;
      border-radius: 99px;
      border: 1px solid var(--border);
    }
    .icon-btn {
      border: 1px solid var(--border);
      background: var(--bg);
      color: var(--fg);
      border-radius: 10px;
      padding: 8px 12px;
      cursor: pointer;
      transition: transform .15s ease, background .2s;
    }
    .icon-btn:hover { transform: translateY(-1px); }

    .container { max-width: 1200px; margin: 24px auto; padding: 0 24px; position: relative; z-index:1; }
    .grid { 
      display: grid; 
      gap: 24px; 
      grid-template-columns: 1fr;
    }
    @media (min-width: 900px) { .grid { grid-template-columns: 1fr 1fr; } }

    .hero {
      position: relative;
      overflow: hidden;
      border-radius: 20px;
      padding: 32px;
      background: linear-gradient(180deg, rgba(255,255,255,.04), rgba(255,255,255,.02)), var(--panel);
      border: 1px solid var(--border);
      box-shadow: var(--shadow);
      margin-bottom: 10px;
      display: grid; gap: 18px;
    }
    .hero::after {
      content:"";
      position: absolute; inset: -1px;
      background: radial-gradient(800px 120px at 20% 0%, rgba(59,130,246,.15), transparent 60%);
      pointer-events:none;
    }
    .hero h2 { 
      margin: 0; 
      font-size: 28px; 
      font-weight: 800; 
      letter-spacing: .2px;
      background: linear-gradient(135deg, var(--fg), #9aa4b2);
      -webkit-background-clip: text;
      -webkit-text-fill-color: transparent;
    }
    .hero p { margin: 0; color: var(--muted); max-width: 60ch; }
    .hero .badges { display:flex; gap:10px; flex-wrap: wrap; }
    .badge {
      font-size: 12px; color: #cbd5e1;
      border: 1px dashed var(--border);
      background: rgba(255,255,255,.04);
      padding: 6px 10px; border-radius: 999px;
    }

    .card { 
      background: linear-gradient(180deg, var(--glass), transparent);
      border: 1px solid var(--border); 
      border-radius: 16px; 
      padding: 22px;
      box-shadow: var(--shadow);
      transition: transform 0.2s ease, border-color .2s ease, box-shadow .2s;
      position: relative; overflow: hidden;
    }
    .card:hover { transform: translateY(-2px); border-color: rgba(99,102,241,.25); }
    .card h2 { 
      margin: 0 0 16px 0; 
      font-size: 18px;
      display: flex;
      align-items: center;
      justify-content: space-between;
      gap: 8px;
    }
    .card h2 .marker {
      width: 36px; height: 10px; border-radius: 999px; 
      background: var(--gradient);
      box-shadow: 0 0 0 3px rgba(59,130,246,.12);
    }

    .muted { color: var(--muted); }
    input, select, button { 
      font: inherit; 
      border-radius: 10px; 
      border: 1px solid var(--border); 
      background: var(--bg); 
      color: var(--fg); 
      padding: 12px 14px;
      transition: all 0.2s;
    }
    input:focus, select:focus, button:focus { 
      outline: none;
      border-color: var(--blue);
      box-shadow: 0 0 0 4px var(--ring);
    }
    input, select { width: 100%; }
    button { 
      cursor: pointer; 
      font-weight: 600;
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 8px;
    }
    button:hover { opacity: 0.98; }
    button.primary { 
      background: linear-gradient(135deg, var(--blue), #60a5fa);
      border-color: transparent;
      color: white;
    }
    button.success { 
      background: linear-gradient(135deg, var(--accent), #4ade80);
      border-color: transparent;
      color: #052e12;
    }
    button.danger { 
      background: linear-gradient(135deg, var(--danger), #fb7185);
      border-color: transparent;
      color: white;
    }
    button.ghost { 
      background: transparent; 
      border: 1px solid var(--border); 
    }
    .row { display: grid; grid-template-columns: 1fr; gap: 12px; }
    @media (min-width: 700px) { .row { grid-template-columns: repeat(4, 1fr); } }

    .two-col { display:grid; gap:16px; grid-template-columns: 1fr; }
    @media (min-width: 900px) { .two-col { grid-template-columns: 2fr 1fr; } }

    .input-wrap { position: relative; }
    .input-wrap .toggle-pass {
      position:absolute; right: 8px; top: 50%; transform: translateY(-50%);
      background: transparent; border: none; color: var(--muted); cursor: pointer; padding: 6px;
    }

    .chips { display:flex; gap:8px; flex-wrap: wrap; margin-top: 8px; }
    .chip { 
      display:inline-flex; align-items:center; gap:6px;
      padding: 6px 10px; border-radius: 999px; 
      border: 1px dashed var(--border);
      background: rgba(255,255,255,.03);
      color: var(--muted); cursor: pointer;
    }
    .chip:hover { border-style: solid; color: var(--fg); }

    table { width: 100%; border-collapse: collapse; }
    thead th { 
      position: sticky; top: 0; z-index: 2;
      background: linear-gradient(180deg, rgba(0,0,0,.2), transparent), var(--panel);
      backdrop-filter: blur(8px);
      border-bottom: 1px solid var(--border);
    }
    th, td { border-bottom: 1px solid var(--border); padding: 12px; text-align: left; font-size: 14px; }
    th { color: var(--muted); font-weight: 700; font-size: 12px; letter-spacing: .04em; text-transform: uppercase; }
    tbody tr { transition: background .15s ease; }
    tbody tr:hover { background: rgba(148,163,184,.06); }
    tbody tr:nth-child(odd) { background: rgba(255,255,255,.02); }
    .right { text-align: right; }
    .actions { display: flex; gap: 6px; }
    .hidden { display: none !important; }
    .pill { display:inline-block; padding: 3px 10px; border-radius: 999px; font-size: 12px; font-weight:700; }
    .pill.income { background: rgba(34,197,94,.15); color: #86efac; }
    .pill.expense { background: rgba(239,68,68,.15); color: #fca5a5; }
    .amount.income { color: #86efac; font-weight:700; }
    .amount.expense { color: #fca5a5; font-weight:700; }

    .stat { display: grid; gap: 6px; grid-template-columns: 1fr auto; align-items: center; }
    .bar { height: 8px; background: #0b1220; border-radius: 999px; overflow: hidden; border: 1px solid var(--border); }
    .bar > span { display: block; height: 100%; background: var(--blue); }

    .flex { display: flex; gap: 10px; align-items: center; }
    .mt { margin-top: 12px; }
    .mb { margin-bottom: 12px; }

    .error { color: #fecaca; background: rgba(239,68,68,.08); padding: 8px 10px; border: 1px solid rgba(239,68,68,.25); border-radius: 8px; }
    .success { color: #dcfce7; background: rgba(34,197,94,.08); padding: 8px 10px; border: 1px solid rgba(34,197,94,.25); border-radius: 8px; }
    small.code { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; color: var(--muted); }

    /* Donut + Sparkline */
    .donut {
      --gap: 10px;
      width: 140px; height: 140px; border-radius: 50%;
      background: conic-gradient(var(--accent) 0deg, var(--accent) var(--incDeg), var(--danger) var(--incDeg), var(--danger) 360deg);
      display: grid; place-items: center;
      border: 1px solid var(--border);
      box-shadow: inset 0 0 30px rgba(0,0,0,.15);
    }
    .donut::after{
      content:"";
      width: calc(100% - 32px); height: calc(100% - 32px); border-radius: 50%;
      background: var(--panel);
      border: 1px solid var(--border);
    }
    .donut-label {
      position: absolute; text-align:center; font-weight:800; font-size:14px;
    }
    .spark-wrap { width: 100%; height: 70px; }
    canvas#sparkline { width: 100%; height: 70px; display:block; }

    /* Skeleton */
    .skeleton {
      background: linear-gradient(90deg, rgba(255,255,255,0.06), rgba(255,255,255,0.15), rgba(255,255,255,0.06));
      border-radius: 8px; height: 12px; animation: shimmer 1.2s infinite; 
    }
    @keyframes shimmer {
      0% { background-position: -200px 0; }
      100% { background-position: 200px 0; }
    }
    .skeleton-row td { padding: 10px; }
    .skeleton-row .skeleton { height: 10px; }

    /* Toast */
    .toast {
      position: fixed; bottom: 20px; right: 20px; z-index: 10;
      display: grid; gap: 8px; width: min(380px, 90vw);
    }
    .toast .item {
      background: var(--panel); border: 1px solid var(--border); padding: 12px 14px; border-radius: 12px; box-shadow: var(--shadow);
      display:flex; align-items:center; gap:8px; animation: toastIn .2s ease;
    }
    .toast .item.success { border-left: 4px solid var(--accent); }
    .toast .item.error { border-left: 4px solid var(--danger); }
    @keyframes toastIn { from { transform: translateY(10px); opacity: 0; } to { transform: translateY(0); opacity: 1; } }

    /* Floating Action Button */
    .fab {
      position: fixed; bottom: 24px; left: 24px; z-index: 10;
      background: var(--blue); color: white; border: none;
      padding: 14px 16px; border-radius: 999px; font-weight:800;
      box-shadow: 0 12px 30px rgba(37,99,235,.35);
    }
    .fab:hover { transform: translateY(-2px); }

    /* Scrollbars */
    ::-webkit-scrollbar { height: 10px; width: 10px; }
    ::-webkit-scrollbar-thumb { background: rgba(148,163,184,.35); border-radius: 10px; }
    ::-webkit-scrollbar-track { background: transparent; }
  </style>
</head>
<body>
  <div class="noise"></div>
  <header>
    <div class="header-content">
      <div class="brand">
        <div style="font-size:20px">💰</div>
        <h1>Personal Finance Tracker</h1>
      </div>
      <div class="header-actions">
        <select id="currencySelect" class="slim" title="Display currency">
          <option>USD</option>
          <option>EUR</option>
          <option>GBP</option>
          <option>INR</option>
        </select>
        <button class="icon-btn" id="themeToggle" title="Toggle theme">🌙</button>
        <div class="user" id="userBar" hidden>
          <span class="muted">Welcome,</span>
          <strong id="username"></strong>
          <button class="ghost" id="logoutBtn" title="Sign out">Logout</button>
        </div>
      </div>
    </div>
  </header>

  <div class="container">
    <!-- Hero (logged-out) -->
    <section id="hero" class="hero">
      <h2>Track your money beautifully</h2>
      <p>Fast, minimal, and secure personal finance tracking. Add transactions, see insights, and stay on top of your budget — all in one sleek view.</p>
      <div class="badges">
        <span class="badge">No external client libraries</span>
        <span class="badge">Instant analytics</span>
        <span class="badge">Dark / Light</span>
        <span class="badge">Keyboard: N (Quick Add), R (Refresh), / (Find)</span>
      </div>
    </section>

    <!-- Auth -->
    <div id="auth" class="grid">
      <div class="card">
        <h2>
          Welcome Back
          <span class="marker" aria-hidden="true"></span>
        </h2>
        <form id="loginForm" class="row">
          <div class="input-wrap" style="grid-column: span 2">
            <input name="username" placeholder="Username" autocomplete="username" required />
          </div>
          <div class="input-wrap" style="grid-column: span 2">
            <input id="loginPass" name="password" placeholder="Password" autocomplete="current-password" type="password" required />
            <button class="toggle-pass" type="button" data-target="#loginPass" title="Show/Hide">👁</button>
          </div>
          <button class="primary" type="submit" style="grid-column: span 2">Login to Account</button>
          <div id="loginMsg" style="grid-column: span 2"></div>
          <button type="button" id="showRegisterBtn" class="ghost" style="grid-column: span 2">Create New Account</button>
        </form>
      </div>
      <div id="registerCard" class="card hidden">
        <h2>
          Get Started
          <span class="marker" aria-hidden="true"></span>
        </h2>
        <form id="registerForm" class="row">
          <div class="input-wrap" style="grid-column: span 2">
            <input name="username" placeholder="Choose a username (3-32 chars)" autocomplete="username" required />
          </div>
          <div class="input-wrap" style="grid-column: span 2">
            <input id="regPass" name="password" placeholder="Create a password (min 6 chars)" autocomplete="new-password" type="password" required />
            <button class="toggle-pass" type="button" data-target="#regPass" title="Show/Hide">👁</button>
          </div>
          <button class="success" type="submit" style="grid-column: span 2">Create Account</button>
          <button type="button" id="cancelRegisterBtn" class="ghost" style="grid-column: span 2">Cancel</button>
          <div id="registerMsg" style="grid-column: span 2"></div>
        </form>
      </div>
    </div>

    <!-- App -->
    <div id="app" class="grid hidden">
      <div class="card">
        <h2>
          Add Transaction
          <span class="marker" aria-hidden="true"></span>
        </h2>
        <form id="txForm" class="row">
          <input name="amount" type="number" step="0.01" min="0" placeholder="Amount" required />
          <select name="type" required>
            <option value="income">Income</option>
            <option value="expense">Expense</option>
          </select>
          <input name="category" id="categoryInput" placeholder="Category (e.g., Groceries)" required />
          <input name="date" type="date" required />
          <button class="success" type="submit" style="grid-column: span 4">Add</button>
        </form>
        <div class="chips" id="categoryChips">
          <button class="chip" data-cat="Groceries">🛒 Groceries</button>
          <button class="chip" data-cat="Rent">🏠 Rent</button>
          <button class="chip" data-cat="Dining Out">🍽️ Dining Out</button>
          <button class="chip" data-cat="Bills">💡 Bills</button>
          <button class="chip" data-cat="Salary">💼 Salary</button>
          <button class="chip" data-cat="Travel">✈️ Travel</button>
          <button class="chip" data-cat="Fuel">⛽ Fuel</button>
        </div>
        <div id="txMsg" class="mt"></div>
      </div>

      <div class="card two-col">
        <div>
          <h2>
            Analytics
            <span class="marker" aria-hidden="true"></span>
          </h2>
          <div id="analytics">
            <div class="flex" style="gap:14px; flex-wrap: wrap;">
              <div class="stat" style="flex:1; min-width: 180px;">
                <div class="muted">Total Income</div>
                <div id="statIncome" class="right skeleton" style="height:16px; border-radius:6px;"></div>
              </div>
              <div class="stat" style="flex:1; min-width: 180px;">
                <div class="muted">Total Expenses</div>
                <div id="statExpenses" class="right skeleton" style="height:16px; border-radius:6px;"></div>
              </div>
              <div class="stat" style="flex:1; min-width: 180px;">
                <div class="muted">Balance</div>
                <div id="statBalance" class="right skeleton" style="height:16px; border-radius:6px;"></div>
              </div>
            </div>

            <div class="mt" style="display:grid; grid-template-columns: 160px 1fr; gap:16px; align-items:center;">
              <div style="position:relative; display:grid; place-items:center;">
                <div id="donut" class="donut" style="--incDeg:180deg; position:relative;"></div>
                <div id="donutLabel" class="donut-label">Loading</div>
              </div>
              <div>
                <h3 class="mt" style="margin-top:0">Monthly Net</h3>
                <div class="spark-wrap">
                  <canvas id="sparkline"></canvas>
                </div>
              </div>
            </div>

            <h3 class="mt">By Category (Expenses)</h3>
            <div id="byCategory"></div>

            <h3 class="mt">Monthly</h3>
            <div id="byMonth"></div>
          </div>
        </div>
      </div>

      <div class="card" style="grid-column: 1 / -1">
        <h2>
          Transactions
          <span class="marker" aria-hidden="true"></span>
        </h2>
        <div class="flex mt" style="flex-wrap: wrap; gap: 10px;">
          <form id="filtersForm" class="flex" style="gap:10px; flex-wrap: wrap;">
            <select name="type" class="ghost" title="Type">
              <option value="">All</option>
              <option value="income">Income</option>
              <option value="expense">Expense</option>
            </select>
            <input name="category" placeholder="Category" title="Filter category" />
            <input type="date" name="from" title="From date"/>
            <input type="date" name="to" title="To date"/>
            <button class="ghost" id="applyFiltersBtn" type="submit">Apply</button>
            <button class="ghost" id="clearFiltersBtn" type="button">Clear</button>
          </form>
          <div class="flex" style="margin-left:auto; gap:6px">
            <button id="refreshBtn" class="ghost" title="Refresh (R)">Refresh</button>
          </div>
        </div>
        <div class="mt" style="overflow:auto; max-height: 420px;">
          <table id="txTable">
            <thead>
              <tr>
                <th style="min-width: 110px;">Date</th>
                <th style="min-width: 90px;">Type</th>
                <th style="min-width: 160px;">Category</th>
                <th class="right" style="min-width: 110px;">Amount</th>
                <th style="min-width: 120px;">Actions</th>
              </tr>
            </thead>
            <tbody id="txBody"></tbody>
          </table>
        </div>
      </div>
    </div>

    <div class="mt muted">
      <small class="code">Single-file app • Express + MongoDB • No external client-side libraries</small>
    </div>
  </div>

  <button id="quickAdd" class="fab" title="Quick Add (N)">＋</button>
  <div class="toast" id="toast"></div>

  <script>
    // ---------- Small Helpers ----------
    const el = (sel, root=document) => root.querySelector(sel);
    const els = (sel, root=document) => Array.from(root.querySelectorAll(sel));
    let currency = localStorage.getItem('currency') || 'USD';
    const fmtMoney = (n) => new Intl.NumberFormat(undefined, { style:'currency', currency, maximumFractionDigits: 2 }).format(n ?? 0);
    const fmtDate = (iso) => new Date(iso).toLocaleDateString();

    function toast(msg, type='success', timeout=2500) {
      const box = el('#toast');
      const item = document.createElement('div');
      item.className = 'item ' + type;
      item.textContent = msg;
      box.appendChild(item);
      setTimeout(()=> { item.style.opacity = '0'; setTimeout(()=> item.remove(), 200); }, timeout);
    }

    function api(path, opts = {}) {
      return fetch(path, {
        credentials: 'same-origin',
        headers: { 'Content-Type': 'application/json' },
        ...opts,
      }).then(async (res) => {
        const data = await res.json().catch(() => ({}));
        if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
        return data;
      });
    }

    function setMsg(node, text, type='success') {
      node.className = type;
      node.textContent = text;
      setTimeout(() => { node.textContent = ''; node.className=''; }, 2200);
    }

    function setUserBar(user) {
      const userBar = el('#userBar');
      if (user) {
        el('#username').textContent = user.username;
        userBar.hidden = false;
      } else {
        userBar.hidden = true;
        el('#username').textContent = '';
      }
    }

    // Theme
    function getPreferredTheme() {
      const saved = localStorage.getItem('theme');
      if (saved) return saved;
      return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
    }
    function applyTheme(theme) {
      document.documentElement.setAttribute('data-theme', theme);
      localStorage.setItem('theme', theme);
      el('#themeToggle').textContent = theme === 'dark' ? '🌙' : '☀️';
    }

    // ---------- App State ----------
    async function checkMe() {
      try {
        const me = await api('/api/me');
        setUserBar(me);
        el('#auth').classList.add('hidden');
        el('#hero').classList.add('hidden');
        el('#app').classList.remove('hidden');
        await loadAll();
      } catch {
        setUserBar(null);
        el('#auth').classList.remove('hidden');
        el('#hero').classList.remove('hidden');
        el('#app').classList.add('hidden');
      }
    }

    async function loadAll() {
      const today = new Date().toISOString().slice(0,10);
      el('#txForm [name="date"]').value = today;
      showTxSkeleton();
      setStatsSkeleton(true);
      await Promise.all([loadTransactions(), loadAnalytics()]);
    }

    // ---------- Transactions ----------
    function showTxSkeleton(count=6){
      const tbody = el('#txBody');
      tbody.innerHTML = '';
      for (let i=0;i<count;i++){
        const tr = document.createElement('tr');
        tr.className = 'skeleton-row';
        tr.innerHTML = '<td><div class="skeleton" style="width:80px;"></div></td>'+
                       '<td><div class="skeleton" style="width:60px;"></div></td>'+
                       '<td><div class="skeleton" style="width:120px;"></div></td>'+
                       '<td class="right"><div class="skeleton" style="width:90px; margin-left:auto;"></div></td>'+
                       '<td><div class="skeleton" style="width:80px;"></div></td>';
        tbody.appendChild(tr);
      }
    }

    async function loadTransactions() {
      const tbody = el('#txBody');
      const params = getFilters();
      const search = new URLSearchParams(params).toString();
      const { items } = await api('/api/transactions?limit=500' + (search ? '&' + search : ''));
      tbody.innerHTML = '';
      if (items.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 5;
        td.className = 'muted';
        td.textContent = 'No transactions yet. Add your first one!';
        tr.appendChild(td);
        tbody.appendChild(tr);
        return;
      }
      for (const t of items) {
        const tr = document.createElement('tr');
        tr.dataset.id = t._id;
        tr.dataset.date = t.date;
        tr.appendChild(td(fmtDate(t.date)));
        tr.appendChild(tdType(t.type));
        tr.appendChild(tdText(t.category));
        tr.appendChild(tdAmount(t.amount, t.type));
        tr.appendChild(tdActions(t));
        tbody.appendChild(tr);
      }
    }

    function td(text){ const d=document.createElement('td'); d.textContent=text; return d; }
    function tdText(text){ return td(text); }
    function tdAmount(amount, type){
      const d=document.createElement('td'); d.className='right';
      const span=document.createElement('span');
      span.className='amount '+type;
      span.textContent=fmtMoney(amount);
      d.appendChild(span); return d;
    }
    function tdType(type){ const d=document.createElement('td'); const span=document.createElement('span'); span.className='pill '+type; span.textContent=type; d.appendChild(span); return d; }
    function tdActions(t){
      const d=document.createElement('td');
      d.className='actions';
      const edit=document.createElement('button'); edit.innerHTML='✏️ Edit'; edit.className='ghost';
      const del=document.createElement('button'); del.innerHTML='🗑️ Delete'; del.className='danger';
      edit.onclick=()=>enterEdit(t._id);
      del.onclick=()=>deleteTx(t._id);
      d.appendChild(edit); d.appendChild(del); return d;
    }

    async function deleteTx(id){
      if(!confirm('Delete this transaction?')) return;
      await api('/api/transactions/'+id, { method:'DELETE' });
      toast('Transaction deleted', 'success');
      await loadAll();
    }

    function enterEdit(id){
      const tr = document.querySelector('tr[data-id="'+id+'"]');
      if(!tr) return;
      const cells = tr.children;
      const dateISO = tr.dataset.date;
      const typeText = cells[1].textContent.trim();
      const catText = cells[2].textContent.trim();
      const amtValue = Number(cells[3].textContent.replace(/[^0-9.-]/g,''));
      tr.innerHTML='';
      const dateInput=document.createElement('input'); dateInput.type='date'; dateInput.value = new Date(dateISO).toISOString().slice(0,10);
      const typeSel=document.createElement('select'); typeSel.innerHTML='<option value="income">income</option><option value="expense">expense</option>'; typeSel.value=typeText;
      const catInput=document.createElement('input'); catInput.value=catText;
      const amtInput=document.createElement('input'); amtInput.type='number'; amtInput.step='0.01'; amtInput.value=amtValue.toFixed(2);

      tr.appendChild(wrap(dateInput));
      tr.appendChild(wrap(typeSel));
      tr.appendChild(wrap(catInput));
      const amtTd=wrap(amtInput); amtTd.className='right'; tr.appendChild(amtTd);

      const actions=document.createElement('td'); actions.className='actions';
      const save=document.createElement('button'); save.textContent='Save'; save.className='success';
      const cancel=document.createElement('button'); cancel.textContent='Cancel'; cancel.className='ghost';
      actions.appendChild(save); actions.appendChild(cancel);
      tr.appendChild(actions);

      cancel.onclick = () => loadTransactions();
      save.onclick = async () => {
        const payload = {
          amount: parseFloat(amtInput.value),
          type: typeSel.value,
          category: catInput.value,
          date: dateInput.value
        };
        await api('/api/transactions/'+id, { method:'PUT', body: JSON.stringify(payload) });
        toast('Transaction updated', 'success');
        await loadAll();
      };

      function wrap(elm){ const td=document.createElement('td'); td.appendChild(elm); return td; }
    }

    // ---------- Analytics ----------
    function setStatsSkeleton(on){
      const ids = ['#statIncome','#statExpenses','#statBalance'];
      for (const id of ids){
        const n = el(id);
        if (!n) continue;
        if (on) { n.classList.add('skeleton'); n.textContent=''; }
        else { n.classList.remove('skeleton'); }
      }
      el('#donutLabel').textContent = on ? 'Loading' : el('#donutLabel').textContent;
    }

    async function loadAnalytics(){
      const data = await api('/api/analytics');
      // Totals
      el('#statIncome').textContent = fmtMoney(data.totalIncome);
      el('#statExpenses').textContent = fmtMoney(data.totalExpenses);
      el('#statBalance').textContent = fmtMoney(data.balance);
      setStatsSkeleton(false);

      // Donut
      const total = (data.totalIncome + data.totalExpenses) || 1;
      const incPct = Math.min(1, data.totalIncome / total);
      const incDeg = Math.round(incPct * 360);
      const donut = el('#donut');
      donut.style.setProperty('--incDeg', incDeg + 'deg');
      el('#donutLabel').textContent = incPct >= .5 ? 'Healthy' : 'Tight';

      // Sparkline (monthly net)
      drawSparkline(data.byMonth.map(m => m.net));

      // Category bars
      const cat = el('#byCategory'); cat.innerHTML='';
      const totalExpense = data.totalExpenses || 1;
      if (data.byCategory.length===0) {
        const p=document.createElement('div'); p.className='muted'; p.textContent='No expense data yet.'; cat.appendChild(p);
      }
      for (const row of data.byCategory) {
        const wrapper=document.createElement('div'); wrapper.className='stat';
        const label=document.createElement('div'); label.textContent=row.category + ' — ' + fmtMoney(row.total);
        const amt=document.createElement('div'); amt.textContent='';
        const bar=document.createElement('div'); bar.className='bar';
        const fill=document.createElement('span'); fill.style.width=Math.min(100, Math.round((row.total/totalExpense)*100))+'%';
        bar.appendChild(fill);
        wrapper.appendChild(label); wrapper.appendChild(amt);
        wrapper.appendChild(bar);
        cat.appendChild(wrapper);
      }

      const mon = el('#byMonth'); mon.innerHTML='';
      if (data.byMonth.length===0) {
        const p=document.createElement('div'); p.className='muted mt'; p.textContent='No monthly data yet.'; mon.appendChild(p);
      }
      for (const row of data.byMonth) {
        const wrapper=document.createElement('div'); wrapper.className='stat';
        const label=document.createElement('div'); label.textContent = row.month + ' — ' + fmtMoney(row.net) + ' (inc ' + fmtMoney(row.income) + ' / exp ' + fmtMoney(row.expense) + ')';
        const amt=document.createElement('div'); amt.textContent='';
        const bar=document.createElement('div'); bar.className='bar';
        const netPerc = Math.min(100, Math.abs(row.net) / (Math.abs(row.income)+Math.abs(row.expense) || 1) * 100);
        const fill=document.createElement('span'); fill.style.width=netPerc+'%'; fill.style.background = row.net>=0 ? 'var(--accent)' : 'var(--danger)';
        bar.appendChild(fill);
        wrapper.appendChild(label); wrapper.appendChild(amt);
        wrapper.appendChild(bar);
        mon.appendChild(wrapper);
      }
    }

    function drawSparkline(values){
      const canvas = el('#sparkline');
      const dpr = window.devicePixelRatio || 1;
      const w = canvas.clientWidth || 600;
      const h = canvas.clientHeight || 70;
      canvas.width = w * dpr; canvas.height = h * dpr;
      const ctx = canvas.getContext('2d');
      ctx.scale(dpr, dpr);
      ctx.clearRect(0,0,w,h);
      if (!values || values.length === 0) {
        ctx.fillStyle = getComputedStyle(document.documentElement).getPropertyValue('--muted');
        ctx.font = '12px ui-sans-serif';
        ctx.fillText('No data yet', 6, h/2);
        return;
      }
      const min = Math.min(0, ...values);
      const max = Math.max(0, ...values);
      const range = (max - min) || 1;
      const pad = 8;
      const step = (w - pad*2) / (values.length - 1 || 1);

      // Grid line at 0
      const y0 = h - pad - ((0 - min) / range) * (h - pad*2);
      ctx.strokeStyle = 'rgba(148,163,184,.35)'; ctx.lineWidth=1;
      ctx.beginPath(); ctx.moveTo(pad, y0); ctx.lineTo(w - pad, y0); ctx.stroke();

      // Path
      ctx.beginPath();
      values.forEach((v, i) => {
        const x = pad + i * step;
        const y = h - pad - ((v - min) / range) * (h - pad*2);
        if (i === 0) ctx.moveTo(x, y); else ctx.lineTo(x, y);
      });
      ctx.strokeStyle = 'rgba(59,130,246,.95)'; ctx.lineWidth=2;
      ctx.stroke();

      // Shade (nice)
      const grad = ctx.createLinearGradient(0, pad, 0, h - pad);
      grad.addColorStop(0, 'rgba(59,130,246,.35)');
      grad.addColorStop(1, 'rgba(59,130,246,0)');
      ctx.lineTo(w - pad, h - pad);
      ctx.lineTo(pad, h - pad);
      ctx.closePath();
      ctx.fillStyle = grad;
      ctx.fill();
    }

    // ---------- Filters ----------
    function getFilters() {
      const fd = new FormData(el('#filtersForm'));
      const q = {};
      const type = fd.get('type'); const cat = (fd.get('category')||'').trim();
      const from = fd.get('from'); const to = fd.get('to');
      if (type) q.type = type;
      if (cat) q.category = cat;
      if (from) q.from = from;
      if (to) q.to = to;
      return q;
    }
    function clearFilters() {
      el('#filtersForm').reset();
      loadTransactions();
    }

    // ---------- Forms/events ----------
    // Show/hide password
    els('.toggle-pass').forEach(btn => {
      btn.addEventListener('click', () => {
        const target = el(btn.dataset.target);
        if (!target) return;
        target.type = target.type === 'password' ? 'text' : 'password';
        btn.textContent = target.type === 'password' ? '👁' : '🙈';
      });
    });

    // Category chips
    el('#categoryChips').addEventListener('click', (e) => {
      if (e.target.classList.contains('chip')) {
        el('#categoryInput').value = e.target.dataset.cat || '';
        el('#categoryInput').focus();
      }
    });

    // Auth
    el('#loginForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const payload = { username: fd.get('username'), password: fd.get('password') };
      const msg = el('#loginMsg');
      try {
        await api('/api/login', { method:'POST', body: JSON.stringify(payload) });
        setMsg(msg, 'Logged in!');
        toast('Welcome back!', 'success');
        await checkMe();
      } catch (err) {
        setMsg(msg, err.message, 'error');
        toast(err.message, 'error');
      }
    });

    el('#registerForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const payload = { username: fd.get('username'), password: fd.get('password') };
      const msg = el('#registerMsg');
      try {
        await api('/api/register', { method:'POST', body: JSON.stringify(payload) });
        setMsg(msg, 'Registered! You can now log in.');
        toast('Account created. Please log in.', 'success');
      } catch (err) {
        setMsg(msg, err.message, 'error');
        toast(err.message, 'error');
      }
    });

    el('#logoutBtn').addEventListener('click', async () => {
      try { await api('/api/logout', { method:'POST' }); } catch {}
      toast('Signed out', 'success');
      await checkMe();
    });

    el('#txForm').addEventListener('submit', async (e) => {
      e.preventDefault();
      const fd = new FormData(e.target);
      const payload = {
        amount: parseFloat(fd.get('amount')),
        type: fd.get('type'),
        category: fd.get('category'),
        date: fd.get('date')
      };
      const msg = el('#txMsg');
      try {
        await api('/api/transactions', { method:'POST', body: JSON.stringify(payload) });
        setMsg(msg, 'Transaction added!');
        toast('Transaction added', 'success');
        e.target.reset();
        await loadAll();
      } catch (err) {
        setMsg(msg, err.message, 'error');
        toast(err.message, 'error');
      }
    });

    el('#refreshBtn').addEventListener('click', async ()=> {
      await loadAll();
      toast('Refreshed', 'success', 1400);
    });

    el('#filtersForm').addEventListener('submit', async (e)=> {
      e.preventDefault();
      await loadTransactions();
    });
    el('#clearFiltersBtn').addEventListener('click', clearFilters);

    // Register form toggle
    el('#showRegisterBtn').addEventListener('click', () => {
      el('#registerCard').classList.remove('hidden');
      el('#showRegisterBtn').classList.add('hidden');
    });

    el('#cancelRegisterBtn').addEventListener('click', () => {
      el('#registerCard').classList.add('hidden');
      el('#showRegisterBtn').classList.remove('hidden');
      el('#registerForm').reset();
      el('#registerMsg').textContent = '';
    });

    // Currency select
    const currencySelect = el('#currencySelect');
    currencySelect.value = currency;
    currencySelect.addEventListener('change', async () => {
      currency = currencySelect.value;
      localStorage.setItem('currency', currency);
      // Re-render numbers
      await Promise.all([loadAnalytics(), loadTransactions()]);
      toast('Currency set to ' + currency, 'success');
    });

    // Theme toggle
    applyTheme(getPreferredTheme());
    el('#themeToggle').addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme') || 'dark';
      applyTheme(cur === 'dark' ? 'light' : 'dark');
    });

    // Quick Add (scroll to Add Transaction)
    el('#quickAdd').addEventListener('click', () => {
      el('#app').classList.remove('hidden');
      el('#txForm [name="amount"]').focus({ preventScroll: false });
      window.scrollTo({ top: el('#txForm').getBoundingClientRect().top + window.scrollY - 80, behavior: 'smooth' });
    });

    // Keyboard shortcuts
    document.addEventListener('keydown', (e) => {
      if (e.target && ['INPUT','TEXTAREA','SELECT'].includes(e.target.tagName)) return;
      if (e.key.toLowerCase() === 'r') { e.preventDefault(); el('#refreshBtn')?.click(); }
      if (e.key.toLowerCase() === 'n') { e.preventDefault(); el('#quickAdd')?.click(); }
      if (e.key === '/') { e.preventDefault(); el('#categoryInput')?.focus(); }
    });

    // Init
    checkMe();
  </script>
</body>
</html>`;


// ---------------------- Server ----------------------
(async () => {
  const app = express();

  // Security-ish headers (simple; avoids CSP to keep inline script working)
  app.use((req, res, next) => {
    res.setHeader('X-Frame-Options', 'DENY');
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
    next();
  });

  // Logger middleware
  app.use((req, res, next) => {
    const start = Date.now();
    res.on('finish', () => {
      const ms = Date.now() - start;
      console.log(`${req.method} ${req.originalUrl} - ${res.statusCode} ${ms}ms`);
    });
    next();
  });

  // Parsers
  app.use(express.json());
  app.use(express.urlencoded({ extended: false }));

  // Attach user from session (if any)
  app.use((req, res, next) => {
    const cookies = parseCookies(req);
    const sid = cookies[COOKIE_NAME];
    if (sid) {
      const s = getSession(sid);
      if (s) {
        req.user = { id: s.userId, username: s.username, token: sid };
      }
    }
    next();
  });

  // Mongo
  const client = new MongoClient(MONGO_URL, { ignoreUndefined: true });
  await client.connect();
  const db = client.db(DB_NAME);
  const users = db.collection('users');
  const transactions = db.collection('transactions');

  // Indexes
  await users.createIndex({ username: 1 }, { unique: true });
  await transactions.createIndex({ userId: 1, date: -1 });
  await transactions.createIndex({ userId: 1, category: 1 });

  // Routes
  app.get('/', (req, res) => {
    res.setHeader('Content-Type', 'text/html; charset=utf-8');
    res.send(html);
  });

  app.get('/api/me', (req, res) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    res.json({ _id: req.user.id, username: req.user.username });
  });

  app.post('/api/register', asyncHandler(async (req, res) => {
    const { username, password } = req.body || {};
    if (!validateUsername(username)) throw new HttpError(400, 'Invalid username (3-32 alphanum, _ . -)');
    if (!validatePassword(password)) throw new HttpError(400, 'Password must be at least 6 chars');

    const existing = await users.findOne({ username: username.trim() });
    if (existing) throw new HttpError(409, 'Username already taken');

    const pass = await hashPassword(password);
    const doc = {
      username: username.trim(),
      password: pass,
      createdAt: new Date(),
    };
    const result = await users.insertOne(doc);
    res.status(201).json({ _id: result.insertedId, username: doc.username });
  }));

  app.post('/api/login', asyncHandler(async (req, res) => {
    const { username, password } = req.body || {};
    if (!validateUsername(username) || !validatePassword(password)) {
      throw new HttpError(400, 'Invalid credentials');
    }
    const user = await users.findOne({ username: username.trim() });
    if (!user || !(await verifyPassword(password, user.password))) {
      throw new HttpError(401, 'Invalid username or password');
    }
    const token = createSession(user);
    setSessionCookie(res, token);
    res.json({ _id: user._id, username: user.username });
  }));

  app.post('/api/logout', (req, res) => {
    if (req.user?.token) destroySession(req.user.token);
    clearSessionCookie(res);
    res.json({ ok: true });
  });

  // Transactions
  app.get('/api/transactions', ensureAuth, asyncHandler(async (req, res) => {
    const userId = new ObjectId(req.user.id);
    const { type, category, from, to, limit = 200 } = req.query;

    const q = { userId };
    if (type && (type === 'income' || type === 'expense')) q.type = type;
    if (category && typeof category === 'string') q.category = category.trim();

    if (from || to) {
      q.date = {};
      if (from) {
        const d = new Date(from);
        if (!isNaN(d)) q.date.$gte = d;
      }
      if (to) {
        const d = new Date(to);
        if (!isNaN(d)) q.date.$lte = d;
      }
      if (Object.keys(q.date).length === 0) delete q.date;
    }

    const items = await transactions
      .find(q)
      .sort({ date: -1, _id: -1 })
      .limit(Math.min(1000, parseInt(limit) || 200))
      .toArray();

    res.json({ items });
  }));

  app.post('/api/transactions', ensureAuth, asyncHandler(async (req, res) => {
    const { amount, type, category, date } = req.body || {};

    const amt = parseAmount(amount);
    if (amt === null || !(amt >= 0)) throw new HttpError(400, 'Invalid amount');
    if (!validateType(type)) throw new HttpError(400, 'Invalid type');
    const cat = sanitizeCategory(category);
    if (!cat) throw new HttpError(400, 'Invalid category');
    const dt = parseDate(date);
    if (!dt) throw new HttpError(400, 'Invalid date');

    const doc = {
      userId: new ObjectId(req.user.id),
      amount: amt,
      type,
      category: cat,
      date: dt,
      createdAt: new Date(),
    };
    const result = await transactions.insertOne(doc);
    res.status(201).json({ _id: result.insertedId, ...doc });
  }));

  app.put('/api/transactions/:id', ensureAuth, asyncHandler(async (req, res) => {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) throw new HttpError(400, 'Invalid id');
    const update = {};
    if (req.body.amount !== undefined) {
      const amt = parseAmount(req.body.amount);
      if (amt === null || !(amt >= 0)) throw new HttpError(400, 'Invalid amount');
      update.amount = amt;
    }
    if (req.body.type !== undefined) {
      if (!validateType(req.body.type)) throw new HttpError(400, 'Invalid type');
      update.type = req.body.type;
    }
    if (req.body.category !== undefined) {
      const cat = sanitizeCategory(req.body.category);
      if (!cat) throw new HttpError(400, 'Invalid category');
      update.category = cat;
    }
    if (req.body.date !== undefined) {
      const dt = parseDate(req.body.date);
      if (!dt) throw new HttpError(400, 'Invalid date');
      update.date = dt;
    }
    if (Object.keys(update).length === 0) throw new HttpError(400, 'No valid fields to update');

    const result = await transactions.findOneAndUpdate(
      { _id: new ObjectId(id), userId: new ObjectId(req.user.id) },
      { $set: update },
      { returnDocument: 'after' }
    );
    if (!result.value) throw new HttpError(404, 'Transaction not found');
    res.json(result.value);
  }));

  app.delete('/api/transactions/:id', ensureAuth, asyncHandler(async (req, res) => {
    const id = req.params.id;
    if (!ObjectId.isValid(id)) throw new HttpError(400, 'Invalid id');
    const result = await transactions.deleteOne({ _id: new ObjectId(id), userId: new ObjectId(req.user.id) });
    if (result.deletedCount === 0) throw new HttpError(404, 'Transaction not found');
    res.json({ ok: true });
  }));

  // Analytics
  app.get('/api/analytics', ensureAuth, asyncHandler(async (req, res) => {
    const userId = new ObjectId(req.user.id);
    const pipeline = [
      { $match: { userId } },
      {
        $facet: {
          totals: [
            { $group: { _id: "$type", total: { $sum: "$amount" } } }
          ],
          byCategory: [
            { $match: { type: "expense" } },
            { $group: { _id: "$category", total: { $sum: "$amount" } } },
            { $sort: { total: -1 } }
          ],
          byMonth: [
            {
              $group: {
                _id: { $dateToString: { format: "%Y-%m", date: "$date" } },
                income: { $sum: { $cond: [{ $eq: ["$type", "income"] }, "$amount", 0] } },
                expense: { $sum: { $cond: [{ $eq: ["$type", "expense"] }, "$amount", 0] } },
              }
            },
            { $sort: { _id: 1 } }
          ]
        }
      }
    ];
    const [agg] = await transactions.aggregate(pipeline).toArray();
    const totalsMap = new Map(agg.totals.map(t => [t._id, t.total]));
    const totalIncome = totalsMap.get('income') || 0;
    const totalExpenses = totalsMap.get('expense') || 0;
    const balance = (totalIncome - totalExpenses);

    const byCategory = agg.byCategory.map(r => ({ category: r._id, total: r.total }));
    const byMonth = agg.byMonth.map(r => ({
      month: r._id,
      income: r.income,
      expense: r.expense,
      net: r.income - r.expense
    }));

    res.json({ totalIncome, totalExpenses, balance, byCategory, byMonth });
  }));

  // Error handler
  app.use((err, req, res, next) => {
    console.error(err);
    if (res.headersSent) return next(err);
    const status = err.status || 500;
    const message = err.message || 'Server error';
    if (req.path.startsWith('/api/')) {
      res.status(status).json({ error: message });
    } else {
      res.status(status).send(`<pre>${status} ${message}</pre>`);
    }
  });

  app.listen(PORT, () => {
    console.log(`Server running on http://localhost:${PORT}`);
    console.log(`DB: ${MONGO_URL}/${DB_NAME}`);
  });
})().catch((e) => {
  console.error('Failed to start server:', e);
  process.exit(1);
});