/**
 * app.js
 *
 * How to run:
 * 1) Install dependencies:
 *    npm install express mongodb multer pdf-lib pdf-parse
 * 2) Start the server:
 *    node app.js
 *
 * Optional environment variables:
 *    PORT=3000
 *    MONGODB_URI=mongodb://localhost:27017
 *    UPLOAD_DIR=./uploads
 *
 * App summary:
 * - Single-file Node.js app (backend-heavy, minimal single-page frontend)
 * - Upload bank-statement PDFs (supports password-protected via pdf-lib)
 * - Extract text, parse transactions with heuristics, store in MongoDB
 * - Compute analytics and return JSON + minimal HTML view
 * - Allowed deps only: express, mongodb, multer, pdf-lib, pdf-parse
 */

const fs = require('fs');
const fsp = fs.promises;
const path = require('path');
const crypto = require('crypto');

const express = require('express');
const multer = require('multer');
const { MongoClient } = require('mongodb');
const { PDFDocument } = require('pdf-lib');
const pdfParse = require('pdf-parse');

// ---------------------- Config ----------------------
const PORT = parseInt(process.env.PORT || '3000', 10);
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017';
const UPLOAD_DIR = process.env.UPLOAD_DIR || path.join(process.cwd(), 'uploads');

if (!fs.existsSync(UPLOAD_DIR)) {
  fs.mkdirSync(UPLOAD_DIR, { recursive: true });
}

// Multer config (limit 10MB)
const upload = multer({
  dest: UPLOAD_DIR,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    // Allow only PDFs based on mimetype and extension (best-effort)
    const okMime = file.mimetype === 'application/pdf' || file.mimetype === 'application/octet-stream';
    const okExt = path.extname(file.originalname || '').toLowerCase() === '.pdf';
    if (okMime || okExt) return cb(null, true);
    return cb(new Error('Invalid file type'), false);
  },
});

// ---------------------- MongoDB ----------------------
let mongoClient;
let transactionsCol; // bank_analytics.transactions

async function initMongo() {
  mongoClient = new MongoClient(MONGODB_URI, { ignoreUndefined: true });
  await mongoClient.connect();
  const db = mongoClient.db('bank_analytics');
  transactionsCol = db.collection('transactions');
  // optional helpful indexes (no error if they already exist)
  try {
    await transactionsCol.createIndex({ statementId: 1, date: 1 });
    await transactionsCol.createIndex({ createdAt: 1 });
  } catch (_) {}
}

// ---------------------- Utils ----------------------
const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : ([1e7]+-1e3+-4e3+-8e3+-1e11).replace(/[018]/g, c =>
  (c ^ crypto.randomBytes(1)[0] & 15 >> c / 4).toString(16)
));

const isPdfBuffer = (buf) => {
  if (!Buffer.isBuffer(buf) || buf.length < 5) return false;
  const header = buf.slice(0, 5).toString('ascii');
  return header.startsWith('%PDF-');
};

const monthMap = {
  jan: 1, feb: 2, mar: 3, apr: 4, may: 5, jun: 6, jul: 7, aug: 8, sep: 9, sept: 9, oct: 10, nov: 11, dec: 12,
};

function pad2(n) {
  return n < 10 ? `0${n}` : `${n}`;
}

// Try to parse a date string into YYYY-MM-DD
function parseDateStr(s) {
  if (!s) return null;
  s = s.trim();

  // yyyy-mm-dd or yyyy/mm/dd or yyyy.mm.dd
  let m = s.match(/^(\d{4})[\/\.\-](\d{1,2})[\/\.\-](\d{1,2})$/);
  if (m) {
    const y = +m[1], mo = +m[2], d = +m[3];
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) return `${y}-${pad2(mo)}-${pad2(d)}`;
  }

  // dd-mm-yyyy or dd/mm/yyyy or dd.mm.yyyy
  m = s.match(/^(\d{1,2})[\/\.\-](\d{1,2})[\/\.\-](\d{2,4})$/);
  if (m) {
    let d = +m[1], mo = +m[2], y = +m[3];
    if (y < 100) y = 2000 + y; // assume 20xx for 2-digit years
    if (mo >= 1 && mo <= 12 && d >= 1 && d <= 31) return `${y}-${pad2(mo)}-${pad2(d)}`;
  }

  // dd MMM yyyy or dd MMM yy (e.g., 20 Jan 2025)
  m = s.match(/^(\d{1,2})\s+([A-Za-z]{3,})\.?,?\s+(\d{2,4})$/);
  if (m) {
    const d = +m[1];
    let mo = monthMap[m[2].toLowerCase().replace(/\.$/, '')];
    let y = +m[3];
    if (y < 100) y = 2000 + y;
    if (mo && d >= 1 && d <= 31) return `${y}-${pad2(mo)}-${pad2(d)}`;
  }

  return null;
}

// Normalize PDF text: unify line breaks and collapse excessive spaces
function normalizeText(txt) {
  if (!txt) return '';
  // Replace tabs with space, unify CRLF to LF
  let t = txt.replace(/\r\n/g, '\n').replace(/\r/g, '\n').replace(/\t/g, ' ');
  // Remove trailing spaces per line
  t = t.split('\n').map(line => line.replace(/\s+$/g, '')).join('\n');
  // Keep multiple spaces in lines minimally to not break amounts: collapse 3+ spaces to 2
  t = t.replace(/ {3,}/g, '  ');
  return t;
}

// Extract text from PDF. Handles password-protected PDFs via pdf-lib.
async function extractTextFromPdf(buffer, password) {
  if (!isPdfBuffer(buffer)) {
    throw new Error('Invalid file type');
  }

  // Helper to detect password-related errors
  const isPasswordError = (msg) => {
    const s = String(msg || '').toLowerCase();
    return s.includes('password') || s.includes('encrypted') || s.includes('need password');
  };

  // If a password was provided, try to open with it using pdf-lib (and then parse)
  if (password && password.trim()) {
    try {
      const pdfDoc = await PDFDocument.load(buffer, { password: password.trim() });
      const bytes = await pdfDoc.save();
      const data = await pdfParse(bytes);
      return normalizeText(data.text || '');
    } catch (err) {
      // Wrong password or cannot decrypt
      if (isPasswordError(err.message)) {
        const e = new Error('Invalid or missing password');
        e.code = 'PASSWORD';
        throw e;
      }
      // Fallback try direct parse (in case doc not actually encrypted and pdf-lib failed)
      try {
        const data = await pdfParse(buffer);
        return normalizeText(data.text || '');
      } catch (e2) {
        throw new Error('Failed to parse PDF');
      }
    }
  }

  // No password provided: Try to load with pdf-lib without password (to detect encryption)
  try {
    const pdfDoc = await PDFDocument.load(buffer);
    // Save (ensures we get a clean, unencrypted buffer if it was not encrypted)
    const bytes = await pdfDoc.save();
    const data = await pdfParse(bytes);
    return normalizeText(data.text || '');
  } catch (err) {
    // If pdf-lib indicates encryption, ask for password
    if (String(err.message || '').toLowerCase().includes('password')) {
      const e = new Error('Invalid or missing password');
      e.code = 'PASSWORD';
      throw e;
    }
    // Try direct parsing with pdf-parse (some PDFs not fully supported by pdf-lib)
    try {
      const data = await pdfParse(buffer);
      return normalizeText(data.text || '');
    } catch (e2) {
      // If pdf-parse indicates password, ask for password
      if (String(e2.message || '').toLowerCase().includes('password')) {
        const e = new Error('Invalid or missing password');
        e.code = 'PASSWORD';
        throw e;
      }
      throw new Error('Failed to parse PDF');
    }
  }
}

// Parse heuristic: detect transactions by date + description + amount in each line
function parseTransactions(rawText, statementId) {
  const lines = rawText.split('\n').map(l => l.trim()).filter(Boolean);

  const parsingSummary = {
    linesScanned: lines.length,
    transactionsExtracted: 0,
    skippedLines: 0,
    examplesOfSkipped: [],
  };

  const transactions = [];
  const skippedExamples = [];

  // Date patterns to look for in each line
  const datePattern = new RegExp([
    '\\d{1,2}[\\/\\.\\-]\\d{1,2}[\\/\\.\\-]\\d{2,4}',  // dd/mm/yyyy, dd-mm-yy, etc.
    '\\d{4}[\\/\\.\\-]\\d{1,2}[\\/\\.\\-]\\d{1,2}',    // yyyy-mm-dd
    '\\d{1,2}\\s+[A-Za-z]{3,}\\s+\\d{2,4}'            // dd MMM yyyy
  ].join('|'));

  // Amount pattern: optional sign/parentheses, thousands separators, decimals
  // We also allow currency words/symbols near amounts (Rs, INR, $, ₹)
  const amtPattern = /(?:rs\.?|inr|usd|\$|₹)?\s*([+\-]?KATEX_INLINE_OPEN?\d{1,3}(?:,\d{3})*|\d+)(?:\.\d{1,2})?KATEX_INLINE_CLOSE?/ig;

  // Keywords for type inference
  const creditKeywords = ['cr', 'credit', 'refund', 'reversal', 'interest', 'salary', 'deposit', 'received'];
  const debitKeywords  = ['dr', 'debit', 'payment', 'upi', 'imps', 'neft', 'atm', 'withdrawal', 'pos', 'charge', 'fee', 'rent', 'emi'];

  // Categories mapping (simple keyword-based)
  const categoryMap = [
    { key: /salary|payroll|wages/i, category: 'salary' },
    { key: /rent/i, category: 'rent' },
    { key: /atm|cash\s*withdrawal/i, category: 'atm-withdrawal' },
    { key: /upi|bill|electricity|gas|water|mobile|dth|recharge/i, category: 'utilities' },
    { key: /grocery|groceries|supermarket|big\s*bazaar|more\s*supermarket|dmart/i, category: 'groceries' },
    { key: /fuel|petrol|diesel|shell|hpcl|bpcl|iocl/i, category: 'fuel' },
    { key: /emi|loan/i, category: 'loan' },
    { key: /insurance/i, category: 'insurance' },
    { key: /amazon|flipkart|myntra|ajio|nykaa|shopping|pos/i, category: 'shopping' },
    { key: /zomato|swiggy|uber|ola|foodpanda|eat|restaurant|coffee/i, category: 'food' },
    { key: /interest/i, category: 'interest' },
    { key: /refund|reversal/i, category: 'refund' },
    { key: /neft|imps|rtgs|transfer|to\s+acct|from\s+acct/i, category: 'transfer' },
  ];

  // Function: categorize based on description
  const categorize = (desc) => {
    for (const rule of categoryMap) {
      if (rule.key.test(desc)) return rule.category;
    }
    // UPI default from instruction -> utilities
    if (/upi/i.test(desc)) return 'utilities';
    return 'other';
  };

  const toNumber = (s) => {
    if (!s) return null;
    const neg = /^\s*KATEX_INLINE_OPEN/.test(s) || /^\s*-\s*/.test(s);
    // strip currency and commas and parentheses
    const t = s.replace(/[₹$,]|rs\.?|inr/gi, '').replace(/KATEX_INLINE_OPEN|KATEX_INLINE_CLOSE/g, '').replace(/\s+/g, '').replace(/[^0-9.\-]/g, '');
    const val = parseFloat(t);
    if (Number.isNaN(val)) return null;
    return neg ? -Math.abs(val) : val;
  };

  // Confidence helper
  const confidenceScore = ({ hasDate, hasAmount, hasType, hasCategory, descLen }) => {
    let score = 0;
    if (hasDate) score += 0.35;
    if (hasAmount) score += 0.35;
    if (hasType) score += 0.15;
    if (hasCategory) score += 0.1;
    if (descLen > 3) score += 0.05;
    return Math.min(1, score);
  };

  // Parse each line independently (simple heuristic; statements vary widely)
  for (const line of lines) {
    try {
      const dateMatch = line.match(datePattern);
      if (!dateMatch) {
        parsingSummary.skippedLines++;
        if (skippedExamples.length < 5) skippedExamples.push(line);
        continue;
      }

      const dateStrRaw = dateMatch[0];
      const dateISO = parseDateStr(dateStrRaw);
      if (!dateISO) {
        parsingSummary.skippedLines++;
        if (skippedExamples.length < 5) skippedExamples.push(line);
        continue;
      }

      // Extract amounts (we'll choose the last amount-like token in the line)
      let amtMatches = [];
      let m;
      while ((m = amtPattern.exec(line)) !== null) {
        // m[0] has whole match (possibly includes currency), m[1] the main number part
        const matchText = m[0];
        // Filter out clearly non-amounts (e.g., 12-digit account numbers with no decimals/commas)
        const digits = (matchText.match(/\d/g) || []).length;
        const hasDecimal = /\.\d{1,2}KATEX_INLINE_CLOSE?$/.test(matchText);
        const hasComma = /,/.test(matchText);
        if (digits >= 2 && (hasDecimal || hasComma || digits <= 8)) {
          amtMatches.push(matchText);
        }
      }
      if (amtMatches.length === 0) {
        parsingSummary.skippedLines++;
        if (skippedExamples.length < 5) skippedExamples.push(line);
        continue;
      }
      const amtRaw = amtMatches[amtMatches.length - 1]; // last amount on the line is often the transaction amount
      const amount = toNumber(amtRaw);
      if (amount === null || !isFinite(amount)) {
        parsingSummary.skippedLines++;
        if (skippedExamples.length < 5) skippedExamples.push(line);
        continue;
      }

      // Description: text between date and last amount occurrence
      const dateIdx = line.indexOf(dateStrRaw);
      const amtIdx = line.lastIndexOf(amtRaw);
      let description = '';
      if (dateIdx !== -1 && amtIdx !== -1 && amtIdx > dateIdx) {
        description = line.substring(dateIdx + dateStrRaw.length, amtIdx).trim();
      } else {
        // fallback: line without the date and amount strings
        description = line.replace(dateStrRaw, '').replace(amtRaw, '').trim();
      }
      // Clean description: remove stray markers
      description = description.replace(/\s{2,}/g, ' ').replace(/\s+(Cr|DR|Dr|CR)\b/g, '');

      // Type inference
      const lower = line.toLowerCase();
      let type = null;
      if (/[()]/.test(amtRaw) || /-\s*\d/.test(amtRaw) || debitKeywords.some(k => lower.includes(k))) {
        type = 'debit';
      }
      if (/[+]/.test(amtRaw) || creditKeywords.some(k => lower.includes(k))) {
        // If both matched, pick by amount sign if any
        if (type === 'debit') {
          if (amount < 0) type = 'debit';
          else type = 'credit';
        } else {
          type = 'credit';
        }
      }
      if (!type) {
        // Default heuristic: refunds, interest, salary -> credit; else debit
        if (/refund|reversal|interest|salary|credited/i.test(line)) type = 'credit';
        else type = 'debit';
      }

      const category = categorize(description || line);

      const conf = confidenceScore({
        hasDate: true,
        hasAmount: true,
        hasType: !!type,
        hasCategory: !!category && category !== 'other',
        descLen: (description || '').length
      });

      const amountSigned = type === 'debit' ? -Math.abs(amount) : Math.abs(amount);

      const tx = {
        statementId,
        date: dateISO,                    // YYYY-MM-DD
        description: description || '(no description)',
        amount: Math.abs(amount),         // store absolute amount
        type,                             // 'debit' | 'credit'
        category,
        confidence: conf,
        rawLine: line,
        createdAt: new Date().toISOString(),
      };

      transactions.push(tx);
    } catch (err) {
      parsingSummary.skippedLines++;
      if (skippedExamples.length < 5) skippedExamples.push(line);
    }
  }

  parsingSummary.transactionsExtracted = transactions.length;
  parsingSummary.examplesOfSkipped = skippedExamples;

  return { transactions, parsingSummary };
}

function computeAnalytics(statementId, transactions, parsingSummary) {
  const sums = {
    income: 0,
    expense: 0,
  };
  const byCategory = {};
  const expenses = []; // for top 5
  const byMonth = new Map();

  for (const t of transactions) {
    const amt = t.amount; // absolute stored
    if (t.type === 'credit') sums.income += amt;
    else sums.expense += amt;

    const cat = t.category || 'other';
    byCategory[cat] = (byCategory[cat] || 0) + amt;

    if (t.type === 'debit') {
      expenses.push({ amount: amt, description: t.description, date: t.date });
    }

    const m = (t.date || '').slice(0, 7); // YYYY-MM
    if (m) {
      if (!byMonth.has(m)) byMonth.set(m, { income: 0, expense: 0 });
      const agg = byMonth.get(m);
      if (t.type === 'credit') agg.income += amt;
      else agg.expense += amt;
    }
  }

  const top5Expenses = expenses.sort((a, b) => b.amount - a.amount).slice(0, 5);
  const monthlyTrends = Array.from(byMonth.entries())
    .sort((a, b) => a[0].localeCompare(b[0]))
    .map(([month, v]) => ({ month, income: round2(v.income), expense: round2(v.expense) }));

  const transactionCount = transactions.length;
  const avgTransactionAmount = transactionCount
    ? round2(transactions.reduce((s, t) => s + t.amount, 0) / transactionCount)
    : 0;

  return {
    statementId,
    totalIncome: round2(sums.income),
    totalExpense: round2(sums.expense),
    net: round2(sums.income - sums.expense),
    byCategory: objectMapRound2(byCategory),
    top5Expenses: top5Expenses.map(e => ({ amount: round2(e.amount), description: e.description, date: e.date })),
    monthlyTrends,
    transactionCount,
    avgTransactionAmount,
    parsingSummary,
  };
}

function round2(n) {
  return Math.round((n + Number.EPSILON) * 100) / 100;
}

function objectMapRound2(obj) {
  const out = {};
  for (const k of Object.keys(obj)) out[k] = round2(obj[k]);
  return out;
}

// ---------------------- Express App ----------------------
const app = express();

app.get('/', (req, res) => {
  res.setHeader('Content-Type', 'text/html; charset=utf-8');
  res.send(`<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>Bank Statement Analytics</title>
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
  :root { color-scheme: light dark; }
  body {
    font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif;
    margin: 2rem auto; max-width: 900px; padding: 0 1rem; line-height: 1.5;
  }
  h1 { font-size: 1.6rem; margin-bottom: 0.25rem; }
  p.lead { color: #666; margin-top: 0; }
  form {
    border: 1px solid #ccc; border-radius: 8px; padding: 1rem; margin: 1rem 0; background: rgba(0,0,0,0.03);
  }
  label { display: block; margin-top: 0.5rem; font-weight: 600; }
  input[type="file"], input[type="password"], input[type="text"] {
    width: 100%; max-width: 420px; padding: 0.5rem; margin-top: 0.25rem;
    border: 1px solid #bbb; border-radius: 6px; background: transparent;
  }
  button {
    margin-top: 0.75rem; padding: 0.6rem 1rem; border: 0; border-radius: 6px;
    background: #2563eb; color: white; font-weight: 600; cursor: pointer;
  }
  button:disabled { opacity: 0.6; cursor: not-allowed; }
  .msg { margin-top: 0.5rem; }
  .error { color: #b91c1c; font-weight: 600; }
  .ok { color: #065f46; }
  .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 0.75rem; }
  .card { border: 1px solid #ddd; border-radius: 8px; padding: 0.75rem; background: rgba(0,0,0,0.02); }
  table { border-collapse: collapse; width: 100%; margin-top: 0.5rem; }
  th, td { border: 1px solid #ddd; padding: 0.4rem 0.5rem; text-align: left; }
  th { background: rgba(0,0,0,0.05); }
  code, pre { background: rgba(0,0,0,0.05); padding: 0.5rem; border-radius: 6px; display: block; overflow: auto; }
  footer { margin-top: 2rem; font-size: 0.9rem; color: #666; }
</style>
</head>
<body>
  <h1>Bank Statement Analytics</h1>
  <p class="lead">Upload a PDF bank statement. If it is password-protected, provide the password. The server will extract transactions, store them in MongoDB, and compute analytics.</p>

  <form id="uploadForm">
    <label>PDF Statement (≤ 10MB)
      <input type="file" name="statement" id="statement" accept="application/pdf" required />
    </label>
    <label>Password (optional, for encrypted PDFs)
      <input type="password" name="password" id="password" placeholder="Enter PDF password if required" />
    </label>
    <button type="submit">Upload & Analyze</button>
    <div class="msg" id="msg"></div>
  </form>

  <div id="result" style="display:none;">
    <h2>Analytics</h2>
    <div class="grid">
      <div class="card">
        <strong>Statement ID</strong>
        <div id="sid"></div>
      </div>
      <div class="card">
        <strong>Total Income</strong>
        <div id="income"></div>
      </div>
      <div class="card">
        <strong>Total Expense</strong>
        <div id="expense"></div>
      </div>
      <div class="card">
        <strong>Net</strong>
        <div id="net"></div>
      </div>
      <div class="card">
        <strong>Count</strong>
        <div id="count"></div>
      </div>
      <div class="card">
        <strong>Average Amount</strong>
        <div id="avg"></div>
      </div>
    </div>

    <h3>By Category</h3>
    <table id="catTable"><thead><tr><th>Category</th><th>Amount</th></tr></thead><tbody></tbody></table>

    <h3>Top 5 Expenses</h3>
    <table id="topTable"><thead><tr><th>Date</th><th>Description</th><th>Amount</th></tr></thead><tbody></tbody></table>

    <h3>Monthly Trends</h3>
    <table id="monthTable"><thead><tr><th>Month</th><th>Income</th><th>Expense</th></tr></thead><tbody></tbody></table>

    <h3>Parsing Summary</h3>
    <pre id="summary"></pre>

    <h3>Raw JSON</h3>
    <pre id="raw"></pre>

    <p>Fetch again later: <code>GET /analytics/&lt;statementId&gt;</code></p>
  </div>

  <footer>Tip: If parsing fails or looks off, try re-exporting the PDF as "Print to PDF" and upload again.</footer>

<script>
const form = document.getElementById('uploadForm');
const msg = document.getElementById('msg');
const result = document.getElementById('result');

form.addEventListener('submit', async (e) => {
  e.preventDefault();
  msg.textContent = '';
  result.style.display = 'none';

  const f = document.getElementById('statement').files[0];
  if (!f) { msg.textContent = 'Please choose a PDF file.'; msg.className = 'msg error'; return; }
  if (f.size > 10 * 1024 * 1024) { msg.textContent = 'File too large (max 10MB).'; msg.className = 'msg error'; return; }

  const fd = new FormData();
  fd.append('statement', f);
  const pwd = document.getElementById('password').value;
  if (pwd) fd.append('password', pwd);

  const btn = form.querySelector('button');
  btn.disabled = true; btn.textContent = 'Processing...';

  try {
    const resp = await fetch('/upload', { method: 'POST', body: fd });
    const data = await resp.json();
    if (!resp.ok || data.error) {
      msg.textContent = data.error || ('Upload failed (HTTP ' + resp.status + ')');
      msg.className = 'msg error';
      return;
    }
    msg.textContent = 'Success!';
    msg.className = 'msg ok';
    renderAnalytics(data);
    result.style.display = 'block';
  } catch (err) {
    msg.textContent = 'Unexpected error: ' + (err.message || err);
    msg.className = 'msg error';
  } finally {
    btn.disabled = false; btn.textContent = 'Upload & Analyze';
  }
});

function renderAnalytics(a) {
  document.getElementById('sid').textContent = a.statementId;
  document.getElementById('income').textContent = a.totalIncome.toFixed(2);
  document.getElementById('expense').textContent = a.totalExpense.toFixed(2);
  document.getElementById('net').textContent = a.net.toFixed(2);
  document.getElementById('count').textContent = a.transactionCount;
  document.getElementById('avg').textContent = a.avgTransactionAmount.toFixed(2);

  // By category
  const catBody = document.querySelector('#catTable tbody');
  catBody.innerHTML = '';
  const catEntries = Object.entries(a.byCategory || {}).sort((x,y)=>y[1]-x[1]);
  for (const [k,v] of catEntries) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + escapeHtml(k) + '</td><td>' + v.toFixed(2) + '</td>';
    catBody.appendChild(tr);
  }

  // Top 5 expenses
  const topBody = document.querySelector('#topTable tbody');
  topBody.innerHTML = '';
  for (const t of (a.top5Expenses || [])) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + escapeHtml(t.date || '') + '</td><td>' + escapeHtml(t.description || '') + '</td><td>' + t.amount.toFixed(2) + '</td>';
    topBody.appendChild(tr);
  }

  // Monthly trends
  const monthBody = document.querySelector('#monthTable tbody');
  monthBody.innerHTML = '';
  for (const m of (a.monthlyTrends || [])) {
    const tr = document.createElement('tr');
    tr.innerHTML = '<td>' + escapeHtml(m.month) + '</td><td>' + m.income.toFixed(2) + '</td><td>' + m.expense.toFixed(2) + '</td>';
    monthBody.appendChild(tr);
  }

  // Summary and raw
  document.getElementById('summary').textContent = JSON.stringify(a.parsingSummary || {}, null, 2);
  document.getElementById('raw').textContent = JSON.stringify(a, null, 2);
}

function escapeHtml(s){ return (''+s).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }
</script>
</body>
</html>`);
});

// POST /upload
app.post('/upload', upload.single('statement'), async (req, res) => {
  let filePath = null;
  try {
    if (!req.file) {
      return res.status(400).json({ error: 'No file uploaded' });
    }
    if (req.file.size > 10 * 1024 * 1024) {
      return res.status(400).json({ error: 'File too large (max 10MB)' });
    }
    filePath = req.file.path;
    const buffer = await fsp.readFile(filePath);

    // Validate file header
    if (!isPdfBuffer(buffer)) {
      return res.status(400).json({ error: 'Invalid file type' });
    }

    const password = (req.body && req.body.password) ? String(req.body.password) : '';

    // Extract text (handles password via pdf-lib)
    let text;
    try {
      text = await extractTextFromPdf(buffer, password);
    } catch (e) {
      if (e.code === 'PASSWORD') {
        return res.status(400).json({ error: 'Invalid or missing password' });
      }
      return res.status(422).json({ error: 'Failed to parse PDF' });
    }

    const statementId = uuid();
    const { transactions, parsingSummary } = parseTransactions(text, statementId);

    if (!transactions || transactions.length === 0) {
      return res.status(422).json({
        error: 'No transactions could be extracted',
        parsingSummary,
      });
    }

    // Store transactions in MongoDB
    if (!transactionsCol) {
      return res.status(503).json({ error: 'Database unavailable' });
    }

    try {
      await transactionsCol.insertMany(transactions, { ordered: false });
    } catch (dbErr) {
      // Even if insertMany partially fails, attempt to proceed with analytics from current batch
      // If it's a connectivity error, abort
      if (!mongoClient || !mongoClient.topology || mongoClient.topology.s.state !== 'connected') {
        return res.status(503).json({ error: 'Database error while storing transactions' });
      }
    }

    const analytics = computeAnalytics(statementId, transactions, parsingSummary);
    return res.json(analytics);
  } catch (err) {
    console.error('Upload error:', err);
    return res.status(500).json({ error: 'Server error' });
  } finally {
    // Clean up uploaded file
    if (filePath) {
      try { await fsp.unlink(filePath); } catch (_) {}
    }
  }
});

// Optional: GET /analytics/:statementId
app.get('/analytics/:statementId', async (req, res) => {
  try {
    const statementId = String(req.params.statementId || '').trim();
    if (!statementId) {
      return res.status(400).json({ error: 'Missing statementId' });
    }
    if (!transactionsCol) {
      return res.status(503).json({ error: 'Database unavailable' });
    }
    const transactions = await transactionsCol.find({ statementId }).toArray();
    if (!transactions || transactions.length === 0) {
      return res.status(404).json({ error: 'No transactions found for this statementId' });
    }
    // Minimal parsing summary for historical fetch
    const parsingSummary = {
      linesScanned: null,
      transactionsExtracted: transactions.length,
      skippedLines: null,
      examplesOfSkipped: [],
    };
    const analytics = computeAnalytics(statementId, transactions, parsingSummary);
    return res.json(analytics);
  } catch (err) {
    console.error('Analytics fetch error:', err);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ---------------------- Start ----------------------
(async function start() {
  try {
    await initMongo();
    console.log('Connected to MongoDB at', MONGODB_URI);
  } catch (err) {
    console.error('MongoDB connection failed:', err.message);
    console.error('The server will still start, but DB-dependent endpoints may return 503.');
  }
  app.listen(PORT, () => {
    console.log(`Server listening on http://localhost:${PORT}`);
  });
})();

/**
 * Notes on parsing heuristics:
 * - We normalize whitespace and split by lines.
 * - For each line, we look for a date in common formats (DD/MM/YYYY, YYYY-MM-DD, "20 Jan 2025", etc.).
 * - We then find amount-like tokens (supports commas, decimals, parentheses for negatives, and currency markers).
 * - We pick the last amount in the line as the transaction amount (common in many statements).
 * - Debit/Credit type is inferred from amount sign/parentheses, and keywords like Dr/Cr, "refund", "salary", etc.
 * - The description is the text between the date and amount; otherwise the remaining cleaned text.
 * - We categorize via a simple keyword map (e.g., SALARY→salary, RENT→rent, UPI/BILL→utilities, etc.).
 * - A confidence score (0–1) is computed based on presence of date/amount/type/category.
 *
 * Error handling:
 * - If the uploaded file is not a PDF, respond with { error: "Invalid file type" }.
 * - If the PDF is encrypted and the password is missing/incorrect, respond with { error: "Invalid or missing password" }.
 * - If no transactions are extracted, respond with 422 and a parsingSummary.
 * - MongoDB errors yield a 503 where applicable.
 * - Uploaded files are always cleaned up after parsing.
 */