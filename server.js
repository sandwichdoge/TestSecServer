etHeader('Pragma', 'no-cache');
  res.setHeader('Expires', '0');
  res.setHeader('Surrogate-Control', 'no-store');
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ═══════════════════════════════════════════════
// XOR OBFUSCATION — keeps staged payloads opaque
// to inline content scanners during transit to
// the client. The client decodes, then POSTs
// cleartext so the security stack can inspect it.
// ═══════════════════════════════════════════════

function xorEncode(buf, key) {
  const keyBuf = Buffer.from(key, 'utf8');
  const out = Buffer.alloc(buf.length);
  for (let i = 0; i < buf.length; i++) {
    out[i] = buf[i] ^ keyBuf[i % keyBuf.length];
  }
  return out;
}

// Per-session rotating key so the encoded blob is never const express = require('express');
const archiver = require('archiver');
const path = require('path');
const { Buffer } = require('buffer');
const crypto = require('crypto');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(express.raw({ type: 'text/csv', limit: '2mb' }));
app.use(express.raw({ type: 'application/octet-stream', limit: '2mb' }));

// Prevent browsers and intermediate proxies from caching ANY API response.
// Without this, stopped-server tests can still "pass" from stale cache.
app.use('/api', (req, res, next) => {
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');
  res.sthe same twice
function generateKey() {
  return crypto.randomBytes(16).toString('hex');
}

// ═══════════════════════════════════════════════
// DATA GENERATORS (all sensitive data lives here)
// ═══════════════════════════════════════════════

function luhnGenerate(prefix, length) {
  const digits = prefix.split('').map(Number);
  while (digits.length < length - 1) digits.push(Math.floor(Math.random() * 10));
  let sum = 0, alt = true;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  digits.push((10 - (sum % 10)) % 10);
  return digits.join('');
}

function generateCreditCards(count = 25) {
  const types = [
    { name: 'Visa', prefix: '4', length: 16 },
    { name: 'Mastercard', prefix: '51', length: 16 },
    { name: 'Mastercard', prefix: '52', length: 16 },
    { name: 'Amex', prefix: '34', length: 15 },
    { name: 'Amex', prefix: '37', length: 15 },
    { name: 'Discover', prefix: '6011', length: 16 },
    { name: 'Diners Club', prefix: '300', length: 14 },
    { name: 'JCB', prefix: '3528', length: 16 },
  ];
  const cards = [];
  for (let i = 0; i < count; i++) {
    const type = types[i % types.length];
    const number = luhnGenerate(type.prefix, type.length);
    const month = String(Math.floor(Math.random() * 12) + 1).padStart(2, '0');
    const year = String(new Date().getFullYear() + Math.floor(Math.random() * 5) + 1).slice(-2);
    const cvv = String(Math.floor(Math.random() * (type.name === 'Amex' ? 9000 : 900)) + (type.name === 'Amex' ? 1000 : 100));
    cards.push({ type: type.name, number, expiry: `${month}/${year}`, cvv });
  }
  return cards;
}

function generateEmails(count = 150) {
  const domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'proton.me', 'hotmail.com', 'icloud.com', 'aol.com', 'mail.com', 'zoho.com', 'fastmail.com'];
  const firstNames = ['james', 'mary', 'john', 'patricia', 'robert', 'jennifer', 'michael', 'linda', 'david', 'elizabeth', 'william', 'barbara', 'richard', 'susan', 'joseph', 'jessica', 'thomas', 'sarah', 'charles', 'karen'];
  const lastNames = ['smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller', 'davis', 'rodriguez', 'martinez', 'hernandez', 'lopez', 'gonzalez', 'wilson', 'anderson', 'thomas', 'taylor', 'moore', 'jackson', 'martin'];
  const emails = [];
  for (let i = 0; i < count; i++) {
    const first = firstNames[Math.floor(Math.random() * firstNames.length)];
    const last = lastNames[Math.floor(Math.random() * lastNames.length)];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const sep = ['', '.', '_'][Math.floor(Math.random() * 3)];
    const num = Math.random() > 0.5 ? Math.floor(Math.random() * 999) : '';
    emails.push(`${first}${sep}${last}${num}@${domain}`);
  }
  return emails;
}

function createMinimalExe() {
  const dosHeader = Buffer.alloc(128, 0);
  dosHeader[0] = 0x4D; dosHeader[1] = 0x5A;
  dosHeader.writeUInt32LE(128, 60);
  const peSignature = Buffer.from('PE\0\0');
  const coffHeader = Buffer.alloc(20, 0);
  coffHeader.writeUInt16LE(0x014C, 0);
  coffHeader.writeUInt16LE(1, 2);
  coffHeader.writeUInt16LE(0x00E0, 16);
  coffHeader.writeUInt16LE(0x0102, 18);
  const optHeader = Buffer.alloc(224, 0);
  optHeader.writeUInt16LE(0x010B, 0);
  optHeader.writeUInt32LE(0x1000, 16);
  optHeader.writeUInt32LE(0x400000, 28);
  optHeader.writeUInt32LE(0x1000, 32);
  optHeader.writeUInt32LE(0x200, 36);
  optHeader.writeUInt16LE(4, 40);
  optHeader.writeUInt16LE(4, 48);
  optHeader.writeUInt32LE(0x3000, 56);
  optHeader.writeUInt32LE(0x200, 60);
  optHeader.writeUInt16LE(3, 68);
  optHeader.writeUInt32LE(0x100000, 72);
  optHeader.writeUInt32LE(0x1000, 76);
  optHeader.writeUInt32LE(0x100000, 80);
  optHeader.writeUInt32LE(0x1000, 84);
  optHeader.writeUInt32LE(16, 92);
  const sectionHeader = Buffer.alloc(40, 0);
  sectionHeader.write('.text', 0, 'ascii');
  sectionHeader.writeUInt32LE(0x1000, 8);
  sectionHeader.writeUInt32LE(0x1000, 12);
  sectionHeader.writeUInt32LE(0x200, 16);
  sectionHeader.writeUInt32LE(0x200, 20);
  sectionHeader.writeUInt32LE(0x60000020, 36);
  const headerSize = 128 + 4 + 20 + 224 + 40;
  const padding = Buffer.alloc(0x200 - headerSize, 0);
  const codeSection = Buffer.alloc(0x200, 0);
  codeSection[0] = 0xC3;
  return Buffer.concat([dosHeader, peSignature, coffHeader, optHeader, sectionHeader, padding, codeSection]);
}

// EICAR stored as base64 so it won't trigger scanners on the server file itself
const EICAR_B64 = 'WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo=';
function getEicar() { return Buffer.from(EICAR_B64, 'base64').toString('ascii'); }

// ─── RAR4 Archive Builder ───
const EICAR_RAR_PATH = path.join(__dirname, 'testdata', 'eicar.rar');

// ═══════════════════════════════════════════════
// RANSOMWARE SIMULATION HELPERS
// ═══════════════════════════════════════════════

// Generate a fake BTC wallet address (valid Base58Check format, testnet prefix)
function fakeBtcWallet() {
  // Use a well-known burn address prefix so it's clearly fake
  const chars = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let addr = '1FAKE';
  for (let i = 0; i < 29; i++) addr += chars[Math.floor(Math.random() * chars.length)];
  return addr;
}

// Random hex blob — simulates encrypted file content
function randomBlob(size) {
  const buf = Buffer.alloc(size);
  for (let i = 0; i < size; i++) buf[i] = Math.floor(Math.random() * 256);
  return buf;
}

// Victim ID that looks like real ransomware victim identifiers
function victimId() {
  return crypto.randomBytes(16).toString('hex').toUpperCase();
}

// Generate a realistic TXT ransom note
function ransomNoteTxt() {
  const wallet = fakeBtcWallet();
  const vid = victimId();
  return [
    '╔══════════════════════════════════════════════════════════════╗',
    '║              ALL YOUR FILES HAVE BEEN ENCRYPTED             ║',
    '╚══════════════════════════════════════════════════════════════╝',
    '',
    'What happened?',
    '─────────────',
    'All your documents, photos, databases, and other important files',
    'have been encrypted with military-grade AES-256 + RSA-4096.',
    'No third-party decryption software can restore your files.',
    '',
    'How to recover?',
    '───────────────',
    'To decrypt your files you need to purchase our decryption tool.',
    '',
    `  Payment amount:  0.5 BTC`,
    `  Bitcoin wallet:  ${wallet}`,
    `  Victim ID:       ${vid}`,
    '',
    'After payment, email your victim ID and transaction hash to:',
    '  ► decrypt_support@onionmail.org',
    '  ► recovery_files@torbox36ijlcevujx7.onion',
    '',
    'WARNINGS:',
    '  • Do NOT rename encrypted files — this will corrupt them.',
    '  • Do NOT use third-party decryptors — they will destroy your key.',
    '  • Do NOT contact law enforcement — they cannot help you and will',
    '    only delay recovery.',
    '  • You have 72 HOURS before the price doubles to 1.0 BTC.',
    '  • After 7 days your decryption key will be permanently deleted.',
    '',
    `Encrypted on: ${new Date().toISOString()}`,
    `System ID:    ${crypto.randomBytes(8).toString('hex')}`,
    '',
  ].join('\n');
}

// Generate an HTML ransom note (mimics .HTA dropper style)
function ransomNoteHtml() {
  const wallet = fakeBtcWallet();
  const vid = victimId();
  return `<!DOCTYPE html>
<html>
<head><title>YOUR FILES ARE ENCRYPTED</title>
<style>
  body { background: #1a0000; color: #ff3333; font-family: 'Courier New', monospace; padding: 40px; }
  .container { max-width: 700px; margin: 0 auto; border: 2px solid #ff3333; padding: 30px; }
  h1 { text-align: center; font-size: 28px; text-transform: uppercase; }
  .warning { background: #330000; padding: 15px; margin: 20px 0; border-left: 4px solid #ff0000; }
  .wallet { font-size: 14px; background: #000; padding: 10px; word-break: break-all; color: #ffcc00; }
  .timer { text-align: center; font-size: 48px; color: #ff0000; margin: 20px 0; }
  .vid { color: #00ff00; }
</style>
</head>
<body>
<div class="container">
  <h1>⚠ YOUR FILES HAVE BEEN ENCRYPTED ⚠</h1>
  <div class="timer" id="countdown">71:59:59</div>
  <p>All your documents, databases, photos, and critical business files
  have been encrypted with <strong>AES-256-CBC + RSA-4096</strong>.</p>

  <div class="warning">
    <strong>DO NOT:</strong>
    <br>• Rename any .locked / .encrypted files
    <br>• Run antivirus scans (they will quarantine your encrypted data)
    <br>• Contact law enforcement (they will seize your machines)
    <br>• Use third-party recovery tools (they corrupt the encryption headers)
  </div>

  <h2>Payment Instructions</h2>
  <p>Send exactly <strong>0.5 BTC</strong> to:</p>
  <div class="wallet">${wallet}</div>

  <p>Then email your Victim ID and transaction hash to:</p>
  <p>Primary: <strong>decrypt_support@onionmail.org</strong></p>
  <p>Backup:  <strong>recover_files@dnmx.org</strong></p>

  <p>Your Victim ID: <span class="vid">${vid}</span></p>

  <div class="warning">
    After 72 hours the ransom doubles to 1.0 BTC.<br>
    After 7 days your private key is permanently destroyed.
  </div>
</div>
<script>
  // Countdown timer — typical ransomware pressure tactic
  var deadline = Date.now() + 72*60*60*1000;
  setInterval(function(){
    var r = Math.max(0, deadline - Date.now());
    var h = Math.floor(r/3600000), m = Math.floor((r%3600000)/60000), s = Math.floor((r%60000)/1000);
    document.getElementById('countdown').textContent =
      String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
  }, 1000);
</script>
</body>
</html>`;
}

// Build a C2 beacon payload (JSON system fingerprint)
function c2BeaconPayload() {
  return JSON.stringify({
    type: 'beacon',
    victim_id: victimId(),
    hostname: `DESKTOP-${crypto.randomBytes(3).toString('hex').toUpperCase()}`,
    username: 'Administrator',
    os: 'Windows 10 Pro 22H2 (19045.3930)',
    arch: 'x64',
    domain: 'CORPNET.local',
    ip_internal: `10.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
    ip_external: `${Math.floor(Math.random()*223)+1}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}.${Math.floor(Math.random()*255)}`,
    antivirus: ['Windows Defender', 'CrowdStrike Falcon'][Math.floor(Math.random()*2)],
    av_disabled: true,
    elevated: true,
    encryption_key: crypto.randomBytes(32).toString('base64'),
    files_encrypted: Math.floor(Math.random() * 50000) + 10000,
    total_size_gb: +(Math.random() * 500 + 50).toFixed(1),
    bitcoin_wallet: fakeBtcWallet(),
    timestamp: new Date().toISOString(),
  }, null, 2);
}

// ═══════════════════════════════════════════════
// TEST MANIFEST
// method: 'GET' (download) or 'POST' (exfiltration)
// ═══════════════════════════════════════════════

const TEST_MANIFEST = [
  {
    id: 'credit-card',
    icon: 'credit-card',
    title: 'Credit Card Exfiltration',
    desc: 'Attempts to exfiltrate Luhn-valid credit card numbers (Visa, Mastercard, Amex, Discover, JCB, Diners) via multiple data formats and transport methods.',
    subtests: [
      { id: 'cc-csv',    label: 'CSV Download',  method: 'GET',  filename: 'customer_cards.csv' },
      { id: 'cc-json',   label: 'JSON API',       method: 'GET',  filename: 'payment_data.json' },
      { id: 'cc-post',   label: 'POST Upload',    method: 'POST', filename: 'exfiltrated_cards.csv' },
      { id: 'cc-hidden', label: 'Hidden HTML',    method: 'GET',  filename: 'order_confirmation.html' },
    ]
  },
  {
    id: 'eicar',
    icon: 'virus',
    title: 'Antivirus Detection',
    desc: 'Downloads the industry-standard antivirus test file in various archive formats. Scanners should detect the signature even inside compressed archives.',
    subtests: [
      { id: 'eicar-plain',  label: 'Plain File',     method: 'GET', filename: 'eicar.com' },
      { id: 'eicar-zip',    label: 'Zipped',          method: 'GET', filename: 'eicar.zip' },
      { id: 'eicar-dblzip', label: 'Double-Zipped',   method: 'GET', filename: 'eicar_nested.zip' },
      { id: 'eicar-rar',    label: 'RAR Archive',     method: 'GET', filename: 'eicar.rar' },
    ]
  },
  {
    id: 'ransomware',
    icon: 'lock',
    title: 'Ransomware Detection',
    desc: 'Simulates a multi-stage ransomware attack: initial payload delivery, ransom notes (TXT and weaponized HTML/HTA), mass file encryption artifacts, C2 beacon callbacks, and double-extortion data theft. Each stage targets a different layer of the security stack.',
    subtests: [
      { id: 'ransom-archive',    label: 'Payload Archive',       method: 'GET',  filename: 'urgent_invoice.zip' },
      { id: 'ransom-note-html',  label: 'HTML Ransom Note',      method: 'GET',  filename: 'DECRYPT_INSTRUCTIONS.html' },
      { id: 'ransom-mass-crypt', label: 'Mass Encryption Sim',   method: 'GET',  filename: 'encrypted_files.zip' },
      { id: 'ransom-c2-beacon',  label: 'C2 Beacon Callback',    method: 'POST', filename: 'telemetry.json' },
      { id: 'ransom-dbl-extort', label: 'Double Extortion',      method: 'GET',  filename: 'stolen_data_sample.zip' },
    ]
  },
  {
    id: 'exe',
    icon: 'binary',
    title: 'Executable Download',
    desc: 'Attempts to download a PE32 executable file. Security policies should block executable downloads from untrusted sources.',
    subtests: [
      { id: 'exe-dl', label: 'PE32 Binary', method: 'GET', filename: 'software_update.exe' },
    ]
  },
  {
    id: 'email-exfil',
    icon: 'email',
    title: 'Mass Email Exfiltration',
    desc: 'Attempts to exfiltrate 150+ email addresses with associated PII data via file download and upload methods.',
    subtests: [
      { id: 'email-dl',   label: 'CSV Download',  method: 'GET',  filename: 'employee_directory.csv' },
      { id: 'email-post', label: 'POST Upload',   method: 'POST', filename: 'exfiltrated_contacts.csv' },
    ]
  },
  {
    id: 'xss',
    icon: 'code',
    title: 'Cross-Site Scripting',
    desc: 'Loads pages with reflected and DOM-based injection vectors. Security proxies should strip or neutralize these patterns.',
    subtests: [
      { id: 'xss-reflect', label: 'Reflected XSS',    method: 'GET', filename: 'search_results.html' },
      { id: 'xss-payload', label: 'Multi-Vector XSS',  method: 'GET', filename: 'page.html' },
    ]
  },
];

// ═══════════════════════════════════════════════
// PAYLOAD GENERATORS for POST staging
// Returns raw cleartext Buffer for a given subtest
// ═══════════════════════════════════════════════

const STAGE_GENERATORS = {
  'cc-post': () => {
    const cards = generateCreditCards(25);
    let csv = 'Card Number,Expiry,CVV\n';
    cards.forEach(c => { csv += `${c.number},${c.expiry},${c.cvv}\n`; });
    return { data: Buffer.from(csv, 'utf8'), contentType: 'text/csv', filename: 'exfiltrated_cards.csv' };
  },

  'email-post': () => {
    const emails = generateEmails(150);
    let csv = 'Name,Email,Phone\n';
    emails.forEach(email => {
      const name = email.split('@')[0].replace(/[._]/g, ' ');
      const phone = `(${Math.floor(Math.random() * 900) + 100}) ${Math.floor(Math.random() * 900) + 100}-${Math.floor(Math.random() * 9000) + 1000}`;
      csv += `"${name}",${email},${phone}\n`;
    });
    return { data: Buffer.from(csv, 'utf8'), contentType: 'text/csv', filename: 'exfiltrated_contacts.csv' };
  },

  // C2 beacon: ransomware phones home with system fingerprint + encryption key
  'ransom-c2-beacon': () => {
    const payload = c2BeaconPayload();
    return { data: Buffer.from(payload, 'utf8'), contentType: 'application/json', filename: 'telemetry.json' };
  },
};

// ═══════════════════════════════════════════════
// SUBTEST HANDLERS — GET tests (downloads)
// ═══════════════════════════════════════════════

const GET_HANDLERS = {
  'cc-csv': (req, res) => {
    const cards = generateCreditCards(25);
    let csv = 'Card Type,Card Number,Expiry,CVV\n';
    cards.forEach(c => { csv += `${c.type},${c.number},${c.expiry},${c.cvv}\n`; });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="customer_cards.csv"');
    res.send(csv);
  },

  'cc-json': (req, res) => {
    res.json({ customer_payment_data: generateCreditCards(25) });
  },

  'cc-hidden': (req, res) => {
    const cards = generateCreditCards(15);
    let html = '<html><body><h1>Order Confirmation</h1>';
    cards.forEach((c, i) => {
      html += `<div class="order" style="display:none" data-payment="${c.number}" data-exp="${c.expiry}" data-cvv="${c.cvv}"></div>`;
      html += `<p>Order #${1000 + i} - Status: Complete</p>`;
    });
    html += '</body></html>';
    res.setHeader('Content-Type', 'text/html');
    res.send(html);
  },

  'eicar-plain': (req, res) => {
    res.setHeader('Content-Type', 'application/octet-stream');
    res.setHeader('Content-Disposition', 'attachment; filename="eicar.com"');
    res.send(getEicar());
  },

  'eicar-zip': (req, res) => {
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="eicar.zip"');
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);
    archive.append(getEicar(), { name: 'eicar.com' });
    archive.finalize();
  },

  'eicar-dblzip': (req, res) => {
    const inner = archiver('zip', { zlib: { level: 9 } });
    const chunks = [];
    inner.on('data', chunk => chunks.push(chunk));
    inner.on('end', () => {
      res.setHeader('Content-Type', 'application/zip');
      res.setHeader('Content-Disposition', 'attachment; filename="eicar_nested.zip"');
      const outer = archiver('zip', { zlib: { level: 9 } });
      outer.pipe(res);
      outer.append(Buffer.concat(chunks), { name: 'eicar_inner.zip' });
      outer.finalize();
    });
    inner.append(getEicar(), { name: 'eicar.com' });
    inner.finalize();
  },

  'eicar-rar': (req, res) => {
    const fs = require('fs');
    if (!fs.existsSync(EICAR_RAR_PATH)) {
      return res.status(500).json({ error: 'eicar.rar not found — place a real RAR archive at testdata/eicar.rar' });
    }
    res.sendFile(EICAR_RAR_PATH, {
      headers: {
        'Content-Type': 'application/x-rar-compressed',
        'Content-Disposition': 'attachment; filename="eicar.rar"',
      },
    }, (err) => {
      if (err && !res.headersSent) {
        res.status(500).json({ error: 'Failed to send eicar.rar' });
      }
    });
  },

  // ─── RANSOMWARE: Stage 1 — Payload Archive ───
  // Classic initial delivery: zip with ransom note, EICAR payload
  // disguised as an exe, and a fake encrypted document.
  // Tests: AV scanning inside archives, malicious filename detection.
  'ransom-archive': (req, res) => {
    const note = ransomNoteTxt();
    const fakeEncrypted = randomBlob(2048);

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="urgent_invoice.zip"');
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);
    archive.append(note, { name: 'README_DECRYPT.txt' });
    archive.append(fakeEncrypted, { name: 'invoice_2024.pdf.encrypted' });
    archive.append(getEicar(), { name: 'decrypt_tool.exe' });
    archive.append(createMinimalExe(), { name: 'WindowsUpdate.exe' });
    archive.finalize();
  },

  // ─── RANSOMWARE: Stage 2 — HTML Ransom Note ───
  // Standalone .html with countdown timer, BTC wallet, and threatening
  // language. Mimics .HTA droppers that ransomware gangs leave behind.
  // Tests: content-based threat detection, malicious HTML patterns.
  'ransom-note-html': (req, res) => {
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('Content-Disposition', 'attachment; filename="DECRYPT_INSTRUCTIONS.html"');
    res.send(ransomNoteHtml());
  },

  // ─── RANSOMWARE: Stage 3 — Mass Encryption Simulation ───
  // Archive containing 50+ files with ransomware-typical extensions
  // (.locked, .encrypted, .crypted, .enc) across fake directory
  // structures, plus the encryption key blob and a ransom note.
  // Tests: heuristic detection of bulk encrypted file patterns.
  'ransom-mass-crypt': (req, res) => {
    const extensions = ['.locked', '.encrypted', '.crypted', '.enc', '.WNCRY', '.zepto', '.cerber'];
    const dirs = ['Documents', 'Desktop', 'Pictures', 'Database', 'Finance', 'HR_Records'];
    const fileTypes = ['.docx', '.xlsx', '.pdf', '.jpg', '.sql', '.pst', '.bak', '.mdb', '.csv', '.txt'];

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="encrypted_files.zip"');
    const archive = archiver('zip', { zlib: { level: 6 } });
    archive.pipe(res);

    // Ransom notes scattered in every directory (as real ransomware does)
    dirs.forEach(dir => {
      archive.append(ransomNoteTxt(), { name: `${dir}/README_DECRYPT.txt` });
      archive.append(ransomNoteHtml(), { name: `${dir}/DECRYPT_INSTRUCTIONS.html` });
    });

    // 50 fake encrypted files across directories
    for (let i = 0; i < 50; i++) {
      const dir = dirs[i % dirs.length];
      const base = `file_${String(i + 1).padStart(3, '0')}${fileTypes[i % fileTypes.length]}`;
      const ext = extensions[i % extensions.length];
      // Vary sizes: small docs to larger DB dumps
      const size = 512 + Math.floor(Math.random() * 4096);
      archive.append(randomBlob(size), { name: `${dir}/${base}${ext}` });
    }

    // Encryption key blob — what ransomware stores locally before exfil
    const keyBlob = JSON.stringify({
      algorithm: 'AES-256-CBC',
      rsa_public_key: `-----BEGIN PUBLIC KEY-----\n${crypto.randomBytes(256).toString('base64').match(/.{1,64}/g).join('\n')}\n-----END PUBLIC KEY-----`,
      encrypted_aes_key: crypto.randomBytes(256).toString('base64'),
      iv: crypto.randomBytes(16).toString('hex'),
      victim_id: victimId(),
      files_encrypted: 50,
      timestamp: new Date().toISOString(),
    }, null, 2);
    archive.append(keyBlob, { name: 'encryption_metadata.json' });

    archive.finalize();
  },

  // ─── RANSOMWARE: Stage 5 — Double Extortion ───
  // Archive containing "stolen" data samples (fake PII, financial
  // records) plus a threat note about public data leakage.
  // Tests: DLP for bulk PII, exfiltration pattern detection.
  'ransom-dbl-extort': (req, res) => {
    const emails = generateEmails(50);
    const cards = generateCreditCards(10);

    // Stolen employee records
    let employeeCsv = 'Full Name,Email,SSN,Salary,Department\n';
    emails.slice(0, 30).forEach(email => {
      const name = email.split('@')[0].replace(/[._]/g, ' ');
      const ssn = `${Math.floor(Math.random() * 900) + 100}-${Math.floor(Math.random() * 90) + 10}-${Math.floor(Math.random() * 9000) + 1000}`;
      const salary = `$${(Math.floor(Math.random() * 150) + 50) * 1000}`;
      const depts = ['Engineering', 'Finance', 'HR', 'Legal', 'Sales', 'Executive'];
      employeeCsv += `"${name}",${email},${ssn},${salary},${depts[Math.floor(Math.random() * depts.length)]}\n`;
    });

    // Stolen payment data
    let paymentCsv = 'Customer,Card Type,Card Number,Expiry,CVV\n';
    cards.forEach(c => {
      const name = `Customer ${Math.floor(Math.random() * 9000) + 1000}`;
      paymentCsv += `"${name}",${c.type},${c.number},${c.expiry},${c.cvv}\n`;
    });

    // Extortion note
    const extortionNote = [
      '═══════════════════════════════════════════════════════════',
      '  NOTICE: YOUR COMPANY DATA HAS BEEN DOWNLOADED',
      '═══════════════════════════════════════════════════════════',
      '',
      'We have exfiltrated the following from your network:',
      '',
      `  • ${30} employee records (SSN, salary, contact info)`,
      `  • ${10} customer payment cards`,
      '  • Financial reports (Q1–Q4)',
      '  • Executive email archives',
      '  • Source code repositories',
      '',
      'SAMPLES ARE INCLUDED IN THIS ARCHIVE AS PROOF.',
      '',
      'If payment is not received within 72 hours, we will:',
      '  1. Publish all data on our leak site',
      '  2. Notify your customers of the breach',
      '  3. Forward data to regulatory authorities',
      '  4. Sell remaining data on darknet markets',
      '',
      `  Payment:    1.0 BTC`,
      `  Wallet:     ${fakeBtcWallet()}`,
      `  Victim ID:  ${victimId()}`,
      `  Contact:    leaks_negotiation@onionmail.org`,
      '',
      'This is not a bluff. The clock is ticking.',
      '',
    ].join('\n');

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="stolen_data_sample.zip"');
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);
    archive.append(extortionNote, { name: 'READ_ME_OR_ELSE.txt' });
    archive.append(employeeCsv, { name: 'proof/employee_records_sample.csv' });
    archive.append(paymentCsv, { name: 'proof/payment_cards_sample.csv' });
    archive.append(ransomNoteHtml(), { name: 'DECRYPT_INSTRUCTIONS.html' });
    archive.finalize();
  },

  'exe-dl': (req, res) => {
    res.setHeader('Content-Type', 'application/x-msdownload');
    res.setHeader('Content-Disposition', 'attachment; filename="software_update.exe"');
    res.send(createMinimalExe());
  },

  'email-dl': (req, res) => {
    const emails = generateEmails(150);
    let csv = 'Name,Email,Phone,SSN\n';
    emails.forEach(email => {
      const name = email.split('@')[0].replace(/[._]/g, ' ');
      const phone = `(${Math.floor(Math.random() * 900) + 100}) ${Math.floor(Math.random() * 900) + 100}-${Math.floor(Math.random() * 9000) + 1000}`;
      const ssn = `${Math.floor(Math.random() * 900) + 100}-${Math.floor(Math.random() * 90) + 10}-${Math.floor(Math.random() * 9000) + 1000}`;
      csv += `"${name}",${email},${phone},${ssn}\n`;
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="employee_directory.csv"');
    res.send(csv);
  },

  'xss-reflect': (req, res) => {
    const payload = Buffer.from('PHNjcmlwdD5hbGVydCgiWFNTIik8L3NjcmlwdD4=', 'base64').toString();
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('X-XSS-Protection', '0');
    res.send(`<html><body><h1>Search Results for: ${payload}</h1><p>No results found.</p></body></html>`);
  },

  'xss-payload': (req, res) => {
    const vectors = [
      Buffer.from('PHNjcmlwdD5kb2N1bWVudC53cml0ZSgnWFNTX1RFU1RfRVhFQ1VURUQnKTwvc2NyaXB0Pg==', 'base64').toString(),
      '<img src=x onerror="alert(1)">',
      '<svg onload="alert(2)">',
      '<div onmouseover="alert(3)">hover me</div>',
    ];
    res.setHeader('Content-Type', 'text/html');
    res.setHeader('X-XSS-Protection', '0');
    res.send(`<html><body>${vectors.join('\n')}</body></html>`);
  },
};

// ═══════════════════════════════════════════════
// API ROUTES
// ═══════════════════════════════════════════════

// Client fetches this on load — display metadata only, zero payloads
app.get('/api/manifest', (req, res) => {
  res.json(TEST_MANIFEST);
});

// ─── STAGE endpoint ───
// Returns XOR-encoded + base64 payload so the delivery
// to the browser doesn't trigger DLP/AV inline scanners.
// The client decodes in JS memory, then POSTs cleartext.
app.get('/api/stage/:subtestId', (req, res) => {
  const generator = STAGE_GENERATORS[req.params.subtestId];
  if (!generator) return res.status(404).json({ error: 'No staging available for this subtest' });

  const key = generateKey();
  const { data, contentType, filename } = generator();
  const encoded = xorEncode(data, key).toString('base64');

  res.json({ key, encoded, contentType, filename });
});

// ─── RUN endpoint for GET tests ───
function handleGetRun(req, res) {
  const handler = GET_HANDLERS[req.params.subtestId];
  if (!handler) return res.status(404).json({ error: 'Unknown subtest or wrong method (use POST)' });
  handler(req, res);
}
app.get('/api/run/:subtestId/:filename', handleGetRun);
app.get('/api/run/:subtestId', handleGetRun);

// ─── RUN endpoint for POST tests ───
function handlePostRun(req, res) {
  const validPostTests = Object.keys(STAGE_GENERATORS);
  if (!validPostTests.includes(req.params.subtestId)) {
    return res.status(404).json({ error: 'Unknown POST subtest' });
  }

  const size = req.headers['content-length'] || '0';
  res.json({
    received: true,
    subtestId: req.params.subtestId,
    bytes: parseInt(size, 10),
    message: 'Payload received — DLP did not block this exfiltration attempt',
  });
}
app.post('/api/run/:subtestId/:filename', handlePostRun);
app.post('/api/run/:subtestId', handlePostRun);

app.get('/api/health', (req, res) => {
  const total = TEST_MANIFEST.reduce((sum, t) => sum + t.subtests.length, 0);
  const postTests = TEST_MANIFEST.reduce((sum, t) => sum + t.subtests.filter(s => s.method === 'POST').length, 0);
  res.json({ status: 'ok', version: '3.1.0', categories: TEST_MANIFEST.length, subtests: total, postTests });
});

// ═══════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════

app.listen(PORT, '0.0.0.0', () => {
  const os = require('os');
  const ifaces = Object.values(os.networkInterfaces()).flat().filter(i => i.family === 'IPv4' && !i.internal);
  const total = TEST_MANIFEST.reduce((sum, t) => sum + t.subtests.length, 0);
  const postTests = TEST_MANIFEST.reduce((sum, t) => sum + t.subtests.filter(s => s.method === 'POST').length, 0);
  console.log(`\n🛡️  Threat Exposure Test Server v3.1`);
  console.log(`   → http://localhost:${PORT}`);
  ifaces.forEach(i => console.log(`   → http://${i.address}:${PORT}`));
  console.log(`\n   ${total} sub-tests across ${TEST_MANIFEST.length} categories`);
  console.log(`   ${postTests} POST exfiltration tests (staged + XOR delivery)\n`);
  const fs = require('fs');
  if (!fs.existsSync(EICAR_RAR_PATH)) {
    console.log(`   ⚠️  testdata/eicar.rar not found — RAR test will return 500`);
    console.log(`      Create it with: mkdir -p testdata && rar a testdata/eicar.rar eicar.com\n`);
  }
});
