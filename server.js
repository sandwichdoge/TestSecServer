const express = require('express');
const archiver = require('archiver');
const path = require('path');
const { Buffer } = require('buffer');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

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

// ═══════════════════════════════════════════════
// TEST MANIFEST — display metadata only
// No URLs, no payloads, no sensitive strings
// ═══════════════════════════════════════════════

const TEST_MANIFEST = [
  {
    id: 'credit-card',
    icon: 'credit-card',
    title: 'Credit Card Exfiltration',
    desc: 'Attempts to exfiltrate Luhn-valid credit card numbers (Visa, Mastercard, Amex, Discover, JCB, Diners) via multiple data formats and transport methods.',
    subtests: [
      { id: 'cc-csv',    label: 'CSV Download' },
      { id: 'cc-json',   label: 'JSON API' },
      { id: 'cc-post',   label: 'POST Upload' },
      { id: 'cc-hidden', label: 'Hidden HTML' },
    ]
  },
  {
    id: 'eicar',
    icon: 'virus',
    title: 'Antivirus Detection',
    desc: 'Downloads the industry-standard antivirus test file in various archive formats. Scanners should detect the signature even inside compressed archives.',
    subtests: [
      { id: 'eicar-plain',  label: 'Plain File' },
      { id: 'eicar-zip',    label: 'Zipped' },
      { id: 'eicar-dblzip', label: 'Double-Zipped' },
      { id: 'eicar-rar',    label: 'RAR Archive' },
    ]
  },
  {
    id: 'ransomware',
    icon: 'lock',
    title: 'Ransomware Detection',
    desc: 'Downloads an archive with ransom note, encrypted file extensions, and embedded malware test payload disguised as an executable.',
    subtests: [
      { id: 'ransom-zip', label: 'Ransom Archive' },
    ]
  },
  {
    id: 'exe',
    icon: 'binary',
    title: 'Executable Download',
    desc: 'Attempts to download a PE32 executable file. Security policies should block executable downloads from untrusted sources.',
    subtests: [
      { id: 'exe-dl', label: 'PE32 Binary' },
    ]
  },
  {
    id: 'email-exfil',
    icon: 'email',
    title: 'Mass Email Exfiltration',
    desc: 'Attempts to exfiltrate 150+ email addresses with associated PII data via file download and upload methods.',
    subtests: [
      { id: 'email-dl',   label: 'CSV Download' },
      { id: 'email-post', label: 'POST Upload' },
    ]
  },
  {
    id: 'xss',
    icon: 'code',
    title: 'Cross-Site Scripting',
    desc: 'Loads pages with reflected and DOM-based injection vectors. Security proxies should strip or neutralize these patterns.',
    subtests: [
      { id: 'xss-reflect', label: 'Reflected XSS' },
      { id: 'xss-payload', label: 'Multi-Vector XSS' },
    ]
  },
];

// ═══════════════════════════════════════════════
// SUBTEST HANDLERS — each generates its payload
// on demand when the test actually runs
// ═══════════════════════════════════════════════

const SUBTEST_HANDLERS = {
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

  'cc-post': (req, res) => {
    const cards = generateCreditCards(25);
    let csv = 'Card Number,Expiry,CVV\n';
    cards.forEach(c => { csv += `${c.number},${c.expiry},${c.cvv}\n`; });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="exfiltrated_cards.csv"');
    res.send(csv);
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
    const eicarBuf = Buffer.from(getEicar(), 'ascii');
    const marker = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);
    const archiveHeader = Buffer.from([0x00, 0x00, 0x73, 0x00, 0x01, 0x0D, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const fileHeader = Buffer.from([0x00, 0x00, 0x74, 0x00, 0x80, 0x28, 0x00]);
    const packSize = Buffer.alloc(4); packSize.writeUInt32LE(eicarBuf.length);
    const unpackSize = Buffer.alloc(4); unpackSize.writeUInt32LE(eicarBuf.length);
    const meta = Buffer.from([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1D, 0x30]);
    const nameSize = Buffer.alloc(2); const fileName = Buffer.from('eicar.com', 'ascii'); nameSize.writeUInt16LE(fileName.length);
    const fileAttr = Buffer.alloc(4);
    res.setHeader('Content-Type', 'application/x-rar-compressed');
    res.setHeader('Content-Disposition', 'attachment; filename="eicar.rar"');
    res.send(Buffer.concat([marker, archiveHeader, fileHeader, packSize, unpackSize, meta, nameSize, fileAttr, fileName, eicarBuf]));
  },

  'ransom-zip': (req, res) => {
    const note = `--- YOUR FILES HAVE BEEN ENCRYPTED ---\nPay 0.5 BTC to wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\nContact: decrypt_service@tormail.org\nID: ${Buffer.from(Date.now().toString()).toString('hex')}\n`;
    const fakeEncrypted = Buffer.alloc(1024);
    for (let i = 0; i < 1024; i++) fakeEncrypted[i] = Math.floor(Math.random() * 256);
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="urgent_invoice.zip"');
    const archive = archiver('zip', { zlib: { level: 9 } });
    archive.pipe(res);
    archive.append(note, { name: 'README_DECRYPT.txt' });
    archive.append(fakeEncrypted, { name: 'document.docx.encrypted' });
    archive.append(getEicar(), { name: 'payload.exe' });
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

  'email-post': (req, res) => {
    const emails = generateEmails(150);
    let csv = 'Name,Email,Phone\n';
    emails.forEach(email => {
      const name = email.split('@')[0].replace(/[._]/g, ' ');
      const phone = `(${Math.floor(Math.random() * 900) + 100}) ${Math.floor(Math.random() * 900) + 100}-${Math.floor(Math.random() * 9000) + 1000}`;
      csv += `"${name}",${email},${phone}\n`;
    });
    res.setHeader('Content-Type', 'text/csv');
    res.setHeader('Content-Disposition', 'attachment; filename="exfiltrated_contacts.csv"');
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

// Single endpoint for ALL test execution
// Client calls: GET /api/run/cc-csv, GET /api/run/eicar-plain, etc.
app.get('/api/run/:subtestId', (req, res) => {
  const handler = SUBTEST_HANDLERS[req.params.subtestId];
  if (!handler) return res.status(404).json({ error: 'Unknown subtest' });
  handler(req, res);
});

app.get('/api/health', (req, res) => {
  const total = TEST_MANIFEST.reduce((sum, t) => sum + t.subtests.length, 0);
  res.json({ status: 'ok', version: '2.0.0', categories: TEST_MANIFEST.length, subtests: total });
});

// ═══════════════════════════════════════════════
// START
// ═══════════════════════════════════════════════

app.listen(PORT, '0.0.0.0', () => {
  const os = require('os');
  const ifaces = Object.values(os.networkInterfaces()).flat().filter(i => i.family === 'IPv4' && !i.internal);
  const total = TEST_MANIFEST.reduce((sum, t) => sum + t.subtests.length, 0);
  console.log(`\n🛡️  Threat Exposure Test Server v2.0`);
  console.log(`   → http://localhost:${PORT}`);
  ifaces.forEach(i => console.log(`   → http://${i.address}:${PORT}`));
  console.log(`\n   ${total} sub-tests across ${TEST_MANIFEST.length} categories\n`);
});
