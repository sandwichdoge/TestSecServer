const express = require('express');
const archiver = require('archiver');
const path = require('path');
const { Buffer } = require('buffer');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3000;

app.use(express.json({ limit: '1mb' }));
app.use(express.urlencoded({ extended: true, limit: '1mb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ─── EICAR string (standard antivirus test) ───
const EICAR_STRING = 'X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*';

// ─── Helper: generate fake credit card numbers (Luhn-valid) ───
function luhnGenerate(prefix, length) {
  const digits = prefix.split('').map(Number);
  while (digits.length < length - 1) {
    digits.push(Math.floor(Math.random() * 10));
  }
  // Calculate Luhn check digit
  let sum = 0;
  let alt = true;
  for (let i = digits.length - 1; i >= 0; i--) {
    let n = digits[i];
    if (alt) { n *= 2; if (n > 9) n -= 9; }
    sum += n;
    alt = !alt;
  }
  digits.push((10 - (sum % 10)) % 10);
  return digits.join('');
}

function generateCreditCards(count = 20) {
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

// ─── Helper: generate fake emails ───
function generateEmails(count = 120) {
  const domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'proton.me', 'hotmail.com', 'icloud.com', 'aol.com', 'mail.com', 'zoho.com', 'fastmail.com'];
  const firstNames = ['james', 'mary', 'john', 'patricia', 'robert', 'jennifer', 'michael', 'linda', 'david', 'elizabeth', 'william', 'barbara', 'richard', 'susan', 'joseph', 'jessica', 'thomas', 'sarah', 'charles', 'karen', 'christopher', 'lisa', 'daniel', 'nancy', 'matthew', 'betty', 'anthony', 'margaret', 'mark', 'sandra'];
  const lastNames = ['smith', 'johnson', 'williams', 'brown', 'jones', 'garcia', 'miller', 'davis', 'rodriguez', 'martinez', 'hernandez', 'lopez', 'gonzalez', 'wilson', 'anderson', 'thomas', 'taylor', 'moore', 'jackson', 'martin'];
  const emails = [];
  for (let i = 0; i < count; i++) {
    const first = firstNames[Math.floor(Math.random() * firstNames.length)];
    const last = lastNames[Math.floor(Math.random() * lastNames.length)];
    const domain = domains[Math.floor(Math.random() * domains.length)];
    const separator = ['', '.', '_'][Math.floor(Math.random() * 3)];
    const num = Math.random() > 0.5 ? Math.floor(Math.random() * 999) : '';
    emails.push(`${first}${separator}${last}${num}@${domain}`);
  }
  return emails;
}

// ─── Helper: create minimal PE (.exe) header ───
// This creates a valid but completely benign PE executable that just exits
function createMinimalExe() {
  // Minimal valid PE32 executable - DOS header + PE header + a single section
  // It does nothing - just returns immediately
  const dosHeader = Buffer.alloc(128, 0);
  // MZ signature
  dosHeader[0] = 0x4D; dosHeader[1] = 0x5A;
  // e_lfanew: offset to PE header at 128
  dosHeader.writeUInt32LE(128, 60);

  const peSignature = Buffer.from('PE\0\0');

  // COFF header (20 bytes)
  const coffHeader = Buffer.alloc(20, 0);
  coffHeader.writeUInt16LE(0x014C, 0); // Machine: i386
  coffHeader.writeUInt16LE(1, 2);       // NumberOfSections
  coffHeader.writeUInt16LE(0x00E0, 16); // SizeOfOptionalHeader
  coffHeader.writeUInt16LE(0x0102, 18); // Characteristics: EXECUTABLE_IMAGE | 32BIT_MACHINE

  // Optional header (224 bytes for PE32)
  const optHeader = Buffer.alloc(224, 0);
  optHeader.writeUInt16LE(0x010B, 0);    // Magic: PE32
  optHeader.writeUInt32LE(0x1000, 16);   // AddressOfEntryPoint
  optHeader.writeUInt32LE(0x400000, 28); // ImageBase
  optHeader.writeUInt32LE(0x1000, 32);   // SectionAlignment
  optHeader.writeUInt32LE(0x200, 36);    // FileAlignment
  optHeader.writeUInt16LE(4, 40);        // MajorOperatingSystemVersion
  optHeader.writeUInt16LE(0, 42);        // MinorOperatingSystemVersion
  optHeader.writeUInt16LE(4, 48);        // MajorSubsystemVersion
  optHeader.writeUInt32LE(0x3000, 56);   // SizeOfImage
  optHeader.writeUInt32LE(0x200, 60);    // SizeOfHeaders
  optHeader.writeUInt16LE(3, 68);        // Subsystem: CONSOLE
  optHeader.writeUInt32LE(0x100000, 72); // SizeOfStackReserve
  optHeader.writeUInt32LE(0x1000, 76);   // SizeOfStackCommit
  optHeader.writeUInt32LE(0x100000, 80); // SizeOfHeapReserve
  optHeader.writeUInt32LE(0x1000, 84);   // SizeOfHeapCommit
  optHeader.writeUInt32LE(16, 92);       // NumberOfRvaAndSizes

  // Section header (.text)
  const sectionHeader = Buffer.alloc(40, 0);
  sectionHeader.write('.text', 0, 'ascii');
  sectionHeader.writeUInt32LE(0x1000, 8);  // VirtualSize
  sectionHeader.writeUInt32LE(0x1000, 12); // VirtualAddress
  sectionHeader.writeUInt32LE(0x200, 16);  // SizeOfRawData
  sectionHeader.writeUInt32LE(0x200, 20);  // PointerToRawData
  sectionHeader.writeUInt32LE(0x60000020, 36); // Characteristics: CODE | EXECUTE | READ

  // Padding to FileAlignment
  const headerSize = 128 + 4 + 20 + 224 + 40;
  const padding = Buffer.alloc(0x200 - headerSize, 0);

  // Code section: just a RET instruction (0xC3)
  const codeSection = Buffer.alloc(0x200, 0);
  codeSection[0] = 0xC3; // RET

  return Buffer.concat([dosHeader, peSignature, coffHeader, optHeader, sectionHeader, padding, codeSection]);
}

// ─────────────────────────────────────────────
// TEST ENDPOINTS
// ─────────────────────────────────────────────

// ── 1. Credit Card Exfiltration (various formats) ──
app.get('/api/test/credit-card-csv', (req, res) => {
  const cards = generateCreditCards(25);
  let csv = 'Card Type,Card Number,Expiry,CVV\n';
  cards.forEach(c => { csv += `${c.type},${c.number},${c.expiry},${c.cvv}\n`; });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="customer_cards.csv"');
  res.send(csv);
});

app.get('/api/test/credit-card-json', (req, res) => {
  const cards = generateCreditCards(25);
  res.json({ customer_payment_data: cards });
});

app.post('/api/test/credit-card-post', (req, res) => {
  // Simulate exfiltration via POST - the request body contains credit card data
  // If security blocks this POST, the test passes
  res.json({ status: 'received', message: 'Credit card data was successfully exfiltrated' });
});

app.get('/api/test/credit-card-hidden', (req, res) => {
  // Card numbers embedded in innocent-looking HTML
  const cards = generateCreditCards(15);
  let html = '<html><body><h1>Order Confirmation</h1>';
  cards.forEach((c, i) => {
    html += `<div class="order" style="display:none" data-payment="${c.number}" data-exp="${c.expiry}" data-cvv="${c.cvv}"></div>`;
    html += `<p>Order #${1000 + i} - Status: Complete</p>`;
  });
  html += '</body></html>';
  res.setHeader('Content-Type', 'text/html');
  res.send(html);
});

// ── 2. EICAR Virus Test Files ──
app.get('/api/test/eicar', (req, res) => {
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Disposition', 'attachment; filename="eicar.com"');
  res.send(EICAR_STRING);
});

app.get('/api/test/eicar-zip', (req, res) => {
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="eicar.zip"');
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);
  archive.append(EICAR_STRING, { name: 'eicar.com' });
  archive.finalize();
});

app.get('/api/test/eicar-double-zip', (req, res) => {
  // Create inner zip first
  const innerArchive = archiver('zip', { zlib: { level: 9 } });
  const innerChunks = [];
  innerArchive.on('data', chunk => innerChunks.push(chunk));
  innerArchive.on('end', () => {
    const innerZip = Buffer.concat(innerChunks);
    // Now create outer zip containing the inner zip
    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="eicar_nested.zip"');
    const outerArchive = archiver('zip', { zlib: { level: 9 } });
    outerArchive.pipe(res);
    outerArchive.append(innerZip, { name: 'eicar_inner.zip' });
    outerArchive.finalize();
  });
  innerArchive.append(EICAR_STRING, { name: 'eicar.com' });
  innerArchive.finalize();
});

// For RAR, we serve a pre-built binary since Node doesn't have native RAR creation
// We'll create a minimal RAR-like archive with proper headers
app.get('/api/test/eicar-rar', (req, res) => {
  // RAR5 signature + marker block + EICAR embedded
  // Simpler approach: use a real RAR archive structure
  // RAR signature: Rar!\x1A\x07\x00 (RAR4) or Rar!\x1A\x07\x01\x00 (RAR5)
  const eicarBuf = Buffer.from(EICAR_STRING, 'ascii');

  // We'll construct a minimal valid-enough RAR4 archive
  // RAR4 Marker: 52 61 72 21 1A 07 00
  const marker = Buffer.from([0x52, 0x61, 0x72, 0x21, 0x1A, 0x07, 0x00]);

  // Archive header block
  const archiveHeader = Buffer.from([
    0x00, 0x00, // HEAD_CRC (placeholder)
    0x73,       // HEAD_TYPE = 0x73 (archive header)
    0x00, 0x01, // HEAD_FLAGS
    0x0D, 0x00, // HEAD_SIZE = 13
    0x00, 0x00, // Reserved
    0x00, 0x00, 0x00, 0x00 // Reserved
  ]);

  // For security scanners to detect this, combining signature + eicar content is sufficient
  // Many scanners check for the RAR signature and scan contained data
  const fileHeader = Buffer.from([
    0x00, 0x00, // HEAD_CRC
    0x74,       // HEAD_TYPE = 0x74 (file header)
    0x00, 0x80, // HEAD_FLAGS
    0x28, 0x00, // HEAD_SIZE = 40
  ]);

  // Pack size (EICAR string length)
  const packSize = Buffer.alloc(4, 0);
  packSize.writeUInt32LE(eicarBuf.length, 0);
  // Unpack size
  const unpackSize = Buffer.alloc(4, 0);
  unpackSize.writeUInt32LE(eicarBuf.length, 0);

  const hostOS = Buffer.from([0x00]); // MS DOS
  const fileCRC = Buffer.alloc(4, 0);
  const ftime = Buffer.alloc(4, 0);
  const unpVer = Buffer.from([0x1D]); // version needed
  const method = Buffer.from([0x30]); // storing (no compression)
  const nameSize = Buffer.alloc(2, 0);
  const fileName = Buffer.from('eicar.com', 'ascii');
  nameSize.writeUInt16LE(fileName.length, 0);
  const fileAttr = Buffer.alloc(4, 0);

  const rarContent = Buffer.concat([
    marker, archiveHeader,
    fileHeader, packSize, unpackSize, hostOS, fileCRC, ftime, unpVer, method, nameSize, fileAttr, fileName,
    eicarBuf
  ]);

  res.setHeader('Content-Type', 'application/x-rar-compressed');
  res.setHeader('Content-Disposition', 'attachment; filename="eicar.rar"');
  res.send(rarContent);
});

// ── 3. Ransomware Simulation ──
app.get('/api/test/ransomware', (req, res) => {
  // Simulate a ransomware payload download
  // Contains typical ransomware indicators: ransom note text + encrypted-looking data
  const ransomNote = `
--- YOUR FILES HAVE BEEN ENCRYPTED ---
All your documents, photos, databases and other important files have been encrypted.
You need to pay 0.5 BTC to wallet: 1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa
Contact: decrypt_service@tormail.org
Your unique ID: ${Buffer.from(Date.now().toString()).toString('hex')}
--- DO NOT DELETE THIS FILE ---
`;

  // Create a ZIP with ransomware-like contents
  res.setHeader('Content-Type', 'application/zip');
  res.setHeader('Content-Disposition', 'attachment; filename="urgent_invoice.zip"');
  const archive = archiver('zip', { zlib: { level: 9 } });
  archive.pipe(res);
  archive.append(ransomNote, { name: 'README_DECRYPT.txt' });
  // Add a fake encrypted file
  const fakeEncrypted = Buffer.alloc(1024);
  for (let i = 0; i < 1024; i++) fakeEncrypted[i] = Math.floor(Math.random() * 256);
  archive.append(fakeEncrypted, { name: 'document.docx.encrypted' });
  archive.append(EICAR_STRING, { name: 'payload.exe' });
  archive.finalize();
});

// ── 4. Executable Download ──
app.get('/api/test/exe-download', (req, res) => {
  const exe = createMinimalExe();
  res.setHeader('Content-Type', 'application/x-msdownload');
  res.setHeader('Content-Disposition', 'attachment; filename="software_update.exe"');
  res.send(exe);
});

// ── 5. Mass Email Exfiltration ──
app.get('/api/test/email-exfil-download', (req, res) => {
  const emails = generateEmails(150);
  let csv = 'Name,Email,Phone,SSN\n';
  emails.forEach((email, i) => {
    const name = email.split('@')[0].replace(/[._]/g, ' ');
    const phone = `(${Math.floor(Math.random() * 900) + 100}) ${Math.floor(Math.random() * 900) + 100}-${Math.floor(Math.random() * 9000) + 1000}`;
    const ssn = `${Math.floor(Math.random() * 900) + 100}-${Math.floor(Math.random() * 90) + 10}-${Math.floor(Math.random() * 9000) + 1000}`;
    csv += `"${name}",${email},${phone},${ssn}\n`;
  });
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', 'attachment; filename="employee_directory.csv"');
  res.send(csv);
});

app.post('/api/test/email-exfil-post', (req, res) => {
  // Simulate POSTing bulk emails to an external server
  res.json({ status: 'received', count: 150, message: 'Email data was successfully exfiltrated' });
});

// ── 6. Cross-Site Scripting ──
app.get('/api/test/xss-reflected', (req, res) => {
  const payload = req.query.q || '<script>alert("XSS")</script>';
  // Deliberately vulnerable - reflects input without sanitization
  res.setHeader('Content-Type', 'text/html');
  res.setHeader('X-XSS-Protection', '0'); // Disable browser XSS filter for testing
  res.send(`<html><body><h1>Search Results for: ${payload}</h1><p>No results found.</p></body></html>`);
});

app.get('/api/test/xss-payload', (req, res) => {
  // Serve a page with multiple XSS vectors
  const html = `<html><body>
    <script>document.write('XSS_TEST_EXECUTED')</script>
    <img src=x onerror="alert('xss_img')">
    <svg onload="alert('xss_svg')">
    <div onmouseover="alert('xss_hover')">hover me</div>
    <iframe src="javascript:alert('xss_iframe')"></iframe>
  </body></html>`;
  res.setHeader('Content-Type', 'text/html');
  res.setHeader('X-XSS-Protection', '0');
  res.send(html);
});

// ── Payload endpoints (fetched by client at test time, not embedded in page) ──
app.get('/api/payload/credit-cards', (req, res) => {
  const cards = generateCreditCards(25);
  res.json({ cards: cards.map(c => c.number) });
});

app.get('/api/payload/emails', (req, res) => {
  const emails = generateEmails(150);
  res.json({ emails });
});

// ── Health check ──
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', version: '1.0.0', tests: 6 });
});

app.listen(PORT, '0.0.0.0', () => {
  const os = require('os');
  const ifaces = Object.values(os.networkInterfaces()).flat().filter(i => i.family === 'IPv4' && !i.internal);
  console.log(`\n🛡️  Threat Exposure Test Server running on:`);
  console.log(`   → http://localhost:${PORT}`);
  ifaces.forEach(i => console.log(`   → http://${i.address}:${PORT}`));
  console.log(`\n   ${getSubtestTotal()} sub-tests across 6 categories\n`);
});

function getSubtestTotal() {
  // Count: 4 CC + 4 EICAR + 1 ransomware + 1 exe + 2 email + 2 XSS = 14
  return 14;
}
