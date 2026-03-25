# 🛡️ Threat Exposure Test Server

A self-hosted, open-source alternative to Zscaler Security Preview and similar tools. Tests whether your network security infrastructure (web proxy, NGFW, DLP, antivirus) properly blocks common threats.

## How It Works

The server hosts test endpoints that serve threat-like payloads. The browser UI fetches each endpoint. If your security stack **blocks** the request (connection reset, HTTP error, timeout), the test **passes**. If the payload reaches the browser successfully, the test **fails** — meaning that threat vector is exposed.

**No real malware is used.** All payloads are inert test patterns (EICAR standard, fake credit card numbers, etc.).

## Test Categories

| # | Test | What It Does |
|---|------|-------------|
| 1 | **Credit Card Exfiltration** | Sends Luhn-valid card numbers (Visa, MC, Amex, Discover) via CSV, JSON, POST body, and hidden HTML fields |
| 2 | **EICAR Antivirus** | Downloads the EICAR test file as plain `.com`, `.zip`, double-zipped `.zip`, and `.rar` |
| 3 | **Ransomware Detection** | Downloads archive with ransom note, `.encrypted` files, and EICAR payload |
| 4 | **Executable Download** | Downloads a minimal valid PE32 `.exe` (benign — just a RET instruction) |
| 5 | **Email Exfiltration** | Exfiltrates 150 email addresses + PII via CSV download and POST upload |
| 6 | **Cross-Site Scripting** | Loads pages with reflected XSS and DOM-based injection vectors |

## Quick Start

```bash
tar xzf threat-exposure-test.tar.gz
cd threat-exposure-test
npm install
npm start
# → http://localhost:3000
```

## Public Deployment

### Option A: Any VPS (Ubuntu/Debian one-liner)

```bash
# Upload the project to your VPS, then:
chmod +x deploy.sh
sudo ./deploy.sh
# → http://YOUR_PUBLIC_IP (port 80, systemd managed)
```

### Option B: Docker

```bash
docker compose up -d
# → http://YOUR_PUBLIC_IP (port 80)
```

### Option C: Manual (any server)

```bash
npm install
PORT=80 node server.js
# Or behind nginx/caddy on any port
```

### Cloud-specific notes

- **AWS EC2 / Lightsail**: Open port 80 in Security Group inbound rules
- **DigitalOcean / Vultr / Linode**: Firewall is open by default; just deploy
- **GCP Compute Engine**: Add firewall rule allowing tcp:80
- **Azure VM**: Add inbound port rule for port 80 in Network Security Group
- **Oracle Cloud**: Add ingress rule for port 80 in Security List + run `sudo iptables -I INPUT -p tcp --dport 80 -j ACCEPT`

## Deployment Notes

- **Host this server OUTSIDE your security perimeter** (e.g., on a public cloud VPS) so requests must traverse your security stack.
- If you run it on `localhost`, requests won't pass through your web proxy/firewall and all tests will "fail" (which is expected — there's no security layer to block them).
- Ideal deployment: cloud VM or container → users access from corporate network through proxy/firewall.

## Interpreting Results

| Result | Meaning |
|--------|---------|
| ✅ **Protected** | Your security blocked this threat vector |
| ❌ **Exposed** | The payload reached the browser — this threat type is not blocked |

**A "perfect" score (100% Protected) means your security stack caught everything.** In practice, most organizations will have gaps — especially around DLP (credit card / email exfiltration) and nested archive scanning.

## Extending

Add new test endpoints in `server.js` and register them in the `TESTS` array in `public/index.html`. Each test needs:

- A server endpoint that serves the test payload
- A subtest entry with `id`, `label`, `url`, and `method`

## Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `PORT` | `3000` | Server listen port |

## License

MIT
