/* FixFlow — Remediation Copilot (simplified)
   3 screens: Upload → Findings → Guided Fix Session */

const S = { findings: [], sessions: {}, activeId: null, source: '', suggestedGroups: [], confirmedGroups: {} };
const SEV_SCORE = { critical: '9.5', high: '7.5', medium: '5.0', low: '2.5' };
const PHASES = ['Understand', 'Fix', 'Verify', 'Complete'];
const DEFAULT_OWNERS = { rce:'DevOps Team', sqli:'Dev Team', tls:'IT Admin', 'mfa-vpn':'IT Admin', 'default-creds-db':'IT Admin', 's3-bucket':'DevOps Team', openssl:'DevOps Team', xss:'Dev Team', 'github-perms':'Security Team', 'backup-encryption':'IT Admin', generic:'Security Team' };
const SLA_DAYS = { critical: 3, high: 7, medium: 14, low: 30 };
const OWNERS = ['DevOps Team', 'Dev Team', 'IT Admin', 'Security Team'];

/* Map individual tech to broader remediation groups (shared root cause) */
const GROUP_MAP = {
  'tls':   { key: 'tls-ssl', name: 'TLS/SSL Hardening', desc: 'Multiple servers have TLS/SSL weaknesses — same configuration fix applies to all affected endpoints.' },
  'openssl': { key: 'tls-ssl', name: 'TLS/SSL Hardening', desc: 'Multiple servers have TLS/SSL weaknesses — same configuration fix applies to all affected endpoints.' },
  'sqli':  { key: 'input-validation', name: 'Input Validation & Injection Prevention', desc: 'Multiple endpoints are vulnerable to injection attacks — a shared input validation fix resolves all of them.' },
  'xss':   { key: 'input-validation', name: 'Input Validation & Injection Prevention', desc: 'Multiple endpoints are vulnerable to injection attacks — a shared input validation fix resolves all of them.' },
  'mfa-vpn': { key: 'access-control', name: 'Access Control & Authentication Hardening', desc: 'Multiple systems have weak authentication — a shared access control policy fix applies to all.' },
  'default-creds-db': { key: 'access-control', name: 'Access Control & Authentication Hardening', desc: 'Multiple systems have weak authentication — a shared access control policy fix applies to all.' },
};

function $(sel) { return document.querySelector(sel); }
function toast(msg) { const t = $('#toast'); t.textContent = msg; t.hidden = false; clearTimeout(t._t); t._t = setTimeout(() => t.hidden = true, 2500); }
function cap(s) { return s ? s[0].toUpperCase() + s.slice(1).toLowerCase() : ''; }
function esc(s) { return (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;'); }
function sevClass(s) { return 'sev-' + (s||'low').toLowerCase(); }

/* ===== PDF.js Extraction ===== */
async function loadPdfJs() {
  // The script tag in index.html should have already loaded pdf.min.js (UMD build)
  if (window.pdfjsLib) {
    window.pdfjsLib.GlobalWorkerOptions.workerSrc = location.origin + location.pathname.replace(/index\.html$/, '') + 'lib/pdf.worker.min.js';
    return window.pdfjsLib;
  }
  // Fallback: dynamically load the local file
  try {
    await new Promise((resolve, reject) => {
      const s = document.createElement('script');
      s.src = 'lib/pdf.min.js';
      s.onload = resolve;
      s.onerror = () => reject(new Error('Failed to load PDF.js from lib/'));
      document.head.appendChild(s);
    });
    if (!window.pdfjsLib) { console.error('pdf.min.js loaded but window.pdfjsLib is not set'); return null; }
    window.pdfjsLib.GlobalWorkerOptions.workerSrc = location.origin + location.pathname.replace(/index\.html$/, '') + 'lib/pdf.worker.min.js';
    console.log('PDF.js loaded, worker set to:', window.pdfjsLib.GlobalWorkerOptions.workerSrc);
    return window.pdfjsLib;
  } catch(e) { console.error('PDF.js load error:', e); return null; }
}

async function extractPdf(file) {
  return new Promise((resolve, reject) => {
    let timeout = setTimeout(() => reject(new Error('PDF extraction timed out after 15s')), 15000);
    const reader = new FileReader();
    reader.onload = async (e) => {
      try {
        const lib = await loadPdfJs();
        if (!lib) { clearTimeout(timeout); return reject(new Error('PDF.js library failed to load. Check browser console.')); }
        console.log('PDF.js loaded, version:', lib.version);
        const pdf = await lib.getDocument({ data: new Uint8Array(e.target.result) }).promise;
        console.log('PDF loaded, pages:', pdf.numPages);
        let text = '';
        for (let i = 1; i <= pdf.numPages; i++) {
          const page = await pdf.getPage(i);
          const content = await page.getTextContent();
          text += content.items.map(it => it.str).join(' ') + '\n\n';
        }
        console.log('Extracted text length:', text.length);
        console.log('First 500 chars:', text.substring(0, 500));
        clearTimeout(timeout);
        resolve(text);
      } catch(err) { clearTimeout(timeout); console.error('extractPdf error:', err); reject(err); }
    };
    reader.onerror = () => { clearTimeout(timeout); reject(new Error('Failed to read file.')); };
    reader.readAsArrayBuffer(file);
  });
}

function parseFindings(text) {
  const out = [];
  // The regex looks for finding IDs like F-001: followed by content up to the next finding or end
  const re = /([A-Z]-\d{3}):\s*(.*?)(?=[A-Z]-\d{3}:|End of Report|$)/gs;
  const matches = [...text.matchAll(re)];
  console.log('parseFindings: regex matched', matches.length, 'findings');
  for (const m of matches) {
    const block = m[0];
    const title = m[2].split(/Severity:|CVSS:|Affected/i)[0].trim().substring(0, 140);
    const severity = cap((block.match(/Severity:\s*(Critical|High|Medium|Low)/i) || [])[1] || 'Medium');
    const cvss = (block.match(/CVSS:\s*([\d.]+)/i) || [])[1] || SEV_SCORE[severity.toLowerCase()];
    const asset = (block.match(/Affected\s*Asset:\s*(.+?)(?:Asset\s*Type:|Exposure:|CVE:|Severity:|CVSS:|$)/i) || [])[1]?.trim() || 'UNKNOWN';
    const cve = (block.match(/CVE:\s*(CVE-\d{4}-\d+|N\/A|None)/i) || [])[1] || 'N/A';
    const desc = (block.match(/Description:\s*(.+?)(?:Impact:|Recommendation:|$)/is) || [])[1]?.trim().substring(0, 500) || '';
    const exposure = (block.match(/Exposure:\s*(\S+)/i) || [])[1]?.toLowerCase().includes('internet') ? 'internet' : 'internal';
    const tech = detectTech(title + ' ' + desc + ' ' + asset);
    console.log(`  ${m[1]}: "${title.substring(0, 50)}..." sev=${severity} tech=${tech}`);
    out.push({ id: m[1], title, severity, cvss, asset, cve, tech, exposure, description: desc });
  }
  // Fallback: if regex didn't match, try splitting by finding IDs manually
  if (!out.length) {
    console.log('parseFindings: regex failed, trying fallback...');
    const ids = [...text.matchAll(/([A-Z]-\d{3})/g)];
    console.log('parseFindings: found', ids.length, 'ID references in text');
  }
  return out;
}

function detectTech(text) {
  const t = (text||'').toLowerCase();
  if (t.includes('nginx')||t.includes('rce')||t.includes('remote code')||t.includes('path traversal')) return 'rce';
  if (t.includes('sql')&&(t.includes('injection')||t.includes('sqli'))) return 'sqli';
  if (t.includes('tls')||t.includes('ssl')||t.includes('cipher')) return 'tls';
  if (t.includes('mfa')||t.includes('multi-factor')||t.includes('vpn')) return 'mfa-vpn';
  if (t.includes('mongodb')||(t.includes('default')&&t.includes('cred'))) return 'default-creds-db';
  if (t.includes('s3')||t.includes('bucket')) return 's3-bucket';
  if (t.includes('openssl')||t.includes('heartbleed')) return 'openssl';
  if (t.includes('xss')||t.includes('cross-site')||t.includes('scripting')) return 'xss';
  if (t.includes('github')||t.includes('permission')) return 'github-perms';
  if (t.includes('backup')||t.includes('tape')||t.includes('encrypt')) return 'backup-encryption';
  return 'generic';
}

/* ===== Playbooks (added via Edit) ===== */
const PB = {
rce: {
  tech: 'nginx Web Server',
  understand: {
    what: 'The legacy upload module on the public nginx server allows path traversal via crafted multipart form data. An attacker can upload a web shell to the webroot, achieving remote code execution.',
    risk: 'Full system compromise. Attacker can read/modify all web content, pivot to the internal network, and access the backend database containing customer PII.',
    impact: 'Complete breach of customer data. Public exploit available. Estimated breach cost: $4.45M average (IBM 2023).',
  },
  fix: [
    { desc: 'Back up the current nginx configuration', cmd: 'cp /etc/nginx/nginx.conf /etc/nginx/nginx.conf.bak.$(date +%F)', out: '[OK] Backup saved: nginx.conf.bak.2026-10-10', time: '1m' },
    { desc: 'Disable the vulnerable legacy upload module', diff: { before: '# VULNERABLE\nload_module modules/ngx_http_upload_module.so;\nhttp {\n  upload_module on;\n  upload_store /var/www/uploads;\n}', after: '# FIXED\n# load_module modules/ngx_http_upload_module.so;\nhttp {\n  client_body_temp_path /var/lib/nginx/body;\n}' }, time: '2m' },
    { desc: 'Upgrade nginx to the latest stable version', cmd: 'sudo apt-get update && sudo apt-get install nginx=1.27.*', out: 'Reading package lists... Done\nSetting up nginx (1.27.2-1)...\n[OK] nginx upgraded to 1.27.2', time: '5m' },
    { desc: 'Test configuration and reload', cmd: 'sudo nginx -t && sudo nginx -s reload', out: 'nginx: configuration test successful\n[OK] nginx reloaded — zero downtime', time: '1m' },
    { desc: 'Review access logs for indicators of compromise', cmd: 'grep -E "(\\.\\./|%2e%2e|webshell|c99)" /var/log/nginx/access.log | tail -50', out: '192.168.1.50 - - [10/Oct/2026:03:22:14] "POST /upload HTTP/1.1" 200\n[!] 1 suspicious request found — investigate', time: '5m' },
  ],
  precautions: [
    'If the server may already be compromised, do NOT patch in place — rebuild from clean image.',
    'Test the upgrade in staging first. A misconfigured reload can take the site offline.',
  ],
  verify: [
    { desc: 'Attempt the original path traversal exploit — must be blocked', cmd: 'curl -X POST -F "file=@shell.php;filename=../../var/www/html/shell.php" http://target/upload', out: 'HTTP/1.1 403 Forbidden\n{"error":"Upload blocked"}\n[OK] Path traversal blocked' },
    { desc: 'Verify nginx version is patched', cmd: 'nginx -v', out: 'nginx version: nginx/1.27.2\n[OK] Patched version' },
    { desc: 'Confirm legacy upload module is unloaded', cmd: 'nginx -M | grep upload', out: '[no output]\n[OK] Upload module not loaded' },
    { desc: 'Run vulnerability scanner — finding must be resolved', cmd: 'nessus-cli scan results --scan-id 12345 | grep "F-001"', out: 'F-001: Remote Code Execution... [RESOLVED]\n[OK] Scanner confirms fix' },
  ],
},
sqli: {
  tech: 'PHP + MySQL',
  understand: {
    what: 'The login endpoint concatenates user input directly into a SQL query without parameterization. An attacker can inject SQL to bypass authentication, dump the database, or execute OS commands.',
    risk: 'Full database compromise. Attackers can read all user data (passwords as MD5, PII), modify records, and bypass authentication.',
    impact: 'GDPR Article 33 requires 72-hour breach notification. PCI DSS 6.5.1 violation. Fines up to 4% of annual revenue.',
  },
  fix: [
    { desc: 'Back up the database before making changes', cmd: 'mysqldump -u root -p customer_portal > /tmp/cp-backup.sql', out: '[INFO] Dumping database...\n[INFO] Table users: 14,230 rows\n[OK] Backup complete', time: '5m' },
    { desc: 'Find all SQL queries using string concatenation', cmd: 'grep -rn "SELECT.*\\$_POST" /var/www/customer-portal/src/', out: 'login.php:15: $query = "SELECT * FROM users WHERE email=\'".$_POST["email"]."\'";\nlogin.php:42: $query = "SELECT * FROM users WHERE id=".$_POST["id"];', time: '2m' },
    { desc: 'Replace the vulnerable login query with a prepared statement', diff: { before: '// VULNERABLE\n$query = "SELECT * FROM users WHERE email=\'"\n  . $_POST["email"] . "\' AND password=\'"\n  . md5($_POST["password"]) . "\'";\n$result = mysqli_query($conn, $query);', after: '// FIXED\n$stmt = $conn->prepare(\n  "SELECT * FROM users WHERE email = ? AND password = ?");\n$hash = md5($_POST["password"]);\n$stmt->bind_param("ss", $_POST["email"], $hash);\n$stmt->execute();\n$result = $stmt->get_result();' }, time: '15m' },
    { desc: 'Rotate database credentials (old password may be compromised)', cmd: 'mysql -u root -p -e "ALTER USER \'portal_app\'@\'localhost\' IDENTIFIED BY \'n3wStr0ng!P@ss\';"', out: 'Query OK, 0 rows affected (0.01 sec)\n[OK] Credentials rotated', time: '2m' },
    { desc: 'Deploy WAF with SQL injection detection rules', cmd: 'sudo a2enmod security2 && sudo systemctl restart apache2', out: 'Enabling module security2.\n[OK] ModSecurity active — SQLi rules enabled', time: '5m' },
  ],
  precautions: [
    'Do NOT use addslashes() — it is bypassable. Use parameterized queries exclusively.',
    'If credentials were dumped, assume ALL passwords compromised. Plan forced password reset.',
    'Notify your DPO immediately — GDPR Article 33 may require 72-hour notification.',
  ],
  verify: [
    { desc: 'Attempt SQL injection payload — must NOT return valid data', cmd: 'curl -X POST http://target/login -d "email=\' OR 1=1 --&password=test"', out: 'HTTP/1.1 401 Unauthorized\n{"error":"Invalid credentials"}\n[OK] Injection blocked' },
    { desc: 'Run SQLMap — must report not injectable', cmd: 'sqlmap -u "http://target/login" --data="email=test&password=test" --level=5', out: '[WARNING] POST parameter \'email\' does not seem to be injectable\n[OK] All parameters NOT injectable' },
    { desc: 'Verify legitimate login still works', cmd: 'curl -X POST http://target/login -d "email=user@acme.com&password=correctpass"', out: 'HTTP/1.1 302 Found\nLocation: /dashboard\n[OK] Login works correctly' },
    { desc: 'Code review — no remaining string concatenation in SQL', cmd: 'grep -rn "SELECT.*\\.\\$_" /var/www/customer-portal/src/', out: '[no output]\n[OK] No string concatenation in SQL queries' },
  ],
},
tls: {
  tech: 'nginx / Payment Gateway',
  understand: {
    what: 'The payment gateway accepts TLS 1.0 and TLS 1.1 connections, which have known cryptographic weaknesses. The server also accepts weak cipher suites including RC4 and 3DES.',
    risk: 'PCI DSS 3.2.1 Requirement 4.1 prohibits TLS 1.0/1.1. Risk of decryption attacks on payment traffic.',
    impact: 'PCI DSS non-compliance. Loss of payment processing capability. Fines up to $100,000/month from card brands.',
  },
  fix: [
    { desc: 'Back up current SSL configuration', cmd: 'cp /etc/nginx/conf.d/payments.conf /etc/nginx/conf.d/payments.conf.bak', out: '[OK] Backup saved', time: '1m' },
    { desc: 'Update nginx to enforce TLS 1.2+ and remove weak ciphers', diff: { before: '# VULNERABLE\nssl_protocols TLSv1 TLSv1.1 TLSv1.2;\nssl_ciphers ECDHE-RSA-AES128-SHA:RC4-MD5:3DES-EDE-CBC-SHA;\nssl_prefer_server_ciphers off;', after: '# FIXED\nssl_protocols TLSv1.2 TLSv1.3;\nssl_ciphers ECDHE-ECDSA-AES256-GCM-SHA384:!RC4:!3DES:!MD5;\nssl_prefer_server_ciphers on;' }, time: '5m' },
    { desc: 'Enable HSTS with 6-month minimum age', diff: { before: '# No HSTS header', after: 'add_header Strict-Transport-Security "max-age=15768000; includeSubDomains" always;' }, time: '1m' },
    { desc: 'Test configuration and reload', cmd: 'sudo nginx -t && sudo nginx -s reload', out: 'nginx: configuration test successful\n[OK] nginx reloaded', time: '1m' },
  ],
  precautions: [
    'Verify no legacy clients require TLS 1.0. Check with the payments team first.',
    'HSTS is a one-way door — test thoroughly before enabling.',
  ],
  verify: [
    { desc: 'Verify TLS 1.0 is rejected', cmd: 'openssl s_client -connect payments.acme.local:443 -tls1 2>&1 | head -3', out: 'error:1409442E: tlsv1 alert protocol version\n[OK] TLS 1.0 rejected' },
    { desc: 'Verify only strong ciphers are offered', cmd: 'nmap --script ssl-enum-ciphers -p 443 payments.acme.local | grep -A3 TLSv1.2', out: '|   TLSv1.2:\n|     TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384 (A)\n[OK] Only strong ciphers' },
    { desc: 'Confirm HSTS header is present', cmd: 'curl -I https://payments.acme.local | grep -i strict', out: 'strict-transport-security: max-age=15768000; includeSubDomains\n[OK] HSTS active' },
  ],
},
'mfa-vpn': {
  tech: 'SSL VPN (Network)',
  understand: {
    what: 'The SSL VPN admin console permits login using only username and password. No multi-factor authentication is enforced. The VPN provides full internal network access.',
    risk: 'A compromised admin credential grants full access to the internal network, bypassing all perimeter controls.',
    impact: 'Full internal network compromise. Potential lateral movement to all internal systems.',
  },
  fix: [
    { desc: 'Enable MFA (TOTP) for all admin VPN accounts', cmd: '# OpenVPN Access Server Admin UI:\n# User Management > User Permissions\n# Set "Require Multi-Factor Authentication" = Yes', out: '[OK] MFA required for admin accounts', time: '5m' },
    { desc: 'Configure TOTP enrollment for each admin', cmd: '# Users self-enroll at:\n# https://vpn.acme.local/+otp\n# Scan QR code with Google Authenticator', out: '[OK] Admins can enroll TOTP tokens', time: '10m' },
    { desc: 'Increase minimum password length to 14 characters', diff: { before: '# Password Policy\nmin_password_length = 8\nrequire_complexity = false', after: '# Password Policy\nmin_password_length = 14\nrequire_complexity = true\nmin_uppercase = 1\nmin_special = 1' }, time: '2m' },
    { desc: 'Implement account lockout after 5 failed attempts', cmd: '# /etc/openvpn/as.conf:\n# pam_tally2 deny=5 unlock_time=900', out: '[OK] Lockout policy: 5 attempts -> 15min lockout', time: '2m' },
    { desc: 'Enable session recording for admin accounts', cmd: '# Admin console > Settings > Session Logging\n# Enable: "Record admin VPN sessions"', out: '[OK] Session recording enabled', time: '2m' },
  ],
  precautions: [
    'Ensure admins enroll TOTP BEFORE enabling the requirement, or they will be locked out.',
    'Provide a break-glass account with sealed password for emergency access.',
  ],
  verify: [
    { desc: 'Attempt VPN login with password only — must fail', cmd: '# Attempt login without TOTP token', out: 'Login failed: Multi-factor authentication required\n[OK] Password-only login rejected' },
    { desc: 'Attempt with password + valid TOTP — must succeed', cmd: '# Login with password + current TOTP code', out: 'Login successful. Welcome admin@acme\n[OK] MFA login works' },
    { desc: 'Verify account lockout works', cmd: '# Attempt 5 failed logins', out: 'Account locked after 5 failed attempts.\nUnlock time: 15 minutes\n[OK] Lockout active' },
    { desc: 'Confirm all admin accounts show MFA enabled', cmd: '# Admin console > User Management\n# Verify all admin accounts have MFA = Yes', out: '[Manual verification]\n[OK] All 6 admin accounts have MFA enabled' },
  ],
},
'default-creds-db': {
  tech: 'MongoDB (Database)',
  understand: {
    what: 'The MongoDB instance is accessible on port 27017 without authentication. Default admin/admin credentials are active. The database contains a mirror of production data.',
    risk: 'Any user on the internal network can access full production-equivalent data. Trivial data exfiltration point.',
    impact: 'Complete PII exposure. GDPR violation — unencrypted customer data accessible without authentication.',
  },
  fix: [
    { desc: 'Create an admin user BEFORE enabling auth', cmd: 'mongo\nuse admin\ndb.createUser({ user: "secadmin", pwd: "Str0ngP@ss!", roles: ["root"] })', out: 'Successfully added user: { user: "secadmin", roles: ["root"] }\n[OK] Admin user created', time: '2m' },
    { desc: 'Enable authentication in mongod.conf', diff: { before: '# VULNERABLE — no security section\n# Authentication disabled', after: '# FIXED\nsecurity:\n  authorization: enabled' }, time: '1m' },
    { desc: 'Bind MongoDB to localhost only', diff: { before: '# net\n  bindIp: 0.0.0.0', after: '# net\n  bindIp: 127.0.0.1' }, time: '1m' },
    { desc: 'Restart MongoDB to apply changes', cmd: 'sudo systemctl restart mongod', out: '[OK] MongoDB restarted with auth enabled', time: '1m' },
    { desc: 'Scrub all PII from development database', cmd: 'mongo -u secadmin -p \'Str0ngP@ss!\' --authenticationDatabase admin dev_mirror\ndb.users.updateMany({}, { $set: { email: "test@test.acme", phone: "000-000-0000" } })', out: '{ "matched": 14230, "modified": 14230 }\n[OK] 14,230 records scrubbed', time: '5m' },
  ],
  precautions: [
    'Creating the admin user BEFORE enabling auth is critical. Enable auth first = permanent lockout.',
    'Binding to localhost may break remote apps. Update connection strings first.',
  ],
  verify: [
    { desc: 'Connect without credentials — must fail', cmd: 'mongo --eval "db.adminCommand({listDatabases:1})"', out: 'command line interface requires authentication\n[OK] Unauthenticated access blocked' },
    { desc: 'Connect with old admin/admin — must fail', cmd: 'mongo -u admin -p admin --authenticationDatabase admin', out: 'Error: Authentication Failed.\n[OK] Default credentials no longer work' },
    { desc: 'Connect from remote host — must be refused', cmd: 'mongo --host dev-db-03.db.acme.local --eval "db.runCommand({ping:1})"', out: 'connect ECONNREFUSED 10.0.1.30:27017\n[OK] Remote access blocked' },
    { desc: 'Verify dev DB contains no real PII', cmd: 'mongo -u secadmin -p \'Str0ngP@ss!\' --authenticationDatabase admin dev_mirror --eval "db.users.count({ email: { $not: /test@test.acme/ } })"', out: '0\n[OK] No real email addresses found' },
  ],
},
's3-bucket': {
  tech: 'AWS S3 (Cloud Storage)',
  understand: {
    what: 'The S3 bucket "acme-logs" has a policy granting read access to all principals (*). The bucket contains logs with customer email addresses, IP addresses, and session tokens.',
    risk: 'Anyone on the internet can download all logs containing PII. Session tokens could enable session hijacking.',
    impact: 'GDPR breach notification may be required. Session tokens could lead to account takeover.',
  },
  fix: [
    { desc: 'Remove the public read policy immediately', cmd: 'aws s3api delete-bucket-policy --bucket acme-logs', out: '[OK] Public bucket policy removed', time: '1m' },
    { desc: 'Apply restrictive bucket policy (log-writer role only)', cmd: 'aws s3api put-bucket-policy --bucket acme-logs --policy file:///tmp/policy.json', out: '[OK] Restrictive policy applied', time: '2m' },
    { desc: 'Enable S3 Block Public Access at account level', cmd: 'aws s3control put-public-access-block --account-id 123 --public-access-block-configuration BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true', out: '[OK] Block Public Access enabled at account level', time: '1m' },
    { desc: 'Enable server-side encryption (SSE-KMS)', cmd: 'aws s3api put-bucket-encryption --bucket acme-logs --server-side-encryption-configuration \'{"Rules":[{"ApplyServerSideEncryptionByDefault":{"SSEAlgorithm":"aws:kms"}}]}\'', out: '[OK] SSE-KMS encryption enabled', time: '1m' },
    { desc: 'Review all other S3 buckets for misconfigurations', cmd: 'aws s3api list-buckets --query "Buckets[].Name" --output text | tr "\\t" "\\n" | while read b; do echo "--- $b ---"; aws s3api get-bucket-policy-status --bucket "$b" 2>/dev/null; done', out: '--- acme-assets ---\n  isPublic: false\n--- acme-uploads ---\n  isPublic: false\n[OK] No other public buckets', time: '5m' },
  ],
  precautions: [
    'Removing bucket policy is immediate — ensure no app depends on public read.',
    'SSE-KMS requires KMS key management. Use a Customer Managed Key.',
  ],
  verify: [
    { desc: 'Anonymous access must return 403', cmd: 'curl -I https://acme-logs.s3.amazonaws.com/test.txt', out: 'HTTP/2 403 Forbidden\n[OK] Anonymous access blocked' },
    { desc: 'Verify bucket policy only allows log-writer role', cmd: 'aws s3api get-bucket-policy --bucket acme-logs --query Policy --output json', out: '{"Statement":[{"Principal":{"AWS":"arn:aws:iam::123:role/log-writer"}}]}\n[OK] Only log-writer role' },
    { desc: 'Confirm Block Public Access is enabled', cmd: 'aws s3control get-public-access-block --account-id 123', out: '{ "BlockPublicAcls": true, "BlockPublicPolicy": true }\n[OK] All blocks enabled' },
    { desc: 'Verify SSE-KMS encryption is active', cmd: 'aws s3api get-bucket-encryption --bucket acme-logs', out: '{ "Rules": [{ "ApplyServerSideEncryptionByDefault": { "SSEAlgorithm": "aws:kms" } }] }\n[OK] SSE-KMS active' },
  ],
},
openssl: {
  tech: 'Mail Server (Docker)',
  understand: {
    what: 'The mail server runs a pinned Docker image with OpenSSL 1.0.1f, vulnerable to CVE-2014-0160 (Heartbleed). This allows reading up to 64KB of server memory per request.',
    risk: 'Exposure of TLS private keys would allow decryption of all mail traffic. Session tokens could enable account takeover.',
    impact: 'Email traffic decryption. Potential access to all mail communications.',
  },
  fix: [
    { desc: 'Update the Dockerfile to use patched OpenSSL', diff: { before: '# VULNERABLE\nFROM debian:jessie-slim\nRUN apt-get install -y openssl=1.0.1f', after: '# FIXED\nFROM debian:bookworm-slim\nRUN apt-get update && apt-get install -y openssl' }, time: '5m' },
    { desc: 'Rebuild the Docker image', cmd: 'docker build -t mail-server:fixed .', out: 'Step 1/8 : FROM debian:bookworm-slim\nStep 8/8 : CMD ["postfix","start-fg"]\n[OK] Image built', time: '5m' },
    { desc: 'Deploy with zero downtime', cmd: 'docker-compose up -d --no-deps --build mail', out: 'Recreating mail ... done\n[OK] Mail server deployed', time: '2m' },
    { desc: 'Rotate the TLS certificate and private key', cmd: 'openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/mail.key -out /etc/ssl/mail.crt -days 365 -nodes', out: 'Generating a RSA private key (4096 bit)\n[OK] New cert and key generated', time: '3m' },
    { desc: 'Invalidate all mail user session tokens', cmd: '# Mail admin console: Sessions > Invalidate All', out: '[OK] All sessions invalidated', time: '1m' },
    { desc: 'Add Trivy vulnerability scan to CI/CD', cmd: 'trivy image mail-server:fixed --severity CRITICAL,HIGH --exit-code 1', out: 'mail-server:fixed (debian 12.4)\nTotal: 0 vulnerabilities\n[OK] No critical/high vulns', time: '5m' },
  ],
  precautions: [
    'Heartbleed may have exposed private keys. Assume compromise — rotate ALL keys.',
    'Rebuilding the image may change behavior if dependencies changed. Test thoroughly.',
  ],
  verify: [
    { desc: 'Verify OpenSSL version in container', cmd: 'docker exec mail openssl version', out: 'OpenSSL 3.0.13 30 Jan 2024\n[OK] Patched version' },
    { desc: 'Run Heartbleed checker', cmd: 'python3 heartbleed-checker.py mail01.mail.acme.local 443', out: 'Checking mail01.mail.acme.local:443...\n[OK] Not vulnerable to Heartbleed' },
    { desc: 'Confirm new TLS certificate is in use', cmd: 'openssl s_client -connect mail01:443 | grep subject', out: 'subject= /CN=mail01.mail.acme.local\n[OK] New certificate active' },
  ],
},
xss: {
  tech: 'WordPress (Marketing Site)',
  understand: {
    what: 'The blog comment field does not sanitize user input before storing and rendering it. A stored XSS payload executes when any user views the comment.',
    risk: 'Attacker can steal session cookies, deface the site, or redirect users to phishing pages.',
    impact: 'Session hijacking of visitors. Reputational damage if exploited publicly.',
  },
  fix: [
    { desc: 'Sanitize all user input using an HTML allowlist library', diff: { before: '// VULNERABLE\n$comment = $_POST["comment"];\necho "<div>" . $comment . "</div>";', after: '// FIXED\n$comment = $_POST["comment"];\n$config = HTMLPurifier_Config::createDefault();\n$purifier = new HTMLPurifier($config);\n$safe = $purifier->purify($comment);\necho "<div>" . $safe . "</div>";' }, time: '15m' },
    { desc: 'Set Content-Security-Policy headers', diff: { before: '# No CSP header', after: 'add_header Content-Security-Policy "script-src \'self\'; object-src \'none\'" always;' }, time: '2m' },
    { desc: 'Set HttpOnly and Secure flags on cookies', diff: { before: 'session.cookie_httponly = 0\nsession.cookie_secure = 0', after: 'session.cookie_httponly = 1\nsession.cookie_secure = 1\nsession.cookie_samesite = Strict' }, time: '1m' },
    { desc: 'Clean existing stored XSS payloads from database', cmd: 'mysql -u root -p marketing_db -e "DELETE FROM comments WHERE body LIKE \'%<script%\' OR body LIKE \'%onerror%\'"', out: 'Query OK, 3 rows affected\n[OK] 3 XSS payloads removed', time: '2m' },
  ],
  precautions: [
    'Do NOT rely on blacklisting — use an allowlist approach (HTML Purifier, DOMPurify).',
    'CSP is defense-in-depth, not a replacement for input sanitization.',
  ],
  verify: [
    { desc: 'Attempt to inject XSS payload — must be sanitized', cmd: 'curl -X POST http://out.marketing.acme.local/comment -d "comment=<script>alert(1)</script>"', out: 'HTTP/1.1 200 OK\n[OK] Script tag stripped' },
    { desc: 'Verify CSP header is present', cmd: 'curl -I http://out.marketing.acme.local | grep -i content-security', out: 'content-security-policy: script-src \'self\'; object-src \'none\'\n[OK] CSP active' },
    { desc: 'Check cookie flags', cmd: 'curl -I http://out.marketing.acme.local | grep -i set-cookie', out: 'set-cookie: session=abc123; HttpOnly; Secure; SameSite=Strict\n[OK] All flags set' },
  ],
},
'github-perms': {
  tech: 'GitHub Organization',
  understand: {
    what: 'The GitHub organization "acme" has 12 members with admin role, including 4 contractors and 2 former employees whose accounts are still active. No audit log export is enabled.',
    risk: 'A compromised or malicious admin account could delete all source code, inject backdoors, or exfiltrate proprietary code.',
    impact: 'Loss of source code. Potential backdoor injection. No audit trail for forensic analysis.',
  },
  fix: [
    { desc: 'Remove access for former employees immediately', cmd: 'gh api -X DELETE "orgs/acme/memberships/FORMER_EMPLOYEE_1"\ngh api -X DELETE "orgs/acme/memberships/FORMER_EMPLOYEE_2"', out: '[OK] 2 former employees removed from organization', time: '2m' },
    { desc: 'Review and reduce admin roles to least privilege', cmd: 'gh api "orgs/acme/members" --jq ".[].login" | while read u; do\n  role=$(gh api "orgs/acme/memberships/$u" --jq ".role")\n  echo "$u: $role"\ndone', out: 'alice: admin\nbob: admin\ncharlie: member\n[!] 4 admins — review each', time: '5m' },
    { desc: 'Convert unnecessary admins to member role', cmd: 'gh api -X PUT "orgs/acme/memberships/alice" -f role=member', out: '[OK] alice demoted from admin to member', time: '1m' },
    { desc: 'Require MFA for all organization members', cmd: '# Organization settings > Authentication security\n# Require two-factor authentication: Enabled', out: '[OK] 2FA required for all org members', time: '2m' },
    { desc: 'Enable audit log export to SIEM', cmd: '# GitHub Enterprise > Settings > Audit log\n# Enable: Export to SIEM webhook', out: '[OK] Audit log export enabled', time: '5m' },
  ],
  precautions: [
    'Before removing admins, ensure they have no active workflows that will break.',
    '2FA enforcement will lock out users without it — send 7-day notice before enabling.',
  ],
  verify: [
    { desc: 'Verify former employees are removed', cmd: 'gh api "orgs/acme/members" --jq ".[].login" | grep -i "FORMER"', out: '[no output]\n[OK] No former employees in org' },
    { desc: 'Verify admin count is reduced', cmd: 'gh api "orgs/acme/members" --paginate --jq ".[] | select(.site_admin) | .login" | wc -l', out: '2\n[OK] Only 2 admins remaining' },
    { desc: 'Confirm 2FA is required', cmd: '# Org settings > Authentication security\n# Verify: "Require 2FA" is ON', out: '[Manual verification]\n[OK] 2FA enforcement is ON' },
  ],
},
'backup-encryption': {
  tech: 'Backup System (LTO Tape)',
  understand: {
    what: 'LTO-8 backup tapes containing full database backups are shipped to an offsite vendor in unencrypted form. The tapes contain customer PII, financial records, and proprietary code.',
    risk: 'Loss or theft of a single tape constitutes a full data breach. No chain-of-custody tracking.',
    impact: 'Full data breach if a tape is lost. Regulatory fines. Loss of customer trust.',
  },
  fix: [
    { desc: 'Enable LTO hardware encryption with managed keys', cmd: '# Backup software config:\n# Encryption: LTO Hardware Encryption\n# Key Manager: KMS / Vault\n# Algorithm: AES-256-GCM', out: '[OK] LTO hardware encryption enabled\n[OK] Keys managed via KMS', time: '10m' },
    { desc: 'Alternatively, migrate to cloud backup with KMS encryption', diff: { before: '# VULNERABLE\nbackend: tape\ntape_device: /dev/nst0\nencryption: none', after: '# FIXED\nbackend: s3\ns3_bucket: acme-backups\nencryption: aws:kms\nkms_key_id: alias/backup-key' }, time: '15m' },
    { desc: 'Require chain-of-custody documentation from shipping vendor', cmd: '# Update vendor contract:\n# - Signed chain-of-custody form per shipment\n# - Barcoded tape tracking with GPS\n# - Notification within 1hr if tape lost', out: '[OK] Vendor contract updated', time: '10m' },
    { desc: 'Implement tape inventory and tracking system', cmd: '# Deploy tape inventory tracker:\n# - Barcode each tape\n# - Track: creation, contents, location, destruction\n# - Auto-alert for overdue rotation', out: '[OK] Tape inventory deployed\n[OK] 47 tapes catalogued', time: '30m' },
  ],
  precautions: [
    'LTO hardware encryption requires compatible tape drives — verify hardware support.',
    'KMS key loss = permanent data loss. Implement key backup and rotation procedures.',
  ],
  verify: [
    { desc: 'Verify new backup tapes are encrypted', cmd: 'grep "encryption" /var/log/backup/latest.log', out: 'Encryption: AES-256-GCM (LTO hardware)\nKey ID: alias/backup-key\n[OK] Encryption active' },
    { desc: 'Verify chain-of-custody forms are being collected', cmd: 'ls /var/backup/custody-forms/ | wc -l', out: '12\n[OK] 12 custody forms on file' },
    { desc: 'Attempt to read a tape without the key — must fail', cmd: '# Attempt restore without KMS key\nmt -f /dev/nst0 rewind\ndd if=/dev/nst0 of=test.bin', out: 'dd: error reading \'/dev/nst0\': Input/output error\n[OK] Tape data is encrypted' },
  ],
},
generic: {
  tech: 'Unknown / General',
  understand: {
    what: 'This vulnerability was identified in your penetration test report. Review the finding description for details on the specific issue.',
    risk: 'Review the impact assessment in the report. The severity rating indicates the potential damage if exploited.',
    impact: 'Refer to the finding details for business impact information.',
  },
  fix: [
    { desc: 'Review the full finding description and recommendation in the pentest report', cmd: '# Open the PDF report\n# Navigate to the finding section\n# Read Description, Impact, and Recommendation', out: '[Manual review required]', time: '5m' },
    { desc: 'Follow the remediation steps recommended in the report', cmd: '# Implement the numbered recommendations\n# from the report\'s Recommendation section', out: '[Implementation in progress]', time: 'varies' },
    { desc: 'Consult vendor documentation for technology-specific guidance', cmd: '# Check vendor security advisories\n# Review CVE database: https://nvd.nist.gov/', out: '[Research complete]', time: '15m' },
  ],
  precautions: [
    'Always test fixes in a staging environment before production deployment.',
    'Back up affected systems before making changes.',
  ],
  verify: [
    { desc: 'Re-run the original test that identified the vulnerability', cmd: '# Use the same tool/method from the pentest\n# to verify the finding is resolved', out: '[Manual verification required]' },
    { desc: 'Confirm the finding no longer appears in vulnerability scans', cmd: '# Run vulnerability scanner\n# Verify finding is marked as resolved', out: '[Scanner verification required]' },
  ],
},
};

/* ===== Group Detection (One Fix, Multiple Vulnerabilities) ===== */
function detectGroups() {
  const groups = {};
  S.findings.forEach(f => {
    const g = GROUP_MAP[f.tech];
    if (!g) return;
    if (!groups[g.key]) groups[g.key] = { ...g, findingIds: [], tech: f.tech };
    groups[g.key].findingIds.push(f.id);
  });
  // Only suggest groups with 2+ findings
  S.suggestedGroups = Object.values(groups).filter(g => g.findingIds.length >= 2);
  S.confirmedGroups = {};
}

function findGroupForFinding(fid) {
  for (const [gkey, confirmed] of Object.entries(S.confirmedGroups)) {
    if (!confirmed) continue;
    const g = S.suggestedGroups.find(x => x.key === gkey);
    if (g && g.findingIds.includes(fid)) return g;
  }
  return null;
}

/* ===== Screen Management ===== */
function showScreen(id) {
  ['s-upload','s-findings','s-fix'].forEach(s => { $('#'+s).hidden = s !== id; });
  $('#newReportBtn').hidden = id === 's-upload';
  window.scrollTo(0, 0);
}

function session(fid) {
  if (!S.sessions[fid]) {
    const f = S.findings.find(x => x.id === fid);
    const sev = f ? f.severity.toLowerCase() : 'medium';
    const tech = f ? f.tech : 'generic';
    const sla = SLA_DAYS[sev] || 14;
    const due = new Date(Date.now() + sla * 86400000).toISOString().split('T')[0];
    S.sessions[fid] = { phase: 0, fixDone: new Set(), verifyDone: new Set(), evidence: '', evidenceImage: '', owner: DEFAULT_OWNERS[tech] || 'Security Team', dueDate: due, notified: false };
  }
  return S.sessions[fid];
}

function getStatus(fid) {
  // Handle group session IDs directly
  if (typeof fid === 'string' && fid.startsWith('group:')) {
    const key = fid.replace('group:', '');
    const g = S.suggestedGroups.find(x => x.key === key);
    if (!g) return 'pending';
    const gf = S.findings.find(f => f.id === g.findingIds[0]);
    if (!gf) return 'pending';
    const pb = PB[gf.tech] || PB.generic;
    const s = S.sessions[fid];
    if (!s) return 'pending';
    if (s.verifyDone.size >= pb.verify.length && s.evidence.trim() && s.evidenceImage) return 'verified';
    if (s.fixDone.size > 0 || s.verifyDone.size > 0) return 'progress';
    return 'pending';
  }
  const f = S.findings.find(x => x.id === fid);
  if (!f) return 'pending';
  const pb = PB[f.tech] || PB.generic;
  // Check if this finding is in a confirmed group
  const grp = findGroupForFinding(fid);
  if (grp) {
    const gs = S.sessions['group:' + grp.key];
    if (!gs) return 'pending';
    if (gs.verifyDone.size >= pb.verify.length && gs.evidence.trim() && gs.evidenceImage) return 'verified';
    if (gs.fixDone.size > 0 || gs.verifyDone.size > 0) return 'progress';
    return 'pending';
  }
  const s = S.sessions[fid];
  if (!s) return 'pending';
  if (s.verifyDone.size >= pb.verify.length && s.evidence.trim() && s.evidenceImage) return 'verified';
  if (s.fixDone.size > 0 || s.verifyDone.size > 0) return 'progress';
  return 'pending';
}

/* ===== Group Rendering ===== */
function renderGroups() {
  const container = $('#groupsSection');
  if (!S.suggestedGroups.length) { container.innerHTML = ''; return; }
  let html = '';
  S.suggestedGroups.forEach(g => {
    const confirmed = S.confirmedGroups[g.key];
    const findings = g.findingIds.map(id => S.findings.find(f => f.id === id)).filter(Boolean);
    if (confirmed) {
      const st = getStatus('group:' + g.key);
      const stLabel = { pending:'Not started', progress:'In progress', verified:'Verified' }[st];
      const pb = PB[g.tech] || PB.generic;
      const totalSteps = pb.fix.length + pb.verify.length;
      const gs = S.sessions['group:' + g.key];
      const done = gs ? (gs.fixDone.size + gs.verifyDone.size) : 0;
      const pct = totalSteps ? Math.round(done/totalSteps*100) : 0;
      html += `<div class="group-card confirmed">
        <div class="group-header">
          <span class="group-icon">\uD83D\uDCE6</span>
          <div class="group-title-wrap">
            <h3 class="group-title">${esc(g.name)}</h3>
            <p class="group-desc">${g.findingIds.length} findings grouped into one fix \u2014 ${esc(g.desc)}</p>
          </div>
          <span class="status-badge status-${st}">${stLabel}</span>
        </div>
        <div class="group-endpoints">
          ${findings.map(f => `<span class="endpoint-chip">\uD83D\uDCCD ${esc(f.asset)}</span>`).join('')}
        </div>
        <div class="group-progress">
          <div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div>
          <button class="btn btn-primary btn-sm" data-act="open-group" data-key="${g.key}">${st==='verified'?'Review':'Fix group'} \u2192</button>
        </div>
      </div>`;
    } else {
      html += `<div class="group-card">
        <div class="group-header">
          <span class="group-icon">\uD83E\uDDEE</span>
          <div class="group-title-wrap">
            <h3 class="group-title">AI Suggestion: ${esc(g.name)}</h3>
            <p class="group-desc">${g.findingIds.length} findings share the same root cause \u2014 fix them together instead of separately.</p>
          </div>
        </div>
        <div class="group-endpoints">
          ${findings.map(f => `<div class="endpoint-row"><span class="endpoint-chip">${esc(f.id)}</span><span class="endpoint-asset">${esc(f.asset)}</span></div>`).join('')}
        </div>
        <div class="group-actions">
          <button class="btn btn-primary btn-sm" data-act="confirm-group" data-key="${g.key}">Group &amp; Fix together</button>
          <button class="btn btn-sm" data-act="dismiss-group" data-key="${g.key}">Keep separate</button>
        </div>
      </div>`;
    }
  });
  container.innerHTML = html;
}

function confirmGroup(key) {
  S.confirmedGroups[key] = true;
  renderFindings();
  openGroupFix(key);
}

function dismissGroup(key) {
  S.suggestedGroups = S.suggestedGroups.filter(g => g.key !== key);
  renderFindings();
  toast('Findings kept separate');
}

function openGroupFix(key) {
  const g = S.suggestedGroups.find(x => x.key === key);
  if (!g) return;
  S.activeId = 'group:' + key;
  session('group:' + key);
  showScreen('s-fix');
  renderFix();
}

/* ===== Findings Rendering ===== */
function renderFindings() {
  const counts = { Critical:0, High:0, Medium:0, Low:0 };
  let verified = 0, progress = 0;
  S.findings.forEach(f => {
    counts[f.severity] = (counts[f.severity]||0) + 1;
    const st = getStatus(f.id);
    if (st === 'verified') verified++;
    if (st === 'progress') progress++;
  });
  $('#findingsCount').textContent = S.findings.length;
  $('#findingsSource').textContent = 'from ' + S.source;
  $('#findingsSummary').innerHTML = Object.entries(counts).filter(([,v]) => v > 0)
    .map(([k,v]) => `<span class="fs-chip"><b>${v}</b> ${k}</span>`).join('')
    + `<span class="fs-chip"><b>${verified}</b> Verified</span>`
    + (progress ? `<span class="fs-chip"><b>${progress}</b> In progress</span>` : '');

  renderGroups();

  $('#findingsGrid').innerHTML = S.findings.map(f => {
    const st = getStatus(f.id);
    const stLabel = { pending:'Not started', progress:'In progress', verified:'Verified' }[st];
    const pb = PB[f.tech] || PB.generic;
    const totalSteps = pb.fix.length + pb.verify.length;
    const s = session(f.id);
    const done = s.fixDone.size + s.verifyDone.size;
    const pct = totalSteps ? Math.round(done/totalSteps*100) : 0;
    const grp = findGroupForFinding(f.id);
    const covered = grp ? `<div class="fc-covered"><span class="covered-badge">\uD83D\uDCE6 Covered by group fix: ${esc(grp.name)}</span><button class="btn btn-sm" data-act="open-group" data-key="${grp.key}">Open group fix \u2192</button></div>` : '';
    return `<div class="finding-card${grp?' grouped':''}" data-id="${f.id}">
      <div class="fc-top"><span class="sev-badge ${sevClass(f.severity)}">${f.severity}</span>
        <span class="status-badge status-${st}">${stLabel}</span></div>
      <h3 class="fc-title">${esc(f.title)}</h3>
      <div class="fc-meta"><span>\uD83D\uDCCD ${esc(f.asset)}</span><span>\uD83D\uDD27 ${esc(pb.tech)}</span>${f.cve&&f.cve!=='N/A'?`<span>\uD83C\uDFAF ${esc(f.cve)}</span>`:''}</div>
      ${covered}
      <div class="fc-bottom"><div class="fc-progress"><div class="progress-bar"><div class="progress-fill" style="width:${pct}%"></div></div></div>
        <button class="btn btn-primary btn-sm">${st==='verified'?'Review':st==='progress'?'Continue':'Start fixing'} \u2192</button></div>
    </div>`;
  }).join('');
  $('#findingsGrid').querySelectorAll('.finding-card').forEach(c => {
    c.addEventListener('click', e => {
      if (e.target.closest('[data-act]')) return;
      openFix(c.dataset.id);
    });
  });
}

/* ===== Fix Session ===== */
function activeFinding() {
  if (S.activeId && S.activeId.startsWith('group:')) {
    const key = S.activeId.replace('group:', '');
    const g = S.suggestedGroups.find(x => x.key === key);
    if (!g || !g.findingIds.length) return null;
    return S.findings.find(f => f.id === g.findingIds[0]);
  }
  return S.findings.find(f => f.id === S.activeId);
}

function isGroupSession() { return S.activeId && S.activeId.startsWith('group:'); }

function activeGroup() {
  if (!isGroupSession()) return null;
  const key = S.activeId.replace('group:', '');
  return S.suggestedGroups.find(x => x.key === key);
}

function openFix(id) { S.activeId = id; session(id); showScreen('s-fix'); renderFix(); }

function renderFix() {
  const f = activeFinding(); if (!f) return;
  const pb = PB[f.tech] || PB.generic;
  const s = session(S.activeId);
  const grp = activeGroup();
  $('#fixSev').className = 'sev-badge ' + sevClass(f.severity);
  $('#fixSev').textContent = grp ? 'GROUP' : f.severity;
  $('#fixTitle').textContent = grp ? grp.name : f.title;
  let html = '';
  if (s.phase === 0) html = htmlUnderstand(f, pb, grp);
  else if (s.phase === 1) html = htmlFix(pb, s);
  else if (s.phase === 2) html = htmlVerify(pb, s);
  else html = htmlComplete(pb, s);
  $('#fixContent').innerHTML = html;
  renderStepper(s.phase);
  updateProgress(f, pb, s);
  updateNav(s.phase, pb, s);
}

function renderStepper(phase) {
  let html = '';
  PHASES.forEach((label, i) => {
    const cls = i===phase?'active':i<phase?'done':'';
    html += `<div class="step ${cls}" data-phase="${i}"><div class="step-circle">${i<phase?'\u2713':i+1}</div><span class="step-label">${label}</span></div>`;
    if (i < PHASES.length-1) html += `<div class="step-line ${i<phase?'done':''}"></div>`;
  });
  $('#stepper').innerHTML = html;
}

function updateProgress(f, pb, s) {
  const total = pb.fix.length + pb.verify.length + 2;
  const done = s.fixDone.size + s.verifyDone.size + (s.evidence.trim()?1:0) + (s.evidenceImage?1:0);
  const pct = Math.round(done/total*100);
  $('#fixProgress').style.width = pct + '%';
  $('#fixProgressText').textContent = pct + '%';
  const st = getStatus(S.activeId);
  const badge = $('#fixStatus');
  badge.className = 'status-badge status-' + st;
  badge.textContent = {pending:'Not started',progress:'In progress',verified:'Verified'}[st];
}

function updateNav(phase, pb, s) {
  $('#fixPrev').disabled = phase === 0;
  const next = $('#fixNext');
  if (phase === 3) { next.textContent = 'Back to findings \u2192'; next.disabled = false; }
  else {
    const checksOk = s.verifyDone.size >= pb.verify.length;
    const evOk = s.evidence.trim() && s.evidenceImage;
    const blocked = phase===2 && (!checksOk || !evOk);
    next.textContent = blocked ? 'Complete checks & evidence first' : 'Next \u2192';
    next.disabled = blocked;
  }
}

function navigatePhase(delta) {
  const s = session(S.activeId);
  const np = s.phase + delta;
  if (np < 0 || np > 3) return;
  if (np === 3) {
    const f = activeFinding(); const pb = PB[f.tech] || PB.generic;
    if (s.verifyDone.size < pb.verify.length || !s.evidence.trim() || !s.evidenceImage) { toast('Complete all checks, write evidence, and upload screenshot'); return; }
  }
  s.phase = np; renderFix();
}

/* ===== Phase Renderers ===== */
function htmlUnderstand(f, pb, grp) {
  const groupHtml = grp ? `<div class="group-banner">
    <div class="group-banner-title">\uD83D\uDCE6 One Fix, Multiple Vulnerabilities</div>
    <p>This fix covers ${grp.findingIds.length} findings that share the same root cause. Completing this fix will resolve all of them.</p>
    <div class="group-endpoints-list">
      ${grp.findingIds.map(id => {
        const gf = S.findings.find(x => x.id === id);
        return gf ? `<div class="ep-item"><span class="ep-id">${esc(gf.id)}</span><span class="ep-asset">${esc(gf.asset)}</span><span class="ep-sev sev-badge ${sevClass(gf.severity)}">${gf.severity}</span></div>` : '';
      }).join('')}
    </div>
  </div>` : '';
  return `${groupHtml}
    <h2 class="phase-title">Understand the vulnerability</h2>
    <p class="phase-desc">What this finding means, why it matters, and what's at risk.</p>
    <div class="meta-grid">
      <div class="meta-item"><div class="meta-label">Technology</div><div class="meta-value">${esc(pb.tech)}</div></div>
      <div class="meta-item"><div class="meta-label">CVSS</div><div class="meta-value">${esc(f.cvss)}</div></div>
      <div class="meta-item"><div class="meta-label">CVE</div><div class="meta-value">${esc(f.cve)}</div></div>
      <div class="meta-item"><div class="meta-label">Exposure</div><div class="meta-value">${esc(cap(f.exposure))}</div></div>
    </div>
    <div class="understand-card"><h3 class="label-what">What is it?</h3><p>${esc(pb.understand.what)}</p></div>
    <div class="understand-card"><h3 class="label-risk">Risk</h3><p>${esc(pb.understand.risk)}</p></div>
    <div class="understand-card"><h3 class="label-impact">Business Impact</h3><p>${esc(pb.understand.impact)}</p></div>`;
}

function htmlFix(pb, s) {
  let steps = '';
  pb.fix.forEach((step, i) => {
    const done = s.fixDone.has(i);
    steps += `<div class="fix-step${done?' done':''}" data-idx="${i}"><div class="fix-step-header">
      <div class="fix-step-num">${done?'\u2713':i+1}</div><div class="fix-step-body">
      <div class="fix-step-desc">${esc(step.desc)}</div>
      ${step.time?`<div class="fix-step-time">\u23F1 ${step.time}</div>`:''}
      ${step.cmd?termBox(step.cmd, i, 'fix'):''}${step.diff?diffPanel(step.diff):''}
      </div><div class="fix-step-check" data-act="step" data-idx="${i}">\u2713</div></div></div>`;
  });
  let prec = (pb.precautions||[]).map(p => `<div class="precaution"><div class="precaution-title">\u26A0 Precaution</div><div class="precaution-text">${esc(p)}</div></div>`).join('');
  return `<h2 class="phase-title">Fix it \u2014 step by step</h2><p class="phase-desc">Follow each step in order. Click "Run" to see expected output.</p>${steps}${prec}`;
}

function htmlVerify(pb, s) {
  let checks = '';
  pb.verify.forEach((c, i) => {
    const done = s.verifyDone.has(i);
    checks += `<div class="check-item${done?' done':''}" data-idx="${i}"><div class="check-header" data-act="check" data-idx="${i}">
      <div class="check-box">\u2713</div><div class="check-desc">${esc(c.desc)}</div></div>
      ${c.cmd?`<div style="padding:0 16px 14px">${termBox(c.cmd, i, 'verify')}</div>`:''}</div>`;
  });
  const imgPreview = s.evidenceImage
    ? `<div class="ev-img-preview"><img src="${s.evidenceImage}" alt="Evidence screenshot"><button class="ev-img-remove" data-act="remove-img">\u2715 Remove</button></div>`
    : `<div class="ev-upload-zone" data-act="upload-zone"><div class="ev-upload-icon">\uD83D\uDCF7</div><div class="ev-upload-text">Click to upload screenshot</div><div class="ev-upload-sub">or drag &amp; drop PNG/JPG</div><input type="file" accept="image/*" data-act="evidence-img" hidden></div>`;
  return `<h2 class="phase-title">Verify the fix</h2><p class="phase-desc">Not "fixed" until every check passes and evidence is uploaded.</p>${checks}
    <div class="evidence-area">
      <label>Evidence notes <span class="ev-required">*required</span></label>
      <textarea data-act="evidence" placeholder="Record what you did, paste output, note scan results...">${esc(s.evidence)}</textarea>
      <div class="evidence-hint">Describe the fix applied and verification results.</div>
    </div>
    <div class="evidence-area">
      <label>Fix screenshot <span class="ev-required">*required</span></label>
      <p class="evidence-hint">Upload a screenshot proving the fix is applied (scanner output, terminal, etc.)</p>
      ${imgPreview}
      <button class="btn btn-sm btn-sample" data-act="sample-img">Use sample screenshot</button>
    </div>`;
}

function htmlComplete(pb, s) {
  const af = s.fixDone.size >= pb.fix.length, av = s.verifyDone.size >= pb.verify.length;
  const ae = !!s.evidence.trim(), ai = !!s.evidenceImage;
  const v = af && av && ae && ai;
  return `<div class="complete-card"><div class="complete-icon">${v?'\u2705':'\u23F3'}</div>
    <h2>${v?'Finding Verified':'Not Yet Complete'}</h2>
    <p class="muted">${v?'All checks passed and evidence uploaded.':'Complete all steps, checks, and upload evidence to verify.'}</p>
    <ul class="complete-list">
      <li class="${af?'':'pending'}">Fix steps completed (${s.fixDone.size}/${pb.fix.length})</li>
      <li class="${av?'':'pending'}">Verification checks passed (${s.verifyDone.size}/${pb.verify.length})</li>
      <li class="${ae?'':'pending'}">Evidence notes written</li>
      <li class="${ai?'':'pending'}">Fix screenshot uploaded</li>
    </ul></div>`;
}

/* ===== Components ===== */
function termBox(cmd, idx, type) {
  return `<div class="terminal"><div class="terminal-bar">
    <span class="term-dots"><i></i><i></i><i></i></span><span class="term-title">terminal</span>
    <div class="term-actions">
      <button class="term-btn" data-act="copy" data-idx="${idx}" data-type="${type}">Copy</button>
      <button class="term-btn run" data-act="run" data-idx="${idx}" data-type="${type}">Run</button>
    </div></div><div class="terminal-body">
    <div class="term-cmd"><span class="term-prompt">$</span>${esc(cmd)}</div><div class="term-out"></div>
  </div></div>`;
}

function diffPanel(diff) {
  return `<div class="diff"><div class="diff-side diff-bad"><div class="diff-label">Before \u2014 Vulnerable</div><pre><code>${esc(diff.before)}</code></pre></div>
    <div class="diff-side diff-good"><div class="diff-label">After \u2014 Fixed</div><pre><code>${esc(diff.after)}</code></pre></div></div>`;
}

/* ===== Terminal Simulation ===== */
function runTerminal(btn) {
  const idx = +btn.dataset.idx, type = btn.dataset.type;
  const f = activeFinding(), pb = PB[f.tech] || PB.generic;
  const step = type==='fix' ? pb.fix[idx] : pb.verify[idx];
  const term = btn.closest('.terminal');
  const out = term.querySelector('.term-out');
  btn.disabled = true; btn.textContent = 'Running...';
  out.classList.remove('show'); out.innerHTML = '';
  setTimeout(() => {
    out.textContent = step.out || ''; out.classList.add('show');
    btn.disabled = false; btn.textContent = '\u2713 Ran'; btn.classList.add('ran'); btn.classList.remove('run');
    if (type === 'fix') {
      const el = btn.closest('.fix-step');
      if (el) { el.classList.add('done'); const n = el.querySelector('.fix-step-num'); if (n) n.textContent = '\u2713'; session(S.activeId).fixDone.add(idx); }
    } else { const el = btn.closest('.check-item'); if (el) { el.classList.add('done'); session(S.activeId).verifyDone.add(idx); } }
    const s = session(S.activeId); updateProgress(f, pb, s); updateNav(s.phase, pb, s);
  }, 700 + Math.random()*600);
}

function copyCmd(idx, type) {
  const f = activeFinding(), pb = PB[f.tech] || PB.generic;
  const step = type==='fix' ? pb.fix[idx] : pb.verify[idx];
  navigator.clipboard.writeText(step.cmd||'').then(() => toast('Copied to clipboard'));
}

function toggleStep(idx) { const s = session(S.activeId); s.fixDone.has(idx) ? s.fixDone.delete(idx) : s.fixDone.add(idx); renderFix(); }
function toggleCheck(idx) { const s = session(S.activeId); s.verifyDone.has(idx) ? s.verifyDone.delete(idx) : s.verifyDone.add(idx); renderFix(); }

/* ===== PDF Loading ===== */
async function handlePdf(file) {
  const st = $('#uploadStatus');
  st.innerHTML = '<span class="info">Extracting findings from PDF...</span>';
  try {
    const text = await extractPdf(file);
    const findings = parseFindings(text);
    if (!findings.length) { st.innerHTML = '<span class="err">No findings detected. Try the sample report.</span>'; return; }
    S.findings = findings; S.source = file.name;
    detectGroups();
    st.innerHTML = `<span class="ok">\u2713 Extracted ${findings.length} findings from ${file.name}</span>`;
    setTimeout(() => { showScreen('s-findings'); renderFindings(); }, 600);
  } catch(e) { st.innerHTML = `<span class="err">Error: ${esc(e.message)}</span>`; }
}

async function loadSample() {
  const st = $('#uploadStatus'); st.innerHTML = '<span class="info">Loading sample report...</span>';
  try {
    const resp = await fetch('sample-data/acme-pentest-report.pdf');
    const blob = await resp.blob();
    await handlePdf(new File([blob], 'acme-pentest-report.pdf', { type: 'application/pdf' }));
  } catch(e) { st.innerHTML = `<span class="err">Error: ${esc(e.message)}</span>`; }
}

/* ===== Init ===== */
function handleImageFile(file) {
  if (!file || !file.type.startsWith('image/')) { toast('Please upload an image file'); return; }
  const reader = new FileReader();
  reader.onload = e => {
    session(S.activeId).evidenceImage = e.target.result;
    renderFix();
    toast('Screenshot uploaded');
  };
  reader.readAsDataURL(file);
}

function loadSampleImage() {
  fetch('sample-data/fix-verified-sample.png')
    .then(r => r.blob())
    .then(blob => {
      const reader = new FileReader();
      reader.onload = e => {
        session(S.activeId).evidenceImage = e.target.result;
        renderFix();
        toast('Sample screenshot loaded');
      };
      reader.readAsDataURL(blob);
    })
    .catch(() => toast('Could not load sample image'));
}

function init() {
  const zone = $('#uploadZone');
  zone.addEventListener('click', () => $('#pdfFile').click());
  zone.addEventListener('dragover', e => { e.preventDefault(); zone.classList.add('dragover'); });
  zone.addEventListener('dragleave', () => zone.classList.remove('dragover'));
  zone.addEventListener('drop', e => { e.preventDefault(); zone.classList.remove('dragover'); if (e.dataTransfer.files[0]) handlePdf(e.dataTransfer.files[0]); });
  $('#pdfFile').addEventListener('change', e => { if (e.target.files[0]) handlePdf(e.target.files[0]); });
  $('#loadSampleBtn').addEventListener('click', loadSample);
  $('#newReportBtn').addEventListener('click', () => { S.findings=[]; S.sessions={}; S.activeId=null; S.suggestedGroups=[]; S.confirmedGroups={}; showScreen('s-upload'); });

  $('#fixBack').addEventListener('click', () => { showScreen('s-findings'); renderFindings(); });
  $('#fixPrev').addEventListener('click', () => navigatePhase(-1));
  $('#fixNext').addEventListener('click', () => {
    const s = session(S.activeId);
    if (s.phase === 3) { showScreen('s-findings'); renderFindings(); }
    else navigatePhase(1);
  });
  $('#stepper').addEventListener('click', e => { const st = e.target.closest('.step'); if (st) { session(S.activeId).phase = +st.dataset.phase; renderFix(); } });

  /* Groups section: confirm, dismiss, open group fix */
  $('#groupsSection').addEventListener('click', e => {
    const el = e.target.closest('[data-act]'); if (!el) return;
    if (el.dataset.act === 'confirm-group') confirmGroup(el.dataset.key);
    else if (el.dataset.act === 'dismiss-group') dismissGroup(el.dataset.key);
    else if (el.dataset.act === 'open-group') openGroupFix(el.dataset.key);
  });
  /* Findings grid: open-group button on covered cards */
  $('#findingsGrid').addEventListener('click', e => {
    const el = e.target.closest('[data-act="open-group"]'); if (!el) return;
    openGroupFix(el.dataset.key);
  });

  /* Fix content: terminal, checks, evidence, image upload */
  $('#fixContent').addEventListener('click', e => {
    const el = e.target.closest('[data-act]'); if (!el) return;
    const act = el.dataset.act;
    if (act === 'run') runTerminal(el);
    else if (act === 'copy') copyCmd(+el.dataset.idx, el.dataset.type);
    else if (act === 'step') toggleStep(+el.dataset.idx);
    else if (act === 'check') toggleCheck(+el.dataset.idx);
    else if (act === 'upload-zone') { el.querySelector('[data-act="evidence-img"]').click(); }
    else if (act === 'sample-img') loadSampleImage();
    else if (act === 'remove-img') { session(S.activeId).evidenceImage = ''; renderFix(); toast('Screenshot removed'); }
  });
  $('#fixContent').addEventListener('change', e => {
    if (e.target.dataset.act === 'evidence-img') { handleImageFile(e.target.files[0]); }
  });
  $('#fixContent').addEventListener('input', e => {
    if (e.target.dataset.act === 'evidence') {
      session(S.activeId).evidence = e.target.value;
      const f = activeFinding(), pb = PB[f.tech]||PB.generic, s = session(S.activeId);
      updateProgress(f, pb, s); updateNav(s.phase, pb, s);
    }
  });
  /* Drag & drop image upload */
  $('#fixContent').addEventListener('dragover', e => {
    if (e.target.closest('[data-act="upload-zone"]')) e.preventDefault();
  });
  $('#fixContent').addEventListener('drop', e => {
    const z = e.target.closest('[data-act="upload-zone"]');
    if (z) { e.preventDefault(); if (e.dataTransfer.files[0]) handleImageFile(e.dataTransfer.files[0]); }
  });
}

document.addEventListener('DOMContentLoaded', init);
