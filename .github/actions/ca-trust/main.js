// The three checks action.yml describes. No dependencies: node's own
// tls, crypto and child_process, and the openssl CLI every runner has.
// Runnable by hand on any Linux with openssl:
// `NODE_OPTIONS=--use-openssl-ca SSL_CERT_FILE=/etc/ssl/certs/ca-certificates.crt node main.js`
// passes; plain `node main.js` fails check 3 on an official Node build
// (a distro's may default to the system store, and pass).
'use strict';
const fs = require('fs');
const os = require('os');
const path = require('path');
const tls = require('tls');
const { X509Certificate } = require('crypto');
const { execFileSync, spawnSync } = require('child_process');

const BUNDLE = '/etc/ssl/certs/ca-certificates.crt';
// Roots no job may trust, by SHA-256 as Node prints it. Add one beside
// the floor in the workflows when a CA is distrusted.
const DISTRUSTED = {
  '86:A1:EC:BA:08:9C:4A:8D:3B:BE:27:34:C6:12:BA:34:1D:81:3E:04:3C:F9:E8:A8:62:CD:5C:57:A3:6B:BE:6B':
    'emSign ECC Root CA - G3 (eMudhra, CVE-2026-111943)',
};
// Fewer roots than this and the bundle is not one: Ubuntu 24.04's has 120.
const MIN_ROOTS = 100;
const REMOTE = 'github.com';

function pems(text) {
  return text.match(/-----BEGIN CERTIFICATE-----[\s\S]+?-----END CERTIFICATE-----/g) || [];
}

// Resolves to {authorized, error} once the handshake ends, so a refused
// certificate (authorized false, with OpenSSL's reason) is told apart
// from a connection that never got that far (rejects).
function handshake(host, port, servername) {
  return new Promise((resolve, reject) => {
    const s = tls.connect({ host, port, servername, rejectUnauthorized: false }, () => {
      resolve({ authorized: s.authorized, error: s.authorizationError && String(s.authorizationError) });
      s.destroy();
    });
    s.setTimeout(10000, () => s.destroy(new Error(`timed out connecting to ${host}:${port}`)));
    s.on('error', reject);
  });
}

// Check 3's half that runs in a child: the store is SSL_CERT_FILE/DIR
// as the parent set them, NODE_OPTIONS is the job's, inherited.
async function child() {
  const [key, cert] = [process.env.CA_TRUST_KEY, process.env.CA_TRUST_CERT].map((f) => fs.readFileSync(f));
  const server = tls.createServer({ key, cert }, (s) => s.end());
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const local = await handshake('127.0.0.1', server.address().port, 'localhost');
  server.close();
  const remote = await handshake(REMOTE, 443, REMOTE);
  process.stdout.write(JSON.stringify({ local, remote }));
}

function throwawayCA(dir) {
  const f = (n) => path.join(dir, n);
  const ossl = (...args) => execFileSync('openssl', args, { stdio: ['ignore', 'ignore', 'pipe'] });
  const ec = ['-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes'];
  ossl('req', '-x509', ...ec, '-keyout', f('ca.key'), '-out', f('ca.pem'), '-days', '1', '-subj', '/CN=hotserve ca-trust check');
  ossl('req', ...ec, '-keyout', f('leaf.key'), '-out', f('leaf.csr'), '-subj', '/CN=localhost');
  fs.writeFileSync(f('leaf.ext'), 'subjectAltName=DNS:localhost\n');
  ossl('x509', '-req', '-in', f('leaf.csr'), '-CA', f('ca.pem'), '-CAkey', f('ca.key'), '-set_serial', '1',
    '-out', f('leaf.pem'), '-days', '1', '-extfile', f('leaf.ext'));
  fs.mkdirSync(f('empty'));
  return { ca: f('ca.pem'), key: f('leaf.key'), cert: f('leaf.pem'), emptyDir: f('empty') };
}

async function main() {
  const failures = [];
  const check = (ok, line) => {
    console.log(`${ok ? 'ok  ' : 'FAIL'} ${line}`);
    if (!ok) failures.push(line);
  };
  console.log(`node ${process.version}, NODE_OPTIONS=${process.env.NODE_OPTIONS || '(unset)'}, SSL_CERT_FILE=${process.env.SSL_CERT_FILE || '(unset)'}`);

  // 1. The system store.
  const fps = pems(fs.readFileSync(BUNDLE, 'utf8')).map((p) => new X509Certificate(p).fingerprint256);
  check(fps.length >= MIN_ROOTS, `${BUNDLE} holds ${fps.length} roots (at least ${MIN_ROOTS})`);
  for (const [fp, name] of Object.entries(DISTRUSTED)) {
    check(!fps.includes(fp), `${BUNDLE} does not hold ${name}`);
  }

  // 2. This Node, as configured, verifies a real site.
  try {
    const r = await handshake(REMOTE, 443, REMOTE);
    check(r.authorized, `node verifies ${REMOTE}${r.authorized ? '' : `: ${r.error}`}`);
  } catch (e) {
    check(false, `node verifies ${REMOTE}: ${e.message}`);
  }

  // 3. With only a throwaway CA in the store: that CA works, the bundled
  // roots do not. SSL_CERT_DIR too: OpenSSL reads the directory as well
  // as the file, and the default one is the system store.
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'ca-trust-'));
  try {
    const t = throwawayCA(dir);
    const r = spawnSync(process.execPath, [__filename], {
      env: { ...process.env, SSL_CERT_FILE: t.ca, SSL_CERT_DIR: t.emptyDir, CA_TRUST_CHILD: '1', CA_TRUST_KEY: t.key, CA_TRUST_CERT: t.cert },
      encoding: 'utf8',
      timeout: 30000,
    });
    if (r.status !== 0) {
      // The child reports its own failures on stdout (the catch at the
      // bottom), and the timeout kills it with no status: say which.
      const how = r.error ? r.error.message : r.signal ? `killed by ${r.signal}` : `exited ${r.status}`;
      throw new Error(`child ${how}: ${(r.stderr || '').trim() || (r.stdout || '').trim()}`);
    }
    const { local, remote } = JSON.parse(r.stdout);
    check(local.authorized, `node trusts a CA that is only in the store${local.authorized ? '' : `: ${local.error}`}`);
    check(!remote.authorized, `node refuses ${REMOTE} when its root is not in the store (${remote.error || 'it verified: the bundled roots are in use'})`);
  } catch (e) {
    check(false, `store-only check: ${e.message}`);
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }

  if (failures.length) {
    console.log(`::error::ca trust: ${failures.length} check(s) failed: ${failures.join('; ')}`);
    process.exitCode = 1;
  }
}

(process.env.CA_TRUST_CHILD ? child : main)().catch((e) => {
  console.log(`::error::ca trust: ${e.stack || e}`);
  process.exitCode = 1;
});
