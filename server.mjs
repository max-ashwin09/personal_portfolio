import http from 'node:http';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const ROOT_DIR = __dirname;
const GATE_DATA_DIR = path.join(ROOT_DIR, '.gate-data');
const REQUESTS_PATH = path.join(GATE_DATA_DIR, 'requests.json');
const ADMIN_PATH = path.join(GATE_DATA_DIR, 'admin.json');
const SESSIONS_PATH = path.join(GATE_DATA_DIR, 'sessions.json');
const VAULT_KEY_PATH = path.join(GATE_DATA_DIR, 'vault-key.json');

const PORT = Number(process.env.PORT || 8123);
const HOST = process.env.HOST || '';
const ADMIN_COOKIE = 'vcrypt_admin';
const VISITOR_COOKIE = 'vcrypt_visitor';
const ADMIN_IDLE_TIMEOUT_MS = Number(process.env.ADMIN_TIMEOUT_MS || 2 * 60 * 1000);
const MAX_BODY_BYTES = 32 * 1024;

const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.mjs': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.jpeg': 'image/jpeg',
  '.webp': 'image/webp',
  '.gif': 'image/gif',
  '.ico': 'image/x-icon',
  '.pdf': 'application/pdf',
  '.woff': 'font/woff',
  '.woff2': 'font/woff2',
  '.ttf': 'font/ttf',
  '.eot': 'application/vnd.ms-fontobject',
};

const BLOCKED_PREFIXES = [
  '.git',
  '.gate-data',
  '.vscode',
  'src-pages',
  'scripts',
  'forms',
  'server.mjs',
  'firestore.rules',
  '.gitignore',
  '.ds_store',
];

const GATED_ASSET_PREFIXES = [
  'assets/img/portfolio/',
  'assets/img/profile/cyber-avatar.jpg',
  'assets/img/vivek(cv).pdf',
];

const visitorStreams = new Set();
const adminStreams = new Set();
const rateLimitBuckets = new Map();

function ensureGateDir() {
  fs.mkdirSync(GATE_DATA_DIR, { recursive: true });
}

function readJsonFile(filePath, fallback) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    return JSON.parse(fs.readFileSync(filePath, 'utf8'));
  } catch {
    return fallback;
  }
}

function writeJsonAtomic(filePath, data) {
  ensureGateDir();
  const tmpPath = `${filePath}.tmp`;
  fs.writeFileSync(tmpPath, JSON.stringify(data, null, 2), { mode: 0o600 });
  fs.renameSync(tmpPath, filePath);
}

function sha256(value) {
  return crypto.createHash('sha256').update(String(value)).digest('hex');
}

function loadVaultKeyBase64() {
  const data = readJsonFile(VAULT_KEY_PATH, null);
  return data && typeof data.keyBase64 === 'string' ? data.keyBase64 : null;
}

function loadRequests() {
  const list = readJsonFile(REQUESTS_PATH, []);
  return Array.isArray(list) ? list : [];
}

function saveRequests(list) {
  writeJsonAtomic(REQUESTS_PATH, list);
}

function loadAdminConfig() {
  return readJsonFile(ADMIN_PATH, null);
}

function hashPasscode(passcode, saltHex) {
  return crypto.scryptSync(passcode, saltHex, 64).toString('hex');
}

function verifyPasscode(passcode, adminCfg) {
  if (!adminCfg || !adminCfg.salt || !adminCfg.hash) return false;
  const derived = Buffer.from(hashPasscode(passcode, adminCfg.salt), 'hex');
  const expected = Buffer.from(adminCfg.hash, 'hex');
  if (derived.length !== expected.length) return false;
  return crypto.timingSafeEqual(derived, expected);
}

function pruneAdminSessions(rawSessions) {
  const now = Date.now();
  const cleaned = {};
  const expiredHashes = [];
  let changed = false;

  for (const [tokenHash, info] of Object.entries(rawSessions || {})) {
    const valid =
      info &&
      typeof info.lastActivityAt === 'number' &&
      Number(info.expiresAt) > now;
    if (valid) {
      cleaned[tokenHash] = info;
    } else {
      changed = true;
      expiredHashes.push(tokenHash);
    }
  }

  return { cleaned, expiredHashes, changed };
}

function loadAdminSessions() {
  const raw = readJsonFile(SESSIONS_PATH, {});
  const { cleaned, changed } = pruneAdminSessions(raw);
  if (changed) {
    writeJsonAtomic(SESSIONS_PATH, cleaned);
  }
  return cleaned;
}

function saveAdminSessions(sessions) {
  writeJsonAtomic(SESSIONS_PATH, sessions);
}

function issueAdminSession(req, sessions) {
  const existingCookie = parseCookies(req)[ADMIN_COOKIE];
  if (existingCookie) {
    delete sessions[sha256(existingCookie)];
  }
  const nowMs = Date.now();
  const expiresAt = nowMs + ADMIN_IDLE_TIMEOUT_MS;
  const rawSession = crypto.randomBytes(32).toString('hex');
  sessions[sha256(rawSession)] = {
    createdAt: new Date(nowMs).toISOString(),
    lastActivityAt: nowMs,
    expiresAt,
    consoleUnlocked: true,
  };
  saveAdminSessions(sessions);
  return { rawSession, expiresAt };
}

function refreshAdminSessionActivity(tokenHash) {
  const sessions = loadAdminSessions();
  const entry = sessions[tokenHash];
  if (!entry) return null;
  const nowMs = Date.now();
  entry.lastActivityAt = nowMs;
  entry.expiresAt = nowMs + ADMIN_IDLE_TIMEOUT_MS;
  saveAdminSessions(sessions);
  return entry.expiresAt;
}

function parseCookies(req) {
  const header = req.headers.cookie || '';
  const out = {};
  for (const part of header.split(';')) {
    const idx = part.indexOf('=');
    if (idx === -1) continue;
    const key = part.slice(0, idx).trim();
    const val = part.slice(idx + 1).trim();
    if (!key) continue;
    try {
      out[key] = decodeURIComponent(val);
    } catch {
      out[key] = val;
    }
  }
  return out;
}

function setCookieHeader(name, value, maxAgeSeconds) {
  const parts = [
    `${name}=${encodeURIComponent(value)}`,
    'Path=/',
    'HttpOnly',
    'SameSite=Lax',
  ];
  if (typeof maxAgeSeconds === 'number') {
    parts.push(`Max-Age=${maxAgeSeconds}`);
  }
  return parts.join('; ');
}

function getAuthenticatedAdmin(req) {
  const cookies = parseCookies(req);
  const rawToken = cookies[ADMIN_COOKIE];
  if (!rawToken) return null;
  const sessions = loadAdminSessions();
  const tokenHash = sha256(rawToken);
  const entry = sessions[tokenHash];
  if (!entry || entry.expiresAt <= Date.now()) return null;
  return { tokenHash, entry };
}

function getVisitorRequest(req, requestsList) {
  const cookies = parseCookies(req);
  const rawToken = cookies[VISITOR_COOKIE];
  if (!rawToken) return null;
  const tokenHash = sha256(rawToken);
  return requestsList.find((item) => item.tokenHash === tokenHash) || null;
}

function isOriginAllowed(req) {
  const origin = req.headers.origin;
  if (!origin) return true;
  try {
    return new URL(origin).host === req.headers.host;
  } catch {
    return false;
  }
}

function checkRateLimit(bucketKey, maxHits, windowMs) {
  const now = Date.now();
  const hits = (rateLimitBuckets.get(bucketKey) || []).filter((ts) => now - ts < windowMs);
  if (hits.length >= maxHits) {
    rateLimitBuckets.set(bucketKey, hits);
    return false;
  }
  hits.push(now);
  rateLimitBuckets.set(bucketKey, hits);
  return true;
}

function sendJson(res, statusCode, payload, extraHeaders = {}) {
  const body = JSON.stringify(payload);
  res.writeHead(statusCode, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store, no-cache, must-revalidate',
    'X-Content-Type-Options': 'nosniff',
    ...extraHeaders,
  });
  res.end(body);
}

function readRequestBody(req) {
  return new Promise((resolve, reject) => {
    let total = 0;
    const chunks = [];
    req.on('data', (chunk) => {
      total += chunk.length;
      if (total > MAX_BODY_BYTES) {
        reject(new Error('PAYLOAD_TOO_LARGE'));
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      try {
        const raw = Buffer.concat(chunks).toString('utf8').trim();
        resolve(raw ? JSON.parse(raw) : {});
      } catch {
        reject(new Error('INVALID_JSON'));
      }
    });
    req.on('error', reject);
  });
}

function safeVisitorSummary(record) {
  if (!record) return null;
  return {
    id: record.id,
    name: record.name,
    email: record.email,
    purpose: record.purpose,
    reason: record.reason,
    status: record.status,
    adminNote: record.adminNote || '',
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  };
}

function safeAdminRecord(record) {
  return {
    ...safeVisitorSummary(record),
    ip: record.ip || 'local',
    userAgent: record.userAgent || '',
  };
}

function buildGateStatusPayloadFromTokens(visitorTokenHash, adminTokenHash, visitorPreview = false) {
  const requests = loadRequests();
  const visitorRecord = visitorTokenHash
    ? requests.find((item) => item.tokenHash === visitorTokenHash) || null
    : null;
  const sessions = adminTokenHash ? loadAdminSessions() : null;
  const adminEntry = adminTokenHash && sessions ? sessions[adminTokenHash] : null;
  const hasValidAdmin = Boolean(adminEntry && Number(adminEntry.expiresAt) > Date.now());
  const isAdmin = hasValidAdmin && !visitorPreview;

  let status = 'none';
  if (visitorRecord) {
    status = visitorRecord.status;
  } else if (isAdmin) {
    status = 'owner';
  }

  const unlocked = status === 'approved' || isAdmin;
  return {
    mode: 'local',
    status,
    isAdmin,
    unlocked,
    adminExpiresAt: isAdmin ? adminEntry.expiresAt : null,
    request: safeVisitorSummary(visitorRecord),
    vaultKey: unlocked ? loadVaultKeyBase64() : null,
  };
}

function buildGateStatusPayload(req, visitorPreview = false) {
  const cookies = parseCookies(req);
  const visitorTokenHash = cookies[VISITOR_COOKIE] ? sha256(cookies[VISITOR_COOKIE]) : null;
  const adminTokenHash = cookies[ADMIN_COOKIE] ? sha256(cookies[ADMIN_COOKIE]) : null;
  return buildGateStatusPayloadFromTokens(visitorTokenHash, adminTokenHash, visitorPreview);
}

function broadcastToVisitor(tokenHash, payload) {
  const msg = `event: status\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of visitorStreams) {
    if (client.visitorPreview) continue;
    if (!tokenHash || client.tokenHash === tokenHash) {
      try {
        client.res.write(msg);
      } catch {
        visitorStreams.delete(client);
      }
    }
  }
}

function broadcastToAdmins(eventName, payload, targetTokenHash = null) {
  const msg = `event: ${eventName}\ndata: ${JSON.stringify(payload)}\n\n`;
  for (const client of adminStreams) {
    if (targetTokenHash && client.tokenHash !== targetTokenHash) continue;
    try {
      client.res.write(msg);
    } catch {
      adminStreams.delete(client);
    }
  }
}

function closeAdminStreams(tokenHash, eventName = null, payload = null) {
  const msg = eventName ? `event: ${eventName}\ndata: ${JSON.stringify(payload || {})}\n\n` : null;
  for (const client of adminStreams) {
    if (client.tokenHash !== tokenHash) continue;
    try {
      if (msg) client.res.write(msg);
      client.res.end();
    } catch {}
    adminStreams.delete(client);
  }
}

function notifyVisitorsOfAdminTermination(adminTokenHash) {
  for (const client of visitorStreams) {
    if (client.adminTokenHash !== adminTokenHash) continue;
    const payload = buildGateStatusPayloadFromTokens(client.tokenHash, null, client.visitorPreview);
    try {
      client.res.write(`event: status\ndata: ${JSON.stringify(payload)}\n\n`);
    } catch {
      visitorStreams.delete(client);
    }
  }
}

function sweepExpiredAdminSessions() {
  if (visitorStreams.size === 0 && adminStreams.size === 0) return;
  const raw = readJsonFile(SESSIONS_PATH, {});
  const { cleaned, expiredHashes, changed } = pruneAdminSessions(raw);
  if (!changed) return;
  writeJsonAtomic(SESSIONS_PATH, cleaned);
  for (const expiredHash of expiredHashes) {
    closeAdminStreams(expiredHash, 'session-expired', { reason: 'timeout' });
    notifyVisitorsOfAdminTermination(expiredHash);
  }
}

function validateEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email) && email.length <= 120;
}

async function handleApi(req, res, pathname, parsedUrl) {
  if ((req.method === 'POST' || req.method === 'DELETE') && !isOriginAllowed(req)) {
    return sendJson(res, 403, { error: 'Origin mismatch rejected.' });
  }

  const clientIp = req.socket.remoteAddress || 'unknown';

  if (req.method === 'GET' && pathname === '/api/gate/mode') {
    return sendJson(res, 200, { mode: 'local', serverTime: new Date().toISOString() });
  }

  if (req.method === 'GET' && pathname === '/api/gate/status') {
    const visitorPreview = parsedUrl.searchParams.get('visitorPreview') === '1';
    return sendJson(res, 200, buildGateStatusPayload(req, visitorPreview));
  }

  if (req.method === 'GET' && pathname === '/api/gate/events') {
    const visitorPreview = parsedUrl.searchParams.get('visitorPreview') === '1';
    const cookies = parseCookies(req);
    const rawVisitorToken = cookies[VISITOR_COOKIE] || '';
    const tokenHash = rawVisitorToken ? sha256(rawVisitorToken) : null;
    const rawAdminToken = cookies[ADMIN_COOKIE] || '';
    const adminTokenHash = rawAdminToken ? sha256(rawAdminToken) : null;

    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store, no-cache',
      Connection: 'keep-alive',
    });

    const client = { res, tokenHash, adminTokenHash, visitorPreview };
    visitorStreams.add(client);
    res.write(
      `event: status\ndata: ${JSON.stringify(buildGateStatusPayloadFromTokens(tokenHash, adminTokenHash, visitorPreview))}\n\n`
    );

    req.on('close', () => {
      visitorStreams.delete(client);
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/gate/request') {
    if (!checkRateLimit(`req:${clientIp}`, 20, 10 * 60 * 1000)) {
      return sendJson(res, 429, { error: 'Too many requests. Please wait a few minutes.' });
    }

    let body;
    try {
      body = await readRequestBody(req);
    } catch (err) {
      return sendJson(res, 400, { error: err.message === 'PAYLOAD_TOO_LARGE' ? 'Request too large.' : 'Invalid JSON payload.' });
    }

    const name = String(body.name || '').trim();
    const email = String(body.email || '').trim().toLowerCase();
    const purpose = String(body.purpose || 'General Portfolio View').trim().slice(0, 80);
    const reason = String(body.reason || '').trim();

    if (name.length < 2 || name.length > 80) {
      return sendJson(res, 400, { error: 'Please enter a valid full name (2–80 characters).' });
    }
    if (!validateEmail(email)) {
      return sendJson(res, 400, { error: 'Please enter a valid email address.' });
    }
    if (reason.length < 3 || reason.length > 400) {
      return sendJson(res, 400, { error: 'Please provide a brief reason to view (3–400 characters).' });
    }

    const requests = loadRequests();
    const forceNew = Boolean(body.forceNew);
    const existing = forceNew ? null : getVisitorRequest(req, requests);
    const now = new Date().toISOString();

    let visitorToken = parseCookies(req)[VISITOR_COOKIE] || '';
    let tokenHash = visitorToken ? sha256(visitorToken) : '';

    if (!existing || forceNew) {
      visitorToken = crypto.randomBytes(24).toString('hex');
      tokenHash = sha256(visitorToken);
      const record = {
        id: `REQ-${crypto.randomBytes(4).toString('hex').toUpperCase()}`,
        tokenHash,
        name,
        email,
        purpose,
        reason,
        status: 'pending',
        adminNote: '',
        ip: clientIp,
        userAgent: String(req.headers['user-agent'] || '').slice(0, 160),
        createdAt: now,
        updatedAt: now,
      };
      requests.unshift(record);
      saveRequests(requests);
      broadcastToAdmins('requests', { type: 'created', request: safeAdminRecord(record) });

      return sendJson(
        res,
        201,
        {
          mode: 'local',
          status: 'pending',
          unlocked: false,
          request: safeVisitorSummary(record),
          vaultKey: null,
        },
        { 'Set-Cookie': setCookieHeader(VISITOR_COOKIE, visitorToken, 30 * 24 * 60 * 60) }
      );
    }

    existing.name = name;
    existing.email = email;
    existing.purpose = purpose;
    existing.reason = reason;
    if (existing.status !== 'approved') {
      existing.status = 'pending';
    }
    existing.updatedAt = now;
    saveRequests(requests);
    broadcastToAdmins('requests', { type: 'updated', request: safeAdminRecord(existing) });

    return sendJson(res, 200, {
      mode: 'local',
      status: existing.status,
      unlocked: existing.status === 'approved',
      request: safeVisitorSummary(existing),
      vaultKey: existing.status === 'approved' ? loadVaultKeyBase64() : null,
    });
  }

  // Admin endpoints
  if (req.method === 'GET' && pathname === '/api/admin/state') {
    const adminCfg = loadAdminConfig();
    const adminSession = getAuthenticatedAdmin(req);
    const authenticated = Boolean(adminSession && adminSession.entry.consoleUnlocked);
    return sendJson(res, 200, {
      mode: 'local',
      configured: Boolean(adminCfg && adminCfg.hash),
      authenticated,
      consoleLocked: Boolean(adminSession && !adminSession.entry.consoleUnlocked),
      ownerSessionActive: Boolean(adminSession),
      expiresAt: adminSession ? adminSession.entry.expiresAt : null,
      timeoutMs: ADMIN_IDLE_TIMEOUT_MS,
      vaultKey: authenticated ? loadVaultKeyBase64() : null,
    });
  }

  if (req.method === 'POST' && pathname === '/api/admin/setup') {
    const existingCfg = loadAdminConfig();
    if (existingCfg && existingCfg.hash) {
      return sendJson(res, 403, { error: 'Admin passcode is already configured.' });
    }

    let body;
    try {
      body = await readRequestBody(req);
    } catch {
      return sendJson(res, 400, { error: 'Invalid request body.' });
    }

    const passcode = String(body.passcode || '');
    if (passcode.length < 6 || passcode.length > 128) {
      return sendJson(res, 400, { error: 'Passcode must be between 6 and 128 characters.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPasscode(passcode, salt);
    const now = new Date().toISOString();
    writeJsonAtomic(ADMIN_PATH, { salt, hash, createdAt: now, updatedAt: now });

    const sessions = loadAdminSessions();
    const { rawSession, expiresAt } = issueAdminSession(req, sessions);

    return sendJson(
      res,
      201,
      {
        configured: true,
        authenticated: true,
        expiresAt,
        timeoutMs: ADMIN_IDLE_TIMEOUT_MS,
        vaultKey: loadVaultKeyBase64(),
      },
      { 'Set-Cookie': setCookieHeader(ADMIN_COOKIE, rawSession) }
    );
  }

  if (req.method === 'POST' && pathname === '/api/admin/login') {
    if (!checkRateLimit(`login:${clientIp}`, 10, 5 * 60 * 1000)) {
      return sendJson(res, 429, { error: 'Too many failed login attempts. Try again in 5 minutes.' });
    }

    const adminCfg = loadAdminConfig();
    if (!adminCfg || !adminCfg.hash) {
      return sendJson(res, 400, { error: 'Admin passcode is not configured yet.' });
    }

    let body;
    try {
      body = await readRequestBody(req);
    } catch {
      return sendJson(res, 400, { error: 'Invalid request body.' });
    }

    const passcode = String(body.passcode || '');
    if (!verifyPasscode(passcode, adminCfg)) {
      return sendJson(res, 401, { error: 'Invalid admin passcode.' });
    }

    const sessions = loadAdminSessions();
    const { rawSession, expiresAt } = issueAdminSession(req, sessions);

    return sendJson(
      res,
      200,
      {
        authenticated: true,
        expiresAt,
        timeoutMs: ADMIN_IDLE_TIMEOUT_MS,
        vaultKey: loadVaultKeyBase64(),
      },
      { 'Set-Cookie': setCookieHeader(ADMIN_COOKIE, rawSession) }
    );
  }

  if (req.method === 'POST' && pathname === '/api/admin/lock') {
    const adminSession = getAuthenticatedAdmin(req);
    if (adminSession) {
      const sessions = loadAdminSessions();
      if (sessions[adminSession.tokenHash]) {
        sessions[adminSession.tokenHash].consoleUnlocked = false;
        saveAdminSessions(sessions);
      }
      closeAdminStreams(adminSession.tokenHash);
    }
    return sendJson(res, 200, { ok: true, consoleLocked: true });
  }

  if (req.method === 'POST' && pathname === '/api/admin/logout') {
    const cookies = parseCookies(req);
    const rawToken = cookies[ADMIN_COOKIE];
    if (rawToken) {
      const tokenHash = sha256(rawToken);
      const sessions = loadAdminSessions();
      if (sessions[tokenHash]) {
        delete sessions[tokenHash];
        saveAdminSessions(sessions);
      }
      closeAdminStreams(tokenHash);
      notifyVisitorsOfAdminTermination(tokenHash);
    }
    return sendJson(res, 200, { authenticated: false }, { 'Set-Cookie': setCookieHeader(ADMIN_COOKIE, '', 0) });
  }

  // Protected Admin routes below
  const adminSession = getAuthenticatedAdmin(req);
  if (pathname.startsWith('/api/admin/') && (!adminSession || !adminSession.entry.consoleUnlocked)) {
    return sendJson(res, 401, {
      error: adminSession
        ? 'Admin console locked. Please enter your passcode again.'
        : 'Admin session expired or not authenticated.',
      code: adminSession ? 'CONSOLE_LOCKED' : 'SESSION_EXPIRED',
    });
  }

  if (req.method === 'POST' && pathname === '/api/admin/touch') {
    const expiresAt = refreshAdminSessionActivity(adminSession.tokenHash);
    if (!expiresAt) {
      return sendJson(res, 401, { error: 'Admin session expired.', code: 'SESSION_EXPIRED' });
    }
    return sendJson(res, 200, { ok: true, expiresAt, timeoutMs: ADMIN_IDLE_TIMEOUT_MS });
  }

  if (req.method === 'POST' && pathname === '/api/admin/change-passcode') {
    let body;
    try {
      body = await readRequestBody(req);
    } catch {
      return sendJson(res, 400, { error: 'Invalid request body.' });
    }

    const currentPasscode = String(body.currentPasscode || '');
    const newPasscode = String(body.newPasscode || '');
    const adminCfg = loadAdminConfig();

    if (!verifyPasscode(currentPasscode, adminCfg)) {
      return sendJson(res, 401, { error: 'Current passcode is incorrect.' });
    }
    if (newPasscode.length < 6 || newPasscode.length > 128) {
      return sendJson(res, 400, { error: 'New passcode must be 6–128 characters.' });
    }

    const salt = crypto.randomBytes(16).toString('hex');
    const hash = hashPasscode(newPasscode, salt);
    writeJsonAtomic(ADMIN_PATH, {
      salt,
      hash,
      createdAt: adminCfg.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString(),
    });
    const expiresAt = refreshAdminSessionActivity(adminSession.tokenHash);

    return sendJson(res, 200, { ok: true, expiresAt });
  }

  if (req.method === 'GET' && pathname === '/api/admin/requests') {
    const requests = loadRequests().map(safeAdminRecord);
    return sendJson(res, 200, { requests });
  }

  if (req.method === 'GET' && pathname === '/api/admin/events') {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream; charset=utf-8',
      'Cache-Control': 'no-store, no-cache',
      Connection: 'keep-alive',
    });
    const client = { res, tokenHash: adminSession.tokenHash };
    adminStreams.add(client);
    res.write(`event: requests\ndata: ${JSON.stringify({ type: 'init', count: loadRequests().length })}\n\n`);
    req.on('close', () => {
      adminStreams.delete(client);
    });
    return;
  }

  if (req.method === 'POST' && pathname === '/api/admin/decision') {
    let body;
    try {
      body = await readRequestBody(req);
    } catch {
      return sendJson(res, 400, { error: 'Invalid request body.' });
    }

    const id = String(body.id || '').trim();
    const decision = String(body.status || '').trim();
    const adminNote = String(body.adminNote || '').trim().slice(0, 240);
    const allowed = new Set(['approved', 'rejected', 'revoked', 'pending']);

    if (!id || !allowed.has(decision)) {
      return sendJson(res, 400, { error: 'Invalid request id or status.' });
    }

    const requests = loadRequests();
    const record = requests.find((item) => item.id === id);
    if (!record) {
      return sendJson(res, 404, { error: 'Request not found.' });
    }

    record.status = decision;
    record.adminNote = adminNote;
    record.updatedAt = new Date().toISOString();
    saveRequests(requests);

    const expiresAt = refreshAdminSessionActivity(adminSession.tokenHash);
    const unlocked = decision === 'approved';
    broadcastToVisitor(record.tokenHash, {
      mode: 'local',
      status: record.status,
      isAdmin: false,
      unlocked,
      request: safeVisitorSummary(record),
      vaultKey: unlocked ? loadVaultKeyBase64() : null,
    });
    broadcastToAdmins('requests', { type: 'updated', request: safeAdminRecord(record) });

    return sendJson(res, 200, { request: safeAdminRecord(record), expiresAt });
  }

  if (req.method === 'DELETE' && pathname === '/api/admin/requests') {
    let id = parsedUrl.searchParams.get('id') || '';
    if (!id) {
      try {
        const body = await readRequestBody(req);
        id = String(body.id || '').trim();
      } catch {
        id = '';
      }
    }

    if (!id) {
      return sendJson(res, 400, { error: 'Request id is required.' });
    }

    const requests = loadRequests();
    const idx = requests.findIndex((item) => item.id === id);
    if (idx === -1) {
      return sendJson(res, 404, { error: 'Request not found.' });
    }

    const [removed] = requests.splice(idx, 1);
    saveRequests(requests);
    const expiresAt = refreshAdminSessionActivity(adminSession.tokenHash);

    broadcastToVisitor(removed.tokenHash, {
      mode: 'local',
      status: 'none',
      isAdmin: false,
      unlocked: false,
      request: null,
      vaultKey: null,
    });
    broadcastToAdmins('requests', { type: 'deleted', id: removed.id });

    return sendJson(res, 200, { deletedId: removed.id, expiresAt });
  }

  return sendJson(res, 404, { error: 'API endpoint not found.' });
}

function isProtectedAsset(relPath) {
  const normalized = relPath.toLowerCase();
  return GATED_ASSET_PREFIXES.some((prefix) => normalized === prefix || normalized.startsWith(prefix));
}

function isBlockedPath(relPath) {
  const lower = relPath.toLowerCase();
  return BLOCKED_PREFIXES.some((prefix) => lower === prefix || lower.startsWith(`${prefix}/`)) || lower.split('/').some((seg) => seg.startsWith('.'));
}

function handleStatic(req, res, pathname) {
  if (req.method !== 'GET' && req.method !== 'HEAD') {
    res.writeHead(405, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Method Not Allowed');
    return;
  }

  let decoded;
  try {
    decoded = decodeURIComponent(pathname);
  } catch {
    res.writeHead(400);
    res.end('Bad Request');
    return;
  }

  let rel = decoded.replace(/^\/+/, '');
  if (!rel || rel.endsWith('/')) {
    rel += 'index.html';
  }

  if (isBlockedPath(rel)) {
    res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Not Found');
    return;
  }

  const fullPath = path.resolve(ROOT_DIR, rel);
  if (!fullPath.startsWith(ROOT_DIR + path.sep) && fullPath !== ROOT_DIR) {
    res.writeHead(403, { 'Content-Type': 'text/plain; charset=utf-8' });
    res.end('Forbidden');
    return;
  }

  if (!fs.existsSync(fullPath) || fs.statSync(fullPath).isDirectory()) {
    const notFoundPath = path.join(ROOT_DIR, '404.html');
    if (fs.existsSync(notFoundPath)) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(notFoundPath).pipe(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('Not Found');
    }
    return;
  }

  const protectedFile = isProtectedAsset(rel);
  if (protectedFile) {
    const requests = loadRequests();
    const visitor = getVisitorRequest(req, requests);
    const admin = getAuthenticatedAdmin(req);
    const allowed = Boolean(admin) || (visitor && visitor.status === 'approved');
    if (!allowed) {
      res.writeHead(403, {
        'Content-Type': 'application/json; charset=utf-8',
        'Cache-Control': 'no-store, no-cache',
      });
      res.end(JSON.stringify({ error: 'Access denied. Owner approval required.' }));
      return;
    }
  }

  const ext = path.extname(fullPath).toLowerCase();
  const contentType = MIME_TYPES[ext] || 'application/octet-stream';
  const headers = {
    'Content-Type': contentType,
    'X-Content-Type-Options': 'nosniff',
  };

  if (protectedFile || rel === 'assets/data/vault.enc.json' || ext === '.html') {
    headers['Cache-Control'] = 'no-store, no-cache, must-revalidate';
  }

  res.writeHead(200, headers);
  if (req.method === 'HEAD') {
    res.end();
    return;
  }
  fs.createReadStream(fullPath).pipe(res);
}

const server = http.createServer(async (req, res) => {
  try {
    const parsedUrl = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const pathname = parsedUrl.pathname;

    if (pathname.startsWith('/api/')) {
      await handleApi(req, res, pathname, parsedUrl);
      return;
    }

    handleStatic(req, res, pathname);
  } catch (err) {
    console.error('Unhandled request error:', err);
    if (!res.headersSent) {
      sendJson(res, 500, { error: 'Internal server error' });
    }
  }
});

// Keep SSE connections alive cleanly & sweep expired admin sessions
setInterval(() => {
  for (const client of visitorStreams) {
    try {
      client.res.write(': ping\n\n');
    } catch {
      visitorStreams.delete(client);
    }
  }
  for (const client of adminStreams) {
    try {
      client.res.write(': ping\n\n');
    } catch {
      adminStreams.delete(client);
    }
  }
}, 25000).unref();

setInterval(() => {
  sweepExpiredAdminSessions();
}, 5000).unref();

if (HOST) {
  server.listen(PORT, HOST, () => {
    console.log(`VCRYPT Portfolio Gate Server listening at http://${HOST}:${PORT}`);
  });
} else {
  server.listen(PORT, () => {
    console.log(`VCRYPT Portfolio Gate Server listening at http://localhost:${PORT}`);
  });
}

function gracefulShutdown() {
  for (const client of visitorStreams) {
    try {
      client.res.end();
    } catch {}
  }
  visitorStreams.clear();
  for (const client of adminStreams) {
    try {
      client.res.end();
    } catch {}
  }
  adminStreams.clear();
  if (typeof server.closeAllConnections === 'function') {
    server.closeAllConnections();
  }
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 250).unref();
}

process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);
