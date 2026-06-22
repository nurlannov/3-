'use strict';

require('dotenv').config();

const fs = require('fs');
const http = require('http');
const https = require('https');
const crypto = require('crypto');
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const webpush = require('web-push');
const bcrypt = require('bcryptjs');
const admin = require('firebase-admin');

const app = express();
app.set('trust proxy', 1);

const PORT = parseInt(process.env.PORT || '3001', 10);
const ALLOWED_ORIGIN = process.env.ALLOWED_ORIGIN || 'https://3korony.vercel.app';
const SESSION_TTL_MS = parseInt(process.env.SESSION_TTL_MS || String(8 * 60 * 60 * 1000), 10);
const CSRF_TTL_MS = parseInt(process.env.CSRF_TTL_MS || String(30 * 60 * 1000), 10);
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || '';
const NOTIFY_TRUSTED_IPS = (process.env.NOTIFY_TRUSTED_IPS || '127.0.0.1,::1,::ffff:127.0.0.1')
  .split(',')
  .map(ip => ip.trim())
  .filter(Boolean);

const VAPID_PUBLIC_KEYS = (process.env.VAPID_PUBLIC_KEYS || process.env.VAPID_PUBLIC_KEY || '')
  .split(',')
  .map(v => v.trim())
  .filter(Boolean);
const VAPID_PRIVATE_KEY = process.env.VAPID_PRIVATE_KEY || '';
const VAPID_EMAIL = process.env.VAPID_EMAIL || 'mailto:admin@example.com';

const allowedCollections = new Set(['guests', 'tables', 'audit_logs']);
const csrfPreAuth = new Map();
const sessions = new Map();
const latestSessionByUid = new Map();

function randomToken(bytes = 32) {
  return crypto.randomBytes(bytes).toString('base64url');
}

function getClientIp(req) {
  const forwarded = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
  return forwarded || req.ip || req.socket.remoteAddress || '';
}

function stripHtml(value) {
  if (value === null || value === undefined) return '';
  return String(value).replace(/<[^>]*>/g, '').trim();
}

function sanitizePlainObject(value) {
  if (Array.isArray(value)) return value.map(sanitizePlainObject);
  if (value && typeof value === 'object') {
    return Object.fromEntries(Object.entries(value).map(([key, val]) => [key, sanitizePlainObject(val)]));
  }
  return typeof value === 'string' ? stripHtml(value) : value;
}

function toIntRange(value, min, max) {
  if (!/^\d+$/.test(String(value))) return null;
  const parsed = Number.parseInt(value, 10);
  if (parsed < min || parsed > max) return null;
  return parsed;
}

function validateGuestPayload(input, partial = false) {
  const data = sanitizePlainObject(input || {});
  const errors = [];

  if (!partial || Object.prototype.hasOwnProperty.call(data, 'room')) {
    if (!/^[^<>{}\[\]]{1,20}$/.test(room)) throw new Error('Недопустимые символы в поле "Комната".');
  }
  if (!partial || Object.prototype.hasOwnProperty.call(data, 'name')) {
    if (!/^[\p{L}\s-]{2,50}$/u.test(String(data.name || ''))) errors.push('name must contain 2-50 letters, spaces or hyphens');
  }
  for (const field of ['adults', 'kids']) {
    if (!partial || Object.prototype.hasOwnProperty.call(data, field)) {
      const parsed = toIntRange(data[field], 0, 10);
      if (parsed === null) errors.push(`${field} must be an integer from 0 to 10`);
      else data[field] = String(parsed);
    }
  }
  if (Object.prototype.hasOwnProperty.call(data, 'notes')) data.notes = stripHtml(data.notes);

  if (errors.length) {
    const err = new Error(errors.join('; '));
    err.status = 400;
    throw err;
  }
  return data;
}

function validateTablePayload(input) {
  return sanitizePlainObject(input || {});
}

function validateCollectionPayload(collectionName, data, partial = false) {
  if (collectionName === 'guests') return validateGuestPayload(data, partial);
  if (collectionName === 'tables') return validateTablePayload(data);
  if (collectionName === 'audit_logs') return sanitizePlainObject(data || {});
  return sanitizePlainObject(data || {});
}

function parseServiceAccount() {
  if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
    return JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON);
  }
  if (process.env.GOOGLE_APPLICATION_CREDENTIALS) {
    return JSON.parse(fs.readFileSync(process.env.GOOGLE_APPLICATION_CREDENTIALS, 'utf8'));
  }
  return null;
}

const serviceAccount = parseServiceAccount();
if (serviceAccount) {
  admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
} else {
  admin.initializeApp({ credential: admin.credential.applicationDefault() });
}
const db = admin.firestore();

if (!VAPID_PUBLIC_KEYS[0] || !VAPID_PRIVATE_KEY) {
  console.warn('[Push] VAPID keys are not fully configured. Push subscription will be disabled until .env is fixed.');
} else {
  webpush.setVapidDetails(VAPID_EMAIL, VAPID_PUBLIC_KEYS[0], VAPID_PRIVATE_KEY);
}

app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: true,
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      styleSrc: ["'self'", "'unsafe-inline'", 'https://fonts.googleapis.com'],
      fontSrc: ["'self'", 'https://fonts.gstatic.com'],
      imgSrc: ["'self'", 'data:', 'blob:'],
      connectSrc: ["'self'"],
      objectSrc: ["'none'"],
      baseUri: ["'self'"],
      frameAncestors: ["'none'"],
      workerSrc: ["'self'"],
      manifestSrc: ["'self'", 'blob:']
    }
  },
  crossOriginEmbedderPolicy: false
}));

app.use(cors({
  origin: (origin, callback) => {
    if (!origin || origin === ALLOWED_ORIGIN) return callback(null, true);
    return callback(new Error('Not allowed by CORS'));
  },
  methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization', 'X-CSRF-Token'],
  credentials: true
}));

app.use('/api/', rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'Too many requests' }
}));

app.use(express.json({ limit: '20kb' }));

function checkOrigin(req, res, next) {
  const origin = req.headers.origin || '';
  const referer = req.headers.referer || '';
  const allowed = (!origin && !referer) || origin === ALLOWED_ORIGIN || referer.startsWith(ALLOWED_ORIGIN);
  if (!allowed) return res.status(403).json({ error: 'Forbidden origin' });
  next();
}

app.use('/api/', checkOrigin);

function hasRole(userRole, allowed) {
  return allowed.includes(userRole);
}

async function writeAudit(req, action, details = '', targetId = null, success = true) {
  try {
    await db.collection('audit_logs').add({
      action: stripHtml(action),
      details: stripHtml(details),
      targetId: targetId || null,
      success: !!success,
      uid: req.user?.uid || null,
      role: req.user?.role || null,
      ip: getClientIp(req),
      userAgent: req.headers['user-agent'] || '',
      geo: null,
      sessionId: req.session?.id || null,
      timestamp: Date.now()
    });
  } catch (err) {
    console.warn('[Audit] write failed:', err.message);
  }
}

function issuePreAuthCsrf() {
  const csrfToken = randomToken(32);
  csrfPreAuth.set(csrfToken, Date.now() + CSRF_TTL_MS);
  return csrfToken;
}

function checkPreAuthCsrf(req) {
  const token = req.headers['x-csrf-token'];
  const expires = csrfPreAuth.get(token);
  if (!token || !expires || expires < Date.now()) return false;
  csrfPreAuth.delete(token);
  return true;
}

async function authenticate(req, res, next) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7) : '';
  const session = sessions.get(token);
  if (!session || session.expiresAt < Date.now() || latestSessionByUid.get(session.uid) !== token) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  req.session = session;
  req.user = { uid: session.uid, email: session.email, role: session.role };
  next();
}

function requireCsrf(req, res, next) {
  if (req.method === 'GET') return next();
  if (req.headers['x-csrf-token'] !== req.session?.csrfToken) {
    return res.status(403).json({ error: 'Bad CSRF token' });
  }
  next();
}

function requireRoles(...roles) {
  return (req, res, next) => {
    if (!hasRole(req.user.role, roles)) return res.status(403).json({ error: 'Forbidden role' });
    next();
  };
}

async function findUserByEmail(email) {
  const normalized = String(email || '').trim().toLowerCase();
  const snapshot = await db.collection('users').where('email', '==', normalized).limit(1).get();
  if (!snapshot.empty) return { id: snapshot.docs[0].id, ...snapshot.docs[0].data() };

  if (normalized && normalized === String(process.env.ADMIN_EMAIL || '').trim().toLowerCase()) {
    return {
      id: 'env-admin',
      uid: process.env.ADMIN_UID || 'env-admin',
      email: normalized,
      role: 'admin',
      passwordHash: process.env.ADMIN_PASSWORD_HASH || '',
      password: process.env.ADMIN_PASSWORD || ''
    };
  }
  return null;
}

async function verifyPassword(user, password) {
  if (user.passwordHash) return bcrypt.compare(String(password || ''), user.passwordHash);
  if (user.password && process.env.NODE_ENV !== 'production') return String(password || '') === String(user.password);
  return false;
}

app.get('/api/csrf', (req, res) => {
  res.json({ csrfToken: issuePreAuthCsrf() });
});

app.get('/api/config', (req, res) => {
  res.json({ vapidPublicKey: VAPID_PUBLIC_KEYS[0] || '' });
});

app.post('/api/auth/login', async (req, res) => {
  if (!checkPreAuthCsrf(req)) return res.status(403).json({ error: 'Bad CSRF token' });

  const email = stripHtml(req.body.email || '').toLowerCase();
  const password = String(req.body.password || '');
  const user = await findUserByEmail(email);
  const ok = user && ['admin', 'manager', 'waiter', 'chef'].includes(user.role) && await verifyPassword(user, password);

  if (!ok) {
    await writeAudit(req, 'login_failed', email, null, false);
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const uid = user.uid || user.id;
  const oldToken = latestSessionByUid.get(uid);
  if (oldToken) sessions.delete(oldToken);

  const token = randomToken(48);
  const session = {
    id: randomToken(18),
    uid,
    email,
    role: user.role,
    csrfToken: randomToken(32),
    expiresAt: Date.now() + SESSION_TTL_MS
  };
  sessions.set(token, session);
  latestSessionByUid.set(uid, token);
  req.session = session;
  req.user = { uid, email, role: user.role };
  await writeAudit(req, 'login_success', email, null, true);

  res.json({
    token,
    csrfToken: session.csrfToken,
    sessionId: session.id,
    user: { uid, email, role: user.role },
    expiresAt: session.expiresAt
  });
});

app.post('/api/auth/logout', authenticate, requireCsrf, async (req, res) => {
  const token = req.headers.authorization.slice(7);
  sessions.delete(token);
  if (latestSessionByUid.get(req.user.uid) === token) latestSessionByUid.delete(req.user.uid);
  await writeAudit(req, 'logout', req.user.email);
  res.json({ ok: true });
});

app.get('/api/auth/me', authenticate, (req, res) => {
  res.json({ user: req.user, sessionId: req.session.id, csrfToken: req.session.csrfToken, expiresAt: req.session.expiresAt });
});

app.use('/api/collection', authenticate, requireCsrf);

app.get('/api/collection/:name', requireRoles('admin', 'manager', 'waiter', 'chef'), async (req, res) => {
  const { name } = req.params;
  if (!allowedCollections.has(name)) return res.status(404).json({ error: 'Unknown collection' });

  let ref = db.collection(name);
  if (req.query.whereField) {
    const value = req.query.whereValueJson ? JSON.parse(req.query.whereValueJson) : req.query.whereValue;
    ref = ref.where(req.query.whereField, req.query.whereOp || '==', value);
  }
  if (req.query.orderField) ref = ref.orderBy(req.query.orderField, req.query.orderDir === 'asc' ? 'asc' : 'desc');
  if (req.query.limit) ref = ref.limit(Math.min(parseInt(req.query.limit, 10) || 50, 500));

  const snapshot = await ref.get();
  res.json({ items: snapshot.docs.map(doc => ({ id: doc.id, ...doc.data() })) });
});

app.post('/api/collection/:name', requireRoles('admin', 'manager'), async (req, res) => {
  const { name } = req.params;
  if (!allowedCollections.has(name)) return res.status(404).json({ error: 'Unknown collection' });
  const data = validateCollectionPayload(name, req.body, false);
  if (name === 'audit_logs') {
    await writeAudit(req, data.action || 'client_audit', data.details || '', data.targetId || null);
    return res.json({ id: null });
  }
  const doc = await db.collection(name).add(data);
  await writeAudit(req, `${name}_create`, '', doc.id);
  res.status(201).json({ id: doc.id });
});

app.patch('/api/collection/:name/:id', requireRoles('admin', 'manager', 'waiter'), async (req, res) => {
  const { name, id } = req.params;
  if (!allowedCollections.has(name) || name === 'audit_logs') return res.status(404).json({ error: 'Unknown collection' });
  const data = validateCollectionPayload(name, req.body, true);
  await db.collection(name).doc(id).update(data);
  await writeAudit(req, `${name}_update`, '', id);
  res.json({ ok: true });
});

app.delete('/api/collection/:name/:id', requireRoles('admin', 'manager'), async (req, res) => {
  const { name, id } = req.params;
  if (!allowedCollections.has(name) || name === 'audit_logs') return res.status(404).json({ error: 'Unknown collection' });
  await db.collection(name).doc(id).delete();
  await writeAudit(req, `${name}_delete`, '', id);
  res.json({ ok: true });
});

app.post('/api/batch', authenticate, requireCsrf, requireRoles('admin', 'manager'), async (req, res) => {
  const batch = db.batch();
  const deletes = Array.isArray(req.body.deletes) ? req.body.deletes : [];
  for (const item of deletes) {
    if (!allowedCollections.has(item.collection) || item.collection === 'audit_logs') continue;
    batch.delete(db.collection(item.collection).doc(item.id));
  }
  await batch.commit();
  await writeAudit(req, 'batch_delete', `deleted ${deletes.length} docs`);
  res.json({ ok: true });
});

const subscriptions = new Map();

app.post('/api/subscribe', authenticate, requireCsrf, requireRoles('admin', 'manager', 'waiter', 'chef'), (req, res) => {
  const sub = sanitizePlainObject(req.body);
  if (!sub || typeof sub.endpoint !== 'string' || !sub.endpoint.startsWith('https://')) {
    return res.status(400).json({ error: 'Invalid subscription object' });
  }
  subscriptions.set(sub.endpoint, sub);
  res.status(200).json({ success: true });
});

function trustedNotifyRequest(req) {
  const ip = getClientIp(req);
  const authHeader = req.headers.authorization || '';
  return INTERNAL_TOKEN.length >= 32 &&
    authHeader === `Bearer ${INTERNAL_TOKEN}` &&
    NOTIFY_TRUSTED_IPS.includes(ip);
}

app.post('/api/notify', async (req, res) => {
  if (!trustedNotifyRequest(req)) return res.status(403).json({ error: 'Forbidden' });
  const { title, body, action } = sanitizePlainObject(req.body);
  if (!title) return res.status(400).json({ error: 'title required' });
  await sendPushToAll(title, body || '', action || '');
  res.status(200).json({ sent: subscriptions.size });
});

async function sendPushToAll(title, body, action) {
  if (!subscriptions.size || !VAPID_PUBLIC_KEYS[0] || !VAPID_PRIVATE_KEY) return;
  const payload = JSON.stringify({ title, body, action, icon: '/icon.svg' });
  const sends = [];
  for (const [endpoint, sub] of subscriptions) {
    sends.push(webpush.sendNotification(sub, payload).catch(err => {
      if (err.statusCode === 410 || err.statusCode === 404) subscriptions.delete(endpoint);
      else console.warn('[Push] send failed:', err.message);
    }));
  }
  await Promise.allSettled(sends);
}

app.get('/health', (req, res) => res.json({ ok: true, subscribers: subscriptions.size }));

function startServer() {
  const keyPath = process.env.HTTPS_KEY_PATH;
  const certPath = process.env.HTTPS_CERT_PATH;
  if (keyPath && certPath) {
    https.createServer({
      key: fs.readFileSync(keyPath),
      cert: fs.readFileSync(certPath)
    }, app).listen(PORT, () => {
      console.log(`HTTPS API server listening on port ${PORT}`);
      console.log(`Allowed origin: ${ALLOWED_ORIGIN}`);
    });
    return;
  }

  if (process.env.REQUIRE_HTTPS === 'true') {
    throw new Error('HTTPS_KEY_PATH and HTTPS_CERT_PATH are required when REQUIRE_HTTPS=true');
  }

  http.createServer(app).listen(PORT, () => {
    console.warn(`HTTP API server listening on port ${PORT}. Use HTTPS behind Nginx/Let's Encrypt in production.`);
    console.log(`Allowed origin: ${ALLOWED_ORIGIN}`);
  });
}

startServer();

setInterval(() => {
  const now = Date.now();
  for (const [key, expires] of csrfPreAuth) if (expires < now) csrfPreAuth.delete(key);
  for (const [token, session] of sessions) {
    if (session.expiresAt < now) {
      sessions.delete(token);
      if (latestSessionByUid.get(session.uid) === token) latestSessionByUid.delete(session.uid);
    }
  }
}, 60 * 1000).unref();
