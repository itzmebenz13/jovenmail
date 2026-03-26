const express  = require('express');
const cron     = require('node-cron');
const crypto   = require('crypto');
const { createClient } = require('@supabase/supabase-js');
const { getAuthUrl, saveToken, fetchEmails, registerWatch } = require('./gmail');
require('dotenv').config();

const app = express();
app.use(express.json());

// ── CORS ──
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').map(o => o.trim()).filter(Boolean);
app.use(function(req, res, next) {
  const origin = req.headers['origin'] || '';
  if (!ALLOWED_ORIGINS.length || ALLOWED_ORIGINS.includes(origin)) {
    res.header('Access-Control-Allow-Origin', origin || '*');
  }
  res.header('Access-Control-Allow-Headers', 'Content-Type');
  res.header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ════════════════════════════════════════════════════════════
// ── RATE LIMITING CONFIG ──
// Block durations (minutes): 1 invalid → 1h, 2 → 24h, 3 → permanent
// ════════════════════════════════════════════════════════════
const BLOCK_DURATIONS = [60, 1440, Infinity]; // 1h → 24h → permanent
const MAX_ATTEMPTS    = 1; // 1 invalid attempt = first block level

// Per-minute burst guard (in-memory)
// { [ipHash]: { count, windowStart } }
const burstMap = {};
const BURST_LIMIT  = 5;
const BURST_WINDOW = 60 * 1000;

// Progressive response delays (ms)
const PROG_DELAYS = [1000, 3000, 5000];

// ════════════════════════════════════════════════════════════
// ── HELPERS ──
// ════════════════════════════════════════════════════════════

function hashIP(ip) {
  const salt = process.env.IP_HASH_SALT || 'joven_salt_changeme_in_env';
  return crypto.createHash('sha256').update(ip + salt).digest('hex');
}

function getRawIP(req) {
  let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  ip = ip.split(',')[0].trim();
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  return ip;
}

function getIPRange(req) {
  const ip = getRawIP(req);
  const parts = ip.split('.');
  if (parts.length === 4) return parts[0] + '.' + parts[1];
  return ip.split(':').slice(0, 4).join(':');
}

// Sentinel key for IP-range row in DB — hashed, never raw
function getIPKey(req) {
  return 'ip:' + hashIP(getIPRange(req));
}

function isBurstBlocked(req) {
  const key = hashIP(getRawIP(req));
  const now = Date.now();
  const e   = burstMap[key];
  if (!e || now - e.windowStart > BURST_WINDOW) {
    burstMap[key] = { count: 1, windowStart: now };
    return false;
  }
  e.count++;
  return e.count > BURST_LIMIT;
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function evaluateRow(row) {
  if (!row) return { blocked: false, attempts: 0 };
  if (row.permanent) return { blocked: true, permanent: true, attempts: row.attempts };
  if (row.blocked_until && new Date(row.blocked_until) > new Date()) {
    const mins = Math.ceil((new Date(row.blocked_until) - new Date()) / 60000);
    return {
      blocked: true,
      message: 'Too many failed attempts. Try again in ' + (mins >= 60 ? Math.ceil(mins/60) + ' hour(s)' : mins + ' minute(s)') + '.',
      attempts: row.attempts
    };
  }
  return { blocked: false, attempts: row.attempts || 0 };
}

function stricter(a, b) {
  if (!a && !b) return null;
  if (!a) return b;
  if (!b) return a;
  if (a.permanent) return a;
  if (b.permanent) return b;
  return (a.block_level || 0) >= (b.block_level || 0) ? a : b;
}

// ════════════════════════════════════════════════════════════
// ── ACCESS PATTERN MONITOR ──
// Tracks per-alias: unique sessions, unique IP hashes, hit frequency
// Returns a suspicion score 0–100
// ════════════════════════════════════════════════════════════
const accessMap = {};

function recordAccess(alias, sessionId, ipHash) {
  const now = Date.now();
  if (!accessMap[alias]) {
    accessMap[alias] = { sessions: new Set(), ips: new Set(), hits: [] };
  }
  const e = accessMap[alias];
  e.sessions.add(sessionId);
  e.ips.add(ipHash);
  e.hits = e.hits.filter(h => now - h < 10 * 60 * 1000);
  e.hits.push(now);

  let score = 0;
  if (e.sessions.size > 10) score += 30;
  else if (e.sessions.size > 5) score += 15;
  if (e.ips.size > 8) score += 25;
  else if (e.ips.size > 4) score += 12;
  if (e.hits.length > 60) score += 30;
  else if (e.hits.length > 30) score += 15;
  else if (e.hits.length > 15) score += 5;

  return Math.min(score, 100);
}

function stealthDelay(score) {
  if (score < 20) return 0;
  if (score < 50) return PROG_DELAYS[0];
  if (score < 80) return PROG_DELAYS[1];
  return PROG_DELAYS[2];
}

// Sweep stale entries every 30 min
setInterval(() => {
  const now = Date.now();
  for (const alias of Object.keys(accessMap)) {
    const e = accessMap[alias];
    e.hits = e.hits.filter(h => now - h < 10 * 60 * 1000);
    if (e.hits.length === 0) delete accessMap[alias];
  }
}, 30 * 60 * 1000);

// ════════════════════════════════════════════════════════════
// ── INBOX TTL — 15-minute inactivity expiry ──
// ════════════════════════════════════════════════════════════
const inboxLastSeen = {};
const INBOX_TTL = 15 * 60 * 1000;

function touchInbox(alias) { inboxLastSeen[alias] = Date.now(); }
function isInboxExpired(alias) {
  const t = inboxLastSeen[alias];
  return t ? Date.now() - t > INBOX_TTL : false;
}

// ════════════════════════════════════════════════════════════
// ── AUTH ──
// ════════════════════════════════════════════════════════════
app.get('/auth/login', (req, res) => res.redirect(getAuthUrl()));

app.get('/auth/callback', async (req, res) => {
  await saveToken(req.query.code);
  await registerWatch();
  res.send('Gmail connected! You can close this tab.');
});

// ════════════════════════════════════════════════════════════
// ── GMAIL PUSH ──
// ════════════════════════════════════════════════════════════
app.post('/gmail/push', async (req, res) => {
  res.sendStatus(200);
  try {
    const data = req.body?.message?.data;
    if (!data) return;
    const emails = await fetchEmails(10);
    if (!emails.length) return;
    const { error } = await supabase
      .from('emails')
      .upsert(emails, { onConflict: 'gmail_id', ignoreDuplicates: true });
    if (error) console.error('Supabase upsert error:', JSON.stringify(error));
    else console.log(`[PUSH] Synced ${emails.length} email(s)`);
  } catch (e) {
    console.error('Push handler error:', e.message);
  }
});

// ════════════════════════════════════════════════════════════
// ── CRON JOBS ──
// ════════════════════════════════════════════════════════════
cron.schedule('0 0 */6 * *', async () => {
  try { await registerWatch(); console.log('Gmail watch refreshed'); }
  catch (e) { console.error('Watch refresh error:', e.message); }
});

// Daily reset for non-permanent blocks older than 24h
cron.schedule('0 0 * * *', async () => {
  try {
    const yesterday = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { error } = await supabase
      .from('recovery_attempts')
      .update({ attempts: 0, blocked_until: null })
      .eq('permanent', false)
      .lt('last_attempt', yesterday);
    if (error) console.error('Daily reset error:', JSON.stringify(error));
    else console.log('[CRON] Daily recovery_attempts reset complete');
  } catch (e) {
    console.error('Daily reset cron error:', e.message);
  }
});

// ════════════════════════════════════════════════════════════
// ── CHECK-BLOCK ──
// ════════════════════════════════════════════════════════════
app.post('/api/check-block', async function(req, res) {
  try {
    const fp    = (req.body.fp || '').trim();
    const ipKey = getIPKey(req);
    if (!fp) return res.status(400).json({ blocked: false });

    if (isBurstBlocked(req)) {
      await sleep(PROG_DELAYS[1]);
      return res.json({ blocked: false, attempts: 0 }); // stealth
    }

    const [{ data: fpRow }, { data: ipRow }] = await Promise.all([
      supabase.from('recovery_attempts').select('*').eq('fingerprint', fp).maybeSingle(),
      supabase.from('recovery_attempts').select('*').eq('fingerprint', ipKey).maybeSingle()
    ]);

    const row  = stricter(fpRow, ipRow);
    const eval_ = evaluateRow(row);

    if (eval_.blocked) {
      // Stealth soft-ban: mask it
      await sleep(2000 + Math.random() * 3000);
      return res.json({ blocked: false, attempts: 0 });
    }

    return res.json(eval_);
  } catch (e) {
    console.error('check-block error:', e);
    res.json({ blocked: false, attempts: 0 });
  }
});

// ════════════════════════════════════════════════════════════
// ── VALIDATE-EMAIL ──
// Core gate: validates alias existence, enforces all limits,
// records failures, applies invisible degradation for abusers.
// ════════════════════════════════════════════════════════════
app.post('/api/validate-email', async function(req, res) {
  try {
    const fp    = (req.body.fp    || '').trim();
    const sid   = (req.body.sid   || fp).trim();
    const alias = (req.body.alias || '').trim().toLowerCase();
    const ipKey = getIPKey(req);
    const ipHash = hashIP(getRawIP(req));

    if (!fp || !alias) return res.status(400).json({ valid: false, error: 'Missing params' });

    // 1. Burst guard
    if (isBurstBlocked(req)) {
      await sleep(PROG_DELAYS[1]);
      return res.json({ valid: false, reason: 'no_emails', remainingAttempts: 3 });
    }

    // 2. Format check
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(alias)) {
      return res.json({ valid: false, reason: 'invalid_format' });
    }

    // 3. DB block check
    const [{ data: fpRow }, { data: ipRow }] = await Promise.all([
      supabase.from('recovery_attempts').select('*').eq('fingerprint', fp).maybeSingle(),
      supabase.from('recovery_attempts').select('*').eq('fingerprint', ipKey).maybeSingle()
    ]);

    const worst = stricter(fpRow, ipRow);
    const blockEval = evaluateRow(worst);

    if (blockEval.blocked) {
      // STEALTH: simulate normal invalid response, never reveal ban
      await sleep(2000 + Math.random() * 3000);
      return res.json({ valid: false, reason: 'no_emails', remainingAttempts: 0 });
    }

    // 4. Mailbox lookup
    const atIdx    = alias.indexOf('@');
    const user     = alias.slice(0, atIdx);
    const domain   = alias.slice(atIdx + 1);
    const baseUser = user.replace(/\./g, '');
    const isGmail  = domain === 'gmail.com' || domain === 'googlemail.com';

    let hasEmails = false;

    if (isGmail) {
      const { data: candidates, error: candErr } = await supabase
        .from('emails').select('id, alias').ilike('alias', '%@' + domain).limit(500);
      if (candErr) return res.status(500).json({ valid: false, error: 'Database error' });
      hasEmails = (candidates || []).some(r => {
        if (!r.alias) return false;
        const p = r.alias.toLowerCase().split('@');
        return p.length === 2 && p[1] === domain && p[0].replace(/\./g, '') === baseUser;
      });
    } else {
      const { data: rows, error: rowErr } = await supabase
        .from('emails').select('id').eq('alias', alias).limit(1);
      if (rowErr) return res.status(500).json({ valid: false, error: 'Database error' });
      hasEmails = !!(rows && rows.length > 0);
    }

    // 5. Invalid alias — record attempt with escalating blocks
    if (!hasEmails) {
      const now = new Date();

      async function recordAttempt(key, existingRow) {
        if (existingRow?.permanent) return existingRow;

        let newAttempts  = (existingRow?.attempts || 0) + 1;
        let newLevel     = existingRow?.block_level || 0;
        let blockedUntil = null;
        let permanent    = false;

        // Each invalid attempt escalates the block level
        // 1 attempt → 1h, 2 → 24h, 3 → permanent
        newLevel = newAttempts; // level mirrors attempt count
        newAttempts = newAttempts; // keep for reference

        const dur = BLOCK_DURATIONS[Math.min(newLevel - 1, BLOCK_DURATIONS.length - 1)];
        if (!isFinite(dur)) {
          permanent    = true;
          blockedUntil = null;
        } else {
          blockedUntil = new Date(now.getTime() + dur * 60000).toISOString();
        }

        const payload = { attempts: newAttempts, block_level: newLevel, blocked_until: blockedUntil, permanent, last_attempt: now.toISOString() };

        if (existingRow) {
          await supabase.from('recovery_attempts').update(payload).eq('fingerprint', key);
        } else {
          await supabase.from('recovery_attempts').insert(Object.assign({ fingerprint: key }, payload));
        }
        return { ...payload };
      }

      const [updFp, updIp] = await Promise.all([
        recordAttempt(fp, fpRow),
        recordAttempt(ipKey, ipRow)
      ]);

      const updated    = stricter(updFp, updIp);
      const nowBlocked = updated && evaluateRow(updated).blocked;
      const remaining  = nowBlocked ? 0 : Math.max(0, 3 - (updated?.attempts || 1));

      // Stealth delay based on attempt number
      const attemptNum = updated?.attempts || 1;
      const delay = attemptNum >= 3 ? PROG_DELAYS[2] : attemptNum >= 2 ? PROG_DELAYS[1] : PROG_DELAYS[0];
      await sleep(delay);

      if (nowBlocked) {
        // Mask the block
        return res.json({ valid: false, reason: 'no_emails', remainingAttempts: 0 });
      }

      return res.json({ valid: false, reason: 'no_emails', remainingAttempts: remaining });
    }

    // 6. Valid alias — access monitoring + suspicious degradation
    const score = recordAccess(alias, sid, ipHash);
    touchInbox(alias);

    // Reset FP attempt counter on success
    if (fpRow && !fpRow.permanent) {
      await supabase.from('recovery_attempts').update({
        attempts: 0, block_level: 0, blocked_until: null, permanent: false,
        last_attempt: new Date().toISOString()
      }).eq('fingerprint', fp);
    }

    const delay = stealthDelay(score);
    if (delay > 0) await sleep(delay);

    return res.json({
      valid: true,
      _s: score > 50 ? 1 : 0 // stealth flag: client should slow refresh
    });

  } catch (e) {
    console.error('validate-email error:', e);
    return res.status(500).json({ valid: false, error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════
// ── INBOX-ACCESS ──
// Called when fetching inbox. Applies TTL and suspicion degradation.
// ════════════════════════════════════════════════════════════
app.post('/api/inbox-access', async function(req, res) {
  try {
    const alias  = (req.body.alias || '').trim().toLowerCase();
    const sid    = (req.body.sid   || '').trim();
    const ipHash = hashIP(getRawIP(req));

    if (!alias) return res.status(400).json({ ok: false });

    if (isBurstBlocked(req)) {
      await sleep(PROG_DELAYS[1]);
      return res.json({ ok: true, degrade: false });
    }

    const expired = isInboxExpired(alias);
    touchInbox(alias);

    const score = recordAccess(alias, sid, ipHash);
    const delay = stealthDelay(score);
    if (delay > 0) await sleep(delay);

    return res.json({
      ok: true,
      degrade:   score > 50,
      empty:     expired && score > 60, // TTL expired + suspicious → appear empty
      refreshMs: score > 50 ? 30000 : 8000
    });
  } catch (e) {
    console.error('inbox-access error:', e);
    res.json({ ok: true, degrade: false });
  }
});

// ════════════════════════════════════════════════════════════
// ── START ──
// ════════════════════════════════════════════════════════════
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
  registerWatch().catch(e => console.error('Initial watch error:', e.message));
});
