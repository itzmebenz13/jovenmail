const express  = require('express');
const cron     = require('node-cron');
const crypto   = require('crypto');
const bcrypt   = require('bcryptjs');
const { createClient } = require('@supabase/supabase-js');
const {
  loadAllAccounts, getAuthUrl, saveToken, fetchEmails,
  registerWatch, registerAllWatches, scheduleFetch,
  listAccounts, removeAccount
} = require('./gmail');
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
  res.header('Access-Control-Allow-Headers', 'Content-Type, x-admin-secret');
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
//
// Block escalation per fingerprint/IP (tracked separately):
//   1st invalid attempt  → blocked_until = now + 1h,  block_level = 1
//   2nd invalid attempt  → blocked_until = now + 24h, block_level = 2
//   3rd invalid attempt  → permanent = true,           block_level = 3
//
// KEY DESIGN: attempts counts UP per bad try and is NEVER reset on success.
// block_level is only incremented when a new block is issued.
// blocked_until is checked on EVERY request — if still in future, request
// is treated as blocked regardless of attempts counter.
// ════════════════════════════════════════════════════════════

// block_level → duration in minutes
// Index 0 = level 1 (1st block), index 1 = level 2, index 2 = level 3 (permanent)
const BLOCK_DURATIONS = [60, 1440]; // level 1 → 1h, level 2 → 24h, level 3 → permanent

// Per-minute burst guard (in-memory, resets on process restart)
const burstMap    = {};
const BURST_LIMIT  = 5;
const BURST_WINDOW = 60 * 1000; // 1 minute

// Progressive delays shown to user on invalid attempts (ms)
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
  if (parts.length === 4) return parts[0] + '.' + parts[1]; // /16
  return ip.split(':').slice(0, 4).join(':');                // IPv6 /64
}

// Sentinel fingerprint key for the IP-range row — hashed, never raw IP
function getIPKey(req) {
  return 'ip:' + hashIP(getIPRange(req));
}

// In-memory burst guard: returns true if this IP has exceeded 5 req/min
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

/**
 * Evaluate a DB row and return whether it is currently blocked.
 * Returns { blocked, permanent, message, attemptsUsed }
 *
 * A row is blocked if:
 *   - permanent === true, OR
 *   - blocked_until is set and still in the future
 *
 * This is the ONLY place block status is determined.
 */
function evaluateRow(row) {
  if (!row) return { blocked: false, attemptsUsed: 0 };

  if (row.permanent) {
    return { blocked: true, permanent: true, attemptsUsed: row.attempts };
  }

  if (row.blocked_until) {
    const until = new Date(row.blocked_until);
    if (until > new Date()) {
      const mins    = Math.ceil((until - new Date()) / 60000);
      const timeStr = mins >= 60
        ? Math.ceil(mins / 60) + ' hour(s)'
        : mins + ' minute(s)';
      return {
        blocked: true,
        permanent: false,
        message: 'Too many failed attempts. Try again in ' + timeStr + '.',
        attemptsUsed: row.attempts
      };
    }
    // blocked_until expired — treat as unblocked (will be cleaned up by cron)
  }

  return { blocked: false, attemptsUsed: row.attempts || 0 };
}

/**
 * Pick the stricter of two rows (permanent > higher block_level).
 */
function stricter(a, b) {
  if (!a && !b) return null;
  if (!a) return b;
  if (!b) return a;
  if (a.permanent) return a;
  if (b.permanent) return b;
  // If one is currently blocked and the other isn't, prefer the blocked one
  const aBlocked = a.blocked_until && new Date(a.blocked_until) > new Date();
  const bBlocked = b.blocked_until && new Date(b.blocked_until) > new Date();
  if (aBlocked && !bBlocked) return a;
  if (bBlocked && !aBlocked) return b;
  // Both blocked or both unblocked — pick higher block_level
  return (a.block_level || 0) >= (b.block_level || 0) ? a : b;
}

/**
 * Record ONE failed attempt for a given fingerprint key.
 *
 * Logic (fixes the previous broken version):
 *   - Read existing row (passed in as existingRow)
 *   - Increment attempts counter
 *   - Determine new block_level and blocked_until based on NEW attempt total:
 *       attempts = 1 → block_level 1, blocked 1h
 *       attempts = 2 → block_level 2, blocked 24h
 *       attempts >= 3 → permanent
 *   - NEVER reset attempts on success — only cron resets old rows
 *   - If already permanently blocked, do nothing
 *
 * Returns the saved row payload.
 */
async function recordFailedAttempt(key, existingRow, now) {
  // Already permanently blocked — do nothing, return as-is
  if (existingRow && existingRow.permanent) {
    return existingRow;
  }

  // Increment the total attempt count
  const newAttempts = (existingRow ? existingRow.attempts || 0 : 0) + 1;

  let newBlockLevel  = existingRow ? existingRow.block_level || 0 : 0;
  let newBlockedUntil = null;
  let newPermanent   = false;

  // Determine block based on total attempt count
  if (newAttempts >= 4) {
    // 4th+ invalid → permanent
    newBlockLevel   = 3;
    newPermanent    = true;
    newBlockedUntil = null;
  } else if (newAttempts === 3) {
    // 3rd invalid → 24h
    newBlockLevel   = 2;
    newBlockedUntil = new Date(now.getTime() + BLOCK_DURATIONS[1] * 60000).toISOString();
  } else if (newAttempts === 2) {
    // 2nd invalid → 1h
    newBlockLevel   = 1;
    newBlockedUntil = new Date(now.getTime() + BLOCK_DURATIONS[0] * 60000).toISOString();
  } else {
    // 1st invalid → warning only, no ban
    newBlockLevel   = 0;
    newBlockedUntil = null;
  }

  const payload = {
    attempts:      newAttempts,
    block_level:   newBlockLevel,
    blocked_until: newBlockedUntil,
    permanent:     newPermanent,
    last_attempt:  now.toISOString()
  };

  if (existingRow) {
    await supabase
      .from('recovery_attempts')
      .update(payload)
      .eq('fingerprint', key);
  } else {
    await supabase
      .from('recovery_attempts')
      .insert(Object.assign({ fingerprint: key }, payload));
  }

  return payload;
}

// ════════════════════════════════════════════════════════════
// ── ACCESS PATTERN MONITOR ──
// Per-alias tracking: unique sessions, IPs, hit frequency
// Returns suspicion score 0–100
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

// Sweep stale access entries every 30 min
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
// ── AUTH — multi-account: ?account=user@gmail.com ──
app.get('/auth/login', (req, res) => {
  // Require admin secret for security
  const secret = req.query.secret || req.headers['x-admin-secret'] || '';
  if (process.env.ADMIN_SECRET && secret !== process.env.ADMIN_SECRET) {
    return res.status(401).send('Unauthorized — include ?secret=ADMIN_SECRET in the URL');
  }
  const accountEmail = (req.query.account || '').trim().toLowerCase() || undefined;
  res.redirect(getAuthUrl(accountEmail));
});

app.get('/auth/callback', async (req, res) => {
  try {
    // ?state= carries the accountEmail set in getAuthUrl()
    const accountEmail = (req.query.state || '').trim().toLowerCase() || undefined;
    const savedEmail = await saveToken(req.query.code, accountEmail);
    await registerWatch(savedEmail);
    res.send(`
      <html><body style="font-family:sans-serif;text-align:center;padding:60px;">
        <h2 style="color:#22c55e">✓ ${savedEmail} connected!</h2>
        <p>Gmail account added successfully. You can close this tab.</p>
      </body></html>
    `);
  } catch (e) {
    console.error('auth/callback error:', e.message);
    res.status(500).send('Authentication failed: ' + e.message);
  }
});

// ════════════════════════════════════════════════════════════
// ── GMAIL PUSH ──
// ════════════════════════════════════════════════════════════
// ── GMAIL PUSH — Option A: ?account=user@gmail.com identifies the source ──
app.post('/gmail/push', async (req, res) => {
  res.sendStatus(200); // acknowledge immediately
  try {
    const data = req.body?.message?.data;
    if (!data) return;

    // Which Gmail account triggered this push?
    const accountEmail = (req.query.account || '').trim().toLowerCase();
    if (!accountEmail) {
      console.warn('[PUSH] No ?account= param — cannot route push notification');
      return;
    }

    // Debounce: schedule a fetch for this account (handles rate-limit backoff)
    scheduleFetch(accountEmail, async (emails) => {
      if (!emails.length) return;
      const { error } = await supabase
        .from('emails')
        .upsert(emails, { onConflict: 'gmail_id', ignoreDuplicates: true });
      if (error) console.error('[PUSH] Supabase upsert error:', JSON.stringify(error));
      else console.log(`[PUSH] Synced ${emails.length} email(s) for ${accountEmail}`);
    });
  } catch (e) {
    console.error('[PUSH] Handler error:', e.message);
  }
});

// ════════════════════════════════════════════════════════════
// ── CRON JOBS ──
// ════════════════════════════════════════════════════════════
// Refresh watches for ALL Gmail accounts every 6 hours
cron.schedule('0 0 */6 * *', async () => {
  try {
    await registerAllWatches();
    console.log('[CRON] All Gmail watches refreshed');
  } catch (e) {
    console.error('[CRON] Watch refresh error:', e.message);
  }
});

// Daily cleanup: clear expired (non-permanent) blocks older than 24h
// This only clears rows whose block has already naturally expired
cron.schedule('0 0 * * *', async () => {
  try {
    const now = new Date().toISOString();
    const { error } = await supabase
      .from('recovery_attempts')
      .update({ attempts: 0, block_level: 0, blocked_until: null })
      .eq('permanent', false)
      .lt('blocked_until', now); // only rows whose block has already expired
    if (error) console.error('Daily reset error:', JSON.stringify(error));
    else console.log('[CRON] Expired blocks cleared');
  } catch (e) {
    console.error('Daily reset cron error:', e.message);
  }
});

// ════════════════════════════════════════════════════════════
// ── CHECK-BLOCK ──
// Pre-flight check called before the recovery form is submitted.
// Returns the real block status — does NOT mask it here since this
// is used to show warnings to the user before they waste an attempt.
// ════════════════════════════════════════════════════════════
app.post('/api/check-block', async function(req, res) {
  try {
    const fp    = (req.body.fp || '').trim();
    const ipKey = getIPKey(req);
    if (!fp) return res.status(400).json({ blocked: false });

    // Burst guard — mask silently (don't waste a DB round-trip)
    if (isBurstBlocked(req)) {
      await sleep(PROG_DELAYS[1]);
      return res.json({ blocked: false, attempts: 0 });
    }

    const [{ data: fpRow }, { data: ipRow }] = await Promise.all([
      supabase.from('recovery_attempts').select('*').eq('fingerprint', fp).maybeSingle(),
      supabase.from('recovery_attempts').select('*').eq('fingerprint', ipKey).maybeSingle()
    ]);

    const row   = stricter(fpRow, ipRow);
    const eval_ = evaluateRow(row);

    // Return real block status — client uses this to show a warning
    return res.json({
      blocked:         eval_.blocked,
      permanent:       eval_.permanent || false,
      message:         eval_.message || null,
      attemptsUsed:    eval_.attemptsUsed || 0
    });

  } catch (e) {
    console.error('check-block error:', e);
    res.json({ blocked: false, attemptsUsed: 0 });
  }
});

// ════════════════════════════════════════════════════════════
// ── VALIDATE-EMAIL ──
//
// This is the main gate. It:
//   1. Checks burst guard (in-memory, 5/min)
//   2. Checks DB block status for both fingerprint + IP range
//   3. Looks up the alias in Supabase
//   4. If invalid: records the attempt (escalates block), returns error
//   5. If valid: records inbox access for pattern monitoring, returns success
//
// IMPORTANT: blocked users get the REAL block message returned here.
// The stealth masking only applies to the CHECK-BLOCK endpoint (pre-flight).
// This endpoint MUST tell the user they are blocked so they stop trying.
// ════════════════════════════════════════════════════════════
app.post('/api/validate-email', async function(req, res) {
  try {
    const fp     = (req.body.fp    || '').trim();
    const sid    = (req.body.sid   || fp).trim();
    const alias  = (req.body.alias || '').trim().toLowerCase();
    const ipKey  = getIPKey(req);
    const ipHash = hashIP(getRawIP(req));

    if (!fp || !alias) {
      return res.status(400).json({ valid: false, error: 'Missing params' });
    }

    // ── 1. Burst guard (in-memory, max 5/min per IP) ──
    if (isBurstBlocked(req)) {
      // Don't record an attempt — this is a spam flood, not a real try
      await sleep(PROG_DELAYS[1]);
      return res.json({
        valid:   false,
        blocked: true,
        message: 'Too many requests. Please wait a minute.'
      });
    }

    // ── 2. Format validation ──
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(alias)) {
      return res.json({ valid: false, reason: 'invalid_format' });
    }

    // ── 3. Load both tracking rows from DB ──
    const [{ data: fpRow }, { data: ipRow }] = await Promise.all([
      supabase.from('recovery_attempts').select('*').eq('fingerprint', fp).maybeSingle(),
      supabase.from('recovery_attempts').select('*').eq('fingerprint', ipKey).maybeSingle()
    ]);

    // ── 4. Check if already blocked ──
    const worst     = stricter(fpRow, ipRow);
    const blockEval = evaluateRow(worst);

    if (blockEval.blocked) {
      // User IS blocked — tell them clearly so they stop wasting attempts
      // Add a small delay to slow down automated scripts
      await sleep(2000 + Math.random() * 1000);
      return res.json({
        valid:     false,
        blocked:   true,
        permanent: blockEval.permanent || false,
        message:   blockEval.permanent
          ? 'Your access has been permanently restricted.'
          : blockEval.message
      });
    }

    // ── 5. Allowed-email lookup (admin-managed whitelist) ──
    const atIdx    = alias.indexOf('@');
    const user     = alias.slice(0, atIdx);
    const domain   = alias.slice(atIdx + 1);
    const baseUser = user.replace(/\./g, '');
    const isGmail  = domain === 'gmail.com' || domain === 'googlemail.com';

    let hasEmails  = false;
    let isHoneypot = false;

    // Exact match only — entered email must exist literally in the whitelist
    {
      const { data: rows, error: rowErr } = await supabase
        .from('allowed_emails').select('id, honeypot').eq('email', alias).limit(1);
      if (rowErr) {
        console.error('validate-email DB error:', JSON.stringify(rowErr));
        return res.status(500).json({ valid: false, error: 'Database error' });
      }
      if (rows && rows.length > 0) {
        hasEmails  = true;
        isHoneypot = !!(rows[0].honeypot);
      }
    }

    // ── 5b. HONEYPOT TRAP — alias exists but is marked as a trap ──
    // Real users only recover emails assigned to them — probing unused/trap
    // emails = immediate 12-hour block on both fingerprint and IP.
    if (hasEmails && isHoneypot) {
      const HONEYPOT_MS = 12 * 60 * 60 * 1000; // 12 hours
      const now         = new Date();
      const blockedUntil = new Date(now.getTime() + HONEYPOT_MS).toISOString();
      const honeypotPayload = {
        attempts:      (fpRow ? fpRow.attempts || 0 : 0) + 1,
        block_level:   2,
        blocked_until: blockedUntil,
        permanent:     false,
        last_attempt:  now.toISOString()
      };
      const honeypotIpPayload = {
        attempts:      (ipRow ? ipRow.attempts || 0 : 0) + 1,
        block_level:   2,
        blocked_until: blockedUntil,
        permanent:     false,
        last_attempt:  now.toISOString()
      };
      // Upsert both rows
      await Promise.all([
        fpRow
          ? supabase.from('recovery_attempts').update(honeypotPayload).eq('fingerprint', fp)
          : supabase.from('recovery_attempts').insert(Object.assign({ fingerprint: fp }, honeypotPayload)),
        ipRow
          ? supabase.from('recovery_attempts').update(honeypotIpPayload).eq('fingerprint', ipKey)
          : supabase.from('recovery_attempts').insert(Object.assign({ fingerprint: ipKey }, honeypotIpPayload))
      ]);
      console.log('[HONEYPOT] Trap triggered for alias:', alias, '| fp:', fp.slice(0, 8), '| ip-key:', ipKey.slice(0, 12));
      await sleep(2000 + Math.random() * 1000);
      return res.json({
        valid:     false,
        blocked:   true,
        permanent: false,
        message:   'Too many failed attempts. Try again in 12 hour(s).'
      });
    }

    // ── 6. INVALID alias → record attempt, escalate block ──
    if (!hasEmails) {
      const now = new Date();

      // Record for BOTH fingerprint row AND IP-range row independently
      const [updFp, updIp] = await Promise.all([
        recordFailedAttempt(fp,    fpRow,  now),
        recordFailedAttempt(ipKey, ipRow,  now)
      ]);

      // Pick the stricter updated row to decide what to tell the user
      const updated    = stricter(updFp, updIp);
      const nowBlocked = updated ? evaluateRow(updated).blocked : false;
      // How many attempts remain before the next block (if not yet blocked)
      const remaining  = nowBlocked ? 0 : Math.max(0, 4 - (updated?.attempts || 1));

      // Progressive delay: 1st attempt=1s, 2nd=3s, 3rd+=5s
      const attemptNum = updated?.attempts || 1;
      const delay      = attemptNum >= 4 ? PROG_DELAYS[2]
                       : attemptNum >= 2 ? PROG_DELAYS[1]
                       :                  PROG_DELAYS[0];
      await sleep(delay);

      if (nowBlocked) {
        const newEval = evaluateRow(updated);
        return res.json({
          valid:     false,
          blocked:   true,
          permanent: updated.permanent || false,
          message:   updated.permanent
            ? 'Your access has been permanently restricted.'
            : newEval.message
        });
      }

      return res.json({
        valid:             false,
        blocked:           false,
        reason:            'no_emails',
        remainingAttempts: remaining
      });
    }

    // ── 7. VALID alias → access monitoring, return success ──
    const score = recordAccess(alias, sid, ipHash);
    touchInbox(alias);

    // NOTE: do NOT reset the attempt counter here.
    // A user who guessed correctly after failed attempts should still
    // carry their previous bad-attempt history.

    const delay = stealthDelay(score);
    if (delay > 0) await sleep(delay);

    return await claimOrVerifyOwnership(req, res, alias, fp);

  } catch (e) {
    console.error('validate-email error:', e);
    return res.status(500).json({ valid: false, error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════
// ── INBOX-ACCESS ──
// Called on each inbox fetch. Applies TTL + pattern-based degradation.
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
      ok:        true,
      degrade:   score > 50,
      empty:     expired && score > 60,
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
app.listen(process.env.PORT || 3000, async () => {
  console.log(`Server running on port ${process.env.PORT || 3000}`);
  // Load all Gmail accounts into memory, then register watches
  await loadAllAccounts();
  await registerAllWatches().catch(e => console.error('[START] Watch registration error:', e.message));
});

// ════════════════════════════════════════════════════════════
// ── FETCH-EMAILS ──
// Clients must use this endpoint to read emails.
// Re-checks the allowed_emails whitelist on every request so
// that removing an email from the admin panel immediately
// kills access — even for sessions that already validated.
// Prevents the anon Supabase key from bypassing the whitelist.
// ════════════════════════════════════════════════════════════
app.post('/api/fetch-emails', async function(req, res) {
  try {
    const alias = (req.body.alias || '').trim().toLowerCase();
    const fp    = (req.body.fp    || '').trim();
    const sid   = (req.body.sid   || fp).trim();

    if (!alias || !fp) return res.status(400).json({ ok: false, error: 'Missing params' });
    if (isBurstBlocked(req)) { await sleep(PROG_DELAYS[1]); return res.json({ ok: false, error: 'Too many requests.' }); }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(alias)) return res.status(400).json({ ok: false, error: 'Invalid alias format' });

    const atIdx    = alias.indexOf('@');
    const user     = alias.slice(0, atIdx);
    const domain   = alias.slice(atIdx + 1);
    const baseUser = user.replace(/\./g, '');
    const isGmail  = domain === 'gmail.com' || domain === 'googlemail.com';
    let allowed = false;

    // Exact match only
    {
      const { data: rows, error: rowErr } = await supabase
        .from('allowed_emails').select('id').eq('email', alias).limit(1);
      if (rowErr) { console.error('fetch-emails whitelist error:', JSON.stringify(rowErr)); return res.status(500).json({ ok: false, error: 'Database error' }); }
      allowed = !!(rows && rows.length > 0);
    }

    if (!allowed) return res.status(403).json({ ok: false, error: 'not_allowed' });

    // ── Ban check — blocked fingerprints/IPs cannot fetch emails ──
    const fetchFp    = (req.body.fp || '').trim();
    const fetchIpKey = getIPKey(req);
    if (fetchFp) {
      const [{ data: fetchFpRow }, { data: fetchIpRow }] = await Promise.all([
        supabase.from('recovery_attempts').select('*').eq('fingerprint', fetchFp).maybeSingle(),
        supabase.from('recovery_attempts').select('*').eq('fingerprint', fetchIpKey).maybeSingle()
      ]);
      const fetchBlock = evaluateRow(stricter(fetchFpRow, fetchIpRow));
      if (fetchBlock.blocked) {
        return res.status(403).json({ ok: false, error: 'blocked', permanent: fetchBlock.permanent || false, message: fetchBlock.permanent ? 'Your access has been permanently restricted.' : fetchBlock.message });
      }
    }

    const ipHash = hashIP(getRawIP(req));
    const score  = recordAccess(alias, sid, ipHash);
    touchInbox(alias);
    const delay = stealthDelay(score);
    if (delay > 0) await sleep(delay);

    const { data: emailRows, error: emailErr } = await supabase
      .from('emails')
      .select('id, sender, sender_email, subject, body, received_at, alias, gmail_id')
      .eq('alias', alias)
      .order('received_at', { ascending: false })
      .limit(50);

    if (emailErr) { console.error('fetch-emails query error:', JSON.stringify(emailErr)); return res.status(500).json({ ok: false, error: 'Database error' }); }

    return res.json({ ok: true, emails: emailRows || [], degrade: score > 50, _s: score > 50 ? 1 : 0 });

  } catch (e) {
    console.error('fetch-emails error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════
// ── SESSION OWNERSHIP ──
//
// REQUIRED SUPABASE TABLE:
//
//   CREATE TABLE email_sessions (
//     email           TEXT PRIMARY KEY,
//     owner_fp        TEXT,
//     owner_ip        TEXT,
//     owner_ua        TEXT,
//     claimed_at      TIMESTAMPTZ,
//     pin_hash        TEXT,
//     has_pin         BOOLEAN DEFAULT false,
//     pin_set_at      TIMESTAMPTZ,
//     transferred_at  TIMESTAMPTZ
//   );
//   CREATE INDEX ON email_sessions (has_pin);
//
// ALSO ADD to your .env:
//   ADMIN_SECRET=some_long_random_string_here
// ════════════════════════════════════════════════════════════

function buildOwnerIdentity(req, fp) {
  const ip = hashIP(getRawIP(req));
  const ua = crypto
    .createHash('sha256')
    .update((req.headers['user-agent'] || '') + (process.env.IP_HASH_SALT || ''))
    .digest('hex');
  return { owner_fp: fp, owner_ip: ip, owner_ua: ua };
}

function isOwner(req, fp, row) {
  // Match on fingerprint ONLY.
  // IP and UA can vary between requests (proxy headers, IPv4/IPv6 toggles,
  // CDN routing) even from the same browser, causing false "not owner" results.
  // The browser fingerprint is already a strong multi-signal identifier.
  return row.owner_fp === fp;
}

async function claimOrVerifyOwnership(req, res, alias, fp) {
  const { data: session, error: selErr } = await supabase
    .from('email_sessions')
    .select('*')
    .eq('email', alias)
    .maybeSingle();

  if (selErr) {
    console.error('session lookup error:', selErr);
    return res.status(500).json({ valid: false, error: 'Database error' });
  }

  if (!session) {
    const identity = buildOwnerIdentity(req, fp);
    const { error: insErr } = await supabase
      .from('email_sessions')
      .insert({
        email:      alias,
        owner_fp:   identity.owner_fp,
        owner_ip:   identity.owner_ip,
        owner_ua:   identity.owner_ua,
        claimed_at: new Date().toISOString(),
        has_pin:    false
      });

    if (insErr) {
      const { data: raceRow } = await supabase
        .from('email_sessions')
        .select('*')
        .eq('email', alias)
        .maybeSingle();
      if (raceRow && !isOwner(req, fp, raceRow)) {
        return res.json({
          valid:   false,
          reason:  'session_taken',
          message: 'This inbox is currently in use by another session.'
        });
      }
    }

    return res.json({ valid: true, owner: true, session: 'new' });
  }

  if (isOwner(req, fp, session)) {
    return res.json({ valid: true, owner: true, session: 'active' });
  }

  return res.json({
    valid:   false,
    reason:  'session_active',
    message: 'This inbox is currently claimed by another session. If you have a transfer PIN, use it to claim access.'
  });
}

// ── SET TRANSFER PIN ─────────────────────────────────────────
app.post('/api/set-transfer-pin', async function(req, res) {
  try {
    const fp    = (req.body.fp    || '').trim();
    const alias = (req.body.alias || '').trim().toLowerCase();
    const pin   = (req.body.pin   || '').trim();

    if (!fp || !alias || !pin) return res.status(400).json({ ok: false, error: 'Missing params' });
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ ok: false, error: 'PIN must be exactly 4 digits' });
    if (isBurstBlocked(req)) { await sleep(PROG_DELAYS[1]); return res.json({ ok: false, error: 'Too many requests.' }); }

    const { data: session } = await supabase
      .from('email_sessions').select('*').eq('email', alias).maybeSingle();

    if (!session || !isOwner(req, fp, session)) {
      return res.status(403).json({ ok: false, error: 'Not authorized.' });
    }

    const pinHash = await bcrypt.hash(pin, 8);

    const { error: updErr } = await supabase
      .from('email_sessions')
      .update({ pin_hash: pinHash, has_pin: true, pin_set_at: new Date().toISOString() })
      .eq('email', alias);

    if (updErr) { console.error('set-transfer-pin error:', updErr); return res.status(500).json({ ok: false, error: 'Database error' }); }

    return res.json({ ok: true, message: 'Transfer PIN set. Share the PIN with the person you want to transfer access to.' });
  } catch (e) {
    console.error('set-transfer-pin error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ── CLAIM WITH PIN ───────────────────────────────────────────
const pinAttempts = {};
const PIN_ATTEMPT_LIMIT  = 5;
const PIN_ATTEMPT_WINDOW = 60 * 60 * 1000;

function isPinBlocked(fp) {
  const now = Date.now();
  const e   = pinAttempts[fp];
  if (!e) return false;
  if (now - e.since > PIN_ATTEMPT_WINDOW) { delete pinAttempts[fp]; return false; }
  return e.count >= PIN_ATTEMPT_LIMIT;
}

function recordPinAttempt(fp) {
  const now = Date.now();
  if (!pinAttempts[fp] || now - pinAttempts[fp].since > PIN_ATTEMPT_WINDOW) {
    pinAttempts[fp] = { count: 1, since: now };
  } else {
    pinAttempts[fp].count++;
  }
}

app.post('/api/claim-with-pin', async function(req, res) {
  try {
    const fp    = (req.body.fp    || '').trim();
    const alias = (req.body.alias || '').trim().toLowerCase();
    const pin   = (req.body.pin   || '').trim();

    if (!fp || !alias || !pin) return res.status(400).json({ ok: false, error: 'Missing params' });
    if (!/^\d{4}$/.test(pin)) return res.status(400).json({ ok: false, error: 'Invalid PIN format' });
    if (isBurstBlocked(req)) { await sleep(PROG_DELAYS[1]); return res.json({ ok: false, error: 'Too many requests.' }); }
    if (isPinBlocked(fp)) return res.json({ ok: false, blocked: true, error: 'Too many incorrect PIN attempts. Try again later.' });

    const { data: session } = await supabase
      .from('email_sessions').select('*').eq('email', alias).maybeSingle();

    if (!session || !session.has_pin || !session.pin_hash) {
      await sleep(1500);
      return res.json({ ok: false, error: 'No transfer is available for this inbox.' });
    }

    const match = await bcrypt.compare(pin, session.pin_hash);

    if (!match) {
      recordPinAttempt(fp);
      await sleep(1000 + Math.random() * 500);
      return res.json({ ok: false, error: 'Incorrect PIN.' });
    }

    const newIdentity = buildOwnerIdentity(req, fp);

    const { error: updErr } = await supabase
      .from('email_sessions')
      .update({
        owner_fp:       newIdentity.owner_fp,
        owner_ip:       newIdentity.owner_ip,
        owner_ua:       newIdentity.owner_ua,
        claimed_at:     new Date().toISOString(),
        transferred_at: new Date().toISOString(),
        pin_hash:       null,
        has_pin:        false,
        pin_set_at:     null
      })
      .eq('email', alias);

    if (updErr) { console.error('claim-with-pin error:', updErr); return res.status(500).json({ ok: false, error: 'Database error' }); }

    delete pinAttempts[fp];
    return res.json({ ok: true, message: 'Access transferred. You are now the session owner.' });
  } catch (e) {
    console.error('claim-with-pin error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ── RELEASE SESSION ──────────────────────────────────────────
app.post('/api/release-session', async function(req, res) {
  try {
    const fp    = (req.body.fp    || '').trim();
    const alias = (req.body.alias || '').trim().toLowerCase();

    if (!fp || !alias) return res.status(400).json({ ok: false });
    if (isBurstBlocked(req)) { await sleep(PROG_DELAYS[1]); return res.json({ ok: false, error: 'Too many requests.' }); }

    const { data: session } = await supabase
      .from('email_sessions').select('*').eq('email', alias).maybeSingle();

    if (!session || !isOwner(req, fp, session)) {
      return res.status(403).json({ ok: false, error: 'Not authorized.' });
    }

    await supabase.from('email_sessions').delete().eq('email', alias);
    return res.json({ ok: true, message: 'Session released.' });
  } catch (e) {
    console.error('release-session error:', e);
    return res.status(500).json({ ok: false, error: 'Server error' });
  }
});

// ── ADMIN ENDPOINTS ──────────────────────────────────────────
function requireAdminSecret(req, res, next) {
  const secret = req.headers['x-admin-secret'] || '';
  if (!process.env.ADMIN_SECRET || secret !== process.env.ADMIN_SECRET) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  next();
}

app.get('/api/admin/sessions', requireAdminSecret, async function(req, res) {
  try {
    const { data: rows, error } = await supabase
      .from('email_sessions')
      .select('email, claimed_at, has_pin, pin_set_at, transferred_at')
      .order('claimed_at', { ascending: false });
    if (error) return res.status(500).json({ error: 'Database error' });
    return res.json({ ok: true, sessions: rows || [] });
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.get('/api/admin/sessions/with-pins', requireAdminSecret, async function(req, res) {
  try {
    const { data: rows, error } = await supabase
      .from('email_sessions')
      .select('email, claimed_at, pin_set_at')
      .eq('has_pin', true)
      .order('pin_set_at', { ascending: false });
    if (error) return res.status(500).json({ error: 'Database error' });
    return res.json({ ok: true, sessions: rows || [] });
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/admin/release-session', requireAdminSecret, async function(req, res) {
  try {
    const alias = (req.body.alias || '').trim().toLowerCase();
    if (!alias) return res.status(400).json({ ok: false });
    await supabase.from('email_sessions').delete().eq('email', alias);
    return res.json({ ok: true, message: `Session for ${alias} cleared.` });
  } catch (e) {
    return res.status(500).json({ error: 'Server error' });
  }
});

// ── SESSION CLEANUP CRON ─────────────────────────────────────
// Clears sessions inactive for 24h (no PIN pending)
cron.schedule('0 * * * *', async () => {
  try {
    const cutoff = new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
    const { error } = await supabase
      .from('email_sessions')
      .delete()
      .lt('claimed_at', cutoff)
      .eq('has_pin', false);
    if (error) console.error('[CRON] session cleanup error:', error);
    else console.log('[CRON] Stale sessions cleared');
  } catch (e) {
    console.error('[CRON] session cleanup cron error:', e);
  }
});

// ════════════════════════════════════════════════════════════
// ── ADMIN — FRAUD LOG ──
// Returns all rows from recovery_attempts, ordered by
// attempts desc. Supports ?limit=N&offset=N pagination.
// ════════════════════════════════════════════════════════════
app.get('/api/admin/fraud-log', requireAdminSecret, async function(req, res) {
  try {
    const limit  = Math.min(parseInt(req.query.limit  || '100', 10), 500);
    const offset = parseInt(req.query.offset || '0',   10);

    const { data: rows, error, count } = await supabase
      .from('recovery_attempts')
      .select('*', { count: 'exact' })
      .order('attempts', { ascending: false })
      .range(offset, offset + limit - 1);

    if (error) return res.status(500).json({ error: 'Database error' });

    // Summarise stats
    const all = rows || [];
    return res.json({
      ok:      true,
      total:   count || 0,
      rows:    all,
      stats: {
        permanent:    all.filter(r => r.permanent).length,
        activeBlocks: all.filter(r => !r.permanent && r.blocked_until && new Date(r.blocked_until) > new Date()).length,
        warned:       all.filter(r => !r.permanent && (!r.blocked_until || new Date(r.blocked_until) <= new Date()) && (r.attempts || 0) >= 1).length
      }
    });
  } catch (e) {
    console.error('fraud-log error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════
// ── ADMIN — FRAUD BAN (manual permanent ban) ──
// ════════════════════════════════════════════════════════════
app.post('/api/admin/fraud-ban', requireAdminSecret, async function(req, res) {
  try {
    const key = (req.body.fingerprint || '').trim();
    if (!key) return res.status(400).json({ ok: false, error: 'Missing fingerprint key' });

    const { data: existing } = await supabase
      .from('recovery_attempts').select('*').eq('fingerprint', key).maybeSingle();

    const payload = {
      attempts:      (existing ? existing.attempts || 0 : 0) + 1,
      block_level:   3,
      blocked_until: null,
      permanent:     true,
      last_attempt:  new Date().toISOString()
    };

    if (existing) {
      await supabase.from('recovery_attempts').update(payload).eq('fingerprint', key);
    } else {
      await supabase.from('recovery_attempts').insert(Object.assign({ fingerprint: key }, payload));
    }

    console.log('[ADMIN] Manual permanent ban:', key.slice(0, 16));
    return res.json({ ok: true, message: 'Permanently banned.' });
  } catch (e) {
    console.error('fraud-ban error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════
// ── ADMIN — FRAUD UNBAN (clear all blocks) ──
// ════════════════════════════════════════════════════════════
app.post('/api/admin/fraud-unban', requireAdminSecret, async function(req, res) {
  try {
    const key = (req.body.fingerprint || '').trim();
    if (!key) return res.status(400).json({ ok: false, error: 'Missing fingerprint key' });

    await supabase
      .from('recovery_attempts')
      .update({ attempts: 0, block_level: 0, blocked_until: null, permanent: false })
      .eq('fingerprint', key);

    console.log('[ADMIN] Unbanned:', key.slice(0, 16));
    return res.json({ ok: true, message: 'Block cleared.' });
  } catch (e) {
    console.error('fraud-unban error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════
// ── ADMIN — SET HONEYPOT FLAG ──
// Sets or clears honeypot=true on an allowed_email row.
// ════════════════════════════════════════════════════════════
app.post('/api/admin/set-honeypot', requireAdminSecret, async function(req, res) {
  try {
    const email     = (req.body.email     || '').trim().toLowerCase();
    const honeypot  = req.body.honeypot === true || req.body.honeypot === 'true';

    if (!email) return res.status(400).json({ ok: false, error: 'Missing email' });

    const { error } = await supabase
      .from('allowed_emails')
      .update({ honeypot: honeypot })
      .eq('email', email);

    if (error) { console.error('set-honeypot error:', error); return res.status(500).json({ ok: false, error: 'Database error' }); }

    console.log('[ADMIN] Honeypot', honeypot ? 'SET' : 'CLEARED', 'for:', email);
    return res.json({ ok: true, honeypot });
  } catch (e) {
    console.error('set-honeypot error:', e);
    return res.status(500).json({ error: 'Server error' });
  }
});

// ════════════════════════════════════════════════════════════
// ── ADMIN — GMAIL ACCOUNTS ──
// List, connect, and remove Gmail accounts for multi-account routing.
// ════════════════════════════════════════════════════════════

/**
 * GET /api/admin/gmail-accounts
 * Returns all connected Gmail accounts with their watch status.
 */
app.get('/api/admin/gmail-accounts', requireAdminSecret, async function(req, res) {
  try {
    const accounts = await listAccounts();
    // Enrich with alias counts
    const emailsResult = await supabase
      .from('allowed_emails')
      .select('gmail_account');
    const emailRows = emailsResult.data || [];
    const aliasCounts = {};
    for (const row of emailRows) {
      if (row.gmail_account) {
        aliasCounts[row.gmail_account] = (aliasCounts[row.gmail_account] || 0) + 1;
      }
    }
    const now = new Date();
    const enriched = accounts.map(acc => ({
      email:         acc.email,
      watch_expiry:  acc.watch_expiry,
      watch_active:  acc.watch_expiry ? new Date(acc.watch_expiry) > now : false,
      alias_count:   aliasCounts[acc.email] || 0,
      added_at:      acc.added_at
    }));
    return res.json({ ok: true, accounts: enriched });
  } catch (e) {
    console.error('admin/gmail-accounts error:', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * GET /api/admin/gmail-connect-url?account=user@gmail.com
 * Returns an OAuth URL the admin opens to connect a new Gmail account.
 */
app.get('/api/admin/gmail-connect-url', requireAdminSecret, async function(req, res) {
  try {
    const accountEmail = (req.query.account || '').trim().toLowerCase();
    if (!accountEmail || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(accountEmail)) {
      return res.status(400).json({ ok: false, error: 'Provide a valid Gmail address as ?account=' });
    }
    // Embed admin secret in the login URL so the callback is also protected
    const baseUrl = process.env.RAILWAY_PUBLIC_DOMAIN
      ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}`
      : 'http://localhost:3000';
    const loginUrl = `${baseUrl}/auth/login?account=${encodeURIComponent(accountEmail)}&secret=${encodeURIComponent(process.env.ADMIN_SECRET || '')}`;
    return res.json({ ok: true, url: loginUrl, account: accountEmail });
  } catch (e) {
    console.error('admin/gmail-connect-url error:', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * POST /api/admin/gmail-accounts/remove
 * Body: { account: "user@gmail.com" }
 * Removes a Gmail account. Aliases assigned to it lose their gmail_account mapping.
 */
app.post('/api/admin/gmail-accounts/remove', requireAdminSecret, async function(req, res) {
  try {
    const accountEmail = (req.body.account || '').trim().toLowerCase();
    if (!accountEmail) return res.status(400).json({ ok: false, error: 'Missing account' });

    await removeAccount(accountEmail);

    // Clear gmail_account on aliases that were assigned to this account
    await supabase
      .from('allowed_emails')
      .update({ gmail_account: null })
      .eq('gmail_account', accountEmail);

    console.log('[ADMIN] Removed Gmail account:', accountEmail);
    return res.json({ ok: true, message: `${accountEmail} removed.` });
  } catch (e) {
    console.error('admin/gmail-accounts/remove error:', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * POST /api/admin/gmail-accounts/refresh-watch
 * Body: { account: "user@gmail.com" }
 * Manually refreshes the Pub/Sub watch for one account.
 */
app.post('/api/admin/gmail-accounts/refresh-watch', requireAdminSecret, async function(req, res) {
  try {
    const accountEmail = (req.body.account || '').trim().toLowerCase();
    if (!accountEmail) return res.status(400).json({ ok: false, error: 'Missing account' });
    await registerWatch(accountEmail);
    console.log('[ADMIN] Watch refreshed for:', accountEmail);
    return res.json({ ok: true, message: `Watch refreshed for ${accountEmail}` });
  } catch (e) {
    console.error('admin/gmail-accounts/refresh-watch error:', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});

/**
 * POST /api/admin/set-alias-account
 * Body: { email: "alias@gmail.com", gmail_account: "source@gmail.com" | null }
 * Assigns or clears the gmail_account for a specific alias.
 */
app.post('/api/admin/set-alias-account', requireAdminSecret, async function(req, res) {
  try {
    const aliasEmail    = (req.body.email         || '').trim().toLowerCase();
    const gmailAccount  = req.body.gmail_account ? (req.body.gmail_account || '').trim().toLowerCase() : null;
    if (!aliasEmail) return res.status(400).json({ ok: false, error: 'Missing email' });

    const { error } = await supabase
      .from('allowed_emails')
      .update({ gmail_account: gmailAccount })
      .eq('email', aliasEmail);

    if (error) return res.status(500).json({ ok: false, error: 'Database error' });
    console.log(`[ADMIN] ${aliasEmail} → gmail_account=${gmailAccount}`);
    return res.json({ ok: true });
  } catch (e) {
    console.error('admin/set-alias-account error:', e.message);
    return res.status(500).json({ ok: false, error: e.message });
  }
});
