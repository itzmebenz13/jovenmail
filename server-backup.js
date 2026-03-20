const express = require('express');
const cron    = require('node-cron');
const { createClient } = require('@supabase/supabase-js');
const { getAuthUrl, saveToken, fetchEmails, registerWatch } = require('./gmail');
require('dotenv').config();

const app = express();
app.use(express.json());

// ── CORS ──
// Restrict to your known front-end origin in production
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

// ── AUTH ──
app.get('/auth/login', (req, res) => res.redirect(getAuthUrl()));

app.get('/auth/callback', async (req, res) => {
  await saveToken(req.query.code);
  await registerWatch();
  res.send('Gmail connected! You can close this tab.');
});

// ── GMAIL PUSH ──
app.post('/gmail/push', async (req, res) => {
  res.sendStatus(200);
  try {
    const data = req.body?.message?.data;
    if (!data) return;
    console.log('Gmail push received — fetching new emails');
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

// ── RE-REGISTER GMAIL WATCH every 6 days ──
cron.schedule('0 0 */6 * *', async () => {
  try { await registerWatch(); console.log('Gmail watch refreshed'); }
  catch (e) { console.error('Watch refresh error:', e.message); }
});

// ── DAILY RESET: clear attempts that are older than 24h and not permanently blocked ──
// Runs at midnight every day. Resets daily attempt counts so the 3/day limit is fresh.
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

// ── RATE LIMITING CONFIG ──
// 3 attempts per day. After 3 failures, a block is applied.
// Block durations escalate per offence level (in minutes).
const BLOCK_DURATIONS = [60, 180, 720, 1440]; // 1h → 3h → 12h → 24h
const MAX_ATTEMPTS    = 3;

/**
 * Returns a normalised IP range string (first two octets for IPv4,
 * first four groups for IPv6) so that 175.176.x.x all map to "175.176".
 */
function getIPRange(req) {
  let ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  ip = ip.split(',')[0].trim();
  // Strip IPv6-mapped IPv4 prefix (::ffff:1.2.3.4 → 1.2.3.4)
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  const parts = ip.split('.');
  if (parts.length === 4) return parts[0] + '.' + parts[1]; // IPv4 /16 range
  return ip.split(':').slice(0, 4).join(':');                // IPv6 /64 range
}

/**
 * Evaluate whether a row is currently blocked.
 * Returns { blocked, message, permanent, attempts }
 */
function evaluateRow(row) {
  if (!row) return { blocked: false, attempts: 0 };

  if (row.permanent) {
    return { blocked: true, message: 'Access permanently denied.', permanent: true, attempts: row.attempts };
  }

  if (row.blocked_until) {
    const until = new Date(row.blocked_until);
    if (until > new Date()) {
      const mins = Math.ceil((until - new Date()) / 60000);
      const timeStr = mins >= 60 ? Math.ceil(mins / 60) + ' hour(s)' : mins + ' minute(s)';
      return {
        blocked: true,
        message: 'Too many failed attempts. Try again in ' + timeStr + '.',
        attempts: row.attempts
      };
    }
  }

  return { blocked: false, attempts: row.attempts || 0 };
}

// ── CHECK-BLOCK: called before every recover attempt ──
app.post('/api/check-block', async function(req, res) {
  try {
    const fp      = (req.body.fp || '').trim();
    const ipRange = getIPRange(req);

    if (!fp) return res.status(400).json({ blocked: false, error: 'Missing fingerprint' });

    // Fetch fingerprint row and IP-range row independently
    const [{ data: fpRow }, { data: ipRows }] = await Promise.all([
      supabase.from('recovery_attempts').select('*').eq('fingerprint', fp).maybeSingle(),
      supabase.from('recovery_attempts').select('*').eq('ip_range', ipRange).order('block_level', { ascending: false }).limit(1)
    ]);

    const ipRow = ipRows && ipRows.length ? ipRows[0] : null;

    // Pick the stricter of the two (higher block_level wins; permanent always wins)
    let row = null;
    if (fpRow && ipRow) {
      if (fpRow.permanent || (!ipRow.permanent && (fpRow.block_level || 0) >= (ipRow.block_level || 0))) {
        row = fpRow;
      } else {
        row = ipRow;
      }
    } else {
      row = fpRow || ipRow;
    }

    return res.json(evaluateRow(row));
  } catch (e) {
    console.error('check-block error:', e);
    res.json({ blocked: false, attempts: 0 });
  }
});

// ── RECORD-ATTEMPT: called only after a confirmed invalid email ──
// Updates BOTH the fingerprint row AND the IP-range row so that
// incognito / different browsers on the same network are also blocked.
app.post('/api/record-attempt', async function(req, res) {
  try {
    const fp      = (req.body.fp || '').trim();
    const ipRange = getIPRange(req);
    const now     = new Date();

    if (!fp) return res.status(400).json({ ok: false, error: 'Missing fingerprint' });

    async function upsertRecord(query) {
      const { data: existing } = await query;

      let newAttempts  = (existing?.attempts || 0) + 1;
      let newLevel     = existing?.block_level || 0;
      let blockedUntil = null;
      let permanent    = existing?.permanent || false;

      // If already permanently blocked, nothing changes
      if (permanent) return;

      if (newAttempts >= MAX_ATTEMPTS) {
        newLevel = (existing?.block_level || 0) + 1;
        newAttempts = 0; // reset daily counter after block is issued
        if (newLevel > BLOCK_DURATIONS.length) {
          permanent    = true;
          blockedUntil = null;
        } else {
          const durationMins = BLOCK_DURATIONS[newLevel - 1] || BLOCK_DURATIONS[BLOCK_DURATIONS.length - 1];
          blockedUntil = new Date(now.getTime() + durationMins * 60000).toISOString();
        }
      }

      return { newAttempts, newLevel, blockedUntil, permanent };
    }

    // ── Fingerprint row ──
    const { data: fpRow } = await supabase
      .from('recovery_attempts').select('*').eq('fingerprint', fp).maybeSingle();

    const fpCalc = await upsertRecord(Promise.resolve({ data: fpRow }));
    if (fpCalc) {
      if (fpRow) {
        await supabase.from('recovery_attempts').update({
          attempts: fpCalc.newAttempts,
          block_level: fpCalc.newLevel,
          blocked_until: fpCalc.blockedUntil,
          permanent: fpCalc.permanent,
          last_attempt: now.toISOString(),
          ip_range: ipRange
        }).eq('fingerprint', fp);
      } else {
        await supabase.from('recovery_attempts').insert({
          fingerprint: fp,
          ip_range: ipRange,
          attempts: 1,
          block_level: 0,
          blocked_until: null,
          permanent: false,
          last_attempt: now.toISOString()
        });
      }
    }

    // ── IP-range row (keyed by ip_range, fingerprint = 'ip:' + ipRange sentinel) ──
    // This ensures the block persists even in incognito / different devices.
    const ipSentinel = 'ip:' + ipRange;
    const { data: ipRow } = await supabase
      .from('recovery_attempts').select('*').eq('fingerprint', ipSentinel).maybeSingle();

    const ipCalc = await upsertRecord(Promise.resolve({ data: ipRow }));
    if (ipCalc) {
      if (ipRow) {
        await supabase.from('recovery_attempts').update({
          attempts: ipCalc.newAttempts,
          block_level: ipCalc.newLevel,
          blocked_until: ipCalc.blockedUntil,
          permanent: ipCalc.permanent,
          last_attempt: now.toISOString(),
          ip_range: ipRange
        }).eq('fingerprint', ipSentinel);
      } else {
        await supabase.from('recovery_attempts').insert({
          fingerprint: ipSentinel,
          ip_range: ipRange,
          attempts: 1,
          block_level: 0,
          blocked_until: null,
          permanent: false,
          last_attempt: now.toISOString()
        });
      }
    }

    res.json({ ok: true });
  } catch (e) {
    console.error('record-attempt error:', e);
    res.json({ ok: false });
  }
});

// ── VALIDATE EMAIL: checks Supabase `emails` table for at least 1 received mail ──
// An alias is only considered valid if it has received at least one email.
// This prevents enumeration / guessing of unused aliases.
app.post('/api/validate-email', async function(req, res) {
  try {
    const fp      = (req.body.fp || '').trim();
    const alias   = (req.body.alias || '').trim().toLowerCase();
    const ipRange = getIPRange(req);

    if (!fp)    return res.status(400).json({ valid: false, error: 'Missing fingerprint' });
    if (!alias) return res.status(400).json({ valid: false, error: 'Missing alias' });

    // Basic email format guard — no point hitting DB for garbage input
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(alias)) {
      return res.json({ valid: false, reason: 'invalid_format' });
    }

    // Pre-check: is this IP/FP already blocked before we even query?
    const [{ data: fpRow }, { data: ipRows }] = await Promise.all([
      supabase.from('recovery_attempts').select('*').eq('fingerprint', fp).maybeSingle(),
      supabase.from('recovery_attempts').select('*').eq('ip_range', ipRange).order('block_level', { ascending: false }).limit(1)
    ]);
    const ipRow    = ipRows && ipRows.length ? ipRows[0] : null;
    const rowToUse = fpRow || ipRow;
    const blockEval = evaluateRow(rowToUse);
    if (blockEval.blocked) {
      return res.json({ valid: false, blocked: true, message: blockEval.message, permanent: blockEval.permanent });
    }

    // ── Gmail dot-blindness normalisation ──
    // Gmail treats all dot-variants of a username as identical.
    // rizamartinez875@gmail.com and r.iza.m.a.rti.nez875@gmail.com are the same inbox.
    // Emails in Supabase may be stored under any dot-variant depending on what the
    // sender addressed. We normalise by stripping dots from the username and matching
    // any stored alias that resolves to the same base username.
    const atIdx       = alias.indexOf('@');
    const inputUser   = alias.slice(0, atIdx);
    const inputDomain = alias.slice(atIdx + 1);
    const baseUser    = inputUser.replace(/\./g, ''); // e.g. "rizamartinez875"

    const dotBlindDomains = ['gmail.com', 'googlemail.com'];
    const isDotBlind = dotBlindDomains.includes(inputDomain);

    let emailRows, emailErr;

    if (isDotBlind) {
      // Fetch stored aliases for this domain, filter in JS for matching base username.
      // ilike on domain suffix avoids a full-table scan.
      const { data: candidates, error: candErr } = await supabase
        .from('emails')
        .select('id, alias')
        .ilike('alias', '%@' + inputDomain)
        .limit(500); // safety cap

      emailErr  = candErr;
      emailRows = candidates
        ? candidates.filter(function(row) {
            if (!row.alias) return false;
            const parts = row.alias.toLowerCase().split('@');
            return parts.length === 2
              && parts[1] === inputDomain
              && parts[0].replace(/\./g, '') === baseUser;
          })
        : [];
    } else {
      // Non-dot-blind domain — exact match only
      const result = await supabase
        .from('emails')
        .select('id')
        .eq('alias', alias)
        .limit(1);
      emailRows = result.data;
      emailErr  = result.error;
    }

    if (emailErr) {
      console.error('validate-email DB error:', JSON.stringify(emailErr));
      return res.status(500).json({ valid: false, error: 'Database error' });
    }

    const hasEmails = emailRows && emailRows.length > 0;

    if (!hasEmails) {
      // Invalid alias — record this failed attempt
      // (We do it server-side so it cannot be skipped by a modified client)
      const ipSentinel = 'ip:' + ipRange;
      const now        = new Date();

      async function recordOne(sentinelKey, existingRow) {
        let newAttempts  = (existingRow?.attempts || 0) + 1;
        let newLevel     = existingRow?.block_level || 0;
        let blockedUntil = null;
        let permanent    = existingRow?.permanent || false;

        if (permanent) return { newAttempts, newLevel, blockedUntil, permanent };

        if (newAttempts >= MAX_ATTEMPTS) {
          newLevel    = (existingRow?.block_level || 0) + 1;
          newAttempts = 0;
          if (newLevel > BLOCK_DURATIONS.length) {
            permanent    = true;
            blockedUntil = null;
          } else {
            const durationMins = BLOCK_DURATIONS[newLevel - 1] || BLOCK_DURATIONS[BLOCK_DURATIONS.length - 1];
            blockedUntil = new Date(now.getTime() + durationMins * 60000).toISOString();
          }
        }

        const payload = {
          attempts: newAttempts, block_level: newLevel,
          blocked_until: blockedUntil, permanent,
          last_attempt: now.toISOString(), ip_range: ipRange
        };

        if (existingRow) {
          await supabase.from('recovery_attempts').update(payload).eq('fingerprint', sentinelKey);
        } else {
          await supabase.from('recovery_attempts').insert({
            fingerprint: sentinelKey, ip_range: ipRange,
            attempts: 1, block_level: 0,
            blocked_until: null, permanent: false,
            last_attempt: now.toISOString()
          });
        }
        return { newAttempts, newLevel, blockedUntil, permanent };
      }

      const [fpResult, ipResult] = await Promise.all([
        recordOne(fp, fpRow),
        recordOne(ipSentinel, ipRow)
      ]);

      // Determine the stricter result to inform the client
      const resultRow = (fpResult.permanent || (fpResult.block_level || 0) >= (ipResult?.block_level || 0))
        ? fpResult : ipResult;

      let remainingAttempts = Math.max(0, MAX_ATTEMPTS - ((resultRow.newAttempts || 0)));
      let responseBlockEval = null;

      if (resultRow.permanent) {
        responseBlockEval = { blocked: true, message: 'Access permanently denied.', permanent: true };
      } else if (resultRow.blockedUntil) {
        const until = new Date(resultRow.blockedUntil);
        const mins  = Math.ceil((until - now) / 60000);
        const timeStr = mins >= 60 ? Math.ceil(mins / 60) + ' hour(s)' : mins + ' minute(s)';
        responseBlockEval = { blocked: true, message: 'Too many failed attempts. Try again in ' + timeStr + '.' };
      }

      return res.json({
        valid: false,
        reason: 'no_emails',
        blocked: !!(responseBlockEval?.blocked),
        message: responseBlockEval?.message || null,
        permanent: responseBlockEval?.permanent || false,
        remainingAttempts: responseBlockEval?.blocked ? 0 : remainingAttempts
      });
    }

    // Valid alias — clear fingerprint attempts (successful recovery resets the counter)
    if (fpRow && !fpRow.permanent) {
      await supabase.from('recovery_attempts').update({
        attempts: 0, block_level: 0,
        blocked_until: null, permanent: false,
        last_attempt: new Date().toISOString()
      }).eq('fingerprint', fp);
    }

    return res.json({ valid: true });
  } catch (e) {
    console.error('validate-email error:', e);
    res.status(500).json({ valid: false, error: 'Server error' });
  }
});

// ── START ──
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
  registerWatch().catch(e => console.error('Initial watch error:', e.message));
});
