const express = require('express');
const cron    = require('node-cron');
const { createClient } = require('@supabase/supabase-js');
const { getAuthUrl, saveToken, fetchEmails, registerWatch } = require('./gmail');
require('dotenv').config();

const app = express();
app.use(express.json());

// CORS
app.use(function(req, res, next) {
  res.header('Access-Control-Allow-Origin', '*');
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

// ── RATE LIMITING ──
// After MAX_ATTEMPTS failed tries, ban for BAN_DURATION_MINUTES (12 hours)
const MAX_ATTEMPTS     = 3;
const BAN_DURATION_MS  = 12 * 60 * 60 * 1000; // 12 hours in ms

// Extract /16 prefix for IPv4, or /32 prefix for IPv6 (first 4 groups)
function getIPRange(req) {
  var ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  ip = ip.split(',')[0].trim();
  // Strip IPv6-mapped IPv4 prefix
  if (ip.startsWith('::ffff:')) ip = ip.slice(7);
  var parts = ip.split('.');
  if (parts.length === 4) return parts[0] + '.' + parts[1]; // /16 range
  return ip.split(':').slice(0, 4).join(':');                // IPv6 /64
}

// ── VALIDATE EMAIL ──
// Checks whether the given alias has any email records in Supabase.
// If no records exist, the alias was never used → treat as invalid.
app.post('/api/validate-email', async function(req, res) {
  try {
    var email = (req.body.email || '').trim().toLowerCase();
    if (!email) return res.json({ valid: false });

    // Normalise: remove dots from local part (Gmail dot-blindness)
    var atIdx = email.indexOf('@');
    if (atIdx === -1) return res.json({ valid: false });
    var local  = email.slice(0, atIdx).replace(/\./g, '');
    var domain = email.slice(atIdx + 1);
    var normalised = local + '@' + domain;

    // Query emails table — match on the raw alias column OR normalised form
    var { data, error } = await supabase
      .from('emails')
      .select('id')
      .or('alias.eq.' + email + ',alias.eq.' + normalised)
      .limit(1);

    if (error) {
      console.error('validate-email supabase error:', error);
      return res.json({ valid: false });
    }

    return res.json({ valid: !!(data && data.length > 0) });
  } catch(e) {
    console.error('validate-email error:', e);
    res.json({ valid: false });
  }
});

// ── CHECK BLOCK ──
// Returns block status by fingerprint OR ip_range — whichever is more restrictive.
app.post('/api/check-block', async function(req, res) {
  try {
    var fp      = req.body.fp || '';
    var ipRange = getIPRange(req);
    var now     = new Date();

    // Look up by fingerprint
    var { data: fpRow }  = await supabase.from('recovery_attempts')
      .select('*').eq('fingerprint', fp).maybeSingle();

    // Look up any row that covers this IP range and is still banned
    var { data: ipRows } = await supabase.from('recovery_attempts')
      .select('*').eq('ip_range', ipRange).order('blocked_until', { ascending: false }).limit(1);
    var ipRow = (ipRows && ipRows.length) ? ipRows[0] : null;

    // Pick the most restrictive row
    function isBanned(row) {
      if (!row) return false;
      if (row.permanent) return true;
      if (row.blocked_until && new Date(row.blocked_until) > now) return true;
      return false;
    }

    var row = null;
    if (isBanned(fpRow) && isBanned(ipRow)) {
      // Both banned — pick whichever expires later (or permanent wins)
      row = (fpRow.permanent || (!ipRow.permanent && new Date(fpRow.blocked_until) >= new Date(ipRow.blocked_until))) ? fpRow : ipRow;
    } else if (isBanned(fpRow)) {
      row = fpRow;
    } else if (isBanned(ipRow)) {
      row = ipRow;
    } else {
      // Neither currently banned — return attempts from fingerprint row
      return res.json({ blocked: false, attempts: (fpRow ? fpRow.attempts : 0) });
    }

    if (row.permanent) {
      return res.json({ blocked: true, permanent: true, message: 'Access permanently denied.' });
    }

    var until   = new Date(row.blocked_until);
    var msLeft  = until - now;
    var minsLeft = Math.ceil(msLeft / 60000);
    var timeStr  = minsLeft >= 60 ? Math.ceil(minsLeft / 60) + ' hour(s)' : minsLeft + ' minute(s)';
    return res.json({
      blocked: true,
      message: 'Too many failed attempts. Access blocked for ' + timeStr + '.',
      blockedUntil: row.blocked_until,
      attempts: row.attempts || 0
    });

  } catch(e) {
    console.error('check-block error:', e);
    res.json({ blocked: false, attempts: 0 });
  }
});

// ── RECORD FAILED ATTEMPT ──
// Increments attempt counter. On the 3rd failure, bans for 12 hours by
// BOTH fingerprint AND ip_range so incognito / different browsers are covered.
app.post('/api/record-attempt', async function(req, res) {
  try {
    var fp      = req.body.fp || '';
    var ipRange = getIPRange(req);
    var now     = new Date();

    // Fetch existing record for this fingerprint
    var { data: existing } = await supabase.from('recovery_attempts')
      .select('*').eq('fingerprint', fp).maybeSingle();

    var newAttempts  = (existing ? existing.attempts : 0) + 1;
    var blockedUntil = null;
    var permanent    = false;

    if (newAttempts >= MAX_ATTEMPTS) {
      // Calculate previous ban cycles to escalate (optional — keeps progressive banning)
      var prevLevel = existing ? (existing.block_level || 0) : 0;
      var nextLevel = prevLevel + 1;

      if (nextLevel >= 5) {
        // 5th+ offence → permanent ban
        permanent = true;
      } else {
        // Escalating bans: 12h, 24h, 48h, 72h
        var escalation = [12, 24, 48, 72];
        var hours = escalation[Math.min(prevLevel, escalation.length - 1)];
        blockedUntil = new Date(now.getTime() + hours * 60 * 60 * 1000).toISOString();
      }

      // ── Write/update fingerprint row ──
      if (existing) {
        await supabase.from('recovery_attempts').update({
          attempts: newAttempts, block_level: nextLevel,
          blocked_until: blockedUntil, permanent,
          last_attempt: now.toISOString(), ip_range: ipRange
        }).eq('fingerprint', fp);
      } else {
        await supabase.from('recovery_attempts').insert({
          fingerprint: fp, ip_range: ipRange,
          attempts: newAttempts, block_level: 1,
          blocked_until: blockedUntil, permanent,
          last_attempt: now.toISOString()
        });
      }

      // ── Also upsert an IP-range ban row so incognito is blocked too ──
      // We store ip_range as primary key in a separate upsert to cover all fingerprints on the same network.
      var { data: ipExisting } = await supabase.from('recovery_attempts')
        .select('*').eq('ip_range', ipRange).eq('fingerprint', 'ip:' + ipRange).maybeSingle();

      var ipLevel = ipExisting ? (ipExisting.block_level || 0) + 1 : 1;
      var ipBannedUntil = blockedUntil; // mirror same ban window
      var ipPermanent   = permanent;

      if (ipExisting) {
        await supabase.from('recovery_attempts').update({
          attempts: newAttempts, block_level: ipLevel,
          blocked_until: ipBannedUntil, permanent: ipPermanent,
          last_attempt: now.toISOString()
        }).eq('fingerprint', 'ip:' + ipRange);
      } else {
        await supabase.from('recovery_attempts').insert({
          fingerprint: 'ip:' + ipRange, ip_range: ipRange,
          attempts: newAttempts, block_level: 1,
          blocked_until: ipBannedUntil, permanent: ipPermanent,
          last_attempt: now.toISOString()
        });
      }

    } else {
      // Under limit — just increment the counter
      if (existing) {
        await supabase.from('recovery_attempts').update({
          attempts: newAttempts,
          last_attempt: now.toISOString(),
          ip_range: ipRange
        }).eq('fingerprint', fp);
      } else {
        await supabase.from('recovery_attempts').insert({
          fingerprint: fp, ip_range: ipRange,
          attempts: newAttempts, block_level: 0,
          blocked_until: null, permanent: false,
          last_attempt: now.toISOString()
        });
      }
    }

    res.json({ ok: true, attempts: newAttempts, banned: !!(blockedUntil || permanent) });
  } catch(e) {
    console.error('record-attempt error:', e);
    res.json({ ok: false });
  }
});

// ── START ──
app.listen(process.env.PORT, () => {
  console.log(`Server running on port ${process.env.PORT}`);
  registerWatch().catch(e => console.error('Initial watch error:', e.message));
});
