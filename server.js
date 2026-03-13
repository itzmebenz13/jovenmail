const express = require('express');
const { google } = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
const { getAuthUrl, saveToken, fetchEmails, registerWatch } = require('./gmail');

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

const sb = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_SERVICE_KEY);

// ── BLOCK DURATIONS ──
const BLOCK_DURATIONS = [
  0,           // level 0 = not blocked
  1 * 60,      // level 1 = 1 hour (in minutes)
  3 * 60,      // level 2 = 3 hours
  12 * 60,     // level 3 = 12 hours
  24 * 60,     // level 4 = 24 hours
];
const MAX_ATTEMPTS = 3;

function getIPRange(req) {
  var ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  ip = ip.split(',')[0].trim();
  // Get /16 subnet (first two octets for IPv4)
  var parts = ip.split('.');
  if (parts.length === 4) return parts[0] + '.' + parts[1];
  // IPv6 — use first 4 groups
  return ip.split(':').slice(0, 4).join(':');
}

// ── CHECK BLOCK STATUS ──
app.post('/api/check-block', async function(req, res) {
  try {
    var fp = req.body.fp || '';
    var ipRange = getIPRange(req);

    // Check by fingerprint first, then IP range
    var { data: fpRow } = await sb.from('recovery_attempts')
      .select('*').eq('fingerprint', fp).single();

    var { data: ipRow } = await sb.from('recovery_attempts')
      .select('*').eq('ip_range', ipRange).order('block_level', { ascending: false }).limit(1).single();

    var row = null;
    if (fpRow && fpRow.block_level >= (ipRow ? ipRow.block_level : 0)) row = fpRow;
    else if (ipRow) row = ipRow;

    if (!row) return res.json({ blocked: false, attempts: 0 });

    if (row.permanent) {
      return res.json({ blocked: true, message: 'Access permanently denied.', permanent: true });
    }

    if (row.blocked_until) {
      var until = new Date(row.blocked_until);
      if (until > new Date()) {
        var mins = Math.ceil((until - new Date()) / 60000);
        var timeStr = mins >= 60 ? Math.ceil(mins/60) + ' hour(s)' : mins + ' minute(s)';
        return res.json({ blocked: true, message: 'Too many failed attempts. Try again in ' + timeStr + '.', attempts: row.attempts });
      }
    }

    return res.json({ blocked: false, attempts: row.attempts || 0 });
  } catch(e) {
    console.error('check-block error:', e);
    res.json({ blocked: false, attempts: 0 });
  }
});

// ── RECORD FAILED ATTEMPT ──
app.post('/api/record-attempt', async function(req, res) {
  try {
    var fp = req.body.fp || '';
    var ipRange = getIPRange(req);
    var now = new Date();

    // Upsert by fingerprint
    var { data: existing } = await sb.from('recovery_attempts')
      .select('*').eq('fingerprint', fp).single();

    if (existing) {
      var newAttempts = (existing.attempts || 0) + 1;
      var newLevel = existing.block_level || 0;
      var blockedUntil = null;
      var permanent = false;

      if (newAttempts >= MAX_ATTEMPTS) {
        newLevel = (existing.block_level || 0) + 1;
        if (newLevel >= BLOCK_DURATIONS.length) {
          permanent = true;
        } else {
          var blockMins = BLOCK_DURATIONS[newLevel];
          blockedUntil = new Date(now.getTime() + blockMins * 60000).toISOString();
        }
        newAttempts = 0; // reset attempt counter for next cycle
      }

      await sb.from('recovery_attempts').update({
        attempts: newAttempts,
        block_level: newLevel,
        blocked_until: blockedUntil,
        permanent: permanent,
        last_attempt: now.toISOString(),
        ip_range: ipRange
      }).eq('fingerprint', fp);
    } else {
      // First failed attempt
      await sb.from('recovery_attempts').insert({
        fingerprint: fp,
        ip_range: ipRange,
        attempts: 1,
        block_level: 0,
        blocked_until: null,
        permanent: false,
        last_attempt: now.toISOString()
      });
    }

    res.json({ ok: true });
  } catch(e) {
    console.error('record-attempt error:', e);
    res.json({ ok: false });
  }
});

// ── GMAIL AUTH ──
app.get('/auth/login', function(req, res) {
  res.redirect(getAuthUrl());
});

app.get('/auth/callback', async function(req, res) {
  const code = req.query.code;
  if (!code) return res.status(400).send('No code');
  try {
    await saveToken(code);
    await registerWatch();
    res.send('Auth complete. Railway is watching Gmail.');
  } catch(e) {
    console.error(e);
    res.status(500).send('Auth failed: ' + e.message);
  }
});

// ── GMAIL PUSH ──
app.post('/gmail/push', async function(req, res) {
  res.sendStatus(200);
  try {
    await fetchEmails(10);
  } catch(e) {
    console.error('Push error:', e.message);
  }
});

// ── STARTUP ──
const PORT = process.env.PORT || 3000;
app.listen(PORT, async function() {
  console.log('Server on port ' + PORT);
  try { await registerWatch(); console.log('Gmail watch registered'); }
  catch(e) { console.error('Watch failed:', e.message); }
});

// Re-register watch every 6 days
setInterval(async function() {
  try { await registerWatch(); console.log('Gmail watch renewed'); }
  catch(e) { console.error('Watch renew failed:', e.message); }
}, 6 * 24 * 60 * 60 * 1000);
