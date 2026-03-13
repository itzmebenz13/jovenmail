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

// ── POLLING every 5s as fallback ──
cron.schedule('*/5 * * * * *', async () => {
  try {
    const emails = await fetchEmails(20);
    if (!emails.length) return;
    const { error } = await supabase
      .from('emails')
      .upsert(emails, { onConflict: 'gmail_id', ignoreDuplicates: true });
    if (error) console.error('Supabase error:', JSON.stringify(error));
    else console.log(`[POLL] Synced ${emails.length} email(s)`);
  } catch (err) {
    console.error('Poll error:', err.message);
  }
});

// ── RE-REGISTER GMAIL WATCH every 6 days ──
cron.schedule('0 0 */6 * *', async () => {
  try { await registerWatch(); console.log('Gmail watch refreshed'); }
  catch (e) { console.error('Watch refresh error:', e.message); }
});

// ── RATE LIMITING ──
const BLOCK_DURATIONS = [0, 60, 180, 720, 1440]; // minutes: 1h, 3h, 12h, 24h
const MAX_ATTEMPTS = 3;

function getIPRange(req) {
  var ip = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  ip = ip.split(',')[0].trim();
  var parts = ip.split('.');
  if (parts.length === 4) return parts[0] + '.' + parts[1];
  return ip.split(':').slice(0, 4).join(':');
}

app.post('/api/check-block', async function(req, res) {
  try {
    var fp = req.body.fp || '';
    var ipRange = getIPRange(req);

    var { data: fpRow } = await supabase.from('recovery_attempts')
      .select('*').eq('fingerprint', fp).single();
    var { data: ipRow } = await supabase.from('recovery_attempts')
      .select('*').eq('ip_range', ipRange).order('block_level', { ascending: false }).limit(1).single();

    var row = null;
    if (fpRow && fpRow.block_level >= (ipRow ? ipRow.block_level : 0)) row = fpRow;
    else if (ipRow) row = ipRow;

    if (!row) return res.json({ blocked: false, attempts: 0 });
    if (row.permanent) return res.json({ blocked: true, message: 'Access permanently denied.', permanent: true });

    if (row.blocked_until) {
      var until = new Date(row.blocked_until);
      if (until > new Date()) {
        var mins = Math.ceil((until - new Date()) / 60000);
        var timeStr = mins >= 60 ? Math.ceil(mins / 60) + ' hour(s)' : mins + ' minute(s)';
        return res.json({ blocked: true, message: 'Too many failed attempts. Try again in ' + timeStr + '.', attempts: row.attempts });
      }
    }
    return res.json({ blocked: false, attempts: row.attempts || 0 });
  } catch(e) {
    console.error('check-block error:', e);
    res.json({ blocked: false, attempts: 0 });
  }
});

app.post('/api/record-attempt', async function(req, res) {
  try {
    var fp = req.body.fp || '';
    var ipRange = getIPRange(req);
    var now = new Date();

    var { data: existing } = await supabase.from('recovery_attempts')
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
          blockedUntil = new Date(now.getTime() + BLOCK_DURATIONS[newLevel] * 60000).toISOString();
        }
        newAttempts = 0;
      }

      await supabase.from('recovery_attempts').update({
        attempts: newAttempts, block_level: newLevel,
        blocked_until: blockedUntil, permanent,
        last_attempt: now.toISOString(), ip_range: ipRange
      }).eq('fingerprint', fp);
    } else {
      await supabase.from('recovery_attempts').insert({
        fingerprint: fp, ip_range: ipRange, attempts: 1,
        block_level: 0, blocked_until: null, permanent: false,
        last_attempt: now.toISOString()
      });
    }
    res.json({ ok: true });
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
