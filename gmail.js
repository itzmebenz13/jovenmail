// ════════════════════════════════════════════════════════════════════
// gmail.js — Multi-Account Gmail Manager
//
// Supports unlimited Gmail accounts. Each account:
//   - has its own OAuth2 token stored in Supabase `gmail_accounts` table
//   - gets its own Pub/Sub subscription (Option A: one subscription per Gmail)
//   - tracks its own lastFetchTime in-memory (keyed by account email)
//
// Exports:
//   getAuthUrl(accountEmail)
//   saveToken(code, accountEmail)
//   fetchEmails(maxResults, accountEmail)   ← accountEmail can be null → uses first account
//   registerWatch(accountEmail)
//   registerAllWatches()
//   listAccounts()
//   removeAccount(accountEmail)
//   scheduleFetch(callback, accountEmail)
//   getAccountBySubscription(subscriptionName)
// ════════════════════════════════════════════════════════════════════
'use strict';

const { google }       = require('googleapis');
const { createClient } = require('@supabase/supabase-js');
require('dotenv').config();

// ── Google OAuth2 credentials (shared across all accounts) ──────────
let credentialsData;
try {
  if (process.env.CREDENTIALS_JSON) {
    credentialsData = JSON.parse(process.env.CREDENTIALS_JSON);
  } else {
    credentialsData = JSON.parse(require('fs').readFileSync('credentials.json'));
  }
} catch (e) {
  console.error('Failed to load Google credentials:', e.message);
  credentialsData = { web: { client_id: '', client_secret: '', redirect_uris: [] } };
}
const { client_id, client_secret } = credentialsData.web;

const redirectUri = process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/auth/callback`
  : (process.env.REDIRECT_URI || 'http://localhost:3000/auth/callback');

// ── Supabase (service role — full access) ────────────────────────────
const _sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── In-memory caches ─────────────────────────────────────────────────
// oauthClients: { email → OAuth2Client }
const oauthClients = {};

// lastFetchTime: { email → ms timestamp }
const lastFetchTimes = {};

// fetchState: { email → { timer, retries, isFetching, pendingCb } }
const fetchStates = {};

// subscriptionMap: { subscriptionName → email }
// Built from gmail_accounts.watch_subscription on startup
const subscriptionMap = {};

// ── OTP filter config (unchanged from original) ───────────────────────
const OTP_SUBJECT_KEYWORDS = [
  'verif', 'otp', 'one-time', 'one time', 'passcode', 'pass code',
  'security code', 'confirmation code', 'auth code', 'authentication',
  'login code', 'sign in code', 'access code', '2fa', 'two-factor',
  'your code', 'enter code', 'your pin', 'temporary', 'activate',
  'validate', 'validation'
];

const PROMO_SUBJECT_KEYWORDS = [
  'sale', 'off', 'discount', 'promo', 'deal', 'offer', 'coupon',
  'shop', 'order', 'shipped', 'delivered', 'invoice', 'receipt',
  'newsletter', 'unsubscribe', 'subscription', 'welcome', 'thank you',
  'thanks for', 'update', 'news', 'announcement', 'invitation',
  'reminder', 'notification', 'alert', 'bill', 'payment', 'refund',
  'reward', 'points', 'voucher', 'flash', 'limited time', 'exclusive',
  'member', 'account created', 'successfully', 'tracking'
];

const OTP_CODE_REGEX = /\b\d{4,8}\b/;

function isOTPEmail(subject, body) {
  const subjectLower  = (subject || '').toLowerCase();
  const hasPromoKeyword = PROMO_SUBJECT_KEYWORDS.some(k => subjectLower.includes(k));
  const hasOTPKeyword   = OTP_SUBJECT_KEYWORDS.some(k => subjectLower.includes(k));
  const hasOTPCode      = OTP_CODE_REGEX.test(body || '');

  if (hasOTPKeyword) return true;
  if (hasOTPCode && !hasPromoKeyword) return true;
  if (hasPromoKeyword && !hasOTPKeyword && !hasOTPCode) return false;
  return true;
}

function normalizeGmail(address) {
  const [user, domain] = (address || '').toLowerCase().split('@');
  if (!user || !domain) return (address || '').toLowerCase();
  return user.replace(/\./g, '') + '@' + domain;
}

// ════════════════════════════════════════════════════════════════════
// ── OAUTH CLIENT FACTORY ─────────────────────────────────────────────
// Returns a cached OAuth2Client for a given account email.
// If no credentials are set yet, returns an unauthenticated client
// (only useful for generating auth URLs).
// ════════════════════════════════════════════════════════════════════
function getOAuthClient(accountEmail) {
  if (!oauthClients[accountEmail]) {
    oauthClients[accountEmail] = new google.auth.OAuth2(
      client_id, client_secret, redirectUri
    );
    // Auto-refresh: save updated tokens back to Supabase
    oauthClients[accountEmail].on('tokens', async (tokens) => {
      try {
        const { data: row } = await _sb
          .from('gmail_accounts')
          .select('tokens')
          .eq('email', accountEmail)
          .maybeSingle();

        const merged = Object.assign({}, row?.tokens || {}, tokens);
        await _sb
          .from('gmail_accounts')
          .update({ tokens: merged })
          .eq('email', accountEmail);

        console.log(`[gmail] Token auto-refreshed for ${accountEmail}`);
      } catch (e) {
        console.error(`[gmail] Failed to save refreshed token for ${accountEmail}:`, e.message);
      }
    });
  }
  return oauthClients[accountEmail];
}

// ════════════════════════════════════════════════════════════════════
// ── ACCOUNT LOADING — runs at startup ────────────────────────────────
// Loads all accounts from Supabase and initialises their OAuth clients.
// Also rebuilds the subscriptionMap.
// ════════════════════════════════════════════════════════════════════
async function loadAllAccounts() {
  try {
    const { data: rows, error } = await _sb
      .from('gmail_accounts')
      .select('*');

    if (error) { console.error('[gmail] loadAllAccounts error:', error); return; }
    if (!rows || !rows.length) {
      console.warn('[gmail] No Gmail accounts found in Supabase. Visit /auth/login to connect one.');
      return;
    }

    for (const row of rows) {
      const client = getOAuthClient(row.email);
      if (row.tokens) {
        client.setCredentials(row.tokens);
        console.log(`[gmail] Loaded account: ${row.email}`);
      }
      if (row.watch_subscription) {
        subscriptionMap[row.watch_subscription] = row.email;
      }
    }

    // Also try legacy single-account env vars (backward-compat migration)
    await migrateLegacyTokenIfNeeded(rows);

  } catch (e) {
    console.error('[gmail] loadAllAccounts fatal:', e.message);
  }
}

// ── Migrate a TOKEN_JSON env var to Supabase (one-time, on first startup) ──
async function migrateLegacyTokenIfNeeded(existingRows) {
  if (!process.env.TOKEN_JSON) return;
  const legacyBase = process.env.GMAIL_BASE && process.env.GMAIL_DOMAIN
    ? `${process.env.GMAIL_BASE}@${process.env.GMAIL_DOMAIN}`
    : null;
  if (!legacyBase) return;

  const alreadyMigrated = existingRows.some(r => r.email === legacyBase);
  if (alreadyMigrated) return;

  try {
    const tokens = JSON.parse(process.env.TOKEN_JSON);
    await _sb.from('gmail_accounts').upsert({
      email:  legacyBase,
      tokens: tokens
    }, { onConflict: 'email' });
    console.log(`[gmail] Migrated legacy TOKEN_JSON → ${legacyBase} in Supabase`);

    // Set credentials on the client
    const client = getOAuthClient(legacyBase);
    client.setCredentials(tokens);
  } catch (e) {
    console.error('[gmail] Legacy migration failed:', e.message);
  }
}

// ── Load lastFetchTimes from Supabase system_state on startup ──────────
async function loadLastFetchTimes() {
  try {
    const { data: rows } = await _sb
      .from('system_state')
      .select('key, value')
      .like('key', 'last_fetch_time:%');

    if (rows) {
      for (const r of rows) {
        const email = r.key.replace('last_fetch_time:', '');
        lastFetchTimes[email] = parseInt(r.value, 10);
        console.log(`[gmail] Restored lastFetchTime for ${email}: ${new Date(lastFetchTimes[email]).toISOString()}`);
      }
    }

    // Also try the legacy single-key for backward compat
    const { data: legacyRow } = await _sb
      .from('system_state')
      .select('value')
      .eq('key', 'last_fetch_time')
      .maybeSingle();
    if (legacyRow?.value) {
      const legacyBase = process.env.GMAIL_BASE && process.env.GMAIL_DOMAIN
        ? `${process.env.GMAIL_BASE}@${process.env.GMAIL_DOMAIN}`
        : null;
      if (legacyBase && !lastFetchTimes[legacyBase]) {
        lastFetchTimes[legacyBase] = parseInt(legacyRow.value, 10);
        console.log(`[gmail] Restored legacy lastFetchTime for ${legacyBase}`);
      }
    }
  } catch (e) {
    console.log('[gmail] No saved lastFetchTimes — will fetch recent on first run');
  }
}

async function saveLastFetchTime(accountEmail, ts) {
  try {
    await _sb.from('system_state').upsert(
      { key: `last_fetch_time:${accountEmail}`, value: String(ts) },
      { onConflict: 'key' }
    );
  } catch (e) {
    console.error('[gmail] saveLastFetchTime error:', e.message);
  }
}

// ── Startup initialisation ────────────────────────────────────────────
loadAllAccounts();
loadLastFetchTimes();

// ════════════════════════════════════════════════════════════════════
// ── PUBLIC API ──────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════

/**
 * Returns the OAuth URL for a specific Gmail account.
 * The account email is passed via the `state` parameter so the
 * callback knows which slot to save the token to.
 *
 * @param {string} accountEmail  e.g. "user@gmail.com"
 */
function getAuthUrl(accountEmail) {
  const client = getOAuthClient(accountEmail || '__new__');
  return client.generateAuthUrl({
    access_type:  'offline',
    prompt:       'consent',
    scope:        ['https://www.googleapis.com/auth/gmail.readonly'],
    login_hint:   accountEmail || undefined,
    state:        accountEmail || '',
  });
}

/**
 * Exchange an OAuth code for tokens and save to Supabase.
 * accountEmail is read from the `state` query parameter.
 *
 * @param {string} code           OAuth authorization code
 * @param {string} accountEmail   Target Gmail address (from state param)
 */
async function saveToken(code, accountEmail) {
  if (!accountEmail) throw new Error('accountEmail is required to save token');

  // Use a temporary fresh client for the token exchange
  const tempClient = new google.auth.OAuth2(client_id, client_secret, redirectUri);
  const { tokens } = await tempClient.getToken(code);

  // Save to Supabase
  await _sb.from('gmail_accounts').upsert({
    email:    accountEmail,
    tokens:   tokens,
    added_at: new Date().toISOString()
  }, { onConflict: 'email' });

  // Activate in-memory
  const client = getOAuthClient(accountEmail);
  client.setCredentials(tokens);

  console.log(`[gmail] Token saved for ${accountEmail}`);
}

/**
 * Returns all Gmail accounts from Supabase with computed status fields.
 */
async function listAccounts() {
  const { data: rows, error } = await _sb
    .from('gmail_accounts')
    .select('email, watch_expiry, watch_subscription, watch_resource, added_at')
    .order('added_at', { ascending: true });

  if (error) throw error;

  return (rows || []).map(row => ({
    email:              row.email,
    added_at:           row.added_at,
    watch_expiry:       row.watch_expiry,
    watch_subscription: row.watch_subscription,
    watch_active:       row.watch_expiry && new Date(row.watch_expiry) > new Date(),
    token_loaded:       !!(oauthClients[row.email]?.credentials?.access_token ||
                           oauthClients[row.email]?.credentials?.refresh_token),
  }));
}

/**
 * Remove a Gmail account — deletes from Supabase, clears in-memory state.
 */
async function removeAccount(accountEmail) {
  await _sb.from('gmail_accounts').delete().eq('email', accountEmail);
  delete oauthClients[accountEmail];
  delete lastFetchTimes[accountEmail];
  delete fetchStates[accountEmail];
  // Remove from subscriptionMap
  for (const [sub, email] of Object.entries(subscriptionMap)) {
    if (email === accountEmail) delete subscriptionMap[sub];
  }
  console.log(`[gmail] Removed account: ${accountEmail}`);
}

/**
 * Resolve a Pub/Sub subscription name → Gmail account email.
 * Used by the /gmail/push endpoint to route incoming notifications.
 *
 * @param {string} subscriptionName  e.g. "projects/myproj/subscriptions/joven-mail-user1"
 * @returns {string|null}  The account email, or null if not found
 */
function getAccountBySubscription(subscriptionName) {
  return subscriptionMap[subscriptionName] || null;
}

/**
 * Returns the first registered Gmail account (for fallback / backward compat).
 */
async function getFirstAccount() {
  const { data } = await _sb
    .from('gmail_accounts')
    .select('email')
    .order('added_at', { ascending: true })
    .limit(1)
    .maybeSingle();
  return data?.email || null;
}

// ════════════════════════════════════════════════════════════════════
// ── FETCH EMAILS ────────────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════

/**
 * Fetch recent OTP emails for a specific Gmail account.
 *
 * @param {number} maxResults     Max messages to fetch
 * @param {string} accountEmail   Which account to fetch from (null → first account)
 */
async function fetchEmails(maxResults = 20, accountEmail = null) {
  // Resolve account
  const email = accountEmail || await getFirstAccount();
  if (!email) {
    console.warn('[gmail] fetchEmails: no account available');
    return [];
  }

  const client = getOAuthClient(email);
  if (!client.credentials || (!client.credentials.access_token && !client.credentials.refresh_token)) {
    console.warn(`[gmail] fetchEmails: no token for ${email}`);
    return [];
  }

  const gmail          = google.gmail({ version: 'v1', auth: client });
  const normalizedBase = normalizeGmail(email);

  let query = 'in:inbox';
  const lfTime = lastFetchTimes[email];
  if (lfTime) {
    const afterSec = Math.floor(lfTime / 1000) - 60;
    query += ' after:' + afterSec;
  }

  console.log(`[gmail] Fetching for ${email}, query: ${query}`);

  let list;
  try {
    list = await gmail.users.messages.list({ userId: 'me', maxResults, q: query });
  } catch (e) {
    throw e;
  }

  lastFetchTimes[email] = Date.now();
  saveLastFetchTime(email, lastFetchTimes[email]);

  if (!list.data.messages) {
    console.log(`[gmail] No messages for ${email}`);
    return [];
  }

  const emails = [];
  for (const msg of list.data.messages) {
    const detail = await gmail.users.messages.get({
      userId: 'me', id: msg.id, format: 'full'
    });

    const headers   = detail.data.payload.headers;
    const getHeader = name => headers.find(h => h.name.toLowerCase() === name)?.value || '';

    const toField      = getHeader('to');
    const normalizedTo = normalizeGmail(toField);

    if (normalizedTo !== normalizedBase) continue;

    const from    = getHeader('from');
    const subject = getHeader('subject');
    const date    = getHeader('date');

    let body = '';
    const payload = detail.data.payload;

    if (payload.body?.data) {
      body = Buffer.from(payload.body.data, 'base64').toString('utf8');
    }

    const parts    = payload.parts || [];
    const textPart = parts.find(p => p.mimeType === 'text/plain');
    if (textPart?.body?.data) {
      body = Buffer.from(textPart.body.data, 'base64').toString('utf8');
    }

    if (!body) {
      for (const part of parts) {
        if (part.parts) {
          const nested = part.parts.find(p => p.mimeType === 'text/plain');
          if (nested?.body?.data) {
            body = Buffer.from(nested.body.data, 'base64').toString('utf8');
            break;
          }
        }
      }
    }

    const m           = from.match(/^(.*?)<(.+?)>$/);
    const senderName  = m ? m[1].trim() : from;
    const senderEmail = m ? m[2].trim() : from;

    const aliasMatch = toField.match(/[\w.]+@[\w.]+/);
    const alias      = aliasMatch ? aliasMatch[0].toLowerCase() : toField.toLowerCase();

    if (!isOTPEmail(subject, body)) {
      console.log(`[gmail] Skipped non-OTP: ${subject}`);
      continue;
    }

    console.log(`[gmail] OTP email: to=${alias}, subject=${subject}`);

    emails.push({
      gmail_id:      msg.id,
      alias,
      gmail_account: email,
      sender:        senderName,
      sender_email:  senderEmail,
      subject,
      body,
      received_at:   new Date(date).toISOString()
    });
  }

  console.log(`[gmail] ${emails.length} email(s) matched for ${email}`);
  return emails;
}

// ════════════════════════════════════════════════════════════════════
// ── GMAIL WATCH / PUB/SUB ────────────────────────────────────────────
// ════════════════════════════════════════════════════════════════════

/**
 * Register (or refresh) a Gmail push watch for one account.
 *
 * Option A: one subscription per Gmail account.
 * Subscription name pattern: {PUBSUB_TOPIC_PREFIX}-{sanitized email}
 * e.g. "joven-mail-user1atgmail" for user1@gmail.com
 *
 * The subscription must already exist in Google Cloud Pub/Sub pointing
 * to your /gmail/push endpoint. This function just tells Gmail to send
 * push notifications to that subscription.
 *
 * @param {string} accountEmail
 */
async function registerWatch(accountEmail = null) {
  const email = accountEmail || await getFirstAccount();
  if (!email) { console.warn('[gmail] registerWatch: no account'); return; }

  const client = getOAuthClient(email);
  if (!client.credentials?.refresh_token && !client.credentials?.access_token) {
    console.warn(`[gmail] registerWatch: no token for ${email} — skipping`);
    return;
  }

  const gmail = google.gmail({ version: 'v1', auth: client });

  // Build subscription name for this account (Option A)
  const subSuffix       = email.toLowerCase().replace(/[@.]/g, '-');
  const topicBase       = process.env.PUBSUB_TOPIC || 'gmail-push';
  const topicName       = `projects/${process.env.GOOGLE_CLOUD_PROJECT}/topics/${topicBase}`;

  // Support per-account subscription override via env, or derive from email
  const subscriptionName = process.env[`PUBSUB_SUB_${subSuffix.toUpperCase().replace(/-/g, '_')}`]
    || `projects/${process.env.GOOGLE_CLOUD_PROJECT}/subscriptions/${topicBase}-${subSuffix}`;

  const resp = await gmail.users.watch({
    userId: 'me',
    requestBody: {
      topicName,
      labelIds: ['INBOX']
    }
  });

  const expiry       = resp.data.expiration ? new Date(parseInt(resp.data.expiration)).toISOString() : null;
  const resourceId   = resp.data.resourceId || null;

  // Persist watch metadata to Supabase
  await _sb.from('gmail_accounts').update({
    watch_expiry:       expiry,
    watch_resource:     resourceId,
    watch_subscription: subscriptionName
  }).eq('email', email);

  // Update in-memory subscription map
  subscriptionMap[subscriptionName] = email;

  console.log(`[gmail] Watch registered for ${email} → sub: ${subscriptionName}, expires: ${expiry}`);
}

/**
 * Refresh watches for ALL connected accounts.
 * Called by the cron job every 6 hours.
 */
async function registerAllWatches() {
  const { data: rows } = await _sb.from('gmail_accounts').select('email');
  if (!rows?.length) return;
  for (const row of rows) {
    try {
      await registerWatch(row.email);
    } catch (e) {
      console.error(`[gmail] Watch refresh failed for ${row.email}:`, e.message);
    }
  }
}

// ════════════════════════════════════════════════════════════════════
// ── DEBOUNCED FETCH WITH EXPONENTIAL BACKOFF ─────────────────────────
// (Per-account state, mirrors original single-account logic)
// ════════════════════════════════════════════════════════════════════
const _maxRetries = 5;
const _baseDelay  = 3000;

function getOrCreateFetchState(email) {
  if (!fetchStates[email]) {
    fetchStates[email] = { timer: null, retries: 0, isFetching: false, pendingCb: null };
  }
  return fetchStates[email];
}

function scheduleFetch(callback, accountEmail) {
  const email = accountEmail || '__pending__';
  const state = getOrCreateFetchState(email);

  if (callback) state.pendingCb = callback;
  if (state.timer) clearTimeout(state.timer);

  const delay = Math.min(_baseDelay * Math.pow(2, state.retries), 60000);
  console.log(`[gmail] Fetch scheduled for ${email} in ${delay / 1000}s`);

  state.timer = setTimeout(async () => {
    state.timer = null;
    if (state.isFetching) { scheduleFetch(null, email); return; }
    state.isFetching = true;
    try {
      const emails = await fetchEmails(20, email === '__pending__' ? null : email);
      state.retries    = 0;
      state.isFetching = false;
      if (state.pendingCb && emails.length > 0) {
        const cb = state.pendingCb;
        state.pendingCb = null;
        await cb(emails);
      }
    } catch (e) {
      state.isFetching = false;
      const isRateLimit = e.message && (
        e.message.includes('rate limit') || e.message.includes('Rate Limit') ||
        e.message.includes('429')        || e.message.includes('User Rate Limit')
      );
      if (isRateLimit) {
        state.retries = Math.min(state.retries + 1, _maxRetries);
        console.log(`[gmail] Rate limited for ${email} — backoff retry #${state.retries}`);
        scheduleFetch(null, email);
      } else {
        console.error(`[gmail] Fetch error for ${email}:`, e.message);
        state.retries = 0;
      }
    }
  }, delay);
}

module.exports = {
  getAuthUrl,
  saveToken,
  fetchEmails,
  registerWatch,
  registerAllWatches,
  listAccounts,
  removeAccount,
  getAccountBySubscription,
  scheduleFetch,
};
