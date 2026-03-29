const { google } = require('googleapis');
const fs = require('fs');
require('dotenv').config();

const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

// ── Load credentials from env var (Railway) or file (local) ──
let credentialsData;
if (process.env.CREDENTIALS_JSON) {
  credentialsData = JSON.parse(process.env.CREDENTIALS_JSON);
} else {
  credentialsData = JSON.parse(fs.readFileSync('credentials.json'));
}
const { client_id, client_secret, redirect_uris } = credentialsData.web;

// ── Redirect URI: use Railway domain if available, else localhost ──
const redirectUri = process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/auth/callback`
  : 'http://localhost:3000/auth/callback';

const oAuth2Client = new google.auth.OAuth2(
  client_id, client_secret, redirectUri
);

// ── Supabase client (for persisting fetch state) ──
const { createClient } = require('@supabase/supabase-js');
const _sb = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

// ── Persist/restore lastFetchTime from Supabase ──
async function saveLastFetchTime(ts) {
  try {
    await _sb.from('system_state').upsert(
      { key: 'last_fetch_time', value: String(ts) },
      { onConflict: 'key' }
    );
  } catch(e) {
    console.error('saveLastFetchTime error:', e.message);
  }
}

async function loadLastFetchTime() {
  try {
    const { data } = await _sb.from('system_state').select('value').eq('key', 'last_fetch_time').single();
    if (data && data.value) {
      _lastFetchTime = parseInt(data.value, 10);
      console.log('Restored lastFetchTime:', new Date(_lastFetchTime).toISOString());
    }
  } catch(e) {
    console.log('No saved lastFetchTime — will fetch recent emails on first run');
  }
}

// ── Load token from env var (Railway) or file (local) ──
function loadToken() {
  if (process.env.TOKEN_JSON) {
    try {
      const token = JSON.parse(process.env.TOKEN_JSON);
      oAuth2Client.setCredentials(token);
      console.log('Token loaded from TOKEN_JSON env var');
      return true;
    } catch (e) {
      console.error('Failed to parse TOKEN_JSON:', e.message);
    }
  }
  if (fs.existsSync('token.json')) {
    oAuth2Client.setCredentials(JSON.parse(fs.readFileSync('token.json')));
    console.log('Token loaded from token.json file');
    return true;
  }
  console.warn('No token found — visit /auth/login to authenticate');
  return false;
}

loadToken();
loadLastFetchTime();

function getAuthUrl() {
  return oAuth2Client.generateAuthUrl({
    access_type: 'offline',
    prompt: 'consent',
    scope: SCOPES
  });
}

async function saveToken(code) {
  const { tokens } = await oAuth2Client.getToken(code);
  oAuth2Client.setCredentials(tokens);
  // Save to file for local use
  fs.writeFileSync('token.json', JSON.stringify(tokens));
  // Print to logs so you can copy it to Railway env var
  console.log('===== COPY THIS TO RAILWAY AS TOKEN_JSON =====');
  console.log(JSON.stringify(tokens));
  console.log('==============================================');
}

function normalizeGmail(address) {
  const [user, domain] = address.toLowerCase().split('@');
  return user.replace(/\./g, '') + '@' + domain;
}

// ── Last fetch timestamp — only fetch emails newer than this ──
var _lastFetchTime = null;

// ── Debounce + Exponential Backoff ──
var _fetchTimer    = null;
var _fetchRetries  = 0;
var _maxRetries    = 5;
var _baseDelay     = 3000;
var _isFetching    = false;
var _pendingCb     = null;

function scheduleFetch(callback) {
  if (callback) _pendingCb = callback;
  if (_fetchTimer) clearTimeout(_fetchTimer);
  var delay = Math.min(_baseDelay * Math.pow(2, _fetchRetries), 60000);
  console.log('Fetch scheduled in ' + (delay / 1000) + 's');
  _fetchTimer = setTimeout(async function() {
    _fetchTimer = null;
    if (_isFetching) { scheduleFetch(null); return; }
    _isFetching = true;
    try {
      const emails = await fetchEmails(20);
      _fetchRetries = 0;
      _isFetching = false;
      if (_pendingCb && emails.length > 0) {
        var cb = _pendingCb;
        _pendingCb = null;
        await cb(emails);
      }
    } catch(e) {
      _isFetching = false;
      if (e.message && (
        e.message.includes('rate limit') ||
        e.message.includes('Rate Limit') ||
        e.message.includes('429') ||
        e.message.includes('User Rate Limit')
      )) {
        _fetchRetries = Math.min(_fetchRetries + 1, _maxRetries);
        console.log('Rate limited — backoff retry #' + _fetchRetries);
        scheduleFetch(null);
      } else {
        console.error('Fetch error:', e.message);
        _fetchRetries = 0;
      }
    }
  }, delay);
}


// ── OTP/Verification Email Filter ──
// Only saves emails that look like OTP or verification emails
// Discards promotions, order confirmations, newsletters, etc.
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

// Regex to detect short numeric codes (4-8 digits) in body
const OTP_CODE_REGEX = /\d{4,8}/;

function isOTPEmail(subject, body) {
  const subjectLower = (subject || '').toLowerCase();
  const bodyLower   = (body || '').toLowerCase().slice(0, 1000); // only check first 1000 chars

  // If subject matches a promo keyword and NOT an OTP keyword — skip it
  const hasPromoKeyword = PROMO_SUBJECT_KEYWORDS.some(k => subjectLower.includes(k));
  const hasOTPKeyword   = OTP_SUBJECT_KEYWORDS.some(k => subjectLower.includes(k));
  const hasOTPCode      = OTP_CODE_REGEX.test(body || '');

  // Definitely OTP if subject has OTP keyword
  if (hasOTPKeyword) return true;

  // Has a numeric code in body — likely OTP even without keyword in subject
  if (hasOTPCode && !hasPromoKeyword) return true;

  // Promo with no OTP signal — skip
  if (hasPromoKeyword && !hasOTPKeyword && !hasOTPCode) return false;

  // Default: include (better to show extra than miss an OTP)
  return true;
}

async function fetchEmails(maxResults = 20) {
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  const base  = process.env.GMAIL_BASE + '@' + process.env.GMAIL_DOMAIN;
  const normalizedBase = normalizeGmail(base);

  // Only fetch emails newer than last fetch — saves massive quota
  var query = 'in:inbox';
  if (_lastFetchTime) {
    // Gmail 'after' uses Unix timestamp in seconds
    var afterSec = Math.floor(_lastFetchTime / 1000) - 60; // 60s buffer
    query += ' after:' + afterSec;
  }

  console.log('Fetching emails, query: ' + query);

  let list;
  try {
    list = await gmail.users.messages.list({ userId: 'me', maxResults, q: query });
  } catch(e) {
    throw e;
  }

  // Update last fetch time BEFORE processing so we don't miss emails
  _lastFetchTime = Date.now();
  saveLastFetchTime(_lastFetchTime);
  if (!list.data.messages) {
    console.log('No messages found in Gmail');
    return [];
  }

  const emails = [];
  for (const msg of list.data.messages) {
    const detail = await gmail.users.messages.get({
      userId: 'me', id: msg.id, format: 'full'
    });

    const headers   = detail.data.payload.headers;
    const getHeader = name =>
      headers.find(h => h.name.toLowerCase() === name)?.value || '';

    const toField = getHeader('to');
    const normalizedTo = normalizeGmail(toField);

    if (normalizedTo !== normalizedBase) {
      continue; // skip emails not sent to our base address
    }

    const from    = getHeader('from');
    const subject = getHeader('subject');
    const date    = getHeader('date');

    // Try to get plain text body
    let body = '';
    const payload = detail.data.payload;

    // Handle simple (non-multipart) emails
    if (payload.body && payload.body.data) {
      body = Buffer.from(payload.body.data, 'base64').toString('utf8');
    }

    // Handle multipart emails
    const parts = payload.parts || [];
    const textPart = parts.find(p => p.mimeType === 'text/plain');
    if (textPart && textPart.body && textPart.body.data) {
      body = Buffer.from(textPart.body.data, 'base64').toString('utf8');
    }

    // Handle nested multipart
    if (!body) {
      for (const part of parts) {
        if (part.parts) {
          const nested = part.parts.find(p => p.mimeType === 'text/plain');
          if (nested && nested.body && nested.body.data) {
            body = Buffer.from(nested.body.data, 'base64').toString('utf8');
            break;
          }
        }
      }
    }

    const m = from.match(/^(.*?)<(.+?)>$/);
    const senderName  = m ? m[1].trim() : from;
    const senderEmail = m ? m[2].trim() : from;

    const aliasMatch = toField.match(/[\w.]+@[\w.]+/);
    const alias = aliasMatch ? aliasMatch[0].toLowerCase() : toField.toLowerCase();

    // Filter — only save OTP/verification emails
    if (!isOTPEmail(subject, body)) {
      console.log('Skipped non-OTP email: ' + subject);
      continue;
    }

    console.log(`Found OTP email: to=${alias}, subject=${subject}`);

    emails.push({
      gmail_id:     msg.id,
      alias,
      sender:       senderName,
      sender_email: senderEmail,
      subject,
      body,
      received_at:  new Date(date).toISOString()
    });
  }

  console.log(`Matched ${emails.length} email(s) for this Gmail`);
  return emails;
}

async function registerWatch() {
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  await gmail.users.watch({
    userId: 'me',
    requestBody: {
      topicName: `projects/${process.env.GOOGLE_CLOUD_PROJECT}/topics/${process.env.PUBSUB_TOPIC}`,
      labelIds: ['INBOX']
    }
  });
  console.log('Gmail watch registered');
}

module.exports = { getAuthUrl, saveToken, fetchEmails, registerWatch, scheduleFetch };
