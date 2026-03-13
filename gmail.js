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

var _rateLimitedUntil = 0;

async function fetchEmails(maxResults = 30) {
  // If we're rate limited, skip until cooldown expires
  if (Date.now() < _rateLimitedUntil) {
    console.log('Rate limit cooldown active, skipping fetch');
    return [];
  }
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  const base  = process.env.GMAIL_BASE + '@' + process.env.GMAIL_DOMAIN;
  const normalizedBase = normalizeGmail(base);

  console.log(`Fetching emails for base: ${normalizedBase}`);

  let list;
  try {
    list = await gmail.users.messages.list({ userId: 'me', maxResults });
  } catch(e) {
    if (e.message && e.message.includes('User-rate limit')) {
      // Extract retry time from error if available
      _rateLimitedUntil = Date.now() + (15 * 60 * 1000); // 15 min cooldown
      console.log('Rate limited — cooling down for 15 minutes');
      return [];
    }
    throw e;
  }
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

    console.log(`Found email: to=${alias}, subject=${subject}`);

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

module.exports = { getAuthUrl, saveToken, fetchEmails, registerWatch };
