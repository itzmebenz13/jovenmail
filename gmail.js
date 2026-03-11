const { google } = require('googleapis');
const fs = require('fs');
require('dotenv').config();

const SCOPES = ['https://www.googleapis.com/auth/gmail.readonly'];

// ── Load credentials ──
let credentialsData;
if (process.env.CREDENTIALS_JSON) {
  credentialsData = JSON.parse(process.env.CREDENTIALS_JSON);
} else {
  credentialsData = JSON.parse(fs.readFileSync('credentials.json'));
}
const { client_id, client_secret } = credentialsData.web;

// ── Redirect URI ──
const redirectUri = process.env.RAILWAY_PUBLIC_DOMAIN
  ? `https://${process.env.RAILWAY_PUBLIC_DOMAIN}/auth/callback`
  : 'http://localhost:3000/auth/callback';

const oAuth2Client = new google.auth.OAuth2(client_id, client_secret, redirectUri);

// ── Auto-refresh: whenever Google issues a new access token, log it ──
oAuth2Client.on('tokens', (tokens) => {
  console.log('Token auto-refreshed by Google');
  if (tokens.refresh_token) {
    console.log('===== NEW TOKEN_JSON (update Railway) =====');
    console.log(JSON.stringify(tokens));
    console.log('==========================================');
  }
  // Merge new tokens into current credentials so refresh_token is not lost
  const current = oAuth2Client.credentials;
  oAuth2Client.setCredentials({ ...current, ...tokens });
});

// ── Load token ──
function loadToken() {
  if (process.env.TOKEN_JSON) {
    try {
      const token = JSON.parse(process.env.TOKEN_JSON);
      oAuth2Client.setCredentials(token);
      console.log('Token loaded — refresh_token present:', !!token.refresh_token);
      return true;
    } catch (e) {
      console.error('Failed to parse TOKEN_JSON:', e.message);
    }
  }
  if (fs.existsSync('token.json')) {
    try {
      const token = JSON.parse(fs.readFileSync('token.json'));
      oAuth2Client.setCredentials(token);
      console.log('Token loaded from file — refresh_token present:', !!token.refresh_token);
      return true;
    } catch (e) {
      console.error('Failed to parse token.json:', e.message);
    }
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
  if (fs.existsSync('.')) fs.writeFileSync('token.json', JSON.stringify(tokens));
  console.log('===== COPY THIS TO RAILWAY AS TOKEN_JSON =====');
  console.log(JSON.stringify(tokens));
  console.log('==============================================');
}

function normalizeGmail(address) {
  const [user, domain] = address.toLowerCase().split('@');
  return user.replace(/\./g, '') + '@' + domain;
}

async function fetchEmails(maxResults = 30) {
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  const base  = process.env.GMAIL_BASE + '@' + process.env.GMAIL_DOMAIN;
  const normalizedBase = normalizeGmail(base);

  console.log(`Fetching emails for base: ${normalizedBase}`);

  const list = await gmail.users.messages.list({ userId: 'me', maxResults });
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

    const toField      = getHeader('to');
    const normalizedTo = normalizeGmail(toField);
    if (normalizedTo !== normalizedBase) continue;

    const from    = getHeader('from');
    const subject = getHeader('subject');
    const date    = getHeader('date');

    let body = '';
    const payload = detail.data.payload;

    if (payload.body && payload.body.data) {
      body = Buffer.from(payload.body.data, 'base64').toString('utf8');
    }

    const parts = payload.parts || [];

    // Prefer HTML body for rich emails, fall back to plain text
    const htmlPart  = parts.find(p => p.mimeType === 'text/html');
    const textPart  = parts.find(p => p.mimeType === 'text/plain');
    const preferred = htmlPart || textPart;
    if (preferred && preferred.body && preferred.body.data) {
      body = Buffer.from(preferred.body.data, 'base64').toString('utf8');
    }

    // Handle nested multipart (e.g. multipart/alternative inside multipart/mixed)
    if (!body) {
      for (const part of parts) {
        if (part.parts) {
          const nestedHtml  = part.parts.find(p => p.mimeType === 'text/html');
          const nestedText  = part.parts.find(p => p.mimeType === 'text/plain');
          const nested      = nestedHtml || nestedText;
          if (nested && nested.body && nested.body.data) {
            body = Buffer.from(nested.body.data, 'base64').toString('utf8');
            break;
          }
        }
      }
    }

    const m           = from.match(/^(.*?)<(.+?)>$/);
    const senderName  = m ? m[1].trim() : from;
    const senderEmail = m ? m[2].trim() : from;
    const aliasMatch  = toField.match(/[\w.]+@[\w.]+/);
    const alias       = aliasMatch ? aliasMatch[0].toLowerCase() : toField.toLowerCase();

    console.log(`Found email: to=${alias}, subject=${subject}`);

    emails.push({
      gmail_id: msg.id, alias,
      sender: senderName, sender_email: senderEmail,
      subject, body,
      received_at: new Date(date).toISOString()
    });
  }

  console.log(`Matched ${emails.length} email(s) for this Gmail`);
  return emails;
}

async function registerWatch() {
  const projectId = process.env.GOOGLE_PROJECT_ID || 'maildot';
  const topicName = `projects/${projectId}/topics/gmail-push`;
  const gmail = google.gmail({ version: 'v1', auth: oAuth2Client });
  try {
    const res = await gmail.users.watch({
      userId: 'me',
      requestBody: { labelIds: ['INBOX'], topicName }
    });
    console.log('Gmail watch registered, expires:', new Date(parseInt(res.data.expiration)).toISOString());
    return res.data;
  } catch(e) {
    console.error('registerWatch failed (non-fatal):', e.message);
  }
}

module.exports = { getAuthUrl, saveToken, fetchEmails, registerWatch };
