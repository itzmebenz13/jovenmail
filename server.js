const express = require('express');
const cron    = require('node-cron');
const { createClient } = require('@supabase/supabase-js');
const { getAuthUrl, saveToken, fetchEmails } = require('./gmail');
require('dotenv').config();

const app = express();

const supabase = createClient(
  process.env.SUPABASE_URL,
  process.env.SUPABASE_SERVICE_KEY
);

app.get('/auth/login', (req, res) => {
  res.redirect(getAuthUrl());
});

app.get('/auth/callback', async (req, res) => {
  await saveToken(req.query.code);
  res.send('Gmail connected! You can close this tab.');
});

cron.schedule('*/5 * * * * *', async () => {
  try {
    const emails = await fetchEmails(20);
    if (!emails.length) return;

    const { error } = await supabase
      .from('emails')
      .upsert(emails, { onConflict: 'gmail_id', ignoreDuplicates: true });

    if (error) console.error('Supabase error:', JSON.stringify(error));
else console.log(`[${new Date().toISOString()}] Synced ${emails.length} email(s)`);
  } catch (err) {
    console.error('Poll error:', err.message);
  }
});

app.listen(process.env.PORT, () =>
  console.log(`Poller running on port ${process.env.PORT}`)
);