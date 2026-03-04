require('dotenv').config();
const { SMTPServer } = require('smtp-server');
const nodemailer = require('nodemailer');

const transport = nodemailer.createTransport({
  host: process.env.SMTP_HOST,
  port: parseInt(process.env.SMTP_PORT),
  secure: process.env.SMTP_SECURE === "true",
  auth: {
    user: process.env.SMTP_USER,
    pass: process.env.SMTP_PASS,
  },
  tls: { rejectUnauthorized: false },
});

function extractSubject(emailData) {
  const subjectMatch = emailData.match(/^Subject:\s*(.+)$/m);
  return subjectMatch ? subjectMatch[1] : 'No Subject';
}

function extractEmailBody(emailData) {
  const lines = emailData.split('\n');
  let inBody = false;
  const bodyLines = [];

  for (const line of lines) {
    if (inBody) {
      bodyLines.push(line);
    } else if (line === '') {
      inBody = true;
    }
  }

  return bodyLines.join('\n').trim();
}

const server = new SMTPServer({
  secure: false,
  disabledCommands: ['STARTTLS'],
  allowInsecureAuth: true,
  onConnect(session, callback) {
    console.log(`[SMTP] New connection from ${session.remoteAddress}`);
    callback();
  },
  onAuth(auth, session, callback) {
    console.log(`[SMTP] Auth: ${auth.username}`);
    callback(null, { user: auth.username });
  },
  onMailFrom(address, session, callback) {
    console.log(`[SMTP] Mail from: ${address.address}`);
    callback();
  },
  onRcptTo(address, session, callback) {
    console.log(`[SMTP] Rcpt to: ${address.address}`);
    callback();
  },
  onData(stream, session, callback) {
    let emailData = '';

    stream.on('data', (chunk) => {
      emailData += chunk.toString();
    });

    stream.on('end', async () => {
      console.log('\n========== NEW EMAIL RECEIVED ==========');
      console.log(emailData);
      console.log('==========================================\n');

      const username = session.user;
      console.log(`[SMTP] Authenticated user: ${username}`);

      const body = extractEmailBody(emailData);
      const subject = extractSubject(emailData);

      try {
        await transport.sendMail({
          from: process.env.SMTP_USER,
          to: username.includes('@') ? username : `${username}@saahild.com`,
          subject: subject,
          text: body,
        });
        console.log('[SMTP] Email forwarded successfully');
      } catch (err) {
        console.error('[SMTP] Error forwarding email:', err.message);
      }

      callback();
    });
  },
});

const PORT = 2525;

server.listen(PORT, () => {
  console.log(`SMTP server listening on port ${PORT}`);
});
