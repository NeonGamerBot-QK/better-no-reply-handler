require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
let rateLimit = require("express-rate-limit");
let postgresStores = require("@acpr/rate-limit-postgresql");
const session = require("express-session");
const pg = require("pg");
const bcrypt = require("bcrypt");
const pgSession = require("connect-pg-simple")(session);
const KeyvPostgres = require("@keyv/postgres");
const Keyv = require("keyv");
const nodemailer = require("nodemailer");
const { SMTPServer } = require("smtp-server");
const { simpleParser } = require("mailparser");
const mailthingy = require("./mailer");
const db = new pg.Pool({
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASS,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DATABASE,
  port: process.env.POSTGRES_PORT || 5432,
});
const stats = new Keyv.Keyv(
  new KeyvPostgres.KeyvPostgres({
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASS,
    host: process.env.POSTGRES_HOST,
    database: process.env.POSTGRES_DATABASE,
    port: process.env.POSTGRES_PORT || 5432,
    table: "stats",
  }),
);

const app = express();

const smtpTransport = nodemailer.createTransport({
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
  return subjectMatch ? subjectMatch[1] : "No Subject";
}

const smtpServer = new SMTPServer({
  secure: false,
  disabledCommands: ["STARTTLS"],
  allowInsecureAuth: true,
  onConnect(session, callback) {
    console.log(`[SMTP] New connection from ${session.remoteAddress}`);
    callback();
  },
  async onAuth(auth, session, callback) {
    console.log(`[SMTP] Auth attempt: ${auth.username}`);
    const providedKey = auth.password;
    if (!providedKey) {
      return callback(new Error("Authentication required"));
    }

    try {
      // Validate against stored API keys and master key
      const keys = await db
        .query("select api_key_hash from api_keys")
        .then((d) => d.rows);
      keys.push({ api_key_hash: await bcrypt.hash(process.env.MASTER_KEY, 10) });

      const matchResults = await Promise.all(
        keys.map((row) => bcrypt.compare(providedKey, row.api_key_hash)),
      );

      if (matchResults.includes(true)) {
        console.log(`[SMTP] Auth successful: ${auth.username}`);
        return callback(null, { user: auth.username });
      } else {
        console.log(`[SMTP] Auth failed: ${auth.username}`);
        return callback(new Error("Invalid credentials"));
      }
    } catch (err) {
      console.error("[SMTP] Auth error:", err.message);
      return callback(new Error("Authentication error"));
    }
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
    let emailData = Buffer.from([]);

    stream.on("data", (chunk) => {
      emailData = Buffer.concat([emailData, chunk]);
    });

    stream.on("end", async () => {
      console.log("\n========== NEW EMAIL RECEIVED ==========");
      console.log(emailData.toString());
      console.log("==========================================\n");

      const username = session.user;
      console.log(`[SMTP] Authenticated user: ${username}`);

      try {
        const parsed = await simpleParser(emailData);
        
        const to = parsed.to?.text || (username.includes("@")
          ? username
          : `${username}@saahild.com`);

        const sendOptions = {
          from: process.env.SMTP_USER,
          to: to,
          subject: parsed.subject || "No Subject",
        };

        if (parsed.text) sendOptions.text = parsed.text;
        if (parsed.html) sendOptions.html = parsed.html;
        if (parsed.attachments?.length > 0) {
          sendOptions.attachments = parsed.attachments.map(att => ({
            filename: att.filename,
            content: att.content,
            contentType: att.contentType,
          }));
        }

        await smtpTransport.sendMail(sendOptions);

        // Audit log the forwarded email
        await db.query(
          `INSERT INTO audit_logs (to_email, from_useragent, subject) VALUES ($1, $2, $3)`,
          [
            JSON.stringify(to),
            `SMTP:${username}@${session.remoteAddress}`,
            sendOptions.subject,
          ],
        );

        console.log("[SMTP] Email forwarded and audit logged successfully");
      } catch (err) {
        console.error("[SMTP] Error forwarding email:", err.message);
      }

      callback();
    });
  },
});

const SMTP_PORT = process.env.SMTP_PORT_RECEIVE || 2525;
smtpServer.listen(SMTP_PORT, () => {
  console.log(`SMTP server listening on port ${SMTP_PORT}`);
});

const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
  standardHeaders: "draft-8", // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers.
  ipv6Subnet: 56, // Set to 60 or 64 to be less aggressive, or 52 or 48 to be more aggressive
  // store: ... , // Redis, Memcached, etc. See below.
  store: new postgresStores.PostgresStore(
    {
      user: process.env.POSTGRES_USER,
      password: process.env.POSTGRES_PASS,
      host: process.env.POSTGRES_HOST,
      database: process.env.POSTGRES_DATABASE,
      port: process.env.POSTGRES_PORT || 5432,
    },
    "aggregated_store",
  ),
  skip: (req, res) => {
    const ratelimitBypass = req.headers["x-ratelimit-bypass"];
    const keys = (process.env.RATELIMIT_BYPASS_KEYS || "").split(",");
    if (ratelimitBypass && keys.includes(ratelimitBypass)) {
      return true;
    }
    return false;
  },
});
// Apply the rate limiting middleware to all requests.
app.use(limiter);
app.use(
  session({
    store: new pgSession({
      pool: db, // Connection pool
      tableName: "sessions", // Use another table-name than the default "session" one
      // Insert connect-pg-simple options here
      createTableIfMissing: true,
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 }, // 30 days
  }),
);

app.use(
  helmet({
    contentSecurityPolicy: false,
  }),
);
app.use(
  express.json({
    limit: "512mb",
  }),
);

app.set("view engine", "ejs");
app.set("views", "./src/views");
// ok now time for route planning
/**
 * GET / - respond w/ smt idk maybe an index page?
 * GET /healthcheck (api key blocked) - does a pg test + keyv test + return 200 if all good
 * GET /audit-logs (api key blocked) - return audit logs from pg (html page btw)
 * GET /apikeys
 * GET /api/audit-logs (api key blocked) - return audit logs from pg (json)
 * POST /api/create-mail (api key blocked) - create a mail entry in pg (aka sends mail wowie)
 * GET /api/keys
 * POST /api/keys/create (returns key & hash)
 * GET /unsubscribe?email=&sentEmailId=&program= unsub thingy hehe
 */
async function apiKey(req, res, next) {
  const providedKey = req.headers["authorization"];
  if (!providedKey) {
    return res.status(401).send("Unauthorized");
  }
  const keys = await db
    .query("select api_key_hash from api_keys")
    .then((d) => d.rows);
  keys.push({ api_key_hash: await bcrypt.hash(process.env.MASTER_KEY, 10) });

  const match = await Promise.all(
    keys.map(async (row) => {
      return await bcrypt.compare(providedKey, row.api_key_hash);
    }),
  );
  if (match.includes(true)) {
    return next();
  } else {
    return res.status(401).send("Unauthorized - No match");
  }
}
app.get("/", (req, res) => {
  res.render("index");
});

app.get("/healthcheck", async (req, res) => {
  await stats.set("healthcheck", new Date().toISOString());
  await stats.get("healthcheck");
  await db.query("SELECT NOW()");
  res.status(200).send("OK");
});

app.get("/audit-logs", apiKey, async (req, res) => {
  res.render("audit-logs");
});
app.get("/api/audit-logs", apiKey, async (req, res) => {
  const logs = await db.query(
    "select * from audit_logs order by created_at desc limit 1000",
  );
  res.json(logs.rows);
});

app.post("/api/create-mail", apiKey, async (req, res) => {
  console.log(req.body);
  if (!req.body || Object.keys(req.body).length === 0) {
    return res.status(400).json({ error: "Empty body" });
  }
  if (!req.body.program) req.body.program = "untitled";

  // FIXME
  const userAgent = req.headers["user-agent"] || req.body.program || "Unknown";
  // create audit log
  const audit_log_creation_out = await db.query(
    `INSERT INTO audit_logs (to_email, from_useragent, subject) VALUES ($1, $2, $3) RETURNING id`,
    [
      JSON.stringify(req.body.to),
      userAgent,
      req.body.subject || "(No Subject)",
    ],
  );
  // send mail — explicitly pick allowed fields to prevent request body from overriding
  // security-sensitive options like `from`, `list`, or transport settings
  const ress = await mailthingy.sendMail({
    list: {
      help: `neon+help@saahild.com?subject=${encodeURIComponent("Help with " + req.body.program)}`,
      unsubscribe: {
        url: `http://${process.env.BASE_URL || "localhost:3000"}/unsubscribe?email=${encodeURIComponent(req.body.to)}&program=${encodeURIComponent(req.body.program)}&sentEmailId=${audit_log_creation_out.rows[0].id}`,
        comment: "Unsubscribe",
      },
      subscribe: {
        url: `http://${process.env.BASE_URL || "localhost:3000"}/subscribe?email=${encodeURIComponent(req.body.to)}&program=${encodeURIComponent(req.body.program)}&sentEmailId=${audit_log_creation_out.rows[0].id}`,
        comment: "Subscribe",
      },
    },
    from: `"${req.body.fromName || "(No Name)"}" <${process.env.SMTP_USER}>`,
    to: req.body.to,
    subject: req.body.subject,
    text: req.body.text,
    html: req.body.html,
    attachments: req.body.attachments,
  });
  res.status(201).json({
    mai: ress,
    audit_log_out: audit_log_creation_out.rows,
  });
});

app.get("/api/keys", apiKey, async (req, res) => {
  const keys = await db.query(
    "select id, api_key_preview, label, created_at from api_keys order by created_at desc",
  );
  res.json(keys.rows);
});

app.post("/api/keys/create", apiKey, async (req, res) => {
  const label = req.body.label || "No Label";
  const apiKey = require("crypto").randomBytes(32).toString("hex");
  const apiKeyHash = await bcrypt.hash(apiKey, 10);
  const apiKeyPreview = apiKey.slice(0, 8);
  await db.query(
    "insert into api_keys (api_key_hash, api_key_preview, label) values ($1, $2, $3)",
    [apiKeyHash, apiKeyPreview, label],
  );
  res.json({ apiKey });
});

app.listen(process.env.PORT || 3000, () => {
  console.log(`Server started on port ${process.env.PORT || 3000}`);
});
