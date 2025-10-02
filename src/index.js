require("dotenv").config();
const express = require("express");
const helmet = require("helmet");
let rateLimit = require("express-rate-limit");
let postgresStores = require("@acpr/rate-limit-postgresql");
const session = require("express-session");
const pg = require("pg");
const bcrypt = require('bcrypt');
const pgSession = require("connect-pg-simple")(session);
const KeyvPostgres = require("@keyv/postgres");
const Keyv = require("keyv");
const db = new pg.Pool({
  user: process.env.POSTGRES_USER,
  password: process.env.POSTGRES_PASS,
  host: process.env.POSTGRES_HOST,
  database: process.env.POSTGRES_DB,
  port: process.env.POSTGRES_PORT || 5432,
});
const stats = new Keyv(
  new KeyvPostgres({
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASS,
    host: process.env.POSTGRES_HOST,
    database: process.env.POSTGRES_DB,
    port: process.env.POSTGRES_PORT || 5432, table: "stats"
  }),
);

const app = express();


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
      database: process.env.POSTGRES_DB,
      port: process.env.POSTGRES_PORT || 5432,
    },
    "aggregated_store",
  ),
  skip: (req, res) => {
    const ratelimitBypass = req.headers.get("X-RateLimit-Bypass");
    const keys = (process.env.RATELIMIT_BYPASS_KEYS || "").split(",");
    if (ratelimitBypass && keys.includes(ratelimitBypass)) {
      return true;
    }
    return false;
  }
});
// Apply the rate limiting middleware to all requests.
app.use(limiter);
app.use(
  session({
    store: new pgSession({
      pool: db, // Connection pool
      tableName: "sessions", // Use another table-name than the default "session" one
      // Insert connect-pg-simple options here
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
// app.use(express.json())
app.use(express.urlencoded({ extended: true }));

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
 */
async function apiKey(req, res, next) {
  const keys = await db.query('select api_key_hash from api_keys')
  const providedKey = req.headers.get('Authorization')
  if (!providedKey) {
    return res.status(401).send('Unauthorized')
  }
  const match = await Promise.all(keys.rows.map(async (row) => {
    return await bcrypt.compare(providedKey, row.api_key_hash)
  }))
  if (match.includes(true)) {
    return next()
  } else {
    return res.status(401).send('Unauthorized - No match')
  }
}
app.get('/', (req, res) => {
  res.render("index")
})

app.get('/healthcheck', async (req, res) => {

  await stats.set('healthcheck', new Date().toISOString())
  await stats.get('healthcheck')
  await db.query('SELECT NOW()')
  res.status(200).send('OK')
})


app.get('/audit-logs', apiKey, async (req, res) => {
  res.render('audit-logs')
})
app.get('/api/audit-logs', apiKey, async (req, res) => {
  const logs = await db.query('select * from audit_logs order by created_at desc limit 1000')
  res.json(logs.rows)
})

app.post('/api/create-mail', apiKey, async (req, res) => {
  // TODO 
  // FIXME
})


app.get('/api/keys', apiKey, async (req, res) => {
  const keys = await db.query('select id, api_key_preview, created_at from api_keys order by created_at desc')
  res.json(keys.rows)
})

// TODO UPDATE SCHEMA TO HAVE name for api keys