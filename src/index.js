require('dotenv').config()
const express = require("express");
const helmet = require("helmet");
let rateLimit = require('express-rate-limit')
let postgresStores = require('@acpr/rate-limit-postgresql')
const session = require('express-session')
const pg = require('pg')
const db = new pg.Pool({
    user: process.env.POSTGRES_USER,
    password: process.env.POSTGRES_PASS,
    host: process.env.POSTGRES_HOST,
    database: process.env.POSTGRES_DB,
    port: process.env.POSTGRES_PORT || 5432,
})
const app = express();

const limiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    limit: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes).
    standardHeaders: 'draft-8', // draft-6: `RateLimit-*` headers; draft-7 & draft-8: combined `RateLimit` header
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
        'aggregated_store',
    ),
})
// Apply the rate limiting middleware to all requests.
app.use(limiter)
app.use(session({
    store: new pgSession({
        pool: db,                // Connection pool
        tableName: 'sessions'   // Use another table-name than the default "session" one
        // Insert connect-pg-simple options here
    }),
    secret: process.env.SESSION_SECRET,
    resave: false,
    cookie: { maxAge: 30 * 24 * 60 * 60 * 1000 } // 30 days
}))

app.use(helmet({
    contentSecurityPolicy: false,
}))

// ok now time for route planning
/**
 * GET / - respond w/ smt idk maybe an index page? 
 * GET /healthcheck (api key blocked) - does a pg test + keyv test + return 200 if all good
 * GET /audit-logs (api key blocked) - return audit logs from pg (html page btw)
 * GET /api/audit-logs (api key blocked) - return audit logs from pg (json)
 * POST /api/create-mail (api key blocked) - create a mail entry in pg (aka sends mail wowie)
 */