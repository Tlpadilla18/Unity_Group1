/**
 * Shape game API 
 *
 * Express + MongoDB. Passwords hashed with bcrypt, input validated with Joi,
 * sessions stored ENCRYPTED in MongoDB (express-session + connect-mongo crypto).
 *
 * Routes
 *   GET  /                          health check
 *   POST /signup   {username,password}  -> 201 progress + token   (400 invalid, 409 taken)
 *   POST /login    {username,password}  -> 200 progress + token   (401 wrong login)
 *   POST /logout                        -> 200
 *   GET  /progress                      -> 200 progress            (401 not logged in)
 *   PUT  /progress  progress JSON       -> 200                     (400 if it names another user)
 *   PUT  /users/:username/progress      -> same, 400 if :username isn't you
 *   GET  /leaderboard                   -> top 10 players (public)
 *
 * Auth: the session cookie "shape.sid". Because the game (GitHub Pages) and this API live on
 * different sites, browsers may block that cookie, so login/signup also return "token"
 * (the signed session id). The game sends it as "Authorization: Bearer <token>" and the
 * middleware below turns it back into the session cookie - same encrypted session either way.
 */
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const { MongoClient, ObjectId } = require('mongodb');
const bcrypt = require('bcrypt');
const Joi = require('joi');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const signature = require('cookie-signature');

// ---------------------------------------------------------------- config

const {
  PORT = 3000,
  MONGODB_URI,
  MONGODB_DB = 'shapegame',
  NODE_SESSION_SECRET,
  MONGODB_SESSION_SECRET,
  ALLOWED_ORIGINS = '',
  NODE_ENV = 'development',
} = process.env;

for (const [name, value] of Object.entries({ MONGODB_URI, NODE_SESSION_SECRET, MONGODB_SESSION_SECRET })) {
  if (!value) {
    console.error(`Missing ${name}. Copy .env.example to .env and fill it in (or set it on your host).`);
    process.exit(1);
  }
}

// connect-mongo's encryption refuses weak secrets with a cryptic error, so check up front.
const count = (re) => (MONGODB_SESSION_SECRET.match(re) || []).length;
if (MONGODB_SESSION_SECRET.length < 8 || count(/[A-Z]/g) < 2 || count(/[a-z]/g) < 2 || count(/[0-9]/g) < 2 ||
    count(/[!@#$%^&*()_+\-=\[\]{};':"\|,.<>/?]/g) < 2) {
  console.error('MONGODB_SESSION_SECRET is too simple: it needs 2+ uppercase, 2+ lowercase, 2+ numbers and 2+ symbols.');
  console.error('Generate one with:  npm run secret');
  process.exit(1);
}

const isProd = NODE_ENV === 'production';
const COOKIE_NAME = 'shape.sid';
const SALT_ROUNDS = 12;
const SESSION_TTL_SECONDS = 7 * 24 * 60 * 60; // 7 days
const allowedOrigins = ALLOWED_ORIGINS.split(',').map((s) => s.trim().replace(/\/$/, '')).filter(Boolean);

const cookieOptions = {
  httpOnly: true,
  secure: isProd,                    // HTTPS only on the host
  sameSite: isProd ? 'none' : 'lax', // 'none' lets the cookie work cross-site (game on another domain)
  maxAge: SESSION_TTL_SECONDS * 1000,
};

// ---------------------------------------------------------------- validation (Joi)

const usernameRule = Joi.string().pattern(/^[A-Za-z0-9_]{3,20}$/).required().messages({
  'string.pattern.base': 'Username must be 3-20 letters, numbers or _',
  'string.empty': 'Username is required',
  'any.required': 'Username is required',
});

const passwordRule = Joi.string()
  .min(10)
  .max(64)
  .pattern(/[a-z]/, 'lowercase')
  .pattern(/[A-Z]/, 'uppercase')
  .pattern(/\d/, 'number')
  .pattern(/[^A-Za-z0-9]/, 'symbol')
  .required()
  .messages({
    'string.min': 'Password must be at least 10 characters',
    'string.max': 'Password must be at most 64 characters',
    'string.pattern.name': 'Password needs at least one {#name} character',
    'string.empty': 'Password is required',
    'any.required': 'Password is required',
  });

const signupSchema = Joi.object({ username: usernameRule, password: passwordRule });

const loginSchema = Joi.object({
  username: Joi.string().max(20).required(),
  password: Joi.string().max(64).required(),
});

const int = (min, max) => Joi.number().integer().min(min).max(max);
const progressSchema = Joi.object({
  username: Joi.string().allow('').max(20),
  bestMass: Joi.number().min(0).max(1e7),
  totalKills: int(0, 1e9),
  gamesPlayed: int(0, 1e9),
  totalTransforms: int(0, 1e9),
  highestLevel: int(0, 10),
  hasActiveRun: Joi.boolean(),
  runLevel: int(0, 10),
  runOverdrive: int(0, 10000),
  runGauge: Joi.number().min(0).max(1e6),
  runMass: Joi.number().min(0).max(1e7),
  runShape: int(0, 50),
  runPowerUps: Joi.string().allow('').max(300).pattern(/^[A-Za-z0-9:,]*$/),
}).options({ stripUnknown: true }); // ignore anything else the client sends (e.g. token)

const defaultProgress = () => ({
  bestMass: 0,
  totalKills: 0,
  gamesPlayed: 0,
  totalTransforms: 0,
  highestLevel: 1,
  hasActiveRun: false,
  runLevel: 1,
  runOverdrive: 0,
  runGauge: 0,
  runMass: 0,
  runShape: 0,
  runPowerUps: '',
});

// ---------------------------------------------------------------- app

const app = express();
app.set('trust proxy', 1); // Render / Qoddi sit behind a proxy; needed for secure cookies + rate limit
app.use(express.json({ limit: '20kb' }));

app.use(cors({
  origin(origin, callback) {
    // No Origin header = Unity editor, curl, Postman (not a browser) -> allowed.
    if (!origin) return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    if (!isProd && allowedOrigins.length === 0) return callback(null, true); // local dev: allow all
    return callback(null, false);
  },
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization'],
}));

// Bearer token -> session cookie (see header comment).
app.use((req, res, next) => {
  const auth = req.headers.authorization || '';
  const hasCookie = (req.headers.cookie || '').includes(`${COOKIE_NAME}=`);
  if (auth.startsWith('Bearer ') && !hasCookie) {
    const token = auth.slice(7).trim();
    if (token) {
      const cookie = `${COOKIE_NAME}=${encodeURIComponent(token)}`;
      req.headers.cookie = req.headers.cookie ? `${req.headers.cookie}; ${cookie}` : cookie;
    }
  }
  next();
});

app.use(session({
  name: COOKIE_NAME,
  secret: NODE_SESSION_SECRET,
  store: MongoStore.create({
    mongoUrl: MONGODB_URI,
    dbName: MONGODB_DB,
    collectionName: 'sessions',
    ttl: SESSION_TTL_SECONDS,
    crypto: { secret: MONGODB_SESSION_SECRET }, // sessions are encrypted at rest
    // Workaround: connect-mongo 5.1 + kruptein 3.4 parse the decrypted session twice
    // ('"[object Object]" is not valid JSON'). Accept either a JSON string or an object.
    serialize: (session) => JSON.stringify(session),
    unserialize: (data) => (typeof data === 'string' ? JSON.parse(data) : data),
  }),
  resave: false,
  saveUninitialized: false,
  cookie: cookieOptions,
}));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 30,
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  message: { error: 'Too many attempts. Try again in a few minutes.' },
});

let users; // MongoDB collection, set in start()

// ---------------------------------------------------------------- helpers

const sessionToken = (req) => `s:${signature.sign(req.sessionID, NODE_SESSION_SECRET)}`;

const publicProgress = (user) => ({
  ...defaultProgress(),
  ...(user.progress || {}),
  username: user.username,
});

function startSession(req, user) {
  return new Promise((resolve, reject) => {
    req.session.regenerate((err) => { // new session id on login (prevents session fixation)
      if (err) return reject(err);
      req.session.userId = user._id.toString();
      req.session.username = user.username;
      req.session.save((saveErr) => (saveErr ? reject(saveErr) : resolve()));
    });
  });
}

function requireAuth(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.status(401).json({ error: 'Please log in first.' });
  }
  next();
}

const asyncRoute = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

// ---------------------------------------------------------------- routes

app.get('/', (req, res) => res.json({ ok: true, name: 'Shape game API' }));

app.post('/signup', authLimiter, asyncRoute(async (req, res) => {
  const { error, value } = signupSchema.validate(req.body || {});
  if (error) return res.status(400).json({ error: error.details[0].message });

  const usernameLower = value.username.toLowerCase();
  if (await users.findOne({ usernameLower })) {
    return res.status(409).json({ error: 'That username is already taken.' });
  }

  const user = {
    username: value.username,
    usernameLower,
    passwordHash: await bcrypt.hash(value.password, SALT_ROUNDS),
    progress: defaultProgress(),
    createdAt: new Date(),
  };
  try {
    const result = await users.insertOne(user);
    user._id = result.insertedId;
  } catch (err) {
    if (err.code === 11000) return res.status(409).json({ error: 'That username is already taken.' });
    throw err;
  }

  await startSession(req, user);
  res.status(201).json({ ...publicProgress(user), token: sessionToken(req) });
}));

app.post('/login', authLimiter, asyncRoute(async (req, res) => {
  const { error, value } = loginSchema.validate(req.body || {});
  if (error) return res.status(400).json({ error: 'Enter your username and password.' });

  const user = await users.findOne({ usernameLower: value.username.toLowerCase() });
  const ok = user && (await bcrypt.compare(value.password, user.passwordHash));
  if (!ok) return res.status(401).json({ error: 'Wrong username or password.' });

  await startSession(req, user);
  res.json({ ...publicProgress(user), token: sessionToken(req) });
}));

app.post('/logout', (req, res) => {
  if (!req.session) return res.json({ ok: true });
  req.session.destroy(() => {
    res.clearCookie(COOKIE_NAME, { ...cookieOptions, maxAge: undefined });
    res.json({ ok: true });
  });
});

app.get('/progress', requireAuth, asyncRoute(async (req, res) => {
  const user = await users.findOne({ _id: new ObjectId(req.session.userId) });
  if (!user) return res.status(401).json({ error: 'Please log in first.' });
  res.json(publicProgress(user));
}));

/**
 * Save progress for the LOGGED-IN user only. The user comes from the session, never from
 * the request. Trying to save as anyone else -> 400 (project requirement).
 */
const saveProgress = asyncRoute(async (req, res) => {
  const body = req.body || {};
  if (body.username && body.username.toLowerCase() !== req.session.username.toLowerCase()) {
    return res.status(400).json({ error: 'You can only edit your own progress.' });
  }

  const { error, value } = progressSchema.validate(body);
  if (error) return res.status(400).json({ error: error.details[0].message });
  delete value.username;

  const result = await users.updateOne(
    { _id: new ObjectId(req.session.userId) },
    { $set: { progress: { ...defaultProgress(), ...value }, updatedAt: new Date() } },
  );
  if (result.matchedCount === 0) return res.status(401).json({ error: 'Please log in first.' });
  res.json({ ok: true });
});

app.put('/progress', requireAuth, saveProgress);

app.put('/users/:username/progress', requireAuth, (req, res, next) => {
  if (req.params.username.toLowerCase() !== req.session.username.toLowerCase()) {
    return res.status(400).json({ error: 'You can only edit your own progress.' });
  }
  req.body = { ...(req.body || {}), username: req.session.username };
  next();
}, saveProgress);

app.get('/leaderboard', asyncRoute(async (req, res) => {
  const top = await users
    .find({}, { projection: { _id: 0, username: 1, 'progress.highestLevel': 1, 'progress.bestMass': 1, 'progress.totalKills': 1 } })
    .sort({ 'progress.highestLevel': -1, 'progress.bestMass': -1 })
    .limit(10)
    .toArray();
  res.json({
    players: top.map((u) => ({
      username: u.username,
      highestLevel: u.progress?.highestLevel ?? 1,
      bestMass: Math.floor(u.progress?.bestMass ?? 0),
      totalKills: u.progress?.totalKills ?? 0,
    })),
  });
}));

app.use((req, res) => res.status(404).json({ error: 'Not found.' }));

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
  console.error(err);
  res.status(500).json({ error: 'Server error. Try again.' });
});

// ---------------------------------------------------------------- start

async function start() {
  const client = new MongoClient(MONGODB_URI);
  await client.connect();
  users = client.db(MONGODB_DB).collection('users');
  await users.createIndex({ usernameLower: 1 }, { unique: true });

  app.listen(PORT, () => {
    console.log(`Shape game API listening on port ${PORT} (${isProd ? 'production' : 'development'})`);
    if (isProd && allowedOrigins.length === 0) {
      console.warn('ALLOWED_ORIGINS is empty: browsers will be blocked. Set it to your game\'s URL.');
    }
  });
}

start().catch((err) => {
  console.error('Could not start:', err.message);
  process.exit(1);
});
