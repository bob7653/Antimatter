// server.js — Antimatter backend (drop-in replacement)
//
// Requirements / env vars (Render):
//   SESSION_SECRET (required for production sessions)
//   BASE_URL (e.g. https://antimatter-w9uh.onrender.com) — strongly recommended
//   EMAIL_USER, EMAIL_PASS (optional — if missing, verification links printed to logs)
//   ADMIN_USERNAME, ADMIN_PASSWORD (optional env admin shortcut)
//   NODE_ENV=production for production mode
//   DEBUG=true for verbose logs while testing
//
// IMPORTANT: do NOT commit node_modules. On Render, remove any PORT override.

require('dotenv').config();
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');
const morgan = require('morgan');

const PORT = Number(process.env.PORT) || 3000;
const DEBUG = process.env.DEBUG === 'true';
const BASE_URL = process.env.BASE_URL || `http://localhost:${PORT}`;
const NODE_ENV = process.env.NODE_ENV || 'development';

const app = express();

// trust proxy (needed on many PaaS so secure cookie detection works)
app.set('trust proxy', 1);

// security headers
app.use(helmet());

// logging
if (DEBUG) {
  app.use(morgan('dev'));
} else {
  app.use(morgan('combined'));
}

// body parsing & static files
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// session config (SQLite store)
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    secure: NODE_ENV === 'production', // require HTTPS in production
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// --- Database (SQLite) ---
const DB_PATH = path.join(__dirname, 'users.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Failed to open DB:', err);
    process.exit(1);
  }
  console.log('Opened DB:', DB_PATH);
});

// Create tables if missing
db.serialize(() => {
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    email TEXT UNIQUE,
    password TEXT,
    verified INTEGER DEFAULT 0,
    verification_token TEXT,
    joinNumber INTEGER UNIQUE,
    isAdmin INTEGER DEFAULT 0
  )`);

  db.run(`CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER,
    token TEXT UNIQUE,
    expires_at INTEGER,
    FOREIGN KEY (user_id) REFERENCES users(id)
  )`);
});

// --- Nodemailer setup (Gmail) ---
let transporter = null;
if (process.env.EMAIL_USER && process.env.EMAIL_PASS) {
  transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });

  transporter.verify()
    .then(() => console.log('Nodemailer ready.'))
    .catch((e) => {
      console.warn('Nodemailer verify failed:', e.message || e);
      transporter = null;
    });
} else {
  console.log('EMAIL_USER / EMAIL_PASS not set — email disabled (dev). Verification links will be printed to logs.');
}

// --- Helpers ---
function nextJoinNumber(cb) {
  db.get('SELECT MAX(joinNumber) AS m FROM users', (err, row) => {
    if (err) return cb(err);
    cb(null, (row && row.m) ? row.m + 1 : 1);
  });
}

function ensureAuthenticated(req, res, next) {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  next();
}

function ensureAdmin(req, res, next) {
  if (!req.session.user || !req.session.user.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// rate limiters for auth endpoints
const authLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 12,
  message: { error: 'Too many requests, slow down' }
});

// send verification email (or log link)
function sendVerification(email, token) {
  const url = `${BASE_URL.replace(/\/$/, '')}/verify/${token}`;
  console.log(`[VERIFICATION] ${email} -> ${url}`);
  if (!transporter) return Promise.resolve();
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Antimatter — Verify your email',
    html: `<p>Please verify your Antimatter account by clicking <a href="${url}">this link</a>.</p>`
  });
}

function sendPasswordReset(email, token) {
  const url = `${BASE_URL.replace(/\/$/, '')}/reset-password?token=${token}`;
  console.log(`[PASSWORD RESET] ${email} -> ${url}`);
  if (!transporter) return Promise.resolve();
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Antimatter — Password reset',
    html: `<p>Reset your password by clicking <a href="${url}">this link</a>. It expires in 1 hour.</p>`
  });
}

// --- Routes: pages ---
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Inline admin page (keeps simple admin UI available)
app.get('/admin', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) return res.redirect('/login');
  // Keep HTML short & same as before (client calls /api/admin/users)
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// --- API endpoints ---

// Register
app.post('/register', authLimiter, (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) return res.status(400).send('Please fill out all fields.');

  nextJoinNumber((err, joinNumber) => {
    if (err) { console.error('joinNumber err', err); return res.status(500).send('DB error'); }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) { console.error('hash err', err); return res.status(500).send('Server error'); }

      const token = crypto.randomBytes(20).toString('hex');
      const sql = `INSERT INTO users (username, email, password, verified, verification_token, joinNumber, isAdmin)
                   VALUES (?, ?, ?, 0, ?, ?, 0)`;
      db.run(sql, [username, email, hash, token, joinNumber], function (err) {
        if (err) {
          console.error('Insert user error:', err.message);
          if (err.message && err.message.includes('UNIQUE')) return res.status(409).send('Username or email already taken.');
          return res.status(500).send('Database error.');
        }

        // registration created — send verification (or log) then inform client
        sendVerification(email, token)
          .then(() => {
            // success: respond 201 so client-side JS redirects to /dashboard or shows message
            res.status(201).send('Registered. Verification email sent.');
          })
          .catch(e => {
            console.error('Send verify error:', e);
            res.status(500).send('Registered but failed to send verification email.');
          });
      });
    });
  });
});

// Resend verification
app.post('/resend-verification', authLimiter, (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).json({ error: 'Email required' });

  db.get('SELECT id, verified FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (!user) return res.status(404).json({ error: 'User not found' });
    if (user.verified) return res.json({ ok: true, message: 'Already verified' });

    const token = crypto.randomBytes(20).toString('hex');
    db.run('UPDATE users SET verification_token = ? WHERE id = ?', [token, user.id], (err) => {
      if (err) return res.status(500).json({ error: 'DB error' });
      sendVerification(email, token).then(() => res.json({ ok: true })).catch(e => { console.error(e); res.status(500).json({ error: 'Email failed' }); });
    });
  });
});

// Verify link
app.get('/verify/:token', (req, res) => {
  const token = req.params.token;
  if (!token) return res.status(400).send('Missing token.');

  db.get('SELECT id, verified FROM users WHERE verification_token = ?', [token], (err, row) => {
    if (err) return res.status(500).send('DB error');
    if (!row) return res.status(400).send('<p>Invalid or expired token.</p><p><a href="/login">Back</a></p>');
    if (row.verified) return res.send('<p>Already verified.</p><p><a href="/login">Login</a></p>');
    db.run('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?', [row.id], (err) => {
      if (err) return res.status(500).send('DB error');
      res.send('<p>Verified! <a href="/login">Login</a></p>');
    });
  });
});

// Login
app.post('/login', authLimiter, (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).send('Please fill out all fields.');

  // env-admin shortcut
  const ADMIN_USER = process.env.ADMIN_USERNAME;
  const ADMIN_PASS = process.env.ADMIN_PASSWORD;
  if (ADMIN_USER && ADMIN_PASS && username === ADMIN_USER) {
    if (password === ADMIN_PASS) {
      req.session.user = { id: 'env-admin', username: ADMIN_USER, isAdmin: true, joinNumber: null };
      return req.session.save(err => {
        if (err) { console.error('sess save', err); return res.status(500).send('err'); }
        return res.redirect('/admin');
      });
    } else return res.status(400).send('Invalid username or password.');
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).send('DB error');
    if (!user) return res.status(400).send('Invalid username or password.');
    if (!user.verified) return res.status(403).send('Please verify your email first.');

    bcrypt.compare(password, user.password, (err, match) => {
      if (err) return res.status(500).send('Server error');
      if (!match) return res.status(400).send('Invalid username or password.');

      req.session.user = { id: user.id, username: user.username, isAdmin: Number(user.isAdmin) === 1, joinNumber: user.joinNumber };
      req.session.save(err => {
        if (err) { console.error('sess save error', err); return res.status(500).send('Server error'); }
        return res.redirect(user.isAdmin === 1 ? '/admin' : '/dashboard');
      });
    });
  });
});

// Forgot password (send reset link)
app.post('/forgot-password', authLimiter, (req, res) => {
  const { email } = req.body || {};
  if (!email) return res.status(400).send('Email required');

  db.get('SELECT id FROM users WHERE email = ?', [email], (err, user) => {
    if (err) return res.status(500).send('DB error');
    if (!user) return res.status(200).send('If that email exists, a reset link has been sent.'); // generic response

    const token = crypto.randomBytes(24).toString('hex');
    const expiresAt = Date.now() + (60 * 60 * 1000);
    db.run('INSERT INTO password_resets (user_id, token, expires_at) VALUES (?, ?, ?)', [user.id, token, expiresAt], function (err) {
      if (err) console.error('Reset insert err', err);
      sendPasswordReset(email, token).then(() => {
        res.status(200).send('If that email exists, a reset link has been sent.');
      }).catch(e => {
        console.error('Password reset email error', e);
        res.status(500).send('Failed to send reset email.');
      });
    });
  });
});

// Reset password (use token)
app.post('/reset-password', authLimiter, (req, res) => {
  const { token, password } = req.body || {};
  if (!token || !password) return res.status(400).send('Missing fields');

  db.get('SELECT * FROM password_resets WHERE token = ?', [token], (err, row) => {
    if (err) return res.status(500).send('DB error');
    if (!row) return res.status(400).send('Invalid or expired token');
    if (row.expires_at < Date.now()) {
      db.run('DELETE FROM password_resets WHERE id = ?', [row.id]);
      return res.status(400).send('Token expired');
    }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) return res.status(500).send('Server error');
      db.run('UPDATE users SET password = ? WHERE id = ?', [hash, row.user_id], function (err) {
        if (err) return res.status(500).send('DB error');
        db.run('DELETE FROM password_resets WHERE id = ?', [row.id]);
        res.send('Password reset successful. You can login now.');
      });
    });
  });
});

// API: current user (returns null if not logged in)
app.get('/api/user', (req, res) => {
  if (!req.session.user) return res.json(null);
  if (req.session.user.id === 'env-admin') return res.json(req.session.user);

  db.get('SELECT id, username, joinNumber, isAdmin FROM users WHERE id = ?', [req.session.user.id], (err, row) => {
    if (err) { console.error('api/user db error', err); return res.status(500).json(null); }
    if (!row) return res.json(req.session.user);
    res.json({
      id: row.id,
      username: row.username,
      joinNumber: row.joinNumber,
      isAdmin: Number(row.isAdmin) === 1
    });
  });
});

// Backwards-compatible endpoint
app.get('/api/me', (req, res) => {
  if (!req.session.user) return res.json(null);
  res.json(req.session.user);
});

// API: list users for dashboard (safe fields only)
app.get('/api/users', ensureAuthenticated, (req, res) => {
  db.all('SELECT id, username, joinNumber FROM users ORDER BY joinNumber ASC', (err, rows) => {
    if (err) { console.error('users fetch', err); return res.status(500).json({ error: 'DB error' }); }
    res.json(rows);
  });
});

// Admin endpoints
app.get('/api/admin/users', ensureAdmin, (req, res) => {
  db.all('SELECT id, username, email, password, joinNumber FROM users ORDER BY joinNumber ASC', (err, rows) => {
    if (err) { console.error('admin users', err); return res.status(500).json({ error: 'DB error' }); }
    res.json(rows);
  });
});
app.delete('/api/admin/users/:id', ensureAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  db.run('DELETE FROM users WHERE id = ?', [id], function (err) {
    if (err) { console.error('admin delete', err); return res.status(500).json({ error: 'DB error' }); }
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    console.log(`ADMIN: user ${id} deleted by ${req.session.user && req.session.user.username}`);
    res.json({ ok: true });
  });
});

// Change password (logged in)
app.post('/api/change-password', ensureAuthenticated, (req, res) => {
  const userId = req.session.user.id;
  const { currentPassword, newPassword } = req.body || {};
  if (!currentPassword || !newPassword) return res.status(400).json({ error: 'Missing fields' });

  db.get('SELECT password FROM users WHERE id = ?', [userId], (err, row) => {
    if (err) { console.error('get pw', err); return res.status(500).json({ error: 'DB error' }); }
    if (!row) return res.status(404).json({ error: 'User not found' });

    bcrypt.compare(currentPassword, row.password, (err, match) => {
      if (err) { console.error('bcrypt compare', err); return res.status(500).json({ error: 'Server error' }); }
      if (!match) return res.status(400).json({ error: 'Current password incorrect' });

      bcrypt.hash(newPassword, 10, (err, hash) => {
        if (err) { console.error('hash new', err); return res.status(500).json({ error: 'Server error' }); }
        db.run('UPDATE users SET password = ? WHERE id = ?', [hash, userId], function (err) {
          if (err) { console.error('update pw', err); return res.status(500).json({ error: 'DB error' }); }
          res.json({ ok: true, message: 'Password changed successfully' });
        });
      });
    });
  });
});

// whoami debug
app.get('/whoami', (req, res) => res.json({ session: req.session || null }));

// logout
app.post('/logout', (req, res) => {
  req.session.destroy(err => {
    if (err) { console.error('logout', err); return res.status(500).json({ error: 'Logout failed' }); }
    res.clearCookie('connect.sid');
    res.json({ ok: true, redirect: '/login' });
  });
});
app.get('/logout', (req, res) => {
  req.session.destroy(() => { res.clearCookie('connect.sid'); res.redirect('/login'); });
});

// final debug middleware
app.use((req, res, next) => {
  if (DEBUG) console.log('Session after:', req.session);
  next();
});

// start server
app.listen(PORT, () => {
  console.log(`Antimatter server listening at ${BASE_URL} (port ${PORT})`);
  if (DEBUG) console.log('DEBUG mode ON');
});