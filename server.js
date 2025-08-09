// server.js — Full, integrated backend with admin management + password change
require('dotenv').config();
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const app = express();
const PORT = Number(process.env.PORT) || 3000;
const DEBUG = process.env.DEBUG === 'true';

// --- Middleware ---
app.use(express.urlencoded({ extended: true }));
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Debug logger
app.use((req, res, next) => {
  if (DEBUG) {
    console.log('---', req.method, req.url);
    console.log('Cookies:', req.headers.cookie || '(none)');
    console.log('Session before:', req.session);
  }
  next();
});

// Session (dev-friendly)
app.use(session({
  store: new SQLiteStore({ db: 'sessions.db', dir: '.' }),
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    maxAge: 7 * 24 * 60 * 60 * 1000,
    secure: false,
    httpOnly: true,
    sameSite: 'lax'
  }
}));

// --- Database ---
const DB_PATH = path.join(__dirname, 'users.db');
const db = new sqlite3.Database(DB_PATH, (err) => {
  if (err) {
    console.error('Failed to open DB:', err);
    process.exit(1);
  }
  console.log('Opened DB:', DB_PATH);
});

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
  )`, (err) => {
    if (err) console.error('Create table error:', err);
  });
});

// --- Email (nodemailer) ---
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
  console.log('EMAIL_USER / EMAIL_PASS not set — email disabled (dev).');
}

function sendVerification(email, token) {
  const baseUrl = process.env.BASE_URL || `http://localhost:${PORT}`;
  const url = `${baseUrl}/verify/${token}`;
  if (!transporter) {
    console.log('[DEV] Verification link:', url);
    return Promise.resolve();
  }
  return transporter.sendMail({
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Antimatter — Verify your email',
    html: `<p>Please verify your Antimatter account: <a href="${url}">${url}</a></p>`
  });
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

// --- Routes: Pages ---
app.get('/', (req, res) => {
  if (req.session.user) return res.redirect('/dashboard');
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
app.get('/login', (req, res) => res.sendFile(path.join(__dirname, 'public', 'login.html')));
app.get('/register', (req, res) => res.sendFile(path.join(__dirname, 'public', 'register.html')));

// Dashboard page (for logged-in users)
app.get('/dashboard', (req, res) => {
  if (!req.session.user) return res.redirect('/login');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Admin page (serves inline admin UI)
app.get('/admin', (req, res) => {
  if (!req.session.user || !req.session.user.isAdmin) return res.redirect('/login');

  // Inline admin HTML (keeps one-file server)
  res.send(`
    <!doctype html><html><head><meta charset="utf-8"><title>Admin - Antimatter</title>
    <style>
      body{font-family:Arial,Helvetica,sans-serif;margin:20px}
      #userList{max-height:500px;overflow:auto;border:1px solid #ccc;padding:10px}
      .userRow{display:flex;justify-content:space-between;padding:8px;border-bottom:1px solid #eee}
      .userInfo{flex:1}
      button{padding:6px 10px}
      .highlight{background:#ffd}
    </style></head><body>
    <h1>Admin — Users</h1>
    <p>Shows username, email, joinNumber and password hash. Use Kick to delete a user.</p>
    <div id="searchC"><label>Search by joinNumber:</label>
      <input id="searchInput" type="number" min="1" style="width:120px"/></div>
    <div id="userList">Loading...</div>
    <script>
      async function fetchUsers(){
        const res = await fetch('/api/admin/users');
        if(!res.ok){ document.getElementById('userList').innerText='Failed to load'; return; }
        const users = await res.json();
        render(users);
      }
      function render(users){
        const c = document.getElementById('userList'); c.innerHTML='';
        users.forEach(u=>{
          const row = document.createElement('div'); row.className='userRow'; row.id='user-'+u.id;
          row.innerHTML = '<div class="userInfo"><b>'+u.username+'</b> | '+u.email+' | Join#: '+u.joinNumber+
            '<br/><small style="font-family:monospace">'+u.password+'</small></div>';
          const btn = document.createElement('button'); btn.textContent='Kick';
          btn.addEventListener('click', async ()=> {
            if(!confirm("Delete "+u.username+"?")) return;
            const r = await fetch('/api/admin/users/'+u.id, { method: 'DELETE' });
            if(r.ok){ row.remove(); alert('Deleted'); } else { alert('Failed'); }
          });
          row.appendChild(btn); c.appendChild(row);
        });
      }
      document.getElementById('searchInput').addEventListener('keydown', e=>{
        if(e.key==='Enter'){ const v=Number(e.target.value); if(!v) return;
          document.querySelectorAll('.highlight').forEach(x=>x.classList.remove('highlight'));
          const rows = Array.from(document.querySelectorAll('.userRow'));
          const found = rows.find(r => r.innerText.includes('Join#: '+v));
          if(found){ found.classList.add('highlight'); found.scrollIntoView({behavior:'smooth',block:'center'}); }
        }
      });
      fetchUsers();
    </script>
    </body></html>
  `);
});

// --- Register (POST) ---
app.post('/register', (req, res) => {
  const { username, email, password } = req.body || {};
  if (!username || !email || !password) return res.status(400).send('Please fill out all fields.');

  nextJoinNumber((err, joinNumber) => {
    if (err) { console.error('joinNumber err', err); return res.status(500).send('DB error'); }

    bcrypt.hash(password, 10, (err, hash) => {
      if (err) { console.error('hash err', err); return res.status(500).send('Server error'); }

      const token = crypto.randomBytes(20).toString('hex');
      const autoVerify = false; // require verification explicitly

      const sql = `INSERT INTO users (username, email, password, verified, verification_token, joinNumber)
                   VALUES (?, ?, ?, ?, ?, ?)`;
      db.run(sql, [username, email, hash, autoVerify ? 1 : 0, autoVerify ? null : token, joinNumber], function(err) {
        if (err) {
          console.error('Insert user error:', err.message);
          if (err.message.includes('UNIQUE')) return res.status(400).send('Username or email already taken.');
          return res.status(500).send('Database error.');
        }

        // destroy existing session to avoid accidental auto-login
        req.session.destroy(() => {
          sendVerification(email, token)
            .then(() => res.send(`Registered. Verification sent to ${email}. Please verify before logging in.`))
            .catch(e => {
              console.error('Send verify error:', e);
              res.status(500).send('Registered but failed to send verification email.');
            });
        });
      });
    });
  });
});

// --- Verify ---
app.get('/verify/:token', (req, res) => {
  const token = req.params.token;
  if (!token) return res.status(400).send('Missing token.');

  db.get('SELECT id, verified FROM users WHERE verification_token = ?', [token], (err, row) => {
    if (err) { console.error('verify get', err); return res.status(500).send('DB error'); }
    if (!row) return res.status(400).send('<p>Invalid or expired token.</p><p><a href="/login">Back</a></p>');
    if (row.verified) return res.send('<p>Already verified.</p><p><a href="/login">Login</a></p>');
    db.run('UPDATE users SET verified = 1, verification_token = NULL WHERE id = ?', [row.id], (err) => {
      if (err) { console.error('verify update', err); return res.status(500).send('DB error'); }
      res.send('<p>Verified! <a href="/login">Login</a></p>');
    });
  });
});

// --- Login (POST) ---
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).send('Please fill out all fields.');

  // ENV admin shortcut
  const ADMIN_USER = process.env.ADMIN_USERNAME;
  const ADMIN_PASS = process.env.ADMIN_PASSWORD;
  if (ADMIN_USER && ADMIN_PASS && username === ADMIN_USER) {
    if (password === ADMIN_PASS) {
      req.session.user = { id: 'env-admin', username: ADMIN_USER, isAdmin: true, joinNumber: null };
      return req.session.save(err => { if (err) { console.error('sess save', err); return res.status(500).send('err'); } return res.redirect('/admin'); });
    } else return res.status(400).send('Invalid username or password.');
  }

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) { console.error('login db get', err); return res.status(500).send('DB error'); }
    if (!user) return res.status(400).send('Invalid username or password.');
    if (!user.verified) return res.status(403).send('Please verify your email first.');

    bcrypt.compare(password, user.password, (err, match) => {
      if (err) { console.error('bcrypt compare', err); return res.status(500).send('Server error'); }
      if (!match) return res.status(400).send('Invalid username or password.');

      req.session.user = { id: user.id, username: user.username, isAdmin: Number(user.isAdmin) === 1, joinNumber: user.joinNumber };
      req.session.save(err => {
        if (err) { console.error('sess save error', err); return res.status(500).send('Server error'); }
        return res.redirect(user.isAdmin === 1 ? '/admin' : '/dashboard');
      });
    });
  });
});

// --- API: current user (for dashboard) ---
app.get('/api/user', (req, res) => {
  if (!req.session.user) return res.status(401).json({ error: 'Not authenticated' });
  return res.json({ username: req.session.user.username, joinNumber: req.session.user.joinNumber, isAdmin: req.session.user.isAdmin });
});

// --- API: list users for dashboard (safe fields only) ---
app.get('/api/users', ensureAuthenticated, (req, res) => {
  db.all('SELECT id, username, joinNumber FROM users ORDER BY joinNumber ASC', (err, rows) => {
    if (err) { console.error('users fetch', err); return res.status(500).json({ error: 'DB error' }); }
    res.json(rows);
  });
});

// --- API: admin full users (email + password hash) ---
app.get('/api/admin/users', ensureAdmin, (req, res) => {
  db.all('SELECT id, username, email, password, joinNumber FROM users ORDER BY joinNumber ASC', (err, rows) => {
    if (err) { console.error('admin users', err); return res.status(500).json({ error: 'DB error' }); }
    res.json(rows);
  });
});

// --- API: admin delete user (kick) ---
app.delete('/api/admin/users/:id', ensureAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid id' });
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) { console.error('admin delete', err); return res.status(500).json({ error: 'DB error' }); }
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ ok: true });
  });
});

// --- Change password (logged-in user) ---
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
        db.run('UPDATE users SET password = ? WHERE id = ?', [hash, userId], function(err) {
          if (err) { console.error('update pw', err); return res.status(500).json({ error: 'DB error' }); }
          // Optionally keep user logged in; we return success
          res.json({ ok: true, message: 'Password changed successfully' });
        });
      });
    });
  });
});

// --- whoami debug ---
app.get('/whoami', (req, res) => res.json({ session: req.session || null }));

// --- logout (POST for fetch and GET for link) ---
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

// --- Final debug middleware ---
app.use((req, res, next) => {
  if (DEBUG) console.log('Session after:', req.session);
  next();
});

// --- Start ---
app.listen(PORT, () => {
  console.log(`Antimatter server listening at http://localhost:${PORT}`);
  if (DEBUG) console.log('DEBUG mode ON');
});