require('dotenv').config();
const express = require('express');
const path = require('path');
const sqlite3 = require('sqlite3').verbose();
const session = require('express-session');
const SQLiteStore = require('connect-sqlite3')(session);
const bcrypt = require('bcrypt');
const crypto = require('crypto');
const nodemailer = require('nodemailer');

const PORT = Number(process.env.PORT) || 3000;
const app = express();
const DEBUG = process.env.DEBUG === 'true';

// Warn if BASE_URL missing
if (!process.env.BASE_URL) {
  console.warn('[WARN] BASE_URL environment variable not set! Defaulting to localhost.');
  process.env.BASE_URL = `http://localhost:${PORT}`;
}

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
  console.log(`[DEBUG] Using BASE_URL: ${baseUrl}`); // Debug line added
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
          return res.status(500).send('DB error');
        }
        if (!autoVerify) {
          sendVerification(email, token).catch(e => console.error('Email send error:', e));
        }
        res.send('Registration successful! Please check your email for verification link.');
      });
    });
  });
});

// --- Verify email link ---
app.get('/verify/:token', (req, res) => {
  const token = req.params.token;
  db.get('SELECT id, verified FROM users WHERE verification_token = ?', [token], (err, user) => {
    if (err) return res.status(500).send('DB error');
    if (!user) return res.status(400).send('Invalid verification link.');
    if (user.verified) return res.send('Your account is already verified.');

    db.run('UPDATE users SET verified=1, verification_token=NULL WHERE id = ?', [user.id], err => {
      if (err) return res.status(500).send('DB error');
      res.send('Email verified! You can now log in.');
    });
  });
});

// --- Login (POST) ---
app.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).send('Missing username or password.');

  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) return res.status(500).send('DB error');
    if (!user) return res.status(400).send('Invalid username or password.');
    if (!user.verified) return res.status(400).send('Please verify your email first.');

    bcrypt.compare(password, user.password, (err, match) => {
      if (err) return res.status(500).send('Server error');
      if (!match) return res.status(400).send('Invalid username or password.');

      req.session.user = {
        id: user.id,
        username: user.username,
        email: user.email,
        isAdmin: user.isAdmin === 1,
        joinNumber: user.joinNumber
      };
      res.send('Login successful!');
    });
  });
});

// --- Logout ---
app.post('/logout', (req, res) => {
  req.session.destroy(() => {
    res.send('Logged out');
  });
});

// --- API: Admin users list ---
app.get('/api/admin/users', ensureAdmin, (req, res) => {
  db.all('SELECT id, username, email, password, joinNumber FROM users ORDER BY joinNumber ASC', (err, rows) => {
    if (err) return res.status(500).json({ error: 'DB error' });
    res.json(rows);
  });
});

// --- API: Admin delete user ---
app.delete('/api/admin/users/:id', ensureAdmin, (req, res) => {
  const id = Number(req.params.id);
  if (!id) return res.status(400).json({ error: 'Invalid user id' });
  db.run('DELETE FROM users WHERE id = ?', [id], function(err) {
    if (err) return res.status(500).json({ error: 'DB error' });
    if (this.changes === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ success: true });
  });
});

// --- Start server ---
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
});