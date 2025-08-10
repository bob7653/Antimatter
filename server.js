// server.js
const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const nodemailer = require('nodemailer');
const sqlite3 = require('sqlite3').verbose();
const bodyParser = require('body-parser');

const app = express();
app.use(bodyParser.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'your_jwt_secret_key';
const EMAIL_FROM = process.env.EMAIL_FROM || 'no-reply@yourdomain.com';
const EMAIL_USER = process.env.EMAIL_USER;      // Set these in your env!
const EMAIL_PASSWORD = process.env.EMAIL_PASSWORD;

if (!EMAIL_USER || !EMAIL_PASSWORD) {
  console.error('ERROR: EMAIL_USER and EMAIL_PASSWORD environment variables must be set!');
  process.exit(1);
}

// Setup SQLite DB
const db = new sqlite3.Database('./antimatter.db', (err) => {
  if (err) {
    console.error('Could not connect to database', err);
    process.exit(1);
  }
  console.log('Connected to SQLite database');
});

// Create users table if not exists
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  email TEXT UNIQUE,
  password TEXT,
  verified INTEGER DEFAULT 0,
  isAdmin INTEGER DEFAULT 0,
  joinNumber INTEGER
)`);

// Nodemailer transporter
const transporter = nodemailer.createTransport({
  service: 'gmail', // or your SMTP provider
  auth: {
    user: EMAIL_USER,
    pass: EMAIL_PASSWORD,
  },
});

// Send verification email helper
async function sendVerificationEmail(userEmail, token) {
  const verifyUrl = `http://localhost:${PORT}/verify-email?token=${token}`; // Change domain to your production

  const mailOptions = {
    from: EMAIL_FROM,
    to: userEmail,
    subject: 'Verify your Antimatter account email',
    html: `
      <h2>Welcome to Antimatter!</h2>
      <p>Click the link below to verify your email address:</p>
      <a href="${verifyUrl}">${verifyUrl}</a>
      <p>This link will expire in 24 hours.</p>
    `,
  };

  await transporter.sendMail(mailOptions);
}

// Registration route
app.post('/register', async (req, res) => {
  try {
    const { username, email, password } = req.body || {};

    // Basic validations
    if (!username || !email || !password) {
      return res.status(400).send('Please fill out all fields.');
    }
    if (password.length < 6) {
      return res.status(400).send('Password must be at least 6 characters.');
    }
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    if (!emailRegex.test(email)) {
      return res.status(400).send('Invalid email format.');
    }

    // Check if username or email exists
    const existingUser = await new Promise((resolve, reject) => {
      db.get('SELECT id FROM users WHERE username = ? OR email = ?', [username, email], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (existingUser) {
      return res.status(400).send('Username or email already taken.');
    }

    // Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // Insert user with verified=0
    const userId = await new Promise((resolve, reject) => {
      const stmt = db.prepare('INSERT INTO users (username, email, password, verified, isAdmin, joinNumber) VALUES (?, ?, ?, 0, 0, NULL)');
      stmt.run(username, email, hashedPassword, function (err) {
        if (err) reject(err);
        else resolve(this.lastID);
      });
    });

    // Generate verification token
    const token = jwt.sign({ userId, email }, JWT_SECRET, { expiresIn: '24h' });

    // Send email (don't await to avoid blocking)
    sendVerificationEmail(email, token).catch((err) => {
      console.error('Email sending error:', err);
    });

    res.status(201).send('Registered successfully! Verification email sent.');
  } catch (error) {
    console.error('Registration error:', error);
    res.status(500).send('Server error');
  }
});

// Email verification route
app.get('/verify-email', async (req, res) => {
  const { token } = req.query;
  if (!token) return res.status(400).send('Missing token.');

  try {
    // Verify token
    const payload = jwt.verify(token, JWT_SECRET);

    // Update user verified flag
    await new Promise((resolve, reject) => {
      db.run('UPDATE users SET verified = 1 WHERE id = ?', [payload.userId], function (err) {
        if (err) reject(err);
        else resolve();
      });
    });

    res.send('Email verified successfully! You can now log in.');
  } catch (error) {
    console.error('Verification error:', error);
    if (error.name === 'TokenExpiredError') {
      res.status(400).send('Verification link expired.');
    } else {
      res.status(400).send('Invalid verification link.');
    }
  }
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
});