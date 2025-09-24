require('dotenv').config();
const express = require('express');
const router = express.Router();
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;

// In-memory store for codes: { email: { code, expires } }
const codeStore = {};

// Configure nodemailer (use your real SMTP in production)
const transporter = nodemailer.createTransport({
  service: 'gmail',
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

// Send login code endpoint
router.post('/send-code', async (req, res) => {
  const { email } = req.body;
  if (!email) return res.status(400).json({ message: 'Email required' });
  const code = (Math.floor(100000 + Math.random() * 900000)).toString();
  codeStore[email] = { code, expires: Date.now() + 10 * 60 * 1000 }; // 10 min expiry
  try {
    await transporter.sendMail({
      from: process.env.EMAIL_USER,
      to: email,
      subject: 'Your Login Code',
      text: `Your login code is: ${code}`
    });
    res.json({ message: 'Code sent' });
  } catch (err) {
    res.status(500).json({ message: 'Failed to send code', error: err.message });
  }
});

// Verify code and login/register endpoint
router.post('/verify-code', (req, res) => {
  const { email, code } = req.body;
  const entry = codeStore[email];
  if (!entry || entry.code !== code || entry.expires < Date.now()) {
    return res.status(400).json({ message: 'Invalid or expired code' });
  }
  // Remove code after use
  delete codeStore[email];
  // Register user if not exists
  let user = users.find(u => u.email === email);
  if (!user) {
    user = { email, username: email.split('@')[0] };
    users.push(user);
  }
  req.session.user = user.username;
  req.login(user, err => {
    if (err) return res.status(500).json({ message: 'Login failed' });
    res.json({ message: 'Login successful', user: { username: user.username, email: user.email } });
  });
});

// ...existing code...

// Get current user info (for frontend after Google login)
router.get('/user', (req, res) => {
  if (req.isAuthenticated && req.isAuthenticated() && req.user) {
    res.json({ displayName: req.user.displayName, email: req.user.email });
  } else {
    res.status(401).json({});
  }
});

// In-memory user store (replace with DB in production)
const users = [];

// Passport config
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: '/auth/google/callback',
  },
  function(accessToken, refreshToken, profile, done) {
    let user = users.find(u => u.googleId === profile.id);
    if (!user) {
      user = {
        googleId: profile.id,
        displayName: profile.displayName,
        email: profile.emails && profile.emails[0] ? profile.emails[0].value : '',
      };
      users.push(user);
    }
    return done(null, user);
  }
));

passport.serializeUser((user, done) => {
  done(null, user.googleId);
});
passport.deserializeUser((id, done) => {
  const user = users.find(u => u.googleId === id);
  done(null, user);
});

// Google OAuth routes
router.get('/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

router.get('/google/callback', passport.authenticate('google', {
  failureRedirect: '/?login=failed',
  session: true
}), (req, res, next) => {
  // Ensure session is saved before redirect
  req.login(req.user, function(err) {
    if (err) { return next(err); }
    req.session.save(() => {
      res.redirect('/?login=success');
    });
  });
});

// Registration (local, not used for Google)
router.post('/register', (req, res) => {
  const { username, password } = req.body;
  if (users.find(u => u.username === username)) {
    return res.status(400).json({ message: 'User already exists' });
  }
  users.push({ username, password });
  res.json({ message: 'Registration successful' });
});

// Login (local, not used for Google)
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const user = users.find(u => u.username === username && u.password === password);
  if (!user) {
    return res.status(401).json({ message: 'Invalid credentials' });
  }
  req.session.user = username;
  res.json({ message: 'Login successful' });
});

// Logout
router.post('/logout', (req, res) => {
  req.session.destroy();
  res.json({ message: 'Logged out' });
});

module.exports = router;
