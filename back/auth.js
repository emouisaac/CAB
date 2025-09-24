
// Load environment variables from .env
require('dotenv').config();

const express = require('express');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const router = express.Router();

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
