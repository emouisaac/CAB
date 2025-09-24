const express = require('express');
const router = express.Router();

// In-memory affiliate data (replace with DB in production)
const affiliates = [];

// Register affiliate
router.post('/register', (req, res) => {
  const { username } = req.body;
  if (affiliates.find(a => a.username === username)) {
    return res.status(400).json({ message: 'Affiliate already exists' });
  }
  affiliates.push({ username, referrals: 0, commission: 0 });
  res.json({ message: 'Affiliate registered' });
});

// Get affiliate dashboard
router.get('/dashboard', (req, res) => {
  const { username } = req.query;
  const affiliate = affiliates.find(a => a.username === username);
  if (!affiliate) {
    return res.status(404).json({ message: 'Affiliate not found' });
  }
  res.json(affiliate);
});

// Add referral (simulate)
router.post('/referral', (req, res) => {
  const { username } = req.body;
  const affiliate = affiliates.find(a => a.username === username);
  if (!affiliate) {
    return res.status(404).json({ message: 'Affiliate not found' });
  }
  affiliate.referrals += 1;
  affiliate.commission += 10; // Example commission
  res.json({ message: 'Referral added', affiliate });
});

module.exports = router;
