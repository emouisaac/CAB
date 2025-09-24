const express = require('express');
const router = express.Router();

// Placeholder payment route
router.post('/pay', (req, res) => {
  // Integrate with payment gateway here
  res.json({ message: 'Payment processed (placeholder)' });
});

module.exports = router;
