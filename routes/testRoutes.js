const express = require("express");
const router = express.Router();

const { protect, sessionProtect } = require("../middleware/authMiddleware");

// JWT route
router.get("/jwt-profile", protect, (req, res) => {
  res.json({ user: req.user });
});

// Session route
router.get("/google-profile", sessionProtect, (req, res) => {
  res.json({ user: req.session.user });
});

module.exports = router;
