const express = require("express");
const { register, login, logout } = require("../controllers/authController");

const protect = require("../middleware/authMiddleware");

const router = express.Router();

// ================= PUBLIC ROUTES =================

// Register
router.post("/register", register);

// Login
router.post("/login", login);

// Logout
router.post("/logout", logout);

// ================= PROTECTED ROUTES =================

// Example: Get current user
router.get("/me", protect, (req, res) => {
  res.json({
    message: "User data fetched successfully",
    user: req.user,
  });
});

module.exports = router;
