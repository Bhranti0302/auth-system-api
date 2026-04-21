const express = require("express");
const router = express.Router();

const {
  signup,
  login,
  logout,
  googleLogin,
  refreshToken,
  verifyEmail,
} = require("../controllers/authController");

const { loginLimiter, signupLimiter } = require("../middlewares/rateLimiter");

// ✅ Apply rate limiting
router.post("/signup", signupLimiter, signup);
router.post("/login", loginLimiter, login);

router.post("/logout", logout);
router.post("/google-login", googleLogin);
router.post("/refresh-token", refreshToken);

router.get("/verify-email", verifyEmail);

module.exports = router;
