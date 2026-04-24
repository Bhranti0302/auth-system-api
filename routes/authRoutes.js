const express = require("express");
const router = express.Router();

const {
  signup,
  login,
  logout,
  googleLogin,
  refreshToken,
  verifyEmail,
  forgotPassword, 
  resetPassword,
} = require("../controllers/authController");

const { loginLimiter, signupLimiter } = require("../middlewares/rateLimiter");
const { protect } = require("../middlewares/authMiddleware"); // ✅ REQUIRED

// ✅ Apply rate limiting
router.post("/signup", signupLimiter, signup);
router.post("/login", loginLimiter, login);

router.post("/logout", logout);
router.post("/google-login", googleLogin);
router.post("/refresh-token", refreshToken);

router.get("/verify-email", verifyEmail);

// ✅ Password reset
router.post("/forgot-password", forgotPassword); // ✅ FIXED
router.post("/reset-password/:token", resetPassword);


module.exports = router;
