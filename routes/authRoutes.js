const express = require("express");
const router = express.Router();

const {
  signup,
  login,
  logout,
  googleLogin,
  githubLogin,
  facebookLogin,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  changePassword,
} = require("../controllers/authController");

const { loginLimiter, signupLimiter } = require("../middlewares/rateLimiter");
const { protect } = require("../middlewares/authMiddleware");

// ================= BASIC AUTH =================

router.post("/signup", signupLimiter, signup);
router.post("/login", loginLimiter, login);

router.post("/logout", logout);
router.post("/google-login", googleLogin);
router.post("/github-login", githubLogin); // ✅ clean
router.post("/facebook-login", facebookLogin); // ✅ clean
router.post("/refresh-token", refreshToken);

router.get("/verify-email", verifyEmail);

// ================= PASSWORD =================

router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

router.post("/change-password", protect, changePassword);

module.exports = router;
