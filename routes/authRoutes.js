const express = require("express");
const router = express.Router();
const passport = require("passport");

const {
  signup,
  login,
  logout,
  googleLogin,
  refreshToken,
  verifyEmail,
  forgotPassword,
  resetPassword,
  changePassword,
} = require("../controllers/authController");

const { loginLimiter, signupLimiter } = require("../middlewares/rateLimiter");

const { protect } = require("../middlewares/authMiddleware");

// utils (needed for GitHub callback)
const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/generateToken");

const cookieOptions = require("../utils/cookieOptions");

// ================= BASIC AUTH =================

// Rate limiting
router.post("/signup", signupLimiter, signup);
router.post("/login", loginLimiter, login);

// Auth actions
router.post("/logout", logout);
router.post("/google-login", googleLogin);
router.post("/refresh-token", refreshToken);

// Email verification
router.get("/verify-email", verifyEmail);

// ================= PASSWORD =================

router.post("/forgot-password", forgotPassword);
router.post("/reset-password/:token", resetPassword);

// Protected route
router.post("/change-password", protect, changePassword);

// ================= GITHUB AUTH =================

// 🔗 Step 1: Redirect to GitHub
router.get(
  "/github",
  passport.authenticate("github", { scope: ["user:email"] }),
);

// 🔗 Step 2: Callback
router.get(
  "/github/callback",
  passport.authenticate("github", {
    session: false,
    failureRedirect: "/login",
  }),
  async (req, res) => {
    try {
      const user = req.user;

      const accessToken = generateAccessToken(user._id);
      const refreshToken = generateRefreshToken(user._id, user.tokenVersion);

      // Save refresh token
      user.refreshToken = refreshToken;
      await user.save();

      res
        .cookie("accessToken", accessToken, cookieOptions)
        .cookie("refreshToken", refreshToken, cookieOptions)
        .redirect("http://localhost:3000/dashboard"); // frontend redirect
    } catch (err) {
      res.redirect("http://localhost:3000/login");
    }
  },
);

module.exports = router;
