const rateLimit = require("express-rate-limit");

// ================= LOGIN LIMITER =================
exports.loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000,
  max: 5,

  keyGenerator: (req) => {
    return req.ip + "-" + (req.body.email || "");
  },

  skipSuccessfulRequests: true,

  message: {
    success: false,
    message: "Too many login attempts. Try again after 10 minutes.",
  },

  standardHeaders: true,
  legacyHeaders: false,
});

// ================= REGISTER LIMITER =================
exports.signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 10,

  message: {
    success: false,
    message: "Too many registration attempts. Try again after an hour.",
  },

  standardHeaders: true,
  legacyHeaders: false,
});

// ================= GLOBAL LIMITER =================
exports.apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 100,

  message: {
    success: false,
    message:
      "Too many requests from this IP, please try again after 15 minutes.",
  },

  standardHeaders: true,
  legacyHeaders: false,
});
