const rateLimit = require("express-rate-limit");

// ================= LOGIN LIMITER =================
exports.loginLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // Limit each IP to 5 login requests per `window` (here, per 10 minutes)
  message: {
    success: false,
    message: "Too many login attempts. Try again after 10 minutes.",
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
});

// ================= REGISTER LIMITER =================
exports.signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 10, // Limit each IP to 10 registration requests per `window` (here, per hour)
  message: {
    success: false,
    message: "Too many registration attempts. Try again after an hour.",
  },
});

// ================= Global Limiter  =================
exports.apiLimiter = rateLimit({
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 100, // Limit each IP to 100 requests per `window` (here, per 15 minutes)
    message: {
        success: false,
        message: "Too many requests from this IP, please try again after 15 minutes."
    }
})