const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const helmet = require("helmet");
const csurf = require("csurf");

const app = express();

const { apiLimiter } = require("./middlewares/rateLimiter");

const authRoutes = require("./routes/authRoutes");
const testRoutes = require("./routes/testRoutes");

// 🔥 Trust proxy (IMPORTANT for deployment)
app.set("trust proxy", 1);

// 🔐 Security headers
app.use(helmet());

// Body parser
app.use(express.json());

// Cookie parser
app.use(cookieParser());

// 🔐 Rate limiter (only API routes)
app.use("/api", apiLimiter);

// 🔐 Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
);

// ================= CSRF SETUP =================

// Create CSRF middleware
const csrfProtection = csurf({
  cookie: true,
});

// ✅ Route to get CSRF token
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// ✅ Apply CSRF protection selectively
app.use("/api", (req, res, next) => {
  // Skip safe methods
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  // Skip public auth routes
  if (
    req.path === "/auth/login" ||
    req.path === "/auth/signup" ||
    req.path === "/auth/google-login" ||
    req.path === "/auth/refresh-token" ||
    req.path === "/auth/verify-email"
  ) {
    return next();
  }

  return csrfProtection(req, res, next);
});

// ================= ROUTES =================

app.get("/", (req, res) => {
  res.json({ success: true, message: "API running" });
});

app.use("/api/auth", authRoutes);
app.use("/api/test", testRoutes);

// ================= ERROR HANDLER =================

app.use((err, req, res, next) => {
  // 🔥 Handle CSRF errors
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({
      success: false,
      message: "Invalid CSRF token",
    });
  }

  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || "Server Error",
  });
});

module.exports = app;
