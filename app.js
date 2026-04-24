const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const MongoStore = require("connect-mongo");
const helmet = require("helmet");
const csurf = require("csurf");
const cors = require("cors");

require("dotenv").config();

const app = express();

// 🔗 Passport (OAuth)
require("./utils/passport");

// 🔐 Rate limiter
const { apiLimiter } = require("./middlewares/rateLimiter");

// Routes
const authRoutes = require("./routes/authRoutes");
const testRoutes = require("./routes/testRoutes");

// 🔥 Trust proxy (for deployment)
app.set("trust proxy", 1);

// ================= MIDDLEWARE =================

// 🔐 Security headers
app.use(helmet());

// 🌐 CORS (IMPORTANT)
app.use(
  cors({
    origin: "http://localhost:3000",
    credentials: true,
  }),
);

// 📦 Body parser
app.use(express.json());

// 🍪 Cookie parser
app.use(cookieParser());

// 🚦 Rate limiting
app.use("/api", apiLimiter);

// 🔐 Session (required for OAuth only)
app.use(
  session({
    name: "sessionId",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,

    store: MongoStore.create({
      mongoUrl: process.env.MONGO_URI,
      collectionName: "sessions",
      ttl: 14 * 24 * 60 * 60,
    }),

    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 14 * 24 * 60 * 60 * 1000,
    },
  }),
);

// 🛂 Passport init (NO session needed)
const passport = require("passport");
app.use(passport.initialize());

// ================= CSRF =================

// CSRF config
const csrfProtection = csurf({
  cookie: {
    httpOnly: true,
    sameSite: "lax",
    secure: process.env.NODE_ENV === "production",
  },
});

// 🔑 Get CSRF token
app.get("/api/csrf-token", csrfProtection, (req, res) => {
  res.json({ csrfToken: req.csrfToken() });
});

// 🛡️ Apply CSRF selectively
app.use("/api", (req, res, next) => {
  // Skip safe methods
  if (["GET", "HEAD", "OPTIONS"].includes(req.method)) {
    return next();
  }

  // Skip auth routes
  if (
    req.path === "/auth/login" ||
    req.path === "/auth/signup" ||
    req.path === "/auth/google-login" ||
    req.path === "/auth/refresh-token" ||
    req.path === "/auth/verify-email" ||
    req.path === "/auth/logout" ||
    req.path === "/auth/forgot-password" ||
    req.path.startsWith("/auth/reset-password") ||
    req.path === "/auth/github" ||
    req.path.startsWith("/auth/github/callback")
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
  // CSRF error
  if (err.code === "EBADCSRFTOKEN") {
    return res.status(403).json({
      success: false,
      message: "Invalid CSRF token",
    });
  }

  res.status(err.statusCode || 500).json({
    success: false,
    message:
      process.env.NODE_ENV === "production" ? "Server Error" : err.message,
  });
});

module.exports = app;
