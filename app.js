const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");
const helmet = require("helmet");

const app = express();

const { apiLimiter } = require("./middlewares/rateLimiter");

const authRoutes = require("./routes/authRoutes");
const testRoutes = require("./routes/testRoutes");

// 🔥 Trust proxy (IMPORTANT)
app.set("trust proxy", 1);

// 🔐 Security headers
app.use(helmet());

// Body parser
app.use(express.json());

// Cookie parser
app.use(cookieParser());

// Rate limiter (only API)
app.use("/api", apiLimiter);

// Session middleware
app.use(
  session({
    secret: process.env.SESSION_SECRET || "secret123",
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: "lax",
      maxAge: 24 * 60 * 60 * 1000,
    },
  }),
);

// Routes
app.get("/", (req, res) => {
  res.json({ success: true, message: "API running" });
});

app.use("/api/auth", authRoutes);
app.use("/api/test", testRoutes);

// Error handler (LAST)
app.use((err, req, res, next) => {
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || "Server Error",
  });
});

module.exports = app;
