const express = require("express");
const cookieParser = require("cookie-parser");
const session = require("express-session");

const app = express();

const authRoutes = require("./routes/authRoutes");
const testRoutes = require("./routes/testRoutes");

// Body parser
app.use(express.json());

// Cookie parser
app.use(cookieParser());

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
      maxAge: 24 * 60 * 60 * 1000, // 24 hours
    },
  }),
);

// Routes
app.get("/", (req, res) => {
  res.json({ success: true, message: "API running" });
});

app.use("/api/auth", authRoutes);
app.use("/api/test", testRoutes);

// Error handler
app.use((err, req, res, next) => {
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || "Server Error",
  });
});

module.exports = app;
