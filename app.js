const express = require("express");
const cookieParser=require("cookie-parser");

const app = express();

const authRoutes = require("./routes/authRoutes");
const testRoutes=require("./routes/testRoutes");

// Middleware

// Body parser
app.use(express.json());

// Cookie parser
app.use(cookieParser());

// Routes
app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "API is running",
  });
});


// Use auth routes
app.use("/api/auth", authRoutes);
app.use("/api/test",testRoutes);

// Global error handler(basic)
app.use((err, req, res, next) => {
  res.status(err.statusCode || 500).json({
    success: false,
    message: err.message || "Server Error",
  });
});

module.exports = app;