const jwt = require("jsonwebtoken");

// Access Token
exports.generateAccessToken = (id) => {
  return jwt.sign({ id }, process.env.JWT_SECRET, {
    expiresIn: "15m",
  });
};

// Refresh Token (FIXED)
exports.generateRefreshToken = (id, tokenVersion) => {
  return jwt.sign({ id, tokenVersion }, process.env.JWT_REFRESH_SECRET, {
    expiresIn: "7d",
  });
};
