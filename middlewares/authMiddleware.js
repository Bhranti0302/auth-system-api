const jwt = require("jsonwebtoken");
const User = require("../models/User");

exports.protect = async (req, res, next) => {
  try {
    let token;

    // ✅ 1. Get accessToken from cookies
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    }

    // ❌ No token
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Not authorized, no access token",
      });
    }

    // ✅ 2. Verify access token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // ✅ 3. Get user
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    // ✅ 4. Attach user
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Access token expired or invalid",
    });
  }
};

exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      });
    }
    next();
  };
};

// Session Protect (Google)
exports.sessionProtect = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Not logged in (session)" });
  }
  next();
};
