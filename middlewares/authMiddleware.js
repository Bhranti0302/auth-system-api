const jwt = require("jsonwebtoken");
const User = require("../models/User");

// ================= PROTECT =================
exports.protect = async (req, res, next) => {
  try {
    let token;

    // ✅ 1. Get token from cookies OR header
    if (req.cookies && req.cookies.accessToken) {
      token = req.cookies.accessToken;
    } else if (
      req.headers.authorization &&
      req.headers.authorization.startsWith("Bearer")
    ) {
      token = req.headers.authorization.split(" ")[1];
    }

    // ❌ No token
    if (!token) {
      return res.status(401).json({
        success: false,
        message: "Not authorized, no token",
      });
    }

    // ✅ 2. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // ✅ 3. Get user
    const user = await User.findById(decoded.id).select("-password");

    if (!user) {
      return res.status(401).json({
        success: false,
        message: "User not found",
      });
    }

    // ❌ Block inactive/blocked users
    if (user.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "User is not active",
      });
    }

    // ❌ Check if password changed after token issued
    if (user.passwordChangedAt) {
      const changedTime = parseInt(user.passwordChangedAt.getTime() / 1000, 10);

      if (decoded.iat < changedTime) {
        return res.status(401).json({
          success: false,
          message: "Password changed. Please login again.",
        });
      }
    }

    // ✅ Attach user
    req.user = user;
    next();
  } catch (error) {
    return res.status(401).json({
      success: false,
      message: "Token expired or invalid",
    });
  }
};

// ================= AUTHORIZE =================
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({
        success: false,
        message: "Not authorized",
      });
    }

    if (!roles.includes(req.user.role)) {
      return res.status(403).json({
        success: false,
        message: "Access denied",
      });
    }

    next();
  };
};

// ================= SESSION PROTECT =================
exports.sessionProtect = (req, res, next) => {
  if (!req.session || !req.session.user) {
    return res.status(401).json({
      success: false,
      message: "Not logged in (session)",
    });
  }

  next();
};
