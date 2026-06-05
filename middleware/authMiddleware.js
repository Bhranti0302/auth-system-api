const jwt = require("jsonwebtoken");

const protect = (req, res, next) => {
  try {
    // 1. Get token from cookies
    const token = req.cookies.token;

    // 2. Check token exists
    if (!token) {
      return res.status(401).json({ message: "Not authorized, no token" });
    }

    // 3. Verify token
    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    // 4. Attach user id to request
    req.user = decoded.id;

    // 5. Move to next (controller)
    next();
  } catch (error) {
    return res.status(401).json({ message: "Not authorized, invalid token" });
  }
};

module.exports = protect;
