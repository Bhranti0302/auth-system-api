const cookieOptions = {
  httpOnly: true,
  secure: process.env.NODE_ENV === "production", // ✅ dynamic
  sameSite: "lax", // ✅ better for frontend-backend communication
  maxAge: 24 * 60 * 60 * 1000, // 7 days
};

module.exports = cookieOptions;
