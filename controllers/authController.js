const User = require("../models/User");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");

const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/generateToken");

const cookieOptions = require("../utils/cookieOptions");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ================= REFRESH TOKEN ===================
exports.refreshToken = async (req, res) => {
  const token = req.cookies.refreshToken;

  if (!token) {
    return res.status(401).json({
      success: false,
      message: "No refresh token",
    });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);

    const user = await User.findById(decoded.id).select("-password");

    if (!user || user.refreshToken !== token) {
      return res.status(401).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    const newAccessToken = generateAccessToken(user._id);

    res.cookie("accessToken", newAccessToken, cookieOptions).status(200).json({
      success: true,
      accessToken: newAccessToken,
    });
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: "Expired or invalid refresh token",
    });
  }
};

// ================= GOOGLE LOGIN (SESSION) =================
exports.googleLogin = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Token is required",
      });
    }

    // ✅ Verify Google token
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    const payload = ticket.getPayload();

    if (!payload.email_verified) {
      return res.status(400).json({
        success: false,
        message: "Email not verified",
      });
    }

    // ✅ Check if user exists
    let user = await User.findOne({ email: payload.email });

    // ✅ Create new user if not exists
    if (!user) {
      user = await User.create({
        name: payload.name,
        email: payload.email,
        googleId: payload.sub,
        password: crypto.randomBytes(8).toString("hex") + "A@1", // regex-safe
        isGoogleUser: true,
        status: "active",
      });
    }

    // ✅ If user exists but not Google user → link account
    if (!user.isGoogleUser) {
      user.googleId = payload.sub;
      user.isGoogleUser = true;
      user.status = "active";
      await user.save();
    }

    // ✅ Ensure active status
    if (user.status !== "active") {
      user.status = "active";
      await user.save();
    }

    // ✅ Create session
    req.session.user = {
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
      isGoogleUser: user.isGoogleUser,
    };

    req.session.save(() => {
      res.status(200).json({
        success: true,
        message: "Google login successful",
      });
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Google login failed",
      error: err.message,
    });
  }
};

// ================= SIGNUP (EMAIL VERIFY) =================
exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // ✅ PASSWORD VALIDATION (ADD THIS)
    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must contain uppercase, lowercase, number and special character",
      });
    }

    // ✅ CHECK EXISTING USER
    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    // ✅ CREATE USER
    const user = await User.create({ name, email, password });

    // ✅ EMAIL VERIFICATION TOKEN
    const emailToken = jwt.sign({ id: user._id }, process.env.JWT_SECRET, {
      expiresIn: "1d",
    });

    user.emailVerifyToken = emailToken;
    await user.save();

    const url = `http://localhost:5000/api/auth/verify-email?token=${emailToken}`;

    await sendEmail(user.email, "Verify your email", url);

    res.status(201).json({
      success: true,
      message: "Signup successful, please verify your email",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};

// ================= LOGIN (JWT + REFRESH) =================
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    if (user.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Please verify your email",
      });
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    user.refreshToken = refreshToken;
    await user.save();

    res
      .cookie("accessToken", accessToken, cookieOptions)
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      })
      .status(200)
      .json({
        success: true,
        message: "Login successful",
      });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};

// ================= LOGOUT =================
exports.logout = async (req, res) => {
  const token = req.cookies.refreshToken;

  if (token) {
    const user = await User.findOne({ refreshToken: token });
    if (user) {
      user.refreshToken = null;
      await user.save();
    }
  }

  req.session.destroy(() => {
    res
      .clearCookie("accessToken")
      .clearCookie("refreshToken")
      .status(200)
      .json({
        success: true,
        message: "Logged out successfully",
      });
  });
};

// ================= VERIFY EMAIL =================
exports.verifyEmail = async (req, res) => {
  try {
    const token = req.query.token;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Token is required",
      });
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET);

    const user = await User.findById(decoded.id);

    if (!user || user.emailVerifyToken !== token) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired token",
      });
    }

    user.status = "active";
    user.emailVerifyToken = null;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Email verified successfully",
    });
  } catch (err) {
    res.status(400).json({
      success: false,
      message: "Token expired or invalid",
    });
  }
};
