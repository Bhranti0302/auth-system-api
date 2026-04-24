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

// ================= REFRESH TOKEN =================
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

    // ✅ ROTATION
    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id);

    user.refreshToken = newRefreshToken;
    await user.save();

    res
      .cookie("accessToken", newAccessToken, cookieOptions)
      .cookie("refreshToken", newRefreshToken, {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      })
      .status(200)
      .json({
        success: true,
      });
  } catch (err) {
    return res.status(401).json({
      success: false,
      message: "Expired or invalid refresh token",
    });
  }
};

// ================= GOOGLE LOGIN =================
exports.googleLogin = async (req, res) => {
  try {
    const { token } = req.body;

    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Token is required",
      });
    }

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

    let user = await User.findOne({ email: payload.email });

    if (!user) {
      user = await User.create({
        name: payload.name,
        email: payload.email,
        googleId: payload.sub,
        password: crypto.randomBytes(8).toString("hex") + "A@1",
        isGoogleUser: true,
        status: "active",
      });
    }

    if (!user.isGoogleUser) {
      user.googleId = payload.sub;
      user.isGoogleUser = true;
      user.status = "active";
      await user.save();
    }

    // ✅ JWT TOKENS (FIXED)
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
        message: "Google login successful",
      });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Google login failed",
      error: err.message,
    });
  }
};

// ================= SIGNUP =================
exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must contain uppercase, lowercase, number and special character",
      });
    }

    const existingUser = await User.findOne({ email });

    if (existingUser && existingUser.isGoogleUser) {
      return res.status(400).json({
        success: false,
        message: "Please login with Google",
      });
    }

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    const user = await User.create({
      name,
      email,
      password,
      status: "inactive", // ✅ FIXED
    });

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

// ================= LOGIN =================
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

    // ✅ Reset attempts if lock expired
    if (user.lockUntil && user.lockUntil < Date.now()) {
      user.loginAttempts = 0;
      user.lockUntil = undefined;
      await user.save();
    }

    if (user.isLocked()) {
      return res.status(403).json({
        success: false,
        message: "Account locked. Try again later",
      });
    }

    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      user.loginAttempts += 1;

      if (user.loginAttempts >= 5) {
        user.lockUntil = Date.now() + 15 * 60 * 1000;
      }

      await user.save();

      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // ✅ Reset attempts
    user.loginAttempts = 0;
    user.lockUntil = undefined;

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

  req.session?.destroy(() => {
    res
      .clearCookie("accessToken", cookieOptions)
      .clearCookie("refreshToken", {
        httpOnly: true,
        secure: process.env.NODE_ENV === "production",
        sameSite: "lax",
      })
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
  } catch {
    res.status(400).json({
      success: false,
      message: "Token expired or invalid",
    });
  }
};

// ================= FORGOT PASSWORD =================
exports.forgotPassword = async (req, res) => {
  try {
    const { email } = req.body;

    const user = await User.findOne({ email });

    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    if (user.isGoogleUser) {
      return res.status(400).json({
        success: false,
        message: "Use Google login",
      });
    }

    const resetToken = crypto.randomBytes(32).toString("hex");

    const hashedToken = crypto
      .createHash("sha256")
      .update(resetToken)
      .digest("hex");

    user.passwordResetToken = hashedToken;
    user.passwordResetExpires = Date.now() + 15 * 60 * 1000;

    await user.save();

    const resetURL = `http://localhost:5000/api/auth/reset-password/${resetToken}`;

    await sendEmail(user.email, "Reset Password", resetURL);

    res.status(200).json({
      success: true,
      message: "Reset link sent",
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ================= RESET PASSWORD =================
exports.resetPassword = async (req, res) => {
  try {
    const { token } = req.params;
    const { password } = req.body;

    const hashedToken = crypto.createHash("sha256").update(token).digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Token invalid or expired",
      });
    }

    user.password = password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.refreshToken = null;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Password reset successful",
    });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ================= CHANGE PASSWORD =================
exports.changePassword = async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;

    const user = await User.findById(req.user.id).select("+password");

    if (!user)
      return res
        .status(404)
        .json({ success: false, message: "User not found" });

    if (user.isGoogleUser) {
      return res.status(400).json({
        success: false,
        message: "Google users cannot change password",
      });
    }

    const isMatch = await user.comparePassword(currentPassword);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Current password is incorrect",
      });
    }

    if (currentPassword === newPassword) {
      return res.status(400).json({
        success: false,
        message: "New password cannot be same as current password",
      });
    }

    const passwordRegex =
      /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

    if (!passwordRegex.test(newPassword)) {
      return res.status(400).json({
        success: false,
        message: "Password must be strong",
      });
    }

    user.password = newPassword;
    user.refreshToken = null;

    await user.save();

    res.status(200).json({
      success: true,
      message: "Password changed successfully",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};
