const User = require("../models/User");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const sendEmail = require("../utils/sendEmail");
const axios = require("axios");

const {
  generateAccessToken,
  generateRefreshToken,
} = require("../utils/generateToken");

const cookieOptions = require("../utils/cookieOptions");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ================= COMMON TOKEN FUNCTION =================
const sendTokens = async (user, res) => {
  const accessToken = generateAccessToken(user._id);
  const refreshToken = generateRefreshToken(user._id, user.tokenVersion);

  user.refreshToken = refreshToken;
  await user.save();

  res
    .cookie("accessToken", accessToken, cookieOptions)
    .cookie("refreshToken", refreshToken, cookieOptions);
};

// ================= PASSWORD REGEX =================
const passwordRegex = /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&]).{8,}$/;

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

    const user = await User.findById(decoded.id);

    if (
      !user ||
      user.refreshToken !== token ||
      decoded.tokenVersion !== user.tokenVersion
    ) {
      return res.status(401).json({
        success: false,
        message: "Invalid refresh token",
      });
    }

    const newAccessToken = generateAccessToken(user._id);
    const newRefreshToken = generateRefreshToken(user._id, user.tokenVersion);

    user.refreshToken = newRefreshToken;
    await user.save();

    res
      .cookie("accessToken", newAccessToken, cookieOptions)
      .cookie("refreshToken", newRefreshToken, cookieOptions)
      .status(200)
      .json({ success: true });
  } catch {
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
        provider: "google",
        providerId: payload.sub,
        password: crypto.randomBytes(8).toString("hex") + "A@1",
        status: "active",
      });
    }

    await sendTokens(user, res);

    res.status(200).json({
      success: true,
      message: "Google login successful",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Google login failed",
    });
  }
};

// ================= FACEBOOK LOGIN =================
exports.facebookLogin = async (req, res) => {
  try {
    const { accessToken } = req.body;

    const fbRes = await axios.get(
      `https://graph.facebook.com/me?fields=id,name,email&access_token=${accessToken}`,
    );

    const { id, name, email } = fbRes.data;

    if (!email) {
      return res.status(400).json({
        success: false,
        message:
          "Facebook email not available. Please use another login method.",
      });
    }

    let user = await User.findOne({ email });

    if (!user) {
      user = await User.create({
        name,
        email,
        provider: "facebook",
        providerId: id,
        password: crypto.randomBytes(8).toString("hex") + "A@1",
        status: "active",
      });
    }

    await sendTokens(user, res);

    res.json({
      success: true,
      message: "Facebook login successful",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Facebook login failed",
    });
  }
};

// ================= GITHUB LOGIN =================
exports.githubLogin = async (req, res) => {
  try {
    const { code } = req.body;

    const tokenRes = await axios.post(
      "https://github.com/login/oauth/access_token",
      {
        client_id: process.env.GITHUB_CLIENT_ID,
        client_secret: process.env.GITHUB_CLIENT_SECRET,
        code,
      },
      {
        headers: { Accept: "application/json" },
      },
    );

    const accessTokenGitHub = tokenRes.data.access_token;

    const userRes = await axios.get("https://api.github.com/user", {
      headers: {
        Authorization: `Bearer ${accessTokenGitHub}`,
      },
    });

    const emailRes = await axios.get("https://api.github.com/user/emails", {
      headers: {
        Authorization: `Bearer ${accessTokenGitHub}`,
      },
    });

    const primaryEmail =
      emailRes.data.find((e) => e.primary)?.email || emailRes.data[0]?.email;

    if (!primaryEmail) {
      return res.status(400).json({
        success: false,
        message: "GitHub email not found",
      });
    }

    let user = await User.findOne({ email: primaryEmail });

    if (!user) {
      user = await User.create({
        name: userRes.data.name || "GitHub User",
        email: primaryEmail,
        provider: "github",
        providerId: userRes.data.id,
        password: crypto.randomBytes(8).toString("hex") + "A@1",
        status: "active",
      });
    }

    await sendTokens(user, res);

    res.json({
      success: true,
      message: "GitHub login successful",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "GitHub login failed",
    });
  }
};

// ================= SIGNUP =================
exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    if (!passwordRegex.test(password)) {
      return res.status(400).json({
        success: false,
        message:
          "Password must contain uppercase, lowercase, number and special character",
      });
    }

    const existingUser = await User.findOne({ email });

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
      status: "inactive",
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

    if (user.lockUntil && user.lockUntil < Date.now()) {
      user.loginAttempts = 0;
      user.lockUntil = undefined;
    }

    if (user.isLocked()) {
      return res.status(403).json({
        success: false,
        message: "Account locked",
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

    user.loginAttempts = 0;
    user.lockUntil = undefined;

    await sendTokens(user, res);

    res.status(200).json({
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
      user.tokenVersion += 1;
      await user.save();
    }
  }

  res
    .clearCookie("accessToken", cookieOptions)
    .clearCookie("refreshToken", cookieOptions)
    .status(200)
    .json({
      success: true,
      message: "Logged out successfully",
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
        message: "Invalid token",
      });
    }

    user.status = "active";
    user.emailVerifyToken = null;

    await user.save();

    res.json({
      success: true,
      message: "Email verified",
    });
  } catch {
    res.status(400).json({
      success: false,
      message: "Token expired",
    });
  }
};

// ================= FORGOT PASSWORD =================
exports.forgotPassword = async (req, res) => {
  try {
    const user = await User.findOne({ email: req.body.email });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found",
      });
    }

    const resetToken = user.createPasswordResetToken();
    await user.save();

    const url = `http://localhost:5000/api/auth/reset-password/${resetToken}`;

    await sendEmail(user.email, "Reset Password", url);

    res.json({
      success: true,
      message: "Reset link sent",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};

// ================= RESET PASSWORD =================
exports.resetPassword = async (req, res) => {
  try {
    const hashedToken = crypto
      .createHash("sha256")
      .update(req.params.token)
      .digest("hex");

    const user = await User.findOne({
      passwordResetToken: hashedToken,
      passwordResetExpires: { $gt: Date.now() },
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired token",
      });
    }

    if (!passwordRegex.test(req.body.password)) {
      return res.status(400).json({
        success: false,
        message: "Weak password",
      });
    }

    user.password = req.body.password;
    user.passwordResetToken = undefined;
    user.passwordResetExpires = undefined;
    user.refreshToken = null;
    user.tokenVersion += 1;

    await user.save();

    res.json({
      success: true,
      message: "Password reset successful",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};

// ================= CHANGE PASSWORD =================
exports.changePassword = async (req, res) => {
  try {
    const user = await User.findById(req.user.id).select("+password");

    const isMatch = await user.comparePassword(req.body.currentPassword);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Wrong password",
      });
    }

    if (!passwordRegex.test(req.body.newPassword)) {
      return res.status(400).json({
        success: false,
        message: "Weak password",
      });
    }

    user.password = req.body.newPassword;
    user.refreshToken = null;
    user.tokenVersion += 1;

    await user.save();

    res.json({
      success: true,
      message: "Password changed",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: err.message,
    });
  }
};
