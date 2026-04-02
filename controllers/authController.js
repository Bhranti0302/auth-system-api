const User = require("../models/User");
const generateToken = require("../utils/generateToken");
const cookieOptions = require("../utils/cookieOptions");

// ================= SIGNUP =================
exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    // 1. Check existing user
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists with this email",
      });
    }

    // 2. Create user
    const user = await User.create({
      name,
      email,
      password,
    });

    // 3. Generate token
    const token = generateToken(user._id);

    // 4. Send response (cookie only)
    res
      .cookie("token", token, cookieOptions)
      .status(201)
      .json({
        success: true,
        message: "User registered successfully",
        data: {
          id: user._id,
          name: user.name,
          email: user.email,
          role: user.role,
          status: user.status,
        },
      });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: err.message,
    });
  }
};

// ================= LOGIN =================
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. Check user exists
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // 2. Check account status
    if (user.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Account is not active",
      });
    }

    // 3. Compare password
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // 4. Generate token
    const token = generateToken(user._id);

    // 5. Send response (cookie only)
    res.cookie("token", token, cookieOptions).status(200).json({
      success: true,
      message: "User logged in successfully",
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: err.message,
    });
  }
};

// ================= LOGOUT =================
exports.logout = (req, res) => {
  res
    .cookie("token", "", {
      httpOnly: true,
      expires: new Date(0),
    })
    .status(200)
    .json({
      success: true,
      message: "User logged out successfully",
    });
};
