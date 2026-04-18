const User = require("../models/User");
const { OAuth2Client } = require("google-auth-library");
const crypto = require("crypto");

const {generateAccessToken, generateRefreshToken} = require("../utils/generateToken");
const cookieOptions = require("../utils/cookieOptions");

const client = new OAuth2Client(process.env.GOOGLE_CLIENT_ID);

// ================= REFRESH TOKEN ===================
exports.refreshToken=async(req,res)=>{
  // 1. Get refresh token
  const token = req.cookies.refreshToken;

  // 2. Check if token is provided
  if(!token){
    return res.status(401).json({
      message: "Not refresh token"
    })
  }

  try{
    // 3. Verify token
     const decoded = jwt.verify(token, process.env.JWT_REFRESH_SECRET);

     // 4. Get user from the token
     const user = await User.findById(decoded.id).select("-password");

     // 5. Check if user exists
     if(!user || user.refreshToken !== token){
       return res.status(401).json({
         message: "Invalid refresh token"
       })
     }

     // 6. Generate new access token
     const newAccessToken = generateAccessToken(user._id);
     
     // 7. Send new access token
     res
     .cookie("accessToken", newAccessToken, cookieOptions)
     .status(200)
     .json({success: true, accessToken: newAccessToken});

  } catch(err){
    console.log(err);
    res.status(500).json({
      message: "Server error"
    })
  }
}
// ================= GOOGLE LOGIN (SESSION) =================
exports.googleLogin = async (req, res) => {
  try {
    const { token } = req.body;

    // 1. Check if token is provided
    if (!token) {
      return res.status(400).json({
        success: false,
        message: "Token is required",
      });
    }

    // 2. Verify token with Google
    const ticket = await client.verifyIdToken({
      idToken: token,
      audience: process.env.GOOGLE_CLIENT_ID,
    });

    // 3. Get user info from token payload
    const payload = ticket.getPayload();

    // 4. Check if email is verified
    if (!payload.email_verified) {
      return res.status(400).json({
        success: false,
        message: "Email not verified",
      });
    }

    // 5. Find or create user in database
    let user = await User.findOne({ email: payload.email });

    // 6. If user doesn't exist, create a new one
    if (!user) {
      user = await User.create({
        name: payload.name,
        email: payload.email,
        googleId: payload.sub,
        password: crypto.randomBytes(20).toString("hex"),
      });
    }

    // 7. Store user info in session
    req.session.user = {
      id: user._id,
      email: user.email,
      name: user.name,
      role: user.role,
      status: user.status,
    };

    // 8. Save session and respond
    req.session.save(() => {
      res.status(200).json({
        success: true,
        message: "Google login successful (session)",
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

// ================= SIGNUP (JWT COOKIE) =================
exports.signup = async (req, res) => {
  try {
    const { name, email, password } = req.body;

    const existingUser = await User.findOne({ email });

    if (existingUser) {
      return res.status(400).json({
        success: false,
        message: "User already exists",
      });
    }

    const user = await User.create({ name, email, password });

    const accessToken = generateAccessToken(user._id);
    const refreshToken = generateRefreshToken(user._id);

    // Save refresh token in DB
    user.refreshToken = refreshToken;
    await user.save();

    res
      .cookie("accessToken", accessToken, cookieOptions)
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
      })
      .status(201)
      .json({
        success: true,
        message: "Signup successful",
      });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ================= LOGIN (JWT COOKIE) =================
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
        message: "Account not active",
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

    // Save refresh token in DB
    user.refreshToken = refreshToken;
    await user.save();

    res
      .cookie("accessToken", accessToken, cookieOptions)
      .cookie("refreshToken", refreshToken, {
        httpOnly: true,
      })
      .status(200)
      .json({
        success: true,
        message: "Login successful",
      });
  } catch (err) {
    res.status(500).json({ success: false, message: err.message });
  }
};

// ================= LOGOUT (BOTH) =================
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
