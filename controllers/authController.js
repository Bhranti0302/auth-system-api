const User=require("../models/User");
const generateToken=require("../utils/generateToken");
const bcrypt=require("bcryptjs");

// @desc    Register a new user
// @route   POST /api/auth/register
// @access  Public

exports.signup=async(req,res)=>{
    try{
       const {name,email,password}=req.body;

       // 1. Check existing user
       const existingUser=await User.findOne({email});
       if(existingUser){
        return res.status(400).json(
            {
                success:false,
                message:"User already exists with this email"
            }
        )
       }

       // 2. Create user
       const user=await User.create({
        name,
        email,
        password
       });

       // 3. Generate token
       const token=generateToken(user._id);

         // 4. Send response
         res.status(201).json({
            success:true,
            message:"User registered successfully",
            token,
            data:{
                id:user._id,
                name:user.name,
                email:user.email,
                role:user.role,
                status:user.status
            }
         })
    } catch(err){
        res.status(500).json({
            success:false,
            message:"Server error",error:err.message});
    }
}

// @desc    Login user
// @route   POST /api/auth/login
// @access  Public
exports.login = async (req, res) => {
  try {
    const { email, password } = req.body;

    // 1. check user exists + include password
    const user = await User.findOne({ email }).select("+password");

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // ✅ 2. CHECK STATUS HERE
    if (user.status !== "active") {
      return res.status(403).json({
        success: false,
        message: "Account is not active",
      });
    }

    // 3. Compare password (FIXED)
    const isMatch = await user.comparePassword(password);

    if (!isMatch) {
      return res.status(400).json({
        success: false,
        message: "Invalid credentials",
      });
    }

    // 4. Generate token
    const token = generateToken(user._id);

    // 5. Send response
    res.status(200).json({
      success: true,
      message: "User logged in successfully",
      token,
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      message: "Server error",
      error: err.message,
    });
  }
};