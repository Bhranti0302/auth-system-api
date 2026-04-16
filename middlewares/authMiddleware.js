const jwt=require('jsonwebtoken');
const User=require("../models/User");

exports.protect=async(req,res,next)=>{
    try{
        let token;

        // 1. Get token from cookies
        if(req.cookies && req.cookies.token){
            token=req.cookies.token;
        }

        // 2. No token
        if(!token){
            return res.status(401).json({message:"Not authorized, no token"})
        }

        // 3. verify token
        const decoded=jwt.verify(token, process.env.JWT_SECRET);

        // 4. Get user from the token
        const user=await User.findById(decoded.id).select("-password");

        if(!user){
            return res.status(401).json({message:"Not authorized, user not found"})
        }

        // 5. Attach user to request object
        req.user=user;
        next();

    } catch(error){
        res.status(401).json({
            success:false,
            message:"Unauthorized"
        });
    }
}


exports.authorize=(...roles)=>{
    return (req,res,next)=>{
        if(!roles.includes(req.user.role)){
            return res
            .status(403)
            .json({
                success:false,
                message:"Access denied"
            });
        }
        next();
    }
}

// Session Protect (Google)
exports.sessionProtect = (req, res, next) => {
  if (!req.session.user) {
    return res.status(401).json({ message: "Not logged in (session)" });
  }
  next();
};