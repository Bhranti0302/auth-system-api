const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");

const userSchemma = new mongoose.Schema(
  {
    name: {
      type: String,
      required: [true, "Please provide a name"],
      trim: true,
      minlength: 2,
      maxlength: 50,
    },

    email: {
      type: String,
      required: [true, "Please provide an email"],
      unique: true,
      lowercase: true,
      trim: true,
      match: [/.+@.+\..+/, "Please provide a valid email address"],
      index: true,
    },
    password: {
      type: String,
      required: [true, "Please provide a password"],
      minlength: 6,
      select: false, // 🔥 don't show password in queries
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },

    status:{
        type:String,
        enum:["active","inactive","blocked"],
        default:"active"
    },
    
    // Password reset fields
    passwordResetToken: String,
    passwordResetExpires: Date,

    // Track password changes
    passwordChangedAt: Date,
  },
  {
    timestamps: true,
  },
);

// 🔐 HASH PASSWORD BEFORE SAVE
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);

  // Update passwordChangedAt
  this.passwordChangedAt = Date.now() - 1000;

  next();
});

// 🔑 COMPARE PASSWORD
userSchema.methods.comparePassword=async function(enteredPassword){
    return await bcrypt.compare(enteredPassword,this.password);
}

// 🔐 GENERATE PASSWORD RESET TOKEN
userSchema.methods.createPasswordResetToken=function(){
    const resetToken=crypto.randomBytes(32).toString("hex");

    this.passwordResetToken=crypto.createHash("sha256").update(resetToken).digest("hex");
    this.passwordResetExpires=Date.now()+10*60*1000; // 10 minutes

    return resetToken;
}

module.exports=mongoose.model("User",userSchema);8