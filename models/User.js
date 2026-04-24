const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
    },

    email: {
      type: String,
      required: true,
      unique: true,
      lowercase: true,
      trim: true,
    },

    password: {
      type: String,
      required: true,
      minlength: 8,
      select: false,
    },

    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },

    googleId: String,

    isGoogleUser: {
      // ✅ ADD THIS
      type: Boolean,
      default: false,
    },

    refreshToken: {
      // ✅ ADD THIS
      type: String,
    },

    emailVerifyToken: String,

    status: {
      type: String,
      enum: ["active", "inactive", "blocked"],
      default: "active",
    },

    loginAttempts: {
      type: Number,
      default: 0,
    },
    lockUntil: Date,

    passwordResetToken: String,
    passwordResetExpires: Date,

    passwordChangedAt: Date,
  },
  { timestamps: true },
);

// HASH PASSWORD
userSchema.pre("save", async function (next) {
  if (!this.isModified("password")) return next();

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);

  this.passwordChangedAt = Date.now() - 1000;
  next();
});

// COMPARE PASSWORD
userSchema.methods.comparePassword = function (enteredPassword) {
  return bcrypt.compare(enteredPassword, this.password);
};

userSchema.methods.isLocked = function () {
  return !!(this.lockUntil && this.lockUntil > Date.now());
};

module.exports = mongoose.model("User", userSchema);
