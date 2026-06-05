const mongoose = require("mongoose");
// 🔐 Password compare method
const bcrypt = require("bcryptjs");

const userSchema = new mongoose.Schema(
  {
    name: {
      type: String,
      required: true,
      trim: true,
      minlength: 3,
    },
    email: {
      type: String,
      required: true,
      unique: true,
      match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, "Invalid email"],
    },
    password: {
      type: String,
      required: true,
      minlength: 6,
      select: false,
    },
    role: {
      type: String,
      enum: ["user", "admin"],
      default: "user",
    },
    
    status: {
      type: String,
      enum: ["online", "offline"],
      default: "offline",
    },
    lastSeen: {
      type: Date,
    },
  },
  { timestamps: true },
);


userSchema.methods.comparePassword = async function (enteredPassword) {
  return await bcrypt.compare(enteredPassword, this.password);
};

// 🔐 Hash password before save
userSchema.pre("save", async function () {
  if (!this.isModified("password")) return;

  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
});

// ✅ IMPORTANT LINE
module.exports = mongoose.model("User", userSchema);
