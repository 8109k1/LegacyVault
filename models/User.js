
const mongoose = require("mongoose");

const userSchema = new mongoose.Schema(
  {
    googleId: {
      type: String,
      required: true,
      unique: true
    },
    name: {
      type: String,
      required: true
    },
    email: {
      type: String,
      required: true,
      lowercase: true
    },
    picture: {
      type: String,
      default: ""
    },
    vaultPasswordHash:{
      type: String,
      select: false,
      default: undefined
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("User", userSchema);
