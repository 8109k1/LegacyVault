
const mongoose = require("mongoose");

const messageSchema = new mongoose.Schema(
  {
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    title: {
      type: String,
      required: true,
      trim: true,
      maxlength: 120
    },
    body: {
      type: String,
      required: true,
      trim: true,
      maxlength: 10000
    },
    beneficiary: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "Beneficiary",
      default: null
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Message", messageSchema);
