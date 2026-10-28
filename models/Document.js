
const mongoose = require("mongoose");

const documentSchema = new mongoose.Schema(
  {
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },
    originalName: {
      type: String,
      required: true
    },
    storedName: {
      type: String,
      required: true,
      unique: true
    },
    category: {
      type: String,
      enum: [
        "Identity Proof",
        "Property",
        "Insurance",
        "Bank",
        "Other"
      ],
      default: "Other"
    },
    mimeType: {
      type: String,
      required: true
    },
    size: {
      type: Number,
      required: true
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model("Document", documentSchema);
