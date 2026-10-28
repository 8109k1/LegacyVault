
const mongoose = require("mongoose");

const beneficiarySchema = new mongoose.Schema(
  {
    owner: {
      type: mongoose.Schema.Types.ObjectId,
      ref: "User",
      required: true,
      index: true
    },

    fullName: {
      type: String,
      required: true,
      trim: true,
      maxlength: 100
    },

    email: {
      type: String,
      required: true,
      trim: true,
      lowercase: true,
      maxlength: 254
    },

    relationship: {
      type: String,
      required: true,
      enum: [
        "Parent",
        "Spouse",
        "Child",
        "Sibling",
        "Relative",
        "Friend",
        "Other"
      ]
    },

    phone: {
      type: String,
      trim: true,
      maxlength: 20,
      default: ""
    },

    notes: {
      type: String,
      trim: true,
      maxlength: 500,
      default: ""
    }
  },
  { timestamps: true }
);

module.exports = mongoose.model(
  "Beneficiary",
  beneficiarySchema
);
