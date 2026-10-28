
require("dotenv").config();
const bcrypt = require("bcrypt");
const express = require("express");
const path = require("path");
const session = require("express-session");
const MongoStore = require("connect-mongo").default;
const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const fs = require("fs");
const fsp = require("fs/promises");
const crypto = require("crypto");
const multer = require("multer");
const Document = require("./models/Document");
const Beneficiary = require("./models/Beneficiary");
const Message = require("./models/Message");
const connectDB = require("./config/db");
const User = require("./models/User");

const app = express();
app.get("/", (req, res) => {
    res.sendFile(path.join(__dirname, "index.html"));
});
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Keep login sessions in MongoDB
app.use(
  session({
    name: "legacyvault.sid",
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    store: MongoStore.create({
      mongoUrl: process.env.MONGODB_URI,
      collectionName: "sessions"
    }),
    cookie: {
      httpOnly: true,
      secure: false, // Localhost uses HTTP during development
      sameSite: "lax",
      maxAge: 1000 * 60 * 60 * 24
    }
  })
);

app.use(passport.initialize());
app.use(passport.session());

// Find or create a user after Google authenticates them
passport.use(
  new GoogleStrategy(
    {
      clientID: process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL: "http://localhost:3000/auth/google/callback"
    },
    async (accessToken, refreshToken, profile, done) => {
      try {
        const email = profile.emails?.[0]?.value;

        if (!email) {
          return done(null, false);
        }

        const user = await User.findOneAndUpdate(
          { googleId: profile.id },
          {
            $set: {
              name: profile.displayName,
              email,
              picture: profile.photos?.[0]?.value || ""
            }
          },
          {
            returnDocument: "after",
            upsert: true,
            runValidators: true,
            setDefaultsOnInsert: true
          }
        );

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findById(id);
    done(null, user || false);
  } catch (error) {
    done(error);
  }
});

// Serve the existing frontend
app.use("/css", express.static(path.join(__dirname, "css")));
app.use("/js", express.static(path.join(__dirname, "js")));
app.use("/pages", express.static(path.join(__dirname, "pages")));
app.use("/images", express.static(path.join(__dirname, "images")));
app.use("/assets", express.static(path.join(__dirname, "assets")));

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "index.html"));
});

// Start Google login
app.get(
  "/auth/google",
  passport.authenticate("google", {
    scope: ["profile", "email"]
  })
);

// Google returns here after authentication
app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/pages/login.html"
  }),
  (req, res) => {
    res.redirect("/pages/dashboard.html");
  }
);

// Check which user is signed in
// Check which user is signed in
app.get("/api/me", (req, res) => {
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      authenticated: false
    });
  }

  res.json({
    authenticated: true,
    user: {
      id: req.user.id,
      name: req.user.name || req.user.displayName,
      email: req.user.email,
      picture: req.user.picture
    }
  });
});
/* ===== MASTER VAULT PASSWORD ===== */

// Require Google authentication for vault operations
function requireLogin(req, res, next) {
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      error: "Please sign in with Google first."
    });
  }

  next();
}

function requireVaultUnlocked(req, res, next) {
  // First, verify Google authentication
  if (!req.isAuthenticated()) {
    return res.status(401).json({
      error: "Please sign in with Google first."
    });
  }

  // Then, verify that this user's vault is unlocked
  const userId = String(req.user._id || req.user.id);

  if (req.session.vaultUnlockedFor !== userId) {
    return res.status(423).json({
      error: "Your vault is locked. Unlock it to continue."
    });
  }

  next();
}

const PRIVATE_UPLOADS = path.join(__dirname, "private_uploads");

// Ensure the private storage directory exists.
fs.mkdirSync(PRIVATE_UPLOADS, { recursive: true });

const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => {
      cb(null, PRIVATE_UPLOADS);
    },
    filename: (req, file, cb) => {
      // Never use the user's filename as the storage filename.
      cb(null, crypto.randomBytes(24).toString("hex"));
    }
  }),
  limits: {
    fileSize: 10 * 1024 * 1024, // 10 MB
    files: 1
  },
  fileFilter: (req, file, cb) => {
    const allowedTypes = [
      "application/pdf",
      "image/jpeg",
      "image/png"
    ];

    if (!allowedTypes.includes(file.mimetype)) {
      return cb(new Error("Only PDF, JPG, and PNG files are allowed."));
    }

    cb(null, true);
  }
});

// Verify file signatures instead of trusting only the browser MIME type.
async function detectFileType(filePath) {
  const handle = await fsp.open(filePath, "r");

  try {
    const buffer = Buffer.alloc(8);
    const { bytesRead } = await handle.read(buffer, 0, 8, 0);
    const header = buffer.subarray(0, bytesRead);

    if (header.subarray(0, 5).toString() === "%PDF-") {
      return "application/pdf";
    }

    if (
      header.length >= 3 &&
      header[0] === 0xff &&
      header[1] === 0xd8 &&
      header[2] === 0xff
    ) {
      return "image/jpeg";
    }

    if (
      header.length >= 8 &&
      header[0] === 0x89 &&
      header.subarray(1, 4).toString() === "PNG" &&
      header[4] === 0x0d &&
      header[5] === 0x0a &&
      header[6] === 0x1a &&
      header[7] === 0x0a
    ) {
      return "image/png";
    }

    return null;
  } finally {
    await handle.close();
  }
}

// Return upload errors as JSON instead of an HTML error page.
function handleUpload(req, res, next) {
  upload.single("document")(req, res, (error) => {
    if (!error) return next();

    if (error instanceof multer.MulterError) {
      const message = error.code === "LIMIT_FILE_SIZE"
        ? "File is too large. Maximum size is 10 MB."
        : "Upload failed. Please choose one file and try again.";

      return res.status(400).json({ error: message });
    }

    return res.status(400).json({
      error: error.message || "Could not upload this file."
    });
  });
}

const allowedCategories = [
  "Identity Proof",
  "Property",
  "Insurance",
  "Bank",
  "Other"
];

// Upload one document into the signed-in user's vault.
app.post(
  "/api/documents",
  requireLogin,
  requireVaultUnlocked,
  handleUpload,
  async (req, res) => {
    let filePath;

    try {
      if (!req.file) {
        return res.status(400).json({
          error: "Choose a document to upload."
        });
      }

      filePath = req.file.path;

      const detectedType = await detectFileType(filePath);

      if (!detectedType || detectedType !== req.file.mimetype) {
        await fsp.unlink(filePath);
        filePath = null;

        return res.status(400).json({
          error: "The file content does not match an allowed file type."
        });
      }

      const requestedCategory = req.body.category || "Other";

      if (!allowedCategories.includes(requestedCategory)) {
        await fsp.unlink(filePath);
        filePath = null;

        return res.status(400).json({
          error: "Choose a valid document category."
        });
      }

      const originalName = path
        .basename(req.file.originalname)
        .replace(/[\u0000-\u001f\u007f]/g, "")
        .slice(0, 180) || "document";

      const document = await Document.create({
        owner: req.user._id,
        originalName,
        storedName: req.file.filename,
        category: requestedCategory,
        mimeType: detectedType,
        size: req.file.size
      });

      res.status(201).json({
        message: "Document uploaded successfully.",
        document: {
          id: document._id,
          name: document.originalName,
          category: document.category,
          size: document.size,
          uploadedAt: document.createdAt
        }
      });
    } catch (error) {
      // If saving metadata failed, remove the newly uploaded file.
      if (filePath) {
        await fsp.unlink(filePath).catch(() => {});
      }

      console.error("Document upload error:", error);
      res.status(500).json({
        error: "Could not save the document."
      });
    }
  }
);

// List only the current user's documents.
app.get(
  "/api/documents",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      const documents = await Document.find({
        owner: req.user._id
      })
        .select("originalName category mimeType size createdAt")
        .sort({ createdAt: -1 })
        .lean();

      res.json({
        documents: documents.map((doc) => ({
          id: doc._id,
          name: doc.originalName,
          category: doc.category,
          mimeType: doc.mimeType,
          size: doc.size,
          uploadedAt: doc.createdAt
        }))
      });
    } catch (error) {
      console.error("Document list error:", error);
      res.status(500).json({
        error: "Could not load documents."
      });
    }
  }
);

// Download a document only if it belongs to this user.
app.get(
  "/api/documents/:id/download",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
        return res.status(400).json({ error: "Invalid document ID." });
      }

      const doc = await Document.findOne({
        _id: req.params.id,
        owner: req.user._id
      });

      if (!doc) {
        return res.status(404).json({ error: "Document not found." });
      }

      const filePath = path.join(PRIVATE_UPLOADS, doc.storedName);

      res.download(filePath, doc.originalName, (error) => {
        if (error && !res.headersSent) {
          if (error.code === "ENOENT") {
            return res.status(404).json({
              error: "The stored file could not be found."
            });
          }

          console.error("Document download error:", error);
          res.status(500).json({
            error: "Could not download the document."
          });
        }
      });
    } catch (error) {
      console.error("Document download error:", error);
      if (!res.headersSent) {
        res.status(500).json({
          error: "Could not download the document."
        });
      }
    }
  }
);

// Delete a document only if it belongs to this user.
app.delete(
  "/api/documents/:id",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
        return res.status(400).json({ error: "Invalid document ID." });
      }

      const doc = await Document.findOne({
        _id: req.params.id,
        owner: req.user._id
      });

      if (!doc) {
        return res.status(404).json({ error: "Document not found." });
      }

      const filePath = path.join(PRIVATE_UPLOADS, doc.storedName);

      // Keep the database record if the file cannot be removed.
      await fsp.unlink(filePath);
      await Document.deleteOne({ _id: doc._id, owner: req.user._id });

      res.json({ message: "Document deleted successfully." });
    } catch (error) {
      console.error("Document deletion error:", error);

      res.status(error.code === "ENOENT" ? 404 : 500).json({
        error: error.code === "ENOENT"
          ? "The stored file is missing; its record was retained."
          : "Could not delete the document."
      });
    }
  }
);

/* ===== BENEFICIARY API ===== */

const allowedRelationships = [
  "Parent",
  "Spouse",
  "Child",
  "Sibling",
  "Relative",
  "Friend",
  "Other"
];

function validateBeneficiary(body) {
  const { fullName, email, relationship, phone = "", notes = "" } = body;

  if (
    typeof fullName !== "string" ||
    !fullName.trim() ||
    fullName.trim().length > 100
  ) {
    return "Enter a name of up to 100 characters.";
  }

  if (
    typeof email !== "string" ||
    email.length > 254 ||
    !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email.trim())
  ) {
    return "Enter a valid email address.";
  }

  if (!allowedRelationships.includes(relationship)) {
    return "Choose a valid relationship.";
  }

  if (
    typeof phone !== "string" ||
    phone.length > 20 ||
    typeof notes !== "string" ||
    notes.length > 500
  ) {
    return "Phone or notes exceed the allowed length.";
  }

  return null;
}

// GET: List the signed-in owner's beneficiaries
app.get(
  "/api/beneficiaries",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      const beneficiaries = await Beneficiary.find({
        owner: req.user._id
      }).sort({ createdAt: -1 }).lean();

      res.json({
        beneficiaries: beneficiaries.map((person) => ({
          id: String(person._id),
          fullName: person.fullName,
          email: person.email,
          relationship: person.relationship,
          phone: person.phone || "",
          notes: person.notes || "",
          createdAt: person.createdAt
        }))
      });
    } catch (error) {
      console.error("Beneficiary list error:", error);
      res.status(500).json({ error: "Could not load beneficiaries." });
    }
  }
);

// POST: Add a beneficiary
app.post(
  "/api/beneficiaries",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      const validationError = validateBeneficiary(req.body || {});

      if (validationError) {
        return res.status(400).json({ error: validationError });
      }

      const person = await Beneficiary.create({
        owner: req.user._id,
        fullName: req.body.fullName.trim(),
        email: req.body.email.trim().toLowerCase(),
        relationship: req.body.relationship,
        phone: (req.body.phone || "").trim(),
        notes: (req.body.notes || "").trim()
      });

      res.status(201).json({
        message: "Beneficiary added successfully.",
        beneficiary: {
          id: String(person._id),
          fullName: person.fullName,
          email: person.email,
          relationship: person.relationship,
          phone: person.phone,
          notes: person.notes
        }
      });
    } catch (error) {
      console.error("Beneficiary creation error:", error);
      res.status(500).json({ error: "Could not add beneficiary." });
    }
  }
);

// PUT: Edit a beneficiary belonging to the signed-in owner
app.put(
  "/api/beneficiaries/:id",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
        return res.status(400).json({ error: "Invalid beneficiary ID." });
      }

      const validationError = validateBeneficiary(req.body || {});

      if (validationError) {
        return res.status(400).json({ error: validationError });
      }

      const person = await Beneficiary.findOneAndUpdate(
        { _id: req.params.id, owner: req.user._id },
        {
          $set: {
            fullName: req.body.fullName.trim(),
            email: req.body.email.trim().toLowerCase(),
            relationship: req.body.relationship,
            phone: (req.body.phone || "").trim(),
            notes: (req.body.notes || "").trim()
          }
        },
        { new: true, runValidators: true }
      );

      if (!person) {
        return res.status(404).json({ error: "Beneficiary not found." });
      }

      res.json({ message: "Beneficiary updated successfully." });
    } catch (error) {
      console.error("Beneficiary update error:", error);
      res.status(500).json({ error: "Could not update beneficiary." });
    }
  }
);

// DELETE: Remove a beneficiary belonging to the signed-in owner
app.delete(
  "/api/beneficiaries/:id",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
        return res.status(400).json({ error: "Invalid beneficiary ID." });
      }

      const person = await Beneficiary.findOneAndDelete({
        _id: req.params.id,
        owner: req.user._id
      });

      if (!person) {
        return res.status(404).json({ error: "Beneficiary not found." });
      }

      res.json({ message: "Beneficiary removed successfully." });
    } catch (error) {
      console.error("Beneficiary deletion error:", error);
      res.status(500).json({ error: "Could not remove beneficiary." });
    }
  }
);


/* ===== LEGACY MESSAGES API ===== */

// Validate message fields and ensure the selected beneficiary belongs
// to the signed-in user.
async function validateMessageInput(body, ownerId) {
  const { title, body: messageBody, beneficiaryId } = body || {};

  if (
    typeof title !== "string" ||
    !title.trim() ||
    title.trim().length > 120
  ) {
    return { error: "Enter a title of up to 120 characters." };
  }

  if (
    typeof messageBody !== "string" ||
    !messageBody.trim() ||
    messageBody.trim().length > 10000
  ) {
    return { error: "Enter a message of up to 10,000 characters." };
  }

  let beneficiary = null;

  if (beneficiaryId) {
    if (
      typeof beneficiaryId !== "string" ||
      !/^[a-f\d]{24}$/i.test(beneficiaryId)
    ) {
      return { error: "Invalid beneficiary selected." };
    }

    beneficiary = await Beneficiary.findOne({
      _id: beneficiaryId,
      owner: ownerId
    }).select("_id");

    if (!beneficiary) {
      return {
        error: "The selected beneficiary was not found in your account."
      };
    }
  }

  return {
    value: {
      title: title.trim(),
      body: messageBody.trim(),
      beneficiary: beneficiary ? beneficiary._id : null
    }
  };
}

// GET: List messages belonging to the current user.
app.get(
  "/api/messages",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      const messages = await Message.find({
        owner: req.user._id
      })
        .populate({
          path: "beneficiary",
          select: "fullName",
          match: { owner: req.user._id }
        })
        .sort({ createdAt: -1 })
        .lean();

      res.json({
        messages: messages.map((message) => ({
          id: String(message._id),
          title: message.title,
          body: message.body,
          beneficiaryId: message.beneficiary
            ? String(message.beneficiary._id)
            : "",
          beneficiaryName: message.beneficiary
            ? message.beneficiary.fullName
            : "",
          createdAt: message.createdAt,
          updatedAt: message.updatedAt
        }))
      });
    } catch (error) {
      console.error("Message list error:", error);
      res.status(500).json({ error: "Could not load messages." });
    }
  }
);

// POST: Create a new message.
app.post(
  "/api/messages",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      const result = await validateMessageInput(
        req.body,
        req.user._id
      );

      if (result.error) {
        return res.status(400).json({ error: result.error });
      }

      const message = await Message.create({
        owner: req.user._id,
        ...result.value
      });

      res.status(201).json({
        message: "Legacy instruction saved successfully.",
        savedMessage: {
          id: String(message._id),
          title: message.title,
          body: message.body,
          beneficiaryId: message.beneficiary
            ? String(message.beneficiary)
            : "",
          createdAt: message.createdAt
        }
      });
    } catch (error) {
      console.error("Message creation error:", error);
      res.status(500).json({ error: "Could not save the message." });
    }
  }
);

// PUT: Update a message belonging to the current user.
app.put(
  "/api/messages/:id",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
        return res.status(400).json({ error: "Invalid message ID." });
      }

      const result = await validateMessageInput(
        req.body,
        req.user._id
      );

      if (result.error) {
        return res.status(400).json({ error: result.error });
      }

      const message = await Message.findOneAndUpdate(
        {
          _id: req.params.id,
          owner: req.user._id
        },
        { $set: result.value },
        { new: true, runValidators: true }
      );

      if (!message) {
        return res.status(404).json({ error: "Message not found." });
      }

      res.json({ message: "Legacy instruction updated successfully." });
    } catch (error) {
      console.error("Message update error:", error);
      res.status(500).json({ error: "Could not update the message." });
    }
  }
);

// DELETE: Remove a message belonging to the current user.
app.delete(
  "/api/messages/:id",
  requireLogin,
  requireVaultUnlocked,
  async (req, res) => {
    try {
      if (!/^[a-f\d]{24}$/i.test(req.params.id)) {
        return res.status(400).json({ error: "Invalid message ID." });
      }

      const message = await Message.findOneAndDelete({
        _id: req.params.id,
        owner: req.user._id
      });

      if (!message) {
        return res.status(404).json({ error: "Message not found." });
      }

      res.json({ message: "Legacy instruction deleted successfully." });
    } catch (error) {
      console.error("Message deletion error:", error);
      res.status(500).json({ error: "Could not delete the message." });
    }
  }
);

app.get("/api/test-route", (req, res) => {
  res.send("LegacyVault server is responding correctly!");
});
// Check whether the user has created and unlocked their vault
app.get("/api/vault/status", requireLogin, async (req, res) => {
  try {
    const user = await User.findById(req.user.id)
      .select("+vaultPasswordHash");

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    res.json({
      passwordSet: Boolean(user.vaultPasswordHash),
      unlocked: req.session.vaultUnlockedFor === String(user._id)
    });
  } catch (error) {
    console.error("Vault status error:", error);
    res.status(500).json({ error: "Could not check vault status." });
  }
});

// Create the master vault password (one time per account)
app.post("/api/vault/setup", requireLogin, async (req, res) => {
  try {
    const { password, confirmPassword } = req.body;

    if (typeof password !== "string" || password.length < 10) {
      return res.status(400).json({
        error: "Use a password with at least 10 characters."
      });
    }

    if (password.length > 128) {
      return res.status(400).json({
        error: "Password must not exceed 128 characters."
      });
    }

    if (password !== confirmPassword) {
      return res.status(400).json({
        error: "Passwords do not match."
      });
    }

    const user = await User.findById(req.user.id)
      .select("+vaultPasswordHash");

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    if (user.vaultPasswordHash) {
      return res.status(409).json({
        error: "A vault password already exists. Use unlock instead."
      });
    }

    user.vaultPasswordHash = await bcrypt.hash(password, 12);
    await user.save();

    req.session.vaultUnlockedFor = String(user._id);

    res.json({ message: "Vault password created successfully." });
  } catch (error) {
    console.error("Vault setup error:", error);
    res.status(500).json({ error: "Could not create vault password." });
  }
});

// Unlock the vault using its master password
app.post("/api/vault/unlock", requireLogin, async (req, res) => {
  try {
    const { password } = req.body;

    if (typeof password !== "string" || password.length > 128) {
      return res.status(400).json({ error: "Enter a valid password." });
    }

    const user = await User.findById(req.user.id)
      .select("+vaultPasswordHash");

    if (!user) {
      return res.status(404).json({ error: "User not found." });
    }

    if (!user.vaultPasswordHash) {
      return res.status(400).json({
        error: "Create your vault password first."
      });
    }

    const matches = await bcrypt.compare(
      password,
      user.vaultPasswordHash
    );

    if (!matches) {
      return res.status(401).json({
        error: "Incorrect vault password."
      });
    }

    req.session.vaultUnlockedFor = String(user._id);

    res.json({ message: "Vault unlocked successfully." });
  } catch (error) {
    console.error("Vault unlock error:", error);
    res.status(500).json({ error: "Could not unlock vault." });
  }
});

// Lock the vault without logging out of Google
app.post("/api/vault/lock", requireLogin, (req, res) => {
  delete req.session.vaultUnlockedFor;

  req.session.save((error) => {
    if (error) {
      console.error("Vault lock error:", error);
      return res.status(500).json({ error: "Could not lock vault." });
    }

    res.json({ message: "Vault locked successfully." });
  });
});

// Log out
app.post("/auth/logout", (req, res, next) => {
  req.logout((error) => {
    if (error) return next(error);

    req.session.destroy((sessionError) => {
      if (sessionError) return next(sessionError);

      res.clearCookie("legacyvault.sid");
      res.json({ message: "Logged out successfully" });
    });
  });
});

// Backend health check
app.get("/api/health", (req, res) => {
  res.json({ message: "LegacyVault backend is running" });
});

async function startServer() {
  if (!process.env.SESSION_SECRET) {
    throw new Error("SESSION_SECRET is missing from .env");
  }

  if (!process.env.GOOGLE_CLIENT_ID ||
      !process.env.GOOGLE_CLIENT_SECRET) {
    throw new Error("Google OAuth credentials are missing from .env");
  }

  await connectDB();

  app.listen(process.env.PORT || 3000, () => {
    console.log("LegacyVault running at http://localhost:3000");
  });
}

startServer().catch((error) => {
  console.error("Failed to start LegacyVault:", error.message);
  process.exit(1);
});
