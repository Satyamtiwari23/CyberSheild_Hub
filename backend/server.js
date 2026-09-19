require("dotenv").config();
const axios = require("axios");
const FormData = require("form-data");
const { google } = require("googleapis");
const crypto = require("crypto");
const dns = require("dns").promises;
const net = require("net");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");
const multer = require("multer");

const SECURITY_ENGINE_URL =
  process.env.SECURITY_ENGINE_URL ||
  "http://127.0.0.1:5002";

const AI_SERVICE_URL =
  process.env.AI_SERVICE_URL ||
  "http://127.0.0.1:5004";

const app = express();
const googleOAuth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.GMAIL_REDIRECT_URI
);

// =====================================================
// GOOGLE LOGIN OAUTH
// =====================================================

const googleLoginClient = new google.auth.OAuth2(
  process.env.GOOGLE_LOGIN_CLIENT_ID,
  process.env.GOOGLE_LOGIN_CLIENT_SECRET,
  process.env.GOOGLE_LOGIN_REDIRECT_URI
);
const googleLinkClient = new google.auth.OAuth2(
  process.env.GOOGLE_LOGIN_CLIENT_ID,
  process.env.GOOGLE_LOGIN_CLIENT_SECRET,
  process.env.GOOGLE_LINK_REDIRECT_URI
);

// =====================================================
// GITHUB LOGIN OAUTH
// =====================================================

const GITHUB_CLIENT_ID =
  process.env.GITHUB_CLIENT_ID;

const GITHUB_CLIENT_SECRET =
  process.env.GITHUB_CLIENT_SECRET;

const GITHUB_REDIRECT_URI =
  process.env.GITHUB_REDIRECT_URI;

const GITHUB_LINK_REDIRECT_URI =
  process.env.GITHUB_LINK_REDIRECT_URI;

googleOAuth2Client.setCredentials({
  refresh_token: process.env.GMAIL_REFRESH_TOKEN
});

const gmail = google.gmail({
  version: "v1",
  auth: googleOAuth2Client
});
app.use(cors({
  origin: [
    "http://127.0.0.1:5501",
    "http://localhost:5501",
    "https://satyamtiwari23.github.io"
  ],
  credentials: true
}));

app.use(express.json());

// =====================================================
// SIGHTENGINE AI IMAGE DETECTION
// =====================================================

const upload = multer({
  storage: multer.memoryStorage(),
  limits: {
    fileSize: 15 * 1024 * 1024
  }
});

// ✅ Connect MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(async () => {

    console.log("MongoDB Connected ✅");

    await migrateAuthProviders();

  })
  .catch((err) => {

    console.log("MongoDB Connection Failed ❌");
    console.log("Error:", err.message);

  });

// ✅ Create Schema
const userSchema = new mongoose.Schema({
  name: String,

  email: {
    type: String,
    lowercase: true,
    trim: true
  },

  password: String,

  // Authentication methods linked to this account
  authProviders: {
    type: [String],
    default: []
  },

  // Keep this temporarily for compatibility
  // with existing users/data
  authProvider: {
    type: String,
    default: "password"
  },

  passwordSet: {
    type: Boolean,
    default: false
  },

  resetToken: String,
  resetTokenExpiry: Date,

  resetOtpHash: String,
  resetOtpExpiry: Date
});

// ✅ Create Model
const User = mongoose.model("User", userSchema);

// =====================================================
// JWT AUTHENTICATION MIDDLEWARE
// =====================================================

function authenticateToken(req, res, next) {

  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    return res.status(401).json({
      message: "Authentication required."
    });
  }

  const token =
    authHeader.split(" ")[1];

  try {

    const decoded =
      jwt.verify(
        token,
        process.env.JWT_SECRET
      );

    req.userId = decoded.userId;

    next();

  } catch (error) {

    return res.status(401).json({
      message: "Invalid or expired token."
    });

  }
}

// =====================================================
// GET CURRENT USER AUTHENTICATION METHODS
// =====================================================

app.get("/api/account/auth-providers", authenticateToken, async (req, res) => {

  try {

    const user =
      await User.findById(req.userId)
        .select("authProviders");

    if (!user) {
      return res.status(404).json({
        message: "User not found."
      });
    }

    res.json({
      authProviders: user.authProviders || []
    });

  } catch (error) {

    console.error(
      "Auth providers fetch error:",
      error.message
    );

    res.status(500).json({
      message: "Unable to load authentication methods."
    });

  }

});

// =====================================================
// START GOOGLE ACCOUNT LINKING
// =====================================================

app.post("/api/auth/link/google/start", authenticateToken, (req, res) => {

  const state =
    crypto.randomBytes(32).toString("hex");

  // Create a signed temporary linking session
  const linkSession =
    jwt.sign(
      {
        userId: req.userId,
        state: state
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "10m"
      }
    );

  const isProduction =
    process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    `google_link_session=${linkSession}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=600`
  );

  const authUrl =
    googleLinkClient.generateAuthUrl({
      access_type: "offline",

      scope: [
        "openid",
        "email",
        "profile"
      ],

      state,

      prompt: "select_account"
    });

  res.json({
    success: true,
    authUrl
  });

});

// =====================================================
// GOOGLE ACCOUNT LINK CALLBACK
// =====================================================

app.get("/auth/link/google/callback", async (req, res) => {

  try {

    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send(
        "Invalid Google account linking request."
      );
    }

    // -------------------------------------------------
    // READ COOKIE
    // -------------------------------------------------

    const cookies =
      req.headers.cookie || "";

    const cookieMap = {};

    cookies
      .split(";")
      .map(cookie => cookie.trim())
      .forEach(cookie => {

        const index = cookie.indexOf("=");

        if (index !== -1) {

          const key =
            cookie.substring(0, index);

          const value =
            cookie.substring(index + 1);

          cookieMap[key] = value;
        }

      });

    const linkSession =
      cookieMap.google_link_session;

    if (!linkSession) {

      return res.status(401).send(
        "Account linking session expired. Please try again."
      );

    }

    // -------------------------------------------------
    // VERIFY SIGNED LINKING SESSION
    // -------------------------------------------------

    let session;

    try {

      session =
        jwt.verify(
          linkSession,
          process.env.JWT_SECRET
        );

    } catch (error) {

      return res.status(403).send(
        "Invalid or expired account linking session."
      );

    }

    // -------------------------------------------------
    // VERIFY OAUTH STATE
    // -------------------------------------------------

    if (
      !session.state ||
      session.state !== state
    ) {

      return res.status(403).send(
        "Invalid OAuth state."
      );

    }

    // -------------------------------------------------
    // FIND CURRENT CYBERSHIELD USER
    // -------------------------------------------------

    const user =
      await User.findById(session.userId);

    if (!user) {

      return res.status(404).send(
        "CyberShield account not found."
      );

    }

    // -------------------------------------------------
    // EXCHANGE GOOGLE CODE
    // -------------------------------------------------

    const { tokens } =
      await googleLinkClient.getToken({
        code,
        redirect_uri:
          process.env.GOOGLE_LINK_REDIRECT_URI
      });

    googleLinkClient.setCredentials(tokens);

    // -------------------------------------------------
    // GET GOOGLE USER
    // -------------------------------------------------

    const oauth2Client =
      google.oauth2({
        auth: googleLinkClient,
        version: "v2"
      });

    const { data } =
      await oauth2Client.userinfo.get();

    const googleEmail =
      data.email?.toLowerCase().trim();

    if (!googleEmail) {

      return res.status(400).send(
        "Google account email could not be retrieved."
      );

    }
    // -------------------------------------------------
    // GOOGLE EMAIL MUST MATCH CYBERSHIELD EMAIL
    // -------------------------------------------------

    if (googleEmail !== user.email) {

      return res.status(409).send(
        "The Google email must match your CyberShield account email."
      );

    }

    // -------------------------------------------------
    // CHECK IF EMAIL BELONGS TO ANOTHER ACCOUNT
    // -------------------------------------------------

    const existingUser =
      await User.findOne({
        email: googleEmail
      });

    if (
      existingUser &&
      existingUser._id.toString() !==
      user._id.toString()
    ) {

      return res.status(409).send(
        "This Google account is already linked to another CyberShield account."
      );

    }

    // -------------------------------------------------
    // MAKE SURE authProviders EXISTS
    // -------------------------------------------------

    if (!user.authProviders) {
      user.authProviders = [];
    }

    // -------------------------------------------------
    // LINK GOOGLE
    // -------------------------------------------------

    if (
      !user.authProviders.includes("google")
    ) {

      user.authProviders.push("google");

    }

    await user.save();

    console.log(
      `Google account linked successfully to ${user.email}`
    );

    res.send(`
      <h2>Google account linked successfully ✅</h2>
      <p>Google has been linked to your CyberShield account.</p>
      <p>You can close this tab and return to CyberShield Hub.</p>
    `);

  } catch (error) {

    console.error(
      "Google Account Linking Error:",
      error.response?.data ||
      error.message ||
      error
    );

    res.status(500).send(
      "Google account linking failed."
    );

  }

});

// =====================================================
// MIGRATE EXISTING USERS TO authProviders
// =====================================================

async function migrateAuthProviders() {

  try {

    const users = await User.find({
      $or: [
        { authProviders: { $exists: false } },
        { authProviders: { $size: 0 } }
      ]
    });

    for (const user of users) {

      let provider = user.authProvider;

      // Old local accounts may have authProvider = "local"
      if (provider === "local") {
        provider = "password";
      }

      if (
        provider &&
        ["password", "google", "github"].includes(provider)
      ) {

        user.authProviders = [provider];

        await user.save();

        console.log(
          `Migrated ${user.email}: ${provider}`
        );
      }
    }

    console.log("Auth provider migration completed ✅");

  } catch (error) {

    console.error(
      "Auth provider migration failed ❌",
      error.message
    );

  }
}


// Google OAuth authorization
app.get("/auth/google", (req, res) => {

  const authUrl = googleOAuth2Client.generateAuthUrl({
    access_type: "offline",
    prompt: "consent",
    scope: [
      "https://www.googleapis.com/auth/gmail.send"
    ]
  });

  res.redirect(authUrl);
});


// Routes
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok' });
});

// ✅ Signup (stores in MongoDB)
app.post('/api/signup', async (req, res) => {
  const { name, email, password } = req.body;

  const normalizedEmail = email.toLowerCase().trim();

  const existingUser =
    await User.findOne({
      email: normalizedEmail
    });
  if (existingUser) {
    return res.status(409).json({ message: "User already exists" });
  }

  const hashedPassword =
    await bcrypt.hash(password, 10);

  const newUser = new User({
    name,
    email: normalizedEmail,
    password: hashedPassword,
    authProvider: "local",
    authProviders: ["password"],
    passwordSet: true
  });
  await newUser.save();

  res.json({ message: "Account created successfully" });
});

// ✅ Login (checks MongoDB)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const normalizedEmail = email.toLowerCase().trim();

  const user =
    await User.findOne({
      email: normalizedEmail
    });

  if (!user) {
    return res.status(401).json({
      message: "Invalid credentials"
    });
  }

  // Password login is allowed only if
  // password authentication is linked
  if (
    !user.authProviders ||
    !user.authProviders.includes("password")
  ) {
    return res.status(401).json({
      message: "Password login is not enabled for this account."
    });
  }

  const isMatch =
    await bcrypt.compare(
      password,
      user.password
    );

  if (!isMatch) {
    return res.status(401).json({
      message: "Invalid credentials"
    });
  }


  const token = jwt.sign(
    {
      userId: user._id
    },
    process.env.JWT_SECRET,
    {
      expiresIn: "7d"
    }
  );

  // Return token + user info
  res.json({
    message: "Login successful",
    token,
    user: {
      name: user.name,
      email: user.email
    }
  });
});



app.post("/api/forgot-password", async (req, res) => {

  try {

    const { email } = req.body;

    if (!email) {
      return res.status(400).json({
        success: false,
        message: "Email is required."
      });
    }

    const normalizedEmail =
      email.toLowerCase().trim();

    const user =
      await User.findOne({
        email: normalizedEmail
      });

    if (!user) {
      return res.status(404).json({
        success: false,
        message: "User not found."
      });
    }

    // Generate secure reset token
    const token = crypto.randomBytes(32).toString("hex");

    const otp = crypto.randomInt(100000, 1000000).toString();

    const otpHash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    user.resetToken = token;

    user.resetTokenExpiry = new Date(
      Date.now() + 60 * 60 * 1000
    );

    user.resetOtpHash = otpHash;

    user.resetOtpExpiry = new Date(
      Date.now() + 10 * 60 * 1000
    );

    await user.save();

    // Reset password page
    const resetLink =
      `https://satyamtiwari23.github.io/CyberSheild_Hub/reset-password.html?token=${token}`;

    // Email content
    const emailContent = [
      `From: CyberShield Hub <${process.env.GMAIL_USER}>`,
      `To: ${user.email}`,
      `Subject: Reset Password - CyberShield Hub`,
      `Content-Type: text/html; charset=utf-8`,
      ``,
      `
      <div style="font-family: Arial, sans-serif; max-width: 600px; margin: auto; padding: 30px;">

        <h2 style="color: #2563eb;">
          CyberShield Hub
        </h2>
     
        <h3>Password Reset Request</h3>

        <p>
          You requested to reset your CyberShield Hub password.
        </p>

        <p>
          Click the button below to create a new password:
        </p>
 
        <p>
    Your verification OTP is:
</p>

<h2 style="
    letter-spacing: 6px;
    font-size: 28px;
    color: #2563eb;
">
    ${otp}
</h2>

<p style="color:#666;">
    This OTP will expire in 10 minutes.
</p>
        <p>
          <a
            href="${resetLink}"
            style="
              display: inline-block;
              padding: 12px 22px;
              background: #2563eb;
              color: white;
              text-decoration: none;
              border-radius: 8px;
              font-weight: bold;
            "
          >
            Reset Password
          </a>
        </p>

        <p style="color: #666; margin-top: 25px;">
          This password reset link will expire in 1 hour.
        </p>

        <p style="color: #888; font-size: 13px;">
          If you did not request this password reset, you can safely ignore this email.
        </p>

      </div>
      `
    ].join("\r\n");

    // Convert email to Gmail API format
    const encodedMessage =
      Buffer.from(emailContent)
        .toString("base64")
        .replace(/\+/g, "-")
        .replace(/\//g, "_")
        .replace(/=+$/, "");

    // Send email using Gmail API
    const result = await gmail.users.messages.send({
      userId: "me",
      requestBody: {
        raw: encodedMessage
      }
    });

    console.log("Gmail email sent successfully:", result.data.id);

    return res.status(200).json({
      success: true,
      message: "Reset link sent successfully."
    });

  } catch (error) {

    console.error("GMAIL SEND ERROR:");
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Failed to send reset email."
    });

  }

});

app.post("/api/reset-password", async (req, res) => {

  try {

    const { token, otp, password } = req.body;

    if (!token || !otp || !password) {
      return res.status(400).json({
        success: false,
        message: "Token, OTP and password are required."
      });
    }

    if (password.length < 6) {
      return res.status(400).json({
        success: false,
        message: "Password must be at least 6 characters."
      });
    }

    const user = await User.findOne({
      resetToken: token,
      resetTokenExpiry: {
        $gt: Date.now()
      }
    });

    if (!user) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired reset link."
      });
    }

    // Hash the OTP entered by the user
    const enteredOtpHash = crypto
      .createHash("sha256")
      .update(otp)
      .digest("hex");

    // Check OTP
    if (
      user.resetOtpHash !== enteredOtpHash ||
      !user.resetOtpExpiry ||
      user.resetOtpExpiry.getTime() < Date.now()
    ) {
      return res.status(400).json({
        success: false,
        message: "Invalid or expired OTP."
      });
    }

    // Change password
    user.password = await bcrypt.hash(password, 10);
    user.passwordSet = true;

    // Enable password authentication
    if (!user.authProviders) {
      user.authProviders = [];
    }

    if (!user.authProviders.includes("password")) {
      user.authProviders.push("password");
    }

    // Remove reset credentials
    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    user.resetOtpHash = undefined;
    user.resetOtpExpiry = undefined;

    await user.save();

    return res.json({
      success: true,
      message: "Password reset successful"
    });

  } catch (error) {

    console.error("RESET PASSWORD ERROR:");
    console.error(error);

    return res.status(500).json({
      success: false,
      message: "Unable to reset password."
    });

  }

});

// Google OAuth callback
app.get("/oauth2callback", async (req, res) => {

  try {

    const { code } = req.query;

    if (!code) {
      return res.status(400).send("Authorization code missing.");
    }

    const { tokens } =
      await googleOAuth2Client.getToken(code);

    console.log("Google OAuth authorization completed successfully.");

    res.send(`
      <h2>Google authorization successful ✅</h2>
      <p>You can close this tab.</p>
      <p>Check your Node.js terminal for the refresh token.</p>
    `);

  } catch (error) {

    console.error("Google OAuth error:", error);

    res.status(500).send(
      "Google authorization failed. Check the server terminal."
    );

  }

});

// Start server
const PORT = process.env.PORT || 5001;
app.get("/", (req, res) => {
  res.send("CyberShield Hub Backend is running successfully 🚀");
});


// =====================================================
// SAFE REMOTE MEDIA FETCH
// =====================================================

function isPrivateIPv4(ip) {
  const parts = ip.split(".").map(Number);

  if (parts.length !== 4 || parts.some(Number.isNaN)) {
    return true;
  }

  const [a, b] = parts;

  return (
    a === 10 ||
    a === 127 ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168)
  );
}


function isPrivateIPv6(ip) {
  const normalized = ip.toLowerCase();

  return (
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    normalized.startsWith("fe80:")
  );
}


async function validatePublicMediaUrl(rawUrl) {

  let parsed;

  try {
    parsed = new URL(rawUrl);
  } catch {
    throw new Error("Invalid media URL.");
  }


  if (!["http:", "https:"].includes(parsed.protocol)) {
    throw new Error(
      "Only HTTP and HTTPS media URLs are supported."
    );
  }


  if (!parsed.hostname) {
    throw new Error("Invalid media hostname.");
  }


  // Prevent requests to localhost/private network addresses.
  const addresses =
    await dns.lookup(
      parsed.hostname,
      {
        all: true
      }
    );


  for (const address of addresses) {

    const ip = address.address;

    if (
      net.isIPv4(ip) &&
      isPrivateIPv4(ip)
    ) {
      throw new Error(
        "Private or local network URLs are not allowed."
      );
    }

    if (
      net.isIPv6(ip) &&
      isPrivateIPv6(ip)
    ) {
      throw new Error(
        "Private or local network URLs are not allowed."
      );
    }

  }


  return parsed.toString();

}


// =====================================================
// SIGHTENGINE AI MEDIA DETECTION
// Supports:
// 1. Uploaded image/video
// 2. Public image/video URL
// =====================================================

app.post(
  "/api/deepfake/analyze",
  upload.single("media"),
  async (req, res) => {

    try {

      // -------------------------------------------------
      // CHECK SIGHTENGINE CREDENTIALS
      // -------------------------------------------------

      if (
        !process.env.SIGHTENGINE_API_USER ||
        !process.env.SIGHTENGINE_SECRET_KEY
      ) {
        return res.status(500).json({
          success: false,
          error: "Sightengine API credentials are not configured."
        });
      }


      // -------------------------------------------------
      // GET MEDIA
      // -------------------------------------------------

      let mediaBuffer;
      let mediaType;
      let mediaName;


      // -------------------------------------------------
      // OPTION 1 — UPLOADED FILE
      // -------------------------------------------------

      if (req.file) {

        mediaBuffer = req.file.buffer;

        mediaType = req.file.mimetype;

        mediaName = req.file.originalname;

      }


      // -------------------------------------------------
      // OPTION 2 — PUBLIC MEDIA URL
      // -------------------------------------------------

      else if (req.body?.url) {

        const mediaUrl =
          await validatePublicMediaUrl(
            req.body.url
          );


        const remoteResponse =
          await axios.get(
            mediaUrl,
            {
              responseType: "arraybuffer",

              timeout: 30000,

              maxContentLength:
                15 * 1024 * 1024,

              maxBodyLength:
                15 * 1024 * 1024,

              maxRedirects: 0,

              validateStatus:
                status =>
                  status >= 200 &&
                  status < 300
            }
          );


        mediaBuffer =
          Buffer.from(
            remoteResponse.data
          );


        mediaType =
          (
            remoteResponse.headers[
              "content-type"
            ] || ""
          ).split(";")[0].trim();


        const supportedTypes = [

          "image/jpeg",
          "image/png",
          "image/webp",
          "image/gif",

          "video/mp4",
          "video/webm",
          "video/avi",
          "video/x-msvideo",
          "video/x-matroska",
          "video/x-ms-wmv",
          "video/quicktime"

        ];


        if (
          !supportedTypes.includes(
            mediaType
          )
        ) {

          throw new Error(
            "The URL does not point directly to a supported image or video file."
          );

        }


        mediaName =
          new URL(mediaUrl)
            .pathname
            .split("/")
            .pop() ||
          "remote-media";

      }


      // -------------------------------------------------
      // NOTHING SUPPLIED
      // -------------------------------------------------

      else {

        return res.status(400).json({
          success: false,
          error:
            "Upload an image/video or provide a public media URL."
        });

      }


      // -------------------------------------------------
      // SIZE CHECK
      // -------------------------------------------------

      if (
        mediaBuffer.length >
        15 * 1024 * 1024
      ) {

        return res.status(413).json({
          success: false,
          error:
            "Media file is too large. Maximum size is 15 MB."
        });

      }


      // -------------------------------------------------
      // DETECT IMAGE OR VIDEO
      // -------------------------------------------------

      const isVideo =
        mediaType.startsWith("video/");


      // -------------------------------------------------
      // SIGHTENGINE REQUEST
      // -------------------------------------------------

      let sightResponse;


      // =================================================
      // IMAGE
      // =================================================

      if (!isVideo) {

        const form =
          new FormData();

        form.append(
          "media",
          mediaBuffer,
          {
            filename: mediaName,
            contentType: mediaType
          }
        );

        form.append(
          "models",
          "genai,deepfake"
        );

        form.append(
          "api_user",
          process.env.SIGHTENGINE_API_USER
        );

        form.append(
          "api_secret",
          process.env.SIGHTENGINE_SECRET_KEY
        );


        sightResponse =
          await axios.post(
            "https://api.sightengine.com/1.0/check.json",
            form,
            {
              headers:
                form.getHeaders(),

              timeout: 60000,

              maxContentLength:
                Infinity,

              maxBodyLength:
                Infinity
            }
          );

      }


      // =================================================
      // VIDEO
      // =================================================

      else {

        const form =
          new FormData();

        form.append(
          "media",
          mediaBuffer,
          {
            filename: mediaName,
            contentType: mediaType
          }
        );

        form.append(
          "models",
          "genai,deepfake"
        );

        form.append(
          "api_user",
          process.env.SIGHTENGINE_API_USER
        );

        form.append(
          "api_secret",
          process.env.SIGHTENGINE_SECRET_KEY
        );

        // Analyze approximately every 2 seconds.
        // This helps control free-plan operation usage.
        form.append(
          "interval",
          "2"
        );


        sightResponse =
          await axios.post(
            "https://api.sightengine.com/1.0/video/check-sync.json",
            form,
            {
              headers:
                form.getHeaders(),

              timeout: 120000,

              maxContentLength:
                Infinity,

              maxBodyLength:
                Infinity
            }
          );

      }


      const sightData =
        sightResponse.data;


      // -------------------------------------------------
      // CHECK API RESPONSE
      // -------------------------------------------------

      if (
        sightData?.status !== "success"
      ) {

        return res.status(502).json({
          success: false,
          error:
            "Sightengine returned an unsuccessful response."
        });

      }


      // =================================================
      // NORMALIZE IMAGE RESULT
      // =================================================

      if (!isVideo) {

        const aiGenerated =
          Number(
            sightData?.type?.ai_generated || 0
          );

        const deepfake =
          Number(
            sightData?.type?.deepfake || 0
          );


        const overall =
          Math.max(
            aiGenerated,
            deepfake
          );


        let verdict;


        if (
          aiGenerated >= 0.5 &&
          deepfake >= 0.5
        ) {

          verdict =
            "Potential AI-Generated / Deepfake";

        }

        else if (
          aiGenerated >= 0.5
        ) {

          verdict =
            "Potential AI-Generated Media";

        }

        else if (
          deepfake >= 0.5
        ) {

          verdict =
            "Potential Deepfake";

        }

        else {

          verdict =
            "Likely Authentic";

        }


        return res.json({

          success: true,

          filename:
            mediaName,

          mimeType:
            mediaType,

          score:
            Math.round(
              overall * 100
            ),

          aiGeneratedScore:
            Math.round(
              aiGenerated * 100
            ),

          deepfakeScore:
            Math.round(
              deepfake * 100
            ),

          confidence:
            Math.round(
              overall * 100
            ),

          verdict,

          aiGeneratedDetected:
            aiGenerated >= 0.5,

          deepfakeDetected:
            deepfake >= 0.5,

          frames: 1,

          frameResults: [
            {
              frameIndex: 0,

              timestamp: 0,

              probability:
                overall,

              aiGenerated,

              deepfake
            }
          ],

          source: null,

          sourceScore: 0,

          sightengine: {
            requestId:
              sightData?.request?.id ||
              null,

            operations:
              sightData?.request?.operations ||
              0
          }

        });

      }


      // =================================================
      // NORMALIZE VIDEO RESULT
      // =================================================

      const videoResults =
        Array.isArray(
          sightData?.data
        )
          ? sightData.data
          : Array.isArray(
              sightData?.frames
            )
            ? sightData.frames
            : [];


      const frameResults =
        videoResults.map(
          (frame, index) => {

            const aiGenerated =
              Number(
                frame?.type?.ai_generated ??
                frame?.ai_generated ??
                0
              );

            const deepfake =
              Number(
                frame?.type?.deepfake ??
                frame?.deepfake ??
                0
              );

            const probability =
              Math.max(
                aiGenerated,
                deepfake
              );


            return {

              frameIndex:
                frame?.frame_index ??
                index,

              timestamp:
                Number(
                  frame?.timestamp ??
                  frame?.time ??
                  0
                ),

              probability,

              aiGenerated,

              deepfake

            };

          }
        );


      const aiGeneratedScore =
        frameResults.length
          ? Math.max(
              ...frameResults.map(
                frame =>
                  frame.aiGenerated
              )
            )
          : 0;


      const deepfakeScore =
        frameResults.length
          ? Math.max(
              ...frameResults.map(
                frame =>
                  frame.deepfake
              )
            )
          : 0;


      const overallProbability =
        Math.max(
          aiGeneratedScore,
          deepfakeScore
        );


      let verdict;


      if (
        aiGeneratedScore >= 0.5 &&
        deepfakeScore >= 0.5
      ) {

        verdict =
          "Potential AI-Generated / Deepfake";

      }

      else if (
        aiGeneratedScore >= 0.5
      ) {

        verdict =
          "Potential AI-Generated Media";

      }

      else if (
        deepfakeScore >= 0.5
      ) {

        verdict =
          "Potential Deepfake";

      }

      else {

        verdict =
          "Likely Authentic";

      }


      return res.json({

        success: true,

        filename:
          mediaName,

        mimeType:
          mediaType,

        score:
          Math.round(
            overallProbability * 100
          ),

        aiGeneratedScore:
          Math.round(
            aiGeneratedScore * 100
          ),

        deepfakeScore:
          Math.round(
            deepfakeScore * 100
          ),

        confidence:
          Math.round(
            overallProbability * 100
          ),

        verdict,

        aiGeneratedDetected:
          aiGeneratedScore >= 0.5,

        deepfakeDetected:
          deepfakeScore >= 0.5,

        frames:
          frameResults.length,

        frameResults,

        source: null,

        sourceScore: 0,

        sightengine: {

          requestId:
            sightData?.request?.id ||
            null,

          operations:
            sightData?.request?.operations ||
            0

        }

      });

    }

    catch (error) {

      console.error(
        "Sightengine Deepfake Analysis Error:",
        error.response?.data ||
        error.message
      );


      return res.status(
        error.response?.status ||
        500
      ).json({

        success: false,

        error:
          error.response?.data?.error?.message ||
          error.response?.data?.message ||
          error.message ||
          "Sightengine analysis failed."

      });

    }

  }
);


app.post("/api/url/analyze", async (req, res) => {

  try {

    const { url } = req.body;

    if (!url) {
      return res.status(400).json({
        error: "URL is required"
      });
    }

    const response = await axios.post(
      `${SECURITY_ENGINE_URL}/analyze-url`,
      {
        url: url
      }
    );

    return res.json(response.data);

  } catch (error) {

    console.error(
      "URL Security Engine Error:",
      error.message
    );

    return res.status(500).json({
      error: "Security engine unavailable"
    });
  }
});

// 🤖 AI Security Assistant
app.post("/api/ai/explain", async (req, res) => {

  try {

    const { topic, source } = req.body;

    if (!topic) {
      return res.status(400).json({
        error: "Topic is required"
      });
    }

    const authHeader =
      req.headers.authorization;

    const response = await axios.post(
      `${AI_SERVICE_URL}/generate`,
      {
        topic: topic,
        source: source || "user"
      },
      {
        headers: {
          Authorization: authHeader || ""
        }
      }
    );

    return res.json(response.data);

  } catch (error) {

    console.error(
      "AI Chatbot Error:",
      error.response?.status,
      error.response?.data || error.message
    );

    return res.status(
      error.response?.status || 500
    ).json(
      error.response?.data || {
        error: "AI service unavailable"
      }
    );
  }
});

// =====================================================
// START GITHUB ACCOUNT LINKING
// =====================================================

app.get("/api/auth/link/github/start", authenticateToken, (req, res) => {

  const state =
    crypto.randomBytes(32).toString("hex");

  const linkSession =
    jwt.sign(
      {
        userId: req.userId,
        state: state
      },
      process.env.JWT_SECRET,
      {
        expiresIn: "10m"
      }
    );

  const isProduction =
    process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    `github_link_session=${linkSession}; HttpOnly; Secure; SameSite=None; Path=/; Max-Age=600`
  );

  const githubAuthUrl =
    "https://github.com/login/oauth/authorize" +
    `?client_id=${encodeURIComponent(GITHUB_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(GITHUB_LINK_REDIRECT_URI)}` +
    `&scope=${encodeURIComponent("read:user user:email")}` +
    `&state=${encodeURIComponent(state)}`;

  res.json({
    success: true,
    authUrl: githubAuthUrl
  });
});


// =====================================================
// GITHUB ACCOUNT LINK CALLBACK
// =====================================================

app.get("/auth/link/github/callback", async (req, res) => {

  try {

    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send(
        "Invalid GitHub account linking request."
      );
    }

    // -------------------------------------------------
    // READ COOKIE
    // -------------------------------------------------

    const cookies =
      req.headers.cookie || "";

    const cookieMap = {};

    cookies
      .split(";")
      .map(cookie => cookie.trim())
      .forEach(cookie => {

        const index = cookie.indexOf("=");

        if (index !== -1) {

          const key =
            cookie.substring(0, index);

          const value =
            cookie.substring(index + 1);

          cookieMap[key] = value;

        }

      });

    const linkSession =
      cookieMap.github_link_session;

    if (!linkSession) {

      return res.status(401).send(
        "GitHub account linking session expired. Please try again."
      );

    }

    // -------------------------------------------------
    // VERIFY LINKING SESSION
    // -------------------------------------------------

    let session;

    try {

      session =
        jwt.verify(
          linkSession,
          process.env.JWT_SECRET
        );

    } catch (error) {

      return res.status(403).send(
        "Invalid or expired GitHub linking session."
      );

    }

    // -------------------------------------------------
    // VERIFY OAUTH STATE
    // -------------------------------------------------

    if (
      !session.state ||
      session.state !== state
    ) {

      return res.status(403).send(
        "Invalid OAuth state."
      );

    }

    // -------------------------------------------------
    // FIND CURRENT CYBERSHIELD USER
    // -------------------------------------------------

    const user =
      await User.findById(session.userId);

    if (!user) {

      return res.status(404).send(
        "CyberShield account not found."
      );

    }

    // -------------------------------------------------
    // EXCHANGE GITHUB CODE FOR ACCESS TOKEN
    // -------------------------------------------------

    const tokenResponse =
      await axios.post(
        "https://github.com/login/oauth/access_token",
        {
          client_id: GITHUB_CLIENT_ID,
          client_secret: GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: GITHUB_LINK_REDIRECT_URI
        },
        {
          headers: {
            Accept: "application/json"
          }
        }
      );

    const githubAccessToken =
      tokenResponse.data.access_token;

    if (!githubAccessToken) {

      console.error(
        "GitHub linking token error:",
        tokenResponse.data
      );

      return res.status(500).send(
        "GitHub authorization failed."
      );

    }

    // -------------------------------------------------
    // GET GITHUB USER
    // -------------------------------------------------

    const githubUserResponse =
      await axios.get(
        "https://api.github.com/user",
        {
          headers: {
            Authorization:
              `Bearer ${githubAccessToken}`,
            Accept: "application/vnd.github+json"
          }
        }
      );

    const githubUser =
      githubUserResponse.data;

    // -------------------------------------------------
    // GET GITHUB EMAIL
    // -------------------------------------------------

    const githubEmailsResponse =
      await axios.get(
        "https://api.github.com/user/emails",
        {
          headers: {
            Authorization:
              `Bearer ${githubAccessToken}`,
            Accept: "application/vnd.github+json"
          }
        }
      );

    const githubEmail =
      githubEmailsResponse.data.find(
        email =>
          email.primary &&
          email.verified
      );

    if (!githubEmail) {

      return res.status(400).send(
        "No verified GitHub email was found."
      );

    }

    const githubEmailAddress =
      githubEmail.email
        .toLowerCase()
        .trim();

    // -------------------------------------------------
    // GITHUB EMAIL MUST MATCH CYBERSHIELD EMAIL
    // -------------------------------------------------

    if (githubEmailAddress !== user.email) {

      return res.status(409).send(
        "The GitHub email must match your CyberShield account email."
      );

    }

    // -------------------------------------------------
    // CHECK IF GITHUB EMAIL BELONGS TO ANOTHER ACCOUNT
    // -------------------------------------------------

    const existingUser =
      await User.findOne({
        email: githubEmailAddress
      });

    if (
      existingUser &&
      existingUser._id.toString() !==
      user._id.toString()
    ) {

      return res.status(409).send(
        "This GitHub account is already linked to another CyberShield account."
      );

    }

    // -------------------------------------------------
    // MAKE SURE authProviders EXISTS
    // -------------------------------------------------

    if (!user.authProviders) {
      user.authProviders = [];
    }

    // -------------------------------------------------
    // LINK GITHUB
    // -------------------------------------------------

    if (
      !user.authProviders.includes("github")
    ) {

      user.authProviders.push("github");

    }

    await user.save();

    console.log(
      `GitHub account linked successfully to ${user.email}`
    );

    res.send(`
      <h2>GitHub account linked successfully ✅</h2>
      <p>GitHub has been linked to your CyberShield account.</p>
      <p>You can close this tab and return to CyberShield Hub.</p>
    `);

  } catch (error) {

    console.error(
      "GitHub Account Linking Error:",
      error.response?.data ||
      error.message ||
      error
    );

    res.status(500).send(
      "GitHub account linking failed."
    );

  }

});


// =====================================================
// START GITHUB LOGIN
// =====================================================

app.get("/auth/github", (req, res) => {

  const mode =
    req.query.mode === "signup"
      ? "signup"
      : "login";

  const state =
    crypto.randomBytes(32).toString("hex");

  const isProduction =
    process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    [
      `github_oauth_state=${state}; HttpOnly; ${isProduction ? "Secure; " : ""}SameSite=Lax; Path=/; Max-Age=600`,
      `github_oauth_mode=${mode}; HttpOnly; ${isProduction ? "Secure; " : ""}SameSite=Lax; Path=/; Max-Age=600`
    ]
  );

  const githubAuthUrl =
    "https://github.com/login/oauth/authorize" +
    `?client_id=${encodeURIComponent(GITHUB_CLIENT_ID)}` +
    `&redirect_uri=${encodeURIComponent(GITHUB_REDIRECT_URI)}` +
    `&scope=${encodeURIComponent("read:user user:email")}` +
    `&state=${encodeURIComponent(state)}`;

  res.redirect(githubAuthUrl);

});

// =====================================================
// GITHUB LOGIN / SIGNUP CALLBACK
// =====================================================

app.get("/auth/github/callback", async (req, res) => {

  try {

    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send(
        "Invalid GitHub OAuth request."
      );
    }

    // -------------------------------------------------
    // READ COOKIES
    // -------------------------------------------------

    const cookies =
      req.headers.cookie || "";

    const cookieMap = {};

    cookies
      .split(";")
      .map(cookie => cookie.trim())
      .forEach(cookie => {

        const index = cookie.indexOf("=");

        if (index !== -1) {

          const key =
            cookie.substring(0, index);

          const value =
            cookie.substring(index + 1);

          cookieMap[key] = value;
        }
      });

    const savedState =
      cookieMap.github_oauth_state;

    const mode =
      cookieMap.github_oauth_mode || "login";


    // -------------------------------------------------
    // VERIFY STATE
    // -------------------------------------------------

    if (!savedState || savedState !== state) {

      return res.status(403).send(
        "Invalid OAuth state."
      );

    }


    // -------------------------------------------------
    // EXCHANGE CODE FOR ACCESS TOKEN
    // -------------------------------------------------

    const tokenResponse =
      await axios.post(
        "https://github.com/login/oauth/access_token",
        {
          client_id: GITHUB_CLIENT_ID,
          client_secret: GITHUB_CLIENT_SECRET,
          code,
          redirect_uri: GITHUB_REDIRECT_URI
        },
        {
          headers: {
            Accept: "application/json"
          }
        }
      );

    const githubAccessToken =
      tokenResponse.data.access_token;

    if (!githubAccessToken) {

      console.error(
        "GitHub token error:",
        tokenResponse.data
      );

      return res.status(500).send(
        "GitHub authorization failed."
      );

    }


    // -------------------------------------------------
    // GET GITHUB USER
    // -------------------------------------------------

    const githubUserResponse =
      await axios.get(
        "https://api.github.com/user",
        {
          headers: {
            Authorization:
              `Bearer ${githubAccessToken}`,
            Accept: "application/vnd.github+json"
          }
        }
      );

    const githubUser =
      githubUserResponse.data;


    // -------------------------------------------------
    // GET GITHUB EMAIL
    // -------------------------------------------------

    const githubEmailsResponse =
      await axios.get(
        "https://api.github.com/user/emails",
        {
          headers: {
            Authorization:
              `Bearer ${githubAccessToken}`,
            Accept: "application/vnd.github+json"
          }
        }
      );

    const githubEmail =
      githubEmailsResponse.data.find(
        email =>
          email.primary &&
          email.verified
      );

    if (!githubEmail) {

      return res.status(400).send(
        "No verified GitHub email was found."
      );

    }

    const email =
      githubEmail.email
        .toLowerCase()
        .trim();

    const name =
      githubUser.name ||
      githubUser.login ||
      "GitHub User";


    // -------------------------------------------------
    // FIND USER IN MONGODB
    // -------------------------------------------------

    let user =
      await User.findOne({
        email
      });


    // =================================================
    // GITHUB SIGNUP
    // =================================================

    if (mode === "signup") {

      if (user) {

        // Allow GitHub signup if this account
        // was already created with GitHub.
        if (!user.authProviders ||
          !user.authProviders.includes("github")) {

          const frontend =
            process.env.FRONTEND_URL ||
            "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";

          return res.redirect(
            `${frontend}/login.html?oauth_error=` +
            encodeURIComponent(
              "This email is already registered with another login method. Please use that method."
            )
          );
        }

        // Same GitHub account → continue to JWT login

      } else {

        // Create NEW GitHub account

        const randomPassword =
          crypto.randomBytes(32).toString("hex");

        const hashedPassword =
          await bcrypt.hash(randomPassword, 10);

        user = new User({
          name,
          email,
          password: hashedPassword,
          authProvider: "github",
          authProviders: ["github"],
          passwordSet: false
        });

        await user.save();
      }

    }


    // =================================================
    // GITHUB LOGIN
    // =================================================

    else {

      if (!user) {

        const frontend =
          process.env.FRONTEND_URL ||
          "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";

        return res.redirect(
          `${frontend}/login.html?oauth_error=` +
          encodeURIComponent(
            "No CyberShield account found with this GitHub email. Please sign up first."
          )
        );

      }


      // Existing account created with another provider

      if (
        !user.authProviders ||
        !user.authProviders.includes("github")
      ) {

        const frontend =
          process.env.FRONTEND_URL ||
          "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";

        return res.redirect(
          `${frontend}/login.html?oauth_error=` +
          encodeURIComponent(
            "GitHub is not linked to this account. Please use your linked login method."
          )
        );

      }

    }


    // -------------------------------------------------
    // CREATE CYBERSHIELD JWT
    // -------------------------------------------------

    const token =
      jwt.sign(
        {
          userId: user._id
        },

        process.env.JWT_SECRET,

        {
          expiresIn: "7d"
        }
      );


    // -------------------------------------------------
    // FRONTEND REDIRECT
    // -------------------------------------------------

    const frontend =
      process.env.FRONTEND_URL ||
      "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";

    const redirectUrl =
      `${frontend}/login.html` +
      `#oauth_token=${encodeURIComponent(token)}` +
      `&name=${encodeURIComponent(user.name)}` +
      `&email=${encodeURIComponent(user.email)}` +
      `&provider=github`;

    res.redirect(redirectUrl);


  } catch (error) {

    console.error(
      "GitHub Login OAuth Error:",
      error.response?.data ||
      error.message ||
      error
    );

    res.status(500).send(
      "GitHub login failed."
    );

  }

});
// =====================================================
// GOOGLE LOGIN / SIGNUP
// =====================================================

app.get("/auth/google-login", (req, res) => {

  const mode =
    req.query.mode === "signup"
      ? "signup"
      : "login";

  const state =
    crypto.randomBytes(32).toString("hex");

  const isProduction =
    process.env.NODE_ENV === "production";

  res.setHeader(
    "Set-Cookie",
    `google_oauth_state=${state}; HttpOnly; ${isProduction ? "Secure; " : ""
    }SameSite=Lax; Path=/; Max-Age=600`
  );

  const authUrl =
    googleLoginClient.generateAuthUrl({
      access_type: "offline",

      scope: [
        "openid",
        "email",
        "profile"
      ],

      state,

      prompt: "select_account",

      login_hint: undefined
    });

  // Save mode in another cookie
  res.setHeader(
    "Set-Cookie",
    [
      `google_oauth_state=${state}; HttpOnly; ${isProduction ? "Secure; " : ""
      }SameSite=Lax; Path=/; Max-Age=600`,

      `google_oauth_mode=${mode}; HttpOnly; ${isProduction ? "Secure; " : ""
      }SameSite=Lax; Path=/; Max-Age=600`
    ]
  );

  res.redirect(authUrl);
});

// =====================================================
// GOOGLE LOGIN / SIGNUP CALLBACK
// =====================================================

app.get("/auth/google-login/callback", async (req, res) => {

  try {

    const { code, state } = req.query;

    if (!code || !state) {
      return res.status(400).send(
        "Invalid Google OAuth request."
      );
    }

    // -------------------------------------------------
    // READ COOKIES
    // -------------------------------------------------

    const cookies =
      req.headers.cookie || "";

    const cookieMap = {};

    cookies
      .split(";")
      .map(cookie => cookie.trim())
      .forEach(cookie => {

        const index = cookie.indexOf("=");

        if (index !== -1) {

          const key =
            cookie.substring(0, index);

          const value =
            cookie.substring(index + 1);

          cookieMap[key] = value;
        }
      });

    const savedState =
      cookieMap.google_oauth_state;

    const mode =
      cookieMap.google_oauth_mode || "login";


    // -------------------------------------------------
    // VERIFY STATE
    // -------------------------------------------------

    if (!savedState || savedState !== state) {

      return res.status(403).send(
        "Invalid OAuth state."
      );

    }


    // -------------------------------------------------
    // EXCHANGE CODE FOR GOOGLE TOKENS
    // -------------------------------------------------

    const { tokens } =
      await googleLoginClient.getToken(code);

    googleLoginClient.setCredentials(tokens);


    // -------------------------------------------------
    // GET GOOGLE USER INFORMATION
    // -------------------------------------------------

    const oauth2Client =
      google.oauth2({
        auth: googleLoginClient,
        version: "v2"
      });

    const { data } =
      await oauth2Client.userinfo.get();

    const email =
      data.email?.toLowerCase().trim();

    const name =
      data.name || "Google User";


    if (!email) {

      return res.status(400).send(
        "Google account email could not be retrieved."
      );

    }


    // -------------------------------------------------
    // FIND USER IN MONGODB
    // -------------------------------------------------

    let user =
      await User.findOne({
        email: email
      });


    // =================================================
    // GOOGLE SIGNUP
    // =================================================

    if (mode === "signup") {

      // Email already exists
      if (user) {

        // Allow Google signup if this account
        // was already created with Google.
        if (!user.authProviders ||
          !user.authProviders.includes("google")) {

          const frontend =
            process.env.FRONTEND_URL ||
            "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";

          return res.redirect(
            `${frontend}/login.html?oauth_error=` +
            encodeURIComponent(
              "This email is already registered with another login method. Please use that method."
            )
          );
        }

        // Same Google account → continue to JWT login

      } else {

        // Create NEW Google account

        const randomPassword =
          crypto.randomBytes(32).toString("hex");

        const hashedPassword =
          await bcrypt.hash(randomPassword, 10);

        user = new User({
          name,
          email,
          password: hashedPassword,
          authProvider: "google",
          authProviders: ["google"],
          passwordSet: false
        });
        await user.save();
      }

    }


    // =================================================
    // GOOGLE LOGIN
    // =================================================

    else {

      // User doesn't exist
      if (!user) {

        const frontend =
          process.env.FRONTEND_URL ||
          "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";

        return res.redirect(
          `${frontend}/login.html?oauth_error=` +
          encodeURIComponent(
            "No CyberShield account found with this Google email. Please sign up first."
          )
        );

      }


      // Existing account created with another provider
      if (
        !user.authProviders ||
        !user.authProviders.includes("google")
      ) {

        const frontend =
          process.env.FRONTEND_URL ||
          "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";

        return res.redirect(
          `${frontend}/login.html?oauth_error=` +
          encodeURIComponent(
            "This email is already registered with another login method. Please use that method."
          )
        );

      }

    }


    // -------------------------------------------------
    // CREATE CYBERSHIELD JWT
    // -------------------------------------------------

    const token =
      jwt.sign(
        {
          userId: user._id
        },

        process.env.JWT_SECRET,

        {
          expiresIn: "7d"
        }
      );


    // -------------------------------------------------
    // FRONTEND REDIRECT
    // -------------------------------------------------

    const frontend =
      process.env.FRONTEND_URL ||
      "http://127.0.0.1:5501/Git/Git_posts/CyberSheild_Hub/frontend";


    const redirectUrl =
      `${frontend}/login.html` +
      `#oauth_token=${encodeURIComponent(token)}` +
      `&name=${encodeURIComponent(user.name)}` +
      `&email=${encodeURIComponent(user.email)}`;


    res.redirect(redirectUrl);


  } catch (error) {

    console.error(
      "Google Login OAuth Error:",
      error.response?.data ||
      error.message ||
      error
    );

    res.status(500).send(
      "Google login failed."
    );

  }

});


app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend running on port ${PORT}`);
});