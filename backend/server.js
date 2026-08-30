require("dotenv").config();
const { google } = require("googleapis");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");

const app = express();
const googleOAuth2Client = new google.auth.OAuth2(
  process.env.GMAIL_CLIENT_ID,
  process.env.GMAIL_CLIENT_SECRET,
  process.env.GMAIL_REDIRECT_URI
);

googleOAuth2Client.setCredentials({
  refresh_token: process.env.GMAIL_REFRESH_TOKEN
});

const gmail = google.gmail({
  version: "v1",
  auth: googleOAuth2Client
});
app.use(cors());
app.use(express.json());

// ✅ Connect MongoDB
mongoose.connect(process.env.MONGODB_URI)
  .then(() => console.log("MongoDB Connected ✅"))
  .catch((err) => console.log(err));

// ✅ Create Schema
const userSchema = new mongoose.Schema({
  name: String,
  email: String,
  password: String,

  resetToken: String,
  resetTokenExpiry: Date,

  resetOtpHash: String,
  resetOtpExpiry: Date
});

// ✅ Create Model
const User = mongoose.model("User", userSchema);


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

  const existingUser = await User.findOne({ email });
  if (existingUser) {
    return res.status(409).json({ message: "User already exists" });
  }

  const hashedPassword =
    await bcrypt.hash(password, 10);

  const newUser = new User({
    name,
    email,
    password: hashedPassword
  });
  await newUser.save();

  res.json({ message: "Account created successfully" });
});

// ✅ Login (checks MongoDB)
app.post('/api/login', async (req, res) => {
  const { email, password } = req.body;

  const user =
    await User.findOne({ email });

  if (!user) {
    return res.status(401).json({
      message: "Invalid credentials"
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

    const user = await User.findOne({ email });

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
    user.password = await bcrypt.hash(
      password,
      10
    );

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

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend running on port ${PORT}`);
});