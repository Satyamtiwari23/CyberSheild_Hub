require("dotenv").config();
const nodemailer = require("nodemailer");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcryptjs");
const express = require('express');
const cors = require('cors');
const mongoose = require("mongoose");

const app = express();
app.use(cors());
app.use(express.json());
const transporter = nodemailer.createTransport({
  service: "gmail",

  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS
  }
});

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
  resetTokenExpiry: Date
});

// ✅ Create Model
const User = mongoose.model("User", userSchema);

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

  const { email } = req.body;

  const user =
    await User.findOne({ email });

  if (!user) {
    return res.status(404).json({
      message: "User not found"
    });
  }

  const token =
    crypto.randomBytes(32).toString("hex");

  user.resetToken = token;

  user.resetTokenExpiry =
    Date.now() + 3600000;

  await user.save();

  const resetLink =
    `http://127.0.0.1:5501/projects/Advanced/CyberSheild_Hub/frontend/reset-password.html?token=${token}`;

  try {

    await transporter.sendMail({
      from: "CyberShield Hub <cybershelidhub26@gmail.com>",
      to: user.email,
      subject: "Reset Password",
      html: `
        <h2>Reset Password</h2>
        <a href="${resetLink}">
            Reset Password
        </a>
        `
    });

    console.log("Email sent successfully");

    return res.status(200).json({
      success: true,
      message: "Reset link sent successfully."
    });

  } catch (err) {

    console.log("EMAIL ERROR:");
    console.log(err);

    return res.status(500).json({
      success: false,
      message: "Failed to send reset email."
    });

  }

});

app.post(
  "/api/reset-password",
  async (req, res) => {

    const { token, password } =
      req.body;

    const user =
      await User.findOne({
        resetToken: token,
        resetTokenExpiry: {
          $gt: Date.now()
        }
      });

    if (!user) {
      return res.status(400).json({
        message: "Invalid or expired token"
      });
    }

    user.password =
      await bcrypt.hash(
        password,
        10
      );

    user.resetToken = undefined;
    user.resetTokenExpiry = undefined;

    await user.save();

    res.json({
      message: "Password reset successful"
    });

  });



// Start server
const PORT = process.env.PORT || 5001;
app.get("/", (req, res) => {
    res.send("CyberShield Hub Backend is running successfully 🚀");
});

app.listen(PORT, "0.0.0.0", () => {
  console.log(`Backend running on port ${PORT}`);
});