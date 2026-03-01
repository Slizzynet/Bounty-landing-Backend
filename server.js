require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const axios = require("axios");

const app = express();
app.use(cors());
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const db = new sqlite3.Database("./database.db");


// ================= DATABASE SETUP =================

db.serialize(async () => {

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      isAdmin INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS missions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT,
      reason TEXT,
      amount REAL,
      createdBy INTEGER
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS claims (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      missionId INTEGER,
      clip TEXT,
      paypal TEXT,
      status TEXT DEFAULT 'pending'
    )
  `);

  // CREATE ADMIN ACCOUNT IF NOT EXISTS
  db.get(
    "SELECT * FROM users WHERE username = ?",
    [ADMIN_USERNAME],
    async (err, user) => {

      if (!user) {

        const hashed = await bcrypt.hash(ADMIN_PASSWORD, 10);

        db.run(
          "INSERT INTO users (username, password, isAdmin) VALUES (?, ?, 1)",
          [ADMIN_USERNAME, hashed],
          () => {
            console.log("Admin account created");
          }
        );

      }

    }
  );

});


// ================= AUTH MIDDLEWARE =================

function authenticateToken(req, res, next) {

  const authHeader = req.headers["authorization"];

  if (!authHeader)
    return res.status(401).json({ error: "Token required" });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, (err, user) => {

    if (err)
      return res.status(403).json({ error: "Invalid token" });

    req.user = user;

    next();

  });

}


function requireAdmin(req, res, next) {

  if (!req.user.isAdmin)
    return res.status(403).json({ error: "Admin only" });

  next();

}


// ================= ROUTES =================

// Health check
app.get("/", (req, res) => {
  res.send("Production backend running ✅");
});


// REGISTER
app.post("/register", async (req, res) => {

  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: "Missing fields" });

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    function(err) {

      if (err)
        return res.status(400).json({ error: "Username exists" });

      res.json({
        message: "User created",
        userId: this.lastID
      });

    }
  );

});


// LOGIN
app.post("/login", (req, res) => {

  const { username, password } = req.body;

  db.get(
    "SELECT * FROM users WHERE username = ?",
    [username],
    async (err, user) => {

      if (!user)
        return res.status(400).json({ error: "Invalid login" });

      const valid = await bcrypt.compare(password, user.password);

      if (!valid)
        return res.status(400).json({ error: "Invalid login" });

      const token = jwt.sign({
        id: user.id,
        username: user.username,
        isAdmin: user.isAdmin
      },
      JWT_SECRET,
      { expiresIn: "7d" });

      res.json({
        token,
        isAdmin: user.isAdmin
      });

    }
  );

});


// CREATE MISSION (ADMIN ONLY)
app.post("/missions",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    const { target, reason, amount } = req.body;

    db.run(
      "INSERT INTO missions (target, reason, amount, createdBy) VALUES (?, ?, ?, ?)",
      [target, reason, amount, req.user.id],
      function(err) {

        if (err)
          return res.status(500).json({ error: err });

        res.json({
          message: "Mission created",
          missionId: this.lastID
        });

      }
    );

});


// GET MISSIONS
app.get("/missions", (req, res) => {

  db.all("SELECT * FROM missions", (err, rows) => {

    res.json(rows);

  });

});


// CLAIM MISSION
app.post("/claims",
  authenticateToken,
  (req, res) => {

    const { missionId, clip, paypal } = req.body;

    db.run(
      "INSERT INTO claims (missionId, clip, paypal) VALUES (?, ?, ?)",
      [missionId, clip, paypal],
      function(err) {

        if (err)
          return res.status(500).json({ error: err });

        res.json({
          message: "Claim submitted",
          claimId: this.lastID
        });

      }
    );

});


// ADMIN GET CLAIMS
app.get("/claims",
  authenticateToken,
  requireAdmin,
  (req, res) => {

    db.all("SELECT * FROM claims", (err, rows) => {

      res.json(rows);

    });

});


// APPROVE CLAIM (READY FOR PAYPAL PAYOUT)
app.post("/claims/:id/approve",
  authenticateToken,
  requireAdmin,
  async (req, res) => {

    const claimId = req.params.id;

    db.run(
      "UPDATE claims SET status = 'approved' WHERE id = ?",
      [claimId],
      function(err) {

        if (err)
          return res.status(500).json({ error: err });

        res.json({
          message: "Claim approved — ready for PayPal payout"
        });

      }
    );

});


// ================= START SERVER =================

app.listen(PORT, () => {

  console.log(`Backend running on port ${PORT}`);

});
