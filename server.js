require("dotenv").config();

const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");

const app = express();

app.use(helmet());
app.use(cors({ origin: "*" }));
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;
const ADMIN_USERNAME = process.env.ADMIN_USERNAME;
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD;

const db = new sqlite3.Database("./database.db");

db.serialize(async () => {

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      claimsCount INTEGER DEFAULT 0,
      rank TEXT DEFAULT 'Unranked',
      isAdmin INTEGER DEFAULT 0
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS missions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT,
      reason TEXT,
      amount REAL,
      createdBy INTEGER,
      createdAt DATETIME DEFAULT CURRENT_TIMESTAMP
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS claims (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      missionId INTEGER,
      userId INTEGER,
      clip TEXT,
      paypal TEXT,
      status TEXT DEFAULT 'pending'
    )
  `);

  db.get("SELECT * FROM users WHERE username = ?", [ADMIN_USERNAME], async (err, user) => {
    if (!user && ADMIN_USERNAME && ADMIN_PASSWORD) {
      const hashed = await bcrypt.hash(ADMIN_PASSWORD, 10);
      db.run(
        "INSERT INTO users (username, password, isAdmin) VALUES (?, ?, 1)",
        [ADMIN_USERNAME, hashed]
      );
      console.log("Admin account created");
    }
  });

});

function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  if (!authHeader) return res.status(401).json({ error: "Token required" });

  const token = authHeader.split(" ")[1];

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

function requireAdmin(req, res, next) {
  if (!req.user.isAdmin)
    return res.status(403).json({ error: "Admin only" });
  next();
}

app.get("/", (req, res) => {
  res.send("Backend running securely ✅");
});

app.post("/register", async (req, res) => {

  const { username, password } = req.body;

  if (!username || !password)
    return res.status(400).json({ error: "Missing fields" });

  const hashed = await bcrypt.hash(password, 10);

  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashed],
    function(err) {
      if (err) return res.status(400).json({ error: "Username exists" });
      res.json({ message: "User created" });
    }
  );

});

app.post("/login", (req, res) => {

  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], async (err, user) => {

    if (!user) return res.status(400).json({ error: "Invalid login" });

    const valid = await bcrypt.compare(password, user.password);
    if (!valid) return res.status(400).json({ error: "Invalid login" });

    const token = jwt.sign({
      id: user.id,
      username: user.username,
      isAdmin: user.isAdmin
    },
    JWT_SECRET,
    { expiresIn: "7d" });

    res.json({ token });

  });

});

app.post("/missions", authenticateToken, requireAdmin, (req, res) => {

  const { target, reason, amount } = req.body;

  if (!target || !reason || !amount)
    return res.status(400).json({ error: "Missing fields" });

  db.run(
    "INSERT INTO missions (target, reason, amount, createdBy) VALUES (?, ?, ?, ?)",
    [target, reason, amount, req.user.id],
    function(err) {
      if (err) return res.status(500).json({ error: "Error creating mission" });
      res.json({ message: "Mission created" });
    }
  );

});

app.get("/missions", (req, res) => {

  db.all(`
    SELECT * FROM missions
    WHERE createdAt >= datetime('now','-20 days')
  `, (err, rows) => {
    res.json(rows);
  });

});

app.post("/claims", authenticateToken, (req, res) => {

  const { missionId, clip, paypal } = req.body;

  if (!missionId || !clip || !paypal)
    return res.status(400).json({ error: "Missing fields" });

  db.run(
    "INSERT INTO claims (missionId, userId, clip, paypal) VALUES (?, ?, ?, ?)",
    [missionId, req.user.id, clip, paypal],
    function(err) {
      if (err) return res.status(500).json({ error: "Claim failed" });
      res.json({ message: "Claim submitted" });
    }
  );

});

app.post("/claims/:id/approve", authenticateToken, requireAdmin, (req, res) => {

  const claimId = req.params.id;

  db.get("SELECT * FROM claims WHERE id = ?", [claimId], (err, claim) => {

    if (!claim) return res.status(404).json({ error: "Not found" });

    db.run("UPDATE claims SET status='approved' WHERE id=?", [claimId]);

    db.get("SELECT * FROM users WHERE id=?", [claim.userId], (err, user) => {

      let newCount = user.claimsCount + 1;
      let newRank = "Bronze";

      if (newCount === 1) newRank = "Bronze";
      else if (newCount === 2) newRank = "Silver";
      else if (newCount === 3) newRank = "Gold";
      else if (newCount === 4) newRank = "Platinum";
      else if (newCount >= 5) newRank = "Legend";

      db.run(
        "UPDATE users SET claimsCount=?, rank=? WHERE id=?",
        [newCount, newRank, user.id]
      );

      res.json({ message: "Claim approved & rank updated" });

    });

  });

});

app.get("/leaderboard", (req, res) => {

  db.all(
    "SELECT username, claimsCount, rank FROM users ORDER BY claimsCount DESC",
    (err, rows) => {
      res.json(rows);
    }
  );

});

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});