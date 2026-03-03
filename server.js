require("dotenv").config();
const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const helmet = require("helmet");
const fetch = require("node-fetch");

const app = express();
app.use(helmet());
app.use(cors({ origin: "*" }));
app.use(express.json());

const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET;

const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;
const PAYPAL_BASE = "https://api-m.sandbox.paypal.com";

if (!JWT_SECRET || !PAYPAL_CLIENT_ID || !PAYPAL_CLIENT_SECRET) {
  console.error("Missing required environment variables.");
  process.exit(1);
}

const db = new sqlite3.Database("./database.db");

/* ---------------- DATABASE ---------------- */

db.serialize(() => {
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
      reward REAL,
      postingFee REAL,
      totalPaid REAL,
      status TEXT DEFAULT 'Active',
      transactionId TEXT,
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
});

/* ---------------- AUTH ---------------- */

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

/* ---------------- PAYPAL TOKEN ---------------- */

async function getPayPalAccessToken() {
  const auth = Buffer.from(
    PAYPAL_CLIENT_ID + ":" + PAYPAL_CLIENT_SECRET
  ).toString("base64");

  const response = await fetch(`${PAYPAL_BASE}/v1/oauth2/token`, {
    method: "POST",
    headers: {
      Authorization: `Basic ${auth}`,
      "Content-Type": "application/x-www-form-urlencoded",
    },
    body: "grant_type=client_credentials",
  });

  const data = await response.json();
  return data.access_token;
}

/* ---------------- CREATE ORDER ---------------- */

app.post("/create-order", authenticateToken, async (req, res) => {
  const { reward, target, reason, termsAccepted } = req.body;

  if (!termsAccepted)
    return res.status(400).json({ error: "You must accept terms." });

  if (!reward || reward < 7)
    return res.status(400).json({ error: "Minimum mission reward is $7." });

  const postingFee = 2;
  const total = (parseFloat(reward) + postingFee).toFixed(2);

  const accessToken = await getPayPalAccessToken();

  const order = await fetch(`${PAYPAL_BASE}/v2/checkout/orders`, {
    method: "POST",
    headers: {
      Authorization: `Bearer ${accessToken}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      intent: "CAPTURE",
      purchase_units: [
        {
          amount: {
            currency_code: "USD",
            value: total,
          },
        },
      ],
    }),
  });

  const orderData = await order.json();
  res.json({ orderID: orderData.id });
});

/* ---------------- CAPTURE ORDER ---------------- */

app.post("/capture-order", authenticateToken, async (req, res) => {
  const { orderID, reward, target, reason } = req.body;

  const postingFee = 2;
  const totalExpected = (parseFloat(reward) + postingFee).toFixed(2);

  const accessToken = await getPayPalAccessToken();

  const capture = await fetch(
    `${PAYPAL_BASE}/v2/checkout/orders/${orderID}/capture`,
    {
      method: "POST",
      headers: {
        Authorization: `Bearer ${accessToken}`,
        "Content-Type": "application/json",
      },
    }
  );

  const captureData = await capture.json();

  if (
    captureData.status !== "COMPLETED" ||
    captureData.purchase_units[0].payments.captures[0].amount.value !== totalExpected
  ) {
    return res.status(400).json({ error: "Payment verification failed." });
  }

  const transactionId =
    captureData.purchase_units[0].payments.captures[0].id;

  db.run(
    `INSERT INTO missions 
    (target, reason, reward, postingFee, totalPaid, transactionId, createdBy) 
    VALUES (?, ?, ?, ?, ?, ?, ?)`,
    [
      target,
      reason,
      reward,
      postingFee,
      totalExpected,
      transactionId,
      req.user.id,
    ]
  );

  res.json({ message: "Mission created successfully." });
});

/* ---------------- MISSIONS ---------------- */

app.get("/missions", (req, res) => {
  db.all("SELECT * FROM missions", (err, rows) => {
    const now = new Date();

    rows.forEach((mission) => {
      const created = new Date(mission.createdAt);
      const diffDays = (now - created) / (1000 * 60 * 60 * 24);

      if (diffDays >= 20 && mission.status === "Active") {
        db.run(
          "UPDATE missions SET status='Expired' WHERE id=?",
          [mission.id]
        );
        mission.status = "Expired";
      }
    });

    res.json(rows);
  });
});

/* ---------------- CLAIM ---------------- */

app.post("/claims", authenticateToken, (req, res) => {
  const { missionId, clip, paypal, termsAccepted } = req.body;

  if (!termsAccepted)
    return res.status(400).json({ error: "You must accept terms." });

  db.run(
    "INSERT INTO claims (missionId, userId, clip, paypal) VALUES (?, ?, ?, ?)",
    [missionId, req.user.id, clip, paypal]
  );

  res.json({ message: "Claim submitted for review." });
});

/* ---------------- APPROVE CLAIM ---------------- */

app.post("/claims/:id/approve", authenticateToken, (req, res) => {
  const claimId = req.params.id;

  db.get("SELECT * FROM claims WHERE id=?", [claimId], (err, claim) => {
    if (!claim) return res.status(404).json({ error: "Not found" });

    db.get("SELECT * FROM missions WHERE id=?", [claim.missionId], (err, mission) => {

      const payout = (mission.reward * 0.8).toFixed(2);

      db.run("UPDATE claims SET status='approved' WHERE id=?", [claimId]);
      db.run("UPDATE missions SET status='Completed' WHERE id=?", [mission.id]);

      db.get("SELECT * FROM users WHERE id=?", [claim.userId], (err, user) => {
        let newCount = user.claimsCount + 1;
        let rank = "Bronze";
        if (newCount === 2) rank = "Silver";
        if (newCount === 3) rank = "Gold";
        if (newCount === 4) rank = "Platinum";
        if (newCount >= 5) rank = "Legend";

        db.run(
          "UPDATE users SET claimsCount=?, rank=? WHERE id=?",
          [newCount, rank, user.id]
        );

        res.json({
          message: "Claim approved.",
          payoutDue: payout,
        });
      });
    });
  });
});

/* ---------------- START ---------------- */

app.listen(PORT, () => {
  console.log("Server running on port " + PORT);
});