const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database("./database.db");

const JWT_SECRET = process.env.JWT_SECRET;
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

/* ------------------ DATABASE SETUP ------------------ */

db.serialize(() => {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS missions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT,
      reason TEXT,
      amount REAL,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      status TEXT DEFAULT 'active'
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS claims (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      mission_id INTEGER,
      clip TEXT,
      paypal_email TEXT,
      status TEXT DEFAULT 'pending'
    )
  `);
});

/* ------------------ AUTH ------------------ */

app.post("/register", async (req, res) => {
  const { username, password } = req.body;
  const hashed = await bcrypt.hash(password, 10);

  db.run(
    `INSERT INTO users (username, password) VALUES (?, ?)`,
    [username, hashed],
    function (err) {
      if (err) return res.status(400).json({ error: "Username taken" });
      res.json({ message: "Registered" });
    }
  );
});

app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get(
    `SELECT * FROM users WHERE username = ?`,
    [username],
    async (err, user) => {
      if (!user) return res.status(400).json({ error: "Invalid login" });

      const valid = await bcrypt.compare(password, user.password);
      if (!valid) return res.status(400).json({ error: "Invalid login" });

      const token = jwt.sign({ id: user.id }, JWT_SECRET);
      res.json({ token });
    }
  );
});

/* ------------------ PAYPAL AUTH ------------------ */

async function getPayPalAccessToken() {
  const auth = Buffer.from(
    PAYPAL_CLIENT_ID + ":" + PAYPAL_CLIENT_SECRET
  ).toString("base64");

  const response = await fetch(
    "https://api-m.sandbox.paypal.com/v1/oauth2/token",
    {
      method: "POST",
      headers: {
        Authorization: `Basic ${auth}`,
        "Content-Type": "application/x-www-form-urlencoded"
      },
      body: "grant_type=client_credentials"
    }
  );

  const data = await response.json();

  console.log("PAYPAL TOKEN RESPONSE:", data);

  if (!data.access_token) {
    throw new Error("Failed to get PayPal access token");
  }

  return data.access_token;
}

/* ------------------ CREATE PAYPAL ORDER ------------------ */

app.post("/create-order", async (req, res) => {
  const { amount } = req.body;

  try {
    const accessToken = await getPayPalAccessToken();

    const response = await fetch(
      "https://api-m.sandbox.paypal.com/v2/checkout/orders",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`
        },
        body: JSON.stringify({
          intent: "CAPTURE",
          purchase_units: [
            {
              amount: {
                currency_code: "USD",
                value: amount
              }
            }
          ]
        })
      }
    );

    const order = await response.json();
    res.json(order);
  } catch (err) {
    res.status(500).json({ error: "PayPal order failed" });
  }
});

/* ------------------ MISSIONS ------------------ */

app.post("/missions", (req, res) => {
  const { target, reason, amount } = req.body;

  const expiresAt = new Date();
  expiresAt.setDate(expiresAt.getDate() + 20);

  db.run(
    `INSERT INTO missions (target, reason, amount, expires_at)
     VALUES (?, ?, ?, ?)`,
    [target, reason, amount, expiresAt.toISOString()],
    function (err) {
      if (err) return res.status(500).json({ error: "Creation failed" });

      res.json({ message: "Mission created", id: this.lastID });
    }
  );
});

app.get("/missions", (req, res) => {
  db.all(`SELECT * FROM missions`, [], (err, rows) => {
    const now = new Date();

    const updated = rows.map((m) => {
      if (new Date(m.expires_at) < now && m.status === "active") {
        m.status = "expired";
      }
      return m;
    });

    res.json(updated);
  });
});

/* ------------------ CLAIMS ------------------ */

app.post("/claims", (req, res) => {
  const { missionId, clip, paypal } = req.body;

  db.run(
    `INSERT INTO claims (mission_id, clip, paypal_email)
     VALUES (?, ?, ?)`,
    [missionId, clip, paypal],
    function (err) {
      if (err) return res.status(500).json({ error: "Claim failed" });

      res.json({
        message:
          "Claim submitted. Approved claimants receive 80% of mission reward. Platform retains 20% service fee."
      });
    }
  );
});

/* ------------------ START SERVER ------------------ */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("Production backend running ✅");
});