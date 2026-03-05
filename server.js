const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const cloudinary = require("cloudinary").v2;
const multer = require("multer");

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database("./database.db");

const JWT_SECRET = process.env.JWT_SECRET;
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

/* ------------------ CLOUDINARY CONFIG ------------------ */

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 }, // 50MB
  fileFilter: (req, file, cb) => {
    if (
      file.mimetype.startsWith("image/") ||
      file.mimetype.startsWith("video/")
    ) {
      cb(null, true);
    } else {
      cb(new Error("Only images and videos are allowed."));
    }
  }
});

/* ------------------ DATABASE SETUP ------------------ */

db.serialize(() => {

  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE,
      password TEXT,
      agreed_terms INTEGER DEFAULT 0,
      is_adult INTEGER DEFAULT 0,
      agreed_at DATETIME
    )
  `);

  db.run(`
    CREATE TABLE IF NOT EXISTS missions (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      target TEXT,
      reason TEXT,
      bounty_amount REAL,
      listing_fee REAL,
      total_charged REAL,
      paypal_order_id TEXT,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
      expires_at DATETIME,
      status TEXT DEFAULT 'pending_payment'
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
  const { username, password, agreedTerms, isAdult } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: "Username and password required." });
  }

  if (!agreedTerms || !isAdult) {
    return res.status(400).json({
      error: "You must agree to Terms and confirm you are 18+."
    });
  }

  try {
    db.get(
      `SELECT id FROM users WHERE username = ?`,
      [username],
      async (err, existingUser) => {

        if (existingUser) {
          return res.status(400).json({
            error: "Username already taken."
          });
        }

        const hashed = await bcrypt.hash(password, 10);

        db.run(
          `INSERT INTO users 
           (username, password, agreed_terms, is_adult, agreed_at)
           VALUES (?, ?, ?, ?, ?)`,
          [
            username,
            hashed,
            1,
            1,
            new Date().toISOString()
          ],
          function (err) {
            if (err) {
              return res.status(500).json({ error: "Registration failed." });
            }
            res.json({ message: "Registered successfully" });
          }
        );
      }
    );
  } catch (err) {
    res.status(500).json({ error: "Registration failed." });
  }
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
    "https://api-m.paypal.com/v1/oauth2/token",
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

  if (!data.access_token) {
    throw new Error("Failed to get PayPal access token");
  }

  return data.access_token;
}

/* ------------------ CREATE ORDER ------------------ */

app.post("/create-order", async (req, res) => {
  const { target, reason, amount } = req.body;

  try {
    const bountyAmount = Number(amount);

    if (!bountyAmount || bountyAmount <= 0) {
      return res.status(400).json({
        error: "Bounty amount must be greater than 0."
      });
    }

    const listingFee = 2;
    const totalAmount = (bountyAmount + listingFee).toFixed(2);

    const accessToken = await getPayPalAccessToken();

    const response = await fetch(
      "https://api-m.paypal.com/v2/checkout/orders",
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
                value: totalAmount
              }
            }
          ]
        })
      }
    );

    const order = await response.json();

    if (!order.id) {
      return res.status(500).json({ error: "PayPal order failed" });
    }

    const expiresAt = new Date();
    expiresAt.setDate(expiresAt.getDate() + 20);

    db.run(
      `INSERT INTO missions 
      (target, reason, bounty_amount, listing_fee, total_charged, paypal_order_id, expires_at)
      VALUES (?, ?, ?, ?, ?, ?, ?)`,
      [
        target,
        reason,
        bountyAmount,
        listingFee,
        totalAmount,
        order.id,
        expiresAt.toISOString()
      ]
    );

    res.json(order);

  } catch (err) {
    res.status(500).json({ error: "PayPal order failed" });
  }
});

/* ------------------ CAPTURE ORDER ------------------ */

app.post("/capture-order", async (req, res) => {
  const { orderId } = req.body;

  try {
    const accessToken = await getPayPalAccessToken();

    const response = await fetch(
      `https://api-m.paypal.com/v2/checkout/orders/${orderId}/capture`,
      {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Authorization: `Bearer ${accessToken}`
        }
      }
    );

    const data = await response.json();

    if (data.status === "COMPLETED") {
      db.run(
        `UPDATE missions SET status = 'active' WHERE paypal_order_id = ?`,
        [orderId]
      );
    }

    res.json(data);

  } catch (err) {
    res.status(500).json({ error: "Capture failed" });
  }
});

/* ------------------ GET MISSIONS ------------------ */

app.get("/missions", (req, res) => {
  db.all(
    `SELECT * FROM missions WHERE status = 'active'`,
    [],
    (err, rows) => {
      if (err) return res.status(500).json({ error: "Fetch failed" });
      res.json(rows);
    }
  );
});

/* ------------------ CLAIMS (CLOUDINARY) ------------------ */

app.post("/claims", upload.single("file"), async (req, res) => {
  try {
    const { missionId, paypal } = req.body;

    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded." });
    }

    const result = await new Promise((resolve, reject) => {
      cloudinary.uploader.upload_stream(
        {
          resource_type: "auto",
          folder: "mission_proofs",
          quality: "auto",
          fetch_format: "auto"
        },
        (error, result) => {
          if (error) reject(error);
          else resolve(result);
        }
      ).end(req.file.buffer);
    });

    db.run(
      `INSERT INTO claims (mission_id, clip, paypal_email)
       VALUES (?, ?, ?)`,
      [missionId, result.secure_url, paypal],
      function (err) {
        if (err) {
          return res.status(500).json({ error: "Claim failed" });
        }

        res.json({
          message: "Proof uploaded successfully.",
          mediaUrl: result.secure_url
        });
      }
    );

  } catch (err) {
    res.status(500).json({ error: err.message || "Upload failed." });
  }
});

/* ------------------ START SERVER ------------------ */

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => {
  console.log("LIVE backend running 🚀");
});