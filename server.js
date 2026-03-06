const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const cloudinary = require("cloudinary").v2;
const streamifier = require("streamifier");

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database("./database.db");

const JWT_SECRET = process.env.JWT_SECRET;
const PAYPAL_CLIENT_ID = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_CLIENT_SECRET = process.env.PAYPAL_CLIENT_SECRET;

/* ---------------- CLOUDINARY CONFIG ---------------- */

cloudinary.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET
});

/* ---------------- FILE UPLOAD SETUP ---------------- */

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {

    if (
      file.mimetype.startsWith("image/") ||
      file.mimetype.startsWith("video/")
    ) {
      cb(null, true);
    } else {
      cb(new Error("Only images or videos allowed"));
    }

  }
});

/* ---------------- DATABASE SETUP ---------------- */

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

/* ---------------- AUTH ---------------- */

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
            return res.status(500).json({
              error: "Registration failed."
            });
          }

          res.json({
            message: "Registered successfully"
          });

        }
      );

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

/* ---------------- PAYPAL AUTH ---------------- */

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
    console.error("PayPal token error:", data);
    throw new Error("Failed to get PayPal token");
  }

  return data.access_token;

}

/* ---------------- CREATE ORDER ---------------- */

app.post("/create-order", async (req, res) => {

  const { target, reason, amount } = req.body;

  try {

    const bountyAmount = Number(amount);

    if (!bountyAmount || bountyAmount <= 0) {
      return res.status(400).json({
        error: "Bounty must be greater than 0"
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
          ],
          application_context: {
            shipping_preference: "NO_SHIPPING"
          }
        })
      }
    );

    const order = await response.json();

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

    console.error(err);

    res.status(500).json({
      error: "PayPal order failed"
    });

  }

});

/* ---------------- CAPTURE PAYMENT ---------------- */

app.post("/capture-order", async (req, res) => {

  const { orderId } = req.body;

  try {

    const accessToken = await getPayPalAccessToken();

    const response = await fetch(
      `https://api-m.paypal.com/v2/checkout/orders/${orderId}/capture`,
      {
        method: "POST",
        headers: {
          Authorization: `Bearer ${accessToken}`,
          "Content-Type": "application/json"
        }
      }
    );

    const data = await response.json();

    if (data.status === "COMPLETED") {

      db.run(
        `UPDATE missions 
         SET status = 'active'
         WHERE paypal_order_id = ?`,
        [orderId]
      );

    }

    res.json(data);

  } catch (err) {

    console.error(err);

    res.status(500).json({
      error: "Capture failed"
    });

  }

});

/* ---------------- GET MISSIONS ---------------- */

app.get("/missions", (req, res) => {

  db.all(
    `SELECT * FROM missions WHERE status='active'`,
    [],
    (err, rows) => {

      if (err) {
        return res.status(500).json({
          error: "Failed to fetch missions"
        });
      }

      res.json(rows);

    }
  );

});

/* ---------------- CLAIM WITH VIDEO/IMAGE ---------------- */

app.post("/claims", upload.single("proof"), async (req, res) => {

  const { missionId, paypal } = req.body;

  if (!req.file) {
    return res.status(400).json({
      error: "Proof image or video required"
    });
  }

  try {

    const streamUpload = () => {

      return new Promise((resolve, reject) => {

        const stream = cloudinary.uploader.upload_stream(
          { resource_type: "auto", folder: "mission_proofs" },
          (error, result) => {

            if (result) resolve(result);
            else reject(error);

          }
        );

        streamifier.createReadStream(req.file.buffer).pipe(stream);

      });

    };

    const uploaded = await streamUpload();

    const clipUrl = uploaded.secure_url;

    db.run(
      `INSERT INTO claims (mission_id, clip, paypal_email)
       VALUES (?, ?, ?)`,
      [missionId, clipUrl, paypal],
      function (err) {

        if (err) {
          return res.status(500).json({
            error: "Claim failed"
          });
        }

        res.json({
          message:
            "Claim submitted. Approved claimants receive 80% of bounty reward. Platform retains 20% service fee.",
          proof: clipUrl
        });

      }
    );

  } catch (error) {

    console.error("Upload failed:", error);

    res.status(500).json({
      error: "Upload failed"
    });

  }

});

/* ---------------- START SERVER ---------------- */

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log("LIVE backend running 🚀");
});