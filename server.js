const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const path = require("path");
const fetch = require("node-fetch");

const app = express();

app.use(express.json());
app.use(cors());
app.use("/uploads", express.static("uploads"));

const upload = multer({ dest: "uploads/" });

const db = new sqlite3.Database("./database.db");

const JWT_SECRET = process.env.JWT_SECRET || "secret";

const PAYPAL_CLIENT = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process.env.PAYPAL_SECRET;

/* ---------------- DATABASE ---------------- */

db.serialize(() => {

db.run(`
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
password TEXT,
agreed_terms INTEGER,
is_adult INTEGER,
agreed_at DATETIME
)`);

db.run(`
CREATE TABLE IF NOT EXISTS missions(
id INTEGER PRIMARY KEY AUTOINCREMENT,
target TEXT,
reason TEXT,
bounty_amount REAL,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
expires_at DATETIME,
status TEXT DEFAULT 'active'
)`);

db.run(`
CREATE TABLE IF NOT EXISTS claims(
id INTEGER PRIMARY KEY AUTOINCREMENT,
mission_id INTEGER,
hunter TEXT,
clip TEXT,
paypal_email TEXT,
status TEXT DEFAULT 'pending'
)`);

db.run(`
CREATE TABLE IF NOT EXISTS bounty_contributions(
id INTEGER PRIMARY KEY AUTOINCREMENT,
mission_id INTEGER,
contributor TEXT,
amount REAL
)`);

});

/* ---------------- REGISTER ---------------- */

app.post("/register", async (req,res)=>{

const {username,password,agreedTerms,isAdult}=req.body;

if(!username || !password){
return res.status(400).json({error:"Missing fields"});
}

if(!agreedTerms || !isAdult){
return res.status(400).json({error:"Must accept terms and confirm 18+"});
}

const hash = await bcrypt.hash(password,10);

db.run(
`INSERT INTO users(username,password,agreed_terms,is_adult,agreed_at)
VALUES(?,?,?,?,datetime('now'))`,
[username,hash,1,1],
function(err){

if(err) return res.json({error:"Username already exists"});

res.json({message:"Account created"});

});

});

/* ---------------- LOGIN ---------------- */

app.post("/login",(req,res)=>{

const {username,password}=req.body;

db.get(
`SELECT * FROM users WHERE username=?`,
[username],
async(err,user)=>{

if(!user) return res.json({error:"Invalid login"});

const match = await bcrypt.compare(password,user.password);

if(!match) return res.json({error:"Invalid login"});

const token = jwt.sign(
{id:user.id,username:user.username},
JWT_SECRET
);

res.json({token});

});

});

/* ---------------- PAYPAL TOKEN ---------------- */

async function getPayPalToken(){

const auth = Buffer.from(
PAYPAL_CLIENT + ":" + PAYPAL_SECRET
).toString("base64");

const res = await fetch(
"https://api-m.paypal.com/v1/oauth2/token",
{
method:"POST",
headers:{
Authorization:`Basic ${auth}`,
"Content-Type":"application/x-www-form-urlencoded"
},
body:"grant_type=client_credentials"
}
);

const data = await res.json();

return data.access_token;

}

/* ---------------- CREATE ORDER ---------------- */

app.post("/create-order", async(req,res)=>{

const {target,reason,amount} = req.body;

if(!target || !reason || !amount){
return res.json({error:"Missing mission data"});
}

if(Number(amount) < 7){
return res.json({error:"Minimum bounty is $7"});
}

const total = Number(amount) + 2;

const token = await getPayPalToken();

const response = await fetch(
"https://api-m.paypal.com/v2/checkout/orders",
{
method:"POST",
headers:{
"Content-Type":"application/json",
Authorization:`Bearer ${token}`
},
body:JSON.stringify({
intent:"CAPTURE",
purchase_units:[{
amount:{
currency_code:"USD",
value:total.toFixed(2)
}
}]
})
}
);

const order = await response.json();

res.json(order);

});

/* ---------------- CAPTURE ORDER ---------------- */

app.post("/capture-order", async(req,res)=>{

const {orderId,target,reason,amount}=req.body;

if(!orderId) return res.json({error:"Missing order ID"});

const token = await getPayPalToken();

const capture = await fetch(
`https://api-m.paypal.com/v2/checkout/orders/${orderId}/capture`,
{
method:"POST",
headers:{
"Content-Type":"application/json",
Authorization:`Bearer ${token}`
}
}
);

const data = await capture.json();

if(data.status !== "COMPLETED"){
return res.json({error:"Payment not completed"});
}

const expires = new Date();
expires.setDate(expires.getDate()+20);

db.run(
`INSERT INTO missions(target,reason,bounty_amount,expires_at)
VALUES(?,?,?,?)`,
[target,reason,amount,expires.toISOString()]
);

res.json({message:"Mission created"});

});

/* ---------------- GET MISSIONS ---------------- */

app.get("/missions",(req,res)=>{

db.all(`SELECT * FROM missions WHERE status='active'`,[],(err,rows)=>{

const now = new Date();

const missions = rows.map(m=>{

const expire = new Date(m.expires_at);

const days = Math.ceil(
(expire-now)/(1000*60*60*24)
);

return{
...m,
days_remaining:days
};

});

res.json(missions);

});

});

/* ---------------- ADD BOUNTY ---------------- */

app.post("/add-bounty",(req,res)=>{

const {missionId,amount,username}=req.body;

if(!missionId || !amount){
return res.json({error:"Invalid request"});
}

db.run(
`UPDATE missions
SET bounty_amount=bounty_amount+?
WHERE id=?`,
[amount,missionId]
);

db.run(
`INSERT INTO bounty_contributions(mission_id,contributor,amount)
VALUES(?,?,?)`,
[missionId,username || "anonymous",amount]
);

res.json({message:"Bounty increased"});

});

/* ---------------- CLAIM ---------------- */

app.post("/claims", upload.single("file"), (req,res)=>{

const missionId=req.body.missionId;
const paypal=req.body.paypal;
const hunter=req.body.hunter || "anonymous";

if(!missionId || !paypal){
return res.json({error:"Missing claim info"});
}

const clip = req.file ? req.file.filename : null;

db.run(
`INSERT INTO claims(mission_id,clip,paypal_email,hunter)
VALUES(?,?,?,?)`,
[missionId,clip,paypal,hunter],
function(err){

if(err) return res.json({error:"Claim failed"});

res.json({message:"Claim submitted"});

});

});

/* ---------------- LIVE PLAYER COUNT ---------------- */

app.get("/live-count",(req,res)=>{

db.get(`
SELECT COUNT(DISTINCT hunter) as players
FROM claims
`,[],(err,row)=>{

res.json({players:row.players || 0});

});

});

/* ---------------- HUNTER LEADERBOARD ---------------- */

app.get("/leaderboard/hunters",(req,res)=>{

db.all(`
SELECT hunter, COUNT(*) as wins
FROM claims
WHERE status='approved'
GROUP BY hunter
ORDER BY wins DESC
LIMIT 5
`,[],(err,rows)=>{

res.json(rows);

});

});

/* ---------------- MOST WANTED ---------------- */

app.get("/leaderboard/wanted",(req,res)=>{

db.all(`
SELECT target, COUNT(*) as hunts
FROM missions
GROUP BY target
ORDER BY hunts DESC
LIMIT 3
`,[],(err,rows)=>{

res.json(rows);

});

});

/* ---------------- SERVER ---------------- */
// Root route to show server is running
app.get("/", (req, res) => {
  res.send("Backend is running 🚀");
});
const PORT = process.env.PORT || 3000;

app.listen(PORT,()=>{

console.log("Server running on port "+PORT);

});