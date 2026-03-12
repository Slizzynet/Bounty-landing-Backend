const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");
const multer = require("multer");
const fetch = require("node-fetch");
const rateLimit = require("express-rate-limit");
const app = express();

app.use(express.json());
app.use(cors());

const limiter = rateLimit({
windowMs: 15 * 60 * 1000,
max: 100,
message: {error:"Too many requests, please slow down"}
});

app.use(limiter);
app.use("/uploads", express.static("uploads"));

/* FILE UPLOAD SECURITY */
const upload = multer({
dest:"uploads/",
limits:{fileSize:50 * 1024 * 1024},
fileFilter:(req,file,cb)=>{

const allowed = [
"video/mp4",
"video/quicktime",
"image/png",
"image/jpeg",
"image/gif",
"video/webm"
]

if(!allowed.includes(file.mimetype)){
return cb(new Error("Invalid file type"))
}

cb(null,true)

}
});

const db = new sqlite3.Database("./database.db");

const JWT_SECRET = process.env.JWT_SECRET || "secret";

/* PAYPAL */
const PAYPAL_CLIENT = process.env.PAYPAL_CLIENT_ID;
const PAYPAL_SECRET = process.env.PAYPAL_SECRET;

let activeUsers = {};

/* AUTHENTICATION MIDDLEWARE */
function authenticateToken(req, res, next) {
  const authHeader = req.headers["authorization"];
  const token = authHeader && authHeader.split(" ")[1];

  if (!token) {
    return res.status(401).json({ error: "No token provided" });
  }

  jwt.verify(token, JWT_SECRET, (err, user) => {
    if (err) return res.status(403).json({ error: "Invalid token" });
    req.user = user;
    next();
  });
}

/* ---------------- DATABASE ---------------- */

db.serialize(()=>{

db.run(`
CREATE TABLE IF NOT EXISTS users(
id INTEGER PRIMARY KEY AUTOINCREMENT,
username TEXT UNIQUE,
email TEXT UNIQUE,
password TEXT,
agreed_terms INTEGER,
is_adult INTEGER,
agreed_at DATETIME
)`);

db.run(`
CREATE TABLE IF NOT EXISTS missions(
id INTEGER PRIMARY KEY AUTOINCREMENT,
target TEXT,
mode TEXT,
bounty_amount REAL,
posted_by TEXT,
created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
expires_at DATETIME,
status TEXT DEFAULT 'active'
)`);

db.run(`
CREATE TABLE IF NOT EXISTS claims(
id INTEGER PRIMARY KEY AUTOINCREMENT,
mission_id INTEGER,
clip TEXT,
hunter TEXT,
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

const {username,email,password,agreedTerms,isAdult}=req.body;

if(!username || !email || !password){
return res.status(400).json({error:"Missing fields"});
}

if(!agreedTerms || !isAdult){
return res.status(400).json({error:"Must accept terms and confirm 18+"});
}

try{
const hash = await bcrypt.hash(password,10);

db.run(
`INSERT INTO users(username,email,password,agreed_terms,is_adult,agreed_at)
VALUES(?,?,?,?,?,datetime('now'))`,
[username,email,hash,1,1],
function(err){

if(err) return res.json({error:"Username or email already exists"});

res.json({message:"Account created"});

});
}catch(e){
console.error("Register error:",e);
res.status(500).json({error:"Registration failed"});
}

});

/* ---------------- LOGIN ---------------- */

app.post("/login",(req,res)=>{

const {email,password}=req.body;

if(!email || !password){
return res.json({error:"Email and password required"});
}

db.get(
`SELECT * FROM users WHERE email=?`,
[email],
async(err,user)=>{

if(err){
console.error("Login query error:",err);
return res.status(500).json({error:"Database error"});
}

if(!user) return res.json({error:"Invalid login"});

try{
const match = await bcrypt.compare(password,user.password);

if(!match) return res.json({error:"Invalid login"});

const token = jwt.sign(
{id:user.id,username:user.username},
JWT_SECRET,
{expiresIn:"7d"}
);

res.json({
token,
username:user.username
});
}catch(e){
console.error("Password comparison error:",e);
res.status(500).json({error:"Login failed"});
}

});

});

/* ---------------- FORGOT PASSWORD ---------------- */

app.post("/forgot-password",(req,res)=>{

const {email} = req.body;

if(!email){
return res.json({error:"Email required"});
}

console.log("Password reset requested for:",email);

res.json({
message:"If the account exists a reset email was sent"
});

});

/* ---------------- USER COUNT ---------------- */

app.get("/user-count",(req,res)=>{

db.get(`SELECT COUNT(*) as total FROM users`,[],(err,row)=>{
if(err){
console.error("User count error:",err);
return res.status(500).json({error:"Database error"});
}
res.json({total:row.total || 0});
});

});

/* ---------------- HEARTBEAT ---------------- */

app.post("/heartbeat",(req,res)=>{

const {username} = req.body;

if(username){
activeUsers[username] = Date.now();
}

res.json({ok:true});

});

/* ---------------- ACTIVE PLAYERS COUNT ---------------- */

app.get("/active-players", authenticateToken, (req,res)=>{

const now = Date.now();

let count = 0;

for(let user in activeUsers){
if(now - activeUsers[user] < 60000){
count++;
}
}

res.json({count});

});

/* CLEAN INACTIVE USERS */
setInterval(()=>{

const now = Date.now()

for(let user in activeUsers){

if(now - activeUsers[user] > 60000){
delete activeUsers[user]
}

}

},30000)

/* ---------------- PAYPAL TOKEN ---------------- */

async function getPayPalToken(){

try{
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
}catch(e){
console.error("PayPal token error:",e);
throw e;
}

}

/* ---------------- CREATE ORDER ---------------- */

app.post("/create-order", authenticateToken, async(req,res)=>{

try{
const {target,mode,amount} = req.body;

if(!target || !mode || !amount){
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
}catch(e){
console.error("Create order error:",e);
res.status(500).json({error:"Failed to create order"});
}

});

/* ---------------- CAPTURE ORDER ---------------- */

app.post("/capture-order", authenticateToken, async(req,res)=>{

try{
const {orderId,target,mode,amount}=req.body;

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

if(!data || data.status !== "COMPLETED"){
return res.json({error:"Payment not completed"});
}

const expires = new Date();
expires.setDate(expires.getDate()+20);

db.run(
`INSERT INTO missions(target,mode,bounty_amount,posted_by,expires_at)
VALUES(?,?,?,?,?)`,
[target,mode,amount,req.user.username,expires.toISOString()],
function(err){
if(err){
console.error("Mission insert error:",err);
return res.status(500).json({error:"Failed to create mission"});
}
res.json({message:"Mission created",id:this.lastID});
}
);
}catch(e){
console.error("Capture order error:",e);
res.status(500).json({error:"Payment processing failed"});
}

});

/* ---------------- GET MISSIONS ---------------- */

app.get("/missions", authenticateToken, (req,res)=>{

db.all(`SELECT * FROM missions WHERE status='active'`,[],(err,rows)=>{

if(err){
console.error("Missions query error:",err);
return res.status(500).json({error:"Database error"});
}

const now = new Date();

const missions = (rows || []).map(m=>{

const expire = new Date(m.expires_at);

const days = Math.max(
Math.ceil((expire-now)/(1000*60*60*24)),
0
);

return{
id:m.id,
target:m.target,
mode:m.mode,
bounty:m.bounty_amount,
postedBy:m.posted_by,
expiresAt:m.expires_at,
daysRemaining:days
};

});

res.json(missions);

});

});

/* ---------------- POST MISSION ---------------- */

app.post("/missions", authenticateToken, (req,res)=>{

try{
const {target,mode,bounty} = req.body;

if(!target || !mode || !bounty){
return res.status(400).json({error:"Missing mission data"});
}

const amount = parseFloat(bounty);
if(amount < 7){
return res.status(400).json({error:"Minimum bounty is $7"});
}

const expires = new Date();
expires.setDate(expires.getDate()+20);

db.run(
`INSERT INTO missions(target,mode,bounty_amount,posted_by,expires_at)
VALUES(?,?,?,?,?)`,
[target,mode,amount,req.user.username,expires.toISOString()],
function(err){
if(err){
console.error("Mission insert error:",err);
return res.status(500).json({error:"Failed to create mission"});
}
res.json({message:"Mission posted",id:this.lastID});
}
);
}catch(e){
console.error("Post mission error:",e);
res.status(500).json({error:"Failed to post mission"});
}

});

/* ---------------- SUBMIT PROOF / CLAIM MISSION ---------------- */

app.post("/missions/:missionId/claim", authenticateToken, upload.single("proof"), (req,res)=>{

try{
const {missionId} = req.params;
const proof = req.file ? req.file.filename : null;

if(!missionId || !proof){
return res.status(400).json({error:"Missing claim info"});
}

db.run(
`INSERT INTO claims(mission_id,clip,hunter)
VALUES(?,?,?)`,
[missionId,proof,req.user.username],
function(err){
if(err){
console.error("Claim insert error:",err);
return res.status(500).json({error:"Claim failed"});
}
res.json({message:"Claim submitted"});
}
);
}catch(e){
console.error("Claim submission error:",e);
res.status(500).json({error:"Failed to submit claim"});
}

});

/* ---------------- ADD BOUNTY TO MISSION ---------------- */

app.post("/missions/:missionId/add-bounty", authenticateToken, (req,res)=>{

try{
const {missionId} = req.params;
const {amount} = req.body;

if(!missionId || !amount){
return res.status(400).json({error:"Missing bounty data"});
}

const addAmount = parseFloat(amount);
if(addAmount < 1){
return res.status(400).json({error:"Minimum bounty is $1"});
}

db.run(
`UPDATE missions SET bounty_amount = bounty_amount + ? WHERE id = ?`,
[addAmount,missionId],
function(err){
if(err){
console.error("Update bounty error:",err);
return res.status(500).json({error:"Failed to add bounty"});
}
res.json({message:"Bounty increased"});
}
);
}catch(e){
console.error("Add bounty error:",e);
res.status(500).json({error:"Failed to add bounty"});
}

});

/* ---------------- AUTO EXPIRE MISSIONS ---------------- */

setInterval(()=>{

db.run(`
UPDATE missions
SET status='expired'
WHERE expires_at < datetime('now')
AND status='active'
`,(err)=>{
if(err) console.error("Auto expire error:",err);
});

},60000);

/* ---------------- LEADERBOARDS (COMBINED) ---------------- */

app.get("/leaderboards", authenticateToken, (req,res)=>{

try{
db.all(
`SELECT hunter, COUNT(*) as score FROM claims 
WHERE status='approved' GROUP BY hunter ORDER BY score DESC LIMIT 5`,
[],
(err,hunters)=>{
if(err){
console.error("Top hunters query error:",err);
return res.status(500).json({error:"Database error"});
}

db.all(
`SELECT target, COUNT(*) as bounty FROM missions 
GROUP BY target ORDER BY bounty DESC LIMIT 5`,
[],
(err2,wanted)=>{
if(err2){
console.error("Most wanted query error:",err2);
return res.status(500).json({error:"Database error"});
}

res.json({
topHunters:hunters||[],
mostWanted:wanted||[]
});
}
);
}
);
}catch(e){
console.error("Leaderboards error:",e);
res.status(500).json({error:"Failed to load leaderboards"});
}

});

/* LEGACY ENDPOINTS (for backwards compatibility) */

app.get("/leaderboard/hunters",(req,res)=>{

db.all(`
SELECT hunter, COUNT(*) as wins
FROM claims
WHERE status='approved'
GROUP BY hunter
ORDER BY wins DESC
LIMIT 5
`,[],(err,rows)=>{
if(err){
console.error("Hunters query error:",err);
return res.status(500).json({error:"Database error"});
}
res.json(rows || []);
});

});

app.get("/leaderboard/wanted",(req,res)=>{

db.all(`
SELECT target, COUNT(*) as hunts
FROM missions
GROUP BY target
ORDER BY hunts DESC
LIMIT 3
`,[],(err,rows)=>{
if(err){
console.error("Wanted query error:",err);
return res.status(500).json({error:"Database error"});
}
res.json(rows || []);
});

});

/* ---------------- ROOT ENDPOINT ---------------- */

app.get("/",(req,res)=>{
res.send("MISSION BOARD Backend is running 🚀");
});

/* ERROR HANDLER */

app.use((err,req,res,next)=>{
console.error("Global error:",err);
res.status(500).json({error:"Internal server error"});
});

const PORT = process.env.PORT || 3000;

app.listen(PORT,()=>{
console.log("Server running on port "+PORT);
});