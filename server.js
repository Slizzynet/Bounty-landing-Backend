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
"image/jpeg"
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

const {username,email,password,agreedTerms,isAdult}=req.body;

if(!username || !email || !password){
return res.status(400).json({error:"Missing fields"});
}

if(!agreedTerms || !isAdult){
return res.status(400).json({error:"Must accept terms and confirm 18+"});
}

const hash = await bcrypt.hash(password,10);

db.run(
`INSERT INTO users(username,email,password,agreed_terms,is_adult,agreed_at)
VALUES(?,?,?,?,?,datetime('now'))`,
[username,email,hash,1,1],
function(err){

if(err) return res.json({error:"Username or email already exists"});

res.json({message:"Account created"});

});

});

/* ---------------- LOGIN ---------------- */

app.post("/login",(req,res)=>{

const {email,password}=req.body;

db.get(
`SELECT * FROM users WHERE email=? OR username=?`,
[email,email],
async(err,user)=>{

if(!user) return res.json({error:"Invalid login"});

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

/* ---------------- LIVE COUNT ---------------- */

app.get("/live-count",(req,res)=>{

const now = Date.now();

let count = 0;

for(let user in activeUsers){
if(now - activeUsers[user] < 60000){
count++;
}
}

res.json({players:count});

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

if(!data || data.status !== "COMPLETED"){
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

/* ---------------- MISSIONS ---------------- */

app.get("/missions",(req,res)=>{

db.all(`SELECT * FROM missions WHERE status='active'`,[],(err,rows)=>{

const now = new Date();

const missions = rows.map(m=>{

const expire = new Date(m.expires_at);

let days = Math.ceil(
(expire-now)/(1000*60*60*24)
);

if(days < 0) days = 0;

return{
...m,
days_remaining:days
};

});

res.json(missions);

});

});

/* ---------------- ADD BOUNTY ---------------- */

app.post("/add-bounty", async(req,res)=>{

const {orderId, missionId, amount, username} = req.body;

if(!orderId || !missionId || !amount){
return res.json({error:"Missing payment data"});
}

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

/* ---------------- AUTO EXPIRE ---------------- */

setInterval(()=>{

db.run(`
UPDATE missions
SET status='expired'
WHERE expires_at < datetime('now')
AND status='active'
`);

},60000);

/* ---------------- LEADERBOARDS ---------------- */

app.get("/leaderboard/hunters",(req,res)=>{

db.all(`
SELECT hunter, COUNT(*) as wins
FROM claims
WHERE status='approved'
GROUP BY hunter
ORDER BY wins DESC
LIMIT 5
`,[],(err,rows)=>{

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

res.json(rows || []);

});

});

/* ---------------- ROOT ---------------- */

app.get("/",(req,res)=>{
res.send("Backend is running 🚀");
});

const PORT = process.env.PORT || 3000;

app.listen(PORT,()=>{
console.log("Server running on port "+PORT);
});