const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const cors = require("cors");

const app = express();
app.use(express.json());
app.use(cors());

const db = new sqlite3.Database("./database.db");

const JWT_SECRET = process.env.JWT_SECRET || "secret";

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

if(!agreedTerms || !isAdult){
return res.status(400).json({error:"Must accept terms and confirm 18+"});
}

const hash=await bcrypt.hash(password,10);

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

const match=await bcrypt.compare(password,user.password);

if(!match) return res.json({error:"Invalid login"});

const token=jwt.sign({id:user.id,username:user.username},JWT_SECRET);

res.json({token});
});
});

/* ---------------- CREATE MISSION ---------------- */

app.post("/missions",(req,res)=>{

const {target,reason,amount}=req.body;

const expires=new Date();
expires.setDate(expires.getDate()+20);

db.run(
`INSERT INTO missions(target,reason,bounty_amount,expires_at)
VALUES(?,?,?,?)`,
[target,reason,amount,expires.toISOString()],
function(err){

if(err) return res.json({error:"Mission creation failed"});

res.json({id:this.lastID});
});
});

/* ---------------- GET MISSIONS ---------------- */

app.get("/missions",(req,res)=>{

db.all(`SELECT * FROM missions WHERE status='active'`,[],(err,rows)=>{

const now=new Date();

const missions=rows.map(m=>{

const expire=new Date(m.expires_at);

const days=Math.ceil((expire-now)/(1000*60*60*24));

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

db.run(
`UPDATE missions
SET bounty_amount=bounty_amount+?
WHERE id=?`,
[amount,missionId]
);

db.run(
`INSERT INTO bounty_contributions(mission_id,contributor,amount)
VALUES(?,?,?)`,
[missionId,username,amount]
);

res.json({message:"Bounty increased"});
});

/* ---------------- CLAIM ---------------- */

app.post("/claims",(req,res)=>{

const {missionId,clip,paypal,hunter}=req.body;

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

const PORT=process.env.PORT||3000;

app.listen(PORT,()=>{
console.log("Server running");
});