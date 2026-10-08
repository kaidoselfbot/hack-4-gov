
const express = require("express");
const cookieParser = require("cookie-parser");
const bcrypt = require("bcryptjs");
const crypto = require("crypto");
const Database = require("better-sqlite3");
const path = require("path");

const app = express();
const PORT = process.env.PORT || 3000;
const db = new Database(path.join(__dirname, "hack4gov.db"));

app.use(express.json({ limit: "20kb" }));
app.use(cookieParser());
app.use(express.static(path.join(__dirname, "public")));

db.exec(`
CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  email TEXT UNIQUE NOT NULL,
  password_hash TEXT NOT NULL,
  team_name TEXT NOT NULL,
  created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS sessions (
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL,
  expires_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS solves (
  user_id INTEGER NOT NULL,
  challenge_id TEXT NOT NULL,
  points INTEGER NOT NULL,
  solved_at TEXT NOT NULL,
  PRIMARY KEY (user_id, challenge_id)
);
`);

const challenges = {
  "web-defense": { points: 500, flag: "H4G{WEB-VAL-204}" },
  "digital-forensics": { points: 650, flag: "H4G{DFIR-7F3A}" },
  "secure-ai": { points: 700, flag: "H4G{SAFE-AI-17}" },
  "threat-intel": { points: 600, flag: "H4G{NIGHT-FERN}" },
  "crypto-lab": { points: 750, flag: "H4G{HYSK-42}" },
  "secure-coding": { points: 800, flag: "H4G{SECURE-MERGE-9}" }
};

const hash = s => crypto.createHash("sha256").update(s).digest("hex");
const normalizeFlag = s => String(s || "").trim().toUpperCase();
const flagHashes = Object.fromEntries(
  Object.entries(challenges).map(([id, c]) => [id, hash(normalizeFlag(c.flag))])
);

function auth(req, res, next) {
  const token = req.cookies.h4g_session;
  if (!token) return res.status(401).json({ error: "Login required" });
  const row = db.prepare(`
    SELECT u.id, u.email, u.team_name
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>?
  `).get(hash(token), Date.now());
  if (!row) return res.status(401).json({ error: "Session expired" });
  req.user = row;
  next();
}

app.get("/api/challenges", (req,res) => {
  res.json(Object.entries(challenges).map(([id,c]) => ({ id, points:c.points })));
});

app.get("/api/challenges/state", auth, (req,res) => {
  const rows = db.prepare("SELECT challenge_id FROM solves WHERE user_id=?").all(req.user.id);
  res.json({ solved: rows.map(r => r.challenge_id) });
});

app.post("/api/challenges/submit", auth, (req,res) => {
  const { challengeId, flag } = req.body || {};
  const challenge = challenges[challengeId];
  if (!challenge) return res.status(404).json({ error: "Unknown challenge" });

  const already = db.prepare(
    "SELECT 1 FROM solves WHERE user_id=? AND challenge_id=?"
  ).get(req.user.id, challengeId);
  if (already) {
    const score = db.prepare(
      "SELECT COALESCE(SUM(points),0) AS score FROM solves WHERE user_id=?"
    ).get(req.user.id).score;
    return res.json({ correct:true, alreadySolved:true, awarded:0, score });
  }

  const submittedHash = hash(normalizeFlag(flag));
  const correct = crypto.timingSafeEqual(
    Buffer.from(submittedHash, "hex"),
    Buffer.from(flagHashes[challengeId], "hex")
  );

  if (!correct) return res.json({ correct:false, message:"Incorrect flag. Check the challenge evidence and try again." });

  db.prepare(`
    INSERT INTO solves(user_id,challenge_id,points,solved_at)
    VALUES(?,?,?,?)
  `).run(req.user.id, challengeId, challenge.points, new Date().toISOString());

  const score = db.prepare(
    "SELECT COALESCE(SUM(points),0) AS score FROM solves WHERE user_id=?"
  ).get(req.user.id).score;

  res.json({ correct:true, alreadySolved:false, awarded:challenge.points, score });
});

app.get("/api/score", auth, (req,res) => {
  const score = db.prepare(
    "SELECT COALESCE(SUM(points),0) AS score FROM solves WHERE user_id=?"
  ).get(req.user.id).score;
  res.json({ score });
});

app.get("/api/leaderboard", (req,res) => {
  const rows = db.prepare(`
    SELECT u.team_name AS team,
           COALESCE(SUM(s.points),0) AS points,
           COUNT(s.challenge_id) AS solved
    FROM users u
    LEFT JOIN solves s ON s.user_id=u.id
    GROUP BY u.id
    ORDER BY points DESC, solved DESC, u.created_at ASC
    LIMIT 100
  `).all();
  res.json(rows);
});

app.post("/api/register", async (req,res) => {
  const { email, password, teamName } = req.body || {};
  if (!email || !password || !teamName || password.length < 8)
    return res.status(400).json({ error:"Email, team name, and a password of at least 8 characters are required." });

  const normalizedEmail = String(email).trim().toLowerCase();
  try {
    const passwordHash = await bcrypt.hash(password, 12);
    const info = db.prepare(`
      INSERT INTO users(email,password_hash,team_name,created_at)
      VALUES(?,?,?,?)
    `).run(normalizedEmail, passwordHash, String(teamName).trim(), new Date().toISOString());

    const token = crypto.randomBytes(32).toString("hex");
    db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)")
      .run(hash(token), info.lastInsertRowid, Date.now()+7*24*60*60*1000);

    res.cookie("h4g_session", token, { httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:7*24*60*60*1000 });
    res.json({ ok:true });
  } catch (e) {
    if (String(e.message).includes("UNIQUE"))
      return res.status(409).json({ error:"That email is already registered." });
    res.status(500).json({ error:"Registration failed." });
  }
});

app.post("/api/login", async (req,res) => {
  const { email, password } = req.body || {};
  const user = db.prepare("SELECT * FROM users WHERE email=?").get(String(email||"").trim().toLowerCase());
  if (!user || !(await bcrypt.compare(String(password||""), user.password_hash)))
    return res.status(401).json({ error:"Invalid email or password." });

  const token = crypto.randomBytes(32).toString("hex");
  db.prepare("INSERT INTO sessions(token_hash,user_id,expires_at) VALUES(?,?,?)")
    .run(hash(token), user.id, Date.now()+7*24*60*60*1000);
  res.cookie("h4g_session", token, { httpOnly:true, sameSite:"lax", secure:process.env.NODE_ENV==="production", maxAge:7*24*60*60*1000 });
  res.json({ ok:true });
});

app.post("/api/logout", (req,res) => {
  const token=req.cookies.h4g_session;
  if(token) db.prepare("DELETE FROM sessions WHERE token_hash=?").run(hash(token));
  res.clearCookie("h4g_session");
  res.json({ok:true});
});

app.get("/api/me", (req,res) => {
  const token=req.cookies.h4g_session;
  if(!token) return res.json({loggedIn:false});
  const row=db.prepare(`
    SELECT u.id,u.email,u.team_name,
           COALESCE((SELECT SUM(points) FROM solves WHERE user_id=u.id),0) AS score,
           (SELECT COUNT(*) FROM solves WHERE user_id=u.id) AS solved
    FROM sessions s JOIN users u ON u.id=s.user_id
    WHERE s.token_hash=? AND s.expires_at>?
  `).get(hash(token),Date.now());
  if(!row) return res.json({loggedIn:false});
  res.json({loggedIn:true,...row});
});

app.listen(PORT, () => {
  console.log(`Hack4Gov challenge server running at http://localhost:${PORT}`);
});
