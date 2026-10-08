# Hack4Gov — Working Challenge Portal

Fictional/Unofficial cybersecurity CTF-style demo. All challenges are simulated and intended for authorized local competition only.

## Run
1. Install Node.js 18+.
2. In this folder run:
   npm install
   npm start
3. Open http://localhost:3000

## What is real
- User registration/login
- HTTP-only session cookie
- SQLite database
- Server-side flag validation
- One-time scoring per challenge
- Persistent solved state
- Live leaderboard API
- Score endpoint

The flags are kept server-side as SHA-256 hashes and are never sent to the browser.
