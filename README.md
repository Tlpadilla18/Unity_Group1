# Shape game API

Login + save-progress API for the Unity shape game (COMP 4925 Project 2).
Node.js + Express + MongoDB, bcrypt-hashed passwords, Joi validation, sessions stored **encrypted**
in MongoDB (`express-session` + `connect-mongo`), and a 400 when anyone tries to edit someone else's progress.

---

## 1. One-time setup

### a) Install Node.js
Download the **LTS** version from https://nodejs.org and install it. Check in a terminal:
```
node -v
```

### b) Create a free MongoDB Atlas database
1. Sign up at https://www.mongodb.com/cloud/atlas and create a **free (M0) cluster**.
2. **Database Access** → Add a database user (username + password). Remember them.
3. **Network Access** → Add IP Address → **Allow access from anywhere (0.0.0.0/0)**
   (needed so Render can connect).
4. **Database** → **Connect** → **Drivers** → copy the connection string. It looks like
   `mongodb+srv://USER:<password>@cluster0.xxxxx.mongodb.net/?retryWrites=true&w=majority`
   Replace `<password>` with your database user's password.

### c) Create your `.env`
In this folder (PowerShell):
```
Copy-Item .env.example .env
```
Open `.env` and fill in:
- `MONGODB_URI` – the connection string from step b.
- `NODE_SESSION_SECRET` and `MONGODB_SESSION_SECRET` – two **different** random strings. Generate each with
  (after `npm install`):
  ```
  npm run secret
  ```
  `MONGODB_SESSION_SECRET` must contain 2+ uppercase, 2+ lowercase, 2+ numbers and 2+ symbols, or the session
  encryption refuses it ("The supplied secret failed to meet complexity requirements").
Leave `NODE_ENV=development` and `ALLOWED_ORIGINS` empty on your computer.

`.env` holds passwords: it is in `.gitignore`, **never commit it**.

### d) Install packages
```
npm install
```

---

## 2. Run it on your computer

```
npm start
```
You should see `Shape game API listening on port 3000 (development)`.
Open http://localhost:3000 in a browser → `{"ok":true,"name":"Shape game API"}`.

### Connect Unity (local)
1. Open `Assets/Scenes/Login`, select the **ApiClient** object, check **Base Url** is `http://localhost:3000`.
2. Press Play → type a username and a strong password → **Sign Up**. You land in the game.
3. Play until you level up (progress saves on every level up and every 30 s), stop, press Play again
   and **Log In** → "Welcome back! Level N".
4. In Atlas → **Browse Collections** → `shapegame`:
   - `users`: your user with a bcrypt `passwordHash` (no plain password) and `progress`.
   - `sessions`: session documents are encrypted (unreadable) – that's the "encrypted MongoDB" requirement.

---

## 3. Host it on Render (free)

1. Put this API folder in a GitHub repo (its own repo, or a folder in your game repo).
2. https://render.com → **New** → **Web Service** → pick the repo.
   - **Root Directory**: the API folder (if it's inside a bigger repo)
   - **Build Command**: `npm install`
   - **Start Command**: `npm start`
   - **Instance type**: Free
3. **Environment** → add:
   | Key | Value |
   |---|---|
   | `MONGODB_URI` | your Atlas connection string |
   | `MONGODB_DB` | `shapegame` |
   | `NODE_SESSION_SECRET` | random string |
   | `MONGODB_SESSION_SECRET` | another random string |
   | `NODE_ENV` | `production` |
   | `ALLOWED_ORIGINS` | your game's URL, e.g. `https://yourname.github.io` (no trailing slash, no path) |
4. Deploy. Your API URL looks like `https://shape-game-api.onrender.com`. Open it → `{"ok":true,...}`.
5. In Unity: Login scene → **ApiClient** → **Base Url** = that URL. Rebuild the WebGL game and re-upload it.

Free Render services sleep when idle; the first request can take ~30-50 s. The game waits up to 45 s.

---

## 4. Routes

| Method | Path | Body | Success | Errors |
|---|---|---|---|---|
| GET | `/` | – | 200 health check | – |
| POST | `/signup` | `{username, password}` | 201 progress + token | 400 invalid, 409 taken, 429 too many tries |
| POST | `/login` | `{username, password}` | 200 progress + token | 401 wrong login, 429 too many tries |
| POST | `/logout` | – | 200 | – |
| GET | `/progress` | – | 200 progress | 401 not logged in |
| PUT | `/progress` | progress JSON | 200 | 401, **400 if `username` isn't you** |
| PUT | `/users/:username/progress` | progress JSON | 200 | 401, **400 if `:username` isn't you** |
| GET | `/leaderboard` | – | 200 top 10 | – |

Errors are always `{"error": "message"}`; the game shows the message to the player.

**Rules enforced on the server** (not just in Unity): username 3-20 letters/numbers/_;
password 10-64 chars with a lowercase, uppercase, number and symbol; progress fields are type/range-checked.

**Why there's a token:** the game (GitHub Pages) and API (Render) are different sites, and browsers often
block cross-site cookies. So login also returns `token` (the signed session id) and the game sends
`Authorization: Bearer <token>`. The server turns that back into the normal session cookie, so it's the same
encrypted MongoDB session either way.

### Demo the authorization rule (for marking)
PowerShell, after `npm start`:
```
# sign up two users
$a = Invoke-RestMethod -Method Post -Uri http://localhost:3000/signup -ContentType 'application/json' -Body '{"username":"alice_1","password":"Str0ng!Pass1"}'
Invoke-RestMethod -Method Post -Uri http://localhost:3000/signup -ContentType 'application/json' -Body '{"username":"bob_1","password":"Str0ng!Pass2"}' | Out-Null

# alice edits her own progress -> 200
Invoke-RestMethod -Method Put -Uri http://localhost:3000/progress -Headers @{Authorization="Bearer $($a.token)"} -ContentType 'application/json' -Body '{"username":"alice_1","bestMass":123}'

# alice tries to edit bob -> 400 "You can only edit your own progress."
Invoke-RestMethod -Method Put -Uri http://localhost:3000/users/bob_1/progress -Headers @{Authorization="Bearer $($a.token)"} -ContentType 'application/json' -Body '{"bestMass":999999}'
```

---

## 5. Troubleshooting

| Problem | Fix |
|---|---|
| `The supplied secret failed to meet complexity requirements` | `MONGODB_SESSION_SECRET` is too simple. Replace it with the output of `npm run secret`. |
| `"[object Object]" is not valid JSON` from connect-mongo | Library version mismatch (connect-mongo 5.1 + kruptein 3.4). Already worked around in server.js (`serialize` / `unserialize` options) - make sure you have the latest server.js. |
| `Missing MONGODB_URI` on start | `.env` missing or not filled in (locally) / env vars not set (Render). |
| `Could not start: ... authentication failed` | Wrong Atlas user/password in `MONGODB_URI`. |
| `Could not start: ... timed out` | Atlas **Network Access** doesn't allow your IP / 0.0.0.0/0. |
| Unity: "Can't reach the server" | API not running, or Base Url wrong (no trailing `/`). |
| Unity: "Insecure connection not allowed" | Project Settings → Player → Other Settings → **Allow downloads over HTTP** → *Allowed in development builds* (the setup tool sets this). |
| Works in the editor, fails in the hosted game | `ALLOWED_ORIGINS` on Render must exactly match the game's origin, e.g. `https://yourname.github.io`. Base Url must be `https://`. |
| `npm install` fails building **bcrypt** | Use Node LTS. As a last resort: `npm uninstall bcrypt && npm install bcryptjs` and change `require('bcrypt')` to `require('bcryptjs')` in server.js. |
