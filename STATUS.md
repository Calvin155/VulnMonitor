# VulnReview — Project Status

Last updated: 2026-05-07

## What This Is

AI-assisted pentest monitoring dashboard. Four nav areas:
- **Dashboard** (default landing) — welcome header, live API health, stat cards, severity donut, findings table, recent scans. All live from DB.
- **Security dropdown** — Requests (submit & track scans) + My Network (ping-sweep)
- **Settings dropdown** (admin only) — Manage Users + Swagger Docs link

The whole SPA is gated behind a JWT login layer with role-based access (admin / user).

---

## Stack

| Layer | Tech | Port |
|---|---|---|
| Frontend | React 19 + Vite | 5173 (local) / 443 (Pi, TLS) |
| Backend (auth + dashboard reads) | Express 5 + node-postgres + bcryptjs + JWT | 3001 |
| Pentester API | FastAPI in Docker (`aipentester-api-1`) | 8000 |
| Postgres | Docker (`aipentester-db-1`) — used by both Express and the pentester | 5432 |

Vite proxies:
- `/api/*` → `http://localhost:3001` (Express)
- `/pentester/*` → `http://localhost:8000` (FastAPI container; path rewritten to strip `/pentester`)

Proxy targets use `process.env.API_URL` / `process.env.PENTESTER_URL` with localhost fallback.

### Run locally

```bash
# 1. AI-pentester docker-compose stack must be up
# 2. Start both Express + Vite with one command:
npm start
```

`npm start` uses `concurrently` — both processes run in the same terminal with colour-coded prefixes. Ctrl+C kills both.

The `JWT_SECRET` in the start script is a dev placeholder. Set a real secret in env before sharing.

### Run on Pi

```bash
# One-time: allow Node to bind port 443 without sudo
sudo setcap cap_net_bind_service=+ep $(which node)

# Then the same command as local
npm start
```

Vite auto-detects the TLS certs (`localhost+1-key.pem` / `localhost+1.pem`) and switches to HTTPS on port 443. No config change needed between environments.

---

## Database Schema (single Postgres on :5432, `aipentester-db-1`, db `pentester`)

### `scans` (owned by the pentester container)

| Column | Type | Notes |
|---|---|---|
| `id` | SERIAL PK | |
| `domain` | text NOT NULL | Scan target |
| `target_ip` | text | |
| `scanned_at` | timestamptz NOT NULL DEFAULT now() | |
| `completed_at` | timestamptz | |
| `status` | text NOT NULL DEFAULT `'completed'` | running / completed / cancelled / failed |
| `error` | text | |
| `scan_duration_seconds` | int | |
| `recon` / `scan_summary` / `report` | text | |
| `vulnerabilities` | jsonb NOT NULL DEFAULT `'[]'` | Findings array |
| `msf` / `network_scan` / `raw_*` / `vuln_raw` / `scan_options` | jsonb | |

### `users` (owned by Express; bootstrapped on startup)

| Column | Type | Notes |
|---|---|---|
| `id` | SERIAL PK | |
| `username` | text UNIQUE | 3–64 chars |
| `password_hash` | text | bcryptjs hash (cost 12) |
| `role` | text NOT NULL DEFAULT `'user'` | `admin` or `user` |
| `created_at` | timestamptz | default `NOW()` |

On every startup Express runs `ALTER TABLE users ADD COLUMN IF NOT EXISTS role ...` (idempotent) and `UPDATE users SET role = 'admin' WHERE username = 'calvin'`.

> Note: if the docker-compose stack wipes the DB, the `users` table goes with it — Login will detect the empty table and flip back to *Create the first user*.

---

## API Endpoints

### Auth (Express, unauthenticated)

| Method | Path | Description |
|---|---|---|
| POST | `/api/auth/register` | Create user. Open to anyone; new users get `role = 'user'`. |
| POST | `/api/auth/login` | Returns `{ token, user }` (includes `role`). Constant-time password compare. |
| GET | `/api/auth/setup-required` | `{ setup_required: bool }` — Login page uses this to flip to register mode |
| GET | `/api/auth/me` | Current user with role (requires Bearer token) |

JWT: HS256, secret from `JWT_SECRET` env (dev fallback warns), 24h expiry, payload includes `sub`, `username`, `role`. Token stored in `localStorage` (XSS surface — revisit before sharing outside trusted network).

### Express data API (all require Bearer token)

| Method | Path | Description |
|---|---|---|
| GET | `/api/stats` | Aggregate counts by severity + total scans |
| GET | `/api/scans` | All scans ordered by date, includes `vuln_count` |
| GET | `/api/scans/:id` | Single scan with full vulnerability array |
| GET | `/api/vulnerabilities` | All vulnerabilities flattened across all scans |
| PATCH | `/api/scans/:id/vuln/:idx` | Update a finding's status (new/reviewing/fixed/fp) |

### Admin API (require Bearer token + `role = 'admin'`)

| Method | Path | Description |
|---|---|---|
| GET | `/api/admin/users` | List all users |
| POST | `/api/admin/users` | Create user with chosen role |
| PATCH | `/api/admin/users/:id/role` | Change a user's role (cannot change own) |
| DELETE | `/api/admin/users/:id` | Delete a user (cannot delete self) |

### Pentester container (FastAPI, proxied as `/pentester/*`, not gated by Express)

| Method | Path | Used by |
|---|---|---|
| POST | `/pentester/scans` | Requests tab — kicks off a scan (returns 202 + id) |
| GET | `/pentester/scans?limit=50` | Requests tab — scan history list |
| GET | `/pentester/scans/{id}/status` | Requests tab — polled every 2s during a run |
| GET | `/pentester/scans/{id}` | Requests tab — drill-down |
| GET | `/pentester/network/scan?cidr=...` | My Network tab — `nmap -sn` ping-sweep |
| GET | `/pentester/health` | Dashboard — live health card (polled every 30s) |

---

## Navigation Structure

```
[ Dashboard ]  [ Security ▾ ]  [ Settings ▾ (admin only) ]
                  Requests         Manage Users
                  My Network       Swagger Docs → :8000/docs
```

**Dashboard** is the default landing page and shows:
- Welcome header ("Welcome back, {username}") + live Pentester API health card
- Stat cards (total scans, total findings, critical, high, medium, low, info)
- Severity donut chart (clickable — filters findings table)
- Recent scans list (clickable — opens drill-down modal)
- Full findings table (sortable, searchable, expandable rows, status pills)

**Swagger Docs** and API link URLs use `window.location.hostname` so they resolve correctly whether accessed from the Pi directly or from another device on the LAN.

---

## Auth & Roles

- Registration is open — anyone can create an account; new users get `role = 'user'`
- First-run: if no users exist, Login flips to "Create the first user" (that user becomes admin)
- Sign-in / Sign-up toggle on the Login page
- `calvin` is always assigned `role = 'admin'` on Express startup
- Admin role gates: Settings nav tab, Manage Users page, all `/api/admin/*` endpoints
- `isAdmin` helper exposed from `AuthContext` — used in UI to show/hide admin features
- Admin badge shown in the header user chip

---

## Feature Status

### Done
- [x] Dashboard — stat cards, severity donut, recent scans, full findings table (all live from DB)
- [x] Dashboard interactivity — clickable severity filters, sortable columns, search, expandable rows, scan drill-down modal
- [x] Reusable `ScanDetail` component with search, severity filtering, expand/collapse-all
- [x] Requests tab — POST `/pentester/scans`, polls status every 2s, cancel button, history list
- [x] My Network tab — ping-sweep, sortable host table, copy-IP, Scan → hand-off to Requests
- [x] JWT login layer — bcryptjs (cost 12), 24h tokens, Bearer middleware on all `/api/*` routes
- [x] Role-based access — `admin` / `user` roles in DB + JWT, `adminOnly` middleware, `isAdmin` in frontend
- [x] First-run setup flow — Login flips to register mode when users table is empty
- [x] Sign-up page — open registration toggle on Login page; new users get `user` role
- [x] Settings tab (admin only) — Manage Users table (list, add, change role, delete) + API Links section
- [x] Settings dropdown — Manage Users (in-app) + Swagger Docs (external link, hostname-aware)
- [x] Security dropdown — Requests + My Network grouped under Security nav item
- [x] Live health card on Dashboard — polls `/pentester/health` every 30s, green/red pulse indicator
- [x] `npm start` — `concurrently` runs Express + Vite in one terminal
- [x] Auto port/TLS — Vite uses port 443 + HTTPS when certs present (Pi), port 5173 + HTTP otherwise (local)
- [x] Hostname-aware external links — Swagger/Health URLs use `window.location.hostname`
- [x] DB consolidation — Express and pentester share the same Postgres instance
- [x] Status PATCH fix — `$3::text` cast; status pills persist correctly
- [x] Vite proxies — `/api/*` → Express `:3001`, `/pentester/*` → container `:8000`

### Not Done / In Progress

- [ ] **Token storage**: JWT in `localStorage` (XSS exposure). Move to httpOnly cookie before deploying outside trusted network.
- [ ] **Rate limiting on `/api/auth/login`** — unlimited; add brute-force protection (`express-rate-limit`).
- [ ] **Environment config** — DB password still hardcoded in `server.js`. Wire `.env` + `dotenv`.
- [ ] **Legacy endpoints** — `POST /api/scans/run` + `GET /api/scans/:id/stream` still defined in `server.js`; no longer used by the UI. Safe to delete.
- [ ] **`adaptScanForDetail()` in `Requests.jsx`** — confirm shape against real completed scan bodies and tighten.
- [ ] **`/network/scan` only sees Docker bridge** — run pentester with `--network host` to scan real LAN.
- [ ] **Metasploit not wired** — form collects exploit + lhost but `msfrpcd` isn't running anywhere.
- [ ] **Mixed content on Pi** — Settings API links and Swagger open HTTP `:8000` from an HTTPS page. Works fine from the Pi directly; a reverse proxy (nginx) in front of `:8000` with the same TLS cert would fix it for remote browsers.

---

## Known Issues

1. **Duplicate `timeAgo` helper** — defined separately in `Dashboard.jsx`, `Requests.jsx`, and `Network.jsx`. Should be extracted to `src/utils/time.js`.
2. **Orphan `running` rows** — when the pentester worker dies, DB rows stay `status='running'` forever. Cancel button is the UI workaround; the real fix is a startup reconciliation pass in the pentester container.

---

## Next Suggested Steps

1. **Lock down auth secrets** — set `JWT_SECRET` in env, move DB password out of `server.js` into `.env` + `dotenv`.
2. **Rate limiting** — add `express-rate-limit` on `/api/auth/login`.
3. **Move JWT off localStorage** — switch to httpOnly + SameSite=Lax cookie before deploying anywhere shared.
4. **Nginx reverse proxy for port 8000** — fixes mixed-content issue for remote browsers on the Pi.

---

## Metasploit Integration (deferred)

Current state: form collects `exploit` + `lhost`, pentester accepts `exploit=true` in `POST /scans`, but `msfrpcd` isn't running.

Recommended approach for Pi deployment: add Metasploit as a sidecar container in docker-compose behind `profiles: ["exploit"]`.

- `MSF_HOST` env on the pentester points at the sidecar's service name
- Named volume for `~/.msf4/`
- LHOST should be the bridge IP the target containers can reach
- **arm64 caveat**: verify the MSF image publishes an arm64 tag before committing

---

## Future Roadmap

### 🔄 Operational
- [ ] **Scheduled / recurring scans** — cron-like layer so the Pi re-sweeps nightly/weekly
- [ ] **Baselines + diffs** — `GET /pentester/scans/{id}/diff/{baseline_id}` backend exists; needs UI
- [ ] **Notifications** — Discord/Slack/email on new critical findings or new MAC on LAN

### 🌐 Network awareness
- [ ] **Asset inventory** — persist every sweep, track first-seen/last-seen per host
- [ ] **DHCP / mDNS enrichment** — parse Pi-hole/dnsmasq leases for friendly names
- [ ] **Per-host history page** — every scan that touched IP X, vuln churn over time

### 📋 Triage workflow
- [ ] **Due-date + owner** on findings — surface stale findings view
- [ ] **Saved scan profiles** — "weekly internal sweep" preset
- [ ] **Bulk status updates** — mark all `info` findings from a scan as `fp` in one click

### 🔐 App-level security
- [ ] **TOTP 2FA** on login
- [ ] **Login audit log** — `auth_events` table (who, when, IP, outcome); surface on Dashboard
- [ ] **httpOnly cookie session** instead of localStorage JWT
- [ ] **`pg_dump` cron + restore script** — Pi SD cards die; back up to SSD or remote storage

### 📤 Reporting & sharing
- [ ] **Markdown / PDF export** of a scan
- [ ] **Trends panel** — open vs fixed per week, mean-time-to-fix

### 🧪 Stretch
- [ ] **Multi-user scan ownership** — tie scans to the user who submitted them; user-specific views
- [ ] **CVE enrichment** from NVD + CISA KEV
- [ ] **SSE/WebSocket live progress** — replace 2s polling once container exposes a stream endpoint
- [ ] **Wake-on-LAN** before scanning sleeping hosts
