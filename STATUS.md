# VulnReview — Project Status

Last updated: 2026-05-03

## What This Is

AI-assisted pentest monitoring dashboard. Three tabs:
- **Dashboard** — read-only analytics over the local Postgres (Express-backed)
- **Requests** — submit & track scans against a separate **AI-pentester Docker container** (FastAPI on `:8000`)
- **My Network** — ping-sweep the local network via the same container's `GET /network/scan`

The whole SPA is gated behind a JWT login layer.

---

## Stack

| Layer            | Tech                                 | Port  |
|------------------|--------------------------------------|-------|
| Frontend         | React 19 + Vite                      | 5173  |
| Backend (auth + dashboard reads) | Express 5 + node-postgres + bcryptjs + JWT | 3001  |
| Pentester API    | FastAPI in Docker (`ai_pentester-api-1`) | 8000  |
| Postgres         | Docker (`ai_pentester-db-1`) — used by **both** Express and the pentester after consolidation | 5432  |

Vite proxies:
- `/api/*` → `http://localhost:3001` (Express)
- `/pentester/*` → `http://localhost:8000` (FastAPI container; path rewritten to strip `/pentester`)

### Run locally

```bash
# 1. AI-pentester docker-compose stack must be up (provides the API container + the Postgres on :5432)
# 2. Then start Express + Vite:
JWT_SECRET=change-me npm run server   # Express API; bootstraps the users table inside the pentester DB
npm run dev                            # Vite dev server
```

First time you load the app, it sees `setup_required: true` and the Login screen
becomes a *Create the first user* form. After that, registration is closed
unless the caller is already authenticated.

---

## Database Schema (single Postgres on :5432, `ai_pentester-db-1`, db `pentester`)

### `scans` (owned by the pentester container; Dashboard + drill-down read this)

The pentester schema is rich — full list:

| Column                  | Type        | Notes                                         |
|-------------------------|-------------|-----------------------------------------------|
| `id`                    | SERIAL PK   |                                               |
| `domain`                | text NOT NULL | Scan target                                 |
| `target_ip`             | text        |                                               |
| `scanned_at`            | timestamptz NOT NULL DEFAULT now() |                       |
| `completed_at`          | timestamptz |                                               |
| `status`                | text NOT NULL DEFAULT `'completed'` | running / completed / cancelled / failed |
| `error`                 | text        |                                               |
| `scan_duration_seconds` | int         |                                               |
| `recon` / `scan_summary` / `report` | text |                                          |
| `vulnerabilities`       | jsonb NOT NULL DEFAULT `'[]'` | Findings array — UI status pills inject `status` per element |
| `msf` / `network_scan` / `raw_*` / `vuln_raw` / `scan_options` | jsonb |          |

The Express read endpoints only touch `id`, `domain`, `scanned_at`, `scan_summary`, and `vulnerabilities` — all compatible with this schema.

### `users` (owned by Express; bootstrapped on startup via `CREATE TABLE IF NOT EXISTS`)

| Column          | Type        | Notes                                                   |
|-----------------|-------------|---------------------------------------------------------|
| `id`            | SERIAL PK   |                                                         |
| `username`      | text UNIQUE | 3–64 chars                                              |
| `password_hash` | text        | bcryptjs hash (cost 12)                                 |
| `created_at`    | timestamptz | default `NOW()`                                         |

> Note: if your other docker-compose-managed app rebuilds and wipes this DB, the `users` table goes with it — Login will detect the empty table on next load and flip back to *Create the first user*.

Each element in `vulnerabilities`:

```json
{
  "name":        "SQL Injection",
  "severity":    "critical",
  "description": "...",
  "cvss":        "9.8",
  "cve":         "CVE-2024-XXXX",
  "remediation": "...",
  "category":    "Injection"
}
```

Valid `severity` values: `critical`, `high`, `medium`, `low`, `info` / `informational` (normalised to `info` in the UI).

---

## API Endpoints

### Auth (Express, **unauthenticated**)

| Method | Path                          | Description                                                      |
|--------|-------------------------------|------------------------------------------------------------------|
| POST   | `/api/auth/register`          | Create user. Open only when zero users exist OR caller is auth'd |
| POST   | `/api/auth/login`             | Returns `{ token, user }`. Constant-time password compare.       |
| GET    | `/api/auth/setup-required`    | `{ setup_required: bool }` — used by Login page to flip to register mode |
| GET    | `/api/auth/me`                | Current user (requires Bearer token)                             |

JWT: HS256, secret from `JWT_SECRET` env (dev fallback warns), 24h expiry, sent as `Authorization: Bearer <token>`. Token stored in `localStorage` on the client (XSS surface — revisit if/when this leaves dev).

### Express data API (all require Bearer token)

| Method | Path                  | Description                                        |
|--------|-----------------------|----------------------------------------------------|
| GET    | `/api/stats`          | Aggregate counts by severity + total scans         |
| GET    | `/api/scans`          | All scans ordered by date, includes `vuln_count`   |
| GET    | `/api/scans/:id`      | Single scan with full vulnerability array          |
| GET    | `/api/vulnerabilities`| All vulnerabilities flattened across all scans     |
| PATCH  | `/api/scans/:id/vuln/:idx` | Update a finding's status (new/reviewing/fixed/fp) |

### Pentester container (FastAPI, proxied as `/pentester/*` on Vite, **not gated by Express**)

| Method | Path                          | Used by             |
|--------|-------------------------------|---------------------|
| POST   | `/pentester/scans`            | Requests tab — kicks off a scan (returns 202 + id) |
| GET    | `/pentester/scans?limit=50`   | Requests tab — scan history list |
| GET    | `/pentester/scans/{id}/status`| Requests tab — polled every 2s during a run |
| GET    | `/pentester/scans/{id}`       | Requests tab — drill-down (run through `adaptScanForDetail()` mapper) |
| GET    | `/pentester/network/scan?cidr=...` | My Network tab — `nmap -sn` ping-sweep |

The container's API has its own `authorization_acknowledged` gate that the Requests form enforces (run button disabled until checked). The container is on a Docker bridge by default — `/network/scan` only sees the bridge subnet unless run with `--network host` or attached to the LAN.

---

## Feature Status

### Done
- [x] Dashboard — stat cards, severity donut chart, recent scans list, full findings table (all live from DB)
- [x] **Dashboard interactivity** — clickable severity cards + donut filter the findings table; sortable columns; search bar; expandable rows showing description/remediation/CVSS; clickable Recent Scans open the drill-down in a modal
- [x] **Reusable `ScanDetail` component** with built-in search + severity-pill filtering + expand/collapse-all (used by Requests inline panel and Dashboard modal)
- [x] **Requests tab now talks to the AI-pentester FastAPI container** — POST `/pentester/scans`, polls `/pentester/scans/{id}/status` every 2s, refreshes history on completion. Live SSE terminal replaced with a status panel since the container API has no streaming.
- [x] **Cancel button on running scans** — `DELETE /pentester/scans/{id}` with a `confirm()` warning; stops the active poller and refreshes history. Useful for clearing rows that get stuck in `running` when a worker dies (the pentester has no soft-cancel/orphan reconciliation).
- [x] **Form fields match the container's `ScanRequest`** — target, wordlist, exploit toggle (with conditional LHOST), engagement ref, required `authorization_acknowledged` checkbox
- [x] **My Network tab** — `GET /pentester/network/scan?cidr=...` ping-sweep, sortable host table (IP / hostname / MAC / vendor), copy-IP button, *Scan →* per-host hand-off that pre-fills the Requests tab via a `vulnreview:request-scan` window event
- [x] **JWT login layer** — `users` table bootstrapped on Express startup, bcryptjs hashing (cost 12), `/api/auth/{register,login,me,setup-required}`, all other `/api/*` routes behind a Bearer-token middleware
- [x] **First-run setup flow** — Login screen flips to "Create the first user" when `users` is empty; after that, registration is closed unless caller is already authenticated
- [x] **Frontend auth gate** — `AuthProvider` + `apiFetch` helper that injects the Bearer header, auto-logs-out on 401; SPA shows Login until authenticated; logout button + username chip in header
- [x] **DB consolidation** — Express now points at the pentester container's Postgres (`ai_pentester-db-1` on `:5432`, `pentester/pentester`). One DB for both `users` and `scans`. Dashboard reads now reflect scans run via the Requests tab.
- [x] **Status PATCH fix** — `PATCH /api/scans/:id/vuln/:idx` was failing with `could not determine data type of parameter $3`; `$3::text` cast added. Status pills (New/Reviewing/Fixed/False Positive) persist correctly.
- [x] Vite proxies — `/api/*` → Express `:3001`, `/pentester/*` → container `:8000`

### Not Done / In Progress

- [ ] **Token storage**: JWT in `localStorage` (XSS exposure). Move to httpOnly cookie before this leaves a trusted environment.
- [ ] **Rate limiting on `/api/auth/login`** — currently unlimited; add brute-force protection.
- [ ] **Express's `POST /api/scans/run` + `/stream`** — legacy subprocess runner endpoints; no longer used by the UI but still defined in `server.js`. They're now behind auth, but `EventSource` can't send `Authorization` headers, so the SSE one is effectively unusable. Safe to delete now that the container is authoritative.
- [ ] **Environment config** — DB password still hardcoded in `server.js` (the pool reads `PG*` env vars but defaults are baked in). Wire `.env` + `dotenv`.
- [ ] **`adaptScanForDetail()` in `Requests.jsx`** is defensive (looks for `vulnerabilities` / `findings` / nested `checks.*.vulnerabilities`). Confirm against real completed scan bodies across all scan types and tighten if needed.
- [ ] **`/network/scan` only sees the Docker bridge** — to scan the real LAN, run the pentester container with `--network host` (or otherwise attach it to the host network).
- [ ] **Metasploit not actually wired** — see *Metasploit Integration* section below.

---

## Known Issues

1. **Duplicate `timeAgo` helper** — defined separately in `Dashboard.jsx`, `Requests.jsx`, and now `Network.jsx`. Should be extracted to `src/utils/time.js`.

2. **Pentester leaves orphan `running` rows** — when its scan worker dies (crash, container restart, OOM), the DB row stays in `status='running'` forever; the container has no startup reconciliation pass. The Cancel button is the workaround on the UI side, but the right fix is on the pentester side: a startup hook that marks orphaned `running` scans as `failed`.

---

## Next Suggested Steps (immediate hardening)

1. **Lock down auth secrets** — set `JWT_SECRET` in env, move DB password out of `server.js` into `.env` + `dotenv` (already reads `PG*` env vars; just needs the `.env` plumbing).
2. **Brute-force protection** — add rate limiting (`express-rate-limit`) on `/api/auth/login`.
3. **Move JWT off localStorage** — switch to httpOnly + SameSite=Lax cookie before deploying anywhere shared.
4. **Confirm `/pentester/scans/{id}` shape** — `adaptScanForDetail()` is defensive; tighten it once real shapes are observed across all scan types.
5. **Container networking** — for `/network/scan` to see the real LAN, run the pentester container with `--network host` (or attach it to the host network).
6. **Metasploit wiring** — current pentester env (`MSF_HOST=127.0.0.1:55553`) expects `msfrpcd` inside the container, but it isn't installed. See *Metasploit Integration* below.

---

## Metasploit Integration (deferred)

Current state: form collects `exploit` + `lhost`, the pentester accepts `exploit=true` in `POST /scans`, but `msfrpcd` isn't actually running anywhere.

Recommended approach for the planned **Raspberry Pi home-server deployment**: add Metasploit as a **sidecar container** in docker-compose, behind a `profiles: ["exploit"]` flag so it only consumes RAM when exploit mode is wanted.

- `MSF_HOST` env on the pentester points at the sidecar's service name.
- Named volume for `~/.msf4/` (sessions, loot, db).
- LHOST in the form should be the bridge IP that target containers can reach the sidecar on (typically the sidecar's bridge IP, or `172.17.0.1` if MSF is host-net'd).
- **arm64 caveat**: verify the chosen MSF image publishes an arm64 tag before committing to it on Pi; if not, build from the official Dockerfile.

---

## Future Roadmap (potentials)

Grouped by payoff. Top three to build first if revisiting: **scheduled scans + diffs + notifications** — they reinforce each other and turn this from a "dashboard you visit" into a "system that pings you."

### 🔄 Operational

- [ ] **Scheduled / recurring scans** — cron-like layer on the pentester so the Pi quietly re-sweeps the LAN nightly/weekly. Without this the app gets forgotten; with it, it earns its keep on its own.
- [ ] **Baselines + diffs** — pin a baseline scan per host, build a "what's new since baseline" view. **Backend already exists**: `GET /pentester/scans/{id}/diff/{baseline_id}`. Just needs UI.
- [ ] **Notifications** — Discord / Slack / email webhook on new high/critical findings, on a previously-unseen MAC appearing on the LAN, or on baseline drift.

### 🌐 Network awareness

- [ ] **Asset inventory** — persist every `My Network` sweep, track first-seen / last-seen per host, flag MACs never seen before. Effectively a passive home-network IDS on top of the existing nmap data.
- [ ] **DHCP / mDNS enrichment** — if the Pi also runs Pi-hole / dnsmasq, parse leases for friendly names so the host list stops being bare IPs.
- [ ] **Per-host history page** — every scan that ever touched IP X, vulnerability churn over time. Pairs naturally with the existing *Scan →* hand-off from My Network.

### 📋 Triage workflow (extends the status pills)

- [ ] **Due-date + owner** on findings — surface a *stale findings* view ("this critical has been open 14 days").
- [ ] **Saved scan profiles / templates** — "weekly internal sweep" preset (targets, depth, wordlist). Stops re-typing the form.
- [ ] **Bulk status updates** — mark every `info` finding from a scan as `fp` in one click.

### 🔐 App-level security

- [ ] **TOTP 2FA** on login — cheap, big upgrade for a server holding scan data.
- [ ] **Login rate-limit + audit log** — `express-rate-limit` + an `auth_events` table (who, when, IP, outcome). Surface failed logins as a Dashboard card.
- [ ] **httpOnly cookie session** instead of localStorage JWT (also listed under immediate hardening).
- [ ] **`pg_dump` cron + restore script** — Pi SD cards die more than people expect; back up to a mounted SSD or remote storage.

### 📤 Reporting & sharing

- [ ] **Markdown / PDF export** of a scan — `scan_summary` markdown already exists, just needs a render-to-PDF button.
- [ ] **Trends panel on Dashboard** — open vs fixed per week, mean-time-to-fix. Makes the Dashboard a "is my home network getting better or worse" view rather than a snapshot.

### 🧪 Stretch

- [ ] **Multi-user with roles** (viewer / operator / admin) — trivial JWT-claim extension.
- [ ] **CVE enrichment** from NVD + CISA KEV — flag "actively exploited in the wild" right in the findings row.
- [ ] **SSE/WebSocket live progress** — replace the 2s status polling once the container API exposes a stream endpoint.
- [ ] **Wake-on-LAN before scanning** sleeping hosts.
