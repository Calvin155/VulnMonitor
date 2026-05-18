# VulnMonitor

AI-assisted pentest monitoring dashboard. React + Vite frontend backed by an Express API, both running inside a single Node container. Connects to the AIPentester FastAPI engine and a shared PostgreSQL instance.

> Full documentation — stack, endpoints, schema, feature status, roadmap — is in [STATUS.md](STATUS.md).

---

## Quick start

### Docker (recommended — runs with the full stack)

```bash
# From the repo root:
cp .env.example .env          # set POSTGRES_PASSWORD, JWT_SECRET, OPENROUTER_API_KEY
docker compose up -d --build
# Dashboard: http://localhost:3001
```

### Local dev

```bash
npm install
npm start    # concurrently runs Express (:3001) + Vite (:5173)
```

First run: the login page flips to "Create the first user" automatically when the users table is empty.

### Raspberry Pi / K3s

See [../k3s-manifest.yml](../k3s-manifest.yml) and [../deploy-to-pi.sh](../deploy-to-pi.sh).

Access via:
- `http://vulnmonitor.local` (after adding DNS/hosts entry)
- `http://<pi-ip>` (direct IP — catch-all Traefik rule)

---

## Stack

| Layer | Tech |
|-------|------|
| Frontend | React 19 + Vite |
| Backend | Express 5 + node-postgres + bcryptjs + JWT |
| Database | PostgreSQL 16 (shared with AIPentester) |
| Pentest engine | AIPentester FastAPI (proxied at `/pentester/*`) |

---

## Navigation

```
[ Dashboard ]  [ Security ▾ ]  [ Settings ▾ (admin only) ]
                  Requests         Manage Users
                  My Network       Swagger Docs
```

- **Dashboard** — stat cards, severity donut, findings table, recent scans, live API health
- **Requests** — submit scans, poll live status, history
- **My Network** — active nmap ping-sweep + passive tshark listener (mDNS/DHCP)
- **Settings** — user management (admin only), API links
