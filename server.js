import express from 'express'
import cors from 'cors'
import pg from 'pg'
import bcrypt from 'bcryptjs'
import jwt from 'jsonwebtoken'
import { spawn } from 'child_process'
import path from 'path'
import { fileURLToPath } from 'url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))

const PYTHON_BIN = '/home/calvin/.cache/pypoetry/virtualenvs/ai-pentester-s7lfeKjm-py3.12/bin/python3'
const RUNNER_SCRIPT = path.join(__dirname, 'scripts', 'pentest_runner.py')
const AI_PROJECT_DIR = '/home/calvin/Projects/AI Project'

const BCRYPT_COST = 12
const JWT_EXPIRES_IN = '24h'
const JWT_SECRET = process.env.JWT_SECRET || 'dev-only-do-not-use-in-prod'
if (JWT_SECRET === 'dev-only-do-not-use-in-prod') {
  console.warn('[auth] JWT_SECRET not set — using insecure dev fallback. Set JWT_SECRET in env before sharing.')
}

// id -> { lines: [], clients: Set, status: 'running'|'completed'|'error' }
const activeScans = new Map()

const { Pool } = pg

// Single Postgres — the same one the pentester container uses (ai_pentester-db-1).
// Express only owns the `users` table here; `scans` belongs to the pentester.
const pool = new Pool({
  host:     process.env.PGHOST     || 'localhost',
  port:     Number(process.env.PGPORT) || 5432,
  database: process.env.PGDATABASE || 'pentester',
  user:     process.env.PGUSER     || 'pentester',
  password: process.env.PGPASSWORD || 'Munster2021',
})

// Bootstrap users table (idempotent)
async function initSchema() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS users (
      id            SERIAL PRIMARY KEY,
      username      TEXT UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
    )
  `)
}
initSchema().catch(err => {
  console.error('[auth] Failed to init users table:', err.message)
  process.exit(1)
})

const app = express()
app.use(cors())
app.use(express.json())

// ── Auth helpers ─────────────────────────────────────────────────────────

function signToken(user) {
  return jwt.sign({ sub: user.id, username: user.username }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN })
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || ''
  const m = header.match(/^Bearer\s+(.+)$/i)
  if (!m) return res.status(401).json({ error: 'missing token' })
  try {
    req.user = jwt.verify(m[1], JWT_SECRET)
    next()
  } catch {
    res.status(401).json({ error: 'invalid or expired token' })
  }
}

// Optional auth — used by /register so that, after the first user is created,
// only an authenticated caller can add more users. Anonymous register is only
// allowed when the users table is empty (first-run setup).
function tryAuth(req, _res, next) {
  const header = req.headers.authorization || ''
  const m = header.match(/^Bearer\s+(.+)$/i)
  if (m) {
    try { req.user = jwt.verify(m[1], JWT_SECRET) } catch { /* ignore */ }
  }
  next()
}

// ── Auth routes (unprotected) ────────────────────────────────────────────

app.post('/api/auth/register', tryAuth, async (req, res) => {
  const { username, password } = req.body || {}
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username and password required' })
  }
  const u = username.trim()
  if (u.length < 3 || u.length > 64)   return res.status(400).json({ error: 'username must be 3–64 chars' })
  if (password.length < 8)             return res.status(400).json({ error: 'password must be at least 8 chars' })
  if (password.length > 200)           return res.status(400).json({ error: 'password too long' })

  try {
    const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM users')
    const isFirstRun = rows[0].n === 0
    if (!isFirstRun && !req.user) {
      return res.status(403).json({ error: 'registration is closed; sign in first' })
    }

    const hash = await bcrypt.hash(password, BCRYPT_COST)
    const ins = await pool.query(
      'INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username, created_at',
      [u, hash]
    )
    const user = ins.rows[0]
    res.status(201).json({ token: signToken(user), user: { id: user.id, username: user.username } })
  } catch (err) {
    if (err.code === '23505') return res.status(409).json({ error: 'username taken' })
    res.status(500).json({ error: err.message })
  }
})

app.post('/api/auth/login', async (req, res) => {
  const { username, password } = req.body || {}
  if (typeof username !== 'string' || typeof password !== 'string') {
    return res.status(400).json({ error: 'username and password required' })
  }
  try {
    const { rows } = await pool.query(
      'SELECT id, username, password_hash FROM users WHERE username = $1',
      [username.trim()]
    )
    const user = rows[0]
    // Always run bcrypt to keep timing roughly constant whether or not the user exists.
    const hash = user?.password_hash || '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidi'
    const ok = await bcrypt.compare(password, hash)
    if (!user || !ok) return res.status(401).json({ error: 'invalid credentials' })

    res.json({ token: signToken(user), user: { id: user.id, username: user.username } })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/auth/me', authMiddleware, async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT id, username, created_at FROM users WHERE id = $1',
      [req.user.sub]
    )
    if (!rows[0]) return res.status(401).json({ error: 'user no longer exists' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

app.get('/api/auth/setup-required', async (_req, res) => {
  try {
    const { rows } = await pool.query('SELECT COUNT(*)::int AS n FROM users')
    res.json({ setup_required: rows[0].n === 0 })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Everything below this line requires a valid JWT.
app.use('/api', authMiddleware)

// Aggregate stats across all scans
app.get('/api/stats', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        COUNT(*)::int                                                         AS total_scans,
        COALESCE(SUM(jsonb_array_length(vulnerabilities)), 0)::int           AS total_vulns,
        COALESCE(SUM((
          SELECT COUNT(*) FROM jsonb_array_elements(vulnerabilities) v
          WHERE lower(v->>'severity') = 'critical'
        )), 0)::int AS critical,
        COALESCE(SUM((
          SELECT COUNT(*) FROM jsonb_array_elements(vulnerabilities) v
          WHERE lower(v->>'severity') = 'high'
        )), 0)::int AS high,
        COALESCE(SUM((
          SELECT COUNT(*) FROM jsonb_array_elements(vulnerabilities) v
          WHERE lower(v->>'severity') = 'medium'
        )), 0)::int AS medium,
        COALESCE(SUM((
          SELECT COUNT(*) FROM jsonb_array_elements(vulnerabilities) v
          WHERE lower(v->>'severity') = 'low'
        )), 0)::int AS low,
        COALESCE(SUM((
          SELECT COUNT(*) FROM jsonb_array_elements(vulnerabilities) v
          WHERE lower(v->>'severity') = 'info' OR lower(v->>'severity') = 'informational'
        )), 0)::int AS info
      FROM scans
    `)
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// All scans (list view)
app.get('/api/scans', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        id,
        domain,
        scanned_at,
        scan_summary,
        jsonb_array_length(vulnerabilities) AS vuln_count,
        vulnerabilities
      FROM scans
      ORDER BY scanned_at DESC
    `)
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Single scan detail
app.get('/api/scans/:id', async (req, res) => {
  try {
    const { rows } = await pool.query(
      'SELECT * FROM scans WHERE id = $1',
      [req.params.id]
    )
    if (!rows[0]) return res.status(404).json({ error: 'Not found' })
    res.json(rows[0])
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Flattened vulnerabilities across all scans (for findings table).
// COALESCEs handle both naming conventions:
//   - pentester writes  owasp / recommendation
//   - legacy schema     category / remediation
app.get('/api/vulnerabilities', async (req, res) => {
  try {
    const { rows } = await pool.query(`
      SELECT
        s.id            AS scan_id,
        (v.ord - 1)::int AS vuln_idx,
        s.domain,
        s.scanned_at,
        v.value->>'name'        AS name,
        v.value->>'severity'    AS severity,
        v.value->>'description' AS description,
        v.value->>'cvss'        AS cvss,
        v.value->>'cve'         AS cve,
        v.value->>'exploit_hint' AS exploit_hint,
        v.value->>'status'      AS status,
        COALESCE(v.value->>'remediation', v.value->>'recommendation') AS remediation,
        COALESCE(v.value->>'category',    v.value->>'owasp')          AS category
      FROM scans s
      CROSS JOIN LATERAL jsonb_array_elements(s.vulnerabilities) WITH ORDINALITY AS v(value, ord)
      ORDER BY s.scanned_at DESC
    `)
    res.json(rows)
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Update a single vulnerability's status inside the JSONB array
app.patch('/api/scans/:id/vuln/:idx', async (req, res) => {
  const { status } = req.body
  const valid = ['new', 'reviewing', 'fixed', 'fp']
  if (!valid.includes(status)) return res.status(400).json({ error: 'invalid status' })
  try {
    const { rowCount } = await pool.query(`
      UPDATE scans
      SET vulnerabilities = (
        SELECT jsonb_agg(
          CASE WHEN (ord - 1) = $2::int
          THEN elem || jsonb_build_object('status', $3::text)
          ELSE elem END
        )
        FROM jsonb_array_elements(vulnerabilities) WITH ORDINALITY t(elem, ord)
      )
      WHERE id = $1
    `, [req.params.id, req.params.idx, status])
    if (rowCount === 0) return res.status(404).json({ error: 'Not found' })
    res.json({ ok: true })
  } catch (err) {
    res.status(500).json({ error: err.message })
  }
})

// Start a real pentest scan via ai_pentester
app.post('/api/scans/run', (req, res) => {
  const { domain } = req.body
  if (!domain?.trim()) return res.status(400).json({ error: 'domain required' })

  const id = `scan_${Date.now()}`
  const scan = { lines: [], clients: new Set(), status: 'running' }
  activeScans.set(id, scan)

  res.json({ id })

  const proc = spawn(PYTHON_BIN, [RUNNER_SCRIPT, domain.trim()], {
    cwd: AI_PROJECT_DIR,
  })

  let buffer = ''
  proc.stdout.on('data', chunk => {
    buffer += chunk.toString()
    const parts = buffer.split('\n')
    buffer = parts.pop()
    for (const line of parts) {
      if (!line.trim()) continue
      let msg
      try { msg = JSON.parse(line) } catch { continue }

      scan.lines.push(msg)
      for (const client of scan.clients) {
        client.write(`data: ${JSON.stringify(msg)}\n\n`)
      }

      if (msg.type === 'result') {
        const vulns = (msg.data.vulnerabilities ?? []).map(v => ({
          name:        v.name,
          severity:    (v.severity ?? '').toLowerCase(),
          description: v.description,
          remediation: v.recommendation,
          category:    v.owasp,
          cvss:        v.cvss   ?? null,
          cve:         v.cve    ?? null,
        }))
        pool.query(
          `INSERT INTO scans (domain, scanned_at, scan_summary, vulnerabilities)
           VALUES ($1, NOW(), $2, $3::jsonb)`,
          [domain.trim(), msg.data.report ?? '', JSON.stringify(vulns)]
        ).catch(err => console.error('DB insert error:', err.message))
      }
    }
  })

  proc.stderr.on('data', chunk => {
    console.error('[runner stderr]', chunk.toString().trim())
  })

  proc.on('close', code => {
    scan.status = code === 0 ? 'completed' : 'error'
    const done = { type: 'done', exitCode: code }
    scan.lines.push(done)
    for (const client of scan.clients) {
      client.write(`data: ${JSON.stringify(done)}\n\n`)
      client.end()
    }
    scan.clients.clear()
  })
})

// SSE stream for a running scan
app.get('/api/scans/:id/stream', (req, res) => {
  const scan = activeScans.get(req.params.id)
  if (!scan) return res.status(404).json({ error: 'scan not found' })

  res.setHeader('Content-Type', 'text/event-stream')
  res.setHeader('Cache-Control', 'no-cache')
  res.setHeader('Connection', 'keep-alive')
  res.flushHeaders()

  // Replay buffered lines to late-connecting clients
  for (const msg of scan.lines) {
    res.write(`data: ${JSON.stringify(msg)}\n\n`)
  }

  if (scan.status !== 'running') {
    res.write(`data: ${JSON.stringify({ type: 'done' })}\n\n`)
    res.end()
    return
  }

  scan.clients.add(res)
  req.on('close', () => scan.clients.delete(res))
})

const PORT = 3001
app.listen(PORT, () => {
  console.log(`API server listening on http://localhost:${PORT}`)
})
