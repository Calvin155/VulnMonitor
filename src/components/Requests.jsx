import { useState, useEffect, useRef } from 'react'
import ScanDetail from './ScanDetail'
import './Requests.css'

const WORDLISTS = [
  { value: 'default',  label: 'Default' },
  { value: 'advanced', label: 'Advanced' },
  { value: 'seclists', label: 'SecLists' },
]

const POLL_INTERVAL_MS = 2000
const TERMINAL_STATUSES = new Set(['completed', 'failed', 'error', 'cancelled'])

function timeAgo(ts) {
  if (!ts) return '—'
  const diff = Math.floor((Date.now() - new Date(ts)) / 1000)
  if (diff < 0)     return 'just now'
  if (diff < 60)    return `${diff}s ago`
  if (diff < 3600)  return `${Math.floor(diff / 60)}m ago`
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`
  return `${Math.floor(diff / 86400)}d ago`
}

function elapsed(start, end) {
  if (!start) return '—'
  const ms = (end ? new Date(end).getTime() : Date.now()) - new Date(start).getTime()
  if (ms < 0) return '—'
  const s = Math.floor(ms / 1000)
  if (s < 60)   return `${s}s`
  const m = Math.floor(s / 60)
  const rs = s % 60
  if (m < 60)   return `${m}m ${rs}s`
  const h = Math.floor(m / 60)
  return `${h}h ${m % 60}m`
}

// Severity collected from various plausible field names in the container's free-form scan blob.
function flattenVulnerabilities(scan) {
  if (!scan || typeof scan !== 'object') return []
  if (Array.isArray(scan.vulnerabilities)) return scan.vulnerabilities
  if (Array.isArray(scan.findings))        return scan.findings

  // Fall back to walking `checks` and pulling any nested vulnerabilities arrays.
  const out = []
  const checks = scan.checks ?? scan.results ?? null
  if (checks && typeof checks === 'object') {
    for (const [checkName, body] of Object.entries(checks)) {
      const nested = body?.vulnerabilities ?? body?.findings ?? null
      if (Array.isArray(nested)) {
        for (const v of nested) out.push({ ...v, category: v.category ?? checkName })
      }
    }
  }
  return out
}

// Map the container's free-form `/scans/{id}` response to what ScanDetail expects.
function adaptScanForDetail(scan) {
  if (!scan) return null
  const vulnerabilities = flattenVulnerabilities(scan)
  return {
    id:            scan.id,
    domain:        scan.domain ?? scan.target ?? '—',
    scanned_at:    scan.scanned_at ?? scan.completed_at ?? scan.started_at ?? null,
    scan_summary:  scan.scan_summary ?? scan.summary ?? scan.report ?? '',
    vulnerabilities,
  }
}

function statusBadgeClass(status) {
  const s = (status ?? '').toLowerCase()
  if (s === 'completed')                    return 'scan-badge-completed'
  if (s === 'running' || s === 'pending')   return 'scan-badge-running'
  if (s === 'queued')                       return 'scan-badge-queued'
  return 'scan-badge-error'
}

function isRunningStatus(s) {
  const v = (s ?? '').toLowerCase()
  return v === 'running' || v === 'pending' || v === 'queued'
}

export default function Requests() {
  const [target, setTarget]               = useState('')
  const [wordlist, setWordlist]           = useState('default')
  const [exploit, setExploit]             = useState(false)
  const [lhost, setLhost]                 = useState('')
  const [engagementRef, setEngagementRef] = useState('')
  const [authAck, setAuthAck]             = useState(false)

  const [scans, setScans]                 = useState([])
  const [scansLoading, setScansLoading]   = useState(true)
  const [activeScan, setActiveScan]       = useState(null)   // currently-running scan from POST
  const [statusLog, setStatusLog]         = useState([])     // status transitions for the panel
  const [submitError, setSubmitError]     = useState(null)
  const [isSubmitting, setIsSubmitting]   = useState(false)

  const [selectedScan, setSelectedScan]   = useState(null)
  const [loadingScan, setLoadingScan]     = useState(false)

  const pollAbort = useRef(null)
  const isRunning = activeScan && isRunningStatus(activeScan.status)

  async function refreshHistory() {
    try {
      const res = await fetch('/pentester/scans?limit=50')
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setScans(data.scans ?? [])
    } catch {
      // surface silently — empty list is fine
    } finally {
      setScansLoading(false)
    }
  }

  useEffect(() => {
    refreshHistory()
    return () => { if (pollAbort.current) pollAbort.current.aborted = true }
  }, [])

  // Pre-fill target when the Network tab fires "Scan →" on a host.
  useEffect(() => {
    function onPrefill(e) {
      if (e.detail?.target) setTarget(e.detail.target)
    }
    window.addEventListener('vulnreview:request-scan', onPrefill)
    return () => window.removeEventListener('vulnreview:request-scan', onPrefill)
  }, [])

  function appendLog(level, text) {
    setStatusLog(prev => [...prev, { level, text, ts: new Date().toISOString() }])
  }

  async function pollUntilDone(scanId, controller) {
    while (!controller.aborted) {
      try {
        const res = await fetch(`/pentester/scans/${scanId}/status`)
        if (!res.ok) throw new Error(`status HTTP ${res.status}`)
        const s = await res.json()
        setActiveScan(prev => prev ? { ...prev, ...s } : s)

        if (TERMINAL_STATUSES.has((s.status ?? '').toLowerCase())) {
          appendLog(
            s.status === 'completed' ? 'ok' : 'alert',
            `Scan ${s.status}${s.error ? ' — ' + s.error : ''}`,
          )
          return s
        }
      } catch (err) {
        appendLog('alert', `Polling error: ${err.message}`)
      }
      await new Promise(r => setTimeout(r, POLL_INTERVAL_MS))
    }
  }

  async function runScan() {
    if (!target.trim() || isSubmitting || isRunning) return
    if (!authAck) {
      setSubmitError('You must acknowledge written authorization before running a scan.')
      return
    }
    if (exploit && !lhost.trim()) {
      setSubmitError('LHOST is required when "Allow exploit" is enabled.')
      return
    }

    setSubmitError(null)
    setIsSubmitting(true)
    setStatusLog([])
    setSelectedScan(null)
    setActiveScan(null)

    const body = {
      target: target.trim(),
      wordlist,
      exploit,
      lhost: exploit ? lhost.trim() : '',
      authorization_acknowledged: authAck,
      engagement_ref: engagementRef.trim(),
    }

    let started
    try {
      const res = await fetch('/pentester/scans', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        const msg = data.detail || data.error || `HTTP ${res.status}`
        throw new Error(typeof msg === 'string' ? msg : JSON.stringify(msg))
      }
      started = data
    } catch (err) {
      setSubmitError(err.message)
      setIsSubmitting(false)
      appendLog('alert', `Failed to start scan: ${err.message}`)
      return
    }

    setIsSubmitting(false)
    setActiveScan(started)
    appendLog('sys', `Scan #${started.id} started for ${started.domain ?? body.target}`)
    setScans(prev => [started, ...prev.filter(s => s.id !== started.id)])

    // Cancel any previous poller, start a new one
    if (pollAbort.current) pollAbort.current.aborted = true
    const controller = { aborted: false }
    pollAbort.current = controller

    const final = await pollUntilDone(started.id, controller)
    if (controller.aborted) return

    if (final?.status === 'completed') {
      appendLog('sys', `Took ${elapsed(final.scanned_at, final.completed_at)}`)
    }
    refreshHistory()
  }

  async function openScan(id) {
    if (!Number.isInteger(id) || id <= 0) return
    setLoadingScan(true)
    setSelectedScan(null)
    try {
      const res = await fetch(`/pentester/scans/${id}`)
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setSelectedScan(adaptScanForDetail(data))
    } catch (err) {
      appendLog('alert', `Failed to load scan ${id}: ${err.message}`)
    }
    setLoadingScan(false)
  }

  async function cancelScan(id) {
    if (!Number.isInteger(id) || id <= 0) return
    const ok = window.confirm(
      `Cancel scan #${id}?\n\nThe pentester API has no soft-cancel — this removes the scan from history entirely. Continue?`
    )
    if (!ok) return

    // If we're cancelling the active scan, stop the poller and clear status.
    if (activeScan?.id === id) {
      if (pollAbort.current) pollAbort.current.aborted = true
      setActiveScan(null)
    }
    if (selectedScan?.id === id) setSelectedScan(null)

    // Optimistic UI: remove from list immediately
    setScans(prev => prev.filter(s => s.id !== id))

    try {
      const res = await fetch(`/pentester/scans/${id}`, { method: 'DELETE' })
      if (!res.ok && res.status !== 404) {
        const data = await res.json().catch(() => ({}))
        throw new Error(data.detail || data.error || `HTTP ${res.status}`)
      }
      appendLog('sys', `Scan #${id} cancelled and removed.`)
    } catch (err) {
      appendLog('alert', `Failed to cancel scan ${id}: ${err.message}`)
    } finally {
      // Re-sync from the source of truth
      refreshHistory()
    }
  }

  return (
    <div className="requests">

      {/* ── Scan Form ── */}
      <div className="card form-card">
        <div className="card-title">New Scan Request</div>

        <div className="form-grid">
          <div className="form-field">
            <label className="field-label">Target</label>
            <input
              className="field-input"
              type="text"
              placeholder="example.com / 10.0.0.5"
              value={target}
              onChange={e => setTarget(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runScan()}
            />
          </div>

          <div className="form-field">
            <label className="field-label">Wordlist</label>
            <select className="field-select" value={wordlist} onChange={e => setWordlist(e.target.value)}>
              {WORDLISTS.map(w => (
                <option key={w.value} value={w.value}>{w.label}</option>
              ))}
            </select>
          </div>

          <div className="form-field">
            <label className="field-label">Engagement Ref <span className="field-optional">(optional)</span></label>
            <input
              className="field-input"
              type="text"
              placeholder="TICKET-123"
              value={engagementRef}
              onChange={e => setEngagementRef(e.target.value)}
            />
          </div>
        </div>

        <div className="checks-row">
          <label className="check-label">
            <input
              type="checkbox"
              className="check-input"
              checked={exploit}
              onChange={e => setExploit(e.target.checked)}
            />
            <span className="check-box">{exploit && <CheckMark />}</span>
            Allow exploit (Metasploit)
          </label>

          {exploit && (
            <div className="form-field inline-field">
              <label className="field-label inline-label">LHOST</label>
              <input
                className="field-input inline-input"
                type="text"
                placeholder="10.0.0.2"
                value={lhost}
                onChange={e => setLhost(e.target.value)}
              />
            </div>
          )}
        </div>

        <label className="auth-ack">
          <input
            type="checkbox"
            className="check-input"
            checked={authAck}
            onChange={e => setAuthAck(e.target.checked)}
          />
          <span className="check-box">{authAck && <CheckMark />}</span>
          <span>
            I have <strong>written authorization</strong> to test this target.
            <span className="auth-ack-sub"> Required by container API ({' '}
              <code>authorization_acknowledged</code>).</span>
          </span>
        </label>

        <div className="form-actions">
          <button
            className={`run-btn ${isRunning ? 'running' : ''}`}
            onClick={runScan}
            disabled={isSubmitting || isRunning || !target.trim() || !authAck}
          >
            {isSubmitting || isRunning ? (
              <><Spinner /> {isSubmitting ? 'Submitting...' : 'Scanning...'}</>
            ) : (
              <><PlayIcon /> Run Scan</>
            )}
          </button>
          {isRunning && (
            <span className="running-hint">
              Scan #{activeScan.id} · {activeScan.status} · {elapsed(activeScan.scanned_at)}
            </span>
          )}
          {submitError && <span className="submit-error">{submitError}</span>}
        </div>
      </div>

      {/* ── Bottom Row: Scans + Status/Detail ── */}
      <div className="bottom-row">

        {/* Scan History */}
        <div className="card scans-card">
          <div className="card-title">
            <span>Scan History</span>
            <button className="scans-refresh" onClick={refreshHistory} title="Refresh">↻</button>
          </div>
          <div className="scans-list">
            {scansLoading && <div className="scans-empty">Loading...</div>}
            {!scansLoading && scans.length === 0 && (
              <div className="scans-empty">No scans yet.</div>
            )}
            {scans.map(s => {
              const status = (s.status ?? '').toLowerCase()
              const clickable = status === 'completed'
              const isSelected = selectedScan?.id === s.id
              return (
                <div
                  key={s.id}
                  className={`scan-item ${status}${clickable ? ' clickable' : ''}${isSelected ? ' selected' : ''}`}
                  onClick={() => clickable && openScan(s.id)}
                >
                  <div className="scan-header">
                    <span className="scan-target">{s.domain ?? s.target}</span>
                    <span className={`scan-status-badge ${statusBadgeClass(status)}`}>
                      {isRunningStatus(status) && <Spinner small />}
                      {status || 'unknown'}
                    </span>
                    {isRunningStatus(status) && (
                      <button
                        className="scan-cancel-btn"
                        onClick={e => { e.stopPropagation(); cancelScan(s.id) }}
                        title="Cancel this scan (removes it from history)"
                      >
                        Cancel
                      </button>
                    )}
                  </div>
                  <div className="scan-meta">
                    <span className="scan-type">#{s.id}</span>
                    <span className="scan-dot-sep">·</span>
                    <span className="scan-time">{timeAgo(s.scanned_at ?? s.completed_at)}</span>
                    {status === 'completed' && s.completed_at && s.scanned_at && (
                      <>
                        <span className="scan-dot-sep">·</span>
                        <span className="scan-findings">{elapsed(s.scanned_at, s.completed_at)}</span>
                      </>
                    )}
                    {s.error && (
                      <>
                        <span className="scan-dot-sep">·</span>
                        <span className="scan-error" title={s.error}>error</span>
                      </>
                    )}
                  </div>
                  {isRunningStatus(status) && (
                    <div className="progress-bar-bg">
                      <div className="progress-bar-fill progress-bar-indet" />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Status panel or scan detail */}
        {loadingScan ? (
          <div className="card terminal-card detail-loading">
            <Spinner /> Loading scan...
          </div>
        ) : selectedScan ? (
          <ScanDetail scan={selectedScan} onClose={() => setSelectedScan(null)} />
        ) : (
          <div className="card terminal-card">
            <div className="card-title">
              <span>Status</span>
              {isRunning && <span className="term-live"><span className="conn-dot" />LIVE</span>}
            </div>
            <div className="status-panel">
              {activeScan ? (
                <>
                  <div className="status-grid">
                    <div className="status-cell">
                      <div className="status-label">Scan</div>
                      <div className="status-value">#{activeScan.id}</div>
                    </div>
                    <div className="status-cell">
                      <div className="status-label">Target</div>
                      <div className="status-value">{activeScan.domain ?? target}</div>
                    </div>
                    <div className="status-cell">
                      <div className="status-label">State</div>
                      <div className={`status-value status-state status-state-${(activeScan.status ?? '').toLowerCase()}`}>
                        {activeScan.status ?? 'unknown'}
                      </div>
                    </div>
                    <div className="status-cell">
                      <div className="status-label">Elapsed</div>
                      <div className="status-value">{elapsed(activeScan.scanned_at, activeScan.completed_at)}</div>
                    </div>
                  </div>
                  {activeScan.error && <div className="status-error">{activeScan.error}</div>}
                  {activeScan.status === 'completed' && (
                    <button className="status-open-btn" onClick={() => openScan(activeScan.id)}>
                      Open results →
                    </button>
                  )}
                </>
              ) : (
                <div className="status-idle">
                  Connected to pentest container at <code>localhost:8000</code>.
                  <br />Configure a target above and click <strong>Run Scan</strong>.
                </div>
              )}
              {statusLog.length > 0 && (
                <div className="status-log">
                  {statusLog.map((line, i) => (
                    <div key={i} className={`status-log-line status-log-${line.level}`}>
                      <span className="status-log-ts">{new Date(line.ts).toLocaleTimeString()}</span>
                      <span>{line.text}</span>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        )}

      </div>
    </div>
  )
}

function CheckMark() {
  return (
    <svg width="9" height="9" viewBox="0 0 12 12" fill="none" stroke="currentColor" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round">
      <polyline points="2 6 5 9 10 3"/>
    </svg>
  )
}

function PlayIcon() {
  return (
    <svg width="12" height="12" viewBox="0 0 24 24" fill="currentColor">
      <polygon points="5 3 19 12 5 21 5 3"/>
    </svg>
  )
}

function Spinner({ small }) {
  return (
    <svg
      width={small ? 10 : 13}
      height={small ? 10 : 13}
      viewBox="0 0 24 24"
      fill="none"
      stroke="currentColor"
      strokeWidth="2.5"
      className="spinner"
    >
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
    </svg>
  )
}
