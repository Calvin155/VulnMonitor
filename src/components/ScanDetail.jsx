import { useState, useEffect, useRef, useMemo } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useAuth } from '../auth/AuthContext'
import './ScanDetail.css'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'informational']
const STATUS_LABELS = { new: 'New', reviewing: 'Reviewing', fixed: 'Fixed', fp: 'False Positive' }

function normSev(v) { return (v.severity ?? 'info').toLowerCase().replace('informational', 'info') }
const cat  = v => v.category    ?? v.owasp          ?? null
const rem  = v => v.remediation ?? v.recommendation ?? null
const hint = v => v.exploit_hint ?? null

// network_scan / msf / scan_options may be stored as Python-style dict strings
function parsePyDict(val) {
  if (!val) return null
  if (typeof val === 'object') return val
  try { return JSON.parse(val) } catch {}
  try {
    return JSON.parse(
      val
        .replace(/'/g, '"')
        .replace(/\bNone\b/g, 'null')
        .replace(/\bTrue\b/g, 'true')
        .replace(/\bFalse\b/g, 'false')
    )
  } catch { return null }
}

// ── Sub-components ────────────────────────────────────────────────────────────

function CveDetail({ cveId, cveCache, onFetch }) {
  useEffect(() => { onFetch(cveId) }, [cveId])
  const cve = cveCache[cveId]
  if (!cve || cve === 'loading') return (
    <div className="vuln-section">
      <div className="vuln-section-label">CVE — {cveId}</div>
      <p className="vuln-section-text cve-loading">Fetching NVD data...</p>
    </div>
  )
  if (cve === 'error') return null
  return (
    <div className="vuln-section">
      <div className="vuln-section-label">CVE — {cveId}</div>
      <div className="cve-detail-body">
        <div className="cve-chips">
          {cve.cvss_score != null && <span className="cve-chip">CVSS {cve.cvss_score}</span>}
          {cve.severity   && <span className={`cve-chip cve-sev-${cve.severity.toLowerCase()}`}>{cve.severity}</span>}
          {cve.vector     && <span className="cve-chip cve-vector" title={cve.vector}>{cve.vector.split('/')[0]}</span>}
        </div>
        {cve.description && <p className="cve-desc">{cve.description}</p>}
        {cve.nvd_link && (
          <a className="cve-nvd-link" href={cve.nvd_link} target="_blank" rel="noreferrer">View on NVD →</a>
        )}
      </div>
    </div>
  )
}

function reconBadge(text) {
  if (!text) return null
  if (/CONFIRMED:\s*YES/i.test(text))     return { label: 'CONFIRMED',     cls: 'confirmed' }
  if (/CONFIRMED:\s*PARTIAL/i.test(text)) return { label: 'PARTIAL',       cls: 'partial'   }
  if (/NOT CONFIRMED/i.test(text))        return { label: 'NOT CONFIRMED', cls: 'denied'    }
  return null
}

function ReconCheck({ name, output }) {
  const [open, setOpen] = useState(false)
  const text = typeof output === 'string' ? output : JSON.stringify(output, null, 2)
  if (!text || text === '{}' || text === 'null' || !text.trim()) return null
  const badge = reconBadge(text)
  return (
    <div className="recon-check" onClick={() => setOpen(o => !o)}>
      <div className="recon-check-header">
        <span className="recon-check-name">{name.replace(/_/g, ' ')}</span>
        <div className="recon-check-meta">
          {badge && (
            <span className={`validation-badge validation-badge-${badge.cls}`}>{badge.label}</span>
          )}
          <span className="vuln-chevron">{open ? '▲' : '▼'}</span>
        </div>
      </div>
      {open && <pre className="recon-check-body">{text}</pre>}
    </div>
  )
}

function ProbeResult({ probe }) {
  const type = (probe.probe ?? probe.type ?? '').toLowerCase()

  if (type === 'credentials') {
    const results   = probe.results ?? probe.findings ?? []
    const successes = results.filter(r => r.success)
    return (
      <div className="probe-card">
        <div className="probe-header">
          <span className="probe-name">Credential Probe</span>
          {successes.length > 0
            ? <span className="probe-badge probe-badge-success">{successes.length} credential{successes.length !== 1 ? 's' : ''} found</span>
            : <span className="probe-badge">No valid credentials</span>}
        </div>
        {results.map((r, i) => (
          <div key={i} className={`probe-result ${r.success ? 'probe-success' : 'probe-fail'}`}>
            <div className="probe-result-header">
              <span className={`probe-status-dot${r.success ? ' success' : ''}`} />
              <span className="probe-endpoint">{r.endpoint ?? r.url ?? '—'}</span>
            </div>
            {r.command  && <pre className="probe-command">{r.command}</pre>}
            {r.evidence && <p  className="probe-evidence">{r.evidence}</p>}
          </div>
        ))}
      </div>
    )
  }

  if (type === 'nmap') {
    const hosts = probe.hosts ?? probe.results ?? []
    return (
      <div className="probe-card">
        <div className="probe-header">
          <span className="probe-name">Port Scan (Nmap)</span>
          <span className="probe-badge">{hosts.length} host{hosts.length !== 1 ? 's' : ''}</span>
        </div>
        {hosts.map((h, i) => (
          <div key={i} className="probe-host">
            <div className="probe-host-row">
              <span className="host-ip">{h.ip}</span>
              {h.hostname && <span className="host-name">{h.hostname}</span>}
            </div>
            {(h.ports ?? h.open_ports ?? []).length > 0 && (
              <div className="host-ports">
                <div className="ports-head"><span>Port</span><span>Service</span><span>Product</span></div>
                {(h.ports ?? h.open_ports ?? []).map((p, j) => (
                  <div key={j} className="port-row">
                    <span className="port-num">{p.port}</span>
                    <span className="port-service">{p.service || '—'}</span>
                    <span className="port-product">{[p.product, p.version].filter(Boolean).join(' ') || '—'}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        ))}
      </div>
    )
  }

  // Generic fallback — show whatever shape we got
  return (
    <div className="probe-card">
      <div className="probe-header">
        <span className="probe-name">{probe.probe ?? probe.type ?? 'Probe'}</span>
      </div>
      <pre className="probe-raw">{JSON.stringify(probe, null, 2)}</pre>
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────

export default function ScanDetail({ scan: initialScan, onClose, onDelete, variant = 'panel' }) {
  const { apiFetch, isAdmin } = useAuth()
  const [scan, setScan]             = useState(initialScan)
  const [tab, setTab]               = useState('findings')
  const [expanded, setExpanded]     = useState(new Set())
  const [search, setSearch]         = useState('')
  const [sevFilter, setSevFilter]   = useState(null)
  const [cveCache, setCveCache]     = useState({})

  useEffect(() => {
    if (scan.status !== 'running') return
    const id = setInterval(async () => {
      try {
        const res = await apiFetch(`/api/scans/${scan.id}`)
        if (res.ok) setScan(await res.json())
      } catch {}
    }, 5000)
    return () => clearInterval(id)
  }, [scan.status, scan.id])

  const networkData = useMemo(() => parsePyDict(scan.network_scan), [scan.network_scan])

  const probesData = useMemo(() => {
    const raw = scan.probes
    if (!raw) return null
    if (Array.isArray(raw) && raw.length > 0) return raw
    const parsed = parsePyDict(raw)
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : null
  }, [scan.probes])

  const msfData = useMemo(() => {
    const raw = scan.msf
    if (!raw) return null
    const parsed = typeof raw === 'object' && !Array.isArray(raw) ? raw : parsePyDict(raw)
    if (!parsed || Object.keys(parsed).length === 0) return null
    return parsed
  }, [scan.msf])

  const scanOpts = useMemo(() => {
    const raw = scan.scan_options
    if (!raw) return null
    return typeof raw === 'object' ? raw : parsePyDict(raw)
  }, [scan.scan_options])

  const attackChains = useMemo(() => {
    const raw = scan.attack_chains
    if (!raw) return null
    if (Array.isArray(raw) && raw.length > 0) return raw
    const parsed = parsePyDict(raw)
    return Array.isArray(parsed) && parsed.length > 0 ? parsed : null
  }, [scan.attack_chains])

  async function deleteScan() {
    if (!window.confirm(`Delete scan #${scan.id} for ${scan.domain}?\nThis cannot be undone.`)) return
    try {
      const res = await apiFetch(`/api/scans/${scan.id}`, { method: 'DELETE' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      window.dispatchEvent(new CustomEvent('vulnreview:scan-deleted', { detail: { id: scan.id } }))
      onDelete?.(scan.id)
      onClose()
    } catch (err) {
      alert(`Delete failed: ${err.message}`)
    }
  }

  const [vulns, setVulns] = useState(() =>
    [...(scan.vulnerabilities ?? [])]
      .map((v, i) => ({ ...v, _origIdx: i }))
      .sort((a, b) => {
        const ai = SEV_ORDER.indexOf((a.severity ?? '').toLowerCase())
        const bi = SEV_ORDER.indexOf((b.severity ?? '').toLowerCase())
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
      })
  )
  // Fingerprint covers count + confirmed status + validation presence so the list
  // re-syncs when validation data arrives (same count, new fields).
  const vulnFingerprint = (scan.vulnerabilities ?? [])
    .map(v => `${v.confirmed ?? ''}:${v.validation_command ? 1 : 0}`)
    .join(',')
  useEffect(() => {
    setVulns(prev => {
      const statusMap = new Map(prev.map(v => [v._origIdx, v.status]))
      return [...(scan.vulnerabilities ?? [])]
        .map((v, i) => ({ ...v, _origIdx: i, status: statusMap.get(i) ?? v.status }))
        .sort((a, b) => {
          const ai = SEV_ORDER.indexOf((a.severity ?? '').toLowerCase())
          const bi = SEV_ORDER.indexOf((b.severity ?? '').toLowerCase())
          return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
        })
    })
  }, [vulnFingerprint])

  useEffect(() => {
    function onKey(e) { if (e.key === 'Escape') onClose() }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  function toggle(i) {
    setExpanded(prev => {
      const next = new Set(prev)
      next.has(i) ? next.delete(i) : next.add(i)
      return next
    })
  }

  async function updateStatus(sortedIdx, status) {
    const origIdx = vulns[sortedIdx]._origIdx
    setVulns(prev => prev.map((v, i) => i === sortedIdx ? { ...v, status } : v))
    try {
      const res = await apiFetch(`/api/scans/${scan.id}/vuln/${origIdx}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      })
      if (!res.ok) throw new Error()
    } catch {
      setVulns(prev => prev.map((v, i) =>
        i === sortedIdx ? { ...v, status: scan.vulnerabilities[origIdx]?.status } : v
      ))
    }
  }

  async function fetchCve(cveId) {
    if (!cveId || cveCache[cveId]) return
    setCveCache(prev => ({ ...prev, [cveId]: 'loading' }))
    try {
      const res  = await fetch(`/pentester/cve/${encodeURIComponent(cveId)}`)
      const data = await res.json()
      setCveCache(prev => ({ ...prev, [cveId]: res.ok ? data : 'error' }))
    } catch {
      setCveCache(prev => ({ ...prev, [cveId]: 'error' }))
    }
  }

  const sevCounts = vulns.reduce((acc, v) => {
    const s = normSev(v)
    acc[s] = (acc[s] ?? 0) + 1
    return acc
  }, {})

  const filtered = vulns.filter(v => {
    if (sevFilter && normSev(v) !== sevFilter) return false
    if (search) {
      const q = search.toLowerCase()
      const blob = [v.name, v.description, v.remediation, v.category, v.cve]
        .filter(Boolean).join(' ').toLowerCase()
      if (!blob.includes(q)) return false
    }
    return true
  })

  function expandAll()   { setExpanded(new Set(filtered.map((_, i) => i))) }
  function collapseAll() { setExpanded(new Set()) }

  return (
    <div className={`card detail-panel detail-${variant}`}>

      {/* ── Header ── */}
      <div className="detail-header">
        <div className="detail-header-info">
          <div className="detail-domain">
            {scan.domain}
            {scan.target_ip && scan.target_ip !== scan.domain && (
              <span className="detail-target-ip">{scan.target_ip}</span>
            )}
          </div>
          <div className="detail-date">
            {scan.scanned_at ? new Date(scan.scanned_at).toLocaleString() : '—'}
            &nbsp;&middot;&nbsp;{vulns.length} finding{vulns.length !== 1 ? 's' : ''}
            {scan.scan_duration_seconds != null && <>&nbsp;&middot;&nbsp;{scan.scan_duration_seconds}s</>}
          </div>
          {scanOpts && (
            <div className="detail-scan-opts">
              {scanOpts.wordlist        && <span className="scan-opt-pill">{scanOpts.wordlist}</span>}
              {scanOpts.model           && <span className="scan-opt-pill">{scanOpts.model}</span>}
              {scanOpts.engagement_ref  && <span className="scan-opt-pill">ref: {scanOpts.engagement_ref}</span>}
              {scanOpts.fast            && <span className="scan-opt-pill">fast mode</span>}
              {scanOpts.exploit         && <span className="scan-opt-pill scan-opt-exploit">exploit mode</span>}
            </div>
          )}
        </div>
        <div className="detail-header-actions">
          {scan.id && (
            <>
              <a className="export-btn" href={`/pentester/scans/${scan.id}/export?format=csv`} download title="Download findings as CSV">CSV</a>
              <a className="export-btn" href={`/pentester/scans/${scan.id}/export?format=markdown`} download title="Download full report">Report ↓</a>
              {isAdmin && (
                <button className="delete-scan-btn" onClick={deleteScan} title="Permanently delete this scan">Delete</button>
              )}
            </>
          )}
          <button className="detail-close" onClick={onClose} title="Close (Esc)">&#x2715;</button>
        </div>
      </div>

      {/* ── Tabs ── */}
      <div className="detail-tabs">
        <button className={`detail-tab${tab === 'findings' ? ' active' : ''}`} onClick={() => setTab('findings')}>
          Findings <span className="detail-tab-count">{vulns.length}</span>
        </button>
        {scan.recon && (
          <button className={`detail-tab${tab === 'recon' ? ' active' : ''}`} onClick={() => setTab('recon')}>Recon</button>
        )}
        {networkData && (
          <button className={`detail-tab${tab === 'network' ? ' active' : ''}`} onClick={() => setTab('network')}>
            Network <span className="detail-tab-count">{networkData.live_count ?? networkData.hosts?.length ?? ''}</span>
          </button>
        )}
        {probesData && (
          <button className={`detail-tab${tab === 'probes' ? ' active' : ''}`} onClick={() => setTab('probes')}>
            Probes <span className="detail-tab-count">{probesData.length}</span>
          </button>
        )}
        {msfData && (
          <button className={`detail-tab${tab === 'msf' ? ' active' : ''}`} onClick={() => setTab('msf')}>MSF</button>
        )}
        {attackChains && (
          <button className={`detail-tab${tab === 'chains' ? ' active' : ''}`} onClick={() => setTab('chains')}>
            Chains <span className="detail-tab-count">{attackChains.length}</span>
          </button>
        )}
        <button className={`detail-tab${tab === 'report' ? ' active' : ''}`} onClick={() => setTab('report')}>Report</button>
      </div>

      {/* ── Findings ── */}
      {tab === 'findings' && (
        <>
          {scan.status === 'running' && (
            <div className="scan-running-banner">
              <span className="scan-running-pulse" />
              Scan in progress — findings appear as they are confirmed
              {vulns.length > 0 && <span className="scan-running-count">{vulns.length} so far</span>}
            </div>
          )}
          <div className="detail-toolbar">
            <input
              className="detail-search"
              type="text"
              placeholder="Search findings..."
              value={search}
              onChange={e => setSearch(e.target.value)}
            />
            <div className="detail-sev-pills">
              {['critical', 'high', 'medium', 'low', 'info'].map(s => {
                const c = sevCounts[s] ?? 0
                if (c === 0) return null
                return (
                  <button
                    key={s}
                    className={`sev-pill sev-pill-${s}${sevFilter === s ? ' active' : ''}`}
                    onClick={() => setSevFilter(sevFilter === s ? null : s)}
                  >
                    {s} <span className="sev-pill-count">{c}</span>
                  </button>
                )
              })}
              {(sevFilter || search) && (
                <button className="sev-pill-clear" onClick={() => { setSevFilter(null); setSearch('') }}>Clear</button>
              )}
            </div>
            <div className="detail-toolbar-actions">
              <button className="detail-link" onClick={expandAll}>Expand all</button>
              <span className="detail-link-sep">·</span>
              <button className="detail-link" onClick={collapseAll}>Collapse all</button>
            </div>
          </div>

          <div className="detail-vulns">
            {filtered.length === 0 && (
              <div className="detail-empty">
                {vulns.length === 0 ? 'No findings recorded for this scan.' : 'No findings match the current filter.'}
              </div>
            )}
            {filtered.map((v, i) => {
              const sortedIdx = vulns.indexOf(v)
              return (
                <div key={i} className={`vuln-item vuln-${normSev(v)}`} onClick={() => toggle(i)}>
                  <div className="vuln-row">
                    <span className={`badge badge-${normSev(v)}`}>{v.severity ?? 'info'}</span>
                    <span className="vuln-name">{v.name}</span>
                    <div className="vuln-tags">
                      {v.status && v.status !== 'new' && (
                        <span className={`badge badge-${v.status}`}>{STATUS_LABELS[v.status]}</span>
                      )}
                      {cat(v) && <span className="vuln-tag">{cat(v)}</span>}
                      {v.cve  && <span className="vuln-tag vuln-cve">{v.cve}</span>}
                      {v.cvss && <span className="vuln-tag vuln-cvss">CVSS {v.cvss}</span>}
                    </div>
                    <span className="vuln-chevron">{expanded.has(i) ? '▲' : '▼'}</span>
                  </div>
                  {expanded.has(i) && (
                    <div className="vuln-body" onClick={e => e.stopPropagation()}>
                      {v.description && (
                        <div className="vuln-section">
                          <div className="vuln-section-label">Description</div>
                          <p className="vuln-section-text">{v.description}</p>
                        </div>
                      )}
                      {rem(v) && (
                        <div className="vuln-section">
                          <div className="vuln-section-label">Remediation</div>
                          <p className="vuln-section-text">{rem(v)}</p>
                        </div>
                      )}
                      {hint(v) && (
                        <div className="vuln-section">
                          <div className="vuln-section-label">Exploit hint</div>
                          <p className="vuln-section-text">{hint(v)}</p>
                        </div>
                      )}
                      {v.validation_command && (
                        <div className="vuln-section vuln-section-validation">
                          <div className="vuln-section-label">
                            Validation probe
                            <span className={`validation-badge validation-badge-${v.confirmed === 'YES' ? 'confirmed' : v.confirmed === 'NO' ? 'denied' : 'unknown'}`}>
                              {v.confirmed === 'YES' ? 'CONFIRMED' : v.confirmed === 'NO' ? 'NOT CONFIRMED' : v.confirmed}
                            </span>
                          </div>
                          <pre className="vuln-validation-cmd">{v.validation_command}</pre>
                          {v.validation_output && (
                            <pre className="vuln-validation-out">{v.validation_output}</pre>
                          )}
                        </div>
                      )}
                      {v.cve && <CveDetail cveId={v.cve} cveCache={cveCache} onFetch={fetchCve} />}
                      <div className="vuln-section vuln-status-section">
                        <div className="vuln-section-label">Status</div>
                        <div className="status-btns">
                          {Object.entries(STATUS_LABELS).map(([val, label]) => (
                            <button
                              key={val}
                              className={`status-btn status-btn-${val}${(v.status ?? 'new') === val ? ' active' : ''}`}
                              onClick={() => updateStatus(sortedIdx, val)}
                            >
                              {label}
                            </button>
                          ))}
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </>
      )}

      {/* ── Recon ── */}
      {tab === 'recon' && (
        <div className="detail-recon">
          {scan.recon && (
            <div className="recon-summary-card">
              <div className="recon-card-header">
                <span className="recon-card-title">AI Recon Summary</span>
                <span className="recon-card-domain">{scan.domain}</span>
              </div>
              <div className="recon-card-body">
                <ReactMarkdown remarkPlugins={[remarkGfm]}>{scan.recon}</ReactMarkdown>
              </div>
            </div>
          )}
          {scan.raw_recon && typeof scan.raw_recon === 'object' && Object.keys(scan.raw_recon).length > 0 && (
            <div className="recon-raw-section">
              <div className="recon-group-label">Recon Checks</div>
              {Object.entries(scan.raw_recon).map(([name, output]) => (
                <ReconCheck key={name} name={name} output={output} />
              ))}
            </div>
          )}
          {scan.raw_scan && typeof scan.raw_scan === 'object' && Object.keys(scan.raw_scan).length > 0 && (
            <div className="recon-raw-section">
              <div className="recon-group-label">Network Scan</div>
              {Object.entries(scan.raw_scan).map(([name, output]) => (
                <ReconCheck key={name} name={name} output={output} />
              ))}
            </div>
          )}
          {scan.raw_webapp && typeof scan.raw_webapp === 'object' && Object.keys(scan.raw_webapp).length > 0 && (
            <div className="recon-raw-section">
              <div className="recon-group-label">Web App Checks</div>
              {Object.entries(scan.raw_webapp).map(([name, output]) => (
                <ReconCheck key={name} name={name} output={output} />
              ))}
            </div>
          )}
          {!scan.recon && (!scan.raw_recon || Object.keys(scan.raw_recon ?? {}).length === 0) &&
           (!scan.raw_scan || Object.keys(scan.raw_scan ?? {}).length === 0) &&
           (!scan.raw_webapp || Object.keys(scan.raw_webapp ?? {}).length === 0) && (
            <div className="detail-empty">No recon data available.</div>
          )}
        </div>
      )}

      {/* ── Network ── */}
      {tab === 'network' && networkData && (
        <div className="detail-network">
          <div className="network-meta-bar">
            <span className="network-meta-chip"><span className="nmc-label">Network</span>{networkData.network ?? '—'}</span>
            <span className="network-meta-chip"><span className="nmc-label">Target</span>{networkData.target_ip ?? scan.target_ip ?? '—'}</span>
            <span className="network-meta-chip"><span className="nmc-label">Live hosts</span>{networkData.live_count ?? networkData.hosts?.length ?? '—'}</span>
          </div>
          <div className="network-hosts">
            {(networkData.hosts ?? []).map((host, i) => {
              const isTarget = host.ip === networkData.target_ip
              return (
                <div key={i} className={`host-card${isTarget ? ' host-target' : ''}`}>
                  <div className="host-header">
                    <span className="host-ip">{host.ip}</span>
                    {host.hostname && <span className="host-name">{host.hostname}</span>}
                    {isTarget && <span className="host-target-badge">TARGET</span>}
                  </div>
                  {host.open_ports?.length > 0 ? (
                    <div className="host-ports">
                      <div className="ports-head"><span>Port</span><span>Service</span><span>Product</span></div>
                      {host.open_ports.map((p, j) => (
                        <div key={j} className="port-row">
                          <span className="port-num">{p.port}</span>
                          <span className="port-service">{p.service || '—'}</span>
                          <span className="port-product">{p.product || '—'}{p.version ? ` ${p.version}` : ''}</span>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="host-no-ports">No open ports detected</div>
                  )}
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* ── Probes ── */}
      {tab === 'probes' && (
        <div className="detail-probes">
          {(!probesData || probesData.length === 0)
            ? <div className="detail-empty">No probe data available.</div>
            : probesData.map((probe, i) => <ProbeResult key={i} probe={probe} />)
          }
        </div>
      )}

      {/* ── MSF ── */}
      {tab === 'msf' && (
        <div className="detail-msf">
          {!msfData ? (
            <div className="detail-empty">No Metasploit data available.</div>
          ) : (
            <>
              {msfData.suggestions && (
                <div className="msf-section">
                  <div className="msf-section-label">Suggested Modules</div>
                  <div className="msf-modules">
                    {(Array.isArray(msfData.suggestions) ? msfData.suggestions : [msfData.suggestions]).map((m, i) => (
                      <div key={i} className="msf-module">
                        <span className="msf-module-name">
                          {typeof m === 'string' ? m : (m.module ?? m.name ?? JSON.stringify(m))}
                        </span>
                        {m.description && <span className="msf-module-desc">{m.description}</span>}
                      </div>
                    ))}
                  </div>
                </div>
              )}
              {msfData.auxiliary && (
                <div className="msf-section">
                  <div className="msf-section-label">Auxiliary Scanner Output</div>
                  <pre className="msf-output">
                    {typeof msfData.auxiliary === 'string' ? msfData.auxiliary : JSON.stringify(msfData.auxiliary, null, 2)}
                  </pre>
                </div>
              )}
              {!msfData.suggestions && !msfData.auxiliary && (
                <pre className="msf-output">{JSON.stringify(msfData, null, 2)}</pre>
              )}
            </>
          )}
        </div>
      )}

      {/* ── Attack Chains ── */}
      {tab === 'chains' && (
        <div className="detail-chains">
          {(!attackChains || attackChains.length === 0) ? (
            <div className="detail-empty">No attack chains available.</div>
          ) : attackChains.map((chain, i) => {
            const steps = Array.isArray(chain.steps) ? chain.steps : null
            const hasKnownFields = chain.description || steps || chain.impact
            return (
              <div key={i} className="chain-card">
                <div className="chain-header">
                  <span className="chain-title">{chain.title ?? chain.name ?? `Chain ${i + 1}`}</span>
                  {chain.severity && (
                    <span className={`badge badge-${(chain.severity ?? '').toLowerCase()}`}>{chain.severity}</span>
                  )}
                </div>
                {chain.description && <p className="chain-desc">{chain.description}</p>}
                {steps && (
                  <div className="chain-steps">
                    {steps.map((step, j) => (
                      <div key={j} className="chain-step">
                        <span className="step-num">{j + 1}</span>
                        <span className="step-text">
                          {typeof step === 'string' ? step : (step.action ?? step.description ?? step.step ?? JSON.stringify(step))}
                        </span>
                      </div>
                    ))}
                  </div>
                )}
                {chain.impact && (
                  <p className="chain-meta"><strong>Impact:</strong> {chain.impact}</p>
                )}
                {chain.prerequisites && (
                  <p className="chain-meta"><strong>Prerequisites:</strong>{' '}
                    {Array.isArray(chain.prerequisites) ? chain.prerequisites.join(', ') : chain.prerequisites}
                  </p>
                )}
                {!hasKnownFields && (
                  <pre className="chain-raw">{JSON.stringify(chain, null, 2)}</pre>
                )}
              </div>
            )
          })}
        </div>
      )}

      {/* ── Report ── */}
      {tab === 'report' && (
        <div className="detail-report">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>
            {scan.scan_summary || '_No report was generated for this scan._'}
          </ReactMarkdown>
        </div>
      )}

    </div>
  )
}

export function ScanDetailModal({ scan, onClose, onDelete }) {
  useEffect(() => {
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = prev }
  }, [])

  return (
    <div className="scan-modal-overlay" onClick={onClose}>
      <div className="scan-modal-shell" onClick={e => e.stopPropagation()}>
        <ScanDetail scan={scan} onClose={onClose} onDelete={onDelete} variant="modal" />
      </div>
    </div>
  )
}
