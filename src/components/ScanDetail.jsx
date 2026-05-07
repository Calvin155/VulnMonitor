import { useState, useEffect, useRef } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useAuth } from '../auth/AuthContext'
import './ScanDetail.css'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'informational']

// network_scan is stored as a Python-style dict string — convert to JS object
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
const STATUS_LABELS = { new: 'New', reviewing: 'Reviewing', fixed: 'Fixed', fp: 'False Positive' }

function normSev(v) {
  return (v.severity ?? 'info').toLowerCase().replace('informational', 'info')
}

// Pentester writes `owasp` / `recommendation`; the legacy schema used `category` / `remediation`.
// Resolve either so the UI shows the data regardless of source.
const cat   = v => v.category    ?? v.owasp          ?? null
const rem   = v => v.remediation ?? v.recommendation ?? null
const hint  = v => v.exploit_hint ?? null

export default function ScanDetail({ scan, onClose, variant = 'panel' }) {
  const { apiFetch } = useAuth()
  const [tab, setTab] = useState('findings')
  const networkData = parsePyDict(scan.network_scan)
  const [expanded, setExpanded] = useState(new Set())
  const [search, setSearch] = useState('')
  const [sevFilter, setSevFilter] = useState(null)
  const [statusFilter, setStatusFilter] = useState(null)
  const [statusError, setStatusError] = useState(null)

  const [vulns, setVulns] = useState(() =>
    [...(scan.vulnerabilities ?? [])]
      .map((v, i) => ({ ...v, _origIdx: i }))
      .sort((a, b) => {
        const ai = SEV_ORDER.indexOf((a.severity ?? '').toLowerCase())
        const bi = SEV_ORDER.indexOf((b.severity ?? '').toLowerCase())
        return (ai === -1 ? 99 : ai) - (bi === -1 ? 99 : bi)
      })
  )
  const prevVulnLen = useRef(scan.vulnerabilities?.length ?? 0)

  // Merge in new findings when the parent refreshes the scan during a live run
  const vulnLen = scan.vulnerabilities?.length ?? 0
  useEffect(() => {
    if (vulnLen <= prevVulnLen.current) return
    prevVulnLen.current = vulnLen
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
  }, [vulnLen])

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

  const sevCounts = vulns.reduce((acc, v) => {
    const s = normSev(v)
    acc[s] = (acc[s] ?? 0) + 1
    return acc
  }, {})

  const filtered = vulns.filter(v => {
    if (sevFilter && normSev(v) !== sevFilter) return false
    if (statusFilter && (v.status ?? 'new') !== statusFilter) return false
    if (search) {
      const q = search.toLowerCase()
      const blob = [v.name, v.description, v.remediation, v.category, v.cve]
        .filter(Boolean).join(' ').toLowerCase()
      if (!blob.includes(q)) return false
    }
    return true
  })

  function expandAll() {
    setExpanded(new Set(filtered.map((_, i) => i)))
  }
  function collapseAll() {
    setExpanded(new Set())
  }

  return (
    <div className={`card detail-panel detail-${variant}`}>

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
            {scan.scan_duration_seconds != null && (
              <>&nbsp;&middot;&nbsp;{scan.scan_duration_seconds}s</>
            )}
          </div>
        </div>
        <button className="detail-close" onClick={onClose} title="Close (Esc)">&#x2715;</button>
      </div>

      <div className="detail-tabs">
        <button className={`detail-tab${tab === 'findings' ? ' active' : ''}`} onClick={() => setTab('findings')}>
          Findings <span className="detail-tab-count">{vulns.length}</span>
        </button>
        {networkData && (
          <button className={`detail-tab${tab === 'network' ? ' active' : ''}`} onClick={() => setTab('network')}>
            Network <span className="detail-tab-count">{networkData.live_count ?? (networkData.hosts?.length ?? '')}</span>
          </button>
        )}
        <button className={`detail-tab${tab === 'report' ? ' active' : ''}`} onClick={() => setTab('report')}>
          Report
        </button>
      </div>

      {tab === 'findings' && (
        <>
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
              {(sevFilter || statusFilter || search) && (
                <button className="sev-pill-clear" onClick={() => { setSevFilter(null); setStatusFilter(null); setSearch('') }}>
                  Clear
                </button>
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
                      {cat(v)  && <span className="vuln-tag">{cat(v)}</span>}
                      {v.cve   && <span className="vuln-tag vuln-cve">{v.cve}</span>}
                      {v.cvss  && <span className="vuln-tag vuln-cvss">CVSS {v.cvss}</span>}
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
                      <div className="ports-head">
                        <span>Port</span><span>Service</span><span>Product</span>
                      </div>
                      {host.open_ports.map((p, j) => (
                        <div key={j} className="port-row">
                          <span className="port-num">{p.port}</span>
                          <span className="port-service">{p.service || '—'}</span>
                          <span className="port-product">
                            {p.product || '—'}{p.version ? ` ${p.version}` : ''}
                          </span>
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

export function ScanDetailModal({ scan, onClose }) {
  useEffect(() => {
    const prev = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => { document.body.style.overflow = prev }
  }, [])

  return (
    <div className="scan-modal-overlay" onClick={onClose}>
      <div className="scan-modal-shell" onClick={e => e.stopPropagation()}>
        <ScanDetail scan={scan} onClose={onClose} variant="modal" />
      </div>
    </div>
  )
}
