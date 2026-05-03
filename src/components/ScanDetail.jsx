import { useState, useEffect } from 'react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import { useAuth } from '../auth/AuthContext'
import './ScanDetail.css'

const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'informational']
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
          <div className="detail-domain">{scan.domain}</div>
          <div className="detail-date">
            {new Date(scan.scanned_at).toLocaleString()} &middot; {vulns.length} finding{vulns.length !== 1 ? 's' : ''}
          </div>
        </div>
        <button className="detail-close" onClick={onClose} title="Close (Esc)">&#x2715;</button>
      </div>

      <div className="detail-tabs">
        <button className={`detail-tab${tab === 'findings' ? ' active' : ''}`} onClick={() => setTab('findings')}>
          Findings <span className="detail-tab-count">{vulns.length}</span>
        </button>
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
