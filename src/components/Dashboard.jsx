import { Fragment, useState, useEffect, useMemo } from 'react'
import { ScanDetailModal } from './ScanDetail'
import { useAuth } from '../auth/AuthContext'
import './Dashboard.css'


const SEV_ORDER = ['critical', 'high', 'medium', 'low', 'info']
const SEV_COLORS = {
  critical: '#ff4757',
  high:     '#ff7c43',
  medium:   '#ffd166',
  low:      '#06d6a0',
  info:     '#4cc9f0',
}

function normalize(sev) {
  const s = (sev || '').toLowerCase()
  if (s === 'informational') return 'info'
  return s
}

function useApi(url, apiFetch) {
  const [data, setData]     = useState(null)
  const [loading, setLoading] = useState(true)
  const [error, setError]   = useState(null)

  useEffect(() => {
    let cancelled = false
    setLoading(true)
    apiFetch(url)
      .then(r => {
        if (!r.ok) throw new Error(`HTTP ${r.status}`)
        return r.json()
      })
      .then(d => { if (!cancelled) { setData(d); setLoading(false) } })
      .catch(e => { if (!cancelled) { setError(e.message); setData(null); setLoading(false) } })
    return () => { cancelled = true }
  }, [url, apiFetch])

  return { data, loading, error }
}

function DonutChart({ stats, activeSev, onSelect }) {
  const total = stats?.total_vulns ?? 0
  const r = 52
  const circ = 2 * Math.PI * r

  const segments = SEV_ORDER.map(s => ({
    key: s,
    value: stats?.[s] ?? 0,
    color: SEV_COLORS[s],
  })).filter(s => s.value > 0)

  let offset = 0
  const rendered = segments.map(seg => {
    const length = (seg.value / total) * circ
    const s = { ...seg, length, offset }
    offset += length
    return s
  })

  return (
    <svg viewBox="0 0 130 130" className="donut-svg">
      <g transform="rotate(-90, 65, 65)">
        <circle cx={65} cy={65} r={r} fill="none" stroke="rgba(255,255,255,0.04)" strokeWidth={11} />
        {total === 0 ? (
          <circle cx={65} cy={65} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={11} />
        ) : rendered.map((seg, i) => {
          const dim = activeSev && activeSev !== seg.key
          return (
            <circle
              key={i}
              cx={65} cy={65} r={r}
              fill="none"
              stroke={seg.color}
              strokeWidth={activeSev === seg.key ? 14 : 11}
              strokeDasharray={`${seg.length} ${circ}`}
              strokeDashoffset={-seg.offset}
              strokeLinecap="butt"
              opacity={dim ? 0.25 : 1}
              style={{ cursor: 'pointer', transition: 'opacity 0.15s, stroke-width 0.15s' }}
              onClick={() => onSelect(seg.key)}
            >
              <title>{`${seg.key}: ${seg.value}`}</title>
            </circle>
          )
        })}
      </g>
      <text x="65" y="60" textAnchor="middle" fill="#e2e8f0" fontSize="20" fontWeight="600" fontFamily="JetBrains Mono, monospace">
        {activeSev ? (stats?.[activeSev] ?? 0) : total}
      </text>
      <text x="65" y="74" textAnchor="middle" fill="#8892a4" fontSize="8.5" fontFamily="Inter, sans-serif" letterSpacing="0.12em">
        {activeSev ? activeSev.toUpperCase() : 'FINDINGS'}
      </text>
    </svg>
  )
}

function SeverityDot({ sev }) {
  return <span className="sev-dot" style={{ background: SEV_COLORS[sev], boxShadow: `0 0 5px ${SEV_COLORS[sev]}` }} />
}

function timeAgo(ts) {
  const diff = Date.now() - new Date(ts).getTime()
  const m = Math.floor(diff / 60000)
  if (m < 1)  return 'just now'
  if (m < 60) return `${m}m ago`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}hr ago`
  return `${Math.floor(h / 24)}d ago`
}

function SortIcon({ dir }) {
  if (!dir) return <span className="sort-icon sort-idle">⇅</span>
  return <span className="sort-icon sort-active">{dir === 'asc' ? '↑' : '↓'}</span>
}

const SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3, info: 4, '': 5 }
const STATUS_RANK = { new: 0, reviewing: 1, fp: 2, fixed: 3, '': 4 }
const STATUS_LABELS = { new: 'New', reviewing: 'Reviewing', fixed: 'Fixed', fp: 'False Positive' }

function compareBy(a, b, key) {
  if (key === 'severity') {
    return (SEV_RANK[normalize(a.severity)] ?? 9) - (SEV_RANK[normalize(b.severity)] ?? 9)
  }
  if (key === 'status') {
    return (STATUS_RANK[a.status ?? 'new'] ?? 9) - (STATUS_RANK[b.status ?? 'new'] ?? 9)
  }
  if (key === 'discovered') {
    return new Date(a.scanned_at).getTime() - new Date(b.scanned_at).getTime()
  }
  const av = (a[key] ?? '').toString().toLowerCase()
  const bv = (b[key] ?? '').toString().toLowerCase()
  if (av < bv) return -1
  if (av > bv) return 1
  return 0
}

export default function Dashboard() {
  const { apiFetch, user } = useAuth()
  const { data: stats, loading: statsLoading }   = useApi('/api/stats', apiFetch)
  const { data: scans, loading: scansLoading }   = useApi('/api/scans', apiFetch)
  const { data: vulns, loading: vulnsLoading }   = useApi('/api/vulnerabilities', apiFetch)

  const loading = statsLoading || scansLoading || vulnsLoading

  const [sevFilter, setSevFilter]       = useState(null)
  const [search, setSearch]             = useState('')
  const [sort, setSort]                 = useState({ key: 'severity', dir: 'asc' })
  const [expandedRow, setExpandedRow]   = useState(null)
  const [selectedScan, setSelectedScan] = useState(null)
  const [loadingScan, setLoadingScan]   = useState(false)
  const [deletedIds, setDeletedIds]     = useState(() => new Set())

  // Listen for deletes that originate inside ScanDetail (from any page)
  useEffect(() => {
    function onDeleted(e) {
      setDeletedIds(prev => new Set([...prev, e.detail.id]))
    }
    window.addEventListener('vulnreview:scan-deleted', onDeleted)
    return () => window.removeEventListener('vulnreview:scan-deleted', onDeleted)
  }, [])
  // Local override layer so status changes from the inline pills reflect instantly
  // without re-fetching `/api/vulnerabilities`. Keyed by `${scan_id}:${idx}`.
  const [statusOverrides, setStatusOverrides] = useState({})

  function toggleSev(s) {
    setSevFilter(prev => prev === s ? null : s)
    setExpandedRow(null)
  }

  function toggleSort(key) {
    setSort(prev =>
      prev.key === key
        ? { key, dir: prev.dir === 'asc' ? 'desc' : 'asc' }
        : { key, dir: 'asc' }
    )
  }

  async function openScan(id) {
    if (!id) return
    setLoadingScan(true)
    try {
      const res = await apiFetch(`/api/scans/${id}`)
      const data = await res.json()
      if (res.ok) setSelectedScan(data)
    } catch {}
    setLoadingScan(false)
  }

  async function updateVulnStatus(v, status) {
    if (v.scan_id == null || v.vuln_idx == null) return
    const key = `${v.scan_id}:${v.vuln_idx}`
    const prevStatus = statusOverrides[key] ?? v.status ?? 'new'
    setStatusOverrides(prev => ({ ...prev, [key]: status }))
    try {
      const res = await apiFetch(`/api/scans/${v.scan_id}/vuln/${v.vuln_idx}`, {
        method: 'PATCH',
        body: JSON.stringify({ status }),
      })
      if (!res.ok) throw new Error()
    } catch {
      setStatusOverrides(prev => ({ ...prev, [key]: prevStatus }))
    }
  }

  function statusOf(v) {
    return statusOverrides[`${v.scan_id}:${v.vuln_idx}`] ?? v.status ?? 'new'
  }

  const filteredVulns = useMemo(() => {
    if (!Array.isArray(vulns)) return []
    const q = search.trim().toLowerCase()
    let list = vulns.filter(v => {
      if (sevFilter && normalize(v.severity) !== sevFilter) return false
      if (q) {
        const blob = [v.name, v.domain, v.category, v.cve, v.description, v.remediation]
          .filter(Boolean).join(' ').toLowerCase()
        if (!blob.includes(q)) return false
      }
      return true
    })
    list = [...list].sort((a, b) => {
      const cmp = compareBy(a, b, sort.key)
      return sort.dir === 'asc' ? cmp : -cmp
    })
    return list
  }, [vulns, sevFilter, search, sort])

  return (
    <div className="dashboard">

      <div className="dashboard-page-header">
        <div>
          <h1 className="dashboard-page-title">Welcome back, {user?.username}</h1>
          <p className="dashboard-page-sub">Your security posture at a glance.</p>
        </div>
      </div>

      {/* ── Stat Cards ── */}
      <div className="stats-row">
        <button
          className={`stat-card stat-total${sevFilter === null ? '' : ' stat-card-clickable'}`}
          onClick={() => setSevFilter(null)}
          title="Show all severities"
        >
          <div className="stat-label">Total Findings</div>
          <div className="stat-value" style={{ color: 'var(--accent)' }}>
            {loading ? '—' : (stats?.total_vulns ?? 0)}
          </div>
          <div className="stat-sub">
            {loading ? '...' : `${stats?.total_scans ?? 0} scans in database`}
          </div>
        </button>

        {SEV_ORDER.map(s => (
          <button
            key={s}
            className={`stat-card stat-card-clickable stat-${s}${sevFilter === s ? ' stat-active' : ''}`}
            onClick={() => toggleSev(s)}
            title={sevFilter === s ? 'Click to clear filter' : `Filter findings by ${s}`}
          >
            <div className="stat-label" style={{ textTransform: 'capitalize' }}>{s}</div>
            <div className="stat-value" style={{ color: SEV_COLORS[s] }}>
              {loading ? '—' : (stats?.[s] ?? 0)}
            </div>
            <div className="stat-bar-bg">
              <div
                className="stat-bar-fill"
                style={{
                  width: stats?.total_vulns
                    ? `${((stats[s] ?? 0) / stats.total_vulns) * 100}%`
                    : '0%',
                  background: SEV_COLORS[s],
                }}
              />
            </div>
          </button>
        ))}
      </div>

      {/* ── Middle Row ── */}
      <div className="mid-row">

        {/* Severity Chart */}
        <div className="card chart-card">
          <div className="card-title">Severity Breakdown</div>
          <div className="chart-body">
            <DonutChart stats={stats} activeSev={sevFilter} onSelect={toggleSev} />
            <div className="chart-legend">
              {SEV_ORDER.map(s => (
                <button
                  key={s}
                  className={`legend-row legend-row-clickable${sevFilter === s ? ' legend-row-active' : ''}`}
                  onClick={() => toggleSev(s)}
                >
                  <SeverityDot sev={s} />
                  <span className="legend-label" style={{ textTransform: 'capitalize' }}>{s}</span>
                  <span className="legend-count" style={{ color: SEV_COLORS[s] }}>
                    {loading ? '—' : (stats?.[s] ?? 0)}
                  </span>
                  <span className="legend-pct">
                    {(!loading && stats?.total_vulns > 0)
                      ? `${(((stats[s] ?? 0) / stats.total_vulns) * 100).toFixed(0)}%`
                      : '—'}
                  </span>
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Recent Scans */}
        <div className="card activity-card">
          <div className="card-title">Recent Scans</div>
          <div className="activity-list">
            {scansLoading && <div className="loading-msg">Loading...</div>}
            {!scansLoading && !Array.isArray(scans) && (
              <div className="empty-msg">API unavailable — is the Express server running?</div>
            )}
            {!scansLoading && Array.isArray(scans) && scans.length === 0 && (
              <div className="empty-msg">No scans yet.</div>
            )}
            {Array.isArray(scans) && scans.filter(s => !deletedIds.has(s.id)).map(scan => {
              const count = Number(scan.vuln_count)
              const topSev = scan.vulnerabilities?.reduce((top, v) => {
                const order = SEV_ORDER.indexOf(normalize(v.severity))
                const topOrder = SEV_ORDER.indexOf(top)
                return order !== -1 && (top === null || order < topOrder)
                  ? normalize(v.severity)
                  : top
              }, null)
              const type = topSev ?? (count > 0 ? 'info' : 'scan')

              return (
                <button
                  key={scan.id}
                  className={`activity-row activity-row-clickable activity-${type}`}
                  onClick={() => openScan(scan.id)}
                  title="Open scan detail"
                >
                  <div className="activity-line" />
                  <div className="activity-content">
                    <div className="activity-event">{scan.domain}</div>
                    <div className="activity-detail">
                      {count > 0 ? `${count} finding${count !== 1 ? 's' : ''}` : 'No findings'}
                      {topSev && <span className={`badge badge-${topSev} activity-sev-badge`}>{topSev}</span>}
                    </div>
                  </div>
                  <div className="activity-time">{timeAgo(scan.scanned_at)}</div>
                </button>
              )
            })}
          </div>
        </div>

      </div>

      {/* ── Findings Table ── */}
      <div className="card findings-card">
        <div className="findings-header">
          <div className="card-title findings-title">
            <span>All Findings</span>
            <span className="findings-count">
              {vulnsLoading
                ? '...'
                : (sevFilter || search)
                  ? `${filteredVulns.length} of ${Array.isArray(vulns) ? vulns.length : 0}`
                  : `${Array.isArray(vulns) ? vulns.length : 0} results`}
            </span>
          </div>
          <div className="findings-toolbar">
            <input
              className="findings-search"
              type="text"
              placeholder="Search findings, hosts, CVEs..."
              value={search}
              onChange={e => { setSearch(e.target.value); setExpandedRow(null) }}
            />
            {sevFilter && (
              <button className="filter-pill" onClick={() => setSevFilter(null)}>
                <SeverityDot sev={sevFilter} />
                <span style={{ textTransform: 'capitalize' }}>{sevFilter}</span>
                <span className="filter-pill-x">✕</span>
              </button>
            )}
          </div>
        </div>
        <div className="table-wrap">
          {vulnsLoading && <div className="loading-msg table-loading">Loading findings...</div>}
          {!vulnsLoading && !Array.isArray(vulns) && (
            <div className="empty-msg table-empty">Could not load findings — check the Express API.</div>
          )}
          {!vulnsLoading && Array.isArray(vulns) && vulns.length === 0 && (
            <div className="empty-msg table-empty">No findings recorded yet.</div>
          )}
          {!vulnsLoading && Array.isArray(vulns) && vulns.length > 0 && filteredVulns.length === 0 && (
            <div className="empty-msg table-empty">No findings match the current filter.</div>
          )}
          {filteredVulns.length > 0 && (
            <table className="findings-table">
              <thead>
                <tr>
                  <th className="th-sortable" onClick={() => toggleSort('severity')}>
                    Severity <SortIcon dir={sort.key === 'severity' ? sort.dir : null} />
                  </th>
                  <th className="th-sortable" onClick={() => toggleSort('status')}>
                    Status <SortIcon dir={sort.key === 'status' ? sort.dir : null} />
                  </th>
                  <th className="th-sortable" onClick={() => toggleSort('name')}>
                    Vulnerability <SortIcon dir={sort.key === 'name' ? sort.dir : null} />
                  </th>
                  <th className="th-sortable" onClick={() => toggleSort('domain')}>
                    Host <SortIcon dir={sort.key === 'domain' ? sort.dir : null} />
                  </th>
                  <th className="th-sortable" onClick={() => toggleSort('category')}>
                    Category <SortIcon dir={sort.key === 'category' ? sort.dir : null} />
                  </th>
                  <th className="th-sortable" onClick={() => toggleSort('cve')}>
                    CVE <SortIcon dir={sort.key === 'cve' ? sort.dir : null} />
                  </th>
                  <th className="th-sortable" onClick={() => toggleSort('discovered')}>
                    Discovered <SortIcon dir={sort.key === 'discovered' ? sort.dir : null} />
                  </th>
                </tr>
              </thead>
              <tbody>
                {filteredVulns.map((v, i) => {
                  const sev = normalize(v.severity)
                  const isExpanded = expandedRow === i
                  const status = statusOf(v)
                  const statusLabel = STATUS_LABELS[status] ?? status
                  return (
                    <Fragment key={i}>
                      <tr
                        className={`finding-row finding-row-clickable${isExpanded ? ' finding-row-expanded' : ''}`}
                        onClick={() => setExpandedRow(isExpanded ? null : i)}
                      >
                        <td><span className={`badge badge-${sev}`}>{sev || v.severity}</span></td>
                        <td>
                          <span className={`badge badge-${status}`}>{statusLabel}</span>
                        </td>
                        <td className="finding-name">
                          <span className="finding-name-text">{v.name}</span>
                          <span className="finding-chevron">{isExpanded ? '▲' : '▼'}</span>
                        </td>
                        <td className="finding-host">{v.domain}</td>
                        <td>
                          {v.category
                            ? <span className="category-tag">{v.category}</span>
                            : <span className="text-muted">—</span>
                          }
                        </td>
                        <td className="finding-host">{v.cve || '—'}</td>
                        <td className="finding-time">{timeAgo(v.scanned_at)}</td>
                      </tr>
                      {isExpanded && (
                        <tr className="finding-detail-row">
                          <td colSpan={7}>
                            <div className="finding-detail" onClick={e => e.stopPropagation()}>
                              {v.description && (
                                <div className="finding-detail-section">
                                  <div className="finding-detail-label">Description</div>
                                  <p className="finding-detail-text">{v.description}</p>
                                </div>
                              )}
                              {v.remediation && (
                                <div className="finding-detail-section">
                                  <div className="finding-detail-label">Remediation</div>
                                  <p className="finding-detail-text">{v.remediation}</p>
                                </div>
                              )}
                              {v.exploit_hint && (
                                <div className="finding-detail-section">
                                  <div className="finding-detail-label">Exploit hint</div>
                                  <p className="finding-detail-text">{v.exploit_hint}</p>
                                </div>
                              )}

                              <div className="finding-detail-section">
                                <div className="finding-detail-label">Status</div>
                                <div className="status-btns">
                                  {Object.entries(STATUS_LABELS).map(([val, label]) => (
                                    <button
                                      key={val}
                                      className={`status-btn status-btn-${val}${status === val ? ' active' : ''}`}
                                      onClick={() => updateVulnStatus(v, val)}
                                    >
                                      {label}
                                    </button>
                                  ))}
                                </div>
                              </div>

                              <div className="finding-detail-meta">
                                {v.cvss && (
                                  <span className="finding-meta-item">
                                    <span className="finding-meta-label">CVSS</span>
                                    <span className="finding-meta-value">{v.cvss}</span>
                                  </span>
                                )}
                                {v.scan_id && (
                                  <button
                                    className="finding-detail-link"
                                    onClick={e => { e.stopPropagation(); openScan(v.scan_id) }}
                                  >
                                    Open full scan →
                                  </button>
                                )}
                              </div>
                            </div>
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {loadingScan && (
        <div className="scan-modal-overlay">
          <div className="scan-modal-loading">Loading scan...</div>
        </div>
      )}
      {selectedScan && (
        <ScanDetailModal
          scan={selectedScan}
          onClose={() => setSelectedScan(null)}
          onDelete={id => {
            setDeletedIds(prev => new Set([...prev, id]))
            setSelectedScan(null)
          }}
        />
      )}

    </div>
  )
}
