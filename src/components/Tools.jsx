import { useState } from 'react'
import './Tools.css'

const enc = encodeURIComponent

const TOOLS = [
  { id: 'dns',        label: 'DNS Lookup',   param: 'Domain', placeholder: 'example.com',   url: (v) => `/pentester/tools/dns/${enc(v)}` },
  { id: 'whois',      label: 'WHOIS',        param: 'Domain', placeholder: 'example.com',   url: (v) => `/pentester/tools/whois/${enc(v)}` },
  { id: 'headers',    label: 'HTTP Headers', param: 'Domain', placeholder: 'example.com',   url: (v) => `/pentester/tools/headers/${enc(v)}` },
  { id: 'tls',        label: 'TLS / Cert',   param: 'Domain', placeholder: 'example.com',   url: (v) => `/pentester/tools/tls/${enc(v)}` },
  { id: 'subdomains', label: 'Subdomains',   param: 'Domain', placeholder: 'example.com',   url: (v) => `/pentester/tools/subdomains/${enc(v)}` },
  { id: 'cors',       label: 'CORS',         param: 'Domain', placeholder: 'example.com',   url: (v) => `/pentester/tools/cors/${enc(v)}` },
  { id: 'port',       label: 'Port Check',   param: 'Host',   placeholder: '10.0.0.1',      url: (v, p) => `/pentester/tools/port/${enc(v)}/${enc(p)}`, hasPort: true },
]

function renderResult(id, data) {
  if (!data || typeof data !== 'object') {
    return <pre className="tool-raw">{String(data)}</pre>
  }

  // DNS: object with record types as keys, or {records: {...}}
  if (id === 'dns') {
    const records = data.records ?? data
    if (typeof records === 'object' && !Array.isArray(records)) {
      const entries = Object.entries(records).filter(([, v]) => v && (Array.isArray(v) ? v.length > 0 : true))
      if (entries.length > 0) {
        return (
          <div className="tool-dns">
            {entries.map(([type, vals]) => (
              <div key={type} className="dns-row">
                <span className="dns-type">{type}</span>
                <div className="dns-vals">
                  {(Array.isArray(vals) ? vals : [vals]).map((v, i) => (
                    <span key={i} className="dns-val">{typeof v === 'object' ? JSON.stringify(v) : String(v)}</span>
                  ))}
                </div>
              </div>
            ))}
          </div>
        )
      }
    }
  }

  // Headers: object with header name keys, or {headers: {...}, grade: '...'}
  if (id === 'headers') {
    const grade = data.grade ?? data.score ?? null
    const headers = data.headers ?? data.present ?? data
    const missing = data.missing ?? []
    return (
      <div className="tool-headers">
        {grade != null && <div className="headers-grade">Grade: <strong>{grade}</strong></div>}
        {typeof headers === 'object' && !Array.isArray(headers) && (
          <div className="headers-list">
            {Object.entries(headers).map(([k, v]) => (
              <div key={k} className="header-row">
                <span className="header-name">{k}</span>
                <span className="header-val">{String(v)}</span>
              </div>
            ))}
          </div>
        )}
        {Array.isArray(missing) && missing.length > 0 && (
          <div className="headers-missing">
            <div className="headers-missing-label">Missing security headers</div>
            {missing.map((h, i) => <span key={i} className="missing-header">{h}</span>)}
          </div>
        )}
      </div>
    )
  }

  // TLS: cert info
  if (id === 'tls') {
    const cert = data.cert ?? data.certificate ?? data
    const fields = [
      ['Subject',    cert.subject    ?? cert.common_name ?? null],
      ['Issuer',     cert.issuer     ?? null],
      ['Valid from', cert.not_before ?? cert.valid_from  ?? null],
      ['Expires',    cert.not_after  ?? cert.valid_until ?? cert.expires ?? null],
      ['SANs',       Array.isArray(cert.san ?? cert.sans) ? (cert.san ?? cert.sans).join(', ') : null],
      ['Protocol',   data.protocol   ?? data.tls_version ?? null],
      ['Cipher',     data.cipher     ?? null],
    ].filter(([, v]) => v != null)
    if (fields.length > 0) {
      return (
        <div className="tool-tls">
          {fields.map(([label, val]) => (
            <div key={label} className="tls-row">
              <span className="tls-label">{label}</span>
              <span className="tls-val">{String(val)}</span>
            </div>
          ))}
        </div>
      )
    }
  }

  // Subdomains: array or {subdomains: [...]}
  if (id === 'subdomains') {
    const list = Array.isArray(data) ? data : (data.subdomains ?? data.domains ?? null)
    if (Array.isArray(list) && list.length > 0) {
      return (
        <div className="tool-subdomains">
          <div className="subdomains-count">{list.length} subdomain{list.length !== 1 ? 's' : ''} found</div>
          <div className="subdomains-list">
            {list.map((s, i) => (
              <span key={i} className="subdomain-item">{typeof s === 'string' ? s : JSON.stringify(s)}</span>
            ))}
          </div>
        </div>
      )
    }
  }

  // Port: open / closed
  if (id === 'port') {
    const open = data.open ?? data.reachable ?? null
    const service = data.service ?? data.banner ?? null
    return (
      <div className="tool-port">
        <div className={`port-status ${open ? 'port-open' : open === false ? 'port-closed' : ''}`}>
          {open === true ? 'Open' : open === false ? 'Closed / filtered' : 'Unknown'}
        </div>
        {service && <div className="port-service-info">{service}</div>}
        {Object.keys(data).length > 0 && <pre className="tool-raw tool-raw-sm">{JSON.stringify(data, null, 2)}</pre>}
      </div>
    )
  }

  // CORS: show policy
  if (id === 'cors') {
    const origin = data.access_control_allow_origin ?? data.allow_origin ?? data['Access-Control-Allow-Origin'] ?? null
    const methods = data.access_control_allow_methods ?? data['Access-Control-Allow-Methods'] ?? null
    const issues = data.issues ?? data.vulnerabilities ?? []
    return (
      <div className="tool-cors">
        {origin   && <div className="cors-row"><span className="cors-label">Allow-Origin</span><span className="cors-val">{String(origin)}</span></div>}
        {methods  && <div className="cors-row"><span className="cors-label">Allow-Methods</span><span className="cors-val">{String(methods)}</span></div>}
        {Array.isArray(issues) && issues.length > 0 && (
          <div className="cors-issues">
            {issues.map((iss, i) => <div key={i} className="cors-issue">{typeof iss === 'string' ? iss : JSON.stringify(iss)}</div>)}
          </div>
        )}
        <pre className="tool-raw tool-raw-sm">{JSON.stringify(data, null, 2)}</pre>
      </div>
    )
  }

  // WHOIS
  if (id === 'whois') {
    const rows = [
      ['Registrar',    data.registrar],
      ['Organisation', data.org],
      ['Country',      data.country],
      ['Created',      Array.isArray(data.creation_date)  ? data.creation_date[0]  : data.creation_date],
      ['Expires',      Array.isArray(data.expiration_date) ? data.expiration_date[0] : data.expiration_date],
      ['Updated',      Array.isArray(data.updated_date)   ? data.updated_date[0]   : data.updated_date],
      ['DNSSEC',       data.dnssec],
    ].filter(([, v]) => v)
    const ns = Array.isArray(data.name_servers) ? data.name_servers : []
    const status = Array.isArray(data.status) ? [...new Set(data.status.map(s => s.split(' ')[0]))] : []
    return (
      <div className="tool-whois">
        {rows.map(([label, val]) => (
          <div key={label} className="whois-row">
            <span className="whois-label">{label}</span>
            <span className="whois-val">{String(val)}</span>
          </div>
        ))}
        {ns.length > 0 && (
          <div className="whois-row">
            <span className="whois-label">Nameservers</span>
            <div className="whois-ns">{ns.map((n, i) => <span key={i} className="whois-ns-item">{n}</span>)}</div>
          </div>
        )}
        {status.length > 0 && (
          <div className="whois-row">
            <span className="whois-label">Status</span>
            <div className="whois-ns">{status.map((s, i) => <span key={i} className="whois-ns-item">{s}</span>)}</div>
          </div>
        )}
      </div>
    )
  }

  // Generic fallback
  return <pre className="tool-raw">{JSON.stringify(data, null, 2)}</pre>
}

export default function Tools() {
  const [activeTool, setActiveTool] = useState(TOOLS[0].id)
  const [query, setQuery]           = useState('')
  const [port,  setPort]            = useState('80')
  const [loading, setLoading]       = useState(false)
  const [result, setResult]         = useState(null)
  const [error,  setError]          = useState(null)

  const tool = TOOLS.find(t => t.id === activeTool)

  function selectTool(id) {
    setActiveTool(id)
    setResult(null)
    setError(null)
  }

  async function runTool() {
    if (!query.trim() || loading) return
    setLoading(true)
    setResult(null)
    setError(null)
    try {
      const url = tool.hasPort ? tool.url(query.trim(), port.trim() || '80') : tool.url(query.trim())
      const res = await fetch(url)
      const data = await res.json().catch(() => res.text())
      if (!res.ok) {
        setError(typeof data === 'string' ? data : (data?.detail ?? data?.error ?? `HTTP ${res.status}`))
      } else {
        setResult(data)
      }
    } catch (err) {
      setError(err.message)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="tools-page">
      {/* Sidebar */}
      <div className="tools-sidebar">
        <div className="tools-sidebar-title">Security Tools</div>
        {TOOLS.map(t => (
          <button
            key={t.id}
            className={`tools-nav-btn${activeTool === t.id ? ' active' : ''}`}
            onClick={() => selectTool(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Panel */}
      <div className="tools-panel">
        <div className="card tools-card">
          <div className="tools-card-title">{tool.label}</div>

          <div className="tools-form">
            <div className="tools-input-row">
              <label className="tools-label">{tool.param}</label>
              <input
                className="tools-input"
                type="text"
                placeholder={tool.placeholder}
                value={query}
                onChange={e => setQuery(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && runTool()}
              />
              {tool.hasPort && (
                <>
                  <label className="tools-label tools-label-port">Port</label>
                  <input
                    className="tools-input tools-input-port"
                    type="text"
                    placeholder="80"
                    value={port}
                    onChange={e => setPort(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && runTool()}
                  />
                </>
              )}
              <button
                className="tools-run-btn"
                onClick={runTool}
                disabled={loading || !query.trim()}
              >
                {loading ? <ToolSpinner /> : 'Run'}
              </button>
            </div>
          </div>

          <div className="tools-results">
            {!result && !error && !loading && (
              <div className="tools-idle">
                Enter a {tool.param.toLowerCase()} above and click Run.
              </div>
            )}
            {loading && (
              <div className="tools-loading">
                <ToolSpinner /> Running {tool.label}...
              </div>
            )}
            {error && (
              <div className="tools-error">{error}</div>
            )}
            {result !== null && !loading && (
              <div className="tools-result-body">
                {renderResult(activeTool, result)}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function ToolSpinner() {
  return (
    <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2.5" className="spinner">
      <path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/>
    </svg>
  )
}
