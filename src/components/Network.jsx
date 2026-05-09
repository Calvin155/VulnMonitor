import { useState, useEffect, useRef } from 'react'
import './Network.css'

function timeNow() {
  return new Date().toLocaleTimeString()
}

export default function Network() {
  const [cidr, setCidr]         = useState('')
  const [scanning, setScanning] = useState(false)
  const [result, setResult]     = useState(null)
  const [error, setError]       = useState(null)
  const [scannedAt, setScannedAt] = useState(null)
  const [filter, setFilter]     = useState('')

  // Passive scan state
  const [passiveDuration, setPassiveDuration] = useState('30')
  const [passiveIface, setPassiveIface]       = useState('')
  const [passiveScanning, setPassiveScanning] = useState(false)
  const [passiveResult, setPassiveResult]     = useState(null)
  const [passiveError, setPassiveError]       = useState(null)
  const [passiveAt, setPassiveAt]             = useState(null)
  const [passiveCountdown, setPassiveCountdown] = useState(0)
  const countdownRef = useRef(null)

  useEffect(() => {
    return () => clearInterval(countdownRef.current)
  }, [])

  async function runScan() {
    if (scanning) return
    setScanning(true)
    setError(null)
    try {
      const url = cidr.trim()
        ? `/pentester/network/scan?cidr=${encodeURIComponent(cidr.trim())}`
        : '/pentester/network/scan'
      const res = await fetch(url)
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        throw new Error(data.detail || data.error || `HTTP ${res.status}`)
      }
      setResult(data)
      setScannedAt(timeNow())
    } catch (err) {
      setError(err.message)
    } finally {
      setScanning(false)
    }
  }

  async function runPassiveScan() {
    if (passiveScanning) return
    const dur = Math.max(5, Math.min(120, parseInt(passiveDuration, 10) || 30))
    setPassiveDuration(String(dur))
    setPassiveScanning(true)
    setPassiveError(null)
    setPassiveCountdown(dur)

    countdownRef.current = setInterval(() => {
      setPassiveCountdown(c => {
        if (c <= 1) { clearInterval(countdownRef.current); return 0 }
        return c - 1
      })
    }, 1000)

    try {
      const params = new URLSearchParams({ duration: dur })
      if (passiveIface.trim()) params.set('interface', passiveIface.trim())
      const res = await fetch(`/pentester/network/passive?${params}`)
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        throw new Error(data.detail || data.error || `HTTP ${res.status}`)
      }
      if (data.error) throw new Error(data.error)
      setPassiveResult(data)
      setPassiveAt(timeNow())
    } catch (err) {
      setPassiveError(err.message)
    } finally {
      clearInterval(countdownRef.current)
      setPassiveScanning(false)
      setPassiveCountdown(0)
    }
  }

  const hosts = Array.isArray(result?.hosts) ? result.hosts : []
  const filteredHosts = filter.trim()
    ? hosts.filter(h => {
        const q = filter.trim().toLowerCase()
        return [h.ip, h.hostname, h.mac, h.vendor]
          .filter(Boolean).join(' ').toLowerCase().includes(q)
      })
    : hosts

  const passiveHosts = Array.isArray(passiveResult?.hosts) ? passiveResult.hosts : []

  function copyTarget(value) {
    if (!value) return
    navigator.clipboard?.writeText(value).catch(() => {})
  }

  return (
    <div className="network">

      <div className="card network-card">
        <div className="card-title network-title">
          <span>Network Scan</span>
          {scannedAt && (
            <span className="network-meta">last scan {scannedAt}</span>
          )}
        </div>

        <p className="network-desc">
          Ping-sweep (<code>nmap -sn</code>) the local network to enumerate live IPs,
          hostnames, and (when reachable at L2) MAC + vendor.
        </p>

        <div className="network-controls">
          <div className="form-field network-cidr-field">
            <label className="field-label">CIDR <span className="field-optional">(optional)</span></label>
            <input
              className="field-input"
              type="text"
              placeholder="192.168.1.0/24 — leave blank to use container's primary /24"
              value={cidr}
              onChange={e => setCidr(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && runScan()}
            />
          </div>
          <button
            className={`run-btn ${scanning ? 'running' : ''}`}
            onClick={runScan}
            disabled={scanning}
          >
            {scanning ? 'Scanning...' : 'Scan network'}
          </button>
        </div>

        {error && <div className="network-error">Error: {error}</div>}

        {!result && !scanning && !error && (
          <div className="network-hint">
            <strong>Heads-up:</strong> the pentester runs inside Docker, so by default
            it sweeps its bridge network — not your real LAN. To scan the host
            network you need to run the container with <code>--network host</code>{' '}
            (or have it joined to the same L2). The scanner returns whatever
            subnet it can actually see.
          </div>
        )}
      </div>

      {(scanning || result) && (
        <div className="card network-results-card">
          <div className="card-title">
            <span>
              {scanning
                ? 'Scanning...'
                : `Hosts on ${result?.cidr ?? 'network'}`}
            </span>
            {result && (
              <span className="network-count">
                {result.host_count ?? hosts.length} live
              </span>
            )}
          </div>

          {result && hosts.length > 0 && (
            <input
              className="network-filter"
              type="text"
              placeholder="Filter by IP, hostname, MAC, vendor..."
              value={filter}
              onChange={e => setFilter(e.target.value)}
            />
          )}

          {scanning && (
            <div className="network-empty">Sweeping {cidr.trim() || 'default subnet'}...</div>
          )}

          {!scanning && hosts.length === 0 && (
            <div className="network-empty">No live hosts found on {result?.cidr ?? 'the network'}.</div>
          )}

          {!scanning && filteredHosts.length === 0 && hosts.length > 0 && (
            <div className="network-empty">No hosts match the filter.</div>
          )}

          {filteredHosts.length > 0 && (
            <div className="network-table-wrap">
              <table className="network-table">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>MAC</th>
                    <th>Vendor</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {filteredHosts.map((h, i) => (
                    <tr key={`${h.ip}-${i}`}>
                      <td className="network-ip">
                        <span>{h.ip}</span>
                        <button
                          className="network-copy"
                          onClick={() => copyTarget(h.ip)}
                          title="Copy IP"
                        >
                          ⧉
                        </button>
                      </td>
                      <td>
                        {h.hostname
                          ? <span className="network-hostname">{h.hostname}</span>
                          : <span className="text-muted">—</span>}
                      </td>
                      <td className="network-mono">{h.mac || <span className="text-muted">—</span>}</td>
                      <td>{h.vendor || <span className="text-muted">—</span>}</td>
                      <td className="network-actions">
                        <a
                          className="network-action-link"
                          href={`#scan-${h.ip}`}
                          onClick={e => {
                            e.preventDefault()
                            window.dispatchEvent(new CustomEvent('vulnreview:request-scan', { detail: { target: h.ip } }))
                          }}
                          title="Pre-fill the Requests tab with this target"
                        >
                          Scan →
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

      {/* ── Passive scan (tshark) ─────────────────────────────── */}
      <div className="card network-card">
        <div className="card-title network-title">
          <span>Passive Discovery <span className="passive-badge">tshark</span></span>
          {passiveAt && (
            <span className="network-meta">last scan {passiveAt}</span>
          )}
        </div>

        <p className="network-desc">
          Zero-probe passive listener — captures <strong>mDNS</strong> (Bonjour/NSD) and{' '}
          <strong>DHCP</strong> broadcasts to find phones and IoT devices that ignore nmap
          pings. Requires the container to have <code>NET_RAW</code> capability and tshark
          installed.
        </p>

        <div className="network-controls passive-controls">
          <div className="form-field passive-dur-field">
            <label className="field-label">Listen duration <span className="field-optional">(seconds)</span></label>
            <input
              className="field-input"
              type="number"
              min="5"
              max="120"
              placeholder="30"
              value={passiveDuration}
              onChange={e => setPassiveDuration(e.target.value)}
              disabled={passiveScanning}
            />
          </div>
          <div className="form-field passive-iface-field">
            <label className="field-label">Interface <span className="field-optional">(optional)</span></label>
            <input
              className="field-input"
              type="text"
              placeholder="any — or eth0, wlan0, etc."
              value={passiveIface}
              onChange={e => setPassiveIface(e.target.value)}
              disabled={passiveScanning}
            />
          </div>
          <button
            className={`run-btn passive-btn ${passiveScanning ? 'running' : ''}`}
            onClick={runPassiveScan}
            disabled={passiveScanning}
          >
            {passiveScanning
              ? `Listening… ${passiveCountdown}s`
              : 'Start listening'}
          </button>
        </div>

        {passiveError && <div className="network-error">Error: {passiveError}</div>}
      </div>

      {(passiveScanning || passiveResult) && (
        <div className="card network-results-card">
          <div className="card-title">
            <span>
              {passiveScanning ? `Sniffing network traffic…` : `Passive hosts detected`}
            </span>
            {passiveResult && !passiveScanning && (
              <span className="network-count">{passiveResult.host_count ?? passiveHosts.length} found</span>
            )}
          </div>

          {passiveScanning && (
            <div className="passive-progress">
              <div
                className="passive-progress-bar"
                style={{ width: `${Math.round((1 - passiveCountdown / (parseInt(passiveDuration, 10) || 30)) * 100)}%` }}
              />
            </div>
          )}

          {passiveScanning && (
            <div className="network-empty">Capturing mDNS + DHCP — {passiveCountdown}s remaining…</div>
          )}

          {!passiveScanning && passiveHosts.length === 0 && (
            <div className="network-empty">No devices announced themselves during the listen window.</div>
          )}

          {!passiveScanning && passiveHosts.length > 0 && (
            <div className="network-table-wrap">
              <table className="network-table">
                <thead>
                  <tr>
                    <th>IP</th>
                    <th>Hostname</th>
                    <th>MAC</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {passiveHosts.map((h, i) => (
                    <tr key={`p-${h.ip}-${i}`}>
                      <td className="network-ip">
                        <span>{h.ip}</span>
                        <button
                          className="network-copy"
                          onClick={() => copyTarget(h.ip)}
                          title="Copy IP"
                        >
                          ⧉
                        </button>
                      </td>
                      <td>
                        {h.hostname
                          ? <span className="network-hostname">{h.hostname}</span>
                          : <span className="text-muted">—</span>}
                      </td>
                      <td className="network-mono">{h.mac || <span className="text-muted">—</span>}</td>
                      <td className="network-actions">
                        <a
                          className="network-action-link"
                          href={`#scan-${h.ip}`}
                          onClick={e => {
                            e.preventDefault()
                            window.dispatchEvent(new CustomEvent('vulnreview:request-scan', { detail: { target: h.ip } }))
                          }}
                          title="Pre-fill the Requests tab with this target"
                        >
                          Scan →
                        </a>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}

    </div>
  )
}
