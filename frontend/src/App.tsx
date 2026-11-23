import { useEffect, useMemo, useState } from 'react'
// import type { ReactNode } from 'react'
import {
  Activity,
  AlertOctagon,
  ArrowDownRight,
  ArrowUpRight,
  Bell,
  ChevronDown,
  ChevronRight,
  CircleHelp,
  Database,
  FileBarChart,
  FileSearch,
  LayoutDashboard,
  RefreshCw,
  Settings,
  Shield,
  ShieldAlert,
  X,
} from 'lucide-react'
import {
  Cell,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
} from 'recharts'
import { getAnalyses, type Analysis } from './services/api'

const navigation = [
  { label: 'Overview', icon: LayoutDashboard },
  { label: 'Alerts', icon: ShieldAlert },
  { label: 'Investigations', icon: FileSearch },
  { label: 'Datasets', icon: Database },
  { label: 'Reports', icon: FileBarChart },
]

const COLORS = ['#A34232', '#C28A3E', '#71877C']

function formatNumber(value?: number) {
  return (value ?? 0).toLocaleString('en-US')
}

function App() {
  const [analyses, setAnalyses] = useState<Analysis[]>([])
  const [loading, setLoading] = useState(true)
  const [error, setError] = useState('')
  const [activePage, setActivePage] = useState('Overview')
  const [sidebarOpen, setSidebarOpen] = useState(false)

  const loadAnalyses = async () => {
    try {
      setError('')
      const data = await getAnalyses()
      setAnalyses(data)
    } catch {
      setError('Unable to retrieve analysis data. Check that FastAPI is running.')
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    loadAnalyses()
  }, [])

  const latestAnalysis = useMemo(
    () => analyses.find(
      item => item.status === 'completed' && item.results
    ),
    [analyses]
  )

  const results = latestAnalysis?.results

  const severityData = [
    { name: 'Critical', value: results?.severity_distribution?.Critical ?? 0 },
    { name: 'High', value: results?.severity_distribution?.High ?? 0 },
    { name: 'Medium', value: results?.severity_distribution?.Medium ?? 0 },
  ]


  const totalAlerts = results?.alerts_generated ?? 0
  const critical = results?.severity_distribution?.Critical ?? 0
  const high = results?.severity_distribution?.High ?? 0
  const medium = results?.severity_distribution?.Medium ?? 0

  return (
    <div className="app-shell">
      {sidebarOpen && (
        <button
          className="mobile-overlay"
          aria-label="Close navigation"
          onClick={() => setSidebarOpen(false)}
        />
      )}

      <aside className={`sidebar ${sidebarOpen ? 'sidebar-open' : ''}`}>
        <div className="brand">
          <div className="brand-symbol">S<span>/</span></div>
          <div>
            <div className="brand-name">SIGNAL</div>
            <div className="brand-subtitle">SECURITY OPERATIONS</div>
          </div>
          <button
            className="mobile-close"
            onClick={() => setSidebarOpen(false)}
            aria-label="Close sidebar"
          >
            <X size={19} />
          </button>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="navigation">
          {navigation.map(({ label, icon: Icon }) => (
            <button
              key={label}
              className={`nav-item ${activePage === label ? 'active' : ''}`}
              onClick={() => {
                setActivePage(label)
                setSidebarOpen(false)
              }}
            >
              <Icon size={18} strokeWidth={1.8} />
              <span>{label}</span>
              {label === 'Alerts' && (
                <span className="nav-count">{formatNumber(totalAlerts)}</span>
              )}
              {activePage === label && <span className="active-mark" />}
            </button>
          ))}
        </nav>

        <div className="sidebar-label tools-label">SYSTEM</div>

        <nav className="navigation">
          <button className="nav-item" onClick={() => setActivePage('Settings')}>
            <Settings size={18} />
            <span>Settings</span>
          </button>
          <button className="nav-item" onClick={() => setActivePage('Help')}>
            <CircleHelp size={18} />
            <span>Documentation</span>
          </button>
        </nav>

        <div className="sidebar-bottom">
          <div className="system-status">
            <span className="status-dot" />
            <span>API CONNECTION</span>
            <strong>{error ? 'OFFLINE' : loading ? 'CHECKING' : 'CONNECTED'}</strong>
          </div>
          <div className="user-profile">
            <div className="user-avatar">SA</div>
            <div className="user-details">
              <strong>Security Analyst</strong>
              <span>Local workspace</span>
            </div>
            <ChevronDown size={16} />
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="topbar-left">
            <button
              className="mobile-menu"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open navigation"
            >
              <Activity size={20} />
            </button>
            <div className="breadcrumb">Workspace <ChevronRight size={14} /> <strong>{activePage}</strong></div>
          </div>

          <div className="topbar-actions">
            <span className="environment-label">LOCAL ENVIRONMENT</span>
            <button className="icon-button" aria-label="Notifications">
              <Bell size={18} />
              <i />
            </button>
            <div className="topbar-date">SOC / 01</div>
          </div>
        </header>

        <div className="content">
          {activePage === 'Overview' ? (
            <>
              <section className="page-heading">
                <div>
                  <div className="eyebrow">SECURITY INTELLIGENCE / 01</div>
                  <h1>Operations overview<span>.</span></h1>
                  <p>Detection activity and incident intelligence across your datasets.</p>
                </div>
                <button className="refresh-button" onClick={loadAnalyses}>
                  <RefreshCw size={15} />
                  Refresh data
                </button>
              </section>

              {error && <div className="error-banner">{error}</div>}

              <section className="overview-strip">
                <div className="strip-heading">
                  <span className="strip-marker" />
                  CURRENT ANALYSIS
                </div>
                <div className="strip-main">
                  <div>
                    <span className="muted-label">SOURCE DATASET</span>
                    <h2>{latestAnalysis?.filename ?? (loading ? 'Loading analysis…' : 'No completed analysis')}</h2>
                  </div>
                  <div>
                    <span className="muted-label">PROCESSING STATUS</span>
                    <div className="completed-status">
                      <span className="status-dot" />
                      {latestAnalysis?.status ?? '—'}
                    </div>
                  </div>
                  <div>
                    <span className="muted-label">RECORDS PROCESSED</span>
                    <strong>{formatNumber(results?.rows_processed)}</strong>
                  </div>
                  <div>
                    <span className="muted-label">DETECTION METHOD</span>
                    <strong className="method-label">Rule-based</strong>
                  </div>
                </div>
              </section>

              <section className="metrics-section">
                <div className="section-heading">
                  <div>
                    <span className="eyebrow">01 / KEY INDICATORS</span>
                    <h2>Detection summary</h2>
                  </div>
                  <span className="section-note">Latest completed analysis</span>
                </div>

                <div className="metrics-grid">
                  <Metric
                    label="Total alerts"
                    value={formatNumber(totalAlerts)}
                    note="Generated by detection pipeline"
                    icon={<Activity size={18} />}
                    accent="ink"
                  />
                  <Metric
                    label="Critical severity"
                    value={formatNumber(critical)}
                    note="Requires highest priority review"
                    icon={<AlertOctagon size={18} />}
                    accent="red"
                  />
                  <Metric
                    label="High severity"
                    value={formatNumber(high)}
                    note="Elevated investigation priority"
                    icon={<ArrowUpRight size={18} />}
                    accent="amber"
                  />
                  <Metric
                    label="Medium severity"
                    value={formatNumber(medium)}
                    note="Requires analyst assessment"
                    icon={<ArrowDownRight size={18} />}
                    accent="green"
                  />
                </div>
              </section>

              <section className="analysis-grid">
                <div className="panel severity-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="eyebrow">02 / CLASSIFICATION</span>
                      <h2>Severity distribution</h2>
                    </div>
                    <span className="panel-index">A</span>
                  </div>

                  <div className="chart-layout">
                    <div className="chart-wrap">
                      <ResponsiveContainer width="100%" height="100%">
                        <PieChart>
                          <Pie
                            data={severityData}
                            dataKey="value"
                            nameKey="name"
                            innerRadius="66%"
                            outerRadius="92%"
                            paddingAngle={3}
                            stroke="none"
                          >
                            {severityData.map((entry, index) => (
                              <Cell key={entry.name} fill={COLORS[index]} />
                            ))}
                          </Pie>
                          <Tooltip
                            formatter={(value) => formatNumber(Number(value))}
                          />
                        </PieChart>
                      </ResponsiveContainer>
                      <div className="chart-center">
                        <strong>{formatNumber(totalAlerts)}</strong>
                        <span>TOTAL ALERTS</span>
                      </div>
                    </div>

                    <div className="severity-legend">
                      {severityData.map((item, index) => {
                        const percentage = totalAlerts
                          ? ((item.value / totalAlerts) * 100).toFixed(1)
                          : '0.0'

                        return (
                          <div className="legend-item" key={item.name}>
                            <div className="legend-top">
                              <span className="legend-name">
                                <i style={{ background: COLORS[index] }} />
                                {item.name}
                              </span>
                              <strong>{percentage}%</strong>
                            </div>
                            <div className="legend-value">
                              {formatNumber(item.value)}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                  <div className="panel-footnote">
                    Distribution of generated alerts by severity classification.
                  </div>
                </div>

                <div className="panel pipeline-panel">
                  <div className="panel-heading">
                    <div>
                      <span className="eyebrow">03 / PIPELINE</span>
                      <h2>Processing activity</h2>
                    </div>
                    <Database size={19} />
                  </div>

                  <div className="pipeline-stat">
                    <span>Records processed</span>
                    <strong>{formatNumber(results?.rows_processed)}</strong>
                  </div>
                  <div className="pipeline-bar">
                    <div
                      style={{
                        width: `${results?.rows_processed ? Math.min(100, (results.matched_rows / results.rows_processed) * 100) : 0}%`,
                      }}
                    />
                  </div>
                  <div className="pipeline-caption">
                    <span>Rule-matched records</span>
                    <strong>{formatNumber(results?.matched_rows)}</strong>
                  </div>

                  <div className="pipeline-divider" />

                  <div className="pipeline-row">
                    <span>Unique incidents detected</span>
                    <strong>{formatNumber(results?.incidents_detected)}</strong>
                  </div>
                  <div className="pipeline-row">
                    <span>Alerts generated</span>
                    <strong>{formatNumber(results?.alerts_generated)}</strong>
                  </div>
                  <div className="pipeline-row">
                    <span>Invalid timestamps</span>
                    <strong>{formatNumber(results?.invalid_timestamps)}</strong>
                  </div>

                  <div className="method-note">
                    <Shield size={16} />
                    <span>Rule-based detection. Scores are heuristic, not probabilities.</span>
                  </div>
                </div>
              </section>

              <section className="panel history-panel">
                <div className="panel-heading history-heading">
                  <div>
                    <span className="eyebrow">04 / DATA MANAGEMENT</span>
                    <h2>Recent analyses</h2>
                  </div>
                  <span className="history-count">{analyses.length} records</span>
                </div>

                <div className="table-scroll">
                  <table className="analysis-table">
                    <thead>
                      <tr>
                        <th>DATASET</th>
                        <th>STATUS</th>
                        <th>RECORDS</th>
                        <th>INCIDENTS</th>
                        <th>ALERTS</th>
                      </tr>
                    </thead>
                    <tbody>
                      {analyses.map((item) => (
                        <tr key={item.analysis_id}>
                          <td>
                            <div className="dataset-cell">
                              <FileBarChart size={17} />
                              <span>{item.filename}</span>
                            </div>
                          </td>
                          <td>
                            <span className={`table-status ${item.status}`}>
                              {item.status}
                            </span>
                          </td>
                          <td>{formatNumber(item.results?.rows_processed)}</td>
                          <td>{formatNumber(item.results?.incidents_detected)}</td>
                          <td>{formatNumber(item.results?.alerts_generated)}</td>
                        </tr>
                      ))}
                      {!loading && analyses.length === 0 && (
                        <tr><td colSpan={5}>No analyses found.</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              <footer className="page-footer">
                <span>SIGNAL / SECURITY OPERATIONS PLATFORM</span>
                <span>DETECTION ENGINE · RULE-BASED</span>
              </footer>
            </>
          ) : (
            <section className="module-placeholder">
              <div className="eyebrow">WORKSPACE / MODULE</div>
              <h1>{activePage}<span>.</span></h1>
              <p>This section will be implemented in the next development milestone.</p>
              <button className="refresh-button" onClick={() => setActivePage('Overview')}>
                Return to overview <ChevronRight size={15} />
              </button>
            </section>
          )}
        </div>
      </main>
    </div>
  )
}

function Metric({
  label,
  value,
  note,
  icon,
  accent,
}: {
  label: string
  value: string
  note: string
  icon: React.ReactNode
  accent: string
}) {
  return (
    <article className={`metric-card ${accent}`}>
      <div className="metric-top">
        <span>{label}</span>
        {icon}
      </div>
      <strong className="metric-value">{value}</strong>
      <span className="metric-note">{note}</span>
    </article>
  )
}

export default App
