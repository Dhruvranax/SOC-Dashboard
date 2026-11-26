
import { useCallback, useEffect, useMemo, useState } from 'react'
import './index.css'

const API_BASE = 'http://127.0.0.1:8000'
const PAGE_SIZE = 20
const MAX_UPLOAD_SIZE = 100 * 1024 * 1024

type Severity = 'Critical' | 'High' | 'Medium'

interface AnalysisResults {
  rows_processed: number
  matched_rows: number
  incidents_detected: number
  alerts_generated: number
  severity_distribution: {
    Critical: number
    High: number
    Medium: number
  }
  invalid_timestamps?: number
  columns_detected?: number
  timestamp_available?: boolean
  score_interpretation?: string
  detection_type?: string
}

interface Analysis {
  analysis_id: string
  filename: string
  status: string
  created_at: string | null
  results: AnalysisResults | null
}

interface AnalysisListResponse {
  total: number
  analyses: Analysis[]
}

interface Alert {
  AlertID?: string
  IncidentID?: string
  RiskAssessment?: {
    Severity?: Severity
    RiskScore?: number
    ScoreType?: string
  }
  IncidentTimeline?: {
    FirstSeen?: string
    LastSeen?: string
  }
  DetectionSummary?: {
    MatchedRecords?: number
    UniqueAlerts?: number
    Categories?: string[]
    DetectionRules?: string[]
    MitreTechniques?: string[]
  }
  [key: string]: unknown
}

interface AlertsResponse {
  analysis_id: string
  total: number
  limit: number
  offset: number
  severity: string | null
  search: string | null
  alerts: Alert[]
}

interface DatasetInspection {
  [key: string]: unknown
}

type Page =
  | 'Overview'
  | 'Alerts'
  | 'Investigations'
  | 'Datasets'
  | 'Reports'

function formatNumber(value?: number) {
  return (value ?? 0).toLocaleString('en-US')
}

function formatOptionalNumber(value?: number | null) {
  if (value === null || value === undefined) {
    return '—'
  }

  return formatNumber(value)
}

function formatDate(value: string | null) {
  if (!value) return '—'

  const date = new Date(value)

  if (Number.isNaN(date.getTime())) return value

  return date.toLocaleString()
}

function getSeverity(alert: Alert): Severity | 'Unknown' {
  const severity = alert.RiskAssessment?.Severity

  if (
    severity === 'Critical' ||
    severity === 'High' ||
    severity === 'Medium'
  ) {
    return severity
  }

  return 'Unknown'
}

function displayInspectionValue(value: unknown): string {
  if (Array.isArray(value)) {
    return value.map((item) => String(item)).join(', ')
  }

  if (typeof value === 'object' && value !== null) {
    return JSON.stringify(value)
  }

  return String(value ?? '—')
}

function getApiError(data: unknown, fallback: string): string {
  if (
    typeof data === 'object' &&
    data !== null &&
    'detail' in data
  ) {
    const detail = (data as { detail: unknown }).detail

    if (typeof detail === 'string') return detail

    if (Array.isArray(detail)) {
      return detail
        .map((item) => {
          if (
            typeof item === 'object' &&
            item !== null &&
            'msg' in item
          ) {
            return String(item.msg)
          }

          return String(item)
        })
        .join(', ')
    }
  }

  return fallback
}

async function readResponse(response: Response): Promise<unknown> {
  const contentType = response.headers.get('content-type') ?? ''

  if (contentType.includes('application/json')) {
    return response.json()
  }

  return response.text()
}

function App() {
  const [page, setPage] = useState<Page>('Overview')
  const [analyses, setAnalyses] = useState<Analysis[]>([])
  const [selectedAnalysisId, setSelectedAnalysisId] = useState('')
  const [alerts, setAlerts] = useState<Alert[]>([])

  const [alertTotal, setAlertTotal] = useState(0)
  const [offset, setOffset] = useState(0)
  const [severity, setSeverity] = useState('')
  const [search, setSearch] = useState('')

  const [loading, setLoading] = useState(true)
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [inspecting, setInspecting] = useState(false)

  const [apiConnected, setApiConnected] = useState(false)
  const [error, setError] = useState('')
  const [uploadMessage, setUploadMessage] = useState('')

  // Dataset upload workflow
  const [selectedFile, setSelectedFile] = useState<File | null>(null)
  const [inspection, setInspection] =
    useState<DatasetInspection | null>(null)
  const [dragActive, setDragActive] = useState(false)

  const completedAnalyses = useMemo(
    () =>
      analyses.filter(
        (analysis) =>
          analysis.status === 'completed' &&
          analysis.results !== null,
      ),
    [analyses],
  )

  const selectedAnalysis = useMemo(
    () =>
      analyses.find(
        (analysis) => analysis.analysis_id === selectedAnalysisId,
      ) ?? null,
    [analyses, selectedAnalysisId],
  )

  const loadAnalyses = useCallback(async () => {
    setLoading(true)
    setError('')

    try {
      const response = await fetch(`${API_BASE}/api/analyses`)

      if (!response.ok) {
        throw new Error(
          `Could not load analyses (${response.status})`,
        )
      }

      const data: AnalysisListResponse = await response.json()

      const analysisList = data.analyses ?? []

      setAnalyses(analysisList)
      setApiConnected(true)

      setSelectedAnalysisId((current) => {
        const exists = analysisList.some(
          (analysis) => analysis.analysis_id === current,
        )

        if (exists) return current

        const completed = analysisList.find(
          (analysis) =>
            analysis.status === 'completed' &&
            analysis.results,
        )

        return completed?.analysis_id ?? ''
      })
    } catch (err) {
      setApiConnected(false)
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to connect to API',
      )
    } finally {
      setLoading(false)
    }
  }, [])

  const loadAlerts = useCallback(async () => {
    if (!selectedAnalysisId) {
      setAlerts([])
      setAlertTotal(0)
      return
    }

    setAlertsLoading(true)
    setError('')

    try {
      const params = new URLSearchParams({
        limit: String(PAGE_SIZE),
        offset: String(offset),
      })

      if (severity) params.set('severity', severity)
      if (search.trim()) params.set('search', search.trim())

      const response = await fetch(
        `${API_BASE}/api/analyses/${selectedAnalysisId}/alerts?${params}`,
      )

      if (!response.ok) {
        throw new Error(
          `Could not load alerts (${response.status})`,
        )
      }

      const data: AlertsResponse = await response.json()

      setAlerts(data.alerts ?? [])
      setAlertTotal(data.total ?? 0)
      setApiConnected(true)
    } catch (err) {
      setError(
        err instanceof Error
          ? err.message
          : 'Unable to load alerts',
      )
    } finally {
      setAlertsLoading(false)
    }
  }, [selectedAnalysisId, severity, search, offset])

  useEffect(() => {
    void loadAnalyses()
  }, [loadAnalyses])

  useEffect(() => {
    if (page === 'Alerts') {
      void loadAlerts()
    }
  }, [page, loadAlerts])

  function changePage(nextPage: Page) {
    setPage(nextPage)
    setError('')
  }

  function selectAnalysis(analysis: Analysis) {
    if (analysis.status !== 'completed' || !analysis.results) {
      setError('This dataset has not been analyzed yet.')
      return
    }

    setSelectedAnalysisId(analysis.analysis_id)
    setOffset(0)
    setSeverity('')
    setSearch('')
    setPage('Overview')
    setError('')
  }

  function changeSeverity(value: string) {
    setSeverity(value)
    setOffset(0)
  }

  function changeSearch(value: string) {
    setSearch(value)
    setOffset(0)
  }

  function resetUpload() {
    setSelectedFile(null)
    setInspection(null)
    setUploadMessage('')
    setInspecting(false)
    setDragActive(false)
  }

  // Stage 1: inspect the selected CSV.
  async function handleUpload(file?: File) {
    if (!file) return

    setUploadMessage('')
    setError('')

    if (!file.name.toLowerCase().endsWith('.csv')) {
      setUploadMessage('Only CSV files are supported.')
      return
    }

    if (file.size === 0) {
      setUploadMessage('The selected file is empty.')
      return
    }

    if (file.size > MAX_UPLOAD_SIZE) {
      setUploadMessage(
        'File exceeds the maximum upload size of 100 MB.',
      )
      return
    }

    setSelectedFile(file)
    setInspection(null)
    setInspecting(true)

    const formData = new FormData()
    formData.append('file', file)

    try {
      const response = await fetch(
        `${API_BASE}/api/uploads/inspect`,
        {
          method: 'POST',
          body: formData,
        },
      )

      const data = await readResponse(response)

      if (!response.ok) {
        throw new Error(
          getApiError(data, 'Dataset inspection failed.'),
        )
      }

      if (
        typeof data !== 'object' ||
        data === null ||
        Array.isArray(data)
      ) {
        throw new Error(
          'The inspection API returned an unexpected response.',
        )
      }

      setInspection(data as DatasetInspection)
      setUploadMessage(
        'Inspection completed. Review the dataset details before running analysis.',
      )
      setApiConnected(true)
    } catch (err) {
      setSelectedFile(null)
      setInspection(null)

      setUploadMessage(
        err instanceof Error
          ? err.message
          : 'Dataset inspection failed.',
      )
    } finally {
      setInspecting(false)
    }
  }

  // Stage 2: execute the existing detection pipeline.
  async function handleRunAnalysis() {
    if (!selectedFile || !inspection || uploading) return

    setUploading(true)
    setUploadMessage(
      'Analysis is running. Large datasets may take some time.',
    )
    setError('')

    const formData = new FormData()
    formData.append('file', selectedFile)

    try {
      const response = await fetch(
        `${API_BASE}/api/analyses`,
        {
          method: 'POST',
          body: formData,
        },
      )

      const data = await readResponse(response)

      if (!response.ok) {
        throw new Error(
          getApiError(data, 'Analysis failed.'),
        )
      }

      const result = data as {
        analysis_id?: string
        filename?: string
      }

      if (!result.analysis_id) {
        throw new Error(
          'Analysis response did not contain an analysis ID.',
        )
      }

      setUploadMessage(
        `Analysis completed: ${result.filename ?? selectedFile.name}`,
      )

      setSelectedAnalysisId(result.analysis_id)

      await loadAnalyses()

      // Keep the new analysis selected after refreshing the list.
      setSelectedAnalysisId(result.analysis_id)

      setSelectedFile(null)
      setInspection(null)
      setPage('Overview')
      setOffset(0)
      setSeverity('')
      setSearch('')
    } catch (err) {
      setUploadMessage(
        err instanceof Error
          ? err.message
          : 'Analysis failed.',
      )
    } finally {
      setUploading(false)
    }
  }

  const results = selectedAnalysis?.results

  const criticalCount =
    results?.severity_distribution.Critical ?? 0

  const highCount =
    results?.severity_distribution.High ?? 0

  const mediumCount =
    results?.severity_distribution.Medium ?? 0

  const currentPage = Math.floor(offset / PAGE_SIZE) + 1
  const totalPages = Math.max(
    1,
    Math.ceil(alertTotal / PAGE_SIZE),
  )

  return (
    <div className="app-shell">
      <aside className="sidebar">
        <div className="brand">
          <div className="brand-mark">S</div>
          <div>
            <div className="brand-name">SIGNAL</div>
            <div className="brand-subtitle">
              SECURITY OPERATIONS
            </div>
          </div>
        </div>

        <div className="sidebar-label">WORKSPACE</div>

        <nav className="navigation">
          {(
            [
              'Overview',
              'Alerts',
              'Investigations',
              'Datasets',
              'Reports',
            ] as Page[]
          ).map((item) => (
            <button
              key={item}
              className={`nav-item ${page === item ? 'active' : ''
                }`}
              onClick={() => changePage(item)}
            >
              <span className="nav-symbol">
                {item === 'Overview'
                  ? '◫'
                  : item === 'Alerts'
                    ? '⌁'
                    : item === 'Investigations'
                      ? '◎'
                      : item === 'Datasets'
                        ? '▤'
                        : '▧'}
              </span>

              {item}

              {item === 'Alerts' && (
                <span className="nav-count">
                  {formatNumber(alertTotal)}
                </span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-bottom">
          <div className="sidebar-label">SYSTEM</div>

          <div className="connection-status">
            <span
              className={`status-dot ${apiConnected ? 'online' : 'offline'
                }`}
            />
            <span>
              {apiConnected
                ? 'API connected'
                : 'API disconnected'}
            </span>
          </div>

          <div className="sidebar-version">
            SIGNAL SOC · v0.2.0
          </div>
        </div>
      </aside>

      <main className="main-area">
        <header className="topbar">
          <div className="breadcrumb">
            SECURITY OPERATIONS <span>/</span>{' '}
            {page.toUpperCase()}
          </div>

          <div className="topbar-right">
            <span className="environment-label">
              LOCAL ENVIRONMENT
            </span>

            <button
              className="refresh-button"
              onClick={() => void loadAnalyses()}
              title="Refresh analyses"
            >
              ↻
            </button>
          </div>
        </header>

        <div className="page-content">
          {error && (
            <div className="error-banner">
              <span>{error}</span>
              <button onClick={() => setError('')}>
                Dismiss
              </button>
            </div>
          )}

          {/* OVERVIEW */}
          {page === 'Overview' && (
            <section>
              <div className="page-heading">
                <div>
                  <div className="eyebrow">
                    COMMAND CENTRE / OVERVIEW
                  </div>

                  <h1>Security overview</h1>

                  <p className="page-description">
                    Detection activity and analysis performance
                    across your datasets.
                  </p>
                </div>

                <button
                  className="primary-button"
                  onClick={() => changePage('Datasets')}
                >
                  + Analyze dataset
                </button>
              </div>

              {loading ? (
                <div className="empty-state">
                  Loading security data...
                </div>
              ) : (
                <>
                  <div className="analysis-selector">
                    <label htmlFor="analysis-select">
                      ACTIVE ANALYSIS
                    </label>

                    <select
                      id="analysis-select"
                      value={selectedAnalysisId}
                      onChange={(event) =>
                        setSelectedAnalysisId(event.target.value)
                      }
                    >
                      {completedAnalyses.map((analysis) => (
                        <option
                          key={analysis.analysis_id}
                          value={analysis.analysis_id}
                        >
                          {analysis.filename}
                        </option>
                      ))}
                    </select>

                    {selectedAnalysis && (
                      <span className="analysis-date">
                        {formatDate(selectedAnalysis.created_at)}
                      </span>
                    )}
                  </div>

                  {!results ? (
                    <div className="empty-state">
                      No completed analysis is available. Upload
                      a CSV dataset to begin.
                    </div>
                  ) : (
                    <>
                      <div className="metrics-grid">
                        <Metric
                          label="RECORDS PROCESSED"
                          value={formatNumber(
                            results.rows_processed,
                          )}
                          note="Total input records"
                        />

                        <Metric
                          label="MATCHED RECORDS"
                          value={formatNumber(
                            results.matched_rows,
                          )}
                          note="Records matching detection rules"
                        />

                        <Metric
                          label="INCIDENTS DETECTED"
                          value={formatNumber(
                            results.incidents_detected,
                          )}
                          note="Unique detected incidents"
                        />

                        <Metric
                          label="ALERTS GENERATED"
                          value={formatNumber(
                            results.alerts_generated,
                          )}
                          note="Generated SOC alerts"
                        />
                      </div>

                      <div className="overview-grid">
                        <section className="panel severity-panel">
                          <div className="panel-heading">
                            <div>
                              <div className="eyebrow">
                                THREAT LANDSCAPE
                              </div>
                              <h2>
                                Severity distribution
                              </h2>
                            </div>

                            <span className="panel-caption">
                              ALERTS
                            </span>
                          </div>

                          <div className="severity-list">
                            <SeverityRow
                              label="Critical"
                              value={criticalCount}
                              total={results.alerts_generated}
                            />

                            <SeverityRow
                              label="High"
                              value={highCount}
                              total={results.alerts_generated}
                            />

                            <SeverityRow
                              label="Medium"
                              value={mediumCount}
                              total={results.alerts_generated}
                            />
                          </div>

                          <div className="severity-total">
                            <span>Total alerts</span>
                            <strong>
                              {formatNumber(
                                results.alerts_generated,
                              )}
                            </strong>
                          </div>
                        </section>

                        <section className="panel">
                          <div className="eyebrow">
                            DETECTION ENGINE
                          </div>

                          <h2>Analysis information</h2>

                          <InfoRow
                            label="Detection method"
                            value="Rule-based"
                          />

                          <InfoRow
                            label="Dataset columns"
                            value={String(
                              results.columns_detected ?? '—',
                            )}
                          />

                          <InfoRow
                            label="Timestamp available"
                            value={
                              results.timestamp_available
                                ? 'Yes'
                                : 'No'
                            }
                          />

                          <InfoRow
                            label="Invalid timestamps"
                            value={formatNumber(
                              results.invalid_timestamps,
                            )}
                          />

                          <div className="method-note">
                            {results.score_interpretation ??
                              'Risk scores are heuristic prioritization scores, not probabilities.'}
                          </div>
                        </section>
                      </div>

                      <section className="panel recent-panel">
                        <div className="panel-heading">
                          <div>
                            <div className="eyebrow">
                              DATA MANAGEMENT
                            </div>
                            <h2>Recent analyses</h2>
                          </div>

                          <button
                            className="text-button"
                            onClick={() =>
                              changePage('Datasets')
                            }
                          >
                            View datasets →
                          </button>
                        </div>

                        <AnalysisTable
                          analyses={analyses}
                          onSelectAnalysis={selectAnalysis}
                        />
                      </section>

                      <div className="overview-footer">
                        <span>
                          Detection type:{' '}
                          {results.detection_type ??
                            'Rule-based'}
                        </span>

                        <span>
                          Analysis ID:{' '}
                          {selectedAnalysis?.analysis_id}
                        </span>
                      </div>
                    </>
                  )}
                </>
              )}
            </section>
          )}

          {/* ALERTS */}
          {page === 'Alerts' && (
            <section>
              <div className="page-heading">
                <div>
                  <div className="eyebrow">
                    SECURITY OPERATIONS / ALERT MANAGEMENT
                  </div>

                  <h1>Alert queue</h1>

                  <p className="page-description">
                    Review, search and prioritize generated
                    security alerts.
                  </p>
                </div>

                <div className="total-alerts">
                  <strong>
                    {formatNumber(alertTotal)}
                  </strong>
                  <span>FILTERED ALERTS</span>
                </div>
              </div>

              <div className="filter-bar">
                <select
                  value={selectedAnalysisId}
                  onChange={(event) => {
                    setSelectedAnalysisId(
                      event.target.value,
                    )
                    setOffset(0)
                  }}
                  aria-label="Select analysis"
                >
                  {completedAnalyses.map((analysis) => (
                    <option
                      key={analysis.analysis_id}
                      value={analysis.analysis_id}
                    >
                      {analysis.filename}
                    </option>
                  ))}
                </select>

                <select
                  value={severity}
                  onChange={(event) =>
                    changeSeverity(event.target.value)
                  }
                  aria-label="Filter severity"
                >
                  <option value="">All severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                </select>

                <input
                  type="search"
                  placeholder="Search alerts or MITRE techniques..."
                  value={search}
                  onChange={(event) =>
                    changeSearch(event.target.value)
                  }
                />

                <button
                  className="secondary-button"
                  onClick={() => {
                    setSearch('')
                    setSeverity('')
                    setOffset(0)
                  }}
                >
                  Clear filters
                </button>
              </div>

              <div className="panel alert-panel">
                <div className="table-heading">
                  <div>
                    <h2>Detected alerts</h2>
                    <span>
                      {alertsLoading
                        ? 'Loading...'
                        : `${formatNumber(alertTotal)} results`}
                    </span>
                  </div>

                  <span className="panel-caption">
                    SORT: API ORDER
                  </span>
                </div>

                {alertsLoading ? (
                  <div className="empty-state">
                    Retrieving alerts...
                  </div>
                ) : alerts.length === 0 ? (
                  <div className="empty-state">
                    No alerts found for the selected filters.
                  </div>
                ) : (
                  <div className="table-scroll">
                    <table>
                      <thead>
                        <tr>
                          <th>ALERT ID</th>
                          <th>INCIDENT ID</th>
                          <th>SEVERITY</th>
                          <th>RISK SCORE</th>
                          <th>FIRST SEEN</th>
                          <th>MATCHED RECORDS</th>
                          <th>TECHNIQUES</th>
                        </tr>
                      </thead>

                      <tbody>
                        {alerts.map((alert, index) => {
                          const level = getSeverity(alert)

                          const techniques =
                            alert.DetectionSummary
                              ?.MitreTechniques ?? []

                          return (
                            <tr
                              key={`${alert.AlertID ?? 'alert'}-${index}`}
                            >
                              <td className="mono">
                                {alert.AlertID ?? '—'}
                              </td>

                              <td className="mono">
                                {alert.IncidentID ?? '—'}
                              </td>

                              <td>
                                <SeverityBadge
                                  severity={level}
                                />
                              </td>

                              <td className="mono">
                                {alert.RiskAssessment
                                  ?.RiskScore ?? '—'}
                              </td>

                              <td>
                                {formatDate(
                                  alert.IncidentTimeline
                                    ?.FirstSeen ?? null,
                                )}
                              </td>

                              <td>
                                {formatNumber(
                                  alert.DetectionSummary
                                    ?.MatchedRecords,
                                )}
                              </td>

                              <td className="technique-cell">
                                {techniques.length
                                  ? techniques.join(', ')
                                  : '—'}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  </div>
                )}

                <div className="pagination">
                  <span>
                    Page {currentPage} of {totalPages}
                  </span>

                  <div>
                    <button
                      className="secondary-button"
                      disabled={
                        offset === 0 || alertsLoading
                      }
                      onClick={() =>
                        setOffset((current) =>
                          Math.max(
                            0,
                            current - PAGE_SIZE,
                          ),
                        )
                      }
                    >
                      ← Previous
                    </button>

                    <button
                      className="secondary-button"
                      disabled={
                        offset + PAGE_SIZE >= alertTotal ||
                        alertsLoading
                      }
                      onClick={() =>
                        setOffset(
                          (current) =>
                            current + PAGE_SIZE,
                        )
                      }
                    >
                      Next →
                    </button>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* DATASETS */}
          {page === 'Datasets' && (
            <section>
              <div className="page-heading">
                <div>
                  <div className="eyebrow">
                    DATA MANAGEMENT / INGESTION
                  </div>

                  <h1>Datasets</h1>

                  <p className="page-description">
                    Upload Microsoft GUIDE CSV files, inspect
                    their structure and run the detection
                    pipeline.
                  </p>
                </div>
              </div>

              <div className="panel upload-panel">
                <div className="eyebrow">
                  NEW ANALYSIS / DATA INGESTION
                </div>

                <h2>Import security dataset</h2>

                <p>
                  Select a Microsoft GUIDE CSV dataset. Inspect
                  its structure before executing the detection
                  pipeline.
                </p>

                <label
                  className={`upload-zone ${dragActive ? 'drag-active' : ''
                    }`}
                  onDragOver={(event) => {
                    event.preventDefault()
                    setDragActive(true)
                  }}
                  onDragLeave={(event) => {
                    event.preventDefault()
                    setDragActive(false)
                  }}
                  onDrop={(event) => {
                    event.preventDefault()
                    setDragActive(false)

                    if (
                      inspecting ||
                      uploading
                    ) {
                      return
                    }

                    void handleUpload(
                      event.dataTransfer.files[0],
                    )
                  }}
                >
                  <span className="upload-icon">↑</span>

                  <strong>
                    {inspecting
                      ? 'Inspecting dataset...'
                      : selectedFile
                        ? selectedFile.name
                        : 'Drop your CSV file here'}
                  </strong>

                  <span>
                    or click to browse · CSV · Maximum 100 MB
                  </span>

                  <input
                    type="file"
                    accept=".csv,text/csv"
                    disabled={inspecting || uploading}
                    onChange={(event) => {
                      void handleUpload(
                        event.target.files?.[0],
                      )
                      event.target.value = ''
                    }}
                  />
                </label>

                {selectedFile && (
                  <div className="selected-file">
                    <div>
                      <strong>
                        {selectedFile.name}
                      </strong>

                      <span>
                        {(
                          selectedFile.size /
                          (1024 * 1024)
                        ).toFixed(2)}{' '}
                        MB
                      </span>
                    </div>

                    <button
                      className="text-button"
                      disabled={uploading || inspecting}
                      onClick={resetUpload}
                    >
                      Remove
                    </button>
                  </div>
                )}

                {inspecting && (
                  <div className="inspection-status">
                    Inspecting CSV structure and required
                    columns...
                  </div>
                )}

                {inspection && (
                  <div className="inspection-panel">
                    <div className="inspection-heading">
                      <div>
                        <div className="eyebrow">
                          PRE-ANALYSIS VALIDATION
                        </div>

                        <h3>Dataset inspection</h3>
                      </div>

                      <span className="status-label completed">
                        Inspection complete
                      </span>
                    </div>

                    <div className="inspection-grid">
                      {Object.entries(inspection).map(
                        ([key, value]) => (
                          <div
                            className="inspection-item"
                            key={key}
                          >
                            <span>
                              {key.replaceAll('_', ' ')}
                            </span>

                            <strong>
                              {displayInspectionValue(value)}
                            </strong>
                          </div>
                        ),
                      )}
                    </div>

                    <button
                      className="primary-button run-analysis-button"
                      disabled={uploading || inspecting}
                      onClick={() =>
                        void handleRunAnalysis()
                      }
                    >
                      {uploading
                        ? 'Running analysis...'
                        : 'Run Analysis →'}
                    </button>
                  </div>
                )}

                {uploadMessage && (
                  <div className="upload-message">
                    {uploadMessage}
                  </div>
                )}
              </div>

              <section className="panel recent-panel">
                <div className="panel-heading">
                  <div>
                    <div className="eyebrow">
                      PROCESSING HISTORY
                    </div>

                    <h2>All analyses</h2>
                  </div>

                  <button
                    className="text-button"
                    onClick={() => void loadAnalyses()}
                  >
                    Refresh →
                  </button>
                </div>

                <AnalysisTable
                  analyses={analyses}
                  onSelectAnalysis={selectAnalysis}
                />
              </section>
            </section>
          )}

          {/* INVESTIGATIONS */}
          {page === 'Investigations' && (
            <Placeholder
              eyebrow="SECURITY OPERATIONS / CASE MANAGEMENT"
              title="Investigations"
              description="Incident investigation and analyst case management will be developed next."
            />
          )}

          {/* REPORTS */}
          {page === 'Reports' && (
            <Placeholder
              eyebrow="SECURITY OPERATIONS / REPORTING"
              title="Reports"
              description="Investigation summaries and downloadable SOC reports will be developed next."
            />
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
}: {
  label: string
  value: string
  note: string
}) {
  return (
    <div className="metric-card">
      <div className="metric-label">{label}</div>
      <div className="metric-value">{value}</div>
      <div className="metric-note">{note}</div>
    </div>
  )
}

function SeverityRow({
  label,
  value,
  total,
}: {
  label: Severity
  value: number
  total: number
}) {
  const percentage =
    total > 0 ? (value / total) * 100 : 0

  return (
    <div className="severity-row">
      <div className="severity-row-top">
        <SeverityBadge severity={label} />
        <strong>{formatNumber(value)}</strong>
      </div>

      <div className="severity-track">
        <div
          className={`severity-fill ${label.toLowerCase()}`}
          style={{ width: `${percentage}%` }}
        />
      </div>

      <div className="severity-percentage">
        {percentage.toFixed(1)}%
      </div>
    </div>
  )
}

function SeverityBadge({
  severity,
}: {
  severity: Severity | 'Unknown'
}) {
  return (
    <span
      className={`severity-badge ${severity.toLowerCase()}`}
    >
      {severity}
    </span>
  )
}

function InfoRow({
  label,
  value,
}: {
  label: string
  value: string
}) {
  return (
    <div className="info-row">
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  )
}

function AnalysisTable({
  analyses,
  onSelectAnalysis,
}: {
  analyses: Analysis[]
  onSelectAnalysis: (analysis: Analysis) => void
}) {
  if (analyses.length === 0) {
    return (
      <div className="empty-state">
        No analyses available.
      </div>
    )
  }

  return (
    <div className="table-scroll">
      <table>
        <thead>
          <tr>
            <th>DATASET</th>
            <th>STATUS</th>
            <th>RECORDS</th>
            <th>INCIDENTS</th>
            <th>ALERTS</th>
            <th>CREATED</th>
          </tr>
        </thead>

        <tbody>
          {analyses.map((analysis) => (
            <tr
              key={analysis.analysis_id}
              className={
                analysis.status === 'completed' && analysis.results
                  ? 'analysis-row-clickable'
                  : 'analysis-row-disabled'
              }
              onClick={() => onSelectAnalysis(analysis)}
              aria-label={`Select analysis ${analysis.filename}`}
              title={
                analysis.status === 'completed' && analysis.results
                  ? 'Open this analysis'
                  : 'This dataset has not been analyzed'
              }
            >
              <td>
                <strong>{analysis.filename}</strong>

                <div className="table-subtext">
                  {analysis.analysis_id.slice(0, 8)}
                </div>
              </td>

              <td>
                <span
                  className={`status-label ${analysis.status === 'completed'
                    ? 'completed'
                    : analysis.status === 'failed'
                      ? 'failed'
                      : 'pending'
                    }`}
                >
                  {analysis.status}
                </span>
              </td>

              <td>
                {formatOptionalNumber(
                  analysis.results?.rows_processed,
                )}
              </td>

              <td>
                {formatOptionalNumber(
                  analysis.results?.incidents_detected,
                )}
              </td>

              <td>
                {formatOptionalNumber(
                  analysis.results?.alerts_generated,
                )}
              </td>


              <td>
                {formatDate(analysis.created_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function Placeholder({
  eyebrow,
  title,
  description,
}: {
  eyebrow: string
  title: string
  description: string
}) {
  return (
    <section>
      <div className="page-heading">
        <div>
          <div className="eyebrow">{eyebrow}</div>
          <h1>{title}</h1>
          <p className="page-description">
            {description}
          </p>
        </div>
      </div>

      <div className="empty-state">
        <strong>Module not implemented yet</strong>
        <p>{description}</p>
      </div>
    </section>
  )
}

export default App
