
import { api } from './api'

export interface SOCAlert {
  AlertID: string
  IncidentID: string

  RiskAssessment?: {
    Severity?: string
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
    MITRETechniques?: string[]
  }

  AffectedEntities?: unknown

  AnalystInvestigation?: {
    RecommendedActions?: string[]
    Disposition?: string
  }

  [key: string]: unknown
}

export interface AlertsResponse {
  analysis_id: string
  total: number
  limit: number
  offset: number
  severity: string | null
  search: string | null
  alerts: SOCAlert[]
}

interface GetAlertsParams {
  analysisId: string
  limit?: number
  offset?: number
  severity?: string
  search?: string
}

export async function getAlerts({
  analysisId,
  limit = 20,
  offset = 0,
  severity,
  search,
}: GetAlertsParams): Promise<AlertsResponse> {
  const response = await api.get<AlertsResponse>(
    `/api/analyses/${analysisId}/alerts`,
    {
      params: {
        limit,
        offset,
        severity: severity || undefined,
        search: search || undefined,
      },
    },
  )

  return response.data
}
