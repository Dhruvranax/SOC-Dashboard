
import axios from 'axios'

export const api = axios.create({
  baseURL: 'http://127.0.0.1:8000',
  timeout: 30000,
})

export interface AnalysisResults {
  input_file?: string
  rows_processed: number
  matched_rows: number
  incidents_detected: number
  alerts_generated: number
  invalid_timestamps?: number
  columns_detected?: number
  timestamp_available?: boolean
  score_interpretation?: string
  detection_type?: string
  status?: string
  severity_distribution: {
    Critical: number
    High: number
    Medium: number
  }
}

export interface Analysis {
  analysis_id: string
  filename: string
  status: 'uploaded' | 'processing' | 'completed' | 'failed' | string
  created_at: string | null
  updated_at?: string | null
  completed_at?: string | null
  failed_at?: string | null
  error?: string | null
  results: AnalysisResults | null
}

interface AnalysisListResponse {
  total: number
  analyses: Analysis[]
}

export const getAnalyses = async (): Promise<Analysis[]> => {
  const response = await api.get<AnalysisListResponse>(
    '/api/analyses'
  )

  return response.data.analyses
}
