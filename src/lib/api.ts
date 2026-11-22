import { supabase } from './supabase'

export type RiskLevel = 'low' | 'medium' | 'high'
export type AssessmentExplanation = { category: 'rule' | 'threat_feed' | 'community' | 'model' | 'service' | string; label: string; detail: string; source: string }
export type HighlightedSignal = { start: number; end: number; text: string; label: string; source: string }
export type LinkIntelligence = { canonical_host: string | null; official_domain: boolean; redirect_hosts: string[]; domain_registered_on: string | null; domain_age_days: number | null; notes: string[] }

export type Assessment = {
  score: number
  level: RiskLevel
  verdict: string
  summary: string
  signals: string[]
  explanations: AssessmentExplanation[]
  highlights: HighlightedSignal[]
  calibrated_scam_probability: number | null
  confidence_basis: string | null
  evidence_confidence: 'high' | 'moderate' | 'limited'
  verification_required: boolean
  verification_message: string
  link_intelligence: LinkIntelligence | null
  recommendation_title: string
  recommendations: string[]
  engine_version: string
  source: string
}
export type Alert = { id: string; title: string; summary: string; severity: RiskLevel; published_at: string; source_name: string; source_url: string; affected_platform: string; region: string | null; review_at: string; expires_at: string }
export type Contributor = { id: string; contributor_name: string; reference: string; scam_type: string; incident_channel: string; created_at: string }

const baseUrl = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'

async function post<T>(path: string, body: Record<string, string>): Promise<T> {
  const { data } = supabase ? await supabase.auth.getSession() : { data: { session: null } }
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (data.session?.access_token) headers.Authorization = `Bearer ${data.session.access_token}`
  const response = await fetch(`${baseUrl}${path}`, { method: 'POST', headers, body: JSON.stringify(body) })
  if (!response.ok) {
    const message = await response.json().catch(() => null)
    throw new Error(message?.detail ?? 'The protection service is unavailable. Please try again.')
  }
  return response.json() as Promise<T>
}

export function analyzeFeature(feature: 'pay' | 'message' | 'link' | 'reports', value: string, entityType = 'gcash'): Promise<Assessment> {
  if (feature === 'message') return post('/analyze/message', { text: value })
  if (feature === 'link') return post('/analyze/link', { url: value })
  if (feature === 'reports') return post('/reports/lookup', { identifier: value, entity_type: entityType })
  return post('/check/payment', { identifier: value, provider: entityType })
}

export async function getAlerts(): Promise<Alert[]> {
  const response = await fetch(`${baseUrl}/alerts`)
  if (!response.ok) throw new Error('Alerts are unavailable.')
  return response.json() as Promise<Alert[]>
}

export async function getContributors(): Promise<Contributor[]> {
  const response = await fetch(`${baseUrl}/contributors`)
  if (!response.ok) throw new Error('Contributors are unavailable.')
  return response.json() as Promise<Contributor[]>
}
