import { supabase } from './supabase'

export type RiskLevel = 'low' | 'medium' | 'high'

export type Assessment = {
  score: number
  level: RiskLevel
  verdict: string
  summary: string
  signals: string[]
  engine_version: string
  source: string
}
export type Alert = { id: string; title: string; summary: string; severity: RiskLevel; published_at: string }

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
