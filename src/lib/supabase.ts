import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL
const key = import.meta.env.VITE_SUPABASE_ANON_KEY
export const supabase = url && key ? createClient(url, key) : null
export const isSupabaseConfigured = Boolean(supabase)

export async function submitScamReport(entityType: 'gcash' | 'maya' | 'bank' | 'phone' | 'url' | 'social', entityValue: string, narrative: string) {
  if (!supabase) throw new Error('Report submission is not configured yet.')
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Please sign in before submitting a report.')
  const { data: report, error } = await supabase.from('scam_reports').insert({ reporter_id: user.id, narrative }).select('id').single()
  if (error) throw error
  const hash = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(entityValue.trim().toLowerCase()))
  const entityHash = Array.from(new Uint8Array(hash)).map(byte => byte.toString(16).padStart(2, '0')).join('')
  const { error: entityError } = await supabase.from('reported_entities').insert({ report_id: report.id, entity_type: entityType, entity_hash: entityHash, entity_last4: entityValue.slice(-4) })
  if (entityError) throw entityError
}
