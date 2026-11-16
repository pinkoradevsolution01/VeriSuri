import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL
const key = import.meta.env.VITE_SUPABASE_ANON_KEY
export const supabase = url && key ? createClient(url, key) : null
export const isSupabaseConfigured = Boolean(supabase)

export type SubscriptionPlan = 'free' | 'pro' | 'premium'
export type SubscriptionState = { subscription_plan: SubscriptionPlan; subscription_status: 'active' | 'pending_payment' | 'cancelled'; pending_plan: SubscriptionPlan | null }

export async function sendMagicLink(email: string) {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { error } = await supabase.auth.signInWithOtp({ email, options: { emailRedirectTo: window.location.origin } })
  if (error) throw error
}

export async function signOut() {
  if (!supabase) return
  const { error } = await supabase.auth.signOut()
  if (error) throw error
}

export async function signInWithProvider(provider: 'google' | 'facebook') {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { error } = await supabase.auth.signInWithOAuth({ provider, options: { redirectTo: window.location.origin } })
  if (error) throw error
}

export async function chooseSubscriptionPlan(plan: SubscriptionPlan): Promise<SubscriptionState> {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { data, error } = await supabase.rpc('select_subscription_plan', { p_plan: plan }).single()
  if (error) throw error
  return data as SubscriptionState
}

export type ReportEntityType = 'gcash' | 'maya' | 'bank' | 'phone' | 'url' | 'social'

export type ReportSubmission = {
  entityType: ReportEntityType
  entityValue: string
  narrative: string
  privacyNoticeVersion: string
  acknowledgesSafeSubmission: boolean
  trainingConsent: boolean
  redactedTrainingSample?: string
}

export type ModerationReport = {
  id: string
  narrative: string
  created_at: string
  privacy_notice_version: string
  training_consent: boolean
  reported_entities: { entity_type: ReportEntityType; entity_last4: string | null }[]
  training_examples: { id: string; text_redacted: string; status: string }[]
}

export async function submitScamReport(submission: ReportSubmission) {
  if (!supabase) throw new Error('Report submission is not configured yet.')
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Please sign in before submitting a report.')
  const { error } = await supabase.rpc('submit_scam_report', {
    p_entity_type: submission.entityType,
    p_entity_value: submission.entityValue.trim(),
    p_narrative: submission.narrative.trim(),
    p_privacy_notice_version: submission.privacyNoticeVersion,
    p_acknowledged_safe_submission: submission.acknowledgesSafeSubmission,
    p_training_consent: submission.trainingConsent,
    p_redacted_training_sample: submission.trainingConsent ? submission.redactedTrainingSample?.trim() || null : null,
  })
  if (error) throw error
}

export async function getModeratorQueue(): Promise<ModerationReport[]> {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { data, error } = await supabase
    .from('scam_reports')
    .select('id,narrative,created_at,privacy_notice_version,training_consent,reported_entities(entity_type,entity_last4),training_examples(id,text_redacted,status)')
    .eq('status', 'pending')
    .order('created_at', { ascending: true })
    .limit(50)
  if (error) throw error
  return (data ?? []) as ModerationReport[]
}

export async function reviewScamReport(reportId: string, decision: 'confirmed' | 'rejected', reason: string, trainingStatus: 'approved' | 'rejected' | null = null) {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { error } = await supabase.rpc('review_scam_report', {
    p_report_id: reportId,
    p_status: decision,
    p_reason: reason.trim() || null,
    p_training_status: trainingStatus,
  })
  if (error) throw error
}

export async function requestDataDeletion() {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { error } = await supabase.rpc('request_privacy_deletion')
  if (error) throw error
}
