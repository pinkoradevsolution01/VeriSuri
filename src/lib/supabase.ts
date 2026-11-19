import { createClient } from '@supabase/supabase-js'

const url = import.meta.env.VITE_SUPABASE_URL
const key = import.meta.env.VITE_SUPABASE_ANON_KEY
const memoryStorage = new Map<string, string>()

// Some private-browsing or restricted mobile browser contexts can throw when
// localStorage is accessed. Retaining sessions in memory keeps the app usable.
const safeStorage = {
  getItem: (storageKey: string) => {
    try { return window.localStorage.getItem(storageKey) }
    catch { return memoryStorage.get(storageKey) ?? null }
  },
  setItem: (storageKey: string, value: string) => {
    try { window.localStorage.setItem(storageKey, value) }
    catch { memoryStorage.set(storageKey, value) }
  },
  removeItem: (storageKey: string) => {
    try { window.localStorage.removeItem(storageKey) }
    catch { memoryStorage.delete(storageKey) }
  },
}

let client = null
if (url && key) {
  try { client = createClient(url, key, { auth: { storage: safeStorage } }) }
  catch { client = null }
}
export const supabase = client
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
  scamType?: 'phishing' | 'investment' | 'marketplace' | 'impersonation' | 'loan' | 'romance' | 'job' | 'delivery' | 'other'
  paymentProvider?: 'gcash' | 'maya' | 'bank' | 'card' | 'crypto' | 'not_applicable'
  amountRange?: 'under_1000' | '1000_4999' | '5000_19999' | '20000_99999' | '100000_plus' | 'not_stated'
  incidentAt?: string
  incidentChannel?: 'sms' | 'messaging_app' | 'social_media' | 'email' | 'call' | 'website' | 'marketplace' | 'other'
  redactedEvidence?: string
  privacyNoticeVersion: string
  acknowledgesSafeSubmission: boolean
  trainingConsent: boolean
  redactedTrainingSample?: string
}

export type ModerationReport = {
  id: string
  narrative: string
  created_at: string
  scam_type: string
  payment_provider: string
  amount_range: string
  incident_at: string | null
  incident_channel: string
  redacted_evidence: string | null
  duplicate_count: number
  duplicate_of: string | null
  privacy_notice_version: string
  training_consent: boolean
  reported_entities: { entity_type: ReportEntityType; entity_last4: string | null }[]
  training_examples: { id: string; text_redacted: string; status: string }[]
}

export type ModeratedAlertDraft = { title: string; summary: string; severity: 'low' | 'medium' | 'high'; sourceName: string; sourceUrl: string; affectedPlatform: string; region?: string; reviewAt: string; expiresAt: string }
export type ModerationAlert = ModeratedAlertDraft & { id: string; status: 'pending'; created_at: string }
export type EvidenceVaultItem = { id: string; item_type: 'screenshot' | 'transaction_reference' | 'note'; filename: string | null; transaction_reference: string | null; occurred_at: string | null; note: string | null; created_at: string }

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
    p_scam_type: submission.scamType ?? 'other',
    p_payment_provider: submission.paymentProvider ?? 'not_applicable',
    p_amount_range: submission.amountRange ?? 'not_stated',
    p_incident_at: submission.incidentAt || null,
    p_incident_channel: submission.incidentChannel ?? 'other',
    p_redacted_evidence: submission.redactedEvidence?.trim() || null,
  })
  if (error) throw error
}

export async function getModeratorQueue(): Promise<ModerationReport[]> {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { data, error } = await supabase
    .from('scam_reports')
    .select('id,narrative,created_at,scam_type,payment_provider,amount_range,incident_at,incident_channel,redacted_evidence,duplicate_count,duplicate_of,privacy_notice_version,training_consent,reported_entities(entity_type,entity_last4),training_examples(id,text_redacted,status)')
    .eq('status', 'pending')
    .order('created_at', { ascending: true })
    .limit(50)
  if (error) throw error
  return (data ?? []) as ModerationReport[]
}

export async function createModeratedAlert(draft: ModeratedAlertDraft) {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { error } = await supabase.rpc('create_moderated_alert', {
    p_title: draft.title.trim(), p_summary: draft.summary.trim(), p_severity: draft.severity,
    p_source_name: draft.sourceName.trim(), p_source_url: draft.sourceUrl.trim(), p_affected_platform: draft.affectedPlatform.trim(),
    p_region: draft.region?.trim() || null, p_review_at: draft.reviewAt, p_expires_at: draft.expiresAt,
  })
  if (error) throw error
}

export async function getPendingModeratedAlerts(): Promise<ModerationAlert[]> {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { data, error } = await supabase.from('fraud_alerts')
    .select('id,title,summary,severity,source_name,source_url,affected_platform,region,review_at,expires_at,status,created_at')
    .eq('status', 'pending').order('created_at', { ascending: true }).limit(30)
  if (error) throw error
  return (data ?? []).map(item => ({
    id: item.id, title: item.title, summary: item.summary, severity: item.severity,
    sourceName: item.source_name, sourceUrl: item.source_url, affectedPlatform: item.affected_platform,
    region: item.region ?? undefined, reviewAt: item.review_at, expiresAt: item.expires_at, status: 'pending' as const, created_at: item.created_at,
  }))
}

export async function reviewModeratedAlert(alertId: string, decision: 'verified' | 'rejected') {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { error } = await supabase.rpc('review_moderated_alert', { p_alert_id: alertId, p_decision: decision })
  if (error) throw error
}

export async function getEvidenceVault(): Promise<EvidenceVaultItem[]> {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { data, error } = await supabase.from('evidence_vault_items').select('id,item_type,filename,transaction_reference,occurred_at,note,created_at').order('created_at', { ascending: false })
  if (error) throw error
  return (data ?? []) as EvidenceVaultItem[]
}

export async function addEvidenceVaultItem(item: { type: EvidenceVaultItem['item_type']; note?: string; reference?: string; occurredAt?: string; file?: File }) {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { data: { user } } = await supabase.auth.getUser(); if (!user) throw new Error('Please sign in before using the Evidence Vault.')
  let storagePath: string | null = null; let filename: string | null = null
  if (item.file) {
    if (!['image/jpeg', 'image/png', 'image/webp'].includes(item.file.type) || item.file.size > 5_242_880) throw new Error('Use a redacted JPG, PNG, or WebP image up to 5 MB.')
    filename = item.file.name.replace(/[^a-zA-Z0-9._-]/g, '_')
    storagePath = `${user.id}/${crypto.randomUUID()}-${filename}`
    const { error } = await supabase.storage.from('evidence-vault').upload(storagePath, item.file, { contentType: item.file.type, upsert: false })
    if (error) throw error
  }
  const { error } = await supabase.from('evidence_vault_items').insert({ owner_id: user.id, item_type: item.type, storage_path: storagePath, filename, transaction_reference: item.reference?.trim() || null, occurred_at: item.occurredAt || null, note: item.note?.trim() || null })
  if (error) throw error
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
