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
  const { error } = await supabase.auth.signOut({ scope: 'local' })
  if (error) throw error
}

export async function getProfileCodename(): Promise<string | null | undefined> {
  if (!supabase) return undefined
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return undefined
  const { data, error } = await supabase.from('profiles').select('codename').eq('id', user.id).maybeSingle()
  if (error) return undefined
  return typeof data?.codename === 'string' && data.codename.trim() ? data.codename.trim() : null
}

export async function setProfileCodename(codename: string): Promise<string> {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { data, error } = await supabase.rpc('set_profile_codename', { p_codename: codename.trim() })
  if (error) {
    if (error.code === '23505') throw new Error('That codename is already in use. Choose another one.')
    throw error
  }
  return String(data)
}

export type MfaFactor = { id: string; friendlyName: string | null; createdAt: string | null; status: string }
export type AccountSecurityState = {
  currentLevel: string | null
  nextLevel: string | null
  factors: MfaFactor[]
}
export type MfaEnrollment = { factorId: string; qrCode: string; secret: string }
export type RecognizedDevice = { id: string; device_name: string; last_seen_at: string; created_at: string }
export type SecurityEvent = { id: string; event_type: string; details: string | null; created_at: string }

async function requireCurrentUser() {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { data: { user }, error } = await supabase.auth.getUser()
  if (error) throw error
  if (!user) throw new Error('Please sign in to manage account security.')
  return user
}

function currentDeviceName() {
  const agent = typeof navigator === 'undefined' ? '' : navigator.userAgent
  if (/iPhone|iPad|iPod/i.test(agent)) return 'Apple mobile browser'
  if (/Android/i.test(agent)) return 'Android browser'
  if (/Macintosh/i.test(agent)) return 'Mac browser'
  if (/Windows/i.test(agent)) return 'Windows browser'
  return 'Browser session'
}

function deviceFingerprint() {
  const storageKey = 'verisuri-device-fingerprint'
  try {
    const saved = window.localStorage.getItem(storageKey)
    if (saved) return saved
    const next = crypto.randomUUID()
    window.localStorage.setItem(storageKey, next)
    return next
  } catch {
    return `temporary-${crypto.randomUUID()}`
  }
}

export async function getAccountSecurityState(): Promise<AccountSecurityState> {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const [{ data: assurance, error: assuranceError }, { data: factors, error: factorsError }] = await Promise.all([
    supabase.auth.mfa.getAuthenticatorAssuranceLevel(),
    supabase.auth.mfa.listFactors(),
  ])
  if (assuranceError) throw assuranceError
  if (factorsError) throw factorsError
  return {
    currentLevel: assurance?.currentLevel ?? null,
    nextLevel: assurance?.nextLevel ?? null,
    factors: (factors?.totp ?? []).map(factor => ({ id: factor.id, friendlyName: factor.friendly_name ?? null, createdAt: factor.created_at ?? null, status: factor.status })),
  }
}

export async function beginMfaEnrollment(): Promise<MfaEnrollment> {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { data, error } = await supabase.auth.mfa.enroll({ factorType: 'totp', friendlyName: 'VeriSuri authenticator' })
  if (error) throw error
  if (!data?.totp) throw new Error('Authenticator enrollment could not be started.')
  void recordSecurityEvent('mfa_enrollment_started', 'Authenticator-app setup started').catch(() => undefined)
  return { factorId: data.id, qrCode: data.totp.qr_code, secret: data.totp.secret }
}

export async function verifyMfaEnrollment(factorId: string, code: string) {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { error } = await supabase.auth.mfa.challengeAndVerify({ factorId, code: code.trim() })
  if (error) throw error
  void recordSecurityEvent('mfa_enabled', 'Authenticator-app MFA enabled').catch(() => undefined)
}

export async function completeMfaChallenge(factorId: string, code: string) {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { error } = await supabase.auth.mfa.challengeAndVerify({ factorId, code: code.trim() })
  if (error) throw error
  void recordSecurityEvent('mfa_challenge_completed', 'Authenticator challenge completed for this session').catch(() => undefined)
}

export async function disableMfaFactor(factorId: string) {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { error } = await supabase.auth.mfa.unenroll({ factorId })
  if (error) throw error
  void recordSecurityEvent('mfa_disabled', 'Authenticator-app MFA disabled').catch(() => undefined)
}

export async function endOtherSessions() {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { error } = await supabase.auth.signOut({ scope: 'others' })
  if (error) throw error
  void recordSecurityEvent('other_sessions_ended', 'Other sessions were signed out').catch(() => undefined)
}

export async function recordSecurityEvent(eventType: string, details?: string) {
  if (!supabase) return
  const user = await requireCurrentUser()
  const { error } = await supabase.from('account_security_events').insert({ user_id: user.id, event_type: eventType, details: details ?? null })
  if (error) throw error
}

export async function registerCurrentDevice() {
  if (!supabase) return
  const user = await requireCurrentUser()
  const { error } = await supabase.from('recognized_devices').upsert({
    user_id: user.id,
    device_fingerprint: deviceFingerprint(),
    device_name: currentDeviceName(),
    last_seen_at: new Date().toISOString(),
  }, { onConflict: 'user_id,device_fingerprint' })
  if (error) throw error
}

export async function getRecognizedDevices(): Promise<RecognizedDevice[]> {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { data, error } = await supabase.from('recognized_devices').select('id,device_name,last_seen_at,created_at').order('last_seen_at', { ascending: false }).limit(20)
  if (error) throw error
  return (data ?? []) as RecognizedDevice[]
}

export async function removeRecognizedDevice(id: string) {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { error } = await supabase.from('recognized_devices').delete().eq('id', id)
  if (error) throw error
  void recordSecurityEvent('device_record_removed', 'A recognized device record was removed').catch(() => undefined)
}

export async function getSecurityEvents(): Promise<SecurityEvent[]> {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { data, error } = await supabase.from('account_security_events').select('id,event_type,details,created_at').order('created_at', { ascending: false }).limit(20)
  if (error) throw error
  return (data ?? []) as SecurityEvent[]
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
  publicContributorConsent: boolean
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
export type MyReport = { id: string; status: 'pending' | 'confirmed' | 'rejected'; created_at: string; reviewed_at: string | null; scam_type: string; payment_provider: string; incident_channel: string; reported_entities: { entity_type: ReportEntityType; entity_last4: string | null }[] }
export type EvidenceVaultItem = { id: string; item_type: 'screenshot' | 'transaction_reference' | 'note'; filename: string | null; transaction_reference: string | null; occurred_at: string | null; note: string | null; created_at: string }

export async function submitScamReport(submission: ReportSubmission) {
  if (!supabase) throw new Error('Report submission is not configured yet.')
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Please sign in before submitting a report.')
  const { data: { session } } = await supabase.auth.getSession()
  if (!session?.access_token) throw new Error('Your sign-in session has expired. Please sign in again before submitting a report.')
  const baseUrl = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'
  const response = await fetch(`${baseUrl}/reports`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}` },
    body: JSON.stringify({
      entity_type: submission.entityType,
      entity_value: submission.entityValue.trim(),
      narrative: submission.narrative.trim(),
      scam_type: submission.scamType ?? 'other',
      payment_provider: submission.paymentProvider ?? 'not_applicable',
      amount_range: submission.amountRange ?? 'not_stated',
      incident_at: submission.incidentAt || null,
      incident_channel: submission.incidentChannel ?? 'other',
      redacted_evidence: submission.redactedEvidence?.trim() || null,
      privacy_notice_version: submission.privacyNoticeVersion,
      acknowledges_safe_submission: submission.acknowledgesSafeSubmission,
      training_consent: submission.trainingConsent,
      redacted_training_sample: submission.trainingConsent ? submission.redactedTrainingSample?.trim() || null : null,
      public_contributor_consent: submission.publicContributorConsent,
    }),
  })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail ?? 'Unable to submit the report. Please try again.')
  }
}

export async function getModeratorQueue(): Promise<ModerationReport[]> {
  const response = await authenticatedApiRequest('/moderation/reports')
  return response as ModerationReport[]
}

export async function getMyReports(): Promise<MyReport[]> {
  const response = await authenticatedApiRequest('/reports/mine')
  return response as MyReport[]
}

export async function getReadAlertIds(alertIds: string[]): Promise<string[]> {
  if (!supabase || !alertIds.length) return []
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) return []
  const { data, error } = await supabase.from('alert_reads').select('alert_id').in('alert_id', alertIds)
  if (error) throw error
  return (data ?? []).map(item => String(item.alert_id))
}

export async function markAlertsRead(alertIds: string[]): Promise<void> {
  if (!supabase) throw new Error('Sign in to keep track of alert reads.')
  const { data: { user } } = await supabase.auth.getUser()
  if (!user) throw new Error('Sign in to mark alerts as read.')
  const uniqueIds = [...new Set(alertIds)]
  if (!uniqueIds.length) return
  const { error } = await supabase.from('alert_reads').upsert(
    uniqueIds.map(alertId => ({ user_id: user.id, alert_id: alertId, read_at: new Date().toISOString() })),
    { onConflict: 'user_id,alert_id' },
  )
  if (error) throw error
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

export async function createExternalThreatObservation(draft: { targetUrl: string; sourceName: string; sourceUrl: string; expiresAt: string }) {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  let canonicalUrl: string
  try {
    const target = new URL(draft.targetUrl.trim().includes('://') ? draft.targetUrl.trim() : `https://${draft.targetUrl.trim()}`)
    if (!['http:', 'https:'].includes(target.protocol)) throw new Error('Use an HTTP or HTTPS suspicious URL.')
    canonicalUrl = target.toString()
    const source = new URL(draft.sourceUrl.trim())
    if (source.protocol !== 'https:') throw new Error('Use an HTTPS source URL.')
  } catch (error) { throw error instanceof Error ? error : new Error('Use valid URLs.') }
  const { error } = await supabase.rpc('create_external_threat_observation', {
    p_canonical_url: canonicalUrl, p_source_name: draft.sourceName.trim(), p_source_url: draft.sourceUrl.trim(), p_expires_at: draft.expiresAt,
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
  void trainingStatus
  await authenticatedApiRequest(`/moderation/reports/${encodeURIComponent(reportId)}/decision`, {
    method: 'POST',
    body: JSON.stringify({ status: decision, reason: reason.trim() || 'Reviewed by moderator.' }),
  })
}

async function authenticatedApiRequest(path: string, init: RequestInit = {}) {
  if (!supabase) throw new Error('Sign-in is not configured yet.')
  const { data: { session } } = await supabase.auth.getSession()
  if (!session?.access_token) throw new Error('Please sign in before using moderator tools.')
  const baseUrl = import.meta.env.VITE_API_BASE_URL ?? '/api/v1'
  const response = await fetch(`${baseUrl}${path}`, {
    ...init,
    headers: { 'Content-Type': 'application/json', Authorization: `Bearer ${session.access_token}`, ...(init.headers ?? {}) },
  })
  if (!response.ok) {
    const body = await response.json().catch(() => null)
    throw new Error(body?.detail ?? 'Moderator service is unavailable. Please try again.')
  }
  return response.json()
}

export async function requestDataDeletion() {
  if (!supabase) throw new Error('Supabase is not configured yet.')
  const { error } = await supabase.rpc('request_privacy_deletion')
  if (error) throw error
}
