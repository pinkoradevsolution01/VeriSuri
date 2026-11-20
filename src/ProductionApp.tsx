import { lazy, Suspense, type CSSProperties, useEffect, useState } from 'react'
import { scrollToTop } from './lib/browser'
import { SafetyActionPlan } from './components/SafetyActionPlan'
import { AssessmentExplainability } from './components/AssessmentExplainability'
import { IncidentRecovery } from './components/IncidentRecovery'
import { ModeratedAlertPanel } from './components/ModeratedAlertPanel'
import { ScreeningEvidence } from './components/ScreeningEvidence'
import { EvidenceVault } from './components/EvidenceVault'
import { VerifiedAlertsPreview } from './components/VerifiedAlertsPreview'
import { AccessibilityControls } from './components/AccessibilityControls'
import './threat-feeds.css'
import './recommendations.css'
import './action-plan.css'
import './explainability.css'
import './reporting.css'
import './recovery.css'
import './moderated-alerts.css'
import './recovery-strip.css'
import './alerts-metadata.css'
import './screening-evidence.css'
import './vault.css'
import './alerts-preview.css'
import './account-security.css'
import './accessibility.css'
import { ArrowDown, Bell, BrainCircuit, ChevronRight, ClipboardList, Database, Flag, Home as HomeIcon, Link2, MessageSquareText, Search, ShieldCheck, TriangleAlert } from 'lucide-react'
import { analyzeFeature, getAlerts, type Alert, type Assessment } from './lib/api'
import { chooseSubscriptionPlan, getModeratorQueue, isSupabaseConfigured, requestDataDeletion, reviewScamReport, sendMagicLink, signInWithProvider, signOut, submitScamReport, supabase, type ModerationReport, type ReportEntityType, type SubscriptionPlan, type SubscriptionState } from './lib/supabase'

type View = 'overview' | 'home' | 'pay' | 'message' | 'link' | 'reports' | 'report' | 'recovery' | 'vault' | 'alerts' | 'moderation' | 'privacy' | 'security'
const views = new Set<View>(['overview', 'home', 'pay', 'message', 'link', 'reports', 'report', 'recovery', 'vault', 'alerts', 'moderation', 'privacy', 'security'])
const PRIVACY_NOTICE_VERSION = '2026-11-19'
const fromHash = (): View => { const value = window.location.hash.replace(/^#\/?/, '') as View; return views.has(value) ? value : 'overview' }
const samples: Record<'pay' | 'message' | 'link' | 'reports', string> = {
  pay: '0917 123 4567', message: 'Urgent: your account will be suspended. Verify now through the link below.', link: 'https://gcash-verify-ph.com/account', reports: '0917 123 4567',
}
const freeSubscription: SubscriptionState = { subscription_plan: 'free', subscription_status: 'active', pending_plan: null }
const AccountSecurity = lazy(() => import('./components/AccountSecurity').then(module => ({ default: module.AccountSecurity })))

function Brand() { return <span className="brand"><span className="brand-mark"><ShieldCheck size={24} /></span><span>Veri<span>Suri</span></span></span> }
function Score({ assessment }: { assessment: Assessment }) {
  const tone = assessment.level === 'high' ? 'high' : 'medium'
  return <>
    <section className={`result-card ${tone}`}>
      <div><span className={`evidence-confidence ${assessment.evidence_confidence}`}>{assessment.evidence_confidence === 'high' ? 'High-confidence evidence' : assessment.evidence_confidence === 'moderate' ? 'Moderate-confidence evidence' : 'Limited evidence — verification required'}</span><h2>{assessment.verdict}</h2><p>{assessment.summary}</p></div>
      <div className={`score-meter score-${tone}`} aria-label={`Risk score ${assessment.score} out of 100`}>
        <div className="score-ring" style={{ '--score': assessment.score } as CSSProperties & { '--score': number }}><b>{assessment.score}</b><small>/100</small></div>
        <span>Risk score</span>
      </div>
    </section>
    <section className={`recommendation-card ${tone}`} aria-label="Recommended next steps">
      <div><ShieldCheck /><div><p className="recommendation-kicker">Recommended next steps</p><h3>{assessment.recommendation_title}</h3></div></div>
      <ul>{assessment.recommendations.map(item => <li key={item}>{item}</li>)}</ul>
      <p className="assessment-disclaimer">Safety screening only — verify independently. A score is not a guarantee or an accusation.</p>
    </section>
    <p className="assessment-disclaimer required-verification">{assessment.verification_message}</p>
    <SafetyActionPlan tone={tone} />
  </>
}

function Header({ view, navigate, userEmail, canModerate, openAuth, openSecurity }: { view: View; navigate: (view: View) => void; userEmail: string | null; canModerate: boolean; openAuth: () => void; openSecurity: () => void }) {
  return <header><button className="brand-button" onClick={() => navigate('overview')} aria-label="VeriSuri overview"><Brand /></button><nav className="desktop-nav" aria-label="Main navigation"><button className={view === 'overview' ? 'active' : ''} onClick={() => navigate('overview')}>Overview</button><button className={view === 'home' ? 'active' : ''} onClick={() => navigate('home')}>Dashboard</button><button className={view === 'reports' ? 'active' : ''} onClick={() => navigate('reports')}>Report lookup</button><button className={view === 'alerts' ? 'active' : ''} onClick={() => navigate('alerts')}>Safety alerts</button><button className={view === 'report' ? 'active' : ''} onClick={() => navigate('report')}>Report incident</button>{canModerate && <button className={view === 'moderation' ? 'active' : ''} onClick={() => navigate('moderation')}>Moderation</button>}</nav><AccessibilityControls />{userEmail && <button className={`security-button ${view === 'security' ? 'active' : ''}`} onClick={openSecurity}>Security</button>}<button className="auth-button" onClick={openAuth}>{userEmail ? 'Sign out' : 'Sign in'}</button><button className="alert-button" onClick={() => navigate('alerts')} aria-label="Safety alerts"><Bell size={20} /></button></header>
}

function AuthDialog({ close }: { close: () => void }) { const [email, setEmail] = useState(''); const [notice, setNotice] = useState(''); const [loading, setLoading] = useState(false); const oauth = async (provider: 'google' | 'facebook') => { setLoading(true); try { await signInWithProvider(provider) } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not start sign in.') } finally { setLoading(false) } }; const magic = async (event: React.FormEvent) => { event.preventDefault(); setLoading(true); try { await sendMagicLink(email); setNotice('Check your email for the VeriSuri sign-in link.') } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not send the sign-in link.') } finally { setLoading(false) } }; return <div className="auth-overlay" role="dialog" aria-modal="true" aria-labelledby="auth-title"><section className="auth-dialog"><button className="dialog-close" onClick={close} aria-label="Close sign in">x</button><ShieldCheck /><h2 id="auth-title">Join VeriSuri</h2><p>Sign in to submit reports and manage your submitted data.</p>{isSupabaseConfigured ? <><div className="oauth-buttons"><button disabled={loading} onClick={() => oauth('google')}>Continue with Google</button><button disabled={loading} onClick={() => oauth('facebook')}>Continue with Facebook</button></div><div className="auth-divider"><span>or use email</span></div><form onSubmit={magic}><label htmlFor="auth-email">Email address</label><input id="auth-email" type="email" required value={email} onChange={event => setEmail(event.target.value)} placeholder="you@example.com" /><button className="primary-action" disabled={loading}>{loading ? 'Sending...' : 'Send sign-in link'}</button></form></> : <p className="form-error">Supabase authentication is not configured.</p>}{notice && <p className="privacy-note" role="status">{notice}</p>}</section></div> }

function Overview({ navigate, member, userEmail, subscription, choosePlan }: { navigate: (view: View) => void; member: () => void; userEmail: string | null; subscription: SubscriptionState; choosePlan: (plan: SubscriptionPlan) => void }) { const plans: { plan: SubscriptionPlan; name: string; price: string; scans: string; detail: string }[] = [{ plan: 'free', name: 'Free', price: '₱0/month', scans: 'Up to 5/day', detail: 'Free allocation adjusts automatically to protect the shared monthly Web Risk budget.' }, { plan: 'pro', name: 'Pro', price: '₱79/month', scans: 'Up to 30/day', detail: 'A fixed daily Web Risk allowance after verified payment.' }, { plan: 'premium', name: 'Premium', price: '₱149/month', scans: 'Up to 100/day', detail: 'A higher fixed daily Web Risk allowance after verified payment.' }]; return <main className="overview-page"><section className="overview-hero motion-item is-visible"><div><p className="eyebrow">Built for a safer Philippines</p><h1>Think twice.<br /><span>Check with VeriSuri.</span></h1><p>Check suspicious messages, links, payment requests, and reviewed community reports before you act.</p><div className="overview-actions"><button className="primary-action" onClick={member}>{userEmail ? 'Manage your plan' : 'Be a member'} <ChevronRight size={18} /></button><button className="secondary-action" onClick={() => navigate('home')}>Explore protection tools</button></div><p className="hero-assurance"><ShieldCheck size={16} /> Explainable checks, human moderation, and privacy-aware design.</p></div><div className="overview-orbit" aria-hidden="true"><div className="orbit-shield"><ShieldCheck /></div><span className="orbit-pill op-one">Message checks</span><span className="orbit-pill op-two">Link checks</span><span className="orbit-pill op-three">Report matching</span></div></section><section className="overview-section motion-item is-visible"><div className="section-heading"><div><p className="eyebrow">How it works</p><h2>Check. Understand. Act safely.</h2></div><p>Pause before sending money or following a suspicious link.</p></div><div className="how-grid"><article><b>01</b><h3>Check</h3><p>Paste a message or link, or enter a payment identifier.</p></article><article><b>02</b><h3>Understand</h3><p>Read clear risk signals, a score, and a safety recommendation.</p></article><article><b>03</b><h3>Act safely</h3><p>Verify through an official channel or submit a report for review.</p></article></div></section><section className="plans-section motion-item is-visible" aria-labelledby="plans-title"><div className="section-heading"><div><p className="eyebrow">Google Web Risk plans</p><h2 id="plans-title">Choose your daily URL-scan allowance.</h2></div><p>Free is ₱0/month. Its daily allocation can reduce fairly when many Free members share the monthly budget.</p></div><div className="plan-grid">{plans.map(item => { const current = subscription.subscription_plan === item.plan && subscription.subscription_status === 'active'; const pending = subscription.pending_plan === item.plan && subscription.subscription_status === 'pending_payment'; return <article className={`plan-card ${current ? 'current' : ''}`} key={item.plan}><div><h3>{item.name}</h3><strong>{item.price}</strong></div><b>{item.scans}</b><p>{item.detail}</p><button className={item.plan === 'premium' ? 'primary-action' : 'secondary-action'} onClick={() => userEmail ? choosePlan(item.plan) : member()} disabled={current || pending}>{current ? 'Current plan' : pending ? 'Payment setup pending' : item.plan === 'free' ? 'Choose Free' : `Choose ${item.name}`}</button></article> })}</div><p className="plan-note">Paid plans become active only after payment verification. Until then, your active allowance remains Free.</p></section><section className="member-band motion-item is-visible"><div><ShieldCheck /><div><h2>Help build a safer digital Philippines.</h2><p>Reports are reviewed before they influence community results or model-improvement data.</p></div></div><button className="primary-action" onClick={member}>{userEmail ? 'Account settings' : 'Be a member'} <ChevronRight size={18} /></button></section></main> }

function Home({ navigate }: { navigate: (view: View) => void }) { const cards: [View, string, string, typeof ShieldCheck][] = [['pay', 'Before You Pay', 'Check a payment request', ShieldCheck], ['message', 'AI Message Analysis', 'Analyze suspicious messages', MessageSquareText], ['link', 'Link Checker', 'Verify a URL before opening', Link2], ['reports', 'Scam Reports Lookup', 'Search confirmed reports', ClipboardList]]; return <main className="screen home-screen"><section className="hero"><div className="hero-copy"><p className="eyebrow">Philippine anti-scam protection</p><h1>Check Before<br /><span>You Pay</span></h1><p>Use clear risk signals before you send money, click, or share.</p></div><div className="hero-shield"><ShieldCheck /></div></section><section className="feature-grid" aria-label="Protection tools">{cards.map(([id, title, caption, Icon]) => <button key={id} className="feature-card" onClick={() => navigate(id)}><span className="feature-icon"><Icon /></span><strong>{title}</strong><small>{caption}</small></button>)}</section><button className="recovery-strip" onClick={() => navigate('recovery')}><ShieldCheck /><span><b>I already sent money or shared an OTP</b><small>Start urgent recovery steps through official channels.</small></span><ChevronRight /></button><button className="report-strip" onClick={() => navigate('report')}><Flag /><span><b>Report a scam responsibly</b><small>Reports are reviewed before community matching.</small></span><ChevronRight /></button></main> }

function Tool({ type, navigate }: { type: 'pay' | 'message' | 'link' | 'reports'; navigate: (view: View) => void }) {
  const [value, setValue] = useState('')
  const [entityType, setEntityType] = useState('gcash')
  const [result, setResult] = useState<Assessment | null>(null)
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)
  const labels = { pay: ['Before You Pay', 'Enter a GCash, Maya, or bank payment identifier.'], message: ['AI Message Analysis', 'Paste a message to identify scam signals.'], link: ['Suspicious Link Checker', 'Paste a link or a message containing one link.'], reports: ['Scam Reports Lookup', 'Search reviewed community reports before you pay.'] } as const
  const entityTypes = type === 'pay' ? ['gcash', 'maya', 'bank'] : ['gcash', 'maya', 'bank', 'phone']
  const run = async () => { if (!value.trim()) return; setLoading(true); setNotice(''); try { setResult(await analyzeFeature(type, value, entityType)) } catch (error) { setNotice(error instanceof Error ? error.message : 'Unable to check this item.') } finally { setLoading(false) } }
  return <main className="screen tool-screen">
    <button className="back" onClick={() => navigate('home')}>Back to dashboard</button>
    <div className="tool-heading"><span className="tool-icon">{type === 'message' ? <MessageSquareText /> : type === 'link' ? <Link2 /> : type === 'reports' ? <ClipboardList /> : <ShieldCheck />}</span><h1>{labels[type][0]}</h1><p>{labels[type][1]}</p></div>
    {(type === 'pay' || type === 'reports') && <div className="type-tabs">{entityTypes.map(item => <button key={item} className={entityType === item ? 'active' : ''} onClick={() => setEntityType(item)}>{item}</button>)}</div>}
    <label className="input-label" htmlFor="check-value">{type === 'message' ? 'Message to analyze' : type === 'link' ? 'Link or message to check' : 'Identifier to check'}</label>
    <div className="field message-field"><textarea id="check-value" rows={type === 'message' ? 6 : 2} value={value} onChange={event => setValue(event.target.value)} placeholder={samples[type]} /><button onClick={run} aria-label="Run check" disabled={loading}><Search /></button></div>
    <button className="primary-action" onClick={run} disabled={loading}>{loading ? 'Checking...' : type === 'reports' ? 'Search scam reports' : 'Run safety check'} <ChevronRight size={18} /></button>
    {notice && <p className="form-error">{notice}</p>}
    {result && <><Score assessment={result} /><AssessmentExplainability explanations={result.explanations ?? []} /><ScreeningEvidence highlights={result.highlights ?? []} probability={result.calibrated_scam_probability ?? null} basis={result.confidence_basis ?? null} link={result.link_intelligence ?? null} /><section className="signal-list"><h3>Technical signals</h3>{result.signals.map(signal => <p key={signal}><TriangleAlert />{signal}</p>)}</section></>}
  </main>
}

function Report({ navigate }: { navigate: (view: View) => void }) {
  const [entityType, setEntityType] = useState<ReportEntityType>('gcash')
  const [entityValue, setEntityValue] = useState('')
  const [narrative, setNarrative] = useState('')
  const [scamType, setScamType] = useState<'phishing' | 'investment' | 'marketplace' | 'impersonation' | 'loan' | 'romance' | 'job' | 'delivery' | 'other'>('phishing')
  const [paymentProvider, setPaymentProvider] = useState<'gcash' | 'maya' | 'bank' | 'card' | 'crypto' | 'not_applicable'>('not_applicable')
  const [amountRange, setAmountRange] = useState<'under_1000' | '1000_4999' | '5000_19999' | '20000_99999' | '100000_plus' | 'not_stated'>('not_stated')
  const [incidentAt, setIncidentAt] = useState('')
  const [incidentChannel, setIncidentChannel] = useState<'sms' | 'messaging_app' | 'social_media' | 'email' | 'call' | 'website' | 'marketplace' | 'other'>('sms')
  const [evidence, setEvidence] = useState('')
  const [sample, setSample] = useState('')
  const [safe, setSafe] = useState(false)
  const [consent, setConsent] = useState(false)
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setNotice('')
    if (!safe) return setNotice('Confirm that you removed sensitive details before submitting.')
    if (entityValue.trim().length < 3 || narrative.trim().length < 20) return setNotice('Provide a suspicious identifier and at least 20 characters of incident detail.')
    if (evidence.trim() && evidence.trim().length < 20) return setNotice('Redacted evidence must be at least 20 characters, or leave it blank.')
    if (consent && sample.trim().length < 30) return setNotice('Add a redacted sample of at least 30 characters, or turn off optional model consent.')
    setLoading(true)
    try {
      await submitScamReport({ entityType, entityValue, narrative, scamType, paymentProvider, amountRange, incidentAt, incidentChannel, redactedEvidence: evidence, privacyNoticeVersion: PRIVACY_NOTICE_VERSION, acknowledgesSafeSubmission: safe, trainingConsent: consent, redactedTrainingSample: sample })
      setNotice('Report submitted for moderation. Similar identifier matches are flagged for moderator review; this report cannot affect community matching until confirmed.')
      setEntityValue(''); setNarrative(''); setEvidence(''); setSample(''); setSafe(false); setConsent(false)
    } catch (error) { setNotice(error instanceof Error ? error.message : 'Unable to submit the report.') } finally { setLoading(false) }
  }
  return <main className="screen tool-screen">
    <button className="back" onClick={() => navigate('home')}>Back to dashboard</button>
    <div className="tool-heading"><span className="tool-icon"><Flag /></span><h1>Report a scam</h1><p>Share only what is necessary. Reports are private and moderated.</p></div>
    <form className="check-panel" onSubmit={submit}>
      <div className="type-tabs">{(['gcash', 'maya', 'bank', 'phone', 'url', 'social'] as ReportEntityType[]).map(item => <button type="button" key={item} className={entityType === item ? 'active' : ''} onClick={() => setEntityType(item)}>{item}</button>)}</div>
      <label className="input-label" htmlFor="entity">Suspicious URL, number, account, or profile</label>
      <div className="field"><textarea id="entity" rows={1} value={entityValue} onChange={event => setEntityValue(event.target.value)} placeholder="Enter only the suspicious identifier you want reviewed" /></div>
      <div className="report-field-grid">
        <label>Scam type<select value={scamType} onChange={event => setScamType(event.target.value as typeof scamType)}><option value="phishing">Phishing</option><option value="investment">Investment</option><option value="marketplace">Marketplace</option><option value="impersonation">Impersonation</option><option value="loan">Loan</option><option value="romance">Romance</option><option value="job">Job offer</option><option value="delivery">Delivery</option><option value="other">Other</option></select></label>
        <label>Payment provider<select value={paymentProvider} onChange={event => setPaymentProvider(event.target.value as typeof paymentProvider)}><option value="not_applicable">No payment / not stated</option><option value="gcash">GCash</option><option value="maya">Maya</option><option value="bank">Bank transfer</option><option value="card">Card</option><option value="crypto">Crypto</option></select></label>
        <label>Amount range<select value={amountRange} onChange={event => setAmountRange(event.target.value as typeof amountRange)}><option value="not_stated">Not stated</option><option value="under_1000">Under PHP 1,000</option><option value="1000_4999">PHP 1,000–4,999</option><option value="5000_19999">PHP 5,000–19,999</option><option value="20000_99999">PHP 20,000–99,999</option><option value="100000_plus">PHP 100,000+</option></select></label>
        <label>How it reached you<select value={incidentChannel} onChange={event => setIncidentChannel(event.target.value as typeof incidentChannel)}><option value="sms">SMS</option><option value="messaging_app">Messaging app</option><option value="social_media">Social media</option><option value="email">Email</option><option value="call">Phone call</option><option value="website">Website</option><option value="marketplace">Marketplace</option><option value="other">Other</option></select></label>
        <label className="report-field-wide" htmlFor="incident-time">When did it happen? (optional)<input id="incident-time" type="datetime-local" value={incidentAt} onChange={event => setIncidentAt(event.target.value)} /></label>
      </div>
      <label className="input-label" htmlFor="narrative">What happened?</label>
      <div className="field message-field"><textarea id="narrative" rows={5} value={narrative} onChange={event => setNarrative(event.target.value)} placeholder="Describe what happened. Do not include passwords, OTPs, PINs, or full card details." /></div>
      <label className="input-label" htmlFor="evidence">Optional redacted evidence</label>
      <p className="report-privacy-hint">Paste a redacted excerpt, transaction reference, or notes for a moderator. Replace names, full account numbers, URLs, OTPs, and passwords with [REDACTED].</p>
      <div className="field message-field"><textarea id="evidence" rows={4} value={evidence} onChange={event => setEvidence(event.target.value)} placeholder="Optional: [REDACTED] text or evidence details for moderator review" /></div>
      <section className="privacy-consent"><p><b>Privacy and safe submission</b><br />We store a protected hash of the reported identifier for matching. Similar reports are marked as possible duplicates for moderator review, not automatically published.</p><label className="consent-row"><input type="checkbox" checked={safe} onChange={event => setSafe(event.target.checked)} /><span>I have the right to submit this report and removed passwords, OTPs, PINs, full card details, and unrelated personal information.</span></label><label className="consent-row optional"><input type="checkbox" checked={consent} onChange={event => setConsent(event.target.checked)} /><span><b>Optional:</b> I consent to provide a separate redacted sample for model improvement after moderator approval. This never happens automatically.</span></label>{consent && <><label className="input-label" htmlFor="sample">Redacted message sample</label><div className="field message-field"><textarea id="sample" rows={4} value={sample} onChange={event => setSample(event.target.value)} placeholder="Replace names, account numbers, links, and OTPs with [REDACTED]." /></div></>}</section>
      <p className="data-link">Notice version {PRIVACY_NOTICE_VERSION}. <button type="button" onClick={() => navigate('privacy')}>Read how VeriSuri handles data</button></p>
      <button className="primary-action" disabled={loading || !isSupabaseConfigured}>{loading ? 'Submitting...' : 'Submit for review'} <ChevronRight size={18} /></button>
      {!isSupabaseConfigured && <p className="form-error">Report submission needs Supabase configuration.</p>}{notice && <p className="privacy-note" role="status">{notice}</p>}
    </form>
  </main>
}

function Moderation({ navigate }: { navigate: (view: View) => void }) {
  const [queue, setQueue] = useState<ModerationReport[]>([])
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(true)
  const [active, setActive] = useState<string | null>(null)
  useEffect(() => { getModeratorQueue().then(setQueue).catch(error => setNotice(error instanceof Error ? error.message : 'Unable to load moderation queue.')).finally(() => setLoading(false)) }, [])
  const decide = async (report: ModerationReport, decision: 'confirmed' | 'rejected') => { setActive(report.id); try { await reviewScamReport(report.id, decision, decision === 'confirmed' ? 'Verified by moderator review.' : 'Not sufficiently verified.'); setQueue(current => current.filter(item => item.id !== report.id)); setNotice(`Report ${decision}.`) } catch (error) { setNotice(error instanceof Error ? error.message : 'Unable to save review.') } finally { setActive(null) } }
  return <main className="screen tool-screen moderation-screen">
    <button className="back" onClick={() => navigate('home')}>Back to dashboard</button>
    <div className="tool-heading"><span className="tool-icon"><ShieldCheck /></span><h1>Moderation queue</h1><p>Confirm reports only when evidence is adequate. Confirmed results can affect community matching.</p></div>
    {loading ? <p className="privacy-note">Loading pending reports...</p> : <section className="moderation-list">{queue.length ? queue.map(report => <article className="moderation-card" key={report.id}>
      <div className="moderation-meta"><b>{report.reported_entities.map(entity => `${entity.entity_type} ending ${entity.entity_last4 ?? 'hidden'}`).join(' / ')}</b><small>{new Date(report.created_at).toLocaleString()}</small></div>
      <div className="moderation-details"><span>{report.scam_type.replace('_', ' ')}</span><span>{report.payment_provider.replace('_', ' ')}</span><span>{report.amount_range.replace(/_/g, ' ')}</span><span>{report.incident_channel.replace(/_/g, ' ')}</span>{report.incident_at && <span>{new Date(report.incident_at).toLocaleString()}</span>}</div>
      {report.duplicate_count > 0 && <p className="moderation-duplicate">Possible duplicate: {report.duplicate_count} existing pending or confirmed report(s) share this protected identifier. Review independently before deciding.</p>}
      <p>{report.narrative}</p>
      {report.redacted_evidence && <p className="moderation-evidence"><b>Redacted evidence:</b> {report.redacted_evidence}</p>}
      {report.training_consent && <p className="training-tag">A separately redacted sample is awaiting model-data review.</p>}
      <div className="moderation-actions"><button disabled={active === report.id} onClick={() => decide(report, 'rejected')}>Reject</button><button className="approve" disabled={active === report.id} onClick={() => decide(report, 'confirmed')}>{active === report.id ? 'Saving...' : 'Confirm report'}</button></div>
    </article>) : <p className="empty-state">No pending reports. Only confirmed reports contribute to matching.</p>}</section>}
    <ModeratedAlertPanel />
    {notice && <p className="privacy-note" role="status">{notice}</p>}
  </main>
}

function Privacy({ navigate, signedIn }: { navigate: (view: View) => void; signedIn: boolean }) { const [notice, setNotice] = useState(''); const [loading, setLoading] = useState(false); const request = async () => { setLoading(true); try { await requestDataDeletion(); setNotice('Your request was recorded. Pending opted-in training samples were withdrawn from review.') } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not submit the request.') } finally { setLoading(false) } }; return <main className="screen tool-screen privacy-screen"><button className="back" onClick={() => navigate('overview')}>Back to overview</button><div className="tool-heading"><span className="tool-icon"><ShieldCheck /></span><h1>Privacy and data use</h1><p>Product implementation notice, version {PRIVACY_NOTICE_VERSION}</p></div><section className="privacy-card"><h2>What we collect</h2><p>Reports contain a narrative and a one-way hash of the reported identifier. Do not provide passwords, OTPs, PINs, full accounts, full card numbers, or unrelated personal data.</p><h2>How training is handled</h2><p>Model-improvement data is opt-in, supplied separately in redacted form, and remains pending until a moderator approves it. Reporting a scam is not permission to train on it.</p><h2>Your choices</h2><p>You can report without contributing training data. You may request deletion of data connected to your account. This notice must be completed with your organization’s DPO contact details and formally reviewed before public launch.</p>{signedIn ? <button className="secondary-action deletion-button" disabled={loading} onClick={request}>{loading ? 'Submitting request...' : 'Request deletion of my submitted data'}</button> : <p className="privacy-note">Sign in to request deletion of data connected to your account.</p>}{notice && <p className="privacy-note" role="status">{notice}</p>}</section></main> }

function Alerts({ navigate }: { navigate: (view: View) => void }) {
  const [items, setItems] = useState<Alert[]>([])
  useEffect(() => { getAlerts().then(setItems).catch(() => undefined) }, [])
  return <main className="screen tool-screen alerts-screen">
    <button className="back" onClick={() => navigate('home')}>Back to dashboard</button>
    <div className="tool-heading"><span className="tool-icon"><Bell /></span><h1>Safety alerts</h1><p>Only moderator-verified advisories with an official source and active review date appear here.</p></div>
    <section className="alert-list">{items.length ? items.map(item => <article className={`alert-item verified-alert ${item.severity === 'high' ? 'danger' : item.severity === 'medium' ? 'warning' : ''}`} key={item.id}>
      <span><TriangleAlert /></span><div><p className="verified-label">Verified advisory</p><h3>{item.title}</h3><p>{item.summary}</p><div className="alert-details"><small>Platform: {item.affected_platform}</small>{item.region && <small>Region: {item.region}</small>}<small>Published: {new Date(item.published_at).toLocaleDateString()}</small><small>Review by: {new Date(item.review_at).toLocaleDateString()}</small></div><a href={item.source_url} target="_blank" rel="noopener noreferrer">Source: {item.source_name}</a></div>
    </article>) : <p className="empty-state">No verified, active advisories are available yet.</p>}</section>
  </main>
}

function FeedArchitecture() { return <><VerifiedAlertsPreview openAlerts={() => { window.location.hash = '#/alerts' }} /><section className="feed-architecture motion-item is-visible" aria-labelledby="feed-architecture-title"><div className="section-heading"><div><p className="eyebrow">Starting URL protection</p><h2 id="feed-architecture-title">Zero-API-fee threat intelligence.</h2></div><p>Live public threat feeds are combined with VeriSuri’s explainable Python checks. A clean result never guarantees that a link is safe.</p></div><div className="feed-flow"><div className="feed-origin"><Link2 /><h3>VeriSuri URL Scanner</h3></div><ArrowDown className="feed-arrow" aria-hidden="true" /><div className="feed-sources"><article><ShieldCheck /><h3>PhishDestroy</h3><p>Live phishing and scam domain reputation</p></article><article><Database /><h3>CERT Polska</h3><p>Known dangerous domains</p></article></div><ArrowDown className="feed-arrow" aria-hidden="true" /><article className="feed-engine"><BrainCircuit /><h3>Your Python Detection Engine</h3><p>URL structure, suspicious keywords, lookalike domains, and transparent risk scoring.</p></article><ArrowDown className="feed-arrow" aria-hidden="true" /><div className="feed-outcome"><ShieldCheck /><h3>VeriSuri Risk Assessment</h3><p>Evidence, uncertainty, score, and a safer next action.</p></div></div><p className="feed-disclosure">Powered in part by PhishDestroy CTI (CC BY 4.0). Google Web Risk remains in the codebase as an optional future commercial source and is disabled by default.</p></section></> }

function BottomNav({ view, navigate }: { view: View; navigate: (view: View) => void }) { return <nav className="bottom-nav" aria-label="Mobile navigation"><button className={view === 'home' ? 'active' : ''} onClick={() => navigate('home')}><HomeIcon /><span>Dashboard</span></button><button className={view === 'reports' ? 'active' : ''} onClick={() => navigate('reports')}><ClipboardList /><span>Reports</span></button><button className={view === 'alerts' ? 'active' : ''} onClick={() => navigate('alerts')}><Bell /><span>Alerts</span></button></nav> }

export default function ProductionApp() { const [view, setView] = useState<View>(fromHash); const [userEmail, setUserEmail] = useState<string | null>(null); const [role, setRole] = useState<string | null>(null); const [subscription, setSubscription] = useState<SubscriptionState>(freeSubscription); const [authOpen, setAuthOpen] = useState(false); const navigate = (next: View) => { if (window.location.hash === `#/${next}`) { setView(next); scrollToTop() } else window.location.hash = `#/${next}` }; useEffect(() => { const sync = () => { setView(fromHash()); scrollToTop() }; window.addEventListener('hashchange', sync); return () => window.removeEventListener('hashchange', sync) }, []); useEffect(() => { const client = supabase; if (!client) return; const sync = async () => { try { const { data } = await client.auth.getUser(); setUserEmail(data.user?.email ?? null); if (!data.user) { setRole(null); setSubscription(freeSubscription); return }; const { data: profile } = await client.from('profiles').select('role,subscription_plan,subscription_status,pending_plan').eq('id', data.user.id).maybeSingle(); setRole(profile?.role ?? 'user'); if (profile?.subscription_plan && profile.subscription_status) setSubscription(profile as SubscriptionState) } catch { setUserEmail(null); setRole(null); setSubscription(freeSubscription) } }; void sync(); const { data: { subscription } } = client.auth.onAuthStateChange(() => { void sync() }); return () => subscription.unsubscribe() }, []); const isModerator = role === 'moderator' || role === 'admin'; const auth = async () => { if (userEmail) { try { await signOut() } catch { setAuthOpen(true) } } else setAuthOpen(true) }; const selectPlan = async (plan: SubscriptionPlan) => { try { setSubscription(await chooseSubscriptionPlan(plan)) } catch { setAuthOpen(true) } }; const overview = <><Overview navigate={navigate} member={auth} userEmail={userEmail} subscription={subscription} choosePlan={plan => void selectPlan(plan)} /><FeedArchitecture /></>; const page = view === 'overview' ? overview : view === 'home' ? <Home navigate={navigate} /> : view === 'alerts' ? <Alerts navigate={navigate} /> : view === 'report' ? <Report navigate={navigate} /> : view === 'recovery' ? <IncidentRecovery report={() => navigate('report')} /> : view === 'vault' ? <EvidenceVault back={() => navigate('home')} /> : view === 'security' ? userEmail ? <AccountSecurity back={() => navigate('overview')} isStaff={isModerator} /> : <Privacy navigate={navigate} signedIn={false} /> : view === 'moderation' ? isModerator ? <Moderation navigate={navigate} /> : <Privacy navigate={navigate} signedIn={Boolean(userEmail)} /> : view === 'privacy' ? <Privacy navigate={navigate} signedIn={Boolean(userEmail)} /> : <Tool type={view} navigate={navigate} />; return <div className={`app-shell antialiased page-${view}`}><a className="skip-link" href="#main-content">Skip to main content</a><div className="ambient ambient-one" /><div className="ambient ambient-two" /><div className="app-canvas"><Header view={view} navigate={navigate} userEmail={userEmail} canModerate={isModerator} openAuth={auth} openSecurity={() => navigate('security')} /><div id="main-content" tabIndex={-1}><Suspense fallback={<main className="screen"><p className="privacy-note" role="status">Loading secure account tools…</p></main>}>{page}</Suspense></div><BottomNav view={view} navigate={navigate} /></div>{authOpen && <AuthDialog close={() => setAuthOpen(false)} />}</div> }
