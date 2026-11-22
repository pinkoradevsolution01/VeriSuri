import { type CSSProperties, useEffect, useRef, useState } from 'react'
import {
  Bell, CheckCircle2, ChevronRight, CircleHelp, ClipboardList,
  Download, Flag, Home, Link2, MessageSquareText, Search, Shield, ShieldAlert,
  ShieldCheck, TriangleAlert
} from 'lucide-react'
import { analyzeFeature, getAlerts, type Alert, type Assessment } from './lib/api'
import { isSupabaseConfigured, sendMagicLink, signInWithProvider, signOut, submitScamReport, supabase } from './lib/supabase'

type View = 'overview' | 'home' | 'pay' | 'message' | 'link' | 'reports' | 'report' | 'alerts'

const validViews = new Set<View>(['overview', 'home', 'pay', 'message', 'link', 'reports', 'report', 'alerts'])
const viewFromHash = (): View => {
  const candidate = window.location.hash.replace('#/', '').replace('#', '') as View
  return validViews.has(candidate) ? candidate : 'overview'
}

const features: { id: View; title: string; caption: string; icon: typeof ShieldCheck }[] = [
  { id: 'pay', title: 'Before You Pay', caption: 'Check a payment request', icon: ShieldCheck },
  { id: 'message', title: 'AI Message Analysis', caption: 'Analyze suspicious messages', icon: MessageSquareText },
  { id: 'link', title: 'Link Checker', caption: 'Verify a URL before opening', icon: Link2 },
  { id: 'reports', title: 'Scam Reports Lookup', caption: 'Search community reports', icon: ClipboardList },
]

const alerts = [
  ['New GCash Phishing Scam Alert', 'Fake account verification messages are being sent to GCash users.', '2h ago', 'danger'],
  ['BPI Impersonation Scam', 'Beware of texts claiming to be from BPI asking for your account.', '5h ago', 'warning'],
  ['Ongoing Smishing Campaign', 'Multiple reports of fake delivery and refund messages in the Philippines.', 'Yesterday', 'info'],
]

function Brand({ compact = false }: { compact?: boolean }) {
  return <div className="brand"><span className="brand-mark"><ShieldCheck size={compact ? 22 : 27} /></span><span>Veri<span>Suri</span></span></div>
}

function RiskCard({ title = 'Safe to Pay', subtle = 'No scam reports found for this account in our database.', danger = false, score }: { title?: string; subtle?: string; danger?: boolean; score?: number }) {
  const scoreTone = typeof score === 'number' ? score >= 65 ? 'high' : score >= 30 ? 'medium' : 'low' : 'low'
  return <div className={`risk-card ${danger ? 'risk-danger' : ''}`}>
    {danger ? <ShieldAlert size={34} /> : <ShieldCheck size={34} />}
    <div><strong>{title}</strong><p>{subtle}</p></div>
    {typeof score === 'number' && <div className={`score-meter score-${scoreTone}`} aria-label={`Risk score ${score} out of 100`}><div className="score-ring" style={{ '--score': score } as CSSProperties & { '--score': number }}><b>{score}</b><small>/100</small></div><span>Risk score</span></div>}
  </div>
}

function Header({ view, setView, canInstall, onInstall, userEmail, onAuth }: { view: View; setView: (view: View) => void; canInstall: boolean; onInstall: () => void; userEmail: string | null; onAuth: () => void }) {
  return <header>
    <button className="brand-button" onClick={() => setView('overview')} aria-label="VeriSuri overview"><Brand compact /></button>
    <nav className="desktop-nav" aria-label="Main navigation">
      <button className={view === 'overview' ? 'active' : ''} onClick={() => setView('overview')}>Overview</button>
      <button className={view === 'home' ? 'active' : ''} onClick={() => setView('home')}>Dashboard</button>
      <button className={view === 'reports' ? 'active' : ''} onClick={() => setView('reports')}>Report lookup</button>
      <button className={view === 'alerts' ? 'active' : ''} onClick={() => setView('alerts')}>Safety alerts</button>
      <button onClick={() => setView('report')}>Report incident</button>
    </nav>
    {canInstall && <button className="install-action" onClick={onInstall}><Download size={17} /> Install</button>}
    <button className="auth-button" onClick={onAuth}>{userEmail ? 'Sign out' : 'Sign in'}</button>
    <button className="alert-button" onClick={() => setView('alerts')} aria-label="Open safety alerts"><Bell size={20} /></button>
  </header>
}

function AuthDialog({ onClose }: { onClose: () => void }) {
  const [email, setEmail] = useState(''); const [notice, setNotice] = useState(''); const [loading, setLoading] = useState(false)
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setLoading(true); setNotice(''); try { await sendMagicLink(email); setNotice('Check your email for the VeriSuri sign-in link.') } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not send the sign-in link.') } finally { setLoading(false) } }
  const oauth = async (provider: 'google' | 'facebook') => { setLoading(true); setNotice(''); try { await signInWithProvider(provider) } catch (error) { setNotice(error instanceof Error ? error.message : 'Could not start sign-in.') } finally { setLoading(false) } }
  return <div className="auth-overlay" role="dialog" aria-modal="true" aria-labelledby="auth-title"><section className="auth-dialog"><button className="dialog-close" onClick={onClose} aria-label="Close sign in">×</button><ShieldCheck /><h2 id="auth-title">Join VeriSuri</h2><p>Create an account to submit reports, help improve community intelligence, and keep track of your submissions.</p>{isSupabaseConfigured ? <><div className="oauth-buttons"><button type="button" onClick={() => oauth('google')} disabled={loading}>Continue with Google</button><button type="button" onClick={() => oauth('facebook')} disabled={loading}>Continue with Facebook</button></div><div className="auth-divider"><span>or use email</span></div><form onSubmit={submit}><label htmlFor="auth-email">Email address</label><input id="auth-email" type="email" value={email} onChange={event => setEmail(event.target.value)} required placeholder="you@example.com" /><button className="primary-action" disabled={loading}>{loading ? 'Sending…' : 'Send sign-in link'}</button></form></> : <p className="form-error">Supabase authentication is not configured.</p>}{notice && <p className="privacy-note" role="status">{notice}</p>}</section></div>
}

function OverviewScreen({ setView, onMember }: { setView: (view: View) => void; onMember: () => void }) {
  const orbitRef = useRef<HTMLDivElement>(null)
  useEffect(() => { let previous = window.scrollY; let rotation = 0; let frame = 0; const onScroll = () => { if (frame) return; frame = requestAnimationFrame(() => { const next = window.scrollY; rotation += (next - previous) * 0.12; previous = next; orbitRef.current?.style.setProperty('--scroll-rotation', `${rotation}deg`); frame = 0 }) }; window.addEventListener('scroll', onScroll, { passive: true }); return () => { window.removeEventListener('scroll', onScroll); cancelAnimationFrame(frame) } }, [])
  return <main className="overview-page"><section className="overview-hero motion-item"><div><p className="eyebrow">Built for a safer Philippines</p><h1>Think twice.<br /><span>Check with VeriSuri.</span></h1><p>VeriSuri is a Philippine-focused protection app that helps people assess suspicious messages, links, payment requests, and community scam reports before they act.</p><div className="overview-actions"><button className="primary-action" onClick={onMember}>Be a member <ChevronRight size={19} /></button><button className="secondary-action" onClick={() => setView('home')}>Explore protection tools</button></div><p className="hero-assurance"><ShieldCheck size={17} /> Built around explainable checks, community review, and privacy-aware design.</p></div><div ref={orbitRef} className="overview-orbit" aria-hidden="true"><div className="orbit-shield"><ShieldCheck /></div><span className="orbit-pill op-one">Message checks</span><span className="orbit-pill op-two">Link checks</span><span className="orbit-pill op-three">Report matching</span></div></section><section className="overview-section motion-item"><div className="section-heading"><div><p className="eyebrow">How VeriSuri works</p><h2>One careful check before one costly decision</h2></div><p>Use the app before you send money, follow a link, or trust an unfamiliar account.</p></div><div className="how-grid"><article><b>01</b><h3>Check</h3><p>Paste a message or link, or enter a payment identifier.</p></article><article><b>02</b><h3>Understand</h3><p>See clear risk signals and a plain-language recommendation.</p></article><article><b>03</b><h3>Act safely</h3><p>Verify through official channels or submit a report for moderation.</p></article></div></section><section className="benefit-section motion-item"><div><p className="eyebrow">Why it matters</p><h2>Safer decisions can scale to millions of Filipinos.</h2><p>When people can pause, verify, and report suspicious activity, communities gain stronger signals against recurring scams. VeriSuri is designed to make those safer choices easier on mobile, desktop, and the web.</p></div><ul><li><CheckCircle2 /> Clear checks for everyday payment and message decisions</li><li><CheckCircle2 /> Reviewed community reporting designed to reduce harmful misinformation</li><li><CheckCircle2 /> Philippine-focused language and scam-pattern support</li></ul></section><section className="member-band motion-item"><div><ShieldCheck /><div><h2>Help build a safer digital Philippines.</h2><p>Join VeriSuri to contribute responsibly reviewed reports and protect your next transaction.</p></div></div><button className="primary-action" onClick={onMember}>Be a member <ChevronRight size={19} /></button></section></main>
}

function HomeScreen({ setView }: { setView: (view: View) => void }) {
  return <main className="screen home-screen">
    <section className="hero">
      <div className="hero-copy"><p className="eyebrow">Philippine anti-scam protection</p><h1>Check Before<br /><span>You Pay</span></h1><p>Prevent scams with AI, community intelligence, and payment safety checks made for Filipinos.</p></div>
      <div className="hero-shield"><ShieldCheck /><span className="map-dot dot-a" /><span className="map-dot dot-b" /><span className="map-dot dot-c" /></div>
    </section>
    <section className="feature-grid" aria-label="Protection tools">
      {features.map(({ id, title, caption, icon: Icon }) => <button key={id} className="feature-card" onClick={() => setView(id)}>
        <span className="feature-icon"><Icon /></span><strong>{title}</strong><small>{caption}</small>
      </button>)}
    </section>
    <button className="report-strip" onClick={() => setView('reports')}><Flag /><span><b>Search scam reports</b><small>Check reviewed community reports before you pay.</small></span><ChevronRight /></button>
    <section className="trust-row"><div><b>250K+</b><span>Filipinos Protected</span></div><div><b>1.8M+</b><span>Messages Analyzed</span></div><div><b>320K+</b><span>Scam Reports</span></div></section>
  </main>
}

function FormScreen({ type, setView }: { type: Exclude<View, 'overview' | 'home' | 'alerts' | 'report'>; setView: (view: View) => void }) {
  const [value, setValue] = useState('')
  const [choice, setChoice] = useState('gcash')
  const [checked, setChecked] = useState(false)
  const [loading, setLoading] = useState(false)
  const [error, setError] = useState('')
  const [assessment, setAssessment] = useState<Assessment | null>(null)
  const content = {
    pay: { title: 'Before You Pay', subtitle: 'Check a GCash, Maya, or bank payment request before sending money.', placeholder: '0917 123 4567', label: 'Enter account, number, or payment link', tabs: ['GCash', 'Maya', 'Bank'], result: ['Safe to Pay', 'No scam reports found for this account in our database.'] },
    message: { title: 'AI Message Analysis', subtitle: 'Paste a message and let VeriSuri AI identify scam signals.', placeholder: 'Paste the message you received here...', label: 'Message to Analyze', tabs: [], result: ['High Risk Detected', 'Urgency language, account verification claims, and a suspicious link were detected.'] },
    link: { title: 'Suspicious Link Checker', subtitle: 'Check if a link is safe before you open it or share information.', placeholder: 'https://example.com/account', label: 'URL to check', tabs: [], result: ['Dangerous Link Detected', 'This link shows phishing indicators. Do not enter account details.'] },
    reports: { title: 'Scam Reports Lookup', subtitle: 'See if an account, mobile number, or seller is reported for scams.', placeholder: '0917 888 1234', label: 'GCash account / mobile number', tabs: ['GCash', 'Bank', 'Phone'], result: ['Reported for Scam', 'This account has confirmed community scam reports.' ], },
  }[type]
  const danger = type === 'message' || type === 'link' || type === 'reports'
  const fallback = { verdict: content.result[0], summary: content.result[1], signals: ['Uses urgency to pressure the recipient', 'Requests verification through a link', 'Mimics an official service'] }
  const result = assessment ?? fallback
  const runAssessment = async () => {
    if (value.trim().length < 3) { setError('Enter a message, account, or link to check.'); return }
    setLoading(true); setError(''); setChecked(false)
    try { setAssessment(await analyzeFeature(type, value, choice)); setChecked(true) }
    catch (cause) { setError(cause instanceof Error ? cause.message : 'Unable to complete this check.') }
    finally { setLoading(false) }
  }
  return <main className="screen tool-screen">
    <button className="back" onClick={() => setView('home')}>← <span>Back</span></button>
    <div className="tool-heading"><span className="tool-icon">{type === 'message' ? <MessageSquareText /> : type === 'link' ? <Link2 /> : type === 'reports' ? <ClipboardList /> : <ShieldCheck />}</span><h1>{content.title}</h1><p>{content.subtitle}</p></div>
    {content.tabs.length > 0 && <div className="type-tabs">{content.tabs.map(tab => { const id = tab.toLowerCase(); return <button type="button" key={tab} className={choice === id ? 'active' : ''} onClick={() => setChoice(id)}>{choice === id && <Shield size={15} />}{tab}</button> })}</div>}
    <label className="input-label">{content.label}</label>
    <div className={`field ${type === 'message' ? 'message-field' : ''}`}><textarea rows={type === 'message' ? 5 : 1} value={value} onChange={e => setValue(e.target.value)} placeholder={content.placeholder} /><button aria-label="Analyze" onClick={runAssessment} disabled={loading}><Search /></button></div>
    <button className="primary-action" onClick={runAssessment} disabled={loading}>{loading ? 'Checking…' : type === 'link' ? 'Check Link' : type === 'message' ? 'Analyze Message' : type === 'reports' ? 'Search Reports' : 'Check Now'} <ChevronRight size={19} /></button>
    {error && <p className="form-error">{error}</p>}
    {checked && <><RiskCard title={result.verdict} subtle={result.summary} danger={assessment ? assessment.level === 'high' : danger} score={assessment?.score} />
      {result.signals.length > 0 && <div className="signal-list"><h3>Detected warning signs</h3>{result.signals.map(signal => <p key={signal}><TriangleAlert /> {signal}</p>)}</div>}
      {!danger && <div className="safe-stats"><span>Account Type<b>{choice === 'gcash' ? 'GCash' : choice === 'maya' ? 'Maya' : 'Bank'} Account</b></span><span>Community Reports<b>0</b></span><span>Last Checked<b>Just now</b></span></div>}
    </>}
    {!checked && <div className="privacy-note"><ShieldCheck size={16} /> Your check is private and protected.</div>}
  </main>
}

function ReportScreen({ setView }: { setView: (view: View) => void }) {
  const [entityType, setEntityType] = useState<'gcash' | 'maya' | 'bank' | 'phone' | 'url' | 'social'>('gcash')
  const [entityValue, setEntityValue] = useState(''); const [narrative, setNarrative] = useState(''); const [notice, setNotice] = useState(''); const [loading, setLoading] = useState(false)
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setNotice(''); if (entityValue.trim().length < 3 || narrative.trim().length < 20) { setNotice('Provide an identifier and at least 20 characters of incident detail.'); return }; setLoading(true); try { await submitScamReport({ entityType, entityValue, narrative, privacyNoticeVersion: 'legacy-ui', acknowledgesSafeSubmission: true, trainingConsent: false, publicContributorConsent: false }); setNotice('Report submitted for moderation. Thank you for helping protect others.'); setEntityValue(''); setNarrative('') } catch (error) { setNotice(error instanceof Error ? error.message : 'Unable to submit your report.') } finally { setLoading(false) } }
  return <main className="screen tool-screen"><button className="back" onClick={() => setView('home')}>← <span>Back to dashboard</span></button><div className="tool-heading"><span className="tool-icon"><Flag /></span><h1>Report a scam</h1><p>Reports are private and reviewed before they affect community matching results.</p></div><section className="check-panel"><form onSubmit={submit}><div className="type-tabs">{(['gcash','maya','bank','phone','url'] as const).map(item => <button type="button" key={item} className={entityType === item ? 'active' : ''} onClick={() => setEntityType(item)}>{item[0].toUpperCase() + item.slice(1)}</button>)}</div><label className="input-label" htmlFor="report-entity">Reported identifier</label><div className="field"><textarea id="report-entity" rows={1} value={entityValue} onChange={event => setEntityValue(event.target.value)} placeholder="Account, phone number, profile, or link" /></div><label className="input-label" htmlFor="report-details">What happened?</label><div className="field message-field"><textarea id="report-details" rows={6} value={narrative} onChange={event => setNarrative(event.target.value)} placeholder="Describe the scam. Do not include OTPs, passwords, or full account details." /></div><button className="primary-action" disabled={loading || !isSupabaseConfigured}>{loading ? 'Submitting…' : 'Submit for review'} <ChevronRight size={19} /></button>{!isSupabaseConfigured && <p className="form-error">Report submission needs VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.</p>}{notice && <p className="privacy-note" role="status">{notice}</p>}</form></section></main>
}

function AlertsScreen({ setView }: { setView: (view: View) => void }) {
  const [liveAlerts, setLiveAlerts] = useState<Alert[]>([])
  useEffect(() => { getAlerts().then(setLiveAlerts).catch(() => undefined) }, [])
  const alertFeed = liveAlerts.length ? liveAlerts.map(item => [item.title, item.summary, new Date(item.published_at).toLocaleDateString(), item.severity === 'high' ? 'danger' : item.severity === 'medium' ? 'warning' : 'info']) : alerts
  return <main className="screen tool-screen alerts-screen"><button className="back" onClick={() => setView('home')}>← <span>Back to dashboard</span></button><div className="tool-heading"><span className="tool-icon"><Bell /></span><h1>Safety alerts</h1><p>Moderated scam advisories and important safety updates for the Philippines.</p></div><section className="alert-list">{alertFeed.map(([title, copy, time, kind]) => <article key={title} className={`alert-item ${kind}`}><span>{kind === 'danger' ? <TriangleAlert /> : kind === 'warning' ? <TriangleAlert /> : <CircleHelp />}</span><div><h3>{title}</h3><p>{copy}</p><small>{time}</small></div><ChevronRight size={18} /></article>)}</section></main>
}

function BottomNav({ view, setView }: { view: View; setView: (view: View) => void }) {
  return <nav className="bottom-nav" aria-label="Mobile navigation"><button className={view === 'home' ? 'active' : ''} onClick={() => setView('home')}><Home /><span>Dashboard</span></button><button className={view === 'reports' ? 'active' : ''} onClick={() => setView('reports')}><ClipboardList /><span>Reports</span></button><button className={view === 'alerts' ? 'active' : ''} onClick={() => setView('alerts')}><Bell /><span>Alerts</span></button></nav>
}

export default function App() {
  const [view, setView] = useState<View>(viewFromHash)
  useEffect(() => { const items = Array.from(document.querySelectorAll<HTMLElement>('.motion-item')); const observer = new IntersectionObserver(entries => entries.forEach(entry => { if (entry.isIntersecting) { entry.target.classList.add('is-visible'); observer.unobserve(entry.target) } }), { threshold: 0.14 }); items.forEach(item => observer.observe(item)); return () => observer.disconnect() }, [view])
  const [userEmail, setUserEmail] = useState<string | null>(null)
  const [authOpen, setAuthOpen] = useState(false)
  useEffect(() => { if (!supabase) return; supabase.auth.getUser().then(({ data }) => setUserEmail(data.user?.email ?? null)); const { data: { subscription } } = supabase.auth.onAuthStateChange((_event, session) => setUserEmail(session?.user.email ?? null)); return () => subscription.unsubscribe() }, [])
  useEffect(() => { const syncRoute = () => { setView(viewFromHash()); window.scrollTo({ top: 0, behavior: 'smooth' }) }; window.addEventListener('hashchange', syncRoute); return () => window.removeEventListener('hashchange', syncRoute) }, [])
  const navigate = (next: View) => { const target = `#/${next}`; if (window.location.hash === target) { setView(next); window.scrollTo({ top: 0, behavior: 'smooth' }) } else window.location.hash = target }
  const [installPrompt, setInstallPrompt] = useState<{ prompt: () => Promise<void>; userChoice: Promise<{ outcome: string }> } | null>(null)
  useEffect(() => { const capture = (event: Event) => { event.preventDefault(); setInstallPrompt(event as unknown as { prompt: () => Promise<void>; userChoice: Promise<{ outcome: string }> }) }; window.addEventListener('beforeinstallprompt', capture); return () => window.removeEventListener('beforeinstallprompt', capture) }, [])
  const install = async () => { if (!installPrompt) return; await installPrompt.prompt(); await installPrompt.userChoice; setInstallPrompt(null) }
  const openAuth = async () => { if (userEmail) { await signOut(); return }; setAuthOpen(true) }
  return <div className={`app-shell antialiased page-${view}`}><div className="ambient ambient-one" /><div className="ambient ambient-two" /><div className="app-canvas"><Header view={view} setView={navigate} canInstall={Boolean(installPrompt)} onInstall={install} userEmail={userEmail} onAuth={openAuth} />{view === 'overview' ? <OverviewScreen setView={navigate} onMember={openAuth} /> : view === 'home' ? <HomeScreen setView={navigate} /> : view === 'alerts' ? <AlertsScreen setView={navigate} /> : view === 'report' ? <ReportScreen setView={navigate} /> : <FormScreen type={view} setView={navigate} />}<BottomNav view={view} setView={navigate} /></div>{authOpen && <AuthDialog onClose={() => setAuthOpen(false)} />}</div>
}
