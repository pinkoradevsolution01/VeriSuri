import { useEffect, useState } from 'react'
import {
  Bell, ChevronRight, CircleHelp, ClipboardList,
  Download, Flag, Home, Link2, MessageSquareText, Search, Shield, ShieldAlert,
  ShieldCheck, TriangleAlert
} from 'lucide-react'
import { analyzeFeature, getAlerts, type Alert, type Assessment } from './lib/api'
import { isSupabaseConfigured, submitScamReport } from './lib/supabase'

type View = 'home' | 'pay' | 'message' | 'link' | 'reports' | 'report' | 'alerts'

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

function RiskCard({ title = 'Safe to Pay', subtle = 'No scam reports found for this account in our database.', danger = false }: { title?: string; subtle?: string; danger?: boolean }) {
  return <div className={`risk-card ${danger ? 'risk-danger' : ''}`}>
    {danger ? <ShieldAlert size={34} /> : <ShieldCheck size={34} />}
    <div><strong>{title}</strong><p>{subtle}</p></div>
  </div>
}

function Header({ view, setView, canInstall, onInstall }: { view: View; setView: (view: View) => void; canInstall: boolean; onInstall: () => void }) {
  return <header>
    <button className="brand-button" onClick={() => setView('home')} aria-label="VeriSuri home"><Brand compact /></button>
    <nav className="desktop-nav" aria-label="Main navigation">
      <button className={view === 'home' ? 'active' : ''} onClick={() => setView('home')}>Dashboard</button>
      <button className={view === 'reports' ? 'active' : ''} onClick={() => setView('reports')}>Report lookup</button>
      <button className={view === 'alerts' ? 'active' : ''} onClick={() => setView('alerts')}>Safety alerts</button>
      <button onClick={() => setView('report')}>Report incident</button>
    </nav>
    {canInstall && <button className="install-action" onClick={onInstall}><Download size={17} /> Install</button>}
    <button className="alert-button" onClick={() => setView('alerts')} aria-label="Open safety alerts"><Bell size={20} /></button>
  </header>
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

function FormScreen({ type, setView }: { type: Exclude<View, 'home' | 'alerts' | 'report'>; setView: (view: View) => void }) {
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
    {checked && <><RiskCard title={result.verdict} subtle={result.summary} danger={assessment ? assessment.level === 'high' : danger} />
      {result.signals.length > 0 && <div className="signal-list"><h3>Detected warning signs</h3>{result.signals.map(signal => <p key={signal}><TriangleAlert /> {signal}</p>)}</div>}
      {!danger && <div className="safe-stats"><span>Account Type<b>{choice === 'gcash' ? 'GCash' : choice === 'maya' ? 'Maya' : 'Bank'} Account</b></span><span>Community Reports<b>0</b></span><span>Last Checked<b>Just now</b></span></div>}
    </>}
    {!checked && <div className="privacy-note"><ShieldCheck size={16} /> Your check is private and protected.</div>}
  </main>
}

function ReportScreen({ setView }: { setView: (view: View) => void }) {
  const [entityType, setEntityType] = useState<'gcash' | 'maya' | 'bank' | 'phone' | 'url' | 'social'>('gcash')
  const [entityValue, setEntityValue] = useState(''); const [narrative, setNarrative] = useState(''); const [notice, setNotice] = useState(''); const [loading, setLoading] = useState(false)
  const submit = async (event: React.FormEvent) => { event.preventDefault(); setNotice(''); if (entityValue.trim().length < 3 || narrative.trim().length < 20) { setNotice('Provide an identifier and at least 20 characters of incident detail.'); return }; setLoading(true); try { await submitScamReport(entityType, entityValue, narrative); setNotice('Report submitted for moderation. Thank you for helping protect others.'); setEntityValue(''); setNarrative('') } catch (error) { setNotice(error instanceof Error ? error.message : 'Unable to submit your report.') } finally { setLoading(false) } }
  return <main className="screen tool-screen"><button className="back" onClick={() => setView('home')}>← <span>Back to dashboard</span></button><div className="tool-heading"><span className="tool-icon"><Flag /></span><h1>Report a scam</h1><p>Reports are private and reviewed before they affect community matching results.</p></div><section className="check-panel"><form onSubmit={submit}><div className="type-tabs">{(['gcash','maya','bank','phone','url'] as const).map(item => <button type="button" key={item} className={entityType === item ? 'active' : ''} onClick={() => setEntityType(item)}>{item[0].toUpperCase() + item.slice(1)}</button>)}</div><label className="input-label" htmlFor="report-entity">Reported identifier</label><div className="field"><textarea id="report-entity" rows={1} value={entityValue} onChange={event => setEntityValue(event.target.value)} placeholder="Account, phone number, profile, or link" /></div><label className="input-label" htmlFor="report-details">What happened?</label><div className="field message-field"><textarea id="report-details" rows={6} value={narrative} onChange={event => setNarrative(event.target.value)} placeholder="Describe the scam. Do not include OTPs, passwords, or full account details." /></div><button className="primary-action" disabled={loading || !isSupabaseConfigured}>{loading ? 'Submitting…' : 'Submit for review'} <ChevronRight size={19} /></button>{!isSupabaseConfigured && <p className="form-error">Report submission needs VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY.</p>}{notice && <p className="privacy-note" role="status">{notice}</p>}</form></section></main>
}

function AlertsScreen({ setView }: { setView: (view: View) => void }) {
  return <main className="screen tool-screen alerts-screen"><button className="back" onClick={() => setView('home')}>← <span>Back to dashboard</span></button><div className="tool-heading"><span className="tool-icon"><Bell /></span><h1>Safety alerts</h1><p>Moderated scam advisories and important safety updates for the Philippines.</p></div><section className="alert-list">{alerts.map(([title, copy, time, kind]) => <article key={title} className={`alert-item ${kind}`}><span>{kind === 'danger' ? <TriangleAlert /> : kind === 'warning' ? <TriangleAlert /> : <CircleHelp />}</span><div><h3>{title}</h3><p>{copy}</p><small>{time}</small></div><ChevronRight size={18} /></article>)}</section></main>
}

function BottomNav({ view, setView }: { view: View; setView: (view: View) => void }) {
  return <nav className="bottom-nav" aria-label="Mobile navigation"><button className={view === 'home' ? 'active' : ''} onClick={() => setView('home')}><Home /><span>Dashboard</span></button><button className={view === 'reports' ? 'active' : ''} onClick={() => setView('reports')}><ClipboardList /><span>Reports</span></button><button className={view === 'alerts' ? 'active' : ''} onClick={() => setView('alerts')}><Bell /><span>Alerts</span></button></nav>
}

export default function App() {
  const [view, setView] = useState<View>('home')
  const [installPrompt, setInstallPrompt] = useState<{ prompt: () => Promise<void>; userChoice: Promise<{ outcome: string }> } | null>(null)
  useEffect(() => { const capture = (event: Event) => { event.preventDefault(); setInstallPrompt(event as unknown as { prompt: () => Promise<void>; userChoice: Promise<{ outcome: string }> }) }; window.addEventListener('beforeinstallprompt', capture); return () => window.removeEventListener('beforeinstallprompt', capture) }, [])
  const install = async () => { if (!installPrompt) return; await installPrompt.prompt(); await installPrompt.userChoice; setInstallPrompt(null) }
  return <div className="app-shell antialiased"><div className="ambient ambient-one" /><div className="ambient ambient-two" /><div className="app-canvas"><Header view={view} setView={setView} canInstall={Boolean(installPrompt)} onInstall={install} />{view === 'home' ? <HomeScreen setView={setView} /> : view === 'alerts' ? <AlertsScreen setView={setView} /> : view === 'report' ? <ReportScreen setView={setView} /> : <FormScreen type={view} setView={setView} />}<BottomNav view={view} setView={setView} /></div></div>
}
