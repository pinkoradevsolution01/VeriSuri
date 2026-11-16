import { useState } from 'react'
import {
  Bell, ChevronRight, CircleHelp, ClipboardList, ExternalLink,
  Flag, Home, Link2, Menu, MessageSquareText, Search, Send, Shield, ShieldAlert,
  ShieldCheck, Sparkles, TriangleAlert, UserRound, X, Zap
} from 'lucide-react'
import { analyzeFeature, type Assessment } from './lib/api'

type View = 'home' | 'pay' | 'message' | 'link' | 'reports' | 'alerts'

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

function Header({ setView }: { setView: (view: View) => void }) {
  return <header>
    <Brand compact />
    <button className="menu-button" aria-label="Open menu"><Menu size={23} /></button>
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
    <button className="report-strip" onClick={() => setView('reports')}><Flag /><span><b>Report a Scam</b><small>Help protect other Filipinos</small></span><ChevronRight /></button>
    <section className="trust-row"><div><b>250K+</b><span>Filipinos Protected</span></div><div><b>1.8M+</b><span>Messages Analyzed</span></div><div><b>320K+</b><span>Scam Reports</span></div></section>
  </main>
}

function FormScreen({ type, setView }: { type: Exclude<View, 'home' | 'alerts'>; setView: (view: View) => void }) {
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

function AlertsScreen({ setView }: { setView: (view: View) => void }) {
  return <main className="screen tool-screen alerts-screen"><button className="back" onClick={() => setView('home')}>← <span>Back</span></button><div className="tool-heading"><span className="tool-icon"><Bell /></span><h1>Alerts & Notifications</h1><p>Real-time scam advisories and important updates for a safer Philippines.</p></div><div className="type-tabs filter-tabs"><button className="active">All</button><button>Advisories</button><button>Alerts</button><button>Updates</button></div><section className="alert-list">{alerts.map(([title, copy, time, kind]) => <article key={title} className={`alert-item ${kind}`}><span>{kind === 'danger' ? <TriangleAlert /> : kind === 'warning' ? <TriangleAlert /> : <CircleHelp />}</span><div><h3>{title}</h3><p>{copy}</p><small>{time}</small></div><ChevronRight size={18} /></article>)}</section><button className="report-strip"><Sparkles /><span><b>App Update: Better Scam Detection</b><small>We’ve improved our AI model for higher accuracy.</small></span><ChevronRight /></button></main>
}

function BottomNav({ view, setView }: { view: View; setView: (view: View) => void }) {
  return <nav className="bottom-nav"><button className={view === 'home' ? 'active' : ''} onClick={() => setView('home')}><Home /><span>Home</span></button><button onClick={() => setView('reports')}><ClipboardList /><span>History</span></button><button className={view === 'alerts' ? 'active' : ''} onClick={() => setView('alerts')}><Bell /><span>Alerts</span><i /></button><button><UserRound /><span>Profile</span></button></nav>
}

export default function App() {
  const [view, setView] = useState<View>('home')
  const [installVisible, setInstallVisible] = useState(true)
  return <div className="app-shell antialiased"><div className="ambient ambient-one" /><div className="ambient ambient-two" /><div className="app-canvas"><Header setView={setView} />{view === 'home' ? <HomeScreen setView={setView} /> : view === 'alerts' ? <AlertsScreen setView={setView} /> : <FormScreen type={view} setView={setView} />}<BottomNav view={view} setView={setView} /></div>{installVisible && <button className="install-banner" onClick={() => setInstallVisible(false)}><span className="install-icon"><Zap /></span><span><b>Available as a PWA</b><small>Install VeriSuri for quick access</small></span><ExternalLink size={19} /><X className="dismiss" size={15} /></button>}</div>
}
