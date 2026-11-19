import { ExternalLink, FileText, Landmark, ShieldAlert } from 'lucide-react'

export type RiskTone = 'low' | 'medium' | 'high'

type SupportEntry = { name: string; kind: string; url: string }

// Provider-owned support pages only. Never derive a contact destination from
// suspicious content supplied by a user.
const supportDirectory: SupportEntry[] = [
  { name: 'GCash', kind: 'Wallet support', url: 'https://help.gcash.com/hc/en-us/p/contact-us' },
  { name: 'Maya', kind: 'Wallet support', url: 'https://www.maya.ph/contact-us' },
  { name: 'BDO', kind: 'Bank consumer assistance', url: 'https://www.bdo.com.ph/consumer-assistance' },
  { name: 'BPI', kind: 'Bank contact centre', url: 'https://www.bpi.com.ph/about-bpi/contact-us' },
  { name: 'Metrobank', kind: 'Bank contact centre', url: 'https://www.metrobank.com.ph/contact-us' },
  { name: 'Globe', kind: 'Telco support', url: 'https://www.globe.com.ph/contact-us' },
  { name: 'Smart / TNT', kind: 'Telco support', url: 'https://smart.com.ph/Help/contact-support' },
  { name: 'DITO', kind: 'Telco support', url: 'https://dito.ph/help-center' },
]

const heading: Record<RiskTone, string> = {
  high: 'Act now to reduce harm',
  medium: 'Pause and verify safely',
  low: 'Keep verifying before you act',
}

export function SafetyActionPlan({ tone }: { tone: RiskTone }) {
  return <section className={`action-plan ${tone}`} aria-labelledby="action-plan-title">
    <div className="action-plan-heading"><ShieldAlert aria-hidden="true" /><div><p>Scam Action Plan</p><h3 id="action-plan-title">{heading[tone]}</h3></div></div>
    <ol>
      <li>Do not send money, reply, click a suspicious link, or use contact details inside suspicious content.</li>
      <li>If you shared an OTP, PIN, password, card detail, or sent money, use the affected provider's official app or support page immediately.</li>
      <li>Save screenshots, the message or URL, account name, transaction reference, amount, and time. Never share an OTP or password as evidence.</li>
      <li>Use only the official-support links below. Check the address bar before entering account information.</li>
    </ol>
    <div className="action-plan-actions"><a className="secondary-action" href="#/report"><FileText size={17} /> Report incident</a><a className="secondary-action" href="https://cicc.gov.ph/report/" target="_blank" rel="noopener noreferrer"><Landmark size={17} /> Official CICC report <ExternalLink size={14} /></a></div>
    <details className="official-directory"><summary>Open verified official support directory</summary><p>These links go only to provider-owned support pages, not contacts from the suspicious content.</p><div className="support-directory-grid">{supportDirectory.map(entry => <a key={entry.name} href={entry.url} target="_blank" rel="noopener noreferrer"><span><b>{entry.name}</b><small>{entry.kind}</small></span><ExternalLink size={16} aria-hidden="true" /></a>)}</div><small className="directory-reviewed">Directory links reviewed 19 November 2026. Use the official page for current support channels.</small></details>
  </section>
}
