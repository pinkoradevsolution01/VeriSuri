import { CheckCircle2, ExternalLink, FileText, Landmark, LockKeyhole, PhoneCall, ShieldAlert } from 'lucide-react'
import { useState } from 'react'
import { supportDirectory } from './SafetyActionPlan'

const checklist = [
  'Screenshots of the messages, profile, and transaction page',
  'Transaction reference, amount, time, recipient, and payment provider',
  'The suspicious URL, account, number, or profile name',
  'A timeline of what happened and any steps already taken',
]

export function IncidentRecovery({ report }: { report: () => void }) {
  const [saved, setSaved] = useState<Record<string, boolean>>({})
  return <main className="screen tool-screen recovery-screen">
    <section className="recovery-hero" aria-labelledby="recovery-title"><ShieldAlert aria-hidden="true" /><div><p>Urgent recovery guidance</p><h1 id="recovery-title">I already sent money or shared an OTP</h1><span>Act quickly, but use only official support channels. VeriSuri cannot recover funds or access accounts.</span></div></section>
    <section className="recovery-card urgent"><h2>Do these first</h2><ol><li>Stop replying, stop sending money, and do not open further links from the scammer.</li><li>Use the affected provider&apos;s official app or the verified support links below to secure your account and ask about transaction-recovery options.</li><li>If you shared an OTP, PIN, password, or card detail, change the affected credentials immediately. Never share another OTP with anyone.</li></ol></section>
    <section className="recovery-card"><h2>Save evidence safely</h2><p>Keep evidence for the provider and official report. Do not upload passwords, OTPs, PINs, or full card numbers.</p><div className="recovery-checklist">{checklist.map(item => <label key={item}><input type="checkbox" checked={Boolean(saved[item])} onChange={event => setSaved(current => ({ ...current, [item]: event.target.checked }))} /><span><CheckCircle2 aria-hidden="true" />{item}</span></label>)}</div></section>
    <section className="recovery-card"><h2>Contact the affected provider</h2><p>Choose the provider&apos;s official support page. Do not use a phone number or link sent by the suspected scammer.</p><div className="support-directory-grid">{supportDirectory.map(entry => <a key={entry.name} href={entry.url} target="_blank" rel="noopener noreferrer"><span><b>{entry.name}</b><small>{entry.kind}</small></span><ExternalLink size={16} aria-hidden="true" /></a>)}</div></section>
    <section className="recovery-card official-report"><Landmark aria-hidden="true" /><div><h2>Report through official channels</h2><p>For online scams, CICC lists Hotline 1326 and official reporting channels. Use the official site to confirm current contact options.</p><div className="recovery-actions"><a className="primary-action" href="https://cicc.gov.ph/report/" target="_blank" rel="noopener noreferrer"><PhoneCall size={17} /> CICC report and Hotline 1326 <ExternalLink size={14} /></a><button className="secondary-action" onClick={report}><FileText size={17} /> Submit a VeriSuri report</button></div></div></section>
    <p className="recovery-note"><LockKeyhole size={15} /> This guide helps you act safely. Follow your provider&apos;s official instructions for account security and transaction concerns.</p>
  </main>
}
