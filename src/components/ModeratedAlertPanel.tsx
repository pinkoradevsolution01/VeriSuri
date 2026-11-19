import { ExternalLink, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { createModeratedAlert, getPendingModeratedAlerts, reviewModeratedAlert, type ModeratedAlertDraft, type ModerationAlert } from '../lib/supabase'

const dateForInput = (days: number) => {
  const value = new Date(Date.now() + days * 86_400_000)
  const offset = value.getTimezoneOffset() * 60_000
  return new Date(value.getTime() - offset).toISOString().slice(0, 16)
}

const initialDraft = (): ModeratedAlertDraft => ({ title: '', summary: '', severity: 'medium', sourceName: '', sourceUrl: '', affectedPlatform: '', region: '', reviewAt: dateForInput(14), expiresAt: dateForInput(30) })

export function ModeratedAlertPanel() {
  const [draft, setDraft] = useState<ModeratedAlertDraft>(initialDraft)
  const [items, setItems] = useState<ModerationAlert[]>([])
  const [notice, setNotice] = useState('')
  const [loading, setLoading] = useState(false)
  const load = () => getPendingModeratedAlerts().then(setItems).catch(error => setNotice(error instanceof Error ? error.message : 'Unable to load pending advisories.'))
  useEffect(() => { load() }, [])
  const update = <K extends keyof ModeratedAlertDraft>(key: K, value: ModeratedAlertDraft[K]) => setDraft(current => ({ ...current, [key]: value }))
  const submit = async (event: React.FormEvent) => {
    event.preventDefault(); setNotice('')
    try { const source = new URL(draft.sourceUrl); if (source.protocol !== 'https:') throw new Error('Use an official HTTPS source URL.') } catch (error) { return setNotice(error instanceof Error ? error.message : 'Use an official HTTPS source URL.') }
    setLoading(true)
    try { await createModeratedAlert(draft); setDraft(initialDraft()); setNotice('Advisory submitted for independent verification.'); load() } catch (error) { setNotice(error instanceof Error ? error.message : 'Unable to submit advisory.') } finally { setLoading(false) }
  }
  const decide = async (id: string, decision: 'verified' | 'rejected') => { setLoading(true); try { await reviewModeratedAlert(id, decision); setNotice(`Advisory ${decision}.`); setItems(current => current.filter(item => item.id !== id)) } catch (error) { setNotice(error instanceof Error ? error.message : 'Unable to review advisory.') } finally { setLoading(false) } }
  return <section className="moderated-alert-panel" aria-labelledby="moderated-alert-title">
    <div className="moderated-alert-heading"><ShieldCheck /><div><p>Moderator-only workflow</p><h2 id="moderated-alert-title">Verified safety advisories</h2></div></div>
    <p>Public alerts require an official HTTPS source, affected platform, review date, expiry date, and a moderator decision.</p>
    <details><summary>Draft an advisory for verification</summary><form className="alert-draft-form" onSubmit={submit}>
      <label>Title<input value={draft.title} onChange={event => update('title', event.target.value)} required minLength={8} /></label>
      <label>Severity<select value={draft.severity} onChange={event => update('severity', event.target.value as ModeratedAlertDraft['severity'])}><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option></select></label>
      <label className="wide">Advisory summary<textarea value={draft.summary} onChange={event => update('summary', event.target.value)} required minLength={20} rows={3} /></label>
      <label>Official source name<input value={draft.sourceName} onChange={event => update('sourceName', event.target.value)} required /></label>
      <label>Official HTTPS source URL<input type="url" value={draft.sourceUrl} onChange={event => update('sourceUrl', event.target.value)} placeholder="https://…" required /></label>
      <label>Affected platform<input value={draft.affectedPlatform} onChange={event => update('affectedPlatform', event.target.value)} placeholder="GCash, SMS, Facebook…" required /></label>
      <label>Region (optional)<input value={draft.region} onChange={event => update('region', event.target.value)} placeholder="Nationwide or a region" /></label>
      <label>Review by<input type="datetime-local" value={draft.reviewAt} onChange={event => update('reviewAt', event.target.value)} required /></label>
      <label>Expires at<input type="datetime-local" value={draft.expiresAt} onChange={event => update('expiresAt', event.target.value)} required /></label>
      <button className="primary-action wide" disabled={loading}>{loading ? 'Saving…' : 'Submit for verification'}</button>
    </form></details>
    <div className="pending-advisories"><h3>Pending verification</h3>{items.length ? items.map(item => <article key={item.id}><div><span>{item.severity} risk</span><h4>{item.title}</h4><p>{item.summary}</p><small>{item.sourceName} · {item.affectedPlatform} · review {new Date(item.reviewAt).toLocaleDateString()}</small><a href={item.sourceUrl} target="_blank" rel="noopener noreferrer">Open official source <ExternalLink size={13} /></a></div><div className="moderation-actions"><button disabled={loading} onClick={() => decide(item.id, 'rejected')}>Reject</button><button className="approve" disabled={loading} onClick={() => decide(item.id, 'verified')}>Verify &amp; publish</button></div></article>) : <p className="empty-state">No advisories are awaiting verification.</p>}</div>
    {notice && <p className="privacy-note" role="status">{notice}</p>}
  </section>
}
