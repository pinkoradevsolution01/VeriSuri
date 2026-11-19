import { Bell, ExternalLink, ShieldCheck } from 'lucide-react'
import { useEffect, useState } from 'react'
import { getAlerts, type Alert } from '../lib/api'

export function VerifiedAlertsPreview({ openAlerts }: { openAlerts: () => void }) {
  const [items, setItems] = useState<Alert[]>([])
  useEffect(() => { getAlerts().then(alerts => setItems(alerts.slice(0, 3))).catch(() => setItems([])) }, [])
  return <section className="verified-preview" aria-labelledby="verified-preview-title"><div className="verified-preview-heading"><div><p>Safety news</p><h2 id="verified-preview-title">Latest verified scam alerts</h2><span>Only active advisories reviewed by VeriSuri moderators and linked to an official source.</span></div><button className="secondary-action" onClick={openAlerts}><Bell size={17} /> View all alerts</button></div>{items.length ? <div className="verified-preview-grid">{items.map(item => <article key={item.id} className={item.severity}><span>{item.severity} risk</span><h3>{item.title}</h3><p>{item.summary}</p><small>{item.affected_platform}{item.region ? ` · ${item.region}` : ''} · Review by {new Date(item.review_at).toLocaleDateString()}</small><a href={item.source_url} target="_blank" rel="noopener noreferrer">{item.source_name} <ExternalLink size={13} /></a></article>)}</div> : <div className="verified-preview-empty"><ShieldCheck /><p>No active verified alerts yet. Check back after a moderator publishes an advisory.</p></div>}</section>
}
