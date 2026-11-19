import type { AssessmentExplanation as Explanation } from '../lib/api'

const sourceLabel: Record<string, string> = {
  rule: 'Local rule',
  threat_feed: 'Threat source',
  community: 'Community match',
  model: 'Approved model',
  service: 'Service status',
}

export function AssessmentExplainability({ explanations }: { explanations: Explanation[] }) {
  if (!explanations.length) return null
  return <section className="explainability-card" aria-labelledby="why-result-title">
    <div className="explainability-heading"><div><p>Explainable result</p><h3 id="why-result-title">Why VeriSuri showed this result</h3></div></div>
    <p className="explainability-intro">These are the signals observed during this check. They are evidence to review, not proof on their own.</p>
    <div className="explanation-list">
      {explanations.map((item, index) => <article key={`${item.source}-${item.label}-${index}`} className={`explanation-item ${item.category}`}>
        <div><span>{sourceLabel[item.category] ?? 'Assessment detail'}</span><h4>{item.label}</h4><p>{item.detail}</p></div>
        <small>{item.source}</small>
      </article>)}
    </div>
  </section>
}
