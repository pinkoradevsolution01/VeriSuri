import { useEffect, useState } from 'react'
import { Accessibility, Check, Contrast, Eye, Type } from 'lucide-react'

type Preferences = { text: 'default' | 'large' | 'largest'; contrast: boolean; reduceMotion: boolean }
const storageKey = 'verisuri-accessibility-preferences'
const defaultPreferences: Preferences = { text: 'default', contrast: false, reduceMotion: false }

function apply(preferences: Preferences) {
  const root = document.documentElement
  root.dataset.textSize = preferences.text
  root.dataset.contrast = preferences.contrast ? 'high' : 'default'
  root.dataset.motion = preferences.reduceMotion ? 'reduce' : 'system'
}

export function AccessibilityControls() {
  const [open, setOpen] = useState(false)
  const [preferences, setPreferences] = useState<Preferences>(defaultPreferences)

  useEffect(() => {
    try {
      const saved = window.localStorage.getItem(storageKey)
      if (saved) setPreferences({ ...defaultPreferences, ...JSON.parse(saved) })
    } catch { /* Accessibility preferences remain optional. */ }
  }, [])
  useEffect(() => {
    const open = () => setOpen(true)
    window.addEventListener('verisuri:open-accessibility', open)
    return () => window.removeEventListener('verisuri:open-accessibility', open)
  }, [])
  useEffect(() => {
    apply(preferences)
    try { window.localStorage.setItem(storageKey, JSON.stringify(preferences)) } catch { /* Private mode may block storage. */ }
  }, [preferences])

  const set = (next: Partial<Preferences>) => setPreferences(current => ({ ...current, ...next }))
  return <>
    <button className="a11y-open" onClick={() => setOpen(true)} aria-label="Accessibility settings"><Accessibility size={19} /></button>
    {open && <div className="a11y-overlay" role="dialog" aria-modal="true" aria-labelledby="a11y-title">
      <section className="a11y-dialog">
        <button className="dialog-close" onClick={() => setOpen(false)} aria-label="Close accessibility settings">×</button>
        <div className="a11y-title"><Accessibility /><div><h2 id="a11y-title">Accessibility settings</h2><p>Preferences are stored only in this browser.</p></div></div>
        <fieldset><legend><Type /> Text size</legend><div className="a11y-options">{([['default', 'Default'], ['large', 'Large'], ['largest', 'Largest']] as const).map(([value, label]) => <button key={value} className={preferences.text === value ? 'selected' : ''} onClick={() => set({ text: value })}>{preferences.text === value && <Check size={15} />}{label}</button>)}</div></fieldset>
        <label className="a11y-toggle"><span><Contrast /><b>High contrast</b><small>Increase borders and text contrast.</small></span><input type="checkbox" checked={preferences.contrast} onChange={event => set({ contrast: event.target.checked })} /></label>
        <label className="a11y-toggle"><span><Eye /><b>Reduce motion</b><small>Minimize animations and movement. Your device setting is always respected.</small></span><input type="checkbox" checked={preferences.reduceMotion} onChange={event => set({ reduceMotion: event.target.checked })} /></label>
        <button className="secondary-action a11y-reset" onClick={() => setPreferences(defaultPreferences)}>Reset settings</button>
      </section>
    </div>}
  </>
}
