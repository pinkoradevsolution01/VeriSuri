export function scrollToTop() {
  if (typeof window === 'undefined') return

  try {
    const reducedMotion = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches
    window.scrollTo({ top: 0, left: 0, behavior: reducedMotion ? 'auto' : 'smooth' })
  } catch {
    // Older Safari accepts numeric scrollTo arguments but not the options object.
    window.scrollTo(0, 0)
  }
}
