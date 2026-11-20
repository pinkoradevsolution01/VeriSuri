import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './ProductionApp'
import './styles.css'
import './production.css'
import './subscription.css'
import './free-plan.css'
import './mobile-pwa.css'
import './responsive-shell.css'
import './mobile-navigation.css'

if ('serviceWorker' in navigator && window.isSecureContext) {
  window.addEventListener('load', () => {
    void navigator.serviceWorker.register('/sw.js')
      .then(registration => registration.update())
      // A PWA cache is optional. A registration problem must never stop the app.
      .catch(() => undefined)
  })
}

createRoot(document.getElementById('root')!).render(
  <StrictMode><App /></StrictMode>,
)
