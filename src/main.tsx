import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import App from './ProductionApp'
import './styles.css'
import './production.css'
import './subscription.css'

if ('serviceWorker' in navigator) {
  window.addEventListener('load', () => navigator.serviceWorker.register('/sw.js').then(registration => registration.update()))
}

createRoot(document.getElementById('root')!).render(
  <StrictMode><App /></StrictMode>,
)
