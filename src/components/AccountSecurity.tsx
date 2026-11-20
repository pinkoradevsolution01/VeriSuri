import { useEffect, useMemo, useState } from 'react'
import { Activity, CheckCircle2, KeyRound, Laptop, LockKeyhole, LogOut, RefreshCw, ShieldCheck, Smartphone, Trash2 } from 'lucide-react'
import {
  beginMfaEnrollment, completeMfaChallenge, disableMfaFactor, endOtherSessions,
  getAccountSecurityState, getRecognizedDevices, getSecurityEvents, isSupabaseConfigured,
  registerCurrentDevice, removeRecognizedDevice, type AccountSecurityState, type MfaEnrollment,
  type RecognizedDevice, type SecurityEvent, verifyMfaEnrollment,
} from '../lib/supabase'

type Props = { back: () => void; isStaff: boolean }

const describeEvent = (event: SecurityEvent) => event.details || event.event_type.replace(/_/g, ' ')
const dateTime = (value: string) => new Date(value).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' })

export function AccountSecurity({ back, isStaff }: Props) {
  const [security, setSecurity] = useState<AccountSecurityState | null>(null)
  const [devices, setDevices] = useState<RecognizedDevice[]>([])
  const [events, setEvents] = useState<SecurityEvent[]>([])
  const [enrollment, setEnrollment] = useState<MfaEnrollment | null>(null)
  const [code, setCode] = useState('')
  const [notice, setNotice] = useState('')
  const [busy, setBusy] = useState('')

  const load = async () => {
    if (!isSupabaseConfigured) return
    setNotice('')
    try {
      const current = await getAccountSecurityState()
      setSecurity(current)
      await registerCurrentDevice().catch(() => undefined)
      const [nextDevices, nextEvents] = await Promise.all([
        getRecognizedDevices().catch(() => []),
        getSecurityEvents().catch(() => []),
      ])
      setDevices(nextDevices)
      setEvents(nextEvents)
    } catch (error) {
      setNotice(error instanceof Error ? error.message : 'Could not load account security.')
    }
  }

  useEffect(() => { void load() }, [])

  const verifiedFactor = useMemo(() => security?.factors.find(factor => factor.status === 'verified') ?? null, [security])
  const needsChallenge = security?.currentLevel === 'aal1' && security?.nextLevel === 'aal2' && Boolean(verifiedFactor)
  const qrSource = enrollment?.qrCode.startsWith('<svg') ? `data:image/svg+xml;charset=utf-8,${encodeURIComponent(enrollment.qrCode)}` : enrollment?.qrCode

  const startEnrollment = async () => {
    setBusy('start'); setNotice('')
    try { setEnrollment(await beginMfaEnrollment()); setCode('') }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Could not start authenticator setup.') }
    finally { setBusy('') }
  }
  const verifyEnrollment = async () => {
    if (!enrollment || !/^\d{6}$/.test(code.trim())) return setNotice('Enter the 6-digit code from your authenticator app.')
    setBusy('verify'); setNotice('')
    try { await verifyMfaEnrollment(enrollment.factorId, code); setEnrollment(null); setCode(''); setNotice('Authenticator-app MFA is enabled. Other sessions were signed out for your protection.'); await load() }
    catch (error) { setNotice(error instanceof Error ? error.message : 'The authenticator code could not be verified.') }
    finally { setBusy('') }
  }
  const verifyExistingFactor = async () => {
    if (!verifiedFactor || !/^\d{6}$/.test(code.trim())) return setNotice('Enter the 6-digit code from your authenticator app.')
    setBusy('challenge'); setNotice('')
    try { await completeMfaChallenge(verifiedFactor.id, code); setCode(''); setNotice('This session is MFA-verified.'); await load() }
    catch (error) { setNotice(error instanceof Error ? error.message : 'The authenticator code could not be verified.') }
    finally { setBusy('') }
  }
  const endSessions = async () => {
    if (!window.confirm('Sign out all other VeriSuri sessions? This device will remain signed in.')) return
    setBusy('sessions'); setNotice('')
    try { await endOtherSessions(); setNotice('Other sessions were signed out.'); await load() }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Could not end other sessions.') }
    finally { setBusy('') }
  }
  const removeDevice = async (id: string) => {
    setBusy(id); setNotice('')
    try { await removeRecognizedDevice(id); setDevices(current => current.filter(device => device.id !== id)); setNotice('The device record was removed. Use “End other sessions” to revoke sign-in sessions.') }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Could not remove this device record.') }
    finally { setBusy('') }
  }
  const removeMfa = async () => {
    if (!verifiedFactor || !window.confirm('Remove your authenticator-app MFA? You will lose this added layer of protection.')) return
    setBusy('remove-mfa'); setNotice('')
    try { await disableMfaFactor(verifiedFactor.id); setNotice('Authenticator-app MFA was removed.'); await load() }
    catch (error) { setNotice(error instanceof Error ? error.message : 'Could not remove authenticator-app MFA.') }
    finally { setBusy('') }
  }

  if (!isSupabaseConfigured) return <main className="screen tool-screen security-screen"><button className="back" onClick={back}>Back to overview</button><div className="tool-heading"><span className="tool-icon"><LockKeyhole /></span><h1>Account security</h1><p>Connect Supabase authentication to manage your account security.</p></div></main>

  return <main className="screen tool-screen security-screen">
    <button className="back" onClick={back}>Back to overview</button>
    <div className="tool-heading"><span className="tool-icon"><LockKeyhole /></span><h1>Account security</h1><p>Protect your VeriSuri account, review recognized devices, and manage active access.</p></div>

    <section className="security-card security-mfa" aria-labelledby="mfa-title">
      <div className="security-card-heading"><div><span className="security-icon"><KeyRound /></span><h2 id="mfa-title">Authenticator-app MFA</h2></div><span className={`security-status ${security?.currentLevel === 'aal2' ? 'secure' : ''}`}>{security?.currentLevel === 'aal2' ? 'MFA verified' : verifiedFactor ? 'Setup complete' : 'Optional'}</span></div>
      <p>Add a time-based code from an authenticator app. VeriSuri never sees or stores the app’s code.</p>
      {security?.currentLevel === 'aal2' && <p className="security-confirmation"><CheckCircle2 /> This session has completed MFA.</p>}
      {!verifiedFactor && !enrollment && <button className="primary-action security-action" disabled={busy === 'start'} onClick={() => void startEnrollment()}>{busy === 'start' ? 'Starting setup…' : 'Set up authenticator app'}</button>}
      {enrollment && <div className="mfa-enrollment"><div>{qrSource && <img src={qrSource} alt="Authenticator app QR code" />}<p>Scan this code with an authenticator app. If you cannot scan it, enter this setup key:</p><code>{enrollment.secret}</code></div><label htmlFor="mfa-enrollment-code">6-digit code from your app<input id="mfa-enrollment-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={event => setCode(event.target.value.replace(/\D/g, ''))} placeholder="123456" /></label><div className="security-actions"><button className="primary-action" disabled={busy === 'verify'} onClick={() => void verifyEnrollment()}>{busy === 'verify' ? 'Verifying…' : 'Verify and enable MFA'}</button><button className="secondary-action" disabled={Boolean(busy)} onClick={() => { setEnrollment(null); setCode('') }}>Cancel</button></div></div>}
      {needsChallenge && <div className="mfa-challenge"><p>Enter a current code to verify this session. Staff moderation and admin controls require this step.</p><label htmlFor="mfa-challenge-code">Authenticator code<input id="mfa-challenge-code" inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={code} onChange={event => setCode(event.target.value.replace(/\D/g, ''))} placeholder="123456" /></label><button className="primary-action" disabled={busy === 'challenge'} onClick={() => void verifyExistingFactor()}>{busy === 'challenge' ? 'Verifying…' : 'Verify this session'}</button></div>}
      {verifiedFactor && !enrollment && <div className="factor-row"><span><Smartphone /><b>{verifiedFactor.friendlyName || 'Authenticator app'}</b><small>Added {verifiedFactor.createdAt ? dateTime(verifiedFactor.createdAt) : 'previously'}</small></span><button className="text-danger" disabled={busy === 'remove-mfa'} onClick={() => void removeMfa()}>{busy === 'remove-mfa' ? 'Removing…' : 'Remove'}</button></div>}
    </section>

    <section className="security-card" aria-labelledby="session-title">
      <div className="security-card-heading"><div><span className="security-icon"><Laptop /></span><h2 id="session-title">Sessions and recognized devices</h2></div><button className="icon-button" onClick={() => void load()} aria-label="Refresh devices and account activity"><RefreshCw size={17} /></button></div>
      <p>“Recognized devices” are private browser records for this account. Removing one deletes the record only; use the session control to revoke sign-ins.</p>
      <div className="session-callout"><LogOut /><div><b>End other sessions</b><small>Signs out other browsers and devices while keeping this session active.</small></div><button className="secondary-action" disabled={busy === 'sessions'} onClick={() => void endSessions()}>{busy === 'sessions' ? 'Ending…' : 'End other sessions'}</button></div>
      <ul className="security-list">{devices.length ? devices.map(device => <li key={device.id}><Laptop /><span><b>{device.device_name}</b><small>Last active {dateTime(device.last_seen_at)}</small></span><button className="icon-danger" disabled={busy === device.id} onClick={() => void removeDevice(device.id)} aria-label={`Remove ${device.device_name} record`}><Trash2 size={16} /></button></li>) : <li className="empty-security">No device activity is available yet. Apply the account-security migration, then revisit this screen.</li>}</ul>
    </section>

    <section className="security-card" aria-labelledby="activity-title">
      <div className="security-card-heading"><div><span className="security-icon"><Activity /></span><h2 id="activity-title">Account activity</h2></div></div>
      <p>This activity history is visible only to you. It records security actions initiated in VeriSuri, not message content or scans.</p>
      <ul className="security-list activity-list">{events.length ? events.map(event => <li key={event.id}><ShieldCheck /><span><b>{describeEvent(event)}</b><small>{dateTime(event.created_at)}</small></span></li>) : <li className="empty-security">No account security activity has been recorded yet.</li>}</ul>
    </section>

    {isStaff && <section className="security-card staff-security" aria-labelledby="staff-security-title"><div className="security-card-heading"><div><span className="security-icon"><ShieldCheck /></span><h2 id="staff-security-title">Moderator and admin protection</h2></div></div><p>Report reviews and alert publishing are MFA-gated in Supabase Row Level Security and in their server-side functions. Complete “Verify this session” above before performing staff actions.</p></section>}
    {notice && <p className="privacy-note" role="status">{notice}</p>}
  </main>
}
