import { useEffect, useMemo, useRef, useState } from 'react'
import * as signalR from '@microsoft/signalr'
import type { Alert, AnalystStatus, LogEvent, Severity } from './types'

const backendUrl = (import.meta.env.VITE_BACKEND_URL || '').replace(/\/$/, '')
const severityOrder: Severity[] = ['critical', 'high', 'medium', 'low']
const statuses: AnalystStatus[] = ['open', 'investigating', 'resolved', 'false_positive']
const tacticNames: Record<string, string> = {
  command_and_control: 'Command and Control', credential_access: 'Credential Access', defense_evasion: 'Defense Evasion',
  discovery: 'Discovery', execution: 'Execution', exfiltration: 'Exfiltration', initial_access: 'Initial Access',
  lateral_movement: 'Lateral Movement', persistence: 'Persistence', privilege_escalation: 'Privilege Escalation',
}

type MitreMapping = { tactic: string; technique: string; ruleTitle: string; ruleId: string }
type RuleMatch = { title?: string; rule_id?: string; evidence?: { tags?: string[]; level?: string; description?: string; events?: unknown[] } }
type LogTimeline = { total: number; timestamped: number; minTimestamp: number | null; maxTimestamp: number | null; buckets: Array<{ startTimestamp: number; count: number }> }
type TimelineChartData = { values: number[]; labels: string[]; tooltips: string[]; count: number; timestamped: number; total: number; intervalLabel: string }
type RelatedEvent = { timestamp?: string; process_id?: number; relation?: string; event_name?: string; process_name?: string; event_id?: number; return_value?: number }
type Assessment = { kind?: 'benign' | 'model_alert' | 'rule_alert'; label?: string; reason?: string; requires_triage?: boolean }
type EventAssessment = { label: string; hint: string; badgeClass: string; requiresTriage: boolean }
type Analysis = {
  status?: string
  assessment?: Assessment
  is_alert?: boolean
  alert?: { anomaly_score?: number; model?: string; timestamp?: string }
  incident_report?: string | null
  incident_report_error?: string | null
  related_event_count?: number
  related_events?: RelatedEvent[]
  rule_matches?: RuleMatch[]
  steps?: Array<{ node: string; finished_at?: string }>
  error?: string
}

function readAnalysis(log: LogEvent): Analysis | null {
  if (!log.aiResult) return null
  try { return JSON.parse(log.aiResult) as Analysis } catch { return null }
}

function getEventAssessment(log: Alert, analysis: Analysis | null): EventAssessment {
  const hasAlertResult = analysis?.is_alert === true
  if (log.aiStatus !== 'completed' && !hasAlertResult) {
    return { label: `AI ${log.aiStatus ?? 'pending'}`, hint: 'The analysis workflow has not completed yet.', badgeClass: 'neutral', requiresTriage: false }
  }
  const reportRetryHint = log.aiStatus === 'report_pending'
    ? ' The alert remains visible while incident report generation retries automatically.'
    : ''
  if (!analysis) {
    return { label: 'Result unavailable', hint: 'The backend returned no readable analysis result.', badgeClass: 'neutral', requiresTriage: false }
  }
  if (!analysis.is_alert) {
    return { label: analysis.assessment?.label ?? 'No anomaly', hint: analysis.assessment?.reason ?? 'The anomaly model classified this event as benign.', badgeClass: 'neutral', requiresTriage: false }
  }
  if (log.severity) {
    return { label: log.severity, hint: `Sigma assigned ${log.severity} severity to the matched alert.${reportRetryHint}`, badgeClass: log.severity, requiresTriage: true }
  }
  if (analysis.assessment?.kind === 'rule_alert') {
    return { label: analysis.assessment.label ?? 'Rule-backed alert', hint: analysis.assessment.reason ?? 'A Sigma rule matched, but it did not provide a supported severity level.', badgeClass: 'model-alert', requiresTriage: true }
  }
  return { label: analysis.assessment?.label ?? 'AI alert', hint: `${analysis.assessment?.reason ?? 'The anomaly model raised an alert, but no configured Sigma rule matched the investigation evidence.'}${reportRetryHint}`, badgeClass: 'model-alert', requiresTriage: true }
}

function getMappings(analysis: Analysis | null): MitreMapping[] {
  const mappings: MitreMapping[] = []
  for (const rule of analysis?.rule_matches ?? []) {
    const tags = rule.evidence?.tags ?? []
    const tacticTag = tags.find(tag => /^attack\.[a-z_]+$/i.test(tag) && !/^attack\.t\d/i.test(tag))
    const techniqueTag = tags.find(tag => /^attack\.t\d/i.test(tag))
    if (!tacticTag && !techniqueTag) continue
    const tacticKey = tacticTag?.slice('attack.'.length).toLowerCase() ?? ''
    const technique = techniqueTag?.slice('attack.'.length).toUpperCase() ?? 'Unmapped technique'
    mappings.push({
      tactic: tacticNames[tacticKey] ?? (tacticKey ? tacticKey.replaceAll('_', ' ').replace(/\b\w/g, letter => letter.toUpperCase()) : 'Unmapped tactic'),
      technique,
      ruleTitle: rule.title ?? 'Detection rule',
      ruleId: rule.rule_id ?? 'unknown',
    })
  }
  return mappings.filter((item, index) => mappings.findIndex(other => other.tactic === item.tactic && other.technique === item.technique) === index)
}

function toAlert(log: LogEvent): Alert {
  const analysis = readAnalysis(log)
  const rawScore = analysis?.alert?.anomaly_score
  const score = typeof rawScore === 'number' && Number.isFinite(rawScore) ? Math.round(rawScore * 100) : 0
  const level = analysis?.rule_matches?.map(rule => rule.evidence?.level?.toLowerCase()).find((value): value is string => ['critical', 'high', 'medium', 'low'].includes(value ?? ''))
  const severity: Severity | null = level ? level as Severity : null
  const mapping = getMappings(analysis)[0]
  const firstRule = analysis?.rule_matches?.[0]
  return {
    ...log,
    alertId: `EVT-${log.id ?? `${log.processid}-${log.timestamp ?? Date.now()}`}`,
    score, severity,
    title: firstRule?.title ?? (log.eventName ? `${log.eventName} process event` : 'Linux process event'),
    tactic: mapping?.tactic ?? 'Unmapped', technique: mapping?.technique ?? '—',
    status: log.analystStatus ?? 'open', receivedAt: Date.now(),
  }
}

function timestampMs(timestamp?: number | string | null) {
  if (timestamp === null || timestamp === undefined || timestamp === '') return null
  const numeric = Number(timestamp)
  if (!Number.isFinite(numeric) || numeric <= 0) return null
  const ms = numeric >= 1e17 ? numeric / 1e6 : numeric >= 1e14 ? numeric / 1e3 : numeric >= 1e11 ? numeric : numeric * 1000
  return Number.isFinite(ms) && Math.abs(ms) <= 8.64e15 ? ms : null
}

function formatTime(timestamp?: number | string | null) {
  const ms = timestampMs(timestamp)
  if (ms === null) return 'time unavailable'
  return new Intl.DateTimeFormat(undefined, { year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }).format(new Date(ms))
}

function mergeHistory(current: Alert[], incoming: LogEvent[]) {
  const rank = { legacy: 0, pending: 1, processing: 2, failed: 2, report_pending: 3, completed: 4 } as const
  const byId = new Map<number | string, Alert>()
  for (const item of current) if (item.id !== undefined) byId.set(item.id, item)
  for (const log of incoming) {
    const mapped = toAlert(log)
    const previous = log.id === undefined ? undefined : byId.get(log.id)
    const prevRank = previous?.aiStatus ? rank[previous.aiStatus] : -1
    const nextRank = mapped.aiStatus ? rank[mapped.aiStatus] : -1
    const recoversMissingReport = previous?.aiStatus === 'completed'
      && mapped.aiStatus === 'report_pending'
      && readAnalysis(previous)?.is_alert === true
      && !readAnalysis(previous)?.incident_report
    if (log.id !== undefined) byId.set(log.id, previous && prevRank > nextRank && !recoversMissingReport ? previous : mapped)
    else byId.set(mapped.alertId, mapped)
  }
  return [...byId.values()].sort((a, b) => (b.id ?? 0) - (a.id ?? 0) || (timestampMs(b.timestamp) ?? 0) - (timestampMs(a.timestamp) ?? 0)).slice(0, 300)
}

function eventHost(log: Alert) { return log.hostName?.trim() || 'Unknown host' }
function Icon({ name }: { name: string }) { return <span className={`icon icon-${name}`} aria-hidden="true" /> }

async function fetchTimeline(): Promise<LogTimeline> {
  const response = await fetch(`${backendUrl}/api/logs/timeline?buckets=12`)
  if (!response.ok) throw new Error(`Log timeline returned ${response.status}`)
  return response.json() as Promise<LogTimeline>
}

async function fetchHistory(): Promise<LogEvent[]> {
  const response = await fetch(`${backendUrl}/api/logs?limit=300`)
  if (!response.ok) throw new Error(`Log history returned ${response.status}`)
  return response.json() as Promise<LogEvent[]>
}

export default function App() {
  const [events, setEvents] = useState<Alert[]>([])
  const [timeline, setTimeline] = useState<LogTimeline | null>(null)
  const [connected, setConnected] = useState(false)
  const [liveEnabled, setLiveEnabled] = useState(true)
  const liveRef = useRef(true)
  const [activeView, setActiveView] = useState<'dashboard' | 'alerts' | 'mitre'>('dashboard')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [theme, setTheme] = useState<'dark' | 'light'>('dark')
  const [filter, setFilter] = useState<Severity | 'all'>('all')
  const [statusFilter, setStatusFilter] = useState<AnalystStatus | 'all'>('all')
  const [tacticFilter, setTacticFilter] = useState('all')
  const [query, setQuery] = useState('')
  const [statusSaving, setStatusSaving] = useState(false)
  const [statusError, setStatusError] = useState('')

  useEffect(() => { document.documentElement.dataset.theme = theme }, [theme])
  useEffect(() => {
    let disposed = false
    fetchHistory().then(logs => { if (!disposed) setEvents(current => mergeHistory(current, logs)) }).catch(() => undefined)
    fetchTimeline().then(data => { if (!disposed) setTimeline(data) }).catch(() => undefined)
    let timelineRefresh: ReturnType<typeof setTimeout> | undefined
    const queueTimelineRefresh = () => {
      if (timelineRefresh) clearTimeout(timelineRefresh)
      timelineRefresh = setTimeout(() => { void fetchTimeline().then(data => { if (!disposed) setTimeline(data) }).catch(() => undefined) }, 1200)
    }

    const hub = new signalR.HubConnectionBuilder().withUrl(`${backendUrl}/logs`).withAutomaticReconnect().build()
    const upsert = (log: LogEvent) => {
      if (!liveRef.current) return
      setEvents(current => {
        const next = toAlert(log)
        const index = current.findIndex(item => item.id === log.id)
        if (index < 0) return [next, ...current].slice(0, 300)
        const updated = [...current]
        updated[index] = next
        return updated
      })
    }
    hub.on('newLog', (log: LogEvent) => { upsert(log); queueTimelineRefresh() })
    hub.on('logAnalyzed', upsert)
    hub.on('logUpdated', upsert)
    hub.onreconnecting(() => setConnected(false))
    hub.onreconnected(() => { setConnected(true); void fetchHistory().then(logs => { if (!disposed) setEvents(current => mergeHistory(current, logs)) }).catch(() => undefined); void fetchTimeline().then(data => { if (!disposed) setTimeline(data) }).catch(() => undefined) })
    hub.onclose(() => setConnected(false))
    hub.start().then(() => setConnected(true)).catch(() => setConnected(false))
    return () => { disposed = true; if (timelineRefresh) clearTimeout(timelineRefresh); hub.stop() }
  }, [])

  useEffect(() => {
    if (!selected?.id || (selected.rawEvent !== undefined && selected.aiResult !== undefined)) return
    let active = true
    fetch(`${backendUrl}/api/logs/${selected.id}`)
      .then(response => response.ok ? response.json() : null)
      .then((log: LogEvent | null) => {
        if (active && log) setEvents(items => items.map(item => item.id === log.id ? toAlert(log) : item))
      })
      .catch(() => undefined)
    return () => { active = false }
  }, [selected?.id, selected?.rawEvent, selected?.aiResult])

  useEffect(() => {
    if (!selected?.id) return
    const current = events.find(item => item.id === selected.id)
    if (current && current !== selected) setSelected(current)
  }, [events, selected])

  const alertEvents = useMemo(() => events.filter(item => readAnalysis(item)?.is_alert === true), [events])
  const counts = useMemo(() => severityOrder.map(severity => [severity, alertEvents.filter(item => item.severity === severity).length] as const), [alertEvents])
  const openCount = alertEvents.filter(item => item.status === 'open').length
  const tacticOptions = [...new Set(alertEvents.flatMap(item => getMappings(readAnalysis(item)).map(mapping => mapping.tactic)))].sort()
  const visible = events.filter(item => {
    const analysis = readAnalysis(item)
    const assessment = getEventAssessment(item, analysis)
    const mappings = getMappings(analysis)
    const matchesTactic = tacticFilter === 'all' || mappings.some(mapping => mapping.tactic === tacticFilter)
    const haystack = `${item.title} ${item.comm ?? ''} ${eventHost(item)} ${item.processid} ${item.eventId} ${mappings.map(mapping => `${mapping.tactic} ${mapping.technique}`).join(' ')}`.toLowerCase()
    return (filter === 'all' || (analysis?.is_alert === true && item.severity === filter))
      && (statusFilter === 'all' || (assessment.requiresTriage && item.status === statusFilter))
      && matchesTactic
      && haystack.includes(query.toLowerCase())
  })

  async function reloadHistory() {
    try { const logs = await fetchHistory(); setEvents(current => mergeHistory(current, logs)) } catch { /* keep the last known stream state */ }
    try { setTimeline(await fetchTimeline()) } catch { /* keep the last known chart state */ }
  }

  async function updateStatus(status: AnalystStatus) {
    if (!selected?.id) return
    setStatusSaving(true)
    setStatusError('')
    try {
      const response = await fetch(`${backendUrl}/api/logs/${selected.id}/status`, {
        method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ status }),
      })
      if (!response.ok) throw new Error(`Status update returned ${response.status}`)
      const log = await response.json() as LogEvent
      const updated = toAlert(log)
      setEvents(items => items.map(item => item.id === log.id ? updated : item))
    } catch {
      setStatusError('Could not save this status to the backend. Check the connection and try again.')
    } finally { setStatusSaving(false) }
  }

  function toggleLive() {
    const enabled = !liveEnabled
    liveRef.current = enabled
    setLiveEnabled(enabled)
    if (enabled) void reloadHistory()
  }

  const headerTitle = activeView === 'dashboard' ? 'Security dashboard' : activeView === 'alerts' ? 'Alerts' : 'MITRE ATT&CK'
  return <div className="app-shell">
    <aside className="sidebar">
      <div className="brand"><span className="brand-mark">S</span><span>Sentinel<em>SOC</em></span></div>
      <nav aria-label="Main navigation">
        {([['dashboard', 'Dashboard'], ['alerts', 'Alerts'], ['mitre', 'MITRE ATT&CK']] as const).map(([id, label]) => <button key={id} className={activeView === id ? 'nav-item active' : 'nav-item'} onClick={() => setActiveView(id)}><Icon name={id} />{label}{id === 'alerts' && openCount > 0 && <b>{openCount}</b>}</button>)}
      </nav>
      <div className="sidebar-bottom">
        <button className="theme-toggle" onClick={() => setTheme(current => current === 'dark' ? 'light' : 'dark')}><Icon name="sun" />{theme === 'dark' ? 'Light mode' : 'Dark mode'}</button>
        <button className={`live-toggle ${liveEnabled ? 'active' : ''}`} onClick={toggleLive} aria-pressed={liveEnabled}><i />{liveEnabled ? 'Live stream' : 'Resume stream'}</button>
        <div className={`connection ${connected ? 'online' : ''}`}><i />{connected ? (liveEnabled ? 'Connected to backend' : 'Connected · paused') : 'Awaiting backend'}</div>
      </div>
    </aside>
    <main>
      <header className="page-head"><div><p className="eyebrow">Security operations center</p><h1>{headerTitle}</h1><p className="subtitle">{connected ? 'Tracee events and SOC analysis are connected to the backend.' : 'Waiting for the backend event stream.'}</p></div><div className="head-status"><span className={connected && liveEnabled ? 'pulse live' : 'pulse'} /><span>{connected && liveEnabled ? 'LIVE' : liveEnabled ? 'STANDBY' : 'PAUSED'}</span></div></header>
      {activeView === 'dashboard' && <Dashboard events={events} alertEvents={alertEvents} timeline={timeline} counts={counts} openCount={openCount} onSelect={setSelected} onQueue={() => setActiveView('alerts')} />}
      {activeView === 'alerts' && <Alerts events={visible} filter={filter} statusFilter={statusFilter} tacticFilter={tacticFilter} tactics={tacticOptions} query={query} onFilter={setFilter} onStatusFilter={setStatusFilter} onTacticFilter={setTacticFilter} onQuery={setQuery} onSelect={setSelected} />}
      {activeView === 'mitre' && <Mitre events={alertEvents} onSelect={setSelected} />}
    </main>
    {selected && <Detail alert={selected} statusSaving={statusSaving} statusError={statusError} onClose={() => { setSelected(null); setStatusError('') }} onStatus={updateStatus} />}
  </div>
}

function Dashboard({ events, alertEvents, timeline, counts, openCount, onSelect, onQueue }: { events: Alert[], alertEvents: Alert[], timeline: LogTimeline | null, counts: readonly (readonly [Severity, number])[], openCount: number, onSelect: (item: Alert) => void, onQueue: () => void }) {
  const chartData = useMemo(() => buildChartData(events, timeline), [events, timeline])
  const mappings = alertEvents.flatMap(item => getMappings(readAnalysis(item)).map(mapping => ({ ...mapping, event: item })))
  const tactics = countBy(mappings.map(item => item.tactic)).slice(0, 5)
  const rules = countBy(mappings.map(item => item.ruleTitle)).slice(0, 5)
  const hosts = countBy(events.map(eventHost).filter(host => host !== 'Unknown host')).slice(0, 5)
  const hostCount = new Set(events.map(item => item.hostName).filter(Boolean)).size
  const critical = counts.find(([severity]) => severity === 'critical')?.[1] ?? 0
  const completed = events.filter(item => item.aiStatus === 'completed' || item.aiStatus === 'report_pending').length
  return <>
    <section className="metrics">
      <Metric label="Recent events" value={events.length} note="latest 300 backend records" icon="activity" />
      <Metric label="AI alerts" value={alertEvents.length} note="flagged by SOC analysis" icon="alert" accent="orange" />
      <Metric label="Open incidents" value={openCount} note={`${critical} critical alerts`} icon="shield" accent="red" />
      <Metric label="Monitored hosts" value={hostCount} note="from Tracee hostName" icon="host" />
    </section>
    <section className="design-grid">
      <div className="panel design-span-8"><div className="panel-title"><div><p className="eyebrow">Stored event timeline</p><h2>Log volume · {chartData.intervalLabel}</h2></div><span className="pill">{chartData.timestamped} timestamped / {chartData.total} in database</span></div><HourlyChart data={chartData} /></div>
      <div className="panel design-span-4"><div className="panel-title"><div><p className="eyebrow">Sigma rule levels</p><h2>Alert severity</h2></div></div><SeverityMix counts={counts} unclassified={alertEvents.filter(item => !item.severity).length} /></div>
      <TopList title="Busiest MITRE tactics" subtitle="from Sigma ATT&CK tags" rows={tactics} empty="No ATT&CK tagged findings yet." />
      <TopList title="Most triggered rules" subtitle="matched against related events" rows={rules} empty="No Sigma matches yet." />
      <TopList title="Most active hosts" subtitle="from Tracee hostName" rows={hosts} empty="Host names are not present in loaded events." />
      <div className="panel design-span-12"><div className="panel-title"><div><p className="eyebrow">Live telemetry</p><h2>Latest alerts and events</h2></div><button className="text-button" onClick={onQueue}>View alert queue →</button></div><EventTable events={events.slice(0, 8)} onSelect={onSelect} /></div>
      <div className="pipeline-footnote">AI classification completed for {completed} of the latest {events.length} loaded events. Timeline buckets count every database record with a timestamp.</div>
    </section>
  </>
}

function countBy(values: string[]) {
  const counts = new Map<string, number>()
  for (const value of values) counts.set(value, (counts.get(value) ?? 0) + 1)
  return [...counts.entries()].sort((left, right) => right[1] - left[1])
}

function Metric({ label, value, note, icon, accent }: { label: string, value: number, note: string, icon: string, accent?: string }) { return <div className={`metric ${accent ?? ''}`}><div className="metric-icon"><Icon name={icon} /></div><div><p>{label}</p><strong>{value}</strong><small>{note}</small></div></div> }

function timelineFormatOptions(spanMs: number): Intl.DateTimeFormatOptions {
  if (spanMs < 3_600_000) return { hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }
  if (spanMs < 48 * 3_600_000) return { hour: '2-digit', minute: '2-digit', hour12: false }
  if (spanMs < 14 * 86_400_000) return { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }
  return { year: 'numeric', month: 'short', day: '2-digit' }
}

function intervalLabel(durationMs: number) {
  if (durationMs < 1_000) return 'sub-second buckets'
  if (durationMs < 60_000) return `${Math.max(1, Math.round(durationMs / 1_000))}-second buckets`
  if (durationMs < 3_600_000) return `${Math.max(1, Math.round(durationMs / 60_000))}-minute buckets`
  if (durationMs < 86_400_000) return `${Math.max(1, Math.round(durationMs / 3_600_000))}-hour buckets`
  return `${Math.max(1, Math.round(durationMs / 86_400_000))}-day buckets`
}

function formatBucketTooltip(startMs: number, endMs: number, amount: number) {
  const formatter = new Intl.DateTimeFormat(undefined, { month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false })
  return `${formatter.format(new Date(startMs))} – ${formatter.format(new Date(endMs))}: ${amount} ${amount === 1 ? 'event' : 'events'}`
}

function makeChartData(values: number[], starts: number[], maxMs: number, timestamped: number, total: number): TimelineChartData {
  const minMs = starts[0] ?? maxMs
  const spanMs = Math.max(0, maxMs - minMs)
  const bucketMs = values.length > 1 ? spanMs / values.length : spanMs
  const formatter = new Intl.DateTimeFormat(undefined, timelineFormatOptions(spanMs))
  return {
    values,
    labels: starts.map(start => formatter.format(new Date(start))),
    tooltips: starts.map((start, index) => formatBucketTooltip(start, index === values.length - 1 ? maxMs : start + bucketMs, values[index])),
    count: timestamped,
    timestamped,
    total,
    intervalLabel: intervalLabel(bucketMs),
  }
}

function buildChartData(events: Alert[], timeline: LogTimeline | null): TimelineChartData {
  if (timeline && timeline.buckets.length) {
    const minMs = timestampMs(timeline.minTimestamp) ?? 0
    const maxMs = timestampMs(timeline.maxTimestamp) ?? minMs
    const starts = timeline.buckets.map(bucket => timestampMs(bucket.startTimestamp) ?? minMs)
    return makeChartData(timeline.buckets.map(bucket => bucket.count), starts, maxMs, timeline.timestamped, timeline.total)
  }
  const points = events.map(item => timestampMs(item.timestamp)).filter((value): value is number => value !== null).sort((a, b) => a - b)
  const values = Array.from({ length: 12 }, () => 0)
  if (!points.length) return { values, labels: Array(12).fill('—') as string[], tooltips: Array(12).fill('No timestamp data') as string[], count: 0, timestamped: 0, total: events.length, intervalLabel: 'time buckets' }
  const min = points[0], max = points[points.length - 1], span = max - min
  for (const time of points) values[span === 0 ? 11 : Math.min(11, Math.floor((time - min) / span * 12))]++
  const starts = values.map((_, index) => span === 0 ? min : min + span * index / values.length)
  return makeChartData(values, starts, max, points.length, events.length)
}

function HourlyChart({ data }: { data: TimelineChartData }) {
  const { values, labels, tooltips, count } = data
  const max = Math.max(...values, 1)
  const points = values.map((value, index) => `${28 + index * 48},${166 - value / max * 130}`).join(' ')
  const area = `28,166 ${points} 556,166`
  return count ? <div className="hour-chart"><svg viewBox="0 0 584 200" role="img" aria-label={`Log counts across ${count} stored event timestamps`} preserveAspectRatio="none">
    {[0, 1, 2, 3].map(index => <line key={index} x1="28" x2="556" y1={166 - index * 43} y2={166 - index * 43} className="chart-grid-line" />)}
    <polygon points={area} className="chart-area" /><polyline points={points} className="chart-line" />
    {values.map((value, index) => <circle key={index} cx={28 + index * 48} cy={166 - value / max * 130} r="3.5" className="chart-point"><title>{tooltips[index]}</title></circle>)}
    {[0, 3, 6, 9, 11].map(index => <text key={index} x={28 + index * 48} y="192" className="chart-label">{labels[index]}</text>)}
  </svg></div> : <div className="analytics-empty">No valid timestamps in the loaded database records.</div>
}
function SeverityMix({ counts, unclassified }: { counts: readonly (readonly [Severity, number])[], unclassified: number }) {
  const total = counts.reduce((sum, [, amount]) => sum + amount, 0) + unclassified
  let cumulative = 0
  const colors = { critical: 'var(--red)', high: 'var(--orange)', medium: 'var(--yellow)', low: 'var(--cyan)' }
  const stops = counts.map(([severity, amount]) => {
    const start = cumulative / Math.max(total, 1) * 360
    cumulative += amount
    return `${colors[severity]} ${start}deg ${cumulative / Math.max(total, 1) * 360}deg`
  })
  if (unclassified) stops.push(`var(--line) ${cumulative / Math.max(total, 1) * 360}deg 360deg`)
  return <div className="severity-mix"><div className="severity-ring" style={{ background: `conic-gradient(${total ? stops.join(',') : 'var(--line) 0deg 360deg'})` }}><strong>{total}</strong><small>alerts</small></div><div className="severity-legend">{counts.map(([severity, amount]) => <div key={severity}><span><i className={severity} />{severity}</span><b>{amount}</b></div>)}<div><span><i className="unclassified" />Unclassified</span><b>{unclassified}</b></div></div></div>
}

function TopList({ title, subtitle, rows, empty }: { title: string, subtitle: string, rows: [string, number][], empty: string }) {
  const max = Math.max(...rows.map(([, value]) => value), 1)
  return <div className="panel design-span-4"><div className="panel-title"><div><p className="eyebrow">{subtitle}</p><h2>{title}</h2></div></div>{rows.length ? <div className="top-list">{rows.map(([label, value]) => <div className="top-list-row" key={label}><span title={label}>{label}</span><div><i style={{ width: `${value / max * 100}%` }} /></div><b>{value}</b></div>)}</div> : <div className="analytics-empty">{empty}</div>}</div>
}

function Alerts({ events, filter, statusFilter, tacticFilter, tactics, query, onFilter, onStatusFilter, onTacticFilter, onQuery, onSelect }: { events: Alert[], filter: Severity | 'all', statusFilter: AnalystStatus | 'all', tacticFilter: string, tactics: string[], query: string, onFilter: (value: Severity | 'all') => void, onStatusFilter: (value: AnalystStatus | 'all') => void, onTacticFilter: (value: string) => void, onQuery: (value: string) => void, onSelect: (item: Alert) => void }) {
  return <section className="panel queue"><div className="filters"><div className="filter-pills">{(['all', ...severityOrder] as const).map(severity => <button key={severity} onClick={() => onFilter(severity)} className={filter === severity ? 'selected' : ''}>{severity}</button>)}</div>
    <div className="filter-controls"><label><span>Status</span><select value={statusFilter} onChange={event => onStatusFilter(event.target.value as AnalystStatus | 'all')}><option value="all">All statuses</option>{statuses.map(status => <option key={status} value={status}>{status.replace('_', ' ')}</option>)}</select></label>
      <label><span>MITRE tactic</span><select value={tacticFilter} onChange={event => onTacticFilter(event.target.value)}><option value="all">All tactics</option>{tactics.map(tactic => <option key={tactic} value={tactic}>{tactic}</option>)}</select></label>
      <label className="search"><Icon name="search" /><input value={query} onChange={event => onQuery(event.target.value)} placeholder="Search event, host, process or technique" /></label>
    </div></div><p className="queue-caption"><strong>No anomaly</strong> means the model completed analysis and found normal behavior. <strong>AI alert</strong> means the model found an anomaly with no matching Sigma rule; colored levels are Sigma-backed alerts.</p><EventTable events={events} onSelect={onSelect} /></section>
}

function EventTable({ events, onSelect }: { events: Alert[], onSelect: (item: Alert) => void }) {
  return <div className="table-wrap"><table><thead><tr><th>Assessment</th><th>Event</th><th>Triage</th><th>Technique</th><th>Tactic</th><th>Host</th><th>Detected</th></tr></thead><tbody>{events.map(item => {
    const analysis = readAnalysis(item)
    const assessment = getEventAssessment(item, analysis)
    const triageLabel = assessment.requiresTriage ? item.status.replace('_', ' ') : 'Not required'
    return <tr key={item.alertId} onClick={() => onSelect(item)} tabIndex={0} onKeyDown={event => { if (event.key === 'Enter') onSelect(item) }}>
      <td><span className={`severity-badge ${assessment.badgeClass}`} title={assessment.hint}>{assessment.label}</span></td>
      <td><strong>{item.title}</strong><small>{item.comm ?? `PID ${item.processid}`}</small></td><td><span className={`status-pill ${assessment.requiresTriage ? item.status : 'not-required'}`} title={assessment.requiresTriage ? 'Analyst triage status.' : assessment.hint}>{triageLabel}</span></td>
      <td><span className="attack-tag">{item.technique}</span></td><td>{item.tactic}</td><td>{eventHost(item)}</td><td title={formatTime(item.timestamp)}>{formatTime(item.timestamp)}</td>
    </tr>
  })}</tbody></table>{events.length === 0 && <div className="empty-state">No events match these filters.</div>}</div>
}

function Mitre({ events, onSelect }: { events: Alert[], onSelect: (item: Alert) => void }) {
  const groups = new Map<string, Array<{ event: Alert; mapping: MitreMapping }>>()
  for (const event of events) for (const mapping of getMappings(readAnalysis(event))) (groups.get(mapping.tactic) ?? groups.set(mapping.tactic, []).get(mapping.tactic)!).push({ event, mapping })
  const sorted = [...groups.entries()].sort((left, right) => right[1].length - left[1].length)
  return <section className="mitre-page"><div className="mitre-intro"><p>Coverage comes from ATT&amp;CK tags on matched Sigma rules. Events without a rule mapping stay visible in the alert queue.</p><span>{sorted.length} tactics · {events.length} AI alerts</span></div>
    <div className="mitre-grid">{sorted.length ? sorted.map(([tactic, items]) => {
      const techniques = [...new Set(items.map(item => item.mapping.technique))]
      return <article className="tactic-card" key={tactic}><p className="eyebrow">ATT&amp;CK TACTIC</p><h2>{tactic}</h2><strong>{items.length}<small> mapped findings</small></strong><div className="technique-chips">{techniques.map(technique => <span className="attack-tag" key={technique}>{technique}</span>)}</div><div className="mitre-events">{items.slice(0, 5).map(({ event, mapping }) => <button key={`${event.alertId}-${mapping.ruleId}`} className="mitre-event" onClick={() => onSelect(event)}><span className={`severity-dot ${event.severity}`} />{mapping.ruleTitle}<small>{event.comm ?? `PID ${event.processid}`}</small></button>)}</div></article>
    }) : <div className="empty-state">No ATT&amp;CK tagged Sigma findings have been recorded yet.</div>}</div>
  </section>
}

function Detail({ alert, statusSaving, statusError, onClose, onStatus }: { alert: Alert, statusSaving: boolean, statusError: string, onClose: () => void, onStatus: (status: AnalystStatus) => void }) {
  const analysis = readAnalysis(alert)
  const assessment = getEventAssessment(alert, analysis)
  const mappings = getMappings(analysis)
  let source: unknown = alert.rawEvent ?? null
  if (typeof source === 'string') { try { source = JSON.parse(source) } catch { /* Keep malformed source text visible. */ } }
  return <div className="drawer-layer" onMouseDown={onClose}><aside className="drawer" onMouseDown={event => event.stopPropagation()}><button className="close" onClick={onClose}>×</button>
    <span className={`severity-badge ${assessment.badgeClass}`} title={assessment.hint}>{assessment.label}{analysis?.alert ? ` · model score ${alert.score}%` : ''}</span>
    <p className="eyebrow">Investigation detail</p><h2>{alert.title}</h2><p className="drawer-lead">Collector evidence, analyst triage, and the SOC workflow result for this event.</p>
    <dl><div><dt>Log ID</dt><dd>{alert.id}</dd></div><div><dt>Host / process</dt><dd>{eventHost(alert)} · {alert.comm ?? 'unknown'} · PID {alert.processid}</dd></div><div><dt>Parent process</dt><dd>PID {alert.parentProcessId}</dd></div><div><dt>User / namespace</dt><dd>UID {alert.userId} · {alert.mountNamespace}</dd></div><div><dt>Event / args</dt><dd>{alert.eventName ?? alert.eventId} · {alert.argsNum} arguments</dd></div><div><dt>Return / flags</dt><dd>{alert.returnValue} · sus {alert.sus ?? '—'} · evil {alert.evil ?? '—'}</dd></div><div><dt>Assessment</dt><dd>{assessment.hint}</dd></div><div><dt>Analyst status</dt><dd>{assessment.requiresTriage ? alert.status.replace('_', ' ') : 'Not required'}</dd></div><div><dt>Event time (local)</dt><dd title={`Raw Tracee timestamp: ${alert.timestamp ?? 'not provided'}`}>{formatTime(alert.timestamp)}</dd></div>{analysis?.alert?.anomaly_score !== undefined && <div><dt>Model anomaly score</dt><dd>{alert.score}% · {analysis.alert.model ?? 'SOC model'}</dd></div>}</dl>
    {mappings.length > 0 && <section className="analysis-section"><h3>MITRE ATT&amp;CK mapping</h3>{mappings.map(mapping => <p key={`${mapping.ruleId}-${mapping.technique}`}><strong>{mapping.tactic} · {mapping.technique}</strong><small>{mapping.ruleTitle}</small></p>)}</section>}
    {analysis?.incident_report && <section className="analysis-section"><h3>AI incident report</h3><pre>{analysis.incident_report}</pre></section>}
    {alert.aiStatus === 'report_pending' && <p className="analysis-meta">This alert stays in the queue while the incident report is retried automatically.</p>}
    {analysis?.incident_report_error && <p className="analysis-error">{analysis.incident_report_error}{alert.aiStatus === 'report_pending' ? ' A retry is scheduled automatically.' : '; model detection and event correlation are still available.'}</p>}
    {analysis?.rule_matches && analysis.rule_matches.length > 0 && <section className="analysis-section"><h3>Sigma matches</h3>{analysis.rule_matches.map((rule, index) => <article className="rule-detail" key={`${rule.rule_id}-${index}`}><strong>{rule.title || rule.rule_id}</strong><small>{rule.evidence?.tags?.join(' · ') || rule.evidence?.level || 'Rule evidence attached'}</small><details><summary>Matched evidence</summary><pre>{JSON.stringify(rule.evidence?.events ?? rule.evidence, null, 2)}</pre></details></article>)}</section>}
    {analysis?.related_events && <section className="analysis-section"><h3>Related activity · {analysis.related_event_count ?? analysis.related_events.length}</h3><div className="related-list">{analysis.related_events.slice(0, 8).map((event, index) => <div key={`${event.process_id}-${event.timestamp}-${index}`}><span>{event.relation}</span><strong>{event.event_name ?? `Event ${event.event_id ?? 'unknown'}`}</strong><small>{event.process_name ?? `PID ${event.process_id ?? '—'}`} · {event.return_value ?? 'return n/a'}</small></div>)}</div></section>}
    {analysis?.steps && <p className="analysis-meta">Workflow: {analysis.steps.map(step => step.node).join(' → ')}</p>}
    {alert.aiStatus === 'failed' && <p className="analysis-error">{analysis?.error ?? 'SOC analysis failed. Check the AI service logs.'}</p>}
    <details className="raw-evidence"><summary>Full Tracee event evidence</summary><pre>{source ? JSON.stringify(source, null, 2) : 'Collector did not include a raw event payload.'}</pre></details>
    {statusError && <p className="analysis-error">{statusError}</p>}
    {assessment.requiresTriage ? <div className="drawer-actions"><button className="primary" disabled={statusSaving} onClick={() => onStatus('investigating')}>Investigating</button><button disabled={statusSaving} onClick={() => onStatus('resolved')}>Resolve</button><button disabled={statusSaving} onClick={() => onStatus('false_positive')}>False positive</button>{alert.status !== 'open' && <button disabled={statusSaving} onClick={() => onStatus('open')}>Reopen</button>}</div> : <p className="analysis-meta">{analysis?.is_alert === false ? 'No analyst triage is needed for this non-anomalous event.' : 'Triage controls will be available after the AI result is completed.'}</p>}
  </aside></div>
}

