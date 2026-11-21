export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type AnalystStatus = 'open' | 'investigating' | 'resolved' | 'false_positive'

export interface LogEvent {
  id?: number
  processid: number
  threadId: number
  parentProcessId: number
  userId: number
  mountNamespace: number
  eventId: number
  argsNum: number
  returnValue: number
  sus?: number | null
  evil?: number | null
  timestamp?: number | null
  eventName?: string | null
  comm?: string | null
  hostName?: string | null
  rawEvent?: string | null
  analystStatus?: AnalystStatus
  aiStatus?: 'legacy' | 'pending' | 'processing' | 'report_pending' | 'completed' | 'failed'
  aiResult?: string | null
}

export interface Alert extends LogEvent {
  alertId: string
  severity: Severity | null
  score: number
  title: string
  tactic: string
  technique: string
  status: AnalystStatus
  receivedAt: number
}

