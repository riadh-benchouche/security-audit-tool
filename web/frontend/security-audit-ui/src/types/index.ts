// API Response Types
export interface ApiResponse<T = any> {
  success: boolean
  message?: string
  data?: T
  error?: string
}

// Scan Types
export interface ScanRequest {
  target: string
  modules: string[]
  options?: Record<string, any>
}

export interface ScanResult {
  target: string
  start_time: string
  end_time: string
  duration: number
  results: ModuleResult[]
  summary: ScanSummary
}

export interface ModuleResult {
  module: string
  status: ScanStatus
  start_time: string
  end_time: string
  duration: number
  findings: Finding[]
  errors?: string[]
  metadata?: Record<string, any>
}

export interface Finding {
  id: string
  type: FindingType
  severity: Severity
  title: string
  description: string
  target: string
  evidence?: Record<string, any>
  remediation?: string
  references?: string[]
  cvss?: CVSSScore
  tags?: string[]
  timestamp: string
}

export interface ScanSummary {
  total_findings: number
  findings_by_severity: Record<Severity, number>
  findings_by_type: Record<FindingType, number>
  modules_executed: string[]
  modules_failed?: string[]
  score: number
  grade: Grade
}

// Network Types
export interface NetworkResult {
  host: string
  ip: string
  ports: PortResult[]
  os?: OSDetection
  services: Service[]
  ping?: PingResult
}

export interface PortResult {
  port: number
  protocol: string
  state: PortState
  service?: Service
  banner?: string
}

export interface Service {
  name: string
  version?: string
  product?: string
  extra_info?: string
  tunnel?: string
  method?: string
  conf?: number
  cpe?: string[]
  scripts?: Record<string, string>
}

export interface OSDetection {
  name: string
  family: string
  generation?: string
  type?: string
  vendor?: string
  accuracy: number
  fingerprint?: string
}

export interface PingResult {
  alive: boolean
  rtt?: number
  method: string
  error?: string
}

// HTTP Types
export interface HTTPResult {
  url: string
  status_code: number
  headers: Record<string, string>
  title?: string
  server?: string
  technologies?: Technology[]
  ssl?: SSLResult
  security: SecurityHeaders
  redirects?: Redirect[]
  response_time: number
}

export interface Technology {
  name: string
  version?: string
  categories?: string[]
  website?: string
  icon?: string
}

export interface SSLResult {
  enabled: boolean
  version?: string
  certificate?: Certificate
  ciphers?: string[]
  protocols?: string[]
  vulnerabilities?: string[]
  grade?: string
}

export interface Certificate {
  subject: string
  issuer: string
  serial_number: string
  not_before: string
  not_after: string
  is_expired: boolean
  is_ca: boolean
  key_size: number
  signature_algorithm: string
  dns_names?: string[]
  email_addresses?: string[]
}

export interface SecurityHeaders {
  hsts?: Header
  csp?: Header
  x_frame_options?: Header
  x_content_type_options?: Header
  x_xss_protection?: Header
  referrer_policy?: Header
  permissions_policy?: Header
  expect_ct?: Header
  score: number
  grade: string
}

export interface Header {
  present: boolean
  value?: string
  valid: boolean
  issues?: string[]
  score: number
}

export interface Redirect {
  from: string
  to: string
  status_code: number
}

export interface CVSSScore {
  version: number
  vector: string
  score: number
  rating: string
}

// Module Types
export interface Module {
  name: string
  description: string
  version: string
  enabled: boolean
}

// Enums
export type ScanStatus = 'pending' | 'running' | 'completed' | 'failed' | 'canceled'
export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type FindingType =
  'vulnerability'
  | 'misconfiguration'
  | 'information'
  | 'compliance'
  | 'best_practice'
export type PortState = 'open' | 'closed' | 'filtered'
export type Grade = 'A' | 'B' | 'C' | 'D' | 'F'

// Chart Types
export interface ChartData {
  labels: string[]
  datasets: ChartDataset[]
}

export interface ChartDataset {
  label: string
  data: number[]
  backgroundColor?: string | string[]
  borderColor?: string | string[]
  borderWidth?: number
}

// UI Types
export interface NotificationOptions {
  title: string
  message: string
  type: 'success' | 'error' | 'warning' | 'info'
  duration?: number
}

export interface ModalOptions {
  title: string
  message: string
  type: 'confirm' | 'alert' | 'prompt'
  confirmText?: string
  cancelText?: string
}

// Store Types
export interface ScanState {
  scans: ScanResult[]
  currentScan?: ScanResult
  isLoading: boolean
  error?: string
}

export interface UIState {
  isDarkMode: boolean
  sidebarOpen: boolean
  currentView: string
}

// Filter Types
export interface ScanFilter {
  target?: string
  modules?: string[]
  severity?: Severity[]
  dateRange?: {
    from: Date
    to: Date
  }
  grade?: Grade[]
}

// Configuration Types
export interface AppConfig {
  apiBaseUrl: string
  defaultTimeout: number
  maxRetries: number
  enableNotifications: boolean
  theme: 'light' | 'dark' | 'auto'
}

// Utility Types
export type Optional<T, K extends keyof T> = Omit<T, K> & Partial<Pick<T, K>>
export type RequiredFields<T, K extends keyof T> = T & Required<Pick<T, K>>

// API Error Types
export interface ApiError {
  code: string
  message: string
  details?: any
}
