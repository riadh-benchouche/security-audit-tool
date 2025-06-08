import {defineStore} from 'pinia'
import {computed, ref} from 'vue'
import type {ApiResponse, Module, ScanRequest, ScanResult} from '@/types'

export const useScansStore = defineStore('scans', () => {
  // State
  const scans = ref<ScanResult[]>([])
  const currentScan = ref<ScanResult | null>(null)
  const isLoading = ref(false)
  const isScanning = ref(false)
  const error = ref<string | null>(null)
  const modules = ref<Module[]>([])

  // API Base URL
  const API_BASE = 'http://localhost:8080/api/v1'

  // Computed
  const totalScans = computed(() => scans.value.length)
  const recentScans = computed(() =>
    scans.value
      .sort((a, b) => new Date(b.start_time).getTime() - new Date(a.start_time).getTime())
      .slice(0, 5)
  )

  const scansByGrade = computed(() => {
    const grades = {A: 0, B: 0, C: 0, D: 0, F: 0}
    scans.value.forEach(scan => {
      if (scan.summary?.grade && scan.summary.grade in grades) {
        grades[scan.summary.grade as keyof typeof grades]++
      }
    })
    return grades
  })

  const averageScore = computed(() => {
    if (scans.value.length === 0) return 0
    const total = scans.value.reduce((sum, scan) => sum + (scan.summary?.score || 0), 0)
    return Math.round(total / scans.value.length)
  })

  // Actions
  const fetchModules = async () => {
    try {
      isLoading.value = true
      error.value = null

      const response = await fetch(`${API_BASE}/modules`)
      const data: ApiResponse<Module[]> = await response.json()

      if (data.success && data.data) {
        modules.value = data.data
      }
    } catch (err) {
      error.value = `Failed to fetch modules: ${err instanceof Error ? err.message : 'Unknown error'}`
      console.error('Error fetching modules:', err)
    } finally {
      isLoading.value = false
    }
  }

  const startScan = async (request: ScanRequest): Promise<ScanResult | null> => {
    try {
      isScanning.value = true
      error.value = null

      const response = await fetch(`${API_BASE}/scans`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
        },
        body: JSON.stringify(request)
      })

      const data: ApiResponse<ScanResult> = await response.json()

      if (data.success && data.data) {
        const scanResult = data.data
        scans.value.unshift(scanResult) // Ajouter au début
        currentScan.value = scanResult
        return scanResult
      } else {
        throw new Error(data.error || 'Scan failed')
      }
    } catch (err) {
      error.value = `Scan failed: ${err instanceof Error ? err.message : 'Unknown error'}`
      console.error('Error starting scan:', err)
      return null
    } finally {
      isScanning.value = false
    }
  }

  const getScan = async (id: string): Promise<ScanResult | null> => {
    try {
      isLoading.value = true
      error.value = null

      const response = await fetch(`${API_BASE}/scans/${id}`)
      const data: ApiResponse<ScanResult> = await response.json()

      if (data.success && data.data) {
        currentScan.value = data.data
        return data.data
      } else {
        throw new Error(data.error || 'Scan not found')
      }
    } catch (err) {
      error.value = `Failed to get scan: ${err instanceof Error ? err.message : 'Unknown error'}`
      console.error('Error getting scan:', err)
      return null
    } finally {
      isLoading.value = false
    }
  }

  const testApiConnection = async (): Promise<boolean> => {
    try {
      const response = await fetch(`${API_BASE}/health`)
      const data: ApiResponse = await response.json()
      return data.success === true
    } catch (err) {
      console.error('API connection test failed:', err)
      return false
    }
  }

  const clearError = () => {
    error.value = null
  }

  const addSampleData = () => {
    // Données d'exemple pour le développement
    const sampleScans: ScanResult[] = [
      {
        target: 'google.com',
        start_time: new Date(Date.now() - 3600000).toISOString(),
        end_time: new Date(Date.now() - 3500000).toISOString(),
        duration: 100000,
        results: [
          {
            module: 'network',
            status: 'completed',
            start_time: new Date().toISOString(),
            end_time: new Date().toISOString(),
            duration: 50000,
            findings: [
              {
                id: 'net-1',
                type: 'information',
                severity: 'info',
                title: 'Open port 443/tcp',
                description: 'HTTPS port is open',
                target: 'google.com:443',
                timestamp: new Date().toISOString()
              }
            ]
          }
        ],
        summary: {
          total_findings: 1,
          findings_by_severity: {info: 1, low: 0, medium: 0, high: 0, critical: 0},
          findings_by_type: {
            information: 1,
            misconfiguration: 0,
            vulnerability: 0,
            compliance: 0,
            best_practice: 0
          },
          modules_executed: ['network'],
          score: 95,
          grade: 'A'
        }
      },
      {
        target: 'httpbin.org',
        start_time: new Date(Date.now() - 7200000).toISOString(),
        end_time: new Date(Date.now() - 7100000).toISOString(),
        duration: 100000,
        results: [
          {
            module: 'http',
            status: 'completed',
            start_time: new Date().toISOString(),
            end_time: new Date().toISOString(),
            duration: 30000,
            findings: [
              {
                id: 'http-1',
                type: 'misconfiguration',
                severity: 'medium',
                title: 'Missing HSTS Header',
                description: 'Strict-Transport-Security header is missing',
                target: 'https://httpbin.org',
                remediation: 'Add HSTS header to enforce HTTPS',
                timestamp: new Date().toISOString()
              }
            ]
          }
        ],
        summary: {
          total_findings: 3,
          findings_by_severity: {info: 1, low: 0, medium: 2, high: 0, critical: 0},
          findings_by_type: {
            information: 1,
            misconfiguration: 2,
            vulnerability: 0,
            compliance: 0,
            best_practice: 0
          },
          modules_executed: ['http'],
          score: 85,
          grade: 'B'
        }
      }
    ]

    scans.value = sampleScans
  }

  return {
    // State
    scans,
    currentScan,
    isLoading,
    isScanning,
    error,
    modules,

    // Computed
    totalScans,
    recentScans,
    scansByGrade,
    averageScore,

    // Actions
    fetchModules,
    startScan,
    getScan,
    testApiConnection,
    clearError,
    addSampleData
  }
})
