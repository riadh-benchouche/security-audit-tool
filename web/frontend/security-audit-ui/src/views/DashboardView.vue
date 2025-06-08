<script setup lang="ts">
import {computed, onMounted} from 'vue'
import {useRouter} from 'vue-router'
import {useScansStore} from '@/stores/scans'
import {format} from 'date-fns'
import type {ScanResult} from '@/types'
import {
  AcademicCapIcon,
  ArrowPathIcon,
  BeakerIcon,
  ChartBarIcon,
  ChevronRightIcon,
  ClockIcon,
  DocumentTextIcon,
  PlusIcon,
  ShieldCheckIcon,
  ShieldExclamationIcon
} from '@heroicons/vue/24/outline'

const router = useRouter()
const scansStore = useScansStore()

// Computed
const overallGrade = computed(() => {
  const grades = scansStore.scansByGrade
  const total = Object.values(grades).reduce((sum, count) => sum + count, 0)

  if (total === 0) return 'N/A'

  // Calculer la moyenne pondérée des grades
  const gradeValues = {A: 5, B: 4, C: 3, D: 2, F: 1}
  let weightedSum = 0

  Object.entries(grades).forEach(([grade, count]) => {
    weightedSum += gradeValues[grade as keyof typeof gradeValues] * count
  })

  const average = weightedSum / total

  if (average >= 4.5) return 'A'
  if (average >= 3.5) return 'B'
  if (average >= 2.5) return 'C'
  if (average >= 1.5) return 'D'
  return 'F'
})

// Methods
const refreshData = async () => {
  await scansStore.fetchModules()
}

const viewScan = (scan: ScanResult) => {
  scansStore.currentScan = scan
  router.push(`/scans/${encodeURIComponent(scan.target)}`)
}

const formatDate = (dateString: string) => {
  return format(new Date(dateString), 'MMM dd, yyyy HH:mm')
}

const getGradeColor = (grade: string) => {
  const colors = {
    A: 'bg-green-100 text-green-800 dark:bg-green-900/20 dark:text-green-400',
    B: 'bg-lime-100 text-lime-800 dark:bg-lime-900/20 dark:text-lime-400',
    C: 'bg-yellow-100 text-yellow-800 dark:bg-yellow-900/20 dark:text-yellow-400',
    D: 'bg-orange-100 text-orange-800 dark:bg-orange-900/20 dark:text-orange-400',
    F: 'bg-red-100 text-red-800 dark:bg-red-900/20 dark:text-red-400'
  }
  return colors[grade as keyof typeof colors] || colors.F
}

const getGradeColorDot = (grade: string) => {
  const colors = {
    A: 'bg-green-500',
    B: 'bg-lime-500',
    C: 'bg-yellow-500',
    D: 'bg-orange-500',
    F: 'bg-red-500'
  }
  return colors[grade as keyof typeof colors] || colors.F
}

const addSampleData = () => {
  scansStore.addSampleData()
}

onMounted(() => {
  refreshData()
})
</script>
<template>
  <div class="container-custom section-spacing">
    <!-- Header avec actions rapides -->
    <div class="flex flex-col sm:flex-row sm:items-center sm:justify-between mb-8">
      <div>
        <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
          Security Dashboard
        </h1>
        <p class="mt-2 text-gray-600 dark:text-gray-400">
          Monitor your security posture and recent scan activities
        </p>
      </div>
      <div class="mt-4 sm:mt-0 flex space-x-3">
        <button
          @click="refreshData"
          :disabled="scansStore.isLoading"
          class="btn-secondary flex items-center space-x-2"
        >
          <ArrowPathIcon class="w-4 h-4" :class="{ 'animate-spin': scansStore.isLoading }"/>
          <span>Refresh</span>
        </button>
        <router-link to="/scan/new" class="btn-primary flex items-center space-x-2">
          <PlusIcon class="w-4 h-4"/>
          <span>New Scan</span>
        </router-link>
      </div>
    </div>

    <!-- Stats Cards -->
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-6 mb-8">
      <!-- Total Scans -->
      <div class="card p-6">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm font-medium text-gray-600 dark:text-gray-400">Total Scans</p>
            <p class="text-2xl font-bold text-gray-900 dark:text-white">
              {{ scansStore.totalScans }}
            </p>
          </div>
          <div class="p-3 bg-security-100 dark:bg-security-900/20 rounded-lg">
            <ShieldCheckIcon class="w-6 h-6 text-security-600 dark:text-security-400"/>
          </div>
        </div>
      </div>

      <!-- Average Score -->
      <div class="card p-6">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm font-medium text-gray-600 dark:text-gray-400">Average Score</p>
            <p class="text-2xl font-bold text-gray-900 dark:text-white">
              {{ scansStore.averageScore }}/100
            </p>
          </div>
          <div class="p-3 bg-blue-100 dark:bg-blue-900/20 rounded-lg">
            <ChartBarIcon class="w-6 h-6 text-blue-600 dark:text-blue-400"/>
          </div>
        </div>
      </div>

      <!-- Active Scans -->
      <div class="card p-6">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm font-medium text-gray-600 dark:text-gray-400">Active Scans</p>
            <p class="text-2xl font-bold text-gray-900 dark:text-white">
              {{ scansStore.isScanning ? '1' : '0' }}
            </p>
          </div>
          <div class="p-3 bg-yellow-100 dark:bg-yellow-900/20 rounded-lg">
            <ClockIcon class="w-6 h-6 text-yellow-600 dark:text-yellow-400"/>
          </div>
        </div>
      </div>

      <!-- Security Grade -->
      <div class="card p-6">
        <div class="flex items-center justify-between">
          <div>
            <p class="text-sm font-medium text-gray-600 dark:text-gray-400">Overall Grade</p>
            <p class="text-2xl font-bold text-gray-900 dark:text-white">
              {{ overallGrade }}
            </p>
          </div>
          <div class="p-3 bg-green-100 dark:bg-green-900/20 rounded-lg">
            <AcademicCapIcon class="w-6 h-6 text-green-600 dark:text-green-400"/>
          </div>
        </div>
      </div>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
      <!-- Recent Scans -->
      <div class="lg:col-span-2">
        <div class="card">
          <div class="px-6 py-4 border-b border-gray-200 dark:border-gray-700">
            <div class="flex items-center justify-between">
              <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                Recent Scans
              </h3>
              <router-link
                to="/scans"
                class="text-sm text-security-600 hover:text-security-700 dark:text-security-400 dark:hover:text-security-300"
              >
                View all
              </router-link>
            </div>
          </div>
          <div class="p-6">
            <div v-if="scansStore.recentScans.length === 0" class="text-center py-8">
              <ShieldExclamationIcon
                class="w-12 h-12 text-gray-400 dark:text-gray-600 mx-auto mb-4"/>
              <p class="text-gray-500 dark:text-gray-400 mb-4">No scans yet</p>
              <router-link to="/scan/new" class="btn-primary">
                Start your first scan
              </router-link>
            </div>
            <div v-else class="space-y-4">
              <div
                v-for="scan in scansStore.recentScans"
                :key="scan.target + scan.start_time"
                class="flex items-center justify-between p-4 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors cursor-pointer"
                @click="viewScan(scan)"
              >
                <div class="flex items-center space-x-3">
                  <div class="flex-shrink-0">
                    <div
                      class="w-10 h-10 rounded-lg flex items-center justify-center"
                      :class="getGradeColor(scan.summary?.grade || 'F')"
                    >
                      <span class="text-sm font-bold">{{ scan.summary?.grade || 'F' }}</span>
                    </div>
                  </div>
                  <div>
                    <p class="text-sm font-medium text-gray-900 dark:text-white">
                      {{ scan.target }}
                    </p>
                    <p class="text-xs text-gray-500 dark:text-gray-400">
                      {{ formatDate(scan.start_time) }}
                    </p>
                  </div>
                </div>
                <div class="flex items-center space-x-2">
                  <span class="text-sm text-gray-500 dark:text-gray-400">
                    {{ scan.summary?.total_findings || 0 }} findings
                  </span>
                  <ChevronRightIcon class="w-4 h-4 text-gray-400"/>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>

      <!-- Quick Actions & Stats -->
      <div class="space-y-6">
        <!-- Quick Actions -->
        <div class="card p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Quick Actions
          </h3>
          <div class="space-y-3">
            <router-link
              to="/scan/new"
              class="flex items-center p-3 bg-security-50 dark:bg-security-900/20 rounded-lg hover:bg-security-100 dark:hover:bg-security-900/30 transition-colors group"
            >
              <PlusIcon class="w-5 h-5 text-security-600 dark:text-security-400 mr-3"/>
              <span class="text-sm font-medium text-security-700 dark:text-security-300">
                New Security Scan
              </span>
            </router-link>
            <router-link
              to="/reports"
              class="flex items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors group"
            >
              <DocumentTextIcon class="w-5 h-5 text-gray-600 dark:text-gray-400 mr-3"/>
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                Generate Report
              </span>
            </router-link>
            <button
              @click="addSampleData"
              class="w-full flex items-center p-3 bg-gray-50 dark:bg-gray-700/50 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors group"
            >
              <BeakerIcon class="w-5 h-5 text-gray-600 dark:text-gray-400 mr-3"/>
              <span class="text-sm font-medium text-gray-700 dark:text-gray-300">
                Add Sample Data
              </span>
            </button>
          </div>
        </div>

        <!-- Grade Distribution -->
        <div class="card p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Grade Distribution
          </h3>
          <div class="space-y-3">
            <div
              v-for="(count, grade) in scansStore.scansByGrade"
              :key="grade"
              class="flex items-center justify-between"
            >
              <div class="flex items-center space-x-2">
                <div
                  class="w-3 h-3 rounded-full"
                  :class="getGradeColorDot(grade)"
                ></div>
                <span class="text-sm text-gray-600 dark:text-gray-400">Grade {{ grade }}</span>
              </div>
              <span class="text-sm font-medium text-gray-900 dark:text-white">{{ count }}</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
