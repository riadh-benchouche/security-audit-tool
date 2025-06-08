<script setup lang="ts">
import {computed, onMounted, ref} from 'vue'
import {useRouter} from 'vue-router'
import {useScansStore} from '@/stores/scans'
import {useToast} from 'vue-toastification'
import type {ScanRequest} from '@/types'
import {
  ExclamationTriangleIcon,
  InformationCircleIcon,
  LightBulbIcon,
  RocketLaunchIcon
} from '@heroicons/vue/24/outline'

const router = useRouter()
const scansStore = useScansStore()
const toast = useToast()

const showAdvanced = ref(false)

const scanRequest = ref<ScanRequest>({
  target: '',
  modules: ['network'],
  options: {
    timeout: 300,
    threads: 10,
    user_agent: 'SecurityAuditTool/1.0'
  }
})

const availableModules = ref([
  {
    name: 'network',
    description: 'Port scanning and service detection',
    enabled: true
  },
  {
    name: 'http',
    description: 'HTTP security headers and SSL analysis',
    enabled: true
  },
  {
    name: 'ssl',
    description: 'Advanced SSL/TLS certificate analysis',
    enabled: false
  },
  {
    name: 'dns',
    description: 'DNS configuration and security checks',
    enabled: false
  },
  {
    name: 'whois',
    description: 'Domain registration and ownership info',
    enabled: false
  }
])

// Computed
const canStartScan = computed(() => {
  return scanRequest.value.target.trim() !== '' && scanRequest.value.modules.length > 0
})

const estimatedDuration = computed(() => {
  const baseTime = 30 // seconds per module
  const moduleCount = scanRequest.value.modules.length
  const estimated = baseTime * moduleCount

  if (estimated < 60) return `~${estimated}s`
  if (estimated < 3600) return `~${Math.round(estimated / 60)}m`
  return `~${Math.round(estimated / 3600)}h`
})

const selectedModuleDetails = computed(() => {
  return availableModules.value.filter(module =>
    scanRequest.value.modules.includes(module.name)
  )
})

const recentTargets = computed(() => {
  return [...new Set(scansStore.scans.map(scan => scan.target))].slice(0, 5)
})

// Methods
const startScan = async () => {
  try {
    const result = await scansStore.startScan(scanRequest.value)

    if (result) {
      toast.success(`Scan started successfully for ${scanRequest.value.target}`)
      await router.push('/')
    } else {
      toast.error('Failed to start scan. Please check your configuration.')
    }
  } catch (error) {
    toast.error(`Scan failed: ${error instanceof Error ? error.message : 'Unknown error'}`)
  }
}

onMounted(() => {
  scansStore.fetchModules()
})
</script>

<template>
  <div class="container-custom section-spacing">
    <div class="mb-8">
      <h1 class="text-3xl font-bold text-gray-900 dark:text-white">
        New Security Scan
      </h1>
      <p class="mt-2 text-gray-600 dark:text-gray-400">
        Configure and launch a comprehensive security audit
      </p>
    </div>

    <div class="grid grid-cols-1 lg:grid-cols-3 gap-8">
      <!-- Formulaire de scan -->
      <div class="lg:col-span-2">
        <form @submit.prevent="startScan" class="space-y-6">
          <div class="card p-6">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Target Configuration
            </h3>

            <!-- Target URL/IP -->
            <div>
              <label for="target"
                     class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                Target URL or IP Address
              </label>
              <input
                id="target"
                v-model="scanRequest.target"
                type="text"
                placeholder="example.com or https://example.com or 192.168.1.1"
                class="input-field w-full"
                required
              />
              <p class="mt-1 text-xs text-gray-500 dark:text-gray-400">
                Enter a domain, URL, or IP address to scan
              </p>
            </div>
          </div>

          <!-- Modules Selection -->
          <div class="card p-6">
            <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
              Scan Modules
            </h3>

            <div class="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div
                v-for="module in availableModules"
                :key="module.name"
                class="relative"
              >
                <label
                  class="flex items-start space-x-3 p-4 border-2 border-gray-200 dark:border-gray-600 rounded-lg cursor-pointer transition-colors hover:border-security-300 dark:hover:border-security-500"
                  :class="{
                    'border-security-500 bg-security-50 dark:bg-security-900/20': scanRequest.modules.includes(module.name),
                    'bg-gray-50 dark:bg-gray-700/50': !module.enabled
                  }"
                >
                  <input
                    v-model="scanRequest.modules"
                    :value="module.name"
                    type="checkbox"
                    class="mt-1 h-4 w-4 text-security-600 focus:ring-security-500 border-gray-300 rounded"
                    :disabled="!module.enabled"
                  />
                  <div class="flex-1">
                    <div class="flex items-center space-x-2">
                      <span class="font-medium text-gray-900 dark:text-white">
                        {{ module.name.charAt(0).toUpperCase() + module.name.slice(1) }}
                      </span>
                      <span
                        v-if="!module.enabled"
                        class="inline-flex items-center px-2 py-0.5 rounded text-xs font-medium bg-gray-100 text-gray-800 dark:bg-gray-700 dark:text-gray-300"
                      >
                        Coming Soon
                      </span>
                    </div>
                    <p class="text-sm text-gray-500 dark:text-gray-400 mt-1">
                      {{ module.description }}
                    </p>
                  </div>
                </label>
              </div>
            </div>
          </div>

          <!-- Advanced Options -->
          <div class="card p-6">
            <div class="flex items-center justify-between mb-4">
              <h3 class="text-lg font-semibold text-gray-900 dark:text-white">
                Advanced Options
              </h3>
              <button
                type="button"
                @click="showAdvanced = !showAdvanced"
                class="text-sm text-security-600 hover:text-security-700 dark:text-security-400 dark:hover:text-security-300"
              >
                {{ showAdvanced ? 'Hide' : 'Show' }} Advanced
              </button>
            </div>

            <div v-show="showAdvanced" class="space-y-4">
              <!-- Timeout -->
              <div>
                <label for="timeout"
                       class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Timeout (seconds)
                </label>
                <input
                  id="timeout"
                  v-model.number="scanRequest.options.timeout"
                  type="number"
                  min="30"
                  max="3600"
                  class="input-field"
                />
              </div>

              <!-- Threads -->
              <div>
                <label for="threads"
                       class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  Concurrent Threads
                </label>
                <input
                  id="threads"
                  v-model.number="scanRequest.options.threads"
                  type="number"
                  min="1"
                  max="100"
                  class="input-field"
                />
              </div>

              <!-- User Agent -->
              <div>
                <label for="userAgent"
                       class="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                  User Agent
                </label>
                <select
                  id="userAgent"
                  v-model="scanRequest.options.user_agent"
                  class="input-field"
                >
                  <option value="SecurityAuditTool/1.0">SecurityAuditTool/1.0 (Default)</option>
                  <option value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36">
                    Chrome/Windows
                  </option>
                  <option
                    value="Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36">
                    Chrome/macOS
                  </option>
                  <option value="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36">Chrome/Linux
                  </option>
                </select>
              </div>
            </div>
          </div>

          <!-- Actions -->
          <div class="flex items-center justify-between">
            <router-link
              to="/"
              class="btn-secondary"
            >
              Cancel
            </router-link>
            <button
              type="submit"
              :disabled="!canStartScan || scansStore.isScanning"
              class="btn-primary flex items-center space-x-2"
              :class="{ 'opacity-50 cursor-not-allowed': !canStartScan || scansStore.isScanning }"
            >
              <div v-if="scansStore.isScanning" class="loading-spinner"></div>
              <RocketLaunchIcon v-else class="w-4 h-4"/>
              <span>{{ scansStore.isScanning ? 'Scanning...' : 'Start Scan' }}</span>
            </button>
          </div>
        </form>
      </div>

      <!-- Sidebar avec info et preview -->
      <div class="space-y-6">
        <!-- Scan Preview -->
        <div class="card p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Scan Preview
          </h3>

          <div class="space-y-3 text-sm">
            <div class="flex justify-between">
              <span class="text-gray-500 dark:text-gray-400">Target:</span>
              <span class="font-medium text-gray-900 dark:text-white">
                {{ scanRequest.target || 'Not specified' }}
              </span>
            </div>
            <div class="flex justify-between">
              <span class="text-gray-500 dark:text-gray-400">Modules:</span>
              <span class="font-medium text-gray-900 dark:text-white">
                {{ scanRequest.modules.length }}
              </span>
            </div>
            <div class="flex justify-between">
              <span class="text-gray-500 dark:text-gray-400">Est. Duration:</span>
              <span class="font-medium text-gray-900 dark:text-white">
                {{ estimatedDuration }}
              </span>
            </div>
          </div>

          <div class="mt-4 p-3 bg-blue-50 dark:bg-blue-900/20 rounded-lg">
            <div class="flex items-start space-x-2">
              <InformationCircleIcon class="w-5 h-5 text-blue-600 dark:text-blue-400 mt-0.5"/>
              <div class="text-sm text-blue-700 dark:text-blue-300">
                <p class="font-medium mb-1">Selected Modules:</p>
                <ul class="space-y-1">
                  <li v-for="module in selectedModuleDetails" :key="module.name">
                    • {{ module.name }}: {{ module.description }}
                  </li>
                </ul>
              </div>
            </div>
          </div>
        </div>

        <!-- Tips -->
        <div class="card p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Scanning Tips
          </h3>

          <div class="space-y-3 text-sm text-gray-600 dark:text-gray-400">
            <div class="flex items-start space-x-2">
              <LightBulbIcon class="w-4 h-4 text-yellow-500 mt-0.5"/>
              <p>Start with basic modules for faster initial assessment</p>
            </div>
            <div class="flex items-start space-x-2">
              <LightBulbIcon class="w-4 h-4 text-yellow-500 mt-0.5"/>
              <p>Use HTTPS URLs for complete SSL/TLS analysis</p>
            </div>
            <div class="flex items-start space-x-2">
              <LightBulbIcon class="w-4 h-4 text-yellow-500 mt-0.5"/>
              <p>Network scans work best with IP addresses or domains</p>
            </div>
            <div class="flex items-start space-x-2">
              <ExclamationTriangleIcon class="w-4 h-4 text-orange-500 mt-0.5"/>
              <p>Only scan systems you own or have permission to test</p>
            </div>
          </div>
        </div>

        <!-- Recent Targets -->
        <div v-if="recentTargets.length > 0" class="card p-6">
          <h3 class="text-lg font-semibold text-gray-900 dark:text-white mb-4">
            Recent Targets
          </h3>

          <div class="space-y-2">
            <button
              v-for="target in recentTargets"
              :key="target"
              @click="scanRequest.target = target"
              class="w-full text-left p-2 text-sm text-gray-600 dark:text-gray-400 hover:text-gray-900 dark:hover:text-white hover:bg-gray-50 dark:hover:bg-gray-700 rounded transition-colors"
            >
              {{ target }}
            </button>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

