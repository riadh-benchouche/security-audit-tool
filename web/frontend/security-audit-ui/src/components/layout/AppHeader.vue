<template>
  <header class="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700 sticky top-0 z-50">
    <div class="container-custom max-w-7xl mx-auto px-4 sm:px-6 lg:px-0 py-6">
      <div class="flex items-center justify-between h-16">
        <!-- Logo et Navigation -->
        <div class="flex items-center space-x-8">
          <!-- Logo -->
          <div class="flex items-center space-x-2">
            <div class="w-8 h-8 bg-security-600 rounded-lg flex items-center justify-center">
              <ShieldCheckIcon class="w-5 h-5 text-white" />
            </div>
            <span class="text-xl font-bold text-gray-900 dark:text-white">
              Security Audit
            </span>
          </div>

          <!-- Navigation Desktop -->
          <nav class="hidden md:flex space-x-6">
            <router-link
              v-for="item in navigation"
              :key="item.name"
              :to="item.to"
              class="nav-link"
              :class="isActiveRoute(item.to) ? 'nav-link-active' : 'nav-link-inactive'"
            >
              <component :is="item.icon" class="w-4 h-4 mr-2" />
              {{ item.name }}
            </router-link>
          </nav>
        </div>

        <!-- Actions de droite -->
        <div class="flex items-center space-x-4">
          <!-- Status API -->
          <div class="hidden sm:flex items-center space-x-2">
            <div class="flex items-center space-x-1">
              <div
                class="w-2 h-2 rounded-full"
                :class="apiConnected ? 'bg-green-500' : 'bg-red-500'"
              ></div>
              <span class="text-xs text-gray-500 dark:text-gray-400">
                {{ apiConnected ? 'API Connected' : 'API Disconnected' }}
              </span>
            </div>
          </div>

          <!-- Toggle Dark Mode -->
          <button
            @click="themeStore.toggleDarkMode()"
            class="p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
            title="Toggle dark mode"
          >
            <SunIcon v-if="themeStore.isDarkMode" class="w-5 h-5" />
            <MoonIcon v-else class="w-5 h-5" />
          </button>

          <!-- Mobile Menu Button -->
          <button
            @click="mobileMenuOpen = !mobileMenuOpen"
            class="md:hidden p-2 text-gray-500 hover:text-gray-700 dark:text-gray-400 dark:hover:text-gray-200 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700"
          >
            <Bars3Icon v-if="!mobileMenuOpen" class="w-5 h-5" />
            <XMarkIcon v-else class="w-5 h-5" />
          </button>
        </div>
      </div>

      <!-- Menu Mobile -->
      <div
        v-show="mobileMenuOpen"
        class="md:hidden py-4 border-t border-gray-200 dark:border-gray-700"
      >
        <nav class="space-y-2">
          <router-link
            v-for="item in navigation"
            :key="item.name"
            :to="item.to"
            @click="mobileMenuOpen = false"
            class="flex items-center px-3 py-2 text-base font-medium rounded-lg transition-colors"
            :class="isActiveRoute(item.to)
              ? 'bg-security-100 text-security-700 dark:bg-security-900/20 dark:text-security-400'
              : 'text-gray-700 hover:bg-gray-100 dark:text-gray-300 dark:hover:bg-gray-700'"
          >
            <component :is="item.icon" class="w-5 h-5 mr-3" />
            {{ item.name }}
          </router-link>
        </nav>
      </div>
    </div>
  </header>
</template>

<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRoute } from 'vue-router'
import { useThemeStore } from '@/stores/theme'
import { useScansStore } from '@/stores/scans'
import {
  ShieldCheckIcon,
  SunIcon,
  MoonIcon,
  PlusIcon,
  Bars3Icon,
  XMarkIcon,
  HomeIcon,
  ChartBarIcon,
  DocumentTextIcon,
  CogIcon,
  ClockIcon
} from '@heroicons/vue/24/outline'

const route = useRoute()
const themeStore = useThemeStore()
const scansStore = useScansStore()

const mobileMenuOpen = ref(false)
const apiConnected = ref(false)

// Navigation items
const navigation = [
  { name: 'Dashboard', to: '/', icon: HomeIcon },
  { name: 'New Scan', to: '/scan/new', icon: PlusIcon },
  { name: 'History', to: '/scans', icon: ClockIcon },
  { name: 'Reports', to: '/reports', icon: DocumentTextIcon },
  { name: 'Analytics', to: '/analytics', icon: ChartBarIcon },
  { name: 'Settings', to: '/settings', icon: CogIcon },
]

// Check if route is active
const isActiveRoute = (to: string) => {
  if (to === '/') {
    return route.path === '/'
  }
  return route.path.startsWith(to)
}

// Test API connection
const testApiConnection = async () => {
  apiConnected.value = await scansStore.testApiConnection()
}

onMounted(() => {
  testApiConnection()
  // Test connection every 30 seconds
  setInterval(testApiConnection, 30000)
})
</script>

<style scoped>
.nav-link {
  @apply flex items-center px-3 py-2 text-sm font-medium rounded-lg transition-colors duration-200;
}

.nav-link-active {
  @apply bg-security-100 text-security-700 dark:bg-security-900/20 dark:text-security-400;
}

.nav-link-inactive {
  @apply text-gray-700 hover:bg-gray-100 hover:text-gray-900 dark:text-gray-300 dark:hover:bg-gray-700 dark:hover:text-white;
}
</style>
