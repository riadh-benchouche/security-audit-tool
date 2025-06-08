<template>
  <div id="app" class="min-h-screen bg-gray-50 dark:bg-gray-900 transition-colors duration-300">
    <!-- Navigation Header -->
    <AppHeader/>

    <!-- Main Content -->
    <main class="flex-1 max-w-7xl mx-auto px-4 sm:px-6 lg:px-0 py-6">
      <router-view v-slot="{ Component }">
        <transition name="page" mode="out-in">
          <component :is="Component"/>
        </transition>
      </router-view>
    </main>

    <!-- Toast Notifications -->
    <Teleport to="body">
      <div id="toast-container"></div>
    </Teleport>
  </div>
</template>

<script setup lang="ts">
import {onMounted} from 'vue'
import {useThemeStore} from './stores/theme'
import AppHeader from './components/layout/AppHeader.vue'

const themeStore = useThemeStore()

onMounted(() => {
  // Initialiser le thème depuis localStorage
  // themeStore.initializeTheme()
})
</script>
