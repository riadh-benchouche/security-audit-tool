import { defineStore } from 'pinia'
import { ref, watch } from 'vue'

export const useThemeStore = defineStore('theme', () => {
  const isDarkMode = ref(false)
  const sidebarOpen = ref(true)

  // Initialiser le thème depuis localStorage
  const initializeTheme = () => {
    const savedTheme = localStorage.getItem('theme')
    const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches

    if (savedTheme === 'dark' || (!savedTheme && prefersDark)) {
      isDarkMode.value = true
      document.documentElement.classList.add('dark')
    } else {
      isDarkMode.value = false
      document.documentElement.classList.remove('dark')
    }
  }

  // Toggle du mode sombre
  const toggleDarkMode = () => {
    isDarkMode.value = !isDarkMode.value
  }

  // Toggle de la sidebar
  const toggleSidebar = () => {
    sidebarOpen.value = !sidebarOpen.value
  }

  // Watcher pour sauvegarder le thème
  watch(isDarkMode, (newValue) => {
    if (newValue) {
      document.documentElement.classList.add('dark')
      localStorage.setItem('theme', 'dark')
    } else {
      document.documentElement.classList.remove('dark')
      localStorage.setItem('theme', 'light')
    }
  })

  // Watcher pour sauvegarder l'état de la sidebar
  watch(sidebarOpen, (newValue) => {
    localStorage.setItem('sidebarOpen', String(newValue))
  })

  // Initialiser l'état de la sidebar
  const initializeSidebar = () => {
    const savedSidebar = localStorage.getItem('sidebarOpen')
    if (savedSidebar !== null) {
      sidebarOpen.value = savedSidebar === 'true'
    }
  }

  return {
    isDarkMode,
    sidebarOpen,
    initializeTheme,
    initializeSidebar,
    toggleDarkMode,
    toggleSidebar
  }
})
