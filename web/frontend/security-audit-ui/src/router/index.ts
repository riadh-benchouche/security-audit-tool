import {createRouter, createWebHistory} from 'vue-router'
import DashboardView from '@/views/DashboardView.vue'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      name: 'dashboard',
      component: DashboardView,
      meta: {
        title: 'Dashboard'
      }
    },
    {
      path: '/scan/new',
      name: 'new-scan',
      component: () => import('@/views/NewScanView.vue'),
      meta: {
        title: 'New Scan'
      }
    },
  ]
})

// Navigation guard pour mettre à jour le titre de la page
router.beforeEach((to) => {
  const title = to.meta?.title as string
  if (title) {
    document.title = `${title} - Security Audit Tool`
  }
})

export default router
