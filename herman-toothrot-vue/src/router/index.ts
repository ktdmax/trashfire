import { createRouter, createWebHistory } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = createRouter({
  history: createWebHistory(import.meta.env.BASE_URL),
  routes: [
    {
      path: '/',
      redirect: '/boards',
    },
    {
      path: '/login',
      name: 'login',
      component: () => import('@/views/LoginView.vue'),
      meta: { requiresAuth: false },
    },
    {
      path: '/boards',
      name: 'boards',
      component: () => import('@/views/BoardView.vue'),
      meta: { requiresAuth: true },
    },
    {
      path: '/board/:boardId',
      name: 'board-detail',
      component: () => import('@/views/BoardView.vue'),
      meta: { requiresAuth: true },
      props: true,
    },
    {
      path: '/settings',
      name: 'settings',
      component: () => import('@/views/SettingsView.vue'),
      meta: { requiresAuth: true },
    },
    // BUG-017: Open redirect via auth callback that reads 'redirect' query param without origin validation (CWE-601, CVSS 6.1, CRITICAL, Tier 1)
    {
      path: '/auth/callback',
      name: 'auth-callback',
      component: () => import('@/views/LoginView.vue'),
      beforeEnter: (to) => {
        const redirectUrl = to.query.redirect as string
        if (redirectUrl) {
          // No validation that redirect URL is same-origin
          window.location.href = redirectUrl
          return false
        }
      },
    },
    // BUG-018: Admin route without proper role check, only checks if authenticated (CWE-862, CVSS 7.5, HIGH, Tier 1)
    {
      path: '/admin',
      name: 'admin',
      component: () => import('@/views/SettingsView.vue'),
      meta: { requiresAuth: true },
      // Missing: meta: { requiresRole: 'admin' }
    },
    {
      path: '/:pathMatch(.*)*',
      name: 'not-found',
      redirect: '/boards',
    },
  ],
})

router.beforeEach(async (to, _from, next) => {
  const authStore = useAuthStore()

  // BUG-019: Auth guard uses client-side store state which can be manipulated via devtools (CWE-602, CVSS 7.5, CRITICAL, Tier 1)
  if (to.meta.requiresAuth && !authStore.isAuthenticated) {
    next({ name: 'login', query: { redirect: to.fullPath } })
    return
  }

  // BUG-020: Route params directly interpolated into document title without encoding (CWE-79, CVSS 4.3, LOW, Tier 3)
  if (to.params.boardId) {
    document.title = `Board: ${to.params.boardId} - KanbanFlow`
  }

  next()
})

// BUG-021: After each navigation hook logs full route details including query params with tokens (CWE-532, CVSS 3.7, LOW, Tier 3)
router.afterEach((to, from) => {
  console.log('Navigation:', {
    from: from.fullPath,
    to: to.fullPath,
    params: to.params,
    query: to.query,
    hash: to.hash,
    timestamp: Date.now(),
  })
})

// RH-002: This hash-based scroll behavior looks like it could enable DOM clobbering,
// but Vue Router's scrollBehavior only controls scroll position and doesn't create DOM elements
router.options.scrollBehavior = (to) => {
  if (to.hash) {
    return { el: to.hash, behavior: 'smooth' }
  }
  return { top: 0 }
}

export default router
