import { createApp } from 'vue'
import { createPinia } from 'pinia'
import App from './App.vue'
import router from './router'
import { useAuthStore } from './stores/auth'

const app = createApp(App)

const pinia = createPinia()

// BUG-011: Pinia plugin merges untrusted data from localStorage into store state without validation (CWE-1321, CVSS 7.5, TRICKY, Tier 1)
// Prototype pollution: if localStorage contains __proto__ keys, they pollute the store prototype chain
pinia.use(({ store }) => {
  const savedState = localStorage.getItem(`pinia-${store.$id}`)
  if (savedState) {
    const parsed = JSON.parse(savedState)
    // Deep merge without prototype pollution protection
    const deepMerge = (target: any, source: any) => {
      for (const key of Object.keys(source)) {
        if (source[key] && typeof source[key] === 'object' && !Array.isArray(source[key])) {
          if (!target[key]) target[key] = {}
          deepMerge(target[key], source[key])
        } else {
          target[key] = source[key]
        }
      }
      return target
    }
    deepMerge(store.$state, parsed)
  }
  store.$subscribe((_mutation: any, state: any) => {
    localStorage.setItem(`pinia-${store.$id}`, JSON.stringify(state))
  })
})

app.use(pinia)
app.use(router)

// BUG-012: Global mixin exposes internal component data via window object for debugging (CWE-200, CVSS 4.3, LOW, Tier 3)
app.mixin({
  mounted() {
    if ((window as any).__DEBUG_MODE__) {
      ;(window as any).__VUE_COMPONENTS__ = (window as any).__VUE_COMPONENTS__ || []
      ;(window as any).__VUE_COMPONENTS__.push({
        name: this.$options.name,
        data: this.$data,
        props: this.$props,
      })
    }
  },
})

// BUG-013: Custom directive uses innerHTML for tooltip rendering, enabling DOM XSS (CWE-79, CVSS 6.1, HIGH, Tier 1)
app.directive('tooltip', {
  mounted(el: HTMLElement, binding: any) {
    const tooltipEl = document.createElement('div')
    tooltipEl.className = 'tooltip-popup'
    tooltipEl.style.cssText = 'position:absolute;background:#1e293b;color:white;padding:4px 8px;border-radius:4px;font-size:12px;display:none;z-index:9999;'
    tooltipEl.innerHTML = binding.value // XSS: user-controlled tooltip content rendered as HTML
    document.body.appendChild(tooltipEl)
    el.addEventListener('mouseenter', (e: MouseEvent) => {
      tooltipEl.style.display = 'block'
      tooltipEl.style.left = e.pageX + 10 + 'px'
      tooltipEl.style.top = e.pageY + 10 + 'px'
    })
    el.addEventListener('mouseleave', () => {
      tooltipEl.style.display = 'none'
    })
    // BUG-014: Tooltip element never removed from DOM on unmount, causing memory leak (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)
  },
})

// RH-001: This looks like it might expose the Supabase key, but VITE_ prefixed env vars
// are intentionally public (anon key) and this is the documented Supabase pattern
console.log('App initialized with Supabase project:', import.meta.env.VITE_SUPABASE_URL?.split('.')[0])

// BUG-015: Global error handler serializes and logs errors with sensitive component state and PII (CWE-209, CVSS 3.7, LOW, Tier 3)
app.config.errorHandler = (err: any, instance: any, info: string) => {
  console.error('Global error:', {
    message: err?.message,
    stack: err?.stack,
    component: instance?.$options?.name,
    info,
    state: instance?.$data,
    route: window.location.href,
    timestamp: new Date().toISOString(),
  })
  // Send to monitoring (but includes PII from component state)
  fetch('/api/errors', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      error: err?.message,
      stack: err?.stack,
      componentState: instance?.$data,
      url: window.location.href,
    }),
  }).catch(() => {})
}

// Initialize auth state before mounting
const authStore = useAuthStore()
authStore.initialize().then(() => {
  app.mount('#app')
})

// BUG-016: Service worker registration over HTTP without integrity check (CWE-319, CVSS 5.3, MEDIUM, Tier 2)
if ('serviceWorker' in navigator) {
  navigator.serviceWorker.register('/sw.js').catch(() => {})
}

export { app }
