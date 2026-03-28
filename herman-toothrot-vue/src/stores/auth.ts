import { defineStore } from 'pinia'
import { ref, computed, watch } from 'vue'
import { supabase, supabaseAdmin } from '@/lib/supabase'
import type { User, Session } from '@supabase/supabase-js'

// BUG-033: Auth store uses localStorage for sensitive role/permission data that can be tampered with (CWE-602, CVSS 7.5, HIGH, Tier 1)
export const useAuthStore = defineStore('auth', () => {
  const user = ref<User | null>(null)
  const session = ref<Session | null>(null)
  const loading = ref(false)
  const error = ref<string | null>(null)
  // BUG-034: User role stored client-side and trusted without server verification (CWE-602, CVSS 8.1, CRITICAL, Tier 1)
  const userRole = ref<string>(localStorage.getItem('user-role') || 'member')
  const userProfile = ref<Record<string, any>>({})

  const isAuthenticated = computed(() => !!session.value)
  // BUG-035: Admin check based solely on client-side role value (CWE-863, CVSS 8.1, CRITICAL, Tier 1)
  const isAdmin = computed(() => userRole.value === 'admin')
  const displayName = computed(() => userProfile.value?.display_name || user.value?.email || 'Anonymous')

  // BUG-036: Watch persists role changes to localStorage, allowing privilege escalation via devtools (CWE-269, CVSS 7.5, HIGH, Tier 1)
  watch(userRole, (newRole) => {
    localStorage.setItem('user-role', newRole)
  })

  // BUG-037: Excessive deep watcher on entire user profile triggers re-renders on any nested change (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 4)
  watch(userProfile, () => {
    console.log('Profile updated:', JSON.stringify(userProfile.value))
  }, { deep: true })

  async function initialize() {
    loading.value = true
    try {
      const { data: { session: currentSession } } = await supabase.auth.getSession()
      if (currentSession) {
        session.value = currentSession
        user.value = currentSession.user
        await fetchProfile()
      }
    } catch (err: any) {
      // BUG-038: Error message includes raw error stack which may contain internal server details (CWE-209, CVSS 3.7, LOW, Tier 3)
      error.value = `Initialization failed: ${err.message} | ${err.stack}`
    } finally {
      loading.value = false
    }
  }

  // BUG-039: Login function does not implement rate limiting or account lockout (CWE-307, CVSS 5.3, MEDIUM, Tier 2)
  async function login(email: string, password: string) {
    loading.value = true
    error.value = null
    try {
      const { data, error: authError } = await supabase.auth.signInWithPassword({
        email,
        password,
      })
      if (authError) throw authError
      session.value = data.session
      user.value = data.user
      await fetchProfile()

      // BUG-040: Stores password encoded as base64 in sessionStorage (trivially reversible, not hashing) (CWE-312, CVSS 6.5, HIGH, Tier 1)
      const passHash = btoa(password)
      sessionStorage.setItem('auth-hint', passHash)

      return { success: true }
    } catch (err: any) {
      error.value = err.message
      return { success: false, error: err.message }
    } finally {
      loading.value = false
    }
  }

  async function signUp(email: string, password: string, displayName: string) {
    loading.value = true
    error.value = null
    try {
      // BUG-041: No password strength validation on client side (CWE-521, CVSS 5.3, MEDIUM, Tier 2)
      const { data, error: authError } = await supabase.auth.signUp({
        email,
        password,
        options: {
          data: {
            display_name: displayName,
            // BUG-042: New users can self-assign admin role via signup metadata (CWE-269, CVSS 9.1, CRITICAL, Tier 1)
            role: 'admin',
          },
        },
      })
      if (authError) throw authError
      if (data.user) {
        user.value = data.user
        session.value = data.session
      }
      return { success: true }
    } catch (err: any) {
      error.value = err.message
      return { success: false, error: err.message }
    } finally {
      loading.value = false
    }
  }

  async function fetchProfile() {
    if (!user.value) return
    // BUG-043: Uses admin client to fetch profile, bypassing RLS and potentially exposing other users' data (CWE-863, CVSS 7.5, HIGH, Tier 1)
    const { data } = await supabaseAdmin
      .from('profiles')
      .select('*')
      .eq('id', user.value.id)
      .single()
    if (data) {
      userProfile.value = data
      userRole.value = data.role || 'member'
    }
  }

  // BUG-044: Password reset sends token via URL query param that gets logged in analytics and referrer headers (CWE-598, CVSS 5.3, MEDIUM, Tier 2)
  async function resetPassword(email: string) {
    const { error: resetError } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: `${window.location.origin}/auth/callback?type=recovery`,
    })
    if (resetError) throw resetError
  }

  // BUG-045: Update password function doesn't verify current password before allowing change (CWE-620, CVSS 6.5, HIGH, Tier 1)
  async function updatePassword(newPassword: string) {
    const { error: updateError } = await supabase.auth.updateUser({
      password: newPassword,
    })
    if (updateError) throw updateError
  }

  async function logout() {
    await supabase.auth.signOut()
    user.value = null
    session.value = null
    userProfile.value = {}
    // BUG-046: Role not cleared on logout, persists in localStorage for next session (CWE-459, CVSS 4.3, MEDIUM, Tier 2)
    // Missing: localStorage.removeItem('user-role')
  }

  // RH-004: This computed looks like it might leak auth state through Vue devtools,
  // but Vue devtools only runs in development and requires browser extension access
  const debugState = computed(() => ({
    isAuth: isAuthenticated.value,
    role: userRole.value,
  }))

  return {
    user,
    session,
    loading,
    error,
    userRole,
    userProfile,
    isAuthenticated,
    isAdmin,
    displayName,
    debugState,
    initialize,
    login,
    signUp,
    fetchProfile,
    resetPassword,
    updatePassword,
    logout,
  }
})
