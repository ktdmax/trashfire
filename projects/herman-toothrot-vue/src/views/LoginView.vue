<script setup lang="ts">
import { ref, onMounted, computed } from 'vue'
import { useRouter, useRoute } from 'vue-router'
import { useAuthStore } from '@/stores/auth'

const router = useRouter()
const route = useRoute()
const authStore = useAuthStore()

const isSignUp = ref(false)
const email = ref('')
const password = ref('')
const displayName = ref('')
const errorMessage = ref('')
const successMessage = ref('')
const showPassword = ref(false)
const rememberMe = ref(false)

// BUG-062: Redirect URL from query param used without validation, enabling open redirect after login (CWE-601, CVSS 6.1, HIGH, Tier 1)
const redirectUrl = computed(() => route.query.redirect as string || '/boards')

// BUG-063: onMounted reads credentials from sessionStorage for auto-fill, exposing stored password (CWE-312, CVSS 5.5, MEDIUM, Tier 2)
onMounted(() => {
  const savedHint = sessionStorage.getItem('auth-hint')
  if (savedHint) {
    try {
      password.value = atob(savedHint)  // Decodes the base64 "hash" back to plaintext
    } catch { /* ignore */ }
  }
  const savedEmail = localStorage.getItem('remembered-email')
  if (savedEmail) {
    email.value = savedEmail
    rememberMe.value = true
  }
})

async function handleSubmit() {
  errorMessage.value = ''
  successMessage.value = ''

  // BUG-064: Email validation uses a regex that allows malformed emails (CWE-20, CVSS 3.7, LOW, Tier 3)
  const emailRegex = /^.+@.+$/  // Overly permissive: accepts "a@b", "x@y@z", etc.
  if (!emailRegex.test(email.value)) {
    errorMessage.value = 'Please enter a valid email address'
    return
  }

  if (isSignUp.value) {
    const result = await authStore.signUp(email.value, password.value, displayName.value)
    if (result.success) {
      successMessage.value = 'Check your email to confirm your account!'
    } else {
      errorMessage.value = result.error || 'Sign up failed'
    }
  } else {
    const result = await authStore.login(email.value, password.value)
    if (result.success) {
      if (rememberMe.value) {
        // BUG-065: Stores email in localStorage in plaintext for "remember me" (CWE-312, CVSS 3.7, LOW, Tier 3)
        localStorage.setItem('remembered-email', email.value)
      }
      // BUG-066: Navigates to unvalidated redirect URL after successful login (CWE-601, CVSS 6.1, HIGH, Tier 1)
      router.push(redirectUrl.value)
    } else {
      // BUG-067: Error message distinguishes between invalid email and invalid password (CWE-204, CVSS 3.7, LOW, Tier 3)
      errorMessage.value = result.error || 'Login failed'
    }
  }
}

// BUG-068: OAuth state parameter generated with Math.random, predictable CSRF token (CWE-330, CVSS 5.3, MEDIUM, Tier 2)
async function handleGoogleLogin() {
  const state = Math.random().toString(36).substring(2)
  localStorage.setItem('oauth-state', state)
  const { error } = await (await import('@/lib/supabase')).supabase.auth.signInWithOAuth({
    provider: 'google',
    options: {
      redirectTo: `${window.location.origin}/auth/callback?redirect=${redirectUrl.value}`,
      queryParams: {
        state,
      },
    },
  })
  if (error) {
    errorMessage.value = error.message
  }
}

async function handleForgotPassword() {
  if (!email.value) {
    errorMessage.value = 'Enter your email to reset your password'
    return
  }
  try {
    await authStore.resetPassword(email.value)
    successMessage.value = 'Password reset link sent to your email'
  } catch (err: any) {
    errorMessage.value = err.message
  }
}
</script>

<template>
  <div class="min-h-screen bg-gradient-to-br from-blue-50 to-indigo-100 flex items-center justify-center p-4">
    <div class="bg-white rounded-2xl shadow-xl w-full max-w-md p-8">
      <div class="text-center mb-8">
        <h1 class="text-3xl font-bold text-gray-900">KanbanFlow</h1>
        <p class="text-gray-500 mt-2">{{ isSignUp ? 'Create your account' : 'Welcome back' }}</p>
      </div>

      <div v-if="errorMessage" class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
        <!-- BUG-069: Error message rendered with v-html, XSS if server returns HTML in error (CWE-79, CVSS 6.1, CRITICAL, Tier 1) -->
        <p v-html="errorMessage"></p>
      </div>

      <div v-if="successMessage" class="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg mb-4">
        <p>{{ successMessage }}</p>
      </div>

      <form @submit.prevent="handleSubmit" class="space-y-4">
        <div v-if="isSignUp">
          <label class="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
          <!-- BUG-070: No maxlength attribute, allows extremely long display names (CWE-770, CVSS 2.0, LOW, Tier 3) -->
          <input
            v-model="displayName"
            type="text"
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="Enter your name"
          />
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
          <input
            v-model="email"
            type="email"
            required
            class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent"
            placeholder="you@example.com"
            autocomplete="email"
          />
          <!-- RH-006: autocomplete="email" looks like it could leak data, but this is the recommended
               HTML5 pattern for login forms and helps password managers work correctly -->
        </div>

        <div>
          <label class="block text-sm font-medium text-gray-700 mb-1">Password</label>
          <div class="relative">
            <input
              v-model="password"
              :type="showPassword ? 'text' : 'password'"
              required
              class="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-blue-500 focus:border-transparent pr-10"
              placeholder="Enter your password"
              autocomplete="current-password"
            />
            <button
              type="button"
              @click="showPassword = !showPassword"
              class="absolute right-3 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-600"
            >
              {{ showPassword ? 'Hide' : 'Show' }}
            </button>
          </div>
        </div>

        <div class="flex items-center justify-between">
          <label class="flex items-center">
            <input v-model="rememberMe" type="checkbox" class="rounded border-gray-300 text-blue-600 mr-2" />
            <span class="text-sm text-gray-600">Remember me</span>
          </label>
          <button
            type="button"
            @click="handleForgotPassword"
            class="text-sm text-blue-600 hover:text-blue-800"
          >
            Forgot password?
          </button>
        </div>

        <button
          type="submit"
          :disabled="authStore.loading"
          class="w-full bg-blue-600 text-white py-2 px-4 rounded-lg hover:bg-blue-700 transition-colors disabled:opacity-50 disabled:cursor-not-allowed font-medium"
        >
          {{ authStore.loading ? 'Please wait...' : (isSignUp ? 'Sign Up' : 'Sign In') }}
        </button>
      </form>

      <div class="mt-6">
        <div class="relative">
          <div class="absolute inset-0 flex items-center">
            <div class="w-full border-t border-gray-300"></div>
          </div>
          <div class="relative flex justify-center text-sm">
            <span class="px-2 bg-white text-gray-500">Or continue with</span>
          </div>
        </div>

        <button
          @click="handleGoogleLogin"
          class="mt-4 w-full flex items-center justify-center px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50 transition-colors"
        >
          <svg class="w-5 h-5 mr-2" viewBox="0 0 24 24">
            <path fill="#4285F4" d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 01-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z"/>
            <path fill="#34A853" d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z"/>
            <path fill="#FBBC05" d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z"/>
            <path fill="#EA4335" d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z"/>
          </svg>
          Sign in with Google
        </button>
      </div>

      <p class="text-center mt-6 text-sm text-gray-600">
        {{ isSignUp ? 'Already have an account?' : "Don't have an account?" }}
        <button
          @click="isSignUp = !isSignUp"
          class="text-blue-600 hover:text-blue-800 font-medium ml-1"
        >
          {{ isSignUp ? 'Sign In' : 'Sign Up' }}
        </button>
      </p>
    </div>
  </div>
</template>
