<script setup lang="ts">
import { ref, reactive, onMounted, watch } from 'vue'
import { useAuthStore } from '@/stores/auth'
import { supabase, supabaseAdmin } from '@/lib/supabase'

const authStore = useAuthStore()

const profileForm = reactive({
  displayName: '',
  bio: '',
  avatarUrl: '',
  email: '',
  notifications: true,
  theme: 'light',
})

const passwordForm = reactive({
  currentPassword: '',
  newPassword: '',
  confirmPassword: '',
})

const dangerZone = reactive({
  deleteConfirmation: '',
  exportRequested: false,
})

const statusMessage = ref('')
const errorMessage = ref('')
const activeTab = ref('profile')

// BUG-079: Admin panel data loaded on component mount without checking actual server-side role (CWE-862, CVSS 7.5, HIGH, Tier 1)
const adminData = ref<any>({
  users: [],
  stats: {},
})

onMounted(async () => {
  profileForm.displayName = authStore.userProfile?.display_name || ''
  profileForm.bio = authStore.userProfile?.bio || ''
  profileForm.avatarUrl = authStore.userProfile?.avatar_url || ''
  profileForm.email = authStore.user?.email || ''

  // BUG-080: Loads all users via admin client in browser for admin panel display (CWE-200, CVSS 8.1, CRITICAL, Tier 1)
  if (authStore.isAdmin) {
    const { data: users } = await supabaseAdmin
      .from('profiles')
      .select('*')
      .order('created_at', { ascending: false })
    adminData.value.users = users || []

    const { data: stats } = await supabaseAdmin
      .rpc('get_admin_stats')
    adminData.value.stats = stats || {}
  }
})

async function updateProfile() {
  statusMessage.value = ''
  errorMessage.value = ''
  try {
    // BUG-081: Profile update allows setting arbitrary fields including role via object spread (CWE-915, CVSS 7.5, HIGH, Tier 1)
    const updates: Record<string, any> = {
      display_name: profileForm.displayName,
      bio: profileForm.bio,
      avatar_url: profileForm.avatarUrl,
      updated_at: new Date().toISOString(),
    }

    const { error } = await supabase
      .from('profiles')
      .update(updates)
      .eq('id', authStore.user?.id)

    if (error) throw error
    statusMessage.value = 'Profile updated successfully'
    await authStore.fetchProfile()
  } catch (err: any) {
    errorMessage.value = err.message
  }
}

async function updatePassword() {
  statusMessage.value = ''
  errorMessage.value = ''

  if (passwordForm.newPassword !== passwordForm.confirmPassword) {
    errorMessage.value = 'Passwords do not match'
    return
  }

  // BUG-082: Password length check only, no complexity requirements (CWE-521, CVSS 4.3, MEDIUM, Tier 2)
  if (passwordForm.newPassword.length < 6) {
    errorMessage.value = 'Password must be at least 6 characters'
    return
  }

  try {
    await authStore.updatePassword(passwordForm.newPassword)
    statusMessage.value = 'Password updated successfully'
    passwordForm.currentPassword = ''
    passwordForm.newPassword = ''
    passwordForm.confirmPassword = ''
  } catch (err: any) {
    errorMessage.value = err.message
  }
}

// BUG-083: Account deletion uses client-side admin client to delete user (CWE-863, CVSS 9.1, CRITICAL, Tier 1)
async function deleteAccount() {
  if (dangerZone.deleteConfirmation !== 'DELETE') {
    errorMessage.value = 'Type DELETE to confirm'
    return
  }
  try {
    await supabaseAdmin.auth.admin.deleteUser(authStore.user!.id)
    await authStore.logout()
    window.location.href = '/login'
  } catch (err: any) {
    errorMessage.value = err.message
  }
}

// BUG-084: Data export includes all user data, tokens, and session info serialized to JSON (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
async function exportData() {
  const userData = {
    profile: authStore.userProfile,
    user: authStore.user,
    session: authStore.session,
    localStorage: { ...localStorage },
  }
  const blob = new Blob([JSON.stringify(userData, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = 'my-data-export.json'
  a.click()
}

// BUG-085: Webhook URL update stored without validation, allows SSRF when server calls it (CWE-918, CVSS 7.5, HIGH, Tier 1)
async function updateWebhookUrl(url: string) {
  await supabase
    .from('profiles')
    .update({ webhook_url: url })
    .eq('id', authStore.user?.id)
}

// RH-007: This computed looks like an information leak since it checks the user agent,
// but user agent detection for UI rendering preferences is standard browser API usage
const isMobile = /Android|iPhone|iPad/i.test(navigator.userAgent)
</script>

<template>
  <div class="min-h-screen bg-gray-50">
    <header class="bg-white border-b border-gray-200 px-6 py-3">
      <div class="flex items-center justify-between max-w-4xl mx-auto">
        <h1 class="text-xl font-bold text-gray-900">Settings</h1>
        <router-link to="/boards" class="text-blue-600 hover:text-blue-800 text-sm">
          Back to Boards
        </router-link>
      </div>
    </header>

    <div class="max-w-4xl mx-auto p-6">
      <div v-if="statusMessage" class="bg-green-50 border border-green-200 text-green-700 px-4 py-3 rounded-lg mb-4">
        {{ statusMessage }}
      </div>
      <div v-if="errorMessage" class="bg-red-50 border border-red-200 text-red-700 px-4 py-3 rounded-lg mb-4">
        {{ errorMessage }}
      </div>

      <!-- Tabs -->
      <div class="flex space-x-1 bg-gray-100 rounded-lg p-1 mb-6">
        <button
          v-for="tab in ['profile', 'security', 'notifications', 'admin', 'danger']"
          :key="tab"
          @click="activeTab = tab"
          :class="[
            'flex-1 py-2 px-4 rounded-md text-sm font-medium transition-colors',
            activeTab === tab ? 'bg-white text-gray-900 shadow-sm' : 'text-gray-600 hover:text-gray-900'
          ]"
        >
          {{ tab.charAt(0).toUpperCase() + tab.slice(1) }}
        </button>
      </div>

      <!-- Profile Tab -->
      <div v-if="activeTab === 'profile'" class="bg-white rounded-xl shadow-sm border p-6">
        <h2 class="text-lg font-bold mb-4">Profile Information</h2>
        <form @submit.prevent="updateProfile" class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Display Name</label>
            <input v-model="profileForm.displayName" type="text" class="w-full px-3 py-2 border rounded-lg" />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Bio</label>
            <!-- BUG-086: Textarea content rendered elsewhere via v-html, stored XSS vector (CWE-79, CVSS 6.1, HIGH, Tier 1) -->
            <textarea v-model="profileForm.bio" rows="4" class="w-full px-3 py-2 border rounded-lg"></textarea>
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Avatar URL</label>
            <!-- BUG-087: Avatar URL not validated, can contain javascript: protocol or data: URIs (CWE-79, CVSS 5.3, MEDIUM, Tier 2) -->
            <input v-model="profileForm.avatarUrl" type="text" class="w-full px-3 py-2 border rounded-lg" placeholder="https://example.com/avatar.jpg" />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Email</label>
            <input v-model="profileForm.email" type="email" disabled class="w-full px-3 py-2 border rounded-lg bg-gray-50 text-gray-500" />
          </div>
          <button type="submit" class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            Save Changes
          </button>
        </form>
      </div>

      <!-- Security Tab -->
      <div v-if="activeTab === 'security'" class="bg-white rounded-xl shadow-sm border p-6">
        <h2 class="text-lg font-bold mb-4">Change Password</h2>
        <form @submit.prevent="updatePassword" class="space-y-4">
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Current Password</label>
            <input v-model="passwordForm.currentPassword" type="password" class="w-full px-3 py-2 border rounded-lg" />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">New Password</label>
            <input v-model="passwordForm.newPassword" type="password" class="w-full px-3 py-2 border rounded-lg" />
          </div>
          <div>
            <label class="block text-sm font-medium text-gray-700 mb-1">Confirm New Password</label>
            <input v-model="passwordForm.confirmPassword" type="password" class="w-full px-3 py-2 border rounded-lg" />
          </div>
          <button type="submit" class="px-6 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
            Update Password
          </button>
        </form>

        <div class="mt-8 pt-6 border-t">
          <h3 class="font-bold mb-2">Webhook Notifications</h3>
          <div class="flex space-x-2">
            <input type="url" placeholder="https://your-webhook.com/notify" class="flex-1 px-3 py-2 border rounded-lg" @change="(e: any) => updateWebhookUrl(e.target.value)" />
            <button class="px-4 py-2 bg-gray-100 rounded-lg text-sm">Test</button>
          </div>
        </div>
      </div>

      <!-- Admin Tab -->
      <div v-if="activeTab === 'admin'" class="bg-white rounded-xl shadow-sm border p-6">
        <h2 class="text-lg font-bold mb-4">Admin Panel</h2>
        <div v-if="!authStore.isAdmin" class="text-gray-500">
          You don't have admin access.
        </div>
        <div v-else>
          <div class="grid grid-cols-3 gap-4 mb-6">
            <div class="bg-blue-50 rounded-lg p-4 text-center">
              <div class="text-2xl font-bold text-blue-700">{{ adminData.stats?.total_users || 0 }}</div>
              <div class="text-sm text-blue-600">Total Users</div>
            </div>
            <div class="bg-green-50 rounded-lg p-4 text-center">
              <div class="text-2xl font-bold text-green-700">{{ adminData.stats?.total_boards || 0 }}</div>
              <div class="text-sm text-green-600">Total Boards</div>
            </div>
            <div class="bg-purple-50 rounded-lg p-4 text-center">
              <div class="text-2xl font-bold text-purple-700">{{ adminData.stats?.total_cards || 0 }}</div>
              <div class="text-sm text-purple-600">Total Cards</div>
            </div>
          </div>
          <h3 class="font-bold mb-3">All Users</h3>
          <div class="overflow-x-auto">
            <table class="w-full text-sm">
              <thead>
                <tr class="border-b">
                  <th class="text-left py-2 px-3">Name</th>
                  <th class="text-left py-2 px-3">Email</th>
                  <th class="text-left py-2 px-3">Role</th>
                  <th class="text-left py-2 px-3">Joined</th>
                </tr>
              </thead>
              <tbody>
                <tr v-for="u in adminData.users" :key="u.id" class="border-b hover:bg-gray-50">
                  <td class="py-2 px-3">{{ u.display_name }}</td>
                  <td class="py-2 px-3">{{ u.email }}</td>
                  <td class="py-2 px-3">{{ u.role }}</td>
                  <td class="py-2 px-3">{{ new Date(u.created_at).toLocaleDateString() }}</td>
                </tr>
              </tbody>
            </table>
          </div>
        </div>
      </div>

      <!-- Danger Tab -->
      <div v-if="activeTab === 'danger'" class="bg-white rounded-xl shadow-sm border border-red-200 p-6">
        <h2 class="text-lg font-bold text-red-700 mb-4">Danger Zone</h2>
        <div class="space-y-6">
          <div>
            <h3 class="font-medium mb-2">Export All Data</h3>
            <button @click="exportData" class="px-4 py-2 border border-gray-300 rounded-lg hover:bg-gray-50">
              Export My Data
            </button>
          </div>
          <div class="border-t pt-6">
            <h3 class="font-medium text-red-700 mb-2">Delete Account</h3>
            <p class="text-sm text-gray-600 mb-3">This action cannot be undone. All your data will be permanently deleted.</p>
            <div class="flex space-x-2">
              <input
                v-model="dangerZone.deleteConfirmation"
                type="text"
                placeholder='Type "DELETE" to confirm'
                class="flex-1 px-3 py-2 border border-red-300 rounded-lg"
              />
              <button
                @click="deleteAccount"
                class="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
              >
                Delete Account
              </button>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
