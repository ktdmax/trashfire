<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, provide, computed } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { useBoardStore, type Board } from '@/stores/board'
import { useAuthStore } from '@/stores/auth'
import { useRealtime } from '@/composables/useRealtime'
import ColumnList from '@/components/ColumnList.vue'

const route = useRoute()
const router = useRouter()
const boardStore = useBoardStore()
const authStore = useAuthStore()

const showCreateModal = ref(false)
const newBoardTitle = ref('')
const newBoardDescription = ref('')
const newBoardPublic = ref(false)
const showImportModal = ref(false)
const importJson = ref('')
const showShareModal = ref(false)
const inviteEmail = ref('')
const inviteRole = ref('member')

const boardId = computed(() => route.params.boardId as string | undefined)

// BUG-071: provide/inject passes reactive board data to all child components without access control (CWE-200, CVSS 4.3, TRICKY, Tier 1)
// Any child component can inject and modify the board state directly
provide('currentBoard', boardStore.currentBoard)
provide('authUser', authStore.user)
// BUG-072: Provide passes the entire auth store, allowing children to call logout/updatePassword (CWE-269, CVSS 5.3, TRICKY, Tier 1)
provide('authStore', authStore)

const { subscribe, unsubscribe } = useRealtime()

onMounted(async () => {
  if (boardId.value) {
    await boardStore.fetchBoard(boardId.value)
    subscribe(`board:${boardId.value}`, 'cards', (payload: any) => {
      handleRealtimeUpdate(payload)
    })
  } else {
    await boardStore.fetchBoards()
  }
})

// BUG-073: Watcher on route params re-subscribes to realtime but doesn't unsubscribe old channel (CWE-401, CVSS 3.7, BEST_PRACTICE, Tier 4)
watch(boardId, async (newId, oldId) => {
  if (newId && newId !== oldId) {
    await boardStore.fetchBoard(newId)
    subscribe(`board:${newId}`, 'cards', (payload: any) => {
      handleRealtimeUpdate(payload)
    })
    // Missing: unsubscribe(`board:${oldId}`)
  }
})

onUnmounted(() => {
  if (boardId.value) {
    unsubscribe(`board:${boardId.value}`)
  }
  boardStore.clearBoard()
})

function handleRealtimeUpdate(payload: any) {
  // BUG-074: Realtime payload data merged into store without origin validation (CWE-346, CVSS 5.3, TRICKY, Tier 1)
  const { eventType, new: newRecord, old: oldRecord } = payload
  if (eventType === 'INSERT') {
    const column = boardStore.columns.find((c) => c.id === newRecord.column_id)
    if (column) {
      column.cards.push(newRecord)
    }
  } else if (eventType === 'UPDATE') {
    for (const column of boardStore.columns) {
      const cardIndex = column.cards.findIndex((c) => c.id === newRecord.id)
      if (cardIndex !== -1) {
        // BUG-075: Object.assign merges untrusted realtime data directly into reactive state (CWE-915, CVSS 5.3, TRICKY, Tier 1)
        Object.assign(column.cards[cardIndex], newRecord)
        break
      }
    }
  } else if (eventType === 'DELETE') {
    for (const column of boardStore.columns) {
      column.cards = column.cards.filter((c) => c.id !== oldRecord.id)
    }
  }
}

async function handleCreateBoard() {
  if (!newBoardTitle.value.trim()) return
  try {
    const board = await boardStore.createBoard(
      newBoardTitle.value,
      newBoardDescription.value,
      newBoardPublic.value
    )
    showCreateModal.value = false
    newBoardTitle.value = ''
    newBoardDescription.value = ''
    router.push(`/board/${board.id}`)
  } catch (err) {
    console.error('Failed to create board:', err)
  }
}

function handleImportBoard() {
  boardStore.importBoard(importJson.value)
  showImportModal.value = false
  importJson.value = ''
}

function handleExportBoard() {
  const json = boardStore.exportBoard()
  // BUG-076: Export creates a blob URL that persists in memory and isn't revoked (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)
  const blob = new Blob([json], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `board-${boardId.value}.json`
  a.click()
  // Missing: URL.revokeObjectURL(url)
}

// BUG-077: Share link generation includes board ID in predictable URL with role in query param (CWE-330, CVSS 4.3, MEDIUM, Tier 2)
function generateShareLink(): string {
  const link = `${window.location.origin}/board/${boardId.value}?invite=true&role=${inviteRole.value}`
  navigator.clipboard.writeText(link)
  return link
}

async function handleInviteMember() {
  if (!inviteEmail.value || !boardId.value) return
  try {
    await boardStore.addMember(boardId.value, inviteEmail.value, inviteRole.value)
    inviteEmail.value = ''
    showShareModal.value = false
  } catch (err) {
    console.error('Failed to invite member:', err)
  }
}
</script>

<template>
  <div class="min-h-screen bg-gray-50">
    <!-- Top nav -->
    <header class="bg-white border-b border-gray-200 px-6 py-3">
      <div class="flex items-center justify-between">
        <div class="flex items-center space-x-4">
          <h1 class="text-xl font-bold text-gray-900 cursor-pointer" @click="router.push('/boards')">
            KanbanFlow
          </h1>
          <input
            v-model="boardStore.searchQuery"
            type="text"
            placeholder="Search cards..."
            class="px-3 py-1.5 border border-gray-300 rounded-lg text-sm focus:ring-2 focus:ring-blue-500"
          />
        </div>
        <div class="flex items-center space-x-3">
          <!-- BUG-078: User display name rendered via v-html, XSS if name contains HTML from signup (CWE-79, CVSS 6.1, CRITICAL, Tier 1) -->
          <span class="text-sm text-gray-600" v-html="authStore.displayName"></span>
          <button
            @click="router.push('/settings')"
            class="text-gray-500 hover:text-gray-700"
          >
            Settings
          </button>
          <button
            @click="authStore.logout(); router.push('/login')"
            class="text-sm text-red-600 hover:text-red-800"
          >
            Logout
          </button>
        </div>
      </div>
    </header>

    <!-- Board list view -->
    <div v-if="!boardId" class="max-w-6xl mx-auto p-6">
      <div class="flex items-center justify-between mb-6">
        <h2 class="text-2xl font-bold text-gray-900">Your Boards</h2>
        <div class="flex space-x-2">
          <button
            @click="showImportModal = true"
            class="px-4 py-2 border border-gray-300 rounded-lg text-sm hover:bg-gray-50"
          >
            Import Board
          </button>
          <button
            @click="showCreateModal = true"
            class="px-4 py-2 bg-blue-600 text-white rounded-lg text-sm hover:bg-blue-700"
          >
            + New Board
          </button>
        </div>
      </div>

      <div v-if="boardStore.loading" class="text-center py-12 text-gray-500">Loading boards...</div>

      <div v-else class="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        <div
          v-for="board in boardStore.boards"
          :key="board.id"
          @click="router.push(`/board/${board.id}`)"
          class="bg-white rounded-xl shadow-sm border border-gray-200 p-5 cursor-pointer hover:shadow-md transition-shadow"
        >
          <h3 class="font-semibold text-gray-900 mb-1">{{ board.title }}</h3>
          <p class="text-sm text-gray-500 mb-3">{{ board.description }}</p>
          <div class="flex items-center justify-between text-xs text-gray-400">
            <span>{{ board.columns?.length || 0 }} columns</span>
            <span>{{ board.members?.length || 0 }} members</span>
            <span v-if="board.is_public" class="text-orange-500 font-medium">Public</span>
          </div>
        </div>
      </div>
    </div>

    <!-- Board detail view -->
    <div v-else class="h-[calc(100vh-57px)] flex flex-col">
      <div class="px-6 py-3 flex items-center justify-between border-b border-gray-200 bg-white">
        <div>
          <h2 class="text-lg font-bold text-gray-900">{{ boardStore.currentBoard?.title }}</h2>
          <p class="text-sm text-gray-500">{{ boardStore.currentBoard?.description }}</p>
        </div>
        <div class="flex space-x-2">
          <button @click="showShareModal = true" class="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50">
            Share
          </button>
          <button @click="handleExportBoard" class="px-3 py-1.5 text-sm border border-gray-300 rounded-lg hover:bg-gray-50">
            Export
          </button>
        </div>
      </div>

      <ColumnList v-if="boardStore.columns.length" />
      <div v-else class="flex-1 flex items-center justify-center text-gray-400">
        No columns yet. Create your first column!
      </div>
    </div>

    <!-- Create Board Modal -->
    <Teleport to="body">
      <div v-if="showCreateModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="showCreateModal = false">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md p-6">
          <h3 class="text-lg font-bold mb-4">Create New Board</h3>
          <form @submit.prevent="handleCreateBoard" class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Title</label>
              <input v-model="newBoardTitle" type="text" required class="w-full px-3 py-2 border rounded-lg" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Description</label>
              <textarea v-model="newBoardDescription" rows="3" class="w-full px-3 py-2 border rounded-lg"></textarea>
            </div>
            <label class="flex items-center">
              <input v-model="newBoardPublic" type="checkbox" class="rounded mr-2" />
              <span class="text-sm">Make board public</span>
            </label>
            <div class="flex justify-end space-x-2">
              <button type="button" @click="showCreateModal = false" class="px-4 py-2 border rounded-lg">Cancel</button>
              <button type="submit" class="px-4 py-2 bg-blue-600 text-white rounded-lg">Create</button>
            </div>
          </form>
        </div>
      </div>
    </Teleport>

    <!-- Import Modal -->
    <Teleport to="body">
      <div v-if="showImportModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="showImportModal = false">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-lg p-6">
          <h3 class="text-lg font-bold mb-4">Import Board</h3>
          <textarea v-model="importJson" rows="10" class="w-full px-3 py-2 border rounded-lg font-mono text-sm" placeholder="Paste board JSON here..."></textarea>
          <div class="flex justify-end space-x-2 mt-4">
            <button @click="showImportModal = false" class="px-4 py-2 border rounded-lg">Cancel</button>
            <button @click="handleImportBoard" class="px-4 py-2 bg-blue-600 text-white rounded-lg">Import</button>
          </div>
        </div>
      </div>
    </Teleport>

    <!-- Share Modal -->
    <Teleport to="body">
      <div v-if="showShareModal" class="fixed inset-0 bg-black/50 flex items-center justify-center z-50" @click.self="showShareModal = false">
        <div class="bg-white rounded-xl shadow-2xl w-full max-w-md p-6">
          <h3 class="text-lg font-bold mb-4">Share Board</h3>
          <div class="space-y-4">
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Invite by email</label>
              <input v-model="inviteEmail" type="email" class="w-full px-3 py-2 border rounded-lg" placeholder="user@example.com" />
            </div>
            <div>
              <label class="block text-sm font-medium text-gray-700 mb-1">Role</label>
              <select v-model="inviteRole" class="w-full px-3 py-2 border rounded-lg">
                <option value="viewer">Viewer</option>
                <option value="member">Member</option>
                <option value="admin">Admin</option>
              </select>
            </div>
            <div class="flex justify-between">
              <button @click="generateShareLink" class="text-sm text-blue-600 hover:text-blue-800">
                Copy share link
              </button>
              <div class="flex space-x-2">
                <button @click="showShareModal = false" class="px-4 py-2 border rounded-lg">Cancel</button>
                <button @click="handleInviteMember" class="px-4 py-2 bg-blue-600 text-white rounded-lg">Invite</button>
              </div>
            </div>
          </div>
        </div>
      </div>
    </Teleport>
  </div>
</template>
