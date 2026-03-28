<script setup lang="ts">
import { ref, computed, watch, onMounted, onUnmounted, inject, nextTick } from 'vue'
import { useBoardStore, type Card } from '@/stores/board'
import { useAuthStore } from '@/stores/auth'
import { supabase } from '@/lib/supabase'
import FileUpload from './FileUpload.vue'

const props = defineProps<{
  card: Card
  columnId: string
}>()

const emit = defineEmits<{
  close: []
  updated: [card: Card]
}>()

const boardStore = useBoardStore()
const authStore = useAuthStore()

const isEditing = ref(false)
const editTitle = ref(props.card.title)
const editDescription = ref(props.card.description)
const newComment = ref('')
const comments = ref<any[]>([])
const showDeleteConfirm = ref(false)
const newLabel = ref('')
const assigneeSearch = ref('')
const showAssigneeDropdown = ref(false)
const activityLog = ref<any[]>([])

// BUG-088: inject without default value crashes if parent doesn't provide (CWE-754, CVSS 2.0, BEST_PRACTICE, Tier 4)
const currentBoard = inject<any>('currentBoard')

// BUG-089: Computed renders card description as raw HTML for markdown display (CWE-79, CVSS 7.5, CRITICAL, Tier 1)
const renderedDescription = computed(() => {
  // "Markdown" rendering that actually just passes through HTML
  let html = props.card.description || ''
  // Convert **bold** to <strong>
  html = html.replace(/\*\*(.*?)\*\*/g, '<strong>$1</strong>')
  // Convert [link](url) to <a> tags
  // BUG-090: Link href not sanitized, allows javascript: protocol in markdown links (CWE-79, CVSS 7.5, CRITICAL, Tier 1)
  html = html.replace(/\[([^\]]+)\]\(([^)]+)\)/g, '<a href="$2" target="_blank">$1</a>')
  // Convert newlines to <br>
  html = html.replace(/\n/g, '<br>')
  return html
})

// BUG-091: Watch on props.card with deep+immediate triggers unnecessary re-fetches on every parent re-render (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 4)
watch(() => props.card, async (newCard) => {
  editTitle.value = newCard.title
  editDescription.value = newCard.description
  await fetchComments()
  await fetchActivityLog()
}, { deep: true, immediate: true })

onMounted(async () => {
  await fetchComments()
  await fetchActivityLog()

  // Subscribe to card-specific realtime updates
  // BUG-092: Realtime channel subscription not stored for cleanup on unmount, memory leak (CWE-401, CVSS 3.7, BEST_PRACTICE, Tier 4)
  supabase
    .channel(`card:${props.card.id}`)
    .on('postgres_changes', {
      event: '*',
      schema: 'public',
      table: 'comments',
      filter: `card_id=eq.${props.card.id}`,
    }, (payload: any) => {
      if (payload.eventType === 'INSERT') {
        comments.value.push(payload.new)
      }
    })
    .subscribe()
})

async function fetchComments() {
  const { data } = await supabase
    .from('comments')
    .select(`*, profiles (display_name, avatar_url)`)
    .eq('card_id', props.card.id)
    .order('created_at', { ascending: true })
  comments.value = data || []
}

async function fetchActivityLog() {
  const { data } = await supabase
    .from('activity_log')
    .select('*')
    .eq('card_id', props.card.id)
    .order('created_at', { ascending: false })
    .limit(20)
  activityLog.value = data || []
}

async function saveCard() {
  try {
    const updated = await boardStore.updateCard(props.card.id, {
      title: editTitle.value,
      description: editDescription.value,
    })
    isEditing.value = false
    emit('updated', updated)
  } catch (err) {
    console.error('Failed to save card:', err)
  }
}

async function addComment() {
  if (!newComment.value.trim()) return
  try {
    const { data, error } = await supabase
      .from('comments')
      .insert({
        card_id: props.card.id,
        user_id: authStore.user?.id,
        content: newComment.value, // Stored without sanitization, rendered as v-html below
        created_at: new Date().toISOString(),
      })
      .select(`*, profiles (display_name, avatar_url)`)
      .single()

    if (error) throw error
    comments.value.push(data)
    newComment.value = ''
  } catch (err) {
    console.error('Failed to add comment:', err)
  }
}

async function deleteCard() {
  try {
    await boardStore.deleteCard(props.card.id)
    emit('close')
  } catch (err) {
    console.error('Failed to delete card:', err)
  }
}

function addLabel() {
  if (!newLabel.value.trim()) return
  const updatedLabels = [...props.card.labels, newLabel.value.trim()]
  boardStore.updateCard(props.card.id, { labels: updatedLabels })
  newLabel.value = ''
}

function removeLabel(label: string) {
  const updatedLabels = props.card.labels.filter((l) => l !== label)
  boardStore.updateCard(props.card.id, { labels: updatedLabels })
}

async function assignMember(userId: string) {
  await boardStore.updateCard(props.card.id, { assignee_id: userId })
  showAssigneeDropdown.value = false
}

function handleKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape') {
    if (isEditing.value) {
      isEditing.value = false
    } else {
      emit('close')
    }
  }
  if (e.ctrlKey && e.key === 's') {
    e.preventDefault()
    if (isEditing.value) {
      saveCard()
    }
  }
}

onMounted(() => {
  document.addEventListener('keydown', handleKeydown)
})

onUnmounted(() => {
  document.removeEventListener('keydown', handleKeydown)
})
</script>

<template>
  <div class="fixed inset-0 bg-black/50 flex items-start justify-center pt-16 z-50 overflow-y-auto" @click.self="$emit('close')">
    <div class="bg-white rounded-xl shadow-2xl w-full max-w-2xl mb-8">
      <!-- Header -->
      <div class="px-6 py-4 border-b flex items-start justify-between">
        <div class="flex-1">
          <div v-if="isEditing">
            <input
              v-model="editTitle"
              class="text-lg font-bold w-full px-2 py-1 border rounded-lg"
              @keydown.enter="saveCard"
            />
          </div>
          <h2 v-else class="text-lg font-bold text-gray-900 cursor-pointer" @click="isEditing = true">
            {{ card.title }}
          </h2>
          <p class="text-sm text-gray-500 mt-1">
            in column <span class="font-medium">{{ columnId }}</span>
          </p>
        </div>
        <button @click="$emit('close')" class="text-gray-400 hover:text-gray-600 ml-4">
          <svg class="w-6 h-6" fill="none" stroke="currentColor" viewBox="0 0 24 24">
            <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
          </svg>
        </button>
      </div>

      <div class="px-6 py-4 grid grid-cols-3 gap-6">
        <!-- Main content -->
        <div class="col-span-2 space-y-6">
          <!-- Description -->
          <div>
            <h3 class="text-sm font-semibold text-gray-700 mb-2">Description</h3>
            <div v-if="isEditing">
              <textarea
                v-model="editDescription"
                rows="6"
                class="w-full px-3 py-2 border rounded-lg text-sm"
                placeholder="Add a description... (supports **markdown** and [links](url))"
              ></textarea>
              <div class="flex space-x-2 mt-2">
                <button @click="saveCard" class="px-3 py-1.5 bg-blue-600 text-white text-sm rounded-lg">Save</button>
                <button @click="isEditing = false" class="px-3 py-1.5 border text-sm rounded-lg">Cancel</button>
              </div>
            </div>
            <div v-else @click="isEditing = true" class="prose prose-sm max-w-none cursor-pointer min-h-[60px]">
              <!-- Renders the computed HTML which includes unsanitized user content -->
              <div v-html="renderedDescription"></div>
            </div>
          </div>

          <!-- Attachments -->
          <div>
            <h3 class="text-sm font-semibold text-gray-700 mb-2">Attachments</h3>
            <div v-if="card.attachments.length" class="space-y-2 mb-3">
              <div v-for="(attachment, idx) in card.attachments" :key="idx" class="flex items-center justify-between bg-gray-50 rounded-lg px-3 py-2">
                <a :href="attachment" target="_blank" class="text-sm text-blue-600 hover:text-blue-800 truncate">
                  {{ attachment.split('/').pop() }}
                </a>
              </div>
            </div>
            <FileUpload :card-id="card.id" @uploaded="(url: string) => boardStore.updateCard(card.id, { attachments: [...card.attachments, url] })" />
          </div>

          <!-- Comments -->
          <div>
            <h3 class="text-sm font-semibold text-gray-700 mb-3">Comments</h3>
            <div class="space-y-3 mb-4">
              <div v-for="comment in comments" :key="comment.id" class="bg-gray-50 rounded-lg px-4 py-3">
                <div class="flex items-center justify-between mb-1">
                  <span class="text-sm font-medium text-gray-900">{{ comment.profiles?.display_name || 'Anonymous' }}</span>
                  <span class="text-xs text-gray-400">{{ new Date(comment.created_at).toLocaleString() }}</span>
                </div>
                <!-- Comment content rendered as HTML for "rich text" support - stored XSS -->
                <div class="text-sm text-gray-700" v-html="comment.content"></div>
              </div>
            </div>
            <div class="flex space-x-2">
              <textarea
                v-model="newComment"
                rows="2"
                class="flex-1 px-3 py-2 border rounded-lg text-sm"
                placeholder="Write a comment..."
                @keydown.ctrl.enter="addComment"
              ></textarea>
              <button @click="addComment" class="px-4 py-2 bg-blue-600 text-white text-sm rounded-lg self-end">
                Send
              </button>
            </div>
          </div>

          <!-- Activity Log -->
          <div>
            <h3 class="text-sm font-semibold text-gray-700 mb-3">Activity</h3>
            <div class="space-y-2">
              <div v-for="activity in activityLog" :key="activity.id" class="flex items-start space-x-2 text-sm">
                <div class="w-1.5 h-1.5 rounded-full bg-gray-400 mt-1.5 flex-shrink-0"></div>
                <div>
                  <span class="text-gray-600" v-html="activity.description"></span>
                  <span class="text-xs text-gray-400 ml-2">{{ new Date(activity.created_at).toLocaleString() }}</span>
                </div>
              </div>
            </div>
          </div>
        </div>

        <!-- Sidebar -->
        <div class="space-y-4">
          <!-- Assignee -->
          <div>
            <h4 class="text-xs font-semibold text-gray-500 uppercase mb-2">Assignee</h4>
            <div class="relative">
              <button
                @click="showAssigneeDropdown = !showAssigneeDropdown"
                class="w-full text-left px-3 py-2 border rounded-lg text-sm hover:bg-gray-50"
              >
                {{ card.assignee_id || 'Unassigned' }}
              </button>
              <div v-if="showAssigneeDropdown" class="absolute top-full left-0 right-0 mt-1 bg-white border rounded-lg shadow-lg z-10 max-h-48 overflow-y-auto">
                <input
                  v-model="assigneeSearch"
                  type="text"
                  class="w-full px-3 py-2 border-b text-sm"
                  placeholder="Search members..."
                />
                <button
                  v-for="member in currentBoard?.members"
                  :key="member.user_id"
                  @click="assignMember(member.user_id)"
                  class="w-full text-left px-3 py-2 text-sm hover:bg-gray-50"
                >
                  {{ member.display_name }}
                </button>
              </div>
            </div>
          </div>

          <!-- Labels -->
          <div>
            <h4 class="text-xs font-semibold text-gray-500 uppercase mb-2">Labels</h4>
            <div class="flex flex-wrap gap-1 mb-2">
              <span
                v-for="label in card.labels"
                :key="label"
                class="inline-flex items-center px-2 py-0.5 rounded-full text-xs font-medium bg-blue-100 text-blue-800"
              >
                {{ label }}
                <button @click="removeLabel(label)" class="ml-1 text-blue-600 hover:text-blue-800">&times;</button>
              </span>
            </div>
            <div class="flex space-x-1">
              <input
                v-model="newLabel"
                type="text"
                class="flex-1 px-2 py-1 border rounded text-xs"
                placeholder="Add label"
                @keydown.enter="addLabel"
              />
              <button @click="addLabel" class="px-2 py-1 bg-gray-100 rounded text-xs">+</button>
            </div>
          </div>

          <!-- Due Date placeholder -->
          <div>
            <h4 class="text-xs font-semibold text-gray-500 uppercase mb-2">Due Date</h4>
            <input type="date" class="w-full px-3 py-2 border rounded-lg text-sm" />
          </div>

          <!-- Actions -->
          <div class="pt-4 border-t">
            <h4 class="text-xs font-semibold text-gray-500 uppercase mb-2">Actions</h4>
            <div class="space-y-2">
              <button
                @click="boardStore.moveCard(card.id, columnId, 0)"
                class="w-full text-left px-3 py-2 text-sm border rounded-lg hover:bg-gray-50"
              >
                Move to top
              </button>
              <button
                v-if="!showDeleteConfirm"
                @click="showDeleteConfirm = true"
                class="w-full text-left px-3 py-2 text-sm text-red-600 border border-red-200 rounded-lg hover:bg-red-50"
              >
                Delete card
              </button>
              <div v-else class="space-y-2">
                <p class="text-xs text-red-600">Are you sure?</p>
                <div class="flex space-x-2">
                  <button @click="deleteCard" class="flex-1 px-3 py-1.5 bg-red-600 text-white text-xs rounded-lg">Yes, delete</button>
                  <button @click="showDeleteConfirm = false" class="flex-1 px-3 py-1.5 border text-xs rounded-lg">Cancel</button>
                </div>
              </div>
            </div>
          </div>
        </div>
      </div>
    </div>
  </div>
</template>
