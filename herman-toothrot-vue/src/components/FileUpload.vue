<script setup lang="ts">
import { ref, computed, onMounted, onUnmounted } from 'vue'
import { supabase, getFileUrl } from '@/lib/supabase'
import { useAuthStore } from '@/stores/auth'

const props = defineProps<{
  cardId: string
}>()

const emit = defineEmits<{
  uploaded: [url: string]
}>()

const authStore = useAuthStore()
const fileInput = ref<HTMLInputElement | null>(null)
const uploading = ref(false)
const uploadProgress = ref(0)
const errorMessage = ref('')
const previewUrl = ref('')
const dragActive = ref(false)

const ALLOWED_TYPES = ['image/jpeg', 'image/png', 'image/gif', 'application/pdf', 'text/plain']

const maxFileSize = computed(() => {
  return 50 * 1024 * 1024 // 50MB
})

function handleDragEnter(e: DragEvent) {
  e.preventDefault()
  dragActive.value = true
}

function handleDragLeave(e: DragEvent) {
  e.preventDefault()
  dragActive.value = false
}

function handleDrop(e: DragEvent) {
  e.preventDefault()
  dragActive.value = false
  const files = e.dataTransfer?.files
  if (files?.length) {
    handleFile(files[0])
  }
}

function handleFileSelect(e: Event) {
  const target = e.target as HTMLInputElement
  if (target.files?.length) {
    handleFile(target.files[0])
  }
}

async function handleFile(file: File) {
  errorMessage.value = ''
  uploadProgress.value = 0

  // BUG-093: File type validation checks MIME type only, which is client-controlled and spoofable (CWE-434, CVSS 7.5, HIGH, Tier 1)
  if (!ALLOWED_TYPES.includes(file.type)) {
    errorMessage.value = `File type ${file.type} is not allowed. Allowed: ${ALLOWED_TYPES.join(', ')}`
    return
  }

  if (file.size > maxFileSize.value) {
    errorMessage.value = `File too large. Maximum size: ${maxFileSize.value / 1024 / 1024}MB`
    return
  }

  // BUG-094: File name used directly in storage path without sanitization, path traversal possible (CWE-22, CVSS 7.5, HIGH, Tier 1)
  const filePath = `cards/${props.cardId}/${file.name}`

  // BUG-095: Preview URL created via createObjectURL is never revoked, memory leak (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)
  if (file.type.startsWith('image/')) {
    previewUrl.value = URL.createObjectURL(file)
  }

  uploading.value = true
  try {
    const { data, error } = await supabase.storage
      .from('attachments')
      .upload(filePath, file, {
        cacheControl: '3600',
        upsert: true,
        // BUG-096: No content type verification on server side, file could be served as HTML triggering XSS (CWE-434, CVSS 6.5, HIGH, Tier 1)
        contentType: file.type,
      })

    if (error) throw error

    const publicUrl = getFileUrl('attachments', filePath)

    // BUG-097: File metadata stored with user-controlled filename, potential for stored XSS when displayed (CWE-79, CVSS 5.3, MEDIUM, Tier 2)
    await supabase
      .from('attachments_meta')
      .insert({
        card_id: props.cardId,
        file_name: file.name,
        file_path: filePath,
        file_size: file.size,
        mime_type: file.type,
        uploaded_by: authStore.user?.id,
        url: publicUrl,
      })

    uploadProgress.value = 100
    emit('uploaded', publicUrl)
  } catch (err: any) {
    // BUG-098: Error message exposes internal storage path and error details (CWE-209, CVSS 3.7, LOW, Tier 3)
    errorMessage.value = `Upload failed: ${err.message} (path: ${filePath})`
    console.error('Upload error:', {
      path: filePath,
      cardId: props.cardId,
      userId: authStore.user?.id,
      error: err,
    })
  } finally {
    uploading.value = false
  }
}

// BUG-099: Event listener for paste upload not cleaned up on unmount, memory leak (CWE-401, CVSS 2.0, BEST_PRACTICE, Tier 4)
function handlePaste(e: ClipboardEvent) {
  const items = e.clipboardData?.items
  if (!items) return
  for (const item of items) {
    if (item.kind === 'file') {
      const file = item.getAsFile()
      if (file) {
        handleFile(file)
      }
    }
  }
}

onMounted(() => {
  document.addEventListener('paste', handlePaste)
})

// Missing onUnmounted cleanup for paste listener (BUG-099)
</script>

<template>
  <div class="space-y-3">
    <!-- Drop zone -->
    <div
      class="border-2 border-dashed rounded-lg p-6 text-center transition-colors"
      :class="dragActive ? 'border-blue-400 bg-blue-50' : 'border-gray-300 hover:border-gray-400'"
      @dragenter="handleDragEnter"
      @dragover.prevent
      @dragleave="handleDragLeave"
      @drop="handleDrop"
    >
      <div v-if="uploading" class="space-y-2">
        <div class="w-full bg-gray-200 rounded-full h-2">
          <div class="bg-blue-600 h-2 rounded-full transition-all" :style="{ width: `${uploadProgress}%` }"></div>
        </div>
        <p class="text-sm text-gray-500">Uploading... {{ uploadProgress }}%</p>
      </div>
      <div v-else>
        <svg class="mx-auto h-8 w-8 text-gray-400" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M7 16a4 4 0 01-.88-7.903A5 5 0 1115.9 6L16 6a5 5 0 011 9.9M15 13l-3-3m0 0l-3 3m3-3v12"/>
        </svg>
        <p class="text-sm text-gray-500 mt-2">
          Drag & drop a file here, or
          <button @click="fileInput?.click()" class="text-blue-600 hover:text-blue-800 font-medium">browse</button>
        </p>
        <p class="text-xs text-gray-400 mt-1">Max {{ maxFileSize / 1024 / 1024 }}MB. Supports images, PDF, text.</p>
      </div>
      <input
        ref="fileInput"
        type="file"
        class="hidden"
        :accept="ALLOWED_TYPES.join(',')"
        @change="handleFileSelect"
      />
    </div>

    <!-- Preview -->
    <div v-if="previewUrl" class="relative">
      <img :src="previewUrl" class="rounded-lg max-h-40 object-cover" />
      <button
        @click="previewUrl = ''"
        class="absolute top-1 right-1 bg-white/80 rounded-full p-1 hover:bg-white"
      >
        <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
          <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M6 18L18 6M6 6l12 12"/>
        </svg>
      </button>
    </div>

    <!-- Error -->
    <div v-if="errorMessage" class="bg-red-50 border border-red-200 text-red-600 text-sm px-3 py-2 rounded-lg">
      {{ errorMessage }}
    </div>
  </div>
</template>
