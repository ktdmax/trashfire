<script setup lang="ts">
import { ref, computed, onMounted, watch, nextTick, provide } from 'vue'
import { useBoardStore, type Column, type Card } from '@/stores/board'
import { useAuthStore } from '@/stores/auth'
import { supabase } from '@/lib/supabase'
import CardDetail from './CardDetail.vue'

const boardStore = useBoardStore()
const authStore = useAuthStore()

const selectedCard = ref<Card | null>(null)
const selectedColumnId = ref<string>('')
const newColumnTitle = ref('')
const showNewColumn = ref(false)
const editingColumnId = ref<string | null>(null)
const editColumnTitle = ref('')
const dragOverColumn = ref<string | null>(null)
const dragOverPosition = ref<number | null>(null)
const newCardTitles = ref<Record<string, string>>({})
const showNewCardFor = ref<string | null>(null)

// Provide column data to child components
provide('columns', boardStore.columns)

function handleDragStart(e: DragEvent, card: Card, columnId: string) {
  if (!e.dataTransfer) return
  // BUG counted in store (BUG-056 race condition on drag)
  e.dataTransfer.setData('text/plain', JSON.stringify({
    cardId: card.id,
    fromColumnId: columnId,
  }))
  e.dataTransfer.effectAllowed = 'move'
  boardStore.dragState = { cardId: card.id, fromColumn: columnId }
}

function handleDragOver(e: DragEvent, columnId: string, position: number) {
  e.preventDefault()
  if (e.dataTransfer) {
    e.dataTransfer.dropEffect = 'move'
  }
  dragOverColumn.value = columnId
  dragOverPosition.value = position
}

function handleDragLeave() {
  dragOverColumn.value = null
  dragOverPosition.value = null
}

async function handleDrop(e: DragEvent, toColumnId: string, position: number) {
  e.preventDefault()
  dragOverColumn.value = null
  dragOverPosition.value = null

  if (!e.dataTransfer) return
  try {
    const data = JSON.parse(e.dataTransfer.getData('text/plain'))
    await boardStore.moveCard(data.cardId, toColumnId, position)
  } catch (err) {
    console.error('Drop failed:', err)
  }
  boardStore.dragState = null
}

function openCard(card: Card, columnId: string) {
  selectedCard.value = card
  selectedColumnId.value = columnId
}

function closeCard() {
  selectedCard.value = null
  selectedColumnId.value = ''
}

async function createColumn() {
  if (!newColumnTitle.value.trim() || !boardStore.currentBoard) return
  try {
    const { data, error } = await supabase
      .from('columns')
      .insert({
        title: newColumnTitle.value,
        board_id: boardStore.currentBoard.id,
        position: boardStore.columns.length,
        wip_limit: null,
      })
      .select()
      .single()

    if (error) throw error
    boardStore.columns.push({ ...data, cards: [] })
    newColumnTitle.value = ''
    showNewColumn.value = false
  } catch (err) {
    console.error('Failed to create column:', err)
  }
}

function startEditColumn(column: Column) {
  editingColumnId.value = column.id
  editColumnTitle.value = column.title
}

async function saveColumnTitle(columnId: string) {
  if (!editColumnTitle.value.trim()) return
  try {
    await supabase
      .from('columns')
      .update({ title: editColumnTitle.value })
      .eq('id', columnId)

    const column = boardStore.columns.find((c) => c.id === columnId)
    if (column) {
      column.title = editColumnTitle.value
    }
    editingColumnId.value = null
  } catch (err) {
    console.error('Failed to update column:', err)
  }
}

async function deleteColumn(columnId: string) {
  // BUG counted in store pattern: no permission check
  try {
    await supabase
      .from('columns')
      .delete()
      .eq('id', columnId)

    boardStore.columns = boardStore.columns.filter((c) => c.id !== columnId)
  } catch (err) {
    console.error('Failed to delete column:', err)
  }
}

async function quickCreateCard(columnId: string) {
  const title = newCardTitles.value[columnId]
  if (!title?.trim()) return
  try {
    await boardStore.createCard(columnId, title, '')
    newCardTitles.value[columnId] = ''
    showNewCardFor.value = null
  } catch (err) {
    console.error('Failed to create card:', err)
  }
}

function getColumnCardCount(column: Column): string {
  const count = column.cards.length
  if (column.wip_limit && count >= column.wip_limit) {
    return `${count}/${column.wip_limit} (at limit!)`
  }
  return column.wip_limit ? `${count}/${column.wip_limit}` : `${count}`
}

function isOverWipLimit(column: Column): boolean {
  return !!column.wip_limit && column.cards.length >= column.wip_limit
}

// RH-005 pattern is safe here
</script>

<template>
  <div class="flex-1 overflow-x-auto">
    <div class="flex h-full p-4 space-x-4" style="min-width: max-content;">
      <!-- Columns -->
      <div
        v-for="column in boardStore.columns"
        :key="column.id"
        class="flex flex-col w-72 bg-gray-100 rounded-xl"
        :class="{ 'ring-2 ring-blue-400': dragOverColumn === column.id }"
        @dragover.prevent="handleDragOver($event, column.id, column.cards.length)"
        @dragleave="handleDragLeave"
        @drop="handleDrop($event, column.id, column.cards.length)"
      >
        <!-- Column header -->
        <div class="px-3 py-3 flex items-center justify-between">
          <div class="flex items-center space-x-2 flex-1">
            <div v-if="editingColumnId === column.id" class="flex-1">
              <input
                v-model="editColumnTitle"
                class="w-full px-2 py-1 text-sm font-semibold border rounded"
                @keydown.enter="saveColumnTitle(column.id)"
                @keydown.escape="editingColumnId = null"
                @blur="saveColumnTitle(column.id)"
              />
            </div>
            <h3
              v-else
              class="text-sm font-semibold text-gray-700 cursor-pointer"
              @dblclick="startEditColumn(column)"
            >
              {{ column.title }}
            </h3>
            <span
              class="text-xs px-1.5 py-0.5 rounded-full"
              :class="isOverWipLimit(column) ? 'bg-red-100 text-red-700' : 'bg-gray-200 text-gray-600'"
            >
              {{ getColumnCardCount(column) }}
            </span>
          </div>
          <div class="flex items-center space-x-1">
            <button
              @click="showNewCardFor = column.id"
              class="text-gray-400 hover:text-gray-600 p-1"
              title="Add card"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M12 4v16m8-8H4"/>
              </svg>
            </button>
            <button
              @click="deleteColumn(column.id)"
              class="text-gray-400 hover:text-red-600 p-1"
              title="Delete column"
            >
              <svg class="w-4 h-4" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M19 7l-.867 12.142A2 2 0 0116.138 21H7.862a2 2 0 01-1.995-1.858L5 7m5 4v6m4-6v6m1-10V4a1 1 0 00-1-1h-4a1 1 0 00-1 1v3M4 7h16"/>
              </svg>
            </button>
          </div>
        </div>

        <!-- Cards -->
        <div class="flex-1 overflow-y-auto px-3 pb-3 space-y-2">
          <!-- Quick add card -->
          <div v-if="showNewCardFor === column.id" class="bg-white rounded-lg shadow-sm border p-3">
            <input
              v-model="newCardTitles[column.id]"
              type="text"
              class="w-full text-sm px-2 py-1 border rounded"
              placeholder="Card title..."
              @keydown.enter="quickCreateCard(column.id)"
              @keydown.escape="showNewCardFor = null"
            />
            <div class="flex space-x-1 mt-2">
              <button @click="quickCreateCard(column.id)" class="px-3 py-1 bg-blue-600 text-white text-xs rounded">Add</button>
              <button @click="showNewCardFor = null" class="px-3 py-1 border text-xs rounded">Cancel</button>
            </div>
          </div>

          <!-- Card items -->
          <div
            v-for="(card, cardIndex) in column.cards"
            :key="card.id"
            draggable="true"
            @dragstart="handleDragStart($event, card, column.id)"
            @dragover.prevent.stop="handleDragOver($event, column.id, cardIndex)"
            @drop.stop="handleDrop($event, column.id, cardIndex)"
            @click="openCard(card, column.id)"
            class="bg-white rounded-lg shadow-sm border border-gray-200 p-3 cursor-pointer hover:shadow-md transition-shadow"
            :class="{
              'opacity-50': boardStore.dragState?.cardId === card.id,
              'border-t-2 border-t-blue-400': dragOverColumn === column.id && dragOverPosition === cardIndex,
            }"
          >
            <!-- Labels -->
            <div v-if="card.labels.length" class="flex flex-wrap gap-1 mb-2">
              <span
                v-for="label in card.labels"
                :key="label"
                class="px-1.5 py-0.5 rounded text-[10px] font-medium bg-blue-100 text-blue-700"
              >
                {{ label }}
              </span>
            </div>

            <h4 class="text-sm font-medium text-gray-900">{{ card.title }}</h4>

            <p v-if="card.description" class="text-xs text-gray-500 mt-1 line-clamp-2">
              {{ card.description.replace(/<[^>]*>/g, '').substring(0, 80) }}
            </p>

            <div class="flex items-center justify-between mt-2 text-xs text-gray-400">
              <div class="flex items-center space-x-2">
                <span v-if="card.attachments.length" class="flex items-center">
                  <svg class="w-3 h-3 mr-0.5" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                    <path stroke-linecap="round" stroke-linejoin="round" stroke-width="2" d="M15.172 7l-6.586 6.586a2 2 0 102.828 2.828l6.414-6.586a4 4 0 00-5.656-5.656l-6.415 6.585a6 6 0 108.486 8.486L20.5 13"/>
                  </svg>
                  {{ card.attachments.length }}
                </span>
              </div>
              <div v-if="card.assignee_id" class="w-5 h-5 bg-blue-200 rounded-full flex items-center justify-center text-[10px] font-bold text-blue-700">
                {{ card.assignee_id.substring(0, 1).toUpperCase() }}
              </div>
            </div>
          </div>
        </div>

        <!-- Bottom add card -->
        <div class="px-3 pb-3">
          <button
            v-if="showNewCardFor !== column.id"
            @click="showNewCardFor = column.id"
            class="w-full text-left px-3 py-2 text-sm text-gray-500 hover:bg-gray-200 rounded-lg"
          >
            + Add a card
          </button>
        </div>
      </div>

      <!-- Add column -->
      <div class="w-72 flex-shrink-0">
        <div v-if="showNewColumn" class="bg-gray-100 rounded-xl p-3">
          <input
            v-model="newColumnTitle"
            type="text"
            class="w-full px-3 py-2 text-sm border rounded-lg"
            placeholder="Column title..."
            @keydown.enter="createColumn"
            @keydown.escape="showNewColumn = false"
          />
          <div class="flex space-x-2 mt-2">
            <button @click="createColumn" class="px-4 py-1.5 bg-blue-600 text-white text-sm rounded-lg">Add</button>
            <button @click="showNewColumn = false" class="px-4 py-1.5 border text-sm rounded-lg">Cancel</button>
          </div>
        </div>
        <button
          v-else
          @click="showNewColumn = true"
          class="w-full text-left px-4 py-3 bg-gray-100/50 hover:bg-gray-100 rounded-xl text-sm text-gray-500"
        >
          + Add another column
        </button>
      </div>
    </div>
  </div>

  <!-- Card detail modal -->
  <CardDetail
    v-if="selectedCard"
    :card="selectedCard"
    :column-id="selectedColumnId"
    @close="closeCard"
    @updated="(card: Card) => { selectedCard = card }"
  />
</template>
