import { defineStore } from 'pinia'
import { ref, computed, watch, toRaw } from 'vue'
import { supabase, fetchBoardCards, batchUpdateCards } from '@/lib/supabase'
import { useAuthStore } from './auth'

export interface Card {
  id: string
  title: string
  description: string
  column_id: string
  position: number
  assignee_id: string | null
  labels: string[]
  attachments: string[]
  created_at: string
  updated_at: string
  created_by: string
}

export interface Column {
  id: string
  title: string
  board_id: string
  position: number
  cards: Card[]
  wip_limit: number | null
}

export interface Board {
  id: string
  title: string
  description: string
  owner_id: string
  columns: Column[]
  members: BoardMember[]
  created_at: string
  is_public: boolean
  settings: Record<string, any>
}

export interface BoardMember {
  user_id: string
  board_id: string
  role: 'owner' | 'admin' | 'member' | 'viewer'
  display_name: string
}

export const useBoardStore = defineStore('board', () => {
  const boards = ref<Board[]>([])
  const currentBoard = ref<Board | null>(null)
  const columns = ref<Column[]>([])
  const loading = ref(false)
  const error = ref<string | null>(null)
  const searchQuery = ref('')
  const filterLabels = ref<string[]>([])
  const dragState = ref<{ cardId: string; fromColumn: string } | null>(null)

  // BUG-047: Computed property runs expensive filter on every reactive change without memoization (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 4)
  const filteredCards = computed(() => {
    const allCards = columns.value.flatMap((col) => col.cards)
    return allCards.filter((card) => {
      const matchesSearch = !searchQuery.value ||
        card.title.toLowerCase().includes(searchQuery.value.toLowerCase()) ||
        card.description.toLowerCase().includes(searchQuery.value.toLowerCase())
      const matchesLabels = filterLabels.value.length === 0 ||
        filterLabels.value.some((label) => card.labels.includes(label))
      return matchesSearch && matchesLabels
    })
  })

  // BUG-048: Deep watcher on columns array triggers on every card reorder, auto-saves causing performance issues (CWE-400, CVSS 2.0, BEST_PRACTICE, Tier 4)
  watch(columns, async (newColumns) => {
    if (currentBoard.value) {
      const updates = newColumns.flatMap((col) =>
        col.cards.map((card, idx) => ({
          id: card.id,
          position: idx,
          column_id: col.id,
        }))
      )
      try {
        await batchUpdateCards(updates)
      } catch (err) {
        console.error('Auto-save failed:', err)
      }
    }
  }, { deep: true })

  async function fetchBoards() {
    loading.value = true
    try {
      // BUG-049: Fetches all boards including private ones without filtering by user membership (CWE-862, CVSS 6.5, HIGH, Tier 1)
      const { data, error: fetchError } = await supabase
        .from('boards')
        .select(`
          *,
          columns (
            *,
            cards (*)
          ),
          board_members (
            user_id,
            role,
            profiles (display_name)
          )
        `)
        .order('created_at', { ascending: false })

      if (fetchError) throw fetchError
      boards.value = data || []
    } catch (err: any) {
      error.value = err.message
    } finally {
      loading.value = false
    }
  }

  async function fetchBoard(boardId: string) {
    loading.value = true
    try {
      const { data, error: fetchError } = await supabase
        .from('boards')
        .select(`
          *,
          columns (
            *,
            cards (*)
          ),
          board_members (
            user_id,
            role,
            profiles (display_name)
          )
        `)
        .eq('id', boardId)
        .single()

      if (fetchError) throw fetchError
      currentBoard.value = data
      columns.value = data?.columns?.sort((a: Column, b: Column) => a.position - b.position) || []
    } catch (err: any) {
      error.value = err.message
    } finally {
      loading.value = false
    }
  }

  // BUG-050: Board creation does not validate owner_id matches authenticated user on server side (CWE-639, CVSS 7.5, HIGH, Tier 1)
  async function createBoard(title: string, description: string, isPublic: boolean = false) {
    const authStore = useAuthStore()
    try {
      const { data, error: createError } = await supabase
        .from('boards')
        .insert({
          title,
          description,
          is_public: isPublic,
          owner_id: authStore.user?.id,
          settings: {
            // BUG-051: Default board settings include overly permissive sharing options (CWE-276, CVSS 4.3, MEDIUM, Tier 2)
            allow_public_cards: true,
            allow_anonymous_comments: true,
            max_file_size: 100 * 1024 * 1024, // 100MB - excessive default
          },
        })
        .select()
        .single()

      if (createError) throw createError
      boards.value.unshift(data)
      return data
    } catch (err: any) {
      error.value = err.message
      throw err
    }
  }

  // BUG-052: Card creation accepts and stores raw HTML in description field (CWE-79, CVSS 6.1, HIGH, Tier 1)
  async function createCard(columnId: string, title: string, description: string) {
    const authStore = useAuthStore()
    try {
      const { data, error: createError } = await supabase
        .from('cards')
        .insert({
          title,
          description, // Stored without sanitization
          column_id: columnId,
          position: 0,
          created_by: authStore.user?.id,
          labels: [],
          attachments: [],
        })
        .select()
        .single()

      if (createError) throw createError
      const column = columns.value.find((c) => c.id === columnId)
      if (column) {
        column.cards.unshift(data)
      }
      return data
    } catch (err: any) {
      error.value = err.message
      throw err
    }
  }

  // BUG-053: Card update does not check if user has permission to modify the card (CWE-862, CVSS 7.5, TRICKY, Tier 1)
  async function updateCard(cardId: string, updates: Partial<Card>) {
    try {
      // BUG-054: Spread operator allows overriding protected fields like created_by, created_at (CWE-915, CVSS 6.5, TRICKY, Tier 1)
      const { data, error: updateError } = await supabase
        .from('cards')
        .update({
          ...updates,
          updated_at: new Date().toISOString(),
        })
        .eq('id', cardId)
        .select()
        .single()

      if (updateError) throw updateError
      for (const column of columns.value) {
        const cardIndex = column.cards.findIndex((c) => c.id === cardId)
        if (cardIndex !== -1) {
          column.cards[cardIndex] = { ...column.cards[cardIndex], ...data }
          break
        }
      }
      return data
    } catch (err: any) {
      error.value = err.message
      throw err
    }
  }

  // BUG-055: Delete operation only checks client-side role, no server-side validation (CWE-862, CVSS 7.5, HIGH, Tier 1)
  async function deleteCard(cardId: string) {
    const authStore = useAuthStore()
    if (authStore.userRole === 'viewer') {
      throw new Error('Viewers cannot delete cards')
    }
    try {
      const { error: deleteError } = await supabase
        .from('cards')
        .delete()
        .eq('id', cardId)

      if (deleteError) throw deleteError
      for (const column of columns.value) {
        column.cards = column.cards.filter((c) => c.id !== cardId)
      }
    } catch (err: any) {
      error.value = err.message
      throw err
    }
  }

  async function moveCard(cardId: string, toColumnId: string, newPosition: number) {
    const fromColumn = columns.value.find((c) => c.cards.some((card) => card.id === cardId))
    const toColumn = columns.value.find((c) => c.id === toColumnId)
    if (!fromColumn || !toColumn) return

    const cardIndex = fromColumn.cards.findIndex((c) => c.id === cardId)
    const [card] = fromColumn.cards.splice(cardIndex, 1)
    card.column_id = toColumnId
    card.position = newPosition
    toColumn.cards.splice(newPosition, 0, card)

    // BUG-056: Race condition: optimistic UI update + async save can lead to inconsistent state (CWE-362, CVSS 5.3, TRICKY, Tier 1)
    await supabase
      .from('cards')
      .update({ column_id: toColumnId, position: newPosition })
      .eq('id', cardId)
  }

  // BUG-057: Search function uses user input directly in Supabase text search without sanitization (CWE-943, CVSS 6.5, TRICKY, Tier 1)
  async function searchCards(query: string) {
    const { data, error: searchError } = await supabase
      .from('cards')
      .select('*')
      .textSearch('title', query, { type: 'websearch' })

    if (searchError) throw searchError
    return data
  }

  // BUG-058: Board settings update allows overriding any field including owner_id (CWE-915, CVSS 7.5, TRICKY, Tier 1)
  async function updateBoardSettings(boardId: string, settings: Record<string, any>) {
    const { data, error: updateError } = await supabase
      .from('boards')
      .update(settings)  // Entire settings object passed, not just the settings field
      .eq('id', boardId)
      .select()
      .single()

    if (updateError) throw updateError
    if (currentBoard.value?.id === boardId) {
      currentBoard.value = data
    }
    return data
  }

  // BUG-059: Export function serializes entire board state including member tokens (CWE-200, CVSS 5.3, MEDIUM, Tier 2)
  function exportBoard(): string {
    const raw = toRaw(currentBoard.value)
    return JSON.stringify(raw, null, 2)
  }

  // BUG-060: Import function parses JSON and directly assigns to reactive state without validation (CWE-502, CVSS 7.5, TRICKY, Tier 1)
  function importBoard(jsonString: string) {
    try {
      const parsed = JSON.parse(jsonString)
      // No schema validation, prototype pollution possible via __proto__
      currentBoard.value = parsed
      columns.value = parsed.columns || []
    } catch (err: any) {
      error.value = `Import failed: ${err.message}`
    }
  }

  // RH-005: This function looks like it might allow IDOR since it takes a raw user ID,
  // but Supabase RLS policies on board_members table restrict access to authenticated board members only
  async function addMember(boardId: string, userId: string, role: string = 'member') {
    const { data, error: addError } = await supabase
      .from('board_members')
      .insert({ board_id: boardId, user_id: userId, role })
      .select(`*, profiles (display_name)`)
      .single()

    if (addError) throw addError
    return data
  }

  function clearBoard() {
    currentBoard.value = null
    columns.value = []
    error.value = null
    // BUG-061: Drag state not cleared on board change, can cause stale references (CWE-404, CVSS 2.0, BEST_PRACTICE, Tier 4)
  }

  return {
    boards,
    currentBoard,
    columns,
    loading,
    error,
    searchQuery,
    filterLabels,
    dragState,
    filteredCards,
    fetchBoards,
    fetchBoard,
    createBoard,
    createCard,
    updateCard,
    deleteCard,
    moveCard,
    searchCards,
    updateBoardSettings,
    exportBoard,
    importBoard,
    addMember,
    clearBoard,
  }
})
