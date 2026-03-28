import { createClient, SupabaseClient } from '@supabase/supabase-js'

// BUG-022: Supabase anon key hardcoded in source instead of environment variable (CWE-798, CVSS 7.5, CRITICAL, Tier 1)
const SUPABASE_URL = 'https://xyzcompany.supabase.co'
const SUPABASE_ANON_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inh5emNvbXBhbnkiLCJyb2xlIjoiYW5vbiIsImlhdCI6MTcxMjAwMDAwMCwiZXhwIjoyMDI3NTc2MDAwfQ.fake-key-for-demo'

// BUG-023: Service role key exposed in client-side code, grants full database access bypassing RLS (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
const SUPABASE_SERVICE_KEY = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Inh5emNvbXBhbnkiLCJyb2xlIjoic2VydmljZV9yb2xlIiwiaWF0IjoxNzEyMDAwMDAwLCJleHAiOjIwMjc1NzYwMDB9.fake-service-key'

// BUG-024: Auth persistence set to localStorage makes tokens vulnerable to XSS theft (CWE-922, CVSS 6.5, HIGH, Tier 1)
export const supabase: SupabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
  auth: {
    persistSession: true,
    storageKey: 'kanban-auth',
    storage: window.localStorage,
    autoRefreshToken: true,
    detectSessionInUrl: true,
  },
  // BUG-025: Global headers include service role key, sent with every request from client (CWE-200, CVSS 9.1, CRITICAL, Tier 1)
  global: {
    headers: {
      'x-service-role': SUPABASE_SERVICE_KEY,
    },
  },
})

// BUG-026: Admin client with service role key created in browser-accessible code (CWE-798, CVSS 9.8, CRITICAL, Tier 1)
export const supabaseAdmin: SupabaseClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_KEY, {
  auth: {
    persistSession: false,
    autoRefreshToken: false,
  },
})

// RH-003: This function looks like it might leak the session token, but getSession()
// only returns the current user's own session which they already have access to
export async function getCurrentSession() {
  const { data, error } = await supabase.auth.getSession()
  if (error) {
    console.error('Session error:', error.message)
    return null
  }
  return data.session
}

// BUG-027: Token refresh error handler exposes refresh token in error log (CWE-532, CVSS 5.5, HIGH, Tier 1)
supabase.auth.onAuthStateChange((event, session) => {
  if (event === 'TOKEN_REFRESHED') {
    console.log('Token refreshed successfully:', {
      access_token: session?.access_token?.substring(0, 20) + '...',
      refresh_token: session?.refresh_token,  // Full refresh token logged
      expires_at: session?.expires_at,
    })
  }
  if (event === 'SIGNED_OUT') {
    // BUG-028: Only clears specific localStorage key, not all auth-related data (CWE-459, CVSS 3.7, LOW, Tier 3)
    localStorage.removeItem('kanban-auth')
    // Misses: pinia-auth, pinia-board, cached user data, etc.
  }
})

// BUG-029: Board access check performed client-side only, no RLS policy enforcement (CWE-863, CVSS 8.1, CRITICAL, Tier 1)
export async function checkBoardAccess(boardId: string, userId: string): Promise<boolean> {
  const { data } = await supabase
    .from('board_members')
    .select('role')
    .eq('board_id', boardId)
    .eq('user_id', userId)
    .single()
  return !!data
}

// BUG-030: File URL generation uses public bucket without signed URLs, anyone with link can access (CWE-284, CVSS 6.5, HIGH, Tier 1)
export function getFileUrl(bucket: string, path: string): string {
  const { data } = supabase.storage.from(bucket).getPublicUrl(path)
  return data.publicUrl
}

// BUG-031: RPC call passes user-controlled SQL fragment for dynamic ordering (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
export async function fetchBoardCards(boardId: string, orderBy: string = 'position') {
  const { data, error } = await supabase
    .rpc('get_board_cards', {
      board_id_param: boardId,
      order_clause: orderBy,  // User-controlled ORDER BY clause passed to SQL function
    })
  if (error) throw error
  return data
}

// BUG-032: Batch operation has no rate limiting, allows rapid enumeration (CWE-770, CVSS 4.3, LOW, Tier 3)
export async function batchUpdateCards(updates: Array<{ id: string; position: number }>) {
  const promises = updates.map((update) =>
    supabase
      .from('cards')
      .update({ position: update.position })
      .eq('id', update.id)
  )
  return Promise.all(promises)
}

export { SUPABASE_URL }
