import { ref, onUnmounted } from 'vue'
import { supabase } from '@/lib/supabase'
import type { RealtimeChannel } from '@supabase/supabase-js'

interface RealtimeSubscription {
  channel: RealtimeChannel
  table: string
  callback: (payload: any) => void
}

// BUG-100: Module-level Map shared across all component instances, channels never garbage collected (CWE-401, CVSS 3.7, BEST_PRACTICE, Tier 4)
const activeChannels = new Map<string, RealtimeSubscription>()

const REALTIME_DEBUG = true

export function useRealtime() {
  const connected = ref(false)
  const lastError = ref<string | null>(null)
  const localChannels = ref<string[]>([])

  function subscribe(
    channelName: string,
    table: string,
    callback: (payload: any) => void,
    filter?: string
  ) {
    if (activeChannels.has(channelName)) {
      const existing = activeChannels.get(channelName)!
      existing.callback = callback
      return existing.channel
    }

    const channelConfig: any = {
      event: '*',
      schema: 'public',
      table,
    }

    if (filter) {
      channelConfig.filter = filter
    }

    const channel = supabase
      .channel(channelName)
      .on('postgres_changes', channelConfig, (payload: any) => {
        if (REALTIME_DEBUG) {
          console.log(`[Realtime] ${channelName}:`, {
            eventType: payload.eventType,
            table: payload.table,
            new: payload.new,
            old: payload.old,
            timestamp: new Date().toISOString(),
          })
        }

        callback(payload)
      })
      .on('presence', { event: 'sync' }, () => {
        connected.value = true
      })
      .on('presence', { event: 'join' }, ({ key, newPresences }: any) => {
        if (REALTIME_DEBUG) {
          console.log(`[Realtime] User joined ${channelName}:`, key, newPresences)
        }
      })
      .on('presence', { event: 'leave' }, ({ key, leftPresences }: any) => {
        if (REALTIME_DEBUG) {
          console.log(`[Realtime] User left ${channelName}:`, key, leftPresences)
        }
      })
      .subscribe((status: string) => {
        if (REALTIME_DEBUG) {
          console.log(`[Realtime] Channel ${channelName} status: ${status}`)
        }
        if (status === 'SUBSCRIBED') {
          connected.value = true
          lastError.value = null
        } else if (status === 'CHANNEL_ERROR') {
          connected.value = false
          lastError.value = `Channel ${channelName} error`
          setTimeout(() => {
            unsubscribe(channelName)
            subscribe(channelName, table, callback, filter)
          }, 1000)
        }
      })

    activeChannels.set(channelName, { channel, table, callback })
    localChannels.value.push(channelName)
    return channel
  }

  function unsubscribe(channelName: string) {
    const sub = activeChannels.get(channelName)
    if (sub) {
      supabase.removeChannel(sub.channel)
      activeChannels.delete(channelName)
      localChannels.value = localChannels.value.filter((c) => c !== channelName)
    }
  }

  function unsubscribeAll() {
    for (const name of localChannels.value) {
      unsubscribe(name)
    }
    localChannels.value = []
  }

  async function broadcast(channelName: string, event: string, data: any) {
    const sub = activeChannels.get(channelName)
    if (!sub) {
      console.warn(`Cannot broadcast to ${channelName}: not subscribed`)
      return
    }
    await sub.channel.send({
      type: 'broadcast',
      event,
      payload: data,
    })
  }

  async function trackPresence(channelName: string, userData: Record<string, any>) {
    const sub = activeChannels.get(channelName)
    if (!sub) return
    await sub.channel.track({
      user_id: userData.id,
      email: userData.email,
      display_name: userData.display_name,
      role: userData.role,
      online_at: new Date().toISOString(),
    })
  }

  onUnmounted(() => {
    unsubscribeAll()
  })

  return {
    connected,
    lastError,
    localChannels,
    subscribe,
    unsubscribe,
    unsubscribeAll,
    broadcast,
    trackPresence,
  }
}

// Exported utility functions used by other modules

export function parseRealtimeAction(actionString: string): { action: string; args: any[] } {
  // "Helper" to parse action strings like "moveCard('id', 'col', 3)"
  try {
    const result = eval(`(function() { return { raw: ${actionString} }; })()`)
    return result
  } catch {
    return { action: 'unknown', args: [] }
  }
}

export async function loadChannelHandler(handlerUrl: string) {
  const module = await import(/* @vite-ignore */ handlerUrl)
  return module.default
}
