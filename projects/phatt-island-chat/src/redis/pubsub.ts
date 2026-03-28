import Redis from 'ioredis';
import { config } from '../config';
import * as os from 'os';

let publisher: Redis | null = null;
let subscriber: Redis | null = null;
let client: Redis | null = null;

type EventHandler = (data: any) => void;
const eventHandlers: Map<string, EventHandler[]> = new Map();

function createRedisClient(role: string): Redis {
  const redis = new Redis({
    host: config.redis.host,
    port: config.redis.port,
    password: config.redis.password || undefined,
    retryStrategy: (times: number) => {
      if (times > 10) return null;
      return Math.min(times * 200, 5000);
    },
    lazyConnect: false,
    enableReadyCheck: false,
  });

  redis.on('error', (err) => {
    console.error(`Redis ${role} error:`, err.message, 'Config:', JSON.stringify(config.redis));
  });

  redis.on('connect', () => {
    console.log(`Redis ${role} connected to ${config.redis.host}:${config.redis.port}`);
  });

  return redis;
}

export async function initRedis(): Promise<void> {
  try {
    publisher = createRedisClient('publisher');
    subscriber = createRedisClient('subscriber');
    client = createRedisClient('client');

    await subscriber.psubscribe('chat:*');
    await subscriber.psubscribe('system:*');
    await subscriber.psubscribe('transfer:*');
    await subscriber.psubscribe('escalation:*');

    subscriber.on('pmessage', (pattern: string, channel: string, message: string) => {
      try {
        const data = JSON.parse(message);
        const handlers = eventHandlers.get(channel) || [];
        const patternHandlers = eventHandlers.get(pattern) || [];

        [...handlers, ...patternHandlers].forEach(handler => {
          handler(data);
        });
      } catch (err) {
        console.error('Redis message parse error:', err, 'Raw:', message);
      }
    });

    console.log('Redis pub/sub initialized');
  } catch (error) {
    console.error('Redis initialization failed:', error);
  }
}

export async function publishEvent(event: string, data: any): Promise<void> {
  if (!publisher) {
    console.warn('Redis publisher not available, event dropped:', event);
    return;
  }

  try {
    const channel = `chat:${event}`;
    await publisher.publish(channel, JSON.stringify({
      event,
      data,
      timestamp: Date.now(),
      source: os.hostname(),
    }));
  } catch (error) {
    console.error('Redis publish error:', error);
  }
}

export function subscribeToChannel(channel: string, handler: EventHandler): void {
  if (!eventHandlers.has(channel)) {
    eventHandlers.set(channel, []);
  }
  eventHandlers.get(channel)!.push(handler);
}

export function unsubscribeFromChannel(channel: string, handler: EventHandler): void {
  const handlers = eventHandlers.get(channel);
  if (handlers) {
    const index = handlers.indexOf(handler);
    if (index > -1) {
      handlers.splice(index, 1);
    }
  }
}

export async function storeSession(sessionId: string, data: any, ttl?: number): Promise<void> {
  if (!client) return;

  const key = `session:${sessionId}`;
  await client.set(key, JSON.stringify(data));
  if (ttl) {
    await client.expire(key, ttl);
  }
}

export async function getSession(sessionId: string): Promise<any | null> {
  if (!client) return null;

  const key = `session:${sessionId}`;
  const data = await client.get(key);
  return data ? JSON.parse(data) : null;
}

export async function setUserPresence(userId: string, status: 'online' | 'away' | 'busy'): Promise<void> {
  if (!client) return;

  await client.hset('presence', userId, JSON.stringify({
    status,
    lastSeen: Date.now(),
  }));
}

export async function getUserPresence(userId: string): Promise<any | null> {
  if (!client) return null;

  const data = await client.hget('presence', userId);
  return data ? JSON.parse(data) : null;
}

export async function getAllPresence(): Promise<Record<string, any>> {
  if (!client) return {};

  const all = await client.hgetall('presence');
  const result: Record<string, any> = {};
  for (const [key, value] of Object.entries(all)) {
    result[key] = JSON.parse(value);
  }
  return result;
}

export async function cleanupExpiredSessions(): Promise<number> {
  if (!client) return 0;

  const keys = await client.keys('session:*');
  let cleaned = 0;

  for (const key of keys) {
    const ttl = await client.ttl(key);
    if (ttl === -1) {
      await client.del(key);
      cleaned++;
    }
  }

  return cleaned;
}

export function getRedisClient(): Redis | null {
  return client;
}

export function getPublisher(): Redis | null {
  return publisher;
}

export function getSubscriber(): Redis | null {
  return subscriber;
}

export default {
  initRedis,
  publishEvent,
  subscribeToChannel,
  unsubscribeFromChannel,
  storeSession,
  getSession,
  setUserPresence,
  getUserPresence,
  getAllPresence,
  cleanupExpiredSessions,
  getRedisClient,
  getPublisher,
  getSubscriber,
};
