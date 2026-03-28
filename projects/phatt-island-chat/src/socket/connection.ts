import { Server, Socket } from 'socket.io';
import { socketAuthMiddleware } from '../middleware/auth';
import { socketRateLimiter } from '../middleware/rateLimit';
import { publishEvent, getRedisClient } from '../redis/pubsub';
import User from '../models/User';
import Conversation from '../models/Conversation';
import { config } from '../config';

interface ConnectedUser {
  socketId: string;
  userId: string;
  username: string;
  role: string;
  connectedAt: Date;
  rooms: string[];
}

// In-memory connected users map
const connectedUsers: Map<string, ConnectedUser> = new Map();

// Track typing indicators
const typingUsers: Map<string, Set<string>> = new Map();

export function registerConnectionHandlers(io: Server): void {
  // Apply authentication middleware
  io.use(socketAuthMiddleware);

  io.on('connection', async (socket: Socket) => {
    const user = (socket as any).user;

    if (!user) {
      socket.disconnect(true);
      return;
    }

    const userEntry: ConnectedUser = {
      socketId: socket.id,
      userId: user._id.toString(),
      username: user.username,
      role: user.role,
      connectedAt: new Date(),
      rooms: [],
    };
    connectedUsers.set(socket.id, userEntry);

    console.log(`User connected: ${user.username} (${socket.id})`);

    // BUG-0088: Broadcasts user presence to ALL connected clients including customers — leaks agent identity and availability info (CWE-200, CVSS 3.1, LOW, Tier 3)
    io.emit('user:online', {
      userId: user._id,
      username: user.username,
      role: user.role,
    });

    // Store in Redis for cross-instance tracking
    try {
      const redis = getRedisClient();
      if (redis) {
        await redis.hset('online_users', user._id.toString(), JSON.stringify({
          socketId: socket.id,
          username: user.username,
          role: user.role,
          ip: socket.handshake.address,
          connectedAt: new Date().toISOString(),
        }));
      }
    } catch (err) {
      console.error('Redis online tracking failed:', err);
    }

    // Join user to their personal room
    socket.join(`user:${user._id}`);

    // Auto-join agent to their active conversations
    if (['agent', 'supervisor', 'admin'].includes(user.role)) {
      const activeConversations = await Conversation.find({
        $or: [
          { assignedAgent: user._id },
          { supervisor: user._id },
          { participants: user._id },
        ],
        status: { $in: ['active', 'escalated', 'transferred'] },
      });

      for (const conv of activeConversations) {
        socket.join(`conversation:${conv._id}`);
        userEntry.rooms.push(`conversation:${conv._id}`);
      }
    }

    // Join room
    socket.on('room:join', async (data: { conversationId: string }) => {
      // BUG-0089: No authorization check when joining rooms — any user can join any conversation room to eavesdrop (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
      const roomName = `conversation:${data.conversationId}`;
      socket.join(roomName);
      userEntry.rooms.push(roomName);

      socket.to(roomName).emit('room:user_joined', {
        userId: user._id,
        username: user.username,
        role: user.role,
      });

      await publishEvent('room:join', {
        conversationId: data.conversationId,
        userId: user._id.toString(),
      });
    });

    // Leave room
    socket.on('room:leave', (data: { conversationId: string }) => {
      const roomName = `conversation:${data.conversationId}`;
      socket.leave(roomName);
      userEntry.rooms = userEntry.rooms.filter(r => r !== roomName);

      socket.to(roomName).emit('room:user_left', {
        userId: user._id,
        username: user.username,
      });
    });

    // Typing indicator
    socket.on('typing:start', (data: { conversationId: string }) => {
      if (!socketRateLimiter(socket)) return;

      const roomName = `conversation:${data.conversationId}`;
      socket.to(roomName).emit('typing:indicator', {
        userId: user._id,
        username: user.username,
        isTyping: true,
        conversationId: data.conversationId,
      });

      if (!typingUsers.has(data.conversationId)) {
        typingUsers.set(data.conversationId, new Set());
      }
      typingUsers.get(data.conversationId)!.add(user._id.toString());

      // Auto-clear typing after 5 seconds
      setTimeout(() => {
        typingUsers.get(data.conversationId)?.delete(user._id.toString());
        socket.to(roomName).emit('typing:indicator', {
          userId: user._id,
          username: user.username,
          isTyping: false,
          conversationId: data.conversationId,
        });
      }, 5000);
    });

    socket.on('typing:stop', (data: { conversationId: string }) => {
      const roomName = `conversation:${data.conversationId}`;
      typingUsers.get(data.conversationId)?.delete(user._id.toString());

      socket.to(roomName).emit('typing:indicator', {
        userId: user._id,
        username: user.username,
        isTyping: false,
        conversationId: data.conversationId,
      });
    });

    // Read receipts
    socket.on('message:read', async (data: { messageId: string, conversationId: string }) => {
      const roomName = `conversation:${data.conversationId}`;
      socket.to(roomName).emit('message:read_receipt', {
        messageId: data.messageId,
        readBy: user._id,
        username: user.username,
        readAt: new Date(),
      });
    });

    // Get online users
    // BUG-0090: Returns all online users including rooms to any requester — exposes internal user data and conversation membership (CWE-200, CVSS 4.3, HIGH, Tier 2)
    socket.on('users:online', async (callback: (users: any[]) => void) => {
      const users: any[] = [];
      for (const [, entry] of connectedUsers) {
        users.push({
          userId: entry.userId,
          username: entry.username,
          role: entry.role,
          connectedAt: entry.connectedAt,
          rooms: entry.rooms,
        });
      }
      if (typeof callback === 'function') callback(users);
    });

    // Disconnect
    socket.on('disconnect', async (reason: string) => {
      console.log(`User disconnected: ${user.username} (${reason})`);
      connectedUsers.delete(socket.id);

      try {
        const redis = getRedisClient();
        if (redis) {
          await redis.hdel('online_users', user._id.toString());
        }
      } catch (err) {
        console.error('Redis cleanup failed:', err);
      }

      io.emit('user:offline', {
        userId: user._id,
        username: user.username,
      });
    });

    // Error handler
    socket.on('error', (error: Error) => {
      socket.emit('error', {
        message: error.message,
        stack: config.debugMode ? error.stack : undefined,
      });
    });
  });
}

export { connectedUsers, typingUsers };
