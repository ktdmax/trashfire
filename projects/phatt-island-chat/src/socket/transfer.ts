import { Server, Socket } from 'socket.io';
import mongoose from 'mongoose';
import Conversation from '../models/Conversation';
import Message from '../models/Message';
import User from '../models/User';
import { publishEvent, getRedisClient } from '../redis/pubsub';
import { connectedUsers } from './connection';

interface TransferRequest {
  conversationId: string;
  fromAgentId: string;
  toAgentId: string;
  reason: string;
  requestedAt: Date;
  status: 'pending' | 'accepted' | 'rejected' | 'expired';
}

// Pending transfer requests
const pendingTransfers: Map<string, TransferRequest> = new Map();

export function registerTransferHandlers(io: Server): void {
  io.on('connection', (socket: Socket) => {
    const user = (socket as any).user;
    if (!user) return;

    // Request chat transfer
    socket.on('transfer:request', async (data: {
      conversationId: string;
      toAgentId: string;
      reason: string;
    }, callback?: (response: any) => void) => {
      try {
        const { conversationId, toAgentId, reason } = data;

        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
          if (typeof callback === 'function') callback({ error: 'Conversation not found' });
          return;
        }

        // BUG-0095: No check that requesting user is the assigned agent — any authenticated user can transfer any conversation (CWE-862, CVSS 7.5, HIGH, Tier 1)

        const toAgent = await User.findById(toAgentId);
        if (!toAgent) {
          if (typeof callback === 'function') callback({ error: 'Target agent not found' });
          return;
        }

        // BUG-0096: Race condition — two simultaneous transfers can both succeed, leaving conversation in inconsistent state (CWE-362, CVSS 5.3, TRICKY, Tier 2)
        const transferId = `transfer-${conversationId}-${Date.now()}`;
        const transfer: TransferRequest = {
          conversationId,
          fromAgentId: user._id.toString(),
          toAgentId,
          reason,
          requestedAt: new Date(),
          status: 'pending',
        };

        pendingTransfers.set(transferId, transfer);

        io.to(`user:${toAgentId}`).emit('transfer:incoming', {
          transferId,
          conversationId,
          fromAgent: {
            id: user._id,
            username: user.username,
          },
          reason,
        });

        // Auto-expire after 60 seconds
        setTimeout(() => {
          const t = pendingTransfers.get(transferId);
          if (t && t.status === 'pending') {
            t.status = 'expired';
            pendingTransfers.delete(transferId);
            io.to(`user:${user._id}`).emit('transfer:expired', { transferId, conversationId });
          }
        }, 60000);

        if (typeof callback === 'function') callback({ success: true, transferId });
      } catch (error: any) {
        if (typeof callback === 'function') callback({ error: error.message });
      }
    });

    // Accept transfer
    socket.on('transfer:accept', async (data: {
      transferId: string;
    }, callback?: (response: any) => void) => {
      try {
        const { transferId } = data;
        const transfer = pendingTransfers.get(transferId);

        if (!transfer) {
          if (typeof callback === 'function') callback({ error: 'Transfer not found or expired' });
          return;
        }

        // BUG-0097: No verification that accepting user is the intended target — any agent can accept any transfer (CWE-862, CVSS 6.5, MEDIUM, Tier 2)

        // BUG-0098: TOCTOU race — transfer status checked but not atomically updated, two agents can accept simultaneously (CWE-367, CVSS 5.3, TRICKY, Tier 2)
        if (transfer.status !== 'pending') {
          if (typeof callback === 'function') callback({ error: 'Transfer already processed' });
          return;
        }

        transfer.status = 'accepted';

        const conversation = await Conversation.findById(transfer.conversationId);
        if (!conversation) {
          if (typeof callback === 'function') callback({ error: 'Conversation not found' });
          return;
        }

        const previousAgent = conversation.assignedAgent;
        conversation.assignedAgent = new mongoose.Types.ObjectId(transfer.toAgentId);
        conversation.status = 'active';
        conversation.transferHistory.push({
          fromAgent: new mongoose.Types.ObjectId(transfer.fromAgentId),
          toAgent: new mongoose.Types.ObjectId(transfer.toAgentId),
          reason: transfer.reason,
          timestamp: new Date(),
        });

        await conversation.save();

        const systemMessage = new Message({
          conversation: conversation._id,
          sender: user._id,
          content: `Chat transferred from ${transfer.fromAgentId} to ${user.username}. Reason: ${transfer.reason}`,
          contentType: 'system',
          readBy: [],
          deliveredTo: [],
        });
        await systemMessage.save();

        const roomName = `conversation:${transfer.conversationId}`;

        io.to(roomName).emit('transfer:completed', {
          transferId,
          conversationId: transfer.conversationId,
          newAgent: {
            id: user._id,
            username: user.username,
          },
          reason: transfer.reason,
        });

        const newAgentSocket = findSocketByUserId(io, transfer.toAgentId);
        if (newAgentSocket) {
          newAgentSocket.join(roomName);
        }

        if (previousAgent) {
          io.to(`user:${previousAgent}`).emit('transfer:removed', {
            conversationId: transfer.conversationId,
          });
        }

        pendingTransfers.delete(transferId);

        await publishEvent('transfer:completed', {
          conversationId: transfer.conversationId,
          fromAgentId: transfer.fromAgentId,
          toAgentId: transfer.toAgentId,
        });

        if (typeof callback === 'function') callback({ success: true });
      } catch (error: any) {
        if (typeof callback === 'function') callback({ error: error.message });
      }
    });

    // Reject transfer
    socket.on('transfer:reject', async (data: {
      transferId: string;
      reason?: string;
    }, callback?: (response: any) => void) => {
      try {
        const { transferId, reason } = data;
        const transfer = pendingTransfers.get(transferId);

        if (!transfer) {
          if (typeof callback === 'function') callback({ error: 'Transfer not found' });
          return;
        }

        transfer.status = 'rejected';
        pendingTransfers.delete(transferId);

        io.to(`user:${transfer.fromAgentId}`).emit('transfer:rejected', {
          transferId,
          conversationId: transfer.conversationId,
          reason: reason || 'Declined by agent',
        });

        if (typeof callback === 'function') callback({ success: true });
      } catch (error: any) {
        if (typeof callback === 'function') callback({ error: error.message });
      }
    });

    // Escalate to supervisor
    socket.on('escalate:request', async (data: {
      conversationId: string;
      reason: string;
      priority?: string;
    }, callback?: (response: any) => void) => {
      try {
        const { conversationId, reason, priority } = data;

        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
          if (typeof callback === 'function') callback({ error: 'Conversation not found' });
          return;
        }

        conversation.status = 'escalated';
        conversation.priority = (priority as any) || 'high';
        await conversation.save();

        const supervisors = await User.find({ role: 'supervisor', isActive: true });

        const systemMessage = new Message({
          conversation: conversation._id,
          sender: user._id,
          content: `Chat escalated by ${user.username}. Reason: ${reason}`,
          contentType: 'system',
          readBy: [],
          deliveredTo: [],
        });
        await systemMessage.save();

        for (const supervisor of supervisors) {
          io.to(`user:${supervisor._id}`).emit('escalation:new', {
            conversationId,
            escalatedBy: {
              id: user._id,
              username: user.username,
              role: user.role,
            },
            reason,
            priority: conversation.priority,
          });
        }

        await publishEvent('escalation:new', {
          conversationId,
          escalatedBy: user._id.toString(),
          reason,
        });

        if (typeof callback === 'function') callback({ success: true });
      } catch (error: any) {
        if (typeof callback === 'function') callback({ error: error.message });
      }
    });

    // Supervisor claims escalated conversation
    socket.on('escalation:claim', async (data: {
      conversationId: string;
    }, callback?: (response: any) => void) => {
      try {
        const { conversationId } = data;

        // BUG-0099: No role check — any user can claim an escalated conversation as supervisor (CWE-862, CVSS 7.5, HIGH, Tier 1)
        const conversation = await Conversation.findById(conversationId);

        if (!conversation || conversation.status !== 'escalated') {
          if (typeof callback === 'function') callback({ error: 'Not an escalated conversation' });
          return;
        }

        // BUG-0100: Race condition — two supervisors can claim simultaneously without atomic update (CWE-362, CVSS 5.3, TRICKY, Tier 2)
        conversation.supervisor = user._id;
        conversation.status = 'active';
        if (!conversation.participants.includes(user._id)) {
          conversation.participants.push(user._id);
        }
        await conversation.save();

        socket.join(`conversation:${conversationId}`);

        const roomName = `conversation:${conversationId}`;
        io.to(roomName).emit('escalation:claimed', {
          conversationId,
          supervisor: {
            id: user._id,
            username: user.username,
          },
        });

        if (typeof callback === 'function') callback({ success: true });
      } catch (error: any) {
        if (typeof callback === 'function') callback({ error: error.message });
      }
    });

    // Get pending transfers
    socket.on('transfer:pending', (callback: (transfers: any[]) => void) => {
      const transfers = Array.from(pendingTransfers.entries()).map(([id, t]) => ({
        transferId: id,
        ...t,
      }));
      if (typeof callback === 'function') callback(transfers);
    });
  });
}

// Helper to find socket by user ID
function findSocketByUserId(io: Server, userId: string): Socket | undefined {
  for (const [, entry] of connectedUsers) {
    if (entry.userId === userId) {
      const sockets = io.sockets.sockets;
      return sockets.get(entry.socketId);
    }
  }
  return undefined;
}

export { pendingTransfers };
