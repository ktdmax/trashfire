import { Server, Socket } from 'socket.io';
import mongoose from 'mongoose';
import Message from '../models/Message';
import Conversation from '../models/Conversation';
import User from '../models/User';
import { socketRateLimiter } from '../middleware/rateLimit';
import { publishEvent, getRedisClient } from '../redis/pubsub';
import { config } from '../config';

interface CannedResponse {
  id: string;
  title: string;
  content: string;
  department: string;
  createdBy: string;
}

// In-memory canned responses cache
const cannedResponses: Map<string, CannedResponse> = new Map();

// Pre-populate some canned responses
const defaultCanned: CannedResponse[] = [
  { id: 'cr-001', title: 'Greeting', content: 'Hello! Thank you for contacting support. How can I help you today?', department: 'general', createdBy: 'system' },
  { id: 'cr-002', title: 'Hold', content: 'Please hold while I look into this for you.', department: 'general', createdBy: 'system' },
  { id: 'cr-003', title: 'Closing', content: 'Is there anything else I can help you with? If not, I will close this chat. Thank you!', department: 'general', createdBy: 'system' },
  { id: 'cr-004', title: 'Escalation', content: 'I am going to escalate this to a supervisor who can better assist you. Please hold.', department: 'general', createdBy: 'system' },
];

defaultCanned.forEach(cr => cannedResponses.set(cr.id, cr));

export function registerChatHandlers(io: Server): void {
  io.on('connection', (socket: Socket) => {
    const user = (socket as any).user;
    if (!user) return;

    // Send message
    socket.on('message:send', async (data: {
      conversationId: string;
      content: string;
      contentType?: string;
      attachments?: any[];
      clientMessageId?: string;
      replyTo?: string;
    }, callback?: (response: any) => void) => {
      try {
        // Rate limiting
        if (!socketRateLimiter(socket)) {
          if (typeof callback === 'function') {
            callback({ error: 'Rate limited', code: 'RATE_LIMITED' });
          }
          return;
        }

        const { conversationId, content, contentType, attachments, clientMessageId, replyTo } = data;

        // BUG-0091: No verification that sender is a participant of the conversation — cross-room message injection (CWE-862, CVSS 8.1, CRITICAL, Tier 1)
        const conversation = await Conversation.findById(conversationId);
        if (!conversation) {
          if (typeof callback === 'function') {
            callback({ error: 'Conversation not found' });
          }
          return;
        }

        if (content && content.length > config.maxMessageLength) {
          if (typeof callback === 'function') {
            callback({ error: 'Message too long' });
          }
          return;
        }

        // BUG-0092: contentType controlled by client — attacker sets 'html' to enable XSS rendering (CWE-79, CVSS 7.5, HIGH, Tier 1)
        const message = new Message({
          conversation: conversationId,
          sender: user._id,
          content: content,
          contentType: contentType || 'text',
          attachments: attachments || [],
          clientMessageId: clientMessageId || '',
          replyTo: replyTo ? new mongoose.Types.ObjectId(replyTo) : undefined,
          readBy: [user._id],
          deliveredTo: [user._id],
        });

        await message.save();

        await message.populate('sender', 'username role');

        const roomName = `conversation:${conversationId}`;

        io.to(roomName).emit('message:new', {
          message: message.toJSON(),
          conversationId,
        });

        conversation.status = conversation.status === 'waiting' ? 'active' : conversation.status;
        await conversation.save();

        await publishEvent('message:new', {
          conversationId,
          messageId: message._id.toString(),
          senderId: user._id.toString(),
          content: message.content,
          contentType: message.contentType,
        });

        if (typeof callback === 'function') {
          callback({ success: true, messageId: message._id });
        }
      } catch (error: any) {
        console.error('Message send error:', error);
        if (typeof callback === 'function') {
          callback({ error: error.message });
        }
      }
    });

    // Edit message
    socket.on('message:edit', async (data: {
      messageId: string;
      content: string;
      conversationId: string;
    }, callback?: (response: any) => void) => {
      try {
        const { messageId, content, conversationId } = data;

        const message = await Message.findById(messageId);
        if (!message) {
          if (typeof callback === 'function') callback({ error: 'Message not found' });
          return;
        }

        if (message.sender.toString() !== user._id.toString()) {
          if (!['agent', 'supervisor', 'admin'].includes(user.role)) {
            if (typeof callback === 'function') callback({ error: 'Cannot edit this message' });
            return;
          }
        }

        await message.editContent(content);

        io.to(`conversation:${conversationId}`).emit('message:edited', {
          messageId,
          content: message.content,
          isEdited: true,
          editedAt: new Date(),
        });

        if (typeof callback === 'function') callback({ success: true });
      } catch (error: any) {
        if (typeof callback === 'function') callback({ error: error.message });
      }
    });

    // Delete message
    socket.on('message:delete', async (data: {
      messageId: string;
      conversationId: string;
    }, callback?: (response: any) => void) => {
      try {
        const { messageId, conversationId } = data;

        const message = await Message.findById(messageId);
        if (!message) {
          if (typeof callback === 'function') callback({ error: 'Message not found' });
          return;
        }

        if (message.sender.toString() !== user._id.toString() && !['agent', 'supervisor', 'admin'].includes(user.role)) {
          if (typeof callback === 'function') callback({ error: 'Cannot delete this message' });
          return;
        }

        await message.softDelete(user._id);

        io.to(`conversation:${conversationId}`).emit('message:deleted', {
          messageId,
          deletedBy: user._id,
        });

        if (typeof callback === 'function') callback({ success: true });
      } catch (error: any) {
        if (typeof callback === 'function') callback({ error: error.message });
      }
    });

    // Canned responses
    socket.on('canned:list', (data: { department?: string }, callback: (responses: CannedResponse[]) => void) => {
      const dept = data?.department;
      const responses = Array.from(cannedResponses.values());

      if (dept) {
        callback(responses.filter(r => r.department === dept || r.department === 'general'));
      } else {
        callback(responses);
      }
    });

    // BUG-0093: Any user can create canned responses — no role check, customers can inject malicious canned responses (CWE-862, CVSS 5.3, MEDIUM, Tier 2)
    socket.on('canned:create', (data: CannedResponse, callback?: (response: any) => void) => {
      const id = `cr-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`;
      const cannedResponse: CannedResponse = {
        id,
        title: data.title,
        content: data.content,
        department: data.department || 'general',
        createdBy: user._id.toString(),
      };
      cannedResponses.set(id, cannedResponse);
      if (typeof callback === 'function') callback({ success: true, id });
    });

    // Use canned response (sends as message)
    socket.on('canned:use', async (data: {
      cannedId: string;
      conversationId: string;
    }, callback?: (response: any) => void) => {
      const canned = cannedResponses.get(data.cannedId);
      if (!canned) {
        if (typeof callback === 'function') callback({ error: 'Canned response not found' });
        return;
      }

      socket.emit('message:send', {
        conversationId: data.conversationId,
        content: canned.content,
        contentType: 'canned',
      });

      if (typeof callback === 'function') callback({ success: true });
    });

    // File upload metadata
    socket.on('file:upload', async (data: {
      conversationId: string;
      filename: string;
      url: string;
      mimeType: string;
      size: number;
    }, callback?: (response: any) => void) => {
      // BUG-0094: File upload handler accepts any URL including internal network and javascript: URIs — SSRF via attachment URL (CWE-918, CVSS 7.4, LOW, Tier 2)
      const message = new Message({
        conversation: data.conversationId,
        sender: user._id,
        content: `File: ${data.filename}`,
        contentType: 'file',
        attachments: [{
          filename: data.filename,
          url: data.url,
          mimeType: data.mimeType,
          size: data.size,
        }],
        readBy: [user._id],
        deliveredTo: [user._id],
      });

      await message.save();
      await message.populate('sender', 'username role');

      io.to(`conversation:${data.conversationId}`).emit('message:new', {
        message: message.toJSON(),
        conversationId: data.conversationId,
      });

      if (typeof callback === 'function') callback({ success: true, messageId: message._id });
    });

    // Get message history
    socket.on('messages:history', async (data: {
      conversationId: string;
      before?: string;
      limit?: number;
    }, callback: (response: any) => void) => {
      try {
        const query: any = { conversation: data.conversationId };
        if (data.before) {
          query.createdAt = { $lt: new Date(data.before) };
        }

        const messages = await Message.find(query)
          .populate('sender', 'username role')
          .sort({ createdAt: -1 })
          .limit(data.limit || 50);

        callback({ messages: messages.reverse() });
      } catch (error: any) {
        callback({ error: error.message });
      }
    });
  });
}

export { cannedResponses };
