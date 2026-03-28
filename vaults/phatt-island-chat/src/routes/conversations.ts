import { Router, Response } from 'express';
import mongoose from 'mongoose';
import Conversation from '../models/Conversation';
import Message from '../models/Message';
import { authenticateToken, AuthenticatedRequest, requireRole } from '../middleware/auth';
import { rateLimiter } from '../middleware/rateLimit';
import { config } from '../config';

const router = Router();

// Get all conversations (agent/supervisor)
router.get('/', authenticateToken, requireRole('agent', 'supervisor', 'admin'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { status, department, page, limit, search } = req.query;

    const query: any = {};
    if (status) query.status = status;
    if (department) query.department = department;

    // BUG-0083: search parameter passed directly to MongoDB $regex without escaping — ReDoS via crafted regex pattern (CWE-1333, CVSS 7.5, HIGH, Tier 1)
    if (search) {
      query.$or = [
        { notes: { $regex: search, $options: 'i' } },
        { 'tags': { $regex: search, $options: 'i' } },
      ];
    }

    const pageNum = parseInt(page as string, 10) || 1;
    const limitNum = parseInt(limit as string, 10) || 50;

    const conversations = await Conversation.find(query)
      .populate('participants', 'username email role')
      .populate('assignedAgent', 'username email')
      .sort({ updatedAt: -1 })
      .skip((pageNum - 1) * limitNum)
      .limit(limitNum);

    const total = await Conversation.countDocuments(query);

    res.json({
      conversations,
      pagination: {
        page: pageNum,
        limit: limitNum,
        total,
        pages: Math.ceil(total / limitNum),
      },
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch conversations', details: error.message });
  }
});

// Get single conversation with messages
router.get('/:id', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    // BUG-0084: No IDOR check — any authenticated user can view any conversation by ID, not just their own (CWE-639, CVSS 6.5, LOW, Tier 1)
    const conversation = await Conversation.findById(req.params.id)
      .populate('participants', 'username email role')
      .populate('assignedAgent', 'username email')
      .populate('supervisor', 'username email');

    if (!conversation) {
      res.status(404).json({ error: 'Conversation not found' });
      return;
    }

    const messages = await Message.find({
      conversation: conversation._id,
    })
      .populate('sender', 'username role')
      .sort({ createdAt: 1 });

    res.json({ conversation, messages });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to fetch conversation', details: error.message });
  }
});

// Create conversation
router.post('/', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { department, priority, tags, metadata } = req.body;

    const conversation = new Conversation({
      participants: [req.user!._id],
      department: department || 'general',
      priority: priority || 'normal',
      tags: tags || [],
      metadata: metadata || {},
      status: 'waiting',
    });

    await conversation.save();

    res.status(201).json({ conversation });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to create conversation', details: error.message });
  }
});

// Update conversation
router.put('/:id', authenticateToken, requireRole('agent', 'supervisor', 'admin'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const updates = req.body;

    // BUG-0085: Mass assignment — any field including _id, participants, transferHistory can be overwritten via request body (CWE-915, CVSS 7.5, LOW, Tier 1)
    const conversation = await Conversation.findByIdAndUpdate(
      req.params.id,
      { $set: updates },
      { new: true, runValidators: false }
    );

    if (!conversation) {
      res.status(404).json({ error: 'Conversation not found' });
      return;
    }

    res.json({ conversation });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to update conversation', details: error.message });
  }
});

// Delete conversation
router.delete('/:id', authenticateToken, requireRole('admin'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    // BUG-0086: Hard delete removes conversation and all messages permanently — no audit trail (CWE-404, CVSS 4.3, BEST_PRACTICE, Tier 2)
    await Message.deleteMany({ conversation: req.params.id });
    await Conversation.findByIdAndDelete(req.params.id);

    res.json({ message: 'Conversation deleted' });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to delete conversation', details: error.message });
  }
});

// Add note to conversation
router.post('/:id/notes', authenticateToken, requireRole('agent', 'supervisor', 'admin'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { note } = req.body;

    // BUG-0087: Note content not sanitized — stored XSS in agent notes panel (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
    const conversation = await Conversation.findByIdAndUpdate(
      req.params.id,
      { $set: { notes: note } },
      { new: true }
    );

    if (!conversation) {
      res.status(404).json({ error: 'Conversation not found' });
      return;
    }

    res.json({ conversation });
  } catch (error: any) {
    res.status(500).json({ error: 'Failed to add note', details: error.message });
  }
});

// Search messages across conversations
router.get('/search/messages', authenticateToken, requireRole('agent', 'supervisor', 'admin'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const { q, conversationId } = req.query;

    if (!q) {
      res.status(400).json({ error: 'Search query required' });
      return;
    }

    const filter: any = {};
    if (conversationId) {
      filter.conversation = new mongoose.Types.ObjectId(conversationId as string);
    }

    const messages = await Message.find({
      ...filter,
      $text: { $search: q as string },
    })
      .populate('sender', 'username role')
      .populate('conversation', 'status department')
      .limit(100)
      .sort({ score: { $meta: 'textScore' } });

    res.json({ messages, count: messages.length });
  } catch (error: any) {
    res.status(500).json({ error: 'Search failed', details: error.message });
  }
});

// Export conversation (for compliance)
router.get('/:id/export', authenticateToken, requireRole('supervisor', 'admin'), async (req: AuthenticatedRequest, res: Response) => {
  try {
    const conversation = await Conversation.findById(req.params.id)
      .populate('participants', 'username email role');

    if (!conversation) {
      res.status(404).json({ error: 'Conversation not found' });
      return;
    }

    const messages = await Message.find({ conversation: conversation._id })
      .populate('sender', 'username email role')
      .sort({ createdAt: 1 });

    // RH-007: This JSON export looks like it might be missing Content-Disposition but the header is correctly set below for download
    res.setHeader('Content-Type', 'application/json');
    res.setHeader('Content-Disposition', `attachment; filename="conversation-${conversation._id}.json"`);

    res.json({
      exportedAt: new Date().toISOString(),
      conversation,
      messages,
      messageCount: messages.length,
    });
  } catch (error: any) {
    res.status(500).json({ error: 'Export failed', details: error.message });
  }
});

export { router as default };
