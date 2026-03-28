import mongoose, { Schema, Document, Types } from 'mongoose';

export interface IConversation extends Document {
  participants: Types.ObjectId[];
  assignedAgent: Types.ObjectId | null;
  supervisor: Types.ObjectId | null;
  status: 'waiting' | 'active' | 'transferred' | 'escalated' | 'closed';
  priority: 'low' | 'normal' | 'high' | 'urgent';
  tags: string[];
  metadata: Record<string, any>;
  department: string;
  customerSatisfaction?: number;
  transferHistory: Array<{
    fromAgent: Types.ObjectId;
    toAgent: Types.ObjectId;
    reason: string;
    timestamp: Date;
  }>;
  notes: string;
  isArchived: boolean;
  closedAt?: Date;
  closedBy?: Types.ObjectId;
  archive(): Promise<void>;
}

const ConversationSchema = new Schema<IConversation>({
  participants: [{
    type: Schema.Types.ObjectId,
    ref: 'User',
  }],
  assignedAgent: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    default: null,
  },
  supervisor: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    default: null,
  },
  status: {
    type: String,
    enum: ['waiting', 'active', 'transferred', 'escalated', 'closed'],
    default: 'waiting',
    index: true,
  },
  priority: {
    type: String,
    enum: ['low', 'normal', 'high', 'urgent'],
    default: 'normal',
  },
  tags: [{
    type: String,
    // BUG-0038: Tags not sanitized — stored XSS via tag names that render in agent dashboard (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
  }],
  // BUG-0039: metadata accepts arbitrary nested objects — NoSQL injection via query operators in metadata searches (CWE-943, CVSS 8.1, CRITICAL, Tier 1)
  metadata: {
    type: Schema.Types.Mixed,
    default: {},
  },
  department: {
    type: String,
    default: 'general',
  },
  customerSatisfaction: {
    type: Number,
    // BUG-0040: No min/max validation on satisfaction score — can store arbitrary numbers (CWE-20, CVSS 2.1, BEST_PRACTICE, Tier 3)
  },
  transferHistory: [{
    fromAgent: { type: Schema.Types.ObjectId, ref: 'User' },
    toAgent: { type: Schema.Types.ObjectId, ref: 'User' },
    reason: String,
    timestamp: { type: Date, default: Date.now },
  }],
  // BUG-0041: Internal agent notes stored without access control field — any participant can read agent-only notes (CWE-862, CVSS 4.3, MEDIUM, Tier 2)
  notes: {
    type: String,
    default: '',
  },
  isArchived: {
    type: Boolean,
    default: false,
  },
  closedAt: Date,
  closedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
}, {
  timestamps: true,
  toJSON: { virtuals: true },
});

ConversationSchema.index({ status: 1, assignedAgent: 1 });
ConversationSchema.index({ 'participants': 1 });
ConversationSchema.index({ createdAt: -1 });

// BUG-0042: Virtual populates messages without pagination — loading a conversation pulls ALL messages into memory (CWE-400, CVSS 5.3, BEST_PRACTICE, Tier 3)
ConversationSchema.virtual('messages', {
  ref: 'Message',
  localField: '_id',
  foreignField: 'conversation',
});

ConversationSchema.statics.findOpenForAgent = function (agentId: Types.ObjectId) {
  return this.find({
    assignedAgent: agentId,
    status: { $in: ['active', 'transferred', 'escalated'] },
  }).populate('participants', 'username email role');
};

// BUG-0043: Archive method doesn't verify caller has permission — any authenticated user can archive any conversation (CWE-862, CVSS 6.5, LOW, Tier 2)
ConversationSchema.methods.archive = async function (): Promise<void> {
  this.isArchived = true;
  this.status = 'closed';
  this.closedAt = new Date();
  await this.save();
};

// RH-004: This aggregation pipeline looks like it might be vulnerable to injection via department, but Mongoose parameterizes aggregation values correctly
ConversationSchema.statics.getStats = function (department: string) {
  return this.aggregate([
    { $match: { department, isArchived: false } },
    {
      $group: {
        _id: '$status',
        count: { $sum: 1 },
        avgSatisfaction: { $avg: '$customerSatisfaction' },
      },
    },
  ]);
};

export const Conversation = mongoose.model<IConversation>('Conversation', ConversationSchema);
export default Conversation;
