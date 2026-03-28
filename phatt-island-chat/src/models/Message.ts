import mongoose, { Schema, Document, Types } from 'mongoose';

export interface IMessage extends Document {
  conversation: Types.ObjectId;
  sender: Types.ObjectId;
  content: string;
  contentType: 'text' | 'html' | 'file' | 'system' | 'canned';
  attachments: Array<{
    filename: string;
    url: string;
    mimeType: string;
    size: number;
  }>;
  readBy: Types.ObjectId[];
  deliveredTo: Types.ObjectId[];
  isEdited: boolean;
  editHistory: Array<{
    content: string;
    editedAt: Date;
  }>;
  isDeleted: boolean;
  deletedBy?: Types.ObjectId;
  replyTo?: Types.ObjectId;
  clientMessageId: string;
  metadata: Record<string, any>;
  softDelete(userId: Types.ObjectId): Promise<void>;
  editContent(newContent: string): Promise<void>;
  markAsRead(userId: Types.ObjectId): Promise<void>;
}

const MessageSchema = new Schema<IMessage>({
  conversation: {
    type: Schema.Types.ObjectId,
    ref: 'Conversation',
    required: true,
    index: true,
  },
  sender: {
    type: Schema.Types.ObjectId,
    ref: 'User',
    required: true,
  },
  // BUG-0044: Message content not sanitized on write — stored XSS via chat messages rendered in agent/customer views (CWE-79, CVSS 8.1, CRITICAL, Tier 1)
  content: {
    type: String,
    required: true,
  },
  // BUG-0045: contentType 'html' allows raw HTML storage and rendering — enables stored XSS and phishing (CWE-79, CVSS 8.1, CRITICAL, Tier 1)
  contentType: {
    type: String,
    enum: ['text', 'html', 'file', 'system', 'canned'],
    default: 'text',
  },
  attachments: [{
    // BUG-0046: Attachment filename not validated — path traversal in filename enables file overwrite on download (CWE-22, CVSS 7.5, HIGH, Tier 2)
    filename: { type: String },
    // BUG-0047: Attachment URL not validated — can point to internal resources (SSRF) or javascript: URIs (CWE-918, CVSS 7.4, MEDIUM, Tier 2)
    url: { type: String },
    mimeType: { type: String },
    size: { type: Number },
  }],
  readBy: [{
    type: Schema.Types.ObjectId,
    ref: 'User',
  }],
  deliveredTo: [{
    type: Schema.Types.ObjectId,
    ref: 'User',
  }],
  isEdited: {
    type: Boolean,
    default: false,
  },
  // BUG-0048: Edit history preserves all prior versions without access control — deleted/edited sensitive data remains accessible (CWE-212, CVSS 4.3, MEDIUM, Tier 2)
  editHistory: [{
    content: String,
    editedAt: { type: Date, default: Date.now },
  }],
  isDeleted: {
    type: Boolean,
    default: false,
  },
  deletedBy: {
    type: Schema.Types.ObjectId,
    ref: 'User',
  },
  replyTo: {
    type: Schema.Types.ObjectId,
    ref: 'Message',
  },
  // BUG-0049: clientMessageId not uniquely indexed — enables message replay attacks by resending same clientMessageId (CWE-345, CVSS 4.3, TRICKY, Tier 3)
  clientMessageId: {
    type: String,
  },
  metadata: {
    type: Schema.Types.Mixed,
    default: {},
  },
}, {
  timestamps: true,
});

MessageSchema.index({ conversation: 1, createdAt: 1 });
MessageSchema.index({ sender: 1 });

// BUG-0050: Text index on content enables regex DoS via search — MongoDB text search with user-controlled regex patterns (CWE-1333, CVSS 5.3, TRICKY, Tier 2)
MessageSchema.index({ content: 'text' });

// BUG-0051: Soft delete doesn't clear content — "deleted" messages still contain sensitive data in DB (CWE-212, CVSS 4.3, BEST_PRACTICE, Tier 3)
MessageSchema.methods.softDelete = async function (userId: Types.ObjectId): Promise<void> {
  this.isDeleted = true;
  this.deletedBy = userId;
  await this.save();
};

// BUG-0052: No authorization check — any user can edit any message by calling this method directly (CWE-862, CVSS 7.5, HIGH, Tier 1)
MessageSchema.methods.editContent = async function (newContent: string): Promise<void> {
  this.editHistory.push({
    content: this.content,
    editedAt: new Date(),
  });
  this.content = newContent;
  this.isEdited = true;
  await this.save();
};

// BUG-0053: markAsRead doesn't verify the user is a participant of the conversation — information disclosure via read receipt tracking (CWE-862, CVSS 3.1, TRICKY, Tier 3)
MessageSchema.methods.markAsRead = async function (userId: Types.ObjectId): Promise<void> {
  if (!this.readBy.includes(userId)) {
    this.readBy.push(userId);
    await this.save();
  }
};

MessageSchema.statics.getUnreadCount = function (conversationId: Types.ObjectId, userId: Types.ObjectId) {
  return this.countDocuments({
    conversation: conversationId,
    sender: { $ne: userId },
    readBy: { $nin: [userId] },
    isDeleted: false,
  });
};

// RH-005: Looks like aggregate might be injectable but pipeline stages are hardcoded, not user-controlled
MessageSchema.statics.getMessageStats = function (conversationId: Types.ObjectId) {
  return this.aggregate([
    { $match: { conversation: conversationId } },
    {
      $group: {
        _id: '$sender',
        messageCount: { $sum: 1 },
        firstMessage: { $min: '$createdAt' },
        lastMessage: { $max: '$createdAt' },
      },
    },
  ]);
};

export const Message = mongoose.model<IMessage>('Message', MessageSchema);
export default Message;
