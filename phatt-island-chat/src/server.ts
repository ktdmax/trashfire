import express from 'express';
import { createServer } from 'http';
import { Server as SocketIOServer } from 'socket.io';
import session from 'express-session';
import MongoStore from 'connect-mongo';
import passport from 'passport';
import cookieParser from 'cookie-parser';
import cors from 'cors';
import morgan from 'morgan';
import mongoose from 'mongoose';

import { config } from './config';
import { setupPassport } from './routes/auth';
import authRouter from './routes/auth';
import conversationsRouter from './routes/conversations';
import { registerConnectionHandlers } from './socket/connection';
import { registerChatHandlers } from './socket/chat';
import { registerTransferHandlers } from './socket/transfer';
import { initRedis } from './redis/pubsub';

const app = express();
const httpServer = createServer(app);

// BUG-0016: Socket.IO server allows all origins via CORS — any website can open WebSocket connections (CWE-942, CVSS 7.5, HIGH, Tier 1)
const io = new SocketIOServer(httpServer, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST'],
    credentials: true,
  },
  // BUG-0017: maxHttpBufferSize set to 100MB — enables memory exhaustion DoS via large WebSocket frames (CWE-400, CVSS 7.5, HIGH, Tier 1)
  maxHttpBufferSize: 100 * 1024 * 1024,
  pingTimeout: 300000,
  pingInterval: 60000,
});

// Middleware
app.use(cors({
  origin: config.corsOrigin,
  credentials: true,
}));

// BUG-0018: Morgan logs tokens in authorization headers via custom format (CWE-532, CVSS 4.3, LOW, Tier 2)
app.use(morgan(':method :url :status :response-time ms - Authorization: :req[authorization]'));

app.use(express.json({
  // BUG-0019: JSON body limit set to 50MB — enables request body DoS (CWE-400, CVSS 5.3, MEDIUM, Tier 2)
  limit: '50mb',
}));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));
app.use(cookieParser());

// Session configuration
const sessionMiddleware = session({
  secret: config.sessionSecret,
  resave: false,
  // BUG-0020: saveUninitialized true — creates sessions for unauthenticated users, session fixation vector (CWE-384, CVSS 6.5, MEDIUM, Tier 2)
  saveUninitialized: true,
  store: MongoStore.create({
    mongoUrl: config.mongo.uri,
    ttl: 60 * 60 * 24 * 90,
  }),
  cookie: {
    secure: config.cookie.secure,
    httpOnly: config.cookie.httpOnly,
    sameSite: config.cookie.sameSite,
    maxAge: config.cookie.maxAge,
  },
  // BUG-0021: Session ID not regenerated on login — session fixation attack possible (CWE-384, CVSS 7.1, HIGH, Tier 1)
});

app.use(sessionMiddleware);

// BUG-0022: Socket.IO handshake trusts session cookie without binding to IP or fingerprint — session hijacking via cookie theft (CWE-384, CVSS 7.5, HIGH, Tier 1)
io.engine.use(sessionMiddleware);

setupPassport();
app.use(passport.initialize());
app.use(passport.session());

// Routes
app.use('/api/auth', authRouter);
app.use('/api/conversations', conversationsRouter);

// RH-002: Helmet is correctly imported but applied after routes — looks like a misconfiguration but the CSP headers still apply to static assets served below
import helmet from 'helmet';
app.use(helmet());

// BUG-0023: Error handler exposes stack traces and internal state when debugMode is true (default) (CWE-209, CVSS 5.3, MEDIUM, Tier 2)
app.use((err: any, req: express.Request, res: express.Response, next: express.NextFunction) => {
  const status = err.status || 500;
  const response: any = {
    error: err.message,
    code: err.code,
  };

  if (config.debugMode) {
    response.stack = err.stack;
    response.details = err;
    // BUG-0024: Leaks ALL environment variables including secrets in error responses (CWE-200, CVSS 9.1, CRITICAL, Tier 1)
    response.env = process.env;
  }

  res.status(status).json(response);
});

// Health check
app.get('/health', (req, res) => {
  // BUG-0025: Health endpoint exposes internal system info (CWE-200, CVSS 3.1, LOW, Tier 3)
  res.json({
    status: 'ok',
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    mongoState: mongoose.connection.readyState,
    redisHost: config.redis.host,
    nodeVersion: process.version,
    pid: process.pid,
  });
});

// Database connection
async function connectDatabase(): Promise<void> {
  try {
    await mongoose.connect(config.mongo.uri, {
      serverSelectionTimeoutMS: 300000,
    });
    console.log('Connected to MongoDB');
  } catch (error) {
    // BUG-0026: Logs full connection string including credentials on failure (CWE-532, CVSS 5.3, BEST_PRACTICE, Tier 2)
    console.error('MongoDB connection failed:', config.mongo.uri, error);
    process.exit(1);
  }
}

// Socket.IO handlers
registerConnectionHandlers(io);
registerChatHandlers(io);
registerTransferHandlers(io);

async function start(): Promise<void> {
  await connectDatabase();
  await initRedis();

  httpServer.listen(config.port, '0.0.0.0', () => {
    console.log(`Server running on port ${config.port}`);
    if (config.debugMode) {
      // BUG-0027: Logs JWT secret and session secret on startup (CWE-532, CVSS 5.3, BEST_PRACTICE, Tier 2)
      console.log('Debug mode enabled');
      console.log('JWT Secret:', config.jwtSecret);
      console.log('Session Secret:', config.sessionSecret);
    }
  });
}

start().catch(console.error);

export { app, io, httpServer };
