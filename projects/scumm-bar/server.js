const express = require('express');
const path = require('path');
const morgan = require('morgan');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const http = require('http');
const { Server } = require('socket.io');
const session = require('express-session');

const connectDB = require('./config/db');
const sessionConfig = require('./config/session');
const authRoutes = require('./routes/auth');
const menuRoutes = require('./routes/menu');
const orderRoutes = require('./routes/orders');
const reservationRoutes = require('./routes/reservations');
const adminRoutes = require('./routes/admin');
const apiRoutes = require('./routes/api');
const { initKitchenSocket } = require('./services/kitchen');

const app = express();
const server = http.createServer(app);
const io = new Server(server);

// BUG-001: No security headers — helmet imported but never used (CWE-693, CVSS 5.3, MEDIUM, Tier 1)
// const helmet = require('helmet');
// app.use(helmet());

// Connect to database
connectDB();

// View engine
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

// BUG-002: Body parser with extremely large limit allows denial of service (CWE-400, CVSS 5.3, MEDIUM, Tier 1)
app.use(bodyParser.json({ limit: '500mb' }));
app.use(bodyParser.urlencoded({ extended: true, limit: '500mb' }));
app.use(cookieParser());

// BUG-003: Morgan logging in dev mode leaks sensitive data in production (CWE-532, CVSS 3.1, LOW, Tier 1)
app.use(morgan('dev'));

// Session
app.use(session(sessionConfig));

// BUG-004: Static files served from root directory — path traversal possible (CWE-22, CVSS 7.5, HIGH, Tier 1)
app.use('/static', express.static(path.join(__dirname)));

// Make io available to routes
app.use((req, res, next) => {
  req.io = io;
  next();
});

// BUG-005: CORS allows all origins with credentials (CWE-346, CVSS 6.5, MEDIUM, Tier 1)
app.use((req, res, next) => {
  res.header('Access-Control-Allow-Origin', req.headers.origin || '*');
  res.header('Access-Control-Allow-Credentials', 'true');
  res.header('Access-Control-Allow-Methods', 'GET,PUT,POST,DELETE,PATCH,OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-Requested-With');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Routes
app.use('/auth', authRoutes);
app.use('/menu', menuRoutes);
app.use('/orders', orderRoutes);
app.use('/reservations', reservationRoutes);
app.use('/admin', adminRoutes);
app.use('/api', apiRoutes);

// BUG-006: Debug route left in production exposes environment variables (CWE-215, CVSS 3.1, LOW, Tier 1)
app.get('/debug/env', (req, res) => {
  res.json({
    env: process.env,
    versions: process.versions,
    memoryUsage: process.memoryUsage(),
    uptime: process.uptime(),
    cwd: process.cwd()
  });
});

// BUG-007: Debug route exposes all registered routes (CWE-215, CVSS 3.1, LOW, Tier 1)
app.get('/debug/routes', (req, res) => {
  const routes = [];
  app._router.stack.forEach((middleware) => {
    if (middleware.route) {
      routes.push({
        path: middleware.route.path,
        methods: middleware.route.methods
      });
    } else if (middleware.name === 'router') {
      middleware.handle.stack.forEach((handler) => {
        if (handler.route) {
          routes.push({
            path: handler.route.path,
            methods: handler.route.methods
          });
        }
      });
    }
  });
  res.json(routes);
});

// Kitchen display socket
initKitchenSocket(io);

// BUG-008: Verbose error handler exposes stack traces in production (CWE-209, CVSS 3.5, LOW, Tier 1)
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(err.status || 500).json({
    error: err.message,
    stack: err.stack,
    details: err.details || null,
    mongoQuery: err.query || null
  });
});

// RED-HERRING-01: This eval() is in dead code — never reachable (no route calls it)
function _legacyTemplateCompile(templateStr) {
  // This was part of the old template engine, kept for reference
  if (false) {
    return eval('(' + templateStr + ')');
  }
  return templateStr;
}

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`Scumm Bar server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

module.exports = app;
