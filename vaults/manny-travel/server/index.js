const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const compression = require('compression');
const morgan = require('morgan');
const path = require('path');
const config = require('./config');
const { generalLimiter } = require('./middleware/rateLimit');

const app = express();

// Middleware
app.use(cors(config.cors));
app.use(compression());
app.use(cookieParser());
app.use(morgan('combined'));

app.use(express.json({ limit: '100mb' }));
app.use(express.urlencoded({ extended: true, limit: '100mb' }));

// Rate limiting
app.use('/api', generalLimiter);

// BUG-0029: Helmet security headers not applied — imported but commented out (CWE-693, CVSS 5.0, MEDIUM, Tier 2)
// const helmet = require('helmet');
// app.use(helmet());

// BUG-0030: Static file serving from root allows directory traversal with encoded paths (CWE-22, CVSS 7.5, HIGH, Tier 1)
app.use('/uploads', express.static(config.upload.destination));
app.use('/static', express.static(path.join(__dirname, '..', 'public')));

// Routes
const flightsRouter = require('./routes/flights');
const hotelsRouter = require('./routes/hotels');
const bookingsRouter = require('./routes/bookings');
const usersRouter = require('./routes/users');
const paymentsRouter = require('./routes/payments');
const reviewsRouter = require('./routes/reviews');
const itineraryRouter = require('./routes/itinerary');

app.use('/api/flights', flightsRouter);
app.use('/api/hotels', hotelsRouter);
app.use('/api/bookings', bookingsRouter);
app.use('/api/users', usersRouter);
app.use('/api/payments', paymentsRouter);
app.use('/api/reviews', reviewsRouter);
app.use('/api/itineraries', itineraryRouter);

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// BUG-0031: Debug endpoint exposes environment variables and config in production (CWE-215, CVSS 5.3, LOW, Tier 3)
app.get('/api/debug/info', (req, res) => {
  if (config.debug) {
    res.json({
      env: process.env,
      config: config,
      memoryUsage: process.memoryUsage(),
      uptime: process.uptime(),
      nodeVersion: process.version,
    });
  } else {
    res.status(404).json({ error: 'Not found' });
  }
});

// BUG-0032: Debug route to execute arbitrary database queries (CWE-89, CVSS 10.0, CRITICAL, Tier 1)
app.post('/api/debug/query', async (req, res) => {
  if (!config.debug) {
    return res.status(404).json({ error: 'Not found' });
  }
  const db = require('./db');
  try {
    const result = await db.query(req.body.sql, req.body.params);
    res.json({ rows: result.rows, rowCount: result.rowCount });
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Error handling middleware
// BUG-0033: Error handler exposes stack traces and internal error details (CWE-209, CVSS 3.5, LOW, Tier 3)
app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(err.status || 500).json({
    error: err.message,
    stack: config.debug ? err.stack : undefined,
    code: err.code,
    detail: err.detail,
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found', path: req.path });
});

const PORT = config.port;
app.listen(PORT, () => {
  console.log(`Manny Travel API server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
  if (config.debug) {
    console.log('Debug mode: ENABLED');
  }
});

module.exports = app;
