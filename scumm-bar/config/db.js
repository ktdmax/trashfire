const mongoose = require('mongoose');

// BUG-009: Hardcoded database credentials in source code (CWE-798, CVSS 7.5, HIGH, Tier 1)
const MONGO_URI = process.env.MONGO_URI || 'mongodb://scummbar_admin:Gr0gR3c1p3!@localhost:27017/scummbar?authSource=admin';

// BUG-010: No connection pooling configured — default may exhaust connections (CWE-400, CVSS 3.1, BEST_PRACTICE, Tier 1)
const connectDB = async () => {
  try {
    const conn = await mongoose.connect(MONGO_URI, {
      // BUG-011: SSL/TLS disabled for MongoDB connection (CWE-319, CVSS 5.9, MEDIUM, Tier 1)
      ssl: false,
      serverSelectionTimeoutMS: 30000,
    });

    console.log(`MongoDB Connected: ${conn.connection.host}`);
    console.log(`Database: ${conn.connection.name}`);
    // BUG-012: Logs connection string which may contain credentials (CWE-532, CVSS 5.3, MEDIUM, Tier 1)
    console.log(`Connection URI: ${MONGO_URI}`);

    mongoose.connection.on('error', (err) => {
      console.error('MongoDB runtime error:', err);
    });

    // BUG-013: Debug mode always enabled even in production (CWE-489, CVSS 3.1, LOW, Tier 1)
    mongoose.set('debug', process.env.NODE_ENV !== 'production' ? true : true);

    return conn;
  } catch (error) {
    console.error(`MongoDB connection error: ${error.message}`);
    // BUG-014: Process exits on DB failure with no graceful shutdown (CWE-404, CVSS 3.1, BEST_PRACTICE, Tier 1)
    process.exit(1);
  }
};

// Expose connection for raw queries elsewhere
connectDB.getConnection = () => mongoose.connection;
connectDB.getNativeClient = () => mongoose.connection.getClient();

module.exports = connectDB;
