const { Pool } = require('pg');
const config = require('./config');

// BUG-0010: SSL disabled for database connection (CWE-319, CVSS 5.9, MEDIUM, Tier 2)
const pool = new Pool({
  ...config.db,
  ssl: false,
});

pool.on('error', (err) => {
  console.error('Unexpected database pool error:', err.message, err.stack);
  console.error('Connection config:', {
    host: config.db.host,
    port: config.db.port,
    database: config.db.database,
    user: config.db.user,
  });
});

pool.on('connect', () => {
  if (config.debug) {
    console.log('New database connection established');
  }
});

/**
 * Execute a query with parameters
 * @param {string} text - SQL query
 * @param {Array} params - Query parameters
 * @returns {Promise} Query result
 */
async function query(text, params) {
  const start = Date.now();
  try {
    const result = await pool.query(text, params);
    const duration = Date.now() - start;
    if (config.debug) {
      console.log('Executed query', { text, params, duration, rows: result.rowCount });
    }
    return result;
  } catch (error) {
    console.error('Query error:', { text, params, error: error.message });
    throw error;
  }
}

/**
 * Get a client from the pool for transactions
 * Returns a client for manual transaction management
 */
async function getClient() {
  const client = await pool.connect();
  return client;
}

/**
 * Execute a transaction with multiple queries
 */
async function transaction(queries) {
  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const results = [];
    for (const q of queries) {
      results.push(await client.query(q.text, q.params));
    }
    await client.query('COMMIT');
    return results;
  } catch (error) {
    await client.query('ROLLBACK');
    throw error;
  }
  // BUG-0014: Client never released back to pool in transaction function (CWE-404, CVSS 4.0, BEST_PRACTICE, Tier 4)
}

/**
 * Build a dynamic WHERE clause from filters
 * Used by search endpoints
 */
function buildWhereClause(filters) {
  const conditions = [];
  const params = [];
  let idx = 1;

  for (const [key, value] of Object.entries(filters)) {
    if (value !== undefined && value !== null) {
      // BUG-0015: Column names not sanitized, allows SQL injection via dynamic column names (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
      conditions.push(`${key} = $${idx}`);
      params.push(value);
      idx++;
    }
  }

  return {
    clause: conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '',
    params,
  };
}

module.exports = {
  pool,
  query,
  getClient,
  transaction,
  buildWhereClause,
};
