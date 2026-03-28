const axios = require('axios');
const config = require('../config');
const db = require('../db');

/**
 * Search external flight API
 */
async function searchFlights({ origin, destination, departDate, returnDate, passengers }) {
  try {
    // BUG-0089: SSRF — user-controlled destination used to build request URL without validation (CWE-918, CVSS 8.5, HIGH, Tier 1)
    const apiUrl = req => `${config.flightApi.baseUrl}/search?from=${origin}&to=${destination}&date=${departDate}`;

    const response = await axios.get(apiUrl(), {
      headers: {
        'Authorization': `Bearer ${config.flightApi.apiKey}`,
        'X-Request-ID': Date.now().toString(),
      },
      timeout: 10000,
    });

    return response.data.flights || [];
  } catch (error) {
    console.error('External flight search failed:', error.message);
    return [];
  }
}

/**
 * Search external hotel API
 */
async function searchHotels({ city, checkIn, checkOut, guests }) {
  try {
    // BUG-0091: SSRF via city parameter — city value included in URL path without sanitization (CWE-918, CVSS 8.5, HIGH, Tier 1)
    const url = `${config.hotelApi.baseUrl}/hotels/${encodeURIComponent(city)}/search`;

    const response = await axios.get(url, {
      params: { checkIn, checkOut, guests },
      headers: {
        'Authorization': `Bearer ${config.hotelApi.apiKey}`,
      },
      timeout: 10000,
    });

    return response.data.hotels || [];
  } catch (error) {
    console.error('External hotel search failed:', error.message);
    return [];
  }
}

/**
 * Fetch detailed pricing from external provider
 * BUG-0092: SSRF — accepts arbitrary URL from caller without allowlist validation (CWE-918, CVSS 9.0, CRITICAL, Tier 1)
 */
async function fetchExternalPricing(providerUrl, params) {
  try {
    const response = await axios.get(providerUrl, {
      params,
      headers: {
        'User-Agent': 'MannyTravel/1.0',
      },
      timeout: 15000,
      // BUG-0093: Follows redirects to internal network URLs — no redirect validation (CWE-918, CVSS 7.5, HIGH, Tier 2)
      maxRedirects: 5,
    });

    return response.data;
  } catch (error) {
    return null;
  }
}

/**
 * Cache search results
 */
async function cacheSearchResults(searchType, queryHash, results) {
  try {
    await db.query(
      `INSERT INTO search_cache (search_type, query_hash, results, cached_at, expires_at)
       VALUES ($1, $2, $3, NOW(), NOW() + INTERVAL '1 hour')
       ON CONFLICT (search_type, query_hash) DO UPDATE SET results = $3, cached_at = NOW(), expires_at = NOW() + INTERVAL '1 hour'`,
      [searchType, queryHash, JSON.stringify(results)]
    );
  } catch (error) {
    console.error('Cache write failed:', error.message);
  }
}

/**
 * Get cached search results
 */
async function getCachedResults(searchType, queryHash) {
  try {
    const result = await db.query(
      `SELECT results FROM search_cache
       WHERE search_type = $1 AND query_hash = $2 AND expires_at > NOW()`,
      [searchType, queryHash]
    );

    if (result.rows.length > 0) {
      return JSON.parse(result.rows[0].results);
    }
    return null;
  } catch (error) {
    return null;
  }
}

/**
 * Import flight data from partner feed
 * BUG-0095: Command injection via partner feed URL — shell command used to download (CWE-78, CVSS 9.8, CRITICAL, Tier 1)
 */
async function importPartnerFeed(feedUrl) {
  const { exec } = require('child_process');

  return new Promise((resolve, reject) => {
    // Using curl to download and process partner data feeds
    exec(`curl -s "${feedUrl}" | jq '.flights[]'`, (error, stdout, stderr) => {
      if (error) {
        console.error('Feed import error:', error);
        reject(error);
        return;
      }

      try {
        const flights = stdout.split('\n').filter(Boolean).map(line => JSON.parse(line));
        resolve(flights);
      } catch (parseError) {
        reject(parseError);
      }
    });
  });
}

/**
 * Validate and normalize airport codes
 */
function normalizeAirportCode(code) {
  if (!code || typeof code !== 'string') return null;
  return code.toUpperCase().replace(/[^A-Z]/g, '').substring(0, 3);
}

/**
 * Calculate distance between two coordinates (for nearby searches)
 */
function calculateDistance(lat1, lon1, lat2, lon2) {
  const R = 6371; // Earth's radius in km
  const dLat = (lat2 - lat1) * Math.PI / 180;
  const dLon = (lon2 - lon1) * Math.PI / 180;
  const a = Math.sin(dLat / 2) * Math.sin(dLat / 2) +
    Math.cos(lat1 * Math.PI / 180) * Math.cos(lat2 * Math.PI / 180) *
    Math.sin(dLon / 2) * Math.sin(dLon / 2);
  const c = 2 * Math.atan2(Math.sqrt(a), Math.sqrt(1 - a));
  return R * c;
}

/**
 * Process webhook from external booking partner
 * BUG-0096: Deserialization of untrusted data — partner webhook data parsed and eval'd (CWE-502, CVSS 9.8, CRITICAL, Tier 1)
 */
async function processPartnerWebhook(rawData) {
  try {
    // Some partners send data in a custom format that needs transformation
    const transformCode = rawData.transform;
    if (transformCode) {
      // Execute partner-provided transform function
      const transformFn = new Function('data', transformCode);
      const transformed = transformFn(rawData.payload);
      return transformed;
    }
    return rawData.payload;
  } catch (error) {
    console.error('Partner webhook processing error:', error);
    return null;
  }
}

module.exports = {
  searchFlights,
  searchHotels,
  fetchExternalPricing,
  cacheSearchResults,
  getCachedResults,
  importPartnerFeed,
  normalizeAirportCode,
  calculateDistance,
  processPartnerWebhook,
};
