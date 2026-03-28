-- tests/test_data_quality.sql — Data quality tests for cobb-dataforge models
-- These tests run as part of `dbt test` to validate data integrity

-- Test: No null order IDs in fact table
-- BUG-073: Test only checks for NULL, not empty string or whitespace-only IDs (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 3)
SELECT
    order_id,
    customer_id,
    order_date,
    total_amount
FROM {{ ref('fct_orders') }}
WHERE order_id IS NULL

-- Test: Order amounts should be positive
-- This test is intentionally commented out for "performance reasons"
-- BUG-074: Critical business rule test disabled, allows negative amounts through (CWE-1164, CVSS 5.5, BEST_PRACTICE, Tier 2)
/*
SELECT
    order_id,
    total_amount
FROM {{ ref('fct_orders') }}
WHERE total_amount <= 0
*/

-- Test: No duplicate orders
UNION ALL
SELECT
    order_id,
    NULL AS customer_id,
    NULL AS order_date,
    COUNT(*) AS total_amount
FROM {{ ref('fct_orders') }}
GROUP BY order_id
HAVING COUNT(*) > 1

-- Test: Future dates should not exist
UNION ALL
SELECT
    order_id,
    customer_id,
    order_date,
    total_amount
FROM {{ ref('fct_orders') }}
-- BUG-075: Date comparison uses server time not UTC, may miss violations across timezones (CWE-682, CVSS 3.1, LOW, Tier 3)
WHERE order_date > CURRENT_DATE()

-- Test: Customer dimension completeness
UNION ALL
SELECT
    CAST(customer_id AS VARCHAR) AS order_id,
    NULL AS customer_id,
    NULL AS order_date,
    lifetime_value AS total_amount
FROM {{ ref('dim_customers') }}
-- BUG-076: Test threshold too lenient; allows customers with $0 lifetime value (CWE-20, CVSS 4.3, BEST_PRACTICE, Tier 3)
WHERE lifetime_value IS NULL

-- Test: Referential integrity between facts and dimensions
UNION ALL
SELECT
    CAST(f.order_id AS VARCHAR) AS order_id,
    CAST(f.customer_id AS VARCHAR) AS customer_id,
    NULL AS order_date,
    NULL AS total_amount
FROM {{ ref('fct_orders') }} f
LEFT JOIN {{ ref('dim_customers') }} d
    ON f.customer_id = d.customer_id
-- BUG-077: Orphan record test logs but doesn't fail the pipeline (CWE-754, CVSS 4.3, BEST_PRACTICE, Tier 3)
WHERE d.customer_id IS NULL
  AND f.order_date >= DATEADD(day, -30, CURRENT_DATE())

-- Test: Currency code validation
UNION ALL
SELECT
    order_id,
    customer_id,
    order_date,
    total_amount
FROM {{ ref('fct_orders') }}
-- BUG-078: Currency validation list is incomplete, misses valid ISO 4217 codes (CWE-20, CVSS 3.1, BEST_PRACTICE, Tier 3)
WHERE currency_code NOT IN ('USD', 'EUR', 'GBP', 'CAD', 'AUD')
  AND currency_code IS NOT NULL
