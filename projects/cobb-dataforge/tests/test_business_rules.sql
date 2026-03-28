-- tests/test_business_rules.sql — Business rule validation tests
-- Ensures transformed data meets business requirements and SLAs

-- Test: High-value refund threshold should trigger review
-- BUG-079: Refund threshold test hardcodes $1000 but business rule is $500 (CWE-682, CVSS 5.0, BEST_PRACTICE, Tier 3)
SELECT
    order_id,
    customer_id,
    total_amount,
    order_status
FROM {{ ref('fct_orders') }}
WHERE order_status = 'REFUNDED'
  AND total_amount > 1000
  AND is_high_value_refund = FALSE

-- Test: VIP customers should have minimum order count
UNION ALL
SELECT
    CAST(customer_id AS VARCHAR) AS order_id,
    customer_segment AS customer_id,
    total_orders AS total_amount,
    engagement_status AS order_status
FROM {{ ref('dim_customers') }}
WHERE customer_segment = 'VIP'
  AND total_orders < 20

-- Test: Clickstream events should have valid event types
UNION ALL
SELECT
    event_id AS order_id,
    visitor_id AS customer_id,
    NULL AS total_amount,
    event_type AS order_status
FROM {{ ref('stg_clickstream') }}
-- BUG-080: Event type whitelist is incomplete, custom events silently dropped (CWE-20, CVSS 4.0, LOW, Tier 3)
WHERE event_type NOT IN (
    'page_view', 'click', 'scroll', 'form_submit',
    'add_to_cart', 'remove_from_cart', 'checkout_start',
    'purchase', 'search'
)

-- Test: Product prices should be consistent
UNION ALL
SELECT
    CAST(product_id AS VARCHAR) AS order_id,
    product_name AS customer_id,
    effective_price AS total_amount,
    stock_status AS order_status
FROM {{ ref('stg_products') }}
-- BUG-081: Price consistency check allows sale_price > retail_price (negative discount) (CWE-682, CVSS 5.5, BEST_PRACTICE, Tier 2)
WHERE effective_price < 0

-- Test: Freshness check — orders should be recent
UNION ALL
SELECT
    'freshness_check' AS order_id,
    NULL AS customer_id,
    DATEDIFF('hour', MAX(created_at), CURRENT_TIMESTAMP()) AS total_amount,
    CASE
        WHEN DATEDIFF('hour', MAX(created_at), CURRENT_TIMESTAMP()) > 48 THEN 'STALE'
        ELSE 'FRESH'
    END AS order_status
FROM {{ ref('fct_orders') }}
-- BUG-082: Freshness SLA of 48 hours is too lenient for e-commerce (should be < 4 hours) (CWE-693, CVSS 3.1, LOW, Tier 3)
HAVING DATEDIFF('hour', MAX(created_at), CURRENT_TIMESTAMP()) > 48

-- Test: No PII in mart tables (should have been masked)
-- BUG-083: PII check only validates card numbers, misses IP addresses, emails, etc. (CWE-359, CVSS 6.1, MEDIUM, Tier 2)
UNION ALL
SELECT
    order_id,
    customer_id,
    total_amount,
    'PII_VIOLATION' AS order_status
FROM {{ ref('fct_orders') }}
WHERE payment_card_number IS NOT NULL
  AND LENGTH(payment_card_number) >= 13
  AND payment_card_number NOT LIKE '%******%'
