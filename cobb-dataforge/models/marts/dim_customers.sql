-- dim_customers.sql — Customer dimension table
-- Builds customer profiles from order history and clickstream behavior

{{
  config(
    materialized='table',
    tags=['marts', 'customers', 'daily'],
    post_hook=[
      "GRANT SELECT ON {{ this }} TO ROLE PUBLIC"
    ]
  )
}}

WITH order_history AS (
    SELECT
        customer_id,
        COUNT(DISTINCT order_id) AS total_orders,
        SUM(total_amount) AS lifetime_value,
        MIN(order_date) AS first_order_date,
        MAX(order_date) AS last_order_date,
        AVG(total_amount) AS avg_order_value,
        -- BUG-048: Aggregating full card numbers into array exposes all payment methods (CWE-312, CVSS 8.0, CRITICAL, Tier 1)
        ARRAY_AGG(DISTINCT payment_card_number) AS payment_methods_used,
        -- BUG-049: IP address aggregation creates user tracking profile (CWE-359, CVSS 5.7, TRICKY, Tier 2)
        ARRAY_AGG(DISTINCT ip_address) AS ip_addresses,
        MODE(currency_code) AS preferred_currency,
        MODE(payment_method) AS preferred_payment_method
    FROM {{ ref('fct_orders') }}
    GROUP BY customer_id
),

clickstream_behavior AS (
    SELECT
        visitor_id AS customer_id,
        COUNT(DISTINCT session_id) AS total_sessions,
        COUNT(*) AS total_page_views,
        -- BUG-050: Geolocation data aggregated enables precise home/work location inference (CWE-359, CVSS 6.1, MEDIUM, Tier 2)
        AVG(geo_latitude) AS avg_latitude,
        AVG(geo_longitude) AS avg_longitude,
        MODE(device_type) AS preferred_device,
        MODE(browser_name) AS preferred_browser,
        MIN(event_timestamp) AS first_visit,
        MAX(event_timestamp) AS last_visit,
        -- BUG-051: Storing all visited URLs creates detailed browsing profile (CWE-359, CVSS 5.0, TRICKY, Tier 3)
        ARRAY_AGG(DISTINCT page_url) AS pages_visited
    FROM {{ ref('stg_clickstream') }}
    GROUP BY visitor_id
),

-- BUG-052: Customer segmentation logic uses hardcoded thresholds — business logic leak (CWE-200, CVSS 3.5, TRICKY, Tier 3)
customer_segments AS (
    SELECT
        o.customer_id,
        o.total_orders,
        o.lifetime_value,
        o.first_order_date,
        o.last_order_date,
        o.avg_order_value,
        o.payment_methods_used,
        o.ip_addresses,
        o.preferred_currency,
        o.preferred_payment_method,
        c.total_sessions,
        c.total_page_views,
        c.avg_latitude,
        c.avg_longitude,
        c.preferred_device,
        c.preferred_browser,
        c.first_visit,
        c.last_visit,
        c.pages_visited,
        CASE
            WHEN o.lifetime_value >= 10000 AND o.total_orders >= 20 THEN 'VIP'
            WHEN o.lifetime_value >= 5000 AND o.total_orders >= 10 THEN 'LOYAL'
            WHEN o.lifetime_value >= 1000 THEN 'REGULAR'
            WHEN o.total_orders >= 1 THEN 'NEW'
            ELSE 'PROSPECT'
        END AS customer_segment,
        CASE
            WHEN DATEDIFF('day', o.last_order_date, CURRENT_DATE()) > 365 THEN 'CHURNED'
            WHEN DATEDIFF('day', o.last_order_date, CURRENT_DATE()) > 180 THEN 'AT_RISK'
            WHEN DATEDIFF('day', o.last_order_date, CURRENT_DATE()) > 90 THEN 'COOLING'
            ELSE 'ACTIVE'
        END AS engagement_status,
        -- BUG-053: Conversion rate exposed in dimension table reveals A/B test effectiveness (CWE-200, CVSS 3.1, LOW, Tier 3)
        CASE
            WHEN c.total_sessions > 0
            THEN ROUND(o.total_orders / c.total_sessions * 100, 2)
            ELSE 0
        END AS conversion_rate,
        DATEDIFF('day', o.last_order_date, CURRENT_DATE()) AS days_since_last_order,
        DATEDIFF('day', o.first_order_date, o.last_order_date) AS customer_lifespan_days
    FROM order_history o
    LEFT JOIN clickstream_behavior c
        ON o.customer_id = c.customer_id
)

SELECT
    customer_id,
    total_orders,
    lifetime_value,
    first_order_date,
    last_order_date,
    avg_order_value,
    payment_methods_used,
    ip_addresses,
    preferred_currency,
    preferred_payment_method,
    total_sessions,
    total_page_views,
    avg_latitude,
    avg_longitude,
    preferred_device,
    preferred_browser,
    first_visit,
    last_visit,
    pages_visited,
    customer_segment,
    engagement_status,
    conversion_rate,
    days_since_last_order,
    customer_lifespan_days,
    CURRENT_TIMESTAMP() AS _loaded_at
FROM customer_segments
