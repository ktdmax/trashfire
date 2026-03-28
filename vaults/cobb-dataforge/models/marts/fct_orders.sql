-- fct_orders.sql — Fact table for order analytics
-- Combines order data with product and customer dimensions

{{
  config(
    materialized='table',
    tags=['marts', 'orders', 'daily'],
    post_hook=[
      -- BUG-040: Post-hook grants SELECT to PUBLIC on production fact table (CWE-732, CVSS 6.5, BEST_PRACTICE, Tier 2)
      "GRANT SELECT ON {{ this }} TO ROLE PUBLIC",
      -- BUG-041: Post-hook creates unprotected clone accessible without auth (CWE-284, CVSS 7.1, MEDIUM, Tier 2)
      "CREATE OR REPLACE TABLE {{ this.schema }}.fct_orders_backup CLONE {{ this }}"
    ]
  )
}}

-- BUG-042: Dynamic table reference via var() enables SQL injection in FROM clause (CWE-89, CVSS 9.1, CRITICAL, Tier 1)
{% set custom_order_source = var('custom_order_source', none) %}

WITH orders AS (
    {% if custom_order_source is not none %}
    SELECT * FROM {{ custom_order_source }}
    {% else %}
    SELECT * FROM {{ ref('stg_orders') }}
    {% endif %}
),

products AS (
    SELECT * FROM {{ ref('stg_products') }}
),

-- BUG-043: Cross-join without proper join condition can cause cartesian product on bad data (CWE-400, CVSS 5.3, TRICKY, Tier 3)
order_items AS (
    SELECT
        o.order_id,
        o.customer_id,
        o.order_date,
        o.order_status,
        o.total_amount,
        o.currency_code,
        o.payment_method,
        -- BUG-044: Full card number passed through to fact table (CWE-312, CVSS 8.5, HIGH, Tier 1)
        o.payment_card_number,
        o.payment_card_expiry,
        o.discount_code,
        o.discount_amount,
        o.tax_amount,
        o.shipping_cost,
        o.ip_address,
        p.product_name,
        p.category_name,
        p.brand,
        p.effective_price AS unit_price,
        p.cost_price,
        p.margin_pct,
        o.created_at,
        o.updated_at
    FROM orders o
    LEFT JOIN products p
        ON 1=1  -- Placeholder join; real implementation would join on order_items
),

aggregated AS (
    SELECT
        order_id,
        customer_id,
        order_date,
        order_status,
        total_amount,
        currency_code,
        payment_method,
        payment_card_number,
        payment_card_expiry,
        discount_code,
        discount_amount,
        tax_amount,
        shipping_cost,
        ip_address,
        -- BUG-045: Net amount calculation doesn't account for currency conversion (CWE-682, CVSS 4.3, BEST_PRACTICE, Tier 3)
        total_amount - discount_amount - tax_amount AS net_revenue,
        total_amount - COALESCE(cost_price, 0) AS gross_profit,
        margin_pct AS avg_product_margin,
        CASE
            WHEN total_amount >= 500 THEN 'HIGH_VALUE'
            WHEN total_amount >= 100 THEN 'MEDIUM_VALUE'
            -- BUG-046: Orders below threshold not flagged, enables many small fraudulent orders (CWE-799, CVSS 5.0, TRICKY, Tier 3)
            ELSE 'LOW_VALUE'
        END AS order_tier,
        CASE
            WHEN order_status = 'REFUNDED' AND total_amount > 1000 THEN TRUE
            ELSE FALSE
        END AS is_high_value_refund,
        -- BUG-047: Day-of-week extraction uses server timezone not order timezone (CWE-682, CVSS 3.1, LOW, Tier 3)
        DAYOFWEEK(order_date) AS order_day_of_week,
        MONTH(order_date) AS order_month,
        YEAR(order_date) AS order_year,
        QUARTER(order_date) AS order_quarter,
        created_at,
        updated_at,
        CURRENT_TIMESTAMP() AS _loaded_at
    FROM order_items
)

SELECT * FROM aggregated
