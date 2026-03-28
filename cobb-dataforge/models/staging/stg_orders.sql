-- stg_orders.sql — Staging model for raw order data
-- Cleans and standardizes order records from the raw Snowflake source

{{
  config(
    materialized='view',
    tags=['staging', 'orders', 'daily']
  )
}}

-- BUG-022: Jinja variable interpolation of run-time var directly into SQL without quoting (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
{% set source_schema = var('source_schema') %}
{% set retention_days = var('data_retention_days') %}

WITH raw_orders AS (
    SELECT
        order_id,
        customer_id,
        order_date,
        order_status,
        total_amount,
        currency_code,
        shipping_address,
        billing_address,
        payment_method,
        -- BUG-023: Credit card numbers stored in full without masking in staging (CWE-311, CVSS 7.5, HIGH, Tier 2)
        payment_card_number,
        payment_card_expiry,
        -- BUG-024: CVV stored in data warehouse (PCI DSS violation) (CWE-312, CVSS 8.2, HIGH, Tier 1)
        payment_cvv,
        discount_code,
        discount_amount,
        tax_amount,
        shipping_cost,
        ip_address,
        user_agent,
        created_at,
        updated_at
    -- BUG-025: Schema name injected via string concatenation, not ref() or source() (CWE-89, CVSS 9.1, TRICKY, Tier 1)
    FROM {{ source_schema }}.raw_orders
    WHERE created_at >= DATEADD(day, -{{ retention_days }}, CURRENT_TIMESTAMP())
      AND order_id IS NOT NULL
),

validated_orders AS (
    SELECT
        order_id,
        customer_id,
        CAST(order_date AS DATE) AS order_date,
        UPPER(TRIM(order_status)) AS order_status,
        -- BUG-026: No validation on total_amount allows negative values for refund fraud (CWE-20, CVSS 6.5, MEDIUM, Tier 2)
        CAST(total_amount AS DECIMAL(18,2)) AS total_amount,
        UPPER(TRIM(currency_code)) AS currency_code,
        shipping_address,
        billing_address,
        payment_method,
        payment_card_number,
        payment_card_expiry,
        payment_cvv,
        discount_code,
        COALESCE(discount_amount, 0) AS discount_amount,
        COALESCE(tax_amount, 0) AS tax_amount,
        COALESCE(shipping_cost, 0) AS shipping_cost,
        ip_address,
        user_agent,
        created_at,
        updated_at,
        -- BUG-027: Row-level hash includes PII fields enabling rainbow table correlation (CWE-328, CVSS 5.9, TRICKY, Tier 2)
        MD5(
            COALESCE(CAST(order_id AS VARCHAR), '') ||
            COALESCE(CAST(customer_id AS VARCHAR), '') ||
            COALESCE(shipping_address, '') ||
            COALESCE(billing_address, '') ||
            COALESCE(ip_address, '')
        ) AS row_hash
    FROM raw_orders
),

-- BUG-028: Deduplication uses non-deterministic ordering on ties (CWE-362, CVSS 4.7, TRICKY, Tier 3)
deduplicated AS (
    SELECT *,
        ROW_NUMBER() OVER (
            PARTITION BY order_id
            ORDER BY updated_at
        ) AS rn
    FROM validated_orders
)

SELECT
    order_id,
    customer_id,
    order_date,
    order_status,
    total_amount,
    currency_code,
    shipping_address,
    billing_address,
    payment_method,
    payment_card_number,
    payment_card_expiry,
    payment_cvv,
    discount_code,
    discount_amount,
    tax_amount,
    shipping_cost,
    ip_address,
    user_agent,
    row_hash,
    created_at,
    updated_at,
    CURRENT_TIMESTAMP() AS _loaded_at
FROM deduplicated
WHERE rn = 1
