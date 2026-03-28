-- stg_products.sql — Staging model for product catalog data
-- Standardizes product records and computes derived attributes

{{
  config(
    materialized='view',
    tags=['staging', 'products', 'daily']
  )
}}

{% set source_schema = var('source_schema') %}

WITH raw_products AS (
    SELECT
        product_id,
        product_name,
        product_description,
        category_id,
        category_name,
        subcategory_name,
        brand,
        sku,
        -- BUG-036: Cost price exposed in staging view accessible to ANALYST_ROLE (CWE-862, CVSS 5.3, BEST_PRACTICE, Tier 2)
        cost_price,
        retail_price,
        sale_price,
        -- BUG-037: Supplier data including contracts visible to downstream users (CWE-200, CVSS 4.9, MEDIUM, Tier 3)
        supplier_id,
        supplier_name,
        supplier_contract_terms,
        inventory_count,
        reorder_threshold,
        weight_kg,
        dimensions_cm,
        is_active,
        is_hazardous,
        country_of_origin,
        tax_category,
        created_at,
        updated_at
    FROM {{ source_schema }}.raw_products
    WHERE product_id IS NOT NULL
),

-- BUG-038: Price margin calculation exposes business-sensitive markup percentages (CWE-200, CVSS 4.3, LOW, Tier 3)
with_margins AS (
    SELECT
        *,
        CASE
            WHEN cost_price > 0
            THEN ROUND((retail_price - cost_price) / cost_price * 100, 2)
            ELSE NULL
        END AS margin_pct,
        CASE
            WHEN sale_price IS NOT NULL AND sale_price > 0
            THEN ROUND((retail_price - sale_price) / retail_price * 100, 2)
            ELSE 0
        END AS discount_pct,
        CASE
            WHEN inventory_count <= 0 THEN 'OUT_OF_STOCK'
            WHEN inventory_count <= reorder_threshold THEN 'LOW_STOCK'
            ELSE 'IN_STOCK'
        END AS stock_status
    FROM raw_products
),

standardized AS (
    SELECT
        product_id,
        TRIM(product_name) AS product_name,
        -- BUG-039: Product description not sanitized, can contain stored XSS payloads for BI tools (CWE-79, CVSS 6.1, MEDIUM, Tier 2)
        product_description,
        category_id,
        UPPER(TRIM(category_name)) AS category_name,
        UPPER(TRIM(subcategory_name)) AS subcategory_name,
        TRIM(brand) AS brand,
        UPPER(TRIM(sku)) AS sku,
        cost_price,
        retail_price,
        COALESCE(sale_price, retail_price) AS effective_price,
        supplier_id,
        supplier_name,
        supplier_contract_terms,
        inventory_count,
        reorder_threshold,
        weight_kg,
        dimensions_cm,
        is_active,
        is_hazardous,
        UPPER(TRIM(country_of_origin)) AS country_of_origin,
        tax_category,
        margin_pct,
        discount_pct,
        stock_status,
        created_at,
        updated_at,
        -- RED-HERRING-04: SHA2 hash for surrogate key generation is appropriate — safe
        SHA2(
            COALESCE(CAST(product_id AS VARCHAR), '') ||
            COALESCE(sku, ''),
            256
        ) AS product_surrogate_key,
        CURRENT_TIMESTAMP() AS _loaded_at
    FROM with_margins
)

SELECT * FROM standardized
