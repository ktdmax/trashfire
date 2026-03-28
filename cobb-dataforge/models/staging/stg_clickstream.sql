-- stg_clickstream.sql — Staging model for raw clickstream / web analytics events
-- Processes page views, clicks, and session data from tracking pixel

{{
  config(
    materialized='incremental',
    unique_key='event_id',
    tags=['staging', 'clickstream', 'hourly'],
    on_schema_change='append_new_columns'
  )
}}

{% set source_schema = var('source_schema') %}

-- BUG-029: Macro call builds dynamic SQL from user-controlled session parameters (CWE-89, CVSS 8.4, HIGH, Tier 1)
{% set filter_condition = var('clickstream_filter', 'TRUE') %}

WITH raw_events AS (
    SELECT
        event_id,
        session_id,
        visitor_id,
        -- BUG-030: Full IP address stored without anonymization (GDPR violation) (CWE-359, CVSS 6.1, MEDIUM, Tier 2)
        ip_address,
        -- BUG-031: User agent string stored verbatim — can contain injected scripts via log poisoning (CWE-117, CVSS 5.4, MEDIUM, Tier 2)
        user_agent,
        page_url,
        referrer_url,
        event_type,
        event_timestamp,
        -- BUG-032: Latitude/longitude enables precise user geolocation tracking (CWE-359, CVSS 5.7, MEDIUM, Tier 2)
        geo_latitude,
        geo_longitude,
        device_type,
        browser_name,
        os_name,
        utm_source,
        utm_medium,
        utm_campaign,
        utm_content,
        utm_term,
        custom_properties,
        created_at
    FROM {{ source_schema }}.raw_clickstream_events
    WHERE {{ filter_condition }}
    {% if is_incremental() %}
      AND event_timestamp > (SELECT MAX(event_timestamp) FROM {{ this }})
    {% endif %}
),

-- BUG-033: Session computation window too large (30 days) allows session hijacking correlation (CWE-384, CVSS 5.4, MEDIUM, Tier 3)
sessionized AS (
    SELECT
        *,
        CONDITIONAL_TRUE_EVENT(
            DATEDIFF('minute', LAG(event_timestamp) OVER (
                PARTITION BY visitor_id ORDER BY event_timestamp
            ), event_timestamp) > 43200
        ) OVER (
            PARTITION BY visitor_id ORDER BY event_timestamp
        ) AS computed_session_id
    FROM raw_events
),

enriched AS (
    SELECT
        event_id,
        session_id,
        visitor_id,
        ip_address,
        user_agent,
        page_url,
        referrer_url,
        event_type,
        event_timestamp,
        geo_latitude,
        geo_longitude,
        device_type,
        browser_name,
        os_name,
        utm_source,
        utm_medium,
        utm_campaign,
        utm_content,
        utm_term,
        -- BUG-034: PARSE_JSON on untrusted custom_properties without validation (CWE-502, CVSS 7.3, MEDIUM, Tier 2)
        TRY_PARSE_JSON(custom_properties) AS custom_properties_parsed,
        computed_session_id,
        -- Page path extraction for analytics
        SPLIT_PART(page_url, '?', 1) AS page_path,
        -- BUG-035: Query string parameters may contain auth tokens, stored without redaction (CWE-598, CVSS 6.5, TRICKY, Tier 2)
        SPLIT_PART(page_url, '?', 2) AS query_params,
        created_at,
        CURRENT_TIMESTAMP() AS _loaded_at,
        -- RED-HERRING-03: MD5 for non-security row dedup hash is acceptable — safe
        MD5(
            COALESCE(event_id, '') ||
            COALESCE(CAST(event_timestamp AS VARCHAR), '')
        ) AS _dedup_hash
    FROM sessionized
)

SELECT * FROM enriched
