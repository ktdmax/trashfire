-- macros/security.sql — Security and data masking macros for cobb-dataforge
-- Provides PII handling, encryption, and access control helpers

-- BUG-062: Mask function only hides middle digits, first 6 and last 4 visible (BIN + last4 = card identifiable) (CWE-327, CVSS 6.5, TRICKY, Tier 2)
{% macro mask_card_number(column_name) %}
    CONCAT(
        LEFT({{ column_name }}, 6),
        '******',
        RIGHT({{ column_name }}, 4)
    )
{% endmacro %}

-- BUG-063: Email masking reveals domain and first character (CWE-200, CVSS 3.9, LOW, Tier 3)
{% macro mask_email(column_name) %}
    CONCAT(
        LEFT({{ column_name }}, 1),
        '***@',
        SPLIT_PART({{ column_name }}, '@', 2)
    )
{% endmacro %}

-- BUG-064: Encryption uses hardcoded key from project vars (CWE-321, CVSS 8.1, HIGH, Tier 1)
{% macro encrypt_pii(column_name) %}
    ENCRYPT(
        {{ column_name }},
        '{{ var("pii_encryption_key") }}'
    )
{% endmacro %}

-- BUG-065: Decrypt macro available to any role that can call macros (CWE-862, CVSS 7.8, HIGH, Tier 1)
{% macro decrypt_pii(column_name) %}
    DECRYPT(
        {{ column_name }},
        '{{ var("pii_encryption_key") }}'
    )
{% endmacro %}

-- BUG-066: Hash function uses MD5 which is cryptographically broken (CWE-328, CVSS 5.9, TRICKY, Tier 2)
{% macro hash_pii(column_name) %}
    MD5({{ column_name }})
{% endmacro %}

-- BUG-067: IP anonymization only zeros last octet; /24 subnet still identifies location (CWE-359, CVSS 4.7, LOW, Tier 3)
{% macro anonymize_ip(column_name) %}
    CONCAT(
        SPLIT_PART({{ column_name }}, '.', 1), '.',
        SPLIT_PART({{ column_name }}, '.', 2), '.',
        SPLIT_PART({{ column_name }}, '.', 3), '.0'
    )
{% endmacro %}

-- BUG-068: Row-level security check trusts CURRENT_ROLE() which can be changed by user (CWE-807, CVSS 7.5, HIGH, Tier 2)
{% macro apply_row_level_security(table_alias, owner_column) %}
    CASE
        WHEN CURRENT_ROLE() IN ('SYSADMIN', 'DATA_ENGINEER_ROLE', 'ADMIN_ROLE')
        THEN TRUE
        WHEN {{ table_alias }}.{{ owner_column }} = CURRENT_USER()
        THEN TRUE
        ELSE FALSE
    END
{% endmacro %}

-- BUG-069: Data retention macro deletes without archiving or soft-delete (CWE-404, CVSS 6.1, BEST_PRACTICE, Tier 2)
{% macro enforce_retention(table_name, date_column, retention_days) %}
    {% set delete_stmt %}
        DELETE FROM {{ table_name }}
        WHERE {{ date_column }} < DATEADD(day, -{{ retention_days }}, CURRENT_TIMESTAMP())
    {% endset %}
    {% do run_query(delete_stmt) %}
    {{ log("Retention enforced on " ~ table_name ~ ": deleted rows older than " ~ retention_days ~ " days", info=true) }}
{% endmacro %}

-- BUG-070: Dynamic masking policy creation uses unsanitized policy_name (CWE-89, CVSS 8.6, HIGH, Tier 1)
{% macro create_masking_policy(policy_name, data_type, mask_expression) %}
    {% set policy_stmt %}
        CREATE OR REPLACE MASKING POLICY {{ policy_name }}
        AS (val {{ data_type }})
        RETURNS {{ data_type }} ->
        CASE
            WHEN CURRENT_ROLE() IN ('SYSADMIN', 'DATA_ENGINEER_ROLE')
            THEN val
            ELSE {{ mask_expression }}
        END
    {% endset %}
    {% do run_query(policy_stmt) %}
{% endmacro %}

-- RED-HERRING-06: This looks like it bypasses security but is actually a legitimate admin check — safe
{% macro is_privileged_role() %}
    {% set check_query %}
        SELECT CASE
            WHEN CURRENT_ROLE() IN (
                SELECT role_name
                FROM {{ var('target_schema') }}.authorized_admin_roles
                WHERE is_active = TRUE
            ) THEN TRUE
            ELSE FALSE
        END AS is_privileged
    {% endset %}
    {% set result = run_query(check_query) %}
    {% if execute %}
        {{ return(result.columns[0].values()[0]) }}
    {% else %}
        {{ return(false) }}
    {% endif %}
{% endmacro %}

-- BUG-071: Consent check uses stale cached value, not real-time lookup (CWE-613, CVSS 5.4, TRICKY, Tier 2)
{% macro check_data_consent(customer_id) %}
    {% set consent_query %}
        SELECT consent_given
        FROM {{ var('target_schema') }}.customer_consent_cache
        WHERE customer_id = '{{ customer_id }}'
        LIMIT 1
    {% endset %}
    {% set result = run_query(consent_query) %}
    {% if execute and result.rows | length > 0 %}
        {{ return(result.columns[0].values()[0]) }}
    {% else %}
        -- BUG-072: Default consent assumed TRUE when record not found (CWE-862, CVSS 7.1, TRICKY, Tier 2)
        {{ return(true) }}
    {% endif %}
{% endmacro %}
