-- macros/utils.sql — Shared utility macros for cobb-dataforge
-- Contains helpers for dynamic SQL generation, logging, and data operations

-- BUG-054: Macro executes arbitrary SQL from caller-supplied table_name without sanitization (CWE-89, CVSS 9.8, CRITICAL, Tier 1)
{% macro get_row_count(table_name) %}
    {% set query %}
        SELECT COUNT(*) AS cnt FROM {{ table_name }}
    {% endset %}
    {% set results = run_query(query) %}
    {% if execute %}
        {{ return(results.columns[0].values()[0]) }}
    {% else %}
        {{ return(0) }}
    {% endif %}
{% endmacro %}

-- BUG-055: Dynamic column selection from user input enables arbitrary column access (CWE-89, CVSS 8.8, HIGH, Tier 1)
{% macro select_columns(table_name, columns) %}
    {% set col_list = columns | join(', ') %}
    SELECT {{ col_list }} FROM {{ table_name }}
{% endmacro %}

-- BUG-056: run_query executes dynamic SQL assembled from multiple untrusted vars (CWE-94, CVSS 9.4, CRITICAL, Tier 1)
{% macro dynamic_filter(table_name, filter_column, filter_value) %}
    {% set query %}
        SELECT *
        FROM {{ table_name }}
        WHERE {{ filter_column }} = '{{ filter_value }}'
    {% endset %}
    {{ return(run_query(query)) }}
{% endmacro %}

-- BUG-057: Log function writes sensitive query text to audit table without redaction (CWE-532, CVSS 5.5, MEDIUM, Tier 2)
{% macro log_query_execution(model_name, query_text, row_count) %}
    {% set log_entry %}
        INSERT INTO {{ var('target_schema') }}.dbt_query_log
        (model_name, query_text, row_count, executed_at, executed_by)
        VALUES (
            '{{ model_name }}',
            '{{ query_text }}',
            {{ row_count }},
            CURRENT_TIMESTAMP(),
            CURRENT_USER()
        )
    {% endset %}
    {% do run_query(log_entry) %}
{% endmacro %}

-- BUG-058: Grant macro uses unsanitized role_name parameter (CWE-89, CVSS 8.4, HIGH, Tier 1)
{% macro grant_access(table_name, role_name, permission) %}
    {% set grant_stmt %}
        GRANT {{ permission }} ON {{ table_name }} TO ROLE {{ role_name }}
    {% endset %}
    {% do run_query(grant_stmt) %}
    {{ log("Granted " ~ permission ~ " on " ~ table_name ~ " to " ~ role_name, info=true) }}
{% endmacro %}

-- BUG-059: Drop table macro with no confirmation or audit trail (CWE-862, CVSS 7.1, MEDIUM, Tier 2)
{% macro cleanup_old_tables(schema_name, prefix, days_old) %}
    {% set query %}
        SELECT TABLE_NAME
        FROM INFORMATION_SCHEMA.TABLES
        WHERE TABLE_SCHEMA = '{{ schema_name }}'
          AND TABLE_NAME LIKE '{{ prefix }}%'
          AND CREATED < DATEADD(day, -{{ days_old }}, CURRENT_TIMESTAMP())
    {% endset %}
    {% set results = run_query(query) %}
    {% if execute %}
        {% for row in results %}
            {% set drop_stmt %}
                DROP TABLE IF EXISTS {{ schema_name }}.{{ row[0] }}
            {% endset %}
            {% do run_query(drop_stmt) %}
            {{ log("Dropped table: " ~ schema_name ~ "." ~ row[0], info=true) }}
        {% endfor %}
    {% endif %}
{% endmacro %}

-- RED-HERRING-05: This macro looks like it could be injection-prone but ref() is safe — safe
{% macro get_latest_record(model_ref, date_column) %}
    SELECT *
    FROM {{ ref(model_ref) }}
    WHERE {{ date_column }} = (
        SELECT MAX({{ date_column }}) FROM {{ ref(model_ref) }}
    )
{% endmacro %}

-- BUG-060: Macro creates temporary table in public schema readable by all roles (CWE-732, CVSS 5.5, BEST_PRACTICE, Tier 2)
{% macro create_staging_temp(table_name, select_query) %}
    {% set create_stmt %}
        CREATE OR REPLACE TABLE {{ var('target_schema') }}.tmp_{{ table_name }} AS
        {{ select_query }}
    {% endset %}
    {% do run_query(create_stmt) %}
{% endmacro %}

-- BUG-061: Audit macro records but never checks for anomalous patterns (CWE-778, CVSS 4.3, BEST_PRACTICE, Tier 3)
{% macro audit_model_run(model_name, status, row_count) %}
    {% set audit_stmt %}
        INSERT INTO {{ var('target_schema') }}.dbt_audit_log
        (model_name, run_status, row_count, run_timestamp, run_id, invocation_id)
        VALUES (
            '{{ model_name }}',
            '{{ status }}',
            {{ row_count }},
            CURRENT_TIMESTAMP(),
            '{{ run_started_at }}',
            '{{ invocation_id }}'
        )
    {% endset %}
    {% do run_query(audit_stmt) %}
{% endmacro %}
