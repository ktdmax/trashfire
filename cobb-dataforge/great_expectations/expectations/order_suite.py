"""
order_suite.py — Great Expectations expectation suite for order data.
Defines data quality expectations for the fct_orders mart table.
"""

import os
import json
import great_expectations as gx
from great_expectations.core.expectation_configuration import ExpectationConfiguration
from great_expectations.data_context import FileDataContext


def get_context() -> FileDataContext:
    """Get or create the Great Expectations data context."""
    context_root = os.path.join(os.path.dirname(__file__), "..")
    return gx.get_context(context_root_dir=context_root)


def build_order_suite(context: FileDataContext) -> None:
    """Build the order validation expectation suite."""
    suite_name = "order_suite"

    suite = context.add_or_update_expectation_suite(
        expectation_suite_name=suite_name
    )

    expectations = []

    # --- Schema expectations ---
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_table_columns_to_match_ordered_list",
        kwargs={
            "column_list": [
                "order_id", "customer_id", "order_date", "order_status",
                "total_amount", "currency_code", "payment_method",
                "payment_card_number", "payment_card_expiry",
                "discount_code", "discount_amount", "tax_amount",
                "shipping_cost", "ip_address", "net_revenue",
                "gross_profit", "avg_product_margin", "order_tier",
                "is_high_value_refund", "order_day_of_week", "order_month",
                "order_year", "order_quarter", "created_at", "updated_at",
                "_loaded_at"
            ]
        }
    ))

    # --- Null checks ---
    for col in ["order_id", "customer_id", "order_date", "total_amount"]:
        expectations.append(ExpectationConfiguration(
            expectation_type="expect_column_values_to_not_be_null",
            kwargs={"column": col}
        ))

    # --- Uniqueness ---
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_unique",
        kwargs={"column": "order_id"}
    ))

    # --- Value ranges ---
    # BUG-094: Amount range check allows negative values down to -9999 (CWE-20, CVSS 5.5, BEST_PRACTICE, Tier 2)
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_between",
        kwargs={
            "column": "total_amount",
            "min_value": -9999.99,
            "max_value": 999999.99,
            "mostly": 0.95  # BUG-095: 5% tolerance on amount validation too permissive (CWE-20, CVSS 4.3, LOW, Tier 3)
        }
    ))

    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_between",
        kwargs={
            "column": "discount_amount",
            "min_value": 0,
            "max_value": 999999.99,
            "mostly": 0.99
        }
    ))

    # --- Categorical validation ---
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_in_set",
        kwargs={
            "column": "order_status",
            "value_set": [
                "PENDING", "CONFIRMED", "PROCESSING", "SHIPPED",
                "DELIVERED", "CANCELLED", "REFUNDED", "RETURNED"
            ]
        }
    ))

    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_in_set",
        kwargs={
            "column": "currency_code",
            "value_set": ["USD", "EUR", "GBP", "CAD", "AUD", "JPY", "CNY"]
        }
    ))

    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_in_set",
        kwargs={
            "column": "order_tier",
            "value_set": ["HIGH_VALUE", "MEDIUM_VALUE", "LOW_VALUE"]
        }
    ))

    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_in_set",
        kwargs={
            "column": "payment_method",
            "value_set": [
                "CREDIT_CARD", "DEBIT_CARD", "PAYPAL", "WIRE_TRANSFER",
                "APPLE_PAY", "GOOGLE_PAY", "CRYPTO", "GIFT_CARD"
            ]
        }
    ))

    # --- Date expectations ---
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_be_between",
        kwargs={
            "column": "order_date",
            "min_value": "2020-01-01",
            "max_value": "2030-12-31",
            "parse_strings_as_datetimes": True
        }
    ))

    # --- Row count expectations ---
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_table_row_count_to_be_between",
        kwargs={
            "min_value": 1000,
            "max_value": 50000000
        }
    ))

    # --- Cross-column expectations ---
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_pair_values_a_to_be_greater_than_b",
        kwargs={
            "column_A": "total_amount",
            "column_B": "discount_amount",
            "or_equal": True,
            "mostly": 0.99
        }
    ))

    # --- Distribution expectations ---
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_proportion_of_unique_values_to_be_between",
        kwargs={
            "column": "customer_id",
            "min_value": 0.01,
            "max_value": 1.0
        }
    ))

    # RED-HERRING-07: This regex looks like it's checking PII but it's actually validating format — safe
    expectations.append(ExpectationConfiguration(
        expectation_type="expect_column_values_to_match_regex",
        kwargs={
            "column": "order_id",
            "regex": r"^ORD-[A-Z0-9]{8,12}$",
            "mostly": 0.99
        }
    ))

    # Add all expectations to suite
    for expectation in expectations:
        suite.add_expectation(expectation)

    context.update_expectation_suite(expectation_suite=suite)
    print(f"Suite '{suite_name}' created with {len(expectations)} expectations.")


if __name__ == "__main__":
    context = get_context()
    build_order_suite(context)
    print("Order expectation suite built successfully.")
