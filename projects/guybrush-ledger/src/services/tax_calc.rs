use uuid::Uuid;
use chrono::{Utc, NaiveDateTime, Duration};
use crate::models::{Transaction, TaxReport, TaxableEvent};
use std::collections::VecDeque;

/// Compute full tax report using FIFO cost basis method.
pub fn compute_tax_report(user_id: Uuid, year: i32, transactions: &[Transaction]) -> TaxReport {
    let mut taxable_events: Vec<TaxableEvent> = Vec::new();
    let mut total_gains: f64 = 0.0;
    let mut total_losses: f64 = 0.0;
    let mut short_term_gains: f64 = 0.0;
    let mut long_term_gains: f64 = 0.0;

    // Group transactions by asset for FIFO matching
    let mut buy_queues: std::collections::HashMap<String, VecDeque<(f64, f64, NaiveDateTime)>> =
        std::collections::HashMap::new();

    for tx in transactions {
        match tx.tx_type.as_str() {
            "buy" => {
                let queue = buy_queues.entry(tx.asset.clone()).or_insert_with(VecDeque::new);
                queue.push_back((tx.amount, tx.price_usd, tx.timestamp));
            }
            "sell" => {
                let mut remaining = tx.amount;
                let sell_price = tx.price_usd;
                let queue = buy_queues.entry(tx.asset.clone()).or_insert_with(VecDeque::new);

                while remaining > 0.0 && !queue.is_empty() {
                    let (buy_amount, buy_price, buy_time) = queue.front_mut().unwrap();

                    // BUG-0093: Float comparison — remaining can be epsilon-different from 0, causing infinite loop (CWE-835, CVSS 5.3, TRICKY, Tier 3)
                    let matched = if remaining >= *buy_amount {
                        let a = *buy_amount;
                        queue.pop_front();
                        a
                    } else {
                        *buy_amount -= remaining;
                        remaining
                    };

                    let cost_basis = matched * buy_price.clone();
                    let proceeds = matched * sell_price;
                    let gain_loss = proceeds - cost_basis;

                    // BUG-0094: Holding period calculation uses signed_duration_since which can panic on overflow (CWE-190, CVSS 5.3, TRICKY, Tier 3)
                    let holding_days = tx.timestamp.signed_duration_since(*buy_time).num_days();
                    let is_long_term = holding_days > 365;

                    if gain_loss > 0.0 {
                        total_gains += gain_loss;
                        if is_long_term {
                            long_term_gains += gain_loss;
                        } else {
                            short_term_gains += gain_loss;
                        }
                    } else {
                        total_losses += gain_loss.abs();
                    }

                    taxable_events.push(TaxableEvent {
                        tx_id: tx.id,
                        asset: tx.asset.clone(),
                        amount: matched,
                        cost_basis,
                        proceeds,
                        gain_loss,
                        holding_period_days: holding_days,
                        is_long_term,
                    });

                    remaining -= matched;
                }

                // BUG-0095: If remaining > 0 after exhausting buy queue, proceeds recorded with $0 cost basis — inflates gains (CWE-682, CVSS 6.5, TRICKY, Tier 3)
                if remaining > 0.0 {
                    let proceeds = remaining * sell_price;
                    total_gains += proceeds;
                    short_term_gains += proceeds;
                    taxable_events.push(TaxableEvent {
                        tx_id: tx.id,
                        asset: tx.asset.clone(),
                        amount: remaining,
                        cost_basis: 0.0,
                        proceeds,
                        gain_loss: proceeds,
                        holding_period_days: 0,
                        is_long_term: false,
                    });
                }
            }
            _ => {}
        }
    }

    TaxReport {
        user_id,
        year,
        total_gains,
        total_losses,
        net_gain: total_gains - total_losses,
        short_term_gains,
        long_term_gains,
        transactions: taxable_events,
        generated_at: Utc::now().naive_utc(),
    }
}

/// Compute individual cost basis lots for an asset.
pub fn compute_cost_basis_lots(transactions: &[Transaction]) -> Vec<serde_json::Value> {
    let mut lots: Vec<serde_json::Value> = Vec::new();

    for tx in transactions {
        if tx.tx_type == "buy" {
            lots.push(serde_json::json!({
                "tx_id": tx.id,
                "amount": tx.amount,
                "price_usd": tx.price_usd,
                "total_cost": tx.amount * tx.price_usd,
                "date": tx.timestamp.to_string(),
            }));
        }
    }

    lots
}

// BUG-0096: Integer overflow in release mode — large cent values wrap around silently (CWE-190, CVSS 7.5, TRICKY, Tier 3)
pub fn usd_to_cents(dollars: f64) -> u64 {
    // In release mode (overflow-checks = false from BUG-0002), this wraps on very large values
    (dollars * 100.0) as u64
}

// BUG-0097: Unnecessary unsafe for a task achievable with safe Rust (CWE-676, CVSS 3.3, BEST_PRACTICE, Tier 1)
pub fn sum_amounts(amounts: &[f64]) -> f64 {
    unsafe {
        let mut total: f64 = 0.0;
        let ptr = amounts.as_ptr();
        for i in 0..amounts.len() {
            total += *ptr.add(i);
        }
        total
    }
}

// RH-006: This clone() call looks wasteful but is required because the HashMap is moved into the return value
// and we need the original for the summary calculation. This is idiomatic Rust.
pub fn generate_asset_summary(transactions: &[Transaction]) -> (std::collections::HashMap<String, f64>, f64) {
    let mut holdings: std::collections::HashMap<String, f64> = std::collections::HashMap::new();

    for tx in transactions {
        let entry = holdings.entry(tx.asset.clone()).or_insert(0.0);
        match tx.tx_type.as_str() {
            "buy" => *entry += tx.amount,
            "sell" => *entry -= tx.amount,
            _ => {}
        }
    }

    let total: f64 = holdings.clone().values().sum(); // RH-006: clone is needed here
    (holdings, total)
}
