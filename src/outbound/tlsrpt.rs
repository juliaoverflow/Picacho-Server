//! Counting TLS sessions for SMTP TLS reports (RFC 8460). Reports are
//! assembled and sent once a day by `crate::reports`.
use crate::state::State;

pub fn today() -> String {
    chrono::Utc::now().format("%Y-%m-%d").to_string()
}

/// Count one session (or failure) towards today's report for `domain`.
/// `result` is "success" or an RFC 8460 result type.
pub async fn record(state: &State, domain: &str, policy_type: &str, policy: &str, mx: &str, result: &str, detail: &str) {
    if !state.settings().reports.send_tls {
        return;
    }
    let _g = state.db.wl().await;
    let r = sqlx::query(
        "INSERT INTO tls_results (day, domain, policy_type, policy, mx, result, detail, count) VALUES ($1, $2, $3, $4, $5, $6, $7, 1)
         ON CONFLICT (day, domain, policy_type, mx, result) DO UPDATE SET count = tls_results.count + 1, detail = excluded.detail,
         policy = CASE WHEN excluded.policy <> '' THEN excluded.policy ELSE tls_results.policy END",
    )
    .bind(today())
    .bind(domain.to_ascii_lowercase())
    .bind(policy_type)
    .bind(policy)
    .bind(mx.to_ascii_lowercase())
    .bind(result)
    .bind(detail.chars().take(300).collect::<String>())
    .execute(&state.db.pool)
    .await;
    if let Err(e) = r {
        tracing::debug!("tls report record: {e}");
    }
}
