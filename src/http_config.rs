//! Tuned `reqwest::Client` builders for low-latency access to Polymarket.
//!
//! Settings are adapted from polyfill-rs (`src/http_config.rs` in
//! `floor-licker/polyfill-rs`, MIT/Apache-2.0), which benchmarks ~11%
//! faster end-to-end vs a default `reqwest::Client` on Polymarket's
//! REST API.
//!
//! Every internal HTTP client in this crate (CLOB, data, gamma, bridge)
//! should build its client through [`build_optimized_client`] so the
//! tuning stays consistent.
//!
//! ## Settings rationale
//! - `pool_max_idle_per_host = 10` — hold enough idle connections to
//!   sustain bursty trading workloads without reconnect churn.
//! - `pool_idle_timeout = 90s` — longer than the default so mid-frequency
//!   polling keeps the same TCP session warm.
//! - `tcp_nodelay(true)` — reqwest defaults to Nagle on; disable it so
//!   small order POSTs aren't held waiting for the ACK clock.
//! - `http2_adaptive_window(true)` + `http2_initial_stream_window_size =
//!   512 KiB` — polyfill-rs benchmarked these against Polymarket's ~469
//!   KiB typical payload and found them empirically optimal.
//! - `no_proxy()` — skip OS proxy probing, which can block for seconds
//!   in sandboxed or WSL environments.

use std::time::Duration;

use reqwest::Client;
use reqwest::header::HeaderMap;

/// Pool idle limit per host (see module docs).
const POOL_MAX_IDLE_PER_HOST: usize = 10;

/// How long to keep an idle connection before dropping it.
const POOL_IDLE_TIMEOUT: Duration = Duration::from_secs(90);

/// HTTP/2 initial stream window, sized for Polymarket market-list payloads.
const HTTP2_INITIAL_STREAM_WINDOW: u32 = 512 * 1024;

/// Build a `reqwest::Client` with the shared latency-tuned settings,
/// attaching the supplied `default_headers` (User-Agent, Accept,
/// Connection, Content-Type — set by the caller).
///
/// Returns a `reqwest::Result` so callers can propagate build errors.
pub(crate) fn build_optimized_client(default_headers: HeaderMap) -> reqwest::Result<Client> {
    Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(POOL_MAX_IDLE_PER_HOST)
        .pool_idle_timeout(POOL_IDLE_TIMEOUT)
        .tcp_nodelay(true)
        .http2_adaptive_window(true)
        .http2_initial_stream_window_size(HTTP2_INITIAL_STREAM_WINDOW)
        .default_headers(default_headers)
        .build()
}

/// Fire-and-forget warmup pings to establish TCP + TLS + HTTP/2 state
/// before the first real request. Polyfill-rs claims ~70% speedup on
/// the first post-warmup request; in our setup the dominant gain comes
/// from TLS handshake reuse.
///
/// Takes `&Client` so connections populate the shared pool. Errors are
/// deliberately swallowed — warmup is best-effort; a cold pool is still
/// correct, just slightly slower.
pub async fn prewarm_connections(client: &Client, base_url: &str) {
    // `/ok` and `/time` exist on every Polymarket service we talk to
    // and return trivially small bodies (good for exercising the TLS
    // handshake + HTTP/2 setup without moving real data).
    for endpoint in ["/ok", "/time"] {
        let _ = client
            .get(format!("{base_url}{endpoint}"))
            .timeout(Duration::from_millis(1000))
            .send()
            .await;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn optimized_client_builds() {
        let client = build_optimized_client(HeaderMap::new());
        assert!(client.is_ok(), "build_optimized_client failed: {client:?}");
    }
}
