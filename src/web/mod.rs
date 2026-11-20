//! Web console: embedded Svelte app plus a JSON API.
//!
//! Security: session tokens are random 256-bit values stored hashed;
//! cookies are HttpOnly + SameSite=Strict (+ Secure over HTTPS); every
//! state-changing request must carry `X-Picacho: 1`, which cross-site forms
//! can't send; strict CSP and frame denial on every response.
mod api;
pub mod wellknown;

use crate::state::State;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{header, HeaderMap, HeaderValue, Method, Request, Response, StatusCode};
use axum::middleware::{self, Next};
use axum::response::IntoResponse;
use axum::Router;
use hyper_util::rt::{TokioExecutor, TokioIo};
use rust_embed::RustEmbed;
use std::net::SocketAddr;
use tower::Service;

#[derive(RustEmbed)]
#[folder = "web/dist"]
#[allow_missing = true]
struct Assets;

pub fn router(state: State) -> Router {
    api::routes(state.clone())
        .merge(crate::jmap::routes(state.clone()))
        .merge(crate::relay::routes(state.clone()))
        .merge(wellknown::routes(state.clone()))
        .merge(crate::dav::routes(state.clone()))
        .fallback(static_file)
        .layer(axum::extract::DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn_with_state(state, guard))
}

/// CSRF check and security headers.
async fn guard(
    axum::extract::State(state): axum::extract::State<State>,
    req: Request<Body>,
    next: Next,
) -> Response<Body> {
    crate::metrics::HTTP_REQUESTS.inc();
    let is_api = req.uri().path().starts_with("/api/") && !req.uri().path().starts_with("/api/relay/");
    if is_api && req.method() != Method::GET && req.method() != Method::HEAD {
        // Token-authenticated calls carry no ambient credentials, so they
        // can't be forged cross-site; cookie sessions need the header.
        let ok = req.headers().get("x-picacho").map(|v| v == "1").unwrap_or(false)
            || req.headers().contains_key(header::AUTHORIZATION);
        if !ok {
            return (StatusCode::FORBIDDEN, axum::Json(serde_json::json!({"error": "missing request header"}))).into_response();
        }
    }
    let mut resp = next.run(req).await;
    let h = resp.headers_mut();
    let set = |h: &mut HeaderMap, k: &'static str, v: &'static str| {
        h.insert(k, HeaderValue::from_static(v));
    };
    set(
        h,
        "content-security-policy",
        "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'; font-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'",
    );
    set(h, "x-content-type-options", "nosniff");
    set(h, "x-frame-options", "DENY");
    set(h, "referrer-policy", "no-referrer");
    set(h, "permissions-policy", "camera=(), microphone=(), geolocation=(), payment=()");
    set(h, "cross-origin-opener-policy", "same-origin");
    if state.config.web.tls {
        set(h, "strict-transport-security", "max-age=31536000");
    }
    if is_api {
        set(h, "cache-control", "no-store");
    }
    resp
}

async fn static_file(req: Request<Body>) -> Response<Body> {
    let path = req.uri().path().trim_start_matches('/');
    let (file, path) = match Assets::get(path) {
        Some(f) if !path.is_empty() => (f, path.to_string()),
        _ => {
            if path.starts_with("api/") {
                return (StatusCode::NOT_FOUND, axum::Json(serde_json::json!({"error": "not found"}))).into_response();
            }
            match Assets::get("index.html") {
                Some(f) => (f, "index.html".to_string()),
                None => {
                    return (StatusCode::OK, [(header::CONTENT_TYPE, "text/plain")], "Web console not built. Run `npm run build` in web/.")
                        .into_response()
                }
            }
        }
    };
    let mime = mime_guess::from_path(&path).first_or_octet_stream();
    let cache = if path.starts_with("assets/") { "public, max-age=31536000, immutable" } else { "no-cache" };
    Response::builder()
        .header(header::CONTENT_TYPE, mime.as_ref())
        .header(header::CACHE_CONTROL, cache)
        .body(Body::from(file.data.into_owned()))
        .unwrap()
}

/// Serve the console on one address (HTTP or HTTPS).
pub async fn serve(state: State, addr: SocketAddr) -> Result<SocketAddr, String> {
    let listener = tokio::net::TcpListener::bind(addr).await.map_err(|e| format!("Web on {addr}: {e}"))?;
    let addr = listener.local_addr().unwrap_or(addr);
    let tls = state.config.web.tls;
    state
        .listeners
        .lock()
        .push(serde_json::json!({"protocol": if tls { "HTTPS" } else { "HTTP" }, "address": addr.to_string()}));
    let app = router(state.clone());
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {
                a = listener.accept() => a,
                _ = state.shutdown.cancelled() => break,
            };
            let Ok((tcp, peer)) = accepted else { continue };
            let _ = tcp.set_nodelay(true);
            let app = app.clone();
            let state = state.clone();
            tokio::spawn(async move {
                let svc = hyper::service::service_fn(move |mut req: Request<hyper::body::Incoming>| {
                    req.extensions_mut().insert(ConnectInfo(peer));
                    let mut app = app.clone();
                    async move { app.call(req.map(Body::new)).await }
                });
                let builder = hyper_util::server::conn::auto::Builder::new(TokioExecutor::new());
                if tls {
                    let Ok(Ok(s)) = tokio::time::timeout(std::time::Duration::from_secs(15), state.tls.acceptor.accept(tcp)).await else {
                        return;
                    };
                    let _ = builder.serve_connection(TokioIo::new(s), svc).await;
                } else {
                    let _ = builder.serve_connection(TokioIo::new(tcp), svc).await;
                }
            });
        }
    });
    Ok(addr)
}
