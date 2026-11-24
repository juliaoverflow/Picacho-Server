//! JMAP over WebSocket (RFC 8887), subprotocol `jmap`: Request objects in,
//! Response objects out (with the request's `id`), and pushed StateChange
//! objects after WebSocketPushEnable until WebSocketPushDisable.
use super::{authenticate_access, process};
use crate::state::State;
use axum::extract::ws::{Message, WebSocket, WebSocketUpgrade};
use axum::extract::{ConnectInfo, State as AxState};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Response};
use serde_json::{json, Value};
use std::net::SocketAddr;
use std::time::Duration;

pub async fn upgrade(
    AxState(state): AxState<State>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    ws: WebSocketUpgrade,
) -> Response {
    let (account, level) = match authenticate_access(&state, &headers, peer, false).await {
        Ok(a) => a,
        Err(r) => return r,
    };
    ws.protocols(["jmap"])
        .max_message_size(super::MAX_REQUEST)
        .on_upgrade(move |socket| session(state, account, level, socket))
        .into_response()
}

fn problem(kind: &str, detail: &str, id: Option<&Value>) -> String {
    let mut p = json!({"@type": "RequestError", "type": kind, "status": 400, "detail": detail});
    if let Some(id) = id {
        p["requestId"] = id.clone();
    }
    p.to_string()
}

async fn session(state: State, account: crate::db::Account, level: crate::auth::Access, mut socket: WebSocket) {
    let mut push: Option<i64> = None;
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let shutdown = state.shutdown.clone();
    loop {
        tokio::select! {
            m = socket.recv() => {
                let text = match m {
                    Some(Ok(Message::Text(t))) => t.to_string(),
                    Some(Ok(Message::Ping(p))) => {
                        let _ = socket.send(Message::Pong(p)).await;
                        continue;
                    }
                    Some(Ok(Message::Binary(_))) => {
                        let _ = socket.send(Message::Text(problem("urn:ietf:params:jmap:error:notJSON", "Send text messages.", None).into())).await;
                        continue;
                    }
                    Some(Ok(_)) => continue,
                    _ => return,
                };
                let v: Value = match serde_json::from_str(&text) {
                    Ok(v) => v,
                    Err(e) => {
                        let _ = socket.send(Message::Text(problem("urn:ietf:params:jmap:error:notJSON", &e.to_string(), None).into())).await;
                        continue;
                    }
                };
                let reply = match v.get("@type").and_then(|t| t.as_str()) {
                    Some("Request") => {
                        let id = v.get("id").cloned();
                        // Accounts can be disabled while connected.
                        let fresh = state.db.get_account(account.id).await.ok().flatten().filter(|a| a.active);
                        let Some(acc) = fresh else { return };
                        match process(&state, acc, level, &v).await {
                            Ok(mut out) => {
                                out["@type"] = json!("Response");
                                if let Some(id) = &id {
                                    out["requestId"] = id.clone();
                                }
                                out.to_string()
                            }
                            Err((kind, detail)) => problem(kind, &detail, id.as_ref()),
                        }
                    }
                    Some("WebSocketPushEnable") => {
                        push = Some(state.db.jmap_state(account.id).await.unwrap_or(0));
                        // pushState given: send the current state at once if it differs.
                        if let Some(old) = v.get("pushState").and_then(|p| p.as_str()).and_then(|p| p.parse::<i64>().ok()) {
                            push = Some(old);
                        }
                        continue;
                    }
                    Some("WebSocketPushDisable") => {
                        push = None;
                        continue;
                    }
                    _ => problem("urn:ietf:params:jmap:error:notRequest", "Unknown @type.", v.get("id")),
                };
                if socket.send(Message::Text(reply.into())).await.is_err() {
                    return;
                }
            }
            _ = tick.tick(), if push.is_some() => {
                let now = state.db.jmap_state(account.id).await.unwrap_or(0);
                if Some(now) != push {
                    push = Some(now);
                    let st = now.to_string();
                    let ev = json!({"@type": "StateChange", "changed": {super::account_id(&account): {
                        "Email": st, "Mailbox": st, "Thread": st, "EmailDelivery": st, "EmailSubmission": st, "Identity": st,
                        "Calendar": st, "CalendarEvent": st, "AddressBook": st, "ContactCard": st}}, "pushState": st});
                    if socket.send(Message::Text(ev.to_string().into())).await.is_err() {
                        return;
                    }
                }
            }
            _ = shutdown.cancelled() => {
                let _ = socket.send(Message::Close(None)).await;
                return;
            }
        }
    }
}
