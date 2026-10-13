//! The status and peer API (axum): `GET /healthz`, `/status`, `/metrics`, `/locks/{lockId}`,
//! `/burns/{nonce}` (read-only, public), and the signing routes `POST /slash/sign`,
//! `/unlock/sign`, `/cancel/sign`, which only a current member's signed request reaches
//! ([`crate::peer_auth`], HK-13).

use axum::extract::{Extension, Path, State};
use axum::http::{StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{Json, Router};
use hawkeye_core::address::encode_address;
use hawkeye_core::recipient::YcashRecipient;
use hawkeye_store::BurnKey;

use crate::engine::Ctx;
use crate::engine::burn::verify_and_sign_unlock;
use crate::engine::slash::verify_and_sign;
use crate::engine::watch::verify_and_sign_cancel;
use crate::peer_auth::PeerMember;
use crate::peers::{
    ApiError, BurnView, CancelSignRequest, LockView, SlashSignRequest, UnlockSignRequest,
};
use crate::status::render_metrics;

fn err(code: StatusCode, msg: impl Into<String>) -> Response {
    (code, Json(ApiError { error: msg.into() })).into_response()
}

/// The router over `ctx`: the signing routes behind [`crate::peer_auth::layer`], the
/// read-only routes outside it.
pub fn router(ctx: Ctx) -> Router {
    Router::new()
        .route("/slash/sign", post(slash_sign))
        .route("/unlock/sign", post(unlock_sign))
        .route("/cancel/sign", post(cancel_sign))
        .route_layer(axum::middleware::from_fn_with_state(
            ctx.clone(),
            crate::peer_auth::layer,
        ))
        .route("/healthz", get(|| async { "ok" }))
        .route("/status", get(status))
        .route("/metrics", get(metrics))
        .route("/locks/{id}", get(lock))
        .route("/burns/{nonce}", get(burn))
        .with_state(ctx)
}

/// Serve [`router`] on `listener` with each connection's peer address (`[peers] allow_from`).
pub async fn serve(listener: tokio::net::TcpListener, ctx: Ctx) -> std::io::Result<()> {
    axum::serve(
        listener,
        router(ctx).into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .await
}

async fn status(State(ctx): State<Ctx>) -> Response {
    let s = ctx.status.read().unwrap_or_else(|e| e.into_inner()).clone();
    Json(s).into_response()
}

async fn metrics(State(ctx): State<Ctx>) -> Response {
    let s = ctx.status.read().unwrap_or_else(|e| e.into_inner()).clone();
    (
        [(header::CONTENT_TYPE, "text/plain; version=0.0.4")],
        render_metrics(&s),
    )
        .into_response()
}

async fn lock(State(ctx): State<Ctx>, Path(id): Path<String>) -> Response {
    let signer = match ctx.guardian() {
        Ok(g) => g.to_string(),
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    };
    let Ok(bytes) = hex::decode(id.trim_start_matches("0x")) else {
        return err(StatusCode::BAD_REQUEST, "lockId is not hex");
    };
    let Ok(lock_id): Result<[u8; 32], _> = bytes.as_slice().try_into() else {
        return err(StatusCode::BAD_REQUEST, "lockId is not 32 bytes");
    };
    let r = ctx.db(|t| Ok((t.lock(&lock_id)?, t.mint_signature(&lock_id)?)));
    match r {
        Ok((Some(l), sig)) => Json(LockView {
            lock_id: format!("0x{}", hex::encode(l.lock_id)),
            outpoint: l.outpoint.to_string(),
            state: l.state.to_string(),
            amount: l.value_zat,
            to: l.destination.map(|d| d.to_string()),
            block_height: l.block_height,
            rejection_reason: l.rejection_reason,
            signature: sig.map(|s| format!("0x{}", hex::encode(s.signature))),
            signer,
        })
        .into_response(),
        Ok((None, _)) => err(StatusCode::NOT_FOUND, "unknown lock"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

async fn burn(State(ctx): State<Ctx>, Path(nonce): Path<u64>) -> Response {
    let k = BurnKey::new(ctx.params.deployment, nonce);
    match ctx.db(|t| t.burn(&k)) {
        Ok(Some(b)) => Json(BurnView {
            nonce,
            tx_hash: format!("0x{}", hex::encode(b.tx_hash)),
            amount: b.amount,
            recipient: format!("0x{}", hex::encode(&b.recipient)),
            recipient_address: YcashRecipient::from_bytes(&b.recipient)
                .ok()
                .map(|r| encode_address(&r, ctx.params.network)),
            state: b.state.to_string(),
            leader: b.leader.map(hex::encode),
            intent: b.intent.map(|i| i.to_string()),
        })
        .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "unknown burn"),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, format!("{e:#}")),
    }
}

async fn slash_sign(
    State(ctx): State<Ctx>,
    member: Option<Extension<PeerMember>>,
    Json(req): Json<SlashSignRequest>,
) -> Response {
    let requester = member.map(|m| hex::encode(m.0.0));
    match verify_and_sign(&ctx, &req).await {
        Ok(r) => {
            tracing::info!(event = "slash_vote_given_to", requester = ?requester);
            Json(r).into_response()
        }
        Err(e) => {
            tracing::warn!(event = "slash_vote_refused_here", requester = ?requester,
                           error = %format!("{e:#}"));
            err(StatusCode::FORBIDDEN, format!("{e:#}"))
        }
    }
}

async fn unlock_sign(
    State(ctx): State<Ctx>,
    member: Option<Extension<PeerMember>>,
    Json(req): Json<UnlockSignRequest>,
) -> Response {
    let requester = member.map(|m| m.0.0);
    match verify_and_sign_unlock(&ctx, requester, &req).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => {
            tracing::warn!(event = "unlock_sign_refused_here",
                           requester = ?requester.map(hex::encode), error = %format!("{e:#}"));
            err(StatusCode::FORBIDDEN, format!("{e:#}"))
        }
    }
}

async fn cancel_sign(
    State(ctx): State<Ctx>,
    member: Option<Extension<PeerMember>>,
    Json(req): Json<CancelSignRequest>,
) -> Response {
    let requester = member.map(|m| m.0.0);
    match verify_and_sign_cancel(&ctx, requester, &req).await {
        Ok(r) => Json(r).into_response(),
        Err(e) => {
            tracing::warn!(event = "cancel_sign_refused_here",
                           requester = ?requester.map(hex::encode), error = %format!("{e:#}"));
            err(StatusCode::FORBIDDEN, format!("{e:#}"))
        }
    }
}
