use crate::service::UmbraService;
use axum::{
    extract::{Json, Query, State},
    http::StatusCode,
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use umbra_rs::core::protocol::RelayerRequest;

#[derive(Serialize)]
pub struct StatusResponse {
    status: String,
    uptime: String,
}

pub async fn health_check() -> Json<StatusResponse> {
    Json(StatusResponse {
        status: "ok".to_string(),
        uptime: "running".to_string(),
    })
}

pub async fn system_status(State(service): State<Arc<UmbraService>>) -> impl IntoResponse {
    match service.get_system_status().await {
        Ok(status) => (StatusCode::OK, Json(status)).into_response(),
        Err(e) => {
            tracing::error!("Failed to get system status: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": e.to_string(),
                "connected": false
            }))).into_response()
        }
    }
}

pub async fn relay_handler(
    State(service): State<Arc<UmbraService>>,
    Json(payload): Json<RelayerRequest>,
) -> impl IntoResponse {
    match service.relay_transaction(payload).await {
        Ok(sig) => (StatusCode::OK, Json(serde_json::json!({
            "status": "success",
            "transaction": sig
        }))).into_response(),
        Err(e) => {
            tracing::error!("Relay failed: {}", e);
            (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "status": "failed",
                "error": e.to_string()
            }))).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct SyncQuery {
    since: Option<String>,
    limit: Option<i64>,
}

pub async fn sync_handler(
    State(service): State<Arc<UmbraService>>,
    Query(params): Query<SyncQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(100);
    match service.db().get_sync(params.since, limit).await {
        Ok(items) => (StatusCode::OK, Json(items)).into_response(),
        Err(e) => {
            tracing::error!("Sync failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": e.to_string()
            }))).into_response()
        }
    }
}
#[derive(Deserialize)]
pub struct MarkClaimedRequest {
    pub recipient: String, // Just logging who claimed it for now, logic relies on ID
    pub id: String,        // Signal ID to mark as claimed
}

pub async fn mark_claimed_handler(
    State(service): State<Arc<UmbraService>>,
    Json(payload): Json<MarkClaimedRequest>,
) -> impl IntoResponse {
    match service.db().mark_as_claimed(&payload.id).await {
        Ok(_) => (StatusCode::OK, Json(serde_json::json!({
            "status": "success"
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to mark claimed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "status": "failed",
                "error": e.to_string()
            }))).into_response()
        }
    }
}

#[derive(Serialize)]
pub struct SeedResponse {
    pub wallet_a: IdentityKeys,
    pub wallet_b: IdentityKeys,
}

#[derive(Serialize)]
pub struct IdentityKeys {
    pub view_secret: String,
    pub spend_secret: String,
    pub view_pub: String,
    pub spend_pub: String,
}

pub async fn seed_handler(State(service): State<Arc<UmbraService>>) -> impl IntoResponse {
    let factory = crate::mock_factory::MockDataFactory::new();

    // Seed the DB
    let stealth_keys_data: Vec<(String, String, String)> = match factory.seed_db_returned_data(service.db()).await {
        Ok(data) => data,
        Err(e) => return Json(serde_json::json!({ "status": "failed", "error": e.to_string() })).into_response(),
    };
    
    // Fund Relayer first to ensure it can pay for mock setup
    let relayer_pubkey = service.get_relayer_pubkey();
    let _ = service.request_airdrop(&relayer_pubkey, 5_000_000_000).await; // 5 SOL
    // Wait a bit for airdrop? Or request_airdrop confirms? (We updated request_airdrop to log only, but standard rpc client call confirms by default? No, send_transaction confirms, request_airdrop confirms).
    // Actually request_airdrop returns sig. We can assume it is fast.

    for (stealth_pk, eph_pk, cipher) in stealth_keys_data {
        match service.send_mock_signal(&stealth_pk, &eph_pk, &cipher, 0).await {
            Ok(_) => {},
            Err(e) => tracing::error!("Failed to initialize mock on-chain: {}", e),
        }
    }
    
    // Return the keys
    let wa = &factory.wallet_a_identity;
    let wb = &factory.wallet_b_identity;
    
    let to_keys = |id: &umbra_rs::core::Identity| IdentityKeys {
        view_secret: hex::encode(id.initiator_view_sk.to_bytes()),
        spend_secret: hex::encode(id.initiator_spend_sk.to_bytes()),
        view_pub: hex::encode(id.initiator_view_pk.to_bytes()),
        spend_pub: hex::encode(id.initiator_spend_pk.to_bytes()),
    };

    Json(SeedResponse {
        wallet_a: to_keys(wa),
        wallet_b: to_keys(wb),
    }).into_response()
}

#[derive(Deserialize)]
pub struct SendRequest {
    pub payer: String,
    pub recipient: String,
    pub amount: u64,
    pub token: Option<String>,
    pub memo: Option<String>,
}

pub async fn send_handler(
    State(service): State<Arc<UmbraService>>,
    Json(payload): Json<SendRequest>,
) -> impl IntoResponse {
    // Validate token
    if let Some(ref t) = payload.token {
        if t != "SOL" {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "status": "failed",
                "error": "SPL tokens not yet supported in MVP"
            }))).into_response();
        }
    }

    // Validate required fields
    if payload.payer.is_empty() || payload.recipient.is_empty() {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "status": "failed",
            "error": "payer and recipient are required"
        }))).into_response();
    }

    if payload.amount == 0 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
            "status": "failed",
            "error": "amount must be greater than 0"
        }))).into_response();
    }

    match service.create_stealth_transaction(
        &payload.payer,
        &payload.recipient,
        payload.amount,
        payload.memo.clone()
    ).await {
        Ok(tx_base64) => (StatusCode::OK, Json(serde_json::json!({
            "status": "created",
            "transaction": tx_base64
        }))).into_response(),
        Err(e) => {
            tracing::error!("Failed to create tx: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "status": "failed",
                "error": e.to_string()
            }))).into_response()
        }
    }
}

#[derive(Deserialize)]
pub struct InboxQuery {
    pub recipient: Option<String>, 
    pub since: Option<String>,
    pub limit: Option<i64>,
}

pub async fn inbox_handler(
    State(service): State<Arc<UmbraService>>,
    Query(params): Query<InboxQuery>,
) -> impl IntoResponse {
    let limit = params.limit.unwrap_or(50).min(100);
    // Return all announcements for client-side scanning
    match service.db().get_sync(params.since, limit).await {
        Ok(items) => (StatusCode::OK, Json(items)).into_response(),
        Err(e) => {
            tracing::error!("Inbox sync failed: {}", e);
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({
                "error": e.to_string()
            }))).into_response()
        }
    }
}
