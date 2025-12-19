use axum::{
    extract::{State, Json, Query},
    response::IntoResponse,
};
use serde::{Deserialize, Serialize};
use std::sync::{Arc, Mutex};
use once_cell::sync::Lazy;
use crate::service::UmbraService;

// --- Transaction Registry (In-Memory for Demo) ---
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxRecord {
    pub id: String,
    pub timestamp: String,
    pub payer: String,
    pub recipient: String,
    pub amount: f64,
    pub token: String,
    pub status: String,
    pub signature: String, // Filled after confirmation if possible, or just tx id
}

// Global Registry
static REGISTRY: Lazy<Mutex<Vec<TxRecord>>> = Lazy::new(|| Mutex::new(Vec::new()));

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

pub async fn system_status(
    State(service): State<Arc<UmbraService>>,
) -> impl IntoResponse {
    match service.get_system_status().await {
        Ok(status) => Json(status),
        Err(e) => {
            tracing::error!("Failed to get system status: {}", e);
            Json(serde_json::json!({ "connected": false, "error": e.to_string() }))
        }
    }
}

#[derive(Deserialize)]
pub struct SendRequest {
    payer: String, 
    recipient: String,
    amount: String,
    token: String,
}

#[derive(Serialize)]
pub struct SendResponse {
    transaction: String, // Base64 serialized tx
    status: String,
}

pub async fn send_handler(
    State(service): State<Arc<UmbraService>>,
    Json(payload): Json<SendRequest>,
) -> impl IntoResponse {
    let amount = payload.amount.parse::<f64>().unwrap_or(0.0);
    
    match service.create_transaction(&payload.payer, &payload.recipient, &payload.token, amount).await {
        Ok(tx_base64) => {
            // Register the transaction in our "DB"
            let record = TxRecord {
                id: uuid::Uuid::new_v4().to_string(),
                timestamp: chrono::Utc::now().to_rfc3339(),
                payer: payload.payer.clone(),
                recipient: payload.recipient.clone(),
                amount,
                token: payload.token.clone(),
                status: "claimable".to_string(), // Assume successful send = claimable for now
                signature: "".to_string(), // We don't know the sig yet until client submits
            };
            
            if let Ok(mut db) = REGISTRY.lock() {
                db.push(record);
            }

            Json(SendResponse {
                transaction: tx_base64,
                status: "created".to_string(),
            })
        },
        Err(e) => {
            tracing::error!("Create tx failed: {}", e);
             Json(SendResponse {
                transaction: "".to_string(),
                status: "failed".to_string(),
            })
        }
    }
}

#[derive(Deserialize)]
pub struct InboxQuery {
    recipient: String,
}

pub async fn inbox_handler(
    Query(params): Query<InboxQuery>,
) -> impl IntoResponse {
    let db = REGISTRY.lock().unwrap();
    // Filter by recipient
    let items: Vec<TxRecord> = db.iter()
        .filter(|r| r.recipient == params.recipient)
        .cloned()
        .collect();
        
    Json(items)
}

#[derive(Deserialize)]
pub struct ClaimRequest {
    recipient: String,
}

pub async fn claim_handler(
    State(service): State<Arc<UmbraService>>,
    Json(payload): Json<ClaimRequest>,
) -> impl IntoResponse {
    match service.claim_funds(&payload.recipient).await {
        Ok(sigs) => Json(serde_json::json!({ 
            "status": "success", 
            "signatures": sigs 
        })),
        Err(e) => {
            tracing::error!("Claim failed: {}", e);
            Json(serde_json::json!({ 
                "status": "failed", 
                "error": e.to_string() 
            }))
        }
    }
}
