use serde::{Deserialize, Serialize};
use sqlx::FromRow;

#[derive(Debug, Clone, Serialize, Deserialize, sqlx::Type, PartialEq)]
#[sqlx(rename_all = "lowercase")]
pub enum AnnouncementStatus {
    Pending,
    Claimed,
}

impl Default for AnnouncementStatus {
    fn default() -> Self {
        Self::Pending
    }
}

// Removed manual TryFrom and Type impls in favor of derive

#[derive(Debug, Clone, Serialize, Deserialize, FromRow)]
pub struct TxRecord {
    pub id: String,
    pub timestamp: String,
    pub payer: String,
    pub recipient: String,
    pub amount: f64,
    pub token: String,
    // Removed #[sqlx(try_from = "String")] - rely on sqlx::Type impl
    pub status: AnnouncementStatus,
    pub signature: String, 
    #[serde(default)]
    pub cipher_text: String,
    #[serde(default)]
    pub ephemeral_pubkey: String,
    #[serde(default)]
    pub hashed_tag: String,
}
