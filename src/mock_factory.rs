use crate::db::Db;
use crate::models::AnnouncementStatus;
use anyhow::Result;
use rand::rngs::OsRng;
use umbra_rs::core::{derive_for_initiator, encrypt_memo, Identity};

pub struct MockDataFactory {
    pub wallet_a_identity: Identity,
    pub wallet_b_identity: Identity,
}

#[derive(Clone)]
pub struct MockAnnouncement {
    pub cipher_text: String,
    pub ephemeral_pubkey: String,
    pub stealth_pubkey: String, // P (needed for funding PDA)
    pub hashed_tag: String,
    pub status: AnnouncementStatus,
    pub recipient_label: String, // "Wallet A" or "Wallet B"
}

impl MockDataFactory {
    // ... new() ...

    pub fn new() -> Self {
        let mut rng = OsRng;

        let wallet_a_identity = Identity::new_random(&mut rng);
        let wallet_b_identity = Identity::new_random(&mut rng);

        MockDataFactory {
            wallet_a_identity,
            wallet_b_identity,
        }
    }

    /// Generate an announcement for a specific recipient
    fn create_signal(
        &self,
        recipient: &Identity,
        status: AnnouncementStatus,
        memo: &str,
    ) -> MockAnnouncement {
        let mut rng = OsRng;

        // Use recipient's public keys only
        let recipient_pub = Identity {
            initiator_spend_sk: umbra_rs::core::ScalarWrapper::from_bytes([0u8; 32]),
            initiator_view_sk: umbra_rs::core::ScalarWrapper::from_bytes([0u8; 32]),
            initiator_spend_pk: recipient.initiator_spend_pk.clone(),
            initiator_view_pk: recipient.initiator_view_pk.clone(),
        };

        let output = derive_for_initiator(&recipient_pub, &mut rng);
        let encrypted =
            encrypt_memo(&mut rng, &output.shared_secret_hash, memo).expect("Encrypt failed");

        MockAnnouncement {
            cipher_text: encrypted,
            ephemeral_pubkey: hex::encode(output.ephemeral_pubkey.to_bytes()), // PointWrapper -> bytes -> hex
            stealth_pubkey: hex::encode(output.one_time_pubkey.to_bytes()),    // Store P
            hashed_tag: "".to_string(), // Tagging not strictly enforced in this mock yet
            status,
            recipient_label: "Unknown".to_string(),
        }
    }

    pub fn generate_set_a(&self) -> Vec<MockAnnouncement> {
        vec![
            self.create_signal(
                &self.wallet_a_identity,
                AnnouncementStatus::Pending,
                "Payment from Alice (Pending)",
            ),
            self.create_signal(
                &self.wallet_a_identity,
                AnnouncementStatus::Pending,
                "Salary Deposit (Pending)",
            ),
            self.create_signal(
                &self.wallet_a_identity,
                AnnouncementStatus::Pending,
                "Secret Gift (Pending)",
            ),
        ]
    }

    pub fn generate_set_b(&self) -> Vec<MockAnnouncement> {
        vec![
            self.create_signal(
                &self.wallet_b_identity,
                AnnouncementStatus::Pending,
                "B's Secret Stash",
            ),
            self.create_signal(
                &self.wallet_b_identity,
                AnnouncementStatus::Pending,
                "Refund for B",
            ),
        ]
    }

    pub fn generate_set_c(&self) -> Vec<MockAnnouncement> {
        vec![
            self.create_signal(
                &self.wallet_a_identity,
                AnnouncementStatus::Claimed,
                "Old Claimed Payment",
            ),
            self.create_signal(
                &self.wallet_a_identity,
                AnnouncementStatus::Claimed,
                "Another Claimed Item",
            ),
        ]
    }

    pub async fn seed_db_returned_data(&self, db: &Db) -> Result<Vec<(String, String, String)>> {
        let all_signals = [
            self.generate_set_a(),
            self.generate_set_b(),
            self.generate_set_c(),
        ]
        .concat();

        let mut pending_signals = Vec::new();

        for sig in all_signals {
            let id = uuid::Uuid::new_v4().to_string();
            let payer = "MockPayer";

            // Status string
            let status_str = match sig.status {
                AnnouncementStatus::Pending => "pending",
                AnnouncementStatus::Claimed => "claimed",
            };

            // Random signature for uniqueness
            let signature = format!("sig_{}", uuid::Uuid::new_v4());

            db.save_test_announcement(
                &id,
                status_str,
                &signature,
                payer,
                &sig.cipher_text,
                &sig.ephemeral_pubkey,
            )
            .await?;

            // Collect stealth keys for Pending signals (need on-chain init)
            if sig.status == AnnouncementStatus::Pending {
                pending_signals.push((
                    sig.stealth_pubkey.clone(),
                    sig.ephemeral_pubkey.clone(),
                    sig.cipher_text.clone(),
                ));
            }
        }
        Ok(pending_signals)
    }
}
