use anyhow::{anyhow, Result};
use base64::{engine::general_purpose, Engine as _};
use rand_core::OsRng;
use solana_sdk::{
    message::Message,
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
};
use std::str::FromStr;
use std::sync::Arc;
use umbra_api::{UmbraApi, UmbraApiConfig};
use umbra_core::Identity;

use std::collections::HashMap;
use std::sync::Mutex;

pub struct UmbraService {
    rpc_url: String, // Stored to recreate API with different sweep dests
    api: Arc<UmbraApi>,
    // We keep a backend keypair for potential relayer usage.
    keypair: Keypair,
    // DEMO ONLY: Store full identities (with secret keys) for recipients so we can claim for them.
    // Map: Recipient Pubkey String -> Identity
    shadow_identities: Mutex<HashMap<String, Identity>>,
}

impl UmbraService {
    pub fn new(rpc_url: &str) -> Self {
        let keypair = Keypair::new();
        // Default sweep dest (unused effectively since we create per-claim APIs)
        let dummy_sweep_dest = Pubkey::new_unique();

        let config = UmbraApiConfig::new(rpc_url, dummy_sweep_dest);
        let api = Arc::new(UmbraApi::new(config));

        Self {
            rpc_url: rpc_url.to_string(),
            api,
            keypair,
            shadow_identities: Mutex::new(HashMap::new()),
        }
    }

    /// Instead of sending the transaction, we build it and return it for the user to sign/send.
    /// Returns: Base64 encoded serialized transaction
    pub async fn create_transaction(
        &self,
        payer: &str,
        recipient: &str,
        token: &str,
        amount_sol: f64,
    ) -> Result<String> {
        if token != "SOL" {
            return Err(anyhow!("Only SOL transfers are currently supported"));
        }
        let payer_pubkey =
            Pubkey::from_str(payer).map_err(|e| anyhow!("Invalid payer pubkey: {}", e))?;

        let amount_lamports = (amount_sol * 1_000_000_000.0) as u64;

        // DEMO: Get or Create Shadow Identity for this Recipient
        // We use this identity so the backend "knows" the private keys and can claim later.
        // We assume the user creates this identity "off-band" or the app manages it.
        let mut map = self.shadow_identities.lock().unwrap();
        let recipient_identity = map.entry(recipient.to_string()).or_insert_with(|| {
            // Generate a fresh random identity for this recipient address
            // In a real app, the recipient would provide their public keys.
            let mut rng = OsRng;
            Identity::new_random(&mut rng)
        });
        
        // We must clone or reference the identity. Identity doesn't impl Clone, 
        // effectively we need to use it to build the transfer.
        // build_initiator_transfer takes &Identity.
        
        // Since we hold the lock, we can just reference it.
        
        let mut rng = OsRng;
        
        // Build Initiator Transfer
        let transfer = self.api.build_initiator_transfer(
            recipient_identity,
            &mut rng,
            payer_pubkey,
            amount_lamports,
        )?;
        
        // Drop lock early
        drop(map);

        let recent_blockhash = self.api.rpc().get_latest_blockhash()?;

        // Create an Unsigned Transaction because the User needs to sign it.
        // We assume the user (payer) will sign.
        let mut msg = Message::new(&transfer.instructions, Some(&payer_pubkey));
        msg.recent_blockhash = recent_blockhash;

        let tx = Transaction::new_unsigned(msg);

        // Serialize
        // Use bincode or solana's serialization
        let serialized = bincode::serialize(&tx)?;
        let base64_tx = general_purpose::STANDARD.encode(&serialized);

        // Simulate to catch errors early
        let sim_result = self.api.rpc().simulate_transaction(&tx);
        match sim_result {
            Ok(sim) => {
                if let Some(err) = sim.value.err {
                    tracing::error!("Simulation failed: {:?}", err);
                    // We can optionally return the error to the user or just log it
                    // For now, let's return it as an error so the frontend knows
                    return Err(anyhow!("Simulation failed: {:?}", err));
                }
                tracing::info!("Simulation successful. Logs: {:?}", sim.value.logs);
            }
            Err(e) => {
                tracing::error!("Simulation RPC error: {}", e);
                return Err(anyhow!("Simulation RPC error: {}", e));
            }
        }

        tracing::info!(
            "Built Transaction for Payer: {}, Amount: {}, Payload Size: {}",
            payer,
            amount_sol,
            base64_tx.len()
        );

        Ok(base64_tx)
    }

    pub async fn get_system_status(&self) -> Result<serde_json::Value> {
        let client = self.api.rpc();
        let version = client
            .get_version()
            .map(|v| v.solana_core)
            .unwrap_or_else(|_| "unknown".to_string());

        Ok(serde_json::json!({
            "system": "umbra-connected",
            "cluster_version": version,
            "connected": true,
        }))
    }
    
    // DEMO: Claim funds for a recipient using the stored Shadow Identity
    pub async fn claim_funds(&self, recipient: &str) -> Result<Vec<String>> {
        let map = self.shadow_identities.lock().unwrap();
        let identity = map.get(recipient).ok_or(anyhow!("No identity found for this recipient. Have you sent funds to them yet?"))?;
        
        let recipient_pubkey = Pubkey::from_str(recipient)?;
        
        // Create a temporary API instance configured to sweep TO the recipient
        let config = UmbraApiConfig::new(&self.rpc_url, recipient_pubkey);
        let temp_api = UmbraApi::new(config);
        
        let current_slot = temp_api.rpc().get_slot()?;
        // Scan a reasonable range (e.g. last 1000 blocks or from 0 for local)
        // Localnet is usually short-lived, so 0 is fine.
        let start_slot = 0; 
        
        tracing::info!("Scanning for claimable funds for {} (Shadow Identity) up to slot {}", recipient, current_slot);
        
        let summary = temp_api.scan_plan_and_sweep_slot_range(identity, start_slot, current_slot)?;
        
        let mut signatures = Vec::new();
        
        for (plan, sig) in summary.successful_sweeps {
             tracing::info!("Swept {} lamports to {} (Sig: {})", plan.amount, plan.destination, sig);
             signatures.push(sig.to_string());
        }
        
        for (plan, err) in summary.failed_sweeps {
             tracing::error!("Failed to sweep {} lamports to {}: {:?}", plan.amount, plan.destination, err);
             // We can return errors too if needed, but for now just log
        }
        
        if signatures.is_empty() && summary.owned_outputs.is_empty() {
             return Err(anyhow!("No claimable funds found."));
        }
        
        Ok(signatures)
    }
}
