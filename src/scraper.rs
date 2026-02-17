use anyhow::Result;
use solana_client::rpc_client::{GetConfirmedSignaturesForAddress2Config, RpcClient};
use solana_sdk::{commitment_config::CommitmentConfig, pubkey::Pubkey, signature::Signature};
use std::{str::FromStr, sync::Arc, time::Duration};
use tokio::time::sleep;
use crate::db::Db;
use base64::Engine;

// Umbra Program ID (Localnet default)
const UMBRA_PROGRAM_ID: &str = "2L2TivMpeKJotzaHuQPUHDgfKaPwrvL5uGuhRw6dju96";

const ANNOUNCEMENT_DISCRIMINATOR: [u8; 8] = [110, 81, 147, 7, 34, 31, 5, 27];

pub async fn start_scraper(rpc_url: String, db: Db) {
    let rpc_client = Arc::new(RpcClient::new_with_commitment(
        rpc_url,
        CommitmentConfig::confirmed(),
    ));
    
    let program_id = Pubkey::from_str(UMBRA_PROGRAM_ID).unwrap();
    let mut last_signature: Option<Signature> = None;

    tracing::info!("Starting Umbra Scraper on {}", UMBRA_PROGRAM_ID);

    loop {
        if let Err(e) = scrape_loop(&rpc_client, &db, program_id, &mut last_signature).await {
            tracing::error!("Scraper error: {}", e);
        }
        sleep(Duration::from_secs(2)).await; // Poll every 2s
    }
}

async fn scrape_loop(
    rpc: &RpcClient,
    db: &Db,
    program_id: Pubkey,
    last_sig: &mut Option<Signature>,
) -> Result<()> {
    // 1. Fetch Signatures
    let mut config = GetConfirmedSignaturesForAddress2Config {
        limit: Some(20),
        commitment: Some(CommitmentConfig::confirmed()),
        ..Default::default()
    };
    if let Some(sig) = last_sig {
        config.until = Some(*sig);
    }

    let signatures = rpc.get_signatures_for_address_with_config(&program_id, config)?;
    
    // Process in reverse (oldest first)
    for sig_info in signatures.iter().rev() { 
        let signature = Signature::from_str(&sig_info.signature)?;
        *last_sig = Some(signature); 

        if let Some(err) = sig_info.err.as_ref() {
            tracing::warn!("Skipping failed transaction: {} - Error: {:?}", signature, err);
            continue; 
        }
        
        let tx = rpc.get_transaction_with_config(&signature, solana_client::rpc_config::RpcTransactionConfig {
            encoding: Some(solana_transaction_status::UiTransactionEncoding::Json),
            commitment: Some(CommitmentConfig::confirmed()),
            max_supported_transaction_version: Some(0),
        })?;

        let payer = extract_payer(&tx.transaction.transaction);

        // 2. Parse Logs for Events
        if let Some(meta) = tx.transaction.meta {
             let logs_opt = match meta.log_messages {
                 solana_transaction_status::option_serializer::OptionSerializer::Some(logs) => Some(logs),
                 _ => None,
             };

            if let Some(log_messages) = logs_opt {
                for log in log_messages {
                    // Look for "Program data: "
                    if let Some(data_str) = log.strip_prefix("Program data: ") {
                         // Decode Base64
                         if let Ok(data) = base64::engine::general_purpose::STANDARD.decode(data_str) {
                             if data.len() > 8 && data[0..8] == ANNOUNCEMENT_DISCRIMINATOR {
                                 
                                 if data.len() < 76 { continue; }
                                 
                                 let ephemeral_pubkey_bytes = &data[8..40];
                                 let hashed_tag_bytes = &data[40..72];
                                 
                                 let len_bytes: [u8; 4] = data[72..76].try_into().unwrap();
                                 let ct_len = u32::from_le_bytes(len_bytes) as usize;
                                 
                                 if data.len() < 76 + ct_len { continue; }
                                 let ciphertext_bytes = &data[76..76+ct_len];
                                 
                                 // Parse optional token_mint after ciphertext
                                 let token_mint = {
                                     let mint_offset = 76 + ct_len;
                                     if data.len() > mint_offset {
                                         // Borsh Option: 0 = None, 1 = Some(pubkey)
                                         if data[mint_offset] == 1 && data.len() >= mint_offset + 1 + 32 {
                                             Some(Pubkey::new_from_array(
                                                 data[mint_offset+1..mint_offset+33].try_into().unwrap()
                                             ).to_string())
                                         } else {
                                             None
                                         }
                                     } else {
                                         None
                                     }
                                 };
                                 
                                 let token = token_mint.as_deref().unwrap_or("SOL");
                                 
                                 // Convert to hex for WASM consistency
                                 let ephemeral_pubkey = hex::encode(ephemeral_pubkey_bytes);
                                 let hashed_tag = hex::encode(hashed_tag_bytes);
                                 let cipher_text = hex::encode(ciphertext_bytes);
                                 
                                 tracing::info!(
                                     "Indexed Announcement: ephem={} token={} payer={} tx={}",
                                     &ephemeral_pubkey[..16], token, &payer, signature
                                 );
                                 
                                 db.save_announcement(
                                     &signature.to_string(),
                                     &payer,
                                     &cipher_text,
                                     &ephemeral_pubkey,
                                     &hashed_tag
                                 ).await?;
                             }
                         }
                    }
                }
            }
        }
    }
    
    Ok(())
}

/// Extract the fee payer (first account key) from a transaction envelope.
fn extract_payer(tx: &solana_transaction_status::EncodedTransaction) -> String {
    use solana_transaction_status::EncodedTransaction;
    match tx {
        EncodedTransaction::Json(ui_tx) => {
            match &ui_tx.message {
                solana_transaction_status::UiMessage::Parsed(msg) => {
                    msg.account_keys.first()
                        .map(|k| k.pubkey.clone())
                        .unwrap_or_else(|| "unknown".to_string())
                }
                solana_transaction_status::UiMessage::Raw(msg) => {
                    msg.account_keys.first()
                        .cloned()
                        .unwrap_or_else(|| "unknown".to_string())
                }
            }
        }
        _ => "unknown".to_string(),
    }
}
