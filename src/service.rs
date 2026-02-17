use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose, Engine as _};
use solana_client::rpc_client::RpcClient;
use solana_sdk::{
    commitment_config::CommitmentConfig,
    instruction::{AccountMeta, Instruction},
    pubkey::Pubkey,
    signature::{Keypair, Signer},
    transaction::Transaction,
    system_program,
    sysvar,
};
use std::str::FromStr;
use std::sync::Arc;
use crate::db::Db;
use umbra_rs::core::protocol::RelayerRequest;
use rand::rngs::OsRng;
use umbra_rs::core::{derive_for_initiator, encrypt_memo, Identity, PointWrapper, ScalarWrapper};

// UMBRA PROGRAM ID
const UMBRA_PROGRAM_ID: &str = "2L2TivMpeKJotzaHuQPUHDgfKaPwrvL5uGuhRw6dju96";

pub struct UmbraService {
    rpc_client: RpcClient,
    db: Db,
    keypair: Arc<Keypair>, // Relayer keypair
    program_id: Pubkey,
}

impl UmbraService {
    pub fn new(rpc_url: &str, db: Db) -> Self {
        let rpc_client = RpcClient::new_with_commitment(rpc_url.to_string(), CommitmentConfig::confirmed());
        
        // Load relayer keypair from keys directory (Tom is our relayer)
        let keypair = match std::fs::read_to_string("../keys/Tom.json") {
            Ok(content) => {
                let bytes: Vec<u8> = serde_json::from_str(&content)
                    .expect("Failed to parse Tom.json keypair");
                Arc::new(Keypair::from_bytes(bytes.as_slice()).expect("Invalid keypair bytes"))
            }
            Err(e) => {
                tracing::warn!("Could not load ../keys/Tom.json: {}, using random keypair", e);
                Arc::new(Keypair::new())
            }
        };
        tracing::info!("Relayer pubkey: {}", keypair.pubkey());
        let program_id = Pubkey::from_str(UMBRA_PROGRAM_ID).unwrap();

        Self {
            rpc_client,
            db,
            keypair,
            program_id,
        }
    }

    pub fn db(&self) -> &Db {
        &self.db
    }

    pub fn get_relayer_pubkey(&self) -> Pubkey {
        self.keypair.pubkey()
    }
    
    pub async fn get_system_status(&self) -> Result<serde_json::Value> {
        let version = self.rpc_client
            .get_version()
            .map(|v| v.solana_core)
            .unwrap_or_else(|_| "unknown".to_string());
        
        // Check balance
        let balance = self.rpc_client.get_balance(&self.keypair.pubkey()).unwrap_or(0);

        Ok(serde_json::json!({
            "system": "umbra-relayer",
            "cluster_version": version,
            "connected": true,
            "relayer_balance": balance,
            "relayer_pubkey": self.keypair.pubkey().to_string(),
        }))
    }

    pub async fn request_airdrop(&self, pubkey: &Pubkey, lamports: u64) -> Result<()> {
        let sig = self.rpc_client.request_airdrop(pubkey, lamports)?;
        // Wait for confirmation?
        // simple simulation usually fast on test validator
        // But for robustness:
        // self.rpc_client.confirm_transaction(&sig)?; // blocking
        // async version? RpcClient is blocking client unless we use nonblocking.
        // solana_client::rpc_client::RpcClient IS blocking.
        // We are in async fn, but calling blocking RPC. It warns but works.
        // We shouldn't block loop too long.
        tracing::info!("Airdropped {} to {}", lamports, pubkey);
        Ok(())
    }

    /// Executed by the Relayer.
    /// 1. Verify fee is enough? (Optional logic here, strictly program checks it).
    /// 2. Construct Transaction with Ed25519 Sig Verify + WithdrawWithRelayer.
    /// 3. Sign and Send.
    pub async fn relay_transaction(&self, req: RelayerRequest) -> Result<String> {
        let stealth_pubkey = Pubkey::from_str(&req.stealth_pubkey).context("Invalid stealth pubkey")?;
        let recipient_pubkey = Pubkey::from_str(&req.recipient_pubkey).context("Invalid recipient pubkey")?;

        // 1. Decode Signature
        let signature_bytes = general_purpose::STANDARD.decode(&req.signature)
            .or_else(|_| hex::decode(&req.signature))
            .context("Invalid signature format")?;

        // 2. Construct Message for verification
        // Message = stealth_pubkey (32) || recipient_pubkey (32) || amount (8) || fee (8)
        let mut message = Vec::new();
        message.extend_from_slice(stealth_pubkey.as_ref());
        message.extend_from_slice(recipient_pubkey.as_ref());
        message.extend_from_slice(&req.amount.to_le_bytes()); 
        message.extend_from_slice(&req.relayer_fee.to_le_bytes());

        // 3. Construct Ed25519 Instruction
        // The Ed25519 Program expects: [num_sigs(1) | padding(1) | offsets...]
        // We construct it manually or use solana_sdk::ed25519_instruction if available?
        // solana_sdk doesn't export a builder easily for arbitrary messages without keypairs?
        // actually `solana_sdk::ed25519_instruction::new_ed25519_instruction` takes keypair.
        // We don't have the signer's private key! We have signature.
        // So we must manually build the instruction data.
        
        let mut ix_data = Vec::new();
        let num_signatures: u8 = 1;
        let padding: u8 = 0;
        let header_size = 16;
        let pubkey_offset = header_size;
        let signature_offset = pubkey_offset + 32;
        let message_offset = signature_offset + 64;
        
        ix_data.push(num_signatures);
        ix_data.push(padding);
        ix_data.extend_from_slice(&(signature_offset as u16).to_le_bytes()); // sig_offset
        ix_data.extend_from_slice(&u16::MAX.to_le_bytes());                  // sig_ix
        ix_data.extend_from_slice(&(pubkey_offset as u16).to_le_bytes());    // pk_offset
        ix_data.extend_from_slice(&u16::MAX.to_le_bytes());                  // pk_ix
        ix_data.extend_from_slice(&(message_offset as u16).to_le_bytes());   // msg_offset
        ix_data.extend_from_slice(&(message.len() as u16).to_le_bytes());    // msg_size
        ix_data.extend_from_slice(&u16::MAX.to_le_bytes());                  // msg_ix

        // Append data
        ix_data.extend_from_slice(stealth_pubkey.as_ref()); // Signer is the stealth pubkey (Wait? No)
        // CHECK: Who signs the message?
        // The Stealth Keypair (P_stealth) signs the message!
        // But `stealth_pubkey` passed here is the PDA? No, it's the `stealth_pubkey` (P)!
        // Verify: Client sends `stealth_pubkey` (P) as the authority.
        // AND the `stealth_pda` is derived from it.
        // The Program checks `stealth_pda` seeds = ["stealth", authority].
        // So `stealth_pubkey` here MUST be the AUTHORITY (P).
        // Correct.
        ix_data.extend_from_slice(&signature_bytes);
        ix_data.extend_from_slice(&message);

        let ed25519_ix = Instruction {
            program_id: solana_sdk::ed25519_program::id(),
            accounts: vec![],
            data: ix_data,
        };

        // 4. Construct Umbra Instruction
        // Discriminator: withdrawWithRelayer = [80, 91, 252, 165, 89, 9, 77, 238]
        let discriminator: [u8; 8] = [80, 91, 252, 165, 89, 9, 77, 238];
        let mut umbra_data = Vec::new();
        umbra_data.extend_from_slice(&discriminator);
        umbra_data.extend_from_slice(&req.relayer_fee.to_le_bytes()); // Args: fee (u64)

        // Accounts:
        // 1. stealth_pda (mut)
        // 2. relayer (mut, signer)
        // 3. recipient (mut)
        // 4. instructions (sysvar)
        
        // Derive PDA
        let (stealth_pda, _bump) = Pubkey::find_program_address(
            &[b"stealth", stealth_pubkey.as_ref()],
            &self.program_id
        );
        
        let accounts = vec![
            AccountMeta::new(stealth_pda, false),
            AccountMeta::new(self.keypair.pubkey(), true), // Relayer signs payer
            AccountMeta::new(recipient_pubkey, false), 
            AccountMeta::new_readonly(sysvar::instructions::id(), false),
        ];

        let umbra_ix = Instruction {
            program_id: self.program_id,
            accounts,
            data: umbra_data,
        };

        // 5. Sign and Send
        let latest_blockhash = self.rpc_client.get_latest_blockhash()
            .context("Failed to get blockhash")?;

        let tx = Transaction::new_signed_with_payer(
            &[ed25519_ix, umbra_ix],
            Some(&self.keypair.pubkey()),
            &[&*self.keypair],
            latest_blockhash,
        );

        // 5. Simulate Transaction (Debug)
        let sim_result = self.rpc_client.simulate_transaction(&tx)
            .context("Simulation failed")?;
        
        if let Some(err) = sim_result.value.err {
            tracing::error!("Simulation error: {:?}", err);
            tracing::error!("Simulation logs: {:?}", sim_result.value.logs);
            return Err(anyhow!("Simulation failed: {:?}", err));
        } else {
            tracing::info!("Simulation successful. Logs: {:?}", sim_result.value.logs);
        }

        let sig = self.rpc_client.send_and_confirm_transaction(&tx)
            .context("Transaction failed")?;
            
        tracing::info!("Relayed transaction: {}", sig);
        Ok(sig.to_string())
    }

    pub async fn send_mock_signal(
        &self,
        stealth_pubkey_hex: &str,
        ephemeral_pubkey_hex: &str,
        cipher_text_hex: &str,
        _amount: u64, // Ignored for now, we use a fixed 1 SOL for mock
    ) -> Result<String> {
        let payer_pubkey = self.keypair.pubkey();
        
        // 1. Parse Keys
        let stealth_pubkey_bytes = hex::decode(stealth_pubkey_hex).context("Invalid stealth pubkey hex")?;
        let stealth_pubkey = Pubkey::new_from_array(stealth_pubkey_bytes.try_into().unwrap());
        
        let eph_bytes = hex::decode(ephemeral_pubkey_hex).context("Invalid ephemeral pubkey hex")?;
        let cipher_bytes = hex::decode(cipher_text_hex).context("Invalid cipher hex")?;

        // 2. Construct Data
        // Discriminator 0: SendStealth
        let discriminator: u8 = 0;
        let amount_u64: u64 = 1_000_000_000; // 1 SOL
        let hashed_tag = [0u8; 32];
        
        let mut ix_data = Vec::new();
        ix_data.push(discriminator);
        ix_data.extend_from_slice(&amount_u64.to_le_bytes());
        ix_data.extend_from_slice(&eph_bytes); // 32
        ix_data.extend_from_slice(&hashed_tag); // 32
        ix_data.extend_from_slice(&(cipher_bytes.len() as u32).to_le_bytes());
        ix_data.extend_from_slice(&cipher_bytes);

        // 3. Derive PDA
        let (stealth_pda, _) = Pubkey::find_program_address(
            &[b"stealth", stealth_pubkey.as_ref()],
            &self.program_id
        );

        // 4. Create Instruction
        let accounts = vec![
            AccountMeta::new(payer_pubkey, true),
            AccountMeta::new(stealth_pda, false),
            AccountMeta::new_readonly(stealth_pubkey, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id: self.program_id,
            accounts,
            data: ix_data,
        };

        // 5. Send
        let latest_blockhash = self.rpc_client.get_latest_blockhash()
            .context("Failed to get blockhash")?;

        let tx = Transaction::new_signed_with_payer(
            &[instruction],
            Some(&payer_pubkey),
            &[&*self.keypair],
            latest_blockhash,
        );

        let sig = self.rpc_client.send_and_confirm_transaction(&tx)
            .context("Mock Send failed")?;
        
        tracing::info!("Mock signal sent on-chain: {} -> PDA: {}", sig, stealth_pda);
        Ok(sig.to_string())
    }
    pub async fn create_stealth_transaction(
        &self,
        payer_pubkey_str: &str,
        recipient_identity: &str, 
        amount: u64,
        memo: Option<String>,
    ) -> Result<String> {
        let payer_pubkey = Pubkey::from_str(payer_pubkey_str).context("Invalid payer pubkey")?;

        // 1. Parse Key (Expect 'view_hex:spend_hex')
        let parts: Vec<&str> = recipient_identity.split(':').collect();
        if parts.len() != 2 {
            return Err(anyhow!("Recipient identity must be 'view_pub_hex:spend_pub_hex'"));
        }
        let view_bytes = hex::decode(parts[0]).context("Invalid view pubkey hex")?;
        let spend_bytes = hex::decode(parts[1]).context("Invalid spend pubkey hex")?;
        
        let view_pt = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&view_bytes).context("Invalid view point")?;
        let spend_pt = curve25519_dalek::edwards::CompressedEdwardsY::from_slice(&spend_bytes).context("Invalid spend point")?;

        // Construct Public Identity (Secrets are dummy)
        let recipient = Identity {
            initiator_view_sk: ScalarWrapper::from_bytes([0u8; 32]), // Dummy
            initiator_spend_sk: ScalarWrapper::from_bytes([0u8; 32]), // Dummy
            initiator_view_pk: PointWrapper(view_pt.decompress().context("Failed to decompress view point")?), 
            initiator_spend_pk: PointWrapper(spend_pt.decompress().context("Failed to decompress spend point")?),
        };

        // 2. Perform ECDH & Derivation
        let mut rng = OsRng;
        let output = derive_for_initiator(&recipient, &mut rng);
        
        // 3. Encrypt Memo
        let encrypted_memo = if let Some(m) = memo {
             encrypt_memo(&mut rng, &output.shared_secret_hash, &m).map_err(|e| anyhow!(e)).context("Encryption failed")?
        } else {
             encrypt_memo(&mut rng, &output.shared_secret_hash, "").map_err(|e| anyhow!(e)).context("Encryption failed")?
        };
        let cipher_bytes = hex::decode(&encrypted_memo).context("Invalid cipher hex output")?;

        // 4. Construct Instruction Data (SendStealth)
        // Format: [0 (discriminator), amount (u64), ephemeral_pk (32), hashed_tag (32), cipher_len (u32), cipher_data...]
        let mut data = Vec::new();
        data.push(0u8); // Discriminator::SendStealth
        data.extend_from_slice(&amount.to_le_bytes());
        data.extend_from_slice(output.ephemeral_pubkey.to_bytes().as_slice());
        data.extend_from_slice(&output.shared_secret_hash.to_bytes()); 
        
        data.extend_from_slice(&(cipher_bytes.len() as u32).to_le_bytes());
        data.extend_from_slice(&cipher_bytes);

        // 5. Construct Keys
        let stealth_pubkey_bytes = output.one_time_pubkey.to_bytes();
        let stealth_pubkey = Pubkey::new_from_array(stealth_pubkey_bytes);
        
        let (stealth_pda, _) = Pubkey::find_program_address(
            &[b"stealth", stealth_pubkey.as_ref()],
            &self.program_id
        );

        let accounts = vec![
            AccountMeta::new(payer_pubkey, true),
            AccountMeta::new(stealth_pda, false),
            AccountMeta::new_readonly(stealth_pubkey, false),
            AccountMeta::new_readonly(system_program::id(), false),
        ];

        let instruction = Instruction {
            program_id: self.program_id,
            accounts,
            data,
        };

        // 6. Build Transaction
        let latest_blockhash = self.rpc_client.get_latest_blockhash()
            .context("Failed to get blockhash")?;

        let mut tx = Transaction::new_unsigned(solana_sdk::message::Message::new(
            &[instruction],
            Some(&payer_pubkey),
        ));
        
        tx.message.recent_blockhash = latest_blockhash;
        
        let serialized = bincode::serialize(&tx).context("Failed to serialize transaction")?;
        Ok(base64::engine::general_purpose::STANDARD.encode(serialized))
    }
}
