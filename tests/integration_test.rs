//! Integration test for the full stealth payment flow.
//!
//! This test simulates:
//! 1. Alice generates Umbra identity
//! 2. Bob generates Umbra identity
//! 3. Alice encrypts a payment for Bob using Bob's public keys
//! 4. Alice sends the stealth transaction
//! 5. Bob scans and finds the payment
//! 6. (Optional) Bob withdraws

use rand::rngs::OsRng;
use solana_sdk::{
    signature::{read_keypair_file, Keypair},
    signer::Signer,
};
use std::path::PathBuf;
use umbra_rs::core::{
    decrypt_memo, derive_for_initiator, derive_shared_secret_view_only, encrypt_memo, Identity,
};

/// Helper to load keypair from keys directory
fn load_keypair(name: &str) -> Keypair {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .join("keys")
        .join(format!("{}.json", name));
    read_keypair_file(&path).expect(&format!("Failed to load keypair: {}", name))
}

#[test]
fn test_stealth_flow_alice_to_bob() {
    // 1. Load Solana keypairs (for funding, not for stealth crypto)
    let alice_keypair = load_keypair("Alice");
    let bob_keypair = load_keypair("Bob");

    println!("Alice wallet: {}", alice_keypair.pubkey());
    println!("Bob wallet: {}", bob_keypair.pubkey());

    // 2. Generate Umbra Identities
    let mut rng = OsRng;
    let alice_identity = Identity::new_random(&mut rng);
    let bob_identity = Identity::new_random(&mut rng);

    println!("\n=== Bob's Stealth Address (share with Alice) ===");
    let bob_view_pub_hex = hex::encode(bob_identity.initiator_view_pk.to_bytes());
    let bob_spend_pub_hex = hex::encode(bob_identity.initiator_spend_pk.to_bytes());
    println!("viewPub: {}", bob_view_pub_hex);
    println!("spendPub: {}", bob_spend_pub_hex);
    println!("Full: {}:{}", bob_view_pub_hex, bob_spend_pub_hex);

    // 3. Alice encrypts a message for Bob
    println!("\n=== Alice Encrypts Payment ===");

    // Create a "recipient identity" with only Bob's public keys (Alice doesn't know secrets)
    let bob_public_identity = Identity {
        initiator_spend_sk: umbra_rs::core::ScalarWrapper::from_bytes([0u8; 32]),
        initiator_view_sk: umbra_rs::core::ScalarWrapper::from_bytes([0u8; 32]),
        initiator_spend_pk: bob_identity.initiator_spend_pk.clone(),
        initiator_view_pk: bob_identity.initiator_view_pk.clone(),
    };

    let output = derive_for_initiator(&bob_public_identity, &mut rng);

    let ephemeral_pubkey_hex = hex::encode(output.ephemeral_pubkey.to_bytes());
    let stealth_pubkey_hex = hex::encode(output.one_time_pubkey.to_bytes());

    println!("Ephemeral Pubkey: {}", ephemeral_pubkey_hex);
    println!("Stealth Pubkey: {}", stealth_pubkey_hex);

    // Encrypt memo
    let memo = "Secret payment from Alice!";
    let encrypted =
        encrypt_memo(&mut rng, &output.shared_secret_hash, memo).expect("Encryption failed");
    println!("Encrypted Memo: {}", encrypted);

    // 4. Simulate what the indexer would store
    // In real flow: Alice sends TX with announcement, indexer stores ephemeral_pubkey + ciphertext

    // 5. Bob scans and decrypts
    println!("\n=== Bob Scans & Decrypts ===");

    // Bob uses his view secret key to derive shared secret from ephemeral pubkey
    let ephemeral_bytes = hex::decode(&ephemeral_pubkey_hex).unwrap();
    let ephemeral_pt =
        curve25519_dalek::edwards::CompressedEdwardsY(ephemeral_bytes.try_into().unwrap())
            .decompress()
            .unwrap();
    let ephemeral_pk = umbra_rs::core::PointWrapper(ephemeral_pt);

    let shared_secret =
        derive_shared_secret_view_only(&ephemeral_pk, &bob_identity.initiator_view_sk);

    // Decrypt
    let decrypted = decrypt_memo(&shared_secret, &encrypted).expect("Decryption failed");

    println!("Decrypted Memo: {}", decrypted);

    // Verify
    assert_eq!(decrypted, memo, "Decryption mismatch!");
    println!("\n✅ SUCCESS: Bob decrypted Alice's message!");

    // 6. Verify Bob can recover the stealth private key (for withdrawal)
    println!("\n=== Bob Recovers Stealth Key ===");

    use umbra_rs::core::derive_stealth_key;
    let stealth_sk = derive_stealth_key(
        &bob_identity.initiator_view_sk,
        &bob_identity.initiator_spend_sk,
        &ephemeral_pk,
    );

    // Verify: stealth_sk * G should equal stealth pubkey
    use curve25519_dalek::constants::ED25519_BASEPOINT_POINT;
    let recovered_stealth_pk = ED25519_BASEPOINT_POINT * stealth_sk.0;
    let recovered_stealth_hex = hex::encode(recovered_stealth_pk.compress().to_bytes());

    assert_eq!(
        recovered_stealth_hex, stealth_pubkey_hex,
        "Stealth key recovery mismatch!"
    );
    println!("✅ SUCCESS: Bob recovered stealth private key!");

    // 7. Bob signs a withdrawal request (simulates relayer flow)
    println!("\n=== Bob Signs Withdrawal Request ===");

    // Construct message: stealth_pubkey || recipient || amount || fee
    let recipient_pubkey = bob_keypair.pubkey();
    let amount: u64 = 1_000_000_000; // 1 SOL
    let fee: u64 = 1000;

    let mut message = Vec::new();
    message.extend_from_slice(&output.one_time_pubkey.to_bytes()); // stealth pubkey (32 bytes)
    message.extend_from_slice(&recipient_pubkey.to_bytes()); // recipient (32 bytes)
    message.extend_from_slice(&amount.to_le_bytes()); // amount (8 bytes)
    message.extend_from_slice(&fee.to_le_bytes()); // fee (8 bytes)

    println!("Message length: {} bytes", message.len());
    println!("Message hex: {}", hex::encode(&message));

    // Sign using stealth secret key (Ed25519)
    use curve25519_dalek::scalar::Scalar;
    use sha2::{Digest, Sha512};

    let stealth_sk_bytes = stealth_sk.to_bytes();
    let stealth_pk_bytes = recovered_stealth_pk.compress().to_bytes();

    // Create nonce: r = H(sk || message) mod order
    let mut nonce_hash = Sha512::new();
    nonce_hash.update(&stealth_sk_bytes);
    nonce_hash.update(&message);
    let r_bytes = nonce_hash.finalize();
    let r_scalar = Scalar::from_bytes_mod_order_wide(&r_bytes.into());

    // R = r * G
    let r_point = ED25519_BASEPOINT_POINT * r_scalar;
    let r_point_bytes = r_point.compress().to_bytes();

    // k = H(R || A || message) mod order
    let mut k_hash = Sha512::new();
    k_hash.update(&r_point_bytes);
    k_hash.update(&stealth_pk_bytes);
    k_hash.update(&message);
    let k_bytes = k_hash.finalize();
    let k_scalar = Scalar::from_bytes_mod_order_wide(&k_bytes.into());

    // S = r + k * a (mod order)
    let s_scalar = r_scalar + (k_scalar * stealth_sk.0);
    let s_bytes = s_scalar.to_bytes();

    // Signature = R || S (64 bytes)
    let mut signature = [0u8; 64];
    signature[..32].copy_from_slice(&r_point_bytes);
    signature[32..].copy_from_slice(&s_bytes);

    println!("Signature: {}", hex::encode(&signature));

    // 8. Verify the signature (simulates what relayer/program does)
    println!("\n=== Relayer Verifies Signature ===");

    // Reconstruct and verify: G*S == R + k*A
    let s_scalar_check = Scalar::from_bytes_mod_order(s_bytes);
    let gs = ED25519_BASEPOINT_POINT * s_scalar_check;

    let r_point_check = curve25519_dalek::edwards::CompressedEdwardsY(r_point_bytes)
        .decompress()
        .expect("Invalid R point");
    let a_point_check = curve25519_dalek::edwards::CompressedEdwardsY(stealth_pk_bytes)
        .decompress()
        .expect("Invalid A point");

    let rhs = r_point_check + (a_point_check * k_scalar);

    assert_eq!(
        gs.compress().to_bytes(),
        rhs.compress().to_bytes(),
        "Signature verification failed!"
    );
    println!("✅ SUCCESS: Signature verified!");

    println!("\n=== Full Flow Complete (Including Withdrawal) ===");
}

#[test]
fn test_stealth_flow_bob_to_alice() {
    // Same but reversed
    let mut rng = OsRng;
    let alice_identity = Identity::new_random(&mut rng);
    let bob_identity = Identity::new_random(&mut rng);

    // Bob sends to Alice
    let alice_public_identity = Identity {
        initiator_spend_sk: umbra_rs::core::ScalarWrapper::from_bytes([0u8; 32]),
        initiator_view_sk: umbra_rs::core::ScalarWrapper::from_bytes([0u8; 32]),
        initiator_spend_pk: alice_identity.initiator_spend_pk.clone(),
        initiator_view_pk: alice_identity.initiator_view_pk.clone(),
    };

    let output = derive_for_initiator(&alice_public_identity, &mut rng);
    let memo = "Reply from Bob!";
    let encrypted = encrypt_memo(&mut rng, &output.shared_secret_hash, memo).unwrap();

    // Alice decrypts
    let ephemeral_bytes = output.ephemeral_pubkey.to_bytes();
    let ephemeral_pt = curve25519_dalek::edwards::CompressedEdwardsY(ephemeral_bytes)
        .decompress()
        .unwrap();
    let ephemeral_pk = umbra_rs::core::PointWrapper(ephemeral_pt);

    let shared_secret =
        derive_shared_secret_view_only(&ephemeral_pk, &alice_identity.initiator_view_sk);

    let decrypted = decrypt_memo(&shared_secret, &encrypted).unwrap();
    assert_eq!(decrypted, memo);

    println!("✅ Bob -> Alice flow works!");
}
