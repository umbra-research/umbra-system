use anyhow::Result;
use umbra_system::db::Db;
use umbra_system::mock_factory::MockDataFactory;
use umbra_system::models::AnnouncementStatus;

#[tokio::test]
async fn test_claim_flow_with_mock_data() -> Result<()> {
    // 1. Initialize In-Memory DB (fresh for this test)
    let db = Db::new("sqlite::memory:").await?;

    // 2. Initialize Mock Factory & Seed DB
    let factory = MockDataFactory::new();
    factory.seed_db_returned_data(&db).await?;

    // 3. Verify Data Seeding
    // Query all records
    let all_records = db.get_sync(None, 100).await?;
    println!("Total records seeded: {}", all_records.len());
    
    // We expect Set A (3) + Set B (2) + Set C (2) = 7 records
    assert_eq!(all_records.len(), 7, "Should have 7 total mock records");

    // 4. Test "Wallet Aware" Filtering (Simulated)
    // The *Backend* serves all signals via `get_sync`.
    // The *Test* acts as the Client scanning for Wallet A.
    // We simulate the client finding its signals.
    
    // 4. Test "Wallet Aware" Filtering (Simulated)
    // The *Backend* serves all signals via `get_sync`.
    // The *Test* acts as the Client scanning for Wallet A.
    // We simulate the client finding its signals.
    
    // (Scan logic skipped - relying on status tagging verification for integration test)
    
    // Check initial counts by status
    let pending_count = all_records.iter().filter(|r| r.status == AnnouncementStatus::Pending).count();
    let claimed_count = all_records.iter().filter(|r| r.status == AnnouncementStatus::Claimed).count();
    
    // Set A (3 Pending) + Set B (2 Pending) = 5 Pending
    // Set C (2 Claimed) = 2 Claimed
    assert_eq!(pending_count, 5, "Should have 5 pending signals initially");
    assert_eq!(claimed_count, 2, "Should have 2 claimed signals initially");

    // 5. Test Claim Flow
    // Pick a Pending signal (from Set A presumably)
    let signal_to_claim = all_records.iter()
        .find(|r| r.status == AnnouncementStatus::Pending)
        .expect("No pending signals found");
    
    let claim_id = &signal_to_claim.id;
    println!("Claiming signal: {}", claim_id);

    // Call mark_as_claimed
    db.mark_as_claimed(claim_id).await?;

    // 6. Verify Status Update
    // Fetch specifically this record or re-fetch all
    let updated_records = db.get_sync(None, 100).await?;
    let updated_signal = updated_records.iter()
        .find(|r| r.id == *claim_id)
        .expect("Signal vanished");
        
    assert_eq!(updated_signal.status, AnnouncementStatus::Claimed, "Signal should be marked as Claimed");
    
    // Verify counts changed
    let new_pending_count = updated_records.iter().filter(|r| r.status == AnnouncementStatus::Pending).count();
    let new_claimed_count = updated_records.iter().filter(|r| r.status == AnnouncementStatus::Claimed).count();
    
    assert_eq!(new_pending_count, 4, "Pending count should decrease by 1");
    assert_eq!(new_claimed_count, 3, "Claimed count should increase by 1");

    Ok(())
}
