use anyhow::Result;
use sqlx::{sqlite::SqlitePoolOptions, Pool, Sqlite};
use std::env;
use crate::models::TxRecord;

#[derive(Clone)]
pub struct Db {
    pool: Pool<Sqlite>,
}

impl Db {
    pub async fn new(database_url: &str) -> Result<Self> {
        let pool = SqlitePoolOptions::new()
            .max_connections(5)
            .connect(database_url)
            .await?;

        // Run migrations
        // Robust setup for dev: Ensure table exists, and ensure status column exists.
        sqlx::query(
            r#"
            CREATE TABLE IF NOT EXISTS announcements (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                signature TEXT NOT NULL,
                payer TEXT NOT NULL,
                recipient TEXT NOT NULL,
                amount REAL NOT NULL,
                cipher_text TEXT NOT NULL,
                ephemeral_pubkey TEXT NOT NULL,
                hashed_tag TEXT NOT NULL DEFAULT '',
                status TEXT NOT NULL DEFAULT 'pending', 
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            );
            "#,
        )
        .execute(&pool)
        .await?;

        // Attempt to add status column if it's missing (for existing dev DBs)
        // Ignore error if it already exists
        let _ = sqlx::query("ALTER TABLE announcements ADD COLUMN status TEXT NOT NULL DEFAULT 'pending'")
            .execute(&pool)
            .await;

        Ok(Self { pool })
    }

    pub async fn save_announcement(
        &self,
        signature: &str,
        payer: &str,
        cipher_text: &str,
        ephemeral_pubkey: &str,
        hashed_tag: &str,
    ) -> Result<()> {
        let id = uuid::Uuid::new_v4().to_string();
        let timestamp = chrono::Utc::now().to_rfc3339();

        sqlx::query(
            r#"
            INSERT INTO announcements (id, timestamp, signature, payer, recipient, amount, cipher_text, ephemeral_pubkey, hashed_tag, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
            "#,
        )
        .bind(id)
        .bind(timestamp)
        .bind(signature)
        .bind(payer)
        .bind("stealth") // Unknown recipient
        .bind(0.0) // Unknown amount (encrypted)
        .bind(cipher_text)
        .bind(ephemeral_pubkey)
        .bind(hashed_tag)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Helper for seeding test data with specific status
    pub async fn save_test_announcement(
        &self,
        id: &str,
        status: &str,
        signature: &str,
        payer: &str,
        cipher_text: &str,
        ephemeral_pubkey: &str,
    ) -> Result<()> {
         let timestamp = chrono::Utc::now().to_rfc3339();
         sqlx::query(
            r#"
            INSERT INTO announcements (id, timestamp, signature, payer, recipient, amount, cipher_text, ephemeral_pubkey, hashed_tag, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            "#,
        )
        .bind(id)
        .bind(timestamp)
        .bind(signature)
        .bind(payer)
        .bind("stealth")
        .bind(0.0)
        .bind(cipher_text)
        .bind(ephemeral_pubkey)
        .bind("") // hashed_tag
        .bind(status)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    pub async fn mark_as_claimed(&self, id: &str) -> Result<()> {
        sqlx::query("UPDATE announcements SET status = 'claimed' WHERE id = ?")
            .bind(id)
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    // New Sync method
    pub async fn get_sync(&self, since: Option<String>, limit: i64) -> Result<Vec<crate::models::TxRecord>> {
        let rows = if let Some(since_ts) = since {
             sqlx::query_as::<_, crate::models::TxRecord>(
                r#"
                SELECT id, timestamp, payer, recipient, amount, 'SOL' as token, status, signature, cipher_text, ephemeral_pubkey, hashed_tag
                FROM announcements
                WHERE timestamp > ?
                ORDER BY timestamp ASC
                LIMIT ?
                "#
            )
            .bind(since_ts)
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        } else {
             sqlx::query_as::<_, crate::models::TxRecord>(
                r#"
                SELECT id, timestamp, payer, recipient, amount, 'SOL' as token, status, signature, cipher_text, ephemeral_pubkey, hashed_tag
                FROM announcements
                ORDER BY timestamp ASC
                LIMIT ?
                "#
            )
            .bind(limit)
            .fetch_all(&self.pool)
            .await?
        };
        Ok(rows)
    }

    // Keep legacy for now or refactor
    pub async fn get_announcements_for_recipient(&self, recipient: &str) -> Result<Vec<crate::models::TxRecord>> {
       self.get_sync(None, 50).await
    }
}
