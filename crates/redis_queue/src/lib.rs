use redis::{Client, Commands, RedisError};
use serde::{Deserialize, Serialize};
use std::time::Duration;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum QueueError {
    #[error("redis error: {0}")]
    Redis(#[from] RedisError),
    #[error("serialization error: {0}")]
    Serialization(String),
    #[error("other: {0}")]
    Other(String),
}

pub type Result<T> = std::result::Result<T, QueueError>;

/// Redis-based queue for BAR hot path (ingest, correlation, alerts)
pub struct RedisQueue {
    client: Client,
    namespace_prefix: String,
}

impl RedisQueue {
    pub fn new(redis_url: &str, namespace_prefix: &str) -> Result<Self> {
        let client = Client::open(redis_url)?;
        Ok(Self {
            client,
            namespace_prefix: namespace_prefix.to_string(),
        })
    }

    fn key(&self, suffix: &str) -> String {
        format!("{}:{}", self.namespace_prefix, suffix)
    }

    /// Push event to ingest queue for a namespace
    pub fn push_ingest<T: Serialize>(&self, namespace_id: &str, event: &T) -> Result<()> {
        let mut conn = self.client.get_connection()?;
        let key = self.key(&format!("q:ingest:{}", namespace_id));
        let json = serde_json::to_string(event)
            .map_err(|e| QueueError::Serialization(e.to_string()))?;
        conn.rpush(key, json)?;
        Ok(())
    }

    /// Pop event from ingest queue for a namespace
    pub fn pop_ingest<T: for<'de> Deserialize<'de>>(&self, namespace_id: &str) -> Result<Option<T>> {
        let mut conn = self.client.get_connection()?;
        let key = self.key(&format!("q:ingest:{}", namespace_id));
        let result: Option<String> = conn.lpop(key, None)?;
        
        match result {
            Some(json) => {
                let event = serde_json::from_str(&json)
                    .map_err(|e| QueueError::Serialization(e.to_string()))?;
                Ok(Some(event))
            }
            None => Ok(None),
        }
    }

    /// Set correlation window data with TTL
    pub fn set_correlation_window<T: Serialize>(
        &self,
        namespace_id: &str,
        window_id: &str,
        data: &T,
        ttl_secs: u64,
    ) -> Result<()> {
        let mut conn = self.client.get_connection()?;
        let key = self.key(&format!("win:correlate:{}:{}", namespace_id, window_id));
        let json = serde_json::to_string(data)
            .map_err(|e| QueueError::Serialization(e.to_string()))?;
        conn.set_ex(key, json, ttl_secs)?;
        Ok(())
    }

    /// Get correlation window data
    pub fn get_correlation_window<T: for<'de> Deserialize<'de>>(
        &self,
        namespace_id: &str,
        window_id: &str,
    ) -> Result<Option<T>> {
        let mut conn = self.client.get_connection()?;
        let key = self.key(&format!("win:correlate:{}:{}", namespace_id, window_id));
        let result: Option<String> = conn.get(key)?;
        
        match result {
            Some(json) => {
                let data = serde_json::from_str(&json)
                    .map_err(|e| QueueError::Serialization(e.to_string()))?;
                Ok(Some(data))
            }
            None => Ok(None),
        }
    }

    /// Check for duplicate event (dedupe)
    pub fn is_duplicate(&self, namespace_id: &str, event_hash: &str, ttl_secs: u64) -> Result<bool> {
        let mut conn = self.client.get_connection()?;
        let key = self.key(&format!("dedupe:{}:{}", namespace_id, event_hash));
        
        let exists: bool = conn.exists(&key)?;
        if !exists {
            conn.set_ex(key, "1", ttl_secs)?;
        }
        Ok(exists)
    }

    /// Publish alert to stream
    pub fn publish_alert<T: Serialize>(&self, namespace_id: &str, alert: &T) -> Result<()> {
        let mut conn = self.client.get_connection()?;
        let key = self.key(&format!("alerts:{}", namespace_id));
        let json = serde_json::to_string(alert)
            .map_err(|e| QueueError::Serialization(e.to_string()))?;
        conn.rpush(key, json)?;
        Ok(())
    }

    /// Get recent alerts
    pub fn get_alerts<T: for<'de> Deserialize<'de>>(
        &self,
        namespace_id: &str,
        count: isize,
    ) -> Result<Vec<T>> {
        let mut conn = self.client.get_connection()?;
        let key = self.key(&format!("alerts:{}", namespace_id));
        let results: Vec<String> = conn.lrange(key, -count, -1)?;
        
        results
            .into_iter()
            .map(|json| {
                serde_json::from_str(&json)
                    .map_err(|e| QueueError::Serialization(e.to_string()))
            })
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
    struct TestEvent {
        id: String,
        data: String,
    }

    // Note: These tests require a running Redis instance
    // They are marked as ignored by default
    
    #[test]
    #[ignore]
    fn redis_queue_push_pop() {
        let queue = RedisQueue::new("redis://127.0.0.1/", "test").expect("connect");
        
        let event = TestEvent {
            id: "evt_1".to_string(),
            data: "test_data".to_string(),
        };
        
        queue.push_ingest("ns://test/prod/app/svc", &event).expect("push");
        
        let popped: Option<TestEvent> = queue.pop_ingest("ns://test/prod/app/svc").expect("pop");
        assert_eq!(popped, Some(event));
    }

    #[test]
    #[ignore]
    fn redis_queue_correlation_window() {
        let queue = RedisQueue::new("redis://127.0.0.1/", "test").expect("connect");
        
        let data = TestEvent {
            id: "win_1".to_string(),
            data: "window_data".to_string(),
        };
        
        queue.set_correlation_window("ns://test/prod/app/svc", "window_1", &data, 60)
            .expect("set");
        
        let retrieved: Option<TestEvent> = queue
            .get_correlation_window("ns://test/prod/app/svc", "window_1")
            .expect("get");
        assert_eq!(retrieved, Some(data));
    }

    #[test]
    #[ignore]
    fn redis_queue_dedupe() {
        let queue = RedisQueue::new("redis://127.0.0.1/", "test").expect("connect");
        
        let is_dup1 = queue.is_duplicate("ns://test/prod/app/svc", "hash_1", 60).expect("check");
        assert!(!is_dup1);
        
        let is_dup2 = queue.is_duplicate("ns://test/prod/app/svc", "hash_1", 60).expect("check");
        assert!(is_dup2);
    }
}
