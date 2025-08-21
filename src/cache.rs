use lru::LruCache;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::num::NonZeroUsize;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

#[derive(Clone)]
pub struct CachedItem {
    pub data: Value,
    pub timestamp: Instant,
    pub hits: u32,
}

pub struct Cache {
    lru: Arc<RwLock<LruCache<String, CachedItem>>>,
    config: CacheConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheConfig {
    #[serde(default = "default_cache_entries")]
    pub max_entries: usize,

    #[serde(default = "default_cache_ttl")]
    pub ttl_seconds: u64,

    #[serde(default = "default_cache_enabled")]
    pub enabled: bool,
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_entries: 500,
            ttl_seconds: 60,
            enabled: true,
        }
    }
}

fn default_cache_entries() -> usize {
    500
}
fn default_cache_ttl() -> u64 {
    60
}
fn default_cache_enabled() -> bool {
    true
}

impl Cache {
    pub fn new(config: CacheConfig) -> Self {
        let capacity = NonZeroUsize::new(config.max_entries.max(1)).unwrap();
        let lru = LruCache::new(capacity);

        Self {
            lru: Arc::new(RwLock::new(lru)),
            config,
        }
    }

    pub async fn get(&self, key: &str) -> Option<Value> {
        if !self.config.enabled {
            return None;
        }

        let mut cache = self.lru.write().await;

        if let Some(item) = cache.get_mut(key) {
            if item.timestamp.elapsed() < Duration::from_secs(self.config.ttl_seconds) {
                item.hits += 1;
                return Some(item.data.clone());
            } else {
                cache.pop(key);
            }
        }

        None
    }

    pub async fn insert(&self, key: String, data: Value) {
        if !self.config.enabled {
            return;
        }

        let item = CachedItem {
            data,
            timestamp: Instant::now(),
            hits: 0,
        };

        let mut cache = self.lru.write().await;
        cache.put(key, item);
    }

    pub async fn clear(&self) {
        let mut cache = self.lru.write().await;
        cache.clear();
    }

    pub async fn stats(&self) -> CacheStats {
        let cache = self.lru.read().await;

        let mut total_hits = 0u32;
        let mut expired = 0;
        let ttl = Duration::from_secs(self.config.ttl_seconds);

        for (_key, item) in cache.iter() {
            total_hits += item.hits;
            if item.timestamp.elapsed() > ttl {
                expired += 1;
            }
        }

        CacheStats {
            entries: cache.len(),
            capacity: cache.cap().get(),
            total_hits,
            expired_entries: expired,
            enabled: self.config.enabled,
        }
    }

    pub async fn cleanup_expired(&self) {
        if !self.config.enabled {
            return;
        }

        let mut cache = self.lru.write().await;
        let ttl = Duration::from_secs(self.config.ttl_seconds);

        let expired_keys: Vec<String> = cache
            .iter()
            .filter(|(_, item)| item.timestamp.elapsed() > ttl)
            .map(|(key, _)| key.clone())
            .collect();

        for key in expired_keys {
            cache.pop(&key);
        }
    }

    pub async fn remove(&self, key: &str) {
        if !self.config.enabled {
            return;
        }

        let mut cache = self.lru.write().await;
        cache.pop(key);
    }
}

#[derive(Serialize)]
pub struct CacheStats {
    pub entries: usize,
    pub capacity: usize,
    pub total_hits: u32,
    pub expired_entries: usize,
    pub enabled: bool,
}
