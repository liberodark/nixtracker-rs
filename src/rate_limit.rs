use governor::clock::DefaultClock;
use governor::middleware::NoOpMiddleware;
use governor::state::{InMemoryState, NotKeyed, keyed::DefaultKeyedStateStore};
use governor::{Quota, RateLimiter};
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::{Request, Response, StatusCode};
use serde::Serialize;
use std::net::IpAddr;
use std::num::NonZeroU32;
use std::sync::Arc;
use std::time::Duration;

type IpRateLimiter = Arc<
    RateLimiter<
        IpAddr,
        DefaultKeyedStateStore<IpAddr>,
        DefaultClock,
        NoOpMiddleware<governor::clock::QuantaInstant>,
    >,
>;

type GlobalRateLimiter = Arc<
    RateLimiter<
        NotKeyed,
        InMemoryState,
        DefaultClock,
        NoOpMiddleware<governor::clock::QuantaInstant>,
    >,
>;

#[derive(Clone)]
pub struct RateLimitManager {
    github_limiter: GlobalRateLimiter,
    ip_limiter: IpRateLimiter,
    config: RateLimitConfig,
}

#[derive(Clone, Debug, Serialize)]
pub struct RateLimitConfig {
    pub global_rps: u32,
    pub per_ip_rps: u32,
    pub global_burst: u32,
    pub per_ip_burst: u32,
    pub has_github_token: bool,
}

impl RateLimitConfig {
    pub fn with_token() -> Self {
        Self {
            global_rps: 30,
            per_ip_rps: 2,
            global_burst: 50,
            per_ip_burst: 10,
            has_github_token: true,
        }
    }

    pub fn without_token() -> Self {
        Self {
            global_rps: 1,
            per_ip_rps: 1,
            global_burst: 3,
            per_ip_burst: 2,
            has_github_token: false,
        }
    }

    pub fn development() -> Self {
        Self {
            global_rps: 100,
            per_ip_rps: 50,
            global_burst: 200,
            per_ip_burst: 100,
            has_github_token: true,
        }
    }
}

impl RateLimitManager {
    pub fn new(config: RateLimitConfig) -> Self {
        let global_quota = if config.global_burst > config.global_rps {
            Quota::per_second(NonZeroU32::new(config.global_rps).unwrap())
                .allow_burst(NonZeroU32::new(config.global_burst).unwrap())
        } else {
            Quota::per_second(NonZeroU32::new(config.global_rps).unwrap())
        };

        let ip_quota = if config.per_ip_burst > config.per_ip_rps {
            Quota::per_second(NonZeroU32::new(config.per_ip_rps).unwrap())
                .allow_burst(NonZeroU32::new(config.per_ip_burst).unwrap())
        } else {
            Quota::per_second(NonZeroU32::new(config.per_ip_rps).unwrap())
        };

        Self {
            github_limiter: Arc::new(RateLimiter::direct(global_quota)),
            ip_limiter: Arc::new(RateLimiter::keyed(ip_quota)),
            config,
        }
    }

    pub async fn check_request(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        if self.ip_limiter.check_key(&ip).is_err() {
            return Err(RateLimitError::IpRateLimitExceeded {
                ip,
                limit_per_second: self.config.per_ip_rps,
            });
        }

        if self.github_limiter.check().is_err() {
            return Err(RateLimitError::GlobalRateLimitExceeded {
                limit_per_second: self.config.global_rps,
            });
        }

        Ok(())
    }

    pub async fn check_request_with_jitter(&self, ip: IpAddr) -> Result<(), RateLimitError> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .subsec_nanos();
        let jitter_ms = (nanos % 10) as u64;
        tokio::time::sleep(Duration::from_millis(jitter_ms)).await;

        self.check_request(ip).await
    }

    pub fn get_stats(&self, ip: IpAddr) -> RateLimitStats {
        RateLimitStats {
            ip_remaining: self.ip_limiter.check_key(&ip).is_ok(),
            global_remaining: self.github_limiter.check().is_ok(),
            config: self.config.clone(),
        }
    }
}

#[derive(Debug)]
pub enum RateLimitError {
    IpRateLimitExceeded { ip: IpAddr, limit_per_second: u32 },
    GlobalRateLimitExceeded { limit_per_second: u32 },
}

impl RateLimitError {
    pub fn to_response(&self) -> Response<Full<Bytes>> {
        let (message, retry_after) = match self {
            RateLimitError::IpRateLimitExceeded {
                ip,
                limit_per_second,
            } => (
                format!(
                    "Rate limit exceeded for IP {}. Max {} requests per second.",
                    ip, limit_per_second
                ),
                60,
            ),
            RateLimitError::GlobalRateLimitExceeded { limit_per_second } => (
                format!(
                    "Service rate limit exceeded. Max {} requests per second globally.",
                    limit_per_second
                ),
                120,
            ),
        };

        let json_error = serde_json::json!({
            "error": "rate_limit_exceeded",
            "message": message,
            "retry_after": retry_after,
        });

        let timestamp = chrono::Utc::now().timestamp() + retry_after as i64;

        Response::builder()
            .status(StatusCode::TOO_MANY_REQUESTS)
            .header("content-type", "application/json")
            .header("retry-after", retry_after.to_string())
            .header("x-ratelimit-limit", "120")
            .header("x-ratelimit-remaining", "0")
            .header("x-ratelimit-reset", timestamp.to_string())
            .body(Full::new(Bytes::from(json_error.to_string())))
            .unwrap()
    }
}

#[derive(Debug, Serialize)]
pub struct RateLimitStats {
    pub ip_remaining: bool,
    pub global_remaining: bool,
    pub config: RateLimitConfig,
}

pub fn extract_client_ip(req: &Request<Incoming>) -> IpAddr {
    if let Some(forwarded) = req.headers().get("x-forwarded-for") {
        if let Ok(forwarded_str) = forwarded.to_str() {
            if let Some(first_ip) = forwarded_str.split(',').next() {
                if let Ok(addr) = first_ip.trim().parse::<IpAddr>() {
                    return addr;
                }
            }
        }
    }

    if let Some(real_ip) = req.headers().get("x-real-ip") {
        if let Ok(ip_str) = real_ip.to_str() {
            if let Ok(addr) = ip_str.parse::<IpAddr>() {
                return addr;
            }
        }
    }

    if let Some(cf_ip) = req.headers().get("cf-connecting-ip") {
        if let Ok(ip_str) = cf_ip.to_str() {
            if let Ok(addr) = ip_str.parse::<IpAddr>() {
                return addr;
            }
        }
    }

    "127.0.0.1".parse().unwrap()
}
