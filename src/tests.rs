#[cfg(test)]
mod tests {
    use crate::TimeoutConfig;
    use crate::cache::{Cache, CacheConfig};
    use crate::github::{Branch, Label, PullRequest, User, get_branch_flow};
    use crate::hydra::{get_hydra_link, is_channel};
    use crate::rate_limit::{RateLimitConfig, RateLimitManager};
    use crate::{Config, extract_pr_number};
    use chrono::Utc;
    use serde_json::json;
    use std::borrow::Cow;
    use std::net::IpAddr;
    use std::time::Duration;
    use tokio::time::{sleep, timeout};

    #[test]
    fn test_get_hydra_link_staging() {
        assert_eq!(
            get_hydra_link("staging"),
            Some("https://hydra.nixos.org/jobset/nixpkgs/staging".to_string())
        );
    }

    #[test]
    fn test_get_hydra_link_staging_next() {
        assert_eq!(
            get_hydra_link("staging-next"),
            Some("https://hydra.nixos.org/jobset/nixpkgs/staging-next#tabs-jobs".to_string())
        );
    }

    #[test]
    fn test_get_hydra_link_master() {
        assert_eq!(
            get_hydra_link("master"),
            Some("https://hydra.nixos.org/jobset/nixpkgs/trunk#tabs-jobs".to_string())
        );
    }

    #[test]
    fn test_get_hydra_link_nixpkgs_unstable() {
        assert_eq!(
            get_hydra_link("nixpkgs-unstable"),
            Some(
                "https://hydra.nixos.org/job/nixpkgs/trunk/unstable#tabs-constituents".to_string()
            )
        );
    }

    #[test]
    fn test_get_hydra_link_nixos_version() {
        assert_eq!(
            get_hydra_link("nixos-25.05"),
            Some(
                "https://hydra.nixos.org/job/nixos/release-25.05/tested#tabs-constituents"
                    .to_string()
            )
        );
    }

    #[test]
    fn test_get_hydra_link_release_version() {
        assert_eq!(
            get_hydra_link("release-25.05"),
            Some("https://hydra.nixos.org/jobset/nixos/release-25.05".to_string())
        );
    }

    #[test]
    fn test_get_hydra_link_darwin() {
        assert_eq!(get_hydra_link("nixpkgs-25.05-darwin"), None);
    }

    #[test]
    fn test_get_hydra_link_unknown() {
        assert_eq!(get_hydra_link("unknown-branch"), None);
    }

    #[test]
    fn test_is_channel() {
        assert!(is_channel("nixpkgs-unstable"));
        assert!(is_channel("nixos-25.05"));
        assert!(is_channel("nixos-unstable"));
        assert!(is_channel("nixpkgs-25.05-darwin"));

        assert!(!is_channel("master"));
        assert!(!is_channel("staging"));
        assert!(!is_channel("release-25.05"));
        assert!(!is_channel("haskell-updates"));
    }

    #[test]
    fn test_get_branch_flow_master() {
        let flow = get_branch_flow("master");
        assert_eq!(
            flow,
            vec![
                Cow::Borrowed("nixpkgs-unstable"),
                Cow::Borrowed("nixos-unstable-small"),
                Cow::Borrowed("nixos-unstable"),
            ]
        );
    }

    #[test]
    fn test_get_branch_flow_staging() {
        let flow = get_branch_flow("staging");
        assert_eq!(
            flow,
            vec![
                Cow::Borrowed("staging-next"),
                Cow::Borrowed("master"),
                Cow::Borrowed("nixpkgs-unstable"),
                Cow::Borrowed("nixos-unstable-small"),
                Cow::Borrowed("nixos-unstable"),
            ]
        );
    }

    #[test]
    fn test_get_branch_flow_staging_next() {
        let flow = get_branch_flow("staging-next");
        assert_eq!(
            flow,
            vec![
                Cow::Borrowed("master"),
                Cow::Borrowed("nixpkgs-unstable"),
                Cow::Borrowed("nixos-unstable-small"),
                Cow::Borrowed("nixos-unstable"),
            ]
        );
    }

    #[test]
    fn test_get_branch_flow_haskell_updates() {
        let flow = get_branch_flow("haskell-updates");
        assert_eq!(
            flow,
            vec![
                Cow::Borrowed("staging"),
                Cow::Borrowed("staging-next"),
                Cow::Borrowed("master"),
                Cow::Borrowed("nixpkgs-unstable"),
                Cow::Borrowed("nixos-unstable-small"),
                Cow::Borrowed("nixos-unstable"),
            ]
        );
    }

    #[test]
    fn test_get_branch_flow_release() {
        let flow = get_branch_flow("release-25.05");
        assert_eq!(flow.len(), 3);
        let flow_strings: Vec<String> = flow.into_iter().map(|c| c.into_owned()).collect();
        assert!(flow_strings.contains(&"nixpkgs-25.05-darwin".to_string()));
        assert!(flow_strings.contains(&"nixos-25.05-small".to_string()));
        assert!(flow_strings.contains(&"nixos-25.05".to_string()));
    }

    #[test]
    fn test_get_branch_flow_unknown() {
        let flow = get_branch_flow("unknown-branch");
        assert!(flow.is_empty());
    }

    #[test]
    fn test_create_pull_request() {
        let pr = PullRequest {
            number: 12345,
            title: "Test PR".to_string(),
            state: "open".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            merged_at: None,
            merge_commit_sha: None,
            html_url: "https://github.com/NixOS/nixpkgs/pull/12345".to_string(),
            user: User {
                login: "testuser".to_string(),
                avatar_url: "https://avatars.githubusercontent.com/u/12345".to_string(),
                html_url: "https://github.com/testuser".to_string(),
            },
            labels: vec![Label {
                name: "test".to_string(),
                color: "ff0000".to_string(),
            }],
            draft: false,
            head: Branch {
                label: "testuser:test-branch".to_string(),
            },
            base: Branch {
                label: "NixOS:master".to_string(),
            },
        };

        assert_eq!(pr.number, 12345);
        assert_eq!(pr.state, "open");
        assert!(!pr.draft);
        assert_eq!(pr.user.login, "testuser");
        assert_eq!(pr.labels.len(), 1);
    }

    #[test]
    fn test_config_default() {
        let config = Config::default();
        assert_eq!(config.ip, "127.0.0.1");
        assert_eq!(config.port, 3000);
        assert_eq!(config.owner, "NixOS");
        assert_eq!(config.repo, "nixpkgs");
        assert!(!config.verbose);
        assert_eq!(config.refresh, 0);
        assert_eq!(config.theme, "dark");
        assert!(config.github_token.is_none());
    }

    #[test]
    fn test_config_with_values() {
        let config = Config {
            base_url: None,
            ip: "0.0.0.0".to_string(),
            port: 8080,
            github_token: Some("token123".to_string()),
            owner: "MyOrg".to_string(),
            repo: "myrepo".to_string(),
            verbose: true,
            refresh: 60,
            theme: "light".to_string(),
            rate_limit: crate::RateLimitConfigWrapper::default(),
            timeouts: crate::TimeoutConfig::default(),
            cache: CacheConfig::default(),
        };

        assert_eq!(config.ip, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.github_token.unwrap(), "token123");
        assert_eq!(config.owner, "MyOrg");
        assert_eq!(config.repo, "myrepo");
        assert!(config.verbose);
        assert_eq!(config.refresh, 60);
        assert_eq!(config.theme, "light");
    }

    #[test]
    fn test_extract_pr_number_valid() {
        assert_eq!(extract_pr_number("pr=12345").unwrap(), 12345);
        assert_eq!(extract_pr_number("other=value&pr=67890").unwrap(), 67890);
        assert_eq!(extract_pr_number("pr=1&other=value").unwrap(), 1);
    }

    #[test]
    fn test_extract_pr_number_invalid() {
        assert!(extract_pr_number("").is_err());
        assert!(extract_pr_number("other=value").is_err());
        assert!(extract_pr_number("pr=").is_err());
        assert!(extract_pr_number("pr=abc").is_err());
        assert!(extract_pr_number("pr=-123").is_err());
    }

    #[test]
    fn test_extract_pr_number_with_multiple_params() {
        assert_eq!(
            extract_pr_number("foo=bar&pr=99999&baz=qux").unwrap(),
            99999
        );
    }

    #[test]
    fn test_index_page_renders() {
        let config = Config::default();
        let markup = crate::templates::index_page(&config);
        let html = markup.into_string();

        assert!(html.contains("PR Tracker"));
        assert!(html.contains("Enter PR number"));
        assert!(html.contains(&config.owner));
        assert!(html.contains(&config.repo));
    }

    #[test]
    fn test_pr_page_renders() {
        let config = Config::default();
        let markup = crate::templates::pr_page(&config, 12345);
        let html = markup.into_string();

        assert!(html.contains("PR #12345"));
        assert!(html.contains("Loading PR #12345"));
    }

    #[test]
    fn test_error_fragment_renders() {
        let markup = crate::templates::error_fragment("Test error message");
        let html = markup.into_string();

        assert!(html.contains("Test error message"));
        assert!(html.contains("error"));
    }

    #[test]
    fn test_pr_details_fragment_renders() {
        let config = Config::default();
        let pr = PullRequest {
            number: 12345,
            title: "Test PR Title".to_string(),
            state: "open".to_string(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
            merged_at: None,
            merge_commit_sha: Some("abc123def456".to_string()),
            html_url: "https://github.com/NixOS/nixpkgs/pull/12345".to_string(),
            user: User {
                login: "testuser".to_string(),
                avatar_url: "https://avatars.githubusercontent.com/u/12345".to_string(),
                html_url: "https://github.com/testuser".to_string(),
            },
            labels: vec![Label {
                name: "backport".to_string(),
                color: "0366d6".to_string(),
            }],
            draft: false,
            head: Branch {
                label: "testuser:test-branch".to_string(),
            },
            base: Branch {
                label: "NixOS:master".to_string(),
            },
        };

        let branch_status = vec![
            crate::github::BranchStatus {
                name: "master".to_string(),
                has_commit: true,
                is_channel: false,
                hydra_link: Some("https://hydra.nixos.org/jobset/nixpkgs/trunk".to_string()),
            },
            crate::github::BranchStatus {
                name: "staging".to_string(),
                has_commit: false,
                is_channel: false,
                hydra_link: None,
            },
        ];

        let markup = crate::templates::pr_details_fragment(pr, branch_status, &config);
        let html = markup.into_string();

        assert!(html.contains("Test PR Title"));
        assert!(html.contains("#12345"));
        assert!(html.contains("testuser"));
        assert!(html.contains("backport"));
        assert!(html.contains("master"));
        assert!(html.contains("staging"));
    }

    #[test]
    fn test_branch_flow_consistency() {
        let master_flow = get_branch_flow("master");
        let staging_flow = get_branch_flow("staging");
        let staging_next_flow = get_branch_flow("staging-next");

        // Master not have staging-next in flow
        assert!(!master_flow.contains(&Cow::Borrowed("staging-next")));
        assert!(!master_flow.contains(&Cow::Borrowed("staging")));

        // Staging have staging-next & master
        assert!(staging_flow.contains(&Cow::Borrowed("staging-next")));
        assert!(staging_flow.contains(&Cow::Borrowed("master")));

        // Staging-next have master but not staging
        assert!(staging_next_flow.contains(&Cow::Borrowed("master")));
        assert!(!staging_next_flow.contains(&Cow::Borrowed("staging")));

        // All have unstable channels
        assert!(master_flow.contains(&Cow::Borrowed("nixpkgs-unstable")));
        assert!(staging_flow.contains(&Cow::Borrowed("nixpkgs-unstable")));
        assert!(staging_next_flow.contains(&Cow::Borrowed("nixpkgs-unstable")));
    }

    #[test]
    fn test_hydra_links_for_channels() {
        let channels = vec![
            "nixpkgs-unstable",
            "nixos-unstable",
            "nixos-unstable-small",
            "nixos-25.05",
        ];

        for channel in channels {
            if !channel.contains("darwin") {
                assert!(
                    get_hydra_link(channel).is_some(),
                    "Channel {} should have a Hydra link",
                    channel
                );
            }
        }
    }

    #[test]
    fn test_config_serialization() {
        let config = Config::default();
        let serialized = toml::to_string(&config).unwrap();

        assert!(serialized.contains("ip ="));
        assert!(serialized.contains("port ="));
        assert!(serialized.contains("owner ="));
        assert!(serialized.contains("repo ="));
        assert!(!serialized.contains("github_token"));
    }

    #[test]
    fn test_config_deserialization() {
        let toml_str = r#"
            ip = "0.0.0.0"
            port = 8080
            owner = "MyOrg"
            repo = "myrepo"
            verbose = true
            refresh = 30
            theme = "light"
        "#;

        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.ip, "0.0.0.0");
        assert_eq!(config.port, 8080);
        assert_eq!(config.owner, "MyOrg");
        assert_eq!(config.repo, "myrepo");
        assert!(config.verbose);
        assert_eq!(config.refresh, 30);
        assert_eq!(config.theme, "light");
    }

    #[tokio::test]
    async fn test_rate_limit_blocks_after_limit() {
        let config = RateLimitConfig {
            global_rps: 2,
            per_ip_rps: 1,
            global_burst: 2,
            per_ip_burst: 1,
            has_github_token: true,
        };

        let limiter = RateLimitManager::new(config);
        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.check_request(test_ip).await.is_ok());
        assert!(limiter.check_request(test_ip).await.is_err());

        tokio::time::sleep(Duration::from_secs(1)).await;

        assert!(limiter.check_request(test_ip).await.is_ok());
    }

    #[tokio::test]
    async fn test_different_ips_independent() {
        let config = RateLimitConfig::development();
        let limiter = RateLimitManager::new(config);

        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        assert!(limiter.check_request(ip1).await.is_ok());
        assert!(limiter.check_request(ip2).await.is_ok());
    }

    #[tokio::test]
    async fn test_global_rate_limit() {
        let config = RateLimitConfig {
            global_rps: 1,
            per_ip_rps: 10,
            global_burst: 1,
            per_ip_burst: 10,
            has_github_token: false,
        };

        let limiter = RateLimitManager::new(config);
        let ip1: IpAddr = "192.168.1.1".parse().unwrap();
        let ip2: IpAddr = "192.168.1.2".parse().unwrap();

        assert!(limiter.check_request(ip1).await.is_ok());

        assert!(limiter.check_request(ip2).await.is_err());
    }

    #[test]
    fn test_extract_client_ip() {
        let test_ip = "192.168.1.100";
        let parsed: IpAddr = test_ip.parse().unwrap();
        assert_eq!(parsed.to_string(), "192.168.1.100");

        let test_ipv6 = "2001:db8::1";
        let parsed_v6: IpAddr = test_ipv6.parse().unwrap();
        assert_eq!(parsed_v6.to_string(), "2001:db8::1");
    }

    #[tokio::test]
    async fn test_rate_limit_with_jitter() {
        let config = RateLimitConfig::development();
        let limiter = RateLimitManager::new(config);
        let test_ip: IpAddr = "192.168.1.1".parse().unwrap();

        assert!(limiter.check_request_with_jitter(test_ip).await.is_ok());
    }

    #[test]
    fn test_timeout_config_default() {
        let config = TimeoutConfig::default();
        assert_eq!(config.global_secs, 30);
        assert_eq!(config.connect_secs, 10);
        assert_eq!(config.request_total_secs, 45);
    }

    #[test]
    fn test_config_with_timeouts() {
        let config = Config {
            base_url: None,
            ip: "127.0.0.1".to_string(),
            port: 3000,
            github_token: None,
            owner: "NixOS".to_string(),
            repo: "nixpkgs".to_string(),
            verbose: false,
            refresh: 0,
            theme: "dark".to_string(),
            rate_limit: crate::RateLimitConfigWrapper::default(),
            timeouts: TimeoutConfig {
                global_secs: 60,
                connect_secs: 5,
                request_total_secs: 90,
            },
            cache: CacheConfig::default(),
        };

        assert_eq!(config.timeouts.global_secs, 60);
        assert_eq!(config.timeouts.connect_secs, 5);
        assert_eq!(config.timeouts.request_total_secs, 90);
    }

    #[test]
    fn test_timeout_config_serialization() {
        let config = Config::default();
        let serialized = toml::to_string(&config).unwrap();

        assert!(serialized.contains("[timeouts]"));
        assert!(serialized.contains("global_secs"));
        assert!(serialized.contains("connect_secs"));
        assert!(serialized.contains("request_total_secs"));
    }

    #[test]
    fn test_timeout_config_deserialization() {
        let toml_str = r#"
        ip = "0.0.0.0"
        port = 8080
        owner = "MyOrg"
        repo = "myrepo"

        [timeouts]
        global_secs = 60
        connect_secs = 15
        request_total_secs = 120
    "#;

        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.timeouts.global_secs, 60);
        assert_eq!(config.timeouts.connect_secs, 15);
        assert_eq!(config.timeouts.request_total_secs, 120);
    }

    #[test]
    fn test_timeout_config_partial_deserialization() {
        let toml_str = r#"
        ip = "127.0.0.1"
        port = 3000

        [timeouts]
        global_secs = 45
    "#;

        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.timeouts.global_secs, 45);
        assert_eq!(config.timeouts.connect_secs, 10);
        assert_eq!(config.timeouts.request_total_secs, 45);
    }

    #[test]
    fn test_timeout_config_missing_section() {
        let toml_str = r#"
        ip = "127.0.0.1"
        port = 3000
        owner = "NixOS"
        repo = "nixpkgs"
    "#;

        let config: Config = toml::from_str(toml_str).unwrap();

        assert_eq!(config.timeouts.global_secs, 30);
        assert_eq!(config.timeouts.connect_secs, 10);
        assert_eq!(config.timeouts.request_total_secs, 45);
    }

    #[test]
    fn test_timeout_values_reasonable() {
        let config = TimeoutConfig::default();

        assert!(config.connect_secs < config.global_secs);
        assert!(config.request_total_secs > config.global_secs);
        assert!(config.connect_secs >= 5 && config.connect_secs <= 30);
        assert!(config.global_secs >= 10 && config.global_secs <= 120);
        assert!(config.request_total_secs >= 30 && config.request_total_secs <= 300);
    }

    #[tokio::test]
    async fn test_handle_request_with_timeout_simulation() {
        use std::time::Instant;

        let start = Instant::now();
        let timeout_duration = Duration::from_millis(100);

        let slow_operation = async {
            sleep(Duration::from_millis(200)).await;
            Ok::<_, Box<dyn std::error::Error + Send + Sync>>("Should not reach here")
        };

        let result = timeout(timeout_duration, slow_operation).await;

        assert!(result.is_err());
        assert!(start.elapsed() < Duration::from_millis(150));
    }

    #[tokio::test]
    async fn test_timeout_config_client_builder() {
        let config = Config {
            timeouts: TimeoutConfig {
                global_secs: 20,
                connect_secs: 5,
                request_total_secs: 30,
            },
            ..Default::default()
        };

        let client_result = reqwest::Client::builder()
            .user_agent("nixtracker-rs/test")
            .timeout(Duration::from_secs(config.timeouts.global_secs))
            .connect_timeout(Duration::from_secs(config.timeouts.connect_secs))
            .build();

        assert!(client_result.is_ok());

        let client = client_result.unwrap();

        let result = client.get("http://192.0.2.1:81").send().await;

        assert!(result.is_err());
    }

    #[test]
    fn test_timeout_config_validation() {
        let valid_config = TimeoutConfig {
            global_secs: 1,
            connect_secs: 1,
            request_total_secs: 1,
        };

        assert_eq!(valid_config.global_secs, 1);

        let large_config = TimeoutConfig {
            global_secs: 3600,
            connect_secs: 60,
            request_total_secs: 7200,
        };

        assert_eq!(large_config.global_secs, 3600);
    }

    #[test]
    fn test_timeout_config_independence() {
        let config1 = Config::default();
        let mut config2 = Config::default();

        config2.timeouts.global_secs = 60;

        assert_ne!(config1.timeouts.global_secs, config2.timeouts.global_secs);
        assert_eq!(config1.timeouts.connect_secs, config2.timeouts.connect_secs);
    }

    #[tokio::test]
    async fn test_cache_basic_operations() {
        let config = CacheConfig {
            max_entries: 10,
            ttl_seconds: 60,
            enabled: true,
        };

        let cache = Cache::new(config);

        let data = json!({"test": "data", "number": 42});
        cache.insert("key1".to_string(), data.clone()).await;

        let retrieved = cache.get("key1").await;
        assert!(retrieved.is_some());
        assert_eq!(retrieved.unwrap(), data);

        let missing = cache.get("nonexistent").await;
        assert!(missing.is_none());
    }

    #[tokio::test]
    async fn test_cache_lru_eviction() {
        let config = CacheConfig {
            max_entries: 3,
            ttl_seconds: 60,
            enabled: true,
        };

        let cache = Cache::new(config);

        cache.insert("key1".to_string(), json!({"id": 1})).await;
        cache.insert("key2".to_string(), json!({"id": 2})).await;
        cache.insert("key3".to_string(), json!({"id": 3})).await;

        assert!(cache.get("key1").await.is_some());

        cache.insert("key4".to_string(), json!({"id": 4})).await;

        assert!(cache.get("key1").await.is_some());
        assert!(cache.get("key3").await.is_some());
        assert!(cache.get("key4").await.is_some());
        assert!(cache.get("key2").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_ttl_expiration() {
        let config = CacheConfig {
            max_entries: 10,
            ttl_seconds: 1,
            enabled: true,
        };

        let cache = Cache::new(config);

        let data = json!({"test": "expires"});
        cache.insert("key1".to_string(), data.clone()).await;

        assert!(cache.get("key1").await.is_some());

        tokio::time::sleep(Duration::from_secs(2)).await;

        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_disabled() {
        let config = CacheConfig {
            max_entries: 10,
            ttl_seconds: 60,
            enabled: false,
        };

        let cache = Cache::new(config);

        cache
            .insert("key1".to_string(), json!({"test": "data"}))
            .await;

        assert!(cache.get("key1").await.is_none());
    }

    #[tokio::test]
    async fn test_cache_cleanup_expired() {
        let config = CacheConfig {
            max_entries: 10,
            ttl_seconds: 1,
            enabled: true,
        };

        let cache = Cache::new(config);

        cache.insert("key1".to_string(), json!({"id": 1})).await;
        cache.insert("key2".to_string(), json!({"id": 2})).await;
        cache.insert("key3".to_string(), json!({"id": 3})).await;

        let stats_before = cache.stats().await;
        assert_eq!(stats_before.entries, 3);

        tokio::time::sleep(Duration::from_secs(2)).await;

        cache.cleanup_expired().await;

        let stats_after = cache.stats().await;
        assert_eq!(stats_after.entries, 0);
    }

    #[tokio::test]
    async fn test_cache_stats() {
        let config = CacheConfig {
            max_entries: 5,
            ttl_seconds: 60,
            enabled: true,
        };

        let cache = Cache::new(config);

        cache.insert("key1".to_string(), json!({"id": 1})).await;
        cache.insert("key2".to_string(), json!({"id": 2})).await;

        cache.get("key1").await;
        cache.get("key1").await;
        cache.get("key2").await;

        let stats = cache.stats().await;

        assert_eq!(stats.entries, 2);
        assert_eq!(stats.capacity, 5);
        assert!(stats.total_hits > 0);
        assert_eq!(stats.expired_entries, 0);
        assert!(stats.enabled);
    }

    #[tokio::test]
    async fn test_cache_clear() {
        let config = CacheConfig {
            max_entries: 10,
            ttl_seconds: 60,
            enabled: true,
        };

        let cache = Cache::new(config);

        cache.insert("key1".to_string(), json!({"id": 1})).await;
        cache.insert("key2".to_string(), json!({"id": 2})).await;
        cache.insert("key3".to_string(), json!({"id": 3})).await;

        assert!(cache.get("key1").await.is_some());

        cache.clear().await;

        assert!(cache.get("key1").await.is_none());
        assert!(cache.get("key2").await.is_none());
        assert!(cache.get("key3").await.is_none());

        let stats = cache.stats().await;
        assert_eq!(stats.entries, 0);
    }

    #[test]
    fn test_cache_config_default() {
        let config = CacheConfig::default();

        assert_eq!(config.max_entries, 500);
        assert_eq!(config.ttl_seconds, 60);
        assert!(config.enabled);
    }

    #[test]
    fn test_cache_config_serialization() {
        let config = CacheConfig {
            max_entries: 1000,
            ttl_seconds: 300,
            enabled: false,
        };

        let serialized = toml::to_string(&config).unwrap();
        assert!(serialized.contains("max_entries = 1000"));
        assert!(serialized.contains("ttl_seconds = 300"));
        assert!(serialized.contains("enabled = false"));

        let deserialized: CacheConfig = toml::from_str(&serialized).unwrap();
        assert_eq!(deserialized.max_entries, 1000);
        assert_eq!(deserialized.ttl_seconds, 300);
        assert!(!deserialized.enabled);
    }
}
