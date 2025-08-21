use chrono::{DateTime, Utc};
use serde::Deserialize;
use std::time::{Duration, Instant};

use crate::hydra::{check_channel_commit, get_hydra_link, is_channel};
use crate::{AppState, CACHE_TTL_SECS, MAX_CACHE_SIZE, Result};

#[derive(Deserialize)]
pub struct PullRequest {
    pub number: u64,
    pub title: String,
    pub state: String,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub merged_at: Option<DateTime<Utc>>,
    pub merge_commit_sha: Option<String>,
    pub html_url: String,
    pub user: User,
    pub labels: Vec<Label>,
    pub draft: bool,
    pub head: Branch,
    pub base: Branch,
}

#[derive(Deserialize)]
pub struct User {
    pub login: String,
    pub avatar_url: String,
    pub html_url: String,
}

#[derive(Deserialize)]
pub struct Label {
    pub name: String,
    pub color: String,
}

#[derive(Deserialize)]
pub struct Branch {
    pub label: String,
}

#[derive(Debug, Clone)]
pub struct BranchStatus {
    pub name: String,
    pub has_commit: bool,
    pub is_channel: bool,
    pub hydra_link: Option<String>,
}

#[derive(Clone)]
pub struct CachedPR {
    pub data: serde_json::Value,
    pub timestamp: Instant,
}

pub fn get_branch_flow(base_branch: &str) -> Vec<&'static str> {
    match base_branch {
        "master" => vec![
            "staging",
            "staging-next",
            "nixpkgs-unstable",
            "nixos-unstable-small",
            "nixos-unstable",
        ],
        "staging" => vec!["staging-next"],
        "staging-next" => vec![],
        "haskell-updates" => vec!["staging"],
        branch if branch.starts_with("release-") || branch.starts_with("nixos-") => {
            let version = branch.split('-').last().unwrap_or("");
            if branch.starts_with("release-") {
                vec![
                    Box::leak(format!("nixpkgs-{}-darwin", version).into_boxed_str()),
                    Box::leak(format!("nixos-{}-small", version).into_boxed_str()),
                    Box::leak(format!("nixos-{}", version).into_boxed_str()),
                ]
            } else {
                vec![]
            }
        }
        _ => vec![],
    }
}

pub async fn check_branch_propagation(state: &AppState, pr: &PullRequest) -> Vec<BranchStatus> {
    let commit_sha = match &pr.merge_commit_sha {
        Some(sha) => sha,
        None => return vec![],
    };

    let base_branch = pr.base.label.split(':').last().unwrap_or("");

    let mut statuses = vec![BranchStatus {
        name: base_branch.to_string(),
        has_commit: true,
        is_channel: false,
        hydra_link: get_hydra_link(base_branch),
    }];

    let flow = get_branch_flow(base_branch);

    let mut tasks = Vec::new();

    for branch_or_channel in flow {
        let is_chan = is_channel(branch_or_channel);
        let hydra_link = get_hydra_link(branch_or_channel);
        let name = branch_or_channel.to_string();
        let commit = commit_sha.clone();
        let token = state.config.github_token.clone();
        let client = state.client.clone();

        if !is_chan {
            let state_clone = state.clone();
            tasks.push(tokio::spawn(async move {
                let mut status = BranchStatus {
                    name: name.clone(),
                    has_commit: false,
                    is_channel: false,
                    hydra_link,
                };

                if let Ok(compare) = fetch_github_api::<serde_json::Value>(
                    &state_clone,
                    &format!(
                        "https://api.github.com/repos/{}/{}/compare/{}...{}",
                        state_clone.config.owner, state_clone.config.repo, commit, name
                    ),
                )
                .await
                {
                    if let Some(status_str) = compare.get("status").and_then(|s| s.as_str()) {
                        status.has_commit = status_str == "ahead" || status_str == "identical";
                    }
                }

                status
            }));
        } else {
            tasks.push(tokio::spawn(async move {
                BranchStatus {
                    name: name.clone(),
                    has_commit: check_channel_commit(&client, &name, &commit, token.as_deref())
                        .await
                        .unwrap_or(false),
                    is_channel: true,
                    hydra_link,
                }
            }));
        }
    }

    for task in tasks {
        if let Ok(status) = task.await {
            statuses.push(status);
        }
    }

    statuses
}

pub async fn fetch_github_api<T: for<'de> Deserialize<'de>>(
    state: &AppState,
    url: &str,
) -> Result<T> {
    {
        let cache = state.cache.read().await;
        if let Some(cached) = cache.get(url) {
            if cached.timestamp.elapsed() < Duration::from_secs(CACHE_TTL_SECS) {
                if state.config.verbose {
                    println!("Cache hit for: {}", url);
                }
                return Ok(serde_json::from_value(cached.data.clone())?);
            }
        }
    }

    let mut request = state.client.get(url);
    if let Some(token) = &state.config.github_token {
        request = request.header("Authorization", format!("Bearer {}", token));
    }

    let response = request.send().await?;
    if !response.status().is_success() {
        return Err(format!("GitHub API error: {}", response.status()).into());
    }

    let json_value: serde_json::Value = response.json().await?;

    {
        let mut cache = state.cache.write().await;
        cache.insert(
            url.to_string(),
            CachedPR {
                data: json_value.clone(),
                timestamp: Instant::now(),
            },
        );

        if cache.len() > MAX_CACHE_SIZE {
            let oldest_key = cache
                .iter()
                .min_by_key(|(_, v)| v.timestamp)
                .map(|(k, _)| k.clone());
            if let Some(key) = oldest_key {
                cache.remove(&key);
            }
        }
    }

    Ok(serde_json::from_value(json_value)?)
}
