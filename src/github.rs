use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::borrow::Cow;

use crate::hydra::{check_channel_commit, get_hydra_link, is_channel};
use crate::{AppState, Result};

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

#[derive(Debug, Clone, Serialize)]
pub struct BranchStatus {
    pub name: String,
    pub has_commit: bool,
    pub is_channel: bool,
    pub hydra_link: Option<String>,
}

pub fn get_branch_flow(base_branch: &str) -> Vec<Cow<'static, str>> {
    match base_branch {
        "staging" => vec![
            Cow::Borrowed("staging-next"),
            Cow::Borrowed("master"),
            Cow::Borrowed("nixpkgs-unstable"),
            Cow::Borrowed("nixos-unstable-small"),
            Cow::Borrowed("nixos-unstable"),
        ],
        "staging-next" => vec![
            Cow::Borrowed("master"),
            Cow::Borrowed("nixpkgs-unstable"),
            Cow::Borrowed("nixos-unstable-small"),
            Cow::Borrowed("nixos-unstable"),
        ],
        "master" => vec![
            Cow::Borrowed("nixpkgs-unstable"),
            Cow::Borrowed("nixos-unstable-small"),
            Cow::Borrowed("nixos-unstable"),
        ],
        "haskell-updates" => vec![
            Cow::Borrowed("staging"),
            Cow::Borrowed("staging-next"),
            Cow::Borrowed("master"),
            Cow::Borrowed("nixpkgs-unstable"),
            Cow::Borrowed("nixos-unstable-small"),
            Cow::Borrowed("nixos-unstable"),
        ],
        branch if branch.starts_with("release-") => {
            let version = branch.strip_prefix("release-").unwrap();
            vec![
                Cow::Owned(format!("nixpkgs-{}-darwin", version)),
                Cow::Owned(format!("nixos-{}-small", version)),
                Cow::Owned(format!("nixos-{}", version)),
            ]
        }
        branch if branch.starts_with("staging-") && branch != "staging" => {
            if let Some(version) = branch.strip_prefix("staging-") {
                vec![
                    Cow::Owned(format!("staging-next-{}", version)),
                    Cow::Owned(format!("release-{}", version)),
                    Cow::Owned(format!("nixpkgs-{}-darwin", version)),
                    Cow::Owned(format!("nixos-{}-small", version)),
                    Cow::Owned(format!("nixos-{}", version)),
                ]
            } else {
                vec![]
            }
        }
        branch if branch.starts_with("staging-next-") => {
            if let Some(version) = branch.strip_prefix("staging-next-") {
                vec![
                    Cow::Owned(format!("release-{}", version)),
                    Cow::Owned(format!("nixpkgs-{}-darwin", version)),
                    Cow::Owned(format!("nixos-{}-small", version)),
                    Cow::Owned(format!("nixos-{}", version)),
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

    let base_branch = pr.base.label.split(':').next_back().unwrap_or("");

    let mut statuses = vec![BranchStatus {
        name: base_branch.to_string(),
        has_commit: true,
        is_channel: false,
        hydra_link: get_hydra_link(base_branch),
    }];

    let flow = get_branch_flow(base_branch);

    let mut tasks = Vec::new();

    for branch_or_channel in flow {
        let is_chan = is_channel(&branch_or_channel);
        let hydra_link = get_hydra_link(&branch_or_channel);
        let name = branch_or_channel.into_owned();
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
                    && let Some(status_str) = compare.get("status").and_then(|s| s.as_str())
                {
                    status.has_commit = status_str == "ahead" || status_str == "identical";
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
    if let Some(cached_value) = state.cache.get(url).await {
        if state.config.verbose {
            println!("Cache hit for: {}", url);
        }
        return Ok(serde_json::from_value(cached_value)?);
    }

    if state.config.verbose {
        println!("Fetching from GitHub API: {}", url);
    }

    let mut request = state
        .client
        .get(url)
        .header("User-Agent", "nixtracker-rs/0.1.0");

    if let Some(token) = &state.config.github_token {
        request = request.header("Authorization", format!("Bearer {}", token));
        if state.config.verbose {
            println!("Using GitHub token for authentication");
        }
    }

    let response = request.send().await?;
    let status = response.status();

    if !status.is_success() {
        let error_text = response
            .text()
            .await
            .unwrap_or_else(|_| "Unknown error".to_string());
        if state.config.verbose {
            eprintln!("GitHub API error {}: {}", status, error_text);
        }
        state.cache.remove(url).await;
        return Err(format!("GitHub API error {}: {}", status, error_text).into());
    }

    let json_value: serde_json::Value = response.json().await?;

    if state.config.verbose {
        println!("Successfully fetched data from GitHub API");
    }

    state
        .cache
        .insert(url.to_string(), json_value.clone())
        .await;

    Ok(serde_json::from_value(json_value)?)
}
