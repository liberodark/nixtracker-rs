use crate::Result;
use reqwest;

pub fn get_hydra_link(branch_or_channel: &str) -> Option<String> {
    match branch_or_channel {
        "staging" => Some("https://hydra.nixos.org/jobset/nixpkgs/staging".to_string()),
        "staging-next" => {
            Some("https://hydra.nixos.org/jobset/nixpkgs/staging-next#tabs-jobs".to_string())
        }
        "haskell-updates" => {
            Some("https://hydra.nixos.org/jobset/nixpkgs/haskell-updates#tabs-jobs".to_string())
        }
        "master" => Some("https://hydra.nixos.org/jobset/nixpkgs/trunk#tabs-jobs".to_string()),
        "nixpkgs-unstable" => {
            Some("https://hydra.nixos.org/job/nixpkgs/trunk/unstable#tabs-constituents".to_string())
        }
        "nixos-unstable-small" => Some(
            "https://hydra.nixos.org/job/nixos/unstable-small/tested#tabs-constituents".to_string(),
        ),
        "nixos-unstable" => Some(
            "https://hydra.nixos.org/job/nixos/trunk-combined/tested#tabs-constituents".to_string(),
        ),
        branch if branch.starts_with("nixos-") => {
            let version = branch.strip_prefix("nixos-")?;
            Some(format!(
                "https://hydra.nixos.org/job/nixos/release-{}/tested#tabs-constituents",
                version
            ))
        }
        branch if branch.starts_with("nixpkgs-") && branch.ends_with("-darwin") => None,
        branch if branch.starts_with("release-") => {
            let version = branch.strip_prefix("release-")?;
            Some(format!(
                "https://hydra.nixos.org/jobset/nixos/release-{}",
                version
            ))
        }
        branch if branch.starts_with("staging-next-") => {
            let version = branch.strip_prefix("staging-next-")?;
            Some(format!(
                "https://hydra.nixos.org/jobset/nixpkgs/staging-next-{}#tabs-jobs",
                version
            ))
        }
        _ => None,
    }
}

pub fn is_channel(name: &str) -> bool {
    name.starts_with("nixpkgs-") || name.starts_with("nixos-")
}

fn get_channel_url_name(channel: &str) -> Option<&str> {
    match channel {
        "nixpkgs-unstable" => Some("nixpkgs-unstable"),
        "nixos-unstable" => Some("nixos-unstable"),
        "nixos-unstable-small" => Some("nixos-unstable-small"),
        c if c.starts_with("nixos-") && !c.contains("unstable") => Some(c),
        c if c.starts_with("nixpkgs-") && c.ends_with("-darwin") => Some(c),
        _ => None,
    }
}

pub async fn check_channel_commit(
    client: &reqwest::Client,
    channel: &str,
    target_commit: &str,
    github_token: Option<&str>,
) -> Result<bool> {
    let channel_url_name = match get_channel_url_name(channel) {
        Some(name) => name,
        None => return Ok(false),
    };

    let channel_commit_url = format!(
        "https://channels.nixos.org/{}/git-revision",
        channel_url_name
    );

    let response = match client.get(&channel_commit_url).send().await {
        Ok(r) => r,
        Err(_) => return Ok(false),
    };

    if !response.status().is_success() {
        return Ok(false);
    }

    let channel_commit = response.text().await?.trim().to_string();

    if channel_commit == target_commit {
        return Ok(true);
    }

    // Check if target_commit is an ancestor of channel_commit
    // This means the channel has advanced past our commit
    let compare_url = format!(
        "https://api.github.com/repos/NixOS/nixpkgs/compare/{}...{}",
        target_commit, channel_commit
    );

    let mut request = client
        .get(&compare_url)
        .header("User-Agent", "nixtracker-rs/0.1.0");

    // Use GitHub token if available (IMPORTANT for rate limits)
    if let Some(token) = github_token {
        request = request.header("Authorization", format!("Bearer {}", token));
    }

    let github_response = request.send().await?;

    if !github_response.status().is_success() {
        return Ok(false);
    }

    let compare_data: serde_json::Value = github_response.json().await?;

    // If status is "ahead", the channel commit is newer and contains our target commit
    // If status is "identical", they're the same
    Ok(matches!(
        compare_data.get("status").and_then(|s| s.as_str()),
        Some("ahead") | Some("identical")
    ))
}
