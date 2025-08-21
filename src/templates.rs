use chrono::{DateTime, Utc};
use maud::{DOCTYPE, Markup, PreEscaped, html};

use crate::Config;
use crate::github::{BranchStatus, PullRequest};

fn search_bar(current_pr: Option<u64>) -> Markup {
    html! {
        div.search-box {
            input id="pr-input" type="number"
                name="pr"
                placeholder="Enter PR number (e.g., 435012)"
                value=[current_pr]
                min="1"
                onkeydown="if(event.key === 'Enter' && this.value) { event.preventDefault(); document.getElementById('track-btn').click(); }";

            button id="track-btn"
                hx-get="/pr"
                hx-include="#pr-input"
                hx-target="#results" {
                "Track PR"
            }
        }
    }
}

pub fn index_page(config: &Config) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=(config.theme) {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { (config.repo) " PR Tracker" }
                script { (PreEscaped(HTMX_JS)) }
                style { (PreEscaped(CSS)) }
                @if config.refresh > 0 {
                    meta http-equiv="refresh" content=(config.refresh);
                }
            }
            body {
                div.container {
                    header {
                        h1 { "🔍 " (config.owner) "/" (config.repo) " Pull Request Tracker" }
                        p { "Track the status of pull requests" }
                        @if config.github_token.is_none() {
                            p.warning { "⚠️ No GitHub token configured - limited to 60 requests/hour" }
                        }
                    }

                    (search_bar(None))

                    div id="results" {}
                }
            }
        }
    }
}

pub fn pr_page(config: &Config, pr_number: u64) -> Markup {
    html! {
        (DOCTYPE)
        html lang="en" data-theme=(config.theme) {
            head {
                meta charset="UTF-8";
                meta name="viewport" content="width=device-width, initial-scale=1.0";
                title { "PR #" (pr_number) " - " (config.repo) " PR Tracker" }
                script { (PreEscaped(HTMX_JS)) }
                style { (PreEscaped(CSS)) }
                @if config.refresh > 0 {
                    meta http-equiv="refresh" content=(config.refresh);
                }
            }
            body {
                div.container {
                    header {
                        h1 { "🔍 " (config.owner) "/" (config.repo) " Pull Request Tracker" }
                        p { "Pull Request #" (pr_number) }
                        @if config.github_token.is_none() {
                            p.warning { "⚠️ No GitHub token configured - limited to 60 requests/hour" }
                        }
                    }

                    (search_bar(Some(pr_number)))

                    div id="results"
                        hx-get=(format!("/pr?pr={}", pr_number))
                        hx-trigger="load" {
                        div.loading-simple {
                            p { "Loading PR #" (pr_number) "..." }
                        }
                    }

                    div.api-info {
                        p.muted {
                            "API: "
                            code { (format!("curl {}/api/pr/{}", config.api_base(), pr_number)) }
                        }
                    }
                }
            }
        }
    }
}

pub fn pr_details_fragment(
    pr: PullRequest,
    branch_status: Vec<BranchStatus>,
    config: &Config,
) -> Markup {
    let state_class = if pr.merged_at.is_some() {
        "merged"
    } else {
        &pr.state
    };

    let state_text = if pr.merged_at.is_some() {
        "MERGED".to_string()
    } else {
        pr.state.to_uppercase()
    };

    html! {
        div.pr-details {
            div.pr-header {
                h2 { (pr.title) }
                div.pr-meta {
                    span.pr-number { "#" (pr.number) }
                    span class=(format!("pr-state {}", state_class)) { (state_text) }
                    @if pr.draft {
                        span.pr-draft { "DRAFT" }
                    }
                }
            }

            div.pr-info {
                div.info-row {
                    strong { "Author:" }
                    div.author-info {
                        img.avatar src=(pr.user.avatar_url) alt=(pr.user.login);
                        a href=(pr.user.html_url) target="_blank" { (pr.user.login) }
                    }
                }
                div.info-row {
                    strong { "Created:" }
                    span { (format_date(&pr.created_at)) }
                }
                div.info-row {
                    strong { "Updated:" }
                    span { (format_date(&pr.updated_at)) }
                }
                @if let Some(merged_at) = pr.merged_at {
                    div.info-row {
                        strong { "Merged:" }
                        span { (format_date(&merged_at)) }
                    }
                }
                div.info-row {
                    strong { "Branch:" }
                    span { (pr.head.label) " → " (pr.base.label) }
                }
            }

            @if !pr.labels.is_empty() {
                div.labels {
                    @for label in &pr.labels {
                        span.label style=(format!("background-color: #{}; color: {}",
                            label.color,
                            get_contrast_color(&label.color)
                        )) {
                            (label.name)
                        }
                    }
                }
            }

            @if !branch_status.is_empty() {
                div.section {
                    h3 { "🔄 Branch & Channel Propagation" }
                    div.propagation-tree {
                        @for (i, status) in branch_status.iter().enumerate() {
                            div class=(format!("tree-node level-{}",
                                if i == 0 { 0 }
                                else if status.is_channel { 2 }
                                else { 1 }
                            )) {
                                @if i > 0 {
                                    div.tree-line {}
                                }
                                div.tree-content {
                                    div.branch-info {
                                        @if status.has_commit {
                                            span.status-icon.success { "✓" }
                                        } @else if i == 0 {
                                            span.status-icon.success { "✓" }
                                        } @else {
                                            span.status-icon.pending { "" }
                                        }
                                        span class=(if status.is_channel { "channel-name" } else { "branch-name" }) {
                                            (status.name)
                                            @if i == 0 {
                                                " (merge target)"
                                            }
                                        }
                                        @if let Some(ref link) = status.hydra_link {
                                            a.hydra-link href=(link) target="_blank" title="View on Hydra" {
                                                "🔗"
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            div.pr-actions {
                a.btn-primary href=(pr.html_url) target="_blank" { "View on GitHub" }
                button.btn-secondary
                    hx-get=(format!("/pr?pr={}", pr.number))
                    hx-target="#results" {
                    "Refresh"
                }
                @if config.refresh > 0 {
                    span.auto-refresh { "Auto-refresh in " (config.refresh) "s" }
                }
            }
        }
    }
}

pub fn error_fragment(message: &str) -> Markup {
    html! {
        div.error {
            p { "❌ " (message) }
        }
    }
}

fn format_date(date: &DateTime<Utc>) -> String {
    let now = Utc::now();
    let diff = now.signed_duration_since(date);

    if diff.num_days() == 0 {
        if diff.num_hours() == 0 {
            "Just now".to_string()
        } else {
            format!("{}h ago", diff.num_hours())
        }
    } else if diff.num_days() < 30 {
        format!("{}d ago", diff.num_days())
    } else {
        date.format("%Y-%m-%d").to_string()
    }
}

fn get_contrast_color(hex_color: &str) -> &'static str {
    let rgb = hex_color.trim_start_matches('#');
    if rgb.len() != 6 {
        return "white";
    }

    let r = u8::from_str_radix(&rgb[0..2], 16).unwrap_or(0) as f32 / 255.0;
    let g = u8::from_str_radix(&rgb[2..4], 16).unwrap_or(0) as f32 / 255.0;
    let b = u8::from_str_radix(&rgb[4..6], 16).unwrap_or(0) as f32 / 255.0;

    let luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b;

    if luminance > 0.5 { "black" } else { "white" }
}

const CSS: &str = include_str!("assets/style.css");
// HTMX Version 2.0.6
const HTMX_JS: &str = include_str!("assets/htmx.min.js");
