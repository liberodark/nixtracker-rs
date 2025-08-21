mod cache;
mod github;
mod hydra;
mod rate_limit;
mod security;
mod templates;

#[cfg(test)]
mod tests;

use clap::Parser;
use directories::ProjectDirs;
use http_body_util::Full;
use hyper::body::{Bytes, Incoming};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use maud::Markup;
use serde::{Deserialize, Serialize};
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::time::{Duration, timeout};

use cache::{Cache, CacheConfig};
use github::{BranchStatus, PullRequest, check_branch_propagation, fetch_github_api};
use rate_limit::{RateLimitConfig, RateLimitManager, extract_client_ip};
use security::add_security_headers;
use templates::{error_fragment, index_page, pr_details_fragment, pr_page};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

#[derive(Parser, Debug)]
#[command(name = "nixtracker-rs")]
#[command(about = "Track nixpkgs pull requests", long_about = None)]
struct Args {
    #[arg(long, env = "BASE_URL")]
    base_url: Option<String>,

    #[arg(long)]
    ip: Option<String>,

    #[arg(short, long)]
    port: Option<u16>,

    #[arg(long, env = "GITHUB_TOKEN")]
    github_token: Option<String>,

    #[arg(short, long)]
    config: Option<PathBuf>,

    #[arg(long)]
    owner: Option<String>,

    #[arg(long)]
    repo: Option<String>,

    #[arg(short, long)]
    verbose: bool,

    #[arg(long)]
    refresh: Option<u64>,

    #[arg(long)]
    theme: Option<String>,

    #[arg(long = "no-rate-limit")]
    no_rate_limit: bool,

    #[arg(long)]
    rate_limit_global: Option<u32>,

    #[arg(long)]
    rate_limit_per_ip: Option<u32>,

    #[arg(long)]
    rate_limit_burst: Option<u32>,

    #[arg(long)]
    rate_limit_ip_burst: Option<u32>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base_url: Option<String>,

    #[serde(default = "default_ip")]
    pub ip: String,

    #[serde(default = "default_port")]
    pub port: u16,

    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_token: Option<String>,

    #[serde(default = "default_owner")]
    pub owner: String,

    #[serde(default = "default_repo")]
    pub repo: String,

    #[serde(default)]
    pub verbose: bool,

    #[serde(default = "default_refresh")]
    pub refresh: u64,

    #[serde(default = "default_theme")]
    pub theme: String,

    #[serde(default = "default_rate_limit_config")]
    pub rate_limit: RateLimitConfigWrapper,

    #[serde(default = "default_timeouts")]
    pub timeouts: TimeoutConfig,

    #[serde(default)]
    pub cache: CacheConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TimeoutConfig {
    #[serde(default = "default_timeout_global")]
    pub global_secs: u64,

    #[serde(default = "default_timeout_connect")]
    pub connect_secs: u64,

    #[serde(default = "default_timeout_request")]
    pub request_total_secs: u64,
}

impl Default for TimeoutConfig {
    fn default() -> Self {
        Self {
            global_secs: 30,
            connect_secs: 10,
            request_total_secs: 45,
        }
    }
}

fn default_timeouts() -> TimeoutConfig {
    TimeoutConfig::default()
}

fn default_timeout_global() -> u64 {
    30
}
fn default_timeout_connect() -> u64 {
    10
}
fn default_timeout_request() -> u64 {
    45
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitConfigWrapper {
    #[serde(default = "default_true")]
    pub enabled: bool,

    #[serde(default = "default_global_rps")]
    pub global_rps: u32,

    #[serde(default = "default_per_ip_rps")]
    pub per_ip_rps: u32,

    #[serde(default = "default_global_burst")]
    pub global_burst: u32,

    #[serde(default = "default_per_ip_burst")]
    pub per_ip_burst: u32,
}

impl Default for RateLimitConfigWrapper {
    fn default() -> Self {
        default_rate_limit_config()
    }
}

impl Default for Config {
    fn default() -> Self {
        Self {
            base_url: None,
            ip: default_ip(),
            port: default_port(),
            github_token: None,
            owner: default_owner(),
            repo: default_repo(),
            verbose: false,
            refresh: default_refresh(),
            theme: default_theme(),
            rate_limit: default_rate_limit_config(),
            timeouts: default_timeouts(),
            cache: CacheConfig::default(),
        }
    }
}

impl Config {
    pub fn api_base(&self) -> String {
        self.base_url
            .as_ref()
            .map(|u| u.trim_end_matches('/').to_string())
            .unwrap_or_else(|| format!("http://{}:{}", self.ip, self.port))
    }
}

fn default_ip() -> String {
    "127.0.0.1".to_string()
}

fn default_port() -> u16 {
    3000
}

fn default_owner() -> String {
    "NixOS".to_string()
}

fn default_repo() -> String {
    "nixpkgs".to_string()
}

fn default_refresh() -> u64 {
    0
}

fn default_theme() -> String {
    "dark".to_string()
}

fn default_rate_limit_config() -> RateLimitConfigWrapper {
    RateLimitConfigWrapper {
        enabled: true,
        global_rps: 30,
        per_ip_rps: 2,
        global_burst: 50,
        per_ip_burst: 10,
    }
}

fn default_true() -> bool {
    true
}

fn default_global_rps() -> u32 {
    30
}

fn default_per_ip_rps() -> u32 {
    2
}

fn default_global_burst() -> u32 {
    50
}

fn default_per_ip_burst() -> u32 {
    10
}

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub client: reqwest::Client,
    pub cache: Arc<Cache>,
    pub rate_limiter: Arc<RateLimitManager>,
}

#[derive(Serialize)]
struct ApiResponse {
    pr: PrSummary,
    branch_status: Vec<BranchStatus>,
}

#[derive(Serialize)]
struct PrSummary {
    number: u64,
    title: String,
    state: String,
    author: String,
    created_at: String,
    updated_at: String,
    merged_at: Option<String>,
    merge_commit_sha: Option<String>,
    html_url: String,
    base_branch: String,
    head_branch: String,
    labels: Vec<String>,
    draft: bool,
}

#[derive(Serialize)]
struct ApiError {
    error: String,
}

fn load_config(args: Args) -> Result<Config> {
    let mut config = Config::default();

    let config_path = if let Some(path) = args.config {
        Some(path)
    } else if PathBuf::from("config.toml").exists() {
        Some(PathBuf::from("config.toml"))
    } else if let Some(proj_dirs) = ProjectDirs::from("", "", "nixtracker-rs") {
        let mut xdg_path = proj_dirs.config_dir().to_path_buf();
        xdg_path.push("config.toml");
        xdg_path.exists().then_some(xdg_path)
    } else {
        None
    };

    if let Some(path) = config_path {
        if args.verbose {
            println!("Loading config from: {}", path.display());
        }
        let contents = fs::read_to_string(&path)?;
        config = toml::from_str(&contents)?;
    }

    if let Some(base_url) = args.base_url {
        config.base_url = Some(base_url);
    }
    if let Some(ip) = args.ip {
        config.ip = ip;
    }
    if let Some(port) = args.port {
        config.port = port;
    }
    if let Some(token) = args.github_token {
        config.github_token = Some(token);
    }
    if let Some(owner) = args.owner {
        config.owner = owner;
    }
    if let Some(repo) = args.repo {
        config.repo = repo;
    }
    if args.verbose {
        config.verbose = true;
    }
    if let Some(refresh) = args.refresh {
        config.refresh = refresh;
    }
    if let Some(theme) = args.theme {
        config.theme = theme;
    }
    if args.no_rate_limit {
        config.rate_limit.enabled = false;
    }
    if let Some(global_rps) = args.rate_limit_global {
        config.rate_limit.global_rps = global_rps;
    }
    if let Some(per_ip_rps) = args.rate_limit_per_ip {
        config.rate_limit.per_ip_rps = per_ip_rps;
    }
    if let Some(burst) = args.rate_limit_burst {
        config.rate_limit.global_burst = burst;
    }
    if let Some(ip_burst) = args.rate_limit_ip_burst {
        config.rate_limit.per_ip_burst = ip_burst;
    }

    Ok(config)
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let config = load_config(args)?;

    if config.verbose {
        println!("Configuration:");
        println!("  Bind: {}:{}", config.ip, config.port);
        println!("  Repository: {}/{}", config.owner, config.repo);
        println!("  Theme: {}", config.theme);
        println!(
            "  Auto-refresh: {}s",
            if config.refresh > 0 {
                config.refresh.to_string()
            } else {
                "disabled".to_string()
            }
        );
        println!(
            "  GitHub token: {}",
            if config.github_token.is_some() {
                "configured"
            } else {
                "not set"
            }
        );
        println!(
            "  Cache: {}",
            if config.cache.enabled {
                format!(
                    "{} entries, {}s TTL",
                    config.cache.max_entries, config.cache.ttl_seconds
                )
            } else {
                "disabled".to_string()
            }
        );
        println!(
            "  Rate limiting: {}",
            if config.rate_limit.enabled {
                "enabled"
            } else {
                "disabled"
            }
        );
        if config.rate_limit.enabled {
            println!(
                "    Global: {} req/s (burst: {})",
                config.rate_limit.global_rps, config.rate_limit.global_burst
            );
            println!(
                "    Per IP: {} req/s (burst: {})",
                config.rate_limit.per_ip_rps, config.rate_limit.per_ip_burst
            );
        }
    }

    let client = reqwest::Client::builder()
        .user_agent("nixtracker-rs/0.1.0")
        .timeout(Duration::from_secs(config.timeouts.global_secs))
        .connect_timeout(Duration::from_secs(config.timeouts.connect_secs))
        .pool_idle_timeout(Duration::from_secs(90))
        .pool_max_idle_per_host(2)
        .tcp_keepalive(Duration::from_secs(60))
        .build()?;

    let rate_limit_config = if config.github_token.is_some() {
        RateLimitConfig {
            global_rps: config.rate_limit.global_rps,
            per_ip_rps: config.rate_limit.per_ip_rps,
            global_burst: config.rate_limit.global_burst,
            per_ip_burst: config.rate_limit.per_ip_burst,
            has_github_token: true,
        }
    } else {
        RateLimitConfig {
            global_rps: 1.max(config.rate_limit.global_rps / 30),
            per_ip_rps: 1,
            global_burst: 2.max(config.rate_limit.global_burst / 25),
            per_ip_burst: 2,
            has_github_token: false,
        }
    };

    let rate_limiter = Arc::new(RateLimitManager::new(rate_limit_config));
    let cache = Arc::new(Cache::new(config.cache.clone()));

    if config.cache.enabled {
        let cache_cleanup = cache.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(60));
            loop {
                interval.tick().await;
                cache_cleanup.cleanup_expired().await;
            }
        });
    }

    let state = Arc::new(AppState {
        config,
        client,
        cache,
        rate_limiter,
    });

    let bind_addr: SocketAddr = format!("{}:{}", state.config.ip, state.config.port).parse()?;
    let listener = TcpListener::bind(bind_addr).await?;

    println!(
        "🚀 Server running on http://{}:{}",
        state.config.ip, state.config.port
    );

    if state.config.github_token.is_none() {
        println!("⚠️  No GitHub token configured - API rate limits will apply (60 req/hour)");
        println!(
            "   Set GITHUB_TOKEN environment variable or add to config.toml for better performance"
        );
    }

    loop {
        let (stream, remote_addr) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| {
                        handle_request_with_timeout(req, state.clone(), remote_addr)
                    }),
                )
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request_with_timeout(
    req: Request<Incoming>,
    state: Arc<AppState>,
    addr: SocketAddr,
) -> Result<Response<Full<Bytes>>> {
    let timeout_duration = Duration::from_secs(state.config.timeouts.request_total_secs);

    match timeout(timeout_duration, handle_request(req, state.clone(), addr)).await {
        Ok(result) => result,
        Err(_) => {
            if state.config.verbose {
                eprintln!(
                    "Request timeout after {}s",
                    state.config.timeouts.request_total_secs
                );
            }

            let response = Response::builder()
                .status(StatusCode::REQUEST_TIMEOUT)
                .header("content-type", "application/json")
                .body(Full::new(Bytes::from(
                    r#"{"error":"Request timeout","message":"The request took too long to process"}"#
                )))
                .unwrap();

            Ok(add_security_headers(response))
        }
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
    _addr: SocketAddr,
) -> Result<Response<Full<Bytes>>> {
    let path = req.uri().path();
    let method = req.method();

    let client_ip = extract_client_ip(&req);

    if state.config.verbose {
        println!("Request: {} {} from {}", method, path, client_ip);
    }

    if !matches!(path, "/health" | "/metrics") && state.config.rate_limit.enabled {
        if let Err(e) = state.rate_limiter.check_request(client_ip).await {
            if state.config.verbose {
                println!("Rate limit exceeded for {}: {:?}", client_ip, e);
            }
            return Ok(e.to_response());
        }
    }

    // IMPORTANT: Check /api/pr/ BEFORE /pr/ because /api/pr/ starts with /pr/
    let response = if method == Method::GET {
        if path == "/" {
            Ok(serve_html(index_page(&state.config)))
        } else if path.starts_with("/api/pr/") {
            // API endpoint
            let pr_number = match path.trim_start_matches("/api/pr/").parse::<u64>() {
                Ok(num) => num,
                Err(_) => {
                    return Ok(serve_json_error(
                        "Invalid PR number",
                        StatusCode::BAD_REQUEST,
                    ));
                }
            };

            if state.config.verbose {
                println!("API request for PR #{}", pr_number);
            }

            match fetch_pr_json(&state, pr_number).await {
                Ok(json) => Ok(serve_json(json)),
                Err(e) => {
                    if state.config.verbose {
                        eprintln!("API error for PR #{}: {}", pr_number, e);
                    }
                    Ok(serve_json_error(
                        &e.to_string(),
                        StatusCode::INTERNAL_SERVER_ERROR,
                    ))
                }
            }
        } else if path == "/pr" {
            // Web UI PR query
            let query = req.uri().query().unwrap_or("");
            if state.config.verbose {
                println!("PR query: {}", query);
            }

            match extract_pr_number(query) {
                Ok(pr_number) => {
                    if state.config.verbose {
                        println!("Fetching PR #{}", pr_number);
                    }

                    match fetch_pr_details(&state, pr_number).await {
                        Ok(markup) => {
                            if state.config.verbose {
                                println!("Successfully fetched PR #{}", pr_number);
                            }
                            Ok(serve_html(markup))
                        }
                        Err(e) => {
                            if state.config.verbose {
                                eprintln!("Error fetching PR #{}: {}", pr_number, e);
                            }
                            Ok(serve_html(error_fragment(&format!(
                                "Failed to fetch PR #{}: {}",
                                pr_number, e
                            ))))
                        }
                    }
                }
                Err(e) => {
                    if state.config.verbose {
                        eprintln!("Invalid PR number: {}", e);
                    }
                    Ok(serve_html(error_fragment("Invalid PR number")))
                }
            }
        } else if path.starts_with("/pr/") {
            let pr_number = path
                .trim_start_matches("/pr/")
                .parse::<u64>()
                .map_err(|_| "Invalid PR number")?;

            if state.config.verbose {
                println!("Loading PR page for #{}", pr_number);
            }

            Ok(serve_html(pr_page(&state.config, pr_number)))
        } else if path == "/health" {
            Ok(Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/plain")
                .body(Full::new(Bytes::from("OK")))
                .unwrap())
        } else if path == "/metrics" {
            let stats = state.rate_limiter.get_stats(client_ip);
            Ok(serve_json(stats))
        } else {
            // 404
            if state.config.verbose {
                println!("404 Not Found: {} {}", method, path);
            }
            let mut res = Response::new(Full::new(Bytes::from("Not Found")));
            *res.status_mut() = StatusCode::NOT_FOUND;
            Ok(res)
        }
    } else {
        if state.config.verbose {
            println!("Method not allowed: {} {}", method, path);
        }
        let mut res = Response::new(Full::new(Bytes::from("Method Not Allowed")));
        *res.status_mut() = StatusCode::METHOD_NOT_ALLOWED;
        Ok(res)
    };

    response
}

fn extract_pr_number(query: &str) -> Result<u64> {
    for pair in query.split('&') {
        if let Some((key, value)) = pair.split_once('=') {
            if key == "pr" {
                return value.parse::<u64>().map_err(|_| "Invalid PR number".into());
            }
        }
    }
    Err("PR number not found in query".into())
}

fn serve_html(markup: Markup) -> Response<Full<Bytes>> {
    let response = Response::builder()
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(markup.into_string())))
        .unwrap();

    add_security_headers(response)
}

fn serve_json<T: Serialize>(data: T) -> Response<Full<Bytes>> {
    let json = serde_json::to_string(&data).unwrap_or_else(|_| "{}".to_string());
    let response = Response::builder() // ← Ajouter "let response ="
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap();

    add_security_headers(response)
}

fn serve_json_error(message: &str, status: StatusCode) -> Response<Full<Bytes>> {
    let error = ApiError {
        error: message.to_string(),
    };
    let json = serde_json::to_string(&error).unwrap();
    let response = Response::builder()
        .status(status)
        .header("content-type", "application/json")
        .body(Full::new(Bytes::from(json)))
        .unwrap();

    add_security_headers(response)
}

async fn fetch_pr_json(state: &AppState, pr_number: u64) -> Result<ApiResponse> {
    let pr = fetch_github_api::<PullRequest>(
        state,
        &format!(
            "https://api.github.com/repos/{}/{}/pulls/{}",
            state.config.owner, state.config.repo, pr_number
        ),
    )
    .await?;

    let branch_status = if pr.merged_at.is_some() && state.config.repo == "nixpkgs" {
        check_branch_propagation(state, &pr).await
    } else {
        Vec::new()
    };

    let pr_summary = PrSummary {
        number: pr.number,
        title: pr.title,
        state: if pr.merged_at.is_some() {
            "merged".to_string()
        } else {
            pr.state
        },
        author: pr.user.login,
        created_at: pr.created_at.to_rfc3339(),
        updated_at: pr.updated_at.to_rfc3339(),
        merged_at: pr.merged_at.map(|dt| dt.to_rfc3339()),
        merge_commit_sha: pr.merge_commit_sha,
        html_url: pr.html_url,
        base_branch: pr
            .base
            .label
            .split(':')
            .next_back()
            .unwrap_or("")
            .to_string(),
        head_branch: pr.head.label,
        labels: pr.labels.into_iter().map(|l| l.name).collect(),
        draft: pr.draft,
    };

    Ok(ApiResponse {
        pr: pr_summary,
        branch_status,
    })
}

async fn fetch_pr_details(state: &AppState, pr_number: u64) -> Result<Markup> {
    if state.config.verbose {
        println!("Starting to fetch PR #{} details", pr_number);
    }

    let pr = fetch_github_api::<PullRequest>(
        state,
        &format!(
            "https://api.github.com/repos/{}/{}/pulls/{}",
            state.config.owner, state.config.repo, pr_number
        ),
    )
    .await?;

    if state.config.verbose {
        println!(
            "PR #{} fetched: {}, state: {}, merged: {}",
            pr_number,
            pr.title,
            pr.state,
            pr.merged_at.is_some()
        );
    }

    let branch_status = if pr.merged_at.is_some() && state.config.repo == "nixpkgs" {
        if state.config.verbose {
            println!("PR #{} is merged, checking branch propagation", pr_number);
        }
        let status = check_branch_propagation(state, &pr).await;
        if state.config.verbose {
            println!(
                "Branch propagation check complete, {} branches/channels found",
                status.len()
            );
        }
        status
    } else {
        if state.config.verbose {
            println!(
                "PR #{} is not merged or not nixpkgs, skipping propagation check",
                pr_number
            );
        }
        Vec::new()
    };

    Ok(pr_details_fragment(pr, branch_status, &state.config))
}
