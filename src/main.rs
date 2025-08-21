mod github;
mod hydra;
mod templates;

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
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::sync::RwLock;

use github::{CachedPR, PullRequest, check_branch_propagation, fetch_github_api};
use templates::{error_fragment, index_page, pr_details_fragment, pr_page};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

const CACHE_TTL_SECS: u64 = 60;
const MAX_CACHE_SIZE: usize = 100;

#[derive(Parser, Debug)]
#[command(name = "nixtracker-rs")]
#[command(about = "Track nixpkgs pull requests", long_about = None)]
struct Args {
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
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
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
}

impl Default for Config {
    fn default() -> Self {
        Self {
            ip: default_ip(),
            port: default_port(),
            github_token: None,
            owner: default_owner(),
            repo: default_repo(),
            verbose: false,
            refresh: default_refresh(),
            theme: default_theme(),
        }
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

#[derive(Clone)]
pub struct AppState {
    pub config: Config,
    pub client: reqwest::Client,
    pub cache: Arc<RwLock<HashMap<String, CachedPR>>>,
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
    }

    let client = reqwest::Client::builder()
        .user_agent("nixtracker-rs/0.1.0")
        .build()?;

    let state = Arc::new(AppState {
        config,
        client,
        cache: Arc::new(RwLock::new(HashMap::new())),
    });

    let bind_addr: SocketAddr = format!("{}:{}", state.config.ip, state.config.port).parse()?;
    let listener = TcpListener::bind(bind_addr).await?;
    println!(
        "🚀 Server running on http://{}:{}",
        state.config.ip, state.config.port
    );
    println!(
        "📦 Tracking {}/{} pull requests",
        state.config.owner, state.config.repo
    );

    if state.config.github_token.is_none() {
        println!("⚠️  No GitHub token configured - API rate limits will apply (60 req/hour)");
        println!(
            "   Set GITHUB_TOKEN environment variable or add to config.toml for better performance"
        );
    }

    loop {
        let (stream, _) = listener.accept().await?;
        let io = TokioIo::new(stream);
        let state = state.clone();

        tokio::spawn(async move {
            if let Err(err) = http1::Builder::new()
                .serve_connection(
                    io,
                    service_fn(move |req| handle_request(req, state.clone())),
                )
                .await
            {
                eprintln!("Error serving connection: {:?}", err);
            }
        });
    }
}

async fn handle_request(
    req: Request<Incoming>,
    state: Arc<AppState>,
) -> Result<Response<Full<Bytes>>> {
    let response = match (req.method(), req.uri().path()) {
        (&Method::GET, "/") => Ok(serve_html(index_page(&state.config))),
        (&Method::GET, "/pr") => {
            let query = req.uri().query().unwrap_or("");
            match extract_pr_number(query) {
                Ok(pr_number) => match fetch_pr_details(&state, pr_number).await {
                    Ok(markup) => Ok(serve_html(markup)),
                    Err(e) => Ok(serve_html(error_fragment(&format!(
                        "Failed to fetch PR #{}: {}",
                        pr_number, e
                    )))),
                },
                Err(_) => Ok(serve_html(error_fragment("Invalid PR number"))),
            }
        }
        (&Method::GET, path) if path.starts_with("/pr/") => {
            let pr_number = path
                .trim_start_matches("/pr/")
                .parse::<u64>()
                .map_err(|_| "Invalid PR number")?;

            Ok(serve_html(pr_page(&state.config, pr_number)))
        }
        _ => {
            let mut res = Response::new(Full::new(Bytes::from("Not Found")));
            *res.status_mut() = StatusCode::NOT_FOUND;
            Ok(res)
        }
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
    Response::builder()
        .header("content-type", "text/html; charset=utf-8")
        .body(Full::new(Bytes::from(markup.into_string())))
        .unwrap()
}

async fn fetch_pr_details(state: &AppState, pr_number: u64) -> Result<Markup> {
    let pr = fetch_github_api::<PullRequest>(
        state,
        &format!(
            "https://api.github.com/repos/{}/{}/pulls/{}",
            state.config.owner, state.config.repo, pr_number
        ),
    )
    .await?;

    let branch_status = if pr.merged_at.is_some() && state.config.repo == "nixpkgs" {
        check_branch_propagation(&state, &pr).await
    } else {
        Vec::new()
    };

    Ok(pr_details_fragment(pr, branch_status, &state.config))
}
