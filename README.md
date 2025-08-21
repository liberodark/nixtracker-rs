# nixtracker-rs

Tracker for NixOS/nixpkgs pull requests, showing branch and channel propagation status.

[![Rust](https://github.com/liberodark/nixtracker-rs/actions/workflows/rust.yml/badge.svg)](https://github.com/liberodark/nixtracker-rs/actions/workflows/rust.yml)

## Features

- Track nixpkgs pull request status and merge propagation
- View branch flow from master → staging → channels
- Real-time channel status checking
- Hydra build status links
- GitHub API integration with rate limit handling
- Auto-refresh capability
- Dark/light theme support

## Installation

### Via cargo
```bash
cargo install nixtracker-rs
```

### Manual build
```bash
git clone https://github.com/liberodark/nixtracker-rs.git
cd nixtracker-rs
cargo build --release
sudo cp target/release/nixtracker-rs /usr/local/bin/
```

## Usage

Start the server:
```bash
./nixtracker-rs
```

Then open your browser at `http://127.0.0.1:3000`

### Configuration

Create a `config.toml` file:
```toml
ip = "127.0.0.1"
port = 3000
owner = "NixOS"
repo = "nixpkgs"
theme = "dark"
refresh = 0  # Auto-refresh in seconds, 0 to disable
github_token = "your_token"
```

### Command Line Options

```bash
# Server configuration
nixtracker-rs --ip 0.0.0.0 --port 8080

# GitHub configuration
nixtracker-rs --owner NixOS --repo nixpkgs

# With GitHub token (recommended)
nixtracker-rs --github-token your_token

# Enable auto-refresh (seconds)
nixtracker-rs --refresh 60

# Theme selection
nixtracker-rs --theme light

# Verbose output
nixtracker-rs --verbose

# Custom config file
nixtracker-rs --config /path/to/config.toml
```

### Environment Variables

```bash
export GITHUB_TOKEN="your_token"
./nixtracker-rs
```

## Example

### Track a specific PR
1. Start the server: `nixtracker-rs`
2. Open browser to `http://127.0.0.1:3000`
3. Enter PR number (e.g., `435012`)
4. View propagation status through branches and channels

## Alternative
If you're looking for a more performant alternative with advanced features, check out:
https://git.qyliss.net/pr-tracker
