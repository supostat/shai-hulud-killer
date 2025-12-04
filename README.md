# Shai-Hulud 2.0 Killer 🐛

A fast, interactive CLI tool to detect the **Shai-Hulud 2.0** npm supply chain attack in your codebase.

![Rust](https://img.shields.io/badge/Rust-1.84-orange)
![Docker](https://img.shields.io/badge/Docker-ready-blue)
![License](https://img.shields.io/badge/license-MIT-green)

## About Shai-Hulud 2.0

Shai-Hulud 2.0 is one of the fastest-spreading npm supply chain attacks ever observed (November 2025). It:

- 🔓 **Steals credentials** — GitHub tokens, npm tokens, and cloud credentials (AWS/GCP/Azure)
- 🤖 **Creates backdoors** — Registers self-hosted GitHub Actions runners for remote code execution
- 🐛 **Auto-propagates** — Injects malware into victim's npm packages and republishes them
- 🔄 **Self-heals** — Forms a distributed botnet using GitHub repos to share stolen tokens

[Read the full Netskope report](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed)

## Features

- 🚀 **Fast parallel scanning** — Multi-threaded using Rayon
- 🖥️ **Interactive TUI** — Browse folders, watch progress, view results
- 🔍 **Pattern detection** — Known malicious code signatures
- 📦 **Package.json analysis** — Dangerous lifecycle hooks (`preinstall`, `postinstall`)
- 🔐 **Hash matching** — Known malicious file SHA256 hashes from Netskope IOCs
- 📊 **JSON output** — CI/CD integration ready

## Quick Start

### Prerequisites

- Docker & Docker Compose

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/shai-hulud-killer.git
cd shai-hulud-killer

# Make dev script executable
chmod +x dev.sh

# Build the release binary
./dev.sh build
```

### Usage

```bash
# Run interactive scanner (default: ~/Projects)
./dev.sh run

# Scan a specific directory
./dev.sh run /path/to/your/project

# Quick scan with pre-built binary
./dev.sh scan /path/to/project

# JSON output for CI/CD
./dev.sh json /path/to/project

# Development shell
./dev.sh dev
```

## TUI Controls

| Key | Action |
|-----|--------|
| `↑` / `↓` or `j` / `k` | Navigate files/folders |
| `Enter` or `l` | Enter selected folder |
| `Backspace` or `h` | Go to parent folder |
| `Space` or `s` | **Start scan** |
| `n` | Toggle node_modules scanning |
| `b` | Back to folder selection (from results) |
| `q` or `Esc` | Quit |

## What It Detects

### 🔴 Critical

| Indicator | Description |
|-----------|-------------|
| `setup_bun.js` / `bun_environment.js` | Known malicious payload files |
| SHA256 hash matches | Netskope IOC file hashes |
| `SHA1HULUD` / `Sha1-Hulud: The Second Coming` | Shai-Hulud marker strings |
| `list_AWS_secrets()` / `list_GCP_secrets()` / `list_Azure_secrets()` | Cloud credential harvesting |
| `githubGetPackagesByMaintainer` / `githubUpdatePackage` | Malicious npm automation |
| Suspicious `preinstall` / `postinstall` hooks | Payload injection vectors |

### 🟠 High

| Indicator | Description |
|-----------|-------------|
| `gh auth token` | GitHub CLI token extraction |
| `trufflehog` | Secret scanning tool abuse |
| `curl \| sh` / `wget \| bash` | Remote code execution |
| `~/.aws/credentials` | AWS credential file access |
| `application_default_credentials.json` | GCP credential access |
| `azureProfile.json` | Azure profile access |

### 🟡 Medium

| Indicator | Description |
|-----------|-------------|
| `.npmrc` access | NPM config/token access |
| `GITHUB_TOKEN` / `GH_TOKEN` | GitHub token env vars |
| `runs-on: self-hosted` | Self-hosted runner config |
| `npm publish --access public` | Public package publishing |

## CI/CD Integration

### GitHub Actions

```yaml
name: Security Scan

on: [push, pull_request]

jobs:
  shai-hulud-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      
      - name: Scan for Shai-Hulud 2.0
        run: |
          docker run --rm -v ${{ github.workspace }}:/scan \
            ghcr.io/yourusername/shai-hulud-killer:latest \
            --json /scan > scan-results.json
          
          # Fail if critical issues found
          if jq -e '.summary.critical > 0 or .summary.high > 0' scan-results.json; then
            echo "::error::Shai-Hulud 2.0 indicators detected!"
            jq '.findings[] | select(.severity == "Critical" or .severity == "High")' scan-results.json
            exit 1
          fi
```

### GitLab CI

```yaml
shai-hulud-scan:
  image: docker:latest
  services:
    - docker:dind
  script:
    - docker run --rm -v $CI_PROJECT_DIR:/scan shai-hulud-killer --json /scan > results.json
    - if [ $(jq '.summary.critical' results.json) -gt 0 ]; then exit 1; fi
  artifacts:
    paths:
      - results.json
```

## Development

```bash
# Enter development container
./dev.sh dev

# Inside container:
cargo build              # Build debug
cargo build --release    # Build release
cargo test              # Run tests
cargo fmt               # Format code
cargo clippy            # Lint

# Clean up Docker resources
./dev.sh clean
```

## Project Structure

```
shai-hulud-killer/
├── Cargo.toml           # Rust dependencies
├── Dockerfile           # Build container
├── docker-compose.yml   # Docker services
├── dev.sh              # Development helper script
├── README.md           # This file
└── src/
    ├── main.rs         # Entry point & CLI args
    ├── app.rs          # Application state & navigation
    ├── patterns.rs     # Detection patterns & IOCs
    ├── scanner.rs      # Parallel file scanning
    └── ui.rs           # Terminal UI (ratatui)
```

## Tech Stack

- **Rust 1.84** — Performance and safety
- **ratatui** — Terminal UI framework
- **rayon** — Parallel processing
- **walkdir** — Directory traversal
- **regex** — Pattern matching
- **sha2** — Hash verification
- **clap** — CLI argument parsing

## License

MIT

## References

- [Netskope Threat Labs: Shai-Hulud 2.0 Analysis](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed)
- [Aikido Security: Original Shai-Hulud Discovery](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again)

---

*Named after the giant sandworms from Frank Herbert's Dune — because this tool hunts the worm that's burrowing through the npm ecosystem.* 🪱
