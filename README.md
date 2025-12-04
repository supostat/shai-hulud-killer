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

## Production Usage

### Using Docker

```bash
# Scan current directory
./dev.sh run .

# Scan specific path
./dev.sh run /path/to/your/project

# JSON output for CI/CD pipelines
./dev.sh json /path/to/your/project
```

### Build Native Binary

**Option 1: Docker (Linux binary)**
```bash
./dev.sh build
./dev.sh extract shk

# Run via Docker (works on any OS)
./dev.sh run /path/to/your/project
./dev.sh json /path/to/your/project
```

**Option 2: Native macOS/Linux build (requires Rust)**
```bash
# Install Rust if needed: curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo build --release

# Run native binary
./target/release/shai-hulud-killer /path/to/your/project

# With JSON output
./target/release/shai-hulud-killer --json /path/to/your/project

# Include node_modules scanning
./target/release/shai-hulud-killer --include-node-modules /path/to/your/project
```

### Quick Command Reference

| Use Case | Command |
|----------|---------|
| Interactive scan | `./dev.sh run /path` |
| JSON output | `./dev.sh json /path` |
| CI/CD pipeline | `docker run --rm -v /path:/scan shai-hulud-killer:latest --json /scan` |
| Native binary | `./shai-hulud-killer --json /path` |

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

## Testing

The project includes comprehensive tests covering malware detection and UI display.

### Run Tests

```bash
./dev.sh test
```

### Test Categories

| Category | Description |
|----------|-------------|
| **Malicious File Detection** | Detects `setup_bun.js`, `bun_environment.js` |
| **Shai-Hulud Markers** | Finds `SHA1HULUD`, `Sha1-Hulud` identifiers |
| **Credential Theft Patterns** | AWS, GCP, Azure, GitHub token patterns |
| **Dangerous Hooks** | `preinstall`, `postinstall` with suspicious commands |
| **Malicious Workflows** | GitHub Actions with self-hosted runners |
| **RCE Patterns** | `curl \| sh`, `wget \| bash` patterns |
| **Clean File Validation** | Ensures no false positives on safe code |
| **Edge Cases** | Boundary conditions and partial matches |

### UI Display Tests

| Test | Validates |
|------|-----------|
| `test_severity_colors` | Critical→Red, High→LightRed, Medium→Yellow, Low→Blue |
| `test_severity_display_strings` | Uppercase labels: CRITICAL, HIGH, MEDIUM, LOW |
| `test_finding_type_variants` | All FindingType enum variants exist |
| `test_findings_have_display_data` | Path, description, severity for each finding |
| `test_all_severity_levels_in_results` | Multiple severity levels triggered |
| `test_summary_display_values` | Summary counts add up correctly |
| `test_finding_context_for_display` | Context data sized for UI |
| `test_ui_icon_mapping` | 📛 🔐 🔍 ⚡ icons for finding types |
| `test_result_status_icon` | 🚨 ⚠️ ✅ status icons |
| `test_json_serialization_for_display` | JSON output serialization |

### Test Samples

```
test_samples/
├── malicious/              # Known bad patterns
│   ├── setup_bun.js
│   ├── bun_environment.js
│   ├── infected_package.json
│   └── .github/workflows/discussion.yaml
├── clean/                  # Safe code (no findings expected)
│   ├── app.js
│   ├── server.js
│   ├── utils.js
│   └── package.json
└── edge_cases/             # Boundary conditions
    ├── config_loader.js
    └── package.json
```

## Project Structure

```
shai-hulud-killer/
├── Cargo.toml           # Rust dependencies
├── Dockerfile           # Build container
├── docker-compose.yml   # Docker services
├── dev.sh              # Development helper script
├── README.md           # This file
├── src/
│   ├── main.rs         # Entry point & CLI args
│   ├── app.rs          # Application state & navigation
│   ├── patterns.rs     # Detection patterns & IOCs
│   ├── scanner.rs      # Parallel file scanning
│   ├── ui.rs           # Terminal UI (ratatui)
│   └── tests.rs        # Test suite (21 tests)
└── test_samples/
    ├── malicious/      # Mocked malware files
    ├── clean/          # Safe sample files
    └── edge_cases/     # Boundary conditions
```

## Tech Stack

- **Rust 1.84** — Performance and safety
- **ratatui** — Terminal UI framework
- **rayon** — Parallel processing
- **walkdir** — Directory traversal
- **regex** — Pattern matching
- **sha2** — Hash verification
- **clap** — CLI argument parsing

## Detection Flow

```
📁 Target Directory
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  TRAVERSAL (walkdir + rayon)                                 │
│  • Multi-threaded directory walking                          │
│  • Skips: .git, node_modules*, dist, build, vendor           │
│  • Scans: .js, .ts, .mjs, .cjs, .json, .yaml, .yml, .sh      │
└──────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  FOR EACH FILE (parallel processing):                        │
│                                                              │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ 1️⃣  FILENAME CHECK                                     │  │
│  │    Match against known malicious files:                │  │
│  │    • setup_bun.js                                      │  │
│  │    • bun_environment.js                                │  │
│  │    → CRITICAL if matched                               │  │
│  └────────────────────────────────────────────────────────┘  │
│                         │                                    │
│                         ▼                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ 2️⃣  HASH CHECK                                         │  │
│  │    Compute SHA256 hash of file content                 │  │
│  │    Compare against Netskope IOC hashes                 │  │
│  │    → CRITICAL if matched                               │  │
│  └────────────────────────────────────────────────────────┘  │
│                         │                                    │
│                         ▼                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ 3️⃣  PATTERN SCAN                                       │  │
│  │    Line-by-line regex matching for:                    │  │
│  │    • Shai-Hulud markers (SHA1HULUD, Second Coming)     │  │
│  │    • Credential theft (gh auth, trufflehog)            │  │
│  │    • Cloud secrets (AWS/GCP/Azure access)              │  │
│  │    • RCE patterns (curl|sh, wget|bash)                 │  │
│  │    → Severity based on pattern type                    │  │
│  └────────────────────────────────────────────────────────┘  │
│                         │                                    │
│                         ▼                                    │
│  ┌────────────────────────────────────────────────────────┐  │
│  │ 4️⃣  PACKAGE.JSON HOOK CHECK (if applicable)            │  │
│  │    Parse scripts section for dangerous hooks:          │  │
│  │    • preinstall                                        │  │
│  │    • postinstall                                       │  │
│  │    • install                                           │  │
│  │    Check hook content for malicious patterns           │  │
│  │    → CRITICAL if suspicious command found              │  │
│  └────────────────────────────────────────────────────────┘  │
│                                                              │
└──────────────────────────────────────────────────────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────┐
│  RESULTS AGGREGATION                                         │
│  • Group findings by severity (Critical/High/Medium/Low)     │
│  • Include file path, line number, and context               │
│  • Output: Interactive TUI or JSON for CI/CD                 │
└──────────────────────────────────────────────────────────────┘
```

\* node_modules scanning is optional (toggle with `-n` flag or `n` key in TUI)

## License

MIT

## References

- [Netskope Threat Labs: Shai-Hulud 2.0 Analysis](https://www.netskope.com/blog/shai-hulud-2-0-aggressive-automated-one-of-fastest-spreading-npm-supply-chain-attacks-ever-observed)
- [Aikido Security: Original Shai-Hulud Discovery](https://www.aikido.dev/blog/s1ngularity-nx-attackers-strike-again)

---

*Named after the giant sandworms from Frank Herbert's Dune — because this tool hunts the worm that's burrowing through the npm ecosystem.* 🪱
