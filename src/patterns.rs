use regex::Regex;
use serde::Serialize;
use std::sync::LazyLock;

/// Known malicious filenames
pub const MALICIOUS_FILES: &[&str] = &["setup_bun.js", "bun_environment.js"];

/// Known malicious file hashes (SHA256) from Netskope IOCs
pub const MALICIOUS_HASHES: &[&str] = &[
    "62ee164b9b306250c1172583f138c9614139264f889fa99614903c12755468d0",
    "f099c5d9ec417d4445a0328ac0ada9cde79fc37410914103ae9c609cbc0ee068",
    "cbb9bc5a8496243e02f3cc080efbe3e4a1430ba0671f2e43a202bf45b05479cd",
    "a3894003ad1d293ba96d77881ccd2071446dc3f65f434669b49b3da92421901a",
];

/// Directories to skip during scanning
pub const SKIP_DIRS: &[&str] = &[".git", ".svn", ".hg", "vendor", "dist", "build", "__pycache__"];

/// Dangerous npm lifecycle hooks
pub const DANGEROUS_HOOKS: &[&str] = &["preinstall", "postinstall", "preuninstall", "install"];

/// File extensions to scan for patterns
pub const SCANNABLE_EXTENSIONS: &[&str] = &["js", "ts", "mjs", "cjs", "json", "yaml", "yml", "sh"];

/// Suspicious code patterns with descriptions and severity
pub static SUSPICIOUS_PATTERNS: LazyLock<Vec<PatternRule>> = LazyLock::new(|| {
    vec![
        PatternRule::new(
            r"(?i)SHA1HULUD",
            "Shai-Hulud runner identifier",
            Severity::Critical,
        ),
        PatternRule::new(
            r"(?i)Sha1-Hulud:\s*The\s*Second\s*Coming",
            "Shai-Hulud 2.0 marker string",
            Severity::Critical,
        ),
        PatternRule::new(
            r"setup_bun\.js",
            "Malicious setup file reference",
            Severity::Critical,
        ),
        PatternRule::new(
            r"bun_environment\.js",
            "Malicious environment file reference",
            Severity::Critical,
        ),
        PatternRule::new(
            r"list_AWS_secrets|list_GCP_secrets|list_Azure_secrets",
            "Cloud secrets enumeration function",
            Severity::Critical,
        ),
        PatternRule::new(
            r"githubGetPackagesByMaintainer|githubUpdatePackage",
            "Malicious GitHub package functions",
            Severity::Critical,
        ),
        PatternRule::new(
            r"github_save_file|githubListRepos",
            "Suspicious GitHub automation",
            Severity::High,
        ),
        PatternRule::new(
            r"gh\s+auth\s+token",
            "GitHub CLI token extraction",
            Severity::High,
        ),
        PatternRule::new(
            r"\.npmrc",
            "NPM config file access",
            Severity::Medium,
        ),
        PatternRule::new(
            r"NPM_TOKEN|npm_token",
            "NPM token reference",
            Severity::High,
        ),
        PatternRule::new(
            r"GITHUB_TOKEN|GH_TOKEN",
            "GitHub token environment variable",
            Severity::Medium,
        ),
        PatternRule::new(
            r"(?i)trufflehog",
            "Secret scanning tool reference",
            Severity::High,
        ),
        PatternRule::new(
            r"actions/runner/config",
            "GitHub Actions runner config access",
            Severity::High,
        ),
        PatternRule::new(
            r"discussion\.ya?ml",
            "Suspicious workflow filename",
            Severity::High,
        ),
        PatternRule::new(
            r"runs-on:\s*\[?\s*self-hosted",
            "Self-hosted runner configuration",
            Severity::Medium,
        ),
        PatternRule::new(
            r"curl.*\|\s*(sh|bash|node)",
            "Remote code execution via curl pipe",
            Severity::High,
        ),
        PatternRule::new(
            r"wget.*\|\s*(sh|bash|node)",
            "Remote code execution via wget pipe",
            Severity::High,
        ),
        PatternRule::new(
            r"~/\.aws/credentials",
            "AWS credentials file access",
            Severity::High,
        ),
        PatternRule::new(
            r"application_default_credentials\.json",
            "GCP credentials file access",
            Severity::High,
        ),
        PatternRule::new(
            r"azureProfile\.json",
            "Azure profile access",
            Severity::High,
        ),
        PatternRule::new(
            r"npm\s+publish\s+--access\s+public",
            "Public npm publish command",
            Severity::Medium,
        ),
    ]
});

/// Suspicious preinstall/postinstall patterns
pub static HOOK_PATTERNS: LazyLock<Vec<HookRule>> = LazyLock::new(|| {
    vec![
        HookRule::new("setup_bun", "Malicious setup script"),
        HookRule::new("bun_environment", "Malicious environment script"),
        HookRule::new(r"node\s+-e", "Inline node code execution"),
        HookRule::new(r"curl.*\|", "Piped curl command"),
        HookRule::new(r"wget.*\|", "Piped wget command"),
        HookRule::new(r"eval\(", "Eval code execution"),
        HookRule::new(r"Function\(", "Dynamic function creation"),
    ]
});

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

impl Severity {
    pub fn as_str(&self) -> &'static str {
        match self {
            Severity::Critical => "CRITICAL",
            Severity::High => "HIGH",
            Severity::Medium => "MEDIUM",
            Severity::Low => "LOW",
        }
    }

    pub fn color(&self) -> ratatui::style::Color {
        use ratatui::style::Color;
        match self {
            Severity::Critical => Color::Red,
            Severity::High => Color::LightRed,
            Severity::Medium => Color::Yellow,
            Severity::Low => Color::Blue,
        }
    }
}

pub struct PatternRule {
    pub regex: Regex,
    pub description: &'static str,
    pub severity: Severity,
}

impl PatternRule {
    fn new(pattern: &str, description: &'static str, severity: Severity) -> Self {
        Self {
            regex: Regex::new(pattern).expect("Invalid regex pattern"),
            description,
            severity,
        }
    }
}

pub struct HookRule {
    pub regex: Regex,
    pub description: &'static str,
}

impl HookRule {
    fn new(pattern: &str, description: &'static str) -> Self {
        Self {
            regex: Regex::new(pattern).expect("Invalid regex pattern"),
            description,
        }
    }
}
