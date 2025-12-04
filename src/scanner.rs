use crate::patterns::*;
use anyhow::Result;
use rayon::prelude::*;
use serde::Serialize;
use sha2::{Digest, Sha256};
use std::fs;
use std::io::{BufRead, BufReader};
use std::path::Path;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use walkdir::WalkDir;

#[derive(Clone)]
pub struct ScanConfig {
    pub include_node_modules: bool,
}

impl Default for ScanConfig {
    fn default() -> Self {
        Self {
            include_node_modules: false,
        }
    }
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanResults {
    pub findings: Vec<Finding>,
    pub summary: Summary,
    pub scanned_files: usize,
    pub scan_path: String,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct Summary {
    pub total: usize,
    pub critical: usize,
    pub high: usize,
    pub medium: usize,
    pub low: usize,
}

#[derive(Debug, Clone, Serialize)]
pub struct Finding {
    pub path: String,
    pub finding_type: FindingType,
    pub severity: Severity,
    pub description: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub line: Option<usize>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub context: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub enum FindingType {
    MaliciousFile,
    MaliciousHash,
    SuspiciousPattern,
    DangerousHook,
    CompromisedPackage,
}

/// Progress callback type for UI updates
pub type ProgressCallback = Box<dyn Fn(usize, usize, &str) + Send + Sync>;

/// Scan directory with progress callback for UI
pub fn scan_directory_with_progress(
    path: &Path,
    config: &ScanConfig,
    on_progress: ProgressCallback,
) -> Result<ScanResults> {
    // First, collect all entries to get total count
    let entries: Vec<_> = WalkDir::new(path)
        .into_iter()
        .filter_entry(|e| should_scan_entry(e, config))
        .filter_map(|e| e.ok())
        .filter(|e| e.path().is_file())
        .collect();

    let total = entries.len();
    let processed = Arc::new(AtomicUsize::new(0));

    let findings: Vec<Finding> = entries
        .par_iter()
        .flat_map(|entry| {
            let file_path = entry.path();
            let mut file_findings = Vec::new();

            // Update progress
            let current = processed.fetch_add(1, Ordering::Relaxed) + 1;
            on_progress(current, total, &file_path.display().to_string());

            file_findings.extend(check_filename(file_path));
            file_findings.extend(check_file_hash(file_path));
            file_findings.extend(check_file_content(file_path));

            if file_path
                .file_name()
                .map(|n| n == "package.json")
                .unwrap_or(false)
            {
                file_findings.extend(check_package_json(file_path));
            }

            // Check package-lock.json for compromised packages
            if file_path
                .file_name()
                .map(|n| n == "package-lock.json" || n == "yarn.lock" || n == "pnpm-lock.yaml")
                .unwrap_or(false)
            {
                file_findings.extend(check_lockfile(file_path));
            }

            file_findings
        })
        .collect();

    let summary = Summary {
        total: findings.len(),
        critical: findings
            .iter()
            .filter(|f| f.severity == Severity::Critical)
            .count(),
        high: findings
            .iter()
            .filter(|f| f.severity == Severity::High)
            .count(),
        medium: findings
            .iter()
            .filter(|f| f.severity == Severity::Medium)
            .count(),
        low: findings
            .iter()
            .filter(|f| f.severity == Severity::Low)
            .count(),
    };

    Ok(ScanResults {
        findings,
        summary,
        scanned_files: total,
        scan_path: path.display().to_string(),
    })
}

/// Synchronous scan without progress (for JSON mode)
pub fn scan_directory_sync(path: &Path, config: &ScanConfig) -> Result<ScanResults> {
    scan_directory_with_progress(path, config, Box::new(|_, _, _| {}))
}

fn should_scan_entry(entry: &walkdir::DirEntry, config: &ScanConfig) -> bool {
    let name = entry.file_name().to_string_lossy();

    if entry.file_type().is_dir() {
        if !config.include_node_modules && name == "node_modules" {
            return false;
        }
        if SKIP_DIRS.contains(&name.as_ref()) {
            return false;
        }
    }

    true
}

fn check_filename(path: &Path) -> Vec<Finding> {
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    if MALICIOUS_FILES.contains(&filename) {
        vec![Finding {
            path: path.display().to_string(),
            finding_type: FindingType::MaliciousFile,
            severity: Severity::Critical,
            description: format!("Known malicious file: {}", filename),
            line: None,
            context: None,
        }]
    } else {
        vec![]
    }
}

fn check_file_hash(path: &Path) -> Vec<Finding> {
    if MALICIOUS_HASHES.is_empty() {
        return vec![];
    }

    let Ok(content) = fs::read(path) else {
        return vec![];
    };

    let hash = hex::encode(Sha256::digest(&content));

    if MALICIOUS_HASHES.contains(&hash.as_str()) {
        vec![Finding {
            path: path.display().to_string(),
            finding_type: FindingType::MaliciousHash,
            severity: Severity::Critical,
            description: format!("File matches known malicious hash: {}...", &hash[..16]),
            line: None,
            context: None,
        }]
    } else {
        vec![]
    }
}

fn check_file_content(path: &Path) -> Vec<Finding> {
    let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");

    if !SCANNABLE_EXTENSIONS.contains(&ext) {
        return vec![];
    }

    let Ok(file) = fs::File::open(path) else {
        return vec![];
    };

    // Skip large files (> 1MB)
    if let Ok(metadata) = file.metadata() {
        if metadata.len() > 1_000_000 {
            return vec![];
        }
    }

    let reader = BufReader::new(file);
    let mut findings = Vec::new();

    for (line_num, line) in reader.lines().enumerate() {
        let Ok(line) = line else { continue };

        for rule in SUSPICIOUS_PATTERNS.iter() {
            if rule.regex.is_match(&line) {
                findings.push(Finding {
                    path: path.display().to_string(),
                    finding_type: FindingType::SuspiciousPattern,
                    severity: rule.severity,
                    description: rule.description.to_string(),
                    line: Some(line_num + 1),
                    context: Some(truncate_string(&line.trim(), 100)),
                });
            }
        }
    }

    findings
}

fn check_package_json(path: &Path) -> Vec<Finding> {
    let Ok(content) = fs::read_to_string(path) else {
        return vec![];
    };

    let Ok(json): Result<serde_json::Value, _> = serde_json::from_str(&content) else {
        return vec![];
    };

    let mut findings = Vec::new();

    // Check for dangerous hooks
    if let Some(scripts) = json.get("scripts").and_then(|s| s.as_object()) {
        for hook in DANGEROUS_HOOKS {
            if let Some(script) = scripts.get(*hook).and_then(|s| s.as_str()) {
                for rule in HOOK_PATTERNS.iter() {
                    if rule.regex.is_match(script) {
                        findings.push(Finding {
                            path: path.display().to_string(),
                            finding_type: FindingType::DangerousHook,
                            severity: Severity::Critical,
                            description: format!("{} in '{}' hook", rule.description, hook),
                            line: None,
                            context: Some(truncate_string(script, 100)),
                        });
                    }
                }
            }
        }
    }

    // Check for compromised packages in dependencies
    let dep_sections = ["dependencies", "devDependencies", "peerDependencies", "optionalDependencies"];
    
    for section in dep_sections {
        if let Some(deps) = json.get(section).and_then(|d| d.as_object()) {
            for (pkg_name, pkg_version) in deps {
                let version = pkg_version.as_str().unwrap_or("unknown");
                
                // Check if this specific version is compromised
                if let Some(infected_versions) = is_version_compromised(pkg_name, version) {
                    findings.push(Finding {
                        path: path.display().to_string(),
                        finding_type: FindingType::CompromisedPackage,
                        severity: Severity::Critical,
                        description: format!("INFECTED package: {} @ {} (Shai-Hulud 2.0)", pkg_name, version),
                        line: None,
                        context: Some(format!("Infected versions: {}", infected_versions.join(", "))),
                    });
                } else if let Some(infected_versions) = is_package_compromised(pkg_name) {
                    // Package is in list but version doesn't match - warn but lower severity
                    findings.push(Finding {
                        path: path.display().to_string(),
                        finding_type: FindingType::CompromisedPackage,
                        severity: Severity::Medium,
                        description: format!("Package {} was targeted (your version {} may be safe)", pkg_name, version),
                        line: None,
                        context: Some(format!("Infected versions: {}", infected_versions.join(", "))),
                    });
                }
            }
        }
    }

    findings
}

fn truncate_string(s: &str, max_len: usize) -> String {
    if s.len() <= max_len {
        s.to_string()
    } else {
        format!("{}...", &s[..max_len])
    }
}

fn check_lockfile(path: &Path) -> Vec<Finding> {
    let Ok(content) = fs::read_to_string(path) else {
        return vec![];
    };

    let mut findings = Vec::new();
    let filename = path.file_name().and_then(|n| n.to_str()).unwrap_or("");

    // For package-lock.json, parse as JSON
    if filename == "package-lock.json" {
        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&content) {
            // Check "packages" section (npm v7+)
            if let Some(packages) = json.get("packages").and_then(|p| p.as_object()) {
                for (pkg_path, pkg_info) in packages {
                    // Extract package name from path like "node_modules/@ctrl/tinycolor"
                    let pkg_name = pkg_path
                        .strip_prefix("node_modules/")
                        .unwrap_or(pkg_path);
                    
                    let version = pkg_info
                        .get("version")
                        .and_then(|v| v.as_str())
                        .unwrap_or("unknown");
                    
                    if let Some(infected_versions) = is_version_compromised(pkg_name, version) {
                        findings.push(Finding {
                            path: path.display().to_string(),
                            finding_type: FindingType::CompromisedPackage,
                            severity: Severity::Critical,
                            description: format!("INFECTED in lockfile: {} @ {}", pkg_name, version),
                            line: None,
                            context: Some(format!("Infected versions: {}", infected_versions.join(", "))),
                        });
                    }
                }
            }
            
            // Check "dependencies" section (npm v6)
            if let Some(deps) = json.get("dependencies").and_then(|d| d.as_object()) {
                check_npm_v6_deps(&path.display().to_string(), deps, &mut findings);
            }
        }
    } else {
        // For yarn.lock and pnpm-lock.yaml, check for package@version patterns
        for (pkg, versions) in COMPROMISED_PACKAGES {
            for version in *versions {
                // Check for patterns like "package@version" or "package@^version"
                let patterns = [
                    format!("{}@{}", pkg, version),
                    format!("\"{}\":\n  version: \"{}\"", pkg, version), // pnpm format
                ];
                for pattern in &patterns {
                    if content.contains(pattern) {
                        findings.push(Finding {
                            path: path.display().to_string(),
                            finding_type: FindingType::CompromisedPackage,
                            severity: Severity::Critical,
                            description: format!("INFECTED in lockfile: {} @ {}", pkg, version),
                            line: None,
                            context: Some(format!("Infected versions: {}", versions.join(", "))),
                        });
                        break; // Found this version, no need to check other patterns
                    }
                }
            }
        }
    }

    findings
}

fn check_npm_v6_deps(
    path: &str,
    deps: &serde_json::Map<String, serde_json::Value>,
    findings: &mut Vec<Finding>,
) {
    for (pkg_name, pkg_info) in deps {
        let version = pkg_info
            .get("version")
            .and_then(|v| v.as_str())
            .unwrap_or("unknown");
        
        if let Some(infected_versions) = is_version_compromised(pkg_name, version) {
            findings.push(Finding {
                path: path.to_string(),
                finding_type: FindingType::CompromisedPackage,
                severity: Severity::Critical,
                description: format!("INFECTED in lockfile: {} @ {}", pkg_name, version),
                line: None,
                context: Some(format!("Infected versions: {}", infected_versions.join(", "))),
            });
        }
        
        // Recursively check nested dependencies
        if let Some(nested_deps) = pkg_info.get("dependencies").and_then(|d| d.as_object()) {
            check_npm_v6_deps(path, nested_deps, findings);
        }
    }
}
