#[cfg(test)]
mod tests {
    use crate::patterns::*;
    use crate::scanner::*;
    use std::path::Path;

    #[test]
    fn test_malicious_files_detected() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Should find setup_bun.js
        assert!(
            results.findings.iter().any(|f| f.path.contains("setup_bun.js")),
            "Should detect setup_bun.js"
        );

        // Should find bun_environment.js
        assert!(
            results.findings.iter().any(|f| f.path.contains("bun_environment.js")),
            "Should detect bun_environment.js"
        );

        // Should have critical findings
        assert!(
            results.summary.critical > 0,
            "Should have critical findings"
        );

        println!("✓ Malicious files test passed");
        println!("  Found {} critical, {} high, {} medium findings",
            results.summary.critical,
            results.summary.high,
            results.summary.medium
        );
    }

    #[test]
    fn test_shai_hulud_markers_detected() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Should find SHA1HULUD marker
        assert!(
            results.findings.iter().any(|f| 
                f.description.contains("Shai-Hulud") || 
                f.description.contains("SHA1HULUD")
            ),
            "Should detect Shai-Hulud markers"
        );

        println!("✓ Shai-Hulud markers test passed");
    }

    #[test]
    fn test_credential_theft_patterns_detected() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Should detect credential-related patterns
        let has_cred_patterns = results.findings.iter().any(|f| {
            f.description.contains("AWS") ||
            f.description.contains("GCP") ||
            f.description.contains("Azure") ||
            f.description.contains("GitHub") ||
            f.description.contains("token") ||
            f.description.contains("credential")
        });

        assert!(has_cred_patterns, "Should detect credential theft patterns");

        println!("✓ Credential theft patterns test passed");
    }

    #[test]
    fn test_dangerous_hooks_detected() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Should detect dangerous package.json hooks
        let has_hook_findings = results.findings.iter().any(|f| {
            f.description.contains("hook") ||
            f.description.contains("preinstall") ||
            f.description.contains("setup") ||
            f.description.contains("curl")
        });

        assert!(has_hook_findings, "Should detect dangerous hooks");

        println!("✓ Dangerous hooks test passed");
    }

    #[test]
    fn test_malicious_workflow_detected() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Should detect self-hosted runner in workflow
        let has_workflow_findings = results.findings.iter().any(|f| {
            f.path.contains("discussion.yaml") ||
            f.description.contains("self-hosted") ||
            f.description.contains("runner")
        });

        assert!(has_workflow_findings, "Should detect malicious workflow patterns");

        println!("✓ Malicious workflow test passed");
    }

    #[test]
    fn test_rce_patterns_detected() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Should detect curl | sh and wget | bash patterns
        let has_rce = results.findings.iter().any(|f| {
            f.description.contains("curl") ||
            f.description.contains("wget") ||
            f.description.contains("Remote code execution") ||
            f.description.contains("Piped")
        });

        assert!(has_rce, "Should detect RCE patterns");

        println!("✓ RCE patterns test passed");
    }

    #[test]
    fn test_clean_files_no_critical() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/clean");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Clean files should have zero critical findings
        assert_eq!(
            results.summary.critical, 0,
            "Clean files should have no critical findings, found: {}",
            results.summary.critical
        );

        // Clean files should have zero high findings
        assert_eq!(
            results.summary.high, 0,
            "Clean files should have no high findings, found: {}",
            results.summary.high
        );

        println!("✓ Clean files test passed");
        println!("  No critical or high severity findings in clean samples");
    }

    #[test]
    fn test_edge_cases_no_critical() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/edge_cases");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Edge cases might have medium/low but should NOT have critical
        assert_eq!(
            results.summary.critical, 0,
            "Edge cases should not trigger critical findings"
        );

        println!("✓ Edge cases test passed");
        println!("  Medium findings: {}", results.summary.medium);
    }

    #[test]
    fn test_severity_levels() {
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::Low.as_str(), "LOW");

        println!("✓ Severity levels test passed");
    }

    #[test]
    fn test_pattern_compilation() {
        // Ensure all patterns compile without panic
        let _ = &*SUSPICIOUS_PATTERNS;
        let _ = &*HOOK_PATTERNS;

        println!("✓ Pattern compilation test passed");
    }

    #[test]
    fn test_scan_results_summary() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Summary should be consistent with findings
        let critical_count = results.findings.iter()
            .filter(|f| f.severity == Severity::Critical)
            .count();
        let high_count = results.findings.iter()
            .filter(|f| f.severity == Severity::High)
            .count();

        assert_eq!(results.summary.critical, critical_count);
        assert_eq!(results.summary.high, high_count);
        assert_eq!(results.summary.total, results.findings.len());

        println!("✓ Summary consistency test passed");
    }

    // ========================================
    // UI Display Tests
    // ========================================

    #[test]
    fn test_severity_colors() {
        use ratatui::style::Color;

        // Test that each severity has the correct color
        assert_eq!(Severity::Critical.color(), Color::Red, "Critical should be Red");
        assert_eq!(Severity::High.color(), Color::LightRed, "High should be LightRed");
        assert_eq!(Severity::Medium.color(), Color::Yellow, "Medium should be Yellow");
        assert_eq!(Severity::Low.color(), Color::Blue, "Low should be Blue");

        println!("✓ Severity colors test passed");
        println!("  Critical: Red");
        println!("  High: LightRed");
        println!("  Medium: Yellow");
        println!("  Low: Blue");
    }

    #[test]
    fn test_severity_display_strings() {
        // Test display strings for UI
        assert_eq!(Severity::Critical.as_str(), "CRITICAL");
        assert_eq!(Severity::High.as_str(), "HIGH");
        assert_eq!(Severity::Medium.as_str(), "MEDIUM");
        assert_eq!(Severity::Low.as_str(), "LOW");

        // Test that they are all uppercase (for consistent UI display)
        for severity in [Severity::Critical, Severity::High, Severity::Medium, Severity::Low] {
            let s = severity.as_str();
            assert_eq!(s, s.to_uppercase(), "{} should be uppercase", s);
        }

        println!("✓ Severity display strings test passed");
    }

    #[test]
    fn test_finding_type_variants() {
        // Test that all finding types exist and can be matched
        let malicious_file = FindingType::MaliciousFile;
        let malicious_hash = FindingType::MaliciousHash;
        let suspicious_pattern = FindingType::SuspiciousPattern;
        let dangerous_hook = FindingType::DangerousHook;

        // Each type should have a different debug representation
        assert_ne!(format!("{:?}", malicious_file), format!("{:?}", malicious_hash));
        assert_ne!(format!("{:?}", suspicious_pattern), format!("{:?}", dangerous_hook));

        println!("✓ Finding type variants test passed");
        println!("  MaliciousFile: {:?}", malicious_file);
        println!("  MaliciousHash: {:?}", malicious_hash);
        println!("  SuspiciousPattern: {:?}", suspicious_pattern);
        println!("  DangerousHook: {:?}", dangerous_hook);
    }

    #[test]
    fn test_findings_have_display_data() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        for finding in &results.findings {
            // Every finding must have a path
            assert!(!finding.path.is_empty(), "Finding path should not be empty");
            
            // Every finding must have a description
            assert!(!finding.description.is_empty(), "Finding description should not be empty");
            
            // Severity should have valid display properties
            let _ = finding.severity.as_str();
            let _ = finding.severity.color();
        }

        println!("✓ Findings display data test passed");
        println!("  All {} findings have valid display data", results.findings.len());
    }

    #[test]
    fn test_all_severity_levels_in_results() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Collect unique severities found
        let mut found_critical = false;
        let mut found_high = false;
        let mut found_medium = false;

        for finding in &results.findings {
            match finding.severity {
                Severity::Critical => found_critical = true,
                Severity::High => found_high = true,
                Severity::Medium => found_medium = true,
                Severity::Low => {}
            }
        }

        // Malicious samples should trigger multiple severity levels
        assert!(found_critical, "Should have Critical severity findings");
        assert!(found_high, "Should have High severity findings");

        println!("✓ All severity levels in results test passed");
        println!("  Critical: {}", if found_critical { "✓" } else { "✗" });
        println!("  High: {}", if found_high { "✓" } else { "✗" });
        println!("  Medium: {}", if found_medium { "✓" } else { "✗" });
    }

    #[test]
    fn test_summary_display_values() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Summary should have displayable values
        println!("✓ Summary display values test passed");
        println!("  Scanned files: {}", results.scanned_files);
        println!("  Scan path: {}", results.scan_path);
        println!("  Total findings: {}", results.summary.total);
        println!("  Critical: {}", results.summary.critical);
        println!("  High: {}", results.summary.high);
        println!("  Medium: {}", results.summary.medium);
        println!("  Low: {}", results.summary.low);

        // Validate summary math
        let calculated_total = results.summary.critical 
            + results.summary.high 
            + results.summary.medium 
            + results.summary.low;
        assert_eq!(
            results.summary.total, calculated_total,
            "Total should equal sum of all severities"
        );
    }

    #[test]
    fn test_finding_context_for_display() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        let mut findings_with_line = 0;
        let mut findings_with_context = 0;

        for finding in &results.findings {
            if finding.line.is_some() {
                findings_with_line += 1;
            }
            if finding.context.is_some() {
                findings_with_context += 1;
                // Context should not be excessively long for display
                if let Some(ctx) = &finding.context {
                    assert!(ctx.len() < 1000, "Context should be reasonably sized for display");
                }
            }
        }

        println!("✓ Finding context for display test passed");
        println!("  Findings with line numbers: {}", findings_with_line);
        println!("  Findings with context: {}", findings_with_context);
    }

    #[test]
    fn test_ui_icon_mapping() {
        // Simulate UI icon selection logic
        fn get_icon(finding_type: &FindingType) -> &'static str {
            match finding_type {
                FindingType::MaliciousFile => "📛",
                FindingType::MaliciousHash => "🔐",
                FindingType::SuspiciousPattern => "🔍",
                FindingType::DangerousHook => "⚡",
            }
        }

        assert_eq!(get_icon(&FindingType::MaliciousFile), "📛");
        assert_eq!(get_icon(&FindingType::MaliciousHash), "🔐");
        assert_eq!(get_icon(&FindingType::SuspiciousPattern), "🔍");
        assert_eq!(get_icon(&FindingType::DangerousHook), "⚡");

        println!("✓ UI icon mapping test passed");
        println!("  MaliciousFile: 📛");
        println!("  MaliciousHash: 🔐");
        println!("  SuspiciousPattern: 🔍");
        println!("  DangerousHook: ⚡");
    }

    #[test]
    fn test_result_status_icon() {
        // Simulate UI status icon logic
        fn get_status_icon(critical: usize, high: usize, total: usize) -> &'static str {
            if critical > 0 || high > 0 {
                "🚨"
            } else if total > 0 {
                "⚠️"
            } else {
                "✅"
            }
        }

        assert_eq!(get_status_icon(1, 0, 1), "🚨", "Critical should show alert");
        assert_eq!(get_status_icon(0, 1, 1), "🚨", "High should show alert");
        assert_eq!(get_status_icon(0, 0, 1), "⚠️", "Medium/Low should show warning");
        assert_eq!(get_status_icon(0, 0, 0), "✅", "No findings should show success");

        println!("✓ Result status icon test passed");
        println!("  Critical/High: 🚨");
        println!("  Medium/Low only: ⚠️");
        println!("  Clean: ✅");
    }

    #[test]
    fn test_json_serialization_for_display() {
        let config = ScanConfig {
            include_node_modules: false,
        };
        let path = Path::new("test_samples/malicious");
        let results = scan_directory_sync(path, &config).expect("Scan should succeed");

        // Results should be serializable to JSON for --json output
        let json = serde_json::to_string_pretty(&results);
        assert!(json.is_ok(), "Results should serialize to JSON");

        let json_str = json.unwrap();
        assert!(json_str.contains("findings"), "JSON should contain findings");
        assert!(json_str.contains("summary"), "JSON should contain summary");
        assert!(json_str.contains("critical"), "JSON should contain critical count");

        println!("✓ JSON serialization test passed");
        println!("  JSON output length: {} bytes", json_str.len());
    }
}
