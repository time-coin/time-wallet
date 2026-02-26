use chrono::Utc;
use std::process::Command;

fn main() {
    // Get current timestamp
    let now = Utc::now();
    let timestamp = now.format("%Y-%m-%d %H:%M:%S").to_string();
    println!("cargo:rustc-env=BUILD_TIMESTAMP={}", timestamp);

    // Get git hash (short form)
    let git_hash = get_git_output(vec!["rev-parse", "--short", "HEAD"], "unknown");
    println!("cargo:rustc-env=GIT_HASH={}", git_hash);

    // Get git branch
    let git_branch = get_git_output(vec!["rev-parse", "--abbrev-ref", "HEAD"], "unknown");
    println!("cargo:rustc-env=GIT_BRANCH={}", git_branch);

    // Get git commit message (first line only)
    let git_message = get_git_output(vec!["log", "-1", "--pretty=%B"], "no message");
    let first_line = git_message
        .lines()
        .next()
        .unwrap_or("no message")
        .to_string();
    // Sanitize message for environment variable (remove special chars)
    let safe_message = first_line
        .chars()
        .take(100) // Limit to 100 chars
        .filter(|c| c.is_alphanumeric() || *c == ' ' || *c == '-' || *c == '_')
        .collect::<String>();
    println!("cargo:rustc-env=GIT_MESSAGE={}", safe_message);

    // Get git commit date in ISO format
    let git_commit_date = get_git_output(
        vec!["log", "-1", "--format=%cI"],
        "2025-01-01T00:00:00+00:00",
    );
    println!("cargo:rustc-env=GIT_COMMIT_DATE={}", git_commit_date);

    // Get number of commits
    let commit_count = get_git_output(vec!["rev-list", "--count", "HEAD"], "0");
    println!("cargo:rustc-env=GIT_COMMIT_COUNT={}", commit_count);

    // Rebuild if git files change (../ because we're in network/ subdirectory)
    println!("cargo:rerun-if-changed=../../.git/HEAD");
    println!("cargo:rerun-if-changed=../../.git/index");

    // Also rerun on Cargo.toml changes
    println!("cargo:rerun-if-changed=Cargo.toml");

    // Print summary to build output
    println!(
        "cargo:info=TIME Coin Build Info: {} | Branch: {} | Commit: {}",
        timestamp, git_branch, git_hash
    );
}

/// Helper function to safely execute git commands
fn get_git_output(args: Vec<&str>, default: &str) -> String {
    Command::new("git")
        .args(&args)
        .output()
        .ok()
        .and_then(|output| {
            if output.status.success() {
                Some(String::from_utf8_lossy(&output.stdout).trim().to_string())
            } else {
                None
            }
        })
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| default.to_string())
}
