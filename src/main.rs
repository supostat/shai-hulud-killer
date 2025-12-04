mod app;
mod patterns;
mod scanner;
mod ui;

#[cfg(test)]
mod tests;

use anyhow::Result;
use app::App;
use clap::Parser;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "Shai-Hulud 2.0 Killer")]
#[command(version = "0.1.0")]
#[command(about = "Detect Shai-Hulud 2.0 npm supply chain attack", long_about = None)]
struct Args {
    /// Directory to scan (interactive mode if not provided)
    path: Option<PathBuf>,

    /// Include node_modules directories
    #[arg(short = 'n', long)]
    include_node_modules: bool,

    /// Output results as JSON (non-interactive)
    #[arg(short, long)]
    json: bool,
}

fn main() -> Result<()> {
    let args = Args::parse();

    if args.json {
        // Non-interactive JSON mode
        if let Some(path) = args.path {
            let config = scanner::ScanConfig {
                include_node_modules: args.include_node_modules,
            };
            let results = scanner::scan_directory_sync(&path, &config)?;
            println!("{}", serde_json::to_string_pretty(&results)?);
        } else {
            eprintln!("Error: Path required for JSON output mode");
            std::process::exit(1);
        }
    } else {
        // Interactive TUI mode
        let mut app = App::new(args.path, args.include_node_modules)?;
        ui::run(&mut app)?;
    }

    Ok(())
}
