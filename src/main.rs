//! jwt-term: A blazing-fast, secure, and offline-first CLI for JWT inspection.
//!
//! Entry point for the application. Parses CLI arguments and delegates
//! to the appropriate command handler.

#![forbid(unsafe_code)]

mod cli;
mod commands;
mod core;
mod display;
mod error;

use std::process::ExitCode;

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};

fn main() -> ExitCode {
    match run() {
        Ok(code) => code,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}

/// Parse CLI arguments and dispatch to the appropriate command handler.
///
/// Returns `ExitCode` so the caller can exit without `process::exit`,
/// allowing all destructors (including `Zeroizing`) to run.
fn run() -> Result<ExitCode> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Decode(args) => {
            commands::decode::execute(args)?;
            Ok(ExitCode::SUCCESS)
        }
        Commands::Verify(args) => {
            let signature_valid = commands::verify::execute(args)?;
            Ok(if signature_valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::FAILURE
            })
        }
    }
}
