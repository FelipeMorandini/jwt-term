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

use anyhow::Result;
use clap::Parser;

use cli::{Cli, Commands};

fn main() -> Result<()> {
    let cli = Cli::parse();

    match &cli.command {
        Commands::Decode(args) => commands::decode::execute(args),
        Commands::Verify(args) => commands::verify::execute(args),
    }
}
