//! Command handlers for each CLI subcommand.
//!
//! Each subcommand is implemented in its own module and exposes
//! a single `execute` function that receives the parsed arguments.

pub mod decode;
pub mod verify;
