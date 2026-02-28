//! Core business logic for JWT operations.
//!
//! This module contains the domain logic separated from CLI concerns.
//! All types and functions here are testable without the CLI layer.
//!
//! Note: Stub modules are allowed dead code until their implementation
//! phases. The `#[allow(dead_code)]` will be removed as each module
//! is fully implemented.

#[allow(dead_code)]
pub mod decoder;
#[allow(dead_code)]
pub mod jwks;
#[allow(dead_code)]
pub mod time_travel;
#[allow(dead_code)]
pub mod validator;
