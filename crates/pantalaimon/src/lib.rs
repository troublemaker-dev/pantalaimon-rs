// Library entry-point: re-exports all modules so integration tests (and
// future library consumers) can import them via `pantalaimon::`.
// The binary (`main.rs`) declares its own module tree independently.
pub mod client;
pub mod config;
pub mod error;
pub mod messages;
pub mod proxy;
pub mod store;
