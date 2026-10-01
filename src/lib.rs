//! aegis: an information-flow firewall for AI agent tool calls.
//!
//! aegis sits between an agent and its MCP servers. It labels tool output by
//! where it came from, carries those labels through the session, and blocks
//! tool calls that policy forbids given what the agent has already read —
//! e.g. no shell commands after the agent has read a web page.

pub mod labels;
pub mod policy;

#[cfg(feature = "runtime")]
pub mod audit;
#[cfg(feature = "runtime")]
pub mod config;
#[cfg(feature = "runtime")]
pub mod http;
#[cfg(feature = "runtime")]
pub mod init;
#[cfg(feature = "runtime")]
pub mod proxy;
#[cfg(feature = "runtime")]
pub mod replay;
#[cfg(feature = "runtime")]
pub mod report;
#[cfg(feature = "runtime")]
pub mod resources;
#[cfg(feature = "runtime")]
pub mod sandbox;
#[cfg(feature = "runtime")]
pub mod upstream;
#[cfg(feature = "runtime")]
pub mod watch;

#[cfg(target_arch = "wasm32")]
mod wasm;
