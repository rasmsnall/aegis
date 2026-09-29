//! aegis: an information-flow firewall for AI agent tool calls.
//!
//! aegis sits between an agent and its MCP servers. It labels tool output by
//! where it came from, carries those labels through the session, and blocks
//! tool calls that policy forbids given what the agent has already read —
//! e.g. no shell commands after the agent has read a web page.

pub mod audit;
pub mod config;
pub mod labels;
pub mod policy;
pub mod proxy;
pub mod replay;
pub mod upstream;
