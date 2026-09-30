//! The MCP server aegis presents to the agent.
//!
//! It aggregates the tools of every upstream server under namespaced names
//! (`<server>__<tool>`), so that one taint context spans all of them: data
//! read through the `web` server must be able to block a call on the `shell`
//! server, which is impossible if each server sits behind its own proxy.

use std::sync::Arc;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, BufReader};
use tokio::sync::Mutex;
use tokio::task::JoinSet;

use crate::audit::{AuditLog, Event};
use crate::config::NAMESPACE_SEP;
use crate::policy::{Action, Policy, Session};
use crate::upstream::{PROTOCOL_VERSION, Upstream, write_line};

type Writer = Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send>>>;

pub struct Proxy {
    upstreams: Vec<Arc<Upstream>>,
    policy: Policy,
    session: Mutex<Session>,
    audit: Mutex<Option<AuditLog>>,
}

impl Proxy {
    pub fn new(
        upstreams: Vec<Arc<Upstream>>,
        policy: Policy,
        audit: Option<AuditLog>,
    ) -> Result<Arc<Self>> {
        let proxy = Arc::new(Self {
            upstreams,
            policy,
            session: Mutex::default(),
            audit: Mutex::new(audit),
        });
        if let Some(log) = proxy.audit.try_lock().expect("fresh mutex").as_mut() {
            let servers = proxy.upstreams.iter().map(|u| u.name.clone()).collect();
            log.record(Event::SessionStart { servers })?;
        }
        Ok(proxy)
    }

    /// Records a clean shutdown. Without it, the session shows up as
    /// unfinished when the log is verified.
    pub async fn finish(&self) -> Result<()> {
        self.record(Event::SessionEnd).await
    }

    /// Serves one agent connection until it closes.
    pub async fn serve(
        self: Arc<Self>,
        reader: impl AsyncRead + Unpin,
        writer: impl AsyncWrite + Unpin + Send + 'static,
    ) -> Result<()> {
        let writer: Writer = Arc::new(Mutex::new(Box::new(writer)));
        let mut tasks = JoinSet::new();
        let mut lines = BufReader::new(reader).lines();
        while let Some(line) = lines.next_line().await? {
            while tasks.try_join_next().is_some() {}
            if line.trim().is_empty() {
                continue;
            }
            let msg: Value = match serde_json::from_str(&line) {
                Ok(msg) => msg,
                Err(e) => {
                    let reply = error_response(Value::Null, -32700, &format!("parse error: {e}"));
                    write_line(&writer, &reply).await?;
                    continue;
                }
            };
            // Notifications need no reply.
            let Some(id) = msg.get("id").cloned() else {
                continue;
            };
            let method = msg
                .get("method")
                .and_then(Value::as_str)
                .unwrap_or("")
                .to_string();
            let params = msg.get("params").cloned().unwrap_or(Value::Null);

            // Handle each request on its own task so a slow tool does not
            // block the others.
            let proxy = self.clone();
            let writer = writer.clone();
            tasks.spawn(async move {
                let reply = match proxy.handle(&method, params).await {
                    Ok(Ok(result)) => json!({ "jsonrpc": "2.0", "id": id, "result": result }),
                    Ok(Err(error)) => json!({ "jsonrpc": "2.0", "id": id, "error": error }),
                    Err(e) => error_response(id, -32603, &format!("{e:#}")),
                };
                if let Err(e) = write_line(&writer, &reply).await {
                    eprintln!("aegis: writing to agent: {e}");
                }
            });
        }
        // Let in-flight calls finish before the connection is dropped.
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    /// Returns `Ok(Ok(result))`, `Ok(Err(json_rpc_error))`, or `Err` for an
    /// internal failure.
    async fn handle(&self, method: &str, params: Value) -> Result<Result<Value, Value>> {
        match method {
            "initialize" => Ok(Ok(json!({
                "protocolVersion": params
                    .get("protocolVersion")
                    .cloned()
                    .unwrap_or_else(|| PROTOCOL_VERSION.into()),
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "aegis", "version": env!("CARGO_PKG_VERSION") },
            }))),
            "ping" => Ok(Ok(json!({}))),
            "tools/list" => self.list_tools().await.map(Ok),
            "tools/call" => self.call_tool(params).await,
            _ => Ok(Err(
                json!({ "code": -32601, "message": format!("method not found: {method}") }),
            )),
        }
    }

    async fn list_tools(&self) -> Result<Value> {
        let listing = list_tools(&self.upstreams).await;
        for (server, error) in &listing.failures {
            eprintln!("aegis: leaving out the tools of {server:?}: {error:#}");
        }
        Ok(json!({ "tools": listing.tools }))
    }

    async fn call_tool(&self, mut params: Value) -> Result<Result<Value, Value>> {
        let Some(name) = params
            .get("name")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return Ok(Err(
                json!({ "code": -32602, "message": "tools/call requires a name" }),
            ));
        };
        let upstream = name.split_once(NAMESPACE_SEP).and_then(|(server, tool)| {
            self.upstreams
                .iter()
                .find(|u| u.name == server)
                .map(|u| (u, tool.to_string()))
        });
        let Some((upstream, tool)) = upstream else {
            return Ok(Err(
                json!({ "code": -32602, "message": format!("unknown tool: {name}") }),
            ));
        };
        let arguments = params.get("arguments").cloned().unwrap_or(Value::Null);

        let (decision, context) = {
            let session = self.session.lock().await;
            (
                session.check_call(&self.policy, &name),
                session.context().clone(),
            )
        };
        // Fail closed: a call that cannot be logged does not run.
        self.record(Event::ToolCall {
            tool: name.clone(),
            arguments,
            context: context.into_iter().collect(),
            decision: decision.clone(),
        })
        .await
        .context("writing audit log")?;

        if decision.action == Action::Deny {
            let rule = decision
                .rule
                .map_or("default policy".to_string(), |r| format!("rule #{r}"));
            let mut text = format!("aegis blocked this call to {name} ({rule})");
            if !decision.matched_labels.is_empty() {
                text += &format!(
                    " because this session has read data labelled {}",
                    decision.matched_labels.join(", ")
                );
            }
            if let Some(reason) = &decision.reason {
                text += &format!(": {reason}");
            }
            return Ok(Ok(
                json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
            ));
        }

        params["name"] = Value::String(tool);
        let response = upstream.request_raw("tools/call", params).await?;

        // Taint the context before the agent can see the output.
        let is_error = match &response {
            Ok(result) => result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            Err(_) => true,
        };
        let added = self
            .session
            .lock()
            .await
            .observe_result(&self.policy, &name);
        self.record(Event::ToolResult {
            tool: name,
            is_error,
            added: added.into_iter().collect(),
        })
        .await
        .context("writing audit log")?;
        Ok(response)
    }

    async fn record(&self, event: Event) -> Result<()> {
        match self.audit.lock().await.as_mut() {
            Some(log) => log.record(event),
            None => Ok(()),
        }
    }
}

/// Tools gathered from every upstream, under their namespaced names.
pub struct Listing {
    pub tools: Vec<Value>,
    /// Servers whose tools could not be listed, and why.
    pub failures: Vec<(String, anyhow::Error)>,
}

/// Most pages a single server may return for one listing.
const MAX_PAGES: usize = 100;

/// Lists the tools of every upstream. A server that fails to answer is left
/// out (and reported) rather than hiding every other server's tools.
pub async fn list_tools(upstreams: &[Arc<Upstream>]) -> Listing {
    let mut listing = Listing {
        tools: Vec::new(),
        failures: Vec::new(),
    };
    let mut seen = std::collections::HashSet::new();
    for upstream in upstreams {
        match list_server_tools(upstream).await {
            Ok(tools) => {
                for tool in tools {
                    // A server listing the same tool twice gets one entry.
                    let name = tool["name"].as_str().unwrap_or_default().to_string();
                    if seen.insert(name) {
                        listing.tools.push(tool);
                    }
                }
            }
            Err(e) => listing.failures.push((upstream.name.clone(), e)),
        }
    }
    listing
}

async fn list_server_tools(upstream: &Upstream) -> Result<Vec<Value>> {
    let mut tools = Vec::new();
    let mut cursors = std::collections::HashSet::new();
    let mut cursor: Option<Value> = None;
    for _ in 0..MAX_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let mut page = upstream.request("tools/list", params).await?;
        if let Some(Value::Array(list)) = page.get_mut("tools").map(Value::take) {
            for mut tool in list {
                if let Some(name) = tool.get("name").and_then(Value::as_str) {
                    let namespaced = format!("{}{NAMESPACE_SEP}{name}", upstream.name);
                    tool["name"] = Value::String(namespaced);
                    tools.push(tool);
                }
            }
        }
        cursor = page.get("nextCursor").filter(|c| !c.is_null()).cloned();
        match &cursor {
            None => return Ok(tools),
            Some(c) if !cursors.insert(c.to_string()) => {
                anyhow::bail!("server repeated page cursor {c}")
            }
            Some(_) => {}
        }
    }
    anyhow::bail!("server returned more than {MAX_PAGES} pages of tools")
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
