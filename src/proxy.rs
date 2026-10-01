//! The MCP server aegis presents to the agent.
//!
//! It aggregates the tools of every upstream server under namespaced names
//! (`<server>__<tool>`), so that one taint context spans all of them: data
//! read through the `web` server must be able to block a call on the `shell`
//! server, which is impossible if each server sits behind its own proxy.
//!
//! For `action = "ask"` it also acts as a client of the agent's host: it
//! sends an MCP `elicitation/create` request, which the host shows to the
//! person using it. The model never sees that request and cannot answer it.

use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use anyhow::{Context, Result};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite, BufReader};
use tokio::sync::{Mutex, oneshot};
use tokio::task::JoinSet;

use crate::audit::{ArgumentLogging, AuditLog, Event, log_arguments};
use crate::config::NAMESPACE_SEP;
use crate::labels::LabelSet;
use crate::policy::{Action, Decision, Policy, Session};
use crate::resources::ResourceStore;
use crate::upstream::{
    DEFAULT_MAX_MESSAGE_BYTES, Line, PROTOCOL_VERSION, Upstream, read_line_limited, write_line,
};

type Writer = Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send>>>;

/// Everything about a proxy beyond its servers and policy.
pub struct Options {
    pub audit: Option<AuditLog>,
    pub arguments: ArgumentLogging,
    pub redact_keys: Vec<String>,
    pub resources: Option<ResourceStore>,
    pub approval_timeout: Duration,
    pub max_message_bytes: usize,
}

impl Default for Options {
    fn default() -> Self {
        Self {
            audit: None,
            arguments: ArgumentLogging::default(),
            redact_keys: Vec::new(),
            resources: None,
            approval_timeout: Duration::from_secs(300),
            max_message_bytes: DEFAULT_MAX_MESSAGE_BYTES,
        }
    }
}

/// Why an `ask` call did or didn't run.
enum Approval {
    Approved,
    Declined,
    TimedOut,
    Unsupported,
}

pub struct Proxy {
    upstreams: Vec<Arc<Upstream>>,
    policy: Policy,
    session: Mutex<Session>,
    audit: Mutex<Option<AuditLog>>,
    resources: Mutex<Option<ResourceStore>>,
    arguments: ArgumentLogging,
    redact_keys: Vec<String>,
    approval_timeout: Duration,
    max_message_bytes: usize,
    /// Connection back to the agent's host, for approval requests.
    client_writer: OnceLock<Writer>,
    client_pending: Mutex<HashMap<String, oneshot::Sender<Value>>>,
    client_can_ask: AtomicBool,
    next_client_id: AtomicU64,
}

impl Proxy {
    pub fn new(
        upstreams: Vec<Arc<Upstream>>,
        policy: Policy,
        options: Options,
    ) -> Result<Arc<Self>> {
        let proxy = Arc::new(Self {
            upstreams,
            policy,
            session: Mutex::default(),
            audit: Mutex::new(options.audit),
            resources: Mutex::new(options.resources.filter(|r| !r.is_empty())),
            arguments: options.arguments,
            redact_keys: options.redact_keys,
            approval_timeout: options.approval_timeout,
            max_message_bytes: options.max_message_bytes,
            client_writer: OnceLock::new(),
            client_pending: Mutex::default(),
            client_can_ask: AtomicBool::new(false),
            next_client_id: AtomicU64::new(1),
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
        let _ = self.client_writer.set(writer.clone());
        let mut tasks = JoinSet::new();
        let mut reader = BufReader::new(reader);
        loop {
            let line = match read_line_limited(&mut reader, self.max_message_bytes).await? {
                Line::Text(line) => line,
                Line::Eof => break,
                Line::TooLong(n) => {
                    let message = format!(
                        "message of {n} bytes exceeds the {}-byte limit",
                        self.max_message_bytes
                    );
                    write_line(&writer, &error_response(Value::Null, -32600, &message)).await?;
                    continue;
                }
            };
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
            let Some(id) = msg.get("id").cloned() else {
                continue; // Notifications need no reply.
            };
            let Some(method) = msg
                .get("method")
                .and_then(Value::as_str)
                .map(str::to_string)
            else {
                // A response to one of our own requests (an approval prompt).
                let key = id
                    .as_str()
                    .map(str::to_string)
                    .unwrap_or_else(|| id.to_string());
                if let Some(tx) = self.client_pending.lock().await.remove(&key) {
                    let _ = tx.send(msg);
                }
                continue;
            };
            let params = msg.get("params").cloned().unwrap_or(Value::Null);

            // Handle each request on its own task so a slow tool (or a
            // person thinking about an approval) does not block the others.
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
        // Nobody is left to answer approval prompts.
        self.client_pending.lock().await.clear();
        // Let in-flight calls finish before the connection is dropped.
        while tasks.join_next().await.is_some() {}
        Ok(())
    }

    /// Returns `Ok(Ok(result))`, `Ok(Err(json_rpc_error))`, or `Err` for an
    /// internal failure.
    async fn handle(&self, method: &str, params: Value) -> Result<Result<Value, Value>> {
        match method {
            "initialize" => {
                let can_ask = params.pointer("/capabilities/elicitation").is_some();
                self.client_can_ask.store(can_ask, Ordering::Release);
                Ok(Ok(json!({
                    "protocolVersion": params
                        .get("protocolVersion")
                        .cloned()
                        .unwrap_or_else(|| PROTOCOL_VERSION.into()),
                    "capabilities": { "tools": {} },
                    "serverInfo": { "name": "aegis", "version": env!("CARGO_PKG_VERSION") },
                })))
            }
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

        let (mut decision, context) = {
            let session = self.session.lock().await;
            (
                session.check_call(&self.policy, &name),
                session.context().clone(),
            )
        };
        let mut note = None;
        if decision.action == Action::Ask {
            let approval = self.ask_person(&name, &arguments, &decision).await;
            decision.approved = Some(matches!(approval, Approval::Approved));
            note = match approval {
                Approval::Approved | Approval::Declined => None,
                Approval::TimedOut => Some("nobody answered in time"),
                Approval::Unsupported => Some("the agent's MCP client cannot ask for approval"),
            };
        }
        // Fail closed: a call that cannot be logged does not run.
        self.record(Event::ToolCall {
            tool: name.clone(),
            arguments: log_arguments(self.arguments, &arguments, &self.redact_keys),
            context: context.iter().cloned().collect(),
            decision: decision.clone(),
        })
        .await
        .context("writing audit log")?;

        if !decision.runs() {
            let mut text = decision.message(&name);
            if let Some(note) = note {
                text += &format!(" ({note})");
            }
            return Ok(Ok(
                json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
            ));
        }

        // Remember what this write carries into later sessions.
        if let Some(store) = self.resources.lock().await.as_mut() {
            store
                .on_write(&name, &arguments, &context)
                .context("saving resource labels")?;
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
        let recalled: LabelSet = match self.resources.lock().await.as_ref() {
            Some(store) => store.on_read(&name, &arguments),
            None => LabelSet::new(),
        };
        let added = {
            let mut session = self.session.lock().await;
            let mut added = session.observe_result(&self.policy, &name, &arguments);
            added.extend(session.add_labels(recalled.iter().cloned()));
            added
        };
        self.record(Event::ToolResult {
            tool: name,
            is_error,
            added: added.into_iter().collect(),
            recalled: recalled.into_iter().collect(),
        })
        .await
        .context("writing audit log")?;
        Ok(response)
    }

    /// Asks the person behind the agent whether `tool` may run.
    async fn ask_person(&self, tool: &str, arguments: &Value, decision: &Decision) -> Approval {
        let Some(writer) = self.client_writer.get() else {
            return Approval::Unsupported;
        };
        if !self.client_can_ask.load(Ordering::Acquire) {
            return Approval::Unsupported;
        }
        // Show the person the call as it will be logged, secrets redacted.
        let mut shown =
            log_arguments(ArgumentLogging::Redacted, arguments, &self.redact_keys).to_string();
        if shown.len() > 600 {
            let mut cut = 600;
            while !shown.is_char_boundary(cut) {
                cut -= 1;
            }
            shown.truncate(cut);
            shown += "…";
        }
        let why = match (&decision.rule, decision.matched_labels.is_empty()) {
            (Some(r), false) => format!(
                "Rule #{r} asks for approval because this session has read data labelled {}.",
                decision.matched_labels.join(", ")
            ),
            (Some(r), true) => format!("Rule #{r} asks for approval."),
            (None, _) => "The default policy asks for approval.".to_string(),
        };
        let message = format!(
            "aegis: the agent wants to call {tool} with {shown}\n\n{why}{}\n\nAllow this one call?",
            decision
                .reason
                .as_deref()
                .map(|r| format!(" ({r})"))
                .unwrap_or_default()
        );

        let id = format!(
            "aegis-{}",
            self.next_client_id.fetch_add(1, Ordering::Relaxed)
        );
        let (tx, rx) = oneshot::channel();
        self.client_pending.lock().await.insert(id.clone(), tx);
        let request = json!({
            "jsonrpc": "2.0",
            "id": id,
            "method": "elicitation/create",
            "params": {
                "message": message,
                "requestedSchema": {
                    "type": "object",
                    "properties": {
                        "approve": {
                            "type": "boolean",
                            "title": "Allow this call",
                            "description": format!("Run {tool} once, despite the rule."),
                        }
                    },
                    "required": ["approve"],
                },
            },
        });
        if let Err(e) = write_line(writer, &request).await {
            eprintln!("aegis: asking for approval: {e}");
            self.client_pending.lock().await.remove(&id);
            return Approval::Unsupported;
        }
        match tokio::time::timeout(self.approval_timeout, rx).await {
            Ok(Ok(response)) => {
                let result = &response["result"];
                let approved = result["action"] == "accept" && result["content"]["approve"] == true;
                if approved {
                    Approval::Approved
                } else {
                    Approval::Declined
                }
            }
            // The client answered with an error, or went away.
            Ok(Err(_)) => Approval::Declined,
            Err(_) => {
                self.client_pending.lock().await.remove(&id);
                Approval::TimedOut
            }
        }
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
