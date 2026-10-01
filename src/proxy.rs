//! The MCP server aegis presents to the agent.
//!
//! It aggregates the tools of every upstream server under namespaced names
//! (`<server>__<tool>`), so that one taint context spans all of them: data
//! read through the `web` server must be able to block a call on the `shell`
//! server, which is impossible if each server sits behind its own proxy.
//!
//! Resources and prompts pass through the same checks: reading a resource
//! on server `web` is checked and labelled as the call `web__resources/read`
//! with arguments `{"uri": ...}`, and getting a prompt as `web__prompts/get`
//! with `{"name": ..., "arguments": ...}`, so `[[source]]` and `[[rule]]`
//! patterns like `web__*` cover them too.
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
    /// Which upstream listed each resource URI, from the last listing.
    resource_owners: Mutex<HashMap<String, usize>>,
    /// URI template prefixes (the part before the first `{`) per upstream.
    resource_templates: Mutex<Vec<(String, usize)>>,
}

/// The pseudo tool name a resource read is checked and logged under.
pub const READ_RESOURCE: &str = "resources/read";
/// The pseudo tool name getting a prompt is checked and logged under.
pub const GET_PROMPT: &str = "prompts/get";

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
            resource_owners: Mutex::default(),
            resource_templates: Mutex::default(),
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
                let mut capabilities = json!({ "tools": {} });
                for capability in ["resources", "prompts"] {
                    if self.upstreams.iter().any(|u| u.supports(capability)) {
                        capabilities[capability] = json!({});
                    }
                }
                Ok(Ok(json!({
                    "protocolVersion": params
                        .get("protocolVersion")
                        .cloned()
                        .unwrap_or_else(|| PROTOCOL_VERSION.into()),
                    "capabilities": capabilities,
                    "serverInfo": { "name": "aegis", "version": env!("CARGO_PKG_VERSION") },
                })))
            }
            "ping" => Ok(Ok(json!({}))),
            "tools/list" => self.list_tools().await.map(Ok),
            "tools/call" => self.call_tool(params).await,
            "resources/list" => self.list_resources().await.map(Ok),
            "resources/templates/list" => self.list_resource_templates().await.map(Ok),
            "resources/read" => self.read_resource(params).await,
            "prompts/list" => self.list_prompts().await.map(Ok),
            "prompts/get" => self.get_prompt(params).await,
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
        params["name"] = Value::String(tool);
        self.guarded(upstream, &name, &arguments, "tools/call", params)
            .await
    }

    async fn list_resources(&self) -> Result<Value> {
        let mut owners = HashMap::new();
        let mut resources = Vec::new();
        for (i, upstream) in self.with("resources") {
            match list_server(upstream, "resources/list", "resources").await {
                Ok(list) => {
                    for mut resource in list {
                        let Some(uri) = resource.get("uri").and_then(Value::as_str) else {
                            continue;
                        };
                        // The first server to list a URI owns it.
                        if owners.contains_key(uri) {
                            continue;
                        }
                        owners.insert(uri.to_string(), i);
                        namespace(&mut resource, &upstream.name);
                        resources.push(resource);
                    }
                }
                Err(e) => eprintln!(
                    "aegis: leaving out the resources of {:?}: {e:#}",
                    upstream.name
                ),
            }
        }
        *self.resource_owners.lock().await = owners;
        Ok(json!({ "resources": resources }))
    }

    async fn list_resource_templates(&self) -> Result<Value> {
        let mut prefixes = Vec::new();
        let mut templates = Vec::new();
        for (i, upstream) in self.with("resources") {
            match list_server(upstream, "resources/templates/list", "resourceTemplates").await {
                Ok(list) => {
                    for mut template in list {
                        let Some(uri) = template.get("uriTemplate").and_then(Value::as_str) else {
                            continue;
                        };
                        let prefix = uri.split('{').next().unwrap_or_default().to_string();
                        prefixes.push((prefix, i));
                        namespace(&mut template, &upstream.name);
                        templates.push(template);
                    }
                }
                Err(e) => eprintln!(
                    "aegis: leaving out the resource templates of {:?}: {e:#}",
                    upstream.name
                ),
            }
        }
        *self.resource_templates.lock().await = prefixes;
        Ok(json!({ "resourceTemplates": templates }))
    }

    /// The upstream that serves `uri`: the one that listed it, else the one
    /// with the longest matching template, else the only resource server.
    async fn resource_owner(&self, uri: &str) -> Option<usize> {
        if let Some(&i) = self.resource_owners.lock().await.get(uri) {
            return Some(i);
        }
        let by_template = self
            .resource_templates
            .lock()
            .await
            .iter()
            .filter(|(prefix, _)| uri.starts_with(prefix.as_str()))
            .max_by_key(|(prefix, _)| prefix.len())
            .map(|&(_, i)| i);
        if by_template.is_some() {
            return by_template;
        }
        let mut servers = self.with("resources").map(|(i, _)| i);
        match (servers.next(), servers.next()) {
            (Some(i), None) => Some(i),
            _ => None,
        }
    }

    async fn read_resource(&self, params: Value) -> Result<Result<Value, Value>> {
        let Some(uri) = params
            .get("uri")
            .and_then(Value::as_str)
            .map(str::to_string)
        else {
            return Ok(Err(
                json!({ "code": -32602, "message": "resources/read requires a uri" }),
            ));
        };
        if self.resource_owners.lock().await.is_empty() {
            // The agent may read a URI it learned elsewhere; learn the owners.
            self.list_resources().await?;
        }
        let Some(i) = self.resource_owner(&uri).await else {
            return Ok(Err(
                json!({ "code": -32002, "message": format!("resource not found: {uri}") }),
            ));
        };
        let upstream = &self.upstreams[i];
        let name = format!("{}{NAMESPACE_SEP}{READ_RESOURCE}", upstream.name);
        let arguments = json!({ "uri": uri });
        self.guarded(upstream, &name, &arguments, "resources/read", params)
            .await
    }

    async fn list_prompts(&self) -> Result<Value> {
        let mut prompts = Vec::new();
        for (_, upstream) in self.with("prompts") {
            match list_server(upstream, "prompts/list", "prompts").await {
                Ok(list) => prompts.extend(list.into_iter().map(|mut prompt| {
                    if let Some(name) = prompt.get("name").and_then(Value::as_str) {
                        prompt["name"] = format!("{}{NAMESPACE_SEP}{name}", upstream.name).into();
                    }
                    prompt
                })),
                Err(e) => eprintln!(
                    "aegis: leaving out the prompts of {:?}: {e:#}",
                    upstream.name
                ),
            }
        }
        Ok(json!({ "prompts": prompts }))
    }

    async fn get_prompt(&self, mut params: Value) -> Result<Result<Value, Value>> {
        let found = params
            .get("name")
            .and_then(Value::as_str)
            .and_then(|n| n.split_once(NAMESPACE_SEP))
            .and_then(|(server, prompt)| {
                self.with("prompts")
                    .find(|(_, u)| u.name == server)
                    .map(|(_, u)| (u, prompt.to_string()))
            });
        let Some((upstream, prompt)) = found else {
            return Ok(Err(json!({ "code": -32602, "message": "unknown prompt" })));
        };
        let name = format!("{}{NAMESPACE_SEP}{GET_PROMPT}", upstream.name);
        let arguments = json!({
            "name": prompt,
            "arguments": params.get("arguments").cloned().unwrap_or_else(|| json!({})),
        });
        params["name"] = Value::String(prompt);
        self.guarded(upstream, &name, &arguments, "prompts/get", params)
            .await
    }

    /// The upstreams (with their index) that announced `capability`.
    fn with(&self, capability: &str) -> impl Iterator<Item = (usize, &Arc<Upstream>)> {
        let capability = capability.to_string();
        self.upstreams
            .iter()
            .enumerate()
            .filter(move |(_, u)| u.supports(&capability))
    }

    /// Checks, logs and forwards one request, then labels the session with
    /// what it returned. `name` and `arguments` are what the policy sees.
    async fn guarded(
        &self,
        upstream: &Upstream,
        name: &str,
        arguments: &Value,
        method: &str,
        params: Value,
    ) -> Result<Result<Value, Value>> {
        let name = name.to_string();
        let (mut decision, context) = {
            let session = self.session.lock().await;
            (
                session.check_call(&self.policy, &name),
                session.context().clone(),
            )
        };
        let mut note = None;
        if decision.action == Action::Ask {
            let approval = self.ask_person(&name, arguments, &decision).await;
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
            arguments: log_arguments(self.arguments, arguments, &self.redact_keys),
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
            if method != "tools/call" {
                // Only tool results can carry an error for the model to read.
                return Ok(Err(json!({ "code": -32001, "message": text })));
            }
            return Ok(Ok(
                json!({ "content": [{ "type": "text", "text": text }], "isError": true }),
            ));
        }

        // Remember what this write carries into later sessions.
        if let Some(store) = self.resources.lock().await.as_mut() {
            store
                .on_write(&name, arguments, &context)
                .context("saving resource labels")?;
        }

        let response = upstream.request_raw(method, params).await?;

        // Taint the context before the agent can see the output.
        let is_error = match &response {
            Ok(result) => result
                .get("isError")
                .and_then(Value::as_bool)
                .unwrap_or(false),
            Err(_) => true,
        };
        let recalled: LabelSet = match self.resources.lock().await.as_ref() {
            Some(store) => store.on_read(&name, arguments),
            None => LabelSet::new(),
        };
        let added = {
            let mut session = self.session.lock().await;
            let mut added = session.observe_result(&self.policy, &name, arguments);
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
    let mut tools = list_server(upstream, "tools/list", "tools").await?;
    tools.retain_mut(|tool| {
        let Some(name) = tool.get("name").and_then(Value::as_str) else {
            return false;
        };
        tool["name"] = Value::String(format!("{}{NAMESPACE_SEP}{name}", upstream.name));
        true
    });
    Ok(tools)
}

/// Collects every page of a `*/list` request: the items under `key`.
async fn list_server(upstream: &Upstream, method: &str, key: &str) -> Result<Vec<Value>> {
    let mut items = Vec::new();
    let mut cursors = std::collections::HashSet::new();
    let mut cursor: Option<Value> = None;
    for _ in 0..MAX_PAGES {
        let params = match &cursor {
            Some(c) => json!({ "cursor": c }),
            None => json!({}),
        };
        let mut page = upstream.request(method, params).await?;
        if let Some(Value::Array(list)) = page.get_mut(key).map(Value::take) {
            items.extend(list);
        }
        cursor = page.get("nextCursor").filter(|c| !c.is_null()).cloned();
        match &cursor {
            None => return Ok(items),
            Some(c) if !cursors.insert(c.to_string()) => {
                anyhow::bail!("server repeated page cursor {c}")
            }
            Some(_) => {}
        }
    }
    anyhow::bail!("server returned more than {MAX_PAGES} pages for {method}")
}

/// Shows which server a resource comes from in its display name.
fn namespace(item: &mut Value, server: &str) {
    if let Some(name) = item.get("name").and_then(Value::as_str) {
        item["name"] = Value::String(format!("{server}{NAMESPACE_SEP}{name}"));
    }
}

fn error_response(id: Value, code: i64, message: &str) -> Value {
    json!({ "jsonrpc": "2.0", "id": id, "error": { "code": code, "message": message } })
}
