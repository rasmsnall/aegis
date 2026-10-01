//! End-to-end: an agent talks to aegis, which fronts in-process fake MCP
//! servers. Reading from `web` must block a later call on `shell`.

use std::sync::Arc;
use std::time::{Duration, Instant};

use aegis::audit::{self, ArgumentLogging, AuditLog, Event};
use aegis::config::Config;
use aegis::policy::Action;
use aegis::proxy::{self, Options, Proxy};
use aegis::resources::ResourceStore;
use aegis::upstream::{DEFAULT_CALL_TIMEOUT, DEFAULT_MAX_MESSAGE_BYTES, Upstream};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex};
use tokio::task::JoinHandle;

/// A minimal MCP server whose tools echo their arguments. A mute server
/// completes the handshake and then never answers again.
async fn fake_server(stream: DuplexStream, tools: &'static [&'static str], mute: bool) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let msg: Value = serde_json::from_str(&line).unwrap();
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        if mute && msg["method"] != "initialize" {
            continue;
        }
        let result = match msg["method"].as_str().unwrap() {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {}, "resources": {}, "prompts": {} },
                "serverInfo": { "name": "fake", "version": "0" },
            }),
            // Each server has one resource, named after its first tool.
            "resources/list" => json!({
                "resources": [{ "uri": format!("mem://{}", tools[0]), "name": "doc" }]
            }),
            "resources/read" => {
                let uri = msg["params"]["uri"].as_str().unwrap();
                assert_eq!(
                    uri,
                    format!("mem://{}", tools[0]),
                    "routed to the wrong server"
                );
                json!({ "contents": [{ "uri": uri, "text": format!("contents of {uri}") }] })
            }
            "prompts/list" => json!({ "prompts": [{ "name": "greet" }] }),
            "prompts/get" => {
                assert_eq!(msg["params"]["name"], "greet");
                json!({ "messages": [{ "role": "user", "content": { "type": "text", "text": "hi" } }] })
            }
            "tools/list" => json!({
                "tools": tools.iter().map(|t| json!({ "name": t, "inputSchema": { "type": "object" } })).collect::<Vec<_>>()
            }),
            "tools/call" => {
                let name = msg["params"]["name"].as_str().unwrap();
                assert!(
                    tools.contains(&name),
                    "aegis must strip the namespace, got {name}"
                );
                json!({ "content": [{ "type": "text", "text": msg["params"]["arguments"].to_string() }] })
            }
            other => panic!("unexpected method {other}"),
        };
        let mut out =
            serde_json::to_vec(&json!({ "jsonrpc": "2.0", "id": id, "result": result })).unwrap();
        out.push(b'\n');
        writer.write_all(&out).await.unwrap();
    }
}

async fn upstream(name: &str, tools: &'static [&'static str]) -> Arc<Upstream> {
    connect(name, tools, false, DEFAULT_CALL_TIMEOUT).await
}

async fn connect(
    name: &str,
    tools: &'static [&'static str],
    mute: bool,
    timeout: Duration,
) -> Arc<Upstream> {
    let (ours, theirs) = duplex(64 * 1024);
    tokio::spawn(fake_server(theirs, tools, mute));
    let (reader, writer) = tokio::io::split(ours);
    let upstream = Upstream::connect(
        name.into(),
        reader,
        writer,
        None,
        timeout,
        DEFAULT_MAX_MESSAGE_BYTES,
    );
    upstream.initialize().await.unwrap();
    upstream
}

/// The agent's side of the connection. Answers approval prompts with
/// `approve` (or with an error when `None`).
struct Agent {
    lines: Lines<BufReader<tokio::io::ReadHalf<DuplexStream>>>,
    writer: tokio::io::WriteHalf<DuplexStream>,
    next_id: u64,
    approve: Option<bool>,
    prompts: Vec<String>,
}

impl Agent {
    async fn send(&mut self, msg: &Value) {
        let mut out = serde_json::to_vec(msg).unwrap();
        out.push(b'\n');
        self.writer.write_all(&out).await.unwrap();
    }

    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let id = self.next_id;
        self.send(&json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params }))
            .await;
        loop {
            let msg: Value =
                serde_json::from_str(&self.lines.next_line().await.unwrap().unwrap()).unwrap();
            if msg["method"] == "elicitation/create" {
                self.prompts
                    .push(msg["params"]["message"].as_str().unwrap().to_string());
                let reply = match self.approve {
                    Some(yes) => json!({ "jsonrpc": "2.0", "id": msg["id"], "result": {
                        "action": "accept", "content": { "approve": yes } } }),
                    None => json!({ "jsonrpc": "2.0", "id": msg["id"], "error": {
                        "code": -32601, "message": "unsupported" } }),
                };
                self.send(&reply).await;
                continue;
            }
            assert_eq!(msg["id"], id);
            return msg;
        }
    }

    async fn call(&mut self, tool: &str, arguments: Value) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": arguments }),
        )
        .await
    }

    async fn initialize(&mut self, can_ask: bool) {
        let capabilities = if can_ask {
            json!({ "elicitation": {} })
        } else {
            json!({})
        };
        let init = self
            .request(
                "initialize",
                json!({ "protocolVersion": "2025-06-18", "capabilities": capabilities }),
            )
            .await;
        assert_eq!(init["result"]["serverInfo"]["name"], "aegis");
    }
}

fn text(reply: &Value) -> &str {
    reply["result"]["content"][0]["text"].as_str().unwrap()
}

fn start(proxy: Arc<Proxy>) -> (Agent, JoinHandle<anyhow::Result<()>>) {
    let (agent_side, proxy_side) = duplex(64 * 1024);
    let (pr, pw) = tokio::io::split(proxy_side);
    let served = tokio::spawn(proxy.serve(pr, pw));
    let (ar, aw) = tokio::io::split(agent_side);
    let agent = Agent {
        lines: BufReader::new(ar).lines(),
        writer: aw,
        next_id: 0,
        approve: None,
        prompts: Vec::new(),
    };
    (agent, served)
}

#[tokio::test]
async fn untrusted_read_blocks_later_shell_call() {
    let config: Config = toml::from_str(
        r#"
        [[source]]
        tool = "web__*"
        labels = ["untrusted"]

        [[source]]
        tool = "shell__*"
        labels = []

        [[rule]]
        tool = "shell__*"
        when_context_has = ["untrusted"]
        action = "deny"
        reason = "no shell after reading the web"
        "#,
    )
    .unwrap();

    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let upstreams = vec![
        upstream("web", &["fetch"]).await,
        upstream("shell", &["exec"]).await,
    ];
    let options = Options {
        audit: Some(AuditLog::open(&log_path, None).unwrap()),
        ..Options::default()
    };
    let proxy = Proxy::new(upstreams, config.policy(), options).unwrap();
    let (mut agent, served) = start(proxy.clone());
    agent.initialize(false).await;

    let list = agent.request("tools/list", json!({})).await;
    let names: Vec<_> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(names, [json!("web__fetch"), json!("shell__exec")]);

    // Clean context: shell runs.
    let r = agent.call("shell__exec", json!({ "x": 1 })).await;
    assert_eq!(text(&r), r#"{"x":1}"#);

    // Read untrusted content.
    let r = agent.call("web__fetch", json!({ "x": 1 })).await;
    assert!(r["result"]["isError"].is_null());

    // Now shell is blocked, with an explanation the model can read.
    let r = agent.call("shell__exec", json!({ "x": 1 })).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(
        text(&r).contains("untrusted") && text(&r).contains("no shell after reading the web"),
        "{}",
        text(&r)
    );

    // Unknown tools are rejected, not forwarded.
    let r = agent.call("nope__x", json!({})).await;
    assert_eq!(r["error"]["code"], -32602);

    drop(agent);
    served.await.unwrap().unwrap();
    proxy.finish().await.unwrap();

    // The audit log records the whole story, verifies, and ends cleanly.
    let entries = audit::read(&log_path).unwrap();
    let report = audit::verify(&entries, None).unwrap();
    assert!(report.unfinished.is_empty());
    let calls: Vec<_> = entries
        .iter()
        .filter_map(|e| match &e.event {
            Event::ToolCall { tool, decision, .. } => Some((tool.as_str(), decision.action)),
            _ => None,
        })
        .collect();
    assert_eq!(
        calls,
        [
            ("shell__exec", Action::Allow),
            ("web__fetch", Action::Allow),
            ("shell__exec", Action::Deny)
        ]
    );
}

#[tokio::test]
async fn unresponsive_server_times_out_without_hiding_others() {
    let timeout = Duration::from_millis(200);
    let upstreams = vec![
        connect("slow", &["tool"], true, timeout).await,
        connect("web", &["fetch"], false, timeout).await,
    ];

    // Listing leaves the silent server out instead of failing entirely.
    let listing = proxy::list_tools(&upstreams).await;
    let names: Vec<_> = listing.tools.iter().map(|t| t["name"].clone()).collect();
    assert_eq!(names, [json!("web__fetch")]);
    assert_eq!(listing.failures.len(), 1);
    assert!(listing.failures[0].1.to_string().contains("did not answer"));

    // A call to it fails after the timeout rather than hanging.
    let started = Instant::now();
    let err = upstreams[0]
        .request("tools/call", json!({ "name": "tool" }))
        .await
        .unwrap_err();
    assert!(
        err.to_string().contains("did not answer tools/call"),
        "{err}"
    );
    assert!(started.elapsed() < Duration::from_secs(2));

    // The healthy server keeps working.
    upstreams[1]
        .request("tools/call", json!({ "name": "fetch", "arguments": {} }))
        .await
        .unwrap();
}

fn ask_policy() -> Config {
    toml::from_str(
        r#"
        [[source]]
        tool = "web__*"
        labels = ["untrusted"]

        [[rule]]
        tool = "shell__*"
        when_context_has = ["untrusted"]
        action = "ask"
        reason = "shell after reading the web needs a person's OK"
        "#,
    )
    .unwrap()
}

#[tokio::test]
async fn ask_runs_the_call_only_when_a_person_approves() {
    let upstreams = vec![
        upstream("web", &["fetch"]).await,
        upstream("shell", &["exec"]).await,
    ];
    let proxy = Proxy::new(upstreams, ask_policy().policy(), Options::default()).unwrap();
    let (mut agent, _served) = start(proxy);
    agent.initialize(true).await;
    agent.call("web__fetch", json!({})).await;

    // Approved: the call runs.
    agent.approve = Some(true);
    let r = agent
        .call("shell__exec", json!({ "cmd": "ls", "token": "s3cret" }))
        .await;
    assert_eq!(text(&r), r#"{"cmd":"ls","token":"s3cret"}"#);
    let prompt = &agent.prompts[0];
    assert!(
        prompt.contains("shell__exec") && prompt.contains("Rule #1"),
        "{prompt}"
    );
    assert!(
        !prompt.contains("s3cret"),
        "secrets must not be shown: {prompt}"
    );

    // Declined: a tool error, and the server is never called.
    agent.approve = Some(false);
    let r = agent.call("shell__exec", json!({ "cmd": "ls" })).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(text(&r).contains("not approved"), "{}", text(&r));

    // The client refuses to show prompts: denied.
    agent.approve = None;
    let r = agent.call("shell__exec", json!({ "cmd": "ls" })).await;
    assert_eq!(r["result"]["isError"], true);
    assert_eq!(agent.prompts.len(), 3);
}

#[tokio::test]
async fn ask_is_denied_when_the_client_cannot_ask() {
    let upstreams = vec![
        upstream("web", &["fetch"]).await,
        upstream("shell", &["exec"]).await,
    ];
    let proxy = Proxy::new(upstreams, ask_policy().policy(), Options::default()).unwrap();
    let (mut agent, _served) = start(proxy);
    agent.initialize(false).await; // no elicitation capability
    agent.approve = Some(true); // would approve, but is never asked
    agent.call("web__fetch", json!({})).await;
    let r = agent.call("shell__exec", json!({ "cmd": "ls" })).await;
    assert_eq!(r["result"]["isError"], true);
    assert!(text(&r).contains("cannot ask"), "{}", text(&r));
    assert!(agent.prompts.is_empty());
}

#[tokio::test]
async fn ask_times_out_to_a_denial() {
    let upstreams = vec![
        upstream("web", &["fetch"]).await,
        upstream("shell", &["exec"]).await,
    ];
    let options = Options {
        approval_timeout: Duration::from_millis(150),
        ..Options::default()
    };
    let proxy = Proxy::new(upstreams, ask_policy().policy(), options).unwrap();
    let (agent_side, proxy_side) = duplex(64 * 1024);
    let (pr, pw) = tokio::io::split(proxy_side);
    tokio::spawn(proxy.serve(pr, pw));
    let (ar, mut aw) = tokio::io::split(agent_side);
    let mut lines = BufReader::new(ar).lines();
    for (id, msg) in [
        (
            1,
            json!({ "method": "initialize", "params": { "capabilities": { "elicitation": {} } } }),
        ),
        (
            2,
            json!({ "method": "tools/call", "params": { "name": "web__fetch", "arguments": {} } }),
        ),
        (
            3,
            json!({ "method": "tools/call", "params": { "name": "shell__exec", "arguments": {} } }),
        ),
    ] {
        let mut msg = msg;
        msg["jsonrpc"] = json!("2.0");
        msg["id"] = json!(id);
        let mut out = serde_json::to_vec(&msg).unwrap();
        out.push(b'\n');
        aw.write_all(&out).await.unwrap();
        // Read until this request's reply, ignoring (not answering) prompts.
        loop {
            let reply: Value =
                serde_json::from_str(&lines.next_line().await.unwrap().unwrap()).unwrap();
            if reply["id"] == id {
                if id == 3 {
                    assert!(
                        reply["result"]["content"][0]["text"]
                            .as_str()
                            .unwrap()
                            .contains("nobody answered in time")
                    );
                }
                break;
            }
        }
    }
}

/// A fresh aegis (a new session) over web, files and shell servers.
async fn files_session(config: &Config, state: &std::path::Path) -> Agent {
    let upstreams = vec![
        upstream("web", &["fetch"]).await,
        upstream("files", &["write_file", "read_file"]).await,
        upstream("shell", &["exec"]).await,
    ];
    let options = Options {
        resources: Some(ResourceStore::open(state, config.resources.clone()).unwrap()),
        ..Options::default()
    };
    let proxy = Proxy::new(upstreams, config.policy(), options).unwrap();
    let (mut agent, _served) = start(proxy);
    agent.initialize(false).await;
    agent
}

#[tokio::test]
async fn file_written_while_untrusted_stays_untrusted_next_session() {
    let config: Config = toml::from_str(
        r#"
        [[source]]
        tool = "web__*"
        labels = ["untrusted"]

        [[source]]
        tool = "files__*"
        labels = []

        [[resource]]
        write = "files__write_file"
        read = "files__read_file"
        key = "path"

        [[rule]]
        tool = "shell__*"
        when_context_has = ["untrusted"]
        action = "deny"
        "#,
    )
    .unwrap();
    let dir = tempfile::tempdir().unwrap();
    let state = dir.path().join("state.json");

    // Session 1 reads the web, then writes what it read into the repo.
    let mut agent = files_session(&config, &state).await;
    agent
        .call("web__fetch", json!({ "url": "https://evil.example" }))
        .await;
    agent
        .call(
            "files__write_file",
            json!({ "path": "src/login.tsx", "content": "..." }),
        )
        .await;
    drop(agent);

    // Session 2 starts clean, and a trusted read of an untouched file keeps it clean.
    let mut agent = files_session(&config, &state).await;
    agent
        .call("files__read_file", json!({ "path": "README.md" }))
        .await;
    let r = agent
        .call("shell__exec", json!({ "cmd": "npm test" }))
        .await;
    assert!(r["result"]["isError"].is_null(), "{r}");

    // Reading the file session 1 wrote (spelled differently) brings the label back.
    agent
        .call(
            "files__read_file",
            json!({ "path": "./src/x/../login.tsx" }),
        )
        .await;
    let r = agent
        .call("shell__exec", json!({ "cmd": "npm test" }))
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
}

#[tokio::test]
async fn oversized_agent_message_is_rejected_and_the_connection_survives() {
    let upstreams = vec![upstream("web", &["fetch"]).await];
    let options = Options {
        max_message_bytes: 2048,
        ..Options::default()
    };
    let proxy = Proxy::new(
        upstreams,
        toml::from_str::<Config>("").unwrap().policy(),
        options,
    )
    .unwrap();
    let (mut agent, _served) = start(proxy);
    agent.initialize(false).await;

    let huge = json!({ "jsonrpc": "2.0", "id": 99, "method": "tools/call",
        "params": { "name": "web__fetch", "arguments": { "blob": "x".repeat(10_000) } } });
    agent.send(&huge).await;
    let reply: Value =
        serde_json::from_str(&agent.lines.next_line().await.unwrap().unwrap()).unwrap();
    assert_eq!(reply["error"]["code"], -32600);
    assert!(
        reply["error"]["message"]
            .as_str()
            .unwrap()
            .contains("exceeds")
    );

    let r = agent.call("web__fetch", json!({ "url": "ok" })).await;
    assert!(r["result"]["isError"].is_null());
}

#[tokio::test]
async fn secrets_in_arguments_are_redacted_in_the_log() {
    let dir = tempfile::tempdir().unwrap();
    let log_path = dir.path().join("audit.jsonl");
    let upstreams = vec![upstream("web", &["fetch"]).await];
    let options = Options {
        audit: Some(AuditLog::open(&log_path, None).unwrap()),
        arguments: ArgumentLogging::Redacted,
        ..Options::default()
    };
    let proxy = Proxy::new(
        upstreams,
        toml::from_str::<Config>("").unwrap().policy(),
        options,
    )
    .unwrap();
    let (mut agent, _served) = start(proxy);
    agent.initialize(false).await;
    let r = agent
        .call(
            "web__fetch",
            json!({ "url": "https://api.example", "headers": { "Authorization": "Bearer abc" } }),
        )
        .await;
    // The server still gets the real value; only the log is redacted.
    assert!(text(&r).contains("Bearer abc"));
    let log = std::fs::read_to_string(&log_path).unwrap();
    assert!(!log.contains("Bearer abc"), "{log}");
    assert!(log.contains("[redacted]") && log.contains("https://api.example"));
}

#[tokio::test]
async fn pages_from_trusted_hosts_keep_the_session_clean() {
    let config: Config = toml::from_str(
        r#"
        [[source]]
        tool = "web__fetch"
        labels = []
        hosts = ["docs.rs", "*.rust-lang.org"]

        [[source]]
        tool = "web__*"
        labels = ["untrusted"]

        [[source]]
        tool = "shell__*"
        labels = []

        [[rule]]
        tool = "shell__*"
        when_context_has = ["untrusted"]
        action = "deny"
        "#,
    )
    .unwrap();
    config.validate().unwrap();
    let upstreams = vec![
        upstream("web", &["fetch"]).await,
        upstream("shell", &["exec"]).await,
    ];
    let proxy = Proxy::new(upstreams, config.policy(), Options::default()).unwrap();
    let (mut agent, _served) = start(proxy);
    agent.initialize(false).await;

    // Reading the docs doesn't taint the session.
    agent
        .call(
            "web__fetch",
            json!({ "url": "https://docs.rs/serde/latest/serde/" }),
        )
        .await;
    agent
        .call(
            "web__fetch",
            json!({ "url": "https://doc.rust-lang.org/std/" }),
        )
        .await;
    let r = agent
        .call("shell__exec", json!({ "cmd": "cargo test" }))
        .await;
    assert!(r["result"]["isError"].is_null(), "{r}");

    // A lookalike URL does.
    agent
        .call(
            "web__fetch",
            json!({ "url": "https://docs.rs@evil.example/" }),
        )
        .await;
    let r = agent
        .call("shell__exec", json!({ "cmd": "cargo test" }))
        .await;
    assert_eq!(r["result"]["isError"], true, "{r}");
}

#[tokio::test]
async fn resources_and_prompts_are_labelled_and_checked() {
    let config: Config = toml::from_str(
        r#"
        [[source]]
        tool = "web__*"
        labels = ["untrusted"]

        [[source]]
        tool = "shell__*"
        labels = []

        [[rule]]
        tool = "shell__*"
        when_context_has = ["untrusted"]
        action = "deny"
        "#,
    )
    .unwrap();
    let upstreams = vec![
        upstream("web", &["fetch"]).await,
        upstream("shell", &["exec"]).await,
    ];
    let proxy = Proxy::new(upstreams, config.policy(), Options::default()).unwrap();
    let (mut agent, served) = start(proxy);
    let init = agent
        .request(
            "initialize",
            json!({ "protocolVersion": "2025-06-18", "capabilities": {} }),
        )
        .await;
    assert!(init["result"]["capabilities"]["resources"].is_object());
    assert!(init["result"]["capabilities"]["prompts"].is_object());

    let list = agent.request("resources/list", json!({})).await;
    let resources = list["result"]["resources"].as_array().unwrap();
    assert_eq!(resources.len(), 2);
    assert_eq!(resources[0]["name"], "web__doc");

    let prompts = agent.request("prompts/list", json!({})).await;
    assert_eq!(prompts["result"]["prompts"][1]["name"], "shell__greet");

    // A clean context lets the shell server's prompt and resource through.
    let r = agent
        .request("prompts/get", json!({ "name": "shell__greet" }))
        .await;
    assert_eq!(r["result"]["messages"][0]["content"]["text"], "hi");
    let r = agent
        .request("resources/read", json!({ "uri": "mem://exec" }))
        .await;
    assert_eq!(r["result"]["contents"][0]["text"], "contents of mem://exec");

    // Reading the web server's resource taints the session...
    let r = agent
        .request("resources/read", json!({ "uri": "mem://fetch" }))
        .await;
    assert_eq!(
        r["result"]["contents"][0]["text"],
        "contents of mem://fetch"
    );

    // ...so the shell server is now off limits, for tools and resources alike.
    let r = agent.call("shell__exec", json!({})).await;
    assert_eq!(r["result"]["isError"], true);
    let r = agent
        .request("resources/read", json!({ "uri": "mem://exec" }))
        .await;
    assert_eq!(r["error"]["code"], -32001);
    assert!(
        r["error"]["message"]
            .as_str()
            .unwrap()
            .contains("shell__resources/read"),
        "{r}"
    );
    let r = agent
        .request("prompts/get", json!({ "name": "shell__greet" }))
        .await;
    assert_eq!(r["error"]["code"], -32001);

    let r = agent
        .request("resources/read", json!({ "uri": "mem://unknown" }))
        .await;
    assert_eq!(r["error"]["code"], -32002);

    drop(agent);
    served.await.unwrap().unwrap();
}
