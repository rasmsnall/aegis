//! End-to-end: an agent talks to aegis, which fronts two in-process fake MCP
//! servers. Reading from `web` must block a later call on `shell`.

use std::sync::Arc;

use aegis::audit::{self, AuditLog, Event};
use aegis::config::Config;
use aegis::policy::Action;
use aegis::proxy::Proxy;
use aegis::upstream::Upstream;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader, DuplexStream, Lines, duplex};

/// A minimal MCP server exposing one tool that echoes its arguments.
async fn fake_server(stream: DuplexStream, tool: &'static str) {
    let (reader, mut writer) = tokio::io::split(stream);
    let mut lines = BufReader::new(reader).lines();
    while let Ok(Some(line)) = lines.next_line().await {
        let msg: Value = serde_json::from_str(&line).unwrap();
        let Some(id) = msg.get("id").cloned() else {
            continue;
        };
        let result = match msg["method"].as_str().unwrap() {
            "initialize" => json!({
                "protocolVersion": "2025-06-18",
                "capabilities": { "tools": {} },
                "serverInfo": { "name": tool, "version": "0" },
            }),
            "tools/list" => {
                json!({ "tools": [{ "name": tool, "inputSchema": { "type": "object" } }] })
            }
            "tools/call" => {
                assert_eq!(
                    msg["params"]["name"], tool,
                    "aegis must strip the namespace"
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

async fn upstream(name: &str, tool: &'static str) -> Arc<Upstream> {
    let (ours, theirs) = duplex(64 * 1024);
    tokio::spawn(fake_server(theirs, tool));
    let (reader, writer) = tokio::io::split(ours);
    let upstream = Upstream::connect(name.into(), reader, writer, None);
    upstream.initialize().await.unwrap();
    upstream
}

struct Agent {
    lines: Lines<BufReader<tokio::io::ReadHalf<DuplexStream>>>,
    writer: tokio::io::WriteHalf<DuplexStream>,
    next_id: u64,
}

impl Agent {
    async fn request(&mut self, method: &str, params: Value) -> Value {
        self.next_id += 1;
        let msg =
            json!({ "jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params });
        let mut out = serde_json::to_vec(&msg).unwrap();
        out.push(b'\n');
        self.writer.write_all(&out).await.unwrap();
        let reply: Value =
            serde_json::from_str(&self.lines.next_line().await.unwrap().unwrap()).unwrap();
        assert_eq!(reply["id"], self.next_id);
        reply
    }

    async fn call(&mut self, tool: &str) -> Value {
        self.request(
            "tools/call",
            json!({ "name": tool, "arguments": { "x": 1 } }),
        )
        .await
    }
}

#[tokio::test]
async fn untrusted_read_blocks_later_shell_call() {
    let config: Config = toml::from_str(
        r#"
        [[source]]
        tool = "web__*"
        labels = ["untrusted"]

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
        upstream("web", "fetch").await,
        upstream("shell", "exec").await,
    ];
    let proxy = Proxy::new(
        upstreams,
        config.policy(),
        Some(AuditLog::open(&log_path).unwrap()),
    )
    .unwrap();

    let (agent_side, proxy_side) = duplex(64 * 1024);
    let (pr, pw) = tokio::io::split(proxy_side);
    let served = tokio::spawn(proxy.serve(pr, pw));
    let (ar, aw) = tokio::io::split(agent_side);
    let mut agent = Agent {
        lines: BufReader::new(ar).lines(),
        writer: aw,
        next_id: 0,
    };

    let init = agent
        .request("initialize", json!({ "protocolVersion": "2025-06-18" }))
        .await;
    assert_eq!(init["result"]["serverInfo"]["name"], "aegis");

    let list = agent.request("tools/list", json!({})).await;
    let names: Vec<_> = list["result"]["tools"]
        .as_array()
        .unwrap()
        .iter()
        .map(|t| t["name"].clone())
        .collect();
    assert_eq!(names, [json!("web__fetch"), json!("shell__exec")]);

    // Clean context: shell runs.
    let r = agent.call("shell__exec").await;
    assert_eq!(r["result"]["content"][0]["text"], r#"{"x":1}"#);

    // Read untrusted content.
    let r = agent.call("web__fetch").await;
    assert!(r["result"]["isError"].is_null());

    // Now shell is blocked, with an explanation the model can read.
    let r = agent.call("shell__exec").await;
    assert_eq!(r["result"]["isError"], true);
    let text = r["result"]["content"][0]["text"].as_str().unwrap();
    assert!(
        text.contains("untrusted") && text.contains("no shell after reading the web"),
        "{text}"
    );

    // Unknown tools are rejected, not forwarded.
    let r = agent.call("nope__x").await;
    assert_eq!(r["error"]["code"], -32602);

    drop(agent);
    served.await.unwrap().unwrap();

    // The audit log records the whole story and verifies.
    let entries = audit::read(&log_path).unwrap();
    audit::verify(&entries).unwrap();
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
