//! aegis fronting a remote server over MCP's Streamable HTTP transport, with
//! a tiny hand-written HTTP server standing in for the remote end.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use aegis::config::ServerConfig;
use aegis::upstream::{DEFAULT_MAX_MESSAGE_BYTES, Upstream};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpListener;

/// (method, session header, protocol header, authorization header)
type Request = (String, Option<String>, Option<String>, Option<String>);

#[derive(Default)]
struct Seen {
    requests: Vec<Request>,
}

async fn serve(listener: TcpListener, seen: Arc<Mutex<Seen>>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            return;
        };
        let seen = seen.clone();
        tokio::spawn(async move {
            let (reader, mut writer) = stream.into_split();
            let mut reader = BufReader::new(reader);
            loop {
                let mut headers = BTreeMap::new();
                let mut line = String::new();
                if reader.read_line(&mut line).await.unwrap_or(0) == 0 {
                    return;
                }
                loop {
                    let mut header = String::new();
                    reader.read_line(&mut header).await.unwrap();
                    let header = header.trim_end();
                    if header.is_empty() {
                        break;
                    }
                    let (k, v) = header.split_once(':').unwrap();
                    headers.insert(k.to_ascii_lowercase(), v.trim().to_string());
                }
                let len: usize = headers["content-length"].parse().unwrap();
                let mut body = vec![0; len];
                reader.read_exact(&mut body).await.unwrap();
                let msg: Value = serde_json::from_slice(&body).unwrap();
                let method = msg["method"].as_str().unwrap_or("").to_string();
                seen.lock().unwrap().requests.push((
                    method.clone(),
                    headers.get("mcp-session-id").cloned(),
                    headers.get("mcp-protocol-version").cloned(),
                    headers.get("authorization").cloned(),
                ));
                let reply = |status: &str, extra: &str, content_type: &str, body: &str| {
                    format!(
                        "HTTP/1.1 {status}\r\n{extra}content-type: {content_type}\r\ncontent-length: {}\r\n\r\n{body}",
                        body.len()
                    )
                };
                let response = if method != "initialize"
                    && headers.get("mcp-session-id").map(String::as_str) != Some("sess-1")
                {
                    reply("400 Bad Request", "", "text/plain", "missing session")
                } else {
                    match method.as_str() {
                        "initialize" => reply(
                            "200 OK",
                            "mcp-session-id: sess-1\r\n",
                            "application/json",
                            &json!({ "jsonrpc": "2.0", "id": msg["id"], "result": {
                                "protocolVersion": "2025-03-26",
                                "capabilities": { "tools": {}, "resources": {} },
                                "serverInfo": { "name": "remote", "version": "1" },
                            }})
                            .to_string(),
                        ),
                        "notifications/initialized" => reply("202 Accepted", "", "text/plain", ""),
                        // An event stream with a notification before the answer.
                        "tools/list" => {
                            let note = json!({ "jsonrpc": "2.0", "method": "notifications/message", "params": {} });
                            let answer = json!({ "jsonrpc": "2.0", "id": msg["id"], "result": {
                                "tools": [{ "name": "search", "inputSchema": { "type": "object" } }]
                            }});
                            reply(
                                "200 OK",
                                "",
                                "text/event-stream",
                                &format!(": comment\n\nevent: message\ndata: {note}\n\nid: 7\ndata: {answer}\n\n"),
                            )
                        }
                        "tools/call" => reply(
                            "200 OK",
                            "",
                            "application/json",
                            &json!({ "jsonrpc": "2.0", "id": msg["id"], "result": {
                                "content": [{ "type": "text", "text": msg["params"]["arguments"].to_string() }]
                            }})
                            .to_string(),
                        ),
                        _ => reply(
                            "200 OK",
                            "",
                            "application/json",
                            &json!({ "jsonrpc": "2.0", "id": msg["id"], "error": { "code": -32601, "message": "no" } })
                                .to_string(),
                        ),
                    }
                };
                writer.write_all(response.as_bytes()).await.unwrap();
            }
        });
    }
}

fn config(url: String) -> ServerConfig {
    toml::from_str(&format!(
        "name = \"remote\"\nurl = {url:?}\nheaders = {{ Authorization = \"Bearer ${{AEGIS_HTTP_TEST_TOKEN}}\" }}"
    ))
    .unwrap()
}

#[tokio::test]
async fn talks_streamable_http() {
    // SAFETY: no other test reads this variable.
    unsafe { std::env::set_var("AEGIS_HTTP_TEST_TOKEN", "t0k3n") };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}/mcp", listener.local_addr().unwrap());
    let seen = Arc::new(Mutex::new(Seen::default()));
    tokio::spawn(serve(listener, seen.clone()));

    let upstream = Upstream::open(&config(url), DEFAULT_MAX_MESSAGE_BYTES)
        .await
        .unwrap();
    assert!(upstream.supports("resources"));
    assert!(!upstream.supports("prompts"));

    let listing = aegis::proxy::list_tools(std::slice::from_ref(&upstream)).await;
    assert!(listing.failures.is_empty(), "{:?}", listing.failures);
    assert_eq!(listing.tools[0]["name"], "remote__search");

    let result = upstream
        .request(
            "tools/call",
            json!({ "name": "search", "arguments": { "q": "rust" } }),
        )
        .await
        .unwrap();
    assert_eq!(result["content"][0]["text"], r#"{"q":"rust"}"#);

    let error = upstream.request("nope", json!({})).await.unwrap_err();
    assert!(error.to_string().contains("nope failed"), "{error}");

    let seen = seen.lock().unwrap();
    let methods: Vec<&str> = seen.requests.iter().map(|r| r.0.as_str()).collect();
    assert_eq!(
        methods,
        [
            "initialize",
            "notifications/initialized",
            "tools/list",
            "tools/call",
            "nope"
        ]
    );
    // No session or version before the server has named them; both after.
    assert_eq!(seen.requests[0].1, None);
    assert_eq!(seen.requests[0].2, None);
    for request in &seen.requests[1..] {
        assert_eq!(request.1.as_deref(), Some("sess-1"));
        assert_eq!(request.2.as_deref(), Some("2025-03-26"));
    }
    for request in &seen.requests {
        assert_eq!(request.3.as_deref(), Some("Bearer t0k3n"));
    }
}

#[tokio::test]
async fn missing_token_fails_before_connecting() {
    let mut config = config("http://127.0.0.1:9/mcp".into());
    // Only the unset variable, so the result doesn't depend on whether the
    // other test has set AEGIS_HTTP_TEST_TOKEN yet.
    config.headers.clear();
    config
        .headers
        .insert("X-Key".into(), "${AEGIS_HTTP_TEST_UNSET}".into());
    let error = Upstream::open(&config, DEFAULT_MAX_MESSAGE_BYTES)
        .await
        .err()
        .unwrap();
    assert!(
        format!("{error:#}").contains("AEGIS_HTTP_TEST_UNSET"),
        "{error:#}"
    );
}

#[tokio::test]
async fn http_errors_are_reported() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut buf = vec![0; 4096];
            let _ = stream.read(&mut buf).await;
            let _ = stream
                .write_all(b"HTTP/1.1 401 Unauthorized\r\ncontent-length: 13\r\n\r\nbad token, no")
                .await;
        }
    });
    let mut config = config(format!("http://{addr}/mcp"));
    config.headers.clear();
    let error = Upstream::open(&config, DEFAULT_MAX_MESSAGE_BYTES)
        .await
        .err()
        .unwrap();
    let text = format!("{error:#}");
    assert!(text.contains("401") && text.contains("bad token"), "{text}");
}
