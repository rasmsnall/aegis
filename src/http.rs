//! MCP's Streamable HTTP transport, for remote servers.
//!
//! Every message is a POST to the server's URL. A request's answer comes
//! back either as a JSON body or as a Server-Sent Events stream that carries
//! it (possibly after notifications). The session id the server returns from
//! `initialize` is sent with every later message, as is the negotiated
//! protocol version.

use std::collections::BTreeMap;
use std::sync::Mutex;

use anyhow::{Context, Result, anyhow, bail};
use reqwest::header::{ACCEPT, CONTENT_TYPE, HeaderMap, HeaderName, HeaderValue};
use serde_json::Value;

const SESSION_HEADER: &str = "mcp-session-id";
const VERSION_HEADER: &str = "mcp-protocol-version";

/// Replaces `${NAME}` with the environment variable `NAME`. A missing
/// variable is an error rather than an empty string, so a token that isn't
/// set fails loudly instead of sending an empty `Authorization` header.
pub fn expand_env(value: &str) -> Result<String> {
    let mut out = String::with_capacity(value.len());
    let mut rest = value;
    while let Some(start) = rest.find("${") {
        out.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let end = after
            .find('}')
            .ok_or_else(|| anyhow!("unclosed ${{ in {value:?}"))?;
        let name = &after[..end];
        let var = std::env::var(name)
            .map_err(|_| anyhow!("environment variable {name} is not set (used in {value:?})"))?;
        out.push_str(&var);
        rest = &after[end + 1..];
    }
    out.push_str(rest);
    Ok(out)
}

pub struct HttpTransport {
    name: String,
    url: String,
    client: reqwest::Client,
    headers: HeaderMap,
    session: Mutex<Option<String>>,
    protocol: Mutex<Option<String>>,
    max_message_bytes: usize,
}

impl HttpTransport {
    pub fn new(
        name: &str,
        url: &str,
        headers: &BTreeMap<String, String>,
        max_message_bytes: usize,
    ) -> Result<Self> {
        // reqwest is built without a default crypto backend; use ring.
        let _ = rustls::crypto::ring::default_provider().install_default();
        let mut map = HeaderMap::new();
        for (key, value) in headers {
            let value =
                expand_env(value).with_context(|| format!("server {name:?} header {key}"))?;
            let key = HeaderName::from_bytes(key.as_bytes())
                .with_context(|| format!("server {name:?}: {key:?} is not a valid header name"))?;
            let mut value = HeaderValue::from_str(&value)
                .with_context(|| format!("server {name:?}: header {key} has an invalid value"))?;
            value.set_sensitive(true);
            map.insert(key, value);
        }
        let client = reqwest::Client::builder()
            .build()
            .context("creating the HTTP client")?;
        Ok(Self {
            name: name.to_string(),
            url: url.to_string(),
            client,
            headers: map,
            session: Mutex::new(None),
            protocol: Mutex::new(None),
            max_message_bytes,
        })
    }

    /// Sends the protocol version negotiated by `initialize` from now on.
    pub fn set_protocol_version(&self, version: &str) {
        *self.protocol.lock().expect("not poisoned") = Some(version.to_string());
    }

    /// Sends `msg`. For a request, returns the response message with the
    /// same id; for a notification or response, `None`.
    pub async fn send(&self, msg: &Value) -> Result<Option<Value>> {
        let expects = msg
            .get("method")
            .is_some()
            .then(|| msg.get("id").cloned())
            .flatten();
        let mut request = self
            .client
            .post(&self.url)
            .headers(self.headers.clone())
            .header(CONTENT_TYPE, "application/json")
            .header(ACCEPT, "application/json, text/event-stream")
            .body(serde_json::to_vec(msg)?);
        if let Some(session) = self.session.lock().expect("not poisoned").clone() {
            request = request.header(SESSION_HEADER, session);
        }
        if let Some(version) = self.protocol.lock().expect("not poisoned").clone() {
            request = request.header(VERSION_HEADER, version);
        }
        let mut response = request
            .send()
            .await
            .with_context(|| format!("server {:?}: request to {} failed", self.name, self.url))?;

        if let Some(session) = response
            .headers()
            .get(SESSION_HEADER)
            .and_then(|v| v.to_str().ok())
        {
            *self.session.lock().expect("not poisoned") = Some(session.to_string());
        }
        let status = response.status();
        if !status.is_success() {
            let body = self.read_body(&mut response, 600).await.unwrap_or_default();
            let snippet = String::from_utf8_lossy(&body);
            bail!(
                "server {:?} answered HTTP {status}{}",
                self.name,
                if snippet.trim().is_empty() {
                    String::new()
                } else {
                    format!(": {}", snippet.trim())
                }
            );
        }
        let Some(id) = expects else {
            return Ok(None);
        };
        let content_type = response
            .headers()
            .get(CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("")
            .to_ascii_lowercase();
        if content_type.starts_with("text/event-stream") {
            self.read_events(&mut response, &id).await.map(Some)
        } else {
            let body = self
                .read_body(&mut response, self.max_message_bytes)
                .await?;
            let value: Value = serde_json::from_slice(&body)
                .with_context(|| format!("server {:?} sent invalid JSON", self.name))?;
            find_response(value, &id).map(Some).ok_or_else(|| {
                anyhow!(
                    "server {:?} replied without an answer to the request",
                    self.name
                )
            })
        }
    }

    async fn read_body(&self, response: &mut reqwest::Response, limit: usize) -> Result<Vec<u8>> {
        let mut body = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if body.len() + chunk.len() > limit {
                if limit == self.max_message_bytes {
                    bail!(
                        "server {:?} sent a reply larger than {limit} bytes",
                        self.name
                    );
                }
                body.extend_from_slice(&chunk[..limit - body.len()]);
                break;
            }
            body.extend_from_slice(&chunk);
        }
        Ok(body)
    }

    /// Reads Server-Sent Events until the one carrying the answer to `id`.
    async fn read_events(&self, response: &mut reqwest::Response, id: &Value) -> Result<Value> {
        let mut buffer: Vec<u8> = Vec::new();
        let mut data = String::new();
        while let Some(chunk) = response.chunk().await? {
            buffer.extend_from_slice(&chunk);
            while let Some(newline) = buffer.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buffer.drain(..=newline).collect();
                let line = String::from_utf8_lossy(&line);
                let line = line.trim_end_matches(['\n', '\r']);
                if line.is_empty() {
                    // End of an event.
                    if !data.is_empty() {
                        let event = std::mem::take(&mut data);
                        if let Ok(value) = serde_json::from_str::<Value>(&event)
                            && let Some(answer) = find_response(value, id)
                        {
                            return Ok(answer);
                        }
                    }
                } else if let Some(rest) = line.strip_prefix("data:") {
                    if !data.is_empty() {
                        data.push('\n');
                    }
                    data.push_str(rest.strip_prefix(' ').unwrap_or(rest));
                }
                // `event:`, `id:`, `retry:` and comments are not needed.
                if data.len() > self.max_message_bytes {
                    bail!(
                        "server {:?} sent an event larger than {} bytes",
                        self.name,
                        self.max_message_bytes
                    );
                }
            }
            if buffer.len() > self.max_message_bytes {
                bail!(
                    "server {:?} sent a line larger than {} bytes",
                    self.name,
                    self.max_message_bytes
                );
            }
        }
        bail!(
            "server {:?} closed the event stream without answering",
            self.name
        )
    }
}

/// The response to `id` in `value`, which may be one message or a batch.
fn find_response(value: Value, id: &Value) -> Option<Value> {
    let is_answer = |m: &Value| m.get("method").is_none() && m.get("id") == Some(id);
    match value {
        Value::Array(items) => items.into_iter().find(is_answer),
        m if is_answer(&m) => Some(m),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn expands_environment_variables() {
        // SAFETY: tests in this module don't read this variable concurrently.
        unsafe { std::env::set_var("AEGIS_TEST_TOKEN", "s3cret") };
        assert_eq!(
            expand_env("Bearer ${AEGIS_TEST_TOKEN}").unwrap(),
            "Bearer s3cret"
        );
        assert_eq!(expand_env("plain").unwrap(), "plain");
        assert!(
            expand_env("${AEGIS_TEST_MISSING_VAR}")
                .unwrap_err()
                .to_string()
                .contains("not set")
        );
        assert!(expand_env("${OOPS").is_err());
    }

    #[test]
    fn finds_responses_in_batches() {
        let id = serde_json::json!(3);
        let batch = serde_json::json!([{ "method": "x" }, { "id": 3, "result": 1 }]);
        assert_eq!(find_response(batch, &id).unwrap()["result"], 1);
        assert!(find_response(serde_json::json!({ "id": 4, "result": 1 }), &id).is_none());
    }
}
