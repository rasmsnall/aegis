//! Client side of a connection to one upstream MCP server (stdio transport:
//! newline-delimited JSON-RPC).

use std::collections::HashMap;
use std::process::Stdio;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use serde_json::{Value, json};
use tokio::io::{AsyncBufRead, AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::process::{Child, Command};
use tokio::sync::{Mutex, oneshot};

use crate::config::ServerConfig;

pub const PROTOCOL_VERSION: &str = "2025-06-18";

/// Request timeout used when none is configured.
pub const DEFAULT_CALL_TIMEOUT: Duration = Duration::from_secs(300);

/// Message size limit used when none is configured.
pub const DEFAULT_MAX_MESSAGE_BYTES: usize = 16 * 1024 * 1024;

/// One newline-delimited message, read with a size limit.
pub(crate) enum Line {
    Text(String),
    /// The message exceeded the limit; it was read to its end and dropped.
    TooLong(usize),
    Eof,
}

/// Reads one line without ever buffering more than `max` bytes of it.
pub(crate) async fn read_line_limited<R: AsyncBufRead + Unpin>(
    reader: &mut R,
    max: usize,
) -> std::io::Result<Line> {
    let mut buf = Vec::new();
    let mut total = 0usize;
    let mut too_long = false;
    loop {
        let available = reader.fill_buf().await?;
        if available.is_empty() {
            return Ok(match (total, too_long) {
                (0, _) => Line::Eof,
                (_, true) => Line::TooLong(total),
                _ => Line::Text(String::from_utf8_lossy(&buf).into_owned()),
            });
        }
        let newline = available.iter().position(|&b| b == b'\n');
        let chunk = &available[..newline.unwrap_or(available.len())];
        total += chunk.len();
        if !too_long {
            if buf.len() + chunk.len() > max {
                too_long = true;
                buf = Vec::new();
            } else {
                buf.extend_from_slice(chunk);
            }
        }
        let used = chunk.len() + usize::from(newline.is_some());
        reader.consume(used);
        if newline.is_some() {
            return Ok(if too_long {
                Line::TooLong(total)
            } else {
                Line::Text(String::from_utf8_lossy(&buf).into_owned())
            });
        }
    }
}

type Pending = Arc<Mutex<HashMap<u64, oneshot::Sender<Value>>>>;
type Writer = Arc<Mutex<Box<dyn AsyncWrite + Unpin + Send>>>;

pub struct Upstream {
    pub name: String,
    writer: Writer,
    pending: Pending,
    next_id: AtomicU64,
    call_timeout: Duration,
    /// Set once the server's output has ended or been cut off.
    closed: Arc<AtomicBool>,
    _child: Option<Child>,
}

impl Upstream {
    /// Launches the server process and performs the MCP initialize handshake.
    pub async fn spawn(config: &ServerConfig, max_message_bytes: usize) -> Result<Arc<Self>> {
        let mut child = Command::new(&config.command)
            .args(&config.args)
            .envs(&config.env)
            // The audit key must stay out of reach of the agent's tools.
            .env_remove(crate::audit::KEY_ENV)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .kill_on_drop(true)
            .spawn()
            .with_context(|| format!("starting server {:?} ({})", config.name, config.command))?;
        let stdin = child.stdin.take().expect("piped stdin");
        let stdout = child.stdout.take().expect("piped stdout");
        let upstream = Self::connect(
            config.name.clone(),
            stdout,
            stdin,
            Some(child),
            Duration::from_secs(config.call_timeout_secs),
            max_message_bytes,
        );
        let startup = Duration::from_secs(config.startup_timeout_secs);
        tokio::time::timeout(startup, upstream.initialize())
            .await
            .map_err(|_| {
                anyhow!(
                    "server {:?} did not finish starting within {}s (raise startup_timeout_secs if it is just slow)",
                    config.name,
                    startup.as_secs()
                )
            })?
            .with_context(|| format!("initializing {:?}", config.name))?;
        Ok(upstream)
    }

    /// Wraps an already-open transport. Spawns a task that routes responses.
    pub fn connect(
        name: String,
        reader: impl AsyncRead + Unpin + Send + 'static,
        writer: impl AsyncWrite + Unpin + Send + 'static,
        child: Option<Child>,
        call_timeout: Duration,
        max_message_bytes: usize,
    ) -> Arc<Self> {
        let upstream = Arc::new(Self {
            name,
            writer: Arc::new(Mutex::new(Box::new(writer))),
            pending: Arc::default(),
            next_id: AtomicU64::new(1),
            call_timeout,
            closed: Arc::default(),
            _child: child,
        });
        tokio::spawn(read_loop(
            upstream.name.clone(),
            reader,
            max_message_bytes,
            upstream.writer.clone(),
            upstream.pending.clone(),
            upstream.closed.clone(),
        ));
        upstream
    }

    pub async fn initialize(&self) -> Result<()> {
        self.request(
            "initialize",
            json!({
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": {},
                "clientInfo": { "name": "aegis", "version": env!("CARGO_PKG_VERSION") },
            }),
        )
        .await?;
        self.notify("notifications/initialized", json!({})).await
    }

    /// Sends a request and waits for the matching response. Returns the
    /// `result` value, or an error carrying the JSON-RPC error object.
    pub async fn request(&self, method: &str, params: Value) -> Result<Value> {
        match self.request_raw(method, params).await? {
            Ok(result) => Ok(result),
            Err(error) => bail!("{} {method} failed: {error}", self.name),
        }
    }

    /// Like [`request`](Self::request) but hands back a JSON-RPC error object
    /// as `Ok(Err(error))` so it can be relayed verbatim.
    /// Fails if the server does not answer within its call timeout.
    pub async fn request_raw(&self, method: &str, params: Value) -> Result<Result<Value, Value>> {
        if self.closed.load(Ordering::Acquire) {
            bail!("server {:?} is disconnected", self.name);
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        let (tx, rx) = oneshot::channel();
        self.pending.lock().await.insert(id, tx);
        let msg = json!({ "jsonrpc": "2.0", "id": id, "method": method, "params": params });
        let exchange = async {
            write_line(&self.writer, &msg).await?;
            rx.await
                .map_err(|_| anyhow!("server {:?} closed the connection", self.name))
        };
        let outcome = tokio::time::timeout(self.call_timeout, exchange).await;
        if !matches!(outcome, Ok(Ok(_))) {
            self.pending.lock().await.remove(&id);
        }
        let mut response = outcome.map_err(|_| {
            anyhow!(
                "server {:?} did not answer {method} within {}s",
                self.name,
                self.call_timeout.as_secs()
            )
        })??;
        if let Some(error) = response.get_mut("error") {
            return Ok(Err(error.take()));
        }
        Ok(Ok(response
            .get_mut("result")
            .map(Value::take)
            .unwrap_or(Value::Null)))
    }

    pub async fn notify(&self, method: &str, params: Value) -> Result<()> {
        write_line(
            &self.writer,
            &json!({ "jsonrpc": "2.0", "method": method, "params": params }),
        )
        .await
    }
}

pub(crate) async fn write_line(writer: &Writer, msg: &Value) -> Result<()> {
    let mut line = serde_json::to_vec(msg)?;
    line.push(b'\n');
    let mut w = writer.lock().await;
    w.write_all(&line).await?;
    w.flush().await?;
    Ok(())
}

async fn read_loop(
    name: String,
    reader: impl AsyncRead + Unpin,
    max_message_bytes: usize,
    writer: Writer,
    pending: Pending,
    closed: Arc<AtomicBool>,
) {
    let mut reader = BufReader::new(reader);
    loop {
        let line = match read_line_limited(&mut reader, max_message_bytes).await {
            Ok(Line::Text(line)) => line,
            Ok(Line::Eof) => break,
            Ok(Line::TooLong(n)) => {
                // A server that floods us is not trusted to stay in sync.
                eprintln!(
                    "aegis: {name:?} sent a {n}-byte message (limit {max_message_bytes}); disconnecting it"
                );
                break;
            }
            Err(e) => {
                eprintln!("aegis: reading from {name:?}: {e}");
                break;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let msg: Value = match serde_json::from_str(&line) {
            Ok(msg) => msg,
            Err(e) => {
                eprintln!("aegis: {name:?} sent invalid JSON: {e}");
                continue;
            }
        };
        let id = msg.get("id").cloned();
        match (msg.get("method").is_some(), id) {
            // A response to one of our requests.
            (false, Some(id)) => {
                let tx = match id.as_u64() {
                    Some(id) => pending.lock().await.remove(&id),
                    None => None,
                };
                if let Some(tx) = tx {
                    let _ = tx.send(msg);
                }
            }
            // A server-initiated request (sampling, elicitation, roots, ...).
            // Not supported yet: refuse it rather than leave the server hanging.
            (true, Some(id)) => {
                let reply = serde_json::json!({
                    "jsonrpc": "2.0",
                    "id": id,
                    "error": { "code": -32601, "message": "not supported through aegis" },
                });
                if let Err(e) = write_line(&writer, &reply).await {
                    eprintln!("aegis: writing to {name:?}: {e}");
                }
            }
            // Notifications (logging, progress, list_changed) are dropped for now.
            (_, None) => {}
        }
    }
    // Dropping the senders fails every in-flight request, and later ones
    // fail straight away.
    closed.store(true, Ordering::Release);
    pending.lock().await.clear();
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn lines(input: &[u8], max: usize) -> Vec<String> {
        // A tiny buffer forces lines to arrive in several chunks.
        let mut reader = BufReader::with_capacity(4, input);
        let mut out = Vec::new();
        loop {
            match read_line_limited(&mut reader, max).await.unwrap() {
                Line::Text(t) => out.push(t),
                Line::TooLong(n) => out.push(format!("<too long: {n}>")),
                Line::Eof => return out,
            }
        }
    }

    #[tokio::test]
    async fn long_lines_are_dropped_whole() {
        let got = lines(b"short\n0123456789abcdef\nok\ntail", 8).await;
        assert_eq!(got, ["short", "<too long: 16>", "ok", "tail"]);
    }
}
