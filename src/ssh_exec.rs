//! Run one command on an SSH target and collect its output: the command mode
//! (`run_ssh`) of the policy engine, where every command can be checked and
//! approved before it reaches the target. Goes through the entry's jump-host
//! chain when it has one.

use russh::ChannelMsg;
use serde::Serialize;
use std::time::Duration;

use crate::tunnel::{self, JumpHost};

/// Where to run it and as whom.
pub struct ExecTarget {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: Option<String>,
    pub private_key: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct ExecOutput {
    /// `None` when the command was killed by a signal or timed out.
    pub exit_status: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signal: Option<String>,
    pub stdout: String,
    pub stderr: String,
    /// Output beyond `max_bytes` (per stream) was dropped.
    pub truncated: bool,
    pub timed_out: bool,
    pub duration_ms: u128,
}

fn push_capped(buf: &mut Vec<u8>, data: &[u8], max: usize, truncated: &mut bool) {
    let room = max.saturating_sub(buf.len());
    if data.len() > room {
        *truncated = true;
    }
    buf.extend_from_slice(&data[..data.len().min(room)]);
}

/// Run `command` on `target`, through `hops` when there are any. Waits at
/// most `timeout` for it to finish and keeps at most `max_bytes` of stdout
/// and of stderr. Errors are for connection, authentication or channel
/// failures; a command that fails is an `ExecOutput` with its exit status.
pub async fn run(
    target: &ExecTarget,
    hops: &[JumpHost],
    command: &str,
    timeout: Duration,
    max_bytes: usize,
) -> Result<ExecOutput, String> {
    let started = std::time::Instant::now();
    // Keep the tunnels alive until the command is done.
    let (_tunnels, addr) = if hops.is_empty() {
        (Vec::new(), format!("{}:{}", target.host, target.port))
    } else {
        let (tunnels, local) = tunnel::start_chain(hops, &target.host, target.port)
            .await
            .map_err(|e| e.to_string())?;
        (tunnels, local.to_string())
    };

    let handle = tunnel::connect_authenticated(
        &addr,
        &target.username,
        target.password.as_deref(),
        target.private_key.as_deref(),
        None,
        hops.len(),
    )
    .await
    .map_err(|e| e.to_string())?;

    let mut channel = handle
        .channel_open_session()
        .await
        .map_err(|e| format!("cannot open an SSH session channel: {}", e))?;
    channel
        .exec(true, command)
        .await
        .map_err(|e| format!("cannot start the command: {}", e))?;

    let (mut stdout, mut stderr) = (Vec::new(), Vec::new());
    let mut truncated = false;
    let mut exit_status = None;
    let mut signal = None;
    let collect = async {
        while let Some(msg) = channel.wait().await {
            match msg {
                ChannelMsg::Data { data } => {
                    push_capped(&mut stdout, &data, max_bytes, &mut truncated)
                }
                ChannelMsg::ExtendedData { data, ext: 1 } => {
                    push_capped(&mut stderr, &data, max_bytes, &mut truncated)
                }
                ChannelMsg::ExitStatus { exit_status: s } => exit_status = Some(s),
                ChannelMsg::ExitSignal { signal_name, .. } => {
                    signal = Some(format!("{:?}", signal_name))
                }
                _ => {}
            }
        }
    };
    let timed_out = tokio::time::timeout(timeout, collect).await.is_err();
    if timed_out {
        let _ = channel.close().await;
    }
    let _ = handle
        .disconnect(russh::Disconnect::ByApplication, "", "")
        .await;

    Ok(ExecOutput {
        exit_status,
        signal,
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
        truncated,
        timed_out,
        duration_ms: started.elapsed().as_millis(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn output_is_capped_per_stream() {
        let (mut buf, mut cut) = (Vec::new(), false);
        push_capped(&mut buf, b"hello ", 8, &mut cut);
        assert!(!cut);
        push_capped(&mut buf, b"world", 8, &mut cut);
        assert_eq!((buf.as_slice(), cut), (&b"hello wo"[..], true));
        push_capped(&mut buf, b"more", 8, &mut cut);
        assert_eq!(buf.len(), 8);
    }
}
