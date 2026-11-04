//! A headless Guacamole client: owns a session's guacd stream in place of a
//! browser, keeps the screen in a `Display`, answers `sync` so guacd keeps
//! streaming, and tees the raw stream to the session recording.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use image::imageops::FilterType;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::watch;
use tokio_util::sync::CancellationToken;

use super::display::{Display, Reply};
use crate::guacd::GuacdStream;
use crate::protocol::{last_instruction_boundary, Instruction, InstructionParser};

/// Guacamole's `UNSUPPORTED` status, for streams the renderer refuses.
const UNSUPPORTED: &str = "256";
/// Bound on bytes held while waiting for the end of an instruction.
const MAX_CARRY: usize = 16 * 1024 * 1024;

type Writer = Arc<tokio::sync::Mutex<tokio::io::WriteHalf<GuacdStream>>>;

/// How the connection ended.
#[derive(Debug, Clone)]
pub struct Ended {
    /// guacd's error or disconnect, if it gave one.
    pub reason: Option<String>,
    /// guacd sent `disconnect` (the remote side ended it).
    pub server_disconnected: bool,
}

pub struct Headless {
    display: Mutex<Display>,
    /// Frames completed so far (`sync`s from guacd).
    frames: watch::Sender<u64>,
    ended: Mutex<Option<Ended>>,
    writer: Writer,
    cancel: CancellationToken,
}

/// A screenshot: PNG bytes, the screen's size and the image's.
pub struct Shot {
    pub png: Vec<u8>,
    pub screen: (u32, u32),
    pub image: (u32, u32),
}

impl Headless {
    /// Start reading `stream`. The task ends with the connection, or when
    /// `cancel` (the session's) fires.
    pub fn start(
        stream: GuacdStream,
        cancel: CancellationToken,
        recording: Option<tokio::fs::File>,
    ) -> (Arc<Self>, tokio::task::JoinHandle<Ended>) {
        let (read, write) = tokio::io::split(stream);
        let (frames, _) = watch::channel(0u64);
        let client = Arc::new(Headless {
            display: Mutex::new(Display::new()),
            frames,
            ended: Mutex::new(None),
            writer: Arc::new(tokio::sync::Mutex::new(write)),
            cancel,
        });
        let task = tokio::spawn(client.clone().run(read, recording));
        (client, task)
    }

    async fn run(
        self: Arc<Self>,
        mut read: tokio::io::ReadHalf<GuacdStream>,
        mut recording: Option<tokio::fs::File>,
    ) -> Ended {
        let mut buf = vec![0u8; 65536];
        let mut carry: Vec<u8> = Vec::new();
        let mut parser = InstructionParser::new();
        let ended = loop {
            let n = tokio::select! {
                _ = self.cancel.cancelled() => break Ended { reason: None, server_disconnected: false },
                r = read.read(&mut buf) => r,
            };
            let n = match n {
                Ok(0) => {
                    break Ended {
                        reason: Some("guacd closed the connection".into()),
                        server_disconnected: false,
                    }
                }
                Ok(n) => n,
                Err(e) => {
                    break Ended {
                        reason: Some(e.to_string()),
                        server_disconnected: false,
                    }
                }
            };
            if let Some(f) = recording.as_mut() {
                let _ = f.write_all(&buf[..n]).await;
            }
            carry.extend_from_slice(&buf[..n]);
            let Some(end) = last_instruction_boundary(&carry) else {
                if carry.len() > MAX_CARRY {
                    break Ended {
                        reason: Some("instruction too large".into()),
                        server_disconnected: false,
                    };
                }
                continue;
            };
            let text = String::from_utf8_lossy(&carry[..end]).into_owned();
            carry.drain(..end);
            let mut replies = Vec::new();
            let mut stop = None;
            {
                let mut display = self.display.lock().unwrap_or_else(|e| e.into_inner());
                for ins in parser.receive(&text).into_iter().flatten() {
                    match display.apply(&ins.opcode, &ins.args) {
                        Reply::None => {}
                        Reply::Sync(ts) => {
                            replies.push(Instruction::new("sync", vec![ts]).encode());
                            self.frames.send_modify(|f| *f += 1);
                        }
                        Reply::RefuseStream(s) => replies.push(
                            Instruction::new(
                                "ack",
                                vec![s, "Unsupported".into(), UNSUPPORTED.into()],
                            )
                            .encode(),
                        ),
                        Reply::End(reason) => {
                            stop = Some(Ended {
                                server_disconnected: ins.opcode == "disconnect",
                                reason: Some(reason),
                            });
                            break;
                        }
                    }
                }
            }
            if !replies.is_empty() {
                if let Err(e) = self
                    .writer
                    .lock()
                    .await
                    .write_all(replies.concat().as_bytes())
                    .await
                {
                    break Ended {
                        reason: Some(e.to_string()),
                        server_disconnected: false,
                    };
                }
            }
            if let Some(s) = stop {
                break s;
            }
        };
        *self.ended.lock().unwrap_or_else(|e| e.into_inner()) = Some(ended.clone());
        // Wake anyone waiting for a frame.
        self.frames.send_modify(|_| {});
        ended
    }

    /// Why it ended, once it has.
    pub fn ended(&self) -> Option<Ended> {
        self.ended.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// The screen's size now; (0, 0) before guacd has sized it.
    pub fn screen_size(&self) -> (u32, u32) {
        self.display
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .size()
    }

    pub fn frames(&self) -> u64 {
        *self.frames.borrow()
    }

    /// Wait until a frame after `after` is complete, the connection ends, or
    /// `timeout` passes. Whether a new frame came.
    pub async fn wait_frame(&self, after: u64, timeout: Duration) -> bool {
        let mut rx = self.frames.subscribe();
        tokio::time::timeout(timeout, async {
            loop {
                if *rx.borrow_and_update() > after {
                    return true;
                }
                if self.ended().is_some() || rx.changed().await.is_err() {
                    return false;
                }
            }
        })
        .await
        .unwrap_or(false)
    }

    /// The screen as a PNG, scaled down to at most `max_width` wide.
    pub fn screenshot(&self, max_width: u32) -> Result<Shot, String> {
        let img = self
            .display
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .screen();
        let screen = img.dimensions();
        if screen.0 == 0 || screen.1 == 0 {
            return Err("nothing on the screen yet".into());
        }
        let img = if screen.0 > max_width && max_width > 0 {
            let h = ((screen.1 as u64 * max_width as u64) / screen.0 as u64).max(1) as u32;
            image::imageops::resize(&img, max_width, h, FilterType::Triangle)
        } else {
            img
        };
        let mut out = std::io::Cursor::new(Vec::new());
        image::DynamicImage::ImageRgba8(img.clone())
            .to_rgb8()
            .write_to(&mut out, image::ImageFormat::Png)
            .map_err(|e| e.to_string())?;
        Ok(Shot {
            png: out.into_inner(),
            screen,
            image: img.dimensions(),
        })
    }

    /// Send instructions to guacd (input, from the tools that act).
    pub async fn send(&self, data: &str) -> Result<(), String> {
        self.writer
            .lock()
            .await
            .write_all(data.as_bytes())
            .await
            .map_err(|e| e.to_string())
    }
}
