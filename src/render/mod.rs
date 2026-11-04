//! Headless Guacamole rendering (Phase 3 of `docs/fork-design.md`): the
//! server holds no picture of a session's screen, so for AI agents it plays
//! the browser itself. `client.rs` owns the guacd stream as the session's
//! first (owner) connection; `display.rs` keeps the screen from guacd's
//! drawing instructions, for screenshots.

pub mod client;
pub mod display;
pub mod input;
