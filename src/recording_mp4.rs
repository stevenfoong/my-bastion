// Changed for My Bastion (2026). Derived from sol1/rustguac, Apache-2.0; see NOTICE.
//! MP4 downloads of recordings (#241).
//!
//! A `.guac` recording only plays inside mybastion. guacenc, which comes with
//! guacamole-server, turns one into a video, so a recording can be offered as
//! an MP4 that plays anywhere. Conversion takes a while on a long session, so
//! it runs in the background on request and the result is cached:
//!
//! - guacenc writes `<input>.m4v` next to its input. The recording directory
//!   is left alone: each job links the recording into a private work
//!   directory inside the cache and converts the link there, then moves the
//!   finished file to `<cache>/<recording stem>.mp4`. A file at that name is
//!   always complete; a failed or abandoned job leaves only its work
//!   directory, which is removed.
//! - guacenc exits 0 even when it fails, so success is the output file
//!   existing and not being empty.
//! - A recording still being written (its session is live) is not converted.
//! - At most `mp4_max_jobs` conversions run at once; the rest wait.
//! - Cached MP4s go after `mp4_cache_hours`, when their recording goes, and
//!   all at once when rotation needs disk space.

use crate::config::RecordingConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime};
use tokio::sync::Semaphore;

/// Where a recording stands with respect to its MP4.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Mp4State {
    /// Conversion is turned off or guacenc is not installed.
    Unavailable,
    /// Not converted, or the conversion has gone from the cache.
    None,
    /// Being converted, or waiting for a free slot.
    Running,
    /// Converted: the MP4 is ready to download.
    Ready { size_bytes: u64 },
    /// The last attempt failed; asking again retries it.
    Failed(String),
}

/// What happened when a conversion was asked for.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StartOutcome {
    Started,
    AlreadyRunning,
    AlreadyReady {
        size_bytes: u64,
    },
    Unavailable,
    /// The recording's session is still live, so the file is incomplete.
    Live,
    NotFound,
}

pub struct Mp4Converter {
    enabled: bool,
    guacenc: PathBuf,
    recording_dir: PathBuf,
    cache_dir: PathBuf,
    cache_max_age: Duration,
    timeout: Duration,
    bitrate: u32,
    max_size: (u32, u32),
    slots: Arc<Semaphore>,
    /// Jobs not yet finished, and the reason for the last failure, by
    /// recording name. Absent: nothing in progress (look at the cache).
    jobs: Mutex<HashMap<String, Job>>,
}

#[derive(Debug, Clone)]
enum Job {
    Running,
    Failed(String),
}

impl Mp4Converter {
    pub fn new(cfg: &RecordingConfig, recording_dir: &Path) -> Self {
        let cache_dir = cfg
            .mp4_cache_path
            .clone()
            .unwrap_or_else(|| recording_dir.join("mp4-cache"));
        let installed = is_executable(&cfg.guacenc_path);
        if cfg.mp4_enabled && !installed {
            tracing::info!(
                path = %cfg.guacenc_path.display(),
                "guacenc not found, so MP4 downloads of recordings are off"
            );
        }
        Self {
            enabled: cfg.mp4_enabled && installed,
            guacenc: cfg.guacenc_path.clone(),
            recording_dir: recording_dir.to_path_buf(),
            cache_dir,
            cache_max_age: Duration::from_secs(cfg.mp4_cache_hours.max(1) * 3600),
            timeout: Duration::from_secs(cfg.mp4_timeout_secs.max(10)),
            bitrate: cfg.mp4_bitrate.max(100_000),
            max_size: (cfg.mp4_max_width.max(16), cfg.mp4_max_height.max(16)),
            slots: Arc::new(Semaphore::new(cfg.mp4_max_jobs.max(1) as usize)),
            jobs: Mutex::new(HashMap::new()),
        }
    }

    pub fn enabled(&self) -> bool {
        self.enabled
    }

    /// The finished MP4 for a recording, once converted. Only ever a
    /// complete file: jobs move their output here when done.
    pub fn mp4_path(&self, name: &str) -> PathBuf {
        let stem = name.strip_suffix(".guac").unwrap_or(name);
        self.cache_dir.join(format!("{stem}.mp4"))
    }

    /// The cached MP4's size, if it exists and is at least as new as its
    /// recording.
    fn ready_size(&self, name: &str) -> Option<u64> {
        let mp4 = std::fs::metadata(self.mp4_path(name)).ok()?;
        let guac = std::fs::metadata(self.recording_dir.join(name)).ok()?;
        let fresh = match (mp4.modified(), guac.modified()) {
            (Ok(m), Ok(g)) => m >= g,
            _ => false,
        };
        (fresh && mp4.len() > 0).then_some(mp4.len())
    }

    pub fn state(&self, name: &str) -> Mp4State {
        if !self.enabled {
            return Mp4State::Unavailable;
        }
        match self.jobs.lock().unwrap().get(name) {
            Some(Job::Running) => return Mp4State::Running,
            Some(Job::Failed(why)) => return Mp4State::Failed(why.clone()),
            None => {}
        }
        match self.ready_size(name) {
            Some(size_bytes) => Mp4State::Ready { size_bytes },
            None => Mp4State::None,
        }
    }

    /// Start converting `name` unless it is converted, being converted, live
    /// or missing. `live` is whether its session is still recording.
    pub fn start(self: &Arc<Self>, name: &str, live: bool, who: &str) -> StartOutcome {
        if !self.enabled {
            return StartOutcome::Unavailable;
        }
        let guac = self.recording_dir.join(name);
        if !guac.is_file() {
            return StartOutcome::NotFound;
        }
        if live {
            return StartOutcome::Live;
        }
        {
            let mut jobs = self.jobs.lock().unwrap();
            if matches!(jobs.get(name), Some(Job::Running)) {
                return StartOutcome::AlreadyRunning;
            }
            if let Some(size_bytes) = self.ready_size(name) {
                jobs.remove(name);
                return StartOutcome::AlreadyReady { size_bytes };
            }
            jobs.insert(name.to_string(), Job::Running);
        }
        tracing::info!(user = %who, recording = %name, "MP4 conversion requested");
        let this = Arc::clone(self);
        let name = name.to_string();
        tokio::spawn(async move {
            let result = this.convert(&name, &guac).await;
            let mut jobs = this.jobs.lock().unwrap();
            match result {
                Ok(()) => {
                    tracing::info!(recording = %name, "MP4 conversion finished");
                    jobs.remove(&name);
                }
                Err(why) => {
                    tracing::warn!(recording = %name, reason = %why, "MP4 conversion failed");
                    jobs.insert(name, Job::Failed(why));
                }
            }
        });
        StartOutcome::Started
    }

    async fn convert(&self, name: &str, guac: &Path) -> Result<(), String> {
        let _slot = self
            .slots
            .clone()
            .acquire_owned()
            .await
            .map_err(|_| "converter shut down".to_string())?;
        tokio::fs::create_dir_all(&self.cache_dir)
            .await
            .map_err(|e| format!("cannot create the MP4 cache: {e}"))?;
        let work = self
            .cache_dir
            .join(format!(".work-{}", uuid::Uuid::new_v4()));
        let result = self.convert_in(name, guac, &work).await;
        let _ = tokio::fs::remove_dir_all(&work).await;
        result
    }

    async fn convert_in(&self, name: &str, guac: &Path, work: &Path) -> Result<(), String> {
        tokio::fs::create_dir(work)
            .await
            .map_err(|e| format!("cannot create a work directory: {e}"))?;
        let source = tokio::fs::canonicalize(guac)
            .await
            .map_err(|_| "the recording has gone".to_string())?;
        let link = work.join(name);
        tokio::fs::symlink(&source, &link)
            .await
            .map_err(|e| format!("cannot link the recording: {e}"))?;

        let size = {
            let source = source.clone();
            tokio::task::spawn_blocking(move || recording_size(&source))
                .await
                .ok()
                .flatten()
        };
        let (w, h) = fit_size(size, self.max_size);

        let mut child = tokio::process::Command::new(&self.guacenc)
            .arg("-s")
            .arg(format!("{w}x{h}"))
            .arg("-r")
            .arg(self.bitrate.to_string())
            .arg(&link)
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| format!("cannot run guacenc: {e}"))?;
        match tokio::time::timeout(self.timeout, child.wait()).await {
            Ok(Ok(_)) => {}
            Ok(Err(e)) => return Err(format!("guacenc did not finish: {e}")),
            Err(_) => {
                let _ = child.kill().await;
                return Err(format!(
                    "took longer than {} seconds",
                    self.timeout.as_secs()
                ));
            }
        }

        // guacenc exits 0 whatever happened: the output is the verdict.
        let produced = work.join(format!("{name}.m4v"));
        match tokio::fs::metadata(&produced).await {
            Ok(m) if m.len() > 0 => {}
            _ => return Err("guacenc produced no video".to_string()),
        }
        tokio::fs::rename(&produced, self.mp4_path(name))
            .await
            .map_err(|e| format!("cannot store the MP4: {e}"))
    }

    /// Remove cached MP4s older than `mp4_cache_hours` or whose recording
    /// has gone (all of them when `everything`), and work directories of
    /// jobs no longer running. Returns how many files went.
    pub fn purge(&self, everything: bool) -> usize {
        let entries = match std::fs::read_dir(&self.cache_dir) {
            Ok(e) => e,
            Err(_) => return 0,
        };
        let running = self
            .jobs
            .lock()
            .unwrap()
            .values()
            .any(|j| matches!(j, Job::Running));
        let now = SystemTime::now();
        let mut removed = 0;
        for entry in entries.flatten() {
            let path = entry.path();
            let file_name = entry.file_name().to_string_lossy().to_string();
            if file_name.starts_with(".work-") {
                // A work directory belongs to a running job, or to one that
                // died with the process.
                if !running && std::fs::remove_dir_all(&path).is_ok() {
                    removed += 1;
                }
                continue;
            }
            let Some(stem) = file_name.strip_suffix(".mp4") else {
                continue;
            };
            let orphaned = !self.recording_dir.join(format!("{stem}.guac")).exists();
            let expired = entry
                .metadata()
                .and_then(|m| m.modified())
                .ok()
                .and_then(|t| now.duration_since(t).ok())
                .is_some_and(|age| age > self.cache_max_age);
            if (everything || orphaned || expired) && std::fs::remove_file(&path).is_ok() {
                removed += 1;
            }
        }
        removed
    }
}

fn is_executable(path: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// The size of a recording's display: the largest size given to the default
/// layer (layer 0) in its first few megabytes, which is where the session
/// sets it. `None` when none is found.
pub fn recording_size(path: &Path) -> Option<(u32, u32)> {
    use std::io::Read;
    let mut head = Vec::new();
    std::fs::File::open(path)
        .ok()?
        .take(4 * 1024 * 1024)
        .read_to_end(&mut head)
        .ok()?;
    largest_layer0_size(&String::from_utf8_lossy(&head))
}

/// Walk Guacamole instructions (`LEN.VALUE,LEN.VALUE;`, lengths counted in
/// characters) and return the largest `size` of layer 0. Stops at the first
/// malformed or truncated element.
fn largest_layer0_size(text: &str) -> Option<(u32, u32)> {
    let mut chars = text.chars().peekable();
    let mut best: Option<(u32, u32)> = None;
    let mut instruction: Vec<String> = Vec::new();
    loop {
        let mut len = String::new();
        while let Some(c) = chars.peek() {
            if c.is_ascii_digit() {
                len.push(*c);
                chars.next();
            } else {
                break;
            }
        }
        if len.is_empty() || chars.next() != Some('.') {
            return best;
        }
        let n: usize = len.parse().ok()?;
        let value: String = chars.by_ref().take(n).collect();
        if value.chars().count() != n {
            return best;
        }
        instruction.push(value);
        match chars.next() {
            Some(',') => {}
            Some(';') => {
                if instruction.len() == 4 && instruction[0] == "size" && instruction[1] == "0" {
                    if let (Ok(w), Ok(h)) = (instruction[2].parse(), instruction[3].parse()) {
                        let area = |(w, h): (u32, u32)| u64::from(w) * u64::from(h);
                        if best.is_none_or(|b| area((w, h)) > area(b)) {
                            best = Some((w, h));
                        }
                    }
                }
                instruction.clear();
            }
            _ => return best,
        }
    }
}

/// The video size for a recording: its own size, scaled down to fit within
/// `max` keeping its shape, rounded down to even numbers (the encoder needs
/// them). 1280 x 720 when the recording's size is unknown.
pub fn fit_size(size: Option<(u32, u32)>, max: (u32, u32)) -> (u32, u32) {
    let (w, h) = match size {
        Some((w, h)) if w > 0 && h > 0 => (w, h),
        _ => (1280, 720),
    };
    let scale = (max.0 as f64 / w as f64)
        .min(max.1 as f64 / h as f64)
        .min(1.0);
    let even = |v: f64| ((v.floor() as u32) & !1).max(2);
    (even(w as f64 * scale), even(h as f64 * scale))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn config(dir: &Path, guacenc: &Path) -> RecordingConfig {
        RecordingConfig {
            path: dir.to_path_buf(),
            guacenc_path: guacenc.to_path_buf(),
            ..RecordingConfig::default()
        }
    }

    struct Scratch(PathBuf);
    impl Scratch {
        fn new(name: &str) -> Self {
            let p =
                std::env::temp_dir().join(format!("mybastion-mp4-{}-{}", name, std::process::id()));
            let _ = std::fs::remove_dir_all(&p);
            std::fs::create_dir_all(&p).unwrap();
            Scratch(p)
        }
    }
    impl Drop for Scratch {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// A stand-in guacenc: a shell script that behaves like the real one
    /// (writes `<input>.m4v` next to its input and exits 0), or one that
    /// writes nothing, as guacenc does when it fails.
    fn fake_guacenc(dir: &Path, works: bool) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let p = dir.join(if works { "guacenc-ok" } else { "guacenc-bad" });
        let body = if works {
            "#!/bin/sh\nfor a; do last=\"$a\"; done\nprintf video > \"$last.m4v\"\nexit 0\n"
        } else {
            "#!/bin/sh\nexit 0\n"
        };
        std::fs::write(&p, body).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    async fn settle(conv: &Arc<Mp4Converter>, name: &str) -> Mp4State {
        for _ in 0..200 {
            let s = conv.state(name);
            if s != Mp4State::Running {
                return s;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        panic!("conversion never finished");
    }

    #[test]
    fn finds_the_recordings_own_size() {
        let rec = "4.size,2.-6,2.41,2.39;4.size,1.0,4.1280,3.720;4.size,1.1,2.10,2.10;\
                   4.size,1.0,4.2556,4.1278;3.png,1.0,2.ab;";
        assert_eq!(largest_layer0_size(rec), Some((2556, 1278)));
        // Lengths count characters, not bytes.
        assert_eq!(
            largest_layer0_size("4.name,3.é?é;4.size,1.0,3.800,3.600;"),
            Some((800, 600))
        );
        assert_eq!(largest_layer0_size("4.sync,1.0;"), None);
        // A truncated tail keeps what was found before it.
        assert_eq!(
            largest_layer0_size("4.size,1.0,3.800,3.600;4.size,1.0,4.99"),
            Some((800, 600))
        );
    }

    #[test]
    fn video_size_fits_and_is_even() {
        assert_eq!(fit_size(Some((1280, 720)), (1920, 1080)), (1280, 720));
        assert_eq!(fit_size(Some((2556, 1278)), (1920, 1080)), (1920, 960));
        assert_eq!(fit_size(Some((1023, 767)), (1920, 1080)), (1022, 766));
        assert_eq!(fit_size(None, (1920, 1080)), (1280, 720));
        assert_eq!(fit_size(Some((0, 0)), (1920, 1080)), (1280, 720));
    }

    #[tokio::test]
    async fn converts_into_the_cache_and_leaves_the_recordings_alone() {
        let s = Scratch::new("convert");
        let rec = s.0.join("rec");
        std::fs::create_dir_all(&rec).unwrap();
        std::fs::write(rec.join("a.guac"), "4.size,1.0,4.1280,3.720;").unwrap();
        let conv = Arc::new(Mp4Converter::new(
            &config(&rec, &fake_guacenc(&s.0, true)),
            &rec,
        ));
        assert_eq!(conv.state("a.guac"), Mp4State::None);
        assert_eq!(conv.start("a.guac", false, "u"), StartOutcome::Started);
        assert_eq!(
            settle(&conv, "a.guac").await,
            Mp4State::Ready { size_bytes: 5 }
        );
        assert!(conv.mp4_path("a.guac").ends_with("mp4-cache/a.mp4"));
        // Nothing new beside the recording, and no work directory left.
        let beside: Vec<_> = std::fs::read_dir(&rec)
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(beside.len(), 2, "{beside:?}");
        let cached: Vec<_> = std::fs::read_dir(rec.join("mp4-cache"))
            .unwrap()
            .map(|e| e.unwrap().file_name().into_string().unwrap())
            .collect();
        assert_eq!(cached, vec!["a.mp4".to_string()]);
        // Asking again reuses it.
        assert_eq!(
            conv.start("a.guac", false, "u"),
            StartOutcome::AlreadyReady { size_bytes: 5 }
        );
    }

    #[tokio::test]
    async fn no_output_is_a_failure_and_leaves_nothing() {
        let s = Scratch::new("fail");
        let rec = s.0.join("rec");
        std::fs::create_dir_all(&rec).unwrap();
        std::fs::write(rec.join("b.guac"), "x").unwrap();
        let conv = Arc::new(Mp4Converter::new(
            &config(&rec, &fake_guacenc(&s.0, false)),
            &rec,
        ));
        assert_eq!(conv.start("b.guac", false, "u"), StartOutcome::Started);
        assert!(matches!(settle(&conv, "b.guac").await, Mp4State::Failed(_)));
        assert_eq!(std::fs::read_dir(rec.join("mp4-cache")).unwrap().count(), 0);
    }

    #[test]
    fn live_missing_and_unavailable_are_not_converted() {
        let s = Scratch::new("refuse");
        let rec = s.0.join("rec");
        std::fs::create_dir_all(&rec).unwrap();
        std::fs::write(rec.join("c.guac"), "x").unwrap();
        let rt = tokio::runtime::Runtime::new().unwrap();
        let _g = rt.enter();
        let conv = Arc::new(Mp4Converter::new(
            &config(&rec, &fake_guacenc(&s.0, true)),
            &rec,
        ));
        assert_eq!(conv.start("c.guac", true, "u"), StartOutcome::Live);
        assert_eq!(conv.start("gone.guac", false, "u"), StartOutcome::NotFound);
        let off = Arc::new(Mp4Converter::new(
            &config(&rec, &s.0.join("no-such-guacenc")),
            &rec,
        ));
        assert!(!off.enabled());
        assert_eq!(off.start("c.guac", false, "u"), StartOutcome::Unavailable);
        assert_eq!(off.state("c.guac"), Mp4State::Unavailable);
    }

    #[test]
    fn purge_removes_orphans_work_dirs_and_everything_on_request() {
        let s = Scratch::new("purge");
        let rec = s.0.join("rec");
        let cache = rec.join("mp4-cache");
        std::fs::create_dir_all(cache.join(".work-old")).unwrap();
        std::fs::write(rec.join("kept.guac"), "x").unwrap();
        std::fs::write(cache.join("kept.mp4"), "v").unwrap();
        std::fs::write(cache.join("orphan.mp4"), "v").unwrap();
        let conv = Mp4Converter::new(&config(&rec, &fake_guacenc(&s.0, true)), &rec);
        assert_eq!(conv.purge(false), 2, "the orphan and the dead work dir");
        assert!(cache.join("kept.mp4").exists());
        assert_eq!(conv.purge(true), 1);
        assert!(!cache.join("kept.mp4").exists());
    }
}
