use std::collections::HashMap;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::thread;

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use portable_pty::{native_pty_system, CommandBuilder, MasterPty, PtySize};

use crate::fsops::contained;

pub struct PtySession {
    writer: Mutex<Box<dyn Write + Send>>,
    master: Mutex<Box<dyn MasterPty + Send>>,
    child: Mutex<Box<dyn portable_pty::Child + Send + Sync>>,
}

#[derive(Default)]
pub struct PtyHub {
    sessions: Mutex<HashMap<String, Arc<PtySession>>>,
}

fn default_shell() -> (String, CommandBuilder) {
    #[cfg(windows)]
    {
        let name = "powershell.exe".to_string();
        let mut cmd = CommandBuilder::new("powershell.exe");
        cmd.arg("-NoLogo");
        (name, cmd)
    }
    #[cfg(not(windows))]
    {
        let name = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
        let cmd = CommandBuilder::new(&name);
        (name, cmd)
    }
}

#[cfg(not(windows))]
fn has_bwrap() -> bool {
    ["/usr/bin/bwrap", "/usr/local/bin/bwrap"]
        .iter()
        .any(|p| Path::new(p).exists())
}

fn build_command(cwd: &Path, root: &Path) -> (String, CommandBuilder) {
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        if has_bwrap() {
            let shell = std::env::var("SHELL").unwrap_or_else(|_| "/bin/bash".into());
            let rel = cwd.strip_prefix(root).unwrap_or(Path::new(""));
            let chdir = if rel.as_os_str().is_empty() {
                "/work".to_string()
            } else {
                format!("/work/{}", rel.to_string_lossy())
            };
            let mut cmd = CommandBuilder::new("bwrap");
            cmd.arg("--die-with-parent");
            cmd.arg("--unshare-pid");
            cmd.arg("--dev");
            cmd.arg("/dev");
            cmd.arg("--proc");
            cmd.arg("/proc");
            cmd.arg("--tmpfs");
            cmd.arg("/tmp");
            cmd.arg("--bind");
            cmd.arg(root.as_os_str());
            cmd.arg("/work");
            cmd.arg("--chdir");
            cmd.arg(&chdir);
            for p in ["/usr", "/bin", "/lib", "/lib64", "/etc"] {
                if Path::new(p).exists() {
                    cmd.arg("--ro-bind");
                    cmd.arg(p);
                    cmd.arg(p);
                }
            }
            cmd.arg(&shell);
            return (format!("bwrap:{shell}"), cmd);
        }
    }
    let (name, mut cmd) = default_shell();
    cmd.cwd(cwd);
    let _ = root;
    (name, cmd)
}

impl PtyHub {
    pub fn open(
        &self,
        id: String,
        root: PathBuf,
        cwd: PathBuf,
        cols: u16,
        rows: u16,
        on_data: impl Fn(Vec<u8>) + Send + 'static,
        on_exit: impl FnOnce() + Send + 'static,
    ) -> Result<(String, String), String> {
        if !contained(&root, &cwd) {
            return Err("cwd outside sandbox".into());
        }
        std::fs::create_dir_all(&cwd).map_err(|e| e.to_string())?;
        let pair = native_pty_system()
            .openpty(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())?;
        let (shell, cmd) = build_command(&cwd, &root);
        let child = pair.slave.spawn_command(cmd).map_err(|e| e.to_string())?;
        let mut reader = pair.master.try_clone_reader().map_err(|e| e.to_string())?;
        let writer = pair.master.take_writer().map_err(|e| e.to_string())?;
        let session = Arc::new(PtySession {
            writer: Mutex::new(writer),
            master: Mutex::new(pair.master),
            child: Mutex::new(child),
        });
        self.sessions.lock().expect("pty").insert(id.clone(), session.clone());
        thread::spawn(move || {
            let mut buf = [0u8; 4096];
            loop {
                match reader.read(&mut buf) {
                    Ok(0) => break,
                    Ok(n) => on_data(buf[..n].to_vec()),
                    Err(_) => break,
                }
            }
            on_exit();
        });
        Ok((shell, cwd.to_string_lossy().into_owned()))
    }

    pub fn write(&self, id: &str, data: &[u8]) -> Result<(), String> {
        let session = {
            let map = self.sessions.lock().expect("pty");
            map.get(id).cloned().ok_or_else(|| "no session".to_string())?
        };
        let mut writer = session.writer.lock().expect("w");
        writer.write_all(data).map_err(|e| e.to_string())
    }

    pub fn resize(&self, id: &str, cols: u16, rows: u16) -> Result<(), String> {
        let session = {
            let map = self.sessions.lock().expect("pty");
            map.get(id).cloned().ok_or_else(|| "no session".to_string())?
        };
        let master = session.master.lock().expect("m");
        master
            .resize(PtySize {
                rows,
                cols,
                pixel_width: 0,
                pixel_height: 0,
            })
            .map_err(|e| e.to_string())
    }

    pub fn close(&self, id: &str) {
        if let Some(s) = self.sessions.lock().expect("pty").remove(id) {
            let _ = s.child.lock().expect("c").kill();
        }
    }
}

pub fn b64(data: &[u8]) -> String {
    B64.encode(data)
}

pub fn b64_decode(s: &str) -> Result<Vec<u8>, String> {
    B64.decode(s).map_err(|e| e.to_string())
}
