use std::path::{Path, PathBuf};

use walkdir::WalkDir;

pub fn contained(root: &Path, candidate: &Path) -> bool {
    let root = std::fs::canonicalize(root).unwrap_or_else(|_| root.to_path_buf());
    let cand = if candidate.exists() {
        std::fs::canonicalize(candidate).unwrap_or_else(|_| candidate.to_path_buf())
    } else if let Some(parent) = candidate.parent() {
        let p = std::fs::canonicalize(parent).unwrap_or_else(|_| parent.to_path_buf());
        p.join(candidate.file_name().unwrap_or_default())
    } else {
        candidate.to_path_buf()
    };
    cand.starts_with(&root)
}

pub fn join_rel(root: &Path, rel: &str) -> Result<PathBuf, String> {
    if rel.split(['/', '\\']).any(|p| p == "..") {
        return Err("path escapes the sandbox".into());
    }
    let trimmed = rel.trim_start_matches('/');
    let dest = if trimmed.is_empty() {
        root.to_path_buf()
    } else {
        root.join(trimmed)
    };
    if !contained(root, &dest) {
        return Err("path escapes the sandbox".into());
    }
    Ok(dest)
}

#[derive(serde::Serialize)]
pub struct TreeEntry {
    pub path: String,
    pub dir: bool,
    pub size: u64,
}

pub fn list_tree(root: &Path) -> Result<Vec<TreeEntry>, String> {
    std::fs::create_dir_all(root).map_err(|e| e.to_string())?;
    let mut out = Vec::new();
    for entry in WalkDir::new(root).into_iter().filter_map(|e| e.ok()) {
        let path = entry.path();
        if path == root {
            continue;
        }
        let rel = path.strip_prefix(root).map_err(|e| e.to_string())?;
        let rel = rel.to_string_lossy().replace('\\', "/");
        if rel.split('/').any(|p| p == ".git") {
            continue;
        }
        let meta = entry.metadata().map_err(|e| e.to_string())?;
        out.push(TreeEntry {
            path: rel,
            dir: meta.is_dir(),
            size: if meta.is_file() { meta.len() } else { 0 },
        });
    }
    out.sort_by(|a, b| a.path.cmp(&b.path));
    Ok(out)
}

pub fn read_file(root: &Path, rel: &str) -> Result<Vec<u8>, String> {
    let dest = join_rel(root, rel)?;
    if dest.is_dir() {
        return Err("is a directory".into());
    }
    std::fs::read(&dest).map_err(|e| e.to_string())
}

pub fn write_file(root: &Path, rel: &str, bytes: &[u8]) -> Result<(), String> {
    if bytes.len() > 12 * 1024 * 1024 {
        return Err("file too large".into());
    }
    let dest = join_rel(root, rel)?;
    if let Some(parent) = dest.parent() {
        std::fs::create_dir_all(parent).map_err(|e| e.to_string())?;
    }
    std::fs::write(&dest, bytes).map_err(|e| e.to_string())
}

pub fn remove_path(root: &Path, rel: &str) -> Result<(), String> {
    let dest = join_rel(root, rel)?;
    if dest == root {
        return Err("refused".into());
    }
    if dest.is_dir() {
        std::fs::remove_dir_all(&dest).map_err(|e| e.to_string())
    } else {
        std::fs::remove_file(&dest).map_err(|e| e.to_string())
    }
}
