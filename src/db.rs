use rusqlite::{params, Connection, OptionalExtension};
use std::path::Path;
use std::sync::Mutex;

pub struct Db {
    conn: Mutex<Connection>,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct User {
    pub id: String,
    pub username: String,
    pub display_name: String,
    pub role: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Sandbox {
    pub id: String,
    pub name: String,
    pub path: String,
    pub description: String,
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct Grant {
    pub user_id: String,
    pub sandbox_id: String,
    pub can_read: bool,
    pub can_write: bool,
    pub can_shell: bool,
    pub can_admin: bool,
}

impl Db {
    pub fn open(path: &Path) -> rusqlite::Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let conn = Connection::open(path)?;
        conn.execute_batch(
            "
            PRAGMA foreign_keys = ON;
            CREATE TABLE IF NOT EXISTS users (
              id TEXT PRIMARY KEY,
              username TEXT UNIQUE NOT NULL,
              display_name TEXT NOT NULL,
              password_hash TEXT NOT NULL,
              role TEXT NOT NULL,
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id TEXT NOT NULL,
              created_at INTEGER NOT NULL,
              expires_at INTEGER NOT NULL,
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS sandboxes (
              id TEXT PRIMARY KEY,
              name TEXT NOT NULL,
              path TEXT NOT NULL,
              description TEXT NOT NULL DEFAULT '',
              created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS grants (
              user_id TEXT NOT NULL,
              sandbox_id TEXT NOT NULL,
              can_read INTEGER NOT NULL DEFAULT 1,
              can_write INTEGER NOT NULL DEFAULT 0,
              can_shell INTEGER NOT NULL DEFAULT 0,
              can_admin INTEGER NOT NULL DEFAULT 0,
              PRIMARY KEY (user_id, sandbox_id),
              FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,
              FOREIGN KEY(sandbox_id) REFERENCES sandboxes(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS meta (
              k TEXT PRIMARY KEY,
              v TEXT NOT NULL
            );
            ",
        )?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn user_count(&self) -> rusqlite::Result<i64> {
        let conn = self.conn.lock().expect("db");
        conn.query_row("SELECT COUNT(*) FROM users", [], |r| r.get(0))
    }

    pub fn insert_user(
        &self,
        id: &str,
        username: &str,
        display_name: &str,
        password_hash: &str,
        role: &str,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        conn.execute(
            "INSERT INTO users (id, username, display_name, password_hash, role, created_at) VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
            params![id, username, display_name, password_hash, role, now()],
        )?;
        Ok(())
    }

    pub fn user_by_username(&self, username: &str) -> rusqlite::Result<Option<(User, String)>> {
        let conn = self.conn.lock().expect("db");
        conn.query_row(
            "SELECT id, username, display_name, role, password_hash FROM users WHERE username = ?1",
            [username],
            |r| {
                Ok((
                    User {
                        id: r.get(0)?,
                        username: r.get(1)?,
                        display_name: r.get(2)?,
                        role: r.get(3)?,
                    },
                    r.get::<_, String>(4)?,
                ))
            },
        )
        .optional()
    }

    pub fn user_by_id(&self, id: &str) -> rusqlite::Result<Option<User>> {
        let conn = self.conn.lock().expect("db");
        conn.query_row(
            "SELECT id, username, display_name, role FROM users WHERE id = ?1",
            [id],
            |r| {
                Ok(User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                })
            },
        )
        .optional()
    }

    pub fn users(&self) -> rusqlite::Result<Vec<User>> {
        let conn = self.conn.lock().expect("db");
        let mut stmt = conn.prepare("SELECT id, username, display_name, role FROM users ORDER BY username")?;
        let rows = stmt.query_map([], |r| {
            Ok(User {
                id: r.get(0)?,
                username: r.get(1)?,
                display_name: r.get(2)?,
                role: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn update_user(
        &self,
        id: &str,
        display_name: Option<&str>,
        role: Option<&str>,
        password_hash: Option<&str>,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        if let Some(n) = display_name {
            conn.execute("UPDATE users SET display_name = ?1 WHERE id = ?2", params![n, id])?;
        }
        if let Some(role) = role {
            conn.execute("UPDATE users SET role = ?1 WHERE id = ?2", params![role, id])?;
        }
        if let Some(h) = password_hash {
            conn.execute("UPDATE users SET password_hash = ?1 WHERE id = ?2", params![h, id])?;
        }
        Ok(())
    }

    pub fn delete_user(&self, id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        conn.execute("DELETE FROM sessions WHERE user_id = ?1", [id])?;
        conn.execute("DELETE FROM grants WHERE user_id = ?1", [id])?;
        conn.execute("DELETE FROM users WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn put_session(&self, token: &str, user_id: &str, ttl_secs: i64) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        let n = now();
        conn.execute(
            "INSERT INTO sessions (token, user_id, created_at, expires_at) VALUES (?1, ?2, ?3, ?4)",
            params![token, user_id, n, n + ttl_secs],
        )?;
        Ok(())
    }

    pub fn session_user(&self, token: &str) -> rusqlite::Result<Option<User>> {
        let conn = self.conn.lock().expect("db");
        conn.query_row(
            "SELECT u.id, u.username, u.display_name, u.role
             FROM sessions s JOIN users u ON u.id = s.user_id
             WHERE s.token = ?1 AND s.expires_at > ?2",
            params![token, now()],
            |r| {
                Ok(User {
                    id: r.get(0)?,
                    username: r.get(1)?,
                    display_name: r.get(2)?,
                    role: r.get(3)?,
                })
            },
        )
        .optional()
    }

    pub fn delete_session(&self, token: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        conn.execute("DELETE FROM sessions WHERE token = ?1", [token])?;
        Ok(())
    }

    pub fn insert_sandbox(&self, id: &str, name: &str, path: &str, description: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        conn.execute(
            "INSERT INTO sandboxes (id, name, path, description, created_at) VALUES (?1, ?2, ?3, ?4, ?5)",
            params![id, name, path, description, now()],
        )?;
        Ok(())
    }

    pub fn sandbox(&self, id: &str) -> rusqlite::Result<Option<Sandbox>> {
        let conn = self.conn.lock().expect("db");
        conn.query_row(
            "SELECT id, name, path, description FROM sandboxes WHERE id = ?1",
            [id],
            |r| {
                Ok(Sandbox {
                    id: r.get(0)?,
                    name: r.get(1)?,
                    path: r.get(2)?,
                    description: r.get(3)?,
                })
            },
        )
        .optional()
    }

    pub fn sandboxes(&self) -> rusqlite::Result<Vec<Sandbox>> {
        let conn = self.conn.lock().expect("db");
        let mut stmt = conn.prepare("SELECT id, name, path, description FROM sandboxes ORDER BY name")?;
        let rows = stmt.query_map([], |r| {
            Ok(Sandbox {
                id: r.get(0)?,
                name: r.get(1)?,
                path: r.get(2)?,
                description: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    pub fn update_sandbox(
        &self,
        id: &str,
        name: Option<&str>,
        path: Option<&str>,
        description: Option<&str>,
    ) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        if let Some(n) = name {
            conn.execute("UPDATE sandboxes SET name = ?1 WHERE id = ?2", params![n, id])?;
        }
        if let Some(p) = path {
            conn.execute("UPDATE sandboxes SET path = ?1 WHERE id = ?2", params![p, id])?;
        }
        if let Some(d) = description {
            conn.execute("UPDATE sandboxes SET description = ?1 WHERE id = ?2", params![d, id])?;
        }
        Ok(())
    }

    pub fn delete_sandbox(&self, id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        conn.execute("DELETE FROM grants WHERE sandbox_id = ?1", [id])?;
        conn.execute("DELETE FROM sandboxes WHERE id = ?1", [id])?;
        Ok(())
    }

    pub fn put_grant(&self, g: &Grant) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        conn.execute(
            "INSERT INTO grants (user_id, sandbox_id, can_read, can_write, can_shell, can_admin)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(user_id, sandbox_id) DO UPDATE SET
               can_read = excluded.can_read,
               can_write = excluded.can_write,
               can_shell = excluded.can_shell,
               can_admin = excluded.can_admin",
            params![
                g.user_id,
                g.sandbox_id,
                g.can_read as i64,
                g.can_write as i64,
                g.can_shell as i64,
                g.can_admin as i64
            ],
        )?;
        Ok(())
    }

    pub fn delete_grant(&self, user_id: &str, sandbox_id: &str) -> rusqlite::Result<()> {
        let conn = self.conn.lock().expect("db");
        conn.execute(
            "DELETE FROM grants WHERE user_id = ?1 AND sandbox_id = ?2",
            params![user_id, sandbox_id],
        )?;
        Ok(())
    }

    pub fn grants(&self) -> rusqlite::Result<Vec<Grant>> {
        let conn = self.conn.lock().expect("db");
        let mut stmt = conn.prepare(
            "SELECT user_id, sandbox_id, can_read, can_write, can_shell, can_admin FROM grants",
        )?;
        let rows = stmt.query_map([], |r| {
            Ok(Grant {
                user_id: r.get(0)?,
                sandbox_id: r.get(1)?,
                can_read: r.get::<_, i64>(2)? != 0,
                can_write: r.get::<_, i64>(3)? != 0,
                can_shell: r.get::<_, i64>(4)? != 0,
                can_admin: r.get::<_, i64>(5)? != 0,
            })
        })?;
        rows.collect()
    }

    pub fn grant(&self, user_id: &str, sandbox_id: &str) -> rusqlite::Result<Option<Grant>> {
        let conn = self.conn.lock().expect("db");
        conn.query_row(
            "SELECT user_id, sandbox_id, can_read, can_write, can_shell, can_admin
             FROM grants WHERE user_id = ?1 AND sandbox_id = ?2",
            params![user_id, sandbox_id],
            |r| {
                Ok(Grant {
                    user_id: r.get(0)?,
                    sandbox_id: r.get(1)?,
                    can_read: r.get::<_, i64>(2)? != 0,
                    can_write: r.get::<_, i64>(3)? != 0,
                    can_shell: r.get::<_, i64>(4)? != 0,
                    can_admin: r.get::<_, i64>(5)? != 0,
                })
            },
        )
        .optional()
    }
}

fn now() -> i64 {
    chrono::Utc::now().timestamp()
}
