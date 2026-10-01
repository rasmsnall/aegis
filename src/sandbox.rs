//! OS-level confinement for launched servers (`[server.sandbox]`).
//!
//! The policy decides which tool calls run; the sandbox limits what a server
//! can do once it runs, so a compromised or careless server can't read your
//! SSH keys or phone home. On Linux it uses Landlock, which needs no root
//! and applies to the server and everything it starts. Elsewhere, and on
//! kernels without Landlock, a server with a sandbox refuses to start
//! rather than run unconfined.

use std::path::PathBuf;

use anyhow::Result;
use serde::Deserialize;
use tokio::process::Command;

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SandboxConfig {
    /// Paths the server may read (and execute) below.
    #[serde(default)]
    pub read: Vec<PathBuf>,
    /// Paths the server may read, write, create and delete below.
    #[serde(default)]
    pub write: Vec<PathBuf>,
    /// Also allow reading the usual system locations (`/usr`, `/etc`,
    /// `/proc`, ...) so interpreters and shared libraries load.
    #[serde(default = "yes")]
    pub system: bool,
    /// Allow all TCP. When false (the default), the server can only connect
    /// to `connect_ports`, and can't listen at all.
    #[serde(default)]
    pub network: bool,
    /// TCP ports the server may connect to when `network` is false.
    #[serde(default)]
    pub connect_ports: Vec<u16>,
}

fn yes() -> bool {
    true
}

/// Read-only locations added by `system = true`; missing ones are skipped.
const SYSTEM_READ: &[&str] = &[
    "/bin", "/sbin", "/usr", "/lib", "/lib32", "/lib64", "/libx32", "/etc", "/opt", "/proc",
    "/sys", "/dev", "/run", "/nix", "/snap",
];

/// Writable devices added by `system = true`.
const SYSTEM_WRITE: &[&str] = &["/dev/null", "/dev/tty"];

/// Arranges for `command` to start confined by `sandbox`.
pub fn apply(command: &mut Command, server: &str, sandbox: Option<&SandboxConfig>) -> Result<()> {
    let Some(sandbox) = sandbox else {
        return Ok(());
    };
    imp::apply(command, server, sandbox)
}

/// The Landlock ABI version the kernel supports; 0 when it has none.
pub fn landlock_abi() -> i64 {
    imp::abi()
}

#[cfg(target_os = "linux")]
mod imp {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
    use std::path::Path;

    use anyhow::{Context, Result, bail};
    use tokio::process::Command;

    use super::{SYSTEM_READ, SYSTEM_WRITE, SandboxConfig};

    // From <linux/landlock.h>.
    const CREATE_RULESET_VERSION: u32 = 1;
    const RULE_PATH_BENEATH: libc::c_int = 1;
    const RULE_NET_PORT: libc::c_int = 2;

    const FS_EXECUTE: u64 = 1 << 0;
    const FS_WRITE_FILE: u64 = 1 << 1;
    const FS_READ_FILE: u64 = 1 << 2;
    const FS_READ_DIR: u64 = 1 << 3;
    const FS_REFER: u64 = 1 << 13;
    const FS_TRUNCATE: u64 = 1 << 14;
    const FS_IOCTL_DEV: u64 = 1 << 15;
    /// Everything from REMOVE_DIR to MAKE_SYM: the ABI 1 directory rights.
    const FS_ABI1: u64 = (1 << 13) - 1;
    /// Rights that make sense on a file (the rest only apply to directories).
    const FS_FILE: u64 = FS_EXECUTE | FS_WRITE_FILE | FS_READ_FILE | FS_TRUNCATE | FS_IOCTL_DEV;
    const FS_READ: u64 = FS_EXECUTE | FS_READ_FILE | FS_READ_DIR;

    const NET_BIND_TCP: u64 = 1 << 0;
    const NET_CONNECT_TCP: u64 = 1 << 1;

    #[repr(C)]
    struct RulesetAttr {
        handled_access_fs: u64,
        handled_access_net: u64,
    }

    #[repr(C, packed)]
    struct PathBeneathAttr {
        allowed_access: u64,
        parent_fd: i32,
    }

    #[repr(C)]
    struct NetPortAttr {
        allowed_access: u64,
        port: u64,
    }

    pub fn abi() -> i64 {
        // SAFETY: with a null attribute and the VERSION flag, the call only
        // reports the ABI version.
        let v = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                std::ptr::null::<RulesetAttr>(),
                0usize,
                CREATE_RULESET_VERSION,
            )
        };
        v.max(0)
    }

    pub fn apply(command: &mut Command, server: &str, sandbox: &SandboxConfig) -> Result<()> {
        let abi = abi();
        if abi < 1 {
            bail!(
                "server {server:?} has a sandbox, but this kernel doesn't support Landlock; refusing to start it unconfined"
            );
        }
        let mut handled_fs = FS_ABI1;
        if abi >= 2 {
            handled_fs |= FS_REFER;
        }
        if abi >= 3 {
            handled_fs |= FS_TRUNCATE;
        }
        if abi >= 5 {
            handled_fs |= FS_IOCTL_DEV;
        }
        let handled_net = if sandbox.network {
            0
        } else if abi >= 4 {
            NET_BIND_TCP | NET_CONNECT_TCP
        } else {
            bail!(
                "server {server:?}: blocking network access needs Landlock ABI 4 (Linux 6.7); this kernel has ABI {abi}. Set network = true to run it with only file restrictions"
            );
        };

        let attr = RulesetAttr {
            handled_access_fs: handled_fs,
            handled_access_net: handled_net,
        };
        // SAFETY: `attr` is a valid ruleset attribute of the given size.
        let fd = unsafe {
            libc::syscall(
                libc::SYS_landlock_create_ruleset,
                &attr as *const RulesetAttr,
                std::mem::size_of::<RulesetAttr>(),
                0u32,
            )
        };
        if fd < 0 {
            return Err(std::io::Error::last_os_error())
                .with_context(|| format!("server {server:?}: creating the Landlock ruleset"));
        }
        // SAFETY: the kernel just handed us this descriptor.
        let ruleset = unsafe { OwnedFd::from_raw_fd(fd as i32) };

        let add_path = |path: &Path, access: u64, required: bool| -> Result<()> {
            let file = match std::fs::File::open(path) {
                Ok(file) => file,
                Err(_) if !required => return Ok(()),
                Err(e) => {
                    return Err(e).with_context(|| {
                        format!("server {server:?}: sandbox path {}", path.display())
                    });
                }
            };
            let is_dir = file.metadata().map(|m| m.is_dir()).unwrap_or(false);
            let mut access = access & handled_fs;
            if !is_dir {
                access &= FS_FILE;
            }
            let rule = PathBeneathAttr {
                allowed_access: access,
                parent_fd: file.as_raw_fd(),
            };
            // SAFETY: both descriptors are open and `rule` is a valid
            // path-beneath attribute.
            let r = unsafe {
                libc::syscall(
                    libc::SYS_landlock_add_rule,
                    ruleset.as_raw_fd(),
                    RULE_PATH_BENEATH,
                    &rule as *const PathBeneathAttr,
                    0u32,
                )
            };
            if r < 0 {
                return Err(std::io::Error::last_os_error()).with_context(|| {
                    format!("server {server:?}: adding sandbox path {}", path.display())
                });
            }
            Ok(())
        };
        if sandbox.system {
            for path in SYSTEM_READ {
                add_path(Path::new(path), FS_READ, false)?;
            }
            for path in SYSTEM_WRITE {
                add_path(Path::new(path), FS_READ | FS_WRITE_FILE, false)?;
            }
        }
        for path in &sandbox.read {
            add_path(path, FS_READ, true)?;
        }
        for path in &sandbox.write {
            add_path(path, handled_fs, true)?;
        }
        if handled_net != 0 {
            for &port in &sandbox.connect_ports {
                let rule = NetPortAttr {
                    allowed_access: NET_CONNECT_TCP,
                    port: u64::from(port),
                };
                // SAFETY: `rule` is a valid net-port attribute.
                let r = unsafe {
                    libc::syscall(
                        libc::SYS_landlock_add_rule,
                        ruleset.as_raw_fd(),
                        RULE_NET_PORT,
                        &rule as *const NetPortAttr,
                        0u32,
                    )
                };
                if r < 0 {
                    return Err(std::io::Error::last_os_error())
                        .with_context(|| format!("server {server:?}: allowing port {port}"));
                }
            }
        }

        let raw = ruleset.as_raw_fd();
        // SAFETY: the closure runs in the forked child before exec and only
        // makes two system calls, both async-signal-safe. `ruleset` is kept
        // alive (and so `raw` stays valid) by the closure that owns it.
        unsafe {
            command.pre_exec(move || {
                let _keep = &ruleset;
                if libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                if libc::syscall(libc::SYS_landlock_restrict_self, raw, 0u32) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        Ok(())
    }
}

#[cfg(not(target_os = "linux"))]
mod imp {
    use anyhow::{Result, bail};
    use tokio::process::Command;

    use super::SandboxConfig;

    pub fn abi() -> i64 {
        0
    }

    pub fn apply(_: &mut Command, server: &str, _: &SandboxConfig) -> Result<()> {
        bail!(
            "server {server:?} has a sandbox, which needs Linux (Landlock); refusing to start it unconfined"
        )
    }
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    use super::*;

    fn config(write: Vec<PathBuf>) -> SandboxConfig {
        SandboxConfig {
            read: vec![],
            write,
            system: true,
            network: true,
            connect_ports: vec![],
        }
    }

    async fn run(sandbox: &SandboxConfig, script: &str) -> std::process::Output {
        let mut command = Command::new("sh");
        command.arg("-c").arg(script);
        apply(&mut command, "test", Some(sandbox)).unwrap();
        command.output().await.unwrap()
    }

    #[tokio::test]
    async fn confines_writes_to_allowed_paths() {
        if landlock_abi() < 1 {
            eprintln!("skipped: no Landlock");
            return;
        }
        let allowed = tempfile::tempdir().unwrap();
        let denied = tempfile::tempdir().unwrap();
        let sandbox = config(vec![allowed.path().to_owned()]);
        let script = format!(
            "echo a > {a}/f && cat {a}/f && echo b > {d}/f",
            a = allowed.path().display(),
            d = denied.path().display()
        );
        let out = run(&sandbox, &script).await;
        assert_eq!(String::from_utf8_lossy(&out.stdout), "a\n");
        assert!(!out.status.success());
        assert!(!denied.path().join("f").exists());
    }

    #[tokio::test]
    async fn hides_unlisted_paths() {
        if landlock_abi() < 1 {
            eprintln!("skipped: no Landlock");
            return;
        }
        let secret = tempfile::tempdir().unwrap();
        std::fs::write(secret.path().join("key"), "hunter2").unwrap();
        let out = run(
            &config(vec![]),
            &format!("cat {}/key", secret.path().display()),
        )
        .await;
        assert!(!out.status.success());
        assert!(out.stdout.is_empty());
    }

    #[tokio::test]
    async fn blocks_network_unless_allowed() {
        if landlock_abi() < 4 {
            eprintln!("skipped: Landlock without network rules");
            return;
        }
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        // bash's /dev/tcp makes a plain TCP connection.
        let script = format!("exec 3<>/dev/tcp/127.0.0.1/{port}");
        let probe = |sandbox: SandboxConfig| {
            let script = script.clone();
            async move {
                let mut command = Command::new("bash");
                command.arg("-c").arg(&script);
                apply(&mut command, "test", Some(&sandbox)).unwrap();
                command.output().await.unwrap().status.success()
            }
        };
        let mut sealed = config(vec![]);
        sealed.network = false;
        assert!(!probe(sealed.clone()).await, "connected without permission");
        sealed.connect_ports = vec![port];
        assert!(probe(sealed).await, "allowed port refused");
    }
}
