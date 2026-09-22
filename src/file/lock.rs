//! 文件身份与跨进程 writer 锁。
//!
//! 从 `file` 门面下沉而来：`FileIdentity` 是跨进程锁与进程内 active-file 去重
//! 共用的文件身份键；`FileProcessLock` 通过 `create_new` 原子创建锁文件实现
//! 跨进程互斥，并在 Linux 下借 `/proc/<pid>` 自动恢复陈旧锁。二者只服务本地
//! durable 适配器的 fail-closed 语义，与门面里的 store / 迭代器职责分离。

use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};

use crate::EvidenceError;

/// 跨进程文件 writer 锁。
///
/// 锁文件通过 `create_new` 原子创建。进程异常退出后不会擅自判断锁是否
/// 过期；残留锁必须由受控运维流程清理，避免两个进程同时写入同一 Evidence
/// 文件。它只提供本地文件互斥，不等价于远程存储的高可用或生产信任锚。
///
/// # 陈旧锁手动清理（非 Linux 平台）
///
/// Linux 下本模块通过 `/proc/<pid>` 检测持有者是否存活并自动恢复陈旧锁。
/// **非 Linux 平台（macOS、Windows 等）不执行自动恢复**（保守策略），
/// 残留锁保持 fail-closed。若进程异常退出后残留锁文件，运维人员需按以下
/// 步骤手动清理：
///
/// 1. **确认持有者是否存活**：通过系统任务管理器或 `ps` 等价命令确认锁
///    文件中记录的 PID 不再运行。
/// 2. **确认无活跃 writer**：检查是否有其他进程正在写入同一 evidence 文件。
/// 3. **手动删除锁文件**：锁文件路径规则如下——
///    - Unix：`/run/user/<uid>/bytechainx-evidence-lock-<device>-<inode>`
///      （回退 `/var/run/user/<uid>/`，再回退 `/tmp`）
///    - 非 Unix：`<evidence-file-path>.evidence-writer-lock`
/// 4. **删除后验证**：尝试重新 `open()` evidence 文件，确认不再返回
///    `PathAlreadyOpen` 错误。
///
/// **警告**：在确认步骤 1 和 2 之前删除锁文件，**将导致双写，破坏
/// evidence 文件完整性**。
pub(super) struct FileProcessLock {
    path: Option<PathBuf>,
    _file: File,
}

impl FileProcessLock {
    #[cfg(unix)]
    pub(super) fn path_for(_path: &Path, identity: &FileIdentity) -> PathBuf {
        match identity {
            FileIdentity::Unix { uid, device, inode } => {
                let namespace = [Path::new("/run/user"), Path::new("/var/run/user")]
                    .iter()
                    .map(|base| base.join(uid.to_string()))
                    .find(|directory| {
                        use std::os::unix::fs::PermissionsExt;

                        std::fs::metadata(directory).is_ok_and(|metadata| {
                            metadata.is_dir() && metadata.permissions().mode() & 0o022 == 0
                        })
                    })
                    .unwrap_or_else(|| PathBuf::from("/tmp"));
                namespace.join(format!("bytechainx-evidence-lock-{device}-{inode}"))
            }
        }
    }

    #[cfg(not(unix))]
    pub(super) fn path_for(path: &Path, _identity: &FileIdentity) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(".evidence-writer-lock");
        PathBuf::from(value)
    }

    pub(super) fn acquire(path: &Path, identity: &FileIdentity) -> Result<Self, EvidenceError> {
        let lock_path = Self::path_for(path, identity);
        // 最多重试一次：第一次创建失败时若陈旧锁可恢复，清理后重试。
        for attempt in 0..=1 {
            match OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&lock_path)
            {
                Ok(mut file) => {
                    let owner = format!("pid={}\n", std::process::id());
                    file.write_all(owner.as_bytes())
                        .map_err(EvidenceError::Durability)?;
                    file.sync_all().map_err(EvidenceError::Durability)?;
                    return Ok(Self {
                        path: Some(lock_path),
                        _file: file,
                    });
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if attempt == 0 {
                        // 尝试恢复陈旧锁
                        if try_recover_stale_lock(&lock_path).is_ok() {
                            continue; // 重试创建
                        }
                    }
                    return Err(EvidenceError::PathAlreadyOpen);
                }
                Err(error) => return Err(EvidenceError::Durability(error)),
            }
        }
        Err(EvidenceError::PathAlreadyOpen)
    }
}

/// 检测 PID 是否存活。
///
/// Linux 下通过 `/proc/<pid>` 检测；非 Linux 平台保守返回 `true`，
/// 避免误判陈旧锁导致双写。非 Linux 平台的陈旧锁需手动清理，
/// 详见 [`FileProcessLock`] 文档中的"陈旧锁手动清理"章节。
fn pid_is_alive(pid: u32) -> bool {
    #[cfg(target_os = "linux")]
    {
        let path = format!("/proc/{pid}");
        std::fs::metadata(path).is_ok()
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = pid;
        true // 保守：非 Linux 平台不尝试恢复
    }
}

/// 尝试恢复陈旧锁文件。
///
/// 读取锁文件中的 PID，若持有者已不存活则删除锁文件并返回 `Ok(())`；
/// 若持有者存活或无法解析返回 `Err(EvidenceError::PathAlreadyOpen)`。
fn try_recover_stale_lock(lock_path: &Path) -> Result<(), EvidenceError> {
    let content = std::fs::read_to_string(lock_path).map_err(|_| EvidenceError::PathAlreadyOpen)?;
    let pid_str = content
        .strip_prefix("pid=")
        .and_then(|rest| rest.lines().next())
        .unwrap_or("");
    let pid: u32 = pid_str
        .parse()
        .map_err(|_| EvidenceError::PathAlreadyOpen)?;
    if pid == 0 {
        return Err(EvidenceError::PathAlreadyOpen);
    }
    if pid_is_alive(pid) {
        // 持有者存活，拒绝
        return Err(EvidenceError::PathAlreadyOpen);
    }
    // 持有者已不存活，删除陈旧锁
    std::fs::remove_file(lock_path).map_err(|_| EvidenceError::PathAlreadyOpen)?;
    Ok(())
}

impl Drop for FileProcessLock {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub(super) enum FileIdentity {
    #[cfg(unix)]
    Unix { uid: u32, device: u64, inode: u64 },
    #[cfg(not(unix))]
    Path(PathBuf),
}

pub(super) fn file_identity(
    file: &File,
    _canonical_path: &Path,
) -> Result<FileIdentity, EvidenceError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;

        let metadata = file.metadata().map_err(EvidenceError::Durability)?;
        Ok(FileIdentity::Unix {
            uid: metadata.uid(),
            device: metadata.dev(),
            inode: metadata.ino(),
        })
    }
    #[cfg(not(unix))]
    {
        Ok(FileIdentity::Path(_canonical_path.to_path_buf()))
    }
}
