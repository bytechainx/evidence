//! 本地行协议 Evidence 持久化实现。
//!
//! 从 crate 根下沉而来：文件 I/O、跨进程 writer 锁与同进程 active-file 去重
//! 都只服务于本地 durable 适配器，集中在此模块便于单独审计其 fail-closed 语义。
//! 行协议本身的解析与校验仍在 crate 根，由本模块按 `crate::parse_line` 复用。

use std::collections::HashSet;
use std::fs::{File, OpenOptions};
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use crate::{
    idempotent_lookup, parse_line, receipt_line, AppendReceipt, EvidenceDurability, EvidenceError,
    EvidenceRecord, EvidenceStore, ReceiptBinding,
};

/// 本地行协议 Evidence 实现。
///
/// 每行格式为 `{seq}\t{canonical_record}\n`。追加会执行 `flush` 与
/// `sync_data`，重新打开时会校验既有行并从最大序号继续。它是本地 durable
/// 适配器，不是远程审计服务、签名链或完整合规产品。
pub struct FileEvidenceStore {
    path: PathBuf,
    identity: FileIdentity,
    _process_lock: FileProcessLock,
    state: Mutex<FileState>,
}

/// 跨进程文件 writer 锁。
///
/// 锁文件通过 `create_new` 原子创建。进程异常退出后不会擅自判断锁是否
/// 过期；残留锁必须由受控运维流程清理，避免两个进程同时写入同一 Evidence
/// 文件。它只提供本地文件互斥，不等价于远程存储的高可用或生产信任锚。
struct FileProcessLock {
    path: Option<PathBuf>,
    _file: File,
}

impl FileProcessLock {
    #[cfg(unix)]
    fn path_for(_path: &Path, identity: &FileIdentity) -> PathBuf {
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
    fn path_for(path: &Path, _identity: &FileIdentity) -> PathBuf {
        let mut value = path.as_os_str().to_os_string();
        value.push(".evidence-writer-lock");
        PathBuf::from(value)
    }

    fn acquire(path: &Path, identity: &FileIdentity) -> Result<Self, EvidenceError> {
        let lock_path = Self::path_for(path, identity);
        let mut file = match OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&lock_path)
        {
            Ok(file) => file,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                return Err(EvidenceError::PathAlreadyOpen);
            }
            Err(error) => return Err(EvidenceError::Durability(error)),
        };
        let owner = format!("pid={}\n", std::process::id());
        file.write_all(owner.as_bytes())
            .map_err(EvidenceError::Durability)?;
        file.sync_all().map_err(EvidenceError::Durability)?;
        Ok(Self {
            path: Some(lock_path),
            _file: file,
        })
    }
}

impl Drop for FileProcessLock {
    fn drop(&mut self) {
        if let Some(path) = self.path.take() {
            let _ = std::fs::remove_file(path);
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
enum FileIdentity {
    #[cfg(unix)]
    Unix { uid: u32, device: u64, inode: u64 },
    #[cfg(not(unix))]
    Path(PathBuf),
}

fn file_identity(file: &File, _canonical_path: &Path) -> Result<FileIdentity, EvidenceError> {
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

fn active_files() -> &'static Mutex<HashSet<FileIdentity>> {
    static ACTIVE_FILES: OnceLock<Mutex<HashSet<FileIdentity>>> = OnceLock::new();
    ACTIVE_FILES.get_or_init(|| Mutex::new(HashSet::new()))
}

struct ActiveFileGuard {
    identity: Option<FileIdentity>,
}

impl ActiveFileGuard {
    fn acquire(identity: FileIdentity) -> Result<Self, EvidenceError> {
        let mut active = active_files()
            .lock()
            .map_err(|_| EvidenceError::LockPoisoned)?;
        if !active.insert(identity.clone()) {
            return Err(EvidenceError::PathAlreadyOpen);
        }
        Ok(Self {
            identity: Some(identity),
        })
    }

    fn disarm(&mut self) {
        self.identity = None;
    }
}

impl Drop for ActiveFileGuard {
    fn drop(&mut self) {
        let Some(identity) = self.identity.take() else {
            return;
        };
        let mut active = active_files()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active.remove(&identity);
    }
}

struct FileState {
    file: File,
    next_seq: u64,
    entries: Vec<AppendReceipt>,
}

impl FileEvidenceStore {
    /// 打开或创建本地 Evidence 行协议文件。
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, EvidenceError> {
        Self::open_inner(path, None)
    }

    #[cfg(test)]
    fn open_with_pause(path: impl Into<PathBuf>, pause: &dyn Fn()) -> Result<Self, EvidenceError> {
        Self::open_inner(path, Some(pause))
    }

    fn open_inner(
        path: impl Into<PathBuf>,
        pause: Option<&dyn Fn()>,
    ) -> Result<Self, EvidenceError> {
        let path = path.into();
        if let Some(parent) = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
        {
            std::fs::create_dir_all(parent).map_err(EvidenceError::Durability)?;
        }
        let file = OpenOptions::new()
            .create(true)
            .append(true)
            .read(true)
            .open(&path)
            .map_err(EvidenceError::Durability)?;
        let path = std::fs::canonicalize(path).map_err(EvidenceError::Durability)?;
        let identity = file_identity(&file, &path)?;
        let process_lock = FileProcessLock::acquire(&path, &identity)?;
        let mut active_guard = ActiveFileGuard::acquire(identity.clone())?;
        if let Some(pause) = pause {
            pause();
        }
        let text = std::fs::read_to_string(&path).map_err(EvidenceError::Durability)?;
        let mut entries = Vec::new();
        let mut last_seq = 0;
        for line in text.lines() {
            let receipt = parse_line(line)?;
            if receipt.seq <= last_seq {
                return Err(EvidenceError::InvalidWire("追加序号不是严格递增".into()));
            }
            last_seq = receipt.seq;
            entries.push(receipt);
        }
        active_guard.disarm();
        Ok(Self {
            path,
            identity,
            _process_lock: process_lock,
            state: Mutex::new(FileState {
                file,
                next_seq: last_seq,
                entries,
            }),
        })
    }

    /// 返回底层文件路径。
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 返回已经校验过的追加快照。
    pub fn entries(&self) -> Result<Vec<AppendReceipt>, EvidenceError> {
        self.state
            .lock()
            .map(|state| state.entries.clone())
            .map_err(|_| EvidenceError::LockPoisoned)
    }
}

impl Drop for FileEvidenceStore {
    fn drop(&mut self) {
        let mut active = active_files()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        active.remove(&self.identity);
    }
}

impl EvidenceStore for FileEvidenceStore {
    fn durability(&self) -> EvidenceDurability {
        EvidenceDurability::LocalDurable
    }

    fn append(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: None,
        };
        let line = receipt_line(seq, record, None);
        state
            .file
            .write_all(line.as_bytes())
            .map_err(EvidenceError::Durability)?;
        state.file.flush().map_err(EvidenceError::Durability)?;
        state.file.sync_data().map_err(EvidenceError::Durability)?;
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }

    fn append_idempotent(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if let Some(existing) = idempotent_lookup(&state.entries, record, None)? {
            return Ok(existing.clone());
        }
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: None,
        };
        let line = receipt_line(seq, record, None);
        state
            .file
            .write_all(line.as_bytes())
            .map_err(EvidenceError::Durability)?;
        state.file.flush().map_err(EvidenceError::Durability)?;
        state.file.sync_data().map_err(EvidenceError::Durability)?;
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }

    fn append_with_binding(
        &self,
        record: &EvidenceRecord,
        binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        binding.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: Some(binding.clone()),
        };
        let line = receipt_line(seq, record, Some(binding));
        state
            .file
            .write_all(line.as_bytes())
            .map_err(EvidenceError::Durability)?;
        state.file.flush().map_err(EvidenceError::Durability)?;
        state.file.sync_data().map_err(EvidenceError::Durability)?;
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }

    fn append_idempotent_with_binding(
        &self,
        record: &EvidenceRecord,
        binding: &ReceiptBinding,
    ) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        binding.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if let Some(existing) = idempotent_lookup(&state.entries, record, Some(binding))? {
            return Ok(existing.clone());
        }
        let seq = state
            .next_seq
            .checked_add(1)
            .ok_or_else(|| EvidenceError::InvalidWire("追加序号溢出".into()))?;
        let receipt = AppendReceipt {
            seq,
            record: record.clone(),
            binding: Some(binding.clone()),
        };
        let line = receipt_line(seq, record, Some(binding));
        state
            .file
            .write_all(line.as_bytes())
            .map_err(EvidenceError::Durability)?;
        state.file.flush().map_err(EvidenceError::Durability)?;
        state.file.sync_data().map_err(EvidenceError::Durability)?;
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }
}

#[cfg(test)]
mod tests;
