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
    /// open() 时是否因尾行半写损坏而截断恢复。
    truncated_on_open: bool,
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
        let lines: Vec<&str> = text.lines().collect();
        let mut entries = Vec::new();
        let mut last_seq = 0;
        let mut truncated_on_open = false;
        for (i, line) in lines.iter().enumerate() {
            match parse_line(line) {
                Ok(receipt) => {
                    if receipt.seq <= last_seq {
                        return Err(EvidenceError::InvalidWire(
                            "追加序号不是严格递增".into(),
                        ));
                    }
                    last_seq = receipt.seq;
                    entries.push(receipt);
                }
                Err(_) if i == lines.len() - 1 && !entries.is_empty() => {
                    // 尾行半写损坏：计算最后完整行结尾的字节偏移，截断文件后继续启动。
                    let truncate_at: u64 = lines[..i]
                        .iter()
                        .map(|l| (l.len() + 1) as u64) // +1 for '\n'
                        .sum();
                    file.set_len(truncate_at).map_err(EvidenceError::Durability)?;
                    truncated_on_open = true;
                    break;
                }
                Err(e) => return Err(e),
            }
        }
        active_guard.disarm();
        Ok(Self {
            path,
            identity,
            _process_lock: process_lock,
            truncated_on_open,
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

    /// open() 时是否因尾行半写损坏而截断恢复。
    ///
    /// 返回 `true` 表示上次写入在追加过程中断电/崩溃，导致最后一行不完整；
    /// open() 已将文件截断至最后一个完整行，此前缀数据完整可用。
    /// 调用方可据此记录 warning 或触发运维检查。
    #[must_use]
    pub fn was_truncated_on_open(&self) -> bool {
        self.truncated_on_open
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
mod tests {
    use super::{file_identity, FileEvidenceStore, FileProcessLock};
    use crate::{sha256_hex, EvidenceError, EvidenceRecord, EvidenceStore};
    use std::fs::OpenOptions;
    use std::process::Command;
    use std::sync::{Arc, Barrier};
    use std::thread;
    use std::time::Duration;

    fn record(snapshot: &str) -> EvidenceRecord {
        EvidenceRecord::new(
            "regime_decision",
            "commit-concurrency-test",
            snapshot,
            vec!["batch-concurrency-test".into()],
            sha256_hex(snapshot.as_bytes()),
            "accepted",
        )
        .expect("并发回归记录有效")
    }

    #[test]
    fn opener_excludes_racing_reader_before_sequence_initialization() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("concurrent.log");
        let first = FileEvidenceStore::open(&path).expect("initial opener");
        assert_eq!(
            first
                .append(&record("snapshot-1"))
                .expect("initial append")
                .seq,
            1
        );
        drop(first);

        let ready = Arc::new(Barrier::new(2));
        let release = Arc::new(Barrier::new(2));
        let thread_ready = Arc::clone(&ready);
        let thread_release = Arc::clone(&release);
        let thread_path = path.clone();
        let opener = thread::spawn(move || {
            FileEvidenceStore::open_with_pause(thread_path, &|| {
                thread_ready.wait();
                thread_release.wait();
            })
        });

        ready.wait();
        let contender = FileEvidenceStore::open(&path);
        let contender_opened = contender.is_ok();
        if let Ok(store) = contender {
            assert_eq!(
                store
                    .append(&record("snapshot-2"))
                    .expect("contender append")
                    .seq,
                2
            );
            drop(store);
        }
        release.wait();

        let second = opener
            .join()
            .expect("opener thread")
            .expect("racing opener");
        assert!(
            !contender_opened,
            "身份未独占时不应允许另一个 opener 读取旧序号"
        );
        assert_eq!(
            second
                .append(&record("snapshot-2"))
                .expect("second append")
                .seq,
            2
        );
    }

    #[test]
    fn file_store_rejects_existing_cross_process_lock() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("cross-process.log");
        let first = FileEvidenceStore::open(&path).expect("initial opener");
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("evidence file");
        let canonical = path.canonicalize().expect("canonical path");
        let identity = file_identity(&file, &canonical).expect("file identity");
        let lock_path = FileProcessLock::path_for(&canonical, &identity);
        assert!(lock_path.is_file());

        assert!(matches!(
            FileEvidenceStore::open(&path),
            Err(EvidenceError::PathAlreadyOpen)
        ));
        drop(first);
        assert!(!lock_path.exists());
        let second = FileEvidenceStore::open(&path).expect("lock released after drop");
        drop(second);
    }

    #[test]
    fn file_store_fails_closed_on_stale_lock_file() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("stale-lock.log");
        FileEvidenceStore::open(&path).expect("create evidence file");
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("evidence file");
        let canonical = path.canonicalize().expect("canonical path");
        let identity = file_identity(&file, &canonical).expect("file identity");
        let lock_path = FileProcessLock::path_for(&canonical, &identity);
        std::fs::write(&lock_path, b"pid=unknown\n").expect("simulate stale lock");

        assert!(matches!(
            FileEvidenceStore::open(&path),
            Err(EvidenceError::PathAlreadyOpen)
        ));
        std::fs::remove_file(lock_path).expect("controlled stale lock cleanup");
    }

    #[test]
    fn cross_process_lock_holder() {
        let Ok(path) = std::env::var("EVIDENCE_LOCK_CHILD_PATH") else {
            return;
        };
        let ready = std::env::var("EVIDENCE_LOCK_CHILD_READY").expect("ready path");
        let _store = FileEvidenceStore::open(path).expect("child lock holder");
        std::fs::write(ready, b"ready").expect("child ready marker");
        thread::sleep(Duration::from_secs(30));
    }

    #[test]
    fn file_store_rejects_open_from_another_process() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("subprocess.log");
        let ready = directory.path().join("ready");
        let child_tmp = directory.path().join("child-tmp");
        std::fs::create_dir(&child_tmp).expect("child TMPDIR");
        let mut child = Command::new(std::env::current_exe().expect("test binary"))
            // 测试已随 `file` 模块外移，libtest 的完整用例名为 `file::tests::...`。
            .args([
                "--exact",
                "file::tests::cross_process_lock_holder",
                "--nocapture",
            ])
            .env("EVIDENCE_LOCK_CHILD_PATH", &path)
            .env("EVIDENCE_LOCK_CHILD_READY", &ready)
            .env("TMPDIR", &child_tmp)
            .spawn()
            .expect("spawn lock holder");

        for _ in 0..100 {
            if ready.is_file() {
                break;
            }
            thread::sleep(Duration::from_millis(10));
        }
        assert!(ready.is_file(), "子进程未在限定时间内取得 Evidence 锁");
        assert!(matches!(
            FileEvidenceStore::open(&path),
            Err(EvidenceError::PathAlreadyOpen)
        ));

        #[cfg(unix)]
        {
            let alias = directory.path().join("subprocess-hard-link.log");
            std::fs::hard_link(&path, &alias).expect("hard-link evidence file");
            assert!(matches!(
                FileEvidenceStore::open(&alias),
                Err(EvidenceError::PathAlreadyOpen)
            ));
        }

        child.kill().expect("kill lock holder");
        let _ = child.wait().expect("wait lock holder");
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("evidence file");
        let canonical = path.canonicalize().expect("canonical path");
        let identity = file_identity(&file, &canonical).expect("file identity");
        let lock_path = FileProcessLock::path_for(&canonical, &identity);
        assert!(lock_path.is_file(), "异常退出后的锁必须保持 fail-closed");
        std::fs::remove_file(lock_path).expect("controlled stale lock cleanup");
    }

    #[test]
    fn open_recovers_from_truncated_last_line() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("truncated.log");
        // 先写入两条完整记录
        {
            let store = FileEvidenceStore::open(&path).expect("open");
            store
                .append(&record("snapshot-1"))
                .expect("append 1");
            store
                .append(&record("snapshot-2"))
                .expect("append 2");
        }
        // 模拟尾行半写：追加一行不完整的内容
        {
            let mut file = OpenOptions::new()
                .append(true)
                .open(&path)
                .expect("open for corruption");
            // 半行：缺少末尾字段，不含换行
            use std::io::Write;
            file.write_all(b"3\tevidence-record/v1|corrupt|v1|s|batch|digest|")
                .expect("write corrupt");
            file.flush().expect("flush");
            file.sync_all().expect("sync");
        }
        // 清理锁文件使 reopen 可行
        {
            let file = OpenOptions::new()
                .read(true)
                .open(&path)
                .expect("open for identity");
            let canonical = path.canonicalize().expect("canonical path");
            let identity = file_identity(&file, &canonical).expect("file identity");
            let lock_path = FileProcessLock::path_for(&canonical, &identity);
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).expect("clean lock");
            }
        }
        // 重新打开：应成功，且标记截断
        let store = FileEvidenceStore::open(&path).expect("reopen after truncation");
        assert!(
            store.was_truncated_on_open(),
            "应检测到尾行半写并截断恢复"
        );
        let entries = store.entries().expect("entries");
        assert_eq!(entries.len(), 2, "两条完整记录应保留");
        assert_eq!(entries[0].seq, 1);
        assert_eq!(entries[1].seq, 2);
    }

    #[test]
    fn open_rejects_corrupt_non_last_line() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("mid-corrupt.log");
        // 写入一条完整记录
        {
            let store = FileEvidenceStore::open(&path).expect("open");
            store
                .append(&record("snapshot-1"))
                .expect("append 1");
        }
        // 手动重写文件：第 1 行有效 → 第 2 行损坏（非尾行） → 第 3 行也是损坏行
        // 第 2 行（i=1）不是最后一行（总行数=3），应触发硬错误而非截断。
        let original = std::fs::read_to_string(&path).expect("read");
        {
            let mut file = OpenOptions::new()
                .write(true)
                .truncate(true)
                .open(&path)
                .expect("open for rewrite");
            use std::io::Write;
            file.write_all(original.as_bytes()).expect("write line 1");
            // 损坏的中间行：字段数不足
            file.write_all(b"2\tbroken\n").expect("write corrupt mid");
            // 第三行使第二行成为真正的"中间行"
            file.write_all(b"3\talso_broken\n").expect("write trailing");
            file.flush().expect("flush");
            file.sync_all().expect("sync");
        }
        // 清理锁
        {
            let file = OpenOptions::new()
                .read(true)
                .open(&path)
                .expect("open for identity");
            let canonical = path.canonicalize().expect("canonical path");
            let identity = file_identity(&file, &canonical).expect("file identity");
            let lock_path = FileProcessLock::path_for(&canonical, &identity);
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).expect("clean lock");
            }
        }
        // 重新打开：非尾行损坏应拒绝（第 2 行损坏但第 3 行存在）
        assert!(
            FileEvidenceStore::open(&path).is_err(),
            "非尾行损坏应拒绝打开"
        );
    }
}
