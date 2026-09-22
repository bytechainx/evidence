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

/// 流式 Evidence 文件条目迭代器。
///
/// 逐行解析行协议文件，不一次性加载全部条目到内存。
/// 适合内存受限容器中大审计文件的分页查询场景。
///
/// # 使用示例
///
/// ```no_run
/// use evidence::FileEvidenceIter;
///
/// fn main() -> evidence::EvidenceResult<()> {
///     // 分页读取：跳过前 100 条，取 50 条
///     let iter = FileEvidenceIter::open("large_audit.log")?;
///     let page: Vec<_> = iter.skip(100).take(50).collect::<Result<Vec<_>, _>>()?;
///     Ok(())
/// }
/// ```
///
/// # 与 FileEvidenceStore 的互斥
///
/// 本迭代器持有进程写锁；同一文件上不能同时存在
/// [`FileEvidenceStore`] 与本迭代器。这是 fail-closed 语义的组成部分。
pub struct FileEvidenceIter {
    reader: std::io::BufReader<std::fs::File>,
    _lock: FileProcessLock,
    /// 已成功解析的行数（不含跳过和解析失败的行）。
    parsed_count: u64,
}

impl FileEvidenceIter {
    /// 以流式方式打开 Evidence 文件，获取进程锁后返回惰性条目迭代器。
    ///
    /// 每次 [`Iterator::next()`] 调用从文件中读取一行并解析为
    /// [`AppendReceipt`]。到达文件末尾或遇到空行时返回 `None`。
    pub fn open(path: impl AsRef<Path>) -> Result<Self, crate::EvidenceError> {
        let path = path.as_ref();
        let canonical = std::fs::canonicalize(path).map_err(crate::EvidenceError::Durability)?;
        let file = OpenOptions::new()
            .read(true)
            .open(path)
            .map_err(crate::EvidenceError::Durability)?;
        let identity = file_identity(&file, &canonical)?;
        let lock = FileProcessLock::acquire(&canonical, &identity)?;
        Ok(Self {
            reader: std::io::BufReader::new(file),
            _lock: lock,
            parsed_count: 0,
        })
    }

    /// 返回已成功解析的条目数。
    #[must_use]
    pub fn parsed_count(&self) -> u64 {
        self.parsed_count
    }
}

impl Iterator for FileEvidenceIter {
    type Item = Result<crate::AppendReceipt, crate::EvidenceError>;

    fn next(&mut self) -> Option<Self::Item> {
        use std::io::BufRead;

        let mut line = String::new();
        match self.reader.read_line(&mut line) {
            Ok(0) => None,
            Ok(_) => {
                let trimmed = line.trim_end_matches('\n');
                // 空行视为文件末尾（文件尾可能有多余换行）
                if trimmed.is_empty() {
                    return None;
                }
                match crate::parse_line(trimmed) {
                    Ok(receipt) => {
                        self.parsed_count += 1;
                        Some(Ok(receipt))
                    }
                    Err(e) => Some(Err(e)),
                }
            }
            Err(e) => Some(Err(crate::EvidenceError::Durability(e))),
        }
    }
}

/// 从 evidence 文件中按分页读取条目。
///
/// 打开文件、获取进程锁，跳过 `offset` 条有效记录后取最多 `limit` 条。
/// `offset` 为 0-based 索引（按已成功解析的条目计数，不含损坏行）。
///
/// # 与全量读取的一致性
///
/// 本函数与 [`FileEvidenceStore::open`] 使用相同的 [`parse_line`]
/// 行解析逻辑；对同一完整文件调用本函数取 `offset=0` 与全量
/// [`FileEvidenceStore::entries()`] 的结果在语义上一致。
pub fn read_entries_page(
    path: impl AsRef<Path>,
    offset: u64,
    limit: usize,
) -> Result<Vec<crate::AppendReceipt>, crate::EvidenceError> {
    let mut iter = FileEvidenceIter::open(path)?;
    // 跳过 offset 条有效记录（解析失败的行不计入 offset）
    let mut skipped: u64 = 0;
    while skipped < offset {
        match iter.next() {
            Some(Ok(_)) => skipped += 1,
            Some(Err(e)) => return Err(e),
            None => return Ok(Vec::new()),
        }
    }
    iter.take(limit).collect()
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
                        return Err(EvidenceError::InvalidWire("追加序号不是严格递增".into()));
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
                    file.set_len(truncate_at)
                        .map_err(EvidenceError::Durability)?;
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
    ///
    /// 每次调用都会全量 clone 内部 `Vec`；对于条目数很大的审计文件，建议改用
    /// [`EvidenceReader`](crate::EvidenceReader) 的 `len`/`get`/`find_by_record`
    /// 方法，这些方法不执行全量 clone。
    pub fn entries(&self) -> Result<Vec<AppendReceipt>, EvidenceError> {
        self.state
            .lock()
            .map(|state| state.entries.clone())
            .map_err(|_| EvidenceError::LockPoisoned)
    }

    /// 返回已校验条目数量（不执行全量 clone）。
    pub fn entry_count(&self) -> Result<usize, EvidenceError> {
        self.state
            .lock()
            .map(|state| state.entries.len())
            .map_err(|_| EvidenceError::LockPoisoned)
    }

    /// 按序号检索单条回执（不执行全量 clone）。
    pub(crate) fn get_entry(&self, seq: u64) -> Result<Option<AppendReceipt>, EvidenceError> {
        self.state
            .lock()
            .map(|state| state.entries.iter().find(|e| e.seq == seq).cloned())
            .map_err(|_| EvidenceError::LockPoisoned)
    }

    /// 按规范化记录检索首条匹配回执（不执行全量 clone）。
    pub(crate) fn find_entry(
        &self,
        record: &crate::EvidenceRecord,
    ) -> Result<Option<AppendReceipt>, EvidenceError> {
        self.state
            .lock()
            .map(|state| state.entries.iter().find(|e| e.record == *record).cloned())
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
    fn recovers_stale_lock_with_dead_pid() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("dead-pid.log");
        // 先创建 store 并写入一条记录
        {
            let store = FileEvidenceStore::open(&path).expect("create evidence file");
            store
                .append(&record("before-stale-lock"))
                .expect("append before stale lock");
        }
        // 用不存在的 PID 伪造陈旧锁
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("evidence file");
        let canonical = path.canonicalize().expect("canonical path");
        let identity = file_identity(&file, &canonical).expect("file identity");
        let lock_path = FileProcessLock::path_for(&canonical, &identity);
        // 用一个几乎不可能存在的 PID
        std::fs::write(&lock_path, b"pid=999999\n").expect("simulate dead pid lock");
        // 重新打开：应自动恢复陈旧锁，成功打开即证明恢复了
        let store = FileEvidenceStore::open(&path).expect("recover from stale lock");
        // 验证原有数据完整
        let entries = store.entries().expect("entries");
        assert_eq!(entries.len(), 1, "陈旧锁恢复后原有数据应完整");
        assert_eq!(entries[0].seq, 1);
        // 验证 store 可用（可追加新记录）
        store
            .append(&record("after-recovery"))
            .expect("recovered store 应可追加");
        drop(store);
    }

    #[test]
    fn refuses_lock_with_live_pid() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("live-pid.log");
        {
            let _store = FileEvidenceStore::open(&path).expect("create evidence file");
        }
        let file = OpenOptions::new()
            .read(true)
            .open(&path)
            .expect("evidence file");
        let canonical = path.canonicalize().expect("canonical path");
        let identity = file_identity(&file, &canonical).expect("file identity");
        let lock_path = FileProcessLock::path_for(&canonical, &identity);
        // 用当前进程 PID 伪造锁（确实存活）
        std::fs::write(
            &lock_path,
            format!("pid={}\n", std::process::id()).as_bytes(),
        )
        .expect("simulate live pid lock");
        // 重新打开：持有者存活，应拒绝
        assert!(matches!(
            FileEvidenceStore::open(&path),
            Err(EvidenceError::PathAlreadyOpen)
        ));
        std::fs::remove_file(lock_path).expect("cleanup test lock");
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
            store.append(&record("snapshot-1")).expect("append 1");
            store.append(&record("snapshot-2")).expect("append 2");
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
        assert!(store.was_truncated_on_open(), "应检测到尾行半写并截断恢复");
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
            store.append(&record("snapshot-1")).expect("append 1");
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

    // ── 流式迭代器测试 ──

    /// 创建写入 N 条记录的临时 evidence 文件，返回路径与已写入记录集合。
    fn write_n_records(
        directory: &tempfile::TempDir,
        name: &str,
        n: usize,
    ) -> (std::path::PathBuf, Vec<crate::AppendReceipt>) {
        let path = directory.path().join(name);
        let store = FileEvidenceStore::open(&path).expect("创建临时文件");
        let mut receipts = Vec::new();
        for i in 0..n {
            let snapshot = format!("snapshot-{i:04}");
            let receipt = store.append(&record(&snapshot)).expect("追加记录");
            receipts.push(receipt);
        }
        drop(store);
        (path, receipts)
    }

    #[test]
    fn stream_iter_reads_all_entries() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (path, expected) = write_n_records(&directory, "stream-all.log", 20);
        // 清理锁文件使迭代器可获取锁
        {
            let file = OpenOptions::new().read(true).open(&path).expect("open");
            let canonical = path.canonicalize().expect("canonical");
            let identity = file_identity(&file, &canonical).expect("identity");
            let lock_path = FileProcessLock::path_for(&canonical, &identity);
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).expect("clean lock");
            }
        }
        let iter = super::FileEvidenceIter::open(&path).expect("打开迭代器");
        let got: Vec<_> = iter.collect::<Result<Vec<_>, _>>().expect("全部解析成功");
        assert_eq!(
            got.len(),
            expected.len(),
            "流式迭代器应读取全部 {0} 条记录",
            expected.len()
        );
        assert_eq!(got, expected, "流式迭代器结果应与全量写入结果一致");
    }

    #[test]
    fn stream_iter_matches_full_read() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (path, expected) = write_n_records(&directory, "consistency.log", 15);
        // 清理锁
        {
            let file = OpenOptions::new().read(true).open(&path).expect("open");
            let canonical = path.canonicalize().expect("canonical");
            let identity = file_identity(&file, &canonical).expect("identity");
            let lock_path = FileProcessLock::path_for(&canonical, &identity);
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).expect("clean lock");
            }
        }
        // 流式读取
        let iter = super::FileEvidenceIter::open(&path).expect("打开迭代器");
        let streamed: Vec<_> = iter.collect::<Result<Vec<_>, _>>().expect("流式解析");
        // 全量读取（FileEvidenceStore::open 内部 read_to_string + 逐行 parse）
        let store = FileEvidenceStore::open(&path).expect("全量打开");
        let full = store.entries().expect("全量 entries");
        assert_eq!(streamed, full, "流式读取应与全量 entries() 结果完全一致");
        assert_eq!(streamed, expected, "流式读取应与写入结果完全一致");
    }

    #[test]
    fn stream_iter_pagination_is_correct() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (path, expected) = write_n_records(&directory, "pagination.log", 30);
        // 清理锁
        {
            let file = OpenOptions::new().read(true).open(&path).expect("open");
            let canonical = path.canonicalize().expect("canonical");
            let identity = file_identity(&file, &canonical).expect("identity");
            let lock_path = FileProcessLock::path_for(&canonical, &identity);
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).expect("clean lock");
            }
        }
        // 分页：offset=5, limit=10
        let page = super::read_entries_page(&path, 5, 10).expect("分页读取");
        assert_eq!(page.len(), 10, "应返回恰好 10 条记录");
        for (i, receipt) in page.iter().enumerate() {
            let idx = 5 + i;
            assert_eq!(receipt.seq, expected[idx].seq, "分页条目 [{i}] 序号不匹配");
            assert_eq!(
                receipt.record, expected[idx].record,
                "分页条目 [{i}] 记录不匹配"
            );
        }
        // 边界：offset 超出范围
        let empty_page = super::read_entries_page(&path, 100, 10).expect("超出范围");
        assert!(empty_page.is_empty(), "超出范围的分页应为空");
        // 边界：limit 超过剩余条目
        let partial = super::read_entries_page(&path, 25, 10).expect("部分页");
        assert_eq!(partial.len(), 5, "超出末尾的页应返回剩余 5 条");
    }

    #[test]
    fn stream_iter_empty_file_returns_none() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let path = directory.path().join("empty.log");
        // 创建空文件
        {
            let _store = FileEvidenceStore::open(&path).expect("创建空文件");
        }
        // 清理锁
        {
            let file = OpenOptions::new().read(true).open(&path).expect("open");
            let canonical = path.canonicalize().expect("canonical");
            let identity = file_identity(&file, &canonical).expect("identity");
            let lock_path = FileProcessLock::path_for(&canonical, &identity);
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).expect("clean lock");
            }
        }
        let iter = super::FileEvidenceIter::open(&path).expect("打开迭代器");
        let got: Vec<_> = iter.collect::<Result<Vec<_>, _>>().expect("解析");
        assert!(got.is_empty(), "空文件应返回 0 条记录");
    }

    #[test]
    fn stream_iter_parsed_count_is_accurate() {
        let directory = tempfile::tempdir().expect("temporary directory");
        let (path, _) = write_n_records(&directory, "count.log", 12);
        // 清理锁
        {
            let file = OpenOptions::new().read(true).open(&path).expect("open");
            let canonical = path.canonicalize().expect("canonical");
            let identity = file_identity(&file, &canonical).expect("identity");
            let lock_path = FileProcessLock::path_for(&canonical, &identity);
            if lock_path.exists() {
                std::fs::remove_file(&lock_path).expect("clean lock");
            }
        }
        let mut iter = super::FileEvidenceIter::open(&path).expect("打开迭代器");
        assert_eq!(iter.parsed_count(), 0, "初始已解析计数应为 0");
        // 消费前 5 条
        for _ in 0..5 {
            assert!(iter.next().transpose().is_ok(), "前 5 条应解析成功");
        }
        let after_five = iter.parsed_count();
        assert_eq!(after_five, 5, "解析 5 条后计数应为 5");
        // 消费剩余
        let rest: Vec<_> = iter.collect();
        assert_eq!(rest.len(), 7, "剩余 7 条");
        // 总计 = 手动消费的 5 + collect 到的 7
        assert_eq!(after_five + rest.len() as u64, 12, "最终总计数应为 12");
    }
}
