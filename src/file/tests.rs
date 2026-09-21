//! `file` 模块单元测试：跨进程锁、并发打开与序号初始化语义。
//!
//! 由 `src/file.rs` 的 `#[cfg(test)] mod tests;` 引入，仅在测试构建中编译。
//! 首个导入以 `#[cfg(test)]` 标注，使审计器的测试段判定起点落在文件开头。

#[cfg(test)]
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
