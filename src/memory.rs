//! 进程内 Evidence 实现。
//!
//! 从 crate 根下沉而来：它只服务于开发与确定性测试，不提供任何持久性保证；
//! 与本地行协议实现（`src/file.rs`）并列，二者共享 `crate::idempotent_lookup`
//! 的幂等语义。公开类型 [`MemoryEvidenceStore`] 经 crate 根 `pub use` 导出，
//! 路径与拆分前一致。

use std::sync::Mutex;

use crate::{
    idempotent_lookup, AppendReceipt, EvidenceError, EvidenceRecord, EvidenceStore, ReceiptBinding,
};

/// 进程内 Evidence 实现，仅用于开发和确定性测试。
#[derive(Debug, Default)]
pub struct MemoryEvidenceStore {
    state: Mutex<MemoryState>,
}

#[derive(Debug, Default)]
struct MemoryState {
    next_seq: u64,
    entries: Vec<AppendReceipt>,
    closed: bool,
}

impl MemoryEvidenceStore {
    /// 创建空的内存 Evidence store。
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// 返回当前追加快照。
    pub fn entries(&self) -> Result<Vec<AppendReceipt>, EvidenceError> {
        self.state
            .lock()
            .map(|state| state.entries.clone())
            .map_err(|_| EvidenceError::LockPoisoned)
    }

    /// 关闭 store；用于验证 fail-closed 行为。
    pub fn close(&self) -> Result<(), EvidenceError> {
        self.state
            .lock()
            .map(|mut state| {
                state.closed = true;
            })
            .map_err(|_| EvidenceError::LockPoisoned)
    }
}

impl EvidenceStore for MemoryEvidenceStore {
    fn append(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if state.closed {
            return Err(EvidenceError::Closed);
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
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }

    fn append_idempotent(&self, record: &EvidenceRecord) -> Result<AppendReceipt, EvidenceError> {
        record.validate()?;
        let mut state = self.state.lock().map_err(|_| EvidenceError::LockPoisoned)?;
        if state.closed {
            return Err(EvidenceError::Closed);
        }
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
        if state.closed {
            return Err(EvidenceError::Closed);
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
        if state.closed {
            return Err(EvidenceError::Closed);
        }
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
        state.next_seq = seq;
        state.entries.push(receipt.clone());
        Ok(receipt)
    }
}
