//! B2 骨架：Evidence 只读查询 port。
//!
//! 提供按序号与规范化记录检索追加回执的能力；不宣称生产查询授权或远程索引。

use crate::{AppendReceipt, EvidenceError, EvidenceRecord, FileEvidenceStore, MemoryEvidenceStore};

/// 只读 Evidence 查询面；与 [`crate::EvidenceStore`] 追加 seam 解耦。
pub trait EvidenceReader {
    /// 返回当前已追加条目数量。
    fn len(&self) -> Result<usize, EvidenceError>;

    /// 是否尚无追加条目。
    fn is_empty(&self) -> Result<bool, EvidenceError> {
        Ok(self.len()? == 0)
    }

    /// 按单调递增序号检索回执；序号不存在时返回 `None`。
    fn get(&self, seq: u64) -> Result<Option<AppendReceipt>, EvidenceError>;

    /// 按规范化 [`EvidenceRecord`] 检索首条匹配回执。
    fn find_by_record(
        &self,
        record: &EvidenceRecord,
    ) -> Result<Option<AppendReceipt>, EvidenceError>;
}

impl EvidenceReader for MemoryEvidenceStore {
    fn len(&self) -> Result<usize, EvidenceError> {
        Ok(self.entries()?.len())
    }

    fn get(&self, seq: u64) -> Result<Option<AppendReceipt>, EvidenceError> {
        Ok(self.entries()?.into_iter().find(|entry| entry.seq == seq))
    }

    fn find_by_record(
        &self,
        record: &EvidenceRecord,
    ) -> Result<Option<AppendReceipt>, EvidenceError> {
        Ok(self
            .entries()?
            .into_iter()
            .find(|entry| entry.record == *record))
    }
}

impl EvidenceReader for FileEvidenceStore {
    fn len(&self) -> Result<usize, EvidenceError> {
        Ok(self.entries()?.len())
    }

    fn get(&self, seq: u64) -> Result<Option<AppendReceipt>, EvidenceError> {
        Ok(self.entries()?.into_iter().find(|entry| entry.seq == seq))
    }

    fn find_by_record(
        &self,
        record: &EvidenceRecord,
    ) -> Result<Option<AppendReceipt>, EvidenceError> {
        Ok(self
            .entries()?
            .into_iter()
            .find(|entry| entry.record == *record))
    }
}
