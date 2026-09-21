//! `evidence` 的错误模型。
//!
//! 错误只描述**可判定**的失败原因；底层 I/O 细节经 `source` 链传递，
//! 不把路径、payload 或凭据直接拼进消息文本。

use std::io;

/// crate 专用 `Result` 别名。
pub type EvidenceResult<T> = Result<T, EvidenceError>;

/// Evidence 追加错误。
#[derive(Debug, thiserror::Error)]
pub enum EvidenceError {
    /// 必填字段为空。
    #[error("证据记录字段为空：{0}")]
    EmptyField(&'static str),
    /// 字段包含行协议保留字符。
    #[error("证据记录字段包含非法字符：{0}")]
    InvalidCharacter(&'static str),
    /// 结果摘要不是规范的 SHA-256 文本。
    #[error("证据记录摘要必须是 64 位十六进制：{0}")]
    InvalidDigest(&'static str),
    /// 存储锁不可用。
    #[error("证据存储锁不可用")]
    LockPoisoned,
    /// 存储已经关闭。
    #[error("证据存储已关闭")]
    Closed,
    /// 存储适配器没有提供幂等追加能力。
    #[error("证据存储不支持幂等追加")]
    IdempotencyUnsupported,
    /// 本地文件持久化失败。
    #[error("证据持久化失败：{0}")]
    Durability(#[source] io::Error),
    /// 同一底层文件已经由当前进程中的另一个 store 占用。
    #[error("证据文件已由另一个 store 打开")]
    PathAlreadyOpen,
    /// 行协议内容无效。
    #[error("证据 wire 无效：{0}")]
    InvalidWire(String),
    /// 远程 Evidence 持久化失败。
    #[error("远程证据持久化失败：{0}")]
    Remote(String),
    /// 存储适配器未实现 B1 receipt 绑定追加。
    #[error("证据存储不支持 receipt 绑定追加")]
    BindingUnsupported,
    /// 同一幂等键已存在但 receipt 绑定不一致。
    #[error("证据 receipt 绑定与已有记录冲突")]
    BindingMismatch,
    /// 签名校验失败。
    #[error("证据签名校验失败")]
    SignatureInvalid,
    /// 签名者标识为空。
    #[error("签名者标识为空")]
    EmptySignerId,
    /// 审批签名角色错误（Owner 与 Reviewer 角色不符）。
    #[error("证据审批签名角色错误")]
    InvalidApprovalRole,
    /// B4 溯源绑定字段无效（PIT/lineage 等格式或一致性不符）。
    #[error("证据溯源绑定无效：{0}")]
    LineageInvalid(String),
}
