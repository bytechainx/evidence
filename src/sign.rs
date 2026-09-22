//! B2：受保护签名 + 审批回读。
//!
//! 签名密钥经 [`SigningKey`] 注入：测试用 [`TestSigningKey`]（确定性 sha256
//! test scheme，**禁止用于生产**）；生产密钥 provider 契约见 CONTRACT_GAP
//! （ops/sre 密钥设施，未决）。

use std::time::{SystemTime, UNIX_EPOCH};

use crate::{sha256_hex, EvidenceError};

/// 签名密钥注入点。
///
/// 生产密钥 provider 契约见 CONTRACT_GAP（依赖 ops/sre 密钥设施，未决）；
/// 本 crate 当前仅提供 [`TestSigningKey`]。
pub trait SigningKey: Send + Sync {
    /// 用于签名材料的密钥字节。
    fn key_material(&self) -> &[u8];
}

/// 测试专用密钥（确定性 sha256 test scheme）；**禁止用于生产**。
///
/// 仅在 `#[cfg(test)]` 或启用 `test-signing-key` feature 时编译。
/// 生产构建中不可用，防止 `strings` 等工具从发布二进制提取硬编码密钥。
#[derive(Clone, Copy, Default)]
#[cfg(any(test, feature = "test-signing-key"))]
pub struct TestSigningKey;

#[cfg(any(test, feature = "test-signing-key"))]
impl SigningKey for TestSigningKey {
    fn key_material(&self) -> &[u8] {
        b"bytechainx-evidence-test-signing-key-v1-NOT-FOR-PRODUCTION"
    }
}

/// 受保护签名角色。
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SignatureRole {
    /// 证据所有者签名。
    Owner,
    /// 证据审查者签名。
    Reviewer,
}

impl SignatureRole {
    fn wire_byte(self) -> u8 {
        match self {
            Self::Owner => 1,
            Self::Reviewer => 2,
        }
    }
}

/// 一条受保护 canonical 签名。
///
/// 字段私有；仅 [`sign_canonical`] 可构造通过校验的实例，避免绕过空 signer 等不变量。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtectedSignature {
    role: SignatureRole,
    signer_id: String,
    signature_hex: String,
    signed_at_ms: u64,
}

impl ProtectedSignature {
    /// 签名角色。
    #[must_use]
    pub fn role(&self) -> SignatureRole {
        self.role
    }

    /// 签名者标识。
    #[must_use]
    pub fn signer_id(&self) -> &str {
        &self.signer_id
    }

    /// 64 位小写十六进制 SHA-256 摘要。
    #[must_use]
    pub fn signature_hex(&self) -> &str {
        &self.signature_hex
    }

    /// 签名时间戳（Unix 毫秒）。
    #[must_use]
    pub fn signed_at_ms(&self) -> u64 {
        self.signed_at_ms
    }
}

/// 用注入的密钥对 canonical payload 生成签名。
pub fn sign_canonical(
    key: &impl SigningKey,
    role: SignatureRole,
    signer_id: impl Into<String>,
    payload: &[u8],
) -> Result<ProtectedSignature, EvidenceError> {
    let signer_id = signer_id.into();
    if signer_id.is_empty() {
        return Err(EvidenceError::EmptySignerId);
    }
    let signed_at_ms = current_time_ms()?;
    let signature_hex =
        compute_signature(key.key_material(), role, &signer_id, signed_at_ms, payload);
    Ok(ProtectedSignature {
        role,
        signer_id,
        signature_hex,
        signed_at_ms,
    })
}

/// 用注入的密钥校验 canonical payload 与受保护签名是否匹配。
pub fn verify_canonical(
    key: &impl SigningKey,
    sig: &ProtectedSignature,
    payload: &[u8],
) -> Result<(), EvidenceError> {
    if sig.signer_id.is_empty() {
        return Err(EvidenceError::EmptySignerId);
    }
    let expected = compute_signature(
        key.key_material(),
        sig.role,
        &sig.signer_id,
        sig.signed_at_ms,
        payload,
    );
    if sig.signature_hex != expected {
        return Err(EvidenceError::SignatureInvalid);
    }
    Ok(())
}

/// B2 审批回读：验证 Owner 签名 + Reviewer 审批签名及角色。
///
/// 状态机 `signed → approved`：Owner 先签（`role=Owner`），Reviewer 再批
/// （`role=Reviewer`）；回读时两者均须通过 [`verify_canonical`]。
pub fn verify_approval(
    key: &impl SigningKey,
    owner: &ProtectedSignature,
    reviewer: &ProtectedSignature,
    payload: &[u8],
) -> Result<(), EvidenceError> {
    if owner.role() != SignatureRole::Owner || reviewer.role() != SignatureRole::Reviewer {
        return Err(EvidenceError::InvalidApprovalRole);
    }
    verify_canonical(key, owner, payload)?;
    verify_canonical(key, reviewer, payload)
}

fn compute_signature(
    key_material: &[u8],
    role: SignatureRole,
    signer_id: &str,
    signed_at_ms: u64,
    payload: &[u8],
) -> String {
    let mut material =
        Vec::with_capacity(key_material.len() + 1 + signer_id.len() + 8 + payload.len());
    material.extend_from_slice(key_material);
    material.push(role.wire_byte());
    material.extend_from_slice(signer_id.as_bytes());
    material.extend_from_slice(&signed_at_ms.to_le_bytes());
    material.extend_from_slice(payload);
    sha256_hex(material)
}

fn current_time_ms() -> Result<u64, EvidenceError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .map_err(|error| EvidenceError::InvalidWire(format!("系统时钟无效：{error}")))
}

#[cfg(test)]
mod tests {
    use super::{
        sign_canonical, verify_approval, verify_canonical, ProtectedSignature, SignatureRole,
        TestSigningKey,
    };
    use crate::{sha256_hex, EvidenceError};

    const KEY: TestSigningKey = TestSigningKey;

    #[test]
    fn sign_rejects_empty_signer() {
        assert!(matches!(
            sign_canonical(&KEY, SignatureRole::Owner, "", b"payload"),
            Err(EvidenceError::EmptySignerId)
        ));
    }

    #[test]
    fn verify_rejects_empty_signer() {
        let sig = ProtectedSignature {
            role: SignatureRole::Owner,
            signer_id: String::new(),
            signature_hex: "0".repeat(64),
            signed_at_ms: 0,
        };
        assert!(matches!(
            verify_canonical(&KEY, &sig, b"payload"),
            Err(EvidenceError::EmptySignerId)
        ));
    }

    #[test]
    fn verify_rejects_tampered_signature_hex() {
        let payload = b"canonical-payload";
        let mut owner =
            sign_canonical(&KEY, SignatureRole::Owner, "owner-test", payload).expect("sign");
        owner.signature_hex = sha256_hex(b"tampered");
        assert!(matches!(
            verify_canonical(&KEY, &owner, payload),
            Err(EvidenceError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_stale_timestamp() {
        let payload = b"canonical-payload";
        let mut owner =
            sign_canonical(&KEY, SignatureRole::Owner, "owner-test", payload).expect("sign");
        owner.signed_at_ms = owner.signed_at_ms.saturating_add(1);
        assert!(matches!(
            verify_canonical(&KEY, &owner, payload),
            Err(EvidenceError::SignatureInvalid)
        ));
    }

    #[test]
    fn approval_roundtrip_owner_then_reviewer() {
        let payload = b"binding-payload";
        let owner =
            sign_canonical(&KEY, SignatureRole::Owner, "owner-test", payload).expect("owner");
        let reviewer = sign_canonical(&KEY, SignatureRole::Reviewer, "reviewer-test", payload)
            .expect("reviewer");
        assert!(verify_approval(&KEY, &owner, &reviewer, payload).is_ok());
    }

    #[test]
    fn approval_rejects_swapped_roles() {
        let payload = b"binding-payload";
        let owner =
            sign_canonical(&KEY, SignatureRole::Owner, "owner-test", payload).expect("owner");
        let reviewer = sign_canonical(&KEY, SignatureRole::Reviewer, "reviewer-test", payload)
            .expect("reviewer");
        assert!(matches!(
            verify_approval(&KEY, &reviewer, &owner, payload),
            Err(EvidenceError::InvalidApprovalRole)
        ));
    }

    #[test]
    fn approval_rejects_missing_reviewer() {
        let payload = b"binding-payload";
        let owner =
            sign_canonical(&KEY, SignatureRole::Owner, "owner-test", payload).expect("owner");
        assert!(matches!(
            verify_approval(&KEY, &owner, &owner, payload),
            Err(EvidenceError::InvalidApprovalRole)
        ));
    }
}
