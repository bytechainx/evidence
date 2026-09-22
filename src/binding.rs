//! B3：不可变 binding + 独立 verifier。
//!
//! binding 绑定 commit/schema/environment/artifact 摘要，并携带 Owner 签名
//! （B2 `sign_canonical` 产物）。字段私有 + 签名覆盖 canonical 内容，实现
//! 不可变：篡改任一字段或签名均使 [`ImmutableBinding::verify`] 失败。

use crate::sign::ProtectedSignature;
#[cfg(any(test, feature = "test-signing-key"))]
use crate::sign::{sign_canonical, verify_canonical, SignatureRole, TestSigningKey};
#[cfg(any(test, feature = "test-signing-key"))]
use crate::{validate_commit, validate_component, validate_digest, EvidenceError};

/// B3 不可变 binding 的行协议 schema 标识。
pub const IMMUTABLE_BINDING_SCHEMA: &str = "evidence-immutable-binding/v1";

/// B3 不可变 binding。
///
/// 字段私有，仅 [`ImmutableBinding::sign`] 可构造通过校验的实例；
/// Owner 签名覆盖 canonical 内容，构成不可变保证。
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ImmutableBinding {
    source_commit: String,
    schema: String,
    environment: String,
    artifact_digest: String,
    owner_signature: ProtectedSignature,
}

impl ImmutableBinding {
    /// 创建并签名：Owner 签名覆盖 canonical 内容。
    ///
    /// 仅在 `#[cfg(test)]` 或启用 `test-signing-key` feature 时可用。
    #[cfg(any(test, feature = "test-signing-key"))]
    pub fn sign(
        owner_id: impl Into<String>,
        source_commit: impl Into<String>,
        schema: impl Into<String>,
        environment: impl Into<String>,
        artifact_digest: impl Into<String>,
    ) -> Result<Self, EvidenceError> {
        let source_commit = source_commit.into();
        let schema = schema.into();
        let environment = environment.into();
        let artifact_digest = artifact_digest.into();
        validate_commit("source_commit", &source_commit)?;
        validate_component("schema", &schema, false)?;
        validate_component("environment", &environment, false)?;
        validate_digest("artifact_digest", &artifact_digest)?;
        let payload =
            Self::canonical_payload(&source_commit, &schema, &environment, &artifact_digest);
        let owner_signature =
            sign_canonical(&TestSigningKey, SignatureRole::Owner, owner_id, &payload)?;
        Ok(Self {
            source_commit,
            schema,
            environment,
            artifact_digest,
            owner_signature,
        })
    }

    /// canonical 内容（被签名的 payload，不含签名本身）。
    #[must_use]
    pub fn canonical_bytes(&self) -> Vec<u8> {
        Self::canonical_payload(
            &self.source_commit,
            &self.schema,
            &self.environment,
            &self.artifact_digest,
        )
    }

    /// 独立验证：签名与摘要一致性。篡改任一字段或签名均失败。
    ///
    /// 仅在 `#[cfg(test)]` 或启用 `test-signing-key` feature 时可用。
    #[cfg(any(test, feature = "test-signing-key"))]
    pub fn verify(&self) -> Result<(), EvidenceError> {
        let payload = self.canonical_bytes();
        verify_canonical(&TestSigningKey, &self.owner_signature, &payload)
    }

    fn canonical_payload(
        source_commit: &str,
        schema: &str,
        environment: &str,
        artifact_digest: &str,
    ) -> Vec<u8> {
        format!(
            "{IMMUTABLE_BINDING_SCHEMA}|{source_commit}|{schema}|{environment}|{artifact_digest}"
        )
        .into_bytes()
    }

    /// 产生该 binding 的 40 位 Git commit。
    #[must_use]
    pub fn source_commit(&self) -> &str {
        &self.source_commit
    }

    /// binding 绑定的 schema 标识。
    #[must_use]
    pub fn schema(&self) -> &str {
        &self.schema
    }

    /// 运行环境标识。
    #[must_use]
    pub fn environment(&self) -> &str {
        &self.environment
    }

    /// artifact 清单摘要（64 位 SHA-256 十六进制）。
    #[must_use]
    pub fn artifact_digest(&self) -> &str {
        &self.artifact_digest
    }

    /// Owner 签名（B2 产物）。
    #[must_use]
    pub fn owner_signature(&self) -> &ProtectedSignature {
        &self.owner_signature
    }
}

/// 独立 verifier（B3 语义：非 Agent 自报，独立验证 binding 签名与摘要）。
///
/// 仅在 `#[cfg(test)]` 或启用 `test-signing-key` feature 时可用。
#[cfg(any(test, feature = "test-signing-key"))]
pub fn verify_binding(binding: &ImmutableBinding) -> Result<(), EvidenceError> {
    binding.verify()
}

#[cfg(test)]
mod tests {
    use super::{verify_binding, ImmutableBinding, IMMUTABLE_BINDING_SCHEMA};
    use crate::sign::{sign_canonical, SignatureRole, TestSigningKey};
    use crate::{sha256_hex, EvidenceError};

    const COMMIT: &str = "0123456789abcdef0123456789abcdef01234567";
    const ENV: &str = "development";

    fn sample_binding() -> ImmutableBinding {
        ImmutableBinding::sign(
            "owner-test",
            COMMIT,
            "evidence-record/v1",
            ENV,
            sha256_hex(b"a"),
        )
        .expect("sign binding")
    }

    #[test]
    fn sign_and_verify_roundtrip() {
        let binding = sample_binding();
        assert_eq!(binding.source_commit(), COMMIT);
        assert_eq!(binding.schema(), "evidence-record/v1");
        assert!(binding.verify().is_ok());
        assert!(verify_binding(&binding).is_ok());
    }

    #[test]
    fn canonical_bytes_contain_all_bound_fields() {
        let binding = sample_binding();
        let bytes = String::from_utf8(binding.canonical_bytes()).expect("utf8");
        assert!(bytes.starts_with(IMMUTABLE_BINDING_SCHEMA));
        assert!(bytes.contains(COMMIT));
        assert!(bytes.contains("evidence-record/v1"));
        assert!(bytes.contains(ENV));
    }

    #[test]
    fn verify_rejects_tampered_signature() {
        // 用另一份 payload 的签名替换 binding 的 Owner 签名 → verify 失败。
        let mut binding = sample_binding();
        let forged = sign_canonical(
            &TestSigningKey,
            SignatureRole::Owner,
            "owner-test",
            b"other-payload",
        )
        .expect("sign forged");
        binding.owner_signature = forged;
        assert!(matches!(
            binding.verify(),
            Err(EvidenceError::SignatureInvalid)
        ));
    }

    #[test]
    fn verify_rejects_tampered_artifact_digest() {
        // 篡改 artifact_digest（签名仍是旧内容的签名）→ verify 失败。
        let mut binding = sample_binding();
        binding.artifact_digest = sha256_hex(b"tampered");
        assert!(matches!(
            binding.verify(),
            Err(EvidenceError::SignatureInvalid)
        ));
    }

    #[test]
    fn sign_rejects_invalid_commit() {
        let result = ImmutableBinding::sign(
            "owner-test",
            "not-a-commit",
            "evidence-record/v1",
            ENV,
            sha256_hex(b"a"),
        );
        assert!(matches!(result, Err(EvidenceError::InvalidDigest(_))));
    }

    #[test]
    fn sign_rejects_invalid_digest() {
        let result = ImmutableBinding::sign("owner-test", COMMIT, "evidence-record/v1", ENV, "xyz");
        assert!(matches!(result, Err(EvidenceError::InvalidDigest(_))));
    }
}
