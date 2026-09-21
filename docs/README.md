# evidence 设计说明

`EvidenceStore` 是唯一的追加 seam。领域 crate 负责生成决策与 provenance，Evidence 只负责
校验、规范化与追加回执；这样基础设施 crate 就不必复制领域 DTO，也不会形成反向业务依赖。

## 分层

| 层 | 类型 | 职责 |
| --- | --- | --- |
| 记录 | `EvidenceRecord`、`ReceiptBinding` | 领域无关的规范化 payload 与 B1 生产绑定 |
| 结果 | `AppendReceipt`、`ResultUnknownReceipt`、`EvidenceAppendOutcome` | 区分已确认新增、幂等重放与远程结果未知 |
| 能力 | `EvidenceDurability` | 显式声明实现能提供多强的持久性，不靠调用方猜测 |
| 端口 | `EvidenceStore`、`AsyncEvidenceStore` | 同步追加面 + 远程异步 port |
| 实现 | `MemoryEvidenceStore`、`FileEvidenceStore` | `Volatile`（测试用）与 `LocalDurable`（本地文件） |
| 只读 | `EvidenceReader` | 不触发写入的查询面 |
| 完整性 | `SigningKey`、`ProtectedSignature`、`LineageBinding` | canonical 签名、审批角色与溯源校验 |

## 关键设计取舍

1. **结果未知必须显式**。远程追加无法确认提交状态时返回 `ResultUnknown`，而不是伪装成失败或成功；
   调用方必须在恢复查询完成前保留 `ResultUnknownReceipt`。
2. **幂等能力不靠默认继承**。未实现幂等追加的适配器默认返回 `IdempotencyUnsupported`，
   避免调用方把普通追加误认为可安全重试。
3. **持久性能力由实现声明**。`durability()` 由实现方给出，调用方据此决定是否允许在生产路径使用；
   例如组合根可以拒绝 `Volatile` store。
4. **锁残留 fail-closed**。异常退出后不猜测锁是否过期，宁愿拒绝服务也不允许两个进程写同一文件。
5. **不复制业务 DTO**。本 crate 只保存可追溯引用与摘要，决策 DTO 与 provenance 的所有权留在领域层。

## 边界

当前 core 提供本地 durable 文件适配器、测试用内存适配器与异步远程 port。远程签名、查询权限、
不可抵赖与合规审计仍属消费方职责，不在本 crate 范围内。
