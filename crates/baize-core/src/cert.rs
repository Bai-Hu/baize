use crate::error::{Error, Result};
use crate::scope::Scope;
use rcgen::{CertificateParams, DnType, IsCa, KeyPair, BasicConstraints, Certificate};
use serde::{Deserialize, Serialize};
use asn1_rs::Oid;

// ─── 数据类型 ───

/// 凭证生命周期状态（IDN-LCM）
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum CredentialStatus {
    Active,
    Suspended,
    Revoked,
    Expired,
}

impl Default for CredentialStatus {
    fn default() -> Self {
        CredentialStatus::Active
    }
}

impl std::fmt::Display for CredentialStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CredentialStatus::Active => write!(f, "active"),
            CredentialStatus::Suspended => write!(f, "suspended"),
            CredentialStatus::Revoked => write!(f, "revoked"),
            CredentialStatus::Expired => write!(f, "expired"),
        }
    }
}

impl std::str::FromStr for CredentialStatus {
    type Err = String;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        match s {
            "active" => Ok(CredentialStatus::Active),
            "suspended" => Ok(CredentialStatus::Suspended),
            "revoked" => Ok(CredentialStatus::Revoked),
            "expired" => Ok(CredentialStatus::Expired),
            _ => Err(format!("invalid credential status: '{}'", s)),
        }
    }
}

/// 证书身份信息（存储在证书的自定义扩展中）
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CertIdentity {
    pub agent_id: String,
    pub parent_id: Option<String>,
    pub level: u8,
    pub zones: Vec<String>,
    /// 凭证生命周期状态（v1 新增，向后兼容：默认 Active）
    #[serde(default)]
    pub status: CredentialStatus,
}

/// 签发结果：证书 PEM + 私钥 PEM + 身份信息（用于持久化）
#[derive(Debug, Clone)]
pub struct CertBundle {
    pub cert_pem: String,
    pub key_pem: String,
    pub identity: CertIdentity,
}

/// 签发上下文：持有内存中的 Certificate + KeyPair（用于签发子证书）
pub struct IssuerCtx {
    cert: Certificate,
    key: KeyPair,
}

// ─── OID 定义（自定义扩展） ───

/// 白泽自定义 OID: 1.3.6.1.4.1.99999.1
/// 同时用于 rcgen 签发（&[u64]）和 x509-parser 解析（Oid）
const BAIZE_IDENTITY_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 99999, 1];

// ─── 证书工具 ───

pub struct CertTool;

impl CertTool {
    /// 生成 Root CA 自签名证书
    pub fn generate_root_ca() -> Result<(CertBundle, IssuerCtx)> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "Baize Root CA");
        params.distinguished_name.push(DnType::OrganizationName, "Baize");
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);

        // Root CA: level 4, 所有 zone（"*" 通配）
        let identity = CertIdentity {
            agent_id: crate::ROOT_AGENT_ID.to_string(),
            parent_id: None,
            level: 4,
            zones: vec!["*".to_string()],
            status: CredentialStatus::Active,
        };
        let identity_json = serde_json::to_string(&identity)
            .map_err(|e| Error::Certificate(format!("serialize identity: {}", e)))?;

        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            BAIZE_IDENTITY_OID,
            identity_json.as_bytes().to_vec(),
        )];

        let key = KeyPair::generate()
            .map_err(|e| Error::Certificate(format!("generate key: {}", e)))?;
        let cert = params.self_signed(&key)
            .map_err(|e| Error::Certificate(format!("self-signed: {}", e)))?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        let bundle = CertBundle {
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            identity,
        };

        let ctx = IssuerCtx { cert, key };

        Ok((bundle, ctx))
    }

    /// 签发 Agent 证书（由 Root CA 或父 Agent 签发）
    pub fn issue_agent(
        agent_id: &str,
        scope: &Scope,
        issuer: &IssuerCtx,
        parent_id: Option<&str>,
    ) -> Result<(CertBundle, IssuerCtx)> {
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, agent_id);
        params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained); // Agent 可签发子 Agent

        let identity = CertIdentity {
            agent_id: agent_id.to_string(),
            parent_id: parent_id.map(String::from),
            level: scope.level.0,
            zones: scope.zones.iter().cloned().collect(),
            status: CredentialStatus::Active,
        };
        let identity_json = serde_json::to_string(&identity)
            .map_err(|e| Error::Certificate(format!("serialize identity: {}", e)))?;

        params.custom_extensions = vec![rcgen::CustomExtension::from_oid_content(
            BAIZE_IDENTITY_OID,
            identity_json.as_bytes().to_vec(),
        )];

        let key = KeyPair::generate()
            .map_err(|e| Error::Certificate(format!("generate key: {}", e)))?;

        let cert = params.signed_by(&key, &issuer.cert, &issuer.key)
            .map_err(|e| Error::Certificate(format!("sign agent cert: {}", e)))?;

        let cert_pem = cert.pem();
        let key_pem = key.serialize_pem();

        let bundle = CertBundle {
            cert_pem: cert_pem.clone(),
            key_pem: key_pem.clone(),
            identity,
        };

        let ctx = IssuerCtx { cert, key };

        Ok((bundle, ctx))
    }

    /// 从证书 PEM + 私钥 PEM 恢复 IssuerCtx（用于跨重启恢复签发能力）
    ///
    /// 限制：使用 self_signed 重建证书。对 Root CA 这正确（Root 本身是自签名的）。
    /// 对 Agent 证书，重建后的 DER 与原始不同（自签名 vs 父签名），但签发子证书
    /// 仍然正常（只需公私钥对一致）。如果需要在恢复后验证该证书自身的签名链，
    /// 应使用存储中的原始 PEM，而非重建后的证书。
    pub fn recover_issuer(cert_pem: &str, key_pem: &str) -> Result<IssuerCtx> {
        let key = KeyPair::from_pem(key_pem)
            .map_err(|e| Error::Certificate(format!("recover key from PEM: {}", e)))?;
        let params = CertificateParams::from_ca_cert_pem(cert_pem)
            .map_err(|e| Error::Certificate(format!("recover cert params from PEM: {}", e)))?;
        let cert = params.self_signed(&key)
            .map_err(|e| Error::Certificate(format!("re-create self-signed cert: {}", e)))?;
        Ok(IssuerCtx { cert, key })
    }

    /// 从证书 PEM 中提取身份信息
    /// 使用 x509-parser 按 OID 精确定位自定义扩展，而非子串匹配
    pub fn parse_identity(cert_pem: &str) -> Result<CertIdentity> {
        let p = pem::parse(cert_pem)
            .map_err(|e| Error::Certificate(format!("parse PEM: {}", e)))?;

        let (_, cert) = x509_parser::parse_x509_certificate(p.contents())
            .map_err(|e| Error::Certificate(format!("parse X.509: {:?}", e)))?;

        Self::extract_identity_from_cert(&cert)
    }

    /// 从已解析的 X509Certificate 中提取 identity 扩展
    fn extract_identity_from_cert(cert: &x509_parser::certificate::X509Certificate<'_>) -> Result<CertIdentity> {
        let baize_oid = Oid::from(BAIZE_IDENTITY_OID)
            .map_err(|e| Error::Certificate(format!("build OID: {:?}", e)))?;

        let ext = cert.extensions().iter()
            .find(|e| e.oid == baize_oid)
            .ok_or_else(|| Error::Certificate("identity extension not found".into()))?;

        let json_str = std::str::from_utf8(ext.value)
            .map_err(|e| Error::Certificate(format!("extension not UTF-8: {}", e)))?;

        let identity: CertIdentity = serde_json::from_str(json_str)
            .map_err(|e| Error::Certificate(format!("parse identity: {}", e)))?;

        Ok(identity)
    }

    /// 验证证书链（子证书 → ... → Root CA）
    /// 1. 逐级验证 X.509 密码学签名（child 由 parent 的公钥签发）
    /// 2. 验证 identity 扩展中 parent_id 文本连续性
    pub fn verify_chain(cert_chain: &[&str], root_cert_pem: &str) -> Result<()> {
        if cert_chain.is_empty() {
            return Err(Error::Certificate("empty cert chain".into()));
        }

        // 解析所有证书的 DER 内容
        let root_der = Self::pem_to_der(root_cert_pem)?;
        let chain_der: Vec<_> = cert_chain.iter()
            .map(|pem| Self::pem_to_der(pem))
            .collect::<Result<Vec<_>>>()?;

        // 解析为 X509Certificate
        let root_cert = x509_parser::parse_x509_certificate(&root_der)
            .map_err(|e| Error::Certificate(format!("parse root cert: {:?}", e)))?
            .1;
        let parsed_certs: Vec<_> = chain_der.iter()
            .map(|der| x509_parser::parse_x509_certificate(der)
                .map_err(|e| Error::Certificate(format!("parse chain cert: {:?}", e))))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .map(|(_, cert)| cert)
            .collect();

        // 1. 逐级验证签名：child[i] 由 parent[i+1] 签发，最后一个由 root 签发
        for (i, child) in parsed_certs.iter().enumerate() {
            let parent = if i + 1 < parsed_certs.len() {
                &parsed_certs[i + 1]
            } else {
                &root_cert
            };
            child.verify_signature(Some(parent.public_key()))
                .map_err(|e| Error::Certificate(
                    format!("signature verification failed at index {}: {:?}", i, e)
                ))?;
        }

        // Root 自签名验证
        root_cert.verify_signature(None)
            .map_err(|e| Error::Certificate(
                format!("root self-signature verification failed: {:?}", e)
            ))?;

        // 2. 验证 identity 链连续性（复用已解析的证书）
        let mut expected_parent: Option<String> = None;
        for (i, cert) in parsed_certs.iter().enumerate() {
            let identity = Self::extract_identity_from_cert(cert)?;
            if i == 0 {
                expected_parent = identity.parent_id.clone();
            } else {
                let expected = expected_parent
                    .ok_or_else(|| Error::Certificate("broken parent chain".into()))?;
                if identity.agent_id != expected {
                    return Err(Error::Certificate(format!(
                        "chain break: expected parent {}, found {}",
                        expected, identity.agent_id
                    )));
                }
                expected_parent = identity.parent_id.clone();
            }
        }

        let root_identity = Self::extract_identity_from_cert(&root_cert)?;
        if let Some(ref pid) = expected_parent {
            if root_identity.agent_id != *pid {
                return Err(Error::Certificate(format!(
                    "chain does not reach root: expected {}, found {}",
                    root_identity.agent_id, pid
                )));
            }
        }

        Ok(())
    }

    /// 生成独立的密钥对 PEM（用于 INF-KMS 多用途密钥）
    pub fn generate_key_pair() -> Result<String> {
        let key = KeyPair::generate()
            .map_err(|e| Error::Certificate(format!("generate key pair: {}", e)))?;
        Ok(key.serialize_pem())
    }

    /// 解析 PEM 为 DER 字节
    fn pem_to_der(cert_pem: &str) -> Result<Vec<u8>> {
        let p = pem::parse(cert_pem)
            .map_err(|e| Error::Certificate(format!("parse PEM: {}", e)))?;
        Ok(p.contents().to_vec())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::scope::Level;

    #[test]
    fn root_ca_generation() {
        let (root, _ctx) = CertTool::generate_root_ca().unwrap();
        assert!(root.cert_pem.contains("CERTIFICATE"));
        assert!(root.key_pem.contains("PRIVATE KEY"));
        assert_eq!(root.identity.agent_id, "baize-root");
        assert_eq!(root.identity.level, 4);
    }

    #[test]
    fn agent_cert_issuance() {
        let (_root, root_ctx) = CertTool::generate_root_ca().unwrap();
        let scope = Scope::new(Level(2), vec!["A", "B"]).unwrap();

        let (agent, _agent_ctx) = CertTool::issue_agent(
            "agent-001",
            &scope,
            &root_ctx,
            Some("baize-root"),
        ).unwrap();

        assert_eq!(agent.identity.agent_id, "agent-001");
        assert_eq!(agent.identity.level, 2);
        assert!(agent.identity.zones.contains(&"A".to_string()));
        assert!(agent.identity.zones.contains(&"B".to_string()));
        assert_eq!(agent.identity.parent_id.as_deref(), Some("baize-root"));
    }

    #[test]
    fn sub_agent_cert() {
        let (_root, root_ctx) = CertTool::generate_root_ca().unwrap();
        let parent_scope = Scope::new(Level(3), vec!["A", "B", "C"]).unwrap();
        let (_parent, parent_ctx) = CertTool::issue_agent(
            "agent-001",
            &parent_scope,
            &root_ctx,
            Some("baize-root"),
        ).unwrap();

        let child_scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let (child, _child_ctx) = CertTool::issue_agent(
            "agent-002",
            &child_scope,
            &parent_ctx,
            Some("agent-001"),
        ).unwrap();

        assert_eq!(child.identity.agent_id, "agent-002");
        assert_eq!(child.identity.level, 2);
        assert_eq!(child.identity.parent_id.as_deref(), Some("agent-001"));
    }

    #[test]
    fn cert_chain_valid() {
        let (root, root_ctx) = CertTool::generate_root_ca().unwrap();
        let parent_scope = Scope::new(Level(3), vec!["A", "B", "C"]).unwrap();
        let (parent, parent_ctx) = CertTool::issue_agent(
            "agent-001",
            &parent_scope,
            &root_ctx,
            Some("baize-root"),
        ).unwrap();

        let child_scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let (child, _child_ctx) = CertTool::issue_agent(
            "agent-002",
            &child_scope,
            &parent_ctx,
            Some("agent-001"),
        ).unwrap();

        // 验证链: child → parent → root
        let result = CertTool::verify_chain(
            &[&child.cert_pem, &parent.cert_pem],
            &root.cert_pem,
        );
        assert!(result.is_ok());
    }

    #[test]
    fn cert_chain_broken() {
        // 创建三层链: child → parent → root，然后验证时去掉中间证书
        let (root, root_ctx) = CertTool::generate_root_ca().unwrap();
        let parent_scope = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        let (_parent, parent_ctx) = CertTool::issue_agent(
            "parent-001",
            &parent_scope,
            &root_ctx,
            Some("baize-root"),
        ).unwrap();

        let child_scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let (child, _child_ctx) = CertTool::issue_agent(
            "child-001",
            &child_scope,
            &parent_ctx,
            Some("parent-001"),
        ).unwrap();

        // 只提供 child，不提供 parent → 链断裂（parent_id "parent-001" ≠ root "baize-root"）
        let result = CertTool::verify_chain(
            &[&child.cert_pem],
            &root.cert_pem,
        );
        assert!(result.is_err());
    }

    #[test]
    fn verify_chain_valid_signature() {
        // root → parent → child: 完整链应通过签名验证
        let (root, root_ctx) = CertTool::generate_root_ca().unwrap();
        let parent_scope = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        let (parent, parent_ctx) = CertTool::issue_agent(
            "parent-001", &parent_scope, &root_ctx, Some("baize-root"),
        ).unwrap();
        let child_scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let (child, _) = CertTool::issue_agent(
            "child-001", &child_scope, &parent_ctx, Some("parent-001"),
        ).unwrap();

        // 完整链: [child, parent] → root
        let result = CertTool::verify_chain(&[child.cert_pem.as_str(), parent.cert_pem.as_str()], &root.cert_pem);
        assert!(result.is_ok(), "valid chain should pass: {:?}", result);
    }

    #[test]
    fn verify_chain_cross_sign_fails() {
        // root 签发 parent-1，parent-1 签发 child
        // 但用 parent-2（另一个 root 签发）来伪造链中间节点
        let (root1, root1_ctx) = CertTool::generate_root_ca().unwrap();
        let (_root2, root2_ctx) = CertTool::generate_root_ca().unwrap();

        let parent1_scope = Scope::new(Level(3), vec!["A"]).unwrap();
        let (parent1, parent1_ctx) = CertTool::issue_agent(
            "parent-1", &parent1_scope, &root1_ctx, Some("baize-root"),
        ).unwrap();

        // parent-2 由 root2 签发
        let parent2_scope = Scope::new(Level(3), vec!["A"]).unwrap();
        let (parent2, _) = CertTool::issue_agent(
            "parent-1", &parent2_scope, &root2_ctx, Some("baize-root"),
        ).unwrap();

        let child_scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let (child, _) = CertTool::issue_agent(
            "child-1", &child_scope, &parent1_ctx, Some("parent-1"),
        ).unwrap();

        // 正确链: [child, parent1] → root1 ✓
        assert!(CertTool::verify_chain(
            &[&child.cert_pem, &parent1.cert_pem], &root1.cert_pem
        ).is_ok());

        // 伪造链: [child, parent2] → root1 — parent2 由 root2 签发，root1 的公钥验不过
        let result = CertTool::verify_chain(
            &[&child.cert_pem, &parent2.cert_pem], &root1.cert_pem,
        );
        assert!(result.is_err(), "cross-signed parent should fail");
    }

    #[test]
    fn verify_chain_wrong_root_fails() {
        // 用 root-A 签发 agent，用 root-B 验证 → 签名不匹配
        let (_root_a, root_a_ctx) = CertTool::generate_root_ca().unwrap();
        let (root_b, _) = CertTool::generate_root_ca().unwrap();
        let scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let (agent, _) = CertTool::issue_agent(
            "agent-001", &scope, &root_a_ctx, Some("baize-root"),
        ).unwrap();

        let result = CertTool::verify_chain(&[&agent.cert_pem], &root_b.cert_pem);
        assert!(result.is_err(), "wrong root should fail");
    }

    #[test]
    fn cert_scope_parsing() {
        let (_root, root_ctx) = CertTool::generate_root_ca().unwrap();
        let scope = Scope::new(Level(2), vec!["A", "B"]).unwrap();
        let (agent, _agent_ctx) = CertTool::issue_agent(
            "agent-001",
            &scope,
            &root_ctx,
            Some("baize-root"),
        ).unwrap();

        let identity = CertTool::parse_identity(&agent.cert_pem).unwrap();
        assert_eq!(identity.agent_id, "agent-001");
        assert_eq!(identity.level, 2);
        assert_eq!(identity.zones.len(), 2);
    }

    #[test]
    fn parse_identity_invalid_pem() {
        let result = CertTool::parse_identity("not a pem");
        assert!(result.is_err());
    }

    #[test]
    fn verify_chain_empty() {
        let (root, _) = CertTool::generate_root_ca().unwrap();
        let result = CertTool::verify_chain(&[], &root.cert_pem);
        assert!(result.is_err());
    }

    #[test]
    fn root_ca_has_wildcard_zone() {
        let (root, _) = CertTool::generate_root_ca().unwrap();
        assert!(root.identity.zones.contains(&"*".to_string()));
        assert_eq!(root.identity.level, 4);
        assert!(root.identity.parent_id.is_none());
    }

    #[test]
    fn agent_cert_not_root() {
        let (_, root_ctx) = CertTool::generate_root_ca().unwrap();
        let scope = Scope::new(Level(1), vec!["X"]).unwrap();
        let (agent, _) = CertTool::issue_agent("agent-x", &scope, &root_ctx, Some("baize-root")).unwrap();
        assert_ne!(agent.identity.level, 4);
        assert_eq!(agent.identity.zones.len(), 1);
    }

    #[test]
    fn parse_identity_uses_oid_not_substring() {
        // 验证 parse_identity 通过 OID 精确定位扩展，而非子串匹配
        let (_, root_ctx) = CertTool::generate_root_ca().unwrap();
        let scope = Scope::new(Level(3), vec!["A"]).unwrap();
        let (agent, _) = CertTool::issue_agent("test-oid", &scope, &root_ctx, Some("baize-root")).unwrap();

        // 应能正确解析
        let identity = CertTool::parse_identity(&agent.cert_pem).unwrap();
        assert_eq!(identity.agent_id, "test-oid");
        assert_eq!(identity.level, 3);
    }

    #[test]
    fn recover_issuer_can_sign_children() {
        // 验证 recover_issuer 后仍可签发子证书
        let (_, root_ctx) = CertTool::generate_root_ca().unwrap();
        let parent_scope = Scope::new(Level(3), vec!["A", "B"]).unwrap();
        let (parent, _parent_ctx) = CertTool::issue_agent(
            "parent", &parent_scope, &root_ctx, Some("baize-root"),
        ).unwrap();

        // 恢复 issuer
        let recovered = CertTool::recover_issuer(&parent.cert_pem, &parent.key_pem).unwrap();

        // 用恢复的 issuer 签发子证书
        let child_scope = Scope::new(Level(2), vec!["A"]).unwrap();
        let result = CertTool::issue_agent("child", &child_scope, &recovered, Some("parent"));
        assert!(result.is_ok());

        let (child, _) = result.unwrap();
        assert_eq!(child.identity.agent_id, "child");
        assert_eq!(child.identity.parent_id.as_deref(), Some("parent"));
    }

    #[test]
    fn parse_identity_cert_without_extension_fails() {
        // 一个没有白泽扩展的 PEM 应该失败
        // 生成一个普通的自签名证书（无自定义扩展）
        let mut params = CertificateParams::default();
        params.distinguished_name.push(DnType::CommonName, "No Extension");
        let key = KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        let pem = cert.pem();

        let result = CertTool::parse_identity(&pem);
        assert!(result.is_err());
    }

    #[test]
    fn credential_status_default_is_active() {
        let status: CredentialStatus = Default::default();
        assert_eq!(status, CredentialStatus::Active);
    }

    #[test]
    fn credential_status_display() {
        assert_eq!(format!("{}", CredentialStatus::Active), "active");
        assert_eq!(format!("{}", CredentialStatus::Suspended), "suspended");
        assert_eq!(format!("{}", CredentialStatus::Revoked), "revoked");
        assert_eq!(format!("{}", CredentialStatus::Expired), "expired");
    }

    #[test]
    fn credential_status_serde_roundtrip() {
        for status in [
            CredentialStatus::Active,
            CredentialStatus::Suspended,
            CredentialStatus::Revoked,
            CredentialStatus::Expired,
        ] {
            let json = serde_json::to_string(&status).unwrap();
            let back: CredentialStatus = serde_json::from_str(&json).unwrap();
            assert_eq!(status, back);
        }
    }

    #[test]
    fn cert_identity_backward_compatible_deserialize() {
        // v0 JSON 没有 status 字段，反序列化时默认为 Active
        let v0_json = r#"{"agent_id":"agent-1","parent_id":"baize-root","level":2,"zones":["A"]}"#;
        let identity: CertIdentity = serde_json::from_str(v0_json).unwrap();
        assert_eq!(identity.agent_id, "agent-1");
        assert_eq!(identity.status, CredentialStatus::Active);
    }

    #[test]
    fn cert_identity_with_status_serialize() {
        let identity = CertIdentity {
            agent_id: "agent-1".into(),
            parent_id: Some("baize-root".into()),
            level: 2,
            zones: vec!["A".into()],
            status: CredentialStatus::Suspended,
        };
        let json = serde_json::to_string(&identity).unwrap();
        assert!(json.contains("suspended"));
        let back: CertIdentity = serde_json::from_str(&json).unwrap();
        assert_eq!(back.status, CredentialStatus::Suspended);
    }

    #[test]
    fn root_ca_has_active_status() {
        let (root, _) = CertTool::generate_root_ca().unwrap();
        assert_eq!(root.identity.status, CredentialStatus::Active);
    }
}
