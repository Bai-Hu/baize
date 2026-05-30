pub mod approval;
pub mod cert;
pub mod constraint;
pub mod crypto;
pub mod error;
pub mod identity;
pub mod labels;
pub mod scope;
pub mod storage;
pub mod workspace;

pub use error::{Error, Result};
pub use storage::{BlobStore, Storage};
pub use crypto::{
    CryptoProvider, KeyEncryption, KeyExchange, KeyDerivation,
    SessionCipher, RequestSigner,
};
pub use identity::{AgentIdentity, IdentityProvider};

/// Root agent 的固定 ID，在 init 时自动创建
pub const ROOT_AGENT_ID: &str = "baize-root";
