use thiserror::Error;

#[derive(Error, Debug)]
pub enum Error {
    #[error("validation error: {0}")]
    Validation(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("conflict: {0}")]
    Conflict(String),

    #[error("permission denied: {0}")]
    PermissionDenied(String),

    #[error("user decision required: {0}")]
    NeedUserDecision(String),

    #[error("certificate error: {0}")]
    Certificate(String),

    #[error("storage error: {0}")]
    Storage(String, #[source] Option<rusqlite::Error>),

    #[error("channel closed: {0}")]
    ChannelClosed(String),

    #[error("constraint violation: {0}")]
    ConstraintViolation(String),

    #[error("chain broken: {0}")]
    ChainBroken(String),

    #[error("invalid signature: {0}")]
    SignatureInvalid(String),

    #[error("expired timestamp: {0}")]
    ExpiredTimestamp(String),

    #[error("credential expired: {0}")]
    CredentialExpired(String),

    #[error("intent expired: {0}")]
    IntentExpired(String),

    #[error("authorization expired: {0}")]
    AuthorizationExpired(String),

    #[error("{0}")]
    Internal(#[from] anyhow::Error),
}

pub type Result<T> = std::result::Result<T, Error>;

impl From<rusqlite::Error> for Error {
    fn from(e: rusqlite::Error) -> Self {
        Error::Storage(e.to_string(), Some(e))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_display_format() {
        let e = Error::Validation("bad input".to_string());
        assert_eq!(format!("{}", e), "validation error: bad input");

        let e = Error::NotFound("thing".to_string());
        assert!(format!("{}", e).contains("thing"));

        let e = Error::PermissionDenied("no access".to_string());
        assert!(format!("{}", e).contains("no access"));
    }

    #[test]
    fn error_from_rusqlite() {
        let rusqlite_err = rusqlite::Error::InvalidColumnIndex(999);
        let e: Error = rusqlite_err.into();
        match e {
            Error::Storage(msg, Some(_)) => assert!(msg.contains("999")),
            _ => panic!("expected Storage with source"),
        }
    }

    #[test]
    fn error_from_anyhow() {
        let e: Error = anyhow::anyhow!("something broke").into();
        match e {
            Error::Internal(err) => assert!(err.to_string().contains("something broke")),
            _ => panic!("expected Internal"),
        }
    }

    #[test]
    fn v1_error_variants() {
        assert!(format!("{}", Error::ChannelClosed("chan-1".into())).contains("chan-1"));
        assert!(format!("{}", Error::ConstraintViolation("budget exceeded".into())).contains("budget exceeded"));
        assert!(format!("{}", Error::ChainBroken("hash mismatch".into())).contains("hash mismatch"));
        assert!(format!("{}", Error::SignatureInvalid("bad hmac".into())).contains("bad hmac"));
        assert!(format!("{}", Error::ExpiredTimestamp("too old".into())).contains("too old"));
        assert!(format!("{}", Error::CredentialExpired("agent-1".into())).contains("agent-1"));
        assert!(format!("{}", Error::IntentExpired("intent-1".into())).contains("intent-1"));
        assert!(format!("{}", Error::AuthorizationExpired("authz-1".into())).contains("authz-1"));
    }
}
