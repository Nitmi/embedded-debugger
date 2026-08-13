use serde::Serialize;
use serde_json::{Value, json};
use thiserror::Error;

pub type Result<T> = std::result::Result<T, DebugError>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum ErrorCode {
    ConfigInvalid,
    FixtureInvalid,
    ProbeUnavailable,
    ProbeAmbiguous,
    TargetUnavailable,
    TargetAmbiguous,
    CapabilityUnavailable,
    ConfirmationMismatch,
    PlanStale,
    VerificationFailed,
    EvidenceInvalid,
    OutputExists,
    PermissionDenied,
    ProtocolError,
    Timeout,
    Internal,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SuggestedAction {
    pub action: String,
    pub arguments: Value,
}

impl SuggestedAction {
    pub fn new(action: impl Into<String>, arguments: Value) -> Self {
        Self {
            action: action.into(),
            arguments,
        }
    }
}

#[derive(Debug, Error)]
#[error("{message}")]
pub struct DebugError {
    pub code: ErrorCode,
    pub message: String,
    pub retryable: bool,
    pub exit_code: i32,
    pub details: Value,
    pub suggested_actions: Vec<SuggestedAction>,
}

impl DebugError {
    pub fn new(
        code: ErrorCode,
        message: impl Into<String>,
        exit_code: i32,
        details: Value,
    ) -> Self {
        Self {
            code,
            message: message.into(),
            retryable: false,
            exit_code,
            details,
            suggested_actions: Vec::new(),
        }
    }

    pub fn config(message: impl Into<String>, details: Value) -> Self {
        Self::new(ErrorCode::ConfigInvalid, message, 7, details)
    }

    pub fn fixture(message: impl Into<String>, details: Value) -> Self {
        Self::new(ErrorCode::FixtureInvalid, message, 7, details)
    }

    pub fn unavailable(code: ErrorCode, message: impl Into<String>, details: Value) -> Self {
        Self::new(code, message, 4, details)
    }

    pub fn confirmation(expected: &str, received: &str) -> Self {
        let mut error = Self::new(
            ErrorCode::ConfirmationMismatch,
            "flash confirmation digest does not match the current plan",
            2,
            json!({
                "expected_confirm_digest": expected,
                "received_confirm_digest": received,
            }),
        );
        error.suggested_actions.push(SuggestedAction::new(
            "review_flash_plan",
            json!({"command": "flash plan"}),
        ));
        error
    }

    pub fn verification(message: impl Into<String>, details: Value) -> Self {
        Self::new(ErrorCode::VerificationFailed, message, 3, details)
    }

    pub fn evidence(message: impl Into<String>, details: Value) -> Self {
        Self::new(ErrorCode::EvidenceInvalid, message, 7, details)
    }

    pub fn output_exists(path: &str) -> Self {
        Self::new(
            ErrorCode::OutputExists,
            "refusing to overwrite an existing evidence file",
            2,
            json!({"path": path}),
        )
    }

    pub fn io(operation: &str, path: Option<&str>, source: &std::io::Error) -> Self {
        let code = if source.kind() == std::io::ErrorKind::PermissionDenied {
            ErrorCode::PermissionDenied
        } else {
            ErrorCode::Internal
        };
        let exit_code = if code == ErrorCode::PermissionDenied {
            8
        } else {
            10
        };
        Self::new(
            code,
            format!("{operation} failed: {source}"),
            exit_code,
            json!({"operation": operation, "path": path}),
        )
    }
}
