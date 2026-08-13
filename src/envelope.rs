use serde::Serialize;
use serde_json::Value;
use uuid::Uuid;

use crate::{SCHEMA_VERSION, error::DebugError};

#[derive(Debug, Serialize)]
pub struct SuccessEnvelope<T: Serialize> {
    pub schema_version: &'static str,
    pub ok: bool,
    pub operation: String,
    pub operation_id: String,
    pub data: T,
    pub warnings: Vec<String>,
    pub artifacts: Vec<Value>,
}

impl<T: Serialize> SuccessEnvelope<T> {
    pub fn new(operation: impl Into<String>, data: T) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: true,
            operation: operation.into(),
            operation_id: format!("op_{}", Uuid::new_v4().simple()),
            data,
            warnings: Vec::new(),
            artifacts: Vec::new(),
        }
    }
}

#[derive(Debug, Serialize)]
pub struct ErrorEnvelope<'a> {
    pub schema_version: &'static str,
    pub ok: bool,
    pub operation: &'a str,
    pub operation_id: String,
    pub error: ErrorPayload<'a>,
}

#[derive(Debug, Serialize)]
pub struct ErrorPayload<'a> {
    pub code: crate::error::ErrorCode,
    pub message: &'a str,
    pub retryable: bool,
    pub details: &'a Value,
    pub suggested_actions: &'a [crate::error::SuggestedAction],
}

impl<'a> ErrorEnvelope<'a> {
    pub fn new(operation: &'a str, error: &'a DebugError) -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            ok: false,
            operation,
            operation_id: format!("op_{}", Uuid::new_v4().simple()),
            error: ErrorPayload {
                code: error.code,
                message: &error.message,
                retryable: error.retryable,
                details: &error.details,
                suggested_actions: &error.suggested_actions,
            },
        }
    }
}
