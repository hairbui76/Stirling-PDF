//! Provider-neutral, tool-forced structured output.
//!
//! Agents describe the result schema they require. Provider adapters translate
//! that request to their native tool/function mechanism and return only the
//! input sent to the named tool. This keeps provider-specific response parsing
//! outside agent orchestration.

use std::{
    error::Error,
    fmt::{Display, Formatter},
    future::Future,
    pin::Pin,
    sync::Arc,
};

use serde_json::Value;

/// A typed failure from a structured-output model provider.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ModelError {
    message: String,
}

impl ModelError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl Display for ModelError {
    fn fmt(&self, formatter: &mut Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl Error for ModelError {}

/// The one forced tool/function an agent permits a model to call.
#[derive(Clone, Copy, Debug)]
pub struct ToolDefinition<'request> {
    pub name: &'request str,
    pub description: &'request str,
    pub input_schema: &'request Value,
}

/// Provider seam for an agent that requires JSON matching a named tool schema.
pub trait StructuredOutputModel: Send + Sync {
    fn complete<'request>(
        &'request self,
        system_prompt: &'request str,
        prompt: &'request str,
        max_tokens: u32,
        tool: ToolDefinition<'request>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, ModelError>> + Send + 'request>>;
}

impl<T: StructuredOutputModel + ?Sized> StructuredOutputModel for Arc<T> {
    fn complete<'request>(
        &'request self,
        system_prompt: &'request str,
        prompt: &'request str,
        max_tokens: u32,
        tool: ToolDefinition<'request>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, ModelError>> + Send + 'request>> {
        (**self).complete(system_prompt, prompt, max_tokens, tool)
    }
}
