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
use tokio::sync::Semaphore;

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

/// Applies one process-wide concurrency ceiling to a structured-output model.
///
/// Multiple wrappers can share the same semaphore so smart and fast model
/// tiers consume one provider-account budget, matching the legacy runtime.
pub struct ConcurrencyLimitedModel {
    wrapped: Arc<dyn StructuredOutputModel>,
    semaphore: Arc<Semaphore>,
}

impl ConcurrencyLimitedModel {
    #[must_use]
    pub fn new(wrapped: Arc<dyn StructuredOutputModel>, semaphore: Arc<Semaphore>) -> Self {
        Self { wrapped, semaphore }
    }
}

impl StructuredOutputModel for ConcurrencyLimitedModel {
    fn complete<'request>(
        &'request self,
        system_prompt: &'request str,
        prompt: &'request str,
        max_tokens: u32,
        tool: ToolDefinition<'request>,
    ) -> Pin<Box<dyn Future<Output = Result<Value, ModelError>> + Send + 'request>> {
        Box::pin(async move {
            let _permit = self
                .semaphore
                .acquire()
                .await
                .map_err(|_| ModelError::new("model concurrency limiter is unavailable"))?;
            self.wrapped
                .complete(system_prompt, prompt, max_tokens, tool)
                .await
        })
    }
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

#[cfg(test)]
mod tests {
    use std::{
        future::{Future, pending},
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        time::Duration,
    };

    use serde_json::{Value, json};
    use tokio::sync::Semaphore;

    use super::{ConcurrencyLimitedModel, ModelError, StructuredOutputModel, ToolDefinition};

    struct ProbeModel {
        active: AtomicUsize,
        peak: AtomicUsize,
    }

    struct PendingModel;

    impl ProbeModel {
        fn new() -> Self {
            Self {
                active: AtomicUsize::new(0),
                peak: AtomicUsize::new(0),
            }
        }
    }

    impl StructuredOutputModel for ProbeModel {
        fn complete<'request>(
            &'request self,
            _system_prompt: &'request str,
            _prompt: &'request str,
            _max_tokens: u32,
            _tool: ToolDefinition<'request>,
        ) -> Pin<Box<dyn Future<Output = Result<Value, ModelError>> + Send + 'request>> {
            Box::pin(async move {
                let active = self.active.fetch_add(1, Ordering::SeqCst) + 1;
                self.peak.fetch_max(active, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(20)).await;
                self.active.fetch_sub(1, Ordering::SeqCst);
                Ok(json!({"ok": true}))
            })
        }
    }

    impl StructuredOutputModel for PendingModel {
        fn complete<'request>(
            &'request self,
            _system_prompt: &'request str,
            _prompt: &'request str,
            _max_tokens: u32,
            _tool: ToolDefinition<'request>,
        ) -> Pin<Box<dyn Future<Output = Result<Value, ModelError>> + Send + 'request>> {
            Box::pin(pending())
        }
    }

    #[tokio::test]
    async fn shared_semaphore_limits_calls_across_model_tiers() {
        let probe = Arc::new(ProbeModel::new());
        let model: Arc<dyn StructuredOutputModel> = probe.clone();
        let semaphore = Arc::new(Semaphore::new(1));
        let fast = ConcurrencyLimitedModel::new(Arc::clone(&model), Arc::clone(&semaphore));
        let smart = ConcurrencyLimitedModel::new(model, semaphore);
        let schema = json!({"type": "object"});
        let tool = ToolDefinition {
            name: "result",
            description: "Return a result",
            input_schema: &schema,
        };

        let (fast_result, smart_result) = tokio::join!(
            fast.complete("system", "fast", 10, tool),
            smart.complete("system", "smart", 10, tool),
        );

        assert!(fast_result.is_ok());
        assert!(smart_result.is_ok());
        assert_eq!(probe.peak.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn cancelling_completion_releases_its_shared_permit() {
        let semaphore = Arc::new(Semaphore::new(1));
        let model: Arc<dyn StructuredOutputModel> = Arc::new(PendingModel);
        let limited = ConcurrencyLimitedModel::new(model, Arc::clone(&semaphore));
        let task = tokio::spawn(async move {
            let schema = json!({"type": "object"});
            limited
                .complete(
                    "system",
                    "prompt",
                    10,
                    ToolDefinition {
                        name: "result",
                        description: "Return a result",
                        input_schema: &schema,
                    },
                )
                .await
        });

        let acquired = tokio::time::timeout(Duration::from_secs(1), async {
            while semaphore.available_permits() != 0 {
                tokio::task::yield_now().await;
            }
        })
        .await;
        assert!(acquired.is_ok(), "model call did not acquire the permit");

        task.abort();
        assert!(matches!(task.await, Err(error) if error.is_cancelled()));
        assert_eq!(semaphore.available_permits(), 1);
    }
}
