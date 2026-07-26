//! Anthropic Messages API adapter for provider-neutral structured output.
//!
//! This module is deliberately the only Anthropic-specific part of the AI
//! engine. Other providers implement `StructuredOutputModel` separately.

use std::{env, time::Duration};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

use crate::structured_output::{ModelError, StructuredOutputModel, ToolDefinition};

const API_VERSION: &str = "2023-06-01";
const DEFAULT_BASE_URL: &str = "https://api.anthropic.com";
/// Anthropic-backed structured-output model.
#[derive(Clone)]
pub struct AnthropicClassifierModel {
    client: Client,
    api_key: String,
    endpoint: String,
    model: String,
}

impl AnthropicClassifierModel {
    /// Builds the default Anthropic adapter from the standard environment.
    ///
    /// `model_name` must use the existing engine's `anthropic:<model-id>`
    /// format. `ANTHROPIC_BASE_URL` is supported for an Anthropic-compatible
    /// gateway and otherwise defaults to the public API origin.
    ///
    /// # Errors
    ///
    /// Returns an error when the model prefix or `ANTHROPIC_API_KEY` is absent.
    pub fn from_environment(model_name: &str) -> Result<Self, ModelError> {
        let api_key = env::var("ANTHROPIC_API_KEY")
            .map_err(|_| ModelError::new("ANTHROPIC_API_KEY is not configured"))?;
        let base_url =
            env::var("ANTHROPIC_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        Self::new(model_name, api_key, base_url)
    }

    /// Builds the adapter for an admin-pushed config: the model name is bare
    /// (no `anthropic:` prefix) and the pushed key wins over the environment.
    ///
    /// The push path deliberately fails closed when no key is available at
    /// all — the Python oracle would accept the push with an "unconfigured"
    /// placeholder key and fail on the first model call instead.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty model name or when neither the push nor
    /// `ANTHROPIC_API_KEY` provides a key.
    pub fn from_pushed_config(bare_model: &str, api_key: Option<&str>) -> Result<Self, ModelError> {
        let api_key = match api_key {
            Some(api_key) if !api_key.is_empty() => api_key.to_owned(),
            _ => env::var("ANTHROPIC_API_KEY")
                .map_err(|_| ModelError::new("ANTHROPIC_API_KEY is not configured"))?,
        };
        let base_url =
            env::var("ANTHROPIC_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        Self::new(&format!("anthropic:{bare_model}"), api_key, base_url)
    }

    /// Builds the adapter with an explicit key and base URL, primarily for
    /// deployment wiring and contract tests.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty key, invalid model prefix, or unsupported
    /// base URL.
    pub fn new(
        model_name: &str,
        api_key: impl Into<String>,
        base_url: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let model = model_name
            .strip_prefix("anthropic:")
            .filter(|model| !model.is_empty())
            .ok_or_else(|| {
                ModelError::new(
                    "Anthropic adapter requires STIRLING_FAST_MODEL=anthropic:<model-id>",
                )
            })?
            .to_owned();
        let api_key = api_key.into();
        if api_key.is_empty() {
            return Err(ModelError::new("ANTHROPIC_API_KEY is not configured"));
        }
        let endpoint = messages_endpoint(base_url.as_ref())?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|error| {
                ModelError::new(format!("failed to configure Anthropic client: {error}"))
            })?;

        Ok(Self {
            client,
            api_key,
            endpoint,
            model,
        })
    }
}

impl StructuredOutputModel for AnthropicClassifierModel {
    fn complete<'request>(
        &'request self,
        system_prompt: &'request str,
        prompt: &'request str,
        max_tokens: u32,
        tool: ToolDefinition<'request>,
    ) -> std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Value, ModelError>> + Send + 'request>,
    > {
        let payload = request_payload(&self.model, system_prompt, prompt, max_tokens, tool);
        let tool_name = tool.name.to_owned();
        Box::pin(async move {
            let response = self
                .client
                .post(&self.endpoint)
                .header("x-api-key", &self.api_key)
                .header("anthropic-version", API_VERSION)
                .json(&payload)
                .send()
                .await
                .map_err(|error| ModelError::new(format!("Anthropic request failed: {error}")))?;
            let status = response.status();
            let body = response.json::<Value>().await.map_err(|error| {
                ModelError::new(format!("Anthropic response was not JSON: {error}"))
            })?;
            if !status.is_success() {
                return Err(remote_error(status, &body));
            }
            parse_response(&body, &tool_name)
        })
    }
}

fn messages_endpoint(base_url: &str) -> Result<String, ModelError> {
    let base_url = base_url.trim_end_matches('/');
    if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
        return Err(ModelError::new(
            "ANTHROPIC_BASE_URL must be an absolute HTTP(S) URL",
        ));
    }
    Ok(format!("{base_url}/v1/messages"))
}

fn request_payload(
    model: &str,
    system_prompt: &str,
    prompt: &str,
    max_tokens: u32,
    tool: ToolDefinition<'_>,
) -> Value {
    json!({
        "model": model,
        "max_tokens": max_tokens,
        "system": system_prompt,
        "messages": [{"role": "user", "content": prompt}],
        "tools": [{
            "name": tool.name,
            "description": tool.description,
            "input_schema": tool.input_schema
        }],
        "tool_choice": {"type": "tool", "name": tool.name}
    })
}

fn parse_response(response: &Value, tool_name: &str) -> Result<Value, ModelError> {
    let content = response
        .get("content")
        .and_then(Value::as_array)
        .ok_or_else(|| ModelError::new("Anthropic response did not contain content blocks"))?;
    let input = content
        .iter()
        .find(|block| {
            block.get("type").and_then(Value::as_str) == Some("tool_use")
                && block.get("name").and_then(Value::as_str) == Some(tool_name)
        })
        .and_then(|block| block.get("input"))
        .ok_or_else(|| {
            ModelError::new("Anthropic response did not invoke the required result tool")
        })?;
    Ok(input.clone())
}

fn remote_error(status: StatusCode, body: &Value) -> ModelError {
    let message = body
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("unknown Anthropic API error");
    ModelError::new(format!("Anthropic API returned {status}: {message}"))
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use serde_json::json;

    use super::{messages_endpoint, parse_response, request_payload};
    use crate::structured_output::ToolDefinition;

    const TEST_TOOL_NAME: &str = "submit_test_result";

    fn test_tool() -> ToolDefinition<'static> {
        ToolDefinition {
            name: TEST_TOOL_NAME,
            description: "Return a test result.",
            input_schema: test_schema(),
        }
    }

    fn test_schema() -> &'static serde_json::Value {
        static SCHEMA: OnceLock<serde_json::Value> = OnceLock::new();
        SCHEMA.get_or_init(|| {
            json!({
                "type": "object",
                "properties": {"labels": {"type": "array", "items": {"type": "string"}}},
                "additionalProperties": false
            })
        })
    }

    #[test]
    fn message_endpoint_requires_absolute_http_url() {
        assert_eq!(
            messages_endpoint("https://gateway.example/").as_deref(),
            Ok("https://gateway.example/v1/messages")
        );
        assert!(messages_endpoint("gateway.example").is_err());
    }

    #[test]
    fn request_forces_the_named_structured_output_tool() {
        let payload = request_payload("claude-test", "system", "prompt", 123, test_tool());
        assert_eq!(payload["model"], "claude-test");
        assert_eq!(payload["max_tokens"], 123);
        assert_eq!(payload["tool_choice"]["name"], TEST_TOOL_NAME);
        assert_eq!(
            payload["tools"][0]["input_schema"]["properties"]["labels"]["type"],
            "array"
        );
    }

    #[test]
    fn response_reads_only_the_named_tool_output() {
        let response = json!({
            "content": [
                {"type": "text", "text": "ignored"},
                {"type": "tool_use", "name": TEST_TOOL_NAME, "input": {"labels": ["Invoice"]}}
            ]
        });

        assert_eq!(
            parse_response(&response, TEST_TOOL_NAME),
            Ok(json!({"labels": ["Invoice"]}))
        );
    }

    #[test]
    fn response_without_the_named_tool_is_rejected() {
        assert!(parse_response(&json!({"content": []}), TEST_TOOL_NAME).is_err());
    }
}
