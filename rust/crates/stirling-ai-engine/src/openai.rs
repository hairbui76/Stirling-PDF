//! `OpenAI` Chat Completions-compatible structured-output adapter.

use std::{env, time::Duration};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

use crate::structured_output::{ModelError, StructuredOutputModel, ToolDefinition};

const DEFAULT_BASE_URL: &str = "https://api.openai.com";
/// Structured-output adapter for `OpenAI` and compatible self-hosted gateways.
#[derive(Clone)]
pub struct OpenAiClassifierModel {
    client: Client,
    api_key: String,
    endpoint: String,
    model: String,
}

impl OpenAiClassifierModel {
    /// Builds from `OPENAI_API_KEY`, `OPENAI_BASE_URL`, and an `openai:` model.
    ///
    /// # Errors
    ///
    /// Returns an error for missing credentials, an unsupported model name, or
    /// a base URL that is not absolute HTTP(S).
    pub fn from_environment(model_name: &str) -> Result<Self, ModelError> {
        let api_key = env::var("OPENAI_API_KEY")
            .map_err(|_| ModelError::new("OPENAI_API_KEY is not configured"))?;
        let base_url = env::var("OPENAI_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        Self::new(model_name, api_key, base_url)
    }

    /// Builds with explicit credentials and a compatible API origin.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid settings or inability to build the HTTPS
    /// client.
    pub fn new(
        model_name: &str,
        api_key: impl Into<String>,
        base_url: impl AsRef<str>,
    ) -> Result<Self, ModelError> {
        let model = model_name
            .strip_prefix("openai:")
            .filter(|model| !model.is_empty())
            .ok_or_else(|| {
                ModelError::new("OpenAI adapter requires STIRLING_FAST_MODEL=openai:<model-id>")
            })?
            .to_owned();
        let api_key = api_key.into();
        if api_key.is_empty() {
            return Err(ModelError::new("OPENAI_API_KEY is not configured"));
        }
        let endpoint = completions_endpoint(base_url.as_ref())?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|error| {
                ModelError::new(format!("failed to configure OpenAI client: {error}"))
            })?;
        Ok(Self {
            client,
            api_key,
            endpoint,
            model,
        })
    }
}

impl StructuredOutputModel for OpenAiClassifierModel {
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
                .bearer_auth(&self.api_key)
                .json(&payload)
                .send()
                .await
                .map_err(|error| {
                    ModelError::new(format!("OpenAI-compatible request failed: {error}"))
                })?;
            let status = response.status();
            let body = response.json::<Value>().await.map_err(|error| {
                ModelError::new(format!("OpenAI-compatible response was not JSON: {error}"))
            })?;
            if !status.is_success() {
                return Err(remote_error(status, &body));
            }
            parse_response(&body, &tool_name)
        })
    }
}

fn completions_endpoint(base_url: &str) -> Result<String, ModelError> {
    let base_url = base_url.trim_end_matches('/');
    if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
        return Err(ModelError::new(
            "OPENAI_BASE_URL must be an absolute HTTP(S) URL",
        ));
    }
    Ok(format!("{base_url}/v1/chat/completions"))
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
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": prompt}
        ],
        "tools": [{"type": "function", "function": {
            "name": tool.name,
            "description": tool.description,
            "strict": true,
            "parameters": tool.input_schema
        }}],
        "tool_choice": {"type": "function", "function": {"name": tool.name}}
    })
}

fn parse_response(response: &Value, tool_name: &str) -> Result<Value, ModelError> {
    let arguments = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("tool_calls"))
        .and_then(Value::as_array)
        .and_then(|calls| {
            calls.iter().find(|call| {
                call.get("type").and_then(Value::as_str) == Some("function")
                    && call
                        .get("function")
                        .and_then(|function| function.get("name"))
                        .and_then(Value::as_str)
                        == Some(tool_name)
            })
        })
        .and_then(|call| call.get("function"))
        .and_then(|function| function.get("arguments"))
        .and_then(Value::as_str)
        .ok_or_else(|| {
            ModelError::new("OpenAI-compatible response did not call the classifier function")
        })?;
    serde_json::from_str(arguments).map_err(|error| {
        ModelError::new(format!(
            "OpenAI-compatible structured-output arguments were invalid: {error}"
        ))
    })
}

fn remote_error(status: StatusCode, body: &Value) -> ModelError {
    let message = body
        .get("error")
        .and_then(|error| error.get("message"))
        .and_then(Value::as_str)
        .unwrap_or("unknown OpenAI-compatible API error");
    ModelError::new(format!(
        "OpenAI-compatible API returned {status}: {message}"
    ))
}

#[cfg(test)]
mod tests {
    use std::sync::OnceLock;

    use serde_json::json;

    use super::{completions_endpoint, parse_response, request_payload};
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
    fn endpoint_supports_local_gateway_origin() {
        assert_eq!(
            completions_endpoint("http://localhost:11434/").as_deref(),
            Ok("http://localhost:11434/v1/chat/completions")
        );
        assert!(completions_endpoint("localhost:11434").is_err());
    }

    #[test]
    fn request_forces_the_named_structured_output_function() {
        let payload = request_payload("gpt-test", "system", "prompt", 123, test_tool());
        assert_eq!(payload["tool_choice"]["function"]["name"], TEST_TOOL_NAME);
        assert_eq!(payload["tools"][0]["function"]["strict"], true);
    }

    #[test]
    fn response_reads_only_named_function_arguments() {
        let response = json!({"choices": [{"message": {"tool_calls": [
            {"type": "function", "function": {"name": "other", "arguments": "{}"}},
            {"type": "function", "function": {"name": TEST_TOOL_NAME, "arguments": "{\"labels\":[\"Invoice\"]}"}}
        ]}}]});
        assert_eq!(
            parse_response(&response, TEST_TOOL_NAME),
            Ok(json!({"labels": ["Invoice"]}))
        );
    }

    #[test]
    fn response_without_named_function_is_rejected() {
        assert!(parse_response(&json!({"choices": []}), TEST_TOOL_NAME).is_err());
    }
}
