//! `OpenAI` Chat Completions-compatible structured-output adapter.

use std::{env, time::Duration};

use reqwest::{Client, StatusCode};
use serde_json::{Value, json};

use crate::structured_output::{ModelError, StructuredOutputModel, ToolDefinition};

const DEFAULT_BASE_URL: &str = "https://api.openai.com";
const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StructuredOutputProtocol {
    ToolCall,
    NativeJsonSchema,
}

/// Structured-output adapter for `OpenAI` and compatible self-hosted gateways.
#[derive(Clone)]
pub struct OpenAiClassifierModel {
    client: Client,
    api_key: Option<String>,
    endpoint: String,
    model: String,
    output_protocol: StructuredOutputProtocol,
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

    /// Builds an `Ollama` adapter from its native model prefix and base URL.
    ///
    /// Local `Ollama` does not require an API key. `OLLAMA_API_KEY` is optional
    /// for authenticated remote gateways and, when present, is sent as a
    /// bearer token. The default endpoint is `http://localhost:11434`.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty model identifier, malformed environment
    /// configuration, or a base URL that is not absolute HTTP(S).
    pub fn from_ollama_environment(model_name: &str) -> Result<Self, ModelError> {
        let base_url = optional_environment_value("OLLAMA_BASE_URL")?
            .unwrap_or_else(|| DEFAULT_OLLAMA_BASE_URL.to_owned());
        let api_key =
            optional_environment_value("OLLAMA_API_KEY")?.filter(|value| !value.trim().is_empty());
        Self::new_compatible(
            model_name,
            "ollama:",
            api_key,
            base_url,
            StructuredOutputProtocol::NativeJsonSchema,
        )
    }

    /// Builds the adapter for an admin-pushed `openai` provider: the model
    /// name is bare and the pushed key wins over `OPENAI_API_KEY`.
    ///
    /// Mirroring the oracle's push path, a pushed base URL is ignored for the
    /// hosted `openai` provider; `OPENAI_BASE_URL` still applies.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty model name or when neither the push nor
    /// the environment provides a key.
    pub fn from_pushed_config(bare_model: &str, api_key: Option<&str>) -> Result<Self, ModelError> {
        let api_key = match api_key {
            Some(api_key) if !api_key.is_empty() => api_key.to_owned(),
            _ => env::var("OPENAI_API_KEY")
                .map_err(|_| ModelError::new("OPENAI_API_KEY is not configured"))?,
        };
        let base_url = env::var("OPENAI_BASE_URL").unwrap_or_else(|_| DEFAULT_BASE_URL.to_owned());
        Self::new(&format!("openai:{bare_model}"), api_key, base_url)
    }

    /// Builds the adapter for an admin-pushed `ollama` or `custom` provider:
    /// an OpenAI-compatible endpoint that needs the native json-schema output
    /// protocol (the Rust analogue of the oracle's `ToolOutput` switch for
    /// local providers) and works keyless.
    ///
    /// An empty pushed base URL falls back to `OLLAMA_BASE_URL` for `ollama`
    /// and to `OPENAI_BASE_URL` (then the hosted default) for `custom`.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty model name or a base URL that is not
    /// absolute HTTP(S).
    pub fn from_pushed_compatible(
        provider: &str,
        bare_model: &str,
        api_key: Option<&str>,
        base_url: Option<&str>,
    ) -> Result<Self, ModelError> {
        let base_url = match base_url {
            Some(base_url) if !base_url.is_empty() => base_url.to_owned(),
            _ if provider == "ollama" => optional_environment_value("OLLAMA_BASE_URL")?
                .unwrap_or_else(|| DEFAULT_OLLAMA_BASE_URL.to_owned()),
            _ => optional_environment_value("OPENAI_BASE_URL")?
                .unwrap_or_else(|| DEFAULT_BASE_URL.to_owned()),
        };
        let api_key = api_key
            .filter(|api_key| !api_key.trim().is_empty())
            .map(str::to_owned);
        Self::new_compatible(
            &format!("{provider}:{bare_model}"),
            &format!("{provider}:"),
            api_key,
            base_url,
            StructuredOutputProtocol::NativeJsonSchema,
        )
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
        let api_key = api_key.into();
        if api_key.is_empty() {
            return Err(ModelError::new("OPENAI_API_KEY is not configured"));
        }
        Self::new_compatible(
            model_name,
            "openai:",
            Some(api_key),
            base_url,
            StructuredOutputProtocol::ToolCall,
        )
    }

    fn new_compatible(
        model_name: &str,
        prefix: &str,
        api_key: Option<String>,
        base_url: impl AsRef<str>,
        output_protocol: StructuredOutputProtocol,
    ) -> Result<Self, ModelError> {
        let endpoint = completions_endpoint(base_url.as_ref())?;
        let model = model_name
            .strip_prefix(prefix)
            .filter(|model| !model.is_empty())
            .ok_or_else(|| {
                ModelError::new(format!(
                    "model must use {prefix}<model-id> for this OpenAI-compatible provider"
                ))
            })?
            .to_owned();
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
            output_protocol,
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
        let payload = request_payload(
            &self.model,
            system_prompt,
            prompt,
            max_tokens,
            tool,
            self.output_protocol,
        );
        let tool_name = tool.name.to_owned();
        Box::pin(async move {
            let mut request = self.client.post(&self.endpoint).json(&payload);
            if let Some(api_key) = &self.api_key {
                request = request.bearer_auth(api_key);
            }
            let response = request.send().await.map_err(|error| {
                ModelError::new(format!("OpenAI-compatible request failed: {error}"))
            })?;
            let status = response.status();
            let body = response.json::<Value>().await.map_err(|error| {
                ModelError::new(format!("OpenAI-compatible response was not JSON: {error}"))
            })?;
            if !status.is_success() {
                return Err(remote_error(status, &body));
            }
            parse_response(&body, &tool_name, self.output_protocol)
        })
    }
}

fn completions_endpoint(base_url: &str) -> Result<String, ModelError> {
    let base_url = base_url.trim_end_matches('/');
    if !(base_url.starts_with("https://") || base_url.starts_with("http://")) {
        return Err(ModelError::new(
            "OpenAI-compatible base URL must be an absolute HTTP(S) URL",
        ));
    }
    if base_url.ends_with("/v1/chat/completions") {
        Ok(base_url.to_owned())
    } else if base_url.ends_with("/v1") {
        Ok(format!("{base_url}/chat/completions"))
    } else {
        Ok(format!("{base_url}/v1/chat/completions"))
    }
}

fn optional_environment_value(name: &str) -> Result<Option<String>, ModelError> {
    match env::var(name) {
        Ok(value) => Ok(Some(value)),
        Err(env::VarError::NotPresent) => Ok(None),
        Err(env::VarError::NotUnicode(_)) => Err(ModelError::new(format!(
            "{name} must contain valid Unicode"
        ))),
    }
}

fn request_payload(
    model: &str,
    system_prompt: &str,
    prompt: &str,
    max_tokens: u32,
    tool: ToolDefinition<'_>,
    output_protocol: StructuredOutputProtocol,
) -> Value {
    match output_protocol {
        StructuredOutputProtocol::ToolCall => json!({
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
        }),
        StructuredOutputProtocol::NativeJsonSchema => json!({
            "model": model,
            "max_tokens": max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": prompt}
            ],
            "response_format": {"type": "json_schema", "json_schema": {
                "name": tool.name,
                "description": tool.description,
                "strict": true,
                "schema": tool.input_schema
            }}
        }),
    }
}

fn parse_response(
    response: &Value,
    tool_name: &str,
    output_protocol: StructuredOutputProtocol,
) -> Result<Value, ModelError> {
    if output_protocol == StructuredOutputProtocol::NativeJsonSchema {
        return parse_native_json_response(response);
    }
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
        .ok_or_else(|| {
            ModelError::new("OpenAI-compatible response did not call the classifier function")
        })?;
    match arguments {
        Value::String(arguments) => serde_json::from_str(arguments).map_err(|error| {
            ModelError::new(format!(
                "OpenAI-compatible structured-output arguments were invalid: {error}"
            ))
        }),
        Value::Object(_) => Ok(arguments.clone()),
        _ => Err(ModelError::new(
            "OpenAI-compatible structured-output arguments were not an object or JSON string",
        )),
    }
}

fn parse_native_json_response(response: &Value) -> Result<Value, ModelError> {
    let content = response
        .get("choices")
        .and_then(Value::as_array)
        .and_then(|choices| choices.first())
        .and_then(|choice| choice.get("message"))
        .and_then(|message| message.get("content"))
        .ok_or_else(|| {
            ModelError::new("Ollama structured-output response did not contain message content")
        })?;
    match content {
        Value::String(content) => serde_json::from_str(content).map_err(|error| {
            ModelError::new(format!(
                "Ollama structured-output content was invalid JSON: {error}"
            ))
        }),
        Value::Object(_) => Ok(content.clone()),
        _ => Err(ModelError::new(
            "Ollama structured-output content was not an object or JSON string",
        )),
    }
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

    use super::{
        OpenAiClassifierModel, StructuredOutputProtocol, completions_endpoint,
        parse_native_json_response, parse_response, request_payload,
    };
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
    fn endpoint_accepts_versioned_and_complete_base_urls() {
        assert_eq!(
            completions_endpoint("http://localhost:11434/v1").as_deref(),
            Ok("http://localhost:11434/v1/chat/completions")
        );
        assert_eq!(
            completions_endpoint("http://localhost:11434/v1/chat/completions").as_deref(),
            Ok("http://localhost:11434/v1/chat/completions")
        );
    }

    #[test]
    fn ollama_compatible_model_accepts_keyless_local_runtime() {
        let model = OpenAiClassifierModel::new_compatible(
            "ollama:qwen3:8b",
            "ollama:",
            None,
            "http://localhost:11434",
            StructuredOutputProtocol::NativeJsonSchema,
        )
        .unwrap_or_else(|error| panic!("Ollama model should configure: {error}"));

        assert_eq!(model.model, "qwen3:8b");
        assert_eq!(model.endpoint, "http://localhost:11434/v1/chat/completions");
        assert!(model.api_key.is_none());
        assert_eq!(
            model.output_protocol,
            StructuredOutputProtocol::NativeJsonSchema
        );
    }

    #[test]
    fn request_forces_the_named_structured_output_function() {
        let payload = request_payload(
            "gpt-test",
            "system",
            "prompt",
            123,
            test_tool(),
            StructuredOutputProtocol::ToolCall,
        );
        assert_eq!(payload["tool_choice"]["function"]["name"], TEST_TOOL_NAME);
        assert_eq!(payload["tools"][0]["function"]["strict"], true);
    }

    #[test]
    fn ollama_request_forces_native_json_schema_output() {
        let payload = request_payload(
            "qwen3:8b",
            "system",
            "prompt",
            123,
            test_tool(),
            StructuredOutputProtocol::NativeJsonSchema,
        );
        assert_eq!(payload["response_format"]["type"], "json_schema");
        assert_eq!(
            payload["response_format"]["json_schema"]["name"],
            TEST_TOOL_NAME
        );
        assert_eq!(
            payload["response_format"]["json_schema"]["schema"],
            *test_schema()
        );
        assert!(payload.get("tools").is_none());
    }

    #[test]
    fn response_reads_only_named_function_arguments() {
        let response = json!({"choices": [{"message": {"tool_calls": [
            {"type": "function", "function": {"name": "other", "arguments": "{}"}},
            {"type": "function", "function": {"name": TEST_TOOL_NAME, "arguments": "{\"labels\":[\"Invoice\"]}"}}
        ]}}]});
        assert_eq!(
            parse_response(
                &response,
                TEST_TOOL_NAME,
                StructuredOutputProtocol::ToolCall
            ),
            Ok(json!({"labels": ["Invoice"]}))
        );
    }

    #[test]
    fn response_accepts_gateway_object_arguments() {
        let response = json!({"choices": [{"message": {"tool_calls": [{
            "type": "function",
            "function": {"name": TEST_TOOL_NAME, "arguments": {"labels": ["Invoice"]}}
        }]}}]});
        assert_eq!(
            parse_response(
                &response,
                TEST_TOOL_NAME,
                StructuredOutputProtocol::ToolCall
            ),
            Ok(json!({"labels": ["Invoice"]}))
        );
    }

    #[test]
    fn ollama_response_accepts_native_json_string_and_object_content() {
        assert_eq!(
            parse_native_json_response(
                &json!({"choices": [{"message": {"content": "{\"labels\":[\"Invoice\"]}"}}]})
            ),
            Ok(json!({"labels": ["Invoice"]}))
        );
        assert_eq!(
            parse_native_json_response(
                &json!({"choices": [{"message": {"content": {"labels": ["Invoice"]}}}]})
            ),
            Ok(json!({"labels": ["Invoice"]}))
        );
    }

    #[test]
    fn response_without_named_function_is_rejected() {
        assert!(
            parse_response(
                &json!({"choices": []}),
                TEST_TOOL_NAME,
                StructuredOutputProtocol::ToolCall,
            )
            .is_err()
        );
    }
}
