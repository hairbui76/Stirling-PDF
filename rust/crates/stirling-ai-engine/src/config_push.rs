//! Wire contract for the admin config push (`POST /api/v1/config`).
//!
//! Mirrors the Python oracle's `stirling.contracts.config`: the Java processor
//! sends camelCase fields, Python-native `snake_case` names are also accepted,
//! and — unlike every other contract in this crate — unknown fields are
//! deliberately *ignored* rather than rejected so a newer processor can push
//! to an older engine without breaking (`TolerantApiModel` in the oracle).
//! Empty strings and absent numbers mean "keep the engine's current value".

use serde::{Deserialize, Serialize};

/// Model provider + credentials pushed by the Java processor; empty fields
/// mean "keep the engine's env value".
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigModelsSection {
    pub provider: String,
    #[serde(rename = "smartModel", alias = "smart_model")]
    pub smart_model: String,
    #[serde(rename = "fastModel", alias = "fast_model")]
    pub fast_model: String,
    #[serde(rename = "smartMaxTokens", alias = "smart_max_tokens")]
    pub smart_max_tokens: Option<u32>,
    #[serde(rename = "fastMaxTokens", alias = "fast_max_tokens")]
    pub fast_max_tokens: Option<u32>,
    #[serde(rename = "apiKey", alias = "api_key")]
    pub api_key: String,
    #[serde(rename = "baseUrl", alias = "base_url")]
    pub base_url: String,
}

/// Retrieval settings pushed by the Java processor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigRagSection {
    #[serde(rename = "embeddingProvider", alias = "embedding_provider")]
    pub embedding_provider: String,
    #[serde(rename = "embeddingModel", alias = "embedding_model")]
    pub embedding_model: String,
    #[serde(rename = "embeddingApiKey", alias = "embedding_api_key")]
    pub embedding_api_key: String,
    #[serde(rename = "embeddingBaseUrl", alias = "embedding_base_url")]
    pub embedding_base_url: String,
    #[serde(rename = "topK", alias = "top_k")]
    pub top_k: Option<usize>,
    #[serde(rename = "maxSearches", alias = "max_searches")]
    pub max_searches: Option<usize>,
}

/// Resource-limit settings pushed by the Java processor.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigLimitsSection {
    #[serde(rename = "maxPages", alias = "max_pages")]
    pub max_pages: Option<usize>,
    #[serde(rename = "maxCharacters", alias = "max_characters")]
    pub max_characters: Option<usize>,
    #[serde(rename = "modelMaxConcurrency", alias = "model_max_concurrency")]
    pub model_max_concurrency: Option<usize>,
}

/// Admin-configured AI settings pushed at processor startup and after saves.
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct ConfigPushRequest {
    pub models: ConfigModelsSection,
    pub rag: ConfigRagSection,
    pub limits: ConfigLimitsSection,
}

impl ConfigPushRequest {
    /// Validates the oracle's numeric bounds; the message names the failing
    /// field like a Python validation error would.
    ///
    /// # Errors
    ///
    /// Returns the field-specific message for an out-of-range value.
    pub fn validate(&self) -> Result<(), String> {
        require_positive_u32(self.models.smart_max_tokens, "models.smartMaxTokens")?;
        require_positive_u32(self.models.fast_max_tokens, "models.fastMaxTokens")?;
        require_positive(self.rag.top_k, "rag.topK")?;
        // rag.maxSearches floors at 0: "no retrieval searches" is legitimate.
        require_positive(self.limits.max_pages, "limits.maxPages")?;
        require_positive(self.limits.max_characters, "limits.maxCharacters")?;
        // Must be >= 1: it becomes the shared model semaphore bound, and 0
        // would construct a permanently locked semaphore; the push is
        // persisted, so a restart would not clear it.
        require_positive(
            self.limits.model_max_concurrency,
            "limits.modelMaxConcurrency",
        )
    }
}

fn require_positive(value: Option<usize>, field: &str) -> Result<(), String> {
    if value == Some(0) {
        return Err(format!("{field} must be greater than or equal to 1"));
    }
    Ok(())
}

fn require_positive_u32(value: Option<u32>, field: &str) -> Result<(), String> {
    if value == Some(0) {
        return Err(format!("{field} must be greater than or equal to 1"));
    }
    Ok(())
}

/// Summary of the effective config after a push. Never echoes credentials.
#[derive(Clone, Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ConfigApplyResponse {
    pub status: &'static str,
    pub provider: String,
    pub smart_model: String,
    pub fast_model: String,
    pub smart_max_tokens: u32,
    pub fast_max_tokens: u32,
    pub rag_embedding_model: String,
    pub rag_top_k: usize,
    pub rag_max_searches: usize,
    pub max_pages: usize,
    pub max_characters: usize,
    pub model_max_concurrency: usize,
    pub notes: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::ConfigPushRequest;

    #[test]
    fn java_processor_body_shape_is_accepted_with_camel_case_names() {
        // Mirrors AiEngineConfigSync.buildConfigNode + the oracle's
        // processor_config_push.json fixture.
        let request: ConfigPushRequest = serde_json::from_value(serde_json::json!({
            "models": {
                "provider": "ollama",
                "smartModel": "smart-model-x",
                "fastModel": "fast-model-x",
                "smartMaxTokens": 1111,
                "fastMaxTokens": 2222,
                "apiKey": "provider-key-abc",
                "baseUrl": "http://engine.example/v1"
            },
            "rag": {
                "embeddingProvider": "custom",
                "embeddingModel": "embed-model-x",
                "embeddingApiKey": "embed-key-abc",
                "embeddingBaseUrl": "http://embed.example/v1",
                "topK": 33,
                "maxSearches": 7
            },
            "limits": {
                "maxPages": 111,
                "maxCharacters": 222_222,
                "modelMaxConcurrency": 9
            }
        }))
        .unwrap_or_else(|error| panic!("Java body should deserialize: {error}"));
        assert_eq!(request.models.provider, "ollama");
        assert_eq!(request.models.smart_model, "smart-model-x");
        assert_eq!(request.models.fast_max_tokens, Some(2222));
        assert_eq!(request.rag.embedding_provider, "custom");
        assert_eq!(request.rag.max_searches, Some(7));
        assert_eq!(request.limits.model_max_concurrency, Some(9));
        assert!(request.validate().is_ok());
    }

    #[test]
    fn python_snake_case_field_names_are_accepted() {
        let request: ConfigPushRequest = serde_json::from_value(serde_json::json!({
            "models": {"smart_model": "claude-haiku-4-5", "smart_max_tokens": 4096},
            "rag": {"top_k": 7, "max_searches": 0},
            "limits": {"max_pages": 50}
        }))
        .unwrap_or_else(|error| panic!("snake_case body should deserialize: {error}"));
        assert_eq!(request.models.smart_model, "claude-haiku-4-5");
        assert_eq!(request.models.smart_max_tokens, Some(4096));
        assert_eq!(request.rag.top_k, Some(7));
        assert_eq!(request.rag.max_searches, Some(0));
        assert_eq!(request.limits.max_pages, Some(50));
    }

    #[test]
    fn unknown_fields_are_tolerated_like_the_python_push_contract() {
        // The push contract deliberately diverges from the crate's usual
        // unknown-field rejection: a newer processor must be able to push to
        // an older engine (oracle: TolerantApiModel, extra="ignore").
        let request: ConfigPushRequest = serde_json::from_value(serde_json::json!({
            "models": {"smartModel": "claude-haiku-4-5", "futureField": true},
            "futureSection": {"nested": 1}
        }))
        .unwrap_or_else(|error| panic!("unknown fields should be ignored: {error}"));
        assert_eq!(request.models.smart_model, "claude-haiku-4-5");
    }

    #[test]
    fn missing_sections_default_to_keep_everything() {
        let request: ConfigPushRequest = serde_json::from_value(serde_json::json!({}))
            .unwrap_or_else(|error| panic!("empty body should deserialize: {error}"));
        assert_eq!(request.models.provider, "");
        assert_eq!(request.rag.top_k, None);
        assert_eq!(request.limits.max_pages, None);
        assert!(request.validate().is_ok());
    }

    #[test]
    fn zero_bounds_are_rejected_except_max_searches() {
        for body in [
            serde_json::json!({"models": {"smartMaxTokens": 0}}),
            serde_json::json!({"models": {"fastMaxTokens": 0}}),
            serde_json::json!({"rag": {"topK": 0}}),
            serde_json::json!({"limits": {"maxPages": 0}}),
            serde_json::json!({"limits": {"maxCharacters": 0}}),
            serde_json::json!({"limits": {"modelMaxConcurrency": 0}}),
        ] {
            let request: ConfigPushRequest = serde_json::from_value(body.clone())
                .unwrap_or_else(|error| panic!("body {body} should deserialize: {error}"));
            assert!(request.validate().is_err(), "{body} should be out of range");
        }
        let zero_searches: ConfigPushRequest =
            serde_json::from_value(serde_json::json!({"rag": {"maxSearches": 0}}))
                .unwrap_or_else(|error| panic!("zero maxSearches should deserialize: {error}"));
        assert!(zero_searches.validate().is_ok());
    }

    #[test]
    fn negative_numbers_fail_deserialization() {
        assert!(
            serde_json::from_value::<ConfigPushRequest>(
                serde_json::json!({"limits": {"maxPages": -1}})
            )
            .is_err()
        );
    }
}
