//! Provider-neutral embedding client for document indexing and retrieval.

use std::{env, fmt, time::Duration};

use reqwest::{Client, StatusCode};
use serde::Deserialize;
use serde_json::{Value, json};

const DEFAULT_VOYAGE_ENDPOINT: &str = "https://api.voyageai.com/v1/embeddings";
const DEFAULT_OPENAI_BASE_URL: &str = "https://api.openai.com";
const DEFAULT_OLLAMA_BASE_URL: &str = "http://localhost:11434";
const EMBEDDING_BATCH_SIZE: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum EmbeddingProvider {
    Voyage,
    OpenAi,
    Ollama,
    Test,
}

#[derive(Clone, Debug)]
pub struct EmbeddingError(String);

impl EmbeddingError {
    fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for EmbeddingError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl std::error::Error for EmbeddingError {}

/// HTTP embedding adapter supporting Voyage, `OpenAI`-compatible gateways,
/// and Ollama's native endpoint.
#[derive(Clone)]
pub struct EmbeddingClient {
    client: Client,
    provider: EmbeddingProvider,
    api_key: Option<String>,
    endpoint: String,
    model: String,
}

impl EmbeddingClient {
    /// Builds the adapter from `STIRLING_RAG_EMBEDDING_MODEL` provider syntax.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported prefixes, missing hosted-provider
    /// credentials, invalid endpoint configuration, or HTTP client failures.
    pub fn from_environment(model_name: &str) -> Result<Self, EmbeddingError> {
        if model_name == "test" {
            return Self::new(EmbeddingProvider::Test, "test", None, "http://localhost");
        }
        if let Some(model) = model_name.strip_prefix("voyageai:") {
            let api_key = env::var("VOYAGE_API_KEY")
                .map_err(|_| EmbeddingError::new("VOYAGE_API_KEY is not configured"))?;
            let endpoint = env::var("VOYAGE_BASE_URL").map_or_else(
                |_| DEFAULT_VOYAGE_ENDPOINT.to_owned(),
                |base_url| voyage_endpoint(&base_url),
            );
            return Self::new(EmbeddingProvider::Voyage, model, Some(api_key), &endpoint);
        }
        if let Some(model) = model_name.strip_prefix("openai:") {
            let api_key = env::var("OPENAI_API_KEY")
                .map_err(|_| EmbeddingError::new("OPENAI_API_KEY is not configured"))?;
            let base_url =
                env::var("OPENAI_BASE_URL").unwrap_or_else(|_| DEFAULT_OPENAI_BASE_URL.to_owned());
            return Self::new(
                EmbeddingProvider::OpenAi,
                model,
                Some(api_key),
                &openai_endpoint(&base_url),
            );
        }
        if let Some(model) = model_name.strip_prefix("ollama:") {
            let base_url =
                env::var("OLLAMA_BASE_URL").unwrap_or_else(|_| DEFAULT_OLLAMA_BASE_URL.to_owned());
            return Self::new(
                EmbeddingProvider::Ollama,
                model,
                None,
                &ollama_endpoint(&base_url),
            );
        }
        Err(EmbeddingError::new(
            "STIRLING_RAG_EMBEDDING_MODEL must use voyageai:, openai:, or ollama:",
        ))
    }

    /// Builds the adapter for an admin-pushed embedding config with explicit
    /// provider parts; empty pushed credentials fall back to the environment.
    ///
    /// `custom` is an OpenAI-compatible endpoint and, like `ollama`, works
    /// keyless. An empty provider defers to the composed
    /// `provider:model` reference via [`Self::from_environment`].
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported provider, a missing hosted-provider
    /// credential, or an invalid endpoint.
    pub fn from_pushed_config(
        provider: &str,
        model: &str,
        api_key: Option<&str>,
        base_url: Option<&str>,
    ) -> Result<Self, EmbeddingError> {
        let pushed_key = api_key.filter(|value| !value.trim().is_empty());
        let pushed_base = base_url.filter(|value| !value.is_empty());
        match provider {
            "" => Self::from_environment(model),
            "voyageai" => {
                let api_key = match pushed_key {
                    Some(api_key) => api_key.to_owned(),
                    None => env::var("VOYAGE_API_KEY")
                        .map_err(|_| EmbeddingError::new("VOYAGE_API_KEY is not configured"))?,
                };
                let endpoint = pushed_base.map_or_else(
                    || {
                        env::var("VOYAGE_BASE_URL").map_or_else(
                            |_| DEFAULT_VOYAGE_ENDPOINT.to_owned(),
                            |base_url| voyage_endpoint(&base_url),
                        )
                    },
                    voyage_endpoint,
                );
                Self::new(EmbeddingProvider::Voyage, model, Some(api_key), &endpoint)
            }
            "openai" => {
                let api_key = match pushed_key {
                    Some(api_key) => api_key.to_owned(),
                    None => env::var("OPENAI_API_KEY")
                        .map_err(|_| EmbeddingError::new("OPENAI_API_KEY is not configured"))?,
                };
                let base_url = pushed_base.map_or_else(
                    || {
                        env::var("OPENAI_BASE_URL")
                            .unwrap_or_else(|_| DEFAULT_OPENAI_BASE_URL.to_owned())
                    },
                    str::to_owned,
                );
                Self::new(
                    EmbeddingProvider::OpenAi,
                    model,
                    Some(api_key),
                    &openai_endpoint(&base_url),
                )
            }
            "custom" => {
                let base_url = pushed_base.map_or_else(
                    || {
                        env::var("OPENAI_BASE_URL")
                            .unwrap_or_else(|_| DEFAULT_OPENAI_BASE_URL.to_owned())
                    },
                    str::to_owned,
                );
                Self::new(
                    EmbeddingProvider::OpenAi,
                    model,
                    pushed_key.map(str::to_owned),
                    &openai_endpoint(&base_url),
                )
            }
            "ollama" => {
                let base_url = pushed_base.map_or_else(
                    || {
                        env::var("OLLAMA_BASE_URL")
                            .unwrap_or_else(|_| DEFAULT_OLLAMA_BASE_URL.to_owned())
                    },
                    str::to_owned,
                );
                Self::new(
                    EmbeddingProvider::Ollama,
                    model,
                    None,
                    &ollama_endpoint(&base_url),
                )
            }
            "test" => Self::new(EmbeddingProvider::Test, model, None, "http://localhost"),
            _ => Err(EmbeddingError::new(
                "embedding provider must be voyageai, openai, ollama, or custom",
            )),
        }
    }

    fn new(
        provider: EmbeddingProvider,
        model: &str,
        api_key: Option<String>,
        endpoint: &str,
    ) -> Result<Self, EmbeddingError> {
        if model.is_empty() {
            return Err(EmbeddingError::new(
                "embedding model identifier must not be empty",
            ));
        }
        validate_http_endpoint(endpoint)?;
        let client = Client::builder()
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(300))
            .pool_max_idle_per_host(0)
            .build()
            .map_err(|error| {
                EmbeddingError::new(format!("failed to configure embedding client: {error}"))
            })?;
        Ok(Self {
            client,
            provider,
            api_key,
            endpoint: endpoint.to_owned(),
            model: model.to_owned(),
        })
    }

    /// Embeds document chunks in bounded provider batches.
    ///
    /// # Errors
    ///
    /// Returns an error for provider failures or malformed vector output.
    pub async fn embed_documents(&self, texts: &[String]) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        self.embed_batched(texts, "document").await
    }

    /// Embeds one search query using the provider's retrieval-query mode.
    ///
    /// # Errors
    ///
    /// Returns an error for provider failures or malformed vector output.
    pub async fn embed_query(&self, query: &str) -> Result<Vec<f32>, EmbeddingError> {
        let vectors = self.embed_batched(&[query.to_owned()], "query").await?;
        vectors.into_iter().next().ok_or_else(|| {
            EmbeddingError::new("embedding provider returned no vector for the query")
        })
    }

    async fn embed_batched(
        &self,
        texts: &[String],
        input_type: &str,
    ) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if texts.is_empty() {
            return Ok(Vec::new());
        }
        if texts.iter().any(String::is_empty) {
            return Err(EmbeddingError::new("embedding input must not be empty"));
        }
        let mut embeddings = Vec::with_capacity(texts.len());
        for batch in texts.chunks(EMBEDDING_BATCH_SIZE) {
            embeddings.extend(self.embed_batch(batch, input_type).await?);
        }
        if embeddings.len() != texts.len() {
            return Err(EmbeddingError::new(format!(
                "embedding provider returned {} vector(s) for {} input(s)",
                embeddings.len(),
                texts.len()
            )));
        }
        validate_vectors(&embeddings)?;
        Ok(embeddings)
    }

    async fn embed_batch(
        &self,
        texts: &[String],
        input_type: &str,
    ) -> Result<Vec<Vec<f32>>, EmbeddingError> {
        if self.provider == EmbeddingProvider::Test {
            return Ok(texts.iter().map(|text| test_embedding(text)).collect());
        }
        let payload = request_payload(self.provider, &self.model, texts, input_type);
        let mut request = self.client.post(&self.endpoint).json(&payload);
        if let Some(api_key) = &self.api_key {
            request = request.bearer_auth(api_key);
        }
        let response = request.send().await.map_err(|error| {
            EmbeddingError::new(format!("embedding provider request failed: {error}"))
        })?;
        let status = response.status();
        let body = response.json::<Value>().await.map_err(|error| {
            EmbeddingError::new(format!("embedding provider response was not JSON: {error}"))
        })?;
        if !status.is_success() {
            return Err(remote_error(status, &body));
        }
        parse_response(self.provider, &body)
    }
}

fn request_payload(
    provider: EmbeddingProvider,
    model: &str,
    texts: &[String],
    input_type: &str,
) -> Value {
    match provider {
        EmbeddingProvider::Voyage => json!({
            "model": model,
            "input": texts,
            "input_type": input_type,
            "truncation": true,
            "output_dtype": "float"
        }),
        EmbeddingProvider::OpenAi => json!({
            "model": model,
            "input": texts,
            "encoding_format": "float"
        }),
        EmbeddingProvider::Ollama => json!({
            "model": model,
            "input": texts,
            "truncate": true
        }),
        EmbeddingProvider::Test => Value::Null,
    }
}

#[derive(Deserialize)]
struct IndexedEmbedding {
    index: usize,
    embedding: Vec<f32>,
}

fn parse_response(
    provider: EmbeddingProvider,
    body: &Value,
) -> Result<Vec<Vec<f32>>, EmbeddingError> {
    if provider == EmbeddingProvider::Ollama {
        return serde_json::from_value::<OllamaEmbeddingResponse>(body.clone())
            .map(|response| response.embeddings)
            .map_err(|error| {
                EmbeddingError::new(format!("invalid Ollama embedding response: {error}"))
            });
    }
    let mut data = serde_json::from_value::<IndexedEmbeddingResponse>(body.clone())
        .map_err(|error| EmbeddingError::new(format!("invalid embedding response: {error}")))?
        .data;
    data.sort_by_key(|item| item.index);
    Ok(data.into_iter().map(|item| item.embedding).collect())
}

#[derive(Deserialize)]
struct IndexedEmbeddingResponse {
    data: Vec<IndexedEmbedding>,
}

#[derive(Deserialize)]
struct OllamaEmbeddingResponse {
    embeddings: Vec<Vec<f32>>,
}

fn validate_vectors(vectors: &[Vec<f32>]) -> Result<(), EmbeddingError> {
    let Some(dimension) = vectors.first().map(Vec::len) else {
        return Ok(());
    };
    if dimension == 0 {
        return Err(EmbeddingError::new(
            "embedding provider returned an empty vector",
        ));
    }
    if vectors
        .iter()
        .any(|vector| vector.len() != dimension || vector.iter().any(|value| !value.is_finite()))
    {
        return Err(EmbeddingError::new(
            "embedding provider returned inconsistent or non-finite vectors",
        ));
    }
    Ok(())
}

fn test_embedding(text: &str) -> Vec<f32> {
    let mut vector = vec![0.0_f32; 8];
    for (index, byte) in text.bytes().enumerate() {
        vector[index % 8] += f32::from(byte) / 255.0;
    }
    if vector.iter().all(|value| *value == 0.0) {
        vector[0] = 1.0;
    }
    vector
}

fn voyage_endpoint(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    if base_url.ends_with("/embeddings") {
        base_url.to_owned()
    } else if base_url.ends_with("/v1") {
        format!("{base_url}/embeddings")
    } else {
        format!("{base_url}/v1/embeddings")
    }
}

fn openai_endpoint(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    if base_url.ends_with("/v1") {
        format!("{base_url}/embeddings")
    } else {
        format!("{base_url}/v1/embeddings")
    }
}

fn ollama_endpoint(base_url: &str) -> String {
    let base_url = base_url.trim_end_matches('/');
    if base_url.ends_with("/api") {
        format!("{base_url}/embed")
    } else {
        format!("{base_url}/api/embed")
    }
}

fn validate_http_endpoint(endpoint: &str) -> Result<(), EmbeddingError> {
    if endpoint.starts_with("https://") || endpoint.starts_with("http://") {
        Ok(())
    } else {
        Err(EmbeddingError::new(
            "embedding endpoint must be an absolute HTTP(S) URL",
        ))
    }
}

fn remote_error(status: StatusCode, body: &Value) -> EmbeddingError {
    let message = body
        .get("detail")
        .and_then(Value::as_str)
        .or_else(|| {
            body.get("error")
                .and_then(|error| error.get("message"))
                .and_then(Value::as_str)
        })
        .or_else(|| body.get("error").and_then(Value::as_str))
        .unwrap_or("unknown embedding provider error");
    EmbeddingError::new(format!("embedding provider returned {status}: {message}"))
}

#[cfg(test)]
mod tests {
    use serde_json::json;

    use super::{
        EmbeddingClient, EmbeddingProvider, ollama_endpoint, openai_endpoint, parse_response,
        request_payload, voyage_endpoint,
    };

    #[test]
    fn endpoints_accept_origins_and_versioned_bases() {
        assert_eq!(
            voyage_endpoint("https://example.test"),
            "https://example.test/v1/embeddings"
        );
        assert_eq!(
            openai_endpoint("http://localhost:11434/v1/"),
            "http://localhost:11434/v1/embeddings"
        );
        assert_eq!(
            ollama_endpoint("http://localhost:11434/api"),
            "http://localhost:11434/api/embed"
        );
    }

    #[test]
    fn voyage_payload_distinguishes_documents_from_queries() {
        let payload = request_payload(
            EmbeddingProvider::Voyage,
            "voyage-4",
            &["text".to_owned()],
            "document",
        );
        assert_eq!(payload["input_type"], "document");
        assert_eq!(payload["output_dtype"], "float");
    }

    #[test]
    fn indexed_responses_are_restored_to_input_order() -> Result<(), Box<dyn std::error::Error>> {
        let vectors = parse_response(
            EmbeddingProvider::OpenAi,
            &json!({"data":[
                {"index":1,"embedding":[0.0,1.0]},
                {"index":0,"embedding":[1.0,0.0]}
            ]}),
        )?;
        assert_eq!(vectors, [vec![1.0, 0.0], vec![0.0, 1.0]]);
        Ok(())
    }

    #[tokio::test]
    async fn test_provider_is_deterministic_and_batch_shaped()
    -> Result<(), Box<dyn std::error::Error>> {
        let client = EmbeddingClient::from_environment("test")?;
        let first = client
            .embed_documents(&["alpha".to_owned(), "beta".to_owned()])
            .await?;
        let second = client.embed_query("alpha").await?;
        assert_eq!(first.len(), 2);
        assert_eq!(first[0], second);
        Ok(())
    }
}
