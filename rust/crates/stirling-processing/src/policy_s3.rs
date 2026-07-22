//! S3-compatible policy object transport with explicit per-connection credentials.

use std::{
    collections::HashMap,
    hash::{Hash, Hasher},
    path::Path,
    sync::{Arc, Mutex},
};

use aws_sdk_s3::{
    Client,
    config::{BehaviorVersion, Credentials, Region},
    primitives::ByteStream,
};
use serde_json::{Map, Value};
use tokio::{fs::File, io::AsyncWriteExt as _};

#[derive(Clone, Eq)]
pub(crate) struct S3Config {
    pub(crate) bucket: String,
    pub(crate) region: String,
    pub(crate) prefix: String,
    pub(crate) endpoint: Option<String>,
    access_key_id: String,
    secret_access_key: String,
    pub(crate) snapshot: bool,
}

impl PartialEq for S3Config {
    fn eq(&self, other: &Self) -> bool {
        self.bucket == other.bucket
            && self.region == other.region
            && self.prefix == other.prefix
            && self.endpoint == other.endpoint
            && self.access_key_id == other.access_key_id
            && self.secret_access_key == other.secret_access_key
            && self.snapshot == other.snapshot
    }
}

impl Hash for S3Config {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.bucket.hash(state);
        self.region.hash(state);
        self.prefix.hash(state);
        self.endpoint.hash(state);
        self.access_key_id.hash(state);
        self.secret_access_key.hash(state);
        self.snapshot.hash(state);
    }
}

impl S3Config {
    pub(crate) fn from_options(options: &Map<String, Value>) -> Result<Self, S3Failure> {
        let bucket = required_string(options, "bucket", "s3 config requires a 'bucket' option")?;
        let access_key_id = required_string(
            options,
            "accessKeyId",
            "s3 config requires an 'accessKeyId' and 'secretAccessKey'",
        )?;
        let secret_access_key = required_string(
            options,
            "secretAccessKey",
            "s3 config requires an 'accessKeyId' and 'secretAccessKey'",
        )?;
        let region = optional_string(options, "region").unwrap_or_else(|| "us-east-1".to_owned());
        let mut prefix = optional_string(options, "prefix").unwrap_or_default();
        if prefix.starts_with('/') {
            prefix.remove(0);
        }
        let endpoint = optional_string(options, "endpoint");
        let mode = optional_string(options, "mode");
        if mode
            .as_deref()
            .is_some_and(|mode| !matches!(mode, "consume" | "snapshot"))
        {
            return Err(S3Failure::configuration(
                "s3 config 'mode' must be 'consume' or 'snapshot'",
            ));
        }
        Ok(Self {
            bucket,
            region,
            prefix,
            endpoint,
            access_key_id,
            secret_access_key,
            snapshot: mode.as_deref() == Some("snapshot"),
        })
    }
}

#[derive(Clone)]
pub(crate) struct S3ConnectionPool {
    clients: Arc<Mutex<HashMap<S3Config, Client>>>,
}

impl S3ConnectionPool {
    pub(crate) fn new() -> Self {
        Self {
            clients: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub(crate) fn client_for(&self, config: &S3Config) -> Result<Client, S3Failure> {
        let mut clients = self
            .clients
            .lock()
            .map_err(|_| S3Failure::configuration("S3 client pool unavailable"))?;
        if let Some(client) = clients.get(config) {
            return Ok(client.clone());
        }
        let credentials = Credentials::new(
            config.access_key_id.clone(),
            config.secret_access_key.clone(),
            None,
            None,
            "stirling-policy",
        );
        let mut builder = aws_sdk_s3::Config::builder()
            .behavior_version(BehaviorVersion::latest())
            .region(Region::new(config.region.clone()))
            .credentials_provider(credentials);
        if let Some(endpoint) = &config.endpoint {
            builder = builder.endpoint_url(endpoint).force_path_style(true);
        }
        let client = Client::from_conf(builder.build());
        clients.insert(config.clone(), client.clone());
        Ok(client)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ListedS3Object {
    pub(crate) key: String,
    pub(crate) etag: Option<String>,
    pub(crate) size: Option<i64>,
    pub(crate) modified_millis: Option<i64>,
}

impl ListedS3Object {
    pub(crate) fn filename(&self) -> String {
        self.key
            .rsplit('/')
            .next()
            .filter(|name| !name.is_empty())
            .unwrap_or("file")
            .to_owned()
    }
}

pub(crate) async fn list_objects(
    client: &Client,
    config: &S3Config,
) -> Result<Vec<ListedS3Object>, S3Failure> {
    let mut continuation = None;
    let mut objects = Vec::new();
    loop {
        let mut request = client.list_objects_v2().bucket(&config.bucket);
        if !config.prefix.is_empty() {
            request = request.prefix(&config.prefix);
        }
        if let Some(token) = continuation {
            request = request.continuation_token(token);
        }
        let page = request.send().await.map_err(|error| {
            S3Failure::request(
                "list S3 objects",
                error.to_string(),
                error
                    .raw_response()
                    .map(|response| response.status().as_u16()),
            )
        })?;
        objects.extend(page.contents().iter().filter_map(|object| {
            let key = object.key()?.to_owned();
            ingestible_key(&key).then(|| ListedS3Object {
                key,
                etag: object.e_tag().map(ToOwned::to_owned),
                size: object.size(),
                modified_millis: object
                    .last_modified()
                    .and_then(|modified| (*modified).to_millis().ok()),
            })
        }));
        continuation = page.next_continuation_token().map(ToOwned::to_owned);
        if continuation.is_none() {
            break;
        }
    }
    Ok(objects)
}

pub(crate) async fn download_object(
    client: &Client,
    config: &S3Config,
    object: &ListedS3Object,
    target: &Path,
) -> Result<(), S3Failure> {
    let mut request = client.get_object().bucket(&config.bucket).key(&object.key);
    if let Some(etag) = object
        .etag
        .as_deref()
        .filter(|etag| !etag.trim().is_empty())
    {
        request = request.if_match(etag);
    }
    let response = request.send().await.map_err(|error| {
        S3Failure::request(
            "read S3 object",
            error.to_string(),
            error
                .raw_response()
                .map(|response| response.status().as_u16()),
        )
    })?;
    let mut reader = response.body.into_async_read();
    let mut output = File::create(target)
        .await
        .map_err(|error| S3Failure::request("create S3 input", error.to_string(), None))?;
    tokio::io::copy(&mut reader, &mut output)
        .await
        .map_err(|error| S3Failure::request("stream S3 object", error.to_string(), None))?;
    output
        .flush()
        .await
        .map_err(|error| S3Failure::request("flush S3 input", error.to_string(), None))?;
    Ok(())
}

pub(crate) async fn current_gate(
    client: &Client,
    config: &S3Config,
    key: &str,
) -> Result<Option<String>, S3Failure> {
    match client
        .head_object()
        .bucket(&config.bucket)
        .key(key)
        .send()
        .await
    {
        Ok(head) => Ok(Some(s3_gate(
            head.e_tag(),
            head.content_length(),
            head.last_modified()
                .and_then(|value| value.to_millis().ok()),
        ))),
        Err(error)
            if error
                .raw_response()
                .is_some_and(|response| response.status().as_u16() == 404) =>
        {
            Ok(None)
        }
        Err(error) => Err(S3Failure::request(
            "inspect S3 object",
            error.to_string(),
            error
                .raw_response()
                .map(|response| response.status().as_u16()),
        )),
    }
}

pub(crate) async fn delete_object(
    client: &Client,
    config: &S3Config,
    key: &str,
) -> Result<(), S3Failure> {
    client
        .delete_object()
        .bucket(&config.bucket)
        .key(key)
        .send()
        .await
        .map_err(|error| {
            S3Failure::request(
                "delete S3 object",
                error.to_string(),
                error
                    .raw_response()
                    .map(|response| response.status().as_u16()),
            )
        })?;
    Ok(())
}

pub(crate) async fn object_exists(
    client: &Client,
    config: &S3Config,
    key: &str,
) -> Result<bool, S3Failure> {
    current_gate(client, config, key)
        .await
        .map(|gate| gate.is_some())
}

pub(crate) async fn put_object(
    client: &Client,
    config: &S3Config,
    key: &str,
    path: &Path,
    conditional: bool,
) -> Result<Option<String>, S3Failure> {
    let body = ByteStream::from_path(path)
        .await
        .map_err(|error| S3Failure::request("open S3 output", error.to_string(), None))?;
    let mut request = client
        .put_object()
        .bucket(&config.bucket)
        .key(key)
        .body(body);
    if conditional {
        request = request.if_none_match("*");
    }
    let response = request.send().await.map_err(|error| {
        S3Failure::request(
            "upload S3 object",
            error.to_string(),
            error
                .raw_response()
                .map(|response| response.status().as_u16()),
        )
    })?;
    Ok(response.e_tag().map(ToOwned::to_owned))
}

pub(crate) fn s3_identity(bucket: &str, key: &str) -> String {
    format!("s3://{bucket}/{key}")
}

pub(crate) fn output_key_prefix(prefix: &str) -> String {
    if prefix.is_empty() || prefix.ends_with('/') {
        prefix.to_owned()
    } else {
        format!("{prefix}/")
    }
}

pub(crate) fn s3_gate(
    etag: Option<&str>,
    size: Option<i64>,
    modified_millis: Option<i64>,
) -> String {
    if let Some(etag) = etag.filter(|etag| !etag.trim().is_empty()) {
        return etag.replace('"', "");
    }
    format!("{}:{}", size.unwrap_or(-1), modified_millis.unwrap_or(0))
}

fn ingestible_key(key: &str) -> bool {
    !key.is_empty()
        && !key.ends_with('/')
        && !key.split('/').any(|segment| segment.starts_with('.'))
}

fn required_string(
    options: &Map<String, Value>,
    key: &str,
    message: &str,
) -> Result<String, S3Failure> {
    optional_string(options, key).ok_or_else(|| S3Failure::configuration(message))
}

fn optional_string(options: &Map<String, Value>, key: &str) -> Option<String> {
    options
        .get(key)
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(ToOwned::to_owned)
}

#[derive(Debug, thiserror::Error)]
#[error("{operation} failed: {message}")]
pub(crate) struct S3Failure {
    operation: &'static str,
    message: String,
    pub(crate) status: Option<u16>,
}

impl S3Failure {
    fn configuration(message: impl Into<String>) -> Self {
        Self {
            operation: "S3 configuration",
            message: message.into(),
            status: None,
        }
    }

    fn request(operation: &'static str, message: String, status: Option<u16>) -> Self {
        Self {
            operation,
            message,
            status,
        }
    }
}

#[cfg(test)]
mod tests {
    use serde_json::{Map, json};

    use super::{S3Config, ingestible_key, s3_gate, s3_identity};

    #[test]
    fn parses_java_s3_defaults_without_exposing_credentials()
    -> Result<(), Box<dyn std::error::Error>> {
        let options = serde_json::from_value::<Map<String, serde_json::Value>>(json!({
            "bucket":"documents",
            "prefix":"/incoming",
            "accessKeyId":"access",
            "secretAccessKey":"secret"
        }))?;
        let config = S3Config::from_options(&options)?;
        assert_eq!(config.bucket, "documents");
        assert_eq!(config.region, "us-east-1");
        assert_eq!(config.prefix, "incoming");
        assert!(!config.snapshot);
        Ok(())
    }

    #[test]
    fn identities_gates_and_hidden_keys_match_java() {
        assert_eq!(
            s3_identity("bucket", "path/a.pdf"),
            "s3://bucket/path/a.pdf"
        );
        assert_eq!(s3_gate(Some("\"etag\""), Some(10), Some(20)), "etag");
        assert_eq!(s3_gate(None, Some(10), Some(20)), "10:20");
        assert!(ingestible_key("path/a.pdf"));
        assert!(!ingestible_key("path/"));
        assert!(!ingestible_key("path/.stirling/a.pdf"));
    }
}
