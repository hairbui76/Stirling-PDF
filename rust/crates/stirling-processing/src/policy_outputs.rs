//! Inline, folder, and S3 policy result delivery.

use std::{
    io,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use chrono::Utc;
use md5::{Digest, Md5};
use rand::RngExt as _;
use sha2::Sha256;
use tokio::{
    fs,
    io::{AsyncReadExt as _, AsyncWriteExt as _, BufReader, BufWriter},
};
use tracing::debug;

use crate::{
    job_manager::JobSubmission,
    pipeline::PipelineOutput,
    policy_config::{OutputSpec, PolicyConfigService, PolicyFailure},
    policy_ledger::ProcessedLedger,
    policy_s3::{
        S3Config, S3ConnectionPool, S3Failure, object_exists, output_key_prefix, put_object,
        s3_gate, s3_identity,
    },
    security::{AuthContext, SecurityError},
};

const STALE_TMP_AGE: Duration = Duration::from_secs(24 * 60 * 60);

#[derive(Clone)]
pub(crate) struct PolicyOutputService {
    config: Arc<PolicyConfigService>,
    ledger: Arc<ProcessedLedger>,
    s3: S3ConnectionPool,
}

impl PolicyOutputService {
    pub(crate) fn new(
        config: Arc<PolicyConfigService>,
        ledger: Arc<ProcessedLedger>,
        s3: S3ConnectionPool,
    ) -> Self {
        Self { config, ledger, s3 }
    }

    pub(crate) async fn deliver(
        &self,
        run_id: &str,
        policy_id: Option<&str>,
        spec: &OutputSpec,
        context: &AuthContext,
        submission: &JobSubmission,
        output: PipelineOutput,
    ) -> Result<DeliveredOutput, PolicyOutputFailure> {
        let persisted = submission.directory.join("policy-result.bin");
        fs::copy(&output.path, &persisted).await?;
        let file_name = match spec.output_type.as_str() {
            "inline" => output.filename,
            "folder" => self
                .deliver_folder(policy_id, spec, &persisted, &output.filename)
                .await?
                .to_string_lossy()
                .into_owned(),
            "s3" => {
                self.deliver_s3(policy_id, spec, context, &persisted, &output.filename)
                    .await?
            }
            value => {
                return Err(PolicyOutputFailure::Unsupported(value.to_owned()));
            }
        };
        debug!(%run_id, %file_name, "delivered policy output");
        Ok(DeliveredOutput {
            persisted,
            file_name,
            content_type: output.content_type,
        })
    }

    async fn deliver_folder(
        &self,
        policy_id: Option<&str>,
        spec: &OutputSpec,
        source: &Path,
        filename: &str,
    ) -> Result<PathBuf, PolicyOutputFailure> {
        let directory = self.config.permitted_folder_directory(&spec.options)?;
        fs::create_dir_all(&directory).await?;
        let canonical = fs::canonicalize(&directory).await?;
        let staging_directory = canonical.join(".stirling/tmp");
        fs::create_dir_all(&staging_directory).await?;
        sweep_stale_staging(&staging_directory).await;
        let staged = staging_directory.join(random_staging_name());
        let content_hash = copy_with_hash::<Sha256>(source, &staged, policy_id.is_some()).await?;
        let gate = super::policy_sources::stat_gate(&staged).await?;
        let name = safe_output_name(filename, 0);
        let mut attempt = 0_usize;
        loop {
            let candidate_name = if attempt == 0 {
                name.clone()
            } else {
                numbered_output_name(&name, attempt)
            };
            let target = canonical.join(candidate_name);
            let identity = target.to_string_lossy().into_owned();
            if let Some(policy_id) = policy_id {
                self.ledger.record_output(
                    policy_id,
                    &identity,
                    &gate,
                    content_hash.as_deref(),
                    Utc::now().timestamp_millis(),
                )?;
            }
            match fs::hard_link(&staged, &target).await {
                Ok(()) => {
                    fs::remove_file(&staged).await?;
                    return Ok(target);
                }
                Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {
                    if let Some(policy_id) = policy_id {
                        self.ledger.forget_output(policy_id, &identity, &gate)?;
                    }
                    attempt = attempt.saturating_add(1);
                }
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn deliver_s3(
        &self,
        policy_id: Option<&str>,
        spec: &OutputSpec,
        context: &AuthContext,
        source: &Path,
        filename: &str,
    ) -> Result<String, PolicyOutputFailure> {
        let options = self.config.resolved_s3_options(&spec.options, context)?;
        let config = S3Config::from_options(&options)?;
        let client = self.s3.client_for(&config)?;
        let predicted_gate = if policy_id.is_some() {
            hash_file::<Md5>(source).await?
        } else {
            String::new()
        };
        let key_prefix = output_key_prefix(&config.prefix);
        let name = safe_output_name(filename, 0);
        let mut conditional = true;
        let mut attempt = 0_usize;
        loop {
            let candidate = if attempt == 0 {
                name.clone()
            } else {
                numbered_output_name(&name, attempt)
            };
            let key = format!("{key_prefix}{candidate}");
            let identity = s3_identity(&config.bucket, &key);
            if !conditional && object_exists(&client, &config, &key).await? {
                attempt = attempt.saturating_add(1);
                continue;
            }
            if let Some(policy_id) = policy_id {
                self.ledger.record_output(
                    policy_id,
                    &identity,
                    &predicted_gate,
                    None,
                    Utc::now().timestamp_millis(),
                )?;
            }
            match put_object(&client, &config, &key, source, conditional).await {
                Ok(etag) => {
                    if let Some(policy_id) = policy_id {
                        let actual_gate = s3_gate(etag.as_deref(), None, None);
                        if actual_gate != predicted_gate {
                            self.ledger.record_output(
                                policy_id,
                                &identity,
                                &actual_gate,
                                None,
                                Utc::now().timestamp_millis(),
                            )?;
                        }
                    }
                    return Ok(identity);
                }
                Err(error) => {
                    if let Some(policy_id) = policy_id {
                        self.ledger
                            .forget_output(policy_id, &identity, &predicted_gate)?;
                    }
                    if conditional && error.status == Some(412) {
                        attempt = attempt.saturating_add(1);
                        continue;
                    }
                    if conditional && error.status == Some(501) {
                        conditional = false;
                        continue;
                    }
                    return Err(error.into());
                }
            }
        }
    }
}

pub(crate) struct DeliveredOutput {
    pub(crate) persisted: PathBuf,
    pub(crate) file_name: String,
    pub(crate) content_type: String,
}

async fn copy_with_hash<D>(
    source: &Path,
    target: &Path,
    hashed: bool,
) -> Result<Option<String>, io::Error>
where
    D: Digest + Default,
{
    let source = fs::File::open(source).await?;
    let mut reader = BufReader::new(source);
    let target = fs::File::create(target).await?;
    let mut writer = BufWriter::new(target);
    let mut digest = D::default();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        writer.write_all(&buffer[..read]).await?;
        if hashed {
            digest.update(&buffer[..read]);
        }
    }
    writer.flush().await?;
    if !hashed {
        return Ok(None);
    }
    Ok(Some(hex_digest(digest.finalize().as_ref())))
}

async fn hash_file<D>(source: &Path) -> Result<String, io::Error>
where
    D: Digest + Default,
{
    let source = fs::File::open(source).await?;
    let mut reader = BufReader::new(source);
    let mut digest = D::default();
    let mut buffer = vec![0_u8; 64 * 1024];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        digest.update(&buffer[..read]);
    }
    Ok(hex_digest(digest.finalize().as_ref()))
}

fn hex_digest(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

async fn sweep_stale_staging(directory: &Path) {
    let Ok(mut entries) = fs::read_dir(directory).await else {
        return;
    };
    loop {
        let Ok(Some(entry)) = entries.next_entry().await else {
            break;
        };
        let path = entry.path();
        let stale = entry
            .metadata()
            .await
            .ok()
            .filter(std::fs::Metadata::is_file)
            .and_then(|metadata| metadata.modified().ok())
            .and_then(|modified| modified.elapsed().ok())
            .is_some_and(|age| age > STALE_TMP_AGE);
        if stale && let Err(error) = fs::remove_file(&path).await {
            debug!(path = %path.display(), %error, "could not remove stale policy staging file");
        }
    }
}

fn safe_output_name(filename: &str, index: usize) -> String {
    let name = filename
        .rsplit(['/', '\\'])
        .next()
        .map(str::trim)
        .filter(|name| !name.is_empty() && !matches!(*name, "." | ".."));
    name.map_or_else(|| format!("output-{index}"), ToOwned::to_owned)
}

fn numbered_output_name(filename: &str, number: usize) -> String {
    let Some((base, extension)) = filename.rsplit_once('.') else {
        return format!("{filename} ({number})");
    };
    format!("{base} ({number}).{extension}")
}

fn random_staging_name() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    hex_digest(&bytes)
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum PolicyOutputFailure {
    #[error("{0}")]
    Policy(#[from] PolicyFailure),
    #[error("{0}")]
    Security(#[from] SecurityError),
    #[error("{0}")]
    Io(#[from] io::Error),
    #[error("{0}")]
    S3(#[from] S3Failure),
    #[error("unsupported policy output type: {0}")]
    Unsupported(String),
}

#[cfg(test)]
mod tests {
    use super::{numbered_output_name, safe_output_name};

    #[test]
    fn output_names_strip_paths_and_number_before_extensions() {
        assert_eq!(safe_output_name("../../report.pdf", 0), "report.pdf");
        assert_eq!(safe_output_name("..\\..\\report.pdf", 0), "report.pdf");
        assert_eq!(safe_output_name("..", 2), "output-2");
        assert_eq!(numbered_output_name("report.pdf", 3), "report (3).pdf");
        assert_eq!(numbered_output_name("report", 3), "report (3)");
    }
}
