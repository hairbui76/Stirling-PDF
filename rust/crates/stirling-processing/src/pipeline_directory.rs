//! Filesystem-backed pipeline automation.
//!
//! The HTTP pipeline endpoint is deliberately synchronous. This module owns the
//! separate watched-folder lifecycle and is started only by the binary runtime,
//! never while a router is constructed for a test.

use std::{
    fs::{self, OpenOptions},
    io,
    path::{Path, PathBuf},
    time::Duration,
};

use chrono::Local;
use tokio::{fs as async_fs, time::sleep};
use tracing::{debug, error, info, warn};

use crate::{
    pipeline::{PipelineConfig, PipelineDispatcher, PipelineFile, read_config_file, run_files},
    runtime_config::{FileReadinessConfig, PipelineDirectoryConfig},
};

const SCAN_INTERVAL: Duration = Duration::from_secs(60);
const MAX_DIRECTORY_DEPTH: usize = 50;

#[derive(Clone)]
pub(crate) struct PipelineDirectoryWatcher {
    dispatcher: PipelineDispatcher,
    config: PipelineDirectoryConfig,
}

impl PipelineDirectoryWatcher {
    pub(crate) fn new(dispatcher: PipelineDispatcher, config: PipelineDirectoryConfig) -> Self {
        Self { dispatcher, config }
    }

    pub(crate) async fn run_forever(self) {
        loop {
            self.scan_once().await;
            sleep(SCAN_INTERVAL).await;
        }
    }

    pub(crate) async fn scan_once(&self) {
        for watched_folder in &self.config.watched_folders {
            self.scan_watched_folder(watched_folder).await;
        }
    }

    async fn scan_watched_folder(&self, watched_folder: &Path) {
        if let Err(error) = async_fs::create_dir_all(watched_folder).await {
            error!(path = %watched_folder.display(), %error, "could not create watched pipeline folder");
            return;
        }

        let directories = match job_directories(watched_folder) {
            Ok(directories) => directories,
            Err(error) => {
                error!(path = %watched_folder.display(), %error, "could not scan watched pipeline folder");
                return;
            }
        };
        for directory in directories {
            self.process_directory(&directory).await;
        }
    }

    async fn process_directory(&self, directory: &Path) {
        let Some(config_path) = find_config_file(directory) else {
            return;
        };
        let mut config = match read_config_file(&config_path) {
            Ok(config) => config,
            Err(error) => {
                warn!(path = %config_path.display(), ?error, "skipping invalid pipeline configuration");
                return;
            }
        };
        if config.name.trim().is_empty() {
            config.name = config_path
                .file_stem()
                .and_then(|name| name.to_str())
                .unwrap_or("pipeline")
                .to_owned();
        }

        let files = self.collect_ready_files(directory, &config_path).await;
        if files.is_empty() {
            return;
        }
        let processing_directory = directory.join("processing");
        let moved_files = match move_inputs(&files, &processing_directory).await {
            Ok(files) => files,
            Err(error) => {
                error!(path = %directory.display(), %error, "could not move pipeline inputs into processing folder");
                return;
            }
        };

        let result = run_files(&self.dispatcher, moved_files.clone(), &config).await;
        let outputs = match result {
            Ok(outputs) => outputs,
            Err(error) => {
                error!(path = %directory.display(), ?error, "watched pipeline failed; restoring input files");
                restore_inputs(&moved_files, directory).await;
                return;
            }
        };

        if let Err(error) = write_outputs(
            &outputs.files,
            &config,
            directory,
            &self.config.finished_folder,
        )
        .await
        {
            error!(path = %directory.display(), %error, "could not write watched pipeline output; restoring input files");
            restore_inputs(&moved_files, directory).await;
            return;
        }
        if let Err(error) = delete_inputs(&moved_files).await {
            error!(path = %directory.display(), %error, "could not remove processed inputs; restoring input files");
            restore_inputs(&moved_files, directory).await;
            return;
        }
        info!(path = %directory.display(), input_count = moved_files.len(), "processed watched pipeline directory");
    }

    async fn collect_ready_files(&self, directory: &Path, config_path: &Path) -> Vec<PipelineFile> {
        let entries = match fs::read_dir(directory) {
            Ok(entries) => entries,
            Err(error) => {
                warn!(path = %directory.display(), %error, "could not read watched pipeline directory");
                return Vec::new();
            }
        };
        let mut files = Vec::new();
        for entry in entries.flatten() {
            let path = entry.path();
            let Ok(file_type) = entry.file_type() else {
                continue;
            };
            if !file_type.is_file() || path == config_path {
                continue;
            }
            if !file_is_ready(&path, &self.config.readiness).await {
                debug!(path = %path.display(), "pipeline input is not ready");
                continue;
            }
            files.push(PipelineFile {
                filename: entry.file_name().to_string_lossy().into_owned(),
                path,
                content_type: None,
                origin: None,
            });
        }
        files.sort_by(|left, right| left.filename.cmp(&right.filename));
        files
    }
}

fn job_directories(root: &Path) -> io::Result<Vec<PathBuf>> {
    let mut directories = Vec::new();
    collect_job_directories(root, 0, &mut directories)?;
    Ok(directories)
}

fn collect_job_directories(
    directory: &Path,
    depth: usize,
    directories: &mut Vec<PathBuf>,
) -> io::Result<()> {
    if depth >= MAX_DIRECTORY_DEPTH {
        warn!(path = %directory.display(), "pipeline directory scan reached maximum depth");
        return Ok(());
    }
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() || !file_type.is_dir() {
            continue;
        }
        let path = entry.path();
        let name = entry.file_name();
        if matches!(name.to_str(), Some("processing" | "error")) {
            continue;
        }
        directories.push(path.clone());
        collect_job_directories(&path, depth.saturating_add(1), directories)?;
    }
    Ok(())
}

fn find_config_file(directory: &Path) -> Option<PathBuf> {
    let mut candidates = fs::read_dir(directory)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let file_type = entry.file_type().ok()?;
            let path = entry.path();
            (file_type.is_file()
                && path
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("json")))
            .then_some(path)
        })
        .collect::<Vec<_>>();
    candidates.sort();
    candidates.into_iter().next()
}

pub(crate) async fn file_is_ready(path: &Path, config: &FileReadinessConfig) -> bool {
    if !config.enabled {
        return true;
    }
    if !extension_is_allowed(path, config) {
        return false;
    }
    let Ok(metadata) = async_fs::metadata(path).await else {
        return false;
    };
    let Ok(modified) = metadata.modified() else {
        return false;
    };
    let Ok(age) = modified.elapsed() else {
        return false;
    };
    if age < config.settle_time {
        return false;
    }
    let initial_size = metadata.len();
    sleep(config.size_check_delay).await;
    let Ok(current_metadata) = async_fs::metadata(path).await else {
        return false;
    };
    if initial_size != current_metadata.len() {
        return false;
    }
    file_has_exclusive_lock(path)
}

fn extension_is_allowed(path: &Path, config: &FileReadinessConfig) -> bool {
    config.allowed_extensions.is_empty()
        || path
            .extension()
            .and_then(|extension| extension.to_str())
            .map(str::to_ascii_lowercase)
            .is_some_and(|extension| config.allowed_extensions.contains(&extension))
}

fn file_has_exclusive_lock(path: &Path) -> bool {
    let Ok(file) = OpenOptions::new().read(true).write(true).open(path) else {
        return false;
    };
    if file.try_lock().is_err() {
        return false;
    }
    file.unlock().is_ok()
}

async fn move_inputs(
    files: &[PipelineFile],
    processing_directory: &Path,
) -> io::Result<Vec<PipelineFile>> {
    async_fs::create_dir_all(processing_directory).await?;
    let mut moved_files = Vec::with_capacity(files.len());
    for file in files {
        let target = unique_path(processing_directory, &file.filename);
        if let Err(error) = move_file(&file.path, &target).await {
            restore_inputs(
                &moved_files,
                file.path.parent().unwrap_or_else(|| Path::new(".")),
            )
            .await;
            return Err(error);
        }
        moved_files.push(PipelineFile {
            filename: file.filename.clone(),
            path: target,
            content_type: file.content_type.clone(),
            origin: file.origin,
        });
    }
    Ok(moved_files)
}

async fn move_file(source: &Path, destination: &Path) -> io::Result<()> {
    if let Ok(()) = async_fs::rename(source, destination).await {
        Ok(())
    } else {
        async_fs::copy(source, destination).await?;
        async_fs::remove_file(source).await
    }
}

async fn restore_inputs(files: &[PipelineFile], directory: &Path) {
    for file in files {
        let target = unique_path(directory, &file.filename);
        if let Err(error) = move_file(&file.path, &target).await {
            error!(path = %file.path.display(), %error, "could not restore watched pipeline input");
        }
    }
}

async fn delete_inputs(files: &[PipelineFile]) -> io::Result<()> {
    for file in files {
        async_fs::remove_file(&file.path).await?;
    }
    Ok(())
}

fn unique_path(directory: &Path, filename: &str) -> PathBuf {
    let filename = safe_filename(filename);
    let mut counter = 0_usize;
    loop {
        let candidate = if counter == 0 {
            directory.join(&filename)
        } else {
            directory.join(filename_with_suffix(&filename, counter))
        };
        if !candidate.exists() {
            return candidate;
        }
        counter = counter.saturating_add(1);
    }
}

async fn write_outputs(
    files: &[PipelineFile],
    config: &PipelineConfig,
    source_directory: &Path,
    finished_directory: &Path,
) -> io::Result<()> {
    let output_directory = output_directory(config, source_directory, finished_directory);
    async_fs::create_dir_all(&output_directory).await?;
    for file in files {
        let filename = output_filename(&file.filename, config);
        async_fs::copy(&file.path, output_directory.join(filename)).await?;
    }
    Ok(())
}

fn output_directory(
    config: &PipelineConfig,
    source_directory: &Path,
    finished_directory: &Path,
) -> PathBuf {
    let configured = config
        .output_dir
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("{outputFolder}");
    let value = configured
        .replace("{outputFolder}", &finished_directory.to_string_lossy())
        .replace("{folderName}", &source_directory.to_string_lossy());
    PathBuf::from(value)
}

fn output_filename(filename: &str, config: &PipelineConfig) -> String {
    let filename = safe_filename(filename);
    let (base_name, extension) = filename
        .rsplit_once('.')
        .map_or((filename.as_str(), "bin"), |(base_name, extension)| {
            (base_name, extension)
        });
    let pattern = config
        .output_pattern
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("{filename}");
    let now = Local::now();
    let value = pattern
        .replace("{filename}", base_name)
        .replace("{pipelineName}", &config.name)
        .replace("{date}", &now.format("%Y%m%d").to_string())
        .replace("{time}", &now.format("%H%M%S").to_string());
    safe_filename(&format!("{value}.{extension}"))
}

fn safe_filename(filename: &str) -> String {
    Path::new(filename)
        .file_name()
        .and_then(|name| name.to_str())
        .filter(|name| !name.trim().is_empty() && *name != "." && *name != "..")
        .unwrap_or("output")
        .to_owned()
}

fn filename_with_suffix(filename: &str, suffix: usize) -> String {
    filename.rsplit_once('.').map_or_else(
        || format!("{filename}({suffix})"),
        |(stem, extension)| format!("{stem}({suffix}).{extension}"),
    )
}

#[cfg(test)]
mod tests {
    use std::{collections::BTreeSet, fs, path::Path, time::Duration};

    use lopdf::{Document, Object, Stream, dictionary};
    use tempfile::tempdir;

    use super::*;

    #[tokio::test]
    async fn scans_a_directory_and_writes_the_named_pipeline_output()
    -> Result<(), Box<dyn std::error::Error>> {
        let temporary = tempdir()?;
        let watched = temporary.path().join("watched");
        let job = watched.join("rotate");
        fs::create_dir_all(&job)?;
        let input = job.join("input.pdf");
        write_pdf(&input)?;
        fs::write(
            job.join("pipeline.json"),
            r#"{
                "name": "rotate-pdf",
                "outputDir": "{outputFolder}",
                "outputFileName": "{filename}-done",
                "pipeline": [{
                    "operation": "/api/v1/general/rotate-pdf",
                    "parameters": {"angle": 90}
                }]
            }"#,
        )?;
        let finished = temporary.path().join("finished");
        let directory_watcher = PipelineDirectoryWatcher::new(
            PipelineDispatcher::new(crate::processing_routes()),
            PipelineDirectoryConfig {
                watched_folders: vec![watched],
                finished_folder: finished.clone(),
                readiness: FileReadinessConfig {
                    enabled: false,
                    settle_time: Duration::ZERO,
                    size_check_delay: Duration::ZERO,
                    allowed_extensions: BTreeSet::new(),
                },
            },
        );

        directory_watcher.scan_once().await;

        assert!(finished.join("input-done.pdf").is_file());
        assert!(!input.exists());
        Ok(())
    }

    fn write_pdf(path: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let mut document = Document::with_version("1.5");
        let page_tree_id = document.new_object_id();
        let leaf_id = document.new_object_id();
        let content_id = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        document.objects.insert(
            leaf_id,
            dictionary! {
                "Type" => "Page",
                "Parent" => page_tree_id,
                "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
                "Contents" => content_id,
            }
            .into(),
        );
        document.objects.insert(
            page_tree_id,
            dictionary! {
                "Type" => "Pages",
                "Kids" => vec![Object::Reference(leaf_id)],
                "Count" => 1,
            }
            .into(),
        );
        let catalog_id =
            document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
        document.trailer.set("Root", catalog_id);
        document.save(path)?;
        Ok(())
    }
}
