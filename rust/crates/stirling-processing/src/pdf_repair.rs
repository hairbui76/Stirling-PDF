//! Java-compatible PDF repair orchestration.

use std::{
    ffi::OsString,
    fs,
    path::{Path, PathBuf},
    process::Output,
};

use thiserror::Error;

use crate::{
    pdf_document_ops::{DocumentOperationError, repair_pdf_to_file},
    process_executor::{ProcessExecutor, ProcessExecutorError},
    runtime_config::{RepairProcessSettings, RuntimeConfig},
};

#[derive(Clone, Debug)]
pub(crate) struct RepairRuntime {
    ghostscript_command: Option<PathBuf>,
    qpdf_command: Option<PathBuf>,
    ghostscript: ProcessExecutor,
    qpdf: ProcessExecutor,
}

#[derive(Debug, Error)]
pub(crate) enum RepairError {
    #[error(transparent)]
    InProcess(#[from] DocumentOperationError),
    #[error("PDF repair failed with the available external tools: {details}")]
    ExternalTools { details: String },
}

impl RepairRuntime {
    pub(crate) fn from_runtime_config(config: &RuntimeConfig) -> Self {
        Self::new(
            config.dependency_command("Ghostscript"),
            config.dependency_command("qpdf"),
            config.repair_process_settings(),
        )
    }

    fn new(
        ghostscript_command: Option<PathBuf>,
        qpdf_command: Option<PathBuf>,
        settings: RepairProcessSettings,
    ) -> Self {
        Self {
            ghostscript_command,
            qpdf_command,
            ghostscript: ProcessExecutor::new(
                settings.ghostscript_session_limit,
                settings.ghostscript_timeout,
            ),
            qpdf: ProcessExecutor::new(settings.qpdf_session_limit, settings.qpdf_timeout),
        }
    }

    /// Runs Ghostscript, then qpdf, or the in-process structural rewrite when
    /// startup discovery found neither external repair tool.
    pub(crate) fn repair(
        &self,
        input_path: &Path,
        filename: &str,
        output_path: &Path,
    ) -> Result<(), RepairError> {
        if self.ghostscript_command.is_none() && self.qpdf_command.is_none() {
            return repair_pdf_to_file(input_path, filename, output_path)
                .map_err(RepairError::from);
        }

        let mut failures = Vec::new();
        if let Some(command) = &self.ghostscript_command {
            let arguments = [
                OsString::from("-o"),
                output_path.as_os_str().to_owned(),
                OsString::from("-sDEVICE=pdfwrite"),
                input_path.as_os_str().to_owned(),
            ];
            match self.ghostscript.run(command, &arguments) {
                Ok(output) if output.status.success() => return Ok(()),
                Ok(output) => failures.push(process_failure("Ghostscript", &output)),
                Err(error) => failures.push(execution_failure("Ghostscript", &error)),
            }
            remove_partial_output(output_path);
        }

        if let Some(command) = &self.qpdf_command {
            let arguments = [
                OsString::from("--replace-input"),
                OsString::from("--qdf"),
                OsString::from("--object-streams=disable"),
                input_path.as_os_str().to_owned(),
                output_path.as_os_str().to_owned(),
            ];
            match self.qpdf.run(command, &arguments) {
                Ok(output) if matches!(output.status.code(), Some(0 | 3)) => return Ok(()),
                Ok(output) => failures.push(process_failure("qpdf", &output)),
                Err(error) => failures.push(execution_failure("qpdf", &error)),
            }
            remove_partial_output(output_path);
        }

        Err(RepairError::ExternalTools {
            details: failures.join("; "),
        })
    }
}

fn remove_partial_output(output_path: &Path) {
    let _ = fs::remove_file(output_path);
}

fn process_failure(tool: &str, output: &Output) -> String {
    format!(
        "{tool} exited with {} ({})",
        output
            .status
            .code()
            .map_or_else(|| "no exit code".to_owned(), |code| code.to_string()),
        process_details(&output.stdout, &output.stderr)
    )
}

fn execution_failure(tool: &str, error: &ProcessExecutorError) -> String {
    format!("{tool} {error}")
}

fn process_details(stdout: &[u8], stderr: &[u8]) -> String {
    let bytes = if stderr.is_empty() { stdout } else { stderr };
    let details = String::from_utf8_lossy(bytes);
    let mut characters = details.trim().chars();
    let result = characters.by_ref().take(2_048).collect::<String>();
    if characters.next().is_some() {
        format!("{result}…")
    } else if result.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use std::{fs, time::Duration};

    use lopdf::{Document, Object, dictionary};
    use tempfile::tempdir;

    use super::{RepairError, RepairRuntime};
    use crate::runtime_config::RepairProcessSettings;

    fn settings() -> RepairProcessSettings {
        RepairProcessSettings {
            qpdf_session_limit: 2,
            qpdf_timeout: Duration::from_secs(5),
            ghostscript_session_limit: 8,
            ghostscript_timeout: Duration::from_secs(5),
        }
    }

    #[cfg(unix)]
    fn executable(path: &std::path::Path, script: &str) -> std::io::Result<()> {
        use std::os::unix::fs::PermissionsExt;

        fs::write(path, script)?;
        let mut permissions = fs::metadata(path)?.permissions();
        permissions.set_mode(0o700);
        fs::set_permissions(path, permissions)
    }

    #[cfg(unix)]
    #[test]
    fn uses_ghostscript_first_with_java_arguments() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let command = directory.path().join("gs");
        let arguments = directory.path().join("arguments");
        executable(
            &command,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncp \"$4\" \"$2\"\n",
                arguments.display()
            ),
        )?;
        let qpdf_marker = directory.path().join("qpdf-ran");
        let qpdf = directory.path().join("qpdf");
        executable(
            &qpdf,
            &format!("#!/bin/sh\ntouch '{}'\nexit 1\n", qpdf_marker.display()),
        )?;
        let input = directory.path().join("input.pdf");
        let output = directory.path().join("output.pdf");
        fs::write(&input, b"external repair fixture")?;

        RepairRuntime::new(Some(command), Some(qpdf), settings()).repair(
            &input,
            "input.pdf",
            &output,
        )?;

        assert_eq!(fs::read(&output)?, b"external repair fixture");
        assert!(!qpdf_marker.exists());
        assert_eq!(
            fs::read_to_string(arguments)?.lines().collect::<Vec<_>>(),
            vec![
                "-o",
                output.to_str().ok_or("non-UTF-8 output path")?,
                "-sDEVICE=pdfwrite",
                input.to_str().ok_or("non-UTF-8 input path")?,
            ]
        );
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn falls_back_to_qpdf_and_accepts_warning_exit_code() -> Result<(), Box<dyn std::error::Error>>
    {
        let directory = tempdir()?;
        let ghostscript = directory.path().join("gs");
        executable(&ghostscript, "#!/bin/sh\necho broken >&2\nexit 1\n")?;
        let qpdf = directory.path().join("qpdf");
        let arguments = directory.path().join("arguments");
        executable(
            &qpdf,
            &format!(
                "#!/bin/sh\nprintf '%s\\n' \"$@\" > '{}'\ncp \"$4\" \"$5\"\nexit 3\n",
                arguments.display()
            ),
        )?;
        let input = directory.path().join("input.pdf");
        let output = directory.path().join("output.pdf");
        fs::write(&input, b"qpdf repair fixture")?;

        RepairRuntime::new(Some(ghostscript), Some(qpdf), settings()).repair(
            &input,
            "input.pdf",
            &output,
        )?;

        assert_eq!(fs::read(&output)?, b"qpdf repair fixture");
        assert_eq!(
            fs::read_to_string(arguments)?.lines().collect::<Vec<_>>(),
            vec![
                "--replace-input",
                "--qdf",
                "--object-streams=disable",
                input.to_str().ok_or("non-UTF-8 input path")?,
                output.to_str().ok_or("non-UTF-8 output path")?,
            ]
        );
        Ok(())
    }

    #[test]
    fn rewrites_in_process_when_no_external_tool_was_discovered()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let input = directory.path().join("input.pdf");
        let output = directory.path().join("output.pdf");
        let mut document = Document::with_version("1.7");
        let pages_root_id = document.new_object_id();
        let page_object_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_root_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
        });
        document.objects.insert(
            pages_root_id,
            Object::Dictionary(dictionary! {
                "Type" => "Pages",
                "Kids" => vec![page_object_id.into()],
                "Count" => 1,
            }),
        );
        let catalog_id = document.add_object(dictionary! {
            "Type" => "Catalog",
            "Pages" => pages_root_id,
        });
        document.trailer.set("Root", catalog_id);
        document.save(&input)?;

        RepairRuntime::new(None, None, settings()).repair(&input, "input.pdf", &output)?;

        assert_eq!(Document::load(&output)?.get_pages().len(), 1);
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn fails_when_a_discovered_external_tool_cannot_repair()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let ghostscript = directory.path().join("gs");
        executable(&ghostscript, "#!/bin/sh\necho malformed >&2\nexit 1\n")?;
        let input = directory.path().join("input.pdf");
        let output = directory.path().join("output.pdf");
        fs::write(&input, b"broken")?;

        let error = match RepairRuntime::new(Some(ghostscript), None, settings()).repair(
            &input,
            "input.pdf",
            &output,
        ) {
            Ok(()) => return Err("Ghostscript failure must not fall through to lopdf".into()),
            Err(error) => error,
        };

        assert!(matches!(error, RepairError::ExternalTools { .. }));
        assert!(error.to_string().contains("Ghostscript exited with 1"));
        assert!(!output.exists());
        Ok(())
    }
}
