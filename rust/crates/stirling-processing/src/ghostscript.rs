use std::{env, process::ExitStatus};

const GHOSTSCRIPT_COMMAND_ENV: &str = "STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND";

pub(crate) struct GhostscriptCommands {
    pub(crate) candidates: Vec<String>,
    pub(crate) explicitly_configured: bool,
}

pub(crate) fn ghostscript_commands() -> GhostscriptCommands {
    if let Ok(command) = env::var(GHOSTSCRIPT_COMMAND_ENV)
        && !command.trim().is_empty()
    {
        return GhostscriptCommands {
            candidates: vec![command],
            explicitly_configured: true,
        };
    }
    let candidates = if cfg!(windows) {
        vec![
            "gswin64c".to_owned(),
            "gswin32c".to_owned(),
            "gs".to_owned(),
        ]
    } else {
        vec!["gs".to_owned()]
    };
    GhostscriptCommands {
        candidates,
        explicitly_configured: false,
    }
}

pub(crate) fn exit_status(status: ExitStatus) -> String {
    status.code().map_or_else(
        || "terminated by signal".to_owned(),
        |code| code.to_string(),
    )
}
