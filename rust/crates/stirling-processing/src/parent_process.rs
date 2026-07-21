use std::{env, io, time::Duration};

use sysinfo::{Pid, ProcessRefreshKind, ProcessesToUpdate, System};

const PARENT_PROCESS_ID_VARIABLE: &str = "TAURI_PARENT_PID";
const PARENT_PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(250);

pub(crate) struct ParentProcessWatcher {
    pid: Pid,
    start_time: u64,
}

impl ParentProcessWatcher {
    pub(crate) fn from_environment() -> Result<Option<Self>, io::Error> {
        let value = match env::var(PARENT_PROCESS_ID_VARIABLE) {
            Ok(value) => value,
            Err(env::VarError::NotPresent) => return Ok(None),
            Err(env::VarError::NotUnicode(_)) => {
                return Err(invalid_parent_process_id("the value is not valid Unicode"));
            }
        };
        let pid = parse_parent_process_id(&value, std::process::id())?;
        Self::for_pid(pid).map(Some)
    }

    fn for_pid(pid: u32) -> Result<Self, io::Error> {
        let pid = Pid::from_u32(pid);
        let start_time = observed_start_time(pid).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::NotFound,
                format!("{PARENT_PROCESS_ID_VARIABLE} process {pid} does not exist"),
            )
        })?;
        Ok(Self { pid, start_time })
    }

    pub(crate) async fn wait_until_exit(self) {
        let mut interval = tokio::time::interval(PARENT_PROCESS_POLL_INTERVAL);
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            interval.tick().await;
            if observed_start_time(self.pid) != Some(self.start_time) {
                return;
            }
        }
    }
}

fn observed_start_time(pid: Pid) -> Option<u64> {
    let mut system = System::new();
    system.refresh_processes_specifics(
        ProcessesToUpdate::Some(&[pid]),
        true,
        ProcessRefreshKind::nothing(),
    );
    system.process(pid).map(sysinfo::Process::start_time)
}

fn parse_parent_process_id(value: &str, current_process_id: u32) -> Result<u32, io::Error> {
    let pid = value.parse::<u32>().map_err(|error| {
        invalid_parent_process_id(format!("it must be a positive process ID: {error}"))
    })?;
    if pid == 0 {
        return Err(invalid_parent_process_id(
            "it must be a positive process ID",
        ));
    }
    if pid == current_process_id {
        return Err(invalid_parent_process_id(
            "it cannot identify the Stirling processing process itself",
        ));
    }
    Ok(pid)
}

fn invalid_parent_process_id(message: impl std::fmt::Display) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{PARENT_PROCESS_ID_VARIABLE} is invalid: {message}"),
    )
}

#[cfg(test)]
mod tests {
    use super::{ParentProcessWatcher, observed_start_time, parse_parent_process_id};
    use std::io;
    use sysinfo::Pid;

    #[test]
    fn rejects_malformed_and_zero_parent_process_ids() {
        for value in ["", "not-a-pid", "-1", "0"] {
            let error = parse_parent_process_id(value, 42)
                .err()
                .unwrap_or_else(|| panic!("{value:?} unexpectedly parsed as a parent PID"));
            assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        }
    }

    #[test]
    fn rejects_the_current_process_id() {
        let current_process_id = std::process::id();
        let error = parse_parent_process_id(&current_process_id.to_string(), current_process_id)
            .err()
            .unwrap_or_else(|| panic!("the current process unexpectedly parsed as its parent"));
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error.to_string().contains("itself"));
    }

    #[test]
    fn rejects_a_parent_process_that_does_not_exist() {
        let nonexistent_process_id = (1_000_000_000..2_000_000_000)
            .find(|candidate| observed_start_time(Pid::from_u32(*candidate)).is_none())
            .unwrap_or_else(|| panic!("could not find a nonexistent test process ID"));
        let result = ParentProcessWatcher::for_pid(nonexistent_process_id);
        let Err(error) = result else {
            panic!("a nonexistent parent process was accepted");
        };
        assert_eq!(error.kind(), io::ErrorKind::NotFound);
        assert!(error.to_string().contains("does not exist"));
    }
}
