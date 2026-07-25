//! Bounded external-command execution with Java-compatible timeout cleanup.

use std::{
    ffi::{OsStr, OsString},
    io::{self, Read},
    process::{Child, Command, Output, Stdio},
    sync::{Arc, Condvar, Mutex, MutexGuard},
    thread,
    time::{Duration, Instant},
};

use sysinfo::{Pid, ProcessesToUpdate, System};
use thiserror::Error;

const PROCESS_POLL_INTERVAL: Duration = Duration::from_millis(10);

#[derive(Clone, Debug)]
pub(crate) struct ProcessExecutor {
    slots: Arc<ProcessSlots>,
    timeout: Duration,
}

#[derive(Debug)]
struct ProcessSlots {
    active: Mutex<usize>,
    released: Condvar,
    limit: usize,
}

struct ProcessPermit<'a> {
    slots: &'a ProcessSlots,
}

#[derive(Debug, Error)]
pub(crate) enum ProcessExecutorError {
    #[error("could not start the process: {0}")]
    Start(#[source] io::Error),
    #[error("process timed out after {timeout:?}")]
    Timeout { timeout: Duration },
    #[error("could not collect process output: {0}")]
    Output(#[source] io::Error),
}

impl ProcessExecutor {
    pub(crate) fn new(limit: usize, timeout: Duration) -> Self {
        Self {
            slots: Arc::new(ProcessSlots {
                active: Mutex::new(0),
                released: Condvar::new(),
                limit: limit.max(1),
            }),
            timeout: timeout.max(Duration::from_millis(1)),
        }
    }

    pub(crate) fn run(
        &self,
        command: impl AsRef<OsStr>,
        arguments: &[OsString],
    ) -> Result<Output, ProcessExecutorError> {
        let _permit = self.slots.acquire();
        let mut child = Command::new(command)
            .args(arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(ProcessExecutorError::Start)?;
        let stdout = child
            .stdout
            .take()
            .ok_or_else(|| output_error("the process stdout pipe was not available"))?;
        let stderr = child
            .stderr
            .take()
            .ok_or_else(|| output_error("the process stderr pipe was not available"))?;
        let stdout_reader = read_output(stdout);
        let stderr_reader = read_output(stderr);

        let deadline = Instant::now() + self.timeout;
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) if Instant::now() >= deadline => {
                    terminate_process_tree(&mut child);
                    let _ = child.wait();
                    let _ = join_output(stdout_reader);
                    let _ = join_output(stderr_reader);
                    return Err(ProcessExecutorError::Timeout {
                        timeout: self.timeout,
                    });
                }
                Ok(None) => thread::sleep(
                    deadline
                        .saturating_duration_since(Instant::now())
                        .min(PROCESS_POLL_INTERVAL),
                ),
                Err(source) => {
                    terminate_process_tree(&mut child);
                    let _ = child.wait();
                    let _ = join_output(stdout_reader);
                    let _ = join_output(stderr_reader);
                    return Err(ProcessExecutorError::Output(source));
                }
            }
        };

        Ok(Output {
            status,
            stdout: join_output(stdout_reader)?,
            stderr: join_output(stderr_reader)?,
        })
    }
}

impl ProcessSlots {
    fn acquire(&self) -> ProcessPermit<'_> {
        let mut active = lock_unpoisoned(&self.active);
        while *active >= self.limit {
            active = self
                .released
                .wait(active)
                .unwrap_or_else(std::sync::PoisonError::into_inner);
        }
        *active += 1;
        ProcessPermit { slots: self }
    }
}

impl Drop for ProcessPermit<'_> {
    fn drop(&mut self) {
        let mut active = lock_unpoisoned(&self.slots.active);
        *active = active.saturating_sub(1);
        self.slots.released.notify_one();
    }
}

fn lock_unpoisoned<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn read_output(mut stream: impl Read + Send + 'static) -> thread::JoinHandle<io::Result<Vec<u8>>> {
    thread::spawn(move || {
        let mut bytes = Vec::new();
        stream.read_to_end(&mut bytes)?;
        Ok(bytes)
    })
}

fn join_output(
    reader: thread::JoinHandle<io::Result<Vec<u8>>>,
) -> Result<Vec<u8>, ProcessExecutorError> {
    reader
        .join()
        .map_err(|_| output_error("a process output reader panicked"))?
        .map_err(ProcessExecutorError::Output)
}

fn output_error(message: &'static str) -> ProcessExecutorError {
    ProcessExecutorError::Output(io::Error::other(message))
}

fn terminate_process_tree(child: &mut Child) {
    let root = Pid::from_u32(child.id());
    let mut system = System::new_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    let mut descendants = Vec::new();
    let mut parents = vec![root];
    while let Some(parent) = parents.pop() {
        for (pid, process) in system.processes() {
            if process.parent() == Some(parent) && !descendants.contains(pid) {
                descendants.push(*pid);
                parents.push(*pid);
            }
        }
    }
    for pid in descendants.into_iter().rev() {
        if let Some(process) = system.process(pid) {
            let _ = process.kill();
        }
    }
    let _ = child.kill();
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::{fs, sync::Arc, thread, time::Duration};

    #[cfg(unix)]
    use tempfile::tempdir;

    #[cfg(unix)]
    use super::{ProcessExecutor, ProcessExecutorError};

    #[cfg(unix)]
    #[test]
    fn session_limit_serializes_commands() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let lock = directory.path().join("active");
        let overlap = directory.path().join("overlap");
        let executor = Arc::new(ProcessExecutor::new(1, Duration::from_secs(5)));
        let script = "if ! mkdir \"$1\"; then touch \"$2\"; fi; sleep 0.15; rmdir \"$1\"";
        let mut threads = Vec::new();
        for _ in 0..2 {
            let executor = Arc::clone(&executor);
            let arguments = [
                "-c".into(),
                script.into(),
                "stirling-process-test".into(),
                lock.as_os_str().to_owned(),
                overlap.as_os_str().to_owned(),
            ];
            threads.push(thread::spawn(move || executor.run("sh", &arguments)));
        }
        for worker in threads {
            let output = worker.join().map_err(|_| "worker panicked")??;
            assert!(output.status.success());
        }
        assert!(!overlap.exists());
        Ok(())
    }

    #[cfg(unix)]
    #[test]
    fn timeout_kills_the_process_and_its_descendants() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let child_pid_path = directory.path().join("child.pid");
        let arguments = [
            "-c".into(),
            "sleep 30 & echo $! > \"$1\"; wait".into(),
            "stirling-process-test".into(),
            child_pid_path.as_os_str().to_owned(),
        ];
        let executor = ProcessExecutor::new(1, Duration::from_millis(150));
        assert!(matches!(
            executor.run("sh", &arguments),
            Err(ProcessExecutorError::Timeout { .. })
        ));

        let child_pid = fs::read_to_string(child_pid_path)?.trim().parse::<u32>()?;
        let deadline = std::time::Instant::now() + Duration::from_secs(2);
        loop {
            let mut system = sysinfo::System::new_all();
            system.refresh_processes(sysinfo::ProcessesToUpdate::All, true);
            if system.process(sysinfo::Pid::from_u32(child_pid)).is_none() {
                break;
            }
            assert!(
                std::time::Instant::now() < deadline,
                "child process survived timeout"
            );
            thread::sleep(Duration::from_millis(20));
        }
        Ok(())
    }
}
