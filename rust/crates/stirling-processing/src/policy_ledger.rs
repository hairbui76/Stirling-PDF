//! Durable per-policy source-file claim lifecycle.

use std::{collections::HashMap, sync::Arc};

use sha2::{Digest as _, Sha256};

use crate::security::{SecurityError, SecurityStore};

pub(crate) const MAX_ATTEMPTS: i64 = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ProcessedFileStatus {
    Processing,
    Done,
    Error,
    Interrupted,
}

impl ProcessedFileStatus {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Processing => "PROCESSING",
            Self::Done => "DONE",
            Self::Error => "ERROR",
            Self::Interrupted => "INTERRUPTED",
        }
    }

    pub(crate) fn parse(value: &str) -> Result<Self, SecurityError> {
        match value {
            "PROCESSING" => Ok(Self::Processing),
            "DONE" => Ok(Self::Done),
            "ERROR" => Ok(Self::Error),
            "INTERRUPTED" => Ok(Self::Interrupted),
            _ => Err(SecurityError::Conflict),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct ClaimState {
    pub(crate) status: ProcessedFileStatus,
    pub(crate) gate: String,
    pub(crate) content_hash: Option<String>,
}

#[derive(Clone)]
pub(crate) struct ProcessedLedger {
    store: Arc<SecurityStore>,
}

impl ProcessedLedger {
    pub(crate) fn new(store: Arc<SecurityStore>) -> Self {
        Self { store }
    }

    pub(crate) fn states_for(
        &self,
        policy_id: &str,
        identities: &[String],
    ) -> Result<HashMap<String, ClaimState>, SecurityError> {
        self.store.policy_processed_states(policy_id, identities)
    }

    pub(crate) fn claim(
        &self,
        policy_id: &str,
        identity: &str,
        gate: &str,
        content_hash: Option<&str>,
        observed: Option<&ClaimState>,
        now_millis: i64,
    ) -> Result<bool, SecurityError> {
        self.store.claim_policy_processed_file(
            policy_id,
            identity,
            gate,
            content_hash,
            observed,
            now_millis,
        )
    }

    pub(crate) fn settle(
        &self,
        policy_id: &str,
        identity: &str,
        gate: &str,
        content_hash: Option<&str>,
        success: bool,
        now_millis: i64,
    ) -> Result<(), SecurityError> {
        self.store.settle_policy_processed_file(
            policy_id,
            identity,
            gate,
            content_hash,
            if success {
                ProcessedFileStatus::Done
            } else {
                ProcessedFileStatus::Error
            },
            now_millis,
        )
    }

    pub(crate) fn record_output(
        &self,
        policy_id: &str,
        identity: &str,
        gate: &str,
        content_hash: Option<&str>,
        now_millis: i64,
    ) -> Result<(), SecurityError> {
        self.store.settle_policy_processed_file(
            policy_id,
            identity,
            gate,
            content_hash,
            ProcessedFileStatus::Done,
            now_millis,
        )
    }

    pub(crate) fn forget_output(
        &self,
        policy_id: &str,
        identity: &str,
        gate: &str,
    ) -> Result<(), SecurityError> {
        self.store
            .forget_policy_processed_output(policy_id, identity, gate)
    }

    pub(crate) fn all_settled_done(&self, identity: &str) -> Result<bool, SecurityError> {
        self.store.all_policy_processed_done(identity)
    }

    pub(crate) fn mark_seen(
        &self,
        policy_id: &str,
        identities: &[String],
        now_millis: i64,
    ) -> Result<(), SecurityError> {
        self.store
            .mark_policy_processed_seen(policy_id, identities, now_millis)
    }

    pub(crate) fn delete_unseen(
        &self,
        policy_id: &str,
        seen_since_millis: i64,
    ) -> Result<usize, SecurityError> {
        self.store
            .delete_unseen_policy_processed(policy_id, seen_since_millis)
    }

    pub(crate) fn clear_policy(&self, policy_id: &str) -> Result<(), SecurityError> {
        self.store.clear_policy_processed_history(policy_id)
    }

    pub(crate) fn recover_interrupted(&self, now_millis: i64) -> Result<usize, SecurityError> {
        self.store.recover_interrupted_policy_files(now_millis)
    }
}

pub(crate) fn identity_hash(identity: &str) -> String {
    let digest = Sha256::digest(identity.as_bytes());
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        let _ = write!(output, "{byte:02x}");
    }
    output
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use tempfile::{TempDir, tempdir};

    use super::{ProcessedFileStatus, ProcessedLedger};
    use crate::security::SecurityStore;

    fn ledger() -> Result<(TempDir, ProcessedLedger), Box<dyn std::error::Error>> {
        let directory = tempdir()?;
        let store = Arc::new(SecurityStore::open(&directory.path().join("security.db"))?);
        Ok((directory, ProcessedLedger::new(store)))
    }

    fn state(
        ledger: &ProcessedLedger,
        policy_id: &str,
        identity: &str,
    ) -> Result<super::ClaimState, Box<dyn std::error::Error>> {
        ledger
            .states_for(policy_id, &[identity.to_owned()])?
            .remove(identity)
            .ok_or_else(|| "claim state missing".into())
    }

    #[test]
    fn claims_refreshes_gates_and_reclaims_changed_content()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, ledger) = ledger()?;
        let identity = "folder:/in/document.pdf";
        assert!(ledger.claim("policy-a", identity, "10:1", Some("aaa"), None, 1)?);
        assert!(!ledger.claim("policy-a", identity, "10:1", Some("aaa"), None, 2)?);
        let processing = state(&ledger, "policy-a", identity)?;
        assert_eq!(processing.status, ProcessedFileStatus::Processing);
        ledger.settle("policy-a", identity, "10:1", Some("aaa"), true, 3)?;

        let done = state(&ledger, "policy-a", identity)?;
        assert!(!ledger.claim("policy-a", identity, "10:2", Some("aaa"), Some(&done), 4,)?);
        assert_eq!(state(&ledger, "policy-a", identity)?.gate, "10:2");
        let refreshed = state(&ledger, "policy-a", identity)?;
        assert!(ledger.claim(
            "policy-a",
            identity,
            "11:3",
            Some("bbb"),
            Some(&refreshed),
            5,
        )?);
        Ok(())
    }

    #[test]
    fn restart_recovery_retries_interrupted_claims_only_three_times()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, ledger) = ledger()?;
        let identity = "s3:bucket:key:version";
        assert!(ledger.claim("policy-a", identity, "v1", None, None, 1)?);
        for attempt in 2..=3 {
            assert_eq!(ledger.recover_interrupted(attempt)?, 1);
            let interrupted = state(&ledger, "policy-a", identity)?;
            assert_eq!(interrupted.status, ProcessedFileStatus::Interrupted);
            assert!(ledger.claim(
                "policy-a",
                identity,
                "v1",
                None,
                Some(&interrupted),
                attempt,
            )?);
        }
        assert_eq!(ledger.recover_interrupted(4)?, 1);
        let interrupted = state(&ledger, "policy-a", identity)?;
        assert!(!ledger.claim("policy-a", identity, "v1", None, Some(&interrupted), 4,)?);
        Ok(())
    }

    #[test]
    fn output_consensus_presence_cleanup_and_clear_match_java_semantics()
    -> Result<(), Box<dyn std::error::Error>> {
        let (_directory, ledger) = ledger()?;
        let identity = "folder:/out/result.pdf";
        ledger.record_output("policy-a", identity, "g1", Some("hash"), 10)?;
        assert!(ledger.all_settled_done(identity)?);
        ledger.settle("policy-b", identity, "g1", Some("hash"), false, 11)?;
        assert!(!ledger.all_settled_done(identity)?);
        ledger.forget_output("policy-a", identity, "wrong")?;
        assert!(
            ledger
                .states_for("policy-a", &[identity.to_owned()])?
                .contains_key(identity)
        );
        ledger.forget_output("policy-a", identity, "g1")?;
        assert!(
            !ledger
                .states_for("policy-a", &[identity.to_owned()])?
                .contains_key(identity)
        );

        ledger.mark_seen("policy-b", &[identity.to_owned()], 20)?;
        assert_eq!(ledger.delete_unseen("policy-b", 20)?, 0);
        assert_eq!(ledger.delete_unseen("policy-b", 21)?, 1);
        ledger.record_output("policy-b", identity, "g2", None, 22)?;
        ledger.clear_policy("policy-b")?;
        assert!(
            ledger
                .states_for("policy-b", &[identity.to_owned()])?
                .is_empty()
        );
        Ok(())
    }
}
