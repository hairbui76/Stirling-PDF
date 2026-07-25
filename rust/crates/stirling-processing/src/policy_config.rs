//! Durable policy/source definitions and their reviewed secured-mode rules.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Component, Path, PathBuf},
    sync::{Arc, OnceLock},
};

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use rand::RngExt as _;
use regex::Regex;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    integration_config::{
        IntegrationConfigService, IntegrationFailure, IntegrationType, mask_config, merge_config,
    },
    policy_ledger::ProcessedLedger,
    security::{AuthContext, SecurityError, SecurityStore},
    storage::StorageConfig,
};

const EDITOR_ID: &str = "editor";
const EDITOR_TYPE: &str = "editor";
const WEBHOOK_TYPE: &str = "webhook";
const MAX_POLICY_JSON_BYTES: usize = 1024 * 1024;

/// The step parameter naming the integration connection to dereference, matching
/// Java `IntegrationStepValidator.CONNECTION_ID_PARAM` /
/// `ApiConnectionResolver.connectionId`.
const CONNECTION_ID_PARAM: &str = "connectionId";

/// Operations under this prefix are integration steps whose `connectionId` is
/// authorization-checked at save time, matching Java
/// `IntegrationStepValidator.INTEGRATION_PREFIX`.
const INTEGRATION_PREFIX: &str = "/api/v1/integration/";

/// Which connection type each integration step dereferences, mirroring Java
/// `IntegrationStepValidator.STEP_CONNECTION_TYPES`. Covers the ported subset:
/// `external-api-call` (`API`, slice 4) and the two Purview label steps. Java also
/// maps `consigno-*` (`CONSIGNO`), which has no dedicated port — it is reached via
/// the generic `external-api-call` step's `bodyTemplate`, so its bespoke endpoints
/// stay absent here on purpose. A step under [`INTEGRATION_PREFIX`] that is absent
/// here is rejected rather than waved through, so a new endpoint cannot silently
/// skip the confused-deputy check by forgetting to register (fail-closed).
const INTEGRATION_STEP_TYPES: &[(&str, IntegrationType)] = &[
    (
        "/api/v1/integration/external-api-call",
        IntegrationType::Api,
    ),
    (
        "/api/v1/integration/purview-apply-label",
        IntegrationType::Purview,
    ),
    (
        "/api/v1/integration/purview-read-label",
        IntegrationType::Purview,
    ),
];

/// Reason key for an implied root backed by the local server file-storage
/// directory. Surfaced verbatim to the admin UI so it can label each root,
/// matching Java's `FolderAccessGuard.IMPLIED_SERVER_STORAGE`.
const IMPLIED_SERVER_STORAGE: &str = "serverStorage";

/// Reason key for an implied root backed by a pipeline watched folder,
/// matching Java's `FolderAccessGuard.IMPLIED_WATCHED_FOLDER`.
const IMPLIED_WATCHED_FOLDER: &str = "watchedFolder";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicySource {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(rename = "type", default)]
    pub(crate) source_type: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) options: Map<String, Value>,
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) owner: Option<String>,
    #[serde(default)]
    pub(crate) team_id: Option<i64>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TriggerConfig {
    #[serde(rename = "type", default)]
    pub(crate) trigger_type: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) options: Map<String, Value>,
}

#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyStep {
    #[serde(default)]
    pub(crate) operation: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) parameters: Map<String, Value>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) file_parameters: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct OutputSpec {
    #[serde(rename = "type", default = "inline_output_type")]
    pub(crate) output_type: String,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) options: Map<String, Value>,
}

impl Default for OutputSpec {
    fn default() -> Self {
        Self {
            output_type: inline_output_type(),
            options: Map::new(),
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct PolicyDefinition {
    #[serde(default)]
    pub(crate) id: String,
    #[serde(default)]
    pub(crate) name: String,
    #[serde(default)]
    pub(crate) owner: Option<String>,
    #[serde(default)]
    pub(crate) enabled: bool,
    #[serde(default)]
    pub(crate) trigger: Option<TriggerConfig>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) source_ids: Vec<String>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) steps: Vec<PolicyStep>,
    #[serde(default, deserialize_with = "deserialize_default_on_null")]
    pub(crate) output: OutputSpec,
    #[serde(default)]
    pub(crate) team_id: Option<i64>,
}

#[derive(Debug, Serialize)]
pub(crate) struct SourcesResponse {
    kpis: Vec<SourceKpi>,
    sources: Vec<SourceView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PoliciesOverviewResponse {
    kpis: Vec<PolicyKpi>,
    pipelines: Vec<PolicyView>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyKpi {
    value: usize,
    description: &'static str,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicyView {
    id: String,
    name: String,
    enabled: bool,
    status: &'static str,
    trigger: String,
    sources: Vec<PolicySourceRef>,
    steps: Vec<String>,
    output: String,
    owner: Option<String>,
}

#[derive(Debug, Serialize)]
pub(crate) struct PolicySourceRef {
    id: String,
    name: String,
}

#[derive(Clone, Copy, Debug, Default)]
pub(crate) struct SourceDocStats {
    pub(crate) total: u64,
    pub(crate) last_24h: u64,
    pub(crate) last_30d: u64,
}

#[derive(Debug, Serialize)]
pub(crate) struct SourceKpi {
    value: usize,
    description: &'static str,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct SourceView {
    id: String,
    name: String,
    #[serde(rename = "type")]
    source_type: String,
    status: &'static str,
    reference_count: usize,
    referencing_policies: Vec<PolicyRef>,
    config: Vec<DetailRow>,
    docs_total: u64,
    docs24h: u64,
    docs30d: u64,
}

#[derive(Debug, Serialize)]
struct PolicyRef {
    id: String,
    name: String,
}

#[derive(Debug, Serialize)]
struct DetailRow {
    label: String,
    value: String,
}

/// A Stirling-owned directory that is always permitted for folder automations
/// regardless of `policies.allowedFolderRoots`, plus the reason key the admin UI
/// uses to label it. Mirrors Java's `FolderAccessGuard.ImpliedRoot`.
#[derive(Clone, Debug)]
pub(crate) struct ImpliedFolderRoot {
    pub(crate) path: PathBuf,
    pub(crate) reason: &'static str,
}

/// Read-only projection of an [`ImpliedFolderRoot`] for the admin endpoint,
/// mirroring Java's `FolderAccessSettingsController.ImpliedFolderRoot` record
/// (`{path, reason}` with the absolute path rendered as a string).
#[derive(Debug, Serialize)]
pub(crate) struct ImpliedFolderRootView {
    path: String,
    reason: &'static str,
}

#[derive(Debug, Error)]
pub(crate) enum PolicyFailure {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("policy persistence failed")]
    Storage(#[from] SecurityError),
}

#[derive(Clone)]
pub(crate) struct PolicyConfigService {
    store: Arc<SecurityStore>,
    integrations: Arc<IntegrationConfigService>,
    allowed_folder_roots: Arc<Vec<PathBuf>>,
    protected_config_root: PathBuf,
    implied_folder_roots: Arc<Vec<ImpliedFolderRoot>>,
}

impl PolicyConfigService {
    pub(crate) fn new(
        store: Arc<SecurityStore>,
        integrations: Arc<IntegrationConfigService>,
        allowed_folder_roots: Vec<PathBuf>,
        protected_config_root: &Path,
        implied_folder_roots: Vec<ImpliedFolderRoot>,
    ) -> Self {
        Self {
            store,
            integrations,
            allowed_folder_roots: Arc::new(
                allowed_folder_roots
                    .into_iter()
                    .map(|path| normalize_path(&path))
                    .collect(),
            ),
            protected_config_root: normalize_path(protected_config_root),
            implied_folder_roots: Arc::new(implied_folder_roots),
        }
    }

    /// Admin-only read of the Stirling-owned directories always permitted for
    /// folder automations, with a reason key for each. Mirrors Java's
    /// `FolderAccessSettingsController.impliedFolderRoots` (`@PreAuthorize
    /// hasRole('ADMIN')`), which is read-only and never editable here.
    pub(crate) fn list_implied_folder_roots(
        &self,
        context: &AuthContext,
    ) -> Result<Vec<ImpliedFolderRootView>, PolicyFailure> {
        if !context.has_role("ROLE_ADMIN") {
            return Err(PolicyFailure::Forbidden(
                "Administrator role required".to_owned(),
            ));
        }
        Ok(self
            .implied_folder_roots
            .iter()
            .map(|root| ImpliedFolderRootView {
                path: root.path.display().to_string(),
                reason: root.reason,
            })
            .collect())
    }

    pub(crate) fn source_overview(
        &self,
        context: &AuthContext,
    ) -> Result<SourcesResponse, PolicyFailure> {
        let sources = self.visible_sources(context)?;
        let policies = self.visible_policies(context)?;
        let editor_key = editor_counter_key(context.team_id);
        let mut stat_ids = sources
            .iter()
            .map(|source| source.id.clone())
            .collect::<Vec<_>>();
        stat_ids.push(editor_key.clone());
        let doc_stats = self.store.policy_source_doc_stats(&stat_ids)?;
        let mut policies_by_source: HashMap<&str, Vec<&PolicyDefinition>> = HashMap::new();
        for policy in &policies {
            for source_id in &policy.source_ids {
                policies_by_source
                    .entry(source_id)
                    .or_default()
                    .push(policy);
            }
        }
        let mut views = Vec::with_capacity(sources.len() + 1);
        let editor_refs = policies
            .iter()
            .filter(|policy| output_references_editor(&policy.output))
            .map(policy_ref)
            .collect::<Vec<_>>();
        let editor_docs = doc_stats.get(&editor_key).copied().unwrap_or_default();
        views.push(SourceView {
            id: EDITOR_ID.to_owned(),
            name: "Editor".to_owned(),
            source_type: EDITOR_TYPE.to_owned(),
            status: "active",
            reference_count: editor_refs.len(),
            referencing_policies: editor_refs,
            config: Vec::new(),
            docs_total: editor_docs.total,
            docs24h: editor_docs.last_24h,
            docs30d: editor_docs.last_30d,
        });

        let mut persisted = sources
            .iter()
            .map(|source| {
                let source_policies = policies_by_source
                    .get(source.id.as_str())
                    .cloned()
                    .unwrap_or_default();
                let reference_count = source_policies.len();
                let source_docs = doc_stats.get(&source.id).copied().unwrap_or_default();
                SourceView {
                    id: source.id.clone(),
                    name: source.name.clone(),
                    source_type: source.source_type.clone(),
                    status: if !source.enabled {
                        "disabled"
                    } else if reference_count == 0 {
                        "unused"
                    } else {
                        "active"
                    },
                    reference_count,
                    referencing_policies: source_policies.into_iter().map(policy_ref).collect(),
                    config: source_config_rows(source),
                    docs_total: source_docs.total,
                    docs24h: source_docs.last_24h,
                    docs30d: source_docs.last_30d,
                }
            })
            .collect::<Vec<_>>();
        persisted.sort_by(|left, right| {
            right
                .reference_count
                .cmp(&left.reference_count)
                .then_with(|| left.name.cmp(&right.name))
        });
        let total = persisted.len();
        let in_use = persisted
            .iter()
            .filter(|source| source.reference_count > 0)
            .count();
        views.extend(persisted);
        Ok(SourcesResponse {
            kpis: vec![
                SourceKpi {
                    value: total,
                    description: "connections",
                },
                SourceKpi {
                    value: in_use,
                    description: "referenced by a policy",
                },
                SourceKpi {
                    value: total - in_use,
                    description: "unused",
                },
            ],
            sources: views,
        })
    }

    pub(crate) fn document_counts(
        &self,
        id: &str,
        context: &AuthContext,
    ) -> Result<Vec<u64>, PolicyFailure> {
        let counter_key = if id == EDITOR_ID {
            editor_counter_key(context.team_id)
        } else {
            self.store
                .get_policy_source(id)?
                .filter(|source| Self::can_access_team(source.team_id, context))
                .ok_or_else(|| PolicyFailure::NotFound(format!("No source: {id}")))?;
            id.to_owned()
        };
        self.store
            .policy_source_daily_series(&counter_key)
            .map_err(Into::into)
    }

    pub(crate) fn get_source(
        &self,
        id: &str,
        context: &AuthContext,
    ) -> Result<PolicySource, PolicyFailure> {
        let source = self
            .store
            .get_policy_source(id)?
            .filter(|source| Self::can_access_team(source.team_id, context))
            .ok_or_else(|| PolicyFailure::NotFound(format!("No source: {id}")))?;
        Ok(mask_source(source))
    }

    pub(crate) fn save_source(
        &self,
        mut incoming: PolicySource,
        context: &AuthContext,
    ) -> Result<PolicySource, PolicyFailure> {
        self.require_edit(context, "Sources")?;
        if incoming.id == EDITOR_ID || incoming.source_type == EDITOR_TYPE {
            return Err(PolicyFailure::BadRequest(
                "The editor is a built-in source and cannot be created, edited, or deleted"
                    .to_owned(),
            ));
        }
        require_name_and_type(&incoming.name, &incoming.source_type, "source")?;
        let existing = (!incoming.id.trim().is_empty())
            .then(|| self.store.get_policy_source(&incoming.id))
            .transpose()?
            .flatten();
        let is_create = existing.is_none();
        if let Some(existing) = &existing {
            if !Self::can_access_team(existing.team_id, context) {
                return Err(PolicyFailure::NotFound(format!(
                    "No source: {}",
                    incoming.id
                )));
            }
            incoming.owner.clone_from(&existing.owner);
            incoming.team_id = existing.team_id;
            incoming.options = merge_config(&existing.options, &incoming.options, 0);
        } else {
            incoming.id = new_uuid_v4();
            incoming.owner = Some(context.username.clone());
            incoming.team_id = context.team_id;
        }
        // Mirror WebhookInputSource.prepareOptionsForSave: a webhook source keeps
        // its client-supplied credentials only when updating an existing source
        // that already carries a non-blank webhookId; otherwise (create, or an
        // update with no id) mint a fresh id + signing secret server-side so
        // credentials can never be forged by the client.
        if incoming.source_type == WEBHOOK_TYPE {
            let has_id = incoming
                .options
                .get("webhookId")
                .and_then(Value::as_str)
                .is_some_and(|value| !value.trim().is_empty());
            // Java's `!(!isCreate && hasId)`, i.e. regenerate on create, or on an
            // update that arrived without a usable webhookId.
            if is_create || !has_id {
                incoming
                    .options
                    .insert("webhookId".to_owned(), Value::String(new_webhook_id()));
                incoming.options.insert(
                    "signingSecret".to_owned(),
                    Value::String(new_signing_secret()),
                );
            }
        }
        self.validate_source(&incoming, context)?;
        validate_serialized_size(&incoming)?;
        self.store.save_policy_source(&incoming)?;
        // Reveal-on-create: a freshly created webhook source returns its plaintext
        // signing secret exactly once so the operator can copy it; every other
        // response (updates, and all non-webhook sources) masks secrets.
        if is_create && incoming.source_type == WEBHOOK_TYPE {
            Ok(incoming)
        } else {
            Ok(mask_source(incoming))
        }
    }

    pub(crate) fn delete_source(
        &self,
        id: &str,
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        self.require_edit(context, "Sources")?;
        if id == EDITOR_ID {
            return Err(PolicyFailure::BadRequest(
                "The editor is a built-in source and cannot be created, edited, or deleted"
                    .to_owned(),
            ));
        }
        let source = self
            .store
            .get_policy_source(id)?
            .filter(|source| Self::can_access_team(source.team_id, context))
            .ok_or_else(|| PolicyFailure::NotFound(format!("No source: {id}")))?;
        let references = self
            .visible_policies(context)?
            .into_iter()
            .filter(|policy| {
                policy
                    .source_ids
                    .iter()
                    .any(|source_id| source_id == &source.id)
            })
            .map(|policy| policy.name)
            .collect::<Vec<_>>();
        if !references.is_empty() {
            return Err(PolicyFailure::Conflict(format!(
                "Source is referenced by {} policy(ies): {}",
                references.len(),
                references.join(", ")
            )));
        }
        self.store.delete_policy_source(id)?;
        Ok(())
    }

    pub(crate) fn list_policies(
        &self,
        context: &AuthContext,
    ) -> Result<Vec<PolicyDefinition>, PolicyFailure> {
        self.visible_policies(context)
            .map(|policies| policies.into_iter().map(mask_policy).collect())
    }

    pub(crate) fn get_policy(
        &self,
        id: &str,
        context: &AuthContext,
    ) -> Result<PolicyDefinition, PolicyFailure> {
        let policy = self
            .store
            .get_policy_definition(id)?
            .filter(|policy| Self::can_access_team(policy.team_id, context))
            .ok_or_else(|| PolicyFailure::NotFound(format!("No policy: {id}")))?;
        Ok(mask_policy(policy))
    }

    pub(crate) fn policy_overview(
        &self,
        context: &AuthContext,
    ) -> Result<PoliciesOverviewResponse, PolicyFailure> {
        let policies = self.visible_policies(context)?;
        let source_names = self
            .visible_sources(context)?
            .into_iter()
            .map(|source| (source.id, source.name))
            .collect::<HashMap<_, _>>();
        let total = policies.len();
        let active = policies.iter().filter(|policy| policy.enabled).count();
        let mut pipelines = policies
            .into_iter()
            .map(|policy| policy_view(policy, &source_names))
            .collect::<Vec<_>>();
        pipelines.sort_by_cached_key(|policy| policy.name.to_lowercase());
        Ok(PoliciesOverviewResponse {
            kpis: vec![
                PolicyKpi {
                    value: total,
                    description: "pipelines",
                },
                PolicyKpi {
                    value: active,
                    description: "running automatically",
                },
                PolicyKpi {
                    value: total - active,
                    description: "paused",
                },
            ],
            pipelines,
        })
    }

    pub(crate) fn get_policy_for_run(
        &self,
        id: &str,
        context: &AuthContext,
    ) -> Result<PolicyDefinition, PolicyFailure> {
        self.store
            .get_policy_definition(id)?
            .filter(|policy| Self::can_access_team(policy.team_id, context))
            .ok_or_else(|| PolicyFailure::NotFound(format!("No policy: {id}")))
    }

    pub(crate) fn policies_for_trigger(
        &self,
        trigger_type: &str,
    ) -> Result<Vec<PolicyDefinition>, PolicyFailure> {
        let policies = self
            .store
            .list_all_policy_definitions()?
            .into_iter()
            .filter(|policy| {
                policy.enabled
                    && policy
                        .trigger
                        .as_ref()
                        .is_some_and(|trigger| trigger.trigger_type == trigger_type)
            })
            .collect();
        Ok(policies)
    }

    pub(crate) fn automation_context(
        &self,
        policy: &PolicyDefinition,
    ) -> Result<AuthContext, PolicyFailure> {
        let owner = policy.owner.as_deref().ok_or_else(|| {
            PolicyFailure::BadRequest(format!("policy '{}' has no owner", policy.id))
        })?;
        let context = self
            .store
            .policy_automation_context(owner, &format!("policy-trigger:{}", policy.id))?;
        if context.team_id != policy.team_id {
            return Err(PolicyFailure::Forbidden(format!(
                "policy '{}' owner is no longer in its team",
                policy.id
            )));
        }
        Ok(context)
    }

    pub(crate) fn watch_directories(
        &self,
        policy: &PolicyDefinition,
    ) -> Result<Vec<PathBuf>, PolicyFailure> {
        let mut directories = Vec::new();
        for source_id in &policy.source_ids {
            let Some(source) = self.store.get_policy_source(source_id)? else {
                continue;
            };
            if source.source_type == "folder" {
                directories.push(self.permitted_folder_directory(&source.options)?);
            }
        }
        Ok(directories)
    }

    /// Whether `policy` references a webhook input source whose stored
    /// `webhookId` equals `webhook_id`. Mirrors Java's
    /// `WebhookTrigger.referencesWebhook`: it consults the raw source store
    /// (`sourceStore.get`) with **no** team filter, because a webhook delivery is
    /// authenticated by its signed id/secret rather than by any caller's team.
    #[allow(
        dead_code,
        reason = "invoked by the public webhook-receiver route port (staged)"
    )]
    pub(crate) fn policy_references_webhook(
        &self,
        policy: &PolicyDefinition,
        webhook_id: &str,
    ) -> Result<bool, PolicyFailure> {
        for source_id in &policy.source_ids {
            let Some(source) = self.store.get_policy_source(source_id)? else {
                continue;
            };
            if source.source_type == WEBHOOK_TYPE
                && source.options.get("webhookId").and_then(Value::as_str) == Some(webhook_id)
            {
                return Ok(true);
            }
        }
        Ok(false)
    }

    /// Resolves the single persisted webhook source whose decrypted
    /// `webhookId` option equals `webhook_id`, scanning **every** source with no
    /// team scope. Mirrors Java's `WebhookReceiverController.findWebhookSource`
    /// (`sourceStore.all()` filtered by `type == "webhook"` and a raw string
    /// equality on the stored `webhookId`), because an inbound webhook delivery is
    /// authenticated by its signed id/secret rather than by any caller's team.
    ///
    /// The returned source carries its **decrypted** options (including
    /// `signingSecret`); the receiver must never log them.
    pub(crate) fn find_webhook_source(
        &self,
        webhook_id: &str,
    ) -> Result<Option<PolicySource>, PolicyFailure> {
        for source in self.store.list_all_policy_sources()? {
            if source.source_type == WEBHOOK_TYPE
                && source.options.get("webhookId").and_then(Value::as_str) == Some(webhook_id)
            {
                return Ok(Some(source));
            }
        }
        Ok(None)
    }

    pub(crate) fn get_source_for_run(
        &self,
        id: &str,
        context: &AuthContext,
    ) -> Result<PolicySource, PolicyFailure> {
        let source = self
            .store
            .get_policy_source(id)?
            .filter(|source| Self::can_access_team(source.team_id, context))
            .ok_or_else(|| PolicyFailure::NotFound(format!("No source: {id}")))?;
        Ok(source)
    }

    pub(crate) fn permitted_folder_directory(
        &self,
        options: &Map<String, Value>,
    ) -> Result<PathBuf, PolicyFailure> {
        self.validate_folder_options(options)
    }

    pub(crate) fn resolved_s3_options(
        &self,
        options: &Map<String, Value>,
        context: &AuthContext,
    ) -> Result<Map<String, Value>, PolicyFailure> {
        self.integrations
            .resolve_s3_options(options, context)
            .map_err(policy_integration_error)
    }

    pub(crate) fn validate_run_output(
        &self,
        output: &OutputSpec,
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        self.validate_output(output, context)
    }

    pub(crate) fn record_editor_documents(
        &self,
        team_id: Option<i64>,
        documents: usize,
    ) -> Result<(), PolicyFailure> {
        let documents = u64::try_from(documents).unwrap_or(u64::MAX);
        self.store
            .record_policy_source_docs(&editor_counter_key(team_id), documents)?;
        Ok(())
    }

    pub(crate) fn record_source_documents(
        &self,
        source_id: &str,
        documents: usize,
    ) -> Result<(), PolicyFailure> {
        let documents = u64::try_from(documents).unwrap_or(u64::MAX);
        self.store.record_policy_source_docs(source_id, documents)?;
        Ok(())
    }

    pub(crate) fn save_policy(
        &self,
        mut incoming: PolicyDefinition,
        context: &AuthContext,
    ) -> Result<PolicyDefinition, PolicyFailure> {
        self.require_edit(context, "Policies")?;
        if incoming.name.trim().is_empty() {
            return Err(PolicyFailure::BadRequest(
                "policy name is required".to_owned(),
            ));
        }
        let existing = (!incoming.id.trim().is_empty())
            .then(|| self.store.get_policy_definition(&incoming.id))
            .transpose()?
            .flatten();
        if let Some(existing) = &existing {
            if !Self::can_access_team(existing.team_id, context) {
                return Err(PolicyFailure::NotFound(format!(
                    "No policy: {}",
                    incoming.id
                )));
            }
            incoming.owner.clone_from(&existing.owner);
            incoming.team_id = existing.team_id;
            incoming.output.options =
                merge_config(&existing.output.options, &incoming.output.options, 0);
        } else {
            incoming.id = new_uuid_v4();
            incoming.owner = Some(context.username.clone());
            incoming.team_id = context.team_id;
        }
        for source_id in &incoming.source_ids {
            let source = self
                .store
                .get_policy_source(source_id)?
                .filter(|source| Self::can_access_team(source.team_id, context))
                .ok_or_else(|| {
                    PolicyFailure::BadRequest(format!(
                        "Unknown or inaccessible source: {source_id}"
                    ))
                })?;
            self.validate_source(&source, context)?;
        }
        self.validate_steps(&incoming.steps, context)?;
        self.validate_output(&incoming.output, context)?;
        self.validate_trigger(&incoming, context)?;
        validate_serialized_size(&incoming)?;
        self.store.save_policy_definition(&incoming)?;
        Ok(mask_policy(incoming))
    }

    pub(crate) fn reorder_policies(
        &self,
        ids: &[String],
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        self.require_edit(context, "Policies")?;
        self.store
            .reorder_policy_definitions(context.team_id, ids)?;
        Ok(())
    }

    pub(crate) fn delete_policy(
        &self,
        id: &str,
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        self.require_edit(context, "Policies")?;
        self.store
            .get_policy_definition(id)?
            .filter(|policy| Self::can_access_team(policy.team_id, context))
            .ok_or_else(|| PolicyFailure::NotFound(format!("No policy: {id}")))?;
        self.store.delete_policy_definition(id)?;
        Ok(())
    }

    pub(crate) fn clear_processed_history(
        &self,
        id: &str,
        context: &AuthContext,
        ledger: &ProcessedLedger,
    ) -> Result<(), PolicyFailure> {
        self.require_edit(context, "Policies")?;
        self.store
            .get_policy_definition(id)?
            .filter(|policy| Self::can_access_team(policy.team_id, context))
            .ok_or_else(|| PolicyFailure::NotFound(format!("No policy: {id}")))?;
        ledger.clear_policy(id)?;
        Ok(())
    }

    fn visible_sources(&self, context: &AuthContext) -> Result<Vec<PolicySource>, PolicyFailure> {
        self.store
            .list_policy_sources(context.team_id)
            .map_err(Into::into)
    }

    fn visible_policies(
        &self,
        context: &AuthContext,
    ) -> Result<Vec<PolicyDefinition>, PolicyFailure> {
        self.store
            .list_policy_definitions(context.team_id)
            .map_err(Into::into)
    }

    fn validate_source(
        &self,
        source: &PolicySource,
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        match source.source_type.as_str() {
            "s3" => self
                .integrations
                .resolve_s3_options(&source.options, context)
                .map(|_| ())
                .map_err(policy_integration_error),
            "folder" => {
                self.validate_folder_options(&source.options)?;
                validate_folder_identity(&source.options)
            }
            WEBHOOK_TYPE => validate_webhook_options(&source.options),
            value => Err(PolicyFailure::BadRequest(format!(
                "unknown source type: {value}"
            ))),
        }
    }

    /// Save-time confused-deputy guard for a policy's steps, ported from Java
    /// `IntegrationStepValidator.validate` (registered as a `PipelineStepValidator`
    /// and invoked by `PolicyValidator.validateSteps`). Each integration step names
    /// a connection by id; the worker thread that later runs it carries **no**
    /// principal, so `resolve_config` there lets the lookup through unchecked. This
    /// runs while the saving caller's identity is still available, forcing the
    /// ownership check to run — otherwise a caller could name any connection id in a
    /// step and have the server dial that tenant's endpoint with that tenant's
    /// stored credentials. Non-integration steps are skipped; the resolved config is
    /// discarded because the call itself is the authorization check.
    pub(crate) fn validate_steps(
        &self,
        steps: &[PolicyStep],
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        for step in steps {
            if let Some((connection_id, integration_type)) = integration_step_connection(step)? {
                self.integrations
                    .resolve_config(connection_id, integration_type, context)
                    .map_err(policy_integration_error)?;
            }
        }
        Ok(())
    }

    fn validate_output(
        &self,
        output: &OutputSpec,
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        match output.output_type.as_str() {
            "inline" => Ok(()),
            "s3" => self
                .integrations
                .resolve_s3_options(&output.options, context)
                .map(|_| ())
                .map_err(policy_integration_error),
            "folder" => self.validate_folder_options(&output.options).map(|_| ()),
            value => Err(PolicyFailure::BadRequest(format!(
                "unknown output type: {value}"
            ))),
        }
    }

    fn validate_trigger(
        &self,
        policy: &PolicyDefinition,
        context: &AuthContext,
    ) -> Result<(), PolicyFailure> {
        let Some(trigger) = &policy.trigger else {
            return Ok(());
        };
        match trigger.trigger_type.as_str() {
            "schedule" => validate_schedule_options(&trigger.options),
            "folder-watch" => {
                for source_id in &policy.source_ids {
                    let source = self
                        .store
                        .get_policy_source(source_id)?
                        .filter(|source| Self::can_access_team(source.team_id, context));
                    if source.is_some_and(|source| source.source_type == "folder") {
                        return Ok(());
                    }
                }
                Err(PolicyFailure::BadRequest(
                    "folder-watch trigger requires at least one watchable (folder) input source"
                        .to_owned(),
                ))
            }
            "webhook" => {
                for source_id in &policy.source_ids {
                    let source = self
                        .store
                        .get_policy_source(source_id)?
                        .filter(|source| Self::can_access_team(source.team_id, context));
                    if source.is_some_and(|source| source.source_type == WEBHOOK_TYPE) {
                        return Ok(());
                    }
                }
                Err(PolicyFailure::BadRequest(
                    "webhook trigger requires at least one webhook input source".to_owned(),
                ))
            }
            value => Err(PolicyFailure::BadRequest(format!(
                "unknown trigger type: {value}"
            ))),
        }
    }

    fn validate_folder_options(
        &self,
        options: &Map<String, Value>,
    ) -> Result<PathBuf, PolicyFailure> {
        let directory = options
            .get("directory")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|directory| !directory.is_empty())
            .ok_or_else(|| {
                PolicyFailure::BadRequest("folder config requires a 'directory' option".to_owned())
            })?;
        let directory = normalize_path(Path::new(directory));
        folder_access_decision(
            &directory,
            &self.protected_config_root,
            &self.implied_folder_roots,
            &self.allowed_folder_roots,
        )?;
        Ok(directory)
    }

    fn require_edit(&self, context: &AuthContext, subject: &str) -> Result<(), PolicyFailure> {
        if context.has_role("ROLE_ADMIN") {
            return Ok(());
        }
        let team_owner = context
            .team_id
            .map(|team_id| self.integrations.access().is_team_owner(context, team_id))
            .transpose()
            .map_err(|_| PolicyFailure::Storage(SecurityError::Conflict))?
            .unwrap_or(false);
        if team_owner {
            Ok(())
        } else {
            Err(PolicyFailure::Forbidden(format!(
                "{subject} may only be created or modified by a team leader"
            )))
        }
    }

    fn can_access_team(team_id: Option<i64>, context: &AuthContext) -> bool {
        team_id == context.team_id
    }
}

fn inline_output_type() -> String {
    "inline".to_owned()
}

fn deserialize_default_on_null<'de, D, T>(deserializer: D) -> Result<T, D::Error>
where
    D: serde::Deserializer<'de>,
    T: Deserialize<'de> + Default,
{
    Option::<T>::deserialize(deserializer).map(Option::unwrap_or_default)
}

fn require_name_and_type(name: &str, value_type: &str, subject: &str) -> Result<(), PolicyFailure> {
    if name.trim().is_empty() {
        return Err(PolicyFailure::BadRequest(format!(
            "{subject} name is required"
        )));
    }
    if value_type.trim().is_empty() {
        return Err(PolicyFailure::BadRequest(format!(
            "{subject} type is required"
        )));
    }
    Ok(())
}

fn validate_folder_identity(options: &Map<String, Value>) -> Result<(), PolicyFailure> {
    let Some(identity) = options.get("identity") else {
        return Ok(());
    };
    if identity
        .as_str()
        .is_some_and(|value| matches!(value, "stat" | "hash"))
    {
        return Ok(());
    }
    Err(PolicyFailure::BadRequest(
        "folder input 'identity' must be 'stat' or 'hash'".to_owned(),
    ))
}

/// Validates a webhook input source's stored options, mirroring Java's
/// `WebhookConfig.from` (via `WebhookInputSource.validate`): a non-blank
/// `webhookId` matching `WebhookIds.VALID_ID`, then a non-blank `signingSecret`.
/// Error messages are kept byte-for-byte identical for parity with the Java
/// oracle.
fn validate_webhook_options(options: &Map<String, Value>) -> Result<(), PolicyFailure> {
    let webhook_id = options
        .get("webhookId")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PolicyFailure::BadRequest("webhook config requires a 'webhookId' option".to_owned())
        })?;
    // Fail closed: a (theoretically impossible) regex-compile failure rejects
    // every id rather than waving it through.
    if !webhook_id_regex().is_some_and(|regex| regex.is_match(webhook_id)) {
        return Err(PolicyFailure::BadRequest(
            "webhook config 'webhookId' has an invalid format".to_owned(),
        ));
    }
    options
        .get("signingSecret")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            PolicyFailure::BadRequest("webhook config requires a 'signingSecret' option".to_owned())
        })?;
    Ok(())
}

/// Compiled-once `webhookId` format check, mirroring Java's
/// `WebhookIds.VALID_ID = Pattern.compile("^[A-Za-z0-9_-]{16,128}$")`. The char
/// class excludes newlines and callers trim before matching, so `^`/`$` anchor
/// the whole (single-line) value exactly as Java's `Matcher.matches()` does.
/// Returns `None` only if the (constant) pattern fails to compile, which the
/// caller treats as an invalid id — matching the crate's `.ok()` regex idiom.
fn webhook_id_regex() -> Option<&'static Regex> {
    static WEBHOOK_ID_REGEX: OnceLock<Option<Regex>> = OnceLock::new();
    WEBHOOK_ID_REGEX
        .get_or_init(|| Regex::new(r"^[A-Za-z0-9_-]{16,128}$").ok())
        .as_ref()
}

fn validate_schedule_options(options: &Map<String, Value>) -> Result<(), PolicyFailure> {
    let schedule = options
        .get("schedule")
        .and_then(Value::as_object)
        .ok_or_else(|| {
            PolicyFailure::BadRequest("schedule trigger requires a 'schedule'".to_owned())
        })?;
    let schedule_type = schedule
        .get("type")
        .and_then(Value::as_str)
        .unwrap_or_default();
    match schedule_type {
        "every" => {
            if schedule
                .get("count")
                .and_then(Value::as_i64)
                .unwrap_or_default()
                <= 0
            {
                return Err(PolicyFailure::BadRequest(
                    "invalid schedule: 'every' schedule needs a positive count".to_owned(),
                ));
            }
            if !matches!(
                schedule.get("unit").and_then(Value::as_str),
                Some("MINUTES" | "HOURS" | "DAYS")
            ) {
                return Err(PolicyFailure::BadRequest(
                    "invalid schedule: 'every' schedule needs a unit".to_owned(),
                ));
            }
        }
        "daily" => validate_schedule_time(schedule)?,
        "weekly" => {
            let valid_days = schedule
                .get("days")
                .and_then(Value::as_array)
                .is_some_and(|days| {
                    !days.is_empty()
                        && days.iter().all(|day| {
                            matches!(
                                day.as_str(),
                                Some(
                                    "MONDAY"
                                        | "TUESDAY"
                                        | "WEDNESDAY"
                                        | "THURSDAY"
                                        | "FRIDAY"
                                        | "SATURDAY"
                                        | "SUNDAY"
                                )
                            )
                        })
                });
            if !valid_days {
                return Err(PolicyFailure::BadRequest(
                    "invalid schedule: 'weekly' schedule needs at least one day".to_owned(),
                ));
            }
            validate_schedule_time(schedule)?;
        }
        "monthly" => {
            if !(1..=31).contains(
                &schedule
                    .get("dayOfMonth")
                    .and_then(Value::as_i64)
                    .unwrap_or_default(),
            ) {
                return Err(PolicyFailure::BadRequest(
                    "invalid schedule: 'monthly' day-of-month must be 1-31".to_owned(),
                ));
            }
            validate_schedule_time(schedule)?;
        }
        _ => {
            return Err(PolicyFailure::BadRequest(
                "invalid schedule: unknown schedule type".to_owned(),
            ));
        }
    }
    if let Some(zone) = options.get("zone") {
        let zone = zone
            .as_str()
            .ok_or_else(|| PolicyFailure::BadRequest("invalid schedule zone".to_owned()))?;
        if !zone.is_empty() && jiff::tz::TimeZone::get(zone).is_err() {
            return Err(PolicyFailure::BadRequest(format!("invalid zone '{zone}'")));
        }
    }
    Ok(())
}

fn validate_schedule_time(schedule: &Map<String, Value>) -> Result<(), PolicyFailure> {
    let valid = schedule
        .get("at")
        .and_then(Value::as_str)
        .is_some_and(|value| {
            ["%H:%M", "%H:%M:%S", "%H:%M:%S%.f"]
                .iter()
                .any(|format| chrono::NaiveTime::parse_from_str(value, format).is_ok())
        });
    if valid {
        Ok(())
    } else {
        Err(PolicyFailure::BadRequest(
            "invalid schedule: schedule needs a time of day ('at')".to_owned(),
        ))
    }
}

/// Classifies a step for the confused-deputy guard, returning the connection it
/// dereferences (id + type) or `None` when the step is not an integration step and
/// should be skipped. Ported from Java `IntegrationStepValidator.validate`:
///
/// - an operation not under [`INTEGRATION_PREFIX`] → `Ok(None)` (skip);
/// - a prefixed operation with no registered type → `unknown integration step`
///   (fail-closed, so an unported endpoint such as `consigno-*` cannot slip
///   through unchecked);
/// - a registered step with no resolvable `connectionId` → the same
///   `requires a 'connectionId' parameter` error Java raises after its `null` check.
///
/// The returned pair is what the caller then authorization-checks; this function is
/// pure so the classification/parsing can be exercised without a live store.
fn integration_step_connection(
    step: &PolicyStep,
) -> Result<Option<(i64, IntegrationType)>, PolicyFailure> {
    let operation = step.operation.as_str();
    if !operation.starts_with(INTEGRATION_PREFIX) {
        return Ok(None);
    }
    let integration_type = integration_step_type(operation).ok_or_else(|| {
        PolicyFailure::BadRequest(format!("unknown integration step: {operation}"))
    })?;
    let connection_id =
        step_connection_id(step.parameters.get(CONNECTION_ID_PARAM))?.ok_or_else(|| {
            PolicyFailure::BadRequest(format!(
                "{operation} requires a '{CONNECTION_ID_PARAM}' parameter"
            ))
        })?;
    Ok(Some((connection_id, integration_type)))
}

/// The connection type a registered integration step dereferences, or `None` for an
/// operation that is not a (ported) integration step. Mirrors a lookup in Java's
/// `STEP_CONNECTION_TYPES` map.
fn integration_step_type(operation: &str) -> Option<IntegrationType> {
    INTEGRATION_STEP_TYPES
        .iter()
        .find(|(step_operation, _)| *step_operation == operation)
        .map(|&(_, integration_type)| integration_type)
}

/// Parses an integration step's `connectionId` parameter into a numeric connection
/// id, mirroring Java `ApiConnectionResolver.connectionId(Object)`. An absent
/// parameter, a JSON null, or a blank string all yield `Ok(None)` — the caller turns
/// that into a "requires a 'connectionId' parameter" error, so blank and absent are
/// indistinguishable. A JSON number or a numeric string yields `Ok(Some(id))`;
/// anything else is an invalid connection reference.
///
/// This is deliberately **not** [`parse_connection_id_param`] (which takes an
/// already-stringified form field) nor the S3 `connection_id` helper (whose error is
/// hard-coded to the s3 source path).
fn step_connection_id(reference: Option<&Value>) -> Result<Option<i64>, PolicyFailure> {
    let Some(reference) = reference else {
        return Ok(None);
    };
    let parsed = match reference {
        Value::Null => return Ok(None),
        Value::String(value) if value.trim().is_empty() => return Ok(None),
        Value::Number(number) => number.as_i64(),
        Value::String(value) => value.trim().parse::<i64>().ok(),
        other => other.to_string().trim().parse::<i64>().ok(),
    };
    parsed.map(Some).ok_or_else(|| {
        PolicyFailure::BadRequest(format!(
            "'{CONNECTION_ID_PARAM}' is not a valid connection reference: {}",
            connection_reference_display(reference)
        ))
    })
}

/// Renders a rejected `connectionId` value for the invalid-reference error the same
/// way Java's string concatenation of the raw `Object` does: a JSON string shows its
/// bare text (no quotes), any other value its compact JSON form.
fn connection_reference_display(reference: &Value) -> String {
    match reference {
        Value::String(value) => value.clone(),
        other => other.to_string(),
    }
}

fn policy_integration_error(error: IntegrationFailure) -> PolicyFailure {
    match error {
        IntegrationFailure::BadRequest(message)
        | IntegrationFailure::Forbidden(message)
        | IntegrationFailure::NotFound(message)
        | IntegrationFailure::Conflict(message) => PolicyFailure::BadRequest(message),
        IntegrationFailure::Storage(error) => PolicyFailure::Storage(error),
        IntegrationFailure::Access(_) => PolicyFailure::Storage(SecurityError::Conflict),
    }
}

fn validate_serialized_size(value: &impl Serialize) -> Result<(), PolicyFailure> {
    let serialized = serde_json::to_vec(value)
        .map_err(|_| PolicyFailure::BadRequest("Invalid policy payload".to_owned()))?;
    if serialized.len() > MAX_POLICY_JSON_BYTES {
        Err(PolicyFailure::BadRequest(
            "Invalid policy payload".to_owned(),
        ))
    } else {
        Ok(())
    }
}

fn mask_source(mut source: PolicySource) -> PolicySource {
    source.options = mask_config(&source.options, 0);
    source
}

fn mask_policy(mut policy: PolicyDefinition) -> PolicyDefinition {
    policy.output.options = mask_config(&policy.output.options, 0);
    policy
}

fn policy_ref(policy: &PolicyDefinition) -> PolicyRef {
    PolicyRef {
        id: policy.id.clone(),
        name: policy.name.clone(),
    }
}

fn policy_view(policy: PolicyDefinition, source_names: &HashMap<String, String>) -> PolicyView {
    PolicyView {
        id: policy.id,
        name: policy.name,
        enabled: policy.enabled,
        status: if policy.enabled { "active" } else { "paused" },
        trigger: policy
            .trigger
            .map_or_else(|| "manual".to_owned(), |trigger| trigger.trigger_type),
        sources: policy
            .source_ids
            .into_iter()
            .map(|id| PolicySourceRef {
                name: source_names.get(&id).cloned().unwrap_or_else(|| id.clone()),
                id,
            })
            .collect(),
        steps: policy
            .steps
            .into_iter()
            .map(|step| step.operation)
            .collect(),
        output: policy.output.output_type,
        owner: policy.owner,
    }
}

fn source_config_rows(source: &PolicySource) -> Vec<DetailRow> {
    mask_config(&source.options, 0)
        .into_iter()
        .map(|(key, value)| DetailRow {
            label: humanize(&key),
            value: json_value_text(&value),
        })
        .collect()
}

fn humanize(key: &str) -> String {
    let mut characters = key.chars();
    characters.next().map_or_else(String::new, |first| {
        first.to_uppercase().collect::<String>() + characters.as_str()
    })
}

fn json_value_text(value: &Value) -> String {
    match value {
        Value::String(value) => value.clone(),
        _ => value.to_string(),
    }
}

fn output_references_editor(output: &OutputSpec) -> bool {
    output
        .options
        .get("sources")
        .and_then(Value::as_array)
        .is_some_and(|sources| sources.iter().any(|source| source == EDITOR_ID))
}

fn editor_counter_key(team_id: Option<i64>) -> String {
    team_id.map_or_else(
        || EDITOR_ID.to_owned(),
        |team_id| format!("{EDITOR_ID}:{team_id}"),
    )
}

fn new_uuid_v4() -> String {
    let mut bytes = [0_u8; 16];
    rand::rng().fill(&mut bytes);
    bytes[6] = (bytes[6] & 0x0f) | 0x40;
    bytes[8] = (bytes[8] & 0x3f) | 0x80;
    format!(
        "{:02x}{:02x}{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}-{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
        bytes[0],
        bytes[1],
        bytes[2],
        bytes[3],
        bytes[4],
        bytes[5],
        bytes[6],
        bytes[7],
        bytes[8],
        bytes[9],
        bytes[10],
        bytes[11],
        bytes[12],
        bytes[13],
        bytes[14],
        bytes[15]
    )
}

/// Mints a fresh webhook id: 18 CSPRNG bytes rendered as URL-safe base64 with no
/// padding (24 characters), mirroring Java's `WebhookIds.newWebhookId`
/// (`randomToken(18)` through a `Base64.getUrlEncoder().withoutPadding()`).
fn new_webhook_id() -> String {
    let mut bytes = [0_u8; 18];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Mints a fresh webhook signing secret: 32 CSPRNG bytes rendered as URL-safe
/// base64 with no padding (43 characters), mirroring Java's
/// `WebhookIds.newSigningSecret` (`randomToken(32)`).
fn new_signing_secret() -> String {
    let mut bytes = [0_u8; 32];
    rand::rng().fill(&mut bytes);
    URL_SAFE_NO_PAD.encode(bytes)
}

/// Builds the Stirling-owned "implied" folder roots always permitted for folder
/// automations regardless of `policies.allowedFolderRoots`, so they work out of
/// the box. Mirrors Java's `FolderAccessGuard.impliedRoots`: the local server
/// file-storage directory (when that provider is enabled with a non-blank base
/// path) followed by each pipeline watched-folder directory, all normalized to
/// absolute paths.
pub(crate) fn implied_folder_roots(
    storage: &StorageConfig,
    watched_folders: &[PathBuf],
) -> Vec<ImpliedFolderRoot> {
    let mut roots = Vec::new();
    if storage.enabled
        && storage.provider.trim().eq_ignore_ascii_case("local")
        && !storage.base_path.as_os_str().is_empty()
    {
        roots.push(ImpliedFolderRoot {
            path: normalize_path(&storage.base_path),
            reason: IMPLIED_SERVER_STORAGE,
        });
    }
    for folder in watched_folders {
        if folder.as_os_str().is_empty() {
            continue;
        }
        roots.push(ImpliedFolderRoot {
            path: normalize_path(folder),
            reason: IMPLIED_WATCHED_FOLDER,
        });
    }
    roots
}

/// Fail-closed folder-access decision shared by save-time and run-time folder
/// validation. Mirrors the ordering of Java's `FolderAccessGuard.requirePermitted`
/// (protected-root rejection → implied-root allowance → allowlist), so a folder
/// automation targeting a watched-folder or server-storage path is permitted even
/// when it is absent from `policies.allowedFolderRoots`. The `directory` and all
/// roots must already be normalized to absolute paths.
fn folder_access_decision(
    directory: &Path,
    protected_config_root: &Path,
    implied_folder_roots: &[ImpliedFolderRoot],
    allowed_folder_roots: &[PathBuf],
) -> Result<(), PolicyFailure> {
    if directory.starts_with(protected_config_root) {
        return Err(PolicyFailure::BadRequest(
            "folder may not point inside a protected Stirling directory".to_owned(),
        ));
    }
    // Stirling-owned implied roots are always permitted, even with no configured
    // allowlist, so automations work against them out of the box.
    if implied_folder_roots
        .iter()
        .any(|root| directory.starts_with(&root.path))
    {
        return Ok(());
    }
    if allowed_folder_roots.is_empty() {
        return Err(PolicyFailure::BadRequest(
            "folder access is disabled; set policies.allowedFolderRoots to permit it".to_owned(),
        ));
    }
    if !allowed_folder_roots
        .iter()
        .any(|root| directory.starts_with(root))
    {
        return Err(PolicyFailure::BadRequest(format!(
            "folder '{}' is outside the allowed folder roots",
            directory.display()
        )));
    }
    Ok(())
}

fn normalize_path(path: &Path) -> PathBuf {
    let absolute = if path.is_absolute() {
        path.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| PathBuf::from("."))
            .join(path)
    };
    let mut normalized = PathBuf::new();
    for component in absolute.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            component => normalized.push(component.as_os_str()),
        }
    }
    normalized
}

#[cfg(test)]
mod tests {
    use super::{
        ImpliedFolderRoot, PolicyFailure, folder_access_decision, implied_folder_roots,
        new_signing_secret, new_uuid_v4, new_webhook_id, normalize_path, validate_webhook_options,
        webhook_id_regex,
    };
    use crate::storage::{StorageConfig, StorageSharingConfig};
    use serde_json::{Map, Value};
    use std::path::{Path, PathBuf};

    fn webhook_options(
        webhook_id: Option<&str>,
        signing_secret: Option<&str>,
    ) -> Map<String, Value> {
        let mut options = Map::new();
        if let Some(webhook_id) = webhook_id {
            options.insert("webhookId".to_owned(), Value::String(webhook_id.to_owned()));
        }
        if let Some(signing_secret) = signing_secret {
            options.insert(
                "signingSecret".to_owned(),
                Value::String(signing_secret.to_owned()),
            );
        }
        options
    }

    fn storage(enabled: bool, provider: &str, base_path: &str) -> StorageConfig {
        StorageConfig {
            enabled,
            provider: provider.to_owned(),
            base_path: PathBuf::from(base_path),
            database_path: PathBuf::from("/srv/security.db"),
            sharing: StorageSharingConfig {
                enabled: false,
                link_enabled: false,
                email_enabled: false,
                link_expiration_days: 3,
            },
            max_file_bytes: None,
            max_user_bytes: None,
            max_total_bytes: None,
            max_upload_bytes: 0,
        }
    }

    fn implied(path: &str, reason: &'static str) -> ImpliedFolderRoot {
        ImpliedFolderRoot {
            path: normalize_path(Path::new(path)),
            reason,
        }
    }

    #[test]
    fn ids_are_rfc_4122_version_four_shape() {
        let id = new_uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn minted_webhook_credentials_match_java_lengths_and_alphabet() {
        // WebhookIds.newWebhookId -> randomToken(18) -> URL-safe base64 no-pad = 24 chars.
        let id = new_webhook_id();
        assert_eq!(id.len(), 24);
        // WebhookIds.newSigningSecret -> randomToken(32) -> URL-safe base64 no-pad = 43 chars.
        let secret = new_signing_secret();
        assert_eq!(secret.len(), 43);
        // URL-safe base64-no-pad alphabet only: A-Za-z0-9-_ and never '=' padding.
        let url_safe = |value: &str| {
            value
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
        };
        assert!(url_safe(&id), "webhook id used a non-url-safe char: {id}");
        assert!(
            url_safe(&secret),
            "signing secret used a non-url-safe char: {secret}"
        );
        // A freshly minted id always satisfies the stored-config format check, and a
        // minted id + secret validate cleanly (24 chars is inside the 16..=128 bound).
        assert!(webhook_id_regex().is_some_and(|regex| regex.is_match(&id)));
        assert!(validate_webhook_options(&webhook_options(Some(&id), Some(&secret))).is_ok());
        // Two mints are distinct (CSPRNG, not a fixed value).
        assert_ne!(new_webhook_id(), new_webhook_id());
        assert_ne!(new_signing_secret(), new_signing_secret());
    }

    #[test]
    fn webhook_validation_mirrors_java_message_order() {
        // Missing webhookId -> first failure, exact Java message.
        assert!(matches!(
            validate_webhook_options(&webhook_options(None, Some("secret-value"))),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config requires a 'webhookId' option"
        ));
        // Whitespace-only webhookId is treated as absent (Java trims then null-checks).
        assert!(matches!(
            validate_webhook_options(&webhook_options(Some("   "), Some("secret-value"))),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config requires a 'webhookId' option"
        ));
        // A non-string webhookId cannot satisfy the string format and reads as absent.
        let mut numeric = Map::new();
        numeric.insert("webhookId".to_owned(), Value::from(1234));
        numeric.insert("signingSecret".to_owned(), Value::String("s".to_owned()));
        assert!(matches!(
            validate_webhook_options(&numeric),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config requires a 'webhookId' option"
        ));
        // Present but below the 16-char minimum -> invalid format.
        assert!(matches!(
            validate_webhook_options(&webhook_options(Some("short-id"), Some("secret-value"))),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config 'webhookId' has an invalid format"
        ));
        // Right length but a disallowed character (space) -> invalid format.
        assert!(matches!(
            validate_webhook_options(&webhook_options(Some("abcdefghij klmnop"), Some("s"))),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config 'webhookId' has an invalid format"
        ));
        // Valid id, but missing signingSecret -> third failure, exact Java message.
        assert!(matches!(
            validate_webhook_options(&webhook_options(Some("abcdefghijklmnop"), None)),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config requires a 'signingSecret' option"
        ));
        // Valid id, but whitespace-only signingSecret is treated as absent.
        assert!(matches!(
            validate_webhook_options(&webhook_options(Some("abcdefghijklmnop"), Some("  "))),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config requires a 'signingSecret' option"
        ));
        // Fully valid: 16-char id + non-blank secret.
        assert!(
            validate_webhook_options(&webhook_options(Some("abcdefghijklmnop"), Some("s"))).is_ok()
        );
    }

    #[test]
    fn webhook_id_format_enforces_length_bounds_and_charset() {
        let matches = |value: &str| webhook_id_regex().is_some_and(|regex| regex.is_match(value));
        // Length bounds: 16 and 128 inclusive; 15 and 129 rejected.
        assert!(matches(&"a".repeat(16)));
        assert!(matches(&"a".repeat(128)));
        assert!(!matches(&"a".repeat(15)));
        assert!(!matches(&"a".repeat(129)));
        // Full permitted charset (A-Za-z0-9_-) accepted.
        assert!(matches("AZaz09_-AZaz09_-"));
        // A disallowed char anywhere is rejected even at a valid length.
        assert!(!matches("abcdefghijklmno."));
        // Anchored end-to-end: an otherwise-valid token with a trailing newline
        // must not match (guards against `$`'s before-final-newline behaviour).
        assert!(!matches("abcdefghijklmnop\n"));
    }

    #[test]
    fn lexical_path_normalization_removes_dot_segments() {
        let normalized = normalize_path(Path::new("/srv/inbox/../outbox/./file"));
        assert_eq!(normalized, Path::new("/srv/outbox/file"));
    }

    #[test]
    fn implied_roots_add_local_server_storage_and_every_watched_folder() {
        let watched = vec![
            PathBuf::from("/srv/watched/one"),
            PathBuf::from("/srv/watched/../watched/two/."),
        ];
        let roots = implied_folder_roots(&storage(true, "local", "/srv/store/./data"), &watched);
        assert_eq!(roots.len(), 3);
        // Server storage is first and normalized to an absolute path.
        assert_eq!(roots[0].path, Path::new("/srv/store/data"));
        assert_eq!(roots[0].reason, "serverStorage");
        assert_eq!(roots[1].path, Path::new("/srv/watched/one"));
        assert_eq!(roots[1].reason, "watchedFolder");
        // Lexical `..`/`.` segments in a watched folder are normalized too.
        assert_eq!(roots[2].path, Path::new("/srv/watched/two"));
        assert_eq!(roots[2].reason, "watchedFolder");
    }

    #[test]
    fn implied_roots_skip_server_storage_unless_enabled_and_local() {
        // Disabled storage contributes no server-storage root.
        assert!(implied_folder_roots(&storage(false, "local", "/srv/store"), &[]).is_empty());
        // A non-local provider (e.g. S3) contributes no server-storage root.
        assert!(implied_folder_roots(&storage(true, "s3", "/srv/store"), &[]).is_empty());
        // A blank base path contributes no server-storage root.
        assert!(implied_folder_roots(&storage(true, "local", ""), &[]).is_empty());
        // Provider matching is case-insensitive, matching Java's equalsIgnoreCase.
        let roots = implied_folder_roots(&storage(true, "LOCAL", "/srv/store"), &[]);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].reason, "serverStorage");
    }

    #[test]
    fn implied_roots_skip_blank_watched_folders() {
        let watched = vec![PathBuf::new(), PathBuf::from("/srv/watched")];
        let roots = implied_folder_roots(&storage(false, "local", ""), &watched);
        assert_eq!(roots.len(), 1);
        assert_eq!(roots[0].path, Path::new("/srv/watched"));
    }

    #[test]
    fn folder_decision_rejects_paths_inside_the_protected_config_root() {
        assert!(matches!(
            folder_access_decision(
                Path::new("/srv/configs/secrets"),
                Path::new("/srv/configs"),
                &[implied("/srv/store", "serverStorage")],
                &[PathBuf::from("/srv/configs")],
            ),
            Err(PolicyFailure::BadRequest(message)) if message.contains("protected")
        ));
    }

    #[test]
    fn folder_decision_permits_implied_roots_even_with_no_allowlist() {
        // Watched-folder path is permitted despite an empty allowlist (the paired
        // parity fix: previously this returned "folder access is disabled").
        assert!(
            folder_access_decision(
                Path::new("/srv/watched/inbox/report.pdf"),
                Path::new("/srv/configs"),
                &[implied("/srv/watched", "watchedFolder")],
                &[],
            )
            .is_ok()
        );
        // A server-storage subtree is likewise permitted.
        assert!(
            folder_access_decision(
                Path::new("/srv/store/user/1"),
                Path::new("/srv/configs"),
                &[implied("/srv/store", "serverStorage")],
                &[],
            )
            .is_ok()
        );
    }

    #[test]
    fn folder_decision_reports_disabled_access_when_nothing_permits_it() {
        assert!(matches!(
            folder_access_decision(
                Path::new("/srv/elsewhere"),
                Path::new("/srv/configs"),
                &[implied("/srv/watched", "watchedFolder")],
                &[],
            ),
            Err(PolicyFailure::BadRequest(message)) if message.contains("folder access is disabled")
        ));
    }

    #[test]
    fn folder_decision_enforces_the_configured_allowlist() {
        let allowed = [PathBuf::from("/srv/allowed")];
        // Outside every allowed root and every implied root.
        assert!(matches!(
            folder_access_decision(
                Path::new("/srv/other/file"),
                Path::new("/srv/configs"),
                &[],
                &allowed,
            ),
            Err(PolicyFailure::BadRequest(message)) if message.contains("outside the allowed folder roots")
        ));
        // Inside an allowed root is permitted.
        assert!(
            folder_access_decision(
                Path::new("/srv/allowed/sub"),
                Path::new("/srv/configs"),
                &[],
                &allowed,
            )
            .is_ok()
        );
    }

    // TESTER: parity coverage for the endpoint method (not just the free fn) —
    // FolderAccessSettingsController.impliedFolderRoots is @PreAuthorize
    // hasRole('ADMIN') and projects each ImpliedRoot to {path, reason} with an
    // absolute path string.
    #[test]
    fn implied_roots_endpoint_is_admin_only_and_projects_path_and_reason()
    -> Result<(), PolicyFailure> {
        use super::PolicyConfigService;
        use crate::integration_config::IntegrationConfigService;
        use crate::resource_access::DefaultAccessPolicy;
        use crate::security::{AuthContext, AuthenticationSource, SecurityStore};
        use std::collections::BTreeSet;
        use std::sync::Arc;

        fn ctx<const N: usize>(roles: [&str; N]) -> AuthContext {
            AuthContext {
                user_id: 1,
                username: "user".to_owned(),
                authentication_source: AuthenticationSource::AccessToken,
                authentication_type: "web".to_owned(),
                roles: roles
                    .into_iter()
                    .map(str::to_owned)
                    .collect::<BTreeSet<_>>(),
                team_id: Some(1),
                permissions: BTreeSet::new(),
                external_subject: None,
                force_password_change: false,
                session_id: "session".to_owned(),
                correlation_id: "request".to_owned(),
            }
        }

        let store = Arc::new(SecurityStore::in_memory()?);
        let integrations = Arc::new(IntegrationConfigService::new(
            Arc::clone(&store),
            DefaultAccessPolicy::ExplicitOnly,
            false,
            false,
            false,
            false,
        ));
        let service = PolicyConfigService::new(
            store,
            integrations,
            Vec::new(),
            Path::new("/srv/configs"),
            vec![
                implied("/srv/store", "serverStorage"),
                implied("/srv/watched", "watchedFolder"),
            ],
        );

        // Non-admin is refused (maps to HTTP 403 via policy_error).
        assert!(matches!(
            service.list_implied_folder_roots(&ctx(["ROLE_USER"])),
            Err(PolicyFailure::Forbidden(_))
        ));

        // Admin sees each implied root projected as {path, reason}, absolute,
        // in insertion order (server storage first, then watched folders).
        let view = service.list_implied_folder_roots(&ctx(["ROLE_ADMIN"]))?;
        assert_eq!(view.len(), 2);
        assert_eq!(view[0].path, "/srv/store");
        assert_eq!(view[0].reason, "serverStorage");
        assert!(Path::new(&view[0].path).is_absolute());
        assert_eq!(view[1].path, "/srv/watched");
        assert_eq!(view[1].reason, "watchedFolder");
        assert!(Path::new(&view[1].path).is_absolute());
        Ok(())
    }

    // ---- TESTER: service-level webhook save/get round-trip parity ----
    // These cover SourceController.save's ordering (resolveOwnership ->
    // withStoredSecrets(merge) -> withPreparedOptions(mint/regen) -> validate ->
    // save -> revealOnCreate) plus SecretMasker mask/restore, which the free-fn
    // tests above cannot reach.

    fn webhook_admin_context() -> crate::security::AuthContext {
        crate::security::AuthContext {
            user_id: 1,
            username: "admin".to_owned(),
            authentication_source: crate::security::AuthenticationSource::AccessToken,
            authentication_type: "web".to_owned(),
            roles: ["ROLE_ADMIN"]
                .into_iter()
                .map(str::to_owned)
                .collect::<std::collections::BTreeSet<_>>(),
            team_id: Some(1),
            permissions: std::collections::BTreeSet::new(),
            external_subject: None,
            force_password_change: false,
            session_id: "session".to_owned(),
            correlation_id: "request".to_owned(),
        }
    }

    fn webhook_service(
        store: std::sync::Arc<crate::security::SecurityStore>,
    ) -> super::PolicyConfigService {
        let integrations =
            std::sync::Arc::new(crate::integration_config::IntegrationConfigService::new(
                std::sync::Arc::clone(&store),
                crate::resource_access::DefaultAccessPolicy::ExplicitOnly,
                false,
                false,
                false,
                false,
            ));
        super::PolicyConfigService::new(
            store,
            integrations,
            Vec::new(),
            Path::new("/srv/configs"),
            Vec::new(),
        )
    }

    fn webhook_source_input(id: &str, options: Map<String, Value>) -> super::PolicySource {
        super::PolicySource {
            id: id.to_owned(),
            name: "Inbound hook".to_owned(),
            source_type: "webhook".to_owned(),
            options,
            enabled: true,
            owner: None,
            team_id: None,
        }
    }

    fn option_str(source: &super::PolicySource, key: &str) -> Option<String> {
        source
            .options
            .get(key)
            .and_then(Value::as_str)
            .map(str::to_owned)
    }

    fn masked_options(webhook_id: &str) -> Map<String, Value> {
        let mut options = Map::new();
        options.insert("webhookId".to_owned(), Value::String(webhook_id.to_owned()));
        options.insert(
            "signingSecret".to_owned(),
            Value::String("********".to_owned()),
        );
        options
    }

    #[test]
    fn webhook_create_reveals_pair_get_masks_secret_and_merge_preserves_it()
    -> Result<(), PolicyFailure> {
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();

        // Create: the server mints the pair and the response reveals BOTH in the
        // clear exactly once (revealOnCreate), never the mask.
        let created = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let (Some(real_id), Some(real_secret)) = (
            option_str(&created, "webhookId"),
            option_str(&created, "signingSecret"),
        ) else {
            return Err(PolicyFailure::BadRequest(
                "create dropped webhook credentials".to_owned(),
            ));
        };
        assert_ne!(
            real_secret, "********",
            "create must reveal the real signing secret"
        );
        assert_eq!(real_id.len(), 24);
        assert_eq!(real_secret.len(), 43);
        assert!(
            validate_webhook_options(&webhook_options(Some(&real_id), Some(&real_secret))).is_ok()
        );
        let source_id = created.id.clone();

        // An immediate get masks the signingSecret but keeps the webhookId plaintext.
        let fetched = service.get_source(&source_id, &ctx)?;
        assert_eq!(
            option_str(&fetched, "webhookId").as_deref(),
            Some(real_id.as_str())
        );
        assert_eq!(
            option_str(&fetched, "signingSecret").as_deref(),
            Some("********")
        );

        // The persisted (decrypted) secret is the real one — the mask was a view.
        let persisted = service.get_source_for_run(&source_id, &ctx)?;
        assert_eq!(
            option_str(&persisted, "signingSecret").as_deref(),
            Some(real_secret.as_str())
        );

        // ADVERSARIAL: an update that posts the MASK back with the real webhookId
        // must preserve the stored secret via merge_config and never persist the
        // sentinel. Response for an update is masked (reveal only on create).
        let mut update = webhook_source_input(&source_id, masked_options(&real_id));
        update.name = "Renamed hook".to_owned();
        let updated = service.save_source(update, &ctx)?;
        assert_eq!(
            option_str(&updated, "signingSecret").as_deref(),
            Some("********")
        );
        assert_eq!(
            option_str(&updated, "webhookId").as_deref(),
            Some(real_id.as_str())
        );
        let after = service.get_source_for_run(&source_id, &ctx)?;
        assert_eq!(
            option_str(&after, "signingSecret").as_deref(),
            Some(real_secret.as_str())
        );
        assert_eq!(after.name, "Renamed hook");
        Ok(())
    }

    #[test]
    fn webhook_update_without_id_regenerates_pair_but_normal_update_keeps_it()
    -> Result<(), PolicyFailure> {
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();

        let created = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let source_id = created.id.clone();
        let first = service.get_source_for_run(&source_id, &ctx)?;
        let (Some(id1), Some(secret1)) = (
            option_str(&first, "webhookId"),
            option_str(&first, "signingSecret"),
        ) else {
            return Err(PolicyFailure::BadRequest("missing initial pair".to_owned()));
        };

        // Update carrying NO webhookId (only a masked secret) => regenerate a fresh
        // pair server-side (prepareOptionsForSave with hasId == false).
        let mut opts = Map::new();
        opts.insert(
            "signingSecret".to_owned(),
            Value::String("********".to_owned()),
        );
        service.save_source(webhook_source_input(&source_id, opts), &ctx)?;
        let regen = service.get_source_for_run(&source_id, &ctx)?;
        let (Some(id2), Some(secret2)) = (
            option_str(&regen, "webhookId"),
            option_str(&regen, "signingSecret"),
        ) else {
            return Err(PolicyFailure::BadRequest(
                "regen dropped the pair".to_owned(),
            ));
        };
        assert_ne!(id1, id2, "no-id update must mint a fresh webhookId");
        assert_ne!(
            secret1, secret2,
            "no-id update must mint a fresh signingSecret"
        );
        assert!(validate_webhook_options(&webhook_options(Some(&id2), Some(&secret2))).is_ok());

        // Normal update WITH the current id + masked secret keeps the pair intact.
        service.save_source(webhook_source_input(&source_id, masked_options(&id2)), &ctx)?;
        let kept = service.get_source_for_run(&source_id, &ctx)?;
        assert_eq!(
            option_str(&kept, "webhookId").as_deref(),
            Some(id2.as_str())
        );
        assert_eq!(
            option_str(&kept, "signingSecret").as_deref(),
            Some(secret2.as_str())
        );
        Ok(())
    }

    #[test]
    fn webhook_rejects_directory_traversal_characters_in_webhook_id() -> Result<(), PolicyFailure> {
        // The regex is the spool's traversal guard: '.', '/', '\' are outside
        // [A-Za-z0-9_-] and must be rejected with the exact invalid-format message.
        for bad in [
            "abcdefghij.klmnop",
            "abcdefghij/klmnop",
            "abcdefghij\\klmnop",
            "../../secrets/xx",
        ] {
            assert!(
                matches!(
                    validate_webhook_options(&webhook_options(Some(bad), Some("secret"))),
                    Err(PolicyFailure::BadRequest(message))
                        if message == "webhook config 'webhookId' has an invalid format"
                ),
                "expected {bad} rejected as invalid format"
            );
        }

        // End-to-end: an UPDATE that supplies a present-but-malicious webhookId is
        // NOT regenerated (hasId is true) and must be rejected by validate_source
        // before anything is persisted.
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();
        let created = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let source_id = created.id.clone();
        let mut opts = Map::new();
        opts.insert(
            "webhookId".to_owned(),
            Value::String("../../secrets/xx".to_owned()),
        );
        opts.insert(
            "signingSecret".to_owned(),
            Value::String("real-secret".to_owned()),
        );
        assert!(matches!(
            service.save_source(webhook_source_input(&source_id, opts), &ctx),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook config 'webhookId' has an invalid format"
        ));
        Ok(())
    }

    #[test]
    fn webhook_signing_secret_is_encrypted_at_rest_never_plaintext()
    -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let database = directory.path().join("security.db");
        let store = std::sync::Arc::new(crate::security::SecurityStore::open_protected(
            &database,
            crate::security_crypto::ProtectedSecretCipher::random(),
        )?);
        let service = webhook_service(std::sync::Arc::clone(&store));
        let ctx = webhook_admin_context();

        let created = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let source_id = created.id.clone();
        let Some(real_secret) = option_str(&created, "signingSecret") else {
            return Err("create dropped signingSecret".into());
        };

        // The raw on-disk column must NOT contain the plaintext secret nor even the
        // option keys — the whole source_json is inside the encrypted blob.
        let raw = rusqlite::Connection::open(&database)?;
        let stored: String = raw.query_row(
            "SELECT source_json FROM policy_sources WHERE id = ?1",
            [&source_id],
            |row| row.get(0),
        )?;
        assert!(
            !stored.contains(&real_secret),
            "signing secret leaked to disk in plaintext"
        );
        assert!(
            !stored.contains("signingSecret"),
            "option keys leaked to disk in plaintext"
        );

        // ...yet it round-trips back to the real secret through the cipher.
        let persisted = service.get_source_for_run(&source_id, &ctx)?;
        assert_eq!(
            option_str(&persisted, "signingSecret").as_deref(),
            Some(real_secret.as_str())
        );
        Ok(())
    }

    // ---- TESTER (WB): webhook TRIGGER validation + delivery reference matching ----
    // Parity target: WebhookTrigger.validate (requires a webhook source) and
    // WebhookTrigger.referencesWebhook / fireForWebhook's policy selection
    // (findByTriggerType(TYPE) + referencesWebhook by stored webhookId).

    fn webhook_policy_input(source_ids: Vec<String>, enabled: bool) -> super::PolicyDefinition {
        super::PolicyDefinition {
            id: String::new(),
            name: "Inbound pipeline".to_owned(),
            owner: None,
            enabled,
            trigger: Some(super::TriggerConfig {
                trigger_type: "webhook".to_owned(),
                options: Map::new(),
            }),
            source_ids,
            steps: Vec::new(),
            output: super::OutputSpec::default(),
            team_id: None,
        }
    }

    #[test]
    fn webhook_trigger_requires_a_webhook_input_source() -> Result<(), PolicyFailure> {
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();

        // No input sources at all: the webhook arm finds nothing to accept and
        // rejects with the exact Java message (WebhookTrigger.validate).
        assert!(matches!(
            service.save_policy(webhook_policy_input(Vec::new(), true), &ctx),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook trigger requires at least one webhook input source"
        ));

        // A webhook input source flips the same policy to valid (success arm).
        let source = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let saved =
            service.save_policy(webhook_policy_input(vec![source.id.clone()], true), &ctx)?;
        assert_eq!(saved.source_ids, vec![source.id]);
        Ok(())
    }

    #[test]
    fn webhook_trigger_rejects_a_source_from_another_team() -> Result<(), PolicyFailure> {
        // validate_trigger filters candidate sources through can_access_team, so a
        // webhook source owned by a different team cannot satisfy the requirement.
        // Exercised directly (save_policy's own source-ownership pre-check would
        // otherwise reject the foreign source before the trigger arm is reached).
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(std::sync::Arc::clone(&store));
        let ctx = webhook_admin_context();
        let source = service.save_source(webhook_source_input("", Map::new()), &ctx)?;

        // Re-persist the same source under a foreign team directly in the store.
        let mut foreign = store
            .get_policy_source(&source.id)?
            .ok_or_else(|| PolicyFailure::BadRequest("source vanished".to_owned()))?;
        foreign.team_id = Some(999);
        store.save_policy_source(&foreign)?;

        let policy = webhook_policy_input(vec![source.id], true);
        assert!(matches!(
            service.validate_trigger(&policy, &ctx),
            Err(PolicyFailure::BadRequest(message))
                if message == "webhook trigger requires at least one webhook input source"
        ));
        Ok(())
    }

    #[test]
    fn policy_references_webhook_matches_only_the_delivered_id() -> Result<(), PolicyFailure> {
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();

        let created = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let real_id = option_str(&created, "webhookId")
            .ok_or_else(|| PolicyFailure::BadRequest("create dropped webhookId".to_owned()))?;
        let policy =
            service.save_policy(webhook_policy_input(vec![created.id.clone()], true), &ctx)?;

        // The delivered id matches (no team filter — a delivery is authenticated by
        // its signed id, mirroring referencesWebhook via sourceStore.get).
        assert!(service.policy_references_webhook(&policy, &real_id)?);
        // A different id never matches (ignoresADeliveryForAnUnknownWebhookId).
        assert!(!service.policy_references_webhook(&policy, "whkZ-unknown-000000")?);
        // A dangling source id references nothing rather than erroring.
        let dangling = webhook_policy_input(vec!["no-such-source".to_owned()], true);
        assert!(!service.policy_references_webhook(&dangling, &real_id)?);
        Ok(())
    }

    #[test]
    fn find_webhook_source_scans_all_sources_and_returns_the_decrypted_secret()
    -> Result<(), PolicyFailure> {
        // Parity with WebhookReceiverController.findWebhookSource: scan every
        // persisted source (no team filter), match type == "webhook" and the raw
        // stored webhookId, and hand back DECRYPTED options so the receiver can
        // read signingSecret. A disabled source is still resolvable — the receiver
        // itself decides how to treat `enabled`.
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();

        // A non-webhook decoy plus the real webhook source.
        let created = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let real_id = option_str(&created, "webhookId")
            .ok_or_else(|| PolicyFailure::BadRequest("create dropped webhookId".to_owned()))?;
        let real_secret = option_str(&created, "signingSecret")
            .ok_or_else(|| PolicyFailure::BadRequest("create dropped secret".to_owned()))?;

        let found = service
            .find_webhook_source(&real_id)?
            .ok_or_else(|| PolicyFailure::NotFound("webhook source not found".to_owned()))?;
        assert_eq!(found.source_type, "webhook");
        assert_eq!(
            option_str(&found, "webhookId").as_deref(),
            Some(real_id.as_str())
        );
        // The DECRYPTED secret is returned (never the "********" get-mask).
        assert_eq!(
            option_str(&found, "signingSecret").as_deref(),
            Some(real_secret.as_str())
        );

        // An unknown id resolves to nothing rather than erroring.
        assert!(
            service
                .find_webhook_source("whkZ-unknown-000000")?
                .is_none()
        );
        Ok(())
    }

    #[test]
    fn policies_for_trigger_returns_only_enabled_webhook_policies() -> Result<(), PolicyFailure> {
        // fireForWebhook / the reconcile loop iterate policies_for_trigger("webhook"),
        // which must be enabled-only (findByTriggerTypeAndEnabledTrue) and exclude
        // other trigger types.
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();

        let source = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let enabled =
            service.save_policy(webhook_policy_input(vec![source.id.clone()], true), &ctx)?;
        // A disabled webhook policy still validates but must not be fired.
        service.save_policy(webhook_policy_input(vec![source.id], false), &ctx)?;

        let fired = service.policies_for_trigger("webhook")?;
        assert_eq!(fired.len(), 1);
        assert_eq!(fired[0].id, enabled.id);
        // A non-webhook trigger type returns none of them.
        assert!(service.policies_for_trigger("schedule")?.is_empty());
        Ok(())
    }

    #[test]
    fn every_enabled_policy_sharing_a_webhook_id_is_selected_and_matches()
    -> Result<(), PolicyFailure> {
        // Models fire_for_webhook's fan-out: it dispatches EVERY enabled webhook
        // policy that referencesWebhook(id). Two enabled policies bound to the same
        // webhook source must BOTH be selected (policies_for_trigger, enabled-only)
        // AND both reference-match the delivered id, while a disabled third policy on
        // the identical webhook is silently dropped (never fired). Parity with
        // WebhookTrigger.fireForWebhook over findByTriggerTypeAndEnabledTrue.
        let store = std::sync::Arc::new(crate::security::SecurityStore::in_memory()?);
        let service = webhook_service(store);
        let ctx = webhook_admin_context();

        let source = service.save_source(webhook_source_input("", Map::new()), &ctx)?;
        let real_id = option_str(&source, "webhookId")
            .ok_or_else(|| PolicyFailure::BadRequest("create dropped webhookId".to_owned()))?;

        let first =
            service.save_policy(webhook_policy_input(vec![source.id.clone()], true), &ctx)?;
        let second =
            service.save_policy(webhook_policy_input(vec![source.id.clone()], true), &ctx)?;
        // A disabled sibling on the SAME webhook id: enabled-only selection excludes it
        // even though it would reference-match, so it can never be dispatched.
        let disabled = service.save_policy(webhook_policy_input(vec![source.id], false), &ctx)?;

        let selected = service.policies_for_trigger("webhook")?;
        let selected_ids = selected
            .iter()
            .map(|policy| policy.id.clone())
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(selected.len(), 2, "only the two enabled policies are fired");
        assert!(selected_ids.contains(&first.id));
        assert!(selected_ids.contains(&second.id));
        assert!(
            !selected_ids.contains(&disabled.id),
            "disabled webhook policy must never be selected for dispatch"
        );
        // Both selected policies reference-match the delivered id, so fire_for_webhook
        // would dispatch each of them (no team scope — raw source-store lookup).
        for policy in &selected {
            assert!(service.policy_references_webhook(policy, &real_id)?);
        }
        Ok(())
    }

    // ---- TESTER: integration-step confused-deputy guard (IntegrationStepValidator) ----

    fn step(operation: &str, parameters: Map<String, Value>) -> super::PolicyStep {
        super::PolicyStep {
            operation: operation.to_owned(),
            parameters,
            ..Default::default()
        }
    }

    fn connection_param(value: Value) -> Map<String, Value> {
        let mut parameters = Map::new();
        parameters.insert("connectionId".to_owned(), value);
        parameters
    }

    #[test]
    fn integration_step_type_lists_the_ported_subset() {
        use super::{IntegrationType, integration_step_type};
        // external-api-call is ported (slice 4) and maps to the API connection type.
        assert_eq!(
            integration_step_type("/api/v1/integration/external-api-call"),
            Some(IntegrationType::Api)
        );
        assert_eq!(
            integration_step_type("/api/v1/integration/purview-apply-label"),
            Some(IntegrationType::Purview)
        );
        assert_eq!(
            integration_step_type("/api/v1/integration/purview-read-label"),
            Some(IntegrationType::Purview)
        );
        // Java maps consigno-* too, but they have no dedicated port (reached via the
        // generic external-api-call bodyTemplate): they must miss the registry so the
        // guard fails them closed rather than resolving an absent connection type.
        assert_eq!(
            integration_step_type("/api/v1/integration/consigno-submit"),
            None
        );
        assert_eq!(
            integration_step_type("/api/v1/integration/consigno-fetch-signed"),
            None
        );
        assert_eq!(integration_step_type("/api/v1/misc/compress-pdf"), None);
    }

    #[test]
    fn step_connection_id_mirrors_api_connection_resolver_parsing() {
        use super::step_connection_id;
        // Absent, JSON null, and blank/whitespace strings all read as "no id" (None),
        // which the caller turns into the requires-parameter error.
        assert!(matches!(step_connection_id(None), Ok(None)));
        assert!(matches!(step_connection_id(Some(&Value::Null)), Ok(None)));
        assert!(matches!(
            step_connection_id(Some(&Value::String(String::new()))),
            Ok(None)
        ));
        assert!(matches!(
            step_connection_id(Some(&Value::String("   ".to_owned()))),
            Ok(None)
        ));
        // A JSON number resolves directly; a numeric string (the form-field shape)
        // resolves after trimming; negatives are preserved.
        assert!(matches!(
            step_connection_id(Some(&Value::from(42))),
            Ok(Some(42))
        ));
        assert!(matches!(
            step_connection_id(Some(&Value::String("42".to_owned()))),
            Ok(Some(42))
        ));
        assert!(matches!(
            step_connection_id(Some(&Value::String("  7 ".to_owned()))),
            Ok(Some(7))
        ));
        assert!(matches!(
            step_connection_id(Some(&Value::from(-3))),
            Ok(Some(-3))
        ));
        // Non-numeric strings and non-scalar values are invalid references; the raw
        // string shows without quotes (Java concatenates the Object's toString).
        assert!(matches!(
            step_connection_id(Some(&Value::String("abc".to_owned()))),
            Err(PolicyFailure::BadRequest(message))
                if message == "'connectionId' is not a valid connection reference: abc"
        ));
        assert!(matches!(
            step_connection_id(Some(&Value::Object(Map::new()))),
            Err(PolicyFailure::BadRequest(message))
                if message == "'connectionId' is not a valid connection reference: {}"
        ));
        assert!(matches!(
            step_connection_id(Some(&Value::Bool(true))),
            Err(PolicyFailure::BadRequest(message))
                if message == "'connectionId' is not a valid connection reference: true"
        ));
    }

    #[test]
    fn integration_step_classification_skips_non_integration_and_fails_closed() {
        use super::integration_step_connection;
        // A non-integration operation is skipped entirely — no connectionId required.
        assert!(matches!(
            integration_step_connection(&step("/api/v1/misc/compress-pdf", Map::new())),
            Ok(None)
        ));
        // A prefixed but unregistered endpoint (Consigno / external-api are unported)
        // fails closed with the exact Java message.
        assert!(matches!(
            integration_step_connection(&step(
                "/api/v1/integration/consigno-submit",
                connection_param(Value::from(1)),
            )),
            Err(PolicyFailure::BadRequest(message))
                if message == "unknown integration step: /api/v1/integration/consigno-submit"
        ));
        // A registered step missing its connectionId reports the required-parameter
        // error (Java's post-`connectionId(...)` null check), byte-for-byte.
        assert!(matches!(
            integration_step_connection(&step(
                "/api/v1/integration/purview-apply-label",
                Map::new(),
            )),
            Err(PolicyFailure::BadRequest(message))
                if message
                    == "/api/v1/integration/purview-apply-label requires a 'connectionId' parameter"
        ));
        // A blank-string connectionId reads as absent -> same required-parameter error.
        assert!(matches!(
            integration_step_connection(&step(
                "/api/v1/integration/purview-read-label",
                connection_param(Value::String("  ".to_owned())),
            )),
            Err(PolicyFailure::BadRequest(message))
                if message
                    == "/api/v1/integration/purview-read-label requires a 'connectionId' parameter"
        ));
        // A well-formed step surfaces the (id, type) pair the caller then authz-checks.
        assert!(matches!(
            integration_step_connection(&step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::from(99)),
            )),
            Ok(Some((99, super::IntegrationType::Purview)))
        ));
    }

    #[test]
    fn validate_steps_runs_the_resolve_authz_check() -> Result<(), PolicyFailure> {
        use super::{IntegrationType, PolicyConfigService, policy_integration_error};
        use crate::integration_config::{IntegrationConfigRequest, IntegrationConfigService};
        use crate::resource_access::{DefaultAccessPolicy, OwnerScope};
        use crate::security::SecurityStore;
        use std::sync::Arc;

        let store = Arc::new(SecurityStore::in_memory()?);
        let integrations = Arc::new(IntegrationConfigService::new(
            Arc::clone(&store),
            DefaultAccessPolicy::ExplicitOnly,
            false,
            false,
            false,
            false,
        ));
        let ctx = webhook_admin_context();

        // A SERVER-scoped Purview connection (server scope leaves owner ids null so the
        // in-memory user FK is not exercised); enabled by default and usable by an admin.
        let mut config = Map::new();
        config.insert(
            "tenantId".to_owned(),
            Value::String("CB46C030-1825-4E81-A295-151C039DBF02".to_owned()),
        );
        integrations
            .create(
                IntegrationConfigRequest {
                    integration_type: Some(IntegrationType::Purview),
                    name: Some("tenant".to_owned()),
                    scope: Some(OwnerScope::Server),
                    config: Some(config),
                    ..Default::default()
                },
                &ctx,
            )
            .map_err(policy_integration_error)?;
        let connection_id = store.list_integration_configs()?[0].id;

        let service = PolicyConfigService::new(
            Arc::clone(&store),
            Arc::clone(&integrations),
            Vec::new(),
            Path::new("/srv/configs"),
            Vec::new(),
        );

        // Non-integration steps require no connection and pass.
        service.validate_steps(&[step("/api/v1/misc/compress-pdf", Map::new())], &ctx)?;

        // A purview step naming the owned+enabled connection resolves cleanly, by a
        // numeric id and by the equivalent numeric string.
        service.validate_steps(
            &[step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::from(connection_id)),
            )],
            &ctx,
        )?;
        service.validate_steps(
            &[step(
                "/api/v1/integration/purview-read-label",
                connection_param(Value::String(connection_id.to_string())),
            )],
            &ctx,
        )?;

        // ADVERSARIAL confused deputy: naming a connection id that does not exist
        // collapses into the opaque resolve error, proving resolve_config actually runs
        // and that its failure maps through policy_integration_error to a 400.
        assert!(matches!(
            service.validate_steps(
                &[step(
                    "/api/v1/integration/purview-apply-label",
                    connection_param(Value::from(connection_id + 9_999)),
                )],
                &ctx,
            ),
            Err(PolicyFailure::BadRequest(message))
                if message == "unknown or inaccessible purview connection"
        ));

        // An unported prefixed endpoint fails closed BEFORE any resolve.
        assert!(matches!(
            service.validate_steps(
                &[step(
                    "/api/v1/integration/consigno-submit",
                    connection_param(Value::from(connection_id)),
                )],
                &ctx,
            ),
            Err(PolicyFailure::BadRequest(message))
                if message == "unknown integration step: /api/v1/integration/consigno-submit"
        ));
        Ok(())
    }

    // ---- TESTER: end-to-end save_policy parity for the confused-deputy step guard ----
    // These drive the guard through the real save_policy entry point (not the free fn) so
    // they also prove a rejected step leaves NOTHING persisted and that the guard re-runs on
    // every save — the actual PolicyValidator.validate contract.

    fn seed_connection(
        integration_type: super::IntegrationType,
        enabled: bool,
    ) -> crate::integration_config::NewIntegrationConfig {
        use crate::resource_access::{DefaultAccessPolicy, OwnerScope};
        let mut config = Map::new();
        config.insert("tenantId".to_owned(), Value::String("tenant".to_owned()));
        crate::integration_config::NewIntegrationConfig {
            integration_type,
            name: "seeded".to_owned(),
            // Server scope leaves the owner ids null so the in-memory user FK is not exercised.
            scope: OwnerScope::Server,
            owner_user_id: None,
            owner_team_id: None,
            enabled,
            locked: false,
            // EXPLICIT_ONLY: nobody but an admin/owner/grantee may use it, so a non-admin
            // stranger is genuinely locked out (foreign-connection parity).
            default_access: DefaultAccessPolicy::ExplicitOnly,
            config,
        }
    }

    fn policy_with_step(policy_step: super::PolicyStep) -> super::PolicyDefinition {
        super::PolicyDefinition {
            id: String::new(),
            name: "Labeling pipeline".to_owned(),
            owner: None,
            enabled: false,
            trigger: None,
            source_ids: Vec::new(),
            steps: vec![policy_step],
            output: super::OutputSpec::default(),
            team_id: None,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn save_policy_gates_integration_steps_and_never_persists_a_rejected_one()
    -> Result<(), PolicyFailure> {
        use super::IntegrationType;
        use crate::security::SecurityStore;
        use std::sync::Arc;

        let store = Arc::new(SecurityStore::in_memory()?);
        // An enabled Purview connection (accept target), an enabled API connection
        // (accept target for the external-api-call step), a same-scope S3 decoy (wrong
        // type), and a disabled Purview connection — all resolvable by id, seeded directly.
        let purview =
            store.create_integration_config(&seed_connection(IntegrationType::Purview, true))?;
        let api = store.create_integration_config(&seed_connection(IntegrationType::Api, true))?;
        let s3 = store.create_integration_config(&seed_connection(IntegrationType::S3, true))?;
        let disabled =
            store.create_integration_config(&seed_connection(IntegrationType::Purview, false))?;
        let service = webhook_service(Arc::clone(&store));
        let ctx = webhook_admin_context();

        // ACCEPT: a purview step naming the enabled connection persists and round-trips out.
        let saved = service.save_policy(
            policy_with_step(step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::from(purview.id)),
            )),
            &ctx,
        )?;
        assert!(!saved.id.is_empty());
        assert_eq!(service.get_policy(&saved.id, &ctx)?.id, saved.id);
        // ACCEPT: the now-ported external-api-call step against the enabled API connection
        // persists too — the previously fail-closed divergence is closed (slice 4).
        let saved_api = service.save_policy(
            policy_with_step(step(
                "/api/v1/integration/external-api-call",
                connection_param(Value::from(api.id)),
            )),
            &ctx,
        )?;
        assert!(!saved_api.id.is_empty());
        let baseline = service.list_policies(&ctx)?.len();

        let reject = |def: super::PolicyDefinition, expected: &str| -> Result<(), PolicyFailure> {
            match service.save_policy(def, &ctx) {
                Err(PolicyFailure::BadRequest(message)) => {
                    assert_eq!(message.as_str(), expected, "wrong rejection message");
                }
                other => panic!("expected BadRequest({expected:?}), got {other:?}"),
            }
            assert_eq!(
                service.list_policies(&ctx)?.len(),
                baseline,
                "a rejected policy must never be persisted"
            );
            Ok(())
        };

        // REJECT wrong type: a purview step naming the S3 connection collapses into the SAME
        // opaque error as a missing one (anti-enumeration) — resolve_config's type filter.
        reject(
            policy_with_step(step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::from(s3.id)),
            )),
            "unknown or inaccessible purview connection",
        )?;
        // REJECT disabled: the port folds Java's distinct "disabled" message into the opaque one.
        reject(
            policy_with_step(step(
                "/api/v1/integration/purview-read-label",
                connection_param(Value::from(disabled.id)),
            )),
            "unknown or inaccessible purview connection",
        )?;
        // REJECT non-existent id -> opaque.
        reject(
            policy_with_step(step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::from(purview.id + 9_999)),
            )),
            "unknown or inaccessible purview connection",
        )?;
        // REJECT missing connectionId -> the required-parameter error (Java's null check).
        reject(
            policy_with_step(step("/api/v1/integration/purview-apply-label", Map::new())),
            "/api/v1/integration/purview-apply-label requires a 'connectionId' parameter",
        )?;
        // REJECT non-numeric connectionId -> invalid-reference, raw value shown without quotes.
        reject(
            policy_with_step(step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::String("not-an-id".to_owned())),
            )),
            "'connectionId' is not a valid connection reference: not-an-id",
        )?;
        // REJECT wrong type for the (now-ported) external-api-call step: naming the PURVIEW
        // connection resolves it as an API step, finds the type mismatch, and collapses into
        // the SAME opaque error as a missing one (anti-enumeration) — proving the confused-deputy
        // guard runs for external-api-call rather than waving it through.
        reject(
            policy_with_step(step(
                "/api/v1/integration/external-api-call",
                connection_param(Value::from(purview.id)),
            )),
            "unknown or inaccessible api connection",
        )?;
        // REJECT a genuinely unported prefixed endpoint -> fails closed (consigno-* has no port).
        reject(
            policy_with_step(step(
                "/api/v1/integration/consigno-submit",
                connection_param(Value::from(api.id)),
            )),
            "unknown integration step: /api/v1/integration/consigno-submit",
        )?;

        // ACCEPT: a non-integration operation is skipped entirely (persists with no connection).
        let compress = service.save_policy(
            policy_with_step(step("/api/v1/misc/compress-pdf", Map::new())),
            &ctx,
        )?;
        assert!(!compress.id.is_empty());
        // PARSE PARITY end-to-end: a numeric-STRING connectionId resolves exactly like the number.
        let via_string = service.save_policy(
            policy_with_step(step(
                "/api/v1/integration/purview-read-label",
                connection_param(Value::String(purview.id.to_string())),
            )),
            &ctx,
        )?;
        assert!(!via_string.id.is_empty());
        Ok(())
    }

    #[test]
    fn save_policy_revalidates_steps_on_every_save_not_just_create() -> Result<(), PolicyFailure> {
        use super::IntegrationType;
        use crate::security::SecurityStore;
        use std::sync::Arc;

        let store = Arc::new(SecurityStore::in_memory()?);
        let purview =
            store.create_integration_config(&seed_connection(IntegrationType::Purview, true))?;
        let service = webhook_service(Arc::clone(&store));
        let ctx = webhook_admin_context();

        // First save succeeds against the enabled connection.
        let saved = service.save_policy(
            policy_with_step(step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::from(purview.id)),
            )),
            &ctx,
        )?;

        // The connection is disabled out from under the stored policy.
        let mut flip = store
            .get_integration_config(purview.id)?
            .ok_or_else(|| PolicyFailure::BadRequest("connection vanished".to_owned()))?;
        flip.enabled = false;
        store.update_integration_config(&flip)?;

        // Re-saving the SAME policy re-runs validate_steps and now rejects: the guard fires on
        // every save, not only on create (parity with PolicyValidator.validate being unconditional).
        let mut resave = policy_with_step(step(
            "/api/v1/integration/purview-apply-label",
            connection_param(Value::from(purview.id)),
        ));
        resave.id = saved.id.clone();
        resave.name = "Renamed".to_owned();
        assert!(matches!(
            service.save_policy(resave, &ctx),
            Err(PolicyFailure::BadRequest(message))
                if message == "unknown or inaccessible purview connection"
        ));
        // The rejected re-save left the stored policy untouched (original name preserved).
        assert_eq!(
            service.get_policy(&saved.id, &ctx)?.name,
            "Labeling pipeline"
        );
        Ok(())
    }

    #[test]
    fn validate_steps_rejects_a_connection_the_caller_may_not_use() -> Result<(), PolicyFailure> {
        use super::IntegrationType;
        use crate::security::{AuthContext, AuthenticationSource, SecurityStore};
        use std::collections::BTreeSet;
        use std::sync::Arc;

        let store = Arc::new(SecurityStore::in_memory()?);
        // Enabled + EXPLICIT_ONLY: only an admin/owner/grantee may use it.
        let purview =
            store.create_integration_config(&seed_connection(IntegrationType::Purview, true))?;
        let service = webhook_service(Arc::clone(&store));

        // A plain non-admin, non-owner, un-granted user: is_admin false, is_owner false (null
        // owner ids), no grant, EXPLICIT_ONLY -> can_use false -> the resolve authz check
        // collapses to the opaque error (confused-deputy foreign-connection parity).
        let stranger = AuthContext {
            user_id: 7,
            username: "stranger".to_owned(),
            authentication_source: AuthenticationSource::AccessToken,
            authentication_type: "web".to_owned(),
            roles: ["ROLE_USER"]
                .into_iter()
                .map(str::to_owned)
                .collect::<BTreeSet<_>>(),
            team_id: Some(1),
            permissions: BTreeSet::new(),
            external_subject: None,
            force_password_change: false,
            session_id: "session".to_owned(),
            correlation_id: "request".to_owned(),
        };
        assert!(matches!(
            service.validate_steps(
                &[step(
                    "/api/v1/integration/purview-apply-label",
                    connection_param(Value::from(purview.id)),
                )],
                &stranger,
            ),
            Err(PolicyFailure::BadRequest(message))
                if message == "unknown or inaccessible purview connection"
        ));

        // Sanity: an admin CAN use the very same connection (is_admin short-circuit), proving the
        // rejection above is the ownership check and not a broken/absent connection.
        service.validate_steps(
            &[step(
                "/api/v1/integration/purview-apply-label",
                connection_param(Value::from(purview.id)),
            )],
            &webhook_admin_context(),
        )?;
        Ok(())
    }
}
