//! Durable policy/source definitions and their reviewed secured-mode rules.

use std::{
    collections::{BTreeMap, HashMap},
    path::{Component, Path, PathBuf},
    sync::Arc,
};

use rand::RngExt as _;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    integration_config::{IntegrationConfigService, IntegrationFailure, mask_config, merge_config},
    policy_ledger::ProcessedLedger,
    security::{AuthContext, SecurityError, SecurityStore},
};

const EDITOR_ID: &str = "editor";
const EDITOR_TYPE: &str = "editor";
const MAX_POLICY_JSON_BYTES: usize = 1024 * 1024;

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
}

impl PolicyConfigService {
    pub(crate) fn new(
        store: Arc<SecurityStore>,
        integrations: Arc<IntegrationConfigService>,
        allowed_folder_roots: Vec<PathBuf>,
        protected_config_root: &Path,
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
        }
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
        self.validate_source(&incoming, context)?;
        validate_serialized_size(&incoming)?;
        self.store.save_policy_source(&incoming)?;
        Ok(mask_source(incoming))
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
            value => Err(PolicyFailure::BadRequest(format!(
                "unknown source type: {value}"
            ))),
        }
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
        if directory.starts_with(&self.protected_config_root) {
            return Err(PolicyFailure::BadRequest(
                "folder may not point inside a protected Stirling directory".to_owned(),
            ));
        }
        if self.allowed_folder_roots.is_empty() {
            return Err(PolicyFailure::BadRequest(
                "folder access is disabled; set policies.allowedFolderRoots to permit it"
                    .to_owned(),
            ));
        }
        if !self
            .allowed_folder_roots
            .iter()
            .any(|root| directory.starts_with(root))
        {
            return Err(PolicyFailure::BadRequest(format!(
                "folder '{}' is outside the allowed folder roots",
                directory.display()
            )));
        }
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
    use super::{new_uuid_v4, normalize_path};
    use std::path::Path;

    #[test]
    fn ids_are_rfc_4122_version_four_shape() {
        let id = new_uuid_v4();
        assert_eq!(id.len(), 36);
        assert_eq!(&id[14..15], "4");
        assert!(matches!(&id[19..20], "8" | "9" | "a" | "b"));
    }

    #[test]
    fn lexical_path_normalization_removes_dot_segments() {
        let normalized = normalize_path(Path::new("/srv/inbox/../outbox/./file"));
        assert_eq!(normalized, Path::new("/srv/outbox/file"));
    }
}
