//! Reviewed-security persistence and authorization for named integration configs.

use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr, ToSocketAddrs as _},
    sync::Arc,
};

use reqwest::Url;
use serde::{Deserialize, Serialize};
use serde_json::{Map, Value};
use thiserror::Error;

use crate::{
    purview::{PurviewConfigError, PurviewConnectionSettings},
    resource_access::{
        DefaultAccessPolicy, OwnerRef, OwnerScope, PrincipalType, ResourceAccessError,
        ResourceAccessService, ResourceType,
    },
    security::{AuthContext, SecurityError, SecurityStore},
};

const SECRET_MASK: &str = "********";
const MAX_CONFIG_DEPTH: usize = 32;
const MAX_CONFIG_BYTES: usize = 1024 * 1024;
const SENSITIVE_HINTS: &[&str] = &[
    "secret",
    "password",
    "passphrase",
    "pwd",
    "token",
    "apikey",
    "accesskey",
    "credential",
    "privatekey",
    "authorization",
    "cookie",
    "session",
    "connectionstring",
    "bearer",
    "signature",
];

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum IntegrationType {
    S3,
    Mcp,
    Api,
    /// Microsoft Purview Information Protection: sensitivity-label taxonomy via Graph.
    Purview,
}

impl IntegrationType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::S3 => "S3",
            Self::Mcp => "MCP",
            Self::Api => "API",
            Self::Purview => "PURVIEW",
        }
    }

    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "S3" => Some(Self::S3),
            "MCP" => Some(Self::Mcp),
            "API" => Some(Self::Api),
            "PURVIEW" => Some(Self::Purview),
            _ => None,
        }
    }
}

#[derive(Clone, Debug)]
pub(crate) struct IntegrationConfig {
    pub(crate) id: i64,
    pub(crate) integration_type: IntegrationType,
    pub(crate) name: String,
    pub(crate) scope: OwnerScope,
    pub(crate) owner_user_id: Option<i64>,
    pub(crate) owner_team_id: Option<i64>,
    pub(crate) enabled: bool,
    pub(crate) locked: bool,
    pub(crate) default_access: DefaultAccessPolicy,
    pub(crate) config: Map<String, Value>,
    pub(crate) created_at: String,
    pub(crate) updated_at: String,
}

#[derive(Clone, Debug)]
pub(crate) struct NewIntegrationConfig {
    pub(crate) integration_type: IntegrationType,
    pub(crate) name: String,
    pub(crate) scope: OwnerScope,
    pub(crate) owner_user_id: Option<i64>,
    pub(crate) owner_team_id: Option<i64>,
    pub(crate) enabled: bool,
    pub(crate) locked: bool,
    pub(crate) default_access: DefaultAccessPolicy,
    pub(crate) config: Map<String, Value>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrationConfigRequest {
    pub(crate) integration_type: Option<IntegrationType>,
    pub(crate) name: Option<String>,
    pub(crate) scope: Option<OwnerScope>,
    pub(crate) owner_team_id: Option<i64>,
    pub(crate) enabled: Option<bool>,
    pub(crate) locked: Option<bool>,
    pub(crate) default_access: Option<DefaultAccessPolicy>,
    pub(crate) config: Option<Map<String, Value>>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct IntegrationConfigResponse {
    id: i64,
    integration_type: IntegrationType,
    name: String,
    scope: OwnerScope,
    owner_user_id: Option<i64>,
    owner_team_id: Option<i64>,
    enabled: bool,
    locked: bool,
    default_access: DefaultAccessPolicy,
    config: Map<String, Value>,
    can_manage: bool,
    created_at: String,
    updated_at: String,
}

#[derive(Debug, Error)]
pub(crate) enum IntegrationFailure {
    #[error("{0}")]
    BadRequest(String),
    #[error("{0}")]
    Forbidden(String),
    #[error("{0}")]
    NotFound(String),
    #[error("{0}")]
    Conflict(String),
    #[error("integration persistence failed")]
    Storage(#[from] SecurityError),
    #[error("integration access evaluation failed")]
    Access(#[from] ResourceAccessError),
}

/// A rejected Purview connection payload surfaces as a client error, matching
/// Java where `PurviewConnectionSettings.from` throws `IllegalArgumentException`
/// and the save fails with a 400.
impl From<PurviewConfigError> for IntegrationFailure {
    fn from(error: PurviewConfigError) -> Self {
        Self::BadRequest(error.to_string())
    }
}

#[derive(Clone)]
pub(crate) struct IntegrationConfigService {
    access: ResourceAccessService,
    policies_enabled: bool,
    allow_private_s3_endpoints: bool,
    allow_custom_api_integrations: bool,
}

impl IntegrationConfigService {
    // Each flag is a distinct Java-compatible policy toggle (portal default access
    // width, policy classification, private S3 endpoints, custom-API authoring),
    // not an accidental boolean-blindness cluster.
    #[allow(clippy::fn_params_excessive_bools)]
    pub(crate) fn new(
        store: Arc<SecurityStore>,
        portal_default: DefaultAccessPolicy,
        deployment_wide_access: bool,
        policies_enabled: bool,
        allow_private_s3_endpoints: bool,
        allow_custom_api_integrations: bool,
    ) -> Self {
        Self {
            access: ResourceAccessService::new(store, portal_default, deployment_wide_access),
            policies_enabled,
            allow_private_s3_endpoints,
            allow_custom_api_integrations,
        }
    }

    pub(crate) fn access(&self) -> &ResourceAccessService {
        &self.access
    }

    /// Whether this caller may author free-form ("custom") API integrations, for
    /// the UI to offer or hide the option. Mirrors Java's
    /// `IntegrationConfigService.canAuthorCustomApi`: authoring is admin-only and
    /// the operator can withdraw it entirely via `policies.allowCustomApiIntegrations`.
    pub(crate) fn can_author_custom_api(&self, context: &AuthContext) -> bool {
        custom_api_authoring_available(self.allow_custom_api_integrations, context)
    }

    pub(crate) fn require_portal(&self, context: &AuthContext) -> Result<(), IntegrationFailure> {
        if self.access.can_access_portal(context)? {
            Ok(())
        } else {
            Err(IntegrationFailure::Forbidden(
                "You cannot access this integration".to_owned(),
            ))
        }
    }

    pub(crate) fn create(
        &self,
        request: IntegrationConfigRequest,
        context: &AuthContext,
    ) -> Result<IntegrationConfigResponse, IntegrationFailure> {
        let integration_type = request.integration_type.ok_or_else(|| {
            IntegrationFailure::BadRequest("integrationType is required".to_owned())
        })?;
        let name = request
            .name
            .filter(|name| !name.trim().is_empty())
            .ok_or_else(|| IntegrationFailure::BadRequest("name is required".to_owned()))?;
        let scope = request.scope.unwrap_or(OwnerScope::User);
        if integration_type == IntegrationType::S3
            && scope == OwnerScope::User
            && !ResourceAccessService::is_admin(context)
        {
            return Err(IntegrationFailure::Forbidden(
                "S3 connections can only be created by administrators or team owners".to_owned(),
            ));
        }
        // A custom API integration names its own host, path and body, so it can
        // point the server anywhere — authoring power gated to admins and
        // withdrawable via `policies.allowCustomApiIntegrations`. Mirrors Java's
        // `requireCustomApiAllowed`, keeping the enforced rule aligned with the
        // capability reported by `can_author_custom_api`.
        self.require_custom_api_allowed(integration_type, context)?;
        let (owner_user_id, owner_team_id) =
            self.assign_ownership(integration_type, scope, request.owner_team_id, context)?;
        let request_config = request.config.unwrap_or_default();
        let config = sanitize_config(&request_config)?;
        self.validate_config(integration_type, &config)?;
        let created = self
            .access
            .store()
            .create_integration_config(&NewIntegrationConfig {
                integration_type,
                name,
                scope,
                owner_user_id,
                owner_team_id,
                enabled: request.enabled.unwrap_or(true),
                locked: request.locked.unwrap_or(false),
                default_access: request
                    .default_access
                    .unwrap_or(DefaultAccessPolicy::ExplicitOnly),
                config,
            })?;
        self.to_response(&created, context)
    }

    pub(crate) fn get(
        &self,
        id: i64,
        context: &AuthContext,
    ) -> Result<IntegrationConfigResponse, IntegrationFailure> {
        let config = self.load(id)?;
        if !self.can_use(&config, context)? {
            return Err(IntegrationFailure::Forbidden(
                "You cannot access this integration".to_owned(),
            ));
        }
        self.to_response(&config, context)
    }

    pub(crate) fn update(
        &self,
        id: i64,
        request: IntegrationConfigRequest,
        context: &AuthContext,
    ) -> Result<IntegrationConfigResponse, IntegrationFailure> {
        let mut config = self.load(id)?;
        if !self.can_manage(&config, context)? {
            return Err(IntegrationFailure::Forbidden(
                "You cannot manage this integration".to_owned(),
            ));
        }
        if config.locked && !ResourceAccessService::is_admin(context) {
            return Err(IntegrationFailure::Forbidden(
                "This integration is locked by an administrator".to_owned(),
            ));
        }
        if let Some(name) = request.name {
            config.name = name;
        }
        if let Some(enabled) = request.enabled {
            config.enabled = enabled;
        }
        if let Some(locked) = request.locked
            && locked != config.locked
        {
            if !ResourceAccessService::is_admin(context) {
                return Err(IntegrationFailure::Forbidden(
                    "Only administrators can change the locked flag".to_owned(),
                ));
            }
            config.locked = locked;
        }
        if let Some(default_access) = request.default_access {
            config.default_access = default_access;
        }
        if let Some(incoming) = request.config {
            // Editing the config of a custom API integration is the same authoring
            // power as creating one — it is where the base URL and body live — so
            // it is gated identically, matching Java's `update`.
            self.require_custom_api_allowed(config.integration_type, context)?;
            validate_config_depth(&Value::Object(incoming.clone()), 0)?;
            config.config = merge_config(&config.config, &incoming, 0);
            self.validate_config(config.integration_type, &config.config)?;
        }
        let updated = self.access.store().update_integration_config(&config)?;
        self.to_response(&updated, context)
    }

    pub(crate) fn delete(&self, id: i64, context: &AuthContext) -> Result<(), IntegrationFailure> {
        let config = self.load(id)?;
        if !self.can_manage(&config, context)? {
            return Err(IntegrationFailure::Forbidden(
                "You cannot manage this integration".to_owned(),
            ));
        }
        let usages = self.access.store().integration_config_usages(id)?;
        if !usages.is_empty() {
            return Err(IntegrationFailure::Conflict(format!(
                "Integration is in use by: {}",
                usages.join(", ")
            )));
        }
        self.access.store().delete_integration_config(id)?;
        Ok(())
    }

    /// Resolves a policy source/output's S3 options through a stored
    /// integration config while the saving caller's identity is available.
    pub(crate) fn resolve_s3_options(
        &self,
        options: &Map<String, Value>,
        context: &AuthContext,
    ) -> Result<Map<String, Value>, IntegrationFailure> {
        let Some(connection_id) = connection_id(options)? else {
            validate_s3_config(options, self.allow_private_s3_endpoints)?;
            return Ok(options.clone());
        };
        let connection = self
            .access
            .store()
            .get_integration_config(connection_id)?
            .filter(|connection| connection.integration_type == IntegrationType::S3)
            .ok_or_else(|| {
                IntegrationFailure::BadRequest("unknown or inaccessible s3 connection".to_owned())
            })?;
        if !self.can_use(&connection, context)? {
            return Err(IntegrationFailure::BadRequest(
                "unknown or inaccessible s3 connection".to_owned(),
            ));
        }
        if !connection.enabled {
            return Err(IntegrationFailure::BadRequest(
                "s3 connection is disabled".to_owned(),
            ));
        }
        let mut resolved = connection.config;
        for key in ["prefix", "mode"] {
            if let Some(value) = options.get(key).filter(|value| !value_is_blank(value)) {
                resolved.insert(key.to_owned(), value.clone());
            }
        }
        validate_s3_config(&resolved, self.allow_private_s3_endpoints)?;
        Ok(resolved)
    }

    /// Dereferences a step's `connectionId` to the stored config of a connection of
    /// the given type. Ported from Java `ApiConnectionResolver.resolveConfig`, used by
    /// the Purview label steps to recover the tenant id.
    ///
    /// Every "you may not have this" outcome — no such row, the wrong integration
    /// type, not permitted for this caller, or disabled — collapses into ONE opaque
    /// error so a caller cannot probe which connection ids exist (anti-enumeration).
    /// Java reports the disabled case with a distinct message; this port folds it into
    /// the same opaque error, which leaks strictly less than Java. Unlike the Java
    /// resolver, the caller's identity is passed explicitly rather than read from a
    /// thread-local security context, so the `can_use` check always runs.
    pub(crate) fn resolve_config(
        &self,
        id: i64,
        integration_type: IntegrationType,
        context: &AuthContext,
    ) -> Result<Map<String, Value>, IntegrationFailure> {
        let opaque = || {
            IntegrationFailure::BadRequest(format!(
                "unknown or inaccessible {} connection",
                integration_type.as_str().to_ascii_lowercase()
            ))
        };
        let connection = self
            .access
            .store()
            .get_integration_config(id)?
            .filter(|connection| connection.integration_type == integration_type)
            .ok_or_else(opaque)?;
        if !self.can_use(&connection, context)? || !connection.enabled {
            return Err(opaque());
        }
        Ok(connection.config)
    }

    pub(crate) fn list(
        &self,
        context: &AuthContext,
    ) -> Result<Vec<IntegrationConfigResponse>, IntegrationFailure> {
        let all = self.access.store().list_integration_configs()?;
        let granted = self
            .access
            .granted_resource_ids(ResourceType::IntegrationConfig, context)?;
        let mut selected = Vec::new();
        let mut included = HashSet::new();

        for config in all.iter().filter(|config| {
            config.scope == OwnerScope::User && config.owner_user_id == Some(context.user_id)
        }) {
            included.insert(config.id);
            selected.push(config);
        }
        for config in all
            .iter()
            .filter(|config| config.scope == OwnerScope::Server)
        {
            if self.can_use(config, context)? && included.insert(config.id) {
                selected.push(config);
            }
        }
        if let Some(team_id) = context.team_id {
            for config in all.iter().filter(|config| {
                config.scope == OwnerScope::Team && config.owner_team_id == Some(team_id)
            }) {
                if self.can_use(config, context)? && included.insert(config.id) {
                    selected.push(config);
                }
            }
        }
        for resource_id in granted {
            let Ok(id) = resource_id.parse::<i64>() else {
                continue;
            };
            if included.contains(&id) {
                continue;
            }
            if let Some(config) = all.iter().find(|config| config.id == id)
                && self.can_use(config, context)?
            {
                included.insert(id);
                selected.push(config);
            }
        }
        selected
            .into_iter()
            .map(|config| self.to_response(config, context))
            .collect()
    }

    fn assign_ownership(
        &self,
        integration_type: IntegrationType,
        scope: OwnerScope,
        requested_team_id: Option<i64>,
        context: &AuthContext,
    ) -> Result<(Option<i64>, Option<i64>), IntegrationFailure> {
        match scope {
            OwnerScope::User => {
                if !ResourceAccessService::is_admin(context)
                    && self
                        .access
                        .store()
                        .locked_server_integration_exists(integration_type)?
                {
                    return Err(IntegrationFailure::Forbidden(
                        "This is locked to the server configuration by an administrator".to_owned(),
                    ));
                }
                Ok((Some(context.user_id), None))
            }
            OwnerScope::Server => {
                if !ResourceAccessService::is_admin(context) {
                    return Err(IntegrationFailure::Forbidden(
                        "Only administrators can create server-owned resources".to_owned(),
                    ));
                }
                Ok((None, None))
            }
            OwnerScope::Team => {
                let team_id = requested_team_id.or(context.team_id).ok_or_else(|| {
                    IntegrationFailure::BadRequest("ownerTeamId is required".to_owned())
                })?;
                if !self.access.principal_exists(PrincipalType::Team, team_id)? {
                    return Err(IntegrationFailure::NotFound("Team not found".to_owned()));
                }
                if !ResourceAccessService::is_admin(context)
                    && !self.access.is_team_owner(context, team_id)?
                {
                    return Err(IntegrationFailure::Forbidden(
                        "Only admins or team leaders can create team-owned resources".to_owned(),
                    ));
                }
                Ok((None, Some(team_id)))
            }
        }
    }

    fn load(&self, id: i64) -> Result<IntegrationConfig, IntegrationFailure> {
        self.access
            .store()
            .get_integration_config(id)?
            .ok_or_else(|| IntegrationFailure::NotFound("Integration not found".to_owned()))
    }

    fn can_use(
        &self,
        config: &IntegrationConfig,
        context: &AuthContext,
    ) -> Result<bool, IntegrationFailure> {
        if !config.enabled {
            return Ok(ResourceAccessService::is_admin(context)
                || self.access.is_owner(owner_ref(config), context)?);
        }
        self.access
            .can_use_resource(
                ResourceType::IntegrationConfig,
                &config.id.to_string(),
                owner_ref(config),
                config.default_access,
                context,
            )
            .map_err(Into::into)
    }

    fn can_manage(
        &self,
        config: &IntegrationConfig,
        context: &AuthContext,
    ) -> Result<bool, IntegrationFailure> {
        if !config.enabled {
            return Ok(ResourceAccessService::is_admin(context)
                || self.access.is_owner(owner_ref(config), context)?);
        }
        self.access
            .can_manage_resource(
                ResourceType::IntegrationConfig,
                &config.id.to_string(),
                owner_ref(config),
                context,
            )
            .map_err(Into::into)
    }

    fn to_response(
        &self,
        config: &IntegrationConfig,
        context: &AuthContext,
    ) -> Result<IntegrationConfigResponse, IntegrationFailure> {
        Ok(IntegrationConfigResponse {
            id: config.id,
            integration_type: config.integration_type,
            name: config.name.clone(),
            scope: config.scope,
            owner_user_id: config.owner_user_id,
            owner_team_id: config.owner_team_id,
            enabled: config.enabled,
            locked: config.locked,
            default_access: config.default_access,
            config: mask_config(&config.config, 0),
            can_manage: self.can_manage(config, context)?,
            created_at: config.created_at.clone(),
            updated_at: config.updated_at.clone(),
        })
    }

    /// Enforces the custom-API authoring rule for `API`-type configs, matching
    /// Java's `requireCustomApiAllowed`: non-API types are unaffected; API types
    /// require the server flag to be on and the caller to be an administrator.
    /// Vendor presets (S3/MCP) carry a fixed shape and are intentionally not
    /// gated here.
    fn require_custom_api_allowed(
        &self,
        integration_type: IntegrationType,
        context: &AuthContext,
    ) -> Result<(), IntegrationFailure> {
        custom_api_allowed(
            self.allow_custom_api_integrations,
            integration_type,
            context,
        )
    }

    fn validate_config(
        &self,
        integration_type: IntegrationType,
        config: &Map<String, Value>,
    ) -> Result<(), IntegrationFailure> {
        let serialized = serde_json::to_vec(config)
            .map_err(|_| IntegrationFailure::BadRequest("Invalid config payload".to_owned()))?;
        if serialized.len() > MAX_CONFIG_BYTES {
            return Err(IntegrationFailure::BadRequest(
                "Invalid config payload".to_owned(),
            ));
        }
        validate_config_depth(&Value::Object(config.clone()), 0)?;
        if self.policies_enabled && integration_type == IntegrationType::S3 {
            validate_s3_config(config, self.allow_private_s3_endpoints)?;
        }
        // Purview connections are schema-validated on save regardless of the S3
        // policy toggle, mirroring Java's always-registered `PurviewIntegrationValidator`.
        // The parsed settings are only needed for their validation side effect here.
        if integration_type == IntegrationType::Purview {
            PurviewConnectionSettings::from(config)?;
        }
        Ok(())
    }
}

/// Whether a caller may author custom API integrations: the server flag is on
/// and the caller is an administrator. Mirrors Java's `canAuthorCustomApi`.
fn custom_api_authoring_available(
    allow_custom_api_integrations: bool,
    context: &AuthContext,
) -> bool {
    allow_custom_api_integrations && ResourceAccessService::is_admin(context)
}

/// Fail-closed custom-API authoring gate shared by create and update. Non-API
/// integration types pass unconditionally; API types require the server flag and
/// administrator privileges. Mirrors Java's `requireCustomApiAllowed`, including
/// its two distinct forbidden messages.
fn custom_api_allowed(
    allow_custom_api_integrations: bool,
    integration_type: IntegrationType,
    context: &AuthContext,
) -> Result<(), IntegrationFailure> {
    if integration_type != IntegrationType::Api {
        return Ok(());
    }
    if !allow_custom_api_integrations {
        return Err(IntegrationFailure::Forbidden(
            "Custom API integrations are disabled on this server \
             (policies.allowCustomApiIntegrations)"
                .to_owned(),
        ));
    }
    if !ResourceAccessService::is_admin(context) {
        return Err(IntegrationFailure::Forbidden(
            "Custom API integrations can only be created by administrators".to_owned(),
        ));
    }
    Ok(())
}

fn owner_ref(config: &IntegrationConfig) -> Option<OwnerRef> {
    match (config.owner_user_id, config.owner_team_id) {
        (Some(principal_id), None) => Some(OwnerRef {
            principal_type: PrincipalType::User,
            principal_id,
        }),
        (None, Some(principal_id)) => Some(OwnerRef {
            principal_type: PrincipalType::Team,
            principal_id,
        }),
        _ => None,
    }
}

fn sanitize_config(config: &Map<String, Value>) -> Result<Map<String, Value>, IntegrationFailure> {
    validate_config_depth(&Value::Object(config.clone()), 0)?;
    Ok(sanitize_map(config, 0))
}

fn sanitize_map(config: &Map<String, Value>, depth: usize) -> Map<String, Value> {
    config
        .iter()
        .filter_map(|(key, value)| {
            if is_sensitive(key) && is_redacted(value, depth) {
                return None;
            }
            let value = match value {
                Value::Object(object) if depth < MAX_CONFIG_DEPTH => {
                    Value::Object(sanitize_map(object, depth + 1))
                }
                _ => value.clone(),
            };
            Some((key.clone(), value))
        })
        .collect()
}

pub(crate) fn mask_config(config: &Map<String, Value>, depth: usize) -> Map<String, Value> {
    config
        .iter()
        .map(|(key, value)| (key.clone(), mask_value(key, value, depth)))
        .collect()
}

fn mask_value(key: &str, value: &Value, depth: usize) -> Value {
    if is_sensitive(key) {
        return match value {
            Value::Null => Value::Null,
            Value::String(value) if value.trim().is_empty() => Value::String(value.clone()),
            _ => Value::String(SECRET_MASK.to_owned()),
        };
    }
    if depth >= MAX_CONFIG_DEPTH {
        return match value {
            Value::Object(_) | Value::Array(_) => Value::String(SECRET_MASK.to_owned()),
            _ => value.clone(),
        };
    }
    match value {
        Value::Object(object) => Value::Object(mask_config(object, depth + 1)),
        Value::Array(values) => Value::Array(
            values
                .iter()
                .map(|value| match value {
                    Value::Object(object) => Value::Object(mask_config(object, depth + 1)),
                    _ => value.clone(),
                })
                .collect(),
        ),
        _ => value.clone(),
    }
}

pub(crate) fn merge_config(
    stored: &Map<String, Value>,
    incoming: &Map<String, Value>,
    depth: usize,
) -> Map<String, Value> {
    incoming
        .iter()
        .filter_map(|(key, value)| {
            if is_sensitive(key) {
                if is_redacted(value, depth) {
                    return stored.get(key).cloned().map(|value| (key.clone(), value));
                }
                return Some((key.clone(), value.clone()));
            }
            let value = match (stored.get(key), value) {
                (Some(Value::Object(stored)), Value::Object(incoming))
                    if depth < MAX_CONFIG_DEPTH =>
                {
                    Value::Object(merge_config(stored, incoming, depth + 1))
                }
                _ => value.clone(),
            };
            Some((key.clone(), value))
        })
        .collect()
}

fn connection_id(options: &Map<String, Value>) -> Result<Option<i64>, IntegrationFailure> {
    let Some(reference) = options.get("connectionId") else {
        return Ok(None);
    };
    if value_is_blank(reference) {
        return Ok(None);
    }
    let parsed = match reference {
        Value::Number(number) => number.as_i64(),
        Value::String(value) => value.trim().parse::<i64>().ok(),
        value => value.to_string().trim_matches('"').parse::<i64>().ok(),
    };
    parsed.map(Some).ok_or_else(|| {
        IntegrationFailure::BadRequest(format!(
            "s3 'connectionId' is not a valid connection reference: {reference}"
        ))
    })
}

/// Parses a `connectionId` request parameter for a label/API step, where the value
/// always arrives as a form-field string. Ported from Java
/// `ApiConnectionResolver.connectionId`, folding its `null` return and the
/// controller's follow-up `null` check into a single required-parameter error so
/// blank and absent are indistinguishable to the caller.
pub(crate) fn parse_connection_id_param(reference: &str) -> Result<i64, IntegrationFailure> {
    let trimmed = reference.trim();
    if trimmed.is_empty() {
        return Err(IntegrationFailure::BadRequest(
            "'connectionId' is required".to_owned(),
        ));
    }
    trimmed.parse::<i64>().map_err(|_| {
        IntegrationFailure::BadRequest(format!(
            "'connectionId' is not a valid connection reference: {reference}"
        ))
    })
}

fn value_is_blank(value: &Value) -> bool {
    matches!(value, Value::Null) || value.as_str().is_some_and(|value| value.trim().is_empty())
}

fn is_sensitive(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    SENSITIVE_HINTS.iter().any(|hint| lower.contains(hint))
}

fn is_redacted(value: &Value, depth: usize) -> bool {
    match value {
        Value::Null => true,
        Value::String(value) => value.trim().is_empty() || value == SECRET_MASK,
        Value::Object(object) if depth < MAX_CONFIG_DEPTH => {
            object.values().any(|value| is_redacted(value, depth + 1))
        }
        Value::Array(values) if depth < MAX_CONFIG_DEPTH => {
            values.iter().any(|value| is_redacted(value, depth + 1))
        }
        _ => false,
    }
}

fn validate_config_depth(value: &Value, depth: usize) -> Result<(), IntegrationFailure> {
    if depth > MAX_CONFIG_DEPTH {
        return Err(IntegrationFailure::BadRequest(
            "Invalid config payload".to_owned(),
        ));
    }
    match value {
        Value::Object(object) => {
            for value in object.values() {
                validate_config_depth(value, depth + 1)?;
            }
        }
        Value::Array(values) => {
            for value in values {
                validate_config_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn validate_s3_config(
    config: &Map<String, Value>,
    allow_private_endpoints: bool,
) -> Result<(), IntegrationFailure> {
    for key in ["bucket", "accessKeyId", "secretAccessKey"] {
        if config
            .get(key)
            .and_then(Value::as_str)
            .is_none_or(|value| value.trim().is_empty())
        {
            let message = if key == "bucket" {
                "s3 config requires a 'bucket' option"
            } else {
                "s3 config requires an 'accessKeyId' and 'secretAccessKey'"
            };
            return Err(IntegrationFailure::BadRequest(message.to_owned()));
        }
    }
    if let Some(mode) = config.get("mode").and_then(Value::as_str)
        && !mode.trim().is_empty()
        && !matches!(mode.trim(), "consume" | "snapshot")
    {
        return Err(IntegrationFailure::BadRequest(
            "s3 config 'mode' must be 'consume' or 'snapshot'".to_owned(),
        ));
    }
    let Some(endpoint) = config
        .get("endpoint")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
    else {
        return Ok(());
    };
    let endpoint = Url::parse(endpoint).map_err(|_| {
        IntegrationFailure::BadRequest("s3 config 'endpoint' is not a valid URL".to_owned())
    })?;
    if !matches!(endpoint.scheme(), "http" | "https") || endpoint.host_str().is_none() {
        return Err(IntegrationFailure::BadRequest(
            "s3 config 'endpoint' must be an http(s) URL, e.g. https://s3.example.com".to_owned(),
        ));
    }
    if allow_private_endpoints {
        return Ok(());
    }
    let host = endpoint.host_str().unwrap_or_default();
    let port = endpoint.port_or_known_default().unwrap_or(443);
    let addresses = if let Ok(address) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(address, port)]
    } else {
        (host, port)
            .to_socket_addrs()
            .map_err(|_| {
                IntegrationFailure::BadRequest(
                    "S3 connection endpoint hostname could not be resolved".to_owned(),
                )
            })?
            .collect::<Vec<_>>()
    };
    if addresses.is_empty() || addresses.iter().any(|address| !is_public_ip(address.ip())) {
        return Err(IntegrationFailure::BadRequest(
            "S3 connection endpoint resolves to a private or local address; set policies.allowPrivateS3Endpoints=true to opt in (e.g. for a local MinIO).".to_owned(),
        ));
    }
    Ok(())
}

fn is_public_ip(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => !matches!(
            address.octets(),
            [0 | 10 | 127 | 224..=255, ..]
                | [100, 64..=127, ..]
                | [169, 254, ..]
                | [172, 16..=31, ..]
                | [192, 0 | 168, ..]
                | [198, 18..=19, ..]
                | [198, 51, 100, _]
                | [203, 0, 113, _]
        ),
        IpAddr::V6(address) => {
            if address.is_unspecified() || address.is_loopback() {
                return false;
            }
            if let Some(mapped) = address.to_ipv4_mapped() {
                return is_public_ip(IpAddr::V4(mapped));
            }
            let segments = address.segments();
            !matches!(
                segments,
                [first, ..] if first & 0xff00 == 0xff00
                    || first & 0xfe00 == 0xfc00
                    || first & 0xffc0 == 0xfe80
                    || (first == 0x2001 && segments[1] == 0x0db8)
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{
        IntegrationFailure, IntegrationType, custom_api_allowed, custom_api_authoring_available,
        mask_config, merge_config, sanitize_config, validate_s3_config,
    };
    use crate::security::{AuthContext, AuthenticationSource};
    use serde_json::{Map, Value, json};
    use std::collections::BTreeSet;

    fn object(value: &Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
    }

    fn context<const N: usize>(roles: [&str; N]) -> AuthContext {
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

    #[test]
    fn custom_api_authoring_requires_flag_and_admin() {
        let admin = context(["ROLE_ADMIN"]);
        let user = context(["ROLE_USER"]);
        // Both the server flag and the admin role are required.
        assert!(custom_api_authoring_available(true, &admin));
        assert!(!custom_api_authoring_available(false, &admin));
        assert!(!custom_api_authoring_available(true, &user));
        assert!(!custom_api_authoring_available(false, &user));
    }

    #[test]
    fn custom_api_gate_only_applies_to_api_integrations() {
        let user = context(["ROLE_USER"]);
        // Vendor presets are never gated here, even with the flag off / non-admin.
        assert!(custom_api_allowed(false, IntegrationType::S3, &user).is_ok());
        assert!(custom_api_allowed(false, IntegrationType::Mcp, &user).is_ok());
    }

    #[test]
    fn custom_api_gate_reports_disabled_before_checking_admin() {
        // Flag-off is reported regardless of role, and the message names the
        // controlling property, matching Java's ordering and text.
        let admin = context(["ROLE_ADMIN"]);
        assert!(matches!(
            custom_api_allowed(false, IntegrationType::Api, &admin),
            Err(IntegrationFailure::Forbidden(message))
                if message.contains("disabled on this server")
                    && message.contains("policies.allowCustomApiIntegrations")
        ));
    }

    #[test]
    fn custom_api_gate_refuses_non_admins_when_enabled() {
        let user = context(["ROLE_USER"]);
        assert!(matches!(
            custom_api_allowed(true, IntegrationType::Api, &user),
            Err(IntegrationFailure::Forbidden(message))
                if message.contains("only be created by administrators")
        ));
    }

    #[test]
    fn custom_api_gate_permits_admins_when_enabled() {
        let admin = context(["ROLE_ADMIN"]);
        assert!(custom_api_allowed(true, IntegrationType::Api, &admin).is_ok());
    }

    #[test]
    fn masks_sanitizes_and_preserves_redacted_secrets() -> Result<(), super::IntegrationFailure> {
        let stored = object(&json!({
            "bucket":"docs",
            "secretAccessKey":"real-secret",
            "nested":{"apiToken":"nested-secret","keep":"old"}
        }));
        assert_eq!(
            mask_config(&stored, 0),
            object(&json!({
                "bucket":"docs",
                "secretAccessKey":"********",
                "nested":{"apiToken":"********","keep":"old"}
            }))
        );
        let incoming = object(&json!({
            "secretAccessKey":"********",
            "nested":{"apiToken":"********","new":"value"}
        }));
        assert_eq!(
            merge_config(&stored, &incoming, 0),
            object(&json!({
                "secretAccessKey":"real-secret",
                "nested":{"apiToken":"nested-secret","new":"value"}
            }))
        );
        assert_eq!(
            sanitize_config(&object(&json!({"apiKey":"", "name":"ok"})))?,
            object(&json!({"name":"ok"}))
        );
        Ok(())
    }

    #[test]
    fn s3_validation_requires_credentials_and_blocks_private_endpoints() {
        let missing = object(&json!({"bucket":"docs"}));
        assert_eq!(
            validate_s3_config(&missing, false)
                .err()
                .map(|error| error.to_string()),
            Some("s3 config requires an 'accessKeyId' and 'secretAccessKey'".to_owned())
        );
        let private = object(&json!({
            "bucket":"docs",
            "accessKeyId":"id",
            "secretAccessKey":"secret",
            "endpoint":"http://127.0.0.1:9000"
        }));
        assert!(
            validate_s3_config(&private, false)
                .err()
                .is_some_and(|error| error.to_string().contains("private or local"))
        );
        assert!(validate_s3_config(&private, true).is_ok());
    }

    // TESTER: the adversarial payoff — a POST create of an API-type integration
    // must be refused SERVER-SIDE (through create(), not just the gate helper)
    // whenever the flag is off OR the caller is not an admin, mirroring Java's
    // create() calling requireCustomApiAllowed. Both refusals fire before any
    // store write, so an in-memory store suffices.
    #[test]
    fn create_refuses_custom_api_server_side_without_flag_and_admin()
    -> Result<(), IntegrationFailure> {
        use super::{IntegrationConfigRequest, IntegrationConfigService};
        use crate::resource_access::DefaultAccessPolicy;
        use crate::security::SecurityStore;
        use std::sync::Arc;

        fn api_request() -> IntegrationConfigRequest {
            IntegrationConfigRequest {
                integration_type: Some(IntegrationType::Api),
                name: Some("custom".to_owned()),
                ..Default::default()
            }
        }

        let store = Arc::new(SecurityStore::in_memory()?);

        // Flag OFF, admin caller: still refused — the operator withdrew the feature.
        let disabled = IntegrationConfigService::new(
            Arc::clone(&store),
            DefaultAccessPolicy::ExplicitOnly,
            false,
            false,
            false,
            false,
        );
        assert!(matches!(
            disabled.create(api_request(), &context(["ROLE_ADMIN"])),
            Err(IntegrationFailure::Forbidden(message))
                if message.contains("disabled on this server")
        ));

        // Flag ON, non-admin caller: refused — authoring is admin-only.
        let enabled = IntegrationConfigService::new(
            store,
            DefaultAccessPolicy::ExplicitOnly,
            false,
            false,
            false,
            true,
        );
        assert!(matches!(
            enabled.create(api_request(), &context(["ROLE_USER"])),
            Err(IntegrationFailure::Forbidden(message))
                if message.contains("only be created by administrators")
        ));

        // Flag ON, admin caller: the custom-API gate does not block (non-Forbidden
        // beyond it — here it proceeds into ownership/config handling).
        let allowed = IntegrationConfigService::new(
            Arc::new(SecurityStore::in_memory()?),
            DefaultAccessPolicy::ExplicitOnly,
            false,
            false,
            false,
            true,
        );
        assert!(!matches!(
            allowed.create(api_request(), &context(["ROLE_ADMIN"])),
            Err(IntegrationFailure::Forbidden(message)) if message.contains("Custom API")
        ));
        Ok(())
    }

    // TESTER: a Purview config's clientSecret must never reach a response body in
    // clear text. The "secret" hint drives is_sensitive, so mask_config replaces it
    // with the mask while the non-sensitive tenantId/clientId are echoed verbatim.
    #[test]
    fn mask_config_hides_purview_client_secret() {
        let stored = object(&json!({
            "tenantId": "cb46c030-1825-4e81-a295-151c039dbf02",
            "clientId": "app-registration",
            "clientSecret": "super-secret-value",
        }));
        let masked = mask_config(&stored, 0);
        assert_eq!(
            masked.get("clientSecret").and_then(Value::as_str),
            Some("********")
        );
        assert_eq!(
            masked.get("tenantId").and_then(Value::as_str),
            Some("cb46c030-1825-4e81-a295-151c039dbf02")
        );
        assert_eq!(
            masked.get("clientId").and_then(Value::as_str),
            Some("app-registration")
        );
    }

    #[test]
    fn integration_type_purview_round_trips_through_the_database_encoding() {
        assert_eq!(IntegrationType::Purview.as_str(), "PURVIEW");
        assert_eq!(
            IntegrationType::from_database("PURVIEW"),
            Some(IntegrationType::Purview)
        );
        assert_eq!(IntegrationType::from_database("purview"), None);
    }

    // TESTER: Purview save-validation must fire SERVER-SIDE through create(), not
    // only in the standalone parser — mirroring Java's PurviewIntegrationValidator
    // running whenever a PURVIEW config is persisted. A malformed tenant id is
    // refused before any store write; a well-formed connection is accepted.
    #[test]
    fn create_validates_purview_config_server_side() -> Result<(), IntegrationFailure> {
        use super::{IntegrationConfigRequest, IntegrationConfigService};
        use crate::resource_access::{DefaultAccessPolicy, OwnerScope};
        use crate::security::SecurityStore;
        use std::sync::Arc;

        fn purview_request(scope: OwnerScope, config: Value) -> IntegrationConfigRequest {
            let config = match config {
                Value::Object(map) => Some(map),
                _ => None,
            };
            IntegrationConfigRequest {
                integration_type: Some(IntegrationType::Purview),
                name: Some("tenant".to_owned()),
                scope: Some(scope),
                config,
                ..Default::default()
            }
        }

        let service = IntegrationConfigService::new(
            Arc::new(SecurityStore::in_memory()?),
            DefaultAccessPolicy::ExplicitOnly,
            false,
            // policies disabled: Purview still validates (unlike the S3 gate).
            false,
            false,
            false,
        );
        let admin = context(["ROLE_ADMIN"]);

        // Missing tenant id: rejected as a client error before persisting.
        assert!(matches!(
            service.create(purview_request(OwnerScope::User, json!({})), &admin),
            Err(IntegrationFailure::BadRequest(message)) if message.contains("tenantId")
        ));

        // Malformed tenant id: rejected as a GUID violation.
        assert!(matches!(
            service.create(
                purview_request(OwnerScope::User, json!({ "tenantId": "not-a-guid" })),
                &admin
            ),
            Err(IntegrationFailure::BadRequest(message)) if message.contains("must be a GUID")
        ));

        // Well-formed connection (no app registration): accepted and stored. Uses
        // SERVER scope so the admin-owned row has null owners and the in-memory
        // store's user foreign key is not exercised.
        let created = service.create(
            purview_request(
                OwnerScope::Server,
                json!({ "tenantId": "CB46C030-1825-4E81-A295-151C039DBF02" }),
            ),
            &admin,
        )?;
        assert_eq!(created.integration_type, IntegrationType::Purview);
        // Save-validation is a pure side effect: the stored config is not
        // rewritten, so the tenant id keeps its original casing (parity with Java,
        // where lowercasing is a read-time concern in PurviewConnectionSettings).
        assert_eq!(
            created.config.get("tenantId").and_then(Value::as_str),
            Some("CB46C030-1825-4E81-A295-151C039DBF02")
        );
        Ok(())
    }
}
