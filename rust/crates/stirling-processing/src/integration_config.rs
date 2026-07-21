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
}

impl IntegrationType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::S3 => "S3",
            Self::Mcp => "MCP",
            Self::Api => "API",
        }
    }

    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "S3" => Some(Self::S3),
            "MCP" => Some(Self::Mcp),
            "API" => Some(Self::Api),
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

#[derive(Clone)]
pub(crate) struct IntegrationConfigService {
    access: ResourceAccessService,
    policies_enabled: bool,
    allow_private_s3_endpoints: bool,
}

impl IntegrationConfigService {
    pub(crate) fn new(
        store: Arc<SecurityStore>,
        portal_default: DefaultAccessPolicy,
        deployment_wide_access: bool,
        policies_enabled: bool,
        allow_private_s3_endpoints: bool,
    ) -> Self {
        Self {
            access: ResourceAccessService::new(store, portal_default, deployment_wide_access),
            policies_enabled,
            allow_private_s3_endpoints,
        }
    }

    pub(crate) fn access(&self) -> &ResourceAccessService {
        &self.access
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
        Ok(())
    }
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
    use super::{mask_config, merge_config, sanitize_config, validate_s3_config};
    use serde_json::{Map, Value, json};

    fn object(value: &Value) -> Map<String, Value> {
        value.as_object().cloned().unwrap_or_default()
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
}
