//! Resource ownership and explicit grant evaluation for reviewed secured mode.
//!
//! The rules mirror the proprietary Java access service: administrator and
//! owner access is implicit, `MANAGE` implies `USE`, disabled owned resources
//! ignore grants/defaults, and deployment-wide defaults are an explicit
//! runtime choice so a future multi-tenant deployment cannot inherit the
//! self-hosted behavior accidentally.

use std::{collections::BTreeSet, sync::Arc};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::security::{AuthContext, SecurityError, SecurityStore};

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum ResourceType {
    Portal,
    IntegrationConfig,
}

impl ResourceType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Portal => "PORTAL",
            Self::IntegrationConfig => "INTEGRATION_CONFIG",
        }
    }

    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "PORTAL" => Some(Self::Portal),
            "INTEGRATION_CONFIG" => Some(Self::IntegrationConfig),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum PrincipalType {
    User,
    Team,
}

impl PrincipalType {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Team => "TEAM",
        }
    }

    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "USER" => Some(Self::User),
            "TEAM" => Some(Self::Team),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum AccessPermission {
    Use,
    Manage,
}

impl AccessPermission {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Use => "USE",
            Self::Manage => "MANAGE",
        }
    }

    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "USE" => Some(Self::Use),
            "MANAGE" => Some(Self::Manage),
            _ => None,
        }
    }

    const fn satisfies(self, required: Self) -> bool {
        matches!((self, required), (Self::Manage, _) | (Self::Use, Self::Use))
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum DefaultAccessPolicy {
    OrgAll,
    AdminsAndTeamLeads,
    ExplicitOnly,
}

impl DefaultAccessPolicy {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::OrgAll => "ORG_ALL",
            Self::AdminsAndTeamLeads => "ADMINS_AND_TEAM_LEADS",
            Self::ExplicitOnly => "EXPLICIT_ONLY",
        }
    }

    pub(crate) fn from_config(value: &str) -> Self {
        match value.trim().to_ascii_uppercase().as_str() {
            "ORG_ALL" => Self::OrgAll,
            "EXPLICIT_ONLY" => Self::ExplicitOnly,
            _ => Self::AdminsAndTeamLeads,
        }
    }

    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "ORG_ALL" => Some(Self::OrgAll),
            "ADMINS_AND_TEAM_LEADS" => Some(Self::AdminsAndTeamLeads),
            "EXPLICIT_ONLY" => Some(Self::ExplicitOnly),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub(crate) enum OwnerScope {
    User,
    Team,
    Server,
}

impl OwnerScope {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::User => "USER",
            Self::Team => "TEAM",
            Self::Server => "SERVER",
        }
    }

    pub(crate) fn from_database(value: &str) -> Option<Self> {
        match value {
            "USER" => Some(Self::User),
            "TEAM" => Some(Self::Team),
            "SERVER" => Some(Self::Server),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct OwnerRef {
    pub(crate) principal_type: PrincipalType,
    pub(crate) principal_id: i64,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct ResourceGrant {
    pub(crate) id: i64,
    pub(crate) resource_type: ResourceType,
    pub(crate) resource_id: String,
    pub(crate) principal_type: PrincipalType,
    pub(crate) principal_id: i64,
    pub(crate) permission: AccessPermission,
    pub(crate) created_at: String,
}

#[derive(Debug, Error)]
pub(crate) enum ResourceAccessError {
    #[error("resource access persistence failed")]
    Storage(#[from] SecurityError),
}

#[derive(Clone)]
pub(crate) struct ResourceAccessService {
    store: Arc<SecurityStore>,
    portal_default: DefaultAccessPolicy,
    deployment_wide_access: bool,
}

impl ResourceAccessService {
    pub(crate) fn new(
        store: Arc<SecurityStore>,
        portal_default: DefaultAccessPolicy,
        deployment_wide_access: bool,
    ) -> Self {
        Self {
            store,
            portal_default,
            deployment_wide_access,
        }
    }

    pub(crate) fn store(&self) -> &Arc<SecurityStore> {
        &self.store
    }

    pub(crate) fn can_access_portal(
        &self,
        context: &AuthContext,
    ) -> Result<bool, ResourceAccessError> {
        self.can_use_resource(ResourceType::Portal, "", None, self.portal_default, context)
    }

    pub(crate) fn can_use_resource(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
        owner: Option<OwnerRef>,
        default_access: DefaultAccessPolicy,
        context: &AuthContext,
    ) -> Result<bool, ResourceAccessError> {
        if Self::is_admin(context) || self.is_owner(owner, context)? {
            return Ok(true);
        }
        if self.has_grant(resource_type, resource_id, context, AccessPermission::Use)? {
            return Ok(true);
        }
        match default_access {
            DefaultAccessPolicy::OrgAll => Ok(self.deployment_wide_access),
            DefaultAccessPolicy::AdminsAndTeamLeads => {
                self.matches_team_lead_default(owner, context)
            }
            DefaultAccessPolicy::ExplicitOnly => Ok(false),
        }
    }

    pub(crate) fn can_manage_resource(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
        owner: Option<OwnerRef>,
        context: &AuthContext,
    ) -> Result<bool, ResourceAccessError> {
        if Self::is_admin(context) || self.is_owner(owner, context)? {
            return Ok(true);
        }
        self.has_grant(
            resource_type,
            resource_id,
            context,
            AccessPermission::Manage,
        )
    }

    pub(crate) fn is_owner(
        &self,
        owner: Option<OwnerRef>,
        context: &AuthContext,
    ) -> Result<bool, ResourceAccessError> {
        let Some(owner) = owner else {
            return Ok(false);
        };
        match owner.principal_type {
            PrincipalType::User => Ok(owner.principal_id == context.user_id),
            PrincipalType::Team => self
                .store
                .is_team_owner(context.user_id, owner.principal_id)
                .map_err(Into::into),
        }
    }

    pub(crate) fn is_admin(context: &AuthContext) -> bool {
        context.has_role("ROLE_ADMIN")
    }

    pub(crate) fn principal_exists(
        &self,
        principal_type: PrincipalType,
        principal_id: i64,
    ) -> Result<bool, ResourceAccessError> {
        self.store
            .resource_principal_exists(principal_type, principal_id)
            .map_err(Into::into)
    }

    pub(crate) fn grant(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
        principal_type: PrincipalType,
        principal_id: i64,
        permission: AccessPermission,
        granted_by_user_id: i64,
    ) -> Result<ResourceGrant, ResourceAccessError> {
        self.store
            .upsert_resource_grant(
                resource_type,
                resource_id,
                principal_type,
                principal_id,
                permission,
                granted_by_user_id,
            )
            .map_err(Into::into)
    }

    pub(crate) fn revoke(&self, id: i64) -> Result<(), ResourceAccessError> {
        self.store.revoke_resource_grant(id).map_err(Into::into)
    }

    pub(crate) fn list_grants(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
    ) -> Result<Vec<ResourceGrant>, ResourceAccessError> {
        self.store
            .list_resource_grants(resource_type, resource_id)
            .map_err(Into::into)
    }

    pub(crate) fn list_grants_for_principal(
        &self,
        principal_type: PrincipalType,
        principal_id: i64,
    ) -> Result<Vec<ResourceGrant>, ResourceAccessError> {
        self.store
            .list_resource_grants_for_principal(principal_type, principal_id)
            .map_err(Into::into)
    }

    pub(crate) fn granted_resource_ids(
        &self,
        resource_type: ResourceType,
        context: &AuthContext,
    ) -> Result<BTreeSet<String>, ResourceAccessError> {
        self.store
            .granted_resource_ids(resource_type, context.user_id, context.team_id)
            .map_err(Into::into)
    }

    pub(crate) fn is_team_owner(
        &self,
        context: &AuthContext,
        team_id: i64,
    ) -> Result<bool, ResourceAccessError> {
        self.store
            .is_team_owner(context.user_id, team_id)
            .map_err(Into::into)
    }

    fn has_grant(
        &self,
        resource_type: ResourceType,
        resource_id: &str,
        context: &AuthContext,
        required: AccessPermission,
    ) -> Result<bool, ResourceAccessError> {
        Ok(self
            .list_grants(resource_type, resource_id)?
            .into_iter()
            .any(|grant| {
                grant.permission.satisfies(required)
                    && match grant.principal_type {
                        PrincipalType::User => grant.principal_id == context.user_id,
                        PrincipalType::Team => context.team_id == Some(grant.principal_id),
                    }
            }))
    }

    fn matches_team_lead_default(
        &self,
        owner: Option<OwnerRef>,
        context: &AuthContext,
    ) -> Result<bool, ResourceAccessError> {
        match owner {
            None => self
                .store
                .is_any_team_owner(context.user_id)
                .map_err(Into::into),
            Some(OwnerRef {
                principal_type: PrincipalType::Team,
                principal_id,
            }) => self
                .store
                .is_team_owner(context.user_id, principal_id)
                .map_err(Into::into),
            Some(OwnerRef {
                principal_type: PrincipalType::User,
                ..
            }) => Ok(false),
        }
    }
}
