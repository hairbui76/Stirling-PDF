//! Java-compatible HTTP surface for resource grants and integration configs.

use std::sync::Arc;

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, rejection::JsonRejection},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{delete, get},
};
use serde::Deserialize;
use serde_json::json;

use crate::{
    integration_config::{IntegrationConfigRequest, IntegrationConfigService, IntegrationFailure},
    resource_access::{AccessPermission, PrincipalType, ResourceType},
    security::AuthContext,
};

pub(crate) fn routes(service: Arc<IntegrationConfigService>) -> Router {
    Router::new()
        .route(
            "/api/v1/admin/access/grants",
            get(list_grants).post(create_grant),
        )
        .route(
            "/api/v1/admin/access/grants/by-principal",
            get(list_grants_by_principal),
        )
        .route("/api/v1/admin/access/grants/{id}", delete(revoke_grant))
        .route(
            "/api/v1/integrations",
            get(list_integrations).post(create_integration),
        )
        .route(
            "/api/v1/integrations/{id}",
            get(get_integration)
                .put(update_integration)
                .delete(delete_integration),
        )
        .layer(Extension(service))
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantListQuery {
    resource_type: ResourceType,
    #[serde(default)]
    resource_id: String,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct PrincipalGrantQuery {
    principal_type: PrincipalType,
    principal_id: i64,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct GrantRequest {
    resource_type: Option<ResourceType>,
    resource_id: Option<String>,
    principal_type: Option<PrincipalType>,
    principal_id: Option<i64>,
    permission: Option<AccessPermission>,
}

async fn list_grants(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<GrantListQuery>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match service
        .access()
        .list_grants(query.resource_type, &query.resource_id)
    {
        Ok(grants) => Json(grants).into_response(),
        Err(_) => internal_error(),
    }
}

async fn list_grants_by_principal(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Query(query): Query<PrincipalGrantQuery>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match service
        .access()
        .list_grants_for_principal(query.principal_type, query.principal_id)
    {
        Ok(grants) => Json(grants).into_response(),
        Err(_) => internal_error(),
    }
}

async fn create_grant(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    request: Result<Json<GrantRequest>, JsonRejection>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    let Ok(Json(request)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid request payload");
    };
    let (Some(resource_type), Some(principal_type), Some(principal_id)) = (
        request.resource_type,
        request.principal_type,
        request.principal_id,
    ) else {
        return json_error(
            StatusCode::BAD_REQUEST,
            "resourceType, principalType and principalId are required",
        );
    };
    let resource_id = if resource_type == ResourceType::Portal {
        String::new()
    } else {
        let Some(resource_id) = request.resource_id.filter(|id| !id.trim().is_empty()) else {
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("resourceId is required for {}", resource_type.as_str()),
            );
        };
        resource_id
    };
    match service
        .access()
        .principal_exists(principal_type, principal_id)
    {
        Ok(true) => {}
        Ok(false) => {
            let label = match principal_type {
                PrincipalType::User => "User",
                PrincipalType::Team => "Team",
            };
            return json_error(
                StatusCode::BAD_REQUEST,
                &format!("{label} {principal_id} does not exist"),
            );
        }
        Err(_) => return internal_error(),
    }
    match service.access().grant(
        resource_type,
        &resource_id,
        principal_type,
        principal_id,
        request.permission.unwrap_or(AccessPermission::Use),
        context.user_id,
    ) {
        Ok(grant) => Json(grant).into_response(),
        Err(_) => internal_error(),
    }
}

async fn revoke_grant(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if !is_admin(&context) {
        return json_error(StatusCode::FORBIDDEN, "Forbidden");
    }
    match service.access().revoke(id) {
        Ok(()) => Json(json!({"message":"Grant revoked"})).into_response(),
        Err(_) => internal_error(),
    }
}

async fn list_integrations(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    match service.list(&context) {
        Ok(integrations) => Json(integrations).into_response(),
        Err(error) => integration_error(error),
    }
}

async fn create_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    request: Result<Json<IntegrationConfigRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    let Ok(Json(request)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid config payload");
    };
    match service.create(request, &context) {
        Ok(integration) => Json(integration).into_response(),
        Err(error) => integration_error(error),
    }
}

async fn get_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    match service.get(id, &context) {
        Ok(integration) => Json(integration).into_response(),
        Err(error) => integration_error(error),
    }
}

async fn update_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
    request: Result<Json<IntegrationConfigRequest>, JsonRejection>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    let Ok(Json(request)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid config payload");
    };
    match service.update(id, request, &context) {
        Ok(integration) => Json(integration).into_response(),
        Err(error) => integration_error(error),
    }
}

async fn delete_integration(
    Extension(service): Extension<Arc<IntegrationConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(id): Path<i64>,
) -> Response {
    if let Err(error) = service.require_portal(&context) {
        return integration_error(error);
    }
    match service.delete(id, &context) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => integration_error(error),
    }
}

fn is_admin(context: &AuthContext) -> bool {
    context.has_role("ROLE_ADMIN")
}

fn integration_error(error: IntegrationFailure) -> Response {
    match error {
        IntegrationFailure::BadRequest(message) => json_error(StatusCode::BAD_REQUEST, &message),
        IntegrationFailure::Forbidden(message) => json_error(StatusCode::FORBIDDEN, &message),
        IntegrationFailure::NotFound(message) => json_error(StatusCode::NOT_FOUND, &message),
        IntegrationFailure::Conflict(message) => json_error(StatusCode::CONFLICT, &message),
        IntegrationFailure::Storage(_) | IntegrationFailure::Access(_) => internal_error(),
    }
}

fn internal_error() -> Response {
    json_error(
        StatusCode::INTERNAL_SERVER_ERROR,
        "Integration service unavailable",
    )
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error":message}))).into_response()
}
