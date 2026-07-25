//! Reviewed secured-mode HTTP boundary for policy and source configuration.

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    extract::{Extension, Multipart, Path, rejection::JsonRejection},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, put},
};
use futures_util::StreamExt as _;
use serde_json::json;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::{
    policy_config::{PolicyConfigService, PolicyDefinition, PolicyFailure, PolicySource},
    policy_execution::{PolicyExecutionFailure, PolicyExecutionService},
    policy_ledger::ProcessedLedger,
    policy_sources::PolicySourceRunner,
    policy_triggers::{PolicyChangeNotifier, trigger_metadata},
    security::{AuthContext, SecurityAuditContext},
};

#[derive(Clone, Copy)]
struct PolicyHttpSettings {
    stream_timeout: Duration,
}

pub(crate) fn routes(
    config_service: Arc<PolicyConfigService>,
    execution_service: Arc<PolicyExecutionService>,
    source_runner: Arc<PolicySourceRunner>,
    processed_ledger: Arc<ProcessedLedger>,
    trigger_notifier: PolicyChangeNotifier,
    stream_timeout: Duration,
) -> Router {
    Router::new()
        .route("/api/v1/sources", get(list_sources).post(save_source))
        .route(
            "/api/v1/sources/{source_id}",
            get(get_source).delete(delete_source),
        )
        .route(
            "/api/v1/sources/{source_id}/document-counts",
            get(source_document_counts),
        )
        .route("/api/v1/policies", get(list_policies).post(save_policy))
        .route("/api/v1/policies/order", put(reorder_policies))
        .route("/api/v1/policies/overview", get(policy_overview))
        .route("/api/v1/policies/triggers", get(available_triggers))
        .route(
            "/api/v1/admin/settings/policies/implied-folder-roots",
            get(implied_folder_roots),
        )
        .route("/api/v1/policies/run", axum::routing::post(run_ad_hoc))
        .route(
            "/api/v1/policies/run/stream",
            axum::routing::post(run_ad_hoc_stream),
        )
        .route("/api/v1/policies/run/{run_id}", get(run_status))
        .route("/api/v1/policies/runs", get(list_runs))
        .route(
            "/api/v1/policies/{policy_id}",
            get(get_policy).delete(delete_policy),
        )
        .route(
            "/api/v1/policies/{policy_id}/run",
            axum::routing::post(run_stored),
        )
        .route(
            "/api/v1/policies/{policy_id}/trigger",
            axum::routing::post(trigger_policy),
        )
        .route(
            "/api/v1/policies/{policy_id}/processed-history",
            axum::routing::delete(clear_processed_history),
        )
        .layer(Extension(config_service))
        .layer(Extension(execution_service))
        .layer(Extension(source_runner))
        .layer(Extension(processed_ledger))
        .layer(Extension(trigger_notifier))
        .layer(Extension(PolicyHttpSettings { stream_timeout }))
}

async fn list_sources(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match service.source_overview(&context) {
        Ok(response) => Json(response).into_response(),
        Err(error) => policy_error(error),
    }
}

async fn get_source(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(source_id): Path<String>,
) -> Response {
    match service.get_source(&source_id, &context) {
        Ok(source) => Json(source).into_response(),
        Err(error) => policy_error(error),
    }
}

async fn source_document_counts(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(source_id): Path<String>,
) -> Response {
    match service.document_counts(&source_id, &context) {
        Ok(counts) => Json(counts).into_response(),
        Err(error) => policy_error(error),
    }
}

async fn save_source(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(notifier): Extension<PolicyChangeNotifier>,
    Extension(context): Extension<AuthContext>,
    request: Result<Json<PolicySource>, JsonRejection>,
) -> Response {
    let Ok(Json(source)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid source payload");
    };
    match service.save_source(source, &context) {
        Ok(source) => {
            notifier.notify();
            Json(source).into_response()
        }
        Err(error) => policy_error(error),
    }
}

async fn delete_source(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(notifier): Extension<PolicyChangeNotifier>,
    Extension(context): Extension<AuthContext>,
    Path(source_id): Path<String>,
) -> Response {
    match service.delete_source(&source_id, &context) {
        Ok(()) => {
            notifier.notify();
            StatusCode::NO_CONTENT.into_response()
        }
        Err(error) => policy_error(error),
    }
}

async fn list_policies(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match service.list_policies(&context) {
        Ok(policies) => Json(policies).into_response(),
        Err(error) => policy_error(error),
    }
}

async fn get_policy(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
    Path(policy_id): Path<String>,
) -> Response {
    match service.get_policy(&policy_id, &context) {
        Ok(policy) => Json(policy).into_response(),
        Err(error) => policy_error(error),
    }
}

async fn policy_overview(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match service.policy_overview(&context) {
        Ok(overview) => Json(overview).into_response(),
        Err(error) => policy_error(error),
    }
}

async fn available_triggers() -> Json<Vec<crate::policy_triggers::TriggerInfo>> {
    Json(trigger_metadata())
}

/// Read-only admin view of the Stirling-owned folder roots always permitted for
/// folder automations (server storage, pipeline watched folders), regardless of
/// `policies.allowedFolderRoots`. Mirrors Java's
/// `FolderAccessSettingsController.impliedFolderRoots`; the service enforces the
/// `hasRole('ADMIN')` gate.
async fn implied_folder_roots(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match service.list_implied_folder_roots(&context) {
        Ok(roots) => Json(roots).into_response(),
        Err(error) => policy_error(error),
    }
}

async fn save_policy(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(notifier): Extension<PolicyChangeNotifier>,
    Extension(context): Extension<AuthContext>,
    request: Result<Json<PolicyDefinition>, JsonRejection>,
) -> Response {
    let Ok(Json(policy)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid policy payload");
    };
    match service.save_policy(policy, &context) {
        Ok(policy) => {
            notifier.notify();
            Json(policy).into_response()
        }
        Err(error) => policy_error(error),
    }
}

async fn reorder_policies(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(context): Extension<AuthContext>,
    request: Result<Json<Vec<String>>, JsonRejection>,
) -> Response {
    let Ok(Json(ids)) = request else {
        return json_error(StatusCode::BAD_REQUEST, "Invalid policy order payload");
    };
    match service.reorder_policies(&ids, &context) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => policy_error(error),
    }
}

async fn delete_policy(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(ledger): Extension<Arc<ProcessedLedger>>,
    Extension(notifier): Extension<PolicyChangeNotifier>,
    Extension(context): Extension<AuthContext>,
    Path(policy_id): Path<String>,
) -> Response {
    match service.delete_policy(&policy_id, &context) {
        Ok(()) => match ledger.clear_policy(&policy_id) {
            Ok(()) => {
                notifier.notify();
                StatusCode::NO_CONTENT.into_response()
            }
            Err(_) => json_error(
                StatusCode::INTERNAL_SERVER_ERROR,
                "Policy service unavailable",
            ),
        },
        Err(error) => policy_error(error),
    }
}

async fn clear_processed_history(
    Extension(service): Extension<Arc<PolicyConfigService>>,
    Extension(ledger): Extension<Arc<ProcessedLedger>>,
    Extension(context): Extension<AuthContext>,
    Path(policy_id): Path<String>,
) -> Response {
    match service.clear_processed_history(&policy_id, &context, &ledger) {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => policy_error(error),
    }
}

async fn run_ad_hoc(
    Extension(service): Extension<Arc<PolicyExecutionService>>,
    Extension(context): Extension<AuthContext>,
    audit_context: Option<Extension<SecurityAuditContext>>,
    multipart: Multipart,
) -> Response {
    match service
        .submit_ad_hoc(
            multipart,
            &context,
            audit_context.as_ref().map(|Extension(context)| context),
        )
        .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({"async":true,"jobId":job_id,"result":null})),
        )
            .into_response(),
        Err(error) => execution_error(error),
    }
}

async fn run_ad_hoc_stream(
    Extension(service): Extension<Arc<PolicyExecutionService>>,
    Extension(settings): Extension<PolicyHttpSettings>,
    Extension(context): Extension<AuthContext>,
    audit_context: Option<Extension<SecurityAuditContext>>,
    multipart: Multipart,
) -> Response {
    let receiver = match service
        .submit_ad_hoc_stream(
            multipart,
            &context,
            audit_context.as_ref().map(|Extension(context)| context),
        )
        .await
    {
        Ok(receiver) => receiver,
        Err(error) => return execution_error(error),
    };
    let timeout = settings.stream_timeout;
    let updates = UnboundedReceiverStream::new(receiver)
        .map(|update| {
            let data = serde_json::to_string(&update.data)
                .unwrap_or_else(|error| json!({"message":error.to_string()}).to_string());
            Ok::<Event, Infallible>(Event::default().event(update.event).data(data))
        })
        .take_until(tokio::time::sleep(timeout));
    Sse::new(updates)
        .keep_alive(KeepAlive::new().interval(Duration::from_secs(10)).text(""))
        .into_response()
}

async fn run_stored(
    Extension(service): Extension<Arc<PolicyExecutionService>>,
    Extension(context): Extension<AuthContext>,
    Path(policy_id): Path<String>,
    audit_context: Option<Extension<SecurityAuditContext>>,
    multipart: Multipart,
) -> Response {
    match service
        .submit_stored(
            &policy_id,
            multipart,
            &context,
            audit_context.as_ref().map(|Extension(context)| context),
        )
        .await
    {
        Ok(job_id) => (
            StatusCode::ACCEPTED,
            Json(json!({"async":true,"jobId":job_id,"result":null})),
        )
            .into_response(),
        Err(error) => execution_error(error),
    }
}

async fn trigger_policy(
    Extension(service): Extension<Arc<PolicySourceRunner>>,
    Extension(context): Extension<AuthContext>,
    Path(policy_id): Path<String>,
) -> Response {
    match service.run_full(&policy_id, &context).await {
        Ok(outcome) => (StatusCode::ACCEPTED, Json(outcome)).into_response(),
        Err(error) => execution_error(error),
    }
}

async fn run_status(
    Extension(service): Extension<Arc<PolicyExecutionService>>,
    Extension(context): Extension<AuthContext>,
    Path(run_id): Path<String>,
) -> Response {
    match service.status(&run_id, &context) {
        Ok(status) => Json(status).into_response(),
        Err(error) => execution_error(error),
    }
}

async fn list_runs(
    Extension(service): Extension<Arc<PolicyExecutionService>>,
    Extension(context): Extension<AuthContext>,
) -> Response {
    match service.list_stored_runs(&context) {
        Ok(runs) => Json(runs).into_response(),
        Err(error) => execution_error(error),
    }
}

fn policy_error(error: PolicyFailure) -> Response {
    match error {
        PolicyFailure::BadRequest(message) => json_error(StatusCode::BAD_REQUEST, &message),
        PolicyFailure::Forbidden(message) => json_error(StatusCode::FORBIDDEN, &message),
        PolicyFailure::NotFound(message) => json_error(StatusCode::NOT_FOUND, &message),
        PolicyFailure::Conflict(message) => json_error(StatusCode::CONFLICT, &message),
        PolicyFailure::Storage(_) => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Policy service unavailable",
        ),
    }
}

fn execution_error(error: PolicyExecutionFailure) -> Response {
    match error {
        PolicyExecutionFailure::BadRequest(message) => {
            json_error(StatusCode::BAD_REQUEST, &message)
        }
        PolicyExecutionFailure::Forbidden(message) => json_error(StatusCode::FORBIDDEN, &message),
        PolicyExecutionFailure::NotFound(message) => json_error(StatusCode::NOT_FOUND, &message),
        PolicyExecutionFailure::ServiceUnavailable(message) => {
            json_error(StatusCode::SERVICE_UNAVAILABLE, &message)
        }
        PolicyExecutionFailure::Unavailable => json_error(
            StatusCode::INTERNAL_SERVER_ERROR,
            "Policy execution unavailable",
        ),
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(json!({"error":message}))).into_response()
}
