//! Reviewed secured-mode HTTP boundary for policy and source configuration.

use std::{convert::Infallible, sync::Arc, time::Duration};

use axum::{
    Json, Router,
    body::Bytes,
    extract::{Extension, Multipart, Path, rejection::JsonRejection},
    http::StatusCode,
    response::{
        IntoResponse, Response,
        sse::{Event, KeepAlive, Sse},
    },
    routing::{get, post, put},
};
use futures_util::StreamExt as _;
use serde::Deserialize;
use serde_json::json;
use tokio_stream::wrappers::UnboundedReceiverStream;

use crate::{
    classification::CLASSIFY_AND_LABEL_PATH,
    policy_config::{PolicyConfigService, PolicyDefinition, PolicyFailure, PolicySource},
    policy_execution::{PolicyExecutionFailure, PolicyExecutionService},
    policy_ledger::ProcessedLedger,
    policy_sources::PolicySourceRunner,
    policy_triggers::{PolicyChangeNotifier, trigger_metadata},
    security::{AuthContext, SecurityAuditContext},
};

/// Client-supplied document-count cap: the frontend meters one document per call,
/// but the value is clamped defensively before it could reach billing. Mirrors
/// Java `ClassificationMeterController.MAX_DOCUMENTS`.
const MAX_CLASSIFY_DOCUMENTS: i64 = 10_000;

/// Fallback audit label when the client omits a policy name. Mirrors Java
/// `ClassificationMeterController`'s `"Classification"` default.
const DEFAULT_CLASSIFY_POLICY_NAME: &str = "Classification";

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
        .route("/api/v1/policies/classify/meter", post(classify_meter))
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

/// Frontend payload for [`classify_meter`]. Mirrors Java
/// `ClassificationMeterController.ClassifyMeterRequest`. `labels` is part of the
/// wire contract but, as in Java, is never read server-side, so it is accepted and
/// silently ignored (serde skips unknown fields by default).
#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ClassifyMeterRequest {
    #[serde(default)]
    policy_name: Option<String>,
    #[serde(default)]
    document_count: Option<i64>,
}

/// Meters + audits a client-side (non-AI) classification run so both classify
/// paths read alike in the audit trail. Side-effect only: it performs no
/// classification. Mirrors Java `ClassificationMeterController.meterClassification`.
///
/// The body is optional (Java `@RequestBody(required = false)`): an absent, empty,
/// or unparseable body collapses to defaults. Billing is a deferred no-op — the
/// SaaS-only `ClassificationRunBiller` bean is absent in the proprietary runtime,
/// exactly as `biller.getIfAvailable()` returns `null` in Java — so the clamped
/// document count is only traced (Java still computes it even when the biller is
/// absent) and the endpoint always returns `202 Accepted` with an empty body.
async fn classify_meter(
    audit_context: Option<Extension<SecurityAuditContext>>,
    body: Bytes,
) -> Response {
    // Tolerate an absent/empty/malformed body: any parse failure collapses to the
    // request defaults, matching Java's `required = false` semantics.
    let request = serde_json::from_slice::<ClassifyMeterRequest>(&body).unwrap_or_default();
    let documents = clamp_document_count(request.document_count);
    let policy_name = resolve_policy_name(request.policy_name.as_deref());

    // Stamp the run so the audit trail records it as a policy run, like the AI
    // classify path: policyName plus policySteps=[classify-and-label].
    if let Some(Extension(audit_context)) = audit_context.as_ref() {
        audit_context.set_policy(policy_name, [CLASSIFY_AND_LABEL_PATH.to_owned()]);
    }

    // Billing is deferred: the SaaS-only biller is absent in this runtime, so the
    // metered count is only traced here.
    tracing::debug!(
        documents,
        policy_name,
        "metered client-side classification run"
    );

    StatusCode::ACCEPTED.into_response()
}

/// Clamps the client-supplied document count into `1..=MAX_CLASSIFY_DOCUMENTS`,
/// defaulting an absent/null value to `1`. Mirrors Java's floor/ceiling guards.
fn clamp_document_count(count: Option<i64>) -> i64 {
    count.unwrap_or(1).clamp(1, MAX_CLASSIFY_DOCUMENTS)
}

/// Resolves the audit label: a blank or absent policy name falls back to
/// [`DEFAULT_CLASSIFY_POLICY_NAME`], mirroring Java's `isBlank()` guard.
fn resolve_policy_name(raw: Option<&str>) -> &str {
    match raw.map(str::trim) {
        Some(name) if !name.is_empty() => name,
        _ => DEFAULT_CLASSIFY_POLICY_NAME,
    }
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

#[cfg(test)]
mod classify_meter_tests {
    //! Parity tests for `POST /api/v1/policies/classify/meter`, mirroring Java
    //! `ClassificationMeterController`: optional-body defaults, count clamping,
    //! blank-name fallback, policy-run audit stamping, and an always-202 reply.

    use super::{
        CLASSIFY_AND_LABEL_PATH, DEFAULT_CLASSIFY_POLICY_NAME, clamp_document_count,
        classify_meter, resolve_policy_name,
    };
    use crate::security::SecurityAuditContext;
    use axum::Router;
    use axum::body::{Body, to_bytes};
    use axum::http::{Method, Request, StatusCode};
    use axum::routing::post;
    use tower::ServiceExt as _;

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    const METER_PATH: &str = "/api/v1/policies/classify/meter";

    fn router() -> Router {
        Router::new().route(METER_PATH, post(classify_meter))
    }

    async fn meter(ctx: Option<&SecurityAuditContext>, body: Body) -> TestResult {
        let mut request = Request::builder()
            .method(Method::POST)
            .uri(METER_PATH)
            .header("content-type", "application/json")
            .body(body)?;
        if let Some(ctx) = ctx {
            request.extensions_mut().insert(ctx.clone());
        }
        let response = router().oneshot(request).await?;
        // Every path replies 202 with an empty body — the endpoint is fire-and-forget.
        assert_eq!(response.status(), StatusCode::ACCEPTED);
        let bytes = to_bytes(response.into_body(), 64).await?;
        assert!(bytes.is_empty(), "meter response body must be empty");
        Ok(())
    }

    #[test]
    fn clamp_document_count_applies_floor_and_ceiling() {
        assert_eq!(clamp_document_count(None), 1); // null/absent -> 1
        assert_eq!(clamp_document_count(Some(0)), 1); // < 1 -> 1
        assert_eq!(clamp_document_count(Some(-42)), 1);
        assert_eq!(clamp_document_count(Some(1)), 1);
        assert_eq!(clamp_document_count(Some(500)), 500);
        assert_eq!(clamp_document_count(Some(10_000)), 10_000);
        assert_eq!(clamp_document_count(Some(10_001)), 10_000); // > cap -> cap
        assert_eq!(clamp_document_count(Some(i64::MAX)), 10_000);
    }

    #[test]
    fn resolve_policy_name_falls_back_when_blank() {
        assert_eq!(resolve_policy_name(None), DEFAULT_CLASSIFY_POLICY_NAME);
        assert_eq!(resolve_policy_name(Some("")), DEFAULT_CLASSIFY_POLICY_NAME);
        assert_eq!(
            resolve_policy_name(Some("   ")),
            DEFAULT_CLASSIFY_POLICY_NAME
        );
        assert_eq!(resolve_policy_name(Some("Legal Hold")), "Legal Hold");
        assert_eq!(resolve_policy_name(Some("  Legal Hold  ")), "Legal Hold"); // trimmed
    }

    #[tokio::test]
    async fn stamps_policy_run_from_body() -> TestResult {
        let ctx = SecurityAuditContext::new(true);
        // `labels` is part of the wire contract but ignored, as in Java.
        meter(
            Some(&ctx),
            Body::from(r#"{"policyName":"  Legal Hold  ","documentCount":5,"labels":["a","b"]}"#),
        )
        .await?;
        let enrichment = ctx.snapshot();
        // Stamped as a policy run: trimmed name + the AI classify step, so both
        // classify paths read alike in the audit trail.
        assert_eq!(enrichment.policy_name.as_deref(), Some("Legal Hold"));
        assert_eq!(
            enrichment.policy_steps,
            vec![CLASSIFY_AND_LABEL_PATH.to_owned()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn absent_body_stamps_default_policy_name() -> TestResult {
        let ctx = SecurityAuditContext::new(true);
        meter(Some(&ctx), Body::empty()).await?;
        let enrichment = ctx.snapshot();
        assert_eq!(
            enrichment.policy_name.as_deref(),
            Some(DEFAULT_CLASSIFY_POLICY_NAME)
        );
        assert_eq!(
            enrichment.policy_steps,
            vec![CLASSIFY_AND_LABEL_PATH.to_owned()]
        );
        Ok(())
    }

    #[tokio::test]
    async fn malformed_body_collapses_to_defaults() -> TestResult {
        let ctx = SecurityAuditContext::new(true);
        meter(Some(&ctx), Body::from("{not valid json")).await?;
        assert_eq!(
            ctx.snapshot().policy_name.as_deref(),
            Some(DEFAULT_CLASSIFY_POLICY_NAME)
        );
        Ok(())
    }

    #[tokio::test]
    async fn accepts_when_audit_context_absent() -> TestResult {
        // No audit plan (e.g. auditing disabled) means no injected context; the
        // handler must still succeed rather than depend on the enrichment seam.
        meter(None, Body::from(r#"{"documentCount":-3}"#)).await
    }
}
