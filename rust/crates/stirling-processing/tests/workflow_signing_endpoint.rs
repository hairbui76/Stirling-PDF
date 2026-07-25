use std::{error::Error, fs};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{Method, Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use serde_json::{Value, json};
use stirling_processing::{
    TimestampSettings, app_with_reviewed_security, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt as _;

const BODY_LIMIT: usize = 8 * 1024 * 1024;

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn collaborative_signing_covers_owner_account_and_token_lifecycles()
-> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let app = signing_router(directory.path(), true)?;
    let admin_token = login(&app, "admin", "test-only-password").await?;
    create_user(&app, &admin_token, "member", "member-password").await?;
    let member_token = login(&app, "member", "member-password").await?;

    let config =
        authorized_empty(&app, Method::GET, "/api/v1/config/app-config", &admin_token).await?;
    assert_eq!(config.status(), StatusCode::OK);
    assert_eq!(
        response_json(config).await?["storageGroupSigningEnabled"],
        true
    );

    let create = authorized_multipart(
        &app,
        Method::POST,
        "/api/v1/security/cert-sign/sessions",
        &admin_token,
        session_multipart(
            "external-session",
            &single_page_pdf()?,
            &[
                ("workflowType", "SIGNING"),
                ("documentName", "agreement.pdf"),
                ("participantEmails[0]", "first@example.test"),
                ("participantEmails[1]", "second@example.test"),
                ("workflowMetadata", r#"{"includeSummaryPage":true}"#),
            ],
        ),
    )
    .await?;
    assert_eq!(create.status(), StatusCode::OK);
    let created = response_json(create).await?;
    let session_id = created["sessionId"]
        .as_str()
        .ok_or("missing session id")?
        .to_owned();
    let first_token = created["participants"][0]["shareToken"]
        .as_str()
        .ok_or("missing first participant token")?
        .to_owned();
    let second_token = created["participants"][1]["shareToken"]
        .as_str()
        .ok_or("missing second participant token")?
        .to_owned();

    let account_token_without_share_token = app
        .clone()
        .oneshot(
            Request::get("/api/v1/workflow/participant/session")
                .header(header::AUTHORIZATION, format!("Bearer {member_token}"))
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(
        account_token_without_share_token.status(),
        StatusCode::BAD_REQUEST
    );
    let invalid_share_token = app
        .clone()
        .oneshot(
            Request::get("/api/v1/workflow/participant/session?token=invalid")
                .body(Body::empty())?,
        )
        .await?;
    assert_eq!(invalid_share_token.status(), StatusCode::FORBIDDEN);

    let participant_session = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/workflow/participant/session?token={first_token}"
            ))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(participant_session.status(), StatusCode::OK);
    let participant_session = response_json(participant_session).await?;
    assert_eq!(
        participant_session["participants"][0]["shareToken"],
        Value::Null
    );
    assert_eq!(
        participant_session["participants"][1]["shareToken"],
        Value::Null
    );
    assert!(!participant_session.to_string().contains(&second_token));

    let details = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/workflow/participant/details?token={first_token}"
            ))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(details.status(), StatusCode::OK);
    assert_eq!(response_json(details).await?["shareToken"], Value::Null);

    let validation = multipart_request(
        &app,
        Method::POST,
        "/api/v1/workflow/participant/validate-certificate",
        None,
        text_multipart(
            "participant-validation",
            &[("participantToken", &first_token), ("certType", "SERVER")],
        ),
    )
    .await?;
    assert_eq!(validation.status(), StatusCode::OK);
    assert_eq!(response_json(validation).await?["valid"], true);

    let submit = multipart_request(
        &app,
        Method::POST,
        "/api/v1/workflow/participant/submit-signature",
        None,
        text_multipart(
            "participant-submit",
            &[
                ("participantToken", &first_token),
                ("certType", "SERVER"),
                ("reason", "Reviewed and approved"),
                (
                    "wetSignaturesData",
                    r#"[{"type":"text","data":"Alice","page":0,"x":0.1,"y":0.1,"width":0.25,"height":0.1}]"#,
                ),
            ],
        ),
    )
    .await?;
    assert_eq!(submit.status(), StatusCode::OK);
    assert_eq!(response_json(submit).await?["status"], "SIGNED");

    let decline = app
        .clone()
        .oneshot(
            Request::post(format!(
                "/api/v1/workflow/participant/decline?token={second_token}&reason=Not%20required"
            ))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(decline.status(), StatusCode::OK);
    assert_eq!(response_json(decline).await?["status"], "DECLINED");

    let owner_view = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/security/cert-sign/sessions/{session_id}"),
        &admin_token,
    )
    .await?;
    assert_eq!(owner_view.status(), StatusCode::OK);
    let owner_view = response_json(owner_view).await?;
    assert_eq!(owner_view["signedCount"], 1);
    assert_eq!(owner_view["participants"][0]["status"], "SIGNED");
    assert_eq!(owner_view["participants"][1]["status"], "DECLINED");

    let finalized = authorized_empty(
        &app,
        Method::POST,
        &format!("/api/v1/security/cert-sign/sessions/{session_id}/finalize"),
        &admin_token,
    )
    .await?;
    if finalized.status() != StatusCode::OK {
        let status = finalized.status();
        let body = to_bytes(finalized.into_body(), BODY_LIMIT).await?;
        return Err(format!(
            "workflow finalization returned {status}: {}",
            String::from_utf8_lossy(&body)
        )
        .into());
    }
    let signed_pdf = to_bytes(finalized.into_body(), BODY_LIMIT).await?.to_vec();
    assert_signed_pdf(&signed_pdf, 2)?;

    let original_after_finalize = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/security/cert-sign/sessions/{session_id}/pdf"),
        &admin_token,
    )
    .await?;
    assert_eq!(original_after_finalize.status(), StatusCode::NOT_FOUND);

    let participant_signed_document = app
        .clone()
        .oneshot(
            Request::get(format!(
                "/api/v1/workflow/participant/document?token={first_token}"
            ))
            .body(Body::empty())?,
        )
        .await?;
    assert_eq!(participant_signed_document.status(), StatusCode::OK);
    assert_eq!(
        to_bytes(participant_signed_document.into_body(), BODY_LIMIT).await?,
        signed_pdf
    );

    let member_id = user_id(&app, &admin_token, "member").await?;
    let member_id_string = member_id.to_string();
    let member_session = authorized_multipart(
        &app,
        Method::POST,
        "/api/v1/security/cert-sign/sessions",
        &admin_token,
        session_multipart(
            "member-session",
            &single_page_pdf()?,
            &[
                ("workflowType", "SIGNING"),
                ("documentName", "member-agreement.pdf"),
                ("participantUserIds[0]", &member_id_string),
            ],
        ),
    )
    .await?;
    assert_eq!(member_session.status(), StatusCode::OK);
    let member_session_id = response_json(member_session).await?["sessionId"]
        .as_str()
        .ok_or("missing member session id")?
        .to_owned();

    let requests = authorized_empty(
        &app,
        Method::GET,
        "/api/v1/security/cert-sign/sign-requests",
        &member_token,
    )
    .await?;
    assert_eq!(requests.status(), StatusCode::OK);
    assert_eq!(
        response_json(requests).await?[0]["sessionId"],
        member_session_id
    );

    let detail = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/security/cert-sign/sign-requests/{member_session_id}"),
        &member_token,
    )
    .await?;
    assert_eq!(detail.status(), StatusCode::OK);
    assert_eq!(response_json(detail).await?["myStatus"], "VIEWED");

    let member_sign = authorized_multipart(
        &app,
        Method::POST,
        &format!("/api/v1/security/cert-sign/sign-requests/{member_session_id}/sign"),
        &member_token,
        text_multipart("member-sign", &[("certType", "SERVER")]),
    )
    .await?;
    assert_eq!(member_sign.status(), StatusCode::NO_CONTENT);

    let cross_owner = authorized_empty(
        &app,
        Method::GET,
        &format!("/api/v1/security/cert-sign/sessions/{member_session_id}"),
        &member_token,
    )
    .await?;
    assert_eq!(cross_owner.status(), StatusCode::FORBIDDEN);
    Ok(())
}

#[tokio::test]
async fn collaborative_signing_fails_closed_when_disabled() -> Result<(), Box<dyn Error>> {
    let directory = tempdir()?;
    let app = signing_router(directory.path(), false)?;
    let token = login(&app, "admin", "test-only-password").await?;
    let response = authorized_empty(
        &app,
        Method::GET,
        "/api/v1/security/cert-sign/sessions",
        &token,
    )
    .await?;
    assert_eq!(response.status(), StatusCode::FORBIDDEN);
    Ok(())
}

fn signing_router(root: &std::path::Path, enabled: bool) -> Result<Router, Box<dyn Error>> {
    let config_directory = root.join("configs");
    fs::create_dir_all(&config_directory)?;
    let settings = config_directory.join("settings.yml");
    fs::write(
        &settings,
        format!(
            "security:\n  initialLogin:\n    username: admin\n    password: test-only-password\nstorage:\n  enabled: true\n  provider: local\n  signing:\n    enabled: {enabled}\nsystem:\n  serverCertificate:\n    enabled: true\n    organizationName: Stirling Workflow Test\n    validity: 30\n"
        ),
    )?;
    Ok(app_with_reviewed_security(
        BODY_LIMIT,
        TimestampSettings::default(),
        RuntimeConfig::from_files(&settings, config_directory.join("missing.yml")),
    )?)
}

async fn login(app: &Router, username: &str, password: &str) -> Result<String, Box<dyn Error>> {
    let response = app
        .clone()
        .oneshot(
            Request::post("/api/v1/auth/login")
                .header(header::CONTENT_TYPE, "application/json")
                .body(Body::from(
                    json!({"username": username, "password": password}).to_string(),
                ))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["session"]["access_token"]
        .as_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| "missing access token".into())
}

async fn create_user(
    app: &Router,
    token: &str,
    username: &str,
    password: &str,
) -> Result<(), Box<dyn Error>> {
    let response = authorized_multipart(
        app,
        Method::POST,
        "/api/v1/user/admin/saveUser",
        token,
        text_multipart(
            "create-workflow-user",
            &[
                ("username", username),
                ("password", password),
                ("role", "ROLE_USER"),
                ("authType", "WEB"),
            ],
        ),
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    Ok(())
}

async fn user_id(app: &Router, token: &str, username: &str) -> Result<i64, Box<dyn Error>> {
    let response = authorized_empty(app, Method::GET, "/api/v1/user/admin/list", token).await?;
    assert_eq!(response.status(), StatusCode::OK);
    response_json(response).await?["users"]
        .as_array()
        .and_then(|users| {
            users
                .iter()
                .find(|user| user["username"] == username)
                .and_then(|user| user["id"].as_i64())
        })
        .ok_or_else(|| "missing workflow user id".into())
}

async fn authorized_empty(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
) -> Result<Response, Box<dyn Error>> {
    Ok(app
        .clone()
        .oneshot(
            Request::builder()
                .method(method)
                .uri(path)
                .header(header::AUTHORIZATION, format!("Bearer {token}"))
                .body(Body::empty())?,
        )
        .await?)
}

async fn authorized_multipart(
    app: &Router,
    method: Method,
    path: &str,
    token: &str,
    multipart: (String, Vec<u8>),
) -> Result<Response, Box<dyn Error>> {
    multipart_request(app, method, path, Some(token), multipart).await
}

async fn multipart_request(
    app: &Router,
    method: Method,
    path: &str,
    token: Option<&str>,
    multipart: (String, Vec<u8>),
) -> Result<Response, Box<dyn Error>> {
    let mut request = Request::builder().method(method).uri(path).header(
        header::CONTENT_TYPE,
        format!("multipart/form-data; boundary={}", multipart.0),
    );
    if let Some(token) = token {
        request = request.header(header::AUTHORIZATION, format!("Bearer {token}"));
    }
    Ok(app
        .clone()
        .oneshot(request.body(Body::from(multipart.1))?)
        .await?)
}

fn session_multipart(boundary: &str, pdf: &[u8], fields: &[(&str, &str)]) -> (String, Vec<u8>) {
    let mut body = Vec::new();
    append_file_part(
        &mut body,
        boundary,
        "file",
        "input.pdf",
        "application/pdf",
        pdf,
    );
    for (name, value) in fields {
        append_value_part(&mut body, boundary, name, value);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary.to_owned(), body)
}

fn text_multipart(boundary: &str, fields: &[(&str, &str)]) -> (String, Vec<u8>) {
    let mut body = Vec::new();
    for (name, value) in fields {
        append_value_part(&mut body, boundary, name, value);
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    (boundary.to_owned(), body)
}

fn append_file_part(
    body: &mut Vec<u8>,
    boundary: &str,
    name: &str,
    filename: &str,
    content_type: &str,
    value: &[u8],
) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
        )
        .as_bytes(),
    );
    body.extend_from_slice(value);
    body.extend_from_slice(b"\r\n");
}

fn append_value_part(body: &mut Vec<u8>, boundary: &str, name: &str, value: &str) {
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
        )
        .as_bytes(),
    );
}

async fn response_json(response: Response) -> Result<Value, Box<dyn Error>> {
    Ok(serde_json::from_slice(
        &to_bytes(response.into_body(), BODY_LIMIT).await?,
    )?)
}

fn assert_signed_pdf(bytes: &[u8], expected_pages: usize) -> Result<(), Box<dyn Error>> {
    let document = Document::load_mem(bytes)?;
    assert_eq!(document.get_pages().len(), expected_pages);
    let acro_form_id = document.catalog()?.get(b"AcroForm")?.as_reference()?;
    let fields = document
        .get_object(acro_form_id)?
        .as_dict()?
        .get(b"Fields")?
        .as_array()?;
    assert!(!fields.is_empty());
    let field_id = fields[0].as_reference()?;
    let signature_id = document
        .get_object(field_id)?
        .as_dict()?
        .get(b"V")?
        .as_reference()?;
    assert!(
        document
            .get_object(signature_id)?
            .as_dict()?
            .has(b"ByteRange")
    );
    Ok(())
}

fn single_page_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(Dictionary::new(), Vec::new()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 200.into()],
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
