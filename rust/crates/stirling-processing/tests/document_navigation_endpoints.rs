use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use serde_json::{Value, json};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn show_javascript_matches_java_text_contract() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/misc/show-javascript",
            "fileInput",
            &pdf_with_navigation_and_script()?,
            &[],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "text/plain");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.pdf.js")
    );
    assert_eq!(
        String::from_utf8(response_bytes(response).await?)?,
        "// File: source.pdf, Script: startup\napp.alert('ready');\n"
    );

    let response = require_status(
        post_pdf(
            "/api/v1/misc/show-javascript",
            "fileInput",
            &basic_pdf()?,
            &[],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(
        String::from_utf8(response_bytes(response).await?)?,
        "PDF 'source.pdf' does not contain Javascript"
    );
    Ok(())
}

#[tokio::test]
async fn extracts_nested_bookmarks_and_resolves_named_destinations()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/general/extract-bookmarks",
            "file",
            &pdf_with_navigation_and_script()?,
            &[],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    let value: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(
        value,
        json!([{
            "title": "Parent",
            "pageNumber": 2,
            "children": [{
                "title": "Child",
                "pageNumber": 1,
                "children": []
            }]
        }])
    );
    Ok(())
}

#[tokio::test]
async fn edits_the_outline_and_rejects_invalid_json() -> Result<(), Box<dyn std::error::Error>> {
    let bookmark_data = r#"[{"title":"Chương 😀","pageNumber":99,"children":[{"title":"Mục","pageNumber":0,"children":[]}]}]"#;
    let response = require_status(
        post_pdf(
            "/api/v1/general/edit-table-of-contents",
            "fileInput",
            &pdf_with_navigation_and_script()?,
            &[
                ("bookmarkData", bookmark_data),
                ("replaceExisting", "false"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_with_toc.pdf")
    );
    let edited = response_bytes(response).await?;
    let response = require_status(
        post_pdf("/api/v1/general/extract-bookmarks", "file", &edited, &[]).await?,
        StatusCode::OK,
    )
    .await?;
    let value: Value = serde_json::from_slice(&response_bytes(response).await?)?;
    assert_eq!(
        value,
        json!([{
            "title": "Chương 😀",
            "pageNumber": 2,
            "children": [{"title": "Mục", "pageNumber": 1, "children": []}]
        }])
    );

    let invalid = post_pdf(
        "/api/v1/general/edit-table-of-contents",
        "fileInput",
        &basic_pdf()?,
        &[("bookmarkData", "not-json")],
    )
    .await?;
    assert_eq!(invalid.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = response_bytes(response).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

async fn post_pdf(
    path: &str,
    file_field: &str,
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-document-navigation-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"{file_field}\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn pdf_with_navigation_and_script() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let page_one = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
    });
    let page_two = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_one), Object::Reference(page_two)],
            "Count" => 2,
        }),
    );

    let outline_root = document.new_object_id();
    let parent = document.new_object_id();
    let child = document.new_object_id();
    let child_action = document.add_object(dictionary! {
        "S" => "GoTo",
        "D" => Object::string_literal("start"),
    });
    document.objects.insert(
        child,
        Object::Dictionary(dictionary! {
            "Title" => Object::string_literal("Child"),
            "Parent" => parent,
            "A" => child_action,
        }),
    );
    document.objects.insert(
        parent,
        Object::Dictionary(dictionary! {
            "Title" => Object::string_literal("Parent"),
            "Parent" => outline_root,
            "Dest" => vec![Object::Reference(page_two), Object::Name(b"Fit".to_vec())],
            "First" => child,
            "Last" => child,
            "Count" => 1,
        }),
    );
    document.objects.insert(
        outline_root,
        Object::Dictionary(dictionary! {
            "Type" => "Outlines",
            "First" => parent,
            "Last" => parent,
            "Count" => 2,
        }),
    );

    let javascript_action = document.add_object(dictionary! {
        "S" => "JavaScript",
        "JS" => Object::string_literal("app.alert('ready');"),
    });
    let javascript_tree = document.add_object(dictionary! {
        "Names" => vec![
            Object::string_literal("startup"),
            Object::Reference(javascript_action),
        ],
    });
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
        "Outlines" => outline_root,
        "Dests" => dictionary! {
            "start" => vec![Object::Reference(page_one), Object::Name(b"Fit".to_vec())],
        },
        "Names" => dictionary! { "JavaScript" => javascript_tree },
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn basic_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let content = document.add_object(Stream::new(dictionary! {}, Vec::new()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
        "Contents" => content,
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => root_pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
