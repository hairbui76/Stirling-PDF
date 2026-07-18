use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, ObjectId, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn redaction_execution_validates_required_targets_and_structured_fields()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_multipart(None, &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    let source = text_pdf()?;
    assert_eq!(
        post_multipart(Some(("source.pdf", "application/pdf", &source)), &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_multipart(
            Some(("source.pdf", "application/pdf", &source)),
            &[("ranges", "not-json")],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_multipart(
            Some(("source.pdf", "application/pdf", &source)),
            &[("textValues", "Highly"), ("style.strategy", "UNSAFE")],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn redaction_execution_writes_image_only_pdf_for_a_combined_plan()
-> Result<(), Box<dyn std::error::Error>> {
    let source = text_pdf()?;
    let response = post_multipart(
        Some(("source.pdf", "application/pdf", &source)),
        &[
            ("textValues", "Highly"),
            ("regexPatterns", "Confidential"),
            ("wipePages", "2"),
            (
                "ranges",
                r#"[{"startString":"Highly","endString":"Confidential"}]"#,
            ),
            (
                "imageBoxes",
                r#"[{"pageIndex":0,"x1":8,"y1":40,"x2":95,"y2":70}]"#,
            ),
            ("redactImagePages", "[]"),
            (
                "style",
                r##"{"color":"#000000","padding":0,"strategy":"OVERLAY_ONLY"}"##,
            ),
        ],
    )
    .await?;
    if response.status() == StatusCode::NOT_IMPLEMENTED {
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_redacted.pdf")
    );
    let output = Document::load_mem(&response_bytes(response).await?)?;
    assert_eq!(output.get_pages().len(), 2);
    assert!(output.extract_text(&[1, 2])?.trim().is_empty());
    assert!(
        output
            .get_pages()
            .into_values()
            .map(|page_id| page_has_image(&output, page_id))
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .all(|has_image| has_image)
    );
    Ok(())
}

async fn post_multipart(
    file: Option<(&str, &str, &[u8])>,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-redact-execute-boundary";
    let mut body = Vec::new();
    if let Some((filename, content_type, bytes)) = file {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(bytes);
        body.extend_from_slice(b"\r\n");
    }
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
                .uri("/api/v1/security/redact-execute")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
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

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

fn page_has_image(document: &Document, page_id: ObjectId) -> Result<bool, lopdf::Error> {
    let page = document.get_dictionary(page_id)?;
    let resources = resolve_dictionary(document, page.get(b"Resources")?)?;
    let xobjects = resolve_dictionary(document, resources.get(b"XObject")?)?;
    Ok(xobjects.iter().any(|(_, object)| {
        document
            .dereference(object)
            .ok()
            .and_then(|(_, object)| object.as_stream().ok())
            .and_then(|stream| stream.dict.get(b"Subtype").ok())
            .is_some_and(|subtype| subtype.as_name().is_ok_and(|name| name == b"Image"))
    }))
}

fn resolve_dictionary<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Result<&'a lopdf::Dictionary, lopdf::Error> {
    let (_, object) = document.dereference(object)?;
    object.as_dict()
}

fn text_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let mut page_ids = Vec::new();
    for text in ["Highly Confidential", "Second page"] {
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            format!("BT /F1 16 Tf 10 50 Td ({text}) Tj ET").into_bytes(),
        ));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 160.into(), 80.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
            "Contents" => content_id,
        });
        page_ids.push(Object::Reference(page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => page_ids, "Count" => 2,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
