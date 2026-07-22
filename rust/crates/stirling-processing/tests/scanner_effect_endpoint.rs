use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, ObjectId, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn applies_scanner_effect_and_preserves_page_size() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_scanner_effect(
        &single_text_page()?,
        &[("quality", "high"), ("rotation", "none")],
    )
    .await?;
    if !native_pdfium_requested() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_scanner_effect.pdf")
    );
    let output = Document::load_mem(&response_bytes(response).await?)?;
    assert_eq!(output.get_pages().len(), 1);
    let page = output.get_dictionary(first_page_id(&output)?)?;
    assert_eq!(page.get(b"MediaBox")?.as_array()?.len(), 4);
    let resources = resolve_dictionary(&output, page.get(b"Resources")?)?;
    let xobjects = resolve_dictionary(&output, resources.get(b"XObject")?)?;
    assert!(xobjects.iter().any(|(_, object)| {
        output
            .dereference(object)
            .ok()
            .and_then(|(_, object)| object.as_stream().ok())
            .and_then(|stream| stream.dict.get(b"Subtype").ok())
            .is_some_and(|subtype| subtype.as_name().is_ok_and(|name| name == b"Image"))
    }));
    assert!(output.extract_text(&[1])?.trim().is_empty());
    Ok(())
}

#[tokio::test]
async fn rejects_a_resolution_above_the_safe_limit() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_scanner_effect(
        &single_text_page()?,
        &[("advancedEnabled", "true"), ("resolution", "100000")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn rejects_an_unknown_quality() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_scanner_effect(&single_text_page()?, &[("quality", "ultra")]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn rejects_an_unknown_colorspace() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_scanner_effect(&single_text_page()?, &[("colorspace", "sepia")]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn requires_a_file() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-scanner-empty";
    let body = format!("--{boundary}--\r\n").into_bytes();
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/scanner-effect")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn native_pdfium_requested() -> bool {
    std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_some()
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

async fn post_scanner_effect(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-scanner-effect-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/scanner-effect")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn first_page_id(document: &Document) -> Result<ObjectId, Box<dyn std::error::Error>> {
    document
        .get_pages()
        .into_values()
        .next()
        .ok_or_else(|| std::io::Error::other("PDF has no pages").into())
}

fn resolve_dictionary<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Result<&'a lopdf::Dictionary, lopdf::Error> {
    let (_, object) = document.dereference(object)?;
    object.as_dict()
}

fn single_text_page() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 50 Td (Selectable text) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
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
