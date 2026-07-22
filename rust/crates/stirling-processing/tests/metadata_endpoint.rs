use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn updates_standard_and_custom_metadata_with_the_browser_field_shape()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_metadata(
            &metadata_pdf()?,
            &[
                ("deleteAll", "false"),
                ("title", "New title"),
                ("author", "undefined"),
                ("creationDate", "2026/07/15 12:34:56"),
                ("modificationDate", "not a date"),
                ("trapped", "False"),
                ("allRequestParams[customKey1]", "Department"),
                ("allRequestParams[customValue1]", "Engineering"),
                ("allRequestParams[ReviewStatus]", "Approved"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_metadata.pdf")
    );
    let output = response_document(response).await?;
    let info_id = output.trailer.get(b"Info")?.as_reference()?;
    let info = output.get_dictionary(info_id)?;
    assert_eq!(text(info.get(b"Title")?)?, "New title");
    assert_eq!(text(info.get(b"Department")?)?, "Engineering");
    assert_eq!(text(info.get(b"ReviewStatus")?)?, "Approved");
    assert_eq!(text(info.get(b"KeepMe")?)?, "existing");
    assert!(text(info.get(b"CreationDate")?)?.starts_with("D:20260715123456"));
    assert_eq!(info.get(b"Trapped")?.as_name()?, b"False");
    assert!(info.get(b"Author").is_err());
    assert!(info.get(b"ModDate").is_err());
    Ok(())
}

#[tokio::test]
async fn delete_all_clears_info_xmp_and_piece_info() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_metadata(&metadata_pdf()?, &[("deleteAll", "true")]).await?,
        StatusCode::OK,
    )
    .await?;
    let output = response_document(response).await?;
    let info_id = output.trailer.get(b"Info")?.as_reference()?;
    assert_eq!(output.get_dictionary(info_id)?.iter().count(), 0);
    let catalog = output.catalog()?;
    assert!(catalog.get(b"Metadata").is_err());
    assert!(catalog.get(b"PieceInfo").is_err());
    Ok(())
}

fn text(object: &Object) -> Result<String, Box<dyn std::error::Error>> {
    Ok(lopdf::decode_text_string(object)?)
}

async fn response_document(response: Response) -> Result<Document, Box<dyn std::error::Error>> {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(Document::load_mem(&bytes)?)
}

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

async fn post_metadata(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-metadata-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
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
                .uri("/api/v1/misc/update-metadata")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn metadata_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let metadata_id = document.add_object(Stream::new(
        dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
        b"<xmp/>".to_vec(),
    ));
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
        "Metadata" => metadata_id,
        "PieceInfo" => dictionary! { "App" => dictionary! {} },
    });
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Old title"),
        "Author" => Object::string_literal("Old author"),
        "ModDate" => Object::string_literal("D:20200101000000Z"),
        "KeepMe" => Object::string_literal("existing"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
