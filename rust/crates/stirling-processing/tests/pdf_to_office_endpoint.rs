use std::process::Command;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn rejects_an_unknown_output_format() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf_to_office(
        "/api/v1/convert/pdf/word",
        &single_page_pdf()?,
        &[("outputFormat", "pages")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn word_conversion_follows_libreoffice_availability() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_pdf_to_office("/api/v1/convert/pdf/word", &single_page_pdf()?, &[]).await?;
    if libreoffice_present() {
        let response = require_status(response, StatusCode::OK).await?;
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("source")
        );
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

#[tokio::test]
async fn xml_endpoint_is_wired() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf_to_office("/api/v1/convert/pdf/xml", &single_page_pdf()?, &[]).await?;
    let status = response.status();
    assert!(
        status == StatusCode::OK || status == StatusCode::NOT_IMPLEMENTED,
        "unexpected status {status}"
    );
    Ok(())
}

fn libreoffice_present() -> bool {
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_SOFFICE_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["soffice.com", "soffice.exe", "soffice"]
    } else {
        &["soffice", "/usr/bin/soffice"]
    };
    candidates
        .iter()
        .any(|command| Command::new(command).arg("--version").output().is_ok())
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

async fn post_pdf_to_office(
    uri: &str,
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-to-office-boundary";
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
                .uri(uri)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn single_page_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 50 Td (Convert me) Tj ET".to_vec(),
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
