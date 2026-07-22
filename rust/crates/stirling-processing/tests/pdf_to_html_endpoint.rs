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
async fn conversion_follows_pdftohtml_availability() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(&single_page_pdf()?).await?;
    if pdftohtml_present() {
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(
            response.headers()[header::CONTENT_TYPE],
            "application/octet-stream"
        );
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("ToHtml.zip")
        );
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

#[tokio::test]
async fn requires_a_file() -> Result<(), Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-html-empty";
    let body = format!("--{boundary}--\r\n").into_bytes();
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/html")
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

fn pdftohtml_present() -> bool {
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_PDFTOHTML_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("-v").output().is_ok();
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["pdftohtml.exe", "pdftohtml"]
    } else {
        &["pdftohtml"]
    };
    candidates
        .iter()
        .any(|command| Command::new(command).arg("-v").output().is_ok())
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

async fn post_pdf(pdf: &[u8]) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-to-html-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/html")
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
        b"BT /F1 12 Tf 10 50 Td (Hello HTML) Tj ET".to_vec(),
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
