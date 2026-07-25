use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn renames_from_text_and_sanitizes_unsafe_filename_characters()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(&text_pdf("Report:/2026", 24.0)?, false).await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("Report2026.pdf")
    );
    let output = response_bytes(response).await?;
    assert_eq!(Document::load_mem(&output)?.get_pages().len(), 1);
    Ok(())
}

#[tokio::test]
async fn preserves_the_uploaded_name_when_no_title_is_found()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(post_pdf(&blank_pdf()?, true).await?, StatusCode::OK).await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.pdf")
    );
    Ok(())
}

#[tokio::test]
async fn native_pdfium_selects_the_largest_font_line() -> Result<(), Box<dyn std::error::Error>> {
    if std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_none() {
        return Ok(());
    }
    let response = require_status(
        post_pdf(&two_size_text_pdf()?, false).await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("Main%20Title.pdf")
    );
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
    pdf: &[u8],
    use_first_text_as_fallback: bool,
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-auto-rename-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"useFirstTextAsFallback\"\r\n\r\n{use_first_text_as_fallback}\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/auto-rename")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn text_pdf(text: &str, font_size: f32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pdf_with_content(format!(
        "BT /F1 {font_size} Tf 40 240 Td ({}) Tj ET",
        escape_pdf_text(text)
    ))
}

fn two_size_text_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pdf_with_content(
        "BT /F1 10 Tf 40 240 Td (Body text) Tj ET BT /F1 24 Tf 40 180 Td (Main Title) Tj ET"
            .to_owned(),
    )
}

fn blank_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pdf_with_content(String::new())
}

fn pdf_with_content(content: String) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "Encoding" => "WinAnsiEncoding",
    });
    let content_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 300.into(), 300.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        "Contents" => content_id,
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

fn escape_pdf_text(text: &str) -> String {
    text.replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}
