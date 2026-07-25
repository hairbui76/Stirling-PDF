use std::{fs, process::Command};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::{
    TimestampSettings, app_with_runtime_config, runtime_config::RuntimeConfig,
};
use tempfile::tempdir;
use tower::ServiceExt;

#[tokio::test]
async fn requires_at_least_one_language() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_ocr(&single_page_pdf()?, &[("ocrRenderType", "hocr")]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_response_contains(response, "OCR language options are not specified").await?;
    Ok(())
}

#[tokio::test]
async fn rejects_an_invalid_render_type() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_ocr(
        &single_page_pdf()?,
        &[("languages", "eng"), ("ocrRenderType", "fancy")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_response_contains(
        response,
        "Invalid OCR render type. Must be 'hocr' or 'sandwich'",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn rejects_a_request_when_no_selected_language_is_installed()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_ocr(
        &single_page_pdf()?,
        &[("languages", "fra"), ("languages", "ENG")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_response_contains(
        response,
        "Invalid OCR languages format: none of the selected languages are valid",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn preserves_whitespace_during_java_compatible_validation()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_ocr(
        &single_page_pdf()?,
        &[("languages", " eng "), ("ocrRenderType", "hocr")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_response_contains(
        response,
        "Invalid OCR languages format: none of the selected languages are valid",
    )
    .await?;

    let response = post_ocr(
        &single_page_pdf()?,
        &[("languages", "eng"), ("ocrRenderType", " hocr ")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    assert_response_contains(
        response,
        "Invalid OCR render type. Must be 'hocr' or 'sandwich'",
    )
    .await?;
    Ok(())
}

#[tokio::test]
async fn ocr_follows_available_tooling() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_ocr(&single_page_pdf()?, &[("languages", "eng")]).await?;
    if ocrmypdf_present() || tesseract_present() {
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
        assert!(response_bytes(response).await?.starts_with(b"%PDF"));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

fn tesseract_present() -> bool {
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_TESSERACT_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["tesseract.exe", "tesseract"]
    } else {
        &["tesseract"]
    };
    candidates
        .iter()
        .any(|command| Command::new(command).arg("--version").output().is_ok())
}

fn ocrmypdf_present() -> bool {
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_OCRMYPDF_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    let candidates: &[&str] = if cfg!(windows) {
        &["ocrmypdf.exe", "ocrmypdf"]
    } else {
        &["ocrmypdf"]
    };
    candidates
        .iter()
        .any(|command| Command::new(command).arg("--version").output().is_ok())
}

async fn response_bytes(response: Response) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    Ok(to_bytes(response.into_body(), usize::MAX).await?.to_vec())
}

async fn assert_response_contains(
    response: Response,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let body = response_bytes(response).await?;
    let body = String::from_utf8_lossy(&body);
    if body.contains(expected) {
        return Ok(());
    }
    Err(std::io::Error::other(format!(
        "expected response body to contain {expected:?}, received {body}"
    ))
    .into())
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

async fn post_ocr(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let directory = tempdir()?;
    let tessdata = directory.path().join("tessdata");
    fs::create_dir(&tessdata)?;
    fs::write(tessdata.join("eng.traineddata"), "test")?;
    let settings = directory.path().join("settings.yml");
    fs::write(
        &settings,
        format!(
            "system:\n  tessdataDir: {}\n",
            tessdata.to_string_lossy().replace('\\', "/")
        ),
    )?;
    let runtime_config = RuntimeConfig::from_files(settings, directory.path().join("missing.yml"));

    let boundary = "stirling-ocr-boundary";
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
    Ok(
        app_with_runtime_config(1024 * 1024, TimestampSettings::default(), runtime_config)
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/api/v1/misc/ocr-pdf")
                    .header(
                        header::CONTENT_TYPE,
                        format!("multipart/form-data; boundary={boundary}"),
                    )
                    .body(Body::from(body))?,
            )
            .await?,
    )
}

fn single_page_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(Stream::new(dictionary! {}, b"".to_vec()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 160.into()],
        "Resources" => dictionary! {},
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
