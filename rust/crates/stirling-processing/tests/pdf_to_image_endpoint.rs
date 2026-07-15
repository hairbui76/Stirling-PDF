use std::io::{Cursor, Read};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, GenericImageView, ImageFormat};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn converts_selected_pages_to_numbered_png_archive() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_pdf(
        &two_page_pdf()?,
        &[
            ("imageFormat", "png"),
            ("singleOrMultiple", "multiple"),
            ("colorType", "grayscale"),
            ("dpi", "72"),
            ("pageNumbers", "2,1"),
            ("includeAnnotations", "false"),
        ],
    )
    .await?;
    if !native_pdfium_available() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(
        response.headers()[header::CONTENT_TYPE],
        "application/octet-stream"
    );
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_convertedToImages.zip")
    );
    let bytes = response_bytes(response).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 2);
    for (name, expected_size) in [("source_1.png", (36, 72)), ("source_2.png", (72, 72))] {
        let mut encoded = Vec::new();
        archive.by_name(name)?.read_to_end(&mut encoded)?;
        let image = image::load_from_memory_with_format(&encoded, ImageFormat::Png)?;
        assert_eq!(image.dimensions(), expected_size);
        assert!(matches!(image, DynamicImage::ImageLuma8(_)));
    }
    Ok(())
}

#[tokio::test]
async fn combines_pages_vertically_and_centres_narrow_pages()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(
        &two_page_pdf()?,
        &[
            ("imageFormat", "png"),
            ("singleOrMultiple", "single"),
            ("colorType", "color"),
            ("dpi", "72"),
            ("pageNumbers", "all"),
        ],
    )
    .await?;
    if !native_pdfium_available() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source.png")
    );
    let image =
        image::load_from_memory_with_format(&response_bytes(response).await?, ImageFormat::Png)?;
    assert_eq!(image.dimensions(), (72, 144));
    assert_eq!(image.get_pixel(5, 100).0[3], 0);
    assert_eq!(image.get_pixel(30, 100).0[3], 255);
    Ok(())
}

#[tokio::test]
async fn encodes_single_jpeg_gif_and_webp_outputs() -> Result<(), Box<dyn std::error::Error>> {
    for (wire_format, image_format, content_type) in [
        ("jpg", ImageFormat::Jpeg, "image/jpeg"),
        ("gif", ImageFormat::Gif, "image/gif"),
        ("webp", ImageFormat::WebP, "image/webp"),
    ] {
        let response = post_pdf(
            &two_page_pdf()?,
            &[
                ("imageFormat", wire_format),
                ("singleOrMultiple", "single"),
                ("colorType", "blackwhite"),
                ("dpi", "72"),
                ("pageNumbers", "1"),
            ],
        )
        .await?;
        if !native_pdfium_available() {
            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
            continue;
        }
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(response.headers()[header::CONTENT_TYPE], content_type);
        let decoded =
            image::load_from_memory_with_format(&response_bytes(response).await?, image_format)?;
        assert_eq!(decoded.dimensions(), (72, 72));
    }
    Ok(())
}

#[tokio::test]
async fn applies_schema_defaults_for_a_pdf_only_request() -> Result<(), Box<dyn std::error::Error>>
{
    let response = post_pdf(&two_page_pdf()?, &[]).await?;
    if !native_pdfium_available() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    let bytes = response_bytes(response).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 2);
    assert!(archive.by_name("source_1.png").is_ok());
    assert!(archive.by_name("source_2.png").is_ok());
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_options_and_a_missing_file() -> Result<(), Box<dyn std::error::Error>> {
    for field in [
        ("imageFormat", "bmp"),
        ("singleOrMultiple", "archive"),
        ("colorType", "sepia"),
        ("dpi", "0"),
        ("dpi", "501"),
        ("includeAnnotations", "sometimes"),
    ] {
        let response = post_pdf(&two_page_pdf()?, &[field]).await?;
        assert_eq!(
            response.status(),
            StatusCode::BAD_REQUEST,
            "field {field:?}"
        );
    }
    let boundary = "stirling-pdf-to-image-missing-file";
    let response = app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/convert/pdf/img")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(format!(
                    "--{boundary}\r\nContent-Disposition: form-data; name=\"dpi\"\r\n\r\n72\r\n--{boundary}--\r\n"
                )))?,
        )
        .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn native_pdfium_available() -> bool {
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

async fn post_pdf(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-to-image-boundary";
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
                .uri("/api/v1/convert/pdf/img")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn two_page_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let page_specs = [
        (72, 72, b"1 0 0 rg 6 6 60 60 re f".as_slice()),
        (36, 72, b"0 0 1 rg 4 4 28 64 re f".as_slice()),
    ];
    let mut pages = Vec::new();
    for (width, height, content) in page_specs {
        let content_id = document.add_object(Stream::new(dictionary! {}, content.to_vec()));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), width.into(), height.into()],
            "CropBox" => vec![0.into(), 0.into(), width.into(), height.into()],
            "Resources" => dictionary! {},
            "Contents" => content_id,
        }));
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => 2,
        }),
    );
    let catalog_id = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
