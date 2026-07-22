use std::io::Cursor;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::ImageFormat;
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;
use zip::ZipArchive;

#[tokio::test]
async fn extracts_unique_page_images_as_png_jpeg_and_gif() -> Result<(), Box<dyn std::error::Error>>
{
    let native = std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_some();
    for (wire_format, extension, image_format) in [
        ("png", "png", ImageFormat::Png),
        ("jpg", "jpg", ImageFormat::Jpeg),
        ("gif", "gif", ImageFormat::Gif),
    ] {
        let response = post_pdf(&pdf_with_reused_image()?, wire_format).await?;
        if !native {
            assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
            continue;
        }
        let response = require_status(response, StatusCode::OK).await?;
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("source_extracted-images.zip")
        );
        let bytes = response_bytes(response).await?;
        let mut archive = ZipArchive::new(Cursor::new(bytes))?;
        assert_eq!(archive.len(), 1, "the reused image must be deduplicated");
        let entry_name = format!("source_page_1_1.{extension}");
        let mut entry = archive.by_name(&entry_name)?;
        let mut encoded = Vec::new();
        std::io::copy(&mut entry, &mut encoded)?;
        let decoded = image::load_from_memory_with_format(&encoded, image_format)?;
        assert_eq!((decoded.width(), decoded.height()), (2, 1));
    }
    Ok(())
}

#[tokio::test]
async fn rejects_an_unknown_output_format() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(&pdf_with_reused_image()?, "bmp").await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
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

async fn post_pdf(pdf: &[u8], format: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-extract-images-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(
        format!(
            "\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"format\"\r\n\r\n{format}\r\n--{boundary}--\r\n"
        )
        .as_bytes(),
    );
    Ok(app(1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/extract-images")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn pdf_with_reused_image() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let image_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => 2,
            "Height" => 1,
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
        },
        vec![255, 0, 0, 0, 255, 0],
    ));
    let mut pages = Vec::new();
    for _ in 0..2 {
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            b"q 20 0 0 10 10 10 cm /Im0 Do Q".to_vec(),
        ));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => root_pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => dictionary! { "XObject" => dictionary! { "Im0" => image_id } },
            "Contents" => content_id,
        }));
    }
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => 2,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => root_pages_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
