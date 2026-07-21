use std::io::Cursor;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, GenericImageView, ImageFormat, Rgb, RgbImage};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn image_scan_extraction_requires_a_file_and_valid_integer_options()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_multipart(None, &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_multipart(
            Some(("scan.png", b"not an image")),
            &[("angleThreshold", "not-an-integer")],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn image_scan_extraction_processes_a_synthetic_png_without_python()
-> Result<(), Box<dyn std::error::Error>> {
    let mut image = RgbImage::from_pixel(180, 140, Rgb([245, 245, 245]));
    for y in 20..120 {
        for x in 30..150 {
            image.put_pixel(x, y, Rgb([30, 80, 130]));
        }
    }
    let mut encoded = Cursor::new(Vec::new());
    DynamicImage::ImageRgb8(image).write_to(&mut encoded, ImageFormat::Png)?;

    let response = post_multipart(
        Some(("scan.png", encoded.get_ref())),
        &[
            ("angleThreshold", "181"),
            ("tolerance", "20"),
            ("minArea", "2147483647"),
            ("minContourArea", "2147483647"),
            ("borderSize", "1"),
        ],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "image/png");
    let output = image::load_from_memory_with_format(
        &to_bytes(response.into_body(), usize::MAX).await?,
        ImageFormat::Png,
    )?;
    assert_eq!(output.dimensions(), (126, 106));
    Ok(())
}

async fn post_multipart(
    file: Option<(&str, &[u8])>,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-image-scans-boundary";
    let mut body = Vec::new();
    if let Some((filename, bytes)) = file {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/octet-stream\r\n\r\n"
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
                .uri("/api/v1/misc/extract-image-scans")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}
