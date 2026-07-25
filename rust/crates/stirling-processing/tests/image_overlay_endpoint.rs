use std::io::Cursor;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use lopdf::{Document, Object, ObjectId, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn overlays_a_transparent_raster_at_intrinsic_size_and_coordinates()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_overlay(
        Some(&two_page_pdf()?),
        Some(&png_overlay()?),
        &[("x", "10.5"), ("y", "20.25")],
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_overlayed.pdf")
    );
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages();
    let first_content = String::from_utf8(document.get_page_content(pages[&1]))?;
    let second_content = String::from_utf8(document.get_page_content(pages[&2]))?;
    assert!(first_content.contains("4 0 0 3 10.5 20.25 cm"));
    assert!(first_content.contains("/OverlayImage0 Do"));
    assert!(!second_content.contains("OverlayImage"));
    let image = page_overlay(&document, pages[&1], b"OverlayImage0")?;
    assert_eq!(image.dict.get(b"Subtype")?.as_name()?, b"Image");
    assert_eq!(image.dict.get(b"Width")?.as_i64()?, 4);
    assert_eq!(image.dict.get(b"Height")?.as_i64()?, 3);
    assert!(image.dict.has(b"SMask"));
    Ok(())
}

#[tokio::test]
async fn every_page_overlays_all_pages() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_overlay(
        Some(&two_page_pdf()?),
        Some(&png_overlay()?),
        &[("everyPage", "true")],
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    for (page_number, page_id) in document.get_pages() {
        let content = String::from_utf8(document.get_page_content(page_id))?;
        assert!(content.contains(&format!("/OverlayImage{} Do", page_number - 1)));
    }
    Ok(())
}

#[tokio::test]
async fn keeps_safe_svg_overlays_as_vector_forms() -> Result<(), Box<dyn std::error::Error>> {
    let svg = br#"<svg xmlns="http://www.w3.org/2000/svg" width="8" height="6"><rect width="8" height="6" fill="red"/></svg>"#;
    let response =
        post_overlay(Some(&two_page_pdf()?), Some(svg), &[("x", "2"), ("y", "3")]).await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = document.get_pages()[&1];
    let form = page_overlay(&document, page_id, b"OverlayImage0")?;
    assert_eq!(form.dict.get(b"Subtype")?.as_name()?, b"Form");
    assert!(String::from_utf8(document.get_page_content(page_id))?.contains(" 2 3 cm"));
    Ok(())
}

#[tokio::test]
async fn rejects_unsafe_svg_malformed_images_and_invalid_pdfs()
-> Result<(), Box<dyn std::error::Error>> {
    let unsafe_svg =
        br#"<svg xmlns="http://www.w3.org/2000/svg"><image href="file:///secret"/></svg>"#;
    assert_eq!(
        post_overlay(Some(&two_page_pdf()?), Some(unsafe_svg), &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_overlay(Some(&two_page_pdf()?), Some(b"not an image"), &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_overlay(Some(b"not a pdf"), Some(&png_overlay()?), &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn validates_required_uploads_booleans_and_finite_coordinates()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_overlay(None, Some(&png_overlay()?), &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_overlay(Some(&two_page_pdf()?), None, &[])
            .await?
            .status(),
        StatusCode::BAD_REQUEST
    );
    for field in [("everyPage", "sometimes"), ("x", "NaN"), ("y", "infinity")] {
        assert_eq!(
            post_overlay(Some(&two_page_pdf()?), Some(&png_overlay()?), &[field])
                .await?
                .status(),
            StatusCode::BAD_REQUEST
        );
    }
    Ok(())
}

async fn post_overlay(
    pdf: Option<&[u8]>,
    image: Option<&[u8]>,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-image-overlay-boundary";
    let mut body = Vec::new();
    if let Some(pdf) = pdf {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(pdf);
        body.extend_from_slice(b"\r\n");
    }
    if let Some(image) = image {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"imageFile\"; filename=\"overlay.bin\"\r\nContent-Type: application/octet-stream\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(image);
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
                .uri("/api/v1/misc/add-image")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
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

fn page_overlay<'a>(
    document: &'a Document,
    page_id: ObjectId,
    name: &[u8],
) -> Result<&'a Stream, lopdf::Error> {
    let page = document.get_dictionary(page_id)?;
    let (_, resources) = document.dereference(page.get(b"Resources")?)?;
    let (_, xobjects) = document.dereference(resources.as_dict()?.get(b"XObject")?)?;
    let (_, overlay) = document.dereference(xobjects.as_dict()?.get(name)?)?;
    overlay.as_stream()
}

fn png_overlay() -> Result<Vec<u8>, image::ImageError> {
    let mut image = RgbaImage::from_pixel(4, 3, Rgba([10, 20, 30, 255]));
    image.put_pixel(0, 0, Rgba([10, 20, 30, 0]));
    let mut bytes = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(image).write_to(&mut bytes, ImageFormat::Png)?;
    Ok(bytes.into_inner())
}

fn two_page_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut pages = Vec::new();
    for index in 0..2 {
        let content = document.add_object(Stream::new(
            dictionary! {},
            format!("q {index} 0 0 {index} 0 0 cm Q").into_bytes(),
        ));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
            "Resources" => dictionary! {},
            "Contents" => content,
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
    let catalog = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
