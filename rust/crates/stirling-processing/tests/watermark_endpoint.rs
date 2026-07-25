use std::io::Cursor;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

struct Upload<'a> {
    field: &'a str,
    filename: &'a str,
    content_type: &'a str,
    bytes: &'a [u8],
}

#[tokio::test]
async fn tiles_unicode_text_watermarks_across_every_page() -> Result<(), Box<dyn std::error::Error>>
{
    let pdf = sample_pdf(2)?;
    let response = post_watermark(
        &[Upload {
            field: "fileInput",
            filename: "source.pdf",
            content_type: "application/pdf",
            bytes: &pdf,
        }],
        &[
            ("watermarkType", "text"),
            ("watermarkText", "DRAFT\\n保密"),
            ("alphabet", "chinese"),
            ("fontSize", "20"),
            ("rotation", "45"),
            ("opacity", "0.35"),
            ("widthSpacer", "20"),
            ("heightSpacer", "20"),
            ("customColor", "ff0000"),
        ],
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_watermarked.pdf")
    );
    let output = Document::load_mem(&response_bytes(response).await?)?;
    assert_eq!(output.get_pages().len(), 2);
    for page_id in output.get_pages().into_values() {
        let page_content = output.get_page_content(page_id);
        let content = String::from_utf8_lossy(&page_content);
        assert!(content.matches("/Watermark").count() > 1);
        assert!(content.contains(" gs "));
        let page = output.get_dictionary(page_id)?;
        let resources = resolve_dictionary(&output, page.get(b"Resources")?)?;
        assert!(!resolve_dictionary(&output, resources.get(b"ExtGState")?)?.is_empty());
        assert!(!resolve_dictionary(&output, resources.get(b"XObject")?)?.is_empty());
    }
    Ok(())
}

#[tokio::test]
async fn tiles_rotated_alpha_images_with_aspect_ratio() -> Result<(), Box<dyn std::error::Error>> {
    let pdf = sample_pdf(1)?;
    let png = alpha_png()?;
    let response = post_watermark(
        &[
            Upload {
                field: "fileInput",
                filename: "image-source.pdf",
                content_type: "application/pdf",
                bytes: &pdf,
            },
            Upload {
                field: "watermarkImage",
                filename: "mark.png",
                content_type: "image/png",
                bytes: &png,
            },
        ],
        &[
            ("watermarkType", "image"),
            ("fontSize", "30"),
            ("rotation", "30"),
            ("opacity", "0.5"),
            ("widthSpacer", "10"),
            ("heightSpacer", "10"),
        ],
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = output.get_pages()[&1];
    let page_content = output.get_page_content(page_id);
    let content = String::from_utf8_lossy(&page_content);
    assert!(content.matches("/WatermarkImage0 Do").count() > 1);
    assert!(content.contains(" 0.5 -0.5 "));
    let resources =
        resolve_dictionary(&output, output.get_dictionary(page_id)?.get(b"Resources")?)?;
    let xobjects = resolve_dictionary(&output, resources.get(b"XObject")?)?;
    let (_, image) = output.dereference(xobjects.get(b"WatermarkImage0")?)?;
    let image = image.as_stream()?;
    assert_eq!(image.dict.get(b"Subtype")?.as_name()?, b"Image");
    assert!(image.dict.has(b"SMask"));
    Ok(())
}

#[tokio::test]
async fn validates_required_inputs_and_watermark_parameters()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = sample_pdf(1)?;
    assert_eq!(
        post_watermark(&[], &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    for fields in [
        vec![("watermarkType", "image")],
        vec![("watermarkType", "text"), ("watermarkText", "")],
        vec![("watermarkType", "text"), ("fontSize", "0")],
        vec![("watermarkType", "text"), ("opacity", "1.1")],
        vec![("watermarkType", "text"), ("widthSpacer", "-1")],
        vec![("watermarkType", "text"), ("convertPDFToImage", "maybe")],
    ] {
        let response = post_watermark(
            &[Upload {
                field: "fileInput",
                filename: "source.pdf",
                content_type: "application/pdf",
                bytes: &pdf,
            }],
            &fields,
        )
        .await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{fields:?}");
    }
    Ok(())
}

#[tokio::test]
async fn preserves_java_no_op_behavior_for_unknown_watermark_types()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = sample_pdf(1)?;
    let response = post_watermark(
        &[Upload {
            field: "fileInput",
            filename: "source.pdf",
            content_type: "application/pdf",
            bytes: &pdf,
        }],
        &[("watermarkType", "nonsense")],
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    assert_eq!(output.get_pages().len(), 1);
    assert!(
        String::from_utf8_lossy(&output.get_page_content(output.get_pages()[&1])).contains("q Q")
    );
    Ok(())
}

#[tokio::test]
async fn convert_to_image_uses_the_shared_native_rasterization_path()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = sample_pdf(1)?;
    let response = post_watermark(
        &[Upload {
            field: "fileInput",
            filename: "source.pdf",
            content_type: "application/pdf",
            bytes: &pdf,
        }],
        &[
            ("watermarkType", "text"),
            ("watermarkText", "FLATTEN"),
            ("convertPDFToImage", "true"),
        ],
    )
    .await?;
    if std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_none() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = output.get_pages()[&1];
    let resources =
        resolve_dictionary(&output, output.get_dictionary(page_id)?.get(b"Resources")?)?;
    assert!(!resolve_dictionary(&output, resources.get(b"XObject")?)?.is_empty());
    Ok(())
}

async fn post_watermark(
    uploads: &[Upload<'_>],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-watermark-boundary";
    let mut body = Vec::new();
    for upload in uploads {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{}\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
                upload.field, upload.filename, upload.content_type
            )
            .as_bytes(),
        );
        body.extend_from_slice(upload.bytes);
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
                .uri("/api/v1/security/add-watermark")
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

fn resolve_dictionary<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Result<&'a lopdf::Dictionary, lopdf::Error> {
    let (_, object) = document.dereference(object)?;
    object.as_dict()
}

fn alpha_png() -> Result<Vec<u8>, image::ImageError> {
    let mut image = RgbaImage::new(4, 2);
    for (index, pixel) in image.pixels_mut().enumerate() {
        let alpha = if index % 2 == 0 { 64 } else { 255 };
        *pixel = Rgba([255, 0, 0, alpha]);
    }
    let mut bytes = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(image).write_to(&mut bytes, ImageFormat::Png)?;
    Ok(bytes.into_inner())
}

fn sample_pdf(page_count: usize) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut pages = Vec::new();
    for _ in 0..page_count {
        let content_id = document.add_object(Stream::new(dictionary! {}, b"q Q".to_vec()));
        pages.push(Object::Reference(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), 180.into(), 120.into()],
            "Resources" => dictionary! {},
            "Contents" => content_id,
        })));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages,
            "Count" => i64::try_from(page_count)?,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
