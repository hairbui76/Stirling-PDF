use std::io::Cursor;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage, Rgba, RgbaImage};
use lopdf::{Document, Object, ObjectId};
use stirling_processing::{app, runtime_metrics::application_version};
use tiff::encoder::{TiffEncoder, colortype};
use tower::ServiceExt;

struct InputImage {
    filename: &'static str,
    content_type: &'static str,
    bytes: Vec<u8>,
}

#[tokio::test]
async fn converts_png_jpeg_gif_webp_and_bmp_in_upload_order()
-> Result<(), Box<dyn std::error::Error>> {
    let inputs = [
        encoded_input("first.png", "image/png", ImageFormat::Png, [255, 0, 0])?,
        encoded_input("second.jpg", "image/jpeg", ImageFormat::Jpeg, [0, 255, 0])?,
        encoded_input("third.gif", "image/gif", ImageFormat::Gif, [0, 0, 255])?,
        encoded_input(
            "fourth.webp",
            "image/webp",
            ImageFormat::WebP,
            [255, 255, 0],
        )?,
        encoded_input("fifth.bmp", "image/bmp", ImageFormat::Bmp, [0, 255, 255])?,
    ];
    let response = post_images(&inputs, &[]).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("first_converted.pdf")
    );
    let document = Document::load_mem(&response_bytes(response).await?)?;
    assert_eq!(document.get_pages().len(), inputs.len());
    assert_default_metadata(&document)?;
    for page_id in document.get_pages().values() {
        let (width, height) = page_size(&document, *page_id)?;
        assert!((width - 595.275_63).abs() < 0.01);
        assert!((height - 841.889_8).abs() < 0.01);
    }
    Ok(())
}

#[tokio::test]
async fn expands_every_frame_of_a_multi_page_tiff() -> Result<(), Box<dyn std::error::Error>> {
    let mut bytes = Cursor::new(Vec::new());
    {
        let mut encoder = TiffEncoder::new(&mut bytes)?;
        encoder.write_image::<colortype::RGB8>(4, 3, &[255; 4 * 3 * 3])?;
        encoder.write_image::<colortype::RGB8>(3, 5, &[0; 3 * 5 * 3])?;
    }
    let inputs = [InputImage {
        filename: "scan.tiff",
        content_type: "image/tiff",
        bytes: bytes.into_inner(),
    }];
    let response = post_images(
        &inputs,
        &[("fitOption", "fitDocumentToImage"), ("colorType", "color")],
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let pages = document.get_pages();
    assert_eq!(pages.len(), 2);
    assert_eq!(page_size(&document, pages[&1])?, (4.0, 3.0));
    assert_eq!(page_size(&document, pages[&2])?, (3.0, 5.0));
    Ok(())
}

#[tokio::test]
async fn auto_rotates_a4_and_accepts_the_ui_grayscale_spelling()
-> Result<(), Box<dyn std::error::Error>> {
    let inputs = [encoded_input(
        "landscape.png",
        "image/png",
        ImageFormat::Png,
        [90, 120, 150],
    )?];
    let response = post_images(
        &inputs,
        &[
            ("fitOption", "maintainAspectRatio"),
            ("colorType", "grayscale"),
            ("autoRotate", "true"),
        ],
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = document.get_pages()[&1];
    let (width, height) = page_size(&document, page_id)?;
    assert!(width > height);
    let image = page_image(&document, page_id)?;
    assert_eq!(image.dict.get(b"ColorSpace")?.as_name()?, b"DeviceGray");
    let content = String::from_utf8(document.get_page_content(page_id))?;
    assert!(content.contains("/Im0 Do"));
    assert!(content.contains("841.88977 0 0"));
    Ok(())
}

#[tokio::test]
async fn preserves_alpha_masks_and_emits_binary_pixels() -> Result<(), Box<dyn std::error::Error>> {
    let mut rgba = RgbaImage::from_pixel(20, 40, Rgba([200, 100, 50, 255]));
    rgba.put_pixel(0, 0, Rgba([0, 0, 0, 0]));
    let transparent = encode_image(&DynamicImage::ImageRgba8(rgba), ImageFormat::Png)?;
    let response = post_images(
        &[InputImage {
            filename: "alpha.png",
            content_type: "image/png",
            bytes: transparent,
        }],
        &[("fitOption", "fitDocumentToImage")],
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = document.get_pages()[&1];
    assert_eq!(page_size(&document, page_id)?, (20.0, 40.0));
    assert!(page_image(&document, page_id)?.dict.has(b"SMask"));

    let gradient = RgbImage::from_fn(2, 1, |x, _| {
        if x == 0 {
            Rgb([20, 20, 20])
        } else {
            Rgb([230, 230, 230])
        }
    });
    let response = post_images(
        &[InputImage {
            filename: "binary.png",
            content_type: "image/png",
            bytes: encode_image(&DynamicImage::ImageRgb8(gradient), ImageFormat::Png)?,
        }],
        &[("colorType", "blackwhite")],
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = document.get_pages()[&1];
    assert_eq!(
        page_image(&document, page_id)?.decompressed_content()?,
        vec![0, 255]
    );
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_options_malformed_images_and_missing_uploads()
-> Result<(), Box<dyn std::error::Error>> {
    let valid = [encoded_input(
        "valid.png",
        "image/png",
        ImageFormat::Png,
        [1, 2, 3],
    )?];
    for field in [
        ("fitOption", "stretchMaybe"),
        ("colorType", "sepia"),
        ("autoRotate", "sometimes"),
    ] {
        assert_eq!(
            post_images(&valid, &[field]).await?.status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        post_images(
            &[InputImage {
                filename: "broken.png",
                content_type: "image/png",
                bytes: b"not an image".to_vec(),
            }],
            &[],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_images(&[], &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

fn encoded_input(
    filename: &'static str,
    content_type: &'static str,
    format: ImageFormat,
    color: [u8; 3],
) -> Result<InputImage, image::ImageError> {
    let dimensions = if filename.contains("landscape") {
        (80, 40)
    } else {
        (8, 12)
    };
    let image =
        DynamicImage::ImageRgb8(RgbImage::from_pixel(dimensions.0, dimensions.1, Rgb(color)));
    Ok(InputImage {
        filename,
        content_type,
        bytes: encode_image(&image, format)?,
    })
}

fn encode_image(image: &DynamicImage, format: ImageFormat) -> Result<Vec<u8>, image::ImageError> {
    let mut output = Cursor::new(Vec::new());
    image.write_to(&mut output, format)?;
    Ok(output.into_inner())
}

async fn post_images(
    inputs: &[InputImage],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-image-to-pdf-boundary";
    let mut body = Vec::new();
    for input in inputs {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{}\"\r\nContent-Type: {}\r\n\r\n",
                input.filename, input.content_type
            )
            .as_bytes(),
        );
        body.extend_from_slice(&input.bytes);
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
                .uri("/api/v1/convert/img/pdf")
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

fn page_size(
    document: &Document,
    page_id: ObjectId,
) -> Result<(f32, f32), Box<dyn std::error::Error>> {
    let media_box = document
        .get_object(page_id)?
        .as_dict()?
        .get(b"MediaBox")?
        .as_array()?;
    Ok((object_number(&media_box[2])?, object_number(&media_box[3])?))
}

#[allow(clippy::cast_precision_loss)]
fn object_number(object: &Object) -> Result<f32, Box<dyn std::error::Error>> {
    match object {
        Object::Integer(value) => Ok(*value as f32),
        Object::Real(value) => Ok(*value),
        _ => Err(std::io::Error::other("expected PDF number").into()),
    }
}

fn page_image(
    document: &Document,
    page_id: ObjectId,
) -> Result<&lopdf::Stream, Box<dyn std::error::Error>> {
    let page = document.get_object(page_id)?.as_dict()?;
    let resources = page.get(b"Resources")?.as_dict()?;
    let xobjects = resources.get(b"XObject")?.as_dict()?;
    let image_id = xobjects.get(b"Im0")?.as_reference()?;
    Ok(document.get_object(image_id)?.as_stream()?)
}

fn assert_default_metadata(document: &Document) -> Result<(), Box<dyn std::error::Error>> {
    let (_, info) = document.dereference(document.trailer.get(b"Info")?)?;
    let info = info.as_dict()?;
    let label = format!("Stirling-PDF v{}", application_version());
    assert_eq!(info.get(b"Creator")?.as_str()?, label.as_bytes());
    assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
    assert!(info.get(b"CreationDate")?.as_datetime().is_some());
    assert!(info.get(b"ModDate")?.as_datetime().is_some());
    Ok(())
}
