use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn structurally_compresses_pdf_streams_and_uses_java_filename()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = pdf_with_large_content()?;
    let response = post_compress(&pdf, &[("optimizeLevel", "3")]).await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_Optimized.pdf")
    );
    let bytes = response_bytes(response).await?;
    assert!(bytes.len() < pdf.len());
    assert_eq!(Document::load_mem(&bytes)?.get_pages().len(), 1);
    Ok(())
}

#[tokio::test]
async fn converts_embedded_images_to_grayscale_without_rasterizing_pages()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = pdf_with_rgb_image(600, 600)?;
    let response = post_compress(&pdf, &[("optimizeLevel", "4"), ("grayscale", "true")]).await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let image = first_image(&output)?;
    assert_eq!(image.dict.get(b"ColorSpace")?.as_name()?, b"DeviceGray");
    assert_eq!(image.dict.get(b"BitsPerComponent")?.as_i64()?, 8);
    assert_eq!(image.dict.get(b"Filter")?.as_name()?, b"DCTDecode");
    assert!(!output.get_page_content(output.get_pages()[&1]).is_empty());
    Ok(())
}

#[tokio::test]
async fn converts_embedded_images_to_one_bit_line_art_natively()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = pdf_with_rgb_image(500, 500)?;
    let response = post_compress(
        &pdf,
        &[
            ("optimizeLevel", "5"),
            ("lineArt", "true"),
            ("lineArtThreshold", "55"),
            ("lineArtEdgeLevel", "2"),
        ],
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let image = first_image(&output)?;
    assert_eq!(image.dict.get(b"ColorSpace")?.as_name()?, b"DeviceGray");
    assert_eq!(image.dict.get(b"BitsPerComponent")?.as_i64()?, 1);
    assert!(image.content.len() < 500 * 500 * 3);
    Ok(())
}

#[tokio::test]
async fn accepts_target_size_mode_and_returns_a_valid_best_effort_pdf()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = pdf_with_large_content()?;
    let response = post_compress(
        &pdf,
        &[("optimizeLevel", "5"), ("expectedOutputSize", "1 KB")],
    )
    .await?;
    let bytes = response_bytes(require_status(response, StatusCode::OK).await?).await?;
    assert_eq!(Document::load_mem(&bytes)?.get_pages().len(), 1);
    Ok(())
}

#[tokio::test]
async fn validates_compression_parameters_before_processing()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = pdf_with_large_content()?;
    assert_eq!(
        post_compress_body(None, &[]).await?.status(),
        StatusCode::BAD_REQUEST
    );
    for fields in [
        vec![("optimizeLevel", "0")],
        vec![("expectedOutputSize", "not-a-size")],
        vec![("lineArtThreshold", "101")],
        vec![("lineArtEdgeLevel", "4")],
        vec![("grayscale", "sometimes")],
    ] {
        let response = post_compress(&pdf, &fields).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST, "{fields:?}");
    }
    Ok(())
}

async fn post_compress(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    post_compress_body(Some(pdf), fields).await
}

async fn post_compress_body(
    pdf: Option<&[u8]>,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-compress-boundary";
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
    for (name, value) in fields {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n\r\n{value}\r\n"
            )
            .as_bytes(),
        );
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(4 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/misc/compress-pdf")
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

fn first_image(document: &Document) -> Result<&Stream, Box<dyn std::error::Error>> {
    document
        .objects
        .values()
        .filter_map(|object| object.as_stream().ok())
        .find(|stream| {
            stream
                .dict
                .get(b"Subtype")
                .ok()
                .and_then(|value| value.as_name().ok())
                .is_some_and(|name| name == b"Image")
        })
        .ok_or_else(|| std::io::Error::other("output PDF has no image").into())
}

fn pdf_with_large_content() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let content = "0 0 m 100 100 l S\n".repeat(20_000).into_bytes();
    pdf_with_streams(Stream::new(dictionary! {}, content), None)
}

fn pdf_with_rgb_image(width: u32, height: u32) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let capacity = usize::try_from(u64::from(width) * u64::from(height) * 3)?;
    let mut pixels = Vec::with_capacity(capacity);
    for y in 0..height {
        for x in 0..width {
            let red = u8::try_from(x % 256)?;
            let green = u8::try_from(y % 256)?;
            let blue = u8::try_from((x + y) % 256)?;
            pixels.extend_from_slice(&[red, green, blue]);
        }
    }
    let image = Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => i64::from(width),
            "Height" => i64::from(height),
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
        },
        pixels,
    );
    pdf_with_streams(
        Stream::new(dictionary! {}, b"q 180 0 0 120 0 0 cm /Im0 Do Q".to_vec()),
        Some(image),
    )
}

fn pdf_with_streams(
    content: Stream,
    image: Option<Stream>,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let content_id = document.add_object(content);
    let mut resources = Dictionary::new();
    if let Some(image) = image {
        let image_id = document.add_object(image);
        resources.set("XObject", dictionary! { "Im0" => image_id });
    }
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 180.into(), 120.into()],
        "Resources" => resources,
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
