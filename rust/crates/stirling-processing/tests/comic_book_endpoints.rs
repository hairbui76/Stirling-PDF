use std::io::{Cursor, Read, Write};

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, ImageFormat, Rgb, RgbImage};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::{app, runtime_metrics::application_version};
use tower::ServiceExt;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

type ComicEntry<'a> = (&'a str, Option<(u32, u32, [u8; 3])>);

#[tokio::test]
async fn cbz_to_pdf_naturally_sorts_images_and_skips_corrupt_entries()
-> Result<(), Box<dyn std::error::Error>> {
    let cbz = comic_archive(&[
        ("page10.png", Some((30, 31, [0, 0, 255]))),
        ("bad.png", None),
        ("page2.png", Some((20, 21, [0, 255, 0]))),
        ("notes.txt", None),
        ("page1.png", Some((10, 11, [255, 0, 0]))),
    ])?;
    let response = post_file(
        "/api/v1/convert/cbz/pdf",
        "comic.cbz",
        "application/vnd.comicbook+zip",
        &cbz,
        &[("optimizeForEbook", "true")],
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("comic_converted.pdf")
    );
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages();
    assert_eq!(pages.len(), 3);
    assert_eq!(page_size(&document, pages[&1])?, (10.0, 11.0));
    assert_eq!(page_size(&document, pages[&2])?, (20.0, 21.0));
    assert_eq!(page_size(&document, pages[&3])?, (30.0, 31.0));
    let (_, info) = document.dereference(document.trailer.get(b"Info")?)?;
    let info = info.as_dict()?;
    let label = format!("Stirling-PDF v{}", application_version());
    assert_eq!(info.get(b"Creator")?.as_str()?, label.as_bytes());
    assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
    assert!(info.get(b"CreationDate")?.as_datetime().is_some());
    assert!(info.get(b"ModDate")?.as_datetime().is_some());
    Ok(())
}

#[tokio::test]
async fn cbz_to_pdf_accepts_zip_and_uses_the_comic_filename_fallback()
-> Result<(), Box<dyn std::error::Error>> {
    let cbz = comic_archive(&[("cover.webp", Some((8, 12, [4, 5, 6])))])?;
    let response = post_file(
        "/api/v1/convert/cbz/pdf",
        ".cbz",
        "application/zip",
        &cbz,
        &[],
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("comic_converted.pdf")
    );
    Ok(())
}

#[tokio::test]
async fn cbz_to_pdf_rejects_invalid_empty_and_imageless_archives()
-> Result<(), Box<dyn std::error::Error>> {
    let empty = comic_archive(&[])?;
    let no_images = comic_archive(&[("readme.txt", None)])?;
    for (filename, bytes) in [
        ("comic.rar", no_images.as_slice()),
        ("comic.cbz", b"not a zip".as_slice()),
        ("comic.cbz", empty.as_slice()),
        ("comic.cbz", no_images.as_slice()),
    ] {
        assert_eq!(
            post_file(
                "/api/v1/convert/cbz/pdf",
                filename,
                "application/zip",
                bytes,
                &[],
            )
            .await?
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    assert_eq!(
        post_without_file("/api/v1/convert/cbz/pdf").await?.status(),
        StatusCode::BAD_REQUEST
    );
    Ok(())
}

#[tokio::test]
async fn cbr_routes_validate_extensions_and_surface_missing_rar_tooling()
-> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        post_file(
            "/api/v1/convert/cbr/pdf",
            "comic.zip",
            "application/octet-stream",
            b"not a rar",
            &[],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    assert_eq!(
        post_file(
            "/api/v1/convert/pdf/cbr",
            "document.txt",
            "application/octet-stream",
            b"not a pdf",
            &[("dpi", "72")],
        )
        .await?
        .status(),
        StatusCode::BAD_REQUEST
    );
    let response = post_file(
        "/api/v1/convert/pdf/cbr",
        "document.pdf",
        "application/pdf",
        &tiny_pdf()?,
        &[("dpi", "72")],
    )
    .await?;
    assert!(matches!(
        response.status(),
        StatusCode::OK | StatusCode::NOT_IMPLEMENTED
    ));
    Ok(())
}

#[tokio::test]
async fn pdf_to_cbz_renders_numbered_rgb_png_pages() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_file(
        "/api/v1/convert/pdf/cbz",
        "document.pdf",
        "application/pdf",
        &two_page_pdf()?,
        &[("dpi", "72")],
    )
    .await?;
    if !native_pdfium_available() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/zip");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("document_converted.cbz")
    );
    let bytes = response_bytes(response).await?;
    let mut archive = ZipArchive::new(Cursor::new(bytes))?;
    assert_eq!(archive.len(), 2);
    for (name, size) in [("page_001.png", (72, 72)), ("page_002.png", (36, 72))] {
        let mut encoded = Vec::new();
        archive.by_name(name)?.read_to_end(&mut encoded)?;
        let image = image::load_from_memory_with_format(&encoded, ImageFormat::Png)?;
        assert_eq!((image.width(), image.height()), size);
    }
    Ok(())
}

#[tokio::test]
async fn pdf_to_cbz_applies_dpi_fallback_and_validates_inputs()
-> Result<(), Box<dyn std::error::Error>> {
    for (filename, pdf, dpi) in [
        ("document.txt", two_page_pdf()?, "72"),
        ("document.pdf", two_page_pdf()?, "501"),
    ] {
        assert_eq!(
            post_file(
                "/api/v1/convert/pdf/cbz",
                filename,
                "application/pdf",
                &pdf,
                &[("dpi", dpi)],
            )
            .await?
            .status(),
            StatusCode::BAD_REQUEST
        );
    }
    let malformed = post_file(
        "/api/v1/convert/pdf/cbz",
        "document.pdf",
        "application/pdf",
        b"not a pdf",
        &[("dpi", "72")],
    )
    .await?;
    assert_eq!(
        malformed.status(),
        if native_pdfium_available() {
            StatusCode::BAD_REQUEST
        } else {
            StatusCode::NOT_IMPLEMENTED
        }
    );
    assert_eq!(
        post_without_file("/api/v1/convert/pdf/cbz").await?.status(),
        StatusCode::BAD_REQUEST
    );

    let response = post_file(
        "/api/v1/convert/pdf/cbz",
        "tiny.pdf",
        "application/pdf",
        &tiny_pdf()?,
        &[("dpi", "0")],
    )
    .await?;
    if native_pdfium_available() {
        let bytes = response_bytes(require_status(response, StatusCode::OK).await?).await?;
        let mut archive = ZipArchive::new(Cursor::new(bytes))?;
        let mut png = Vec::new();
        archive.by_name("page_001.png")?.read_to_end(&mut png)?;
        let image = image::load_from_memory_with_format(&png, ImageFormat::Png)?;
        assert_eq!((image.width(), image.height()), (30, 30));
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

fn native_pdfium_available() -> bool {
    std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_some()
}

fn comic_archive(entries: &[ComicEntry<'_>]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut output = Cursor::new(Vec::new());
    {
        let mut archive = ZipWriter::new(&mut output);
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, image) in entries {
            archive.start_file(*name, options)?;
            if let Some((width, height, color)) = image {
                let dynamic =
                    DynamicImage::ImageRgb8(RgbImage::from_pixel(*width, *height, Rgb(*color)));
                let format = ImageFormat::from_extension(
                    std::path::Path::new(name)
                        .extension()
                        .and_then(|extension| extension.to_str())
                        .unwrap_or("png"),
                )
                .unwrap_or(ImageFormat::Png);
                let mut encoded = Cursor::new(Vec::new());
                dynamic.write_to(&mut encoded, format)?;
                archive.write_all(&encoded.into_inner())?;
            } else if name.ends_with("bad.png") {
                archive.write_all(b"broken image")?;
            } else {
                archive.write_all(b"metadata")?;
            }
        }
        archive.finish()?;
    }
    Ok(output.into_inner())
}

async fn post_file(
    path: &str,
    filename: &str,
    content_type: &str,
    bytes: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-comic-book-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: {content_type}\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(bytes);
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
                .uri(path)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

async fn post_without_file(path: &str) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-comic-book-empty-boundary";
    Ok(app(1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri(path)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(format!("--{boundary}--\r\n")))?,
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
    page_id: lopdf::ObjectId,
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

fn two_page_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pdf_with_page_sizes(&[(72, 72), (36, 72)])
}

fn tiny_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    pdf_with_page_sizes(&[(7.2_f32, 7.2_f32)])
}

fn pdf_with_page_sizes<T>(sizes: &[(T, T)]) -> Result<Vec<u8>, Box<dyn std::error::Error>>
where
    T: Copy + Into<Object>,
{
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut pages = Vec::new();
    for (width, height) in sizes {
        let content = document.add_object(Stream::new(dictionary! {}, Vec::new()));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), (*width).into(), (*height).into()],
            "Resources" => dictionary! {},
            "Contents" => content,
        }));
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => i64::try_from(sizes.len())?,
        }),
    );
    let catalog = document.add_object(dictionary! { "Type" => "Catalog", "Pages" => pages_id });
    document.trailer.set("Root", catalog);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
