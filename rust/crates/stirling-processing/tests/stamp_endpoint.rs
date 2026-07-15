use std::io::Cursor;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use image::{DynamicImage, ImageFormat, Rgba, RgbaImage};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, StringFormat, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

type InvalidStampCase<'a> = (&'a [u8], Option<&'a [u8]>, &'a [(&'a str, &'a str)]);

#[tokio::test]
async fn stamps_processed_text_on_selected_pages_with_rotation_and_opacity()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_stamp(
        &metadata_pdf()?,
        None,
        &[
            ("stampType", "text"),
            (
                "stampText",
                "Page @page/@total_pages @filename @title @@literal",
            ),
            ("pageNumbers", "2"),
            ("fontSize", "20"),
            ("rotation", "30"),
            ("opacity", "0.4"),
            ("position", "5"),
            ("customColor", "#112233"),
        ],
    )
    .await?;
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_stamped.pdf")
    );
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages();
    assert!(!String::from_utf8(document.get_page_content(pages[&1]))?.contains("Stamp"));
    let content = String::from_utf8(document.get_page_content(pages[&2]))?;
    assert!(content.contains("/StampGS2 gs"));
    assert!(content.contains("0.866025 0.5 -0.5 0.866025"));
    assert!(content.contains("/Stamp2 Do"));
    let form = page_resource(&document, pages[&2], b"XObject", b"Stamp2")?;
    assert_eq!(form.as_stream()?.dict.get(b"Subtype")?.as_name()?, b"Form");
    let state = page_resource(&document, pages[&2], b"ExtGState", b"StampGS2")?;
    assert!((state.as_dict()?.get(b"ca")?.as_float()? - 0.4).abs() < 0.001);
    Ok(())
}

#[tokio::test]
async fn accepts_unicode_text_and_java_style_page_expressions()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_stamp(
        &metadata_pdf()?,
        None,
        &[
            ("stampType", "text"),
            ("stampText", "مرحبا 日本語 @date{dd/MM/yyyy}"),
            ("alphabet", "arabic"),
            ("pageNumbers", "2n"),
            ("fontSize", "18"),
        ],
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let pages = document.get_pages();
    assert!(!String::from_utf8(document.get_page_content(pages[&1]))?.contains("Stamp"));
    assert!(String::from_utf8(document.get_page_content(pages[&2]))?.contains("/Stamp2 Do"));
    Ok(())
}

#[tokio::test]
async fn sizes_positions_and_clamps_transparent_image_stamps()
-> Result<(), Box<dyn std::error::Error>> {
    let image = png_stamp()?;
    let response = post_stamp(
        &metadata_pdf()?,
        Some(&image),
        &[
            ("stampType", "image"),
            ("pageNumbers", "1"),
            ("fontSize", "20"),
            ("position", "1"),
            ("customMargin", "small"),
            ("opacity", "0.75"),
        ],
    )
    .await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page_id = document.get_pages()[&1];
    let content = String::from_utf8(document.get_page_content(page_id))?;
    assert!(content.contains("1 0 0 1 3 177 cm"));
    assert!(content.contains("40 0 0 20 0 0 cm"));
    let image = page_resource(&document, page_id, b"XObject", b"Stamp1")?.as_stream()?;
    assert_eq!(image.dict.get(b"Subtype")?.as_name()?, b"Image");
    assert!(image.dict.has(b"SMask"));
    Ok(())
}

#[tokio::test]
async fn applies_documented_defaults_to_all_pages() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_stamp(&metadata_pdf()?, None, &[("stampType", "text")]).await?;
    let document = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    for (page_number, page_id) in document.get_pages() {
        let content = String::from_utf8(document.get_page_content(page_id))?;
        assert!(content.contains(&format!("/Stamp{page_number} Do")));
        assert!(content.contains(&format!("/StampGS{page_number} gs")));
    }
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_parameters_uploads_and_inputs() -> Result<(), Box<dyn std::error::Error>> {
    let pdf = metadata_pdf()?;
    let image = png_stamp()?;
    let invalid_cases: &[InvalidStampCase<'_>] = &[
        (&pdf, None, &[("stampType", "image")]),
        (&pdf, None, &[("stampType", "seal")]),
        (
            &pdf,
            Some(&image),
            &[("stampType", "image"), ("fontSize", "0")],
        ),
        (&pdf, None, &[("stampType", "text"), ("opacity", "1.1")]),
        (&pdf, None, &[("stampType", "text"), ("position", "10")]),
        (&pdf, None, &[("stampType", "text"), ("rotation", "NaN")]),
        (&pdf, Some(b"not an image"), &[("stampType", "image")]),
        (b"not a pdf", None, &[("stampType", "text")]),
    ];
    for (input_pdf, stamp_image, fields) in invalid_cases {
        assert_eq!(
            post_stamp(input_pdf, *stamp_image, fields).await?.status(),
            StatusCode::BAD_REQUEST
        );
    }
    Ok(())
}

async fn post_stamp(
    pdf: &[u8],
    stamp_image: Option<&[u8]>,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-stamp-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"source.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
    if let Some(image) = stamp_image {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"stampImage\"; filename=\"stamp.png\"\r\nContent-Type: image/png\r\n\r\n"
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
                .uri("/api/v1/misc/add-stamp")
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

fn page_resource<'a>(
    document: &'a Document,
    page_id: ObjectId,
    category: &[u8],
    name: &[u8],
) -> Result<&'a Object, lopdf::Error> {
    let page = document.get_dictionary(page_id)?;
    let (_, resources) = document.dereference(page.get(b"Resources")?)?;
    let (_, category) = document.dereference(resources.as_dict()?.get(category)?)?;
    let (_, value) = document.dereference(category.as_dict()?.get(name)?)?;
    Ok(value)
}

fn png_stamp() -> Result<Vec<u8>, image::ImageError> {
    let mut image = RgbaImage::from_pixel(4, 2, Rgba([200, 20, 30, 255]));
    image.put_pixel(0, 0, Rgba([200, 20, 30, 0]));
    let mut bytes = Cursor::new(Vec::new());
    DynamicImage::ImageRgba8(image).write_to(&mut bytes, ImageFormat::Png)?;
    Ok(bytes.into_inner())
}

fn metadata_pdf() -> Result<Vec<u8>, lopdf::Error> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut pages = Vec::new();
    for page_number in 1..=2 {
        let content = document.add_object(Stream::new(
            dictionary! {},
            format!("q {page_number} 0 0 {page_number} 0 0 cm Q").into_bytes(),
        ));
        pages.push(document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "MediaBox" => vec![0.into(), 0.into(), 100.into(), 200.into()],
            "Resources" => Dictionary::new(),
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
    let info = document.add_object(dictionary! {
        "Title" => Object::String(b"Quarterly Report".to_vec(), StringFormat::Literal),
        "Author" => Object::String(b"Stirling".to_vec(), StringFormat::Literal),
    });
    document.trailer.set("Root", catalog);
    document.trailer.set("Info", info);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
