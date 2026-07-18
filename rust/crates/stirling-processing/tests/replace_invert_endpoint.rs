use std::process::Command;

use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, ObjectId, Stream, content::Content, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn full_inversion_rebuilds_pages_as_images() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_replace_invert(
        &single_text_page()?,
        &[("replaceAndInvertOption", "FULL_INVERSION")],
    )
    .await?;
    if !native_pdfium_requested() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("source_inverted.pdf")
    );
    let output = Document::load_mem(&response_bytes(response).await?)?;
    let page = output.get_dictionary(first_page_id(&output)?)?;
    assert_eq!(page.get(b"MediaBox")?.as_array()?.len(), 4);
    let resources = resolve_dictionary(&output, page.get(b"Resources")?)?;
    let xobjects = resolve_dictionary(&output, resources.get(b"XObject")?)?;
    assert!(xobjects.iter().any(|(_, object)| {
        output
            .dereference(object)
            .ok()
            .and_then(|(_, object)| object.as_stream().ok())
            .and_then(|stream| stream.dict.get(b"Subtype").ok())
            .is_some_and(|subtype| subtype.as_name().is_ok_and(|name| name == b"Image"))
    }));
    assert!(output.extract_text(&[1])?.trim().is_empty());
    Ok(())
}

#[tokio::test]
async fn high_contrast_mode_recolors_text_and_prepends_background()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_replace_invert(
        &single_text_page()?,
        &[
            ("replaceAndInvertOption", "HIGH_CONTRAST_COLOR"),
            ("highContrastColorCombination", "YELLOW_TEXT_ON_BLACK"),
        ],
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    assert_eq!(output.extract_text(&[1])?.trim(), "Selectable text");
    assert_recolor_operations(&output, [1.0, 1.0, 0.0], [0.0, 0.0, 0.0])?;
    Ok(())
}

#[tokio::test]
async fn custom_color_mode_accepts_java_color_values() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_replace_invert(
        &single_text_page()?,
        &[
            ("replaceAndInvertOption", "CUSTOM_COLOR"),
            ("textColor", "#112233"),
            ("backGroundColor", "0xAABBCC"),
        ],
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    assert_recolor_operations(
        &output,
        [17.0 / 255.0, 34.0 / 255.0, 51.0 / 255.0],
        [170.0 / 255.0, 187.0 / 255.0, 204.0 / 255.0],
    )?;
    Ok(())
}

#[tokio::test]
async fn custom_color_mode_rejects_missing_colors() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_replace_invert(
        &single_text_page()?,
        &[("replaceAndInvertOption", "CUSTOM_COLOR")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn custom_color_mode_recolors_nested_form_text() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_replace_invert(
        &form_text_page()?,
        &[
            ("replaceAndInvertOption", "CUSTOM_COLOR"),
            ("textColor", "#336699"),
            ("backGroundColor", "#FFFFFF"),
        ],
    )
    .await?;
    let output = Document::load_mem(
        &response_bytes(require_status(response, StatusCode::OK).await?).await?,
    )?;
    let page = output.get_dictionary(first_page_id(&output)?)?;
    let resources = resolve_dictionary(&output, page.get(b"Resources")?)?;
    let xobjects = resolve_dictionary(&output, resources.get(b"XObject")?)?;
    let form_id = xobjects.get(b"Fm1")?.as_reference()?;
    let form = output.get_object(form_id)?.as_stream()?;
    let content = Content::decode(&form.decompressed_content()?)?;
    let text_index = content
        .operations
        .iter()
        .position(|operation| operation.operator == "Tj")
        .ok_or("missing Form Tj operation")?;
    assert_eq!(content.operations[text_index - 1].operator, "rg");
    assert_rgb(
        &content.operations[text_index - 1].operands,
        [51.0 / 255.0, 102.0 / 255.0, 153.0 / 255.0],
    )?;
    Ok(())
}

#[tokio::test]
async fn color_space_conversion_follows_ghostscript_availability()
-> Result<(), Box<dyn std::error::Error>> {
    let response = post_replace_invert(
        &single_text_page()?,
        &[("replaceAndInvertOption", "COLOR_SPACE_CONVERSION")],
    )
    .await?;
    if ghostscript_present() {
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    } else {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
    }
    Ok(())
}

#[tokio::test]
async fn rejects_an_unknown_option() -> Result<(), Box<dyn std::error::Error>> {
    let response =
        post_replace_invert(&single_text_page()?, &[("replaceAndInvertOption", "SEPIA")]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

#[tokio::test]
async fn requires_the_option_field() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_replace_invert(&single_text_page()?, &[]).await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn native_pdfium_requested() -> bool {
    std::env::var_os("STIRLING_PDFIUM_LIBRARY_PATH").is_some()
}

fn ghostscript_present() -> bool {
    let candidates: &[&str] = if cfg!(windows) {
        &["gswin64c", "gswin32c", "gs"]
    } else {
        &["gs"]
    };
    if let Some(command) = std::env::var_os("STIRLING_PROCESSING_GHOSTSCRIPT_COMMAND")
        && !command.is_empty()
    {
        return Command::new(command).arg("--version").output().is_ok();
    }
    candidates
        .iter()
        .any(|command| Command::new(command).arg("--version").output().is_ok())
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

async fn post_replace_invert(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-replace-invert-boundary";
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
                .uri("/api/v1/misc/replace-invert-pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn first_page_id(document: &Document) -> Result<ObjectId, Box<dyn std::error::Error>> {
    document
        .get_pages()
        .into_values()
        .next()
        .ok_or_else(|| std::io::Error::other("PDF has no pages").into())
}

fn resolve_dictionary<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Result<&'a lopdf::Dictionary, lopdf::Error> {
    let (_, object) = document.dereference(object)?;
    object.as_dict()
}

fn assert_recolor_operations(
    document: &Document,
    text_color: [f32; 3],
    background_color: [f32; 3],
) -> Result<(), Box<dyn std::error::Error>> {
    let page_id = first_page_id(document)?;
    let content = Content::decode(&document.get_page_content(page_id))?;
    assert_eq!(
        content
            .operations
            .iter()
            .take(5)
            .map(|operation| operation.operator.as_str())
            .collect::<Vec<_>>(),
        ["q", "rg", "re", "f", "Q"]
    );
    assert_rgb(&content.operations[1].operands, background_color)?;
    let text_index = content
        .operations
        .iter()
        .position(|operation| operation.operator == "Tj")
        .ok_or("missing Tj operation")?;
    assert!(text_index > 0);
    assert_eq!(content.operations[text_index - 1].operator, "rg");
    assert_rgb(&content.operations[text_index - 1].operands, text_color)?;
    Ok(())
}

#[allow(clippy::cast_precision_loss)]
fn assert_rgb(operands: &[Object], expected: [f32; 3]) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(operands.len(), 3);
    for (operand, expected) in operands.iter().zip(expected) {
        let actual = match operand {
            Object::Integer(value) => *value as f32,
            Object::Real(value) => *value,
            _ => return Err("color operand is not numeric".into()),
        };
        assert!((actual - expected).abs() < 0.0001);
    }
    Ok(())
}

fn single_text_page() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 50 Td (Selectable text) Tj ET".to_vec(),
    ));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 80.into()],
        "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
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

fn form_text_page() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_id = document.add_object(dictionary! {
        "Type" => "Font", "Subtype" => "Type1", "BaseFont" => "Helvetica",
    });
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject", "Subtype" => "Form",
            "BBox" => vec![0.into(), 0.into(), 100.into(), 80.into()],
            "Resources" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        },
        b"BT /F1 12 Tf 10 50 Td (Nested text) Tj ET".to_vec(),
    ));
    let content_id = document.add_object(Stream::new(dictionary! {}, b"q /Fm1 Do Q".to_vec()));
    let page_id = document.add_object(dictionary! {
        "Type" => "Page", "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 80.into()],
        "Resources" => dictionary! { "XObject" => dictionary! { "Fm1" => form_id } },
        "Contents" => content_id,
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages", "Kids" => vec![Object::Reference(page_id)], "Count" => 1,
        }),
    );
    let catalog_id =
        document.add_object(dictionary! { "Type" => "Catalog", "Pages" => page_tree_id });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
