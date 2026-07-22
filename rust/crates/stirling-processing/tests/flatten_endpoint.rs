use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, ObjectId, Stream, dictionary};
use stirling_processing::{app, runtime_metrics::application_version};
use tower::ServiceExt;

#[tokio::test]
async fn rasterizes_each_page_and_preserves_page_size() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_flatten(
        &pdf_with_text_and_form(false)?,
        &[("flattenOnlyForms", "false"), ("renderDpi", "1")],
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
            .contains("source.pdf")
    );
    let output = Document::load_mem(&response_bytes(response).await?)?;
    let page_id = first_page_id(&output)?;
    let page = output.get_dictionary(page_id)?;
    assert_eq!(page.get(b"MediaBox")?.as_array()?.len(), 4);
    let resources = resolve_dictionary(&output, page.get(b"Resources")?)?;
    let xobjects = resolve_dictionary(&output, resources.get(b"XObject")?)?;
    assert!(!xobjects.is_empty());
    assert!(xobjects.iter().any(|(_, object)| {
        output
            .dereference(object)
            .ok()
            .and_then(|(_, object)| object.as_stream().ok())
            .and_then(|stream| stream.dict.get(b"Subtype").ok())
            .is_some_and(|subtype| subtype.as_name().is_ok_and(|name| name == b"Image"))
    }));
    assert!(output.extract_text(&[1])?.trim().is_empty());
    assert_rebuilt_metadata(&output)?;
    Ok(())
}

#[tokio::test]
async fn flattens_form_widgets_into_page_content() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_flatten(
        &pdf_with_text_and_form(true)?,
        &[("flattenOnlyForms", "true")],
    )
    .await?;
    if !native_pdfium_requested() {
        assert_eq!(response.status(), StatusCode::NOT_IMPLEMENTED);
        return Ok(());
    }
    let response = require_status(response, StatusCode::OK).await?;
    let output = Document::load_mem(&response_bytes(response).await?)?;
    let page = output.get_dictionary(first_page_id(&output)?)?;
    let widget_count = page
        .get(b"Annots")
        .ok()
        .and_then(|annots| resolve_array(&output, annots).ok())
        .map_or(0, |annots| {
            annots
                .iter()
                .filter(|annotation| {
                    output
                        .dereference(annotation)
                        .ok()
                        .and_then(|(_, object)| object.as_dict().ok())
                        .and_then(|dictionary| dictionary.get(b"Subtype").ok())
                        .is_some_and(|subtype| {
                            subtype.as_name().is_ok_and(|name| name == b"Widget")
                        })
                })
                .count()
        });
    assert_eq!(widget_count, 0);
    assert_eq!(output.get_pages().len(), 1);
    assert_loaded_metadata(&output)?;
    Ok(())
}

#[tokio::test]
async fn rejects_a_non_integer_render_dpi() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_flatten(
        &pdf_with_text_and_form(false)?,
        &[("renderDpi", "not-an-integer")],
    )
    .await?;
    assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    Ok(())
}

fn native_pdfium_requested() -> bool {
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

async fn post_flatten(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-flatten-boundary";
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
                .uri("/api/v1/misc/flatten")
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

fn resolve_array(document: &Document, object: &Object) -> Result<Vec<Object>, lopdf::Error> {
    let (_, object) = document.dereference(object)?;
    Ok(object.as_array()?.clone())
}

fn pdf_with_text_and_form(with_form: bool) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
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
    let mut catalog = dictionary! { "Type" => "Catalog", "Pages" => page_tree_id };
    if with_form {
        let appearance_id = document.add_object(Stream::new(
            dictionary! {
                "Type" => "XObject",
                "Subtype" => "Form",
                "BBox" => vec![0.into(), 0.into(), 40.into(), 20.into()],
                "Resources" => dictionary! {},
            },
            b"0 0 1 rg 0 0 40 20 re f".to_vec(),
        ));
        let widget_id = document.add_object(dictionary! {
            "Type" => "Annot",
            "Subtype" => "Widget",
            "FT" => "Tx",
            "T" => Object::string_literal("name"),
            "V" => Object::string_literal("Alice"),
            "Rect" => vec![10.into(), 10.into(), 50.into(), 30.into()],
            "F" => 4,
            "P" => page_id,
            "AP" => dictionary! { "N" => appearance_id },
        });
        document
            .get_dictionary_mut(page_id)?
            .set("Annots", vec![Object::Reference(widget_id)]);
        let acroform_id = document.add_object(dictionary! {
            "Fields" => vec![Object::Reference(widget_id)],
            "NeedAppearances" => false,
            "DA" => Object::string_literal("/F1 12 Tf 0 g"),
            "DR" => dictionary! { "Font" => dictionary! { "F1" => font_id } },
        });
        catalog.set("AcroForm", acroform_id);
    }
    let catalog_id = document.add_object(catalog);
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Source title"),
        "Creator" => Object::string_literal("Source creator"),
        "Producer" => Object::string_literal("Source producer"),
        "CreationDate" => Object::string_literal("D:20240102030405+00'00'"),
        "ModDate" => Object::string_literal("D:20240203040506+00'00'"),
        "Custom" => Object::string_literal("source custom value"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn assert_rebuilt_metadata(document: &Document) -> Result<(), Box<dyn std::error::Error>> {
    let info = info_dictionary(document)?;
    let label = format!("Stirling-PDF v{}", application_version());
    assert_eq!(info.get(b"Title")?.as_str()?, b"Source title");
    assert_eq!(info.get(b"Creator")?.as_str()?, label.as_bytes());
    assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
    assert_eq!(
        info.get(b"CreationDate")?.as_str()?,
        b"D:20240102030405+00'00'"
    );
    assert_eq!(info.get(b"ModDate")?.as_str()?, b"D:20240203040506+00'00'");
    assert!(info.get(b"Custom").is_err());
    Ok(())
}

fn assert_loaded_metadata(document: &Document) -> Result<(), Box<dyn std::error::Error>> {
    let info = info_dictionary(document)?;
    let label = format!("Stirling-PDF v{}", application_version());
    assert_eq!(info.get(b"Title")?.as_str()?, b"Source title");
    assert_eq!(info.get(b"Creator")?.as_str()?, b"Source creator");
    assert_eq!(info.get(b"Producer")?.as_str()?, label.as_bytes());
    assert_eq!(
        info.get(b"CreationDate")?.as_str()?,
        b"D:20240102030405+00'00'"
    );
    assert_eq!(info.get(b"ModDate")?.as_str()?, b"D:20240203040506+00'00'");
    assert_eq!(info.get(b"Custom")?.as_str()?, b"source custom value");
    Ok(())
}

fn info_dictionary(document: &Document) -> Result<&lopdf::Dictionary, lopdf::Error> {
    let (_, info) = document.dereference(document.trailer.get(b"Info")?)?;
    info.as_dict()
}
