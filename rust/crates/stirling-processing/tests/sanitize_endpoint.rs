use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn selectively_removes_every_java_sanitize_category() -> Result<(), Box<dyn std::error::Error>>
{
    let response = require_status(
        post_sanitize(
            &unsafe_pdf()?,
            &[
                ("removeJavaScript", "true"),
                ("removeEmbeddedFiles", "true"),
                ("removeXMPMetadata", "true"),
                ("removeMetadata", "true"),
                ("removeLinks", "true"),
                ("removeFonts", "true"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("unsafe_sanitized.pdf")
    );
    let output = response_document(response).await?;
    let catalog = output.catalog()?;
    assert!(catalog.get(b"OpenAction").is_err());
    assert!(catalog.get(b"Metadata").is_err());

    let names = resolved_dictionary(&output, catalog.get(b"Names")?)?;
    assert!(names.get(b"JavaScript").is_err());
    assert!(names.get(b"EmbeddedFiles").is_err());
    assert!(names.get(b"Dests").is_ok());

    let catalog_actions = resolved_dictionary(&output, catalog.get(b"AA")?)?;
    assert!(catalog_actions.get(b"WC").is_err());
    assert!(catalog_actions.get(b"WS").is_ok());

    let acroform = resolved_dictionary(&output, catalog.get(b"AcroForm")?)?;
    let fields = resolved_array(&output, acroform.get(b"Fields")?)?;
    let field = resolved_dictionary(&output, &fields[0])?;
    let field_actions = resolved_dictionary(&output, field.get(b"AA")?)?;
    assert!(field_actions.get(b"K").is_err());
    assert!(field_actions.get(b"V").is_ok());

    let info_id = output.trailer.get(b"Info")?.as_reference()?;
    assert_eq!(output.get_dictionary(info_id)?.iter().count(), 0);

    let page_id = output
        .get_pages()
        .into_values()
        .next()
        .ok_or("missing page")?;
    let page = output.get_dictionary(page_id)?;
    let page_actions = resolved_dictionary(&output, page.get(b"AA")?)?;
    assert!(page_actions.get(b"O").is_err());
    assert!(page_actions.get(b"C").is_ok());
    let resources = resolved_dictionary(&output, page.get(b"Resources")?)?;
    assert!(resources.get(b"Font").is_err());
    assert!(resources.get(b"XObject").is_ok());

    let annotations = resolved_array(&output, page.get(b"Annots")?)?;
    assert_eq!(annotations.len(), 3);
    let widget = annotation_by_subtype(&output, annotations, b"Widget")?;
    let link = annotation_by_subtype(&output, annotations, b"Link")?;
    let text = annotation_by_subtype(&output, annotations, b"Text")?;
    assert!(widget.get(b"A").is_err());
    assert!(link.get(b"A").is_err());
    assert!(text.get(b"A").is_ok());
    Ok(())
}

fn annotation_by_subtype<'a>(
    document: &'a Document,
    annotations: &'a [Object],
    subtype: &[u8],
) -> Result<&'a Dictionary, Box<dyn std::error::Error>> {
    annotations
        .iter()
        .find_map(|annotation| {
            let dictionary = resolved_dictionary(document, annotation).ok()?;
            (dictionary.get(b"Subtype").ok()?.as_name().ok()? == subtype).then_some(dictionary)
        })
        .ok_or_else(|| std::io::Error::other("annotation subtype not found").into())
}

fn resolved_dictionary<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Result<&'a Dictionary, Box<dyn std::error::Error>> {
    Ok(document.dereference(object)?.1.as_dict()?)
}

fn resolved_array<'a>(
    document: &'a Document,
    object: &'a Object,
) -> Result<&'a Vec<Object>, Box<dyn std::error::Error>> {
    Ok(document.dereference(object)?.1.as_array()?)
}

async fn response_document(response: Response) -> Result<Document, Box<dyn std::error::Error>> {
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    let bytes = to_bytes(response.into_body(), usize::MAX).await?;
    Ok(Document::load_mem(&bytes)?)
}

async fn require_status(
    response: Response,
    expected: StatusCode,
) -> Result<Response, Box<dyn std::error::Error>> {
    if response.status() == expected {
        return Ok(response);
    }
    let status = response.status();
    let body = to_bytes(response.into_body(), usize::MAX).await?;
    Err(std::io::Error::other(format!(
        "expected HTTP {expected}, received {status}: {}",
        String::from_utf8_lossy(&body)
    ))
    .into())
}

async fn post_sanitize(
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-sanitize-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"unsafe.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
    )
    .into_bytes();
    body.extend_from_slice(pdf);
    body.extend_from_slice(b"\r\n");
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
                .uri("/api/v1/security/sanitize-pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn unsafe_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let root_pages_id = document.new_object_id();
    let javascript_action_id = document.add_object(dictionary! {
        "Type" => "Action",
        "S" => "JavaScript",
        "JS" => Object::string_literal("app.alert('x')"),
    });
    let uri_action_id = document.add_object(dictionary! {
        "Type" => "Action",
        "S" => "URI",
        "URI" => Object::string_literal("https://example.com"),
    });
    let field_id = document.add_object(dictionary! {
        "FT" => "Tx",
        "T" => Object::string_literal("field"),
        "AA" => dictionary! {
            "K" => javascript_action_id,
            "V" => uri_action_id,
        },
    });
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(field_id)],
    });
    let widget_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Widget",
        "Rect" => vec![0.into(), 0.into(), 10.into(), 10.into()],
        "A" => javascript_action_id,
    });
    let link_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Link",
        "Rect" => vec![10.into(), 10.into(), 20.into(), 20.into()],
        "A" => uri_action_id,
    });
    let file_attachment_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "FileAttachment",
        "Rect" => vec![20.into(), 20.into(), 30.into(), 30.into()],
    });
    let text_annotation_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Text",
        "Rect" => vec![30.into(), 30.into(), 40.into(), 40.into()],
        "A" => uri_action_id,
    });
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => root_pages_id,
        "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
        "AA" => dictionary! { "O" => javascript_action_id, "C" => uri_action_id },
        "Annots" => vec![
            Object::Reference(widget_id),
            Object::Reference(link_id),
            Object::Reference(file_attachment_id),
            Object::Reference(text_annotation_id),
        ],
        "Resources" => dictionary! {
            "Font" => dictionary! { "F1" => dictionary! { "Type" => "Font" } },
            "XObject" => dictionary! {},
        },
    });
    document.objects.insert(
        root_pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(page_id)],
            "Count" => 1,
        }),
    );
    let metadata_id = document.add_object(Stream::new(
        dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
        b"<xmp/>".to_vec(),
    ));
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => root_pages_id,
        "OpenAction" => javascript_action_id,
        "AA" => dictionary! { "WC" => javascript_action_id, "WS" => uri_action_id },
        "AcroForm" => acroform_id,
        "Metadata" => metadata_id,
        "Names" => dictionary! {
            "JavaScript" => dictionary! {},
            "EmbeddedFiles" => dictionary! {},
            "Dests" => dictionary! {},
        },
    });
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("secret"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
