use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{
    Document, Object, Stream,
    content::{Content, Operation},
    dictionary,
};
use stirling_processing::{app, runtime_metrics::application_version};
use tower::ServiceExt;

#[tokio::test]
async fn creates_default_saddle_stitch_sides_and_fresh_catalog()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_booklet(&labeled_pdf(8, false)?, "source.pdf", &[]).await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"source_booklet.pdf\""
    );
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages().into_values().collect::<Vec<_>>();
    assert_eq!(pages.len(), 4);
    assert_eq!(form_labels(&document, pages[0])?, ["P8", "P1"]);
    assert_eq!(form_labels(&document, pages[1])?, ["P2", "P7"]);
    assert_eq!(form_labels(&document, pages[2])?, ["P6", "P3"]);
    assert_eq!(form_labels(&document, pages[3])?, ["P4", "P5"]);
    assert_numbers_close(&page_box(&document, pages[0])?, &[260.0, 180.0], 0.001);
    let catalog = document.catalog()?;
    assert!(catalog.get(b"AcroForm").is_err());
    assert!(catalog.get(b"Outlines").is_err());
    assert_rebuilt_metadata(&document)?;
    Ok(())
}

#[tokio::test]
async fn applies_second_pass_short_edge_right_spine_gutter_and_border()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_booklet(
            &labeled_pdf(8, false)?,
            "source.pdf",
            &[
                ("duplexPass", "SECOND"),
                ("doubleSided", "true"),
                ("flipOnShortEdge", "true"),
                ("spineLocation", "RIGHT"),
                ("addGutter", "true"),
                ("gutterSize", "20"),
                ("addBorder", "true"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages().into_values().collect::<Vec<_>>();
    assert_eq!(pages.len(), 2);
    assert_eq!(form_labels(&document, pages[0])?, ["P7", "P2"]);
    assert_eq!(form_labels(&document, pages[1])?, ["P5", "P4"]);
    let operations = page_operations(&document, pages[0])?;
    let matrices = operations
        .iter()
        .filter(|operation| operation.operator == "cm")
        .map(operation_numbers)
        .collect::<Result<Vec<_>, _>>()?;
    assert!((matrices[0][4] - 133.333_33).abs() < 0.001);
    assert!((matrices[2][4] + 16.666_67).abs() < 0.001);
    assert_eq!(
        operations
            .iter()
            .filter(|operation| operation.operator == "re")
            .count(),
        2
    );
    let line_width = operations
        .iter()
        .find(|operation| operation.operator == "w")
        .and_then(|operation| operation.operands.first())
        .and_then(|operand| operand.as_float().ok())
        .ok_or("missing border width")?;
    assert!((line_width - 1.5).abs() < f32::EPSILON);
    Ok(())
}

#[tokio::test]
async fn preserves_crop_and_rotation_transform_contract() -> Result<(), Box<dyn std::error::Error>>
{
    let response = require_status(
        post_booklet(&labeled_pdf(4, true)?, "rotated.pdf", &[]).await?,
        StatusCode::OK,
    )
    .await?;
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let first_page = *document.get_pages().values().next().ok_or("missing page")?;
    let resources = document
        .get_dictionary(first_page)?
        .get(b"Resources")?
        .as_dict()?;
    let xobjects = resources.get(b"XObject")?.as_dict()?;
    let (_, rotated_form) = document.dereference(xobjects.get(b"BookletPage0")?)?;
    let rotated_form = rotated_form.as_stream()?;
    assert_numbers_close(
        &object_numbers(rotated_form.dict.get(b"BBox")?)?,
        &[10.0, 20.0, 190.0, 280.0],
        0.001,
    );
    assert_numbers_close(
        &object_numbers(rotated_form.dict.get(b"Matrix")?)?,
        &[0.0, -1.444_444_4, 0.692_307_7, 0.0, -23.846_153, 254.444_44],
        0.001,
    );
    assert_numbers_close(&page_box(&document, first_page)?, &[260.0, 180.0], 0.001);
    assert!(
        page_operations(&document, first_page)?
            .iter()
            .filter(|operation| operation.operator == "cm")
            .count()
            >= 6
    );
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_sheet_count_empty_pdf_and_non_finite_gutter()
-> Result<(), Box<dyn std::error::Error>> {
    for (pdf, fields) in [
        (labeled_pdf(4, false)?, vec![("pagesPerSheet", "4")]),
        (labeled_pdf(0, false)?, Vec::new()),
        (labeled_pdf(4, false)?, vec![("gutterSize", "NaN")]),
    ] {
        let response = post_booklet(&pdf, "source.pdf", &fields).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let error: serde_json::Value = serde_json::from_slice(&response_bytes(response).await?)?;
        assert_eq!(error["path"], "/api/v1/general/booklet-imposition");
    }
    Ok(())
}

fn form_labels(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let resources = document
        .get_dictionary(page_id)?
        .get(b"Resources")?
        .as_dict()?;
    let xobjects = resources.get(b"XObject")?.as_dict()?;
    let mut labels = Vec::new();
    for name in [b"BookletPage0".as_slice(), b"BookletPage1"] {
        let Ok(xobject) = xobjects.get(name) else {
            continue;
        };
        let (_, xobject) = document.dereference(xobject)?;
        let content = Content::decode(&xobject.as_stream()?.content)?;
        let label = content
            .operations
            .into_iter()
            .find(|operation| operation.operator == "Tj")
            .and_then(|operation| operation.operands.into_iter().next())
            .and_then(|operand| operand.as_str().ok().map(<[u8]>::to_vec))
            .map(|value| String::from_utf8_lossy(&value).into_owned())
            .ok_or("missing label")?;
        labels.push(label);
    }
    Ok(labels)
}

fn page_box(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<[f32; 2], Box<dyn std::error::Error>> {
    let values = object_numbers(document.get_dictionary(page_id)?.get(b"MediaBox")?)?;
    Ok([values[2] - values[0], values[3] - values[1]])
}

fn object_numbers(object: &Object) -> Result<Vec<f32>, lopdf::Error> {
    object.as_array()?.iter().map(Object::as_float).collect()
}

fn page_operations(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<Vec<Operation>, Box<dyn std::error::Error>> {
    Ok(Content::decode(&document.get_page_content(page_id))?.operations)
}

fn operation_numbers(operation: &Operation) -> Result<Vec<f32>, lopdf::Error> {
    operation.operands.iter().map(Object::as_float).collect()
}

fn assert_numbers_close(actual: &[f32], expected: &[f32], tolerance: f32) {
    assert_eq!(actual.len(), expected.len());
    for (actual, expected) in actual.iter().zip(expected) {
        assert!((*actual - *expected).abs() <= tolerance);
    }
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

async fn post_booklet(
    pdf: &[u8],
    filename: &str,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-booklet-boundary";
    let mut body = format!(
        "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
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
                .uri("/api/v1/general/booklet-imposition")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn labeled_pdf(
    page_count: usize,
    rotate_last: bool,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let mut pages = Vec::new();
    for index in 0..page_count {
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            format!("BT (P{}) Tj ET", index + 1).into_bytes(),
        ));
        let mut page = dictionary! {
            "Type" => "Page",
            "Parent" => pages_id,
            "CropBox" => vec![10.into(), 20.into(), 190.into(), 280.into()],
            "Contents" => content_id,
        };
        if rotate_last && index + 1 == page_count {
            page.set("Rotate", 90);
        }
        pages.push(document.add_object(page));
    }
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => pages.into_iter().map(Object::Reference).collect::<Vec<_>>(),
            "Count" => i64::try_from(page_count)?,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
            "Resources" => dictionary! {},
        }),
    );
    let outlines_id = document.add_object(dictionary! { "Type" => "Outlines" });
    let acroform_id = document.add_object(dictionary! { "Fields" => Vec::<Object>::new() });
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
        "Outlines" => outlines_id,
        "AcroForm" => acroform_id,
    });
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Source title"),
        "Creator" => Object::string_literal("Source creator"),
        "Producer" => Object::string_literal("Source producer"),
        "CreationDate" => Object::string_literal("D:20240102030405+00'00'"),
        "ModDate" => Object::string_literal("D:20240203040506+00'00'"),
        "Custom" => Object::string_literal("discard me"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn assert_rebuilt_metadata(document: &Document) -> Result<(), Box<dyn std::error::Error>> {
    let (_, info) = document.dereference(document.trailer.get(b"Info")?)?;
    let info = info.as_dict()?;
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
