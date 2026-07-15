use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Document, Object, Stream, dictionary};
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn stacks_pages_into_one_page_with_maximum_width_and_total_height()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/general/pdf-to-single-page",
            "stack.pdf",
            &pdf_with_page_sizes(&[(100, 200), (150, 300), (120, 100)])?,
            &[],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("stack_singlePage.pdf")
    );
    let output = response_document(response).await?;
    assert_eq!(output.get_pages().len(), 1);
    assert_eq!(page_size(&output, 0)?, (150.0, 600.0));
    assert_eq!(form_draw_count(&output, 0), 3);
    Ok(())
}

#[tokio::test]
async fn scales_pages_to_landscape_and_keep_target_sizes() -> Result<(), Box<dyn std::error::Error>>
{
    let source = pdf_with_page_sizes(&[(100, 200), (300, 400)])?;
    let landscape = require_status(
        post_pdf(
            "/api/v1/general/scale-pages",
            "scale.pdf",
            &source,
            &[
                ("pageSize", "A4"),
                ("orientation", "LANDSCAPE"),
                ("scaleFactor", "1"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let landscape = response_document(landscape).await?;
    assert_eq!(landscape.get_pages().len(), 2);
    assert_close(page_size(&landscape, 0)?, (841.890, 595.276));

    let keep = require_status(
        post_pdf(
            "/api/v1/general/scale-pages",
            "keep.pdf",
            &source,
            &[
                ("pageSize", "KEEP"),
                ("orientation", "LANDSCAPE"),
                ("scaleFactor", "0.5"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let keep = response_document(keep).await?;
    assert_eq!(page_size(&keep, 0)?, (100.0, 200.0));
    assert_eq!(page_size(&keep, 1)?, (100.0, 200.0));
    Ok(())
}

#[tokio::test]
async fn lays_out_pages_across_a4_sheets_with_optional_borders()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/general/multi-page-layout",
            "layout.pdf",
            &pdf_with_page_sizes(&[(100, 200), (110, 200), (120, 200), (130, 200)])?,
            &[
                ("pagesPerSheet", "2"),
                ("addBorder", "true"),
                ("borderWidth", "2"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("layout_multi_page_layout.pdf")
    );
    let output = response_document(response).await?;
    assert_eq!(output.get_pages().len(), 2);
    assert_close(page_size(&output, 0)?, (595.276, 841.890));
    assert_eq!(form_draw_count(&output, 0), 2);
    assert_eq!(form_draw_count(&output, 1), 2);
    assert_eq!(content_occurrences(&output, 0, b" re S Q"), 2);
    Ok(())
}

#[tokio::test]
async fn supports_custom_column_first_rtl_layouts() -> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/general/multi-page-layout",
            "custom.pdf",
            &pdf_with_page_sizes(&[(100, 100); 7])?,
            &[
                ("mode", "CUSTOM"),
                ("rows", "2"),
                ("cols", "3"),
                ("arrangement", "BY_COLUMNS"),
                ("readingDirection", "RTL"),
                ("orientation", "LANDSCAPE"),
                ("innerMargin", "2"),
                ("topMargin", "4"),
                ("bottomMargin", "4"),
                ("leftMargin", "5"),
                ("rightMargin", "5"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let output = response_document(response).await?;
    assert_eq!(output.get_pages().len(), 2);
    assert_close(page_size(&output, 0)?, (841.890, 595.276));
    assert_eq!(form_draw_count(&output, 0), 6);
    assert_eq!(form_draw_count(&output, 1), 1);
    Ok(())
}

#[tokio::test]
async fn transforms_interactive_fields_for_portrait_unrotated_layouts()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_pdf(
            "/api/v1/general/multi-page-layout",
            "forms.pdf",
            &pdf_with_text_fields()?,
            &[("pagesPerSheet", "2")],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    let output = response_document(response).await?;
    let acroform_id = output.catalog()?.get(b"AcroForm")?.as_reference()?;
    let fields = output
        .get_dictionary(acroform_id)?
        .get(b"Fields")?
        .as_array()?;
    assert_eq!(fields.len(), 2);
    for (index, field) in fields.iter().enumerate() {
        let field = output.get_dictionary(field.as_reference()?)?;
        assert_eq!(
            lopdf::decode_text_string(field.get(b"T")?)?,
            format!("page{index}_name")
        );
        assert_eq!(
            lopdf::decode_text_string(field.get(b"V")?)?,
            format!("value-{index}")
        );
    }
    let page_id = output
        .get_pages()
        .into_values()
        .next()
        .ok_or("missing page")?;
    assert_eq!(
        output
            .get_dictionary(page_id)?
            .get(b"Annots")?
            .as_array()?
            .len(),
        2
    );
    Ok(())
}

#[tokio::test]
async fn reports_route_specific_geometry_validation_errors()
-> Result<(), Box<dyn std::error::Error>> {
    let pdf = pdf_with_page_sizes(&[(100, 100)])?;
    for (path, fields) in [
        (
            "/api/v1/general/scale-pages",
            vec![("pageSize", "UNKNOWN"), ("scaleFactor", "1")],
        ),
        (
            "/api/v1/general/multi-page-layout",
            vec![("pagesPerSheet", "3")],
        ),
    ] {
        let response = require_status(
            post_pdf(path, "invalid.pdf", &pdf, &fields).await?,
            StatusCode::BAD_REQUEST,
        )
        .await?;
        let body = String::from_utf8(to_bytes(response.into_body(), usize::MAX).await?.to_vec())?;
        assert!(body.contains(path));
    }
    Ok(())
}

fn form_draw_count(document: &Document, page_index: usize) -> usize {
    content_occurrences(document, page_index, b" Do Q")
}

fn content_occurrences(document: &Document, page_index: usize, needle: &[u8]) -> usize {
    let page_id = document
        .get_pages()
        .into_values()
        .nth(page_index)
        .unwrap_or_default();
    document
        .get_page_content(page_id)
        .windows(needle.len())
        .filter(|window| *window == needle)
        .count()
}

fn page_size(
    document: &Document,
    page_index: usize,
) -> Result<(f32, f32), Box<dyn std::error::Error>> {
    let page_id = document
        .get_pages()
        .into_values()
        .nth(page_index)
        .ok_or_else(|| std::io::Error::other("missing page"))?;
    let media_box = document
        .get_dictionary(page_id)?
        .get(b"MediaBox")?
        .as_array()?;
    Ok((media_box[2].as_float()?, media_box[3].as_float()?))
}

fn assert_close(actual: (f32, f32), expected: (f32, f32)) {
    assert!(
        (actual.0 - expected.0).abs() < 0.01,
        "{actual:?} != {expected:?}"
    );
    assert!(
        (actual.1 - expected.1).abs() < 0.01,
        "{actual:?} != {expected:?}"
    );
}

async fn response_document(response: Response) -> Result<Document, Box<dyn std::error::Error>> {
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

async fn post_pdf(
    path: &str,
    filename: &str,
    pdf: &[u8],
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-geometry-boundary";
    let mut body = Vec::new();
    body.extend_from_slice(
        format!(
            "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"{filename}\"\r\nContent-Type: application/pdf\r\n\r\n"
        )
        .as_bytes(),
    );
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
                .uri(path)
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn pdf_with_page_sizes(sizes: &[(i64, i64)]) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let mut page_ids = Vec::with_capacity(sizes.len());
    for (index, (width, height)) in sizes.iter().enumerate() {
        let content_id = document.add_object(Stream::new(
            dictionary! {},
            format!("{index} 0 m 10 10 l S").into_bytes(),
        ));
        let page_id = document.add_object(dictionary! {
            "Type" => "Page",
            "Parent" => page_tree_id,
            "MediaBox" => vec![0.into(), 0.into(), (*width).into(), (*height).into()],
            "Contents" => content_id,
        });
        page_ids.push(Object::Reference(page_id));
    }
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => page_ids,
            "Count" => i64::try_from(sizes.len())?,
            "Resources" => dictionary! {},
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => page_tree_id,
        "AcroForm" => dictionary! { "Fields" => Vec::<Object>::new() },
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}

fn pdf_with_text_fields() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::load_mem(&pdf_with_page_sizes(&[(100, 100), (100, 100)])?)?;
    let page_ids: Vec<_> = document.get_pages().into_values().collect();
    let mut fields = Vec::new();
    for (index, page_id) in page_ids.into_iter().enumerate() {
        let field_id = document.new_object_id();
        let widget_id = document.new_object_id();
        document.objects.insert(
            field_id,
            Object::Dictionary(dictionary! {
                "FT" => "Tx",
                "T" => Object::string_literal("name"),
                "V" => Object::string_literal(format!("value-{index}")),
                "Kids" => vec![Object::Reference(widget_id)],
            }),
        );
        document.objects.insert(
            widget_id,
            Object::Dictionary(dictionary! {
                "Type" => "Annot",
                "Subtype" => "Widget",
                "Rect" => vec![10.into(), 20.into(), 30.into(), 40.into()],
                "P" => page_id,
                "Parent" => field_id,
            }),
        );
        document
            .get_dictionary_mut(page_id)?
            .set("Annots", vec![Object::Reference(widget_id)]);
        fields.push(Object::Reference(field_id));
    }
    let acroform_id = document.add_object(dictionary! { "Fields" => fields });
    document.catalog_mut()?.set("AcroForm", acroform_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
