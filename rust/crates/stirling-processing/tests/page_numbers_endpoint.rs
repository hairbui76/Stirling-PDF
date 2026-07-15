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
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn numbers_selected_pages_with_java_template_and_sequence_semantics()
-> Result<(), Box<dyn std::error::Error>> {
    let response = require_status(
        post_page_numbers(
            &three_page_pdf()?,
            "archive.tar.pdf",
            &[
                ("customMargin", "small"),
                ("position", "3"),
                ("startingNumber", "7"),
                ("pagesToNumber", "1,3"),
                ("customText", "Page {n} of {total} - {filename}"),
                ("zeroPad", "3"),
                ("fontSize", "10"),
                ("fontType", "times"),
                ("fontColor", "#FF8000"),
            ],
        )
        .await?,
        StatusCode::OK,
    )
    .await?;
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/pdf");
    assert_eq!(
        response.headers()[header::CONTENT_DISPOSITION],
        "attachment; filename=\"archive.tar_page_numbers_added.pdf\""
    );

    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages().into_values().collect::<Vec<_>>();
    assert_eq!(
        page_texts(&document, pages[0])?,
        ["original", "Page 007 of 3 - archive.tar"]
    );
    assert_eq!(page_texts(&document, pages[1])?, Vec::<String>::new());
    assert_eq!(
        page_texts(&document, pages[2])?,
        ["Page 008 of 3 - archive.tar"]
    );

    let operations = page_operations(&document, pages[0])?;
    let color = operation_numbers(&operations, "rg").ok_or("missing color")?;
    assert!((color[0] - 1.0).abs() < f32::EPSILON);
    assert!((color[1] - 128.0 / 255.0).abs() < 0.000_01);
    assert!((color[2] - 0.0).abs() < f32::EPSILON);
    let font_name = operations
        .iter()
        .rev()
        .find(|operation| operation.operator == "Tf")
        .and_then(|operation| operation.operands.first())
        .and_then(|operand| operand.as_name().ok())
        .ok_or("missing font")?;
    let resources = document
        .get_dictionary(pages[0])?
        .get(b"Resources")?
        .as_dict()?;
    let fonts = resources.get(b"Font")?.as_dict()?;
    let (_, font) = document.dereference(fonts.get(font_name)?)?;
    assert_eq!(font.as_dict()?.get(b"BaseFont")?.as_name()?, b"Times-Roman");
    assert_eq!(
        font.as_dict()?.get(b"Encoding")?.as_name()?,
        b"WinAnsiEncoding"
    );
    Ok(())
}

#[tokio::test]
async fn applies_java_model_defaults_and_clamps_position() -> Result<(), Box<dyn std::error::Error>>
{
    let response = require_status(
        post_page_numbers(&three_page_pdf()?, "source.pdf", &[("position", "99")]).await?,
        StatusCode::OK,
    )
    .await?;
    let document = Document::load_mem(&response_bytes(response).await?)?;
    let pages = document.get_pages().into_values().collect::<Vec<_>>();
    assert_eq!(page_texts(&document, pages[0])?, ["original", "0"]);
    assert_eq!(page_texts(&document, pages[1])?, ["1"]);
    assert_eq!(page_texts(&document, pages[2])?, ["2"]);
    let operations = page_operations(&document, pages[1])?;
    let offset = operation_numbers(&operations, "Td").ok_or("missing offset")?;
    assert!((offset[0] - 193.0).abs() < 0.001);
    assert!((offset[1] - 10.5).abs() < 0.001);
    Ok(())
}

#[tokio::test]
async fn rejects_invalid_values_unsafe_padding_and_non_win_ansi_text()
-> Result<(), Box<dyn std::error::Error>> {
    for fields in [
        vec![("position", "not-an-integer")],
        vec![("zeroPad", "4097")],
        vec![("customText", "Trang 😀 {n}")],
        vec![("pagesToNumber", "n^2")],
    ] {
        let response = post_page_numbers(&three_page_pdf()?, "source.pdf", &fields).await?;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let body = response_bytes(response).await?;
        let error: serde_json::Value = serde_json::from_slice(&body)?;
        assert_eq!(error["path"], "/api/v1/misc/add-page-numbers");
    }
    Ok(())
}

fn page_texts(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    Ok(page_operations(document, page_id)?
        .into_iter()
        .filter(|operation| operation.operator == "Tj")
        .filter_map(|operation| operation.operands.into_iter().next())
        .filter_map(|operand| operand.as_str().ok().map(<[u8]>::to_vec))
        .map(|value| String::from_utf8_lossy(&value).into_owned())
        .collect())
}

fn page_operations(
    document: &Document,
    page_id: lopdf::ObjectId,
) -> Result<Vec<Operation>, Box<dyn std::error::Error>> {
    Ok(Content::decode(&document.get_page_content(page_id))?.operations)
}

fn operation_numbers(operations: &[Operation], operator: &str) -> Option<Vec<f32>> {
    operations
        .iter()
        .find(|operation| operation.operator == operator)
        .map(|operation| {
            operation
                .operands
                .iter()
                .map(Object::as_float)
                .collect::<Result<Vec<_>, _>>()
        })
        .transpose()
        .ok()
        .flatten()
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

async fn post_page_numbers(
    pdf: &[u8],
    filename: &str,
    fields: &[(&str, &str)],
) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-page-numbers-boundary";
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
                .uri("/api/v1/misc/add-page-numbers")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

fn three_page_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let pages_id = document.new_object_id();
    let existing_font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
    });
    let original_content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /Existing 8 Tf 5 5 Td (original) Tj ET".to_vec(),
    ));
    let page_one_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
        "Contents" => original_content_id,
    });
    let page_two_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
    });
    let page_three_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => pages_id,
    });
    document.objects.insert(
        pages_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![page_one_id.into(), page_two_id.into(), page_three_id.into()],
            "Count" => 3,
            "MediaBox" => vec![0.into(), 0.into(), 200.into(), 300.into()],
            "Resources" => dictionary! {
                "Font" => dictionary! { "Existing" => existing_font_id },
            },
        }),
    );
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => pages_id,
    });
    document.trailer.set("Root", catalog_id);
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
