use axum::{
    body::{Body, to_bytes},
    http::{Request, StatusCode, header},
    response::Response,
};
use lopdf::{Dictionary, Document, Object, Stream, dictionary};
use serde_json::Value;
use stirling_processing::app;
use tower::ServiceExt;

#[tokio::test]
async fn returns_comprehensive_java_shaped_report() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(Some(&information_pdf()?)).await?;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.headers()[header::CONTENT_TYPE], "application/json");
    assert!(
        response.headers()[header::CONTENT_DISPOSITION]
            .to_str()?
            .contains("response.json")
    );
    let report: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;

    assert_eq!(report["Metadata"]["Title"], "Information fixture");
    assert_eq!(report["Metadata"]["StirlingPDFClassification"], "Internal");
    assert_eq!(report["BasicInfo"]["Number of pages"], 2);
    assert_eq!(report["BasicInfo"]["TotalImages"], 1);
    assert_eq!(report["BasicInfo"]["UniqueImages"], 1);
    assert_eq!(report["BasicInfo"]["Language"], "en-US");
    assert_eq!(report["DocumentInfo"]["PDF version"], "1.7");
    assert_eq!(report["DocumentInfo"]["Page Mode"], "USE_OUTLINES");
    assert_eq!(report["Encryption"]["IsEncrypted"], false);
    assert_eq!(report["Permissions"]["Printing"], "Allowed");
    assert_eq!(report["FormFields"]["person.name"], "Alice");
    assert_eq!(report["Compliancy"]["IsPDF/SECCompliant"], false);

    assert_eq!(report["Other"]["JavaScript"][0]["JS Name"], "startup");
    assert_eq!(report["Other"]["Layers"][0]["Name"], "Review layer");
    assert_eq!(
        report["Other"]["Bookmarks/Outline/TOC"][0]["Title"],
        "First page"
    );
    assert!(
        report["Other"]["XMPMetadata"]
            .as_str()
            .is_some_and(|xmp| xmp.contains("xmpmeta"))
    );

    assert_eq!(
        report["PerPageInfo"]["Page 1"]["Size"]["Standard Page"],
        "A4"
    );
    assert_eq!(report["PerPageInfo"]["Page 1"]["Rotation"], 90);
    assert_eq!(
        report["PerPageInfo"]["Page 1"]["Annotations"]["AnnotationsCount"],
        1
    );
    assert_eq!(
        report["PerPageInfo"]["Page 1"]["Links"][0]["URI"],
        "https://example.com"
    );
    assert_eq!(report["PerPageInfo"]["Page 1"]["Images"][0]["Width"], 2);
    assert_eq!(report["PerPageInfo"]["Page 1"]["XObjectCounts"]["Image"], 1);
    assert_eq!(
        report["PerPageInfo"]["Page 2"]["Size"]["Standard Page"],
        "Letter"
    );
    assert_eq!(
        report["SummaryData"]["Compliance"][0]["Standard"],
        "not-pdfa"
    );
    Ok(())
}

#[tokio::test]
async fn preserves_java_error_json_with_http_200() -> Result<(), Box<dyn std::error::Error>> {
    for pdf in [None, Some(b"".as_slice()), Some(b"not a PDF".as_slice())] {
        let response = post_pdf(pdf).await?;
        assert_eq!(response.status(), StatusCode::OK);
        assert!(
            response.headers()[header::CONTENT_DISPOSITION]
                .to_str()?
                .contains("error.json")
        );
        let body: Value =
            serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
        assert!(body["error"].is_string());
        assert!(body["timestamp"].is_number());
    }
    Ok(())
}

#[tokio::test]
async fn clean_document_is_sec_compliant() -> Result<(), Box<dyn std::error::Error>> {
    let response = post_pdf(Some(&clean_pdf()?)).await?;
    let report: Value = serde_json::from_slice(&to_bytes(response.into_body(), usize::MAX).await?)?;
    assert_eq!(report["Compliancy"]["IsPDF/SECCompliant"], true);
    assert_eq!(report["Other"]["EmbeddedFiles"], Value::Array(Vec::new()));
    assert_eq!(report["Other"]["Attachments"], Value::Array(Vec::new()));
    Ok(())
}

async fn post_pdf(pdf: Option<&[u8]>) -> Result<Response, Box<dyn std::error::Error>> {
    let boundary = "stirling-pdf-info-boundary";
    let mut body = Vec::new();
    if let Some(pdf) = pdf {
        body.extend_from_slice(
            format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"fileInput\"; filename=\"information.pdf\"\r\nContent-Type: application/pdf\r\n\r\n"
            )
            .as_bytes(),
        );
        body.extend_from_slice(pdf);
        body.extend_from_slice(b"\r\n");
    }
    body.extend_from_slice(format!("--{boundary}--\r\n").as_bytes());
    Ok(app(2 * 1024 * 1024)
        .oneshot(
            Request::builder()
                .method("POST")
                .uri("/api/v1/security/get-info-on-pdf")
                .header(
                    header::CONTENT_TYPE,
                    format!("multipart/form-data; boundary={boundary}"),
                )
                .body(Body::from(body))?,
        )
        .await?)
}

#[allow(clippy::too_many_lines)]
fn information_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let font_descriptor_id = document.add_object(dictionary! {
        "Type" => "FontDescriptor",
        "FontName" => "Helvetica",
        "Flags" => 32,
        "ItalicAngle" => 0,
        "FontWeight" => 400,
        "FontFamily" => Object::string_literal("Helvetica"),
    });
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => "Helvetica",
        "FontDescriptor" => font_descriptor_id,
    });
    let image_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Image",
            "Width" => 2,
            "Height" => 1,
            "ColorSpace" => "DeviceRGB",
            "BitsPerComponent" => 8,
        },
        vec![255, 0, 0, 0, 255, 0],
    ));
    let link_action_id = document.add_object(dictionary! {
        "S" => "URI",
        "URI" => Object::string_literal("https://example.com"),
    });
    let link_id = document.add_object(dictionary! {
        "Type" => "Annot",
        "Subtype" => "Link",
        "Rect" => vec![0.into(), 0.into(), 20.into(), 20.into()],
        "A" => link_action_id,
        "Contents" => Object::string_literal("External link"),
    });
    let first_content_id = document.add_object(Stream::new(
        dictionary! {},
        b"BT /F1 12 Tf 10 10 Td (Hello world) Tj ET q 2 0 0 1 0 0 cm /Im0 Do Q".to_vec(),
    ));
    let first_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 595.276.into(), 841.89.into()],
        "Rotate" => 90,
        "Resources" => dictionary! {
            "Font" => dictionary! { "F1" => font_id },
            "XObject" => dictionary! { "Im0" => image_id },
        },
        "Contents" => first_content_id,
        "Annots" => vec![Object::Reference(link_id)],
    });
    let second_page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 612.into(), 792.into()],
        "Resources" => Dictionary::new(),
    });
    document.objects.insert(
        page_tree_id,
        Object::Dictionary(dictionary! {
            "Type" => "Pages",
            "Kids" => vec![Object::Reference(first_page_id), Object::Reference(second_page_id)],
            "Count" => 2,
        }),
    );

    let form_field_id = document.add_object(dictionary! {
        "FT" => "Tx",
        "T" => Object::string_literal("person.name"),
        "V" => Object::string_literal("Alice"),
    });
    let acroform_id = document.add_object(dictionary! {
        "Fields" => vec![Object::Reference(form_field_id)],
    });
    let script_action_id = document.add_object(dictionary! {
        "S" => "JavaScript",
        "JS" => Object::string_literal("app.alert('ready');"),
    });
    let javascript_tree_id = document.add_object(dictionary! {
        "Names" => vec![Object::string_literal("startup"), Object::Reference(script_action_id)],
    });
    let names_id = document.add_object(dictionary! { "JavaScript" => javascript_tree_id });
    let layer_id = document.add_object(dictionary! {
        "Type" => "OCG",
        "Name" => Object::string_literal("Review layer"),
    });
    let outline_item_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("First page"),
        "Dest" => vec![Object::Reference(first_page_id), Object::Name(b"Fit".to_vec())],
    });
    let outlines_id = document.add_object(dictionary! {
        "Type" => "Outlines",
        "First" => outline_item_id,
        "Last" => outline_item_id,
        "Count" => 1,
    });
    document
        .get_dictionary_mut(outline_item_id)?
        .set("Parent", outlines_id);
    let xmp_id = document.add_object(Stream::new(
        dictionary! { "Type" => "Metadata", "Subtype" => "XML" },
        br#"<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"/></x:xmpmeta>"#.to_vec(),
    ));
    let catalog_id = document.add_object(dictionary! {
        "Type" => "Catalog",
        "Pages" => page_tree_id,
        "PageMode" => "UseOutlines",
        "Lang" => Object::string_literal("en-US"),
        "AcroForm" => acroform_id,
        "Names" => names_id,
        "OCProperties" => dictionary! { "OCGs" => vec![Object::Reference(layer_id)] },
        "Outlines" => outlines_id,
        "Metadata" => xmp_id,
    });
    let info_id = document.add_object(dictionary! {
        "Title" => Object::string_literal("Information fixture"),
        "Author" => Object::string_literal("Stirling"),
        "CreationDate" => Object::string_literal("D:20260715123456+07'00'"),
        "ModDate" => Object::string_literal("D:20260715130000+07'00'"),
        "StirlingPDFClassification" => Object::string_literal("Internal"),
    });
    document.trailer.set("Root", catalog_id);
    document.trailer.set("Info", info_id);
    save(document)
}

fn clean_pdf() -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut document = Document::with_version("1.7");
    let page_tree_id = document.new_object_id();
    let page_id = document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => page_tree_id,
        "MediaBox" => vec![0.into(), 0.into(), 100.into(), 100.into()],
        "Resources" => Dictionary::new(),
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
    save(document)
}

fn save(mut document: Document) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut bytes = Vec::new();
    document.save_to(&mut bytes)?;
    Ok(bytes)
}
