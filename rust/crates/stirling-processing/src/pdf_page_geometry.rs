use std::{collections::HashSet, fmt::Write as _};

use lopdf::{Dictionary, Document, Object, ObjectId, Stream, dictionary};

#[derive(Debug, Clone, Copy)]
pub struct PageForm {
    pub id: ObjectId,
    pub width: f32,
    pub height: f32,
}

#[derive(Debug, Clone, Copy)]
pub struct FormPlacement {
    pub form: PageForm,
    pub scale_x: f32,
    pub scale_y: f32,
    pub translate_x: f32,
    pub translate_y: f32,
    pub clip: Option<(f32, f32, f32, f32)>,
    pub border_width: Option<f32>,
}

pub fn page_form(document: &mut Document, page_id: ObjectId) -> Result<PageForm, lopdf::Error> {
    let media_box = inherited_value(document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let media_box = media_box.as_array()?;
    let lower_x = media_box[0].as_float()?;
    let lower_y = media_box[1].as_float()?;
    let upper_x = media_box[2].as_float()?;
    let upper_y = media_box[3].as_float()?;
    let width = upper_x - lower_x;
    let height = upper_y - lower_y;
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
    let content = document.get_page_content(page_id);
    let form_id = document.add_object(Stream::new(
        dictionary! {
            "Type" => "XObject",
            "Subtype" => "Form",
            "FormType" => 1,
            "BBox" => vec![lower_x.into(), lower_y.into(), upper_x.into(), upper_y.into()],
            "Matrix" => vec![1.into(), 0.into(), 0.into(), 1.into(), (-lower_x).into(), (-lower_y).into()],
            "Resources" => resources,
        },
        content,
    ));
    Ok(PageForm {
        id: form_id,
        width,
        height,
    })
}

pub fn add_geometry_page(
    document: &mut Document,
    parent_id: ObjectId,
    width: f32,
    height: f32,
    placements: &[FormPlacement],
) -> ObjectId {
    let mut xobjects = Dictionary::new();
    let mut content = String::new();
    for (index, placement) in placements.iter().enumerate() {
        let name = format!("Fm{index}");
        xobjects.set(name.as_bytes(), placement.form.id);
        content.push_str("q ");
        if let Some((clip_x, clip_y, clip_width, clip_height)) = placement.clip {
            let _ = write!(
                content,
                "{clip_x} {clip_y} {clip_width} {clip_height} re W n "
            );
        }
        let _ = writeln!(
            content,
            "{} 0 0 {} {} {} cm /{name} Do Q",
            placement.scale_x, placement.scale_y, placement.translate_x, placement.translate_y
        );
        if let Some(border_width) = placement.border_width {
            let _ = writeln!(
                content,
                "q {border_width} w 0 G {} {} {} {} re S Q",
                placement.translate_x,
                placement.translate_y,
                placement.form.width * placement.scale_x,
                placement.form.height * placement.scale_y
            );
        }
    }
    let content_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    document.add_object(dictionary! {
        "Type" => "Page",
        "Parent" => parent_id,
        "MediaBox" => vec![0.into(), 0.into(), width.into(), height.into()],
        "Resources" => dictionary! { "XObject" => xobjects },
        "Contents" => content_id,
    })
}

/// The page attributes a `/Pages` node hands down to its kids (PDF 32000-1
/// table 30).
const INHERITABLE_PAGE_ATTRIBUTES: [&[u8]; 4] = [b"Resources", b"MediaBox", b"CropBox", b"Rotate"];

/// Re-roots the page tree onto freshly generated pages.
///
/// Java builds its output into a brand-new `PDDocument`, so the page tree root
/// it hands to `addPage` carries no inheritable attributes at all. We rewrite
/// the source document in place and therefore reuse its root, so those
/// attributes have to be cleared: otherwise a source whose `/Pages` node
/// carries `/Rotate` or `/CropBox` would pass them down to the generated pages,
/// which already have the rotation baked into their form matrices and their own
/// boxes written out. Leaving `/Rotate 90` in place rotates the page a second
/// time (827x1169 becomes 1169x827); leaving `/CropBox` crops the result.
pub fn replace_page_tree(
    document: &mut Document,
    root_pages_id: ObjectId,
    output_pages: Vec<ObjectId>,
) -> Result<(), lopdf::Error> {
    let count = i64::try_from(output_pages.len())
        .map_err(|error| lopdf::Error::NumericCast(error.to_string()))?;
    let pages = document.get_dictionary_mut(root_pages_id)?;
    for attribute in INHERITABLE_PAGE_ATTRIBUTES {
        pages.remove(attribute);
    }
    pages.set(
        "Kids",
        output_pages
            .into_iter()
            .map(Object::Reference)
            .collect::<Vec<_>>(),
    );
    pages.set("Count", count);
    let catalog = document.catalog_mut()?;
    catalog.remove(b"Outlines");
    Ok(())
}

pub fn inherited_value(
    document: &Document,
    mut object_id: ObjectId,
    key: &[u8],
) -> Result<Object, lopdf::Error> {
    let mut visited = HashSet::new();
    loop {
        if !visited.insert(object_id) {
            return Err(lopdf::Error::ReferenceCycle(object_id));
        }
        let dictionary = document.get_dictionary(object_id)?;
        if let Ok(value) = dictionary.get(key) {
            return Ok(value.clone());
        }
        object_id = dictionary.get(b"Parent")?.as_reference()?;
    }
}
