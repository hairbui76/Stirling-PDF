use std::{collections::HashSet, path::Path};

use lopdf::{
    Document, Object, ObjectId, Stream, StringFormat,
    content::{Content, Operation},
    dictionary,
};
use thiserror::Error;

use crate::page_selection::{PageSelectionError, parse_page_list};

const MAX_ZERO_PAD: usize = 4_096;

#[derive(Debug, Clone)]
pub struct PageNumberOptions {
    pub custom_margin: Option<String>,
    pub position: i32,
    pub starting_number: i32,
    pub pages_to_number: Option<String>,
    pub custom_text: Option<String>,
    pub zero_pad: i32,
    pub font_size: f32,
    pub font_type: Option<String>,
    pub font_color: Option<String>,
}

#[derive(Debug, Error)]
pub enum PageNumberError {
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("page selection is invalid: {0}")]
    PageSelection(#[from] PageSelectionError),
    #[error("zeroPad must not exceed {MAX_ZERO_PAD}")]
    ZeroPadTooLarge,
    #[error("fontSize must be finite")]
    NonFiniteFontSize,
    #[error("page {page_number} has an invalid MediaBox")]
    InvalidMediaBox { page_number: u32 },
    #[error("the page-number text contains a character unsupported by WinAnsi: {character}")]
    UnsupportedCharacter { character: char },
    #[error("malformed PDF page structure: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write the numbered PDF: {0}")]
    Write(#[from] std::io::Error),
}

#[derive(Debug, Clone, Copy)]
enum StandardFont {
    Helvetica,
    Courier,
    TimesRoman,
}

impl StandardFont {
    fn from_request(value: Option<&str>) -> Self {
        match value.unwrap_or_default().to_ascii_lowercase().as_str() {
            "courier" => Self::Courier,
            "times" => Self::TimesRoman,
            _ => Self::Helvetica,
        }
    }

    fn base_name(self) -> &'static str {
        match self {
            Self::Helvetica => "Helvetica",
            Self::Courier => "Courier",
            Self::TimesRoman => "Times-Roman",
        }
    }

    fn metrics(self) -> (&'static [u16; 256], f32, f32) {
        match self {
            Self::Helvetica => (&HELVETICA_WIDTHS, 718.0, -207.0),
            Self::Courier => (&COURIER_WIDTHS, 629.0, -157.0),
            Self::TimesRoman => (&TIMES_ROMAN_WIDTHS, 683.0, -217.0),
        }
    }
}

/// Adds visible page-number text using Standard 14 fonts and Java-compatible
/// page-selection, placement, template, color, and numbering semantics.
///
/// # Errors
///
/// Returns [`PageNumberError`] for unreadable PDFs, unsafe padding, invalid
/// page structures, unsupported `WinAnsi` text, or output failures.
pub fn add_page_numbers_to_file(
    input_path: &Path,
    filename: &str,
    options: &PageNumberOptions,
    output_path: &Path,
) -> Result<(), PageNumberError> {
    if !options.font_size.is_finite() {
        return Err(PageNumberError::NonFiniteFontSize);
    }
    let zero_pad = if options.zero_pad > 0 {
        usize::try_from(options.zero_pad).map_err(|_| PageNumberError::ZeroPadTooLarge)?
    } else {
        0
    };
    if zero_pad > MAX_ZERO_PAD {
        return Err(PageNumberError::ZeroPadTooLarge);
    }

    let mut document = Document::load(input_path).map_err(|source| PageNumberError::ReadPdf {
        filename: filename.to_owned(),
        source,
    })?;
    let pages = document.get_pages();
    let pages_expression = options
        .pages_to_number
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("all");
    let selected_pages = parse_page_list(pages_expression, pages.len())?;
    if selected_pages.is_empty() {
        document.save(output_path)?;
        return Ok(());
    }

    let font = StandardFont::from_request(options.font_type.as_deref());
    let font_id = document.add_object(dictionary! {
        "Type" => "Font",
        "Subtype" => "Type1",
        "BaseFont" => font.base_name(),
        "Encoding" => "WinAnsiEncoding",
    });
    let margin_factor = margin_factor(options.custom_margin.as_deref());
    let color = decode_java_color(options.font_color.as_deref());
    let custom_text = options
        .custom_text
        .as_deref()
        .filter(|value| !value.is_empty())
        .unwrap_or("{n}");
    let filename_stem = filename_stem(filename);
    let position = options.position.clamp(1, 9);
    let mut page_number = options.starting_number;
    let page_ids = pages.into_iter().collect::<Vec<_>>();

    for selected_index in selected_pages {
        let Some((pdf_page_number, page_id)) = page_ids.get(selected_index).copied() else {
            continue;
        };
        let formatted_number = padded_number(page_number, zero_pad);
        let text = custom_text
            .replace("{n}", &formatted_number)
            .replace("{total}", &page_ids.len().to_string())
            .replace("{filename}", filename_stem);
        let encoded_text = encode_win_ansi(&text)?;
        let media_box =
            media_box(&document, page_id).map_err(|_| PageNumberError::InvalidMediaBox {
                page_number: pdf_page_number,
            })?;
        let (x, y) = text_position(
            media_box,
            margin_factor,
            position,
            font,
            options.font_size,
            &encoded_text,
        );
        let font_name = install_font(&mut document, page_id, font_id)?;
        wrap_existing_page_content(&mut document, page_id)?;
        append_number_content(
            &mut document,
            page_id,
            font_name,
            options.font_size,
            color,
            (x, y),
            encoded_text,
        )?;
        page_number = page_number.wrapping_add(1);
    }

    document.save(output_path)?;
    Ok(())
}

fn margin_factor(value: Option<&str>) -> f32 {
    match value.unwrap_or_default().to_ascii_lowercase().as_str() {
        "small" => 0.02,
        "large" => 0.05,
        "x-large" => 0.075,
        _ => 0.035,
    }
}

fn padded_number(value: i32, width: usize) -> String {
    if width == 0 {
        value.to_string()
    } else {
        format!("{value:0width$}")
    }
}

fn filename_stem(filename: &str) -> &str {
    filename
        .rsplit_once('.')
        .filter(|(stem, extension)| !stem.is_empty() && !extension.is_empty())
        .map_or(filename, |(stem, _)| stem)
}

fn decode_java_color(value: Option<&str>) -> [f32; 3] {
    let Some(value) = value.filter(|value| !value.trim().is_empty()) else {
        return [0.0; 3];
    };
    let Some(rgb) = decode_java_integer(value) else {
        return [0.0; 3];
    };
    [
        color_channel(rgb, 16),
        color_channel(rgb, 8),
        color_channel(rgb, 0),
    ]
}

fn color_channel(rgb: i32, shift: u32) -> f32 {
    u8::try_from((rgb >> shift) & 0xff).map_or(0.0, f32::from) / 255.0
}

fn decode_java_integer(value: &str) -> Option<i32> {
    let (negative, unsigned) = match value.as_bytes().first().copied() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    if unsigned.is_empty() {
        return None;
    }
    let (radix, digits) = if let Some(digits) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
    {
        (16, digits)
    } else if let Some(digits) = unsigned.strip_prefix('#') {
        (16, digits)
    } else if unsigned.len() > 1 && unsigned.starts_with('0') {
        (8, &unsigned[1..])
    } else {
        (10, unsigned)
    };
    let magnitude = i64::from_str_radix(digits, radix).ok()?;
    let signed = if negative { -magnitude } else { magnitude };
    i32::try_from(signed).ok()
}

fn encode_win_ansi(text: &str) -> Result<Vec<u8>, PageNumberError> {
    text.chars()
        .map(|character| {
            win_ansi_byte(character).ok_or(PageNumberError::UnsupportedCharacter { character })
        })
        .collect()
}

fn win_ansi_byte(character: char) -> Option<u8> {
    match character {
        '\u{0000}'..='\u{007f}' | '\u{00a0}'..='\u{00ff}' => Some(character as u8),
        '\u{20ac}' => Some(0x80),
        '\u{201a}' => Some(0x82),
        '\u{0192}' => Some(0x83),
        '\u{201e}' => Some(0x84),
        '\u{2026}' => Some(0x85),
        '\u{2020}' => Some(0x86),
        '\u{2021}' => Some(0x87),
        '\u{02c6}' => Some(0x88),
        '\u{2030}' => Some(0x89),
        '\u{0160}' => Some(0x8a),
        '\u{2039}' => Some(0x8b),
        '\u{0152}' => Some(0x8c),
        '\u{017d}' => Some(0x8e),
        '\u{2018}' => Some(0x91),
        '\u{2019}' => Some(0x92),
        '\u{201c}' => Some(0x93),
        '\u{201d}' => Some(0x94),
        '\u{2022}' => Some(0x95),
        '\u{2013}' => Some(0x96),
        '\u{2014}' => Some(0x97),
        '\u{02dc}' => Some(0x98),
        '\u{2122}' => Some(0x99),
        '\u{0161}' => Some(0x9a),
        '\u{203a}' => Some(0x9b),
        '\u{0153}' => Some(0x9c),
        '\u{017e}' => Some(0x9e),
        '\u{0178}' => Some(0x9f),
        _ => None,
    }
}

fn media_box(document: &Document, page_id: ObjectId) -> Result<[f32; 4], lopdf::Error> {
    let media_box = inherited_value(document, page_id, b"MediaBox")?;
    let (_, media_box) = document.dereference(&media_box)?;
    let values = media_box.as_array()?;
    if values.len() != 4 {
        return Err(lopdf::Error::Syntax(
            "MediaBox must contain four values".to_owned(),
        ));
    }
    let box_values = [
        values[0].as_float()?,
        values[1].as_float()?,
        values[2].as_float()?,
        values[3].as_float()?,
    ];
    if box_values.iter().all(|value| value.is_finite())
        && box_values[2] > box_values[0]
        && box_values[3] > box_values[1]
    {
        Ok(box_values)
    } else {
        Err(lopdf::Error::Syntax(
            "MediaBox dimensions are invalid".to_owned(),
        ))
    }
}

fn text_position(
    media_box: [f32; 4],
    margin_factor: f32,
    position: i32,
    font: StandardFont,
    font_size: f32,
    text: &[u8],
) -> (f32, f32) {
    let [lower_x, lower_y, upper_x, upper_y] = media_box;
    let width = upper_x - lower_x;
    let height = upper_y - lower_y;
    let (widths, ascent, descent) = font.metrics();
    let text_width = text
        .iter()
        .map(|byte| f32::from(widths[usize::from(*byte)]))
        .sum::<f32>()
        / 1_000.0
        * font_size;
    let ascent = ascent / 1_000.0 * font_size;
    let descent = descent / 1_000.0 * font_size;
    let column = ((position - 1) % 3) + 1;
    let row = ((position - 1) / 3) + 1;
    let left_x = lower_x + margin_factor * width;
    let middle_x = lower_x + width / 2.0;
    let right_x = upper_x - margin_factor * width;
    let bottom_y = lower_y + margin_factor * height;
    let middle_y = lower_y + height / 2.0;
    let top_y = upper_y - margin_factor * height;
    let x = match column {
        1 => left_x,
        2 => middle_x - text_width / 2.0,
        _ => right_x - text_width,
    };
    let y = match row {
        1 => top_y - ascent,
        2 => middle_y - ascent.midpoint(descent),
        _ => bottom_y,
    };
    (x, y)
}

fn install_font(
    document: &mut Document,
    page_id: ObjectId,
    font_id: ObjectId,
) -> Result<Vec<u8>, lopdf::Error> {
    let mut resources = effective_page_resources(document, page_id)?;
    let mut fonts = resources
        .get(b"Font")
        .ok()
        .and_then(|fonts| document.dereference(fonts).ok())
        .and_then(|(_, fonts)| fonts.as_dict().ok())
        .cloned()
        .unwrap_or_default();
    let mut suffix = 0usize;
    let font_name = loop {
        let name = format!("StirlingPageNumber{suffix}").into_bytes();
        if !fonts.has(&name) {
            break name;
        }
        suffix = suffix.saturating_add(1);
    };
    fonts.set(font_name.clone(), font_id);
    resources.set("Font", fonts);
    document
        .get_dictionary_mut(page_id)?
        .set("Resources", resources);
    Ok(font_name)
}

fn append_number_content(
    document: &mut Document,
    page_id: ObjectId,
    font_name: Vec<u8>,
    font_size: f32,
    color: [f32; 3],
    position: (f32, f32),
    text: Vec<u8>,
) -> Result<(), lopdf::Error> {
    let (x, y) = position;
    document.add_to_page_content(
        page_id,
        Content {
            operations: vec![
                Operation::new("Q", Vec::new()),
                Operation::new("BT", Vec::new()),
                Operation::new("Tf", vec![Object::Name(font_name), Object::Real(font_size)]),
                Operation::new("rg", color.into_iter().map(Object::Real).collect()),
                Operation::new("Td", vec![Object::Real(x), Object::Real(y)]),
                Operation::new("Tj", vec![Object::String(text, StringFormat::Literal)]),
                Operation::new("ET", Vec::new()),
            ],
        },
    )
}

fn effective_page_resources(
    document: &Document,
    page_id: ObjectId,
) -> Result<lopdf::Dictionary, lopdf::Error> {
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(lopdf::Dictionary::new()));
    let (_, resources) = document.dereference(&resources)?;
    Ok(resources.as_dict()?.clone())
}

fn inherited_value(
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

fn wrap_existing_page_content(
    document: &mut Document,
    page_id: ObjectId,
) -> Result<(), lopdf::Error> {
    let current = document
        .get_dictionary(page_id)?
        .get(b"Contents")
        .ok()
        .cloned();
    let mut contents = match current {
        Some(Object::Array(contents)) => contents,
        Some(content) => vec![content],
        None => Vec::new(),
    };
    let prefix_id = document.add_object(Stream::new(lopdf::Dictionary::new(), b"q\n".to_vec()));
    contents.insert(0, Object::Reference(prefix_id));
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

const HELVETICA_WIDTHS: [u16; 256] = [
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 278, 278, 355, 556, 556, 889,
    667, 191, 333, 333, 389, 584, 278, 333, 278, 278, 556, 556, 556, 556, 556, 556, 556, 556, 556,
    556, 278, 278, 584, 584, 584, 556, 1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667,
    556, 833, 722, 778, 667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469,
    556, 333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556, 556, 556,
    333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584, 350, 556, 350, 222, 556, 333,
    1000, 556, 556, 333, 1000, 667, 333, 1000, 350, 611, 350, 350, 222, 222, 333, 333, 350, 556,
    1000, 333, 1000, 500, 333, 944, 350, 500, 667, 278, 333, 556, 556, 556, 556, 260, 556, 333,
    737, 370, 556, 584, 333, 737, 333, 400, 584, 333, 333, 333, 556, 537, 278, 333, 333, 365, 556,
    834, 834, 834, 611, 667, 667, 667, 667, 667, 667, 1000, 722, 667, 667, 667, 667, 278, 278, 278,
    278, 722, 722, 778, 778, 778, 778, 778, 584, 778, 722, 722, 722, 722, 667, 667, 611, 556, 556,
    556, 556, 556, 556, 889, 500, 556, 556, 556, 556, 278, 278, 278, 278, 556, 556, 556, 556, 556,
    556, 556, 584, 611, 556, 556, 556, 556, 500, 556, 500,
];

const COURIER_WIDTHS: [u16; 256] = [
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600, 600,
    600, 600, 600, 600, 600, 600, 600, 600, 600,
];

const TIMES_ROMAN_WIDTHS: [u16; 256] = [
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250,
    250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 250, 333, 408, 500, 500, 833,
    778, 180, 333, 333, 500, 564, 250, 333, 250, 278, 500, 500, 500, 500, 500, 500, 500, 500, 500,
    500, 278, 278, 564, 564, 564, 444, 921, 722, 667, 667, 722, 611, 556, 722, 722, 333, 389, 722,
    611, 889, 722, 722, 556, 722, 667, 556, 611, 722, 722, 944, 722, 722, 611, 333, 278, 333, 469,
    500, 333, 444, 500, 444, 500, 444, 333, 500, 500, 278, 278, 500, 278, 778, 500, 500, 500, 500,
    333, 389, 278, 500, 500, 722, 500, 500, 444, 480, 200, 480, 541, 350, 500, 350, 333, 500, 444,
    1000, 500, 500, 333, 1000, 556, 333, 889, 350, 611, 350, 350, 333, 333, 444, 444, 350, 500,
    1000, 333, 980, 389, 333, 722, 350, 444, 722, 250, 333, 500, 500, 500, 500, 200, 500, 333, 760,
    276, 500, 564, 333, 760, 333, 400, 564, 300, 300, 333, 500, 453, 250, 333, 300, 310, 500, 750,
    750, 750, 444, 722, 722, 722, 722, 722, 722, 889, 667, 611, 611, 611, 611, 333, 333, 333, 333,
    722, 722, 722, 722, 722, 722, 722, 564, 722, 722, 722, 722, 722, 722, 556, 500, 444, 444, 444,
    444, 444, 444, 667, 444, 444, 444, 444, 444, 278, 278, 278, 278, 500, 500, 500, 500, 500, 500,
    500, 564, 500, 500, 500, 500, 500, 500, 500, 500,
];

#[cfg(test)]
mod tests {
    use super::{
        StandardFont, decode_java_color, encode_win_ansi, filename_stem, padded_number,
        text_position,
    };

    #[test]
    fn matches_java_number_color_and_filename_rules() {
        assert_eq!(padded_number(7, 4), "0007");
        assert_eq!(padded_number(-7, 4), "-007");
        assert_eq!(filename_stem("archive.tar.pdf"), "archive.tar");
        assert_color_close(
            decode_java_color(Some("#FF8000")),
            [1.0, 128.0 / 255.0, 0.0],
        );
        assert_color_close(decode_java_color(Some("010")), [0.0, 0.0, 8.0 / 255.0]);
        assert_color_close(decode_java_color(Some(" #fff ")), [0.0; 3]);
        assert_color_close(decode_java_color(Some("-1")), [1.0; 3]);
    }

    #[test]
    fn encodes_win_ansi_and_uses_pdfbox_standard_font_metrics() -> Result<(), super::PageNumberError>
    {
        assert_eq!(encode_win_ansi("A€Ÿ")?, [65, 128, 159]);
        assert!(encode_win_ansi("😀").is_err());
        let (x, y) = text_position(
            [0.0, 0.0, 200.0, 300.0],
            0.035,
            2,
            StandardFont::Helvetica,
            10.0,
            b"AA",
        );
        assert!((x - 93.33).abs() < 0.001);
        assert!((y - 282.32).abs() < 0.001);
        Ok(())
    }

    fn assert_color_close(actual: [f32; 3], expected: [f32; 3]) {
        for (actual, expected) in actual.into_iter().zip(expected) {
            assert!((actual - expected).abs() < f32::EPSILON);
        }
    }
}
