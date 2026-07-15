use std::{fmt::Write as _, fs::File, io::BufReader, path::Path};

use chrono::{Datelike, Local};
use image::{ImageReader, Limits};
use lopdf::{Dictionary, Document, Object, ObjectId, Stream, decode_text_string, dictionary};
use rand::RngExt as _;
use thiserror::Error;

use crate::{
    image_to_pdf::{ImageToPdfError, add_color_image_xobject},
    page_selection::{PageSelectionError, parse_page_list},
    pdf_image_overlay::{ImageOverlayError, import_svg_form},
    pdf_overlay::{append_original_contents, install_xobject},
    pdf_page_geometry::{PageForm, inherited_value},
};

const MAX_IMAGE_DIMENSION: u32 = 50_000;

#[derive(Debug, Clone)]
pub struct StampOptions {
    pub stamp_type: String,
    pub stamp_text: String,
    pub alphabet: String,
    pub font_size: f32,
    pub rotation: f32,
    pub opacity: f32,
    pub position: i32,
    pub override_x: f32,
    pub override_y: f32,
    pub custom_margin: String,
    pub custom_color: String,
    pub page_numbers: String,
}

#[derive(Debug, Error)]
pub enum StampError {
    #[error("stampType must be text or image")]
    InvalidStampType,
    #[error("stampImage is required when stampType is image")]
    MissingStampImage,
    #[error("fontSize must be positive for image stamps")]
    InvalidImageSize,
    #[error("opacity must be a finite number between 0 and 1")]
    InvalidOpacity,
    #[error("position must be between 1 and 9")]
    InvalidPosition,
    #[error("stamp coordinates and rotation must be finite")]
    InvalidCoordinates,
    #[error("could not read PDF '{filename}': {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("input PDF '{filename}' has no pages")]
    EmptyPdf { filename: String },
    #[error("invalid page selection: {0}")]
    PageSelection(#[from] PageSelectionError),
    #[error("could not open stamp image: {0}")]
    OpenImage(std::io::Error),
    #[error("could not determine stamp image format: {0}")]
    GuessImageFormat(std::io::Error),
    #[error("could not decode stamp image: {0}")]
    DecodeImage(#[from] image::ImageError),
    #[error("could not embed stamp image: {0}")]
    ImagePdf(#[from] ImageToPdfError),
    #[error("could not construct text stamp: {0}")]
    TextSvg(#[from] ImageOverlayError),
    #[error("PDF structure error: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write stamped PDF: {0}")]
    WritePdf(std::io::Error),
}

#[derive(Debug, Clone, Copy)]
struct StampObject {
    id: ObjectId,
    width: f32,
    height: f32,
    scale_to_size: bool,
}

/// Adds text or raster-image stamps to selected pages and writes a new PDF.
///
/// # Errors
///
/// Returns [`StampError`] for invalid parameters, malformed inputs, unsafe page selections, or
/// PDF/SVG output failures.
pub fn add_stamp_to_file(
    input_path: &Path,
    input_filename: &str,
    stamp_image_path: Option<&Path>,
    options: &StampOptions,
    output_path: &Path,
) -> Result<(), StampError> {
    let stamp_type = options.stamp_type.trim().to_ascii_lowercase();
    if stamp_type != "text" && stamp_type != "image" {
        return Err(StampError::InvalidStampType);
    }
    validate_options(options, &stamp_type)?;

    let mut document = Document::load(input_path).map_err(|source| StampError::ReadPdf {
        filename: input_filename.to_owned(),
        source,
    })?;
    document.renumber_objects_with(1);
    let pages = document.get_pages().into_iter().collect::<Vec<_>>();
    if pages.is_empty() {
        return Err(StampError::EmptyPdf {
            filename: input_filename.to_owned(),
        });
    }
    let selected_pages = parse_page_list(&options.page_numbers, pages.len())?;
    let image_stamp = if stamp_type == "image" {
        Some(build_image_stamp(
            &mut document,
            stamp_image_path.ok_or(StampError::MissingStampImage)?,
            options.font_size,
        )?)
    } else {
        None
    };

    for selected_index in selected_pages {
        let Some((page_number, page_id)) = pages.get(selected_index).copied() else {
            continue;
        };
        let stamp = if let Some(stamp) = image_stamp {
            stamp
        } else {
            build_text_stamp(
                &mut document,
                input_filename,
                page_number,
                pages.len(),
                options,
            )?
        };
        apply_stamp(&mut document, page_id, page_number, stamp, options)?;
    }

    document.renumber_objects();
    document.compress();
    document.save(output_path).map_err(StampError::WritePdf)?;
    Ok(())
}

fn validate_options(options: &StampOptions, stamp_type: &str) -> Result<(), StampError> {
    if !options.opacity.is_finite() || !(0.0..=1.0).contains(&options.opacity) {
        return Err(StampError::InvalidOpacity);
    }
    if !(1..=9).contains(&options.position) {
        return Err(StampError::InvalidPosition);
    }
    if !options.rotation.is_finite()
        || !options.override_x.is_finite()
        || !options.override_y.is_finite()
        || !options.font_size.is_finite()
    {
        return Err(StampError::InvalidCoordinates);
    }
    if stamp_type == "image" && options.font_size <= 0.0 {
        return Err(StampError::InvalidImageSize);
    }
    Ok(())
}

fn build_image_stamp(
    document: &mut Document,
    image_path: &Path,
    height: f32,
) -> Result<StampObject, StampError> {
    let file = File::open(image_path).map_err(StampError::OpenImage)?;
    let mut reader = ImageReader::new(BufReader::new(file))
        .with_guessed_format()
        .map_err(StampError::GuessImageFormat)?;
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_IMAGE_DIMENSION);
    limits.max_image_height = Some(MAX_IMAGE_DIMENSION);
    reader.limits(limits);
    let image = reader.decode()?;
    let image_width =
        f32::from(u16::try_from(image.width()).map_err(|_| StampError::InvalidImageSize)?);
    let image_height =
        f32::from(u16::try_from(image.height()).map_err(|_| StampError::InvalidImageSize)?);
    let aspect_ratio = image_width / image_height;
    let (id, _, _) = add_color_image_xobject(document, &image)?;
    Ok(StampObject {
        id,
        width: height * aspect_ratio,
        height,
        scale_to_size: true,
    })
}

fn build_text_stamp(
    document: &mut Document,
    filename: &str,
    page_number: u32,
    page_count: usize,
    options: &StampOptions,
) -> Result<StampObject, StampError> {
    let font_size = if options.font_size > 0.0 {
        options.font_size
    } else {
        40.0
    };
    let text = process_stamp_text(
        &options.stamp_text,
        page_number,
        page_count,
        filename,
        document,
    );
    let text = text.replace("\\n", "\n");
    let lines = text.split(['\r', '\n']).collect::<Vec<_>>();
    let family = font_family(&options.alphabet);
    let color = normalized_color(&options.custom_color);
    let line_height = font_size * 1.2;
    let markup = text_markup(&lines, font_size, line_height, family, &color);
    let measurement = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"100000\" height=\"100000\" viewBox=\"0 0 100000 100000\">{markup}</svg>"
    );
    let mut parse_options = svg2pdf::usvg::Options::default();
    parse_options.fontdb_mut().load_system_fonts();
    let tree = svg2pdf::usvg::Tree::from_str(&measurement, &parse_options)
        .map_err(|error| ImageOverlayError::ParseSvg(error.to_string()))?;
    let bounds = tree.root().abs_bounding_box();
    let width = bounds.width().max(1.0);
    let height = bounds.height().max(1.0);
    let final_svg = format!(
        "<svg xmlns=\"http://www.w3.org/2000/svg\" width=\"{width}pt\" height=\"{height}pt\" viewBox=\"0 0 {width} {height}\"><g transform=\"translate({} {})\">{markup}</g></svg>",
        -bounds.x(),
        -bounds.y(),
    );
    let PageForm { id, width, height } = import_svg_form(document, final_svg.as_bytes())?;
    Ok(StampObject {
        id,
        width,
        height,
        scale_to_size: false,
    })
}

fn text_markup(
    lines: &[&str],
    font_size: f32,
    line_height: f32,
    family: &str,
    color: &str,
) -> String {
    let mut tspans = String::new();
    for (index, line) in lines.iter().enumerate() {
        let index = u16::try_from(index).map_or(f32::from(u16::MAX), f32::from);
        let y = font_size + index * line_height;
        let _ = write!(
            tspans,
            "<tspan x=\"0\" y=\"{y}\">{}</tspan>",
            xml_escape(line)
        );
    }
    format!(
        "<text xml:space=\"preserve\" font-family=\"{family}\" font-size=\"{font_size}\" fill=\"{color}\">{tspans}</text>"
    )
}

fn apply_stamp(
    document: &mut Document,
    page_id: ObjectId,
    page_number: u32,
    stamp: StampObject,
    options: &StampOptions,
) -> Result<(), StampError> {
    let media_box = media_box(document, page_id)?;
    let margin = margin_factor(&options.custom_margin)
        * ((media_box[2] - media_box[0]) + (media_box[3] - media_box[1]))
        / 2.0;
    let (mut x, mut y) = stamp_position(media_box, stamp.width, stamp.height, margin, options);
    if stamp.scale_to_size {
        x = x.clamp(media_box[0], (media_box[2] - stamp.width).max(media_box[0]));
        y = y.clamp(
            media_box[1],
            (media_box[3] - stamp.height).max(media_box[1]),
        );
    }

    let xobject_name = format!("Stamp{page_number}");
    let graphics_name = format!("StampGS{page_number}");
    install_xobject(document, page_id, xobject_name.as_bytes(), stamp.id)?;
    install_graphics_state(document, page_id, graphics_name.as_bytes(), options.opacity)?;
    let radians = options.rotation.to_radians();
    let cosine = radians.cos();
    let sine = radians.sin();
    let scale = if stamp.scale_to_size {
        format!(
            "{} 0 0 {} 0 0 cm\n",
            pdf_number(stamp.width),
            pdf_number(stamp.height)
        )
    } else {
        String::new()
    };
    let content = format!(
        "q\n/{graphics_name} gs\n{} {} {} {} {} {} cm\n{scale}/{xobject_name} Do\nQ\n",
        pdf_number(cosine),
        pdf_number(sine),
        pdf_number(-sine),
        pdf_number(cosine),
        pdf_number(x),
        pdf_number(y),
    );
    let content_id = document.add_object(Stream::new(dictionary! {}, content.into_bytes()));
    let original = document
        .get_dictionary(page_id)?
        .get(b"Contents")
        .ok()
        .cloned();
    let mut contents = Vec::new();
    append_original_contents(document, original, &mut contents);
    contents.push(Object::Reference(content_id));
    document
        .get_dictionary_mut(page_id)?
        .set("Contents", contents);
    Ok(())
}

pub(crate) fn install_graphics_state(
    document: &mut Document,
    page_id: ObjectId,
    name: &[u8],
    opacity: f32,
) -> Result<(), lopdf::Error> {
    let state_id = document.add_object(dictionary! {
        "Type" => "ExtGState",
        "ca" => opacity,
    });
    let resources = inherited_value(document, page_id, b"Resources")
        .unwrap_or_else(|_| Object::Dictionary(Dictionary::new()));
    let (_, resources) = document.dereference(&resources)?;
    let mut resources = resources.as_dict()?.clone();
    let mut states = match resources.get(b"ExtGState") {
        Ok(value) => {
            let (_, value) = document.dereference(value)?;
            value.as_dict()?.clone()
        }
        Err(_) => Dictionary::new(),
    };
    states.set(name, state_id);
    resources.set("ExtGState", states);
    document
        .get_dictionary_mut(page_id)?
        .set("Resources", resources);
    Ok(())
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
    let values = [
        values[0].as_float()?,
        values[1].as_float()?,
        values[2].as_float()?,
        values[3].as_float()?,
    ];
    if values.iter().all(|value| value.is_finite())
        && values[2] > values[0]
        && values[3] > values[1]
    {
        Ok(values)
    } else {
        Err(lopdf::Error::Syntax(
            "MediaBox dimensions are invalid".to_owned(),
        ))
    }
}

fn stamp_position(
    media_box: [f32; 4],
    content_width: f32,
    content_height: f32,
    margin: f32,
    options: &StampOptions,
) -> (f32, f32) {
    if options.override_x >= 0.0 && options.override_y >= 0.0 {
        return (options.override_x, options.override_y);
    }
    let [lower_x, lower_y, upper_x, upper_y] = media_box;
    let width = upper_x - lower_x;
    let height = upper_y - lower_y;
    let x = match options.position % 3 {
        1 => lower_x + margin,
        2 => lower_x + (width - content_width) / 2.0,
        _ => upper_x - content_width - margin,
    };
    let y = match (options.position - 1) / 3 {
        0 => upper_y - margin - content_height,
        1 => lower_y + (height - content_height) / 2.0,
        _ => lower_y + margin,
    };
    (x, y)
}

fn margin_factor(value: &str) -> f32 {
    match value.trim().to_ascii_lowercase().as_str() {
        "small" => 0.02,
        "large" => 0.05,
        "x-large" => 0.075,
        _ => 0.035,
    }
}

pub(crate) fn font_family(alphabet: &str) -> &'static str {
    match alphabet.trim().to_ascii_lowercase().as_str() {
        "arabic" => "Noto Sans Arabic, sans-serif",
        "japanese" => "Meiryo, Noto Sans CJK JP, sans-serif",
        "korean" => "Malgun Gothic, Noto Sans CJK KR, sans-serif",
        "chinese" => "SimSun, Noto Sans CJK SC, sans-serif",
        "thai" => "Noto Sans Thai, sans-serif",
        _ => "Noto Sans, Arial, sans-serif",
    }
}

fn normalized_color(value: &str) -> String {
    decode_java_integer(value).map_or_else(
        || "#d3d3d3".to_owned(),
        |value| format!("#{:06x}", value & 0x00ff_ffff),
    )
}

fn decode_java_integer(value: &str) -> Option<i32> {
    let value = value.trim();
    let (negative, unsigned) = match value.as_bytes().first().copied() {
        Some(b'-') => (true, &value[1..]),
        Some(b'+') => (false, &value[1..]),
        _ => (false, value),
    };
    let (radix, digits) = if let Some(digits) = unsigned
        .strip_prefix("0x")
        .or_else(|| unsigned.strip_prefix("0X"))
        .or_else(|| unsigned.strip_prefix('#'))
    {
        (16, digits)
    } else if unsigned.len() > 1 && unsigned.starts_with('0') {
        (8, &unsigned[1..])
    } else {
        (10, unsigned)
    };
    let magnitude = i64::from_str_radix(digits, radix).ok()?;
    i32::try_from(if negative { -magnitude } else { magnitude }).ok()
}

fn process_stamp_text(
    text: &str,
    page_number: u32,
    page_count: usize,
    filename: &str,
    document: &Document,
) -> String {
    if text.is_empty() {
        return String::new();
    }
    let escaped_at = "\u{e000}ESCAPED_AT\u{e000}";
    let now = Local::now();
    let mut result = text.replace("@@", escaped_at);
    result = replace_custom_dates(&result, &now);
    let filename_stem = Path::new(filename)
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or(filename);
    let mut random = [0_u8; 4];
    rand::rng().fill(&mut random);
    let short_uuid = random
        .iter()
        .fold(String::with_capacity(8), |mut output, byte| {
            let _ = write!(output, "{byte:02x}");
            output
        });
    let replacements = [
        ("@datetime", now.format("%Y-%m-%d %H:%M:%S").to_string()),
        ("@date", now.format("%Y-%m-%d").to_string()),
        ("@time", now.format("%H:%M:%S").to_string()),
        ("@year", now.year().to_string()),
        ("@month", format!("{:02}", now.month())),
        ("@day", format!("{:02}", now.day())),
        ("@page_number", page_number.to_string()),
        ("@page_count", page_count.to_string()),
        ("@total_pages", page_count.to_string()),
        ("@page", page_number.to_string()),
        ("@filename_full", filename.to_owned()),
        ("@filename", filename_stem.to_owned()),
        ("@author", document_info_text(document, b"Author")),
        ("@title", document_info_text(document, b"Title")),
        ("@subject", document_info_text(document, b"Subject")),
        ("@uuid", short_uuid),
    ];
    for (token, replacement) in replacements {
        result = result.replace(token, &replacement);
    }
    result.replace(escaped_at, "@")
}

fn replace_custom_dates(text: &str, now: &chrono::DateTime<Local>) -> String {
    let mut output = String::with_capacity(text.len());
    let mut remainder = text;
    while let Some(start) = remainder.find("@date{") {
        output.push_str(&remainder[..start]);
        let after_open = &remainder[start + 6..];
        let Some(end) = after_open.find('}') else {
            output.push_str(&remainder[start..]);
            return output;
        };
        let pattern = &after_open[..end];
        output.push_str(&format_custom_date(pattern, now));
        remainder = &after_open[end + 1..];
    }
    output.push_str(remainder);
    output
}

fn format_custom_date(pattern: &str, now: &chrono::DateTime<Local>) -> String {
    if pattern.is_empty() || pattern.len() > 50 {
        return "[invalid format: too long]".to_owned();
    }
    let Some(format) = java_date_pattern_to_chrono(pattern) else {
        return format!("[invalid format: {pattern}]");
    };
    now.format(&format).to_string()
}

fn java_date_pattern_to_chrono(pattern: &str) -> Option<String> {
    let characters = pattern.chars().collect::<Vec<_>>();
    let mut output = String::new();
    let mut index = 0;
    let mut quoted = false;
    while index < characters.len() {
        let character = characters[index];
        if character == '\'' {
            if characters.get(index + 1) == Some(&'\'') {
                output.push('\'');
                index += 2;
            } else {
                quoted = !quoted;
                index += 1;
            }
            continue;
        }
        if quoted || !character.is_ascii_alphabetic() {
            if character == '%' {
                output.push('%');
            }
            output.push(character);
            index += 1;
            continue;
        }
        let start = index;
        while characters.get(index) == Some(&character) {
            index += 1;
        }
        let count = index - start;
        if character == 'S' && (1..=9).contains(&count) {
            output.push('%');
            output.push_str(&count.to_string());
            output.push('f');
            continue;
        }
        output.push_str(match (character, count) {
            ('y', 2) => "%y",
            ('y', _) => "%Y",
            ('M', 1) => "%-m",
            ('M', 2) => "%m",
            ('M', 3) => "%b",
            ('M', _) => "%B",
            ('d', 1) => "%-d",
            ('d', _) => "%d",
            ('H', 1) => "%-H",
            ('H', _) => "%H",
            ('h', 1) => "%-I",
            ('h', _) => "%I",
            ('m', 1) => "%-M",
            ('m', _) => "%M",
            ('s', 1) => "%-S",
            ('s', _) => "%S",
            ('E', 1..=3) => "%a",
            ('E', _) => "%A",
            ('a', _) => "%p",
            _ => return None,
        });
    }
    (!quoted).then_some(output)
}

fn document_info_text(document: &Document, key: &[u8]) -> String {
    document
        .trailer
        .get(b"Info")
        .ok()
        .and_then(|value| document.dereference(value).ok())
        .and_then(|(_, value)| value.as_dict().ok())
        .and_then(|dictionary| dictionary.get(key).ok())
        .and_then(|value| decode_text_string(value).ok())
        .unwrap_or_default()
}

pub(crate) fn xml_escape(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&apos;")
}

pub(crate) fn pdf_number(value: f32) -> String {
    let value = if value.abs() < 0.000_000_5 {
        0.0
    } else {
        value
    };
    let mut output = format!("{value:.6}");
    while output.contains('.') && output.ends_with('0') {
        output.pop();
    }
    if output.ends_with('.') {
        output.pop();
    }
    output
}

#[cfg(test)]
mod tests {
    use chrono::{Local, TimeZone as _};

    use super::{StampOptions, format_custom_date, normalized_color, stamp_position};

    #[test]
    fn converts_common_java_date_patterns() {
        let now = Local.with_ymd_and_hms(2026, 7, 15, 9, 8, 7).unwrap();
        assert_eq!(
            format_custom_date("dd/MM/yyyy HH:mm:ss", &now),
            "15/07/2026 09:08:07"
        );
        assert_eq!(format_custom_date("yyyy-MM-dd", &now), "2026-07-15");
    }

    #[test]
    fn matches_java_color_fallbacks_and_grid_positions() {
        assert_eq!(normalized_color("#ff0080"), "#ff0080");
        assert_eq!(normalized_color("bad"), "#d3d3d3");
        let options = StampOptions {
            stamp_type: "image".to_owned(),
            stamp_text: String::new(),
            alphabet: "roman".to_owned(),
            font_size: 20.0,
            rotation: 0.0,
            opacity: 0.5,
            position: 1,
            override_x: -1.0,
            override_y: -1.0,
            custom_margin: "medium".to_owned(),
            custom_color: "#d3d3d3".to_owned(),
            page_numbers: "all".to_owned(),
        };
        assert_eq!(
            stamp_position([0.0, 0.0, 100.0, 200.0], 20.0, 10.0, 5.0, &options),
            (5.0, 185.0)
        );
    }
}
