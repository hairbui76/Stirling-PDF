use std::{collections::HashSet, ffi::OsString, io::ErrorKind, path::Path, process::Command};

use lopdf::{
    Dictionary, Document, Object, ObjectId,
    content::{Content, Operation},
};
use thiserror::Error;

use crate::{
    ghostscript::{exit_status, ghostscript_commands},
    pdf_flatten::configured_max_render_dpi,
    pdfium_backend::{PdfiumInvertAttempt, PdfiumInvertError, try_invert_pdf_to_file},
};

/// Color transformation requested by the `replace-invert-pdf` endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReplaceAndInvert {
    HighContrastColor,
    CustomColor,
    FullInversion,
    ColorSpaceConversion,
}

/// Preset text/background combinations accepted by the Java request model.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HighContrastColorCombination {
    WhiteTextOnBlack,
    BlackTextOnWhite,
    YellowTextOnBlack,
    GreenTextOnBlack,
}

impl HighContrastColorCombination {
    /// Parses `highContrastColorCombination`.
    ///
    /// # Errors
    ///
    /// Returns [`ReplaceInvertError::InvalidHighContrastCombination`] for unknown values.
    pub fn parse(value: &str) -> Result<Self, ReplaceInvertError> {
        match value.trim() {
            "WHITE_TEXT_ON_BLACK" => Ok(Self::WhiteTextOnBlack),
            "BLACK_TEXT_ON_WHITE" => Ok(Self::BlackTextOnWhite),
            "YELLOW_TEXT_ON_BLACK" => Ok(Self::YellowTextOnBlack),
            "GREEN_TEXT_ON_BLACK" => Ok(Self::GreenTextOnBlack),
            _ => Err(ReplaceInvertError::InvalidHighContrastCombination),
        }
    }

    fn colors(self) -> ([u8; 3], [u8; 3]) {
        match self {
            Self::WhiteTextOnBlack => ([255, 255, 255], [0, 0, 0]),
            Self::BlackTextOnWhite => ([0, 0, 0], [255, 255, 255]),
            Self::YellowTextOnBlack => ([255, 255, 0], [0, 0, 0]),
            Self::GreenTextOnBlack => ([0, 255, 0], [0, 0, 0]),
        }
    }
}

/// Complete request options for the replace/invert endpoint.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReplaceInvertOptions {
    pub option: ReplaceAndInvert,
    pub high_contrast_combination: HighContrastColorCombination,
    pub background_color: Option<String>,
    pub text_color: Option<String>,
}

impl ReplaceAndInvert {
    /// Parses the `replaceAndInvertOption` form value.
    ///
    /// # Errors
    ///
    /// Returns [`ReplaceInvertError::InvalidOption`] for unknown values.
    pub fn parse(value: &str) -> Result<Self, ReplaceInvertError> {
        match value.trim() {
            "HIGH_CONTRAST_COLOR" => Ok(Self::HighContrastColor),
            "CUSTOM_COLOR" => Ok(Self::CustomColor),
            "FULL_INVERSION" => Ok(Self::FullInversion),
            "COLOR_SPACE_CONVERSION" => Ok(Self::ColorSpaceConversion),
            _ => Err(ReplaceInvertError::InvalidOption),
        }
    }
}

#[derive(Debug, Error)]
pub enum ReplaceInvertError {
    #[error(
        "replaceAndInvertOption must be HIGH_CONTRAST_COLOR, CUSTOM_COLOR, FULL_INVERSION, or COLOR_SPACE_CONVERSION"
    )]
    InvalidOption,
    #[error("highContrastColorCombination is invalid")]
    InvalidHighContrastCombination,
    #[error("{0} must be a Java Color.decode-compatible value")]
    InvalidColor(&'static str),
    #[error("could not read '{filename}' as a PDF: {source}")]
    ReadPdf {
        filename: String,
        #[source]
        source: lopdf::Error,
    },
    #[error("could not recolor PDF content: {0}")]
    Pdf(#[from] lopdf::Error),
    #[error("could not write recolored PDF: {0}")]
    Write(#[from] std::io::Error),
    #[error("PDFium is required to invert PDF colors: {details}")]
    PdfiumUnavailable {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumInvertError),
    #[error(
        "CMYK color space conversion requires Ghostscript, which is not available on this system"
    )]
    GhostscriptUnavailable,
    #[error("Ghostscript CMYK conversion with '{command}' failed with status {status}: {details}")]
    GhostscriptFailed {
        command: String,
        status: String,
        details: String,
    },
    #[error("could not start Ghostscript command '{command}': {source}")]
    GhostscriptStart {
        command: String,
        #[source]
        source: std::io::Error,
    },
}

/// Applies the requested color transformation and writes the result to `output_path`.
///
/// `FULL_INVERSION` rasterizes each page and inverts its colors. `COLOR_SPACE_CONVERSION`
/// shells out to Ghostscript for a CMYK/prepress conversion. High-contrast and custom modes
/// prepend a page background and recolor text-showing operations in page/Form content streams.
///
/// # Errors
///
/// Returns [`ReplaceInvertError`] when the option is unsupported, `PDFium` or Ghostscript
/// is unavailable, or the underlying tool fails.
pub fn replace_invert_color_to_file(
    input_path: &Path,
    filename: &str,
    options: &ReplaceInvertOptions,
    output_path: &Path,
) -> Result<(), ReplaceInvertError> {
    match options.option {
        ReplaceAndInvert::FullInversion => invert_full_color(input_path, filename, output_path),
        ReplaceAndInvert::ColorSpaceConversion => convert_color_space_cmyk(input_path, output_path),
        ReplaceAndInvert::HighContrastColor => {
            let (text_color, background_color) = options.high_contrast_combination.colors();
            recolor_text_content(
                input_path,
                filename,
                text_color,
                background_color,
                output_path,
            )
        }
        ReplaceAndInvert::CustomColor => {
            let text_color = decode_java_color(options.text_color.as_deref(), "textColor")?;
            let background_color =
                decode_java_color(options.background_color.as_deref(), "backGroundColor")?;
            recolor_text_content(
                input_path,
                filename,
                text_color,
                background_color,
                output_path,
            )
        }
    }
}

#[derive(Debug, Clone, Default)]
struct NonStrokingColorState {
    color_space: Option<Operation>,
    color: Option<Operation>,
}

fn recolor_text_content(
    input_path: &Path,
    filename: &str,
    text_color: [u8; 3],
    background_color: [u8; 3],
    output_path: &Path,
) -> Result<(), ReplaceInvertError> {
    let mut document =
        Document::load(input_path).map_err(|source| ReplaceInvertError::ReadPdf {
            filename: filename.to_owned(),
            source,
        })?;
    let page_ids = document.page_iter().collect::<Vec<_>>();
    let mut visited_forms = HashSet::new();
    for page_id in page_ids {
        let form_ids = page_form_xobject_ids(&document, page_id)?;
        recolor_page_content(&mut document, page_id, text_color, background_color)?;
        for form_id in form_ids {
            recolor_form_xobject(&mut document, form_id, text_color, &mut visited_forms)?;
        }
    }
    document.save(output_path)?;
    Ok(())
}

fn recolor_page_content(
    document: &mut Document,
    page_id: ObjectId,
    text_color: [u8; 3],
    background_color: [u8; 3],
) -> Result<(), ReplaceInvertError> {
    let content_data = document.get_page_content(page_id);
    let mut content = Content::decode(&content_data)?;
    recolor_text_operations(&mut content.operations, text_color);
    let media_box = inherited_page_box(document, page_id)?;
    let mut operations = background_operations(media_box, background_color);
    operations.extend(content.operations);
    document.change_page_content(page_id, Content { operations }.encode()?)?;
    Ok(())
}

fn recolor_form_xobject(
    document: &mut Document,
    form_id: ObjectId,
    text_color: [u8; 3],
    visited_forms: &mut HashSet<ObjectId>,
) -> Result<(), ReplaceInvertError> {
    if !visited_forms.insert(form_id) {
        return Ok(());
    }
    let child_forms = form_xobject_ids(document, form_id)?;
    let content_data = document
        .get_object(form_id)?
        .as_stream()?
        .decompressed_content()?;
    let mut content = Content::decode(&content_data)?;
    recolor_text_operations(&mut content.operations, text_color);
    document
        .get_object_mut(form_id)?
        .as_stream_mut()?
        .set_plain_content(content.encode()?);
    for child_id in child_forms {
        recolor_form_xobject(document, child_id, text_color, visited_forms)?;
    }
    Ok(())
}

fn recolor_text_operations(operations: &mut Vec<Operation>, text_color: [u8; 3]) {
    let mut output = Vec::with_capacity(operations.len());
    let mut state = NonStrokingColorState::default();
    let mut stack = Vec::new();
    for operation in operations.drain(..) {
        match operation.operator.as_str() {
            "q" => stack.push(state.clone()),
            "Q" => state = stack.pop().unwrap_or_default(),
            "cs" => {
                state.color_space = Some(operation.clone());
                state.color = None;
            }
            "g" | "rg" | "k" => {
                state.color_space = None;
                state.color = Some(operation.clone());
            }
            "sc" | "scn" => state.color = Some(operation.clone()),
            "Tj" | "TJ" | "'" | "\"" => {
                output.push(rgb_operation(text_color));
                output.push(operation);
                append_color_restore(&mut output, &state);
                continue;
            }
            _ => {}
        }
        output.push(operation);
    }
    *operations = output;
}

fn append_color_restore(output: &mut Vec<Operation>, state: &NonStrokingColorState) {
    if let Some(color_space) = &state.color_space {
        output.push(color_space.clone());
    }
    if let Some(color) = &state.color {
        output.push(color.clone());
    } else if state.color_space.is_none() {
        output.push(Operation::new("g", vec![Object::Real(0.0)]));
    }
}

fn rgb_operation(color: [u8; 3]) -> Operation {
    Operation::new(
        "rg",
        color
            .into_iter()
            .map(|channel| Object::Real(f32::from(channel) / 255.0))
            .collect(),
    )
}

fn background_operations(media_box: [f32; 4], color: [u8; 3]) -> Vec<Operation> {
    vec![
        Operation::new("q", Vec::new()),
        rgb_operation(color),
        Operation::new(
            "re",
            vec![
                Object::Real(media_box[0]),
                Object::Real(media_box[1]),
                Object::Real(media_box[2] - media_box[0]),
                Object::Real(media_box[3] - media_box[1]),
            ],
        ),
        Operation::new("f", Vec::new()),
        Operation::new("Q", Vec::new()),
    ]
}

fn inherited_page_box(
    document: &Document,
    mut object_id: ObjectId,
) -> Result<[f32; 4], ReplaceInvertError> {
    loop {
        let dictionary = document.get_dictionary(object_id)?;
        if let Ok(media_box) = dictionary.get(b"MediaBox") {
            let (_, media_box) = document.dereference(media_box)?;
            let values = media_box.as_array()?;
            if values.len() == 4 {
                return Ok([
                    object_number(&values[0])?,
                    object_number(&values[1])?,
                    object_number(&values[2])?,
                    object_number(&values[3])?,
                ]);
            }
        }
        object_id = dictionary.get(b"Parent")?.as_reference()?;
    }
}

#[allow(clippy::cast_precision_loss)]
fn object_number(object: &Object) -> Result<f32, ReplaceInvertError> {
    match object {
        Object::Integer(value) => Ok(*value as f32),
        Object::Real(value) => Ok(*value),
        _ => Err(lopdf::Error::ObjectType {
            expected: "Integer or Real",
            found: object.enum_variant(),
        }
        .into()),
    }
}

fn page_form_xobject_ids(
    document: &Document,
    page_id: ObjectId,
) -> Result<Vec<ObjectId>, ReplaceInvertError> {
    let (resources, resource_ids) = document.get_page_resources(page_id)?;
    let mut forms = HashSet::new();
    if let Some(resources) = resources {
        forms.extend(form_xobject_ids_from_resources(document, resources));
    }
    for resource_id in resource_ids {
        if let Ok(resources) = document.get_dictionary(resource_id) {
            forms.extend(form_xobject_ids_from_resources(document, resources));
        }
    }
    Ok(forms.into_iter().collect())
}

fn form_xobject_ids(
    document: &Document,
    form_id: ObjectId,
) -> Result<Vec<ObjectId>, ReplaceInvertError> {
    let form = document.get_object(form_id)?.as_stream()?;
    Ok(form
        .dict
        .get(b"Resources")
        .ok()
        .and_then(|resources| resource_dictionary(document, resources))
        .map_or_else(Vec::new, |resources| {
            form_xobject_ids_from_resources(document, resources)
        }))
}

fn form_xobject_ids_from_resources(document: &Document, resources: &Dictionary) -> Vec<ObjectId> {
    resources
        .get(b"XObject")
        .ok()
        .and_then(|xobjects| resource_dictionary(document, xobjects))
        .map(|xobjects| {
            xobjects
                .iter()
                .filter_map(|(_, object)| object.as_reference().ok())
                .filter(|object_id| is_form_xobject(document, *object_id))
                .collect()
        })
        .unwrap_or_default()
}

fn resource_dictionary<'a>(document: &'a Document, object: &'a Object) -> Option<&'a Dictionary> {
    match object {
        Object::Reference(object_id) => document.get_dictionary(*object_id).ok(),
        Object::Dictionary(dictionary) => Some(dictionary),
        _ => None,
    }
}

fn is_form_xobject(document: &Document, object_id: ObjectId) -> bool {
    document
        .get_object(object_id)
        .ok()
        .and_then(|object| object.as_stream().ok())
        .and_then(|stream| stream.dict.get(b"Subtype").ok())
        .is_some_and(|subtype| subtype.as_name().is_ok_and(|name| name == b"Form"))
}

fn decode_java_color(
    value: Option<&str>,
    field: &'static str,
) -> Result<[u8; 3], ReplaceInvertError> {
    let value = value
        .filter(|value| !value.is_empty())
        .ok_or(ReplaceInvertError::InvalidColor(field))?;
    let decoded = decode_java_integer(value).ok_or(ReplaceInvertError::InvalidColor(field))?;
    let bytes = u32::from_ne_bytes(decoded.to_ne_bytes()).to_be_bytes();
    Ok([bytes[1], bytes[2], bytes[3]])
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

fn invert_full_color(
    input_path: &Path,
    filename: &str,
    output_path: &Path,
) -> Result<(), ReplaceInvertError> {
    let render_dpi = configured_max_render_dpi();
    match try_invert_pdf_to_file(input_path, filename, render_dpi, output_path)? {
        PdfiumInvertAttempt::Inverted => Ok(()),
        PdfiumInvertAttempt::Unavailable {
            explicitly_configured,
            details,
        } => Err(ReplaceInvertError::PdfiumUnavailable {
            explicitly_configured,
            details,
        }),
    }
}

fn convert_color_space_cmyk(
    input_path: &Path,
    output_path: &Path,
) -> Result<(), ReplaceInvertError> {
    let commands = ghostscript_commands();
    let mut output_argument = OsString::from("-sOutputFile=");
    output_argument.push(output_path.as_os_str());
    let arguments = [
        OsString::from("-sDEVICE=pdfwrite"),
        OsString::from("-dCompatibilityLevel=1.5"),
        OsString::from("-dPDFSETTINGS=/prepress"),
        OsString::from("-dNOPAUSE"),
        OsString::from("-dQUIET"),
        OsString::from("-dBATCH"),
        OsString::from("-sProcessColorModel=DeviceCMYK"),
        OsString::from("-sColorConversionStrategy=CMYK"),
        OsString::from("-sColorConversionStrategyForImages=CMYK"),
        output_argument,
        input_path.as_os_str().to_owned(),
    ];
    for command in &commands.candidates {
        match Command::new(command).args(&arguments).output() {
            Ok(output) if output.status.success() => {
                if output_path
                    .metadata()
                    .is_ok_and(|metadata| metadata.len() > 0)
                {
                    return Ok(());
                }
                return Err(ReplaceInvertError::GhostscriptFailed {
                    command: command.clone(),
                    status: exit_status(output.status),
                    details: "Ghostscript produced no output".to_owned(),
                });
            }
            Ok(output) => {
                return Err(ReplaceInvertError::GhostscriptFailed {
                    command: command.clone(),
                    status: exit_status(output.status),
                    details: process_details(&output.stdout, &output.stderr),
                });
            }
            Err(source) if source.kind() == ErrorKind::NotFound => {}
            Err(source) => {
                return Err(ReplaceInvertError::GhostscriptStart {
                    command: command.clone(),
                    source,
                });
            }
        }
    }
    Err(ReplaceInvertError::GhostscriptUnavailable)
}

fn process_details(stdout: &[u8], stderr: &[u8]) -> String {
    let bytes = if stderr.is_empty() { stdout } else { stderr };
    let details = String::from_utf8_lossy(bytes);
    let mut characters = details.trim().chars();
    let result = characters.by_ref().take(2_048).collect::<String>();
    if characters.next().is_some() {
        format!("{result}…")
    } else if result.is_empty() {
        "no diagnostic output".to_owned()
    } else {
        result
    }
}

#[cfg(test)]
mod tests {
    use lopdf::{Object, content::Operation};

    use super::{
        HighContrastColorCombination, ReplaceAndInvert, ReplaceInvertError, decode_java_color,
        recolor_text_operations,
    };

    #[test]
    fn parses_every_known_option() {
        assert!(matches!(
            ReplaceAndInvert::parse("FULL_INVERSION"),
            Ok(ReplaceAndInvert::FullInversion)
        ));
        assert!(matches!(
            ReplaceAndInvert::parse(" COLOR_SPACE_CONVERSION "),
            Ok(ReplaceAndInvert::ColorSpaceConversion)
        ));
        assert!(matches!(
            ReplaceAndInvert::parse("HIGH_CONTRAST_COLOR"),
            Ok(ReplaceAndInvert::HighContrastColor)
        ));
        assert!(matches!(
            ReplaceAndInvert::parse("CUSTOM_COLOR"),
            Ok(ReplaceAndInvert::CustomColor)
        ));
    }

    #[test]
    fn rejects_unknown_option() {
        assert!(matches!(
            ReplaceAndInvert::parse("SEPIA"),
            Err(ReplaceInvertError::InvalidOption)
        ));
    }

    #[test]
    fn parses_high_contrast_presets_and_java_colors() {
        assert!(matches!(
            HighContrastColorCombination::parse("YELLOW_TEXT_ON_BLACK"),
            Ok(HighContrastColorCombination::YellowTextOnBlack)
        ));
        assert!(matches!(
            decode_java_color(Some("#12ABEF"), "textColor"),
            Ok([0x12, 0xAB, 0xEF])
        ));
        assert!(matches!(
            decode_java_color(Some("010"), "textColor"),
            Ok([0, 0, 8])
        ));
        assert!(matches!(
            decode_java_color(None, "textColor"),
            Err(ReplaceInvertError::InvalidColor("textColor"))
        ));
    }

    #[test]
    fn text_recoloring_restores_the_previous_non_stroking_color() {
        let original = Operation::new(
            "rg",
            vec![Object::Real(1.0), Object::Real(0.0), Object::Real(0.0)],
        );
        let mut operations = vec![
            original.clone(),
            Operation::new("Tj", vec![Object::string_literal("text")]),
            Operation::new("re", vec![0.into(), 0.into(), 10.into(), 10.into()]),
        ];
        recolor_text_operations(&mut operations, [0, 0, 255]);
        assert_eq!(
            operations
                .iter()
                .map(|operation| operation.operator.as_str())
                .collect::<Vec<_>>(),
            ["rg", "rg", "Tj", "rg", "re"]
        );
        assert_eq!(operations[3].operator, original.operator);
        assert_eq!(operations[3].operands, original.operands);
    }
}
