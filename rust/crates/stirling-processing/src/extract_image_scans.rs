use std::{
    fs::{self, File},
    io::{self, Read},
    path::{Path, PathBuf},
};

use image::{GrayImage, ImageFormat, ImageReader, Luma, Rgb, RgbImage, imageops};
use imageproc::{
    contours::{BorderType, Contour, find_contours},
    distance_transform::Norm,
    edges::canny,
    geometric_transformations::{Interpolation, warp_into_with},
    hough::{LineDetectionOptions, detect_lines},
    morphology::dilate,
};
use tempfile::tempdir;
use thiserror::Error;
use zip::{CompressionMethod, ZipArchive, ZipWriter, write::SimpleFileOptions};

use crate::{
    pdf_flatten::configured_max_render_dpi,
    pdf_to_image::{PdfToImageError, PdfToImageOptions, PdfToImageOutput, convert_pdf_to_images},
};

const MAX_OUTPUT_FILES: usize = 100_000;
const MAX_OUTPUT_BYTES: u64 = 2_000 * 1024 * 1024;
const EFFECTIVE_MIN_AREA: u64 = 10_000;
const EFFECTIVE_MIN_CONTOUR_AREA: f64 = 500.0;
const DILATION_RADIUS: u8 = 2;
const HOUGH_VOTE_THRESHOLD: u32 = 200;
const REPLICATED_ROTATION_PADDING: u32 = 3;
const REPLICATED_ROTATION_PADDING_F32: f32 = 3.0;

#[derive(Debug, Clone, Copy)]
pub struct ExtractImageScansOptions {
    pub angle_threshold: i32,
    pub tolerance: i32,
    pub min_area: i32,
    pub min_contour_area: i32,
    pub border_size: i32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExtractImageScansOutput {
    Png,
    Zip,
}

#[derive(Debug, Error)]
pub enum ExtractImageScansError {
    #[error(transparent)]
    PdfToImage(#[from] PdfToImageError),
    #[error("could not read or write image-scan conversion data: {0}")]
    Io(#[from] io::Error),
    #[error("could not read rendered PDF image archive: {0}")]
    Zip(#[from] zip::result::ZipError),
    #[error("could not decode or encode image-scan data: {0}")]
    Image(#[from] image::ImageError),
    #[error("image-scan extraction received an invalid border size: {0}")]
    InvalidBorderSize(i32),
    #[error("image-scan dimensions are too large to process safely")]
    InvalidDimensions,
    #[error("image-scan extraction produced an unsafe symbolic link")]
    UnsafeOutput,
    #[error("image-scan extraction produced more than {MAX_OUTPUT_FILES} images")]
    TooManyOutputs,
    #[error("image-scan extraction output exceeds the {MAX_OUTPUT_BYTES}-byte safety limit")]
    OutputTooLarge,
    #[error("no images were detected")]
    NoImages,
}

/// Extracts one or more photograph scans from a PDF or raster upload with the native Rust image
/// pipeline. PDF pages are rendered with the configured global maximum DPI first.
///
/// # Errors
///
/// Returns [`ExtractImageScansError`] for unavailable `PDFium` runtimes, invalid image data, unsafe
/// output paths, image limits, or a request with no detected images.
pub fn extract_image_scans_file(
    input_path: &Path,
    filename: &str,
    options: ExtractImageScansOptions,
    output_path: &Path,
) -> Result<ExtractImageScansOutput, ExtractImageScansError> {
    let directory = tempdir()?;
    let inputs = prepare_inputs(input_path, filename, directory.path())?;
    let mut outputs = Vec::new();
    for (index, input) in inputs.iter().enumerate() {
        let output_directory = directory.path().join(format!("output-{index}"));
        fs::create_dir(&output_directory)?;
        split_photos(input, &output_directory, options)?;
        collect_output_files(&output_directory, &mut outputs)?;
    }
    outputs.sort();
    if outputs.is_empty() {
        return Err(ExtractImageScansError::NoImages);
    }
    if outputs.len() == 1 {
        fs::copy(&outputs[0], output_path)?;
        return Ok(ExtractImageScansOutput::Png);
    }
    write_output_zip(&outputs, filename, output_path)?;
    Ok(ExtractImageScansOutput::Zip)
}

fn prepare_inputs(
    input_path: &Path,
    filename: &str,
    directory: &Path,
) -> Result<Vec<PathBuf>, ExtractImageScansError> {
    if has_pdf_extension(filename) {
        let rendered = directory.join("rendered-pages.zip");
        let options = PdfToImageOptions {
            image_format: "png".to_owned(),
            single_or_multiple: "multiple".to_owned(),
            color_type: "color".to_owned(),
            dpi: configured_max_render_dpi(),
            page_numbers: "all".to_owned(),
            include_annotations: true,
        };
        if convert_pdf_to_images(input_path, filename, &options, &rendered)?
            != PdfToImageOutput::Multiple
        {
            return Err(ExtractImageScansError::NoImages);
        }
        extract_rendered_pages(&rendered, directory)
    } else {
        let extension = Path::new(filename)
            .extension()
            .and_then(|value| value.to_str())
            .filter(|value| !value.is_empty())
            .unwrap_or("img");
        let copied = directory.join(format!("source.{extension}"));
        fs::copy(input_path, &copied)?;
        Ok(vec![copied])
    }
}

fn extract_rendered_pages(
    archive_path: &Path,
    directory: &Path,
) -> Result<Vec<PathBuf>, ExtractImageScansError> {
    let mut archive = ZipArchive::new(File::open(archive_path)?)?;
    let mut pages = Vec::new();
    let mut total_bytes = 0_u64;
    for index in 0..archive.len() {
        if pages.len() >= MAX_OUTPUT_FILES {
            return Err(ExtractImageScansError::TooManyOutputs);
        }
        let entry = archive.by_index(index)?;
        let Some(name) = entry.enclosed_name() else {
            return Err(ExtractImageScansError::UnsafeOutput);
        };
        if entry.is_dir() || !has_png_extension(&name) {
            continue;
        }
        total_bytes = total_bytes.saturating_add(entry.size());
        if total_bytes > MAX_OUTPUT_BYTES {
            return Err(ExtractImageScansError::OutputTooLarge);
        }
        let page = directory.join(format!("page-{index:05}.png"));
        let mut output = File::create(&page)?;
        io::copy(&mut entry.take(MAX_OUTPUT_BYTES + 1), &mut output)?;
        pages.push(page);
    }
    if pages.is_empty() {
        return Err(ExtractImageScansError::NoImages);
    }
    Ok(pages)
}

fn split_photos(
    input_path: &Path,
    output_directory: &Path,
    options: ExtractImageScansOptions,
) -> Result<(), ExtractImageScansError> {
    if options.border_size < 0 {
        return Err(ExtractImageScansError::InvalidBorderSize(
            options.border_size,
        ));
    }
    let image = ImageReader::open(input_path)?
        .with_guessed_format()?
        .decode()?;
    let image = image.to_rgb8();
    if image.width() == 0 || image.height() == 0 {
        return Err(ExtractImageScansError::InvalidDimensions);
    }
    let background = estimate_background_color(&image);
    let border_size = u32::try_from(options.border_size)
        .map_err(|_| ExtractImageScansError::InvalidBorderSize(options.border_size))?;
    let image = add_constant_border(&image, background, border_size)?;

    // The legacy script accepts these two values but accidentally omits them when it calls
    // find_photo_boundaries(). Preserve its observable default thresholds until the API contract
    // intentionally changes.
    let _ = (options.min_area, options.min_contour_area);
    let boundaries = find_photo_boundaries(&image, background, options.tolerance);
    let input_base = input_path
        .file_stem()
        .and_then(|value| value.to_str())
        .unwrap_or("source");
    for (index, boundary) in boundaries.into_iter().enumerate() {
        if index >= MAX_OUTPUT_FILES {
            return Err(ExtractImageScansError::TooManyOutputs);
        }
        let cropped = imageops::crop_imm(
            &image,
            boundary.x,
            boundary.y,
            boundary.width,
            boundary.height,
        )
        .to_image();
        let rotated = auto_rotate(&cropped, options.angle_threshold)?;
        let Some(cropped) = remove_added_border(rotated, border_size) else {
            continue;
        };
        let output_path = output_directory.join(format!("{input_base}_{}.png", index + 1));
        cropped.save_with_format(output_path, ImageFormat::Png)?;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct PhotoBoundary {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
}

fn estimate_background_color(image: &RgbImage) -> [u8; 3] {
    let width = image.width();
    let height = image.height();
    let points = [
        (0, 0),
        (width - 1, 0),
        (width - 1, height - 1),
        (0, height - 1),
        (width / 2, height / 2),
    ];
    std::array::from_fn(|channel| {
        let mut values = points.map(|(x, y)| image.get_pixel(x, y)[channel]);
        values.sort_unstable();
        values[values.len() / 2]
    })
}

fn add_constant_border(
    image: &RgbImage,
    background: [u8; 3],
    border_size: u32,
) -> Result<RgbImage, ExtractImageScansError> {
    if border_size == 0 {
        return Ok(image.clone());
    }
    let border_diameter = border_size
        .checked_mul(2)
        .ok_or(ExtractImageScansError::InvalidDimensions)?;
    let width = image
        .width()
        .checked_add(border_diameter)
        .ok_or(ExtractImageScansError::InvalidDimensions)?;
    let height = image
        .height()
        .checked_add(border_diameter)
        .ok_or(ExtractImageScansError::InvalidDimensions)?;
    let mut bordered = RgbImage::from_pixel(width, height, Rgb(background));
    imageops::replace(
        &mut bordered,
        image,
        i64::from(border_size),
        i64::from(border_size),
    );
    Ok(bordered)
}

fn find_photo_boundaries(
    image: &RgbImage,
    background: [u8; 3],
    tolerance: i32,
) -> Vec<PhotoBoundary> {
    let mask = GrayImage::from_fn(image.width(), image.height(), |x, y| {
        let pixel = image.get_pixel(x, y);
        let is_background = pixel.0.iter().zip(background).all(|(channel, expected)| {
            let channel = i64::from(*channel);
            let expected = i64::from(expected);
            let tolerance = i64::from(tolerance);
            channel >= expected - tolerance && channel <= expected + tolerance
        });
        Luma([if is_background { 0 } else { 255 }])
    });
    let dilated = dilate(&mask, Norm::LInf, DILATION_RADIUS);
    let dilated = dilate(&dilated, Norm::LInf, DILATION_RADIUS);
    find_contours::<u32>(&dilated)
        .into_iter()
        .filter(|contour| contour.border_type == BorderType::Outer && contour.parent.is_none())
        .filter_map(|contour| {
            let boundary = boundary_from_contour(&contour)?;
            let bounding_area = u64::from(boundary.width) * u64::from(boundary.height);
            (bounding_area >= EFFECTIVE_MIN_AREA
                && contour_area(&contour) >= EFFECTIVE_MIN_CONTOUR_AREA)
                .then_some(boundary)
        })
        .collect()
}

fn boundary_from_contour(contour: &Contour<u32>) -> Option<PhotoBoundary> {
    let first = contour.points.first()?;
    let (mut min_x, mut max_x) = (first.x, first.x);
    let (mut min_y, mut max_y) = (first.y, first.y);
    for point in &contour.points[1..] {
        min_x = min_x.min(point.x);
        max_x = max_x.max(point.x);
        min_y = min_y.min(point.y);
        max_y = max_y.max(point.y);
    }
    Some(PhotoBoundary {
        x: min_x,
        y: min_y,
        width: max_x - min_x + 1,
        height: max_y - min_y + 1,
    })
}

fn contour_area(contour: &Contour<u32>) -> f64 {
    if contour.points.len() < 3 {
        return 0.0;
    }
    contour
        .points
        .iter()
        .zip(contour.points.iter().cycle().skip(1))
        .take(contour.points.len())
        .fold(0.0, |area, (current, next)| {
            area + f64::from(current.x) * f64::from(next.y)
                - f64::from(next.x) * f64::from(current.y)
        })
        .abs()
        / 2.0
}

fn auto_rotate(image: &RgbImage, angle_threshold: i32) -> Result<RgbImage, ExtractImageScansError> {
    let Some(angle) = estimate_rotation_angle(image)? else {
        return Ok(image.clone());
    };
    if f64::from(angle.abs()) < f64::from(angle_threshold) {
        return Ok(image.clone());
    }
    rotate_with_replicated_border(image, angle)
}

fn estimate_rotation_angle(image: &RgbImage) -> Result<Option<f32>, ExtractImageScansError> {
    image
        .width()
        .checked_mul(image.width())
        .and_then(|width| {
            image
                .height()
                .checked_mul(image.height())
                .and_then(|height| width.checked_add(height))
        })
        .ok_or(ExtractImageScansError::InvalidDimensions)?;
    let gray = imageops::grayscale(image);
    let edges = canny(&gray, 50.0, 150.0);
    let lines = detect_lines(
        &edges,
        LineDetectionOptions {
            vote_threshold: HOUGH_VOTE_THRESHOLD,
            suppression_radius: 1,
        },
    );
    if lines.is_empty() {
        return Ok(None);
    }
    let mut angles = lines
        .into_iter()
        .filter_map(|line| u16::try_from(line.angle_in_degrees).ok())
        .map(|angle| f32::from(angle) - 90.0)
        .collect::<Vec<_>>();
    if angles.is_empty() {
        return Ok(None);
    }
    angles.sort_by(f32::total_cmp);
    let midpoint = angles.len() / 2;
    let median = if angles.len().is_multiple_of(2) {
        f32::midpoint(angles[midpoint - 1], angles[midpoint])
    } else {
        angles[midpoint]
    };
    Ok(Some(median))
}

fn rotate_with_replicated_border(
    image: &RgbImage,
    angle_degrees: f32,
) -> Result<RgbImage, ExtractImageScansError> {
    let padded = add_replicated_border(image, REPLICATED_ROTATION_PADDING);
    let width = image.width();
    let height = image.height();
    let center_x =
        f32::from(u16::try_from(width / 2).map_err(|_| ExtractImageScansError::InvalidDimensions)?);
    let center_y = f32::from(
        u16::try_from(height / 2).map_err(|_| ExtractImageScansError::InvalidDimensions)?,
    );
    let (sin, cos) = angle_degrees.to_radians().sin_cos();
    let max_x = f32::from(
        u16::try_from(width.saturating_sub(1))
            .map_err(|_| ExtractImageScansError::InvalidDimensions)?,
    );
    let max_y = f32::from(
        u16::try_from(height.saturating_sub(1))
            .map_err(|_| ExtractImageScansError::InvalidDimensions)?,
    );
    let mapping = move |x: f32, y: f32| {
        let translated_x = x - center_x;
        let translated_y = y - center_y;
        let source_x = (cos * translated_x - sin * translated_y + center_x).clamp(0.0, max_x);
        let source_y = (sin * translated_x + cos * translated_y + center_y).clamp(0.0, max_y);
        (
            source_x + REPLICATED_ROTATION_PADDING_F32,
            source_y + REPLICATED_ROTATION_PADDING_F32,
        )
    };
    let mut rotated = RgbImage::new(width, height);
    warp_into_with(
        &padded,
        mapping,
        Interpolation::Bicubic,
        Rgb([0, 0, 0]),
        &mut rotated,
    );
    Ok(rotated)
}

fn add_replicated_border(image: &RgbImage, padding: u32) -> RgbImage {
    let width = image.width() + 2 * padding;
    let height = image.height() + 2 * padding;
    RgbImage::from_fn(width, height, |x, y| {
        let source_x = x.saturating_sub(padding).min(image.width() - 1);
        let source_y = y.saturating_sub(padding).min(image.height() - 1);
        *image.get_pixel(source_x, source_y)
    })
}

fn remove_added_border(image: RgbImage, border_size: u32) -> Option<RgbImage> {
    if image.width() == 0 || image.height() == 0 {
        return None;
    }
    let border_diameter = border_size.saturating_mul(2);
    if border_size == 0 || image.width() <= border_diameter || image.height() <= border_diameter {
        return Some(image);
    }
    Some(
        imageops::crop_imm(
            &image,
            border_size,
            border_size,
            image.width() - border_diameter,
            image.height() - border_diameter,
        )
        .to_image(),
    )
}

fn collect_output_files(
    directory: &Path,
    outputs: &mut Vec<PathBuf>,
) -> Result<(), ExtractImageScansError> {
    let mut total_bytes = outputs.iter().try_fold(0_u64, |total, path| {
        fs::metadata(path).map(|metadata| total.saturating_add(metadata.len()))
    })?;
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        let file_type = entry.file_type()?;
        if file_type.is_symlink() {
            return Err(ExtractImageScansError::UnsafeOutput);
        }
        if !file_type.is_file() {
            continue;
        }
        if outputs.len() >= MAX_OUTPUT_FILES {
            return Err(ExtractImageScansError::TooManyOutputs);
        }
        let size = entry.metadata()?.len();
        total_bytes = total_bytes.saturating_add(size);
        if total_bytes > MAX_OUTPUT_BYTES {
            return Err(ExtractImageScansError::OutputTooLarge);
        }
        outputs.push(entry.path());
    }
    Ok(())
}

fn write_output_zip(
    outputs: &[PathBuf],
    filename: &str,
    output_path: &Path,
) -> Result<(), ExtractImageScansError> {
    let output = File::create(output_path)?;
    let mut archive = ZipWriter::new(output);
    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
    for (index, image) in outputs.iter().enumerate() {
        archive.start_file(
            format!("{}_processed_{}.png", output_base(filename), index + 1),
            options,
        )?;
        let mut source = File::open(image)?;
        io::copy(&mut source, &mut archive)?;
    }
    archive.finish()?;
    Ok(())
}

fn has_pdf_extension(filename: &str) -> bool {
    Path::new(filename)
        .extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("pdf"))
}

fn has_png_extension(path: &Path) -> bool {
    path.extension()
        .and_then(|value| value.to_str())
        .is_some_and(|value| value.eq_ignore_ascii_case("png"))
}

fn output_base(filename: &str) -> &str {
    filename.rsplit_once('.').map_or(filename, |(base, _)| base)
}

#[cfg(test)]
mod tests {
    use image::{Rgb, RgbImage};
    use imageproc::drawing::draw_line_segment_mut;

    use super::{
        PhotoBoundary, estimate_background_color, estimate_rotation_angle, find_photo_boundaries,
        output_base, remove_added_border, rotate_with_replicated_border,
    };

    #[test]
    fn preserves_generated_filename_base() {
        assert_eq!(output_base("scan.pdf"), "scan");
        assert_eq!(output_base("scan"), "scan");
    }

    #[test]
    fn estimates_background_from_the_channel_median_of_five_points() {
        let mut image = RgbImage::from_pixel(5, 5, Rgb([1, 2, 3]));
        image.put_pixel(0, 0, Rgb([10, 200, 90]));
        image.put_pixel(4, 0, Rgb([30, 40, 100]));
        image.put_pixel(4, 4, Rgb([250, 30, 110]));
        image.put_pixel(0, 4, Rgb([200, 20, 120]));
        image.put_pixel(2, 2, Rgb([30, 10, 130]));

        assert_eq!(estimate_background_color(&image), [30, 30, 110]);
    }

    #[test]
    fn detects_external_regions_after_two_five_by_five_dilations() {
        let mut image = RgbImage::from_pixel(260, 160, Rgb([245, 245, 245]));
        fill_rectangle(&mut image, 20, 30, 100, 100, Rgb([30, 60, 90]));
        fill_rectangle(&mut image, 140, 30, 100, 100, Rgb([90, 60, 30]));

        let mut boundaries = find_photo_boundaries(&image, [245, 245, 245], 20);
        boundaries.sort_by_key(|boundary| boundary.x);

        assert_eq!(
            boundaries,
            [
                PhotoBoundary {
                    x: 16,
                    y: 26,
                    width: 108,
                    height: 108,
                },
                PhotoBoundary {
                    x: 136,
                    y: 26,
                    width: 108,
                    height: 108,
                },
            ]
        );
    }

    #[test]
    fn preserves_the_scripts_effective_default_minimum_area() {
        let mut image = RgbImage::from_pixel(180, 140, Rgb([255, 255, 255]));
        fill_rectangle(&mut image, 20, 20, 90, 90, Rgb([0, 0, 0]));

        assert!(find_photo_boundaries(&image, [255, 255, 255], 20).is_empty());
    }

    #[test]
    fn estimates_hough_median_angle_and_rotates_with_fixed_dimensions()
    -> Result<(), Box<dyn std::error::Error>> {
        let mut image = RgbImage::from_pixel(320, 240, Rgb([255, 255, 255]));
        for offset in 0_u8..6 {
            draw_line_segment_mut(
                &mut image,
                (20.0, 60.0 + f32::from(offset)),
                (300.0, 110.0 + f32::from(offset)),
                Rgb([0, 0, 0]),
            );
        }

        let angle = estimate_rotation_angle(&image)?.ok_or_else(|| {
            std::io::Error::other("the long synthetic line did not pass the Hough vote threshold")
        })?;
        assert!((8.0..=12.0).contains(&angle), "detected angle was {angle}");

        let rotated = rotate_with_replicated_border(&image, angle)?;
        assert_eq!(rotated.dimensions(), image.dimensions());
        assert_ne!(rotated, image);
        Ok(())
    }

    #[test]
    fn removes_a_border_only_when_the_result_stays_nonempty() {
        let image = RgbImage::from_pixel(20, 16, Rgb([20, 30, 40]));
        assert_eq!(
            remove_added_border(image.clone(), 3).map(|cropped| cropped.dimensions()),
            Some((14, 10))
        );
        assert_eq!(
            remove_added_border(image, 8).map(|cropped| cropped.dimensions()),
            Some((20, 16))
        );
    }

    fn fill_rectangle(
        image: &mut RgbImage,
        x: u32,
        y: u32,
        width: u32,
        height: u32,
        color: Rgb<u8>,
    ) {
        for pixel_y in y..y + height {
            for pixel_x in x..x + width {
                image.put_pixel(pixel_x, pixel_y, color);
            }
        }
    }
}
