//! Scanner-effect image pipeline ported from `ScannerEffectController`.
//!
//! Pages are rasterized (in [`crate::pdfium_backend`]) and then run through this
//! pure pipeline: colorspace conversion, a random grey gradient border, a small
//! random rotation over that gradient, edge feathering, a box-blur approximation
//! of a Gaussian blur, and a combined brightness/contrast/yellowing/noise pass.
//! The output is deliberately non-deterministic, matching the Java behavior.
#![allow(
    clippy::cast_precision_loss,
    clippy::cast_possible_truncation,
    clippy::cast_sign_loss,
    clippy::cast_possible_wrap,
    clippy::many_single_char_names,
    clippy::similar_names,
    clippy::needless_range_loop
)]

use std::{f64::consts::PI, path::Path};

use image::RgbImage;
use rand::RngExt;
use thiserror::Error;

use crate::{
    pdf_flatten::configured_max_render_dpi,
    pdfium_backend::{PdfiumScannerAttempt, PdfiumScannerError, try_scanner_effect_to_file},
};

const MAX_IMAGE_WIDTH: i64 = 8192;
const MAX_IMAGE_HEIGHT: i64 = 8192;
const MAX_IMAGE_PIXELS: i64 = 16_777_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Quality {
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Rotation {
    None,
    Slight,
    Moderate,
    Severe,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Colorspace {
    Grayscale,
    Color,
}

impl Quality {
    /// # Errors
    /// Returns [`ScannerEffectError::InvalidQuality`] for unknown values.
    pub fn parse(value: &str) -> Result<Self, ScannerEffectError> {
        match value.trim() {
            "low" => Ok(Self::Low),
            "medium" => Ok(Self::Medium),
            "high" => Ok(Self::High),
            _ => Err(ScannerEffectError::InvalidQuality),
        }
    }
}

impl Rotation {
    /// # Errors
    /// Returns [`ScannerEffectError::InvalidRotation`] for unknown values.
    pub fn parse(value: &str) -> Result<Self, ScannerEffectError> {
        match value.trim() {
            "none" => Ok(Self::None),
            "slight" => Ok(Self::Slight),
            "moderate" => Ok(Self::Moderate),
            "severe" => Ok(Self::Severe),
            _ => Err(ScannerEffectError::InvalidRotation),
        }
    }

    const fn degrees(self) -> i32 {
        match self {
            Self::None => 0,
            Self::Slight => 2,
            Self::Moderate => 5,
            Self::Severe => 8,
        }
    }
}

impl Colorspace {
    /// # Errors
    /// Returns [`ScannerEffectError::InvalidColorspace`] for unknown values.
    pub fn parse(value: &str) -> Result<Self, ScannerEffectError> {
        match value.trim() {
            "grayscale" => Ok(Self::Grayscale),
            "color" => Ok(Self::Color),
            _ => Err(ScannerEffectError::InvalidColorspace),
        }
    }
}

/// Raw request values before quality presets are applied.
#[derive(Debug, Clone, Copy)]
pub struct ScannerEffectRequestValues {
    pub quality: Quality,
    pub rotation: Rotation,
    pub colorspace: Colorspace,
    pub border: i32,
    pub rotate: i32,
    pub rotate_variance: i32,
    pub brightness: f32,
    pub contrast: f32,
    pub blur: f32,
    pub noise: f32,
    pub yellowish: bool,
    pub resolution: i32,
    pub advanced_enabled: bool,
}

impl Default for ScannerEffectRequestValues {
    fn default() -> Self {
        Self {
            quality: Quality::High,
            rotation: Rotation::Slight,
            colorspace: Colorspace::Grayscale,
            border: 20,
            rotate: 0,
            rotate_variance: 2,
            brightness: 1.0,
            contrast: 1.0,
            blur: 1.0,
            noise: 8.0,
            yellowish: false,
            resolution: 300,
            advanced_enabled: false,
        }
    }
}

/// Resolved parameters used by the per-page pipeline.
#[derive(Debug, Clone, Copy)]
pub struct ScannerEffectParams {
    pub base_rotation: i32,
    pub rotate_variance: i32,
    pub border_px: u32,
    pub brightness: f32,
    pub contrast: f32,
    pub blur: f32,
    pub noise: f32,
    pub yellowish: bool,
    pub resolution: i32,
    pub grayscale: bool,
}

impl ScannerEffectParams {
    /// Applies the quality preset (unless advanced mode is on) and folds the
    /// rotation preset into the base rotation, mirroring the Java controller.
    #[must_use]
    pub fn resolve(values: &ScannerEffectRequestValues) -> Self {
        let mut brightness = values.brightness;
        let mut contrast = values.contrast;
        let mut blur = values.blur;
        let mut noise = values.noise;
        let mut resolution = values.resolution;
        if !values.advanced_enabled {
            match values.quality {
                Quality::High => {
                    blur = 0.10;
                    noise = 1.0;
                    brightness = 1.03;
                    contrast = 1.06;
                    resolution = 150;
                }
                Quality::Medium => {
                    blur = 0.10;
                    noise = 1.0;
                    brightness = 1.06;
                    contrast = 1.12;
                    resolution = 100;
                }
                Quality::Low => {
                    blur = 0.9;
                    noise = 2.5;
                    brightness = 1.08;
                    contrast = 1.15;
                    resolution = 75;
                }
            }
        }
        Self {
            base_rotation: values.rotation.degrees() + values.rotate,
            rotate_variance: values.rotate_variance,
            border_px: values.border.max(0) as u32,
            brightness,
            contrast,
            blur,
            noise,
            yellowish: values.yellowish,
            resolution,
            grayscale: matches!(values.colorspace, Colorspace::Grayscale),
        }
    }
}

#[derive(Debug, Error)]
pub enum ScannerEffectError {
    #[error("quality must be low, medium, or high")]
    InvalidQuality,
    #[error("rotation must be none, slight, moderate, or severe")]
    InvalidRotation,
    #[error("colorspace must be grayscale or color")]
    InvalidColorspace,
    #[error("DPI value {requested} exceeds maximum safe limit of {maximum}")]
    DpiExceedsLimit { requested: i32, maximum: i32 },
    #[error("PDFium is required to apply the scanner effect: {details}")]
    PdfiumUnavailable {
        explicitly_configured: bool,
        details: String,
    },
    #[error(transparent)]
    Pdfium(#[from] PdfiumScannerError),
}

/// A processed page image together with where to place it on the output page.
#[derive(Debug)]
pub struct ProcessedPage {
    pub image: RgbImage,
    pub offset_x: f32,
    pub offset_y: f32,
    pub draw_width: f32,
    pub draw_height: f32,
}

/// Applies the scanner effect to every page and writes the result.
///
/// # Errors
///
/// Returns [`ScannerEffectError`] when the requested DPI exceeds the safe limit,
/// `PDFium` is unavailable, or the document cannot be processed.
pub fn scanner_effect_to_file(
    input_path: &Path,
    filename: &str,
    params: &ScannerEffectParams,
    output_path: &Path,
) -> Result<(), ScannerEffectError> {
    let maximum = configured_max_render_dpi();
    if params.resolution > maximum {
        return Err(ScannerEffectError::DpiExceedsLimit {
            requested: params.resolution,
            maximum,
        });
    }
    match try_scanner_effect_to_file(input_path, filename, params, output_path)? {
        PdfiumScannerAttempt::Processed => Ok(()),
        PdfiumScannerAttempt::Unavailable {
            explicitly_configured,
            details,
        } => Err(ScannerEffectError::PdfiumUnavailable {
            explicitly_configured,
            details,
        }),
    }
}

/// Clamps a render DPI so the rasterized page stays within safe pixel bounds.
#[must_use]
pub fn calculate_safe_resolution(
    page_width_pts: f32,
    page_height_pts: f32,
    resolution: i32,
) -> i32 {
    let projected_width = (f64::from(page_width_pts) * f64::from(resolution) / 72.0).ceil() as i64;
    let projected_height =
        (f64::from(page_height_pts) * f64::from(resolution) / 72.0).ceil() as i64;
    let projected_pixels = projected_width.saturating_mul(projected_height);
    if projected_width <= MAX_IMAGE_WIDTH
        && projected_height <= MAX_IMAGE_HEIGHT
        && projected_pixels <= MAX_IMAGE_PIXELS
    {
        return resolution;
    }
    let width_scale = MAX_IMAGE_WIDTH as f64 / projected_width.max(1) as f64;
    let height_scale = MAX_IMAGE_HEIGHT as f64 / projected_height.max(1) as f64;
    let pixel_scale = (MAX_IMAGE_PIXELS as f64 / projected_pixels.max(1) as f64).sqrt();
    let min_scale = width_scale.min(height_scale).min(pixel_scale);
    72.max((f64::from(resolution) * min_scale) as i32)
}

/// Runs the full per-page effect pipeline on a rendered page image.
#[must_use]
pub fn process_page(
    image: RgbImage,
    page_width_pts: f32,
    page_height_pts: f32,
    params: &ScannerEffectParams,
) -> ProcessedPage {
    let mut rng = rand::rng();
    let base = if params.grayscale {
        to_grayscale(&image)
    } else {
        image
    };
    let gradient = random_gradient(&mut rng);
    let bordered = add_border_with_gradient(&base, params.border_px, gradient);
    let rotation = calculate_rotation(params.base_rotation, params.rotate_variance, &mut rng);
    let rotated = rotate_image(&bordered, rotation, gradient);

    let rot_w = rotated.width();
    let rot_h = rotated.height();
    let scale = (page_width_pts / rot_w as f32).max(page_height_pts / rot_h as f32);
    let draw_width = rot_w as f32 * scale;
    let draw_height = rot_h as f32 * scale;
    let offset_x = (page_width_pts - draw_width) / 2.0;
    let offset_y = (page_height_pts - draw_height) / 2.0;

    let feather = ((rot_w.min(rot_h) as f32 * 0.02).round() as i32).max(10) as u32;
    let softened = soften_edges(&rotated, feather, gradient);
    let blurred = gaussian_blur(&softened, params.blur);
    let adjusted = apply_all_effects(
        &blurred,
        params.brightness,
        params.contrast,
        params.yellowish,
        params.noise,
        &mut rng,
    );

    ProcessedPage {
        image: adjusted,
        offset_x,
        offset_y,
        draw_width,
        draw_height,
    }
}

#[derive(Debug, Clone, Copy)]
struct Gradient {
    vertical: bool,
    start: [u8; 3],
    end: [u8; 3],
}

fn image_from(width: u32, height: u32, buffer: Vec<u8>) -> RgbImage {
    RgbImage::from_raw(width, height, buffer).unwrap_or_else(|| RgbImage::new(width, height))
}

fn to_grayscale(image: &RgbImage) -> RgbImage {
    let mut buffer = image.as_raw().clone();
    for pixel in buffer.chunks_exact_mut(3) {
        let gray = ((u16::from(pixel[0]) + u16::from(pixel[1]) + u16::from(pixel[2])) / 3) as u8;
        pixel[0] = gray;
        pixel[1] = gray;
        pixel[2] = gray;
    }
    image_from(image.width(), image.height(), buffer)
}

fn random_gradient(rng: &mut impl RngExt) -> Gradient {
    let vertical = rng.random_bool(0.5);
    let start_grey = 0.6 + 0.3 * rng.random::<f32>();
    let end_grey = 0.6 + 0.3 * rng.random::<f32>();
    let start = (start_grey * 255.0).round() as u8;
    let end = (end_grey * 255.0).round() as u8;
    Gradient {
        vertical,
        start: [start, start, start],
        end: [end, end, end],
    }
}

fn gradient_lut(width: u32, height: u32, gradient: Gradient) -> Vec<[u8; 3]> {
    let size = if gradient.vertical { height } else { width }.max(1) as usize;
    let denom = (size - 1).max(1) as f32;
    let mut lut = Vec::with_capacity(size);
    for i in 0..size {
        let frac = i as f32 / denom;
        let mut channel = [0u8; 3];
        for c in 0..3 {
            let start = f32::from(gradient.start[c]);
            let diff = f32::from(gradient.end[c]) - start;
            channel[c] = (start + diff * frac).round().clamp(0.0, 255.0) as u8;
        }
        lut.push(channel);
    }
    lut
}

fn fill_with_gradient(buffer: &mut [u8], width: u32, height: u32, gradient: Gradient) {
    let lut = gradient_lut(width, height, gradient);
    let width = width as usize;
    for y in 0..height as usize {
        for x in 0..width {
            let color = if gradient.vertical { lut[y] } else { lut[x] };
            let index = (y * width + x) * 3;
            buffer[index] = color[0];
            buffer[index + 1] = color[1];
            buffer[index + 2] = color[2];
        }
    }
}

fn add_border_with_gradient(image: &RgbImage, border: u32, gradient: Gradient) -> RgbImage {
    let width = image.width() + 2 * border;
    let height = image.height() + 2 * border;
    let mut buffer = vec![0u8; width as usize * height as usize * 3];
    fill_with_gradient(&mut buffer, width, height, gradient);
    let src = image.as_raw();
    let src_width = image.width() as usize;
    let dst_width = width as usize;
    for y in 0..image.height() as usize {
        let src_row = y * src_width * 3;
        let dst_row = ((y + border as usize) * dst_width + border as usize) * 3;
        let count = src_width * 3;
        buffer[dst_row..dst_row + count].copy_from_slice(&src[src_row..src_row + count]);
    }
    image_from(width, height, buffer)
}

fn calculate_rotation(base_rotation: i32, rotate_variance: i32, rng: &mut impl RngExt) -> f64 {
    if base_rotation == 0 && rotate_variance == 0 {
        return 0.0;
    }
    f64::from(base_rotation) + (rng.random::<f64>() * 2.0 - 1.0) * f64::from(rotate_variance)
}

fn rotate_image(image: &RgbImage, rotation_deg: f64, gradient: Gradient) -> RgbImage {
    if rotation_deg == 0.0 {
        return image.clone();
    }
    let w = image.width();
    let h = image.height();
    let radians = rotation_deg.to_radians();
    let sin = radians.sin();
    let cos = radians.cos();
    let abs_sin = sin.abs();
    let abs_cos = cos.abs();
    let rot_w = (f64::from(w) * abs_cos + f64::from(h) * abs_sin)
        .floor()
        .max(1.0) as u32;
    let rot_h = (f64::from(h) * abs_cos + f64::from(w) * abs_sin)
        .floor()
        .max(1.0) as u32;

    let mut buffer = vec![0u8; rot_w as usize * rot_h as usize * 3];
    fill_with_gradient(&mut buffer, rot_w, rot_h, gradient);

    let src = image.as_raw();
    let src_width = w as usize;
    let tx = (f64::from(rot_w) - f64::from(w)) / 2.0;
    let ty = (f64::from(rot_h) - f64::from(h)) / 2.0;
    let cx = f64::from(w) / 2.0;
    let cy = f64::from(h) / 2.0;
    // Inverse of Java's translate-then-rotate transform: undo the translation,
    // then rotate the destination point about the source center by -radians.
    let inv_cos = cos;
    let inv_sin = sin;
    let dst_width = rot_w as usize;
    for dy in 0..rot_h as usize {
        for dx in 0..rot_w as usize {
            let qx = dx as f64 - tx - cx;
            let qy = dy as f64 - ty - cy;
            let sx = inv_cos * qx + inv_sin * qy + cx;
            let sy = -inv_sin * qx + inv_cos * qy + cy;
            if sx < 0.0 || sy < 0.0 || sx > f64::from(w - 1) || sy > f64::from(h - 1) {
                continue;
            }
            let color = bicubic_sample(src, src_width, w, h, sx, sy);
            let index = (dy * dst_width + dx) * 3;
            buffer[index] = color[0];
            buffer[index + 1] = color[1];
            buffer[index + 2] = color[2];
        }
    }
    image_from(rot_w, rot_h, buffer)
}

fn bicubic_sample(src: &[u8], src_width: usize, w: u32, h: u32, sx: f64, sy: f64) -> [u8; 3] {
    let base_x = sx.floor() as i64;
    let base_y = sy.floor() as i64;
    let x_weight = sx - base_x as f64;
    let y_weight = sy - base_y as f64;
    let mut result = [0u8; 3];
    for (channel, output) in result.iter_mut().enumerate() {
        let mut rows = [0.0; 4];
        for (row_offset, row) in rows.iter_mut().enumerate() {
            let y = (base_y + row_offset as i64 - 1).clamp(0, i64::from(h) - 1) as usize;
            let mut samples = [0.0; 4];
            for (column_offset, sample) in samples.iter_mut().enumerate() {
                let x = (base_x + column_offset as i64 - 1).clamp(0, i64::from(w) - 1) as usize;
                *sample = f64::from(src[(y * src_width + x) * 3 + channel]);
            }
            *row = cubic_blend(samples, x_weight);
        }
        *output = cubic_blend(rows, y_weight).round().clamp(0.0, 255.0) as u8;
    }
    result
}

fn cubic_blend(samples: [f64; 4], weight: f64) -> f64 {
    let [p0, p1, p2, p3] = samples;
    p1 + 0.5
        * weight
        * (p2 - p0
            + weight * (2.0 * p0 - 5.0 * p1 + 4.0 * p2 - p3 + weight * (3.0 * (p1 - p2) + p3 - p0)))
}

fn soften_edges(image: &RgbImage, feather: u32, gradient: Gradient) -> RgbImage {
    let width = image.width();
    let height = image.height();
    let lut = gradient_lut(width, height, gradient);
    let src = image.as_raw();
    let mut buffer = vec![0u8; width as usize * height as usize * 3];
    let w = width as usize;
    let h = height as usize;
    let feather = feather.max(1) as f32;
    for y in 0..h {
        for x in 0..w {
            let dx = x.min(w - 1 - x);
            let dy = y.min(h - 1 - y);
            let d = dx.min(dy) as f32;
            let alpha = if d < feather { d / feather } else { 1.0 };
            let bg = if gradient.vertical { lut[y] } else { lut[x] };
            let index = (y * w + x) * 3;
            for c in 0..3 {
                let fg = f32::from(src[index + c]);
                let value = fg * alpha + f32::from(bg[c]) * (1.0 - alpha);
                buffer[index + c] = value.round().clamp(0.0, 255.0) as u8;
            }
        }
    }
    image_from(width, height, buffer)
}

fn gaussian_blur(image: &RgbImage, sigma: f32) -> RgbImage {
    if sigma <= 0.0 {
        return image.clone();
    }
    let width = image.width();
    let height = image.height();
    let scaled_sigma = f64::from(sigma) * f64::from(width.min(height)) / 1000.0;
    let radius = 1.max((scaled_sigma * 2.0).ceil() as i32);
    let mut temp = image.as_raw().clone();
    let mut dst = vec![0u8; temp.len()];
    for _ in 0..2 {
        box_blur_horizontal(&temp, &mut dst, width, height, radius);
        box_blur_vertical(&dst, &mut temp, width, height, radius);
    }
    image_from(width, height, temp)
}

fn box_blur_horizontal(src: &[u8], dst: &mut [u8], width: u32, height: u32, radius: i32) {
    let width = width as i32;
    let diameter = radius * 2 + 1;
    let inv = 1.0 / diameter as f32;
    for y in 0..height as i32 {
        let row = (y * width) as usize * 3;
        let mut sum = [0i32; 3];
        for x in -radius..=radius {
            let px = x.clamp(0, width - 1) as usize;
            for c in 0..3 {
                sum[c] += i32::from(src[row + px * 3 + c]);
            }
        }
        for x in 0..width {
            let index = row + x as usize * 3;
            for c in 0..3 {
                dst[index + c] = (sum[c] as f32 * inv) as u8;
            }
            let left = (x - radius).clamp(0, width - 1) as usize;
            let right = (x + radius + 1).clamp(0, width - 1) as usize;
            for c in 0..3 {
                sum[c] += i32::from(src[row + right * 3 + c]) - i32::from(src[row + left * 3 + c]);
            }
        }
    }
}

fn box_blur_vertical(src: &[u8], dst: &mut [u8], width: u32, height: u32, radius: i32) {
    let height_i = height as i32;
    let diameter = radius * 2 + 1;
    let inv = 1.0 / diameter as f32;
    let w = width as usize;
    for x in 0..w {
        let mut sum = [0i32; 3];
        for y in -radius..=radius {
            let py = y.clamp(0, height_i - 1) as usize;
            for c in 0..3 {
                sum[c] += i32::from(src[(py * w + x) * 3 + c]);
            }
        }
        for y in 0..height_i {
            let index = (y as usize * w + x) * 3;
            for c in 0..3 {
                dst[index + c] = (sum[c] as f32 * inv) as u8;
            }
            let top = (y - radius).clamp(0, height_i - 1) as usize;
            let bottom = (y + radius + 1).clamp(0, height_i - 1) as usize;
            for c in 0..3 {
                sum[c] += i32::from(src[(bottom * w + x) * 3 + c])
                    - i32::from(src[(top * w + x) * 3 + c]);
            }
        }
    }
}

fn apply_all_effects(
    image: &RgbImage,
    brightness: f32,
    contrast: f32,
    yellowish: bool,
    noise: f32,
    rng: &mut impl RngExt,
) -> RgbImage {
    let width = image.width();
    let height = image.height();
    let src = image.as_raw();
    let mut buffer = vec![0u8; src.len()];
    let scaled_strength = f64::from(noise) * f64::from(width.min(height)) / 1000.0;
    let apply_noise = scaled_strength > 0.0;
    let contrast_offset = 128.0 - 128.0 * contrast;
    let inv765 = 1.0 / 765.0;
    for i in (0..src.len()).step_by(3) {
        let mut r = ((f32::from(src[i]) * contrast + contrast_offset) * brightness) as i32;
        let mut g = ((f32::from(src[i + 1]) * contrast + contrast_offset) * brightness) as i32;
        let mut b = ((f32::from(src[i + 2]) * contrast + contrast_offset) * brightness) as i32;
        r = r.clamp(0, 255);
        g = g.clamp(0, 255);
        b = b.clamp(0, 255);
        if yellowish {
            let bright = (r + g + b) as f32 * inv765;
            r = (r as f32 + (255.0 - r as f32) * 0.18 * bright).min(255.0) as i32;
            g = (g as f32 + (255.0 - g as f32) * 0.12 * bright).min(255.0) as i32;
            b = (b as f32 * (1.0 - 0.25 * bright)).max(0.0) as i32;
        }
        if apply_noise {
            r = (r + (next_gaussian(rng) * scaled_strength) as i32).clamp(0, 255);
            g = (g + (next_gaussian(rng) * scaled_strength) as i32).clamp(0, 255);
            b = (b + (next_gaussian(rng) * scaled_strength) as i32).clamp(0, 255);
        }
        buffer[i] = r as u8;
        buffer[i + 1] = g as u8;
        buffer[i + 2] = b as u8;
    }
    image_from(width, height, buffer)
}

fn next_gaussian(rng: &mut impl RngExt) -> f64 {
    let u1 = rng.random::<f64>().max(1e-12);
    let u2 = rng.random::<f64>();
    (-2.0 * u1.ln()).sqrt() * (2.0 * PI * u2).cos()
}

#[cfg(test)]
mod tests {
    use super::{
        Colorspace, Quality, Rotation, ScannerEffectParams, ScannerEffectRequestValues,
        bicubic_sample, calculate_safe_resolution,
    };

    #[test]
    fn high_quality_preset_overrides_when_not_advanced() {
        let values = ScannerEffectRequestValues::default();
        let params = ScannerEffectParams::resolve(&values);
        assert_eq!(params.resolution, 150);
        assert!((params.brightness - 1.03).abs() < 1e-6);
        assert!((params.blur - 0.10).abs() < 1e-6);
        // rotation preset "slight" (2) folds into base rotation.
        assert_eq!(params.base_rotation, 2);
        assert!(params.grayscale);
    }

    #[test]
    fn advanced_mode_keeps_request_values() {
        let values = ScannerEffectRequestValues {
            advanced_enabled: true,
            resolution: 220,
            brightness: 1.5,
            rotation: Rotation::None,
            rotate: 3,
            colorspace: Colorspace::Color,
            ..ScannerEffectRequestValues::default()
        };
        let params = ScannerEffectParams::resolve(&values);
        assert_eq!(params.resolution, 220);
        assert!((params.brightness - 1.5).abs() < 1e-6);
        assert_eq!(params.base_rotation, 3);
        assert!(!params.grayscale);
    }

    #[test]
    fn quality_parses_and_rejects() {
        assert!(matches!(Quality::parse("low"), Ok(Quality::Low)));
        assert!(Quality::parse("ultra").is_err());
    }

    #[test]
    fn safe_resolution_passes_small_pages_through() {
        assert_eq!(calculate_safe_resolution(595.0, 842.0, 150), 150);
    }

    #[test]
    fn safe_resolution_clamps_oversized_renders() {
        let clamped = calculate_safe_resolution(2000.0, 2000.0, 1200);
        assert!(clamped < 1200);
        assert!(clamped >= 72);
    }

    #[test]
    fn bicubic_rotation_sampling_uses_the_four_by_four_neighbourhood() {
        let mut source = vec![10_u8; 5 * 5 * 3];
        for channel in 0..3 {
            source[(2 * 5 + 4) * 3 + channel] = 255;
        }

        assert_eq!(bicubic_sample(&source, 5, 5, 5, 2.0, 2.0), [10; 3]);
        assert_eq!(bicubic_sample(&source, 5, 5, 5, 2.5, 2.0), [0; 3]);
    }
}
