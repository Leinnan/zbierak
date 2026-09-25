//! Avatar image normalization.
//!
//! Uploaded avatars are decoded from a small allowlist of formats, validated
//! against size limits, center-cropped to a square, resized, and re-encoded as
//! PNG. Re-encoding drops metadata and guarantees stored and served bytes are
//! a canonical image, so no untrusted container format (notably SVG) ever
//! reaches a browser.

use std::io::Cursor;

use image::{GenericImageView, ImageFormat};

use crate::AppError;

/// Largest upload accepted before decoding, in bytes.
pub const MAX_UPLOAD_BYTES: usize = 2 * 1024 * 1024;

/// Smallest accepted source edge, in pixels; smaller sources would blur badly.
pub const MIN_SOURCE_EDGE: u32 = 16;

/// Edge length of the stored, square avatar, in pixels.
pub const AVATAR_SIZE: u32 = 256;

/// Decodes an uploaded image and returns canonical PNG bytes.
///
/// The format is detected from magic bytes, not the filename or the request's
/// declared content type, and only PNG, JPEG, and WebP are accepted. The image
/// is center-cropped to a square and scaled to [`AVATAR_SIZE`].
///
/// # Errors
///
/// Returns [`AppError::BadRequest`] when the upload is empty, exceeds
/// [`MAX_UPLOAD_BYTES`], is not PNG/JPEG/WebP, is smaller than
/// [`MIN_SOURCE_EDGE`] on either edge, or cannot be decoded or encoded.
pub fn normalize_upload(upload: &[u8]) -> Result<Vec<u8>, AppError> {
    if upload.is_empty() {
        return Err(AppError::BadRequest("avatar image is empty".into()));
    }
    if upload.len() > MAX_UPLOAD_BYTES {
        return Err(AppError::BadRequest(format!(
            "avatar image must not exceed {} KiB",
            MAX_UPLOAD_BYTES / 1024
        )));
    }
    let format = image::guess_format(upload).map_err(|_| unsupported_format())?;
    if !matches!(
        format,
        ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP
    ) {
        return Err(unsupported_format());
    }
    let decoded = image::load_from_memory_with_format(upload, format)
        .map_err(|_| AppError::BadRequest("avatar image could not be decoded".into()))?;
    let (width, height) = decoded.dimensions();
    if width < MIN_SOURCE_EDGE || height < MIN_SOURCE_EDGE {
        return Err(AppError::BadRequest(format!(
            "avatar image must be at least {MIN_SOURCE_EDGE}x{MIN_SOURCE_EDGE} pixels"
        )));
    }
    let square = decoded.resize_to_fill(
        AVATAR_SIZE,
        AVATAR_SIZE,
        image::imageops::FilterType::Lanczos3,
    );
    let mut png = Vec::new();
    square
        .write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|_| AppError::BadRequest("avatar image could not be processed".into()))?;
    Ok(png)
}

fn unsupported_format() -> AppError {
    AppError::BadRequest("avatar must be a PNG, JPEG, or WebP image".into())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::expect_used)]
mod tests {
    use std::io::Cursor;

    use image::{DynamicImage, GenericImageView, ImageFormat, Rgb, RgbImage};

    use super::{AVATAR_SIZE, MIN_SOURCE_EDGE, normalize_upload};

    fn encoded(format: ImageFormat, width: u32, height: u32) -> Vec<u8> {
        let image =
            DynamicImage::ImageRgb8(RgbImage::from_pixel(width, height, Rgb([10, 120, 90])));
        let mut bytes = Vec::new();
        image
            .write_to(&mut Cursor::new(&mut bytes), format)
            .unwrap();
        bytes
    }

    #[test]
    fn normalizes_a_wide_png_to_a_square_avatar() {
        let upload = encoded(ImageFormat::Png, 400, 100);
        let normalized = normalize_upload(&upload).unwrap();
        let decoded = image::load_from_memory(&normalized).unwrap();
        assert_eq!(decoded.dimensions(), (AVATAR_SIZE, AVATAR_SIZE));
    }

    #[test]
    fn accepts_jpeg_and_webp_sources() {
        for format in [ImageFormat::Jpeg, ImageFormat::WebP] {
            let upload = encoded(format, 64, 64);
            let normalized = normalize_upload(&upload).unwrap();
            assert_eq!(image::guess_format(&normalized).unwrap(), ImageFormat::Png);
        }
    }

    #[test]
    fn rejects_empty_and_oversized_uploads() {
        assert!(normalize_upload(&[]).is_err());
        assert!(normalize_upload(&vec![0_u8; super::MAX_UPLOAD_BYTES + 1]).is_err());
    }

    #[test]
    fn rejects_non_image_and_svg_and_tiny_sources() {
        assert!(normalize_upload(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>").is_err());
        assert!(normalize_upload(b"not an image").is_err());
        assert!(normalize_upload(&encoded(ImageFormat::Png, MIN_SOURCE_EDGE - 1, 64)).is_err());
    }
}
