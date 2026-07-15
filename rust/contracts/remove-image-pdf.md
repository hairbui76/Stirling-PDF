# `POST /api/v1/general/remove-image-pdf`

Rust compatibility contract for `RemoveImagesController.removeImages()`.

- Multipart request: required `fileInput` PDF.
- Success: `200 OK`, `application/pdf`, download name
  `<base>_images_removed.pdf`.
- Removes image XObjects from every page resource dictionary and recursively
  from nested Form XObject resources. Form XObjects and non-image resources are
  retained; cyclic form references are bounded.
- Endpoint coverage verifies direct and nested image removal while retaining the
  enclosing form.
