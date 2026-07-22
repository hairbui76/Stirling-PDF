# `POST /api/v1/security/remove-cert-sign`

Rust compatibility contract for `RemoveCertSignController.removeCertSignPDF()`.

- Multipart request: required `fileInput` PDF.
- Success: `200 OK`, `application/pdf`, download name `<base>_unsigned.pdf`.
- Root signature fields are flattened with their visible appearances when
  available, their widgets are removed, and non-signature fields/annotations
  remain. Signature flags and XFA are cleared when no signatures remain.
- Endpoint tests verify signature-only removal and response naming; the shared
  signature suite covers visible/hidden appearances and mixed forms.
