# `POST /api/v1/misc/unlock-pdf-forms`

Rust compatibility contract for `UnlockPDFFormsController.unlockPDFForms()`.

- Multipart request: required `fileInput` PDF.
- Success: `200 OK`, `application/pdf`, download name
  `<base>_unlocked_forms.pdf`.
- Sets `NeedAppearances`, traverses the field tree, removes `Lock`, clears the
  read-only bit from `Ff`, and replaces XFA attributes matching
  `access\s*=\s*"readOnly"` with `access="open"` in stream and packet-array XFA.
- Endpoint coverage verifies field flags, locks, appearance mode, XFA content,
  and response naming.
