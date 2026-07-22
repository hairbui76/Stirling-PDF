# `POST /api/v1/security/add-password` and `remove-password`

Rust compatibility contract for `PasswordController`.

## Add password

- Content type: `multipart/form-data`
- `fileInput`: one non-empty PDF, required
- Optional `ownerPassword` and user `password`; missing values are empty
- `keyLength`: `40`, `128`, or `256`, default `256`
- Permission booleans: `preventAssembly`, `preventExtractContent`,
  `preventExtractForAccessibility`, `preventFillInForm`, `preventModify`,
  `preventModifyAnnotations`, `preventPrinting`, and
  `preventPrintingFaithful`
- 40-bit and 128-bit files use the corresponding standard RC4 revisions;
  256-bit files use the standard AES-256 crypt filter.
- Output is `<base>_passworded.pdf` when either password is non-empty, or
  `<base>_permissions.pdf` for permission-only encryption with empty passwords.

## Remove password

- Accepts `fileInput` plus `password`; either a valid user or owner password
  decrypts the PDF.
- Incorrect passwords return `400 Bad Request` on the route-specific API path.
- Success returns an unencrypted `<base>_password_removed.pdf`.

## Verification

Endpoint tests create and reopen all three key lengths, prove a wrong password
cannot open them, inspect allowed/blocked permission bits, remove a 128-bit
password with the correct credential, and verify the resulting file is no
longer encrypted. A separate test covers empty-password permission-only AES-256
and its download name.
