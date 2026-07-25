"""Minimal multipart/form-data POST client.

Uses ``requests`` when it is importable, otherwise falls back to a hand-built
multipart body over ``urllib.request`` (stdlib only). Both paths return the same
:class:`HttpResult`, so the rest of the harness never cares which was used.

Connection failures (backend down / unreachable) are returned as a result with
``status is None`` and ``error`` set, rather than raising -- the driver turns
that into SKIP (for an optional Java backend) or ERROR (for the required Rust
backend).
"""

from __future__ import annotations

import mimetypes
import os
import ssl
import urllib.error
import urllib.parse
import urllib.request
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic

try:  # optional dependency
    import requests  # type: ignore

    _HAVE_REQUESTS = True
except Exception:  # noqa: BLE001
    requests = None  # type: ignore
    _HAVE_REQUESTS = False


@dataclass
class HttpResult:
    status: int | None
    headers: dict[str, str] = field(default_factory=dict)
    body: bytes = b""
    error: str | None = None
    elapsed: float = 0.0

    @property
    def ok(self) -> bool:
        return self.status is not None and 200 <= self.status < 300

    @property
    def reached(self) -> bool:
        """True if we got any HTTP response (even a 4xx/5xx)."""
        return self.status is not None

    @property
    def content_type(self) -> str:
        return self.headers.get("content-type", "").split(";")[0].strip().lower()


def backend() -> str:
    return "requests" if _HAVE_REQUESTS else "stdlib-urllib"


def _guess_type(filename: str) -> str:
    return mimetypes.guess_type(filename)[0] or "application/octet-stream"


def _build_url(url: str, query: dict[str, str] | None) -> str:
    if not query:
        return url
    sep = "&" if "?" in url else "?"
    return url + sep + urllib.parse.urlencode(query)


def _post_requests(
    url: str,
    fields: dict[str, str],
    files: list[tuple[str, Path]],
    timeout: float,
) -> HttpResult:
    multipart: list[tuple[str, tuple[str, bytes, str]]] = []
    for field_name, path in files:
        data = Path(path).read_bytes()
        multipart.append(
            (field_name, (Path(path).name, data, _guess_type(Path(path).name)))
        )
    start = monotonic()
    try:
        resp = requests.post(  # type: ignore[union-attr]
            url,
            data=dict(fields),
            files=multipart,
            timeout=timeout,
        )
    except Exception as exc:  # noqa: BLE001 - normalized to error result
        return HttpResult(status=None, error=f"{type(exc).__name__}: {exc}", elapsed=monotonic() - start)
    return HttpResult(
        status=resp.status_code,
        headers={k.lower(): v for k, v in resp.headers.items()},
        body=resp.content,
        elapsed=monotonic() - start,
    )


def _encode_multipart(
    fields: dict[str, str], files: list[tuple[str, Path]]
) -> tuple[bytes, str]:
    boundary = f"----diffharness{uuid.uuid4().hex}"
    crlf = b"\r\n"
    out = bytearray()
    for name, value in fields.items():
        out += b"--" + boundary.encode() + crlf
        out += f'Content-Disposition: form-data; name="{name}"'.encode() + crlf + crlf
        out += str(value).encode("utf-8") + crlf
    for field_name, path in files:
        p = Path(path)
        filename = p.name
        data = p.read_bytes()
        out += b"--" + boundary.encode() + crlf
        out += (
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"'.encode()
            + crlf
        )
        out += f"Content-Type: {_guess_type(filename)}".encode() + crlf + crlf
        out += data + crlf
    out += b"--" + boundary.encode() + b"--" + crlf
    return bytes(out), boundary


def _post_stdlib(
    url: str,
    fields: dict[str, str],
    files: list[tuple[str, Path]],
    timeout: float,
) -> HttpResult:
    body, boundary = _encode_multipart(fields, files)
    req = urllib.request.Request(url, data=body, method="POST")
    req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
    req.add_header("Content-Length", str(len(body)))
    ctx = ssl.create_default_context()
    if os.environ.get("DIFF_INSECURE_TLS") == "1":
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    start = monotonic()
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=ctx) as resp:
            data = resp.read()
            return HttpResult(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=data,
                elapsed=monotonic() - start,
            )
    except urllib.error.HTTPError as exc:
        # A 4xx/5xx is still a reached response we want to compare.
        data = exc.read()
        return HttpResult(
            status=exc.code,
            headers={k.lower(): v for k, v in (exc.headers.items() if exc.headers else [])},
            body=data,
            elapsed=monotonic() - start,
        )
    except Exception as exc:  # noqa: BLE001 - connection refused, timeout, DNS...
        return HttpResult(status=None, error=f"{type(exc).__name__}: {exc}", elapsed=monotonic() - start)


def post_multipart(
    url: str,
    fields: dict[str, str],
    files: list[tuple[str, Path]],
    query: dict[str, str] | None = None,
    timeout: float = 300.0,
) -> HttpResult:
    full_url = _build_url(url, query)
    if _HAVE_REQUESTS:
        return _post_requests(full_url, fields, files, timeout)
    return _post_stdlib(full_url, fields, files, timeout)


def get(url: str, timeout: float = 10.0) -> HttpResult:
    """Simple GET, used for health probes."""
    if _HAVE_REQUESTS:
        start = monotonic()
        try:
            resp = requests.get(url, timeout=timeout)  # type: ignore[union-attr]
        except Exception as exc:  # noqa: BLE001
            return HttpResult(status=None, error=f"{type(exc).__name__}: {exc}", elapsed=monotonic() - start)
        return HttpResult(
            status=resp.status_code,
            headers={k.lower(): v for k, v in resp.headers.items()},
            body=resp.content,
            elapsed=monotonic() - start,
        )
    start = monotonic()
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return HttpResult(
                status=resp.status,
                headers={k.lower(): v for k, v in resp.headers.items()},
                body=resp.read(),
                elapsed=monotonic() - start,
            )
    except urllib.error.HTTPError as exc:
        return HttpResult(status=exc.code, elapsed=monotonic() - start)
    except Exception as exc:  # noqa: BLE001
        return HttpResult(status=None, error=f"{type(exc).__name__}: {exc}", elapsed=monotonic() - start)
