"""Multipart form parsing for the upload endpoint."""

from __future__ import annotations

import hashlib
import re
from typing import Any

MAX_BOUNDARY_LENGTH = 70
DEFAULT_FILENAME_PREFIX = "upload"
DEFAULT_MAX_PARTS = 32
DEFAULT_MAX_PART_BYTES = 1024 * 1024
DEFAULT_MAX_TOTAL_BYTES = 8 * 1024 * 1024


class MultipartError(ValueError):
    """Raised when a multipart request cannot be parsed safely."""


def _as_bytes(value: Any) -> bytes:
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("utf-8")
    raise MultipartError("multipart body must be bytes or text")


def parse_boundary(content_type: str) -> str:
    """Extract the boundary token declared by a multipart content type."""

    if not isinstance(content_type, str) or not content_type.strip():
        raise MultipartError("content type is required")
    if not content_type.strip().lower().startswith("multipart/form-data"):
        raise MultipartError("content type is not multipart/form-data")

    match = re.search(
        r'(?i)(?:^|;)\s*boundary\s*=\s*(?:"([^"]*)"|([^;\s]+))',
        content_type,
    )
    if match is None:
        raise MultipartError("multipart boundary is missing")

    boundary = match.group(1) if match.group(1) is not None else match.group(2)
    boundary = boundary.strip()
    if not boundary:
        raise MultipartError("multipart boundary is empty")
    if len(boundary) > MAX_BOUNDARY_LENGTH:
        raise MultipartError("multipart boundary is too long")
    if any(ord(char) < 0x20 or ord(char) == 0x7F for char in boundary):
        raise MultipartError("multipart boundary contains control characters")
    return boundary


def _sniff_boundary(body: Any) -> str | None:
    data = _as_bytes(body)
    if not data:
        return None
    first = data.split(b"\n", 1)[0]
    if first.endswith(b"\r"):
        first = first[:-1]
    if not first.startswith(b"--"):
        return None
    token = first[2:].rstrip(b" \t")
    if token.endswith(b"--"):
        token = token[:-2]
    if not token:
        return None
    try:
        return token.decode("latin-1")
    except UnicodeDecodeError:
        return None


def split_parts(body: bytes, boundary: str) -> list[dict[str, Any]]:
    """Split a multipart body into raw header and payload segments."""

    data = _as_bytes(body)
    if not isinstance(boundary, str) or not boundary:
        raise MultipartError("boundary is required")

    try:
        marker = b"--" + boundary.encode("latin-1")
    except UnicodeEncodeError as exc:
        raise MultipartError("boundary is not representable") from exc

    pattern = re.compile(
        rb"(?m)^" + re.escape(marker) + rb"(--)?[ \t]*(?:\r\n|\n|\Z)"
    )
    matches = list(pattern.finditer(data))
    if not matches or matches[0].start() != 0:
        raise MultipartError("multipart opening boundary is missing")

    parts: list[dict[str, Any]] = []

    for index, match in enumerate(matches):
        if match.group(1) is not None:
            break

        start = match.end()
        end = matches[index + 1].start() if index + 1 < len(matches) else len(data)
        segment = data[start:end]
        if segment.endswith(b"\r\n"):
            segment = segment[:-2]
        elif segment.endswith(b"\n"):
            segment = segment[:-1]

        header_blob, separator, payload = segment.partition(b"\r\n\r\n")
        if not separator:
            header_blob, separator, payload = segment.partition(b"\n\n")
        if not separator:
            raise MultipartError("multipart part is missing its header block")
        if not header_blob.strip():
            raise MultipartError("multipart part has no headers")

        parts.append(
            {
                "headers_raw": header_blob.decode("latin-1"),
                "body": payload,
            }
        )

    return parts


def _split_parameter_segments(value: str) -> list[str]:
    segments: list[str] = []
    buffer: list[str] = []
    quoted = False
    escaped = False

    for char in value:
        if escaped:
            buffer.append(char)
            escaped = False
            continue
        if quoted and char == "\\":
            buffer.append(char)
            escaped = True
            continue
        if char == '"':
            quoted = not quoted
            buffer.append(char)
            continue
        if char == ";" and not quoted:
            segments.append("".join(buffer))
            buffer = []
            continue
        buffer.append(char)

    if quoted or escaped:
        raise MultipartError("unterminated quoted header parameter")
    segments.append("".join(buffer))
    return segments


def _unquote_parameter(value: str) -> str:
    if len(value) < 2 or not value.startswith('"') or not value.endswith('"'):
        raise MultipartError("malformed quoted header parameter")
    inner = value[1:-1]
    return re.sub(r'\\([\\"])', r"\1", inner)


def _parse_parameters(value: str) -> dict[str, str]:
    segments = _split_parameter_segments(value)
    parameters: dict[str, str] = {}

    for segment in segments[1:]:
        piece = segment.strip()
        if not piece:
            continue
        if "=" not in piece:
            raise MultipartError("malformed header parameter")
        name, raw_value = piece.split("=", 1)
        name = name.strip()
        raw_value = raw_value.strip()
        if not name:
            raise MultipartError("empty header parameter name")
        if raw_value.startswith('"'):
            parsed_value = _unquote_parameter(raw_value)
        else:
            if '"' in raw_value:
                raise MultipartError("malformed header parameter quotes")
            parsed_value = raw_value
        parameters[name] = parsed_value

    return parameters


def parse_headers(raw: str | bytes) -> dict[str, str]:
    """Parse one part header block into lower-cased field names."""

    if isinstance(raw, bytes):
        text = raw.decode("latin-1")
    elif isinstance(raw, str):
        text = raw
    else:
        raise MultipartError("part headers must be text or bytes")

    text = text.replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"\n[ \t]+", " ", text)

    headers: dict[str, str] = {}
    for line in text.split("\n"):
        if not line.strip():
            continue
        if ":" not in line:
            raise MultipartError("malformed part header line")
        name, value = line.split(":", 1)
        name = name.strip()
        value = value.strip()
        if not name:
            raise MultipartError("empty part header name")
        if any(char.isspace() for char in name):
            raise MultipartError("invalid part header name")

        key = name.lower()
        if key in headers:
            headers[key] = headers[key] + ", " + value
        else:
            headers[key] = value

    disposition = headers.get("content-disposition")
    if disposition:
        parameters = _parse_parameters(disposition)
        for key, value in parameters.items():
            headers[key] = value

    return headers


def safe_filename(name: str | None, policy: dict[str, Any]) -> str:
    """Create a filesystem-safe name for an uploaded part."""

    prefix = str(policy.get("filename_prefix", DEFAULT_FILENAME_PREFIX))
    if name is None:
        return ""

    clean = str(name).replace("\x00", "").strip()
    if not clean:
        return f"{prefix}-file"
    if "/" not in clean and "\\" not in clean:
        return clean

    base = clean.rsplit("/", 1)[-1]
    return f"{prefix}-{base}"


def check_limits(parts: list[dict[str, Any]], policy: dict[str, Any]) -> list[str]:
    """Return policy violations for a parsed part list."""

    errors: list[str] = []
    max_part_bytes = int(
        policy.get("max_part_bytes", DEFAULT_MAX_PART_BYTES)
    )

    for index, part in enumerate(parts):
        size = len(part.get("body", b""))
        if size > max_part_bytes:
            errors.append(
                f"part {index} exceeds max_part_bytes ({size} > {max_part_bytes})"
            )

    return errors


def reject_nested(part: dict[str, Any]) -> bool:
    """Report whether a part carries a nested multipart payload."""

    content_type = str(part.get("content_type", "")).strip().lower()
    return content_type.startswith("multipart/")


def _parse_with_boundary(
    body: Any, boundary: str, policy: dict[str, Any]
) -> dict[str, Any]:
    raw_parts = split_parts(body, boundary)
    parts: list[dict[str, Any]] = []
    errors: list[str] = []

    for raw_part in raw_parts:
        try:
            headers = parse_headers(raw_part["headers_raw"])
            raw_name = headers.get("filename")
            filename = (
                safe_filename(raw_name, policy) if raw_name is not None else None
            )
            part = {
                "headers": headers,
                "filename": filename,
                "body": raw_part["body"],
                "size": len(raw_part["body"]),
            }
            if reject_nested(part):
                raise MultipartError("nested multipart parts are not allowed")
            parts.append(part)
        except MultipartError as exc:
            errors.append(str(exc))
            break

    if errors:
        return {
            "boundary": boundary,
            "parts": parts,
            "errors": errors,
            "ok": False,
        }

    limit_errors = check_limits(parts, policy)
    if limit_errors:
        raise MultipartError("; ".join(limit_errors))

    return {"boundary": boundary, "parts": parts, "ok": True}


def parse_multipart(
    body: Any, content_type: str, policy: dict[str, Any]
) -> dict[str, Any]:
    """Parse a complete multipart request under the supplied policy."""

    boundary = parse_boundary(content_type)
    sniffed = _sniff_boundary(body)
    if sniffed is not None:
        boundary = sniffed
    return _parse_with_boundary(body, boundary, policy)


def multipart_batch(
    requests: list[dict[str, Any]], policy: dict[str, Any]
) -> dict[str, Any]:
    """Parse a batch of independent multipart requests."""

    results: list[dict[str, Any]] = []
    if not requests:
        return {"results": results}

    cached_boundary = None
    for request in requests:
        try:
            if cached_boundary is None:
                cached_boundary = parse_boundary(request.get("content_type", ""))
            parsed = _parse_with_boundary(
                request.get("body", b""), cached_boundary, policy
            )
            results.append({"ok": True, "result": parsed})
        except MultipartError as exc:
            results.append({"ok": False, "error": str(exc)})

    return {"results": results}