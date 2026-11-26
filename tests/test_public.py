import pytest

from mp import (
    MultipartError,
    multipart_batch,
    parse_boundary,
    parse_multipart,
    safe_filename,
    split_parts,
)

POLICY = {
    "max_parts": 8,
    "max_part_bytes": 1024,
    "max_total_bytes": 8192,
    "filename_prefix": "upload",
}


def _content_type(boundary):
    return f'multipart/form-data; boundary="{boundary}"'


def _part(filename, payload):
    disposition = 'Content-Disposition: form-data; name="file"'
    if filename is not None:
        disposition += f'; filename="{filename}"'
    headers = disposition + "\r\nContent-Type: text/plain"
    return headers, payload


def _build(boundary, parts, closed=True):
    chunks = []
    for headers, payload in parts:
        chunks.extend((f"--{boundary}", headers, "", payload))
    if closed:
        chunks.append(f"--{boundary}--")
    return ("\r\n".join(chunks) + "\r\n").encode("utf-8")


def test_boundary_must_match_declared_content_type():
    assert parse_boundary('multipart/form-data; boundary="alpha"') == "alpha"

    with pytest.raises(MultipartError):
        parse_boundary("multipart/form-data")

    with pytest.raises(MultipartError):
        parse_boundary("multipart/form-data; boundary=" + "a" * 71)

    body = _build("beta", [_part("note.txt", "hello")])
    with pytest.raises(MultipartError):
        parse_multipart(body, _content_type("alpha"), POLICY)


def test_split_rejects_unterminated_body():
    valid = _build("alpha", [_part("note.txt", "hello")])
    parts = split_parts(valid, "alpha")
    assert len(parts) == 1
    assert parts[0]["body"] == b"hello"

    unterminated = _build("alpha", [_part("note.txt", "hello")], closed=False)
    with pytest.raises(MultipartError):
        split_parts(unterminated, "alpha")


def test_safe_filename_removes_path_and_renames():
    raw_name = r"..\..\secret.txt"
    name = safe_filename(raw_name, POLICY)

    assert "\\" not in name
    assert "/" not in name
    assert name != raw_name
    assert name.startswith("upload-")


def test_part_count_limit():
    body = _build(
        "alpha",
        [_part(f"file-{index}.txt", "x") for index in range(3)],
    )
    policy = {
        "max_parts": 2,
        "max_part_bytes": 100,
        "max_total_bytes": 1000,
        "filename_prefix": "upload",
    }

    with pytest.raises(MultipartError):
        parse_multipart(body, _content_type("alpha"), policy)


def test_batch_parses_requests_independently():
    requests = [
        {
            "body": _build("first", [_part("first.txt", "first")]),
            "content_type": _content_type("first"),
        },
        {
            "body": _build("second", [_part("second.txt", "second")]),
            "content_type": _content_type("second"),
        },
    ]

    outcome = multipart_batch(requests, POLICY)
    assert [entry["ok"] for entry in outcome["results"]] == [True, True]
    assert outcome["results"][1]["result"]["parts"][0]["body"] == b"second"