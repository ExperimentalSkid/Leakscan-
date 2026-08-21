from leakscan.utils.urls import looks_like_archive_url, normalize_url, safe_url


def test_url_normalization_removes_tracking_and_fragment():
    value = normalize_url("HTTPS://Example.COM:443/a%20b?utm_source=x&b=2&a=1#fragment")
    assert value == "https://example.com/a%20b?a=1&b=2"


def test_url_normalization_resolves_relative_url():
    assert normalize_url("../file.7z", "https://example.com/a/page") == "https://example.com/file.7z"


def test_url_normalization_collapses_trailing_slash_variants():
    assert normalize_url("https://example.com/item/abc/") == "https://example.com/item/abc"


def test_archive_detection_uses_path_not_query():
    assert looks_like_archive_url("https://example.com/files/sample.7z?download=1", [".7z"])
    assert not looks_like_archive_url("https://example.com/page?name=sample.7z", [".7z"])


def test_compound_and_split_archive_paths_are_detected():
    extensions = [".tar.gz", ".7z.001", ".zip.001", ".part1.rar", ".part01.rar"]
    assert looks_like_archive_url("https://example.com/files/sample.tar.gz", extensions)
    assert looks_like_archive_url("https://example.com/files/sample.7z.001", extensions)
    assert looks_like_archive_url("https://example.com/files/sample.zip.001", extensions)
    assert looks_like_archive_url("https://example.com/files/sample.part1.rar", extensions)
    assert looks_like_archive_url("https://example.com/files/sample.part01.rar", extensions)


def test_private_host_is_rejected():
    allowed, reason = safe_url("http://127.0.0.1/admin", ["http", "https"], reject_private=True)
    assert not allowed
    assert "public" in reason.lower()
