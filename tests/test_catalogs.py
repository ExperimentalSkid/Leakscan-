from leakscan.catalogs import BiteBlobCatalogAdapter
from leakscan.config import SeedConfig


def test_catalog_adapter_extracts_listing_fingerprints(app_config):
    body = b"""
    <html><head><title>Example Dataset</title></head><body>
      <dl>
        <dt>Item ID</dt><dd>abcDEF123</dd>
        <dt>Uploader</dt><dd>sample_account</dd>
        <dt>Size</dt><dd>549.04 MB</dd>
      </dl>
      <p>Example Dataset.7z</p>
      <p>SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa</p>
      <a href="https://files.example/sample.7z">metadata candidate</a>
    </body></html>
    """
    adapter = BiteBlobCatalogAdapter()
    seed = SeedConfig(url="https://biteblob.com/Information/abcDEF123/#Example%20Dataset.7z", adapter="biteblob")
    assert adapter.matches(seed)
    record = adapter.parse(body, seed.url, "text/html; charset=utf-8", app_config)
    assert "abcDEF123" in record.item_ids
    assert "Example Dataset.7z" in record.filenames
    assert record.sizes[0]["bytes"] == 549_040_000
    assert record.accounts == ["sample_account"]
    assert record.hashes[0]["algorithm"] == "sha256"
