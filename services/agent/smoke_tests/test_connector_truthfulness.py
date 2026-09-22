"""Real connector failures must never become mock evidence or empty inventories."""
from unittest.mock import Mock

import pytest
import requests

from document_processing import connectors as c
from services.tenant_context import tenant_context


@pytest.fixture(autouse=True)
def connector_io(monkeypatch):
    monkeypatch.setenv("AUTHCLAW_CONNECTOR_TENANT_ID", "7")
    monkeypatch.setenv("ENABLE_REAL_CONNECTORS", "true")
    monkeypatch.setenv("SHAREPOINT_SITE_ID", "site")
    for name in ("validate_aws_connector_config", "validate_gcp_connector_config",
                 "validate_ms_graph_connector_config", "validate_connector_config"):
        monkeypatch.setattr(c, name, lambda *args: {"valid": True})
    monkeypatch.setattr(c, "_ms_graph_access_token", lambda: "token")
    monkeypatch.setattr(c, "_google_drive_headers", lambda: {})
    with tenant_context(7):
        yield


@pytest.mark.parametrize("tenant", [None, 8])
def test_other_tenants_cannot_read_process_sources(monkeypatch, tenant):
    from fastapi import HTTPException
    request = Mock(side_effect=AssertionError("Unauthorized source I/O"))
    monkeypatch.setattr(requests, "get", request)
    monkeypatch.setattr(requests, "post", request)
    monkeypatch.setattr(c, "_aws_session", request)
    with tenant_context(tenant):
        for source in ("s3", "gdrive", "onedrive", "sharepoint", "dropbox"):
            with pytest.raises(HTTPException) as failure:
                c.list_cloud_source_files(source)
            assert failure.value.status_code == 403
            args = ("scope", "item") if source in {"s3", "sharepoint"} else ("item",)
            with pytest.raises(HTTPException):
                getattr(c, f"fetch_{source}_document")(*args)
    request.assert_not_called()


def test_unconfigured_source_owner_fails_closed(monkeypatch):
    from fastapi import HTTPException
    monkeypatch.delenv("AUTHCLAW_CONNECTOR_TENANT_ID")
    monkeypatch.delenv("AUTHCLAW_BACKGROUND_MONITOR_TENANT_ID", raising=False)
    with pytest.raises(HTTPException) as failure:
        c.list_cloud_source_files("gdrive")
    assert failure.value.status_code == 503


@pytest.mark.parametrize("source,key,payload", [
    ("gdrive", "files", {"nextPageToken": "next"}),
    ("onedrive", "value", {"@odata.nextLink": "https://untrusted.invalid"}),
    ("sharepoint", "value", {"@odata.nextLink": "https://untrusted.invalid"}),
    ("dropbox", "entries", {"has_more": True}),
])
def test_listing_empty_complete_and_incomplete(monkeypatch, source, key, payload):
    response = Mock(status_code=200)
    monkeypatch.setattr(requests, "get", Mock(return_value=response))
    monkeypatch.setattr(requests, "post", Mock(return_value=response))
    response.json.return_value = {key: []}
    assert c.list_cloud_source_files(source) == []
    for invalid in ({key: [], **payload}, {}, {key: None}, {key: [{}]}, {key: [None]}):
        response.json.return_value = invalid
        with pytest.raises((RuntimeError, KeyError, TypeError)):
            c.list_cloud_source_files(source)


@pytest.mark.parametrize("source", ["gdrive", "onedrive", "sharepoint", "dropbox"])
@pytest.mark.parametrize("failure", ["status", "transport"])
def test_real_http_errors_propagate(monkeypatch, source, failure):
    response = Mock(status_code=503)
    request = Mock(return_value=response, side_effect=OSError("offline") if failure == "transport" else None)
    monkeypatch.setattr(requests, "get", request)
    monkeypatch.setattr(requests, "post", request)
    with pytest.raises((RuntimeError, OSError)):
        c.list_cloud_source_files(source)
    args = ("site", "item") if source == "sharepoint" else ("item",)
    with pytest.raises((RuntimeError, OSError)):
        getattr(c, f"fetch_{source}_document")(*args)


def test_s3_empty_and_partial_failure(monkeypatch):
    client = Mock()
    monkeypatch.setattr(c, "_aws_session", lambda: Mock(client=lambda name: client))
    client.list_buckets.return_value = {"Buckets": []}
    assert c.discover_s3_buckets() == []
    assert c.list_cloud_source_files("s3") == []
    client.list_buckets.return_value = {"Buckets": [{"Name": "one"}, {"Name": "two"}]}
    client.list_objects_v2.side_effect = [{"KeyCount": 1, "Contents": [{"Key": "x.txt", "Size": 0}]}, OSError("denied")]
    with pytest.raises(OSError):
        c.list_cloud_source_files("s3")
    client.list_buckets.side_effect = OSError("denied")
    with pytest.raises(OSError):
        c.discover_s3_buckets()
    client.get_object.side_effect = OSError("denied")
    with pytest.raises(OSError):
        c.fetch_s3_document("one", "x.txt")


def test_invalid_config_never_returns_mock(monkeypatch):
    for name in ("validate_aws_connector_config", "validate_gcp_connector_config",
                 "validate_ms_graph_connector_config", "validate_connector_config"):
        monkeypatch.setattr(c, name, lambda *args: {"valid": False})
    for source in ("s3", "gdrive", "onedrive", "sharepoint", "dropbox"):
        with pytest.raises(c.ConnectorValidationError):
            c.list_cloud_source_files(source)
        args = ("scope", "item") if source in {"s3", "sharepoint"} else ("item",)
        with pytest.raises(c.ConnectorValidationError):
            getattr(c, f"fetch_{source}_document")(*args)
    with pytest.raises(c.ConnectorValidationError):
        c.discover_s3_buckets()


def test_explicit_mock_mode_still_works(monkeypatch):
    monkeypatch.setenv("ENABLE_REAL_CONNECTORS", "false")
    for source in ("s3", "gdrive", "onedrive", "sharepoint", "dropbox"):
        assert c.list_cloud_source_files(source)
        args = ("scope", "item") if source in {"s3", "sharepoint"} else ("item",)
        assert getattr(c, f"fetch_{source}_document")(*args)


def test_s3_truncated_inventory_cannot_reconcile(monkeypatch):
    client = Mock()
    monkeypatch.setattr(c, "_aws_session", lambda: Mock(client=lambda name: client))
    client.list_buckets.return_value = {"Buckets": [], "ContinuationToken": "next"}
    with pytest.raises(RuntimeError):
        c.discover_s3_buckets()
    client.list_buckets.return_value = {"Buckets": [{"Name": "one"}]}
    client.list_objects_v2.return_value = {"IsTruncated": True, "Contents": []}
    with pytest.raises(RuntimeError):
        c.list_cloud_source_files("s3")
    for payload in ({}, {"KeyCount": 0, "Contents": {}}, {"KeyCount": True}, {"KeyCount": 1}):
        client.list_objects_v2.return_value = payload
        with pytest.raises(RuntimeError):
            c.list_cloud_source_files("s3")
    client.list_objects_v2.return_value = {"KeyCount": 0}
    assert c.list_cloud_source_files("s3") == []
    for payload in ({"Buckets": {}}, {"Buckets": [], "NextToken": "next"}):
        client.list_buckets.return_value = payload
        with pytest.raises(RuntimeError):
            c.discover_s3_buckets()


def test_security_scan_preserves_empty_and_rejects_unknown(monkeypatch):
    from botocore.exceptions import ClientError

    client = Mock()
    monkeypatch.setattr(c, "_aws_session", lambda: Mock(client=lambda name: client))
    client.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": {
        name: True for name in ("BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets")}}
    client.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {"Rules": [{}]}}
    client.get_bucket_versioning.return_value = {"Status": "Enabled"}
    client.get_bucket_logging.return_value = {"LoggingEnabled": {}}
    client.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": False}}
    assert c.scan_s3_bucket_security("one") == []
    for method in ("get_public_access_block", "get_bucket_encryption", "get_bucket_versioning",
                   "get_bucket_logging", "get_bucket_policy_status"):
        getattr(client, method).side_effect = ClientError({"Error": {"Code": "AccessDenied"}}, method)
        with pytest.raises(ClientError):
            c.scan_s3_bucket_security("one")
        getattr(client, method).side_effect = None


@pytest.mark.parametrize("size", [0, None, 99])
def test_real_inventory_preserves_size_provenance(monkeypatch, size):
    response = Mock(status_code=200)
    response.json.return_value = {"files": [{"id": "id", "name": "file", "size": size}]}
    monkeypatch.setattr(requests, "get", Mock(return_value=response))
    assert c.list_cloud_source_files("gdrive")[0]["size_bytes"] == size


@pytest.mark.parametrize("api_key", ["", "test-key"])
def test_drive_requests_size_and_completeness_metadata(monkeypatch, api_key):
    monkeypatch.setenv("GOOGLE_API_KEY", api_key)
    request = Mock(return_value=Mock(status_code=200, json=lambda: {"files": []}))
    monkeypatch.setattr(requests, "get", request)
    assert c.list_cloud_source_files("gdrive") == []
    fields = "nextPageToken,incompleteSearch,files(id,name,size)"
    if api_key:
        assert f"fields={fields}" in request.call_args.args[0]
    else:
        assert request.call_args.kwargs["params"]["fields"] == fields


@pytest.mark.parametrize("source", ["gdrive", "onedrive", "sharepoint", "dropbox"])
def test_successful_http_fetch_preserves_actual_bytes(monkeypatch, source):
    response = Mock(status_code=200, content=b"")
    monkeypatch.setattr(requests, "get", Mock(return_value=response))
    monkeypatch.setattr(requests, "post", Mock(return_value=response))
    args = ("site", "item") if source == "sharepoint" else ("item",)
    assert getattr(c, f"fetch_{source}_document")(*args) == b""


def test_sharepoint_missing_site_is_not_empty_inventory(monkeypatch):
    monkeypatch.delenv("SHAREPOINT_SITE_ID")
    with pytest.raises(RuntimeError):
        c.list_cloud_source_files("sharepoint")


@pytest.mark.parametrize("source", ["onedrive", "sharepoint"])
def test_graph_requires_recognized_item_facet(monkeypatch, source):
    response = Mock(status_code=200)
    monkeypatch.setattr(requests, "get", Mock(return_value=response))
    for item in ({"id": "x", "name": "existing.txt"},
                 {"id": "x", "name": "existing.txt", "file": None},
                 {"id": 3, "name": "existing.txt", "file": {}},
                 {"id": "x", "name": ["existing.txt"], "file": {}},
                 {"id": " ", "name": "existing.txt", "file": {}},
                 {"id": "x", "name": " ", "file": {}}):
        response.json.return_value = {"value": [item]}
        with pytest.raises(RuntimeError):
            c.list_cloud_source_files(source)
    response.json.return_value = {"value": [{"id": "x", "name": "folder", "folder": {}}]}
    assert c.list_cloud_source_files(source) == []
    response.json.return_value = {"value": [{"id": "x", "name": "file", "file": {}, "size": 0}]}
    assert c.list_cloud_source_files(source)[0]["size_bytes"] == 0
