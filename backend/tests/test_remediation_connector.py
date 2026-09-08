import io

from app.orchestrator.connectors import DocumentScanner


class FakeS3:
    def __init__(self):
        self.objects = {
            "tenant-a/doc.txt": {
                "Body": b"Patient email jane@example.com and phone 555-123-4567",
                "ContentType": "text/plain",
                "VersionId": "v1",
            }
        }
        self.version = 1

    def get_object(self, Bucket, Key):
        obj = self.objects[Key]
        return {
            "Body": io.BytesIO(obj["Body"]),
            "ContentType": obj.get("ContentType", "text/plain"),
            "VersionId": obj.get("VersionId"),
            "ETag": f'"etag-{obj.get("VersionId", "0")}"',
            "Metadata": obj.get("Metadata", {}),
        }

    def put_object(
        self,
        Bucket,
        Key,
        Body,
        ContentType="text/plain",
        Metadata=None,
        IfMatch=None,
        IfNoneMatch=None,
        ChecksumSHA256=None,
    ):
        if IfNoneMatch == "*" and Key in self.objects:
            raise RuntimeError("PreconditionFailed: object already exists")
        if IfMatch is not None:
            if Key not in self.objects:
                raise RuntimeError("PreconditionFailed: target is missing")
            current_etag = f'etag-{self.objects[Key].get("VersionId", "0")}'
            if IfMatch.strip('"') != current_etag:
                raise RuntimeError("PreconditionFailed: ETag changed")
        self.version += 1
        self.objects[Key] = {
            "Body": bytes(Body),
            "ContentType": ContentType,
            "VersionId": f"v{self.version}",
            "Metadata": Metadata or {},
        }
        return {"VersionId": f"v{self.version}", "ETag": f'"etag-v{self.version}"'}


def test_s3_remediation_applies_verifies_and_rolls_back():
    scanner = DocumentScanner()
    scanner.bucket = "authclaw-test"
    scanner.s3_client = FakeS3()

    plan = scanner.build_remediation_plan("tenant-a/doc.txt", "Entities: EMAIL_ADDRESS, PHONE_NUMBER")
    result = scanner.execute_remediation("workflow-1", "action-1", {
        "finding_control": "tenant-a/doc.txt",
        **plan,
    })

    assert result["status"] == "success"
    assert result["before_verification"]["total"] == 2
    assert result["after_verification"]["total"] == 0
    assert result["rollback_ref"]["backup_key"] in scanner.s3_client.objects
    assert b"jane@example.com" not in scanner.s3_client.objects["tenant-a/doc.txt"]["Body"]

    rollback = scanner.rollback_remediation({"rollback_ref": result["rollback_ref"]})

    assert rollback["status"] == "rolled_back"
    assert b"jane@example.com" in scanner.s3_client.objects["tenant-a/doc.txt"]["Body"]
