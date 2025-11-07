from mcpguard.acl import ResourceACL


def test_resource_acl() -> None:
    acl = ResourceACL(
        allow=["file://**/*.md", "http://docs.example.com/**"],
        deny=["file://**/.env", "s3://secret/**"],
    )
    assert acl.is_allowed("file://project/readme.md")
    assert not acl.is_allowed("file://project/.env")
    assert acl.is_allowed("http://docs.example.com/page")
    assert not acl.is_allowed("s3://secret/data")
