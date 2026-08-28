from security_framework.findings import Confidence, Evidence, Finding, Severity


def test_finding_to_dict() -> None:
    finding = Finding(
        title="Test",
        description="Description",
        asset="https://example.com",
        severity=Severity.LOW,
        confidence=Confidence.HIGH,
        evidence=[Evidence(kind="unit", description="test")],
        remediation=["Fix it"],
    )
    data = finding.to_dict()
    assert data["title"] == "Test"
    assert data["severity"] == "low"
