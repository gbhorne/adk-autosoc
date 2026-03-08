import uuid
from datetime import datetime, timezone
from shared.models import Alert, AlertType, SeverityLevel
from shared.config import TOPIC_INVESTIGATION_EVENTS, PROJECT_ID
from shared.pubsub_client import publish_message


def classify_alert_type(category: str) -> AlertType:
    category = category.upper()
    if 'BUCKET' in category or 'STORAGE' in category:
        return AlertType.PUBLIC_BUCKET
    elif 'IAM' in category or 'PRIVILEGE' in category:
        return AlertType.IAM_ANOMALY
    elif 'DATA' in category or 'ACCESS' in category:
        return AlertType.DATA_ACCESS
    elif 'NETWORK' in category or 'FIREWALL' in category:
        return AlertType.NETWORK_ANOMALY
    elif 'MALWARE' in category or 'THREAT' in category:
        return AlertType.MALWARE
    else:
        return AlertType.UNKNOWN


def classify_severity(severity: str) -> SeverityLevel:
    severity = severity.upper()
    if severity == 'CRITICAL':
        return SeverityLevel.CRITICAL
    elif severity == 'HIGH':
        return SeverityLevel.HIGH
    elif severity == 'MEDIUM':
        return SeverityLevel.MEDIUM
    elif severity == 'LOW':
        return SeverityLevel.LOW
    else:
        return SeverityLevel.INFO


def process_scc_finding(finding: dict) -> Alert:
    date_str = datetime.now(timezone.utc).strftime("%Y%m%d")
    short_id = str(uuid.uuid4())[:8]
    investigation_id = f"inv-{date_str}-{short_id}"
    alert = Alert(
        investigation_id=investigation_id,
        alert_type=classify_alert_type(finding.get('category', '')),
        severity=classify_severity(finding.get('severity', 'LOW')),
        resource=finding.get('resourceName', 'unknown'),
        principal=finding.get('principal', None),
        project_id=finding.get('projectId', PROJECT_ID),
        scc_finding_id=finding.get('findingId', 'unknown'),
        timestamp=datetime.now(timezone.utc),
        raw_finding=finding
    )
    return alert


def run(finding: dict):
    finding_id = finding.get('findingId', 'unknown')
    print(f"Detection Agent: processing SCC finding {finding_id}")
    alert = process_scc_finding(finding)
    print(f"Detection Agent: classified as {alert.alert_type} severity {alert.severity}")
    publish_message(TOPIC_INVESTIGATION_EVENTS, alert.model_dump())
    print(f"Detection Agent: published alert {alert.investigation_id} to investigation-events")
    return alert


if __name__ == '__main__':
    test_finding = {
        'findingId': 'test-finding-001',
        'category': 'PUBLIC_BUCKET',
        'resourceName': 'gs://test-exposed-bucket',
        'projectId': PROJECT_ID,
        'severity': 'HIGH',
        'principal': 'test-sa@sec-autosoc.iam.gserviceaccount.com'
    }
    run(test_finding)
