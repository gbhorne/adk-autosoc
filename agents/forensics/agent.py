from datetime import datetime, timezone, timedelta
from google.cloud import logging_v2
from google.cloud import firestore
from shared.models import Investigation, ForensicsResult, InvestigationStatus
from shared.config import PROJECT_ID, TOPIC_INVESTIGATION_EVENTS, FIRESTORE_COLLECTION_INVESTIGATIONS
from shared.pubsub_client import publish_message

db = firestore.Client(project=PROJECT_ID)
log_client = logging_v2.Client(project=PROJECT_ID)


def pull_audit_logs(resource: str, hours_back: int = 24) -> list:
    try:
        since = datetime.now(timezone.utc) - timedelta(hours=hours_back)
        since_str = since.strftime("%Y-%m-%dT%H:%M:%SZ")
        filter_str = (
            f'resource.type="gcs_bucket" '
            f'AND timestamp>="{since_str}"'
        )
        entries = []
        for entry in log_client.list_entries(filter_=filter_str, max_results=50):
            entries.append({
                "timestamp": str(entry.timestamp),
                "principal": str(entry.http_request) if entry.http_request else "unknown",
                "action": str(entry.log_name),
                "resource": resource,
                "result": "SUCCESS"
            })
        print(f"Forensics Agent: pulled {len(entries)} log entries")
        return entries
    except Exception as e:
        print(f"Forensics Agent: log pull error: {e}")
        return []


def identify_blast_radius(investigation: Investigation) -> list:
    blast_radius = []
    alert = investigation.alert
    if not alert:
        return blast_radius

    if alert.alert_type.value == "PUBLIC_BUCKET":
        blast_radius.append(f"All objects in {alert.resource} are publicly accessible")
        blast_radius.append("Any service account with storage access may be implicated")
        if investigation.triage and investigation.triage.principal_has_bq_access:
            blast_radius.append("Principal has BigQuery access - data exfiltration risk")

    elif alert.alert_type.value == "IAM_ANOMALY":
        blast_radius.append("Elevated permissions may allow lateral movement")
        blast_radius.append("All resources accessible by this principal are at risk")

    return blast_radius


def run(investigation_data: dict):
    investigation = Investigation(**investigation_data)
    investigation_id = investigation.investigation_id
    print(f"Forensics Agent: building timeline for {investigation_id}")

    resource = investigation.alert.resource if investigation.alert else ""
    timeline_events = pull_audit_logs(resource, hours_back=24)
    blast_radius = identify_blast_radius(investigation)

    now = datetime.now(timezone.utc)
    earliest = now - timedelta(hours=24)

    forensics_result = ForensicsResult(
        investigation_id=investigation_id,
        timeline_events=timeline_events,
        blast_radius=blast_radius,
        related_resources=[resource],
        earliest_event=earliest,
        latest_event=now,
        forensics_summary=(
            f"Analyzed {len(timeline_events)} log events over 24 hours. "
            f"Blast radius includes {len(blast_radius)} affected areas. "
            f"Resource: {resource}"
        )
    )

    investigation.forensics = forensics_result
    investigation.status = InvestigationStatus.REMEDIATING
    investigation.current_agent = "remediation"
    investigation.agents_completed.append("forensics")
    investigation.last_updated = now

    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(investigation_id)
    doc_ref.update({
        "forensics": forensics_result.model_dump(),
        "status": InvestigationStatus.REMEDIATING.value,
        "current_agent": "remediation",
        "agents_completed": firestore.ArrayUnion(["forensics"]),
        "last_updated": now
    })

    payload = investigation.model_dump()
    payload["next_agent"] = "remediation"
    publish_message(TOPIC_INVESTIGATION_EVENTS, payload)
    print(f"Forensics Agent: complete - {len(blast_radius)} blast radius items, routing to remediation")
    return forensics_result


if __name__ == '__main__':
    test_investigation = {
        "investigation_id": "inv-20260307-test001",
        "status": "INVESTIGATING",
        "alert": {
            "investigation_id": "inv-20260307-test001",
            "alert_type": "PUBLIC_BUCKET",
            "severity": "HIGH",
            "resource": "gs://test-exposed-bucket",
            "principal": "test-sa@sec-autosoc.iam.gserviceaccount.com",
            "project_id": PROJECT_ID,
            "scc_finding_id": "test-finding-001",
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "triage": {
            "investigation_id": "inv-20260307-test001",
            "severity_score": 7,
            "severity_reasoning": "HIGH severity | Principal has BigQuery access",
            "principal_roles": ["roles/bigquery.dataViewer"],
            "principal_has_bq_access": True,
            "principal_has_storage_access": True,
            "resource_has_sensitive_tags": False,
            "normal_behavior_deviation": True,
            "recommended_next_agent": "threat_intel"
        },
        "current_agent": "forensics",
        "agents_completed": ["detection", "orchestrator", "triage", "threat_intel"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": PROJECT_ID
    }
    run(test_investigation)