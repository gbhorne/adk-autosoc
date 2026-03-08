import requests
from datetime import datetime, timezone
from google.cloud import firestore
from google.cloud import storage
from shared.models import Investigation, RemediationResult, RemediationAction, InvestigationStatus
from shared.config import (
    PROJECT_ID, TOPIC_FINDINGS_COMPLETE,
    FIRESTORE_COLLECTION_INVESTIGATIONS,
    AUTO_REMEDIATE_MAX_SCORE, SLACK_WEBHOOK_URL
)
from shared.pubsub_client import publish_message

db = firestore.Client(project=PROJECT_ID)
storage_client = storage.Client(project=PROJECT_ID)


def remove_public_bucket_access(bucket_name: str) -> bool:
    try:
        bucket_name = bucket_name.replace("gs://", "").split("/")[0]
        bucket = storage_client.bucket(bucket_name)
        bucket.iam_configuration.public_access_prevention = "enforced"
        bucket.patch()
        print(f"Remediation Agent: removed public access from {bucket_name}")
        return True
    except Exception as e:
        print(f"Remediation Agent: could not remediate bucket: {e}")
        return False


def notify_human(investigation: Investigation, reason: str):
    message = (
        f"*AutoSOC Human Approval Required*\n"
        f"Investigation: {investigation.investigation_id}\n"
        f"Severity Score: {investigation.triage.severity_score if investigation.triage else 'N/A'}/10\n"
        f"Resource: {investigation.alert.resource if investigation.alert else 'unknown'}\n"
        f"Reason: {reason}\n"
        f"Action Required: Review and approve remediation in GCP Console"
    )
    if SLACK_WEBHOOK_URL:
        try:
            requests.post(SLACK_WEBHOOK_URL, json={"text": message})
            print("Remediation Agent: Slack notification sent")
        except Exception as e:
            print(f"Remediation Agent: Slack notification failed: {e}")
    else:
        print(f"Remediation Agent: HUMAN APPROVAL NEEDED - {message}")


def run(investigation_data: dict):
    investigation = Investigation(**investigation_data)
    investigation_id = investigation.investigation_id
    print(f"Remediation Agent: evaluating {investigation_id}")

    severity_score = investigation.triage.severity_score if investigation.triage else 5
    alert = investigation.alert
    alert_type = alert.alert_type.value if alert else "UNKNOWN"
    resource = alert.resource if alert else ""

    action_taken = ""
    action_successful = False
    action_type = RemediationAction.NO_ACTION
    human_approval = False

    if severity_score <= AUTO_REMEDIATE_MAX_SCORE:
        print(f"Remediation Agent: score {severity_score} <= {AUTO_REMEDIATE_MAX_SCORE} - auto executing")
        action_type = RemediationAction.AUTO_EXECUTE

        if alert_type == "PUBLIC_BUCKET":
            action_taken = f"Removed public access from {resource}"
            action_successful = remove_public_bucket_access(resource)
        else:
            action_taken = f"Logged finding for {alert_type} - no auto-remediation available"
            action_successful = True
    else:
        print(f"Remediation Agent: score {severity_score} > {AUTO_REMEDIATE_MAX_SCORE} - requesting human approval")
        action_type = RemediationAction.HUMAN_APPROVAL_REQUIRED
        human_approval = True
        action_taken = f"Human approval requested for {alert_type} on {resource}"
        action_successful = None
        notify_human(investigation, f"Severity score {severity_score}/10 exceeds auto-remediation threshold")

    remediation_result = RemediationResult(
        investigation_id=investigation_id,
        action_type=action_type,
        action_taken=action_taken,
        action_successful=action_successful,
        human_approval_requested=human_approval,
        remediation_notes=f"Severity score: {severity_score}/10. Action: {action_taken}"
    )

    investigation.remediation = remediation_result
    investigation.status = InvestigationStatus.RESOLVED
    investigation.current_agent = "reporting"
    investigation.agents_completed.append("remediation")
    investigation.last_updated = datetime.now(timezone.utc)

    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(investigation_id)
    doc_ref.update({
        "remediation": remediation_result.model_dump(),
        "status": InvestigationStatus.RESOLVED.value,
        "current_agent": "reporting",
        "agents_completed": firestore.ArrayUnion(["remediation"]),
        "last_updated": datetime.now(timezone.utc)
    })

    payload = investigation.model_dump()
    payload["next_agent"] = "reporting"
    publish_message(TOPIC_FINDINGS_COMPLETE, payload)
    print(f"Remediation Agent: complete - action={action_type.value}, routing to reporting")
    return remediation_result


if __name__ == '__main__':
    test_investigation = {
        "investigation_id": "inv-20260307-test001",
        "status": "REMEDIATING",
        "alert": {
            "investigation_id": "inv-20260307-test001",
            "alert_type": "PUBLIC_BUCKET",
            "severity": "HIGH",
            "resource": "gs://autosoc-sec-evidence",
            "principal": "test-sa@sec-autosoc.iam.gserviceaccount.com",
            "project_id": PROJECT_ID,
            "scc_finding_id": "test-finding-001",
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "triage": {
            "investigation_id": "inv-20260307-test001",
            "severity_score": 5,
            "severity_reasoning": "MEDIUM severity test",
            "principal_roles": [],
            "principal_has_bq_access": False,
            "principal_has_storage_access": False,
            "resource_has_sensitive_tags": False,
            "normal_behavior_deviation": False,
            "recommended_next_agent": "forensics"
        },
        "current_agent": "remediation",
        "agents_completed": ["detection", "orchestrator", "triage", "threat_intel", "forensics"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": PROJECT_ID
    }
    run(test_investigation)