import json
from datetime import datetime, timezone
from google.cloud import firestore
from shared.models import Investigation, InvestigationStatus, Alert
from shared.config import (
    FIRESTORE_COLLECTION_INVESTIGATIONS,
    TOPIC_INVESTIGATION_EVENTS,
    PROJECT_ID
)
from shared.pubsub_client import publish_message, pull_messages, acknowledge_message
from shared.config import SUB_INVESTIGATION_EVENTS


db = firestore.Client(project=PROJECT_ID)


def create_investigation(alert: Alert) -> Investigation:
    investigation = Investigation(
        investigation_id=alert.investigation_id,
        status=InvestigationStatus.NEW,
        alert=alert,
        current_agent="triage",
        agents_completed=["detection"],
        created_at=datetime.now(timezone.utc),
        last_updated=datetime.now(timezone.utc),
        project_id=alert.project_id
    )
    return investigation


def save_investigation(investigation: Investigation):
    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(
        investigation.investigation_id
    )
    doc_ref.set(investigation.model_dump())
    print(f"Orchestrator: saved investigation {investigation.investigation_id} to Firestore")


def get_investigation(investigation_id: str) -> dict:
    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(investigation_id)
    doc = doc_ref.get()
    if doc.exists:
        return doc.to_dict()
    return None


def update_investigation_status(investigation_id: str, status: InvestigationStatus, current_agent: str, agent_completed: str):
    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(investigation_id)
    doc_ref.update({
        "status": status.value,
        "current_agent": current_agent,
        "agents_completed": firestore.ArrayUnion([agent_completed]),
        "last_updated": datetime.now(timezone.utc)
    })
    print(f"Orchestrator: updated {investigation_id} status to {status.value}")


def route_to_next_agent(investigation: Investigation):
    alert = investigation.alert
    severity = alert.severity.value if alert else "LOW"

    next_topic = TOPIC_INVESTIGATION_EVENTS
    payload = investigation.model_dump()
    payload["next_agent"] = "triage"

    publish_message(next_topic, payload)
    print(f"Orchestrator: routed {investigation.investigation_id} to triage agent")


def run(alert_data: dict):
    print(f"Orchestrator: received alert {alert_data.get('investigation_id', 'unknown')}")

    alert = Alert(**alert_data)
    investigation = create_investigation(alert)
    investigation.status = InvestigationStatus.TRIAGING

    save_investigation(investigation)
    route_to_next_agent(investigation)

    print(f"Orchestrator: investigation {investigation.investigation_id} initiated")
    return investigation


if __name__ == '__main__':
    test_alert = {
        "investigation_id": "inv-20260307-test001",
        "alert_type": "PUBLIC_BUCKET",
        "severity": "HIGH",
        "resource": "gs://test-exposed-bucket",
        "principal": "test-sa@sec-autosoc.iam.gserviceaccount.com",
        "project_id": PROJECT_ID,
        "scc_finding_id": "test-finding-001",
        "timestamp": datetime.now(timezone.utc).isoformat()
    }
    run(test_alert)