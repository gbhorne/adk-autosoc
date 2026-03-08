from datetime import datetime, timezone
from google.cloud import firestore
from shared.models import Investigation, ThreatIntelResult, InvestigationStatus
from shared.config import PROJECT_ID, TOPIC_INVESTIGATION_EVENTS, FIRESTORE_COLLECTION_INVESTIGATIONS
from shared.pubsub_client import publish_message

db = firestore.Client(project=PROJECT_ID)

MITRE_MAPPINGS = {
    "PUBLIC_BUCKET": ("T1530", "Data from Cloud Storage"),
    "IAM_ANOMALY": ("T1078", "Valid Accounts"),
    "DATA_ACCESS": ("T1530", "Data from Cloud Storage"),
    "NETWORK_ANOMALY": ("T1046", "Network Service Discovery"),
    "MALWARE": ("T1204", "User Execution"),
    "PRIVILEGE_ESCALATION": ("T1548", "Abuse Elevation Control Mechanism"),
    "UNKNOWN": ("T1078", "Valid Accounts"),
}


def lookup_mitre(alert_type: str) -> tuple:
    return MITRE_MAPPINGS.get(alert_type, ("T1078", "Valid Accounts"))


def check_known_threats(resource: str, principal: str) -> tuple[bool, int]:
    suspicious_patterns = ["public", "exposed", "test", "temp", "backup"]
    resource_lower = resource.lower() if resource else ""
    is_suspicious = any(p in resource_lower for p in suspicious_patterns)
    confidence = 65 if is_suspicious else 30
    return is_suspicious, confidence


def run(investigation_data: dict):
    investigation = Investigation(**investigation_data)
    investigation_id = investigation.investigation_id
    print(f"Threat Intel Agent: analyzing {investigation_id}")

    alert = investigation.alert
    alert_type = alert.alert_type.value if alert else "UNKNOWN"
    resource = alert.resource if alert else ""
    principal = alert.principal if alert else ""

    mitre_id, mitre_name = lookup_mitre(alert_type)
    is_suspicious, confidence = check_known_threats(resource, principal)

    print(f"Threat Intel Agent: mapped to MITRE {mitre_id} - {mitre_name}")
    print(f"Threat Intel Agent: threat confidence {confidence}%")

    threat_result = ThreatIntelResult(
        investigation_id=investigation_id,
        mitre_technique_id=mitre_id,
        mitre_technique_name=mitre_name,
        virustotal_hits=0,
        known_malicious_ip=False,
        threat_confidence=confidence,
        threat_summary=f"Mapped to MITRE {mitre_id} ({mitre_name}). Resource pattern analysis confidence: {confidence}%"
    )

    investigation.threat_intel = threat_result
    investigation.status = InvestigationStatus.INVESTIGATING
    investigation.current_agent = "forensics"
    investigation.agents_completed.append("threat_intel")
    investigation.last_updated = datetime.now(timezone.utc)

    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(investigation_id)
    doc_ref.update({
        "threat_intel": threat_result.model_dump(),
        "current_agent": "forensics",
        "agents_completed": firestore.ArrayUnion(["threat_intel"]),
        "last_updated": datetime.now(timezone.utc)
    })

    payload = investigation.model_dump()
    payload["next_agent"] = "forensics"
    publish_message(TOPIC_INVESTIGATION_EVENTS, payload)
    print(f"Threat Intel Agent: complete, routing to forensics")
    return threat_result


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
        "current_agent": "threat_intel",
        "agents_completed": ["detection", "orchestrator", "triage"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": PROJECT_ID
    }
    run(test_investigation)