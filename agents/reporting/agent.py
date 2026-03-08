from datetime import datetime, timezone
from google.cloud import bigquery
from google.cloud import firestore
from google import genai
from shared.models import Investigation, Finding, InvestigationStatus
from shared.config import (
    PROJECT_ID, LOCATION,
    BQ_TABLE_FINDINGS,
    FIRESTORE_COLLECTION_INVESTIGATIONS
)

db = firestore.Client(project=PROJECT_ID)
bq_client = bigquery.Client(project=PROJECT_ID)


def generate_nl_summary(investigation: Investigation) -> str:
    try:
        client = genai.Client(vertexai=True, project=PROJECT_ID, location=LOCATION)
        alert = investigation.alert
        triage = investigation.triage
        threat = investigation.threat_intel
        forensics = investigation.forensics
        remediation = investigation.remediation

        prompt = f"""
You are a security analyst. Write a concise 3-sentence incident summary for a CISO.

Incident Details:
- Type: {alert.alert_type.value if alert else 'unknown'}
- Severity Score: {triage.severity_score if triage else 'N/A'}/10
- Resource: {alert.resource if alert else 'unknown'}
- MITRE Technique: {threat.mitre_technique_id if threat else 'N/A'} - {threat.mitre_technique_name if threat else 'N/A'}
- Blast Radius: {len(forensics.blast_radius) if forensics else 0} items affected
- Action Taken: {remediation.action_taken if remediation else 'none'}
- Resolution: {remediation.action_type.value if remediation else 'none'}

Write the summary in plain English. Be specific and actionable.
"""
        response = client.models.generate_content(
            model="gemini-2.0-flash",
            contents=prompt
        )
        return response.text
    except Exception as e:
        print(f"Reporting Agent: Vertex AI summary failed: {e}")
        alert = investigation.alert
        triage = investigation.triage
        remediation = investigation.remediation
        return (
            f"Security incident detected: {alert.alert_type.value if alert else 'unknown'} "
            f"with severity score {triage.severity_score if triage else 'N/A'}/10. "
            f"Action taken: {remediation.action_taken if remediation else 'none'}."
        )


def write_to_bigquery(finding: Finding):
    row = {
        "investigation_id": finding.investigation_id,
        "alert_type": finding.alert_type,
        "severity_score": finding.severity_score,
        "resource_affected": finding.resource_affected,
        "principal": finding.principal,
        "resolution": finding.resolution,
        "time_to_resolve": finding.time_to_resolve,
        "nl_summary": finding.nl_summary,
        "created_at": finding.created_at.isoformat()
    }
    errors = bq_client.insert_rows_json(BQ_TABLE_FINDINGS, [row])
    if errors:
        print(f"Reporting Agent: BigQuery insert errors: {errors}")
    else:
        print(f"Reporting Agent: written to BigQuery successfully")


def run(investigation_data: dict):
    investigation = Investigation(**investigation_data)
    investigation_id = investigation.investigation_id
    print(f"Reporting Agent: generating report for {investigation_id}")

    nl_summary = generate_nl_summary(investigation)
    print(f"Reporting Agent: NL summary generated")

    alert = investigation.alert
    triage = investigation.triage
    remediation = investigation.remediation
    created_at = investigation.created_at
    now = datetime.now(timezone.utc)
    time_to_resolve = int((now - created_at).total_seconds()) if created_at else 0

    finding = Finding(
        investigation_id=investigation_id,
        alert_type=alert.alert_type.value if alert else "UNKNOWN",
        severity_score=triage.severity_score if triage else 0,
        resource_affected=alert.resource if alert else "unknown",
        principal=alert.principal if alert else "unknown",
        resolution=remediation.action_type.value if remediation else "NO_ACTION",
        time_to_resolve=time_to_resolve,
        nl_summary=nl_summary,
        created_at=now
    )

    write_to_bigquery(finding)

    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(investigation_id)
    doc_ref.update({
        "status": InvestigationStatus.RESOLVED.value,
        "current_agent": "complete",
        "agents_completed": firestore.ArrayUnion(["reporting"]),
        "last_updated": now
    })

    print(f"Reporting Agent: investigation {investigation_id} complete")
    print(f"Summary: {nl_summary}")
    return finding


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
            "severity_reasoning": "HIGH severity test",
            "principal_roles": [],
            "principal_has_bq_access": False,
            "principal_has_storage_access": False,
            "resource_has_sensitive_tags": False,
            "normal_behavior_deviation": False,
            "recommended_next_agent": "forensics"
        },
        "threat_intel": {
            "investigation_id": "inv-20260307-test001",
            "mitre_technique_id": "T1530",
            "mitre_technique_name": "Data from Cloud Storage",
            "virustotal_hits": 0,
            "known_malicious_ip": False,
            "threat_confidence": 65,
            "threat_summary": "Mapped to MITRE T1530"
        },
        "forensics": {
            "investigation_id": "inv-20260307-test001",
            "timeline_events": [],
            "blast_radius": ["Public bucket exposure", "Data exfiltration risk"],
            "related_resources": ["gs://autosoc-sec-evidence"],
            "earliest_event": datetime.now(timezone.utc).isoformat(),
            "latest_event": datetime.now(timezone.utc).isoformat(),
            "forensics_summary": "2 blast radius items identified"
        },
        "remediation": {
            "investigation_id": "inv-20260307-test001",
            "action_type": "AUTO_EXECUTE",
            "action_taken": "Removed public access from gs://autosoc-sec-evidence",
            "action_successful": True,
            "human_approval_requested": False,
            "remediation_notes": "Auto-remediated successfully"
        },
        "current_agent": "reporting",
        "agents_completed": ["detection", "orchestrator", "triage", "threat_intel", "forensics", "remediation"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": PROJECT_ID
    }
    run(test_investigation)