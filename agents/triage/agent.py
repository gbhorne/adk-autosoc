import json
from datetime import datetime, timezone
from google.cloud import asset_v1
from google.cloud import firestore
from shared.models import Investigation, TriageResult, InvestigationStatus, SeverityLevel
from shared.config import (
    PROJECT_ID,
    TOPIC_INVESTIGATION_EVENTS,
    FIRESTORE_COLLECTION_INVESTIGATIONS
)
from shared.pubsub_client import publish_message

db = firestore.Client(project=PROJECT_ID)


def get_principal_roles(principal: str) -> list:
    try:
        client = asset_v1.AssetServiceClient()
        scope = f"projects/{PROJECT_ID}"
        query = f"policy:({principal})"
        request = asset_v1.SearchAllIamPoliciesRequest(
            scope=scope,
            query=query,
            page_size=10
        )
        response = client.search_all_iam_policies(request=request)
        roles = []
        for result in response:
            for binding in result.policy.bindings:
                if any(principal in m for m in binding.members):
                    roles.append(binding.role)
        return roles
    except Exception as e:
        print(f"Triage: could not fetch IAM roles: {e}")
        return []


def score_severity(investigation: Investigation, roles: list) -> tuple[int, str]:
    score = 5
    reasoning = []

    alert = investigation.alert
    severity = alert.severity if alert else SeverityLevel.LOW

    if severity == SeverityLevel.CRITICAL:
        score += 3
        reasoning.append("CRITICAL severity from SCC")
    elif severity == SeverityLevel.HIGH:
        score += 2
        reasoning.append("HIGH severity from SCC")
    elif severity == SeverityLevel.MEDIUM:
        score += 1
        reasoning.append("MEDIUM severity from SCC")

    has_bq = any('bigquery' in r.lower() for r in roles)
    has_storage = any('storage' in r.lower() for r in roles)
    is_owner = any('owner' in r.lower() or 'editor' in r.lower() for r in roles)

    if is_owner:
        score += 2
        reasoning.append("Principal has owner/editor role")
    if has_bq:
        score += 1
        reasoning.append("Principal has BigQuery access")
    if has_storage:
        score += 1
        reasoning.append("Principal has Storage access")

    score = min(score, 10)
    return score, " | ".join(reasoning) if reasoning else "Standard scoring applied"


def run(investigation_data: dict):
    investigation = Investigation(**investigation_data)
    investigation_id = investigation.investigation_id
    print(f"Triage Agent: starting triage for {investigation_id}")

    principal = investigation.alert.principal if investigation.alert else None
    roles = get_principal_roles(principal) if principal else []
    print(f"Triage Agent: found {len(roles)} roles for principal")

    score, reasoning = score_severity(investigation, roles)
    has_bq = any('bigquery' in r.lower() for r in roles)
    has_storage = any('storage' in r.lower() for r in roles)

    next_agent = "threat_intel" if score >= 6 else "forensics"

    triage_result = TriageResult(
        investigation_id=investigation_id,
        severity_score=score,
        severity_reasoning=reasoning,
        principal_roles=roles,
        principal_has_bq_access=has_bq,
        principal_has_storage_access=has_storage,
        resource_has_sensitive_tags=False,
        normal_behavior_deviation=score >= 7,
        recommended_next_agent=next_agent
    )

    investigation.triage = triage_result
    investigation.status = InvestigationStatus.INVESTIGATING
    investigation.current_agent = next_agent
    investigation.agents_completed.append("triage")
    investigation.last_updated = datetime.now(timezone.utc)

    doc_ref = db.collection(FIRESTORE_COLLECTION_INVESTIGATIONS).document(investigation_id)
    doc_ref.set({
        "triage": triage_result.model_dump(),
        "status": InvestigationStatus.INVESTIGATING.value,
        "current_agent": next_agent,
        "agents_completed": ["detection", "triage"],
        "last_updated": datetime.now(timezone.utc),
        "investigation_id": investigation_id,
        "project_id": PROJECT_ID
    }, merge=True)

    payload = investigation.model_dump()
    payload["next_agent"] = next_agent
    publish_message(TOPIC_INVESTIGATION_EVENTS, payload)
    print(f"Triage Agent: score={score}/10 routing to {next_agent}")
    return triage_result


if __name__ == '__main__':
    test_investigation = {
        "investigation_id": "inv-20260307-test001",
        "status": "TRIAGING",
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
        "current_agent": "triage",
        "agents_completed": ["detection", "orchestrator"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": PROJECT_ID
    }
    run(test_investigation)