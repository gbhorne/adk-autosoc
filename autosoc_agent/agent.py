from google.adk.agents import Agent
from agents.detection.agent import process_scc_finding
from agents.triage.agent import run as triage_run
from agents.threat_intel.agent import run as threat_intel_run
from agents.forensics.agent import run as forensics_run
from agents.remediation.agent import run as remediation_run
from agents.reporting.agent import run as reporting_run
from shared.config import PROJECT_ID
from datetime import datetime, timezone


def tool_detect_finding(
    finding_id: str,
    category: str,
    resource_name: str,
    severity: str,
    principal: str
) -> dict:
    """Process a raw SCC security finding and classify it into a structured alert."""
    finding = {
        "findingId": finding_id,
        "category": category,
        "resourceName": resource_name,
        "projectId": PROJECT_ID,
        "severity": severity,
        "principal": principal
    }
    alert = process_scc_finding(finding)
    return alert.model_dump()


def tool_triage(
    investigation_id: str,
    alert_type: str,
    severity: str,
    resource: str,
    principal: str,
    project_id: str,
    scc_finding_id: str
) -> dict:
    """Enrich the alert with IAM context and score severity 1-10."""
    investigation_data = {
        "investigation_id": investigation_id,
        "status": "TRIAGING",
        "alert": {
            "investigation_id": investigation_id,
            "alert_type": alert_type,
            "severity": severity,
            "resource": resource,
            "principal": principal,
            "project_id": project_id,
            "scc_finding_id": scc_finding_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "current_agent": "triage",
        "agents_completed": ["detection"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": project_id
    }
    result = triage_run(investigation_data)
    return result.model_dump()


def tool_threat_intel(
    investigation_id: str,
    alert_type: str,
    severity: str,
    resource: str,
    principal: str,
    project_id: str,
    scc_finding_id: str,
    severity_score: int
) -> dict:
    """Map the finding to MITRE ATT&CK techniques and assess threat confidence."""
    investigation_data = {
        "investigation_id": investigation_id,
        "status": "INVESTIGATING",
        "alert": {
            "investigation_id": investigation_id,
            "alert_type": alert_type,
            "severity": severity,
            "resource": resource,
            "principal": principal,
            "project_id": project_id,
            "scc_finding_id": scc_finding_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "triage": {
            "investigation_id": investigation_id,
            "severity_score": severity_score,
            "severity_reasoning": "Scored by triage agent",
            "principal_roles": [],
            "principal_has_bq_access": False,
            "principal_has_storage_access": False,
            "resource_has_sensitive_tags": False,
            "normal_behavior_deviation": severity_score >= 7,
            "recommended_next_agent": "threat_intel"
        },
        "current_agent": "threat_intel",
        "agents_completed": ["detection", "triage"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": project_id
    }
    result = threat_intel_run(investigation_data)
    return result.model_dump()


def tool_forensics(
    investigation_id: str,
    alert_type: str,
    severity: str,
    resource: str,
    principal: str,
    project_id: str,
    scc_finding_id: str,
    severity_score: int
) -> dict:
    """Pull audit logs, build a timeline, and identify blast radius."""
    investigation_data = {
        "investigation_id": investigation_id,
        "status": "INVESTIGATING",
        "alert": {
            "investigation_id": investigation_id,
            "alert_type": alert_type,
            "severity": severity,
            "resource": resource,
            "principal": principal,
            "project_id": project_id,
            "scc_finding_id": scc_finding_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "triage": {
            "investigation_id": investigation_id,
            "severity_score": severity_score,
            "severity_reasoning": "Scored by triage agent",
            "principal_roles": [],
            "principal_has_bq_access": False,
            "principal_has_storage_access": False,
            "resource_has_sensitive_tags": False,
            "normal_behavior_deviation": severity_score >= 7,
            "recommended_next_agent": "forensics"
        },
        "current_agent": "forensics",
        "agents_completed": ["detection", "triage", "threat_intel"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": project_id
    }
    result = forensics_run(investigation_data)
    return result.model_dump()


def tool_remediate(
    investigation_id: str,
    alert_type: str,
    severity: str,
    resource: str,
    principal: str,
    project_id: str,
    scc_finding_id: str,
    severity_score: int
) -> dict:
    """Auto-execute low risk remediations or request human approval for high risk."""
    investigation_data = {
        "investigation_id": investigation_id,
        "status": "REMEDIATING",
        "alert": {
            "investigation_id": investigation_id,
            "alert_type": alert_type,
            "severity": severity,
            "resource": resource,
            "principal": principal,
            "project_id": project_id,
            "scc_finding_id": scc_finding_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "triage": {
            "investigation_id": investigation_id,
            "severity_score": severity_score,
            "severity_reasoning": "Scored by triage agent",
            "principal_roles": [],
            "principal_has_bq_access": False,
            "principal_has_storage_access": False,
            "resource_has_sensitive_tags": False,
            "normal_behavior_deviation": severity_score >= 7,
            "recommended_next_agent": "remediation"
        },
        "current_agent": "remediation",
        "agents_completed": ["detection", "triage", "threat_intel", "forensics"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": project_id
    }
    result = remediation_run(investigation_data)
    return result.model_dump()


def tool_report(
    investigation_id: str,
    alert_type: str,
    severity: str,
    resource: str,
    principal: str,
    project_id: str,
    scc_finding_id: str,
    severity_score: int,
    action_taken: str
) -> dict:
    """Generate a Gemini NL summary and write the completed investigation to BigQuery."""
    investigation_data = {
        "investigation_id": investigation_id,
        "status": "REMEDIATING",
        "alert": {
            "investigation_id": investigation_id,
            "alert_type": alert_type,
            "severity": severity,
            "resource": resource,
            "principal": principal,
            "project_id": project_id,
            "scc_finding_id": scc_finding_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        },
        "triage": {
            "investigation_id": investigation_id,
            "severity_score": severity_score,
            "severity_reasoning": "Scored by triage agent",
            "principal_roles": [],
            "principal_has_bq_access": False,
            "principal_has_storage_access": False,
            "resource_has_sensitive_tags": False,
            "normal_behavior_deviation": severity_score >= 7,
            "recommended_next_agent": "reporting"
        },
        "threat_intel": {
            "investigation_id": investigation_id,
            "mitre_technique_id": "T1530",
            "mitre_technique_name": "Data from Cloud Storage",
            "virustotal_hits": 0,
            "known_malicious_ip": False,
            "threat_confidence": 65,
            "threat_summary": "Mapped to MITRE T1530"
        },
        "forensics": {
            "investigation_id": investigation_id,
            "timeline_events": [],
            "blast_radius": ["Public bucket exposure"],
            "related_resources": [resource],
            "earliest_event": datetime.now(timezone.utc).isoformat(),
            "latest_event": datetime.now(timezone.utc).isoformat(),
            "forensics_summary": "Forensic analysis complete"
        },
        "remediation": {
            "investigation_id": investigation_id,
            "action_type": "AUTO_EXECUTE",
            "action_taken": action_taken,
            "action_successful": True,
            "human_approval_requested": False,
            "remediation_notes": "Remediation complete"
        },
        "current_agent": "reporting",
        "agents_completed": ["detection", "triage", "threat_intel", "forensics", "remediation"],
        "created_at": datetime.now(timezone.utc).isoformat(),
        "last_updated": datetime.now(timezone.utc).isoformat(),
        "project_id": project_id
    }
    result = reporting_run(investigation_data)
    return result.model_dump()


root_agent = Agent(
    name="autosoc_orchestrator",
    model="gemini-2.5-flash",
    description=(
        "AutoSOC Orchestrator — an autonomous security operations agent that "
        "investigates GCP security findings end to end."
    ),
    instruction="""
You are an autonomous security operations center (AutoSOC) orchestrator running on GCP.

When given a security finding, run a complete investigation by calling tools in this exact order:

1. tool_detect_finding — pass the raw finding fields directly
2. tool_triage — pass investigation_id, alert_type, severity, resource, principal, project_id, scc_finding_id from step 1
3. tool_threat_intel — pass same fields plus severity_score from step 2
4. tool_forensics — pass same fields plus severity_score
5. tool_remediate — pass same fields plus severity_score
6. tool_report — pass same fields plus severity_score and action_taken from step 5

After each tool call summarize what was found.
At the end provide a complete incident summary.
Always complete all 6 steps. Never skip a step.
""",
    tools=[
        tool_detect_finding,
        tool_triage,
        tool_threat_intel,
        tool_forensics,
        tool_remediate,
        tool_report
    ]
)