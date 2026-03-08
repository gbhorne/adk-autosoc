# AutoSOC: Autonomous Security Operations Center

A production-grade multi-agent security investigation system built on GCP using Google Agent Development Kit (ADK) and Gemini. AutoSOC autonomously detects, triages, investigates, remediates, and reports on GCP security findings end to end with no human intervention below the configurable risk threshold.

---

## Architecture

![AutoSOC Architecture](docs/architecture.svg)

AutoSOC is composed of seven specialized agents that communicate through GCP-native services. Each agent has a discrete responsibility, a defined input contract, and a defined output contract. No agent has direct knowledge of any other agent's implementation.

---

## Agent Pipeline

### 1. Detection Agent
Ingests raw Security Command Center findings from a Pub/Sub subscription. Classifies each finding into a structured `Alert` with an `AlertType` enum (`PUBLIC_BUCKET`, `PRIVILEGE_ESCALATION`, `EXFILTRATION`, `IAM_ANOMALY`, `BRUTE_FORCE`, `MALWARE`, `NETWORK_ANOMALY`), a `SeverityLevel`, and a unique investigation ID in the format `inv-YYYYMMDD-{uuid8}`.

### 2. Orchestrator Agent
Receives the classified alert and creates an `Investigation` state object in Firestore. Routes the investigation to downstream agents and tracks which agents have completed. Manages the state machine transitions: `OPEN` -> `TRIAGING` -> `INVESTIGATING` -> `REMEDIATING` -> `RESOLVED`.

### 3. Triage Agent
Enriches the alert using Cloud Asset Inventory to retrieve IAM roles held by the principal. Scores severity 1-10 using a weighted formula that combines SCC severity, role sensitivity (owner/editor = +2, BigQuery access = +1, Storage access = +1), and behavioral deviation. Investigations scoring >= 6 route to Threat Intel; below 6 route directly to Forensics.

### 4. Threat Intel Agent
Maps the alert type to MITRE ATT&CK techniques using a structured lookup:
- `PUBLIC_BUCKET` -> T1530 (Data from Cloud Storage)
- `PRIVILEGE_ESCALATION` / `IAM_ANOMALY` -> T1078 (Valid Accounts)
- `EXFILTRATION` -> T1537 (Transfer Data to Cloud Account)
- `BRUTE_FORCE` -> T1110 (Brute Force)

Produces a confidence score based on resource name patterns, principal characteristics, and known IOC matches.

### 5. Forensics Agent
Pulls the last 24 hours of Cloud Audit Log entries for the affected resource and principal using the Cloud Logging API. Builds a chronological event timeline. Constructs a blast radius list of resources and principals potentially affected by the incident.

### 6. Remediation Agent
Applies a configurable auto-remediation threshold (default: score <= 6 = auto-execute, score > 6 = human approval required). Auto-executed actions include removing public access prevention enforcement on GCS buckets and disabling overprivileged service accounts. High-risk actions trigger a Slack webhook with the investigation ID, severity score, resource, and recommended action.

### 7. Reporting Agent
Generates a three-sentence CISO-ready natural language summary using Gemini via Vertex AI. Writes a structured `Finding` record to BigQuery `autosoc_data.findings`. Updates the Firestore investigation document to `RESOLVED` with a resolution timestamp.

---

## Tech Stack

| Component | Technology |
|---|---|
| Agent framework | Google ADK 1.26 |
| LLM | Gemini 2.5 Flash (ADK UI) / Gemini 2.0 Flash (Vertex AI reporting) |
| Agent memory | Firestore (investigation state) |
| Event bus | Cloud Pub/Sub (4 topics, 4 subscriptions) |
| Data store | BigQuery (findings, baselines, timelines) |
| Evidence store | Cloud Storage |
| IAM enrichment | Cloud Asset Inventory API |
| Audit logs | Cloud Logging API |
| Human gate | Slack webhook |
| Dev UI | ADK Web (localhost:8000) |

---

## GCP Infrastructure

### APIs Enabled
`run.googleapis.com`, `cloudfunctions.googleapis.com`, `pubsub.googleapis.com`, `firestore.googleapis.com`, `bigquery.googleapis.com`, `securitycenter.googleapis.com`, `cloudasset.googleapis.com`, `aiplatform.googleapis.com`, `logging.googleapis.com`, `artifactregistry.googleapis.com`, `storage.googleapis.com`

### Service Account Roles
`bigquery.dataEditor`, `bigquery.jobUser`, `pubsub.editor`, `datastore.user`, `logging.viewer`, `securitycenter.findingsViewer`, `cloudasset.viewer`, `run.invoker`, `aiplatform.user`, `storage.admin`

### Pub/Sub Topics
| Topic | Subscription |
|---|---|
| scc-findings-raw | scc-findings-sub |
| investigation-events | investigation-events-sub |
| remediation-requests | remediation-requests-sub |
| findings-complete | findings-complete-sub |

### BigQuery
Dataset: `autosoc_data` with tables: `findings`, `baselines`, `timelines`

### Firestore
Default database, Native mode, `nam5` (US multi-region), collection: `investigations`

---

## Setup

### Prerequisites
- Python 3.11+
- GCP project with billing enabled
- `gcloud` CLI authenticated
- ADC configured: `gcloud auth application-default login`

### Install

```bash
git clone https://github.com/gbhorne/adk-autosoc.git
cd adk-autosoc
python -m venv venv
source venv/bin/activate  # Windows: venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

### Configure

```bash
cp .env.example .env
# Edit .env with your PROJECT_ID, LOCATION, GCS_EVIDENCE_BUCKET
# Add GOOGLE_API_KEY from aistudio.google.com/apikey
```

### Verify Infrastructure

```bash
python -m scripts.verify_autosoc
```

All checks should return PASS before running the agents.

### Run ADK Web UI

```bash
adk web .
```

Open `http://localhost:8000`, select `autosoc_agent`, and submit a finding prompt.

---

## Sample Investigation Prompt

```
Investigate this GCP security finding:

Finding ID: finding-001
Category: PUBLIC_BUCKET
Resource: gs://your-bucket-name
Severity: HIGH
Principal: your-service-account@your-project.iam.gserviceaccount.com

Run the full investigation through all 6 steps.
```

---

## Supported Finding Categories

| Category | MITRE Technique | Auto-Remediation |
|---|---|---|
| PUBLIC_BUCKET | T1530 | Yes (score <= 6) |
| PRIVILEGE_ESCALATION | T1078 | No (always human approval) |
| IAM_ANOMALY | T1078 | Threshold-based |
| EXFILTRATION | T1537 | No |
| BRUTE_FORCE | T1110 | Threshold-based |
| MALWARE | T1204 | No |
| NETWORK_ANOMALY | T1046 | No |

---

## Verification

```bash
python -m scripts.verify_autosoc
```

This script checks all infrastructure components and runs a live end-to-end detection test. A full verification pass output is included in [`docs/VERIFICATION_PASS.txt`](docs/VERIFICATION_PASS.txt), confirming 33/33 checks passing across GCP authentication, all 4 Pub/Sub topics and subscriptions, BigQuery dataset and tables, Firestore, Cloud Storage, Vertex AI Gemini, Cloud Asset Inventory, Cloud Logging, all 9 agent module imports, and a live end-to-end detection test.

---

## Repository Structure

```
adk-autosoc/
    autosoc_agent/
        __init__.py
        agent.py              # ADK root_agent with 6 tools
    agents/
        detection/agent.py
        orchestrator/agent.py
        triage/agent.py
        threat_intel/agent.py
        forensics/agent.py
        remediation/agent.py
        reporting/agent.py
    shared/
        config.py             # All constants and configuration
        models.py             # Pydantic models for all data structures
        pubsub_client.py      # Pub/Sub publish/subscribe utilities
    docs/
        architecture.svg
        VERIFICATION_PASS.txt
        QA.md                 # In-depth technical Q&A
    scripts/
        verify_autosoc.py
    requirements.txt
```

---

## Screenshots

### PUBLIC_BUCKET Investigation

**Step 1: Detection and triage start**
![Detection and triage start](docs/screenshots/autosoc_agent_01_detection_triage_start.png)

**Step 2: Triage complete, routing to threat intel**
![Triage complete](docs/screenshots/autosoc_agent_02_triage_complete_threat_intel.png)

**Step 3: Forensics complete, routing to remediation**
![Forensics complete](docs/screenshots/autosoc_agent_03_forensics_complete_remediation.png)

**Step 4: Report complete - full incident summary**
![Report complete](docs/screenshots/autosoc_agent_04_report_complete_incident_summary.png)

**ADK trace: full execution tree with timing**
![ADK trace execution tree](docs/screenshots/autosoc_agent_05_adk_trace_execution_tree.png)

### PRIVILEGE_ESCALATION Investigation

**Detection and triage - CRITICAL severity**
![Privilege escalation detection](docs/screenshots/autosoc_agent_06_priv_escalation_detection_triage.png)

**Triage score 8/10 - MITRE T1078 mapped**
![Triage score 8](docs/screenshots/autosoc_agent_07_priv_escalation_triage_score8_mitre_t1078.png)

**Forensics - lateral movement blast radius**
![Forensics lateral movement](docs/screenshots/autosoc_agent_08_priv_escalation_forensics_lateral_movement.png)

**Reporting - CISO-ready summary**
![CISO summary](docs/screenshots/autosoc_agent_09_priv_escalation_report_ciso_summary.png)

**ADK trace - 43 second resolution**
![Trace 43 seconds](docs/screenshots/autosoc_agent_10_priv_escalation_trace_43sec.png)

---

## Investigation Examples

### PUBLIC_BUCKET (Score 7/10)
- MITRE: T1530 (Data from Cloud Storage)
- Blast radius: all objects publicly accessible, service accounts with storage access implicated
- Remediation: human approval requested (score > 6)
- Resolution time: 28 seconds

### PRIVILEGE_ESCALATION (Score 8/10)
- MITRE: T1078 (Valid Accounts)
- Blast radius: elevated permissions allow lateral movement, all resources accessible by principal at risk
- Remediation: human approval requested (CRITICAL severity)
- Resolution time: 43 seconds

---

## Q&A

See [docs/QA.md](docs/QA.md) for in-depth answers covering ADK vs Vertex AI Agent Builder, inter-agent communication design, human-in-the-loop architecture, Firestore vs BigQuery, severity scoring, failure recovery, production deployment, cost, and security controls.

---

## Disclaimer

Built as a portfolio project for educational and demonstration purposes. Not intended for production use without further hardening, security review, and compliance validation.

---

## Author

**Gregory B. Horne**
Cloud Solutions Architect

[GitHub: gbhorne](https://github.com/gbhorne) | [LinkedIn](https://linkedin.com/in/gbhorne)

---

## License

MIT
