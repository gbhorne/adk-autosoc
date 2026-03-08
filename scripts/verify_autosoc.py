"""
AutoSOC Verification Script
Runs end-to-end infrastructure and agent checks to confirm the system is
fully operational. Prints a pass/fail result for every component.
"""

import os
import sys
import json
import uuid
from datetime import datetime, timezone
from dotenv import load_dotenv

load_dotenv()

PROJECT_ID = os.getenv("PROJECT_ID", "sec-autosoc")
LOCATION = os.getenv("LOCATION", "us-central1")
GCS_BUCKET = os.getenv("GCS_EVIDENCE_BUCKET", "autosoc-sec-evidence")

PASS = "PASS"
FAIL = "FAIL"
SKIP = "SKIP"

results = []


def check(label, fn):
    try:
        msg = fn()
        results.append((PASS, label, msg))
        print(f"  [{PASS}] {label}: {msg}")
    except Exception as e:
        results.append((FAIL, label, str(e)))
        print(f"  [{FAIL}] {label}: {e}")


def section(title):
    print(f"\n{'='*60}")
    print(f"  {title}")
    print(f"{'='*60}")


# ─── GCP AUTH ────────────────────────────────────────────────

section("GCP Authentication")


def check_adc():
    import google.auth
    credentials, project = google.auth.default()
    return f"project={project}"

check("Application Default Credentials", check_adc)


def check_project():
    from google.cloud import resourcemanager_v3
    client = resourcemanager_v3.ProjectsClient()
    project = client.get_project(name=f"projects/{PROJECT_ID}")
    return f"project_id={project.project_id}, state={project.state.name}"

check("GCP Project accessible", check_project)


# ─── PUB/SUB ─────────────────────────────────────────────────

section("Pub/Sub Topics and Subscriptions")

TOPICS = [
    "scc-findings-raw",
    "investigation-events",
    "remediation-requests",
    "findings-complete",
]

SUBSCRIPTIONS = [
    "scc-findings-sub",
    "investigation-events-sub",
    "remediation-requests-sub",
    "findings-complete-sub",
]


def make_topic_check(topic):
    def fn():
        from google.cloud import pubsub_v1
        client = pubsub_v1.PublisherClient()
        name = f"projects/{PROJECT_ID}/topics/{topic}"
        t = client.get_topic(request={"topic": name})
        return f"exists: {t.name}"
    return fn


def make_sub_check(sub):
    def fn():
        from google.cloud import pubsub_v1
        client = pubsub_v1.SubscriberClient()
        name = f"projects/{PROJECT_ID}/subscriptions/{sub}"
        s = client.get_subscription(request={"subscription": name})
        return f"exists, ack_deadline={s.ack_deadline_seconds}s"
    return fn


for topic in TOPICS:
    check(f"Topic: {topic}", make_topic_check(topic))

for sub in SUBSCRIPTIONS:
    check(f"Subscription: {sub}", make_sub_check(sub))


# ─── BIGQUERY ─────────────────────────────────────────────────

section("BigQuery Dataset and Tables")

BQ_TABLES = ["findings", "baselines", "timelines"]


def check_bq_dataset():
    from google.cloud import bigquery
    client = bigquery.Client(project=PROJECT_ID)
    dataset = client.get_dataset("autosoc_data")
    return f"dataset_id={dataset.dataset_id}, location={dataset.location}"

check("BigQuery dataset: autosoc_data", check_bq_dataset)


def make_table_check(table):
    def fn():
        from google.cloud import bigquery
        client = bigquery.Client(project=PROJECT_ID)
        t = client.get_table(f"{PROJECT_ID}.autosoc_data.{table}")
        return f"rows={t.num_rows}, schema_fields={len(t.schema)}"
    return fn


for table in BQ_TABLES:
    check(f"BigQuery table: {table}", make_table_check(table))


# ─── FIRESTORE ────────────────────────────────────────────────

section("Firestore")


def check_firestore_write_read():
    from google.cloud import firestore
    db = firestore.Client(project=PROJECT_ID)
    test_id = f"verify-{uuid.uuid4().hex[:8]}"
    doc_ref = db.collection("verify_checks").document(test_id)
    doc_ref.set({
        "test": True,
        "timestamp": datetime.now(timezone.utc),
        "verification_id": test_id
    })
    doc = doc_ref.get()
    assert doc.exists, "Document not found after write"
    doc_ref.delete()
    return f"write/read/delete successful, doc_id={test_id}"

check("Firestore write/read/delete", check_firestore_write_read)


def check_firestore_investigations():
    from google.cloud import firestore
    db = firestore.Client(project=PROJECT_ID)
    docs = list(db.collection("investigations").limit(5).stream())
    return f"investigations collection accessible, sample_count={len(docs)}"

check("Firestore investigations collection", check_firestore_investigations)


# ─── CLOUD STORAGE ────────────────────────────────────────────

section("Cloud Storage")


def check_gcs_bucket():
    from google.cloud import storage
    client = storage.Client(project=PROJECT_ID)
    bucket = client.get_bucket(GCS_BUCKET)
    return f"bucket={bucket.name}, location={bucket.location}"

check(f"GCS bucket: {GCS_BUCKET}", check_gcs_bucket)


def check_gcs_write():
    from google.cloud import storage
    client = storage.Client(project=PROJECT_ID)
    bucket = client.bucket(GCS_BUCKET)
    blob_name = f"verify/test-{uuid.uuid4().hex[:8]}.txt"
    blob = bucket.blob(blob_name)
    blob.upload_from_string("autosoc verification check")
    blob.delete()
    return f"write/delete to {GCS_BUCKET} successful"

check("GCS write/delete", check_gcs_write)


# ─── VERTEX AI / GEMINI ───────────────────────────────────────

section("Vertex AI / Gemini")


def check_gemini():
    from google import genai
    client = genai.Client(
        vertexai=True,
        project=PROJECT_ID,
        location=LOCATION
    )
    response = client.models.generate_content(
        model="gemini-2.0-flash",
        contents="Reply with exactly: AutoSOC verification successful"
    )
    text = response.text.strip()
    assert "AutoSOC" in text or "verification" in text, f"Unexpected response: {text}"
    return f"Gemini responded: {text[:60]}"

check("Vertex AI Gemini model", check_gemini)


# ─── CLOUD ASSET INVENTORY ────────────────────────────────────

section("Cloud Asset Inventory")


def check_asset_api():
    from google.cloud import asset_v1
    client = asset_v1.AssetServiceClient()
    request = asset_v1.SearchAllIamPoliciesRequest(
        scope=f"projects/{PROJECT_ID}",
        query="",
        page_size=1
    )
    response = client.search_all_iam_policies(request=request)
    results_list = list(response)
    return f"IAM policy search returned {len(results_list)} result(s)"

check("Cloud Asset Inventory API", check_asset_api)


# ─── CLOUD LOGGING ────────────────────────────────────────────

section("Cloud Logging")


def check_logging():
    from google.cloud import logging_v2
    client = logging_v2.Client(project=PROJECT_ID)
    entries = list(client.list_entries(
        max_results=3,
        page_size=3
    ))
    return f"log entries accessible, count={len(entries)}"

check("Cloud Logging API", check_logging)


# ─── AGENT IMPORTS ────────────────────────────────────────────

section("Agent Module Imports")

AGENT_MODULES = [
    ("shared.config", "shared config"),
    ("shared.models", "shared models"),
    ("shared.pubsub_client", "pubsub client"),
    ("agents.detection.agent", "detection agent"),
    ("agents.triage.agent", "triage agent"),
    ("agents.threat_intel.agent", "threat intel agent"),
    ("agents.forensics.agent", "forensics agent"),
    ("agents.remediation.agent", "remediation agent"),
    ("agents.reporting.agent", "reporting agent"),
]


def make_import_check(module, label):
    def fn():
        import importlib
        mod = importlib.import_module(module)
        return f"imported successfully"
    return fn


for module, label in AGENT_MODULES:
    check(f"Import: {label}", make_import_check(module, label))


# ─── END-TO-END INVESTIGATION ─────────────────────────────────

section("End-to-End Agent Pipeline")


def check_detection_agent():
    from agents.detection.agent import process_scc_finding
    finding = {
        "findingId": f"verify-{uuid.uuid4().hex[:8]}",
        "category": "PUBLIC_BUCKET",
        "resourceName": "gs://autosoc-verify-bucket",
        "projectId": PROJECT_ID,
        "severity": "HIGH",
        "principal": "verify-sa@sec-autosoc.iam.gserviceaccount.com"
    }
    alert = process_scc_finding(finding)
    assert alert.investigation_id.startswith("inv-"), "Invalid investigation_id format"
    assert alert.alert_type is not None
    return f"alert created: {alert.investigation_id}, type={alert.alert_type.value}"

check("Detection agent: classify finding", check_detection_agent)


def check_bigquery_findings():
    from google.cloud import bigquery
    client = bigquery.Client(project=PROJECT_ID)
    query = f"""
        SELECT investigation_id, alert_type, severity_score, created_at
        FROM `{PROJECT_ID}.autosoc_data.findings`
        ORDER BY created_at DESC
        LIMIT 5
    """
    rows = list(client.query(query).result())
    if len(rows) == 0:
        return "table exists, no findings yet (run a full investigation first)"
    latest = rows[0]
    return f"latest finding: {latest['investigation_id']}, score={latest['severity_score']}"

check("BigQuery: findings table queryable", check_bigquery_findings)


def check_firestore_investigations_count():
    from google.cloud import firestore
    db = firestore.Client(project=PROJECT_ID)
    docs = list(db.collection("investigations").stream())
    if len(docs) == 0:
        return "collection exists, no investigations yet (run a full investigation first)"
    latest = sorted(docs, key=lambda d: d.id, reverse=True)[0]
    data = latest.to_dict()
    status = data.get("status", "unknown")
    return f"total investigations: {len(docs)}, latest: {latest.id}, status={status}"

check("Firestore: investigations count", check_firestore_investigations_count)


# ─── SUMMARY ─────────────────────────────────────────────────

section("Verification Summary")

passed = [r for r in results if r[0] == PASS]
failed = [r for r in results if r[0] == FAIL]
skipped = [r for r in results if r[0] == SKIP]

print(f"\n  Total checks : {len(results)}")
print(f"  Passed       : {len(passed)}")
print(f"  Failed       : {len(failed)}")
print(f"  Skipped      : {len(skipped)}")

if failed:
    print(f"\n  FAILED CHECKS:")
    for _, label, msg in failed:
        print(f"    - {label}: {msg}")
    print(f"\n  STATUS: INCOMPLETE - {len(failed)} check(s) require attention")
    sys.exit(1)
else:
    print(f"\n  STATUS: ALL CHECKS PASSED - AutoSOC infrastructure is fully operational")
    sys.exit(0)
