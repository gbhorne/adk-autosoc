import os
from dotenv import load_dotenv

load_dotenv()

PROJECT_ID = os.getenv('PROJECT_ID', 'sec-autosoc')
LOCATION = os.getenv('LOCATION', 'us-central1')
TOPIC_SCC_FINDINGS_RAW = f'projects/{PROJECT_ID}/topics/scc-findings-raw'
TOPIC_INVESTIGATION_EVENTS = f'projects/{PROJECT_ID}/topics/investigation-events'
TOPIC_REMEDIATION_REQUESTS = f'projects/{PROJECT_ID}/topics/remediation-requests'
TOPIC_FINDINGS_COMPLETE = f'projects/{PROJECT_ID}/topics/findings-complete'
SUB_SCC_FINDINGS = f'projects/{PROJECT_ID}/subscriptions/scc-findings-sub'
SUB_INVESTIGATION_EVENTS = f'projects/{PROJECT_ID}/subscriptions/investigation-events-sub'
SUB_REMEDIATION_REQUESTS = f'projects/{PROJECT_ID}/subscriptions/remediation-requests-sub'
SUB_FINDINGS_COMPLETE = f'projects/{PROJECT_ID}/subscriptions/findings-complete-sub'
BQ_DATASET = 'autosoc_data'
BQ_TABLE_FINDINGS = f'{PROJECT_ID}.{BQ_DATASET}.findings'
BQ_TABLE_BASELINES = f'{PROJECT_ID}.{BQ_DATASET}.baselines'
BQ_TABLE_TIMELINES = f'{PROJECT_ID}.{BQ_DATASET}.timelines'
FIRESTORE_COLLECTION_INVESTIGATIONS = 'investigations'
GCS_EVIDENCE_BUCKET = os.getenv('GCS_EVIDENCE_BUCKET', 'autosoc-sec-evidence')
VERTEX_AI_MODEL = 'gemini-2.0-flash'
SERVICE_ACCOUNT = os.getenv('SERVICE_ACCOUNT', 'autosoc-sa@sec-autosoc.iam.gserviceaccount.com')
AUTO_REMEDIATE_MAX_SCORE = 6
SLACK_WEBHOOK_URL = os.getenv('SLACK_WEBHOOK_URL', '')
