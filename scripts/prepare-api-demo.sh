#!/bin/sh
# Prepare a fresh, bounded HTTP inspection request. Does not enqueue anything.
set -eu
cd "$(dirname "$0")/.."
mkdir -p work
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
cat > work/api-enqueue.json <<EOF
{
  "task": {
    "schema_version": 1,
    "task_id": "api-lab-web",
    "project_id": "lab-project",
    "run_id": "queue-demo",
    "investigation_id": "investigation-lab-inspection",
    "stage": "prepare",
    "target": {
      "mode": "web",
      "web": {
        "deployment_id": "lab-patched",
        "observation_id": "api-demo",
        "origin": "http://127.0.0.1:8082",
        "seed_urls": ["http://127.0.0.1:8082/healthz"]
      }
    },
    "policy_ref": "local-lab-v1",
    "question": "Collect a bounded health response; no vulnerability judgment.",
    "created_at": "$now",
    "deadline": "$deadline",
    "retry_class": "read_only",
    "budget": {
      "max_wall_seconds": 60,
      "max_model_tokens": 0,
      "max_requests": 2,
      "max_artifact_bytes": 65536
    },
    "dependencies": []
  },
  "options": {"max_attempts": 3, "cost_microusd": 0}
}
EOF
cat > work/api-scope.json <<'EOF'
{"project_id":"lab-project","run_id":"queue-demo"}
EOF
cat > work/api-task.json <<'EOF'
{"project_id":"lab-project","run_id":"queue-demo","task_id":"api-lab-web"}
EOF
printf '%s\n' 'Prepared work/api-enqueue.json, work/api-scope.json and work/api-task.json.'
