#!/bin/sh
# Synthetic fixtures only. No requests are sent and no task is enqueued.
set -eu
cd "$(dirname "$0")/.."
run_id=${1:-tenant-demo}
case "$run_id" in
  ''|*[!A-Za-z0-9._:-]*) printf '%s\n' 'Run ID must be an identifier.' >&2; exit 1 ;;
esac
case "$run_id" in [A-Za-z0-9]*) ;; *) exit 1 ;; esac
[ "${#run_id}" -le 128 ] || exit 1
demo="work/$run_id"
umask 077
mkdir -p work
mkdir "$demo" || { printf '%s\n' 'Demo directory must be new; choose a fresh run ID.' >&2; exit 1; }
now=$(date -u +%Y-%m-%dT%H:%M:%SZ)
deadline=$(date -u -d '+1 hour' +%Y-%m-%dT%H:%M:%SZ)
printf '%s' 'lab-only-token-a' > "$demo/tenant-a.token"
printf '%s' 'lab-only-token-b' > "$demo/tenant-b.token"
cat > "$demo/probe-credentials.json" <<'EOF'
[
 {"project_id":"lab-project","policy_ref":"local-lab-v1","origin":"http://127.0.0.1:8081","identity_ref":"tenant-a-reader","token_file":"tenant-a.token"},
 {"project_id":"lab-project","policy_ref":"local-lab-v1","origin":"http://127.0.0.1:8081","identity_ref":"tenant-b-reader","token_file":"tenant-b.token"},
 {"project_id":"lab-project","policy_ref":"local-lab-v1","origin":"http://127.0.0.1:8082","identity_ref":"tenant-a-reader","token_file":"tenant-a.token"},
 {"project_id":"lab-project","policy_ref":"local-lab-v1","origin":"http://127.0.0.1:8082","identity_ref":"tenant-b-reader","token_file":"tenant-b.token"}
]
EOF
cat > "$demo/run.json" <<EOF
{"project_id":"lab-project","run_id":"$run_id","max_tasks":10,"max_attempts":30,"limits":{"artifact_bytes":1048576,"tokens":0,"requests":100,"wall_seconds":3600,"cost_microusd":0}}
EOF
printf '{"project_id":"lab-project","run_id":"%s"}\n' "$run_id" > "$demo/scope.json"
for variant in vulnerable patched; do
 port=8081
 if [ "$variant" = patched ]; then port=8082; fi
 cat > "$demo/$variant.json" <<EOF
{
 "task":{
  "schema_version":1,"task_id":"tenant-$variant","project_id":"lab-project","run_id":"$run_id",
  "investigation_id":"tenant-isolation-demo","stage":"hunt",
  "target":{"mode":"web","web":{"deployment_id":"lab-$variant","observation_id":"tenant-demo-$variant","origin":"http://127.0.0.1:$port","seed_urls":["http://127.0.0.1:$port/exports"]}},
  "check":{"kind":"tenant_isolation","identity_a_ref":"tenant-a-reader","identity_b_ref":"tenant-b-reader","tenant_a":"tenant-a","tenant_b":"tenant-b","export_a":"export-a","export_b":"export-b"},
  "policy_ref":"local-lab-v1","question":"Can tenant A read tenant B's synthetic export?",
  "created_at":"$now","deadline":"$deadline","retry_class":"read_only",
  "budget":{"max_wall_seconds":60,"max_model_tokens":0,"max_requests":3,"max_artifact_bytes":65536},
  "dependencies":[]
 },
 "options":{"max_attempts":3,"cost_microusd":0}
}
EOF
 printf '{"project_id":"lab-project","run_id":"%s","task_id":"tenant-%s"}\n' "$run_id" "$variant" > "$demo/$variant-task.json"
done
printf 'Prepared %s for run %s. Fixture credentials are synthetic.\n' "$demo" "$run_id"
