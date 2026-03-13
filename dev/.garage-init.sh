#!/bin/sh
set -e

ADMIN="http://garage:3901"

echo "[garage-init] Waiting for Garage..."
until curl -sf "${ADMIN}/health" >/dev/null 2>&1; do
  sleep 1
done
echo "[garage-init] Garage is ready"

# Get this node's ID from the admin API
NODE_ID=$(curl -sf "${ADMIN}/v1/status" | jq -r '.node')
echo "[garage-init] Node ID: ${NODE_ID}"

# Apply layout if not yet done (version 0 = fresh cluster)
LAYOUT_VERSION=$(curl -sf "${ADMIN}/v1/layout" | jq -r '.version')
if [ "${LAYOUT_VERSION}" = "0" ]; then
  echo "[garage-init] Staging layout..."
  curl -sf -X POST "${ADMIN}/v1/layout" \
    -H "Content-Type: application/json" \
    -d "{\"${NODE_ID}\": {\"zone\": \"dc1\", \"capacity\": 1000000000}}" >/dev/null

  echo "[garage-init] Applying layout v1..."
  curl -sf -X POST "${ADMIN}/v1/layout/apply" \
    -H "Content-Type: application/json" \
    -d '{"version": 1}' >/dev/null
else
  echo "[garage-init] Layout already at version ${LAYOUT_VERSION}, skipping"
fi

# Create bucket (safe to call again; Garage returns 409 if it exists)
echo "[garage-init] Ensuring bucket '${S3_BUCKET}'..."
curl -sf -X POST "${ADMIN}/v1/bucket" \
  -H "Content-Type: application/json" \
  -d "{\"globalAlias\": \"${S3_BUCKET}\"}" >/dev/null 2>&1 || true

# Import key with known credentials (409 if already imported)
echo "[garage-init] Ensuring access key '${S3_ACCESS_KEY_ID}'..."
curl -sf -X POST "${ADMIN}/v1/key/import" \
  -H "Content-Type: application/json" \
  -d "{\"accessKeyId\": \"${S3_ACCESS_KEY_ID}\", \"secretAccessKey\": \"${S3_SECRET_ACCESS_KEY}\", \"name\": \"natlas-dev\"}" >/dev/null 2>&1 || true

# Grant the key read/write/owner on the bucket (idempotent)
BUCKET_ID=$(curl -sf "${ADMIN}/v1/bucket?globalAlias=${S3_BUCKET}" | jq -r '.id')
echo "[garage-init] Granting access: key=${S3_ACCESS_KEY_ID} bucket=${S3_BUCKET} (${BUCKET_ID})"
curl -sf -X POST "${ADMIN}/v1/bucket/allow" \
  -H "Content-Type: application/json" \
  -d "{\"bucketId\": \"${BUCKET_ID}\", \"accessKeyId\": \"${S3_ACCESS_KEY_ID}\", \"permissions\": {\"read\": true, \"write\": true, \"owner\": true}}" >/dev/null

echo "[garage-init] Done"
