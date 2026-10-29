#!/usr/bin/env bash
set -euo pipefail

IMAGE="${1:-}"
OUT="${2:-}"

if [[ -z "$IMAGE" ]]; then
  echo "Usage: $0 <image-name[:tag|@digest]> [output-file]" >&2
  echo "Example: $0 acrfuturefitwedev001.azurecr.io/marimo:latest marimo.sbom.json" >&2
  exit 2
fi

for command in az syft; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

registry_host="${IMAGE%%/*}"
if [[ "$registry_host" == *azurecr.io ]]; then
  if ! az account show --output none 2>/dev/null; then
    echo "No Azure CLI login found. Run: az login" >&2
    exit 1
  fi

  registry_name="${registry_host%%.*}"
  echo "Logging in to ACR: $registry_name" >&2
  az acr login --name "$registry_name" --only-show-errors
fi

if [[ -z "$OUT" ]]; then
  image_name="${IMAGE##*/}"
  image_name="${image_name%%@*}"
  image_name="${image_name%%:*}"
  image_name="${image_name//[^a-zA-Z0-9._-]/_}"
  OUT="${image_name:-image}.sbom.json"
fi

echo "Generating CycloneDX SBOM for $IMAGE" >&2
syft "$IMAGE" --output cyclonedx-json > "$OUT"
echo "SBOM written to $OUT"
