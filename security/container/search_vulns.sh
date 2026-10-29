#!/usr/bin/env bash
set -euo pipefail

ACR_NAME="${ACR_NAME:-acrfuturefitwedev001}"
CVE="${1:-CVE-2026-111497}"
OUT="${2:-acr-${CVE}-images.csv}"

for command in az jq; do
  if ! command -v "$command" >/dev/null 2>&1; then
    echo "Required command not found: $command" >&2
    exit 1
  fi
done

if ! az account show --output none 2>/dev/null; then
  echo "No Azure CLI login found. Run: az login" >&2
  exit 1
fi

if ! az extension show --name resource-graph >/dev/null 2>&1; then
  echo "Install the Azure Resource Graph extension first: az extension add --name resource-graph" >&2
  exit 1
fi

query="
securityresources
| where type =~ 'microsoft.security/assessments'
| where id contains '/registries/${ACR_NAME}/'
    and tostring(properties.status.code) == 'Unhealthy'
| extend ad = properties.additionalData,
         image = parse_json(tostring(properties.resourceAdditionalData)),
         cves = parse_json(tostring(properties.additionalData.CvesDetails))
| mv-expand cve = cves
| where tostring(cve.CveId) == '${CVE}'
| summarize Packages = make_set(tostring(ad.SoftwareName), 20),
            DetectedVersions = make_set(tostring(ad.DetectedSoftwareVersions), 20),
            FixedVersions = make_set(tostring(cve.FixedVersion), 20),
            Tags = make_set(tostring(image.Tags), 20)
    by Image = tostring(image.ImageUri),
       Repository = tostring(image.RepositoryDetails.RepositoryName)
| project Image, Repository,
          Tags = strcat_array(Tags, '; '),
          Packages = strcat_array(Packages, '; '),
          DetectedVersions = strcat_array(DetectedVersions, '; '),
          FixedVersions = strcat_array(FixedVersions, '; ')
| order by Repository asc, Image asc
"

printf 'Image,Repository,Tags,Packages,DetectedVersions,FixedVersions\n' > "$OUT"

skip_token=""
while :; do
  args=(graph query --graph-query "$query" --first 1000 --output json --only-show-errors)
  if [[ -n "$skip_token" ]]; then
    args+=(--skip-token "$skip_token")
  fi

  response=$(az "${args[@]}")
  jq -r '.data[] | [
    .Image,
    .Repository,
    .Tags,
    .Packages,
    .DetectedVersions,
    .FixedVersions
  ] | @csv' <<< "$response" >> "$OUT"

  skip_token=$(jq -r '.skip_token // empty' <<< "$response")
  [[ -z "$skip_token" ]] && break
done

echo "Exported $(( $(wc -l < "$OUT") - 1 )) image rows to $OUT"
