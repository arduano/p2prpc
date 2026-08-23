#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
validator="$script_dir/validate-lab-driver.sh"
relay_validator="$script_dir/validate-relay-urls.mjs"
fixture_dir=$(mktemp -d)
trap 'rm -rf -- "$fixture_dir"' EXIT

make_result() {
  local path=$1
  local driver=$2
  local campaign=$3
  local parameters=$4
  local metrics=$5
  local scenarios=$6
  local started=$7
  local finished=$8

  jq -n \
    --arg driver "$driver" \
    --arg campaign "$campaign" \
    --arg started "$started" \
    --arg finished "$finished" \
    --argjson parameters "$parameters" \
    --argjson metrics "$metrics" \
    --argjson scenarios "$scenarios" '
      ($scenarios | map({ id: ., status: "passed", assertions: { passed: 1, failed: 0 } })) as $results |
      {
        schemaVersion: 2,
        driver: { name: $driver, version: "1.2.3" },
        status: "passed",
        assertions: { passed: ($results | length), failed: 0 },
        campaign: { id: $campaign, parameters: $parameters, metrics: $metrics },
        scenarios: $results,
        startedAt: $started,
        finishedAt: $finished
      }
    ' > "$path"
}

expect_failure() {
  if "$@" >/dev/null 2>&1; then
    printf 'expected command to fail:' >&2
    printf ' %q' "$@" >&2
    printf '\n' >&2
    exit 1
  fi
}

expect_relay_failure() {
  local required=$1
  local urls=$2
  if node "$relay_validator" "$required" <<< "$urls" >/dev/null 2>&1; then
    printf 'expected relay URL validation to fail for: %s\n' "$urls" >&2
    exit 1
  fi
}

normalized_relays=$(node "$relay_validator" 2 <<< '["https://Relay-A.Example", "https://relay-b.example:8443/"]')
[[ "$normalized_relays" == '["https://relay-a.example","https://relay-b.example:8443"]' ]]
expect_relay_failure 2 '["https://relay.example", "https://relay.example/"]'
expect_relay_failure 2 '["https://RELAY.example", "https://relay.example"]'
expect_relay_failure 2 '["https://relay.example:443", "https://relay.example/"]'
expect_relay_failure 2 '["https://relay.example.", "https://relay.example"]'
expect_relay_failure 2 '["https://relay-a.example/path", "https://relay-b.example"]'
expect_relay_failure 2 '["https://relay-a.example/segment/..", "https://relay-b.example"]'
expect_relay_failure 2 '["https://relay-a.example?query", "https://relay-b.example"]'
expect_relay_failure 2 '["https://user@relay-a.example", "https://relay-b.example"]'
expect_relay_failure 2 '["https://@relay-a.example", "https://relay-b.example"]'
expect_relay_failure 2 '["https://relay-a.example:", "https://relay-b.example"]'
expect_relay_failure 2 '["http://relay-a.example", "https://relay-b.example"]'
expect_relay_failure 2 '["https://relay.example"]'

route='{"locator":"ticket","relay":"custom","dnsEnabled":false,"customRelayCount":2}'
canary_metrics='{"connectionsOpened":1,"connectionsClosed":1,"streamsOpened":1,"streamsClosed":1,"echoedBytes":64,"activeConnectionsAfter":0,"activeStreamsAfter":0}'
canary_scenarios='["transport.connect","stream.open","stream.echo-integrity","stream.close","transport.close"]'
make_result \
  "$fixture_dir/canary.json" \
  p2prpc-lab-canary \
  raw-iroh-canary \
  "$route" \
  "$canary_metrics" \
  "$canary_scenarios" \
  2026-08-23T00:00:00Z \
  2026-08-23T00:00:01Z
LOCATOR=ticket RELAY=custom bash "$validator" evidence p2prpc-lab-canary "$fixture_dir/canary.json"

topology_scenarios='[
  "locator.ticket.ipv4",
  "locator.ticket.ipv6",
  "locator.ticket.dual-stack",
  "locator.ticket.multiple-candidates",
  "locator.ticket.blackholed-first-fallback",
  "locator.ticket.address-refresh",
  "locator.ticket.expiry-rejected",
  "locator.ticket.tampering-rejected",
  "locator.ticket.staleness-rejected",
  "identity.wrong-endpoint-rejected",
  "identity.wrong-principal-rejected",
  "relay.custom.https",
  "relay.custom.multiple",
  "relay.custom.outage-failover",
  "relay.custom.invalid-tls-rejected",
  "relay.custom.egress-denial",
  "relay.custom.direct-upgrade.rpc",
  "relay.custom.direct-upgrade.subscription",
  "relay.custom.direct-upgrade.file",
  "protocol.rpc",
  "protocol.subscription",
  "protocol.file-transfer",
  "lifecycle.clean-shutdown"
]'
topology_metrics='{"scenariosPassed":23,"scenariosFailed":0,"activeConnectionsAfter":0,"activeStreamsAfter":0,"activeTransfersAfter":0,"activeHandlesAfter":0}'
make_result \
  "$fixture_dir/topology.json" \
  p2prpc-lab-topology-suite \
  topology-and-fault-matrix \
  "$route" \
  "$topology_metrics" \
  "$topology_scenarios" \
  2026-08-23T00:00:00Z \
  2026-08-23T00:01:00Z
LOCATOR=ticket RELAY=custom bash "$validator" evidence p2prpc-lab-topology-suite "$fixture_dir/topology.json"
EXPECTED_CUSTOM_RELAY_COUNT=2 LOCATOR=ticket RELAY=custom bash "$validator" evidence \
  p2prpc-lab-topology-suite "$fixture_dir/topology.json"
expect_failure env EXPECTED_CUSTOM_RELAY_COUNT=3 LOCATOR=ticket RELAY=custom bash "$validator" evidence \
  p2prpc-lab-topology-suite "$fixture_dir/topology.json"

jq '.campaign.parameters.customRelayCount = 1' "$fixture_dir/topology.json" > "$fixture_dir/one-relay.json"
expect_failure env LOCATOR=ticket RELAY=custom bash "$validator" evidence \
  p2prpc-lab-topology-suite "$fixture_dir/one-relay.json"

clean_metrics='"activeConnectionsAfter":0,"activeStreamsAfter":0,"activeTransfersAfter":0,"activeHandlesAfter":0'
mixed_scenarios='[
  "workload.rpc",
  "workload.files",
  "workload.subscriptions",
  "workload.soak",
  "lifecycle.reconnect-resume",
  "fault.bounded-partition",
  "fault.relay-restart",
  "lifecycle.session-expiry",
  "security.capability-revocation",
  "storage.failure",
  "admission.overflow",
  "lifecycle.connect-work-close-waves",
  "lifecycle.clean-shutdown"
]'
mixed_parameters='{"peers":100,"rpcStreams":1000,"fileTransfers":16,"durationSeconds":14400}'
mixed_metrics="{\"peerCount\":100,\"peakConcurrentRpcStreams\":1000,\"peakConcurrentFileTransfers\":16,\"elapsedSeconds\":14400,$clean_metrics}"
make_result \
  "$fixture_dir/mixed.json" \
  p2prpc-lab-mixed-suite \
  mixed-load \
  "$mixed_parameters" \
  "$mixed_metrics" \
  "$mixed_scenarios" \
  2026-08-23T00:00:00Z \
  2026-08-23T04:00:00Z
bash "$validator" evidence p2prpc-lab-mixed-suite "$fixture_dir/mixed.json" release

release_scenarios='[
  "storage.filesystem-transfer",
  "identity.oidc-token-rotation",
  "identity.jwks-rotation",
  "identity.issuer-outage",
  "identity.endpoint-key-rotation",
  "fault.relay-failover",
  "lifecycle.clean-shutdown"
]'
release_parameters='{"fileBytes":17179869184,"customRelayCount":2}'
release_metrics="{\"fileBytesTransferred\":17179869184,\"fileDigestVerified\":true,\"oidcTokenRotations\":1,\"jwksRotations\":1,\"issuerOutagesInjected\":1,\"endpointKeyRotations\":1,\"identityRotations\":3,\"relayFailovers\":1,\"cleanShutdowns\":2,$clean_metrics}"
make_result \
  "$fixture_dir/release.json" \
  p2prpc-lab-release-suite \
  release-storage-identity-and-faults \
  "$release_parameters" \
  "$release_metrics" \
  "$release_scenarios" \
  2026-08-23T00:00:00Z \
  2026-08-23T00:10:00Z
bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/release.json"
EXPECTED_CUSTOM_RELAY_COUNT=2 bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/release.json"
expect_failure env EXPECTED_CUSTOM_RELAY_COUNT=3 bash "$validator" evidence \
  p2prpc-lab-release-suite "$fixture_dir/release.json"

manifest='{"p2prpc-lab-release-suite":{"version":"1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schemaVersion":2}}'
bash "$validator" output p2prpc-lab-release-suite "$fixture_dir/release.json" "$manifest"

old_manifest='{"p2prpc-lab-release-suite":{"version":"1.2.3","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","schemaVersion":1}}'
expect_failure bash "$validator" output p2prpc-lab-release-suite "$fixture_dir/release.json" "$old_manifest"

jq '.assertions.passed = 0' "$fixture_dir/release.json" > "$fixture_dir/vacuous.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/vacuous.json"

jq '.assertions.passed += 1' "$fixture_dir/release.json" > "$fixture_dir/bad-rollup.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/bad-rollup.json"

jq '.schemaVersion = 1' "$fixture_dir/release.json" > "$fixture_dir/old-schema.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/old-schema.json"

jq '.scenarios[1].id = .scenarios[0].id' "$fixture_dir/release.json" > "$fixture_dir/duplicate.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/duplicate.json"

jq '
  del(.scenarios[] | select(.id == "fault.relay-failover")) |
  .assertions.passed = (.scenarios | length)
' "$fixture_dir/release.json" > "$fixture_dir/missing-scenario.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/missing-scenario.json"

jq 'del(.campaign.metrics.fileBytesTransferred)' "$fixture_dir/release.json" > "$fixture_dir/missing-metric.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/missing-metric.json"

jq '.campaign.metrics.fileBytesTransferred = 1' "$fixture_dir/release.json" > "$fixture_dir/wrong-metric.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/wrong-metric.json"

jq '.campaign.metrics.fileDigestVerified = false' "$fixture_dir/release.json" > "$fixture_dir/unverified-file.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/unverified-file.json"

jq '.campaign.metrics.activeHandlesAfter = 1' "$fixture_dir/release.json" > "$fixture_dir/leaked-handle.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/leaked-handle.json"

jq '.campaign.parameters.customRelayCount = 1' "$fixture_dir/release.json" > "$fixture_dir/one-release-relay.json"
expect_failure bash "$validator" evidence p2prpc-lab-release-suite "$fixture_dir/one-release-relay.json"

expect_failure env LOCATOR=dns RELAY=custom bash "$validator" evidence p2prpc-lab-canary "$fixture_dir/canary.json"

jq '
  .campaign.parameters.durationSeconds = 1800 |
  .campaign.metrics.elapsedSeconds = 1800 |
  .finishedAt = "2026-08-23T00:30:00Z"
' "$fixture_dir/mixed.json" > "$fixture_dir/nightly.json"
bash "$validator" evidence p2prpc-lab-mixed-suite "$fixture_dir/nightly.json"
expect_failure bash "$validator" evidence p2prpc-lab-mixed-suite "$fixture_dir/nightly.json" release

printf 'Lab evidence contract regression tests passed.\n'
