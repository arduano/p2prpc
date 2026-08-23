#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: $0 check <driver> <manifest-json> | output <driver> <result-json> <manifest-json> | evidence <driver> <result-json> [standard|release]" >&2
  exit 2
}

[[ $# -ge 1 ]] || usage
mode=$1
shift

manifest_entry() {
  local driver=$1
  local manifest=$2
  jq -e --arg driver "$driver" '
    type == "object" and
    (.[$driver] | type == "object") and
    (.[$driver].version | type == "string" and length > 0) and
    (.[$driver].sha256 | type == "string" and test("^[0-9a-fA-F]{64}$")) and
    (.[$driver].schemaVersion | type == "number" and . >= 2 and floor == .)
  ' <<< "$manifest" >/dev/null
}

validate_evidence_envelope() {
  local driver=$1
  local result=$2

  [[ -f "$result" ]]

  # Schema v2 makes a pass non-vacuous: unique scenarios own the assertions,
  # and their exact roll-up must match the top-level summary.
  jq -e --arg driver "$driver" '
    def positive_integer:
      type == "number" and . > 0 and floor == .;
    def nonnegative_integer:
      type == "number" and . >= 0 and floor == .;

    . as $result |
    type == "object" and
    (.schemaVersion | positive_integer) and
    .schemaVersion >= 2 and
    (.driver | type == "object") and
    .driver.name == $driver and
    (.driver.version | type == "string" and length > 0 and length <= 128) and
    .status == "passed" and
    (.assertions | type == "object") and
    (.assertions.passed | positive_integer) and
    (.assertions.failed | nonnegative_integer) and
    .assertions.failed == 0 and
    (.campaign | type == "object") and
    (.campaign.id | type == "string" and test("^[a-z0-9]+([.-][a-z0-9]+)*$") and length <= 128) and
    (.campaign.parameters | type == "object") and
    (.campaign.metrics | type == "object") and
    (.scenarios | type == "array" and length > 0) and
    all(.scenarios[];
      type == "object" and
      (.id | type == "string" and test("^[a-z0-9]+([.-][a-z0-9]+)*$") and length <= 128) and
      .status == "passed" and
      (.assertions | type == "object") and
      (.assertions.passed | positive_integer) and
      (.assertions.failed | nonnegative_integer) and
      .assertions.failed == 0
    ) and
    ([.scenarios[].id] | length) == ([.scenarios[].id] | unique | length) and
    ([.scenarios[].assertions.passed] | add) == $result.assertions.passed and
    ([.scenarios[].assertions.failed] | add) == $result.assertions.failed and
    (
      .startedAt as $started_text |
      .finishedAt as $finished_text |
      ($started_text | type == "string") and
      ($finished_text | type == "string") and
      (($started_text | fromdateiso8601) as $started |
        ($finished_text | fromdateiso8601) as $finished |
        $finished >= $started)
    )
  ' "$result" >/dev/null || {
    echo "$result does not satisfy the non-vacuous lab evidence envelope" >&2
    exit 1
  }
}

validate_campaign_contract() {
  local driver=$1
  local result=$2
  local profile=$3
  local expected_locator=${LOCATOR:-}
  local expected_relay=${RELAY:-}
  local expected_custom_relay_count=${EXPECTED_CUSTOM_RELAY_COUNT:-}

  [[ "$profile" == "standard" || "$profile" == "release" ]] || usage
  if [[ -n "$expected_custom_relay_count" ]]; then
    [[ "$expected_custom_relay_count" =~ ^(0|[1-9][0-9]?)$ ]] &&
      (( expected_custom_relay_count <= 32 )) || {
        echo "EXPECTED_CUSTOM_RELAY_COUNT must be an integer between 0 and 32" >&2
        exit 1
      }
  fi

  # These IDs and observed metrics are the repository-owned release contract.
  # A pinned driver may report more scenarios, but it cannot omit a named gate.
  jq -e \
    --arg driver "$driver" \
    --arg profile "$profile" \
    --arg expectedLocator "$expected_locator" \
    --arg expectedRelay "$expected_relay" \
    --arg expectedCustomRelayCount "$expected_custom_relay_count" '
      def positive_integer:
        type == "number" and . > 0 and floor == .;
      def nonnegative_integer:
        type == "number" and . >= 0 and floor == .;
      def scenario_ids:
        [.scenarios[].id];
      def elapsed_wall_seconds:
        (.finishedAt | fromdateiso8601) - (.startedAt | fromdateiso8601);
      def includes_scenarios($required):
        scenario_ids as $actual |
        all($required[]; . as $required_id | $actual | index($required_id) != null);
      def expected_route_parameters:
        (.campaign.parameters.locator | IN("ticket", "dns", "mdns")) and
        (.campaign.parameters.relay | IN("default", "custom", "disabled")) and
        (.campaign.parameters.dnsEnabled | type == "boolean") and
        .campaign.parameters.dnsEnabled == (.campaign.parameters.locator == "dns") and
        (.campaign.parameters.customRelayCount | nonnegative_integer) and
        (if .campaign.parameters.relay == "custom" then
          .campaign.parameters.customRelayCount > 0
        else
          .campaign.parameters.customRelayCount == 0
        end) and
        ($expectedCustomRelayCount == "" or
          .campaign.parameters.customRelayCount == ($expectedCustomRelayCount | tonumber)) and
        (if .campaign.parameters.locator == "mdns" then
          (.campaign.parameters.mdnsServiceName | type == "string" and length > 0 and length <= 253)
        else
          true
        end) and
        ($expectedLocator == "" or .campaign.parameters.locator == $expectedLocator) and
        ($expectedRelay == "" or .campaign.parameters.relay == $expectedRelay);
      def clean_metrics:
        (.campaign.metrics.activeConnectionsAfter | nonnegative_integer) and
        .campaign.metrics.activeConnectionsAfter == 0 and
        (.campaign.metrics.activeStreamsAfter | nonnegative_integer) and
        .campaign.metrics.activeStreamsAfter == 0 and
        (.campaign.metrics.activeTransfersAfter | nonnegative_integer) and
        .campaign.metrics.activeTransfersAfter == 0 and
        (.campaign.metrics.activeHandlesAfter | nonnegative_integer) and
        .campaign.metrics.activeHandlesAfter == 0;
      def topology_locator_scenarios:
        if .campaign.parameters.locator == "ticket" then
          [
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
            "identity.wrong-principal-rejected"
          ]
        elif .campaign.parameters.locator == "dns" then
          [
            "locator.dns.default-resolver",
            "locator.dns.controlled-resolver",
            "locator.dns.ttl-refresh",
            "locator.dns.route-replacement",
            "locator.dns.poisoned-record-rejected",
            "locator.dns.stale-record-rejected",
            "locator.dns.reconnect-resolution",
            "identity.wrong-endpoint-rejected",
            "identity.wrong-principal-rejected"
          ]
        elif .campaign.parameters.locator == "mdns" then
          [
            "locator.mdns.advertise-browse",
            "locator.mdns.duplicates",
            "locator.mdns.expiry",
            "locator.mdns.reappearance",
            "locator.mdns.address-change",
            "locator.mdns.service-isolation",
            "locator.mdns.spoofed-node-id-rejected",
            "identity.wrong-endpoint-rejected",
            "identity.wrong-principal-rejected"
          ]
        else
          []
        end;
      def topology_relay_scenarios:
        if .campaign.parameters.relay == "default" then
          [
            "relay.default.public-smoke",
            "relay.default.direct-upgrade.rpc",
            "relay.default.direct-upgrade.subscription",
            "relay.default.direct-upgrade.file"
          ]
        elif .campaign.parameters.relay == "custom" then
          [
            "relay.custom.https",
            "relay.custom.multiple",
            "relay.custom.outage-failover",
            "relay.custom.invalid-tls-rejected",
            "relay.custom.egress-denial",
            "relay.custom.direct-upgrade.rpc",
            "relay.custom.direct-upgrade.subscription",
            "relay.custom.direct-upgrade.file"
          ]
        elif .campaign.parameters.relay == "disabled" then
          ["relay.disabled.enforced"]
        else
          []
        end;

      if $driver == "p2prpc-lab-canary" then
        .campaign.id == "raw-iroh-canary" and
        expected_route_parameters and
        includes_scenarios([
          "transport.connect",
          "stream.open",
          "stream.echo-integrity",
          "stream.close",
          "transport.close"
        ]) and
        (.campaign.metrics.connectionsOpened | positive_integer) and
        .campaign.metrics.connectionsOpened == 1 and
        (.campaign.metrics.connectionsClosed | positive_integer) and
        .campaign.metrics.connectionsClosed == 1 and
        (.campaign.metrics.streamsOpened | positive_integer) and
        .campaign.metrics.streamsOpened == 1 and
        (.campaign.metrics.streamsClosed | positive_integer) and
        .campaign.metrics.streamsClosed == 1 and
        (.campaign.metrics.echoedBytes | positive_integer) and
        (.campaign.metrics.activeConnectionsAfter | nonnegative_integer) and
        .campaign.metrics.activeConnectionsAfter == 0 and
        (.campaign.metrics.activeStreamsAfter | nonnegative_integer) and
        .campaign.metrics.activeStreamsAfter == 0
      elif $driver == "p2prpc-lab-topology-suite" then
        .campaign.id == "topology-and-fault-matrix" and
        expected_route_parameters and
        (.campaign.parameters.relay != "custom" or .campaign.parameters.customRelayCount >= 2) and
        includes_scenarios(topology_locator_scenarios + topology_relay_scenarios + [
          "protocol.rpc",
          "protocol.subscription",
          "protocol.file-transfer",
          "lifecycle.clean-shutdown"
        ]) and
        (.campaign.metrics.scenariosPassed | positive_integer) and
        .campaign.metrics.scenariosPassed == (.scenarios | length) and
        (.campaign.metrics.scenariosFailed | nonnegative_integer) and
        .campaign.metrics.scenariosFailed == 0 and
        clean_metrics
      elif $driver == "p2prpc-lab-mixed-suite" then
        .campaign.id == "mixed-load" and
        includes_scenarios([
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
        ]) and
        .campaign.parameters.peers == 100 and
        .campaign.parameters.rpcStreams == 1000 and
        .campaign.parameters.fileTransfers == 16 and
        (.campaign.parameters.durationSeconds | positive_integer) and
        .campaign.parameters.durationSeconds >= 1800 and
        ($profile != "release" or .campaign.parameters.durationSeconds >= 14400) and
        (.campaign.metrics.peerCount | positive_integer) and
        .campaign.metrics.peerCount == .campaign.parameters.peers and
        (.campaign.metrics.peakConcurrentRpcStreams | positive_integer) and
        .campaign.metrics.peakConcurrentRpcStreams >= .campaign.parameters.rpcStreams and
        (.campaign.metrics.peakConcurrentFileTransfers | positive_integer) and
        .campaign.metrics.peakConcurrentFileTransfers >= .campaign.parameters.fileTransfers and
        (.campaign.metrics.elapsedSeconds | positive_integer) and
        .campaign.metrics.elapsedSeconds >= .campaign.parameters.durationSeconds and
        elapsed_wall_seconds >= .campaign.parameters.durationSeconds and
        clean_metrics
      elif $driver == "p2prpc-lab-release-suite" then
        .campaign.id == "release-storage-identity-and-faults" and
        includes_scenarios([
          "storage.filesystem-transfer",
          "identity.oidc-token-rotation",
          "identity.jwks-rotation",
          "identity.issuer-outage",
          "identity.endpoint-key-rotation",
          "fault.relay-failover",
          "lifecycle.clean-shutdown"
        ]) and
        .campaign.parameters.fileBytes == 17179869184 and
        (.campaign.parameters.customRelayCount | positive_integer) and
        .campaign.parameters.customRelayCount >= 2 and
        ($expectedCustomRelayCount == "" or
          .campaign.parameters.customRelayCount == ($expectedCustomRelayCount | tonumber)) and
        (.campaign.metrics.fileBytesTransferred | positive_integer) and
        .campaign.metrics.fileBytesTransferred == .campaign.parameters.fileBytes and
        .campaign.metrics.fileDigestVerified == true and
        (.campaign.metrics.oidcTokenRotations | positive_integer) and
        (.campaign.metrics.jwksRotations | positive_integer) and
        (.campaign.metrics.issuerOutagesInjected | positive_integer) and
        (.campaign.metrics.endpointKeyRotations | positive_integer) and
        (.campaign.metrics.identityRotations | positive_integer) and
        .campaign.metrics.identityRotations == (
          .campaign.metrics.oidcTokenRotations +
          .campaign.metrics.jwksRotations +
          .campaign.metrics.endpointKeyRotations
        ) and
        (.campaign.metrics.relayFailovers | positive_integer) and
        (.campaign.metrics.cleanShutdowns | positive_integer) and
        clean_metrics
      else
        false
      end
    ' "$result" >/dev/null || {
      echo "$result does not satisfy the $profile $driver campaign evidence contract" >&2
      exit 1
    }
}

if [[ "$mode" == "check" ]]; then
  [[ $# -eq 2 ]] || usage
  driver=$1
  manifest=$2
  manifest_entry "$driver" "$manifest"

  executable=$(type -P "$driver")
  executable=$(readlink -f -- "$executable")
  [[ -f "$executable" && -x "$executable" ]]

  expected_version=$(jq -er --arg driver "$driver" '.[$driver].version' <<< "$manifest")
  expected_sha256=$(jq -er --arg driver "$driver" '.[$driver].sha256 | ascii_downcase' <<< "$manifest")
  expected_schema=$(jq -er --arg driver "$driver" '.[$driver].schemaVersion' <<< "$manifest")
  actual_sha256=$(sha256sum -- "$executable" | cut -d ' ' -f 1)
  [[ "$actual_sha256" == "$expected_sha256" ]] || {
    echo "$driver SHA-256 does not match P2PRPC_LAB_DRIVER_MANIFEST" >&2
    exit 1
  }

  version_json=$("$executable" --version-json)
  jq -e \
    --arg driver "$driver" \
    --arg version "$expected_version" \
    --argjson schemaVersion "$expected_schema" '
      type == "object" and
      .name == $driver and
      .version == $version and
      .schemaVersion == $schemaVersion
    ' <<< "$version_json" >/dev/null || {
      echo "$driver version metadata does not match P2PRPC_LAB_DRIVER_MANIFEST" >&2
      exit 1
    }
  exit 0
fi

if [[ "$mode" == "output" ]]; then
  [[ $# -eq 3 ]] || usage
  driver=$1
  result=$2
  manifest=$3
  manifest_entry "$driver" "$manifest"
  [[ -f "$result" ]]

  expected_version=$(jq -er --arg driver "$driver" '.[$driver].version' <<< "$manifest")
  expected_schema=$(jq -er --arg driver "$driver" '.[$driver].schemaVersion' <<< "$manifest")
  validate_evidence_envelope "$driver" "$result"
  jq -e \
    --arg driver "$driver" \
    --arg version "$expected_version" \
    --argjson schemaVersion "$expected_schema" '
      .schemaVersion == $schemaVersion and
      .driver == { name: $driver, version: $version }
    ' "$result" >/dev/null || {
      echo "$result does not satisfy the pinned $driver output contract" >&2
      exit 1
    }
  validate_campaign_contract "$driver" "$result" standard
  exit 0
fi

if [[ "$mode" == "evidence" ]]; then
  [[ $# -eq 2 || $# -eq 3 ]] || usage
  driver=$1
  result=$2
  profile=${3:-standard}
  [[ -f "$result" ]]
  validate_evidence_envelope "$driver" "$result"
  validate_campaign_contract "$driver" "$result" "$profile"
  exit 0
fi

usage
