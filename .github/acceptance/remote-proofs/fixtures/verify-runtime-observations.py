"""Check measured coordinator/boundary observations without assuming E2E coverage."""

import json
import pathlib
import sys
import uuid


def unsigned(value):
    assert type(value) is int and value >= 0, "expected a nonnegative integer"
    return value


def identifier(value):
    assert type(value) is str
    parsed = uuid.UUID(value)
    assert parsed.int and str(parsed) == value, "expected a canonical nonnil UUID"


def boundary_snapshot(snapshot):
    """Reject coercible scalar types before comparing the measured snapshots."""
    assert type(snapshot) is dict and type(snapshot["active"]) is bool
    assert unsigned(snapshot["publication_generation"]) > 0
    identifier(snapshot["provider_env_installation_id"])
    identity = snapshot["identity"]
    assert type(identity) is dict and type(identity["runtime_generation"]) is str
    assert identity["runtime_generation"] and not any(c.isspace() for c in identity["runtime_generation"])
    assert unsigned(identity["registration_revision"]) > 0
    for key in ("boundary_session_id", "supervisor_instance_id", "boundary_instance_id"):
        identifier(identity[key])
    installation(snapshot["installed"])


def installation(value):
    assert type(value) is dict
    for key in ("config_revision", "policy_version", "policy_source", "provider_env_revision"):
        assert unsigned(value[key]) > 0
    for key in ("policy_hash", "provider_attachment_epoch"):
        assert type(value[key]) is str and value[key] and not any(c.isspace() for c in value[key])


def rejection(row):
    """Policy retention never permits execution with revoked provider material."""
    retains_policy = row["posture"] == "retain_last_valid"
    mismatch = row["fault"] == "provider-revision-mismatch"
    retains_execution = retains_policy and not mismatch
    for key in ("pid_before", "pid_after", "start_count", "heartbeat_before",
                "heartbeat_after_rejection", "heartbeat_after_repair",
                "provider_after_rejection", "provider_after_repair",
                "opa_generation_before", "opa_generation_after_rejection"):
        unsigned(row[key])
    for key in ("rejected_ready", "rejected_exec_allowed", "ready_after_repair",
                "provider_static_revoked", "provider_child_env_empty_after_rejection",
                "provider_resolver_present_after_rejection"):
        assert type(row[key]) is bool, "expected a concrete boolean: " + key
    assert row["execution_posture"] == ("running" if retains_execution else "held")
    assert row["pid_before"] == row["pid_after"] > 0 and row["start_count"] == 1
    assert row["rejected_ready"] == row["rejected_exec_allowed"] == retains_execution
    if retains_execution:
        assert row["heartbeat_after_rejection"] > row["heartbeat_before"]
    else:
        assert row["heartbeat_after_rejection"] == row["heartbeat_before"]
    assert row["heartbeat_after_repair"] > row["heartbeat_after_rejection"]
    assert row["provider_after_rejection"] == (6 if mismatch else 5)
    assert row["provider_after_repair"] == 6 and row["ready_after_repair"]
    assert row["provider_static_revoked"] == row["provider_child_env_empty_after_rejection"] == mismatch
    assert row["provider_resolver_present_after_rejection"] == (not mismatch)
    if retains_policy:
        assert row["opa_generation_after_rejection"] == row["opa_generation_before"]
    else:
        assert row["opa_generation_after_rejection"] > row["opa_generation_before"]

    # The rejected candidate may change execution state, but cannot replace any
    # coordinate of the last installed boundary publication.
    before, after = row["boundary_before_rejection"], row["boundary_after_rejection"]
    boundary_snapshot(before)
    boundary_snapshot(after)
    installation(row["retained_installation"])
    assert before["active"] is True and after["active"] == retains_execution
    assert before["installed"] == after["installed"] == row["retained_installation"]
    for key in ("identity", "publication_generation", "provider_env_installation_id"):
        assert before[key] == after[key], "rejected candidate changed boundary " + key

    # Full captures include traffic before rejection and after repair. Compare
    # the measured rejection interval instead of assuming an empty history.
    counts_before, counts_after = row["upstream_requests_before_rejection"], row["upstream_requests_after_rejection"]
    for counts in (counts_before, counts_after):
        assert type(counts) is list and len(counts) == 2
        for count in counts:
            unsigned(count)
    for index, key in enumerate(("upstream_a", "upstream_b")):
        assert type(row[key]) is list and all(type(request) is str for request in row[key])
        assert counts_before[index] <= counts_after[index] <= len(row[key])
    assert [after - before for before, after in zip(counts_before, counts_after)] == ([1, 0] if retains_execution else [0, 0])


def main():
    evidence = pathlib.Path(sys.argv[1])
    marker = "configuration_activation_runtime_observation "
    records = []
    for log in evidence.glob("configuration-*.log"):
        for line in log.read_text().splitlines():
            if marker in line:
                records.append(json.loads(line.split(marker, 1)[1]))
    publication = [row for row in records if row["scenario"] == "atomic-live-publication"]
    assert len(publication) == 1, "publication pause proof is missing"
    row = publication[0]
    assert row["pid_before"] == row["pid_after"] > 0 and row["start_count"] == 1
    assert row["heartbeat_after"] > row["heartbeat_held"] > 0
    assert row["held_exec_denied"] and not row["held_readiness"] and row["ready_after"]
    assert row["provider_before"] == row["provider_while_held"] == 5
    assert row["provider_after"] == 6
    assert row["opa_generation_before"] == row["opa_generation_while_held"] == 0
    assert row["opa_generation_after"] == 1
    rejections = [row for row in records if row["scenario"] == "rejected-live-posture"]
    combinations = {(posture, fault) for posture in ("retain_last_valid", "fail_closed") for fault in ("unresolved-binding", "provider-revision-mismatch", "opa-rejection")}
    assert len(rejections) == len(combinations)
    assert {(row["posture"], row["fault"]) for row in rejections} == combinations
    for row in rejections:
        rejection(row)
    for row in publication + rejections:
        assert row["probe_origin"] == "actual-coordinator-opa-and-provider-state"
        assert row["upstream_b"] and all("Authorization: Bearer cred-B\r\n" in request for request in row["upstream_b"])
        assert all("Authorization: Bearer cred-A\r\n" in request for request in row["upstream_a"])
    (evidence / "runtime-observations.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Real coordinator/boundary proof passed; controlled gateway delivery and coordinator-origin TCP probes are compositional coverage.")


if __name__ == "__main__":
    main()
