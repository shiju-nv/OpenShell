"""Check measured coordinator/boundary observations without assuming E2E coverage."""

import json
import pathlib
import sys


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
        retains = row["posture"] == "retain_last_valid"
        assert row["pid_before"] == row["pid_after"] > 0 and row["start_count"] == 1
        assert row["rejected_ready"] == row["rejected_exec_allowed"] == retains
        if retains:
            assert row["heartbeat_after_rejection"] > row["heartbeat_before"]
        else:
            assert row["heartbeat_after_rejection"] == row["heartbeat_before"]
        assert row["heartbeat_after_repair"] > row["heartbeat_after_rejection"]
        assert row["provider_after_rejection"] == 5 and row["provider_after_repair"] == 6
        assert row["ready_after_repair"]
    for row in publication + rejections:
        assert row["probe_origin"] == "actual-coordinator-opa-and-provider-state"
        assert row["upstream_b"] and all("Authorization: Bearer cred-B\r\n" in request for request in row["upstream_b"])
        assert all("Authorization: Bearer cred-A\r\n" in request for request in row["upstream_a"])
    (evidence / "runtime-observations.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Real coordinator/boundary proof passed; controlled gateway delivery and coordinator-origin TCP probes are compositional coverage.")


if __name__ == "__main__":
    main()
