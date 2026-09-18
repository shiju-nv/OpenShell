"""Validate observations from real-child Linux boundary transition tests."""

import json
import pathlib
import sys


def main():
    evidence = pathlib.Path(sys.argv[1])
    marker = "configuration_activation_observation "
    observations = []
    for log in evidence.glob("boundary*.log"):
        for line in log.read_text().splitlines():
            if marker not in line:
                continue
            raw = line.split(marker, 1)[1]
            if raw.startswith("{"):
                observations.append(json.loads(raw))
    fields = {
        "configuration_revision", "policy_version", "policy_hash", "policy_source",
        "provider_revision", "runtime_generation", "session", "supervisor_instance",
        "boundary_instance", "registration_revision", "transition_id",
        "provider_attachment_epoch", "publication_generation", "provider_installation_id",
    }
    matrix = [record for record in observations if record.get("scenario") == "exact-activation-mismatch-matrix"]
    assert {record["field"] for record in matrix} == fields, "missing exact boundary mismatch cases"
    for record in matrix:
        assert record["pid"] > 0 and record["starts"] == 1
        assert record["wrong_commit_rejected"] is True
        assert record["wrong_release_rejected"] is True
        assert record["released_heartbeat"] > record["held_heartbeat"]
        assert record["old_configuration"] != record["candidate_configuration"]
    aborted = next(record for record in observations if record.get("scenario") == "aborted-candidate-reactivation")
    assert aborted["starts"] == 1 and aborted["pid"] > 0
    assert aborted["candidate_credentials_installed"] is False
    assert aborted["old_release_rejected"] is True
    assert aborted["released_heartbeat"] > aborted["held_heartbeat"]
    delayed = next(record for record in observations if record.get("scenario") == "delayed-release-after-quiesce")
    assert delayed["starts"] == 1 and delayed["pid"] > 0
    assert delayed["delayed_commit_rejected"] and delayed["delayed_release_rejected"]
    vfork = [record for record in observations if "vfork_group_parent_d" in record]
    assert len(vfork) == 1, "missing or duplicate deterministic vfork freeze proof"
    assert vfork[0]["vfork_group_parent_d"] is True
    assert vfork[0]["ancestor_first_parent_t"] is True
    assert vfork[0]["freeze_entrypoints"] == 2
    (evidence / "boundary-observations.json").write_text(json.dumps(observations, indent=2) + "\n")
    (evidence / "boundary-coverage.json").write_text(json.dumps({
        "suite": "boundary",
        "requested_slice_passed": True,
        "full_frozen_contract_passed": False,
        "boundary_fields_exercised": sorted(fields),
        "remaining_boundaries": [
            "gateway admission token and old-runtime JWT rejection",
            "gateway durable repair and readiness reports",
            "supervisor selection of both failure postures for each preparation failure",
            "controlled upstream requests across the complete gateway/control/boundary transaction",
        ],
    }, indent=2) + "\n")
    print("Real-child boundary observations passed; cross-component contract remains separately gated.")


if __name__ == "__main__":
    main()
