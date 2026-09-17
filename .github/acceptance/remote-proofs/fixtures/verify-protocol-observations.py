"""Check completeness of the real-boundary protocol preparation/update matrix."""

import json
import hashlib
from pathlib import Path
import sys


CASES = {"Rest", "Graphql", "Websocket", "JsonRpc", "McpOmitted", "McpEmptyProto", "McpRevisions"}
FAULTS = {(case, "misplaced-mcp-options") for case in ("Rest", "Graphql", "Websocket", "JsonRpc")}
FAULTS.update(("McpOmitted", fault) for fault in (
    "empty-revision", "duplicate-revision", "padded-revision", "unsupported-revision", "draft-revision",
))
FAULTS.update({
    ("Rest", "conflicting-query-matchers"),
    ("Websocket", "conflicting-query-matchers"),
    ("Graphql", "invalid-graphql-operation"),
    ("JsonRpc", "json-rpc-params-matcher"),
})


def exact_rows(rows, expected, fields):
    """Reject omissions and duplicates, even if every emitted row claims success."""
    actual = [tuple(row[field] for field in fields) for row in rows]
    assert len(actual) == len(expected), (fields, "wrong observation count", actual)
    assert set(actual) == expected, (fields, "incomplete observation matrix", actual)


def reports(rows, state):
    assert rows, "The current attempt emitted no admission report"
    assert all(row["state"] == state for row in rows), "Unexpected admission state"
    if state == 2:
        assert not rows[0]["activation_confirmed"] and rows[-1]["activation_confirmed"], "Missing installed-then-released admission transition"
        confirmations = [row["activation_confirmed"] for row in rows]
        assert confirmations == sorted(confirmations), "Activation confirmation moved backwards"
    else:
        assert all(not row["activation_confirmed"] for row in rows), "Rejection claimed activation"


def main():
    evidence = Path(sys.argv[1])
    manifest = json.loads((Path(__file__).parent / "expected-protocol-observations.json").read_text())
    assert hashlib.sha256(Path(manifest["source"]).read_bytes()).hexdigest() == manifest["source_sha256"], "Protocol observation schema source changed"
    marker = "configuration_protocol_runtime_observation "
    records = []
    for log in evidence.glob("configuration-*.log"):
        for line in log.read_text().splitlines():
            if marker in line:
                records.append(json.loads(line.split(marker, 1)[1]))
    phases = {phase: [row for row in records if row["phase"] == phase] for phase in (
        "startup-rejected-and-repaired", "startup-activated", "update-rejected", "update-repaired",
    )}
    identity = ("phase", "case", "fault", "retains")
    expected_keys = {tuple(row.get(field) for field in identity) for row in manifest["expected_rows"]}
    actual_keys = [tuple(row.get(field) for field in identity) for row in records]
    assert len(actual_keys) == len(expected_keys) and set(actual_keys) == expected_keys, "Pinned protocol matrix incomplete"
    assert sum(map(len, phases.values())) == len(records), "Unknown protocol observation phase"
    exact_rows(phases["startup-rejected-and-repaired"], FAULTS, ("case", "fault"))
    exact_rows(phases["startup-activated"], {(case,) for case in CASES}, ("case",))
    exact_rows(phases["update-rejected"], {(case, fault, retains) for case, fault in FAULTS for retains in (False, True)}, ("case", "fault", "retains"))
    exact_rows(phases["update-repaired"], {(case, retains) for case in CASES for retains in (False, True)}, ("case", "retains"))
    for row in phases["startup-rejected-and-repaired"]:
        assert not row["boundary"]["active"] and row["boundary"]["installed"] is None
        assert row["starts_before_commit"] == row["upstream_requests"] == 0
        assert row["workload_processes_before_commit"] == []
        assert row["repaired_installation"]["active"] and row["repaired_installation"]["installed"] is not None
        reports(row["reports"], 3)
        reports(row["accepted_reports"], 2)
        assert row["delivery"] == "controlled" and row["transport"] == "actual-authenticated-boundary"
    for row in phases["update-rejected"]:
        assert row["pid"] > 0 and row["start_ticks"] > 0 and row["starts"] == 1 and row["heartbeat"] > 0
        assert row["provider_revision"] == 5
        assert row["boundary"]["active"] == row["retains"]
        assert row["boundary"]["installed"] is not None
        reports(row["reports"], 3)
    for phase, credential in (("startup-activated", "cred-A"), ("update-repaired", "cred-B")):
        for row in phases[phase]:
            assert row["pid"] > 0 and row["start_ticks"] > 0 and row["starts"] == 1 and row["boundary"]["active"]
            assert row["boundary"]["installed"] is not None
            assert row["probe_scope"] == "installed-network-decision-and-credential-rewrite"
            assert row["upstream"] and all(f"Authorization: Bearer {credential}\r\n" in request for request in row["upstream"])
            if phase == "update-repaired":
                assert row["provider_revision"] == 6
                reports(row["reports"], 2)
            else:
                reports(row["accepted_reports"], 2)
            installed = row["installed"]
            if row["case"].startswith("Mcp"):
                expected = ["2025-03-26", "2025-11-25"] if row["case"] == "McpRevisions" else ["2025-11-25"]
                assert installed["mcp_versions"] == expected
            else:
                assert "mcp_versions" not in installed
    for case in CASES:
        for retains in (False, True):
            updates = [row for row in phases["update-rejected"] + phases["update-repaired"] if row["case"] == case and row["retains"] == retains]
            assert len({(row["pid"], row["start_ticks"]) for row in updates}) == 1, "Process identity changed during rejection or repair"
    (evidence / "protocol-observations.json").write_text(json.dumps(records, indent=2) + "\n")
    print("Protocol preparation/update observations passed with controlled gateway delivery and installed-decision/credential probes.")


if __name__ == "__main__":
    main()
