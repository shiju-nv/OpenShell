"""Build a separate Debian fixture image without changing shipping products."""

import hashlib
import json
from pathlib import Path
import re
import shutil
import uuid


HERE = Path(__file__).resolve().parent
PROBE = r"""set -eu
. /etc/os-release
printf 'FIXTURE_OS\t%s\t%s\n' "$ID" "$VERSION_ID"
dpkg-query -W -f='FIXTURE_PACKAGE\t${Package}\t${Version}\t${Architecture}\t${Status}\n' coreutils dash libc-bin libc6 libgcc-s1
test "$(id -u):$(id -g)" = 1000:1000
test -s /etc/passwd
test -s /etc/group
/bin/sh -c 'printf fixture > /tmp/fixture-probe'
test "$(/bin/cat /tmp/fixture-probe)" = fixture
/bin/sleep 0.01
/usr/bin/touch /tmp/fixture-touch
test -f /tmp/fixture-touch
printf 'FIXTURE_UTILITIES_OK\n'
sha256sum /bin/sh /bin/cat /bin/sleep /usr/bin/touch /lib64/ld-linux-x86-64.so.2
/openshell-supervisor --version
/activation-sandbox --version
for executable in /openshell-supervisor /activation-sandbox-tests /activation-supervisor-tests; do
    printf 'FIXTURE_LINKS_BEGIN\t%s\n' "$executable"
    ldd "$executable"
    printf 'FIXTURE_LINKS_END\t%s\n' "$executable"
done
"""


def require(condition, message):
    """Reject inconsistent fixture identities before any proof invocation."""
    if not condition:
        raise ValueError(message)


def digest(path):
    """Hash retained executables and receipts without loading large files."""
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def reference(path):
    """Record the exact local asset consumed by a fixture operation."""
    return {"path": str(path), "sha256": digest(path)}


def inspection(raw, expected_id=None):
    """Use exactly one native Linux image with its immutable config identity."""
    rows = json.loads(raw)
    require(isinstance(rows, list) and len(rows) == 1, "Ambiguous fixture image inspection")
    image = rows[0]
    require(image.get("Os") == "linux" and image.get("Architecture") == "amd64", "Fixture image platform differs")
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image.get("Id", "")), "Invalid fixture image identity")
    require(expected_id is None or image["Id"] == expected_id, "Fixture image identity differs")
    return image


def verify_probe(raw, pins):
    """Require package, utility, identity and loader checks from one real probe."""
    lines = raw.splitlines()
    require([line for line in lines if line.startswith("FIXTURE_OS\t")] ==
            ["FIXTURE_OS\t" + pins["os"] + "\t" + pins["version_id"]], "Fixture release differs")
    packages = {}
    for line in lines:
        if not line.startswith("FIXTURE_PACKAGE\t"):
            continue
        fields = line.split("\t")
        require(len(fields) == 5, "Malformed fixture package receipt")
        _, name, version, arch, status = fields
        require(name not in packages and version and arch == pins["architecture"] and
                status == "install ok installed", "Fixture package is absent, duplicated or foreign")
        packages[name] = {"version": version, "architecture": arch, "status": status}
    require(set(packages) == set(pins["required_packages"]), "Fixture package set differs")
    require(lines.count("FIXTURE_UTILITIES_OK") == 1, "Fixture utility exercise is incomplete")
    tools = {}
    for line in lines:
        match = re.fullmatch(r"([0-9a-f]{64})  (/(?:bin/(?:sh|cat|sleep)|usr/bin/touch|lib64/ld-linux-x86-64.so.2))", line)
        if match:
            require(match[2] not in tools, "Duplicate fixture utility digest")
            tools[match[2]] = match[1]
    require(set(tools) == {"/bin/sh", "/bin/cat", "/bin/sleep", "/usr/bin/touch", "/lib64/ld-linux-x86-64.so.2"}, "Fixture utility bytes are incomplete")
    for binary in ("openshell-supervisor", "openshell-sandbox"):
        require(len([line for line in lines if line.startswith(binary + " ")]) == 1, "Fixture executable did not report its version")
    linkages = {}
    for binary in ("/openshell-supervisor", "/activation-sandbox-tests", "/activation-supervisor-tests"):
        start, end = "FIXTURE_LINKS_BEGIN\t" + binary, "FIXTURE_LINKS_END\t" + binary
        require(lines.count(start) == lines.count(end) == 1, "Fixture dependency probe is incomplete")
        first, last = lines.index(start), lines.index(end)
        require(first < last, "Fixture dependency probe is reordered")
        body = lines[first + 1:last]
        require(body and not any("not found" in line for line in body) and
                any("ld-linux-x86-64.so.2" in line for line in body), "Unresolved GNU fixture dependencies")
        linkages[binary] = body
    return {"packages": packages, "utilities": tools, "linkages": linkages}


def prepare(helper, source, logs, evidence, shipping, supervisor, sandbox, builds, expected_files):
    """Build and attest one proof environment from the current shipping binary.

    Product images remain separate. This image supplies the real workload
    utilities needed by libtests while retaining the exact supervisor bytes.
    """
    for name in ("fixture_image.py", "fixture-image.Dockerfile", "fixture-image-pins.json"):
        require(digest(HERE / name) == expected_files[name], "Fixture producer input changed: " + name)
    pins = json.loads((HERE / "fixture-image-pins.json").read_text())
    require(pins["schema_version"] == 1 and pins["base_reference"] ==
            "docker.io/library/debian@" + pins["base_manifest_digest"], "Fixture base is not digest pinned")
    directory = evidence / "fixture-image"
    directory.mkdir(exist_ok=False)
    context = directory / "context"
    context.mkdir()
    dockerfile = HERE / "fixture-image.Dockerfile"
    shutil.copyfile(dockerfile, context / "Dockerfile")
    run = lambda name, argv: helper.run(source, logs, "fixture-" + name, argv)
    shipping_before = inspection(run("shipping-before", ["docker", "image", "inspect", shipping["reference"]]), shipping["id"])
    suffix = uuid.uuid4().hex[:12]
    cid = run("extract-create", ["docker", "create", "--name", "acceptance-fixture-source-" + suffix,
                                "--network", "none", "--entrypoint", "/unused", shipping["id"]]).strip()
    require(re.fullmatch(r"[0-9a-f]{64}", cid), "Malformed fixture extraction container")
    copied = context / "openshell-supervisor"
    try:
        run("extract-copy", ["docker", "cp", cid + ":/openshell-supervisor", str(copied)])
        require(digest(copied) == digest(supervisor), "Shipping and downloaded supervisor bytes differ")
    finally:
        run("extract-remove", ["docker", "rm", cid])
    run("base-pull", ["docker", "pull", "--platform", "linux/amd64", pins["base_reference"]])
    base = inspection(run("base-inspect", ["docker", "image", "inspect", pins["base_reference"]]), pins["base_config_digest"])
    canonical_digests = {pins["base_reference"], "debian@" + pins["base_manifest_digest"]}
    require(canonical_digests.intersection(base.get("RepoDigests", [])), "Fixture base manifest digest differs")
    tag = "openshell/acceptance-fixture:" + suffix
    run("build", ["docker", "build", "--platform", "linux/amd64", "--network", "none", "--file", str(context / "Dockerfile"),
                  "--target", "fixture", "--tag", tag, str(context)])
    image = inspection(run("inspect", ["docker", "image", "inspect", tag]))
    require(image["Config"].get("Entrypoint") == ["/openshell-supervisor"] and
            image["Config"].get("Cmd") in (None, []) and
            image["Config"].get("User", "") in ("", "0", "0:0"), "Fixture default launch differs")
    cid = run("verify-create", ["docker", "create", "--name", "acceptance-fixture-verify-" + suffix,
                               "--network", "none", "--entrypoint", "/unused", image["Id"]]).strip()
    require(re.fullmatch(r"[0-9a-f]{64}", cid), "Malformed fixture verification container")
    extracted = directory / "supervisor-image-binary"
    try:
        run("verify-copy", ["docker", "cp", cid + ":/openshell-supervisor", str(extracted)])
        require(digest(extracted) == digest(copied), "Fixture image changed the supervisor executable")
    finally:
        run("verify-remove", ["docker", "rm", cid])
    mounts = {"/activation-sandbox": sandbox, "/activation-sandbox-tests": Path(builds["sandbox"]["executable"]),
              "/activation-supervisor-tests": Path(builds["supervisor"]["executable"])}
    argv = ["docker", "run", "--rm", "--network", "none", "--user", "1000:1000", "--cap-drop", "ALL",
            "--security-opt", "seccomp=unconfined", "--security-opt", "no-new-privileges=true",
            "--read-only", "--tmpfs", "/tmp:rw,nosuid,nodev"]
    for target, path in mounts.items():
        argv += ["--mount", "type=bind,source=" + str(path) + ",target=" + target + ",readonly"]
    argv += ["--entrypoint", "/bin/sh", image["Id"], "-c", PROBE]
    probe = verify_probe(run("probe", argv), pins)
    inspection(run("shipping-after", ["docker", "image", "inspect", shipping["reference"]]), shipping["id"])
    inspection(run("after", ["docker", "image", "inspect", tag]), image["Id"])
    result = {"schema_version": 1, "passed": True, "scope": "isolated libtest fixture environment",
              "shipping_image": {"reference": shipping["reference"], "id": shipping_before["Id"]},
              "image": {"reference": tag, "id": image["Id"]}, "base": pins,
              "producer_files": {name: reference(HERE / name) for name in expected_files},
              "supervisor_chain": {"downloaded": reference(supervisor), "shipping_extracted": reference(copied), "fixture_extracted": reference(extracted)},
              "probe": probe, "probe_command": argv, "probe_mounts": {target: reference(path) for target, path in mounts.items()}}
    helper.save(directory / "result.json", result)
    return result
