"""Real SBOM, local key signing, verification and blocking vulnerability scan."""

import json
import os
import subprocess
import tempfile
from pathlib import Path


def threshold_blocked(returncode: int, report: dict) -> bool:
    return returncode == 2 and any(
        match.get("vulnerability", {}).get("severity") in {"High", "Critical"}
        for match in report.get("matches", [])
    )


def benchmark() -> dict:
    tools = Path(".cache/bin").resolve()
    versions = {}
    for name in ["syft", "cosign", "grype"]:
        versions[name] = subprocess.check_output(
            [str(tools / name), "version"], text=True, stderr=subprocess.STDOUT
        ).strip()
    sbom = Path("evidence/sbom.cdx.json").resolve()
    with sbom.open("w") as out:
        subprocess.run(
            [str(tools / "syft"), "dir:data", "-o", "cyclonedx-json"], stdout=out, check=True
        )
    with tempfile.TemporaryDirectory() as directory:
        env = {**os.environ, "COSIGN_PASSWORD": ""}
        key = Path(directory) / "cosign"
        subprocess.run(
            [str(tools / "cosign"), "generate-key-pair", "--output-key-prefix", str(key)],
            env=env,
            check=True,
            capture_output=True,
        )
        signature = Path("evidence/sbom.sig").resolve()
        subprocess.run(
            [
                str(tools / "cosign"),
                "sign-blob",
                "--key",
                str(key) + ".key",
                "--tlog-upload=false",
                "--output-signature",
                str(signature),
                str(sbom),
            ],
            env=env,
            check=True,
            capture_output=True,
        )
        public = Path("evidence/cosign.pub")
        public.write_bytes(Path(str(key) + ".pub").read_bytes())
        verified = subprocess.run(
            [
                str(tools / "cosign"),
                "verify-blob",
                "--key",
                str(public),
                "--signature",
                str(signature),
                "--insecure-ignore-tlog",
                str(sbom),
            ],
            capture_output=True,
            text=True,
            check=True,
        )
        Path("evidence/verification.log").write_text(verified.stdout + verified.stderr)
    scan = subprocess.run(
        [str(tools / "grype"), "sbom:" + str(sbom), "--fail-on", "high", "-o", "json"],
        capture_output=True,
        text=True,
        check=False,
    )
    Path("evidence/grype.json").write_text(scan.stdout)
    report = json.loads(scan.stdout)
    blocked = threshold_blocked(scan.returncode, report)
    Path("evidence/gate-failure.log").write_text(
        f"grype sbom:evidence/sbom.cdx.json --fail-on high\nexit_code={scan.returncode}\n"
        + scan.stderr
        + f"\nVulnerability matches: {len(report.get('matches', []))}\n"
    )
    assert blocked, "scanner failed or bad dependency was not blocked"
    return {
        "sbom_components": len(json.loads(sbom.read_text()).get("components", [])),
        "signature_verified": True,
        "signatures_verified": int(verified.returncode == 0),
        "vulnerability_matches": len(report["matches"]),
        "bad_build_blocked": blocked,
        "versions": versions,
    }


if __name__ == "__main__":
    print(json.dumps(benchmark(), indent=2))
