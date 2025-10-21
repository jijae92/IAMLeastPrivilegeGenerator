import json
import subprocess
import sys
from pathlib import Path


def test_pr_comment_outputs(tmp_path: Path) -> None:
    repo_root = Path(__file__).resolve().parents[1]
    input_json = repo_root / "tests/golden/sample_pip_audit.json"
    allowlist = repo_root / "tests/golden/sample_allowlist.json"
    expected = json.loads((repo_root / "tests/golden/expected_scan.json").read_text(encoding="utf-8"))["comment"].strip()

    sarif_path = tmp_path / "scan.sarif"
    comment_path = tmp_path / "comment.md"

    subprocess.run(
        [
            sys.executable,
            str(repo_root / "scripts/pr_comment.py"),
            "--input",
            str(input_json),
            "--sarif",
            str(sarif_path),
            "--top",
            "10",
            "--output",
            str(comment_path),
            "--allowlist",
            str(allowlist),
        ],
        check=True,
    )

    comment = comment_path.read_text(encoding="utf-8").strip()
    assert comment == expected

    sarif = json.loads(sarif_path.read_text(encoding="utf-8"))
    results = sarif.get("runs", [{}])[0].get("results", [])
    assert results, "Expected SARIF results"
    assert any(r.get("properties", {}).get("waived") for r in results), "Expected at least one waived finding"
