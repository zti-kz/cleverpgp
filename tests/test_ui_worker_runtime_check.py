from __future__ import annotations

import json
import subprocess
import sys


def test_ui_worker_runtime_check_completes(tmp_path) -> None:
    marker = tmp_path / "ui-worker.json"

    completed = subprocess.run(
        [sys.executable, "-m", "cleverpgp", "--ui-worker-check", str(marker)],
        check=False,
        capture_output=True,
        text=True,
        timeout=20,
    )

    assert completed.returncode == 0, completed.stderr

    result = json.loads(marker.read_text(encoding="utf-8"))
    assert result["status"] == "ok"
    assert result["result"]["created_size"] > 32 * 1024 * 1024
    assert [100, "completed"] in result["progress"]
