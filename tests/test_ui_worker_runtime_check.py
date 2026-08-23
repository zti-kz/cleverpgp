from __future__ import annotations

import json

from biopgp.runtime_check import run_ui_worker


def test_ui_worker_runtime_check_completes(tmp_path) -> None:
    marker = tmp_path / "ui-worker.json"

    assert run_ui_worker(marker) == 0

    result = json.loads(marker.read_text(encoding="utf-8"))
    assert result["status"] == "ok"
    assert result["result"] == "completed"
    assert result["progress"] == [[37, "working"]]
