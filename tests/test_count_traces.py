import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_count_traces_separates_datasets_and_matches_disk(tmp_path):
    out = tmp_path / "c.json"
    subprocess.run([sys.executable, str(ROOT / "scripts/count_traces.py"), "--json", str(out)], check=True, capture_output=True)
    res = json.loads(out.read_text())
    assert set(res) == {"groq", "haiku", "smoke"}  # never pooled, no combined total
    for name, d in (("groq", "artifacts/raw_traces"), ("haiku", "artifacts/raw_traces_haiku")):
        assert res[name]["raw_trace_files"] == len(list((ROOT / d).glob("*.json")))
        assert res[name]["raw_valid_json"] + len(res[name]["raw_invalid_json"]) == res[name]["raw_trace_files"]
