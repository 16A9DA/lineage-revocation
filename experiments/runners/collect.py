from __future__ import annotations

import json
import os
import signal
import time
from pathlib import Path


class TaskTimeout(Exception):
    pass


def _alarm(signum, frame):
    raise TaskTimeout("task exceeded wall-clock budget")

import requests
from smolagents import CodeAgent, MultiStepAgent, OpenAIServerModel, ToolCallingAgent, WebSearchTool

from experiments.configs.workloads import WORKLOADS
from measurement.adapters.smolagents_adapter import adapt

ROOT = Path(__file__).resolve().parents[2]
RAW_DIR = ROOT / "artifacts" / "raw_traces"
NORM_DIR = ROOT / "experiments" / "traces" / "normalized"


class TimedWebSearchTool(WebSearchTool):
    # WebSearchTool.search_duckduckgo/search_bing call requests.get with no
    # timeout and no safe-search, in the underlying smolagents implementation;
    # a stalled response hangs the run forever, and an unfiltered query can
    # return illegal/objectionable content (observed directly: a benign
    # research prompt returned CSAM-adjacent results with safe-search off).
    # Same requests, bounded and filtered.
    def search_duckduckgo(self, query: str) -> list:
        response = requests.get(
            "https://lite.duckduckgo.com/lite/",
            params={"q": query, "kp": "1"},  # kp=1: strict safe-search
            headers={"User-Agent": "Mozilla/5.0"},
            timeout=15,
        )
        response.raise_for_status()
        parser = self._create_duckduckgo_parser()
        parser.feed(response.text)
        return parser.results

    def search_bing(self, query: str) -> list:
        import xml.etree.ElementTree as ET

        response = requests.get(
            "https://www.bing.com/search",
            params={"q": query, "format": "rss", "adlt": "strict"},  # adlt=strict: safe-search
            timeout=15,
        )
        response.raise_for_status()
        root = ET.fromstring(response.text)
        items = root.findall(".//item")
        return [
            {
                "title": item.findtext("title"),
                "link": item.findtext("link"),
                "description": item.findtext("description"),
            }
            for item in items[: self.max_results]
        ]


def _step_to_dict(step) -> dict:
    return {
        "step_type": type(step).__name__,
        "step_number": getattr(step, "step_number", None),
        "timing": {
            "start_time": getattr(step.timing, "start_time", None),
            "end_time": getattr(step.timing, "end_time", None),
        } if getattr(step, "timing", None) else None,
        "tool_calls": [
            {"name": tc.name, "arguments": tc.arguments}
            for tc in (getattr(step, "tool_calls", None) or [])
        ],
        "error": str(step.error) if getattr(step, "error", None) else None,
    }


def _build(topology: str, model) -> tuple[str, dict[str, MultiStepAgent]]:
    if topology == "solo":
        name = "solo_agent"
        agent = ToolCallingAgent(
            tools=[TimedWebSearchTool(engine="bing")], model=model, name=name, max_steps=6,
            description="Answers questions, searching the web as needed.",
        )
        return name, {name: agent}

    research_name = "research_agent"
    research_agent = ToolCallingAgent(
        tools=[TimedWebSearchTool(engine="bing")], model=model, name=research_name, max_steps=6,
        description="Searches the web and returns findings for a given question.",
    )
    managed: list[MultiStepAgent] = [research_agent]
    agents: dict[str, MultiStepAgent] = {research_name: research_agent}

    if topology == "manager_2":
        math_name = "math_agent"
        math_agent = CodeAgent(
            tools=[], model=model, name=math_name, max_steps=6,
            description="Performs numeric calculations given the needed numbers.",
        )
        managed.append(math_agent)
        agents[math_name] = math_agent

    manager_name = "manager_agent"
    manager = CodeAgent(
        tools=[], model=model, managed_agents=managed, max_steps=6,
        name=manager_name, description="Delegates to specialists as needed.",
    )
    agents[manager_name] = manager
    return manager_name, agents


def run_one(workload_id: str, topology: str, task: str, run_id: str, model) -> Path:
    root_name, agents = _build(topology, model)
    agents[root_name].run(task)

    raw = {
        "workload_id": workload_id,
        "run_id": run_id,
        "task": task,
        "root_agent": root_name,
        "agents": {
            name: {"steps": [_step_to_dict(s) for s in agent.memory.steps]}
            for name, agent in agents.items()
        },
    }
    task_id = f"{workload_id}_{run_id}"
    RAW_DIR.mkdir(parents=True, exist_ok=True)
    (RAW_DIR / f"{task_id}.json").write_text(json.dumps(raw, indent=2, default=str))

    NORM_DIR.mkdir(parents=True, exist_ok=True)
    norm_path = NORM_DIR / f"{task_id}.jsonl"
    events = adapt(raw, task_id)
    norm_path.write_text("\n".join(json.dumps(e) for e in events) + "\n")
    return norm_path


MAX_ATTEMPTS = 3


def _record_failure(workload_id: str, index: int, task: str, attempts: list[dict]) -> None:
    fail_dir = RAW_DIR / "failed"
    fail_dir.mkdir(parents=True, exist_ok=True)
    task_id = f"{workload_id}_{index:02d}_{int(time.time())}"
    record = {"workload_id": workload_id, "index": index, "task": task, "status": "failed", "attempts": attempts}
    (fail_dir / f"{task_id}.json").write_text(json.dumps(record, indent=2, default=str))


def main() -> None:
    model = OpenAIServerModel(
        # gpt-oss-120b intermittently emits tool-call JSON on CodeAgent's plain
        # code-gen turns (no tools registered there); Groq then 400s with
        # "Tool choice is none, but model called a tool". qwen3.6-27b doesn't
        # share that habit.
        model_id="qwen/qwen3.6-27b",
        api_base="https://api.groq.com/openai/v1",
        api_key=os.environ["GROQ_API_KEY"],
        client_kwargs={"timeout": 60.0, "max_retries": 2},
    )
    signal.signal(signal.SIGALRM, _alarm)
    ok, failed, skipped = 0, 0, 0
    for workload_id, topology, tasks in WORKLOADS:
        for i, task in enumerate(tasks):
            if any(RAW_DIR.glob(f"{workload_id}_{i:02d}_*.json")):
                skipped += 1
                continue
            attempts: list[dict] = []
            success = False
            for attempt in range(1, MAX_ATTEMPTS + 1):
                run_id = f"{i:02d}_{int(time.time())}"
                signal.alarm(150)
                try:
                    run_one(workload_id, topology, task, run_id, model)
                    success = True
                    break
                except Exception as exc:
                    attempts.append(
                        {"attempt": attempt, "run_id": run_id, "error_type": type(exc).__name__, "error": str(exc)}
                    )
                finally:
                    signal.alarm(0)
            if success:
                ok += 1
                suffix = f" (attempt {attempt})" if attempt > 1 else ""
                print(f"[{ok + failed}] {workload_id} {run_id}: ok{suffix}")
            else:
                failed += 1
                _record_failure(workload_id, i, task, attempts)
                print(
                    f"[{ok + failed}] {workload_id} {i:02d}: FAILED after {MAX_ATTEMPTS} attempts "
                    f"({attempts[-1]['error_type']})"
                )
    print(f"collected {ok} real traces, {failed} failed, {skipped} skipped (already present)")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
