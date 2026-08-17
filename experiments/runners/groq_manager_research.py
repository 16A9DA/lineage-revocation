# First real agent workload: User -> Manager -> Research agent -> web search tool.
# Runs against Groq via smolagents' OpenAI-compatible endpoint. Captures the
# raw smolagents memory trace to artifacts/raw_traces/ (JSON, no API key in it).
from __future__ import annotations

import json
import os
import time
from pathlib import Path

from smolagents import CodeAgent, OpenAIServerModel, ToolCallingAgent, WebSearchTool

RAW_TRACE_DIR = Path(__file__).resolve().parents[2] / "artifacts" / "raw_traces"


def _step_to_dict(step) -> dict:
    return {
        "step_type": type(step).__name__,
        "step_number": getattr(step, "step_number", None),
        "timing": {
            "start_time": getattr(step.timing, "start_time", None),
            "end_time": getattr(step.timing, "end_time", None),
            "duration": getattr(step.timing, "duration", None),
        }
        if getattr(step, "timing", None)
        else None,
        "tool_calls": [
            {"name": tc.name, "arguments": tc.arguments}
            for tc in (getattr(step, "tool_calls", None) or [])
        ],
        "error": str(step.error) if getattr(step, "error", None) else None,
    }


def main() -> None:
    model = OpenAIServerModel(
        model_id="llama-3.3-70b-versatile",
        api_base="https://api.groq.com/openai/v1",
        api_key=os.environ["GROQ_API_KEY"],
    )

    research_agent = ToolCallingAgent(
        tools=[WebSearchTool()],
        model=model,
        name="research_agent",
        description="Searches the web and returns findings for a given question.",
    )

    manager_agent = CodeAgent(
        tools=[],
        model=model,
        managed_agents=[research_agent],
        name="manager_agent",
        description="Delegates research questions to research_agent.",
    )

    task = "What is the current version of the Python programming language?"
    manager_agent.run(task)

    trace = {
        "task": task,
        "manager": {
            "name": manager_agent.name,
            "steps": [_step_to_dict(s) for s in manager_agent.memory.steps],
        },
        "research_agent": {
            "name": research_agent.name,
            "steps": [_step_to_dict(s) for s in research_agent.memory.steps],
        },
    }

    RAW_TRACE_DIR.mkdir(parents=True, exist_ok=True)
    out_path = RAW_TRACE_DIR / f"groq_manager_research_{int(time.time())}.json"
    out_path.write_text(json.dumps(trace, indent=2, default=str))
    print(f"raw trace written: {out_path}")


if __name__ == "__main__":
    main()
