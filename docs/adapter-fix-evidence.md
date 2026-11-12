# Adapter Fix Evidence

Historical fix commit: `eff0fb9b16e72d94045888d7b852be1bb18a6a84`.

## Exact Diff

```diff
diff --git a/measurement/adapters/smolagents_adapter.py b/measurement/adapters/smolagents_adapter.py
index 0efce4e..b2963a2 100644
--- a/measurement/adapters/smolagents_adapter.py
+++ b/measurement/adapters/smolagents_adapter.py
@@ -4,9 +4,24 @@ import json
 from pathlib import Path
 
 
+class DelegationValidationError(Exception):
+    pass
+
+
+def _agent_has_activity(raw: dict, agent_name: str) -> bool:
+    # A registered agent "did something" only if at least one of its steps
+    # actually ran (non-null timing). A TaskStep placeholder alone means the
+    # agent was registered but never invoked.
+    steps = raw["agents"].get(agent_name, {}).get("steps", [])
+    return any(step.get("timing") for step in steps)
+
+
 def adapt(raw: dict, task_id: str) -> list[dict]:
     # A tool_call whose code invokes another known agent by name is
-    # delegation, not tool use, in a smolagents CodeAgent.
+    # delegation, not tool use, in a smolagents CodeAgent. A single code
+    # block can call more than one managed agent, so every registered
+    # agent name found in the code is its own delegation, not just the
+    # first one matched.
     agent_names = set(raw["agents"])
     events: list[dict] = []
     starts: list[float] = []
@@ -22,16 +37,19 @@ def adapt(raw: dict, task_id: str) -> list[dict]:
             ends.append(timing.get("end_time", ts))
             for tc in step.get("tool_calls", []):
                 args = tc.get("arguments")
-                target = next(
-                    (o for o in agent_names if o != agent_name and isinstance(args, str) and f"{o}(" in args),
-                    None,
-                )
-                if target:
+                targets = []
+                if isinstance(args, str):
+                    targets = sorted(
+                        (o for o in agent_names if o != agent_name and f"{o}(" in args),
+                        key=lambda o: args.find(f"{o}("),
+                    )
+                if targets:
+                    for target in targets:
+                        events.append({
+                            "event": "delegation", "task_id": task_id,
+                            "parent_agent_id": agent_name, "agent_id": target,
+                            "timestamp": ts,
+                        })
+                else:
                     events.append({
-                        "event": "delegation", "task_id": task_id,
-                        "parent_agent_id": agent_name, "agent_id": target,
+                        "event": "tool_call", "task_id": task_id,
+                        "agent_id": agent_name, "tool": tc["name"],
                         "timestamp": ts,
                     })
-                else:
-                    events.append({
-                        "event": "tool_call", "task_id": task_id,
-                        "agent_id": agent_name, "tool": tc["name"],
-                        "timestamp": ts,
-                    })
 
+    for e in events:
+        if e["event"] != "delegation":
+            continue
+        child = e["agent_id"]
+        if not _agent_has_activity(raw, child):
+            raise DelegationValidationError(
+                f"task {task_id}: delegation {e['parent_agent_id']!r} -> {child!r} has no "
+                f"corroborating activity from {child!r} in the raw trace (likely a comment, "
+                f"string, or dead-code match on the agent's name rather than a real call)"
+            )
+
     out = [{"event": "task_start", "task_id": task_id, "timestamp": min(starts)}]
     out.extend(events)
     out.append({"event": "task_end", "task_id": task_id, "timestamp": max(ends)})
```

## Tests

- `tests/test_smolagents_adapter.py::test_adapt_produces_one_delegation_and_valid_topology`
- `tests/test_smolagents_adapter.py::test_single_step_calling_two_agents_yields_two_delegations`
- `tests/test_smolagents_adapter.py::test_delegation_without_child_activity_fails_validation`

The multi-agent test confirms every registered agent matched in one step is recorded. The validation test rejects an unexecuted matched agent. Cycle handling remains in the unchanged topology layer; full pytest includes `tests/test_measurement.py::test_cycle_detected`, which still raises `TopologyError` for `a -> b -> a`.

`src/lineage_revocation/` has no diff in this evidence run.
