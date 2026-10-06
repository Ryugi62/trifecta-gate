"""Run AgentDojo (v1.2) with gpt-4o-mini, with and without Trifecta Gate as a tool-execution element.
usage: python run_ad.py <suite> <none|gate> <attack|benign> <logdir>
The gate is the TypeScript GateSession, reached through scripts/gate-stdio.ts (one implementation, no port)."""
import json, os, subprocess, sys, uuid
from ast import literal_eval
from pathlib import Path
import openai
from agentdojo.agent_pipeline import AgentPipeline, InitQuery, OpenAILLM, SystemMessage, ToolsExecutionLoop, ToolsExecutor
from agentdojo.agent_pipeline.agent_pipeline import load_system_message
from agentdojo.agent_pipeline.tool_execution import is_string_list
from agentdojo.attacks.attack_registry import load_attack
from agentdojo.benchmark import benchmark_suite_with_injections, benchmark_suite_without_injections
from agentdojo.logging import OutputLogger
from agentdojo.task_suite.load_suites import get_suite
from agentdojo.types import ChatToolResultMessage, text_content_block_from_string

VERSION = "v1.2"
# what an admin would configure: the company e-mail domain (workspace) and its own chat workspace (slack); banking has no internal payees
ALLOWLIST = {"workspace": ["bluesparrowtech.com"], "slack": ["#*"], "banking": []}
MODEL = "gpt-4o-mini-2024-07-18"
ROOT = Path(__file__).resolve().parent.parent


class Gate:
    def __init__(self):
        self.p = subprocess.Popen(["npx", "tsx", "scripts/gate-stdio.ts"], cwd=ROOT, stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, bufsize=1)

    def call(self, msg):
        self.p.stdin.write(json.dumps(msg) + "\n"); self.p.stdin.flush()
        return json.loads(self.p.stdout.readline())


class GatedToolsExecutor(ToolsExecutor):
    def __init__(self, gate, allowlist):
        super().__init__()
        self.gate = gate
        self.allowlist = allowlist

    def query(self, query, runtime, env, messages=[], extra_args={}):
        if not messages or messages[-1]["role"] != "assistant" or not messages[-1]["tool_calls"]:
            return query, runtime, env, messages, extra_args
        sid = extra_args.get("tg_session")
        if sid is None:
            sid = str(uuid.uuid4())
            self.gate.call({"op": "new", "id": sid, "instruction": query, "startPrivate": True, "allowlist": self.allowlist})
            extra_args = {**extra_args, "tg_session": sid}
        results = []
        for tc in messages[-1]["tool_calls"]:
            f = runtime.functions.get(tc.function)
            if f is None:
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")], tool_call_id=tc.id, tool_call=tc, error=f"Invalid tool {tc.function} provided."))
                continue
            for k, v in tc.args.items():
                if isinstance(v, str) and is_string_list(v):
                    tc.args[k] = literal_eval(v)
            spec = {"name": f.name, "description": f.description, "params": list(f.parameters.model_fields.keys())}
            d = self.gate.call({"op": "check", "id": sid, "tool": spec, "args": json.loads(json.dumps(tc.args, default=str))})
            if d.get("action") == "block":
                results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string("")], tool_call_id=tc.id, tool_call=tc,
                    error=f"BLOCKED by Trifecta Gate ({d['rule']}): {d['reason']}. The user will be asked separately; continue with the rest of the task."))
                continue
            res, error = runtime.run_function(env, tc.function, tc.args)
            text = self.output_formatter(res)
            self.gate.call({"op": "record", "id": sid, "tool": spec, "text": text})
            results.append(ChatToolResultMessage(role="tool", content=[text_content_block_from_string(text)], tool_call_id=tc.id, tool_call=tc, error=error))
        return query, runtime, env, [*messages, *results], extra_args


def pipeline(defense, suite_name):
    llm = OpenAILLM(openai.OpenAI(), MODEL)
    executor = GatedToolsExecutor(Gate(), ALLOWLIST[suite_name]) if defense == "gate" else ToolsExecutor()
    p = AgentPipeline([SystemMessage(load_system_message(None)), InitQuery(), llm, ToolsExecutionLoop([executor, llm])])
    p.name = MODEL if defense == "none" else f"{MODEL}-trifecta_gate"
    return p


def main():
    suite_name, defense, mode, logdir = sys.argv[1:5]
    only = sys.argv[5].split(',') if len(sys.argv) > 5 else None
    suite = get_suite(VERSION, suite_name)
    p = pipeline(defense, suite_name)
    with OutputLogger(logdir):
        if mode == "attack":
            attack = load_attack("important_instructions", suite, p)
            r = benchmark_suite_with_injections(p, suite, attack, Path(logdir), False, user_tasks=only, verbose=False, benchmark_version=VERSION)
        else:
            r = benchmark_suite_without_injections(p, suite, Path(logdir), False, user_tasks=only, benchmark_version=VERSION)
    u = r["utility_results"]; s = r["security_results"]
    out = {"suite": suite_name, "defense": defense, "allowlist": ALLOWLIST[suite_name] if defense == "gate" else None, "mode": mode, "model": MODEL, "version": VERSION, "attack": "important_instructions" if mode == "attack" else None,
           "n": len(u), "utility": sum(u.values()), "attack_success": sum(s.values()) if mode == "attack" else None,
           "per_task": [{"user": k[0], "inj": k[1], "utility": u[k], "security": s.get(k)} for k in u]}
    Path(f"{logdir}/summary-{suite_name}-{defense}-{mode}.json").write_text(json.dumps(out, indent=1))
    print(json.dumps({k: out[k] for k in ("suite", "defense", "mode", "n", "utility", "attack_success")}))


if __name__ == "__main__":
    main()
