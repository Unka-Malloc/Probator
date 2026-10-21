#!/usr/bin/env python3
"""Minimal ACP agent double for the Probator audit-host tests.

Protocol: ACP v1 over NDJSON stdio. Behavior is steered by files under
STUB_DIR (declared as a literal env entry in the fixture's registry.json):

- acp.mode: complete (default) | failed | interrupted | disconnect
- fixture-instructions.txt: receives the verbatim prompt text
- mcp_servers.json: receives the session/new mcpServers params verbatim
- stub-trace.jsonl: every session/prompt and session/set_config_option
- STUB_MODELS: comma list the model option offers (defaults to STUB_MODEL)
- STUB_QUOTA: comma list of models that answer prompts with a rate-limit
  error — the model-fallback test surface
- STUB_SESSION: session id to report (defaults to acp-stub-session)
"""
import json
import os
import sys

BASE = os.environ.get("STUB_DIR", ".")
MODE_FILE = os.path.join(BASE, "acp.mode")
MODE = open(MODE_FILE).read().strip() if os.path.exists(MODE_FILE) else "complete"
MODEL = os.environ.get("STUB_MODEL", "opencode/stub-free")
MODELS = [m for m in os.environ.get("STUB_MODELS", MODEL).split(",") if m]
QUOTA = [m for m in os.environ.get("STUB_QUOTA", "").split(",") if m]
SESSION = os.environ.get("STUB_SESSION", "acp-stub-session")


def emit(value):
    sys.stdout.write(json.dumps(value) + "\n")
    sys.stdout.flush()


def trace(event):
    with open(os.path.join(BASE, "stub-trace.jsonl"), "a") as handle:
        handle.write(json.dumps(event) + "\n")


def config_options(model):
    return [
        {
            "id": "cfg-model",
            "name": "Model",
            "category": "model",
            "type": "select",
            "currentValue": model,
            "options": [{"value": m, "name": m} for m in MODELS],
        }
    ]


current = {"model": os.environ.get("STUB_CURRENT_MODEL", MODEL)}

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        frame = json.loads(line)
    except ValueError:
        continue
    fid = frame.get("id")
    method = frame.get("method", "")
    params = frame.get("params") or {}
    if not method:
        continue
    if method == "initialize":
        emit({"jsonrpc": "2.0", "id": fid, "result": {
            "protocolVersion": 1,
            "agentCapabilities": {"loadSession": True},
            "agentInfo": {"name": "acp-stub", "version": "0"},
            "authMethods": []}})
    elif method == "session/new":
        with open(os.path.join(BASE, "mcp_servers.json"), "w") as handle:
            json.dump(params.get("mcpServers", []), handle)
        emit({"jsonrpc": "2.0", "id": fid, "result": {
            "sessionId": SESSION,
            "configOptions": config_options(current["model"])}})
    elif method in ("session/load", "session/resume"):
        emit({"jsonrpc": "2.0", "id": fid, "result": {
            "sessionId": params.get("sessionId", SESSION),
            "configOptions": config_options(current["model"])}})
    elif method == "session/set_config_option":
        current["model"] = params.get("value", current["model"])
        trace({"method": method, "model": current["model"]})
        emit({"jsonrpc": "2.0", "id": fid, "result": {
            "configOptions": config_options(current["model"])}})
    elif method == "session/set_model":
        current["model"] = params.get("modelId", current["model"])
        emit({"jsonrpc": "2.0", "id": fid, "result": {}})
    elif method == "session/prompt":
        text = "".join(
            part.get("text", "")
            for part in params.get("prompt", [])
            if isinstance(part, dict)
        )
        with open(os.path.join(BASE, "fixture-instructions.txt"), "w") as handle:
            handle.write(text)
        trace({"method": method, "model": current["model"]})
        if current["model"] in QUOTA:
            emit({"jsonrpc": "2.0", "id": fid,
                  "error": {"code": -32000,
                            "message": "AI.Error: Rate limit exceeded. "
                                       "Please try again later."}})
            continue
        if MODE == "disconnect":
            os._exit(3)
        if MODE == "failed":
            emit({"jsonrpc": "2.0", "id": fid,
                  "error": {"code": -32000, "message": "agent failed"}})
            continue
        emit({"jsonrpc": "2.0", "method": "session/update", "params": {
            "sessionId": params.get("sessionId", SESSION),
            "update": {"sessionUpdate": "agent_message_chunk",
                       "content": {"type": "text", "text": "echo"}}}})
        if MODE == "interrupted":
            emit({"jsonrpc": "2.0", "id": fid, "result": {"stopReason": "interrupted"}})
            continue
        emit({"jsonrpc": "2.0", "id": fid, "result": {
            "stopReason": "end_turn",
            "usage": {"inputTokens": 9, "outputTokens": 4,
                      "cachedReadTokens": 2, "cachedWriteTokens": 1,
                      "totalTokens": 15}}})
    elif method == "session/cancel":
        continue
    elif fid is not None:
        emit({"jsonrpc": "2.0", "id": fid,
              "error": {"code": -32601, "message": "unknown method"}})
