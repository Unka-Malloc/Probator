#!/usr/bin/env python3
"""Deterministic `va serve` double for probator-agent tests.

Speaks a4aa.v1 JSON-RPC NDJSON on stdio. Records every session/open so
tests can prove the host delegated binding failover instead of walking
candidates itself.
"""
import json
import os
import sys

STUB_DIR = os.environ.get("PROBATOR_VA_STUB_DIR", ".")
MODE = os.environ.get("PROBATOR_VA_STUB_MODE", "complete")
PROFILE = os.environ.get("PROBATOR_VA_STUB_PROFILE", "synthetic-reviewer")
AGENT = os.environ.get("PROBATOR_VA_STUB_AGENT", "opencode")
MODEL = os.environ.get("PROBATOR_VA_STUB_MODEL", "opencode/stub-free")
SESSION = os.environ.get("PROBATOR_VA_STUB_SESSION", "acp-stub-session")


def record(name, payload):
    path = os.path.join(STUB_DIR, name)
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(json.dumps(payload, sort_keys=True) + "\n")


def emit(message):
    sys.stdout.write(json.dumps(message) + "\n")
    sys.stdout.flush()


def reply(req_id, result):
    emit({"jsonrpc": "2.0", "id": req_id, "result": result})


def reject(req_id, code, stage, message):
    emit(
        {
            "jsonrpc": "2.0",
            "id": req_id,
            "error": {
                "code": -32603,
                "message": message,
                "data": {"code": code, "stage": stage, "retryable": False, "uncertainEffect": False},
            },
        }
    )


os.makedirs(STUB_DIR, exist_ok=True)
record(
    "va-spawned.jsonl",
    {
        "argv": sys.argv[1:],
        "virtual_agent_home": os.environ.get("VIRTUAL_AGENT_HOME", ""),
        "path": os.environ.get("PATH", ""),
    },
)

for line in sys.stdin:
    line = line.strip()
    if not line:
        continue
    try:
        request = json.loads(line)
    except json.JSONDecodeError:
        continue
    method = request.get("method")
    req_id = request.get("id")
    params = request.get("params") or {}
    if method == "session/open":
        record("session-open.jsonl", params)
        if MODE in ("refuse-open", "exhausted"):
            extra = {"attempts": 2} if MODE == "exhausted" else {}
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": "no candidate available",
                        "data": {
                            "code": "session_open_failed",
                            "stage": "session/open",
                            "retryable": False,
                            "uncertainEffect": False,
                            **extra,
                        },
                    },
                }
            )
            continue
        if MODE == "stale-resume" and params.get("resume"):
            reject(req_id, "resume_unsupported", "session/open", "stale resume")
            continue
        if MODE == "permanent-resume" and params.get("resume"):
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": "authorization failed for resume",
                        "data": {
                            "code": "auth_denied",
                            "stage": "session/open",
                            "retryable": False,
                            "uncertainEffect": False,
                        },
                    },
                }
            )
            continue
        if MODE == "uncertain-resume" and params.get("resume"):
            emit(
                {
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "error": {
                        "code": -32603,
                        "message": "resume transport dropped",
                        "data": {
                            "code": "resume_uncertain",
                            "stage": "session/open",
                            "retryable": True,
                            "uncertainEffect": True,
                        },
                    },
                }
            )
            continue
        reply(
            req_id,
            {
                "sessionId": "va-session-1",
                "nativeSessionId": SESSION,
                "custody": {
                    "selector": "binding:audit",
                    "profile": PROFILE,
                    "specHash": "spec",
                    "registryHash": "registry",
                },
                "sessionState": {"models": {"currentModelId": MODEL}},
                "agentInfo": {"name": AGENT, "version": "stub"},
            },
        )
    elif method == "session/prompt":
        record("session-prompt.jsonl", params)
        if MODE == "disconnect":
            break
        if MODE == "sealed-drop":
            emit(
                {
                    "jsonrpc": "2.0",
                    "method": "session/event",
                    "params": {
                        "sessionId": params.get("sessionId"),
                        "event": {
                            "kind": "usage",
                            "usage": {
                                "input": 9,
                                "output": 4,
                                "cachedInput": 2,
                                "cachedWrite": 1,
                            },
                        },
                    },
                }
            )
            break
        if MODE == "failed":
            reject(req_id, "agent_failed", "session/prompt", "stub failed")
            continue
        stop = "end_turn" if MODE not in ("interrupted",) else "max_tokens"
        emit(
            {
                "jsonrpc": "2.0",
                "method": "session/event",
                "params": {
                    "sessionId": params.get("sessionId"),
                    "event": {"kind": "message-chunk", "text": "ok"},
                },
            }
        )
        emit(
            {
                "jsonrpc": "2.0",
                "method": "session/event",
                "params": {
                    "sessionId": params.get("sessionId"),
                    "event": {
                        "kind": "usage",
                        "usage": {
                            "input": 9,
                            "output": 4,
                            "cachedInput": 2,
                            "cachedWrite": 1,
                        },
                    },
                },
            }
        )
        usage = {
            "input": 42 if MODE == "rpc" else 9,
            "output": 10 if MODE == "rpc" else 4,
            "cachedInput": 5 if MODE == "rpc" else 2,
            "cachedWrite": 2 if MODE == "rpc" else 1,
        }
        reply(
            req_id,
            {
                "stopReason": stop,
                "text": "ok",
                "truncated": False,
                "usage": usage,
            },
        )
    elif method in ("session/cancel", "session/close", "ping"):
        reply(req_id, {} if method != "ping" else {"protocol": "a4aa.v1", "version": "stub"})
    elif req_id is not None:
        emit(
            {
                "jsonrpc": "2.0",
                "id": req_id,
                "error": {"code": -32601, "message": f"method not found: {method}"},
            }
        )
