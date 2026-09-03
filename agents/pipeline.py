"""SentinelAI Agentic Pipeline -- LangGraph with Groq LLM.

Defines three LLM-backed nodes (triage, severity, response) wired into a
sequential LangGraph StateGraph.  Each node calls the Groq API via
langchain-groq and includes error handling for API failures.
"""

from __future__ import annotations

import json
import os
from typing import TypedDict

from dotenv import load_dotenv
from langchain_groq import ChatGroq
from langchain_core.messages import HumanMessage, SystemMessage
from langgraph.graph import END, StateGraph

from attack_mapping import map_attack_techniques

# ---------------------------------------------------------------------------
# Load environment variables
# ---------------------------------------------------------------------------

from pathlib import Path
load_dotenv(Path(__file__).resolve().parent / ".env")
load_dotenv()

_GROQ_API_KEY: str = os.getenv("GROQ_API_KEY", "")
_GROQ_MODEL: str = os.getenv("GROQ_MODEL", "qwen/qwen3.6-27b")


def _get_llm() -> ChatGroq:
    """Return a configured ChatGroq instance."""
    api_key = os.getenv("GROQ_API_KEY") or _GROQ_API_KEY
    if not api_key:
        raise EnvironmentError(
            "GROQ_API_KEY is not set. "
            "Create an agents/.env file with GROQ_API_KEY=<your-key>."
        )
    return ChatGroq(
        model=_GROQ_MODEL,
        api_key=api_key,
        max_tokens=2048,  # triage node needs room for <think> + answer
        temperature=0.2,
    )


def _safe_print(text: str) -> None:
    """Print text, replacing unencodable characters (emoji etc.) on Windows."""
    try:
        print(text)
    except UnicodeEncodeError:
        print(text.encode("utf-8", errors="replace").decode("ascii", errors="replace"))


def _strip_thinking(text: str) -> str:
    """Strip <think>...</think> blocks from LLM output (e.g. Qwen reasoning)."""
    import re
    # Handle complete <think>...</think> blocks
    text = re.sub(r"<think>.*?</think>", "", text, flags=re.DOTALL)
    # Handle truncated think blocks (model hit token limit mid-thought)
    text = re.sub(r"<think>.*$", "", text, flags=re.DOTALL)
    return text.strip()


def _extract_json(text: str) -> dict | None:
    """Try to extract a JSON object from possibly messy LLM output."""
    import re
    text = _strip_thinking(text)
    # Try direct parse first
    try:
        return json.loads(text)
    except (json.JSONDecodeError, ValueError):
        pass
    # Find the first { ... } block
    match = re.search(r"\{[^{}]*\}", text)
    if match:
        try:
            return json.loads(match.group())
        except (json.JSONDecodeError, ValueError):
            pass
    return None


# ---------------------------------------------------------------------------
# Shared state schema
# ---------------------------------------------------------------------------

class AlertState(TypedDict):
    """State passed through the triage → severity → response graph."""

    alert: dict[str, str | int | float]
    triage_explanation: str
    attack_techniques: list[dict[str, str]]
    severity_level: str
    severity_justification: str
    response_action: str
    error: str


# ---------------------------------------------------------------------------
# Prompts
# ---------------------------------------------------------------------------

_TRIAGE_SYSTEM = (
    "You are a network security analyst. You receive a structured network event "
    "and must explain IN PLAIN ENGLISH why the pattern could be suspicious. "
    "Ground your analysis STRICTLY in the fields provided — do NOT invent "
    "details that are not in the input. Be concise (3-5 sentences max)."
)

_SEVERITY_SYSTEM = (
    "/no_think "
    "You are a network security severity assessor. Given a triage explanation "
    "of a network event, assign exactly ONE severity level from this list:\n"
    "  Low, Medium, High, Critical\n"
    'Reply with ONLY a JSON object on one line: {"severity": "<level>", "justification": "<one sentence>"}\n'
    "No preamble, no explanation, no markdown — just the JSON object."
)

_RESPONSE_SYSTEM = (
    "/no_think "
    "You are a network security response advisor. Given the severity assessment, "
    "propose exactly ONE action from this FIXED list ONLY:\n"
    "  block_ip, isolate_host, flag_for_review, no_action\n"
    'Reply with ONLY a JSON object on one line: {"action": "<action_from_list>"}\n'
    "No preamble, no explanation, no markdown — just the JSON object."
)


# ---------------------------------------------------------------------------
# Node functions
# ---------------------------------------------------------------------------

def triage_node(state: AlertState) -> dict:
    """Analyse the network event and explain why it may be suspicious.

    After the LLM produces a plain-English explanation, the raw event is
    run through the deterministic ATT&CK mapping lookup (attack_mapping.py)
    to attach zero or more MITRE technique IDs.  The LLM is NOT asked to
    guess technique IDs — that comes from the rule-based lookup only.
    """
    llm = _get_llm()
    raw_event = state["alert"]
    alert_json = json.dumps(raw_event, indent=2)

    try:
        response = llm.invoke([
            SystemMessage(content=_TRIAGE_SYSTEM),
            HumanMessage(content=f"Analyse this network event:\n```json\n{alert_json}\n```"),
        ])
        explanation: str = response.content.strip()  # type: ignore[union-attr]
        explanation = _strip_thinking(explanation)

        # --- ATT&CK mapping (deterministic, NOT LLM-generated) ---
        techniques = map_attack_techniques(raw_event)

        _safe_print(f"\n{'='*60}")
        _safe_print("  TRIAGE NODE")
        _safe_print(f"{'='*60}")
        _safe_print(explanation)
        if techniques:
            tags = ", ".join(f"{t['id']} ({t['name']})" for t in techniques)
            _safe_print(f"  ATT&CK: {tags}")
        else:
            _safe_print("  ATT&CK: (none matched)")

        return {"triage_explanation": explanation, "attack_techniques": techniques}

    except Exception as exc:
        error_msg = f"[triage_node] Groq API error: {exc}"
        _safe_print(f"\n[ERROR] {error_msg}")
        return {
            "triage_explanation": "",
            "attack_techniques": [],
            "error": error_msg,
        }


def severity_node(state: AlertState) -> dict[str, str]:
    """Assign a severity level based on the triage explanation."""
    # If triage failed, propagate error
    if state.get("error"):
        _safe_print("\n[WARN] severity_node skipped -- upstream error.")
        return {"severity_level": "UNKNOWN", "severity_justification": "Skipped due to upstream error."}

    llm = _get_llm()
    triage_text = state["triage_explanation"]

    try:
        response = llm.invoke([
            SystemMessage(content=_SEVERITY_SYSTEM),
            HumanMessage(content=f"Triage explanation:\n{triage_text}"),
        ])
        raw: str = response.content.strip()  # type: ignore[union-attr]

        # Robust parse: strips <think> tags and finds JSON anywhere in output
        parsed = _extract_json(raw)
        if parsed is None:
            raise ValueError(f"No JSON found in severity response: {raw[:200]!r}")
        level = parsed.get("severity", "UNKNOWN")
        justification = parsed.get("justification", "No justification provided.")

        _safe_print(f"\n{'='*60}")
        _safe_print("  SEVERITY NODE")
        _safe_print(f"{'='*60}")
        _safe_print(f"Level: {level}")
        _safe_print(f"Justification: {justification}")
        return {"severity_level": level, "severity_justification": justification}

    except Exception as exc:
        error_msg = f"[severity_node] error: {exc}"
        _safe_print(f"\n[ERROR] {error_msg}")
        return {
            "severity_level": "UNKNOWN",
            "severity_justification": str(exc)[:200],
            "error": error_msg,
        }


def response_node(state: AlertState) -> dict[str, str]:
    """Recommend one action from the fixed action list."""
    ALLOWED_ACTIONS = {"block_ip", "isolate_host", "flag_for_review", "no_action"}

    if state.get("error"):
        _safe_print("\n[WARN] response_node skipped -- upstream error.")
        return {"response_action": "flag_for_review"}

    llm = _get_llm()
    severity_text = (
        f"Severity: {state['severity_level']}\n"
        f"Justification: {state['severity_justification']}"
    )

    try:
        response = llm.invoke([
            SystemMessage(content=_RESPONSE_SYSTEM),
            HumanMessage(content=severity_text),
        ])
        raw: str = response.content.strip()  # type: ignore[union-attr]

        # Robust parse: strips <think> tags and finds JSON anywhere in output
        parsed = _extract_json(raw)
        if parsed is None:
            raise ValueError(f"No JSON found in response: {raw[:200]!r}")
        action = parsed.get("action", "flag_for_review")

        # Enforce the fixed action list
        if action not in ALLOWED_ACTIONS:
            action = "flag_for_review"

        _safe_print(f"\n{'='*60}")
        _safe_print("  RESPONSE NODE")
        _safe_print(f"{'='*60}")
        _safe_print(f"Action: {action}")
        return {"response_action": action}

    except json.JSONDecodeError:
        raw_content: str = response.content.strip()  # type: ignore[union-attr, possibly-undefined]
        raw_content = _strip_thinking(raw_content)
        _safe_print(f"\n{'='*60}")
        _safe_print("  RESPONSE NODE  (raw -- JSON parse failed)")
        _safe_print(f"{'='*60}")
        _safe_print(raw_content)
        return {"response_action": "flag_for_review"}

    except Exception as exc:
        error_msg = f"[response_node] Groq API error: {exc}"
        _safe_print(f"\n[ERROR] {error_msg}")
        return {"response_action": "flag_for_review", "error": error_msg}


# ---------------------------------------------------------------------------
# Graph construction
# ---------------------------------------------------------------------------

def build_graph() -> StateGraph:
    """Build and compile the triage -> severity -> response graph."""
    graph = StateGraph(AlertState)

    graph.add_node("triage", triage_node)
    graph.add_node("severity", severity_node)
    graph.add_node("response", response_node)

    graph.set_entry_point("triage")
    graph.add_edge("triage", "severity")
    graph.add_edge("severity", "response")
    graph.add_edge("response", END)

    return graph.compile()


# Pre-built compiled graph (singleton)
_compiled_graph = None


def get_graph():
    """Return the compiled graph, building it once on first call."""
    global _compiled_graph
    if _compiled_graph is None:
        _compiled_graph = build_graph()
    return _compiled_graph


def run_pipeline(raw_event: dict) -> dict:
    """Run the full triage -> severity -> response chain on a raw event.

    Parameters
    ----------
    raw_event : dict
        The raw network event fields (41 NSL-KDD features).

    Returns
    -------
    dict with keys:
        triage, severity, severity_justification, recommended_action, error
    """
    graph = get_graph()

    initial_state: AlertState = {
        "alert": raw_event,
        "triage_explanation": "",
        "attack_techniques": [],
        "severity_level": "",
        "severity_justification": "",
        "response_action": "",
        "error": "",
    }

    result = graph.invoke(initial_state)

    return {
        "triage": result.get("triage_explanation", ""),
        "attack_techniques": result.get("attack_techniques", []),
        "severity": result.get("severity_level", "UNKNOWN"),
        "severity_justification": result.get("severity_justification", ""),
        "recommended_action": result.get("response_action", "flag_for_review"),
        "error": result.get("error", ""),
    }
