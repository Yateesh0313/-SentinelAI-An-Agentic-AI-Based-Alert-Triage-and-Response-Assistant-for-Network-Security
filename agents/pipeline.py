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
    "You are a senior SOC analyst writing alert explanations in CLEAN, PLAIN ENGLISH that ANYONE can understand.\n"
    "\n"
    "You will receive structured network event data and optional MITRE ATT&CK techniques.\n"
    "\n"
    "CRITICAL WRITING REQUIREMENTS:\n"
    "1. WRITE IN NATURAL, CLEAN ENGLISH: Do NOT use numbered headers like '1. WHAT HAPPENED' or '2. WHY IT MATTERS'. Write a smooth, professional 2-to-3 sentence narrative that anyone (executive, student, or judge) can read and understand immediately.\n"
    "2. NO CODE OR VARIABLE JARGON: NEVER use raw database column names like 'serror_rate', 'diff_srv_rate', 'src_bytes', 'dst_bytes', 'flag=SF', or 'same_srv_rate'. Instead, translate them into everyday terms (e.g., 'transferred 54 KB of data with zero response back', 'failed all 120 connection handshakes', 'clean web browsing session with balanced data exchange').\n"
    "3. EXPLAIN THE SPECIFIC SITUATION: Describe what the device was doing, what tools or techniques caused the alert (e.g. automated port scan, SYN flood denial-of-service, password guessing, data theft/exfiltration, or normal file transfer), and why it matters in real-world terms.\n"
    "4. STATE THE RECOMMENDED ACTION: Conclude with a clear recommendation (e.g. blocking the IP, isolating the host, or taking no action for safe baseline traffic).\n"
    "5. ATT&CK REFERENCE: If MITRE ATT&CK technique IDs are provided, append them on a new line at the end as: [Ref: T1046 — Network Service Discovery]. If none, omit.\n"
)

_SEVERITY_SYSTEM = (
    "/no_think "
    "You are a network security severity assessor.\n"
    "Given the triage explanation and network event evidence, assign exactly ONE severity level: Low, Medium, High, or Critical.\n\n"
    "Write your justification as ONE CLEAN ENGLISH SENTENCE that anyone can understand without technical jargon.\n"
    "Cite the specific real-world evidence naturally — for example:\n"
    "  - '120 uncompleted connection requests with a 100% failure rate targeted directly at the administrative Telnet service.'\n"
    "  - 'Confirmed administrative compromise where an unauthorized user obtained root shell access.'\n"
    "  - 'Abnormal one-way data transfer of 58 KB uploaded outside the network with zero return traffic.'\n"
    "  - 'Routine web browsing session with balanced data exchange and zero connection errors.'\n\n"
    "DO NOT use raw variable syntax like 'serror_rate=1.0' or 'src_bytes=5000'. Use clean, readable English.\n\n"
    'Reply with ONLY a JSON object on one line: {"severity": "<level>", "justification": "<one clean English sentence>"}\n'
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

def _build_event_summary(raw_event: dict) -> str:
    """Build a concise human-readable summary of the key event signals.

    This pre-digested summary is appended to the LLM prompt so the model
    can easily cite specific values without hunting through the raw JSON.
    """
    def _n(key: str, default: float = 0.0) -> float:
        try:
            return float(raw_event.get(key, default))
        except (TypeError, ValueError):
            return default

    lines = []
    proto = str(raw_event.get("protocol_type", "tcp")).upper()
    service = str(raw_event.get("service", "other"))
    flag = str(raw_event.get("flag", "SF"))
    lines.append(f"Protocol: {proto}, Service: {service}, Flag: {flag}")
    lines.append(f"Duration: {_n('duration')}s, src_bytes: {int(_n('src_bytes'))}, dst_bytes: {int(_n('dst_bytes'))}")

    count = _n("count")
    srv_count = _n("srv_count")
    if count > 0:
        lines.append(f"Connection count: {int(count)}, srv_count: {int(srv_count)}")

    serror = _n("serror_rate")
    rerror = _n("rerror_rate")
    if serror > 0 or rerror > 0:
        lines.append(f"serror_rate: {serror:.2f}, rerror_rate: {rerror:.2f}")

    failed = _n("num_failed_logins")
    if failed > 0:
        lines.append(f"Failed logins: {int(failed)}")

    root_shell = _n("root_shell")
    su_attempted = _n("su_attempted")
    if root_shell >= 1 or su_attempted >= 1:
        lines.append(f"root_shell: {int(root_shell)}, su_attempted: {int(su_attempted)}")

    logged_in = _n("logged_in")
    num_comp = _n("num_compromised")
    if logged_in >= 1 or num_comp >= 1:
        lines.append(f"logged_in: {int(logged_in)}, num_compromised: {int(num_comp)}")

    diff_srv = _n("diff_srv_rate")
    same_srv = _n("same_srv_rate")
    lines.append(f"same_srv_rate: {same_srv:.2f}, diff_srv_rate: {diff_srv:.2f}")

    return "\n".join(lines)


def triage_node(state: AlertState) -> dict:
    """Analyse the network event and produce a structured 3-part explanation.

    Flow:
      1. Run the deterministic ATT&CK mapping first so we can feed the
         matched technique IDs into the LLM prompt as context.
      2. Build a pre-digested event summary highlighting key signals.
      3. Call the LLM with the structured triage prompt.  The LLM is told
         to cite specific values and append ATT&CK IDs as reference tags.
    """
    llm = _get_llm()
    raw_event = state["alert"]
    alert_json = json.dumps(raw_event, indent=2)

    # --- ATT&CK mapping (deterministic, NOT LLM-generated) ---
    techniques = map_attack_techniques(raw_event)

    # --- Build enriched prompt with pre-digested key signals ---
    event_summary = _build_event_summary(raw_event)

    attack_context = ""
    if techniques:
        tag_lines = ", ".join(
            f"{t['id']} — {t['name']}" for t in techniques
        )
        attack_context = (
            f"\n\nMatched MITRE ATT&CK techniques (use as reference tags):\n"
            f"{tag_lines}"
        )

    user_prompt = (
        f"Analyse this network event. Cite SPECIFIC values from the fields below.\n\n"
        f"KEY SIGNALS:\n{event_summary}\n\n"
        f"FULL RAW EVENT:\n```json\n{alert_json}\n```"
        f"{attack_context}"
    )

    try:
        response = llm.invoke([
            SystemMessage(content=_TRIAGE_SYSTEM),
            HumanMessage(content=user_prompt),
        ])
        explanation: str = response.content.strip()  # type: ignore[union-attr]
        explanation = _strip_thinking(explanation)

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
    """Assign a severity level based on the triage explanation and raw event evidence."""
    # If triage failed, propagate error
    if state.get("error"):
        _safe_print("\n[WARN] severity_node skipped -- upstream error.")
        return {"severity_level": "UNKNOWN", "severity_justification": "Skipped due to upstream error."}

    llm = _get_llm()
    triage_text = state["triage_explanation"]
    raw_event = state["alert"]
    techniques = state.get("attack_techniques", [])

    # Build evidence context so severity justification is grounded in specifics
    evidence_parts = [f"Triage explanation:\n{triage_text}"]

    # Add key raw event fields for grounding
    event_summary = _build_event_summary(raw_event)
    evidence_parts.append(f"\nKey event signals:\n{event_summary}")

    if techniques:
        tech_str = ", ".join(f"{t['id']} ({t['name']})" for t in techniques)
        evidence_parts.append(f"\nMatched ATT&CK techniques: {tech_str}")

    evidence = "\n".join(evidence_parts)

    try:
        response = llm.invoke([
            SystemMessage(content=_SEVERITY_SYSTEM),
            HumanMessage(content=evidence),
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


# ---------------------------------------------------------------------------
# Heuristic (rule-based) triage fallback -- used when LLM API is unavailable
# ---------------------------------------------------------------------------

def _safe_num(event: dict, key: str, default: float = 0.0) -> float:
    """Get a numeric value from *event*, returning *default* on failure."""
    try:
        return float(event.get(key, default))
    except (TypeError, ValueError):
        return default


def heuristic_triage(raw_event: dict) -> dict:
    """Deterministic, rule-based triage that requires NO LLM call.

    Inspects NSL-KDD features and applies threshold heuristics to
    produce a severity assessment and recommended action.  This is the
    fallback used when the Groq API is unreachable or returns errors.

    Each triage explanation cites SPECIFIC evidence from the event fields
    so no two different events produce identical triage text.

    Returns the same dict shape as run_pipeline():
        triage, severity, severity_justification, recommended_action,
        attack_techniques
    """
    # --- Extract key signals ---
    failed_logins   = _safe_num(raw_event, "num_failed_logins")
    root_shell      = _safe_num(raw_event, "root_shell")
    su_attempted    = _safe_num(raw_event, "su_attempted")
    num_compromised = _safe_num(raw_event, "num_compromised")
    serror_rate     = _safe_num(raw_event, "serror_rate")
    rerror_rate     = _safe_num(raw_event, "rerror_rate")
    src_bytes       = _safe_num(raw_event, "src_bytes")
    dst_bytes       = _safe_num(raw_event, "dst_bytes")
    count           = _safe_num(raw_event, "count")
    srv_count       = _safe_num(raw_event, "srv_count")
    diff_srv_rate   = _safe_num(raw_event, "diff_srv_rate")
    same_srv_rate   = _safe_num(raw_event, "same_srv_rate")
    logged_in       = _safe_num(raw_event, "logged_in")
    duration        = _safe_num(raw_event, "duration")
    hot             = _safe_num(raw_event, "hot")
    num_root        = _safe_num(raw_event, "num_root")
    num_shells      = _safe_num(raw_event, "num_shells")
    service         = str(raw_event.get("service", "other"))
    protocol        = str(raw_event.get("protocol_type", "tcp"))
    flag            = str(raw_event.get("flag", "SF"))

    # --- Deterministic ATT&CK mapping (same as LLM path) ---
    techniques = map_attack_techniques(raw_event)
    tech_names = [t["name"] for t in techniques]

    # --- Classify severity by rule priority ---
    severity = "Low"
    justification = ""
    action = "no_action"
    triage_text = ""

    # CRITICAL: root shell obtained or privilege escalation
    if root_shell >= 1 or su_attempted >= 1:
        severity = "Critical"
        priv_detail = []
        if root_shell >= 1:
            priv_detail.append("gained root administrator shell access")
        if su_attempted >= 1:
            priv_detail.append("attempted to switch to superuser privileges")
        priv_str = " and ".join(priv_detail)

        triage_text = (
            f"An attacker {priv_str} during a session on the {service} service over {protocol.upper()}. "
        )
        if logged_in >= 1:
            triage_text += f"The attacker authenticated successfully and executed {int(num_root)} administrative commands. "
        triage_text += (
            "Having obtained full administrative control, the intruder can view confidential files, "
            "alter system configurations, or deploy persistent malware. "
            "We recommend immediately isolating the host from the network to contain the breach."
        )
        justification = (
            f"Confirmed root administrative compromise on the {service} service with full system control achieved."
        )
        action = "isolate_host"

    # CRITICAL: mass brute-force (many failed logins)
    elif failed_logins >= 5:
        severity = "Critical"
        triage_text = (
            f"A heavy credential brute-force attack was detected on the {service} service over {protocol.upper()}, "
            f"with {int(failed_logins)} failed login attempts recorded in rapid succession. "
        )
        if logged_in >= 1:
            triage_text += "The attacker eventually succeeded in guessing a valid password, making this a critical emergency. "
        else:
            triage_text += "While login has not yet succeeded, the speed and volume confirm an automated password-cracking tool. "
        triage_text += (
            "This threatens unauthorized access to core internal data. "
            "We recommend blocking the source IP address immediately to stop the attack."
        )
        justification = (
            f"Aggressive automated credential attack with {int(failed_logins)} failed login attempts against the {service} service."
        )
        action = "block_ip"

    # HIGH: host compromise indicators
    elif num_compromised >= 1 and logged_in >= 1:
        severity = "High"
        triage_text = (
            f"An authenticated user session on the {service} service ({protocol.upper()}) "
            f"exhibited {int(num_compromised)} compromise indicators and abnormal system commands. "
            "This suggests an attacker has hijacked legitimate user credentials or an insider threat "
            "is operating within authorized accounts. "
            "We recommend isolating the host for security inspection and credential revocation."
        )
        justification = (
            f"Active host compromise indicators detected inside an authenticated {service} session."
        )
        action = "isolate_host"

    # HIGH: SYN flood / connection-reset storm
    elif serror_rate > 0.70 and count > 50:
        severity = "High"
        triage_text = (
            f"A denial-of-service SYN flood attack was detected targeting the {service} service. "
            f"The remote device blasted {int(count)} connection attempts over {protocol.upper()}, "
            f"failing to complete the initial handshake on {serror_rate:.0%} of the attempts. "
            "This flood deliberately exhausts the server's connection memory so legitimate users cannot connect. "
            "We recommend blocking the source IP to restore normal service availability."
        )
        justification = (
            f"Denial-of-service attack flooding {int(count)} uncompleted connection handshakes against the {service} service."
        )
        action = "block_ip"

    # HIGH: large data exfiltration
    elif src_bytes > 10_000 and dst_bytes < 1_000 and src_bytes > 10 * max(dst_bytes, 1):
        severity = "High"
        kb_sent = int(src_bytes / 1024)
        triage_text = (
            f"A large one-way data transfer was detected: {int(src_bytes):,} bytes ({kb_sent} KB) were transmitted outward "
            f"over the {service} service while virtually zero response data was received. "
            "Normal communication exchanges data in both directions; sending substantial data outward with no return "
            "is the primary indicator of data theft or unauthorized file exfiltration. "
            "We recommend blocking this connection immediately to prevent further data loss."
        )
        justification = (
            f"Abnormal one-way data transmission of {int(src_bytes):,} bytes uploaded outside the network with zero return traffic."
        )
        action = "block_ip"

    # MEDIUM: port scanning
    elif diff_srv_rate > 0.50 and count > 10:
        severity = "Medium"
        triage_text = (
            f"An automated port scan was detected across {int(count)} connection attempts over {protocol.upper()}, "
            f"systematically probing multiple different services to see which ports are listening. "
            "Port scanning is the initial reconnaissance phase where attackers map out reachable software to find vulnerabilities. "
            "We recommend flagging the source for analyst review to monitor for subsequent exploitation."
        )
        justification = (
            f"Automated network reconnaissance scanning across multiple {protocol.upper()} service ports to discover listening targets."
        )
        action = "flag_for_review"

    # MEDIUM: moderate brute-force
    elif failed_logins >= 3:
        severity = "Medium"
        triage_text = (
            f"Repeated credential guessing was detected on the {service} service over {protocol.upper()}, "
            f"with {int(failed_logins)} failed login attempts observed. "
            "This pattern suggests someone is testing known passwords to gain unauthorized access. "
            "We recommend flagging for review to verify whether the targeted account requires a password reset."
        )
        justification = (
            f"Repeated login failures on the {service} service indicating deliberate password guessing."
        )
        action = "flag_for_review"

    # MEDIUM: high connection-reset rate
    elif rerror_rate > 0.70 and count > 30:
        severity = "Medium"
        triage_text = (
            f"Network probing was detected: {rerror_rate:.0%} of {int(count)} connection attempts to the {service} service "
            f"were immediately rejected by the firewall over {protocol.upper()}. "
            "A high rejection rate across multiple attempts indicates either an automated scanner hitting closed ports "
            "or an operational misconfiguration. "
            "We recommend flagging for review to determine if the traffic is hostile or operational."
        )
        justification = (
            f"High volume of rejected connection attempts ({rerror_rate:.0%} failure rate across {int(count)} attempts) indicating service probing."
        )
        action = "flag_for_review"

    # MEDIUM: C2-like steady beacon pattern
    elif count > 200 and same_srv_rate > 0.85:
        severity = "Medium"
        triage_text = (
            f"A repetitive beaconing pattern was observed: {int(count)} rapid, evenly-spaced connections "
            f"were made to the {service} service over {protocol.upper()}. "
            "This steady pulse is typical of malware checking in with a remote command-and-control server. "
            "We recommend flagging for review to investigate the destination endpoint."
        )
        justification = (
            f"Repetitive, high-frequency connection pattern to {service} resembling automated command-and-control communication."
        )
        action = "flag_for_review"

    # LOW: normal or low-risk traffic
    else:
        severity = "Low"
        service_label = service
        if service == "http":
            service_label = "web browsing"
        elif service == "ftp_data":
            service_label = "file transfer"
        elif service == "smtp":
            service_label = "email delivery"

        triage_text = (
            f"Standard {protocol.upper()} network activity was observed on the {service_label} service, "
            f"transferring {int(src_bytes):,} bytes out and {int(dst_bytes):,} bytes in normally. "
            "The connection completed cleanly with zero authentication failures, zero error spikes, "
            "and normal traffic volume. This represents healthy baseline communication and requires no action."
        )
        justification = (
            f"Routine {protocol.upper()} communication with the {service} service that completed normally with no security anomalies."
        )
        action = "no_action"

    # Append ATT&CK reference tags
    if techniques:
        tags = ", ".join(f"{t['id']} — {t['name']}" for t in techniques)
        triage_text += f"\n[Ref: {tags}]"

    return {
        "triage": triage_text,
        "severity": severity,
        "severity_justification": justification,
        "recommended_action": action,
        "attack_techniques": techniques,
    }
