"""SentinelAI -- Dataset Adapter & Schema Detection Layer.

Detects uploaded CSV schemas against known NIDS benchmark templates:
  - NSL-KDD (41 features)
  - CICIDS2017 (CICFlowMeter 78-85 features)
  - UNSW-NB15 (Argus / Bro 45-49 features)

Maps detected features onto the 41-column NSL-KDD representation expected by
the trained XGBoost and Random Forest models, filling sensible defaults for
unmapped fields while clearly reporting matched vs. defaulted columns.
If no template matches, strictly fails with a detailed report of missing and
unexpected columns (no guessing).
"""

from __future__ import annotations

import io
import re
from dataclasses import dataclass
from typing import Any

import numpy as np
import pandas as pd

# ---------------------------------------------------------------------------
# Canonical NSL-KDD 41 Feature Schema (Order matters for inference)
# ---------------------------------------------------------------------------

NSL_KDD_FEATURE_COLS: list[str] = [
    "duration", "protocol_type", "service", "flag", "src_bytes", "dst_bytes",
    "land", "wrong_fragment", "urgent", "hot", "num_failed_logins", "logged_in",
    "num_compromised", "root_shell", "su_attempted", "num_root",
    "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
    "is_host_login", "is_guest_login", "count", "srv_count", "serror_rate",
    "srv_serror_rate", "rerror_rate", "srv_rerror_rate", "same_srv_rate",
    "diff_srv_rate", "srv_diff_host_rate", "dst_host_count", "dst_host_srv_count",
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate", "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

CATEGORICAL_COLS: list[str] = ["protocol_type", "service", "flag"]
NUMERIC_COLS: list[str] = [c for c in NSL_KDD_FEATURE_COLS if c not in CATEGORICAL_COLS]


# ---------------------------------------------------------------------------
# Known Benchmark Templates & Signatures
# ---------------------------------------------------------------------------

# Canonical CICIDS2017 columns (CICFlowMeter output)
CICIDS2017_CANONICAL_COLS: list[str] = [
    "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
    "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
    "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean",
    "Bwd Packet Length Std", "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean",
    "Flow IAT Std", "Flow IAT Max", "Flow IAT Min", "Fwd IAT Total", "Fwd IAT Mean",
    "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min", "Bwd IAT Total", "Bwd IAT Mean",
    "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min", "Fwd PSH Flags", "Bwd PSH Flags",
    "Fwd URG Flags", "Bwd URG Flags", "Fwd Header Length", "Bwd Header Length",
    "Fwd Packets/s", "Bwd Packets/s", "Min Packet Length", "Max Packet Length",
    "Packet Length Mean", "Packet Length Std", "Packet Length Variance", "FIN Flag Count",
    "SYN Flag Count", "RST Flag Count", "PSH Flag Count", "ACK Flag Count",
    "URG Flag Count", "CWE Flag Count", "ECE Flag Count", "Down/Up Ratio",
    "Average Packet Size", "Avg Fwd Segment Size", "Avg Bwd Segment Size",
    "Fwd Header Length.1", "Fwd Avg Bytes/Bulk", "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk", "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate", "Subflow Fwd Packets", "Subflow Fwd Bytes",
    "Subflow Bwd Packets", "Subflow Bwd Bytes", "Init_Win_bytes_forward",
    "Init_Win_bytes_backward", "act_data_pkt_fwd", "min_seg_size_forward",
    "Active Mean", "Active Std", "Active Max", "Active Min", "Idle Mean",
    "Idle Std", "Idle Max", "Idle Min", "Label",
]

# Unique signature columns that distinguish CICIDS2017
CICIDS2017_SIGNATURES: set[str] = {
    "flow_duration", "total_fwd_packets", "total_backward_packets",
    "total_length_of_fwd_packets", "total_length_of_bwd_packets",
    "flow_iat_mean", "fin_flag_count", "syn_flag_count", "rst_flag_count",
    "destination_port", "init_win_bytes_forward", "act_data_pkt_fwd",
    "bwd_packet_length_mean", "fwd_packet_length_mean",
}

# Canonical UNSW-NB15 columns
UNSW_NB15_CANONICAL_COLS: list[str] = [
    "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
    "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "sinpkt",
    "dinpkt", "sjit", "djit", "swin", "dwin", "stcpb", "dtcpb", "tcprtt",
    "synack", "ackdat", "smean", "dmean", "trans_depth", "response_body_len",
    "ct_srv_src", "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_ftp_login", "ct_ftp_cmd",
    "ct_flw_http_mthd", "ct_src_ltm", "ct_srv_dst", "is_sm_ips_ports",
    "attack_cat", "label",
]

# Unique signature columns that distinguish UNSW-NB15
UNSW_NB15_SIGNATURES: set[str] = {
    "dur", "proto", "sbytes", "dbytes", "sttl", "dttl", "sloss", "dloss",
    "sload", "dload", "ct_srv_src", "ct_dst_ltm", "ct_src_dport_ltm",
    "ct_dst_sport_ltm", "ct_dst_src_ltm", "is_sm_ips_ports",
}

# Unique signature columns that distinguish NSL-KDD
NSL_KDD_SIGNATURES: set[str] = {
    "dst_host_same_srv_rate", "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate", "dst_host_srv_serror_rate",
    "num_compromised", "root_shell", "num_file_creations", "num_outbound_cmds",
    "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate",
}


# ---------------------------------------------------------------------------
# Data Classes & Custom Exceptions
# ---------------------------------------------------------------------------

class SchemaDetectionError(ValueError):
    """Raised when an uploaded CSV does not match any known template."""

    def __init__(self, message: str, details: dict[str, Any]):
        super().__init__(message)
        self.details = details


@dataclass
class SchemaDetectionResult:
    schema_name: str  # "NSL-KDD" | "CICIDS2017" | "UNSW-NB15"
    format_display: str  # e.g. "Detected format: NSL-KDD (41/41 columns)"
    total_columns_in_file: int
    matched_columns_count: int
    matched_columns: list[str]
    missing_template_columns: list[str]
    confidence: float


@dataclass
class MappedDatasetResult:
    schema_name: str
    format_display: str
    df_mapped: pd.DataFrame
    total_rows: int
    columns_matched: list[str]
    columns_defaulted: list[str]
    raw_df: pd.DataFrame


# ---------------------------------------------------------------------------
# Helper Functions: Header Normalization
# ---------------------------------------------------------------------------

def normalize_col(col: str) -> str:
    """Normalize column name for schema matching: strip whitespace, lower, replace space/dot with underscore."""
    s = str(col).strip().lower()
    s = re.sub(r"[\s\.\-]+", "_", s)
    s = re.sub(r"[^\w]", "", s)
    return s


def _build_col_map(columns: list[str]) -> dict[str, str]:
    """Return mapping of normalized_col_name -> original_col_name."""
    mapping: dict[str, str] = {}
    for c in columns:
        mapping[normalize_col(c)] = c
    return mapping


# ---------------------------------------------------------------------------
# 1. Schema Detection Layer
# ---------------------------------------------------------------------------

def detect_schema(raw_columns: list[str]) -> SchemaDetectionResult:
    """Check uploaded CSV's column headers against NSL-KDD, CICIDS2017, and UNSW-NB15.

    Detects which one matches by column names and signatures.
    If no known schema matches, raises SchemaDetectionError detailing missing and
    unexpected columns without guessing.
    """
    if not raw_columns:
        raise SchemaDetectionError(
            "Uploaded file contains no columns or has an empty header row.",
            {"error": "empty_columns", "uploaded_columns": []},
        )

    norm_map = _build_col_map(raw_columns)
    norm_set = set(norm_map.keys())
    total_cols = len(raw_columns)

    # 1. Evaluate NSL-KDD
    nsl_norm = {normalize_col(c) for c in NSL_KDD_FEATURE_COLS}
    nsl_matched = norm_set.intersection(nsl_norm)
    nsl_signatures_matched = norm_set.intersection(NSL_KDD_SIGNATURES)
    nsl_missing = [c for c in NSL_KDD_FEATURE_COLS if normalize_col(c) not in norm_set]

    # 2. Evaluate CICIDS2017
    cic_norm = {normalize_col(c) for c in CICIDS2017_CANONICAL_COLS}
    cic_matched = norm_set.intersection(cic_norm)
    cic_signatures_matched = norm_set.intersection(CICIDS2017_SIGNATURES)
    cic_missing = [c for c in CICIDS2017_CANONICAL_COLS if normalize_col(c) not in norm_set]

    # 3. Evaluate UNSW-NB15
    unsw_norm = {normalize_col(c) for c in UNSW_NB15_CANONICAL_COLS}
    unsw_matched = norm_set.intersection(unsw_norm)
    unsw_signatures_matched = norm_set.intersection(UNSW_NB15_SIGNATURES)
    unsw_missing = [c for c in UNSW_NB15_CANONICAL_COLS if normalize_col(c) not in norm_set]

    # Match scoring
    is_nsl = len(nsl_matched) >= 32 or (len(nsl_matched) >= 20 and len(nsl_signatures_matched) >= 4)
    is_cic = len(cic_matched) >= 30 or len(cic_signatures_matched) >= 5
    is_unsw = len(unsw_matched) >= 20 or len(unsw_signatures_matched) >= 5

    # Specificity resolution
    scores = {
        "NSL-KDD": (len(nsl_matched) / len(NSL_KDD_FEATURE_COLS), len(nsl_signatures_matched), len(nsl_matched)),
        "CICIDS2017": (len(cic_matched) / len(CICIDS2017_CANONICAL_COLS), len(cic_signatures_matched), len(cic_matched)),
        "UNSW-NB15": (len(unsw_matched) / len(UNSW_NB15_CANONICAL_COLS), len(unsw_signatures_matched), len(unsw_matched)),
    }

    best_schema = None
    if is_nsl and scores["NSL-KDD"][0] >= scores["CICIDS2017"][0] and scores["NSL-KDD"][0] >= scores["UNSW-NB15"][0]:
        best_schema = "NSL-KDD"
    elif is_cic and scores["CICIDS2017"][1] >= scores["UNSW-NB15"][1]:
        best_schema = "CICIDS2017"
    elif is_unsw:
        best_schema = "UNSW-NB15"
    elif is_cic:
        best_schema = "CICIDS2017"
    elif is_nsl:
        best_schema = "NSL-KDD"

    # Strict check: if no schema clearly matched, fail without guessing
    if not best_schema:
        # Build diagnostic report
        unexpected_sample = [c for c in raw_columns[:15]]
        diag = {
            "error": "schema_detection_failed",
            "message": (
                "Uploaded CSV schema does not match any recognized NIDS template "
                "(NSL-KDD, CICIDS2017, UNSW-NB15)."
            ),
            "uploaded_column_count": total_cols,
            "uploaded_columns_sample": unexpected_sample,
            "templates_evaluated": {
                "NSL-KDD": {
                    "matched_count": len(nsl_matched),
                    "total_expected": len(NSL_KDD_FEATURE_COLS),
                    "missing_key_columns": nsl_missing[:10],
                },
                "CICIDS2017": {
                    "matched_count": len(cic_matched),
                    "total_expected": len(CICIDS2017_CANONICAL_COLS),
                    "missing_key_columns": cic_missing[:10],
                },
                "UNSW-NB15": {
                    "matched_count": len(unsw_matched),
                    "total_expected": len(UNSW_NB15_CANONICAL_COLS),
                    "missing_key_columns": unsw_missing[:10],
                },
            },
            "hint": (
                "Please verify that your CSV contains the standard headers for NSL-KDD (41 features), "
                "CICIDS2017 (CICFlowMeter output), or UNSW-NB15."
            ),
        }
        raise SchemaDetectionError(diag["message"], diag)

    # Build result
    if best_schema == "NSL-KDD":
        matched_cols = [norm_map[k] for k in nsl_matched]
        display = f"Detected format: NSL-KDD ({len(nsl_matched)}/{len(NSL_KDD_FEATURE_COLS)} columns)"
        return SchemaDetectionResult(
            schema_name="NSL-KDD",
            format_display=display,
            total_columns_in_file=total_cols,
            matched_columns_count=len(nsl_matched),
            matched_columns=matched_cols,
            missing_template_columns=nsl_missing,
            confidence=round(scores["NSL-KDD"][0], 2),
        )

    elif best_schema == "CICIDS2017":
        matched_cols = [norm_map[k] for k in cic_matched]
        display = f"Detected format: CICIDS2017 ({total_cols} columns, {len(cic_matched)} standard CICFlowMeter attributes)"
        return SchemaDetectionResult(
            schema_name="CICIDS2017",
            format_display=display,
            total_columns_in_file=total_cols,
            matched_columns_count=len(cic_matched),
            matched_columns=matched_cols,
            missing_template_columns=cic_missing,
            confidence=round(scores["CICIDS2017"][0], 2),
        )

    else:  # UNSW-NB15
        matched_cols = [norm_map[k] for k in unsw_matched]
        display = f"Detected format: UNSW-NB15 ({total_cols} columns, {len(unsw_matched)} standard Argus/Bro attributes)"
        return SchemaDetectionResult(
            schema_name="UNSW-NB15",
            format_display=display,
            total_columns_in_file=total_cols,
            matched_columns_count=len(unsw_matched),
            missing_template_columns=unsw_missing,
            matched_columns=matched_cols,
            confidence=round(scores["UNSW-NB15"][0], 2),
        )


# ---------------------------------------------------------------------------
# 2. Column Mapping Layer (Maps detected dataset to 41 NSL-KDD features)
# ---------------------------------------------------------------------------

def _safe_float(val: Any, default: float = 0.0) -> float:
    """Safely convert value to float, handling nulls, strings, infinities."""
    if val is None or pd.isna(val):
        return default
    try:
        f = float(val)
        return default if np.isinf(f) or np.isnan(f) else f
    except (ValueError, TypeError):
        return default


def _infer_service_from_port(port: int | float) -> str:
    """Infer NSL-KDD service name from destination port."""
    p = int(_safe_float(port, 0))
    port_map: dict[int, str] = {
        80: "http", 443: "http", 8080: "http", 8000: "http",
        21: "ftp", 20: "ftp_data",
        22: "ssh",
        23: "telnet",
        25: "smtp", 465: "smtp", 587: "smtp",
        53: "domain_u",
        110: "pop_3", 995: "pop_3",
        143: "imap4", 993: "imap4",
        123: "ntp_u",
        161: "snmp", 162: "snmp",
        3389: "remote_job",
        67: "bootps", 68: "bootpc",
        69: "tftp_u",
        70: "gopher",
        79: "finger",
        88: "klogin",
        119: "nntp",
    }
    return port_map.get(p, "other")


def map_dataset_to_nsl_kdd(
    df: pd.DataFrame,
    detection: SchemaDetectionResult,
) -> MappedDatasetResult:
    """Map detected dataset rows onto the exact 41 feature columns expected by the trained model.

    Returns MappedDatasetResult containing the mapped DataFrame with all 41 columns,
    the list of matched features, and the list of safe defaulted features.
    """
    n_rows = len(df)
    norm_col_map = _build_col_map(list(df.columns))

    mapped_dict: dict[str, list[Any]] = {col: [] for col in NSL_KDD_FEATURE_COLS}
    columns_matched: set[str] = set()
    columns_defaulted: set[str] = set()

    def get_val(norm_key: str, default: Any = 0.0) -> pd.Series:
        if norm_key in norm_col_map:
            return df[norm_col_map[norm_key]]
        return pd.Series([default] * n_rows)

    # ── CASE A: NSL-KDD (Direct 1:1 mapping) ──────────────────────────────
    if detection.schema_name == "NSL-KDD":
        for col in NSL_KDD_FEATURE_COLS:
            norm_k = normalize_col(col)
            if norm_k in norm_col_map:
                orig_col = norm_col_map[norm_k]
                columns_matched.add(col)
                if col in CATEGORICAL_COLS:
                    mapped_dict[col] = df[orig_col].fillna("other").astype(str).tolist()
                else:
                    mapped_dict[col] = pd.to_numeric(df[orig_col], errors="coerce").fillna(0.0).astype(float).tolist()
            else:
                columns_defaulted.add(col)
                if col == "protocol_type":
                    mapped_dict[col] = ["tcp"] * n_rows
                elif col == "service":
                    mapped_dict[col] = ["http"] * n_rows
                elif col == "flag":
                    mapped_dict[col] = ["SF"] * n_rows
                else:
                    mapped_dict[col] = [0.0] * n_rows

    # ── CASE B: CICIDS2017 ───────────────────────────────────────────────
    elif detection.schema_name == "CICIDS2017":
        # Flow duration in CICIDS2017 is in microseconds -> convert to seconds
        dur_series = get_val("flow_duration", 0.0)
        dur_sec = pd.to_numeric(dur_series, errors="coerce").fillna(0.0) / 1_000_000.0
        mapped_dict["duration"] = dur_sec.clip(lower=0.0).tolist()
        columns_matched.add("duration")

        # Destination port for service inference
        dst_port_series = get_val("destination_port", 80)
        services = [_infer_service_from_port(p) for p in dst_port_series]
        mapped_dict["service"] = services
        columns_matched.add("service")

        # Protocol
        proto_series = get_val("protocol", None)
        protocols: list[str] = []
        for i, val in enumerate(proto_series):
            if val is not None and not pd.isna(val):
                p_int = int(_safe_float(val, 6))
                protocols.append("tcp" if p_int == 6 else ("udp" if p_int == 17 else ("icmp" if p_int == 1 else "tcp")))
            else:
                port = int(_safe_float(dst_port_series.iloc[i], 80))
                protocols.append("udp" if port in (53, 123, 161, 162) else "tcp")
        mapped_dict["protocol_type"] = protocols
        columns_matched.add("protocol_type")

        # Flag mapping from TCP flag counts
        syn_cnt = pd.to_numeric(get_val("syn_flag_count", 0), errors="coerce").fillna(0)
        ack_cnt = pd.to_numeric(get_val("ack_flag_count", 0), errors="coerce").fillna(0)
        rst_cnt = pd.to_numeric(get_val("rst_flag_count", 0), errors="coerce").fillna(0)
        fin_cnt = pd.to_numeric(get_val("fin_flag_count", 0), errors="coerce").fillna(0)
        urg_cnt = pd.to_numeric(get_val("urg_flag_count", 0), errors="coerce").fillna(0)

        flags: list[str] = []
        for i in range(n_rows):
            if rst_cnt.iloc[i] > 0:
                flags.append("REJ")
            elif syn_cnt.iloc[i] > 0 and ack_cnt.iloc[i] == 0:
                flags.append("S0")
            elif fin_cnt.iloc[i] > 0 and ack_cnt.iloc[i] > 0:
                flags.append("SF")
            elif urg_cnt.iloc[i] > 0:
                flags.append("RSTR")
            else:
                flags.append("SF")
        mapped_dict["flag"] = flags
        columns_matched.add("flag")

        # Bytes
        src_bytes_s = get_val("total_length_of_fwd_packets", get_val("subflow_fwd_bytes", 0))
        dst_bytes_s = get_val("total_length_of_bwd_packets", get_val("subflow_bwd_bytes", 0))
        mapped_dict["src_bytes"] = pd.to_numeric(src_bytes_s, errors="coerce").fillna(0.0).tolist()
        mapped_dict["dst_bytes"] = pd.to_numeric(dst_bytes_s, errors="coerce").fillna(0.0).tolist()
        columns_matched.add("src_bytes")
        columns_matched.add("dst_bytes")

        # Packets / Flow counts
        fwd_pkts = pd.to_numeric(get_val("total_fwd_packets", 1), errors="coerce").fillna(1)
        bwd_pkts = pd.to_numeric(get_val("total_backward_packets", 0), errors="coerce").fillna(0)
        tot_pkts = (fwd_pkts + bwd_pkts).clip(lower=1.0)
        mapped_dict["count"] = tot_pkts.tolist()
        mapped_dict["srv_count"] = fwd_pkts.tolist()
        columns_matched.add("count")
        columns_matched.add("srv_count")

        # Rates & Host stats
        serror_rate = ((syn_cnt > 0) & (ack_cnt == 0)).astype(float)
        rerror_rate = (rst_cnt > 0).astype(float)
        mapped_dict["serror_rate"] = serror_rate.tolist()
        mapped_dict["srv_serror_rate"] = serror_rate.tolist()
        mapped_dict["rerror_rate"] = rerror_rate.tolist()
        mapped_dict["srv_rerror_rate"] = rerror_rate.tolist()
        mapped_dict["same_srv_rate"] = [1.0] * n_rows
        mapped_dict["diff_srv_rate"] = [0.0] * n_rows
        mapped_dict["srv_diff_host_rate"] = [0.0] * n_rows

        mapped_dict["dst_host_count"] = tot_pkts.clip(upper=255.0).tolist()
        mapped_dict["dst_host_srv_count"] = fwd_pkts.clip(upper=255.0).tolist()
        mapped_dict["dst_host_same_srv_rate"] = [1.0] * n_rows
        mapped_dict["dst_host_diff_srv_rate"] = [0.0] * n_rows
        mapped_dict["dst_host_same_src_port_rate"] = [0.0] * n_rows
        mapped_dict["dst_host_srv_diff_host_rate"] = [0.0] * n_rows
        mapped_dict["dst_host_serror_rate"] = serror_rate.tolist()
        mapped_dict["dst_host_srv_serror_rate"] = serror_rate.tolist()
        mapped_dict["dst_host_rerror_rate"] = rerror_rate.tolist()
        mapped_dict["dst_host_srv_rerror_rate"] = rerror_rate.tolist()

        columns_matched.update([
            "serror_rate", "rerror_rate", "dst_host_count", "dst_host_srv_count",
            "dst_host_serror_rate", "dst_host_rerror_rate",
        ])

        # Content features safely defaulted to 0.0 (not captured by flow meters)
        flow_defaults = [
            "land", "wrong_fragment", "urgent", "hot", "num_failed_logins",
            "logged_in", "num_compromised", "root_shell", "su_attempted", "num_root",
            "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
            "is_host_login", "is_guest_login", "srv_serror_rate", "srv_rerror_rate",
            "same_srv_rate", "diff_srv_rate", "srv_diff_host_rate", "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate", "dst_host_same_src_port_rate", "dst_host_srv_diff_host_rate",
            "dst_host_srv_serror_rate", "dst_host_srv_rerror_rate",
        ]
        for col in flow_defaults:
            if col not in columns_matched:
                mapped_dict[col] = [0.0] * n_rows
                columns_defaulted.add(col)

    # ── CASE C: UNSW-NB15 ─────────────────────────────────────────────────
    else:  # UNSW-NB15
        mapped_dict["duration"] = pd.to_numeric(get_val("dur", 0.0), errors="coerce").fillna(0.0).tolist()
        columns_matched.add("duration")

        # Protocol
        raw_proto = get_val("proto", "tcp").astype(str).str.lower().str.strip()
        mapped_dict["protocol_type"] = [
            p if p in ("tcp", "udp", "icmp") else "tcp" for p in raw_proto
        ]
        columns_matched.add("protocol_type")

        # Service
        raw_service = get_val("service", "other").astype(str).str.lower().str.strip()
        mapped_dict["service"] = [
            "other" if s in ("-", "", "none", "null") else s for s in raw_service
        ]
        columns_matched.add("service")

        # Flag mapping from state
        raw_state = get_val("state", "SF").astype(str).str.upper().str.strip()
        state_map: dict[str, str] = {
            "FIN": "SF", "CON": "SF", "INT": "SF", "CLO": "SF",
            "REQ": "S0", "RST": "REJ", "ACC": "S1", "ECO": "SF",
        }
        mapped_dict["flag"] = [state_map.get(s, "SF") for s in raw_state]
        columns_matched.add("flag")

        # Bytes
        mapped_dict["src_bytes"] = pd.to_numeric(get_val("sbytes", 0.0), errors="coerce").fillna(0.0).tolist()
        mapped_dict["dst_bytes"] = pd.to_numeric(get_val("dbytes", 0.0), errors="coerce").fillna(0.0).tolist()
        columns_matched.add("src_bytes")
        columns_matched.add("dst_bytes")

        # Land & Logged in
        mapped_dict["land"] = pd.to_numeric(get_val("is_sm_ips_ports", 0.0), errors="coerce").fillna(0.0).tolist()
        mapped_dict["logged_in"] = pd.to_numeric(get_val("is_ftp_login", 0.0), errors="coerce").fillna(0.0).tolist()
        columns_matched.add("land")
        columns_matched.add("logged_in")

        # Counts
        ct_src_dport = pd.to_numeric(get_val("ct_src_dport_ltm", 1.0), errors="coerce").fillna(1.0)
        ct_srv_src = pd.to_numeric(get_val("ct_srv_src", 1.0), errors="coerce").fillna(1.0)
        ct_dst = pd.to_numeric(get_val("ct_dst_ltm", 1.0), errors="coerce").fillna(1.0)
        ct_srv_dst = pd.to_numeric(get_val("ct_srv_dst", 1.0), errors="coerce").fillna(1.0)
        ct_dst_sport = pd.to_numeric(get_val("ct_dst_sport_ltm", 0.0), errors="coerce").fillna(0.0)

        mapped_dict["count"] = ct_src_dport.tolist()
        mapped_dict["srv_count"] = ct_srv_src.tolist()
        mapped_dict["dst_host_count"] = ct_dst.clip(upper=255.0).tolist()
        mapped_dict["dst_host_srv_count"] = ct_srv_dst.clip(upper=255.0).tolist()

        # Rates computed from UNSW aggregated counters
        same_srv_calc = (ct_srv_src / (ct_src_dport + 1e-5)).clip(lower=0.0, upper=1.0)
        diff_srv_calc = (1.0 - same_srv_calc).clip(lower=0.0, upper=1.0)
        dst_same_srv = (ct_srv_dst / (ct_dst + 1e-5)).clip(lower=0.0, upper=1.0)
        dst_diff_srv = (1.0 - dst_same_srv).clip(lower=0.0, upper=1.0)
        dst_same_port = (ct_dst_sport / (ct_dst + 1e-5)).clip(lower=0.0, upper=1.0)

        mapped_dict["same_srv_rate"] = same_srv_calc.round(4).tolist()
        mapped_dict["diff_srv_rate"] = diff_srv_calc.round(4).tolist()
        mapped_dict["srv_diff_host_rate"] = [0.0] * n_rows
        mapped_dict["dst_host_same_srv_rate"] = dst_same_srv.round(4).tolist()
        mapped_dict["dst_host_diff_srv_rate"] = dst_diff_srv.round(4).tolist()
        mapped_dict["dst_host_same_src_port_rate"] = dst_same_port.round(4).tolist()
        mapped_dict["dst_host_srv_diff_host_rate"] = [0.0] * n_rows

        # Errors
        rerr = (raw_state == "RST").astype(float)
        serr = (raw_state == "REQ").astype(float)
        mapped_dict["serror_rate"] = serr.tolist()
        mapped_dict["srv_serror_rate"] = serr.tolist()
        mapped_dict["rerror_rate"] = rerr.tolist()
        mapped_dict["srv_rerror_rate"] = rerr.tolist()
        mapped_dict["dst_host_serror_rate"] = serr.tolist()
        mapped_dict["dst_host_srv_serror_rate"] = serr.tolist()
        mapped_dict["dst_host_rerror_rate"] = rerr.tolist()
        mapped_dict["dst_host_srv_rerror_rate"] = rerr.tolist()

        columns_matched.update([
            "count", "srv_count", "dst_host_count", "dst_host_srv_count",
            "same_srv_rate", "diff_srv_rate", "dst_host_same_srv_rate",
            "dst_host_diff_srv_rate", "dst_host_same_src_port_rate",
            "serror_rate", "rerror_rate",
        ])

        # Content defaults
        unsw_defaults = [
            "wrong_fragment", "urgent", "hot", "num_failed_logins",
            "num_compromised", "root_shell", "su_attempted", "num_root",
            "num_file_creations", "num_shells", "num_access_files", "num_outbound_cmds",
            "is_host_login", "is_guest_login", "srv_diff_host_rate", "dst_host_srv_diff_host_rate",
        ]
        for col in unsw_defaults:
            mapped_dict[col] = [0.0] * n_rows
            columns_defaulted.add(col)

    # Convert to standard DataFrame
    mapped_df = pd.DataFrame(mapped_dict, columns=NSL_KDD_FEATURE_COLS)

    return MappedDatasetResult(
        schema_name=detection.schema_name,
        format_display=detection.format_display,
        df_mapped=mapped_df,
        total_rows=n_rows,
        columns_matched=sorted(list(columns_matched)),
        columns_defaulted=sorted(list(columns_defaulted)),
        raw_df=df,
    )


# ---------------------------------------------------------------------------
# 3. CSV File Parser & Wrapper
# ---------------------------------------------------------------------------

def process_csv_upload(csv_bytes: bytes, max_rows: int = 100) -> MappedDatasetResult:
    """End-to-end parser: reads CSV bytes, detects schema, and maps onto model features."""
    if not csv_bytes or len(csv_bytes.strip()) == 0:
        raise SchemaDetectionError("Uploaded CSV file is empty.", {"error": "empty_file"})

    # Try utf-8-sig first (handles Excel BOM), fallback to latin-1
    text: str = ""
    for enc in ["utf-8-sig", "utf-8", "latin-1"]:
        try:
            text = csv_bytes.decode(enc)
            break
        except UnicodeDecodeError:
            continue

    if not text:
        raise SchemaDetectionError("Could not decode CSV content. Please upload a standard UTF-8 encoded CSV.", {"error": "encoding_error"})

    # Parse headers first
    header_line = text.splitlines()[0] if text.splitlines() else ""
    try:
        sample_df = pd.read_csv(io.StringIO(header_line))
        raw_cols = list(sample_df.columns)
    except Exception as exc:
        raise SchemaDetectionError(f"Failed to parse CSV headers: {exc}", {"error": "csv_parse_error"})

    # Detect schema (raises SchemaDetectionError if no template matches)
    detection = detect_schema(raw_cols)

    # Load data up to max_rows
    try:
        df = pd.read_csv(io.StringIO(text), nrows=max_rows)
    except Exception as exc:
        raise SchemaDetectionError(f"Failed to read CSV data rows: {exc}", {"error": "csv_read_error"})

    if len(df) == 0:
        raise SchemaDetectionError("The CSV file has header columns but no data rows.", {"error": "no_data_rows"})

    return map_dataset_to_nsl_kdd(df, detection)


# ---------------------------------------------------------------------------
# 4. Sample CSV Data Generators for 1-Click Testing & Demos
# ---------------------------------------------------------------------------

def generate_sample_csv(template_name: str) -> str:
    """Generate a valid, benchmark-accurate sample CSV string for quick testing."""
    t = template_name.lower().replace("-", "_")

    if "nsl" in t or "kdd" in t:
        # Valid 41-feature NSL-KDD CSV with 3 sample rows
        header = ",".join(NSL_KDD_FEATURE_COLS)
        row1 = "0,tcp,http,SF,215,45076,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,1,1,0.0,0.0,0.0,0.0,1.0,0.0,0.0,0,0,0.0,0.0,0.0,0.0,0.0,0.0,0.0,0.0"
        row2 = "0,tcp,private,S0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,123,6,1.0,1.0,0.0,0.0,0.05,0.07,0.0,255,6,0.02,0.06,0.0,0.0,1.0,1.0,0.0,0.0"
        row3 = "0,tcp,ftp,SF,334,0,0,0,0,0,0,1,0,0,0,0,0,0,0,0,0,0,2,2,0.0,0.0,0.0,0.0,1.0,0.0,0.0,2,2,1.0,0.0,1.0,0.0,0.0,0.0,0.0,0.0"
        return f"{header}\n{row1}\n{row2}\n{row3}\n"

    elif "cic" in t:
        # Valid CICIDS2017 sample CSV with standard CICFlowMeter headers
        cols = [
            "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
            "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Flow Bytes/s",
            "Flow Packets/s", "Flow IAT Mean", "FIN Flag Count", "SYN Flag Count",
            "RST Flag Count", "PSH Flag Count", "ACK Flag Count", "URG Flag Count",
            "Init_Win_bytes_forward", "Label"
        ]
        header = ",".join(cols)
        r1 = "80,1250000,4,5,340,4200,4432.0,7.2,312500.0,1,1,0,0,1,0,29200,BENIGN"
        r2 = "445,45000,10,0,0,0,0.0,222.2,4500.0,0,1,0,0,0,0,0,DoS Hulk"
        r3 = "22,950000,8,6,650,1200,1947.3,14.7,158333.3,1,1,0,1,1,0,14600,SSH-Patator"
        return f"{header}\n{r1}\n{r2}\n{r3}\n"

    elif "unsw" in t:
        # Valid UNSW-NB15 sample CSV
        cols = [
            "dur", "proto", "service", "state", "spkts", "dpkts", "sbytes", "dbytes",
            "rate", "sttl", "dttl", "sload", "dload", "sloss", "dloss", "ct_srv_src",
            "ct_state_ttl", "ct_dst_ltm", "ct_src_dport_ltm", "ct_dst_sport_ltm",
            "ct_dst_src_ltm", "is_ftp_login", "is_sm_ips_ports", "attack_cat", "label"
        ]
        header = ",".join(cols)
        r1 = "0.121478,tcp,http,FIN,6,4,258,172,74.087,252,254,14158.9,9448.6,0,0,1,0,1,1,1,1,0,0,Normal,0"
        r2 = "0.000008,udp,dns,INT,2,0,114,0,125000.0,254,0,57000000.0,0.0,0,0,2,0,2,2,2,2,0,0,Generic,1"
        r3 = "0.451200,tcp,smtp,CON,10,8,1240,3200,39.89,64,60,21985.8,56737.5,1,1,3,0,2,1,1,1,0,0,Normal,0"
        return f"{header}\n{r1}\n{r2}\n{r3}\n"

    else:
        # Invalid / Unrecognized schema for error testing
        return "customer_id,transaction_amount,merchant_category,country,is_fraud\n1001,45.50,groceries,US,0\n1002,1250.00,electronics,CA,1\n"
