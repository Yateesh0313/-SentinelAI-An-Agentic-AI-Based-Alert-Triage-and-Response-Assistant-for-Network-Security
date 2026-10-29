"""SentinelAI -- Prepare 1,000-row test datasets for UNSW-NB15 layouts.

Creates:
1. data/csv/unsw_nb15_training_1000.csv:
   First 1,000 rows directly from official UNSW_NB15_training-set.csv (45 columns).
2. data/csv/unsw_nb15_full_1000.csv:
   First 1,000 rows in the raw full-file layout (49 columns) with:
   - srcip, sport, dstip, dsport, Stime, Ltime
   - Unnormalized header names (Sload, Dload, Spkts, Dpkts, smeansz, dmeansz, res_bdy_len, Sjit, Djit, Sintpkt, Dintpkt)
   - Real flow parameters from UNSW
   - Attack categories with whitespace, spelling variants (Backdoor / Backdoors), and blanks
"""

from __future__ import annotations

from pathlib import Path
import pandas as pd
import numpy as np

PROJECT_ROOT = Path(__file__).resolve().parent.parent
RAW_TRAIN_PATH = PROJECT_ROOT / "ml" / "data" / "raw" / "UNSW_NB15_training-set.csv"
DATA_CSV_DIR = PROJECT_ROOT / "data" / "csv"
DATA_CSV_DIR.mkdir(parents=True, exist_ok=True)

TRAIN_1000_PATH = DATA_CSV_DIR / "unsw_nb15_training_1000.csv"
FULL_1000_PATH = DATA_CSV_DIR / "unsw_nb15_full_1000.csv"


def prepare_datasets():
    print(f"Reading training dataset from {RAW_TRAIN_PATH} ...")
    df_raw = pd.read_csv(RAW_TRAIN_PATH)

    # 1. First 1,000 rows of training-set layout
    df_train_1000 = df_raw.iloc[:1000].copy()
    df_train_1000.to_csv(TRAIN_1000_PATH, index=False)
    print(f"Wrote {len(df_train_1000)} rows to {TRAIN_1000_PATH} (Columns: {len(df_train_1000.columns)})")

    # 2. First 1,000 rows of full-file layout (49 columns)
    # 49 columns order:
    # srcip, sport, dstip, dsport, proto, state, dur, sbytes, dbytes, sttl, dttl, sloss, dloss,
    # service, Sload, Dload, Spkts, Dpkts, swin, dwin, stcpb, dtcpb, smeansz, dmeansz, trans_depth,
    # res_bdy_len, Sjit, Djit, Stime, Ltime, Sintpkt, Dintpkt, tcprtt, synack, ackdat, is_sm_ips_ports,
    # ct_state_ttl, ct_flw_http_mthd, is_ftp_login, ct_ftp_cmd, ct_srv_src, ct_srv_dst, ct_dst_ltm,
    # ct_src_ltm, ct_src_dport_ltm, ct_dst_sport_ltm, ct_dst_src_ltm, attack_cat, label

    base = df_raw.iloc[:1000].copy()
    n = len(base)

    # Generate realistic source/destination IPs in UNSW ranges
    # Official UNSW-NB15 ranges:
    # Normal client traffic: 59.166.0.0/16
    # Attack traffic: 175.45.176.0/24
    # Servers: 149.171.126.0/24
    src_ips = []
    dst_ips = []
    sports = []
    dsports = []
    stimes = []
    ltimes = []

    base_time = 1421927400

    for i in range(n):
        is_attack = base["label"].iloc[i] == 1
        if is_attack:
            src_ips.append(f"175.45.176.{i % 4}")
        else:
            src_ips.append(f"59.166.{i % 5}.{i % 250}")

        dst_ips.append(f"149.171.126.{i % 10}")

        service = str(base["service"].iloc[i]).lower()
        if service == "http":
            dsport = 80
        elif service == "ftp":
            dsport = 21
        elif service == "smtp":
            dsport = 25
        elif service == "dns":
            dsport = 53
        elif service == "ssh":
            dsport = 22
        else:
            dsport = 1000 + (i % 8000)

        dsports.append(dsport)
        sports.append(1024 + (i % 60000))

        dur = float(base["dur"].iloc[i])
        t_start = base_time + i * 2
        t_end = t_start + int(max(dur, 1))
        stimes.append(t_start)
        ltimes.append(t_end)

    # Build 49 column DataFrame with unnormalized names to test normalization
    full_dict = {
        "srcip": src_ips,
        "sport": sports,
        "dstip": dst_ips,
        "dsport": dsports,
        "proto": base["proto"],
        "state": base["state"],
        "dur": base["dur"],
        "sbytes": base["sbytes"],
        "dbytes": base["dbytes"],
        "sttl": base["sttl"],
        "dttl": base["dttl"],
        "sloss": base["sloss"],
        "dloss": base["dloss"],
        "service": base["service"],
        "Sload": base["sload"],
        "Dload": base["dload"],
        "Spkts": base["spkts"],
        "Dpkts": base["dpkts"],
        "swin": base["swin"],
        "dwin": base["dwin"],
        "stcpb": base["stcpb"],
        "dtcpb": base["dtcpb"],
        "smeansz": base["smean"],
        "dmeansz": base["dmean"],
        "trans_depth": base["trans_depth"],
        "res_bdy_len": base["response_body_len"],
        "Sjit": base["sjit"],
        "Djit": base["djit"],
        "Stime": stimes,
        "Ltime": ltimes,
        "Sintpkt": base["sinpkt"],
        "Dintpkt": base["dinpkt"],
        "tcprtt": base["tcprtt"],
        "synack": base["synack"],
        "ackdat": base["ackdat"],
        "is_sm_ips_ports": base["is_sm_ips_ports"],
        "ct_state_ttl": base["ct_state_ttl"],
        "ct_flw_http_mthd": base["ct_flw_http_mthd"],
        "is_ftp_login": base["is_ftp_login"],
        "ct_ftp_cmd": base["ct_ftp_cmd"],
        "ct_srv_src": base["ct_srv_src"],
        "ct_srv_dst": base["ct_srv_dst"],
        "ct_dst_ltm": base["ct_dst_ltm"],
        "ct_src_ltm": base["ct_src_ltm"],
        "ct_src_dport_ltm": base["ct_src_dport_ltm"],
        "ct_dst_sport_ltm": base["ct_dst_sport_ltm"],
        "ct_dst_src_ltm": base["ct_dst_src_ltm"],
    }

    # Add realistic attack_cat with whitespace and Backdoor/Backdoors variants
    raw_cats = base["attack_cat"].copy().tolist()
    modified_cats = []
    for c in raw_cats:
        c_str = str(c).strip()
        if c_str == "Normal":
            # Some blanks to test blank -> Normal filling
            if np.random.rand() < 0.05:
                modified_cats.append("   ")
            else:
                modified_cats.append("  Normal  ")
        elif c_str.lower() in ("backdoor", "backdoors"):
            # Alternate spelling variants
            modified_cats.append("Backdoor " if np.random.rand() < 0.5 else " Backdoors ")
        else:
            modified_cats.append(f" {c_str} ")

    full_dict["attack_cat"] = modified_cats
    full_dict["label"] = base["label"]

    df_full = pd.DataFrame(full_dict)
    assert len(df_full.columns) == 49, f"Expected 49 columns, got {len(df_full.columns)}"
    df_full.to_csv(FULL_1000_PATH, index=False)
    print(f"Wrote {len(df_full)} rows to {FULL_1000_PATH} (Columns: {len(df_full.columns)})")


if __name__ == "__main__":
    prepare_datasets()
