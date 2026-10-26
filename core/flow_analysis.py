"""Bidirectional flow reconstruction from the packet table."""
from __future__ import annotations

import numpy as np
import pandas as pd

IDLE_SPLIT_SEC = 30.0  # idle gap that starts a new UDP/ICMP flow
FLOW_COLUMNS = ["flow_id", "proto", "src", "sport", "dst", "dport", "start", "end", "duration", "pkts_fwd",
                "pkts_rev", "bytes_fwd", "bytes_rev", "payload_fwd", "payload_rev", "syn", "synack", "rst",
                "fin", "state", "app", "sni", "http_host", "syn_win", "bytes_total"]


def build_flows(pkts: pd.DataFrame) -> pd.DataFrame:
    """Group packets into flows. 'fwd' is the initiator (first SYN, else first packet seen)."""
    empty = pd.DataFrame(columns=FLOW_COLUMNS)
    if pkts is None or pkts.empty:
        return empty
    d = pkts[pkts["proto"].isin(["TCP", "UDP", "ICMP", "ICMPv6"])].copy()
    if d.empty:
        return empty
    d["sport"] = d["sport"].fillna(0).astype(int)
    d["dport"] = d["dport"].fillna(0).astype(int)
    d["payload_len"] = d["payload_len"].fillna(0).astype(int)
    d["ep_s"] = d["src"] + "|" + d["sport"].astype(str)
    d["ep_d"] = d["dst"] + "|" + d["dport"].astype(str)
    fwd_order = d["ep_s"] <= d["ep_d"]
    lo = d["ep_s"].where(fwd_order, d["ep_d"])
    hi = d["ep_d"].where(fwd_order, d["ep_s"])
    d["key"] = d["proto"] + "#" + lo + "#" + hi
    d = d.sort_values("ts", kind="stable")
    # UDP/ICMP have no handshake: split a 5-tuple into separate flows after an idle gap so that
    # fixed-port periodic traffic (e.g. NTP) is not merged into one giant flow.
    nontcp = d["proto"] != "TCP"
    gap = d.groupby("key")["ts"].diff()
    seg = ((gap > IDLE_SPLIT_SEC) & nontcp).groupby(d["key"]).cumsum().astype(int)
    d["key"] = d["key"] + "@" + seg.astype(str)

    flags = d["tcp_flags"].fillna("")
    has_s, has_a = flags.str.contains("S"), flags.str.contains("A")
    d["is_syn"] = has_s & ~has_a
    d["has_synack"] = has_s & has_a
    d["has_rst"] = flags.str.contains("R")
    d["has_fin"] = flags.str.contains("F")
    d["syn_win"] = d["tcp_window"].astype("float").where(d["is_syn"])

    init = d.groupby("key")["ep_s"].first()
    syn_ep = d[d["is_syn"]].groupby("key")["ep_s"].first()
    init.loc[syn_ep.index] = syn_ep
    d["init_ep"] = d["key"].map(init)
    d["fwd"] = d["ep_s"] == d["init_ep"]
    d["n_fwd"] = d["fwd"].astype(int)
    d["n_rev"] = 1 - d["n_fwd"]
    d["b_fwd"] = d["length"].where(d["fwd"], 0)
    d["b_rev"] = d["length"].where(~d["fwd"], 0)
    d["p_fwd"] = d["payload_len"].where(d["fwd"], 0)
    d["p_rev"] = d["payload_len"].where(~d["fwd"], 0)
    resp = d[d["fwd"]].groupby("key")["ep_d"].first()

    agg = d.groupby("key", sort=False).agg(
        proto=("proto", "first"), start=("ts", "min"), end=("ts", "max"),
        pkts_fwd=("n_fwd", "sum"), pkts_rev=("n_rev", "sum"), bytes_fwd=("b_fwd", "sum"),
        bytes_rev=("b_rev", "sum"), payload_fwd=("p_fwd", "sum"), payload_rev=("p_rev", "sum"),
        syn=("is_syn", "sum"), synack=("has_synack", "sum"), rst=("has_rst", "sum"), fin=("has_fin", "sum"),
        app=("app", "first"), port_app=("port_app", "first"), sni=("tls_sni", "first"),
        http_host=("http_host", "first"), syn_win=("syn_win", "first"), init_ep=("init_ep", "first"))
    agg["resp_ep"] = resp.reindex(agg.index)
    agg = agg.dropna(subset=["resp_ep"])
    split_i = agg["init_ep"].str.rsplit("|", n=1, expand=True)
    split_r = agg["resp_ep"].str.rsplit("|", n=1, expand=True)
    agg["src"], agg["sport"] = split_i[0], split_i[1].astype(int)
    agg["dst"], agg["dport"] = split_r[0], split_r[1].astype(int)
    agg["app"] = agg["app"].fillna(agg["port_app"])

    tcp = agg["proto"] == "TCP"
    conds = [tcp & (agg.synack > 0) & (agg.rst > 0), tcp & (agg.synack > 0) & (agg.fin > 0),
             tcp & (agg.synack > 0), tcp & (agg.syn > 0) & (agg.pkts_rev > 0) & (agg.rst > 0),
             tcp & (agg.syn > 0) & (agg.pkts_rev == 0), tcp & (agg.syn > 0), tcp,
             ~tcp & (agg.pkts_rev > 0), ~tcp]
    labels = ["RESET", "CLOSED", "ESTABLISHED", "REJECTED", "NO_RESPONSE", "SYN_OTHER", "PARTIAL",
              "REPLIED", "NO_REPLY"]
    agg["state"] = np.select(conds, labels, default="OTHER")
    agg["duration"] = agg["end"] - agg["start"]
    agg["bytes_total"] = agg["bytes_fwd"] + agg["bytes_rev"]
    agg = agg.sort_values("start").reset_index(drop=True)
    agg["flow_id"] = agg.index
    for c in ("syn", "synack", "rst", "fin"):
        agg[c] = agg[c].astype(int)
    return agg[FLOW_COLUMNS]
