#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import sys
from datetime import datetime
from pathlib import Path
import pandas as pd
import numpy as np

def parse_args(argv=None):
    p = argparse.ArgumentParser(
        description="Generate an EPSS-prioritized XLSX report with KPIs.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    p.add_argument("-i", "--input", required=True, help="Input CSV path")
    p.add_argument("-o", "--output", help="Output XLSX path; if omitted, auto: report_YYYYMMDD_HHMM.xlsx")
    p.add_argument("-e", "--epss", type=float, default=90.0, help="Min EPSS to include (e.g. 90 or 0.90)")
    p.add_argument("-s", "--severity", help="Comma list of severities to include (e.g. critical,high)")
    p.add_argument("-v", "--verbose", action="store_true", help="Verbose mode")
    p.add_argument("--no-theme", action="store_true", help="Disable rich formatting (compat mode)")
    p.add_argument("--lang", choices=["pt","en"], default="en", help="Language for headers/labels")
    return p.parse_args(argv)


def vprint(flag, *a, **k):
    if flag:
        print(*a, **k)

def normalize_epss_threshold(val: float) -> float:
    if val is None:
        return 0.90
    return val/100.0 if val > 1 else float(val)

def parse_severities(sev_str):
    if not sev_str:
        return None
    mapping = {
        "critical":"Critical","high":"High","medium":"Medium","low":"Low",
        "info":"Info","informational":"Info","informacao":"Info"
    }
    out = []
    for token in sev_str.split(","):
        t = token.strip().lower()
        if not t: continue
        out.append(mapping.get(t, t.capitalize()))
    return out

def best_asset_key(row):
    name = str(row.get("asset.name","")).strip()
    ipv4 = str(row.get("asset.display_ipv4_address","")).strip()
    return name if name and name.lower() != "nan" else ipv4

def detect_flags(df):
    yes, no = "Yes", "No"
    kev_cols = [c for c in df.columns if "kev" in c.lower() or "known_exploit" in c.lower() or "cisa" in c.lower()]
    if kev_cols:
        s_kev = df[kev_cols].apply(lambda x: x.astype(str).str.lower().isin(["1","true","yes","y","sim"]).any(), axis=1)
    else:
        s_kev = pd.Series(False, index=df.index)
    exploit_cols = [c for c in df.columns if any(k in c.lower() for k in ["metasploit","canvas","exploit","edb"])]
    if exploit_cols:
        s_exp = df[exploit_cols].apply(lambda x: x.astype(str).str.lower().isin(["1","true","yes","y","sim"]).any(), axis=1)
    else:
        s_exp = pd.Series(False, index=df.index)
    return s_kev.map({True:yes, False:no}), s_exp.map({True:yes, False:no})

def normalize_last_seen(series):
    dt = pd.to_datetime(series, errors="coerce", utc=True)
    dt = dt.dt.tz_convert(None)
    return dt.dt.strftime("%d/%m/%Y").fillna("")

def severity_categorical(series):
    order = ["Critical","High","Medium","Low","Info"]
    try:
        return pd.Categorical(series, categories=order, ordered=True)
    except Exception:
        return series

def translate_headers(lang):
    return {
        "HOSTNAME": "HOSTNAME" if lang=="en" else "HOSTNAME",
        "IPV4": "IPV4",
        "OPERATING SYSTEM": "OPERATING SYSTEM" if lang=="en" else "SISTEMA OPERACIONAL",
        "CVE": "CVE",
        "EPSS SCORE": "EPSS SCORE",
        "PLUGIN ID": "PLUGIN ID",
        "PLUGIN NAME": "PLUGIN NAME" if lang=="en" else "NOME DO PLUGIN",
        "SOLUTION": "SOLUTION" if lang=="en" else "SOLUÇÃO",
        "LAST SEEN": "LAST SEEN" if lang=="en" else "ÚLTIMO VISTO",
        "SEVERITY": "SEVERITY" if lang=="en" else "SEVERIDADE",
        "KEV": "KEV",
        "EXPLOIT": "EXPLOIT",
    }

def build_excel(df_sel, output_path, verbose=False, apply_theme=True, lang="en"):
    output_path = Path(output_path)
    main_cols_map = {
        "asset.name": "HOSTNAME",
        "asset.display_ipv4_address": "IPV4",
        "asset.operating_system": "OPERATING SYSTEM",
        "definition.cve": "CVE",
        "definition.epss.score": "EPSS SCORE",
        "definition.id": "PLUGIN ID",
        "definition.name": "PLUGIN NAME",
        "definition.solution": "SOLUTION",
        "last_seen": "LAST SEEN",
        "severity": "SEVERITY",
    }
    cols = [c for c in main_cols_map if c in df_sel.columns]
    df_main = df_sel.copy()[cols].rename(columns=main_cols_map)

    if "EPSS SCORE" in df_main.columns:
        df_main["EPSS SCORE"] = pd.to_numeric(df_main["EPSS SCORE"], errors="coerce")
    if "LAST SEEN" in df_main.columns:
        df_main["LAST SEEN"] = normalize_last_seen(df_main["LAST SEEN"])

    kev, exp = detect_flags(df_sel)
    df_main["KEV"] = kev
    df_main["EXPLOIT"] = exp

    headers_map = translate_headers(lang)
    df_main = df_main.rename(columns=headers_map)

    dtemp = df_sel.copy()
    dtemp["asset_key"] = dtemp.apply(best_asset_key, axis=1)

    sev_counts = (dtemp.groupby("severity", observed=False).size().reindex(["Critical","High","Medium","Low"], fill_value=0).reset_index(name="Count").rename(columns={"severity":"Severity"}))

    if "definition.cve" in dtemp.columns:
        rows = []
        for _, row in dtemp.iterrows():
            key = row["asset_key"]
            cves = str(row.get("definition.cve","")).split(",")
            cves = [c.strip().upper() for c in cves if c.strip()]
            for c in cves:
                rows.append((c,key))
        if rows:
            df_top_cves_assets = (pd.DataFrame(rows, columns=["CVE","asset_key"])
                                  .groupby("CVE")["asset_key"].nunique()
                                  .reset_index(name="Unique Assets")
                                  .sort_values("Unique Assets", ascending=False))
        else:
            df_top_cves_assets = pd.DataFrame(columns=["CVE","Unique Assets"])
    else:
        df_top_cves_assets = pd.DataFrame(columns=["CVE","Unique Assets"])

    if "id" not in dtemp.columns:
        dtemp["id"] = np.arange(1, len(dtemp)+1)
    df_top_assets = (dtemp.groupby("asset_key")["id"].nunique()
                     .reset_index(name="Vulns Count")
                     .rename(columns={"asset_key":"Hostname"})
                     .sort_values("Vulns Count", ascending=False))

    with pd.ExcelWriter(output_path, engine="xlsxwriter") as writer:
        wb = writer.book

        if apply_theme:
            col_header_txt  = "#FFFFFF"
            col_accent      = "#991B1B"
            col_tittle      = "#0F0F0F"
            col_band        = "#DBDBDB"
            col_sev_crit    = "#991B1B"
            col_sev_high    = "#E85100"
            col_sev_med     = "#E89A00"
            col_sev_low     = "#00A308"
            grid_color      = "#C4C4C4"

            fmt_header = wb.add_format({"bold": True, "font_color": col_header_txt, "bg_color": col_tittle,
                                        "align": "center", "valign": "vcenter", "bottom": 2, "bottom_color": col_tittle})
            fmt_title = wb.add_format({"bold": True, "font_size": 12, "font_color": "#FFFFFF",
                                       "bg_color": col_accent, "align":"center", "valign":"vcenter"})
            fmt_cell = wb.add_format({"font_name": "Segoe UI", "font_size": 10, "valign": "top"})
            fmt_wrap = wb.add_format({"font_name": "Segoe UI", "font_size": 10, "text_wrap": True, "valign": "top"})
            fmt_center = wb.add_format({"font_name": "Segoe UI", "font_size": 10, "align":"center", "valign":"vcenter"})
            fmt_percent = wb.add_format({"num_format":"0.00%", "align":"center", "valign":"vcenter"})
            fmt_date = wb.add_format({"num_format":"dd/mm/yyyy", "align":"center", "valign":"vcenter"})
            fmt_band = wb.add_format({"bg_color": col_band})
            fmt_grid = wb.add_format({"border":1, "border_color": grid_color})
            fmt_sev_crit = wb.add_format({"bg_color": col_sev_crit, "font_color":"#FFFFFF", "bold":True, "align":"center"})
            fmt_sev_high = wb.add_format({"bg_color": col_sev_high, "font_color":"#FFFFFF", "bold":True, "align":"center"})
            fmt_sev_med  = wb.add_format({"bg_color": col_sev_med,  "font_color":"#FFFFFF", "bold":True, "align":"center"})
            fmt_sev_low  = wb.add_format({"bg_color": col_sev_low,  "font_color":"#FFFFFF", "bold":True, "align":"center"})
        else:
            fmt_header = wb.add_format({"bold": True})
            fmt_title  = wb.add_format({"bold": True})
            fmt_cell = wb.add_format({})
            fmt_wrap = wb.add_format({"text_wrap": True})
            fmt_center = wb.add_format({"align":"center"})
            fmt_percent = wb.add_format({"num_format":"0.00%"})
            fmt_date = wb.add_format({"num_format":"dd/mm/yyyy"})
            fmt_band = wb.add_format({})
            fmt_grid = wb.add_format({})
            fmt_sev_crit = fmt_center
            fmt_sev_high = fmt_center
            fmt_sev_med  = fmt_center
            fmt_sev_low  = fmt_center

        # Main sheet
        df_main.to_excel(writer, index=False, sheet_name="vulns_filtradas", startrow=1)
        ws = writer.sheets["vulns_filtradas"]
        ws.merge_range(0, 0, 0, max(0, len(df_main.columns)-1), "EPSSight - PRIORITIZATION REPORT", fmt_title)
        ws.set_row(0, 22)
        ws.set_row(1, 18)
        for c, col in enumerate(df_main.columns):
            ws.write(1, c, col, fmt_header)
        ws.freeze_panes(2, 0)
        ws.autofilter(1, 0, 1+len(df_main), len(df_main.columns)-1)

        for c, col in enumerate(df_main.columns):
            width = 18
            fmt = fmt_cell
            if col in (headers_map.get("HOSTNAME","HOSTNAME"), headers_map.get("PLUGIN NAME","PLUGIN NAME"), headers_map.get("SOLUTION","SOLUTION")):
                width = 38; fmt = fmt_wrap
            elif col in ("CVE",):
                width = 24; fmt = fmt_cell
            elif col in (headers_map.get("OPERATING SYSTEM","OPERATING SYSTEM"),):
                width = 28; fmt = fmt_wrap
            elif col in ("IPV4","PLUGIN ID", headers_map.get("SEVERITY","SEVERITY")):
                width = 14; fmt = fmt_center
            elif col == headers_map.get("EPSS SCORE","EPSS SCORE"):
                width = 12; fmt = fmt_percent
            elif col == headers_map.get("LAST SEEN","LAST SEEN"):
                width = 14; fmt = fmt_date
            elif col in (headers_map.get("KEV","KEV"), headers_map.get("EXPLOIT","EXPLOIT")):
                width = 10; fmt = fmt_center
            ws.set_column(c, c, width, fmt)

        if len(df_main) > 0:
            total_cols = len(df_main.columns)-1
            # severity column index
            try:
                c_sev = list(df_main.columns).index(headers_map.get("SEVERITY","SEVERITY"))
            except ValueError:
                c_sev = None
            r1, r2 = 2, 1+len(df_main)
            if apply_theme:
                if c_sev is None or c_sev > 0:
                    ws.conditional_format(r1, 0, r2, (c_sev-1) if c_sev else total_cols, {"type":"formula","criteria":"=MOD(ROW(),2)=0","format":fmt_band})
                if c_sev is not None and c_sev < total_cols:
                    ws.conditional_format(r1, c_sev+1, r2, total_cols, {"type":"formula","criteria":"=MOD(ROW(),2)=0","format":fmt_band})
                # subtle grid
                ws.conditional_format(r1, 0, r2, total_cols, {"type":"no_blanks","format":fmt_grid})
                # EPSS data bar
                try:
                    c_epss = list(df_main.columns).index(headers_map.get("EPSS SCORE","EPSS SCORE"))
                    ws.conditional_format(r1, c_epss, r2, c_epss, {"type":"data_bar", "bar_color": col_accent})
                except ValueError:
                    pass

        if apply_theme and c_sev is not None:
            ws.conditional_format(r1, c_sev, r2, c_sev, {"type":"cell","criteria":"==","value":'"Critical"',"format":fmt_sev_crit})
            ws.conditional_format(r1, c_sev, r2, c_sev, {"type":"cell","criteria":"==","value":'"High"',    "format":fmt_sev_high})
            ws.conditional_format(r1, c_sev, r2, c_sev, {"type":"cell","criteria":"==","value":'"Medium"',  "format":fmt_sev_med})
            ws.conditional_format(r1, c_sev, r2, c_sev, {"type":"cell","criteria":"==","value":'"Low"',     "format":fmt_sev_low})

        # Other sheets (kept)
        def write_simple(name, df):
            df.to_excel(writer, index=False, sheet_name=name, startrow=1)
            w = writer.sheets[name]
            w.merge_range(0, 0, 0, max(0,len(df.columns)-1), name.replace("_"," ").title(), fmt_title)
            w.set_row(0, 22); w.set_row(1, 18)
            for cc, coln in enumerate(df.columns):
                w.write(1, cc, coln, fmt_header)
                w.set_column(cc, cc, 24, fmt_cell)
            w.freeze_panes(2,0)
            w.autofilter(1, 0, 1+len(df), max(0,len(df.columns)-1))
            if apply_theme and len(df) > 0:
                w.conditional_format(2, 0, 1+len(df), max(0,len(df.columns)-1), {"type":"formula","criteria":"=MOD(ROW(),2)=0","format":fmt_band})
                w.conditional_format(2, 0, 1+len(df), max(0,len(df.columns)-1), {"type":"no_blanks","format":fmt_grid})

        write_simple("por_severidade", sev_counts)
        write_simple("top_cves_por_ativos", df_top_cves_assets)
        write_simple("top_ativos_por_vulns", df_top_assets)

def print_summary_terminal(df_selected, epss_thr, severities_chosen=None, lang="en"):
    def label(s):
        if lang=="pt":
            return {"Critical":"Críticas","High":"Altas","Medium":"Médias","Low":"Baixas","Info":"Informativas"}.get(s,s)
        return s

    # asset key
    def _ak(r):
        n = str(r.get("asset.name","")).strip()
        ip = str(r.get("asset.display_ipv4_address","")).strip()
        return n if n and n.lower()!="nan" else ip

    if len(df_selected):
        tmp = df_selected.copy()
        tmp["asset_key"] = tmp.apply(_ak, axis=1)
        itens = len(tmp)
        assets = tmp["asset_key"].nunique()
        crit = (tmp["severity"]=="Critical").sum()
        high = (tmp["severity"]=="High").sum()
        med  = (tmp["severity"]=="Medium").sum()
        low  = (tmp["severity"]=="Low").sum()
    else:
        itens=assets=crit=high=med=low=0

    if lang=="pt":
        print("\nResumo executivo (KPIs)")
        print("Métrica\tValor")
        print(f"Itens (EPSS {int(round(epss_thr*100))}%+)\t{itens}")
        print(f"Ativos únicos impactados\t{assets}")
        print(f"Críticas\t{crit}")
        print(f"Altas\t{high}")
        print(f"Médias\t{med}")
        print(f"Baixas\t{low}")
    else:
        print("\nExecutive Summary (KPIs)")
        print("Metric\tValue")
        print(f"Items (EPSS {int(round(epss_thr*100))}%+)\t{itens}")
        print(f"Unique impacted assets\t{assets}")
        print(f"Critical\t{crit}")
        print(f"High\t{high}")
        print(f"Medium\t{med}")
        print(f"Low\t{low}")

    # Top 10 CVEs by impacted assets
    if len(df_selected) and "definition.cve" in df_selected.columns:
        rows = []
        tmp = df_selected.copy()
        tmp["asset_key"] = tmp.apply(_ak, axis=1)
        for _, row in tmp.iterrows():
            key = row["asset_key"]
            cves = str(row.get("definition.cve","")).split(",")
            cves = [c.strip().upper() for c in cves if c.strip()]
            for c in cves:
                rows.append((c,key))
        if rows:
            tdf = pd.DataFrame(rows, columns=["CVE","asset_key"])
            top = (tdf.groupby("CVE")["asset_key"].nunique()
                      .reset_index(name="Unique Assets")
                      .sort_values("Unique Assets", ascending=False)
                      .head(10))
            print("\nTop CVEs por ativos afetados" if lang=="pt" else "\nTop CVEs by impacted assets")
            for _, r in top.iterrows():
                print(f"{r['CVE']}\t{int(r['Unique Assets'])}")
        else:
            if lang=="pt":
                print("\n(sem CVEs no conjunto filtrado)")
            else:
                print("\n(no CVEs in filtered set)")

def banner():
    RED   = "\033[31m"
    RESET = "\033[0m"

    print(RED + rf"                                 @@@@@@@@@                                      ")
    print(rf"                            @@@@@@@@@@@@@@@@@@@                                 ")
    print(rf"                         @@@@@@@           @@@@@@@@                             ") 
    print(rf"                      @@@@  @@@        @@@   @@@@@@@@                           ") 
    print(rf"                    @@@@    @@         @@@    @@@@@@@@@                         ") 
    print(rf"                   @@@     @@      @@@ @@@    @@@@@@@@@@@                       ") 
    print(rf"                  @@@@     @@   @@ @@@ @@@    @@@@@@@@@@@                       ") 
    print(rf"                    @@@@   @@@  @@ @@@ @@@    @@@@@@@@@                         ") 
    print(rf"                      @@@@  @@@ @@ @@@ @@@   @@@@@@@@                           ") 
    print(rf"                         @@@@@@@@@ @@@ @@@ @@@@@@@@                             ") 
    print(rf"                            @@@@@@@@@@ @@@@@@@@@                                ") 
    print(rf"                                 @@@@@@@@@@                                     ") 
    print(rf"                                                                                ") 
    print(RESET + rf"                                                                                ") 
    print(rf"         ####### #######  #######" + RED + rf"  @@@@@@@  @@          @@       @@             " + RESET) 
    print(rf"         ##      ##    ## ##   " + RED + rf"    @@       @@   @@@ @@ @@ @@@  @@@@@           " + RESET) 
    print(rf"         ######  ##   ###  ######  " + RED + rf" @@@@@   @@ @@@  @@@ @@@  @@  @@             " + RESET) 
    print(rf"         ##      ######        ###  " + RED + rf"    @@@ @@ @@    @@ @@   @@  @@             " + RESET) 
    print(rf"         ####### ##       ###  ###" + RED + rf" @@@  @@@ @@  @@@@@@@ @@   @@  @@@            " + RESET) 
    print(rf"         ####### ##         ####  " + RED + rf"   @@@    @@       @@ @@   @@    @@           ") 
    print(rf"                                                @@@@@@                          " + RESET)
    print(rf"           *-__---_-* Exploit Prediction Scoring System *---__-_--*")
    print()

def main(argv=None):
    banner()
    args = parse_args(argv)
    verbose = args.verbose
    epss_thr = normalize_epss_threshold(args.epss)
    apply_theme = not args.no_theme
    lang = args.lang

    out_path = args.output
    if not out_path:
        ts = datetime.now().strftime("report_%Y%m%d_%H%M.xlsx")
        out_path = ts

    vprint(verbose, f"[+] EPSS threshold (fraction): {epss_thr:.2f}")
    vprint(verbose, f"[+] Reading CSV: {args.input}")

    df = pd.read_csv(args.input)

    vprint(verbose, f"[+] Filtering EPSS >= {epss_thr:.2f}")
    df_epss = df[df["definition.epss.score"].fillna(0) >= epss_thr].copy()

    severities = parse_severities(args.severity)
    if severities:
        vprint(verbose, f"[+] Filtering severities: {severities}")
        df_selected = df_epss[df_epss["severity"].isin(severities)].copy()
    else:
        df_selected = df_epss

    df_selected["severity"] = severity_categorical(df_selected["severity"])
    df_selected = df_selected.sort_values(by=["severity","definition.epss.score"], ascending=[True, False]).copy()

    vprint(verbose, f"[+] Writing XLSX: {out_path} (theme={'off' if not apply_theme else 'on'}, lang={lang})")
    build_excel(df_selected, out_path, verbose=verbose, apply_theme=apply_theme, lang=lang)

    print_summary_terminal(df_selected, epss_thr, severities_chosen=severities, lang=lang)
    print()

if __name__ == "__main__":
    sys.exit(main())
