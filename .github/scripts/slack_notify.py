#!/usr/bin/env python3
import sys, os, json
import requests

def load_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except FileNotFoundError:
        return {}

def summarize_snyk(data):
    vulns = data.get("vulnerabilities", [])
    high = sum(1 for v in vulns if v.get("severity") == "high")
    return f"{len(vulns)} total ({high} high)"

def summarize_gitleaks(data):
    findings = data.get("findings", [])
    return f"{len(findings)} secrets"

def summarize_zap(data):
    alerts = data.get("site", [{}])[0].get("alerts", [])
    sev = {"High":0,"Medium":0,"Low":0}
    for a in alerts:
        sev[a["risk"]] += 1
    return f"High: {sev['High']}, Medium: {sev['Medium']}, Low: {sev['Low']}"

def summarize_pii(data):
    counts = data.get("summary", {})
    return ", ".join(f"{k}: {v}" for k,v in counts.items())

def build_message(reports_dir):
    snyk = summarize_snyk(load_json(os.path.join(reports_dir, "snyk-report.json")))
    leaks = summarize_gitleaks(load_json(os.path.join(reports_dir, "gitleaks-report.json")))
    zap   = summarize_zap(load_json(os.path.join(reports_dir, "zap-report.json")))
    pii   = summarize_pii(load_json(os.path.join(reports_dir, "pii-report.json")))

    text = (
        "*Privacy Scan Results*\n"
        f"> *Snyk:* {snyk}\n"
        f"> *GitLeaks:* {leaks}\n"
        f"> *ZAP:* {zap}\n"
        f"> *PII Scan:* {pii}\n"
    )
    return {"text": text}

def main():
    reports_dir = sys.argv[1]
    payload = build_message(reports_dir)
    resp = requests.post(os.environ["SLACK_WEBHOOK"], json=payload)
    resp.raise_for_status()

if __name__ == "__main__":
    main()
