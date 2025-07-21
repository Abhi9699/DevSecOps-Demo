import argparse
import json
import os
import sys
import google.generativeai as genai


SEVERITY_KEYWORDS = [
    "critical", "high", "medium", "low", "info", "informational", "warning", "error"
]
# Optionally, map findings keys from different tools to a common format for better normalization
STANDARD_FINDING_KEYS = ["severity", "file", "location", "line", "message", "rule_id", "resource", "evidence", "url"]


def load_json_report(path):
    """Load standard JSON file, fallback to empty list."""
    if not os.path.isfile(path):
        print(f"[WARN] JSON not found: {path}")
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load JSON from {path}: {e}")
        return []


def load_jsonl_report(path):
    """Load a JSONL (newline-delimited JSON) file as a list."""
    if not os.path.isfile(path):
        print(f"[WARN] JSONL not found: {path}")
        return []
    report = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if line:
                try:
                    report.append(json.loads(line))
                except Exception as e:
                    print(f"[WARN] Invalid JSONL at line {i}: {e}")
    return report


def get_severity(finding):
    if not isinstance(finding, dict):
        return "unknown"
    for key in ["severity", "level", "impact"]:
        if key in finding:
            val = str(finding[key]).strip().lower()
            for sev in SEVERITY_KEYWORDS:
                if sev in val:
                    return sev
    # Pattern search fallback
    for v in finding.values():
        if isinstance(v, str):
            sval = v.lower()
            for sev in SEVERITY_KEYWORDS:
                if sev in sval:
                    return sev
    return "unknown"


def normalize_finding(finding):
    # Maps tool-specific fields to a flat dict
    n = {}
    if not isinstance(finding, dict):
        n["message"] = str(finding)
        n["severity"] = "unknown"
        return n
    # Copy known keys or best effort mapping
    n["severity"] = get_severity(finding)
    for std_key in STANDARD_FINDING_KEYS:
        for key in finding:
            if std_key.lower() in key.lower():
                n[std_key] = finding[key]
    # Merge basic context from finding
    n.update({k: v for k, v in finding.items() if k in ("filepath", "file", "url", "rule_id", "message", "description", "line", "column")})
    return n


def format_finding_md(finding):
    # Returns a Markdown bullet for one finding (normalized).
    n = normalize_finding(finding)
    parts = []
    if n.get("severity"):
        parts.append(f"**[{n.get('severity').capitalize()}]**")
    if n.get("file"):
        line = f":{n.get('line')}" if n.get("line") else ""
        parts.append(f"`{n.get('file')}{line}`")
    elif n.get("resource"):
        parts.append(f"`{n.get('resource')}`")
    elif n.get("url"):
        parts.append(f"<{n.get('url')}>")
    msg = n.get("message") or n.get("description") or n.get("rule_id") or ""
    if msg:
        parts.append(msg.strip().replace("\n", " ")[:180])
    # Evidence/secret hints, but do not leak secrets!
    if "secret" in finding or "evidence" in finding:
        parts.append("**[Evidence Redacted]**")
    return " - " + " • ".join(parts)


def group_and_sort_findings(findings):
    # Normalize, group by severity, then order by severity level
    severity_order = {"critical": 1, "high": 2, "medium": 3, "warning": 4, "low": 5, "info": 6, "informational": 6, "unknown": 7}
    grouped = {}
    for f in findings:
        sev = get_severity(f)
        grouped.setdefault(sev, []).append(f)
    # Always order: critical, high, medium, low, info, unknown
    ordered = []
    for sev in sorted(grouped, key=lambda s: severity_order.get(s, 99)):
        ordered.extend(grouped[sev])
    return ordered, grouped


def summarize_findings_md(findings, tool_name):
    ordered, grouped = group_and_sort_findings(findings)
    total = sum(len(g) for g in grouped.values())
    if total == 0:
        return f"_No issues detected by **{tool_name}**._"
    count_by_sev = {k: len(v) for k, v in grouped.items()}
    top = ordered[:10]
    summary = f"**Findings:** {total} ({', '.join(f'{k}: {v}' for k, v in count_by_sev.items())})\n\n"
    if len(ordered) > 10:
        summary += f"> _Showing top 10 by severity. {total-10} more not shown for brevity._\n"
    # Collapsible details for longer lists
    summary += "<details>\n<summary>View Top 10 Findings</summary>\n\n"
    for f in top:
        summary += format_finding_md(f) + "\n"
    summary += "\n</details>\n"
    # Highlight most critical remediation actions at top
    urgent = [f for f in top if get_severity(f) in ("critical", "high")]
    if urgent:
        summary += "\n**🚨 Critical/High Action Items:**\n"
        for f in urgent:
            n = normalize_finding(f)
            # Add tool-specific action hints, or use general
            advice = recommend_remediation(n, tool_name)
            if advice:
                summary += f"- {advice}\n"
    return summary.strip()


def recommend_remediation(finding, tool):
    sev = finding.get("severity", "")
    msg = finding.get("message", "") or finding.get("rule_id", "")
    location = ""
    if finding.get("file"):
        location = f" (`{finding.get('file')}`"
        if finding.get("line"): location += f":{finding.get('line')}"
        location += ")"
    # These can be made more sophisticated per tool/rule
    if tool.lower() == "trivy":
        if sev in ("critical", "high", "medium"):
            return f"Review and immediately patch/update vulnerable dependency{location}."
        else:
            return f"Consider updating dependencies{location}."
    elif tool.lower() == "semgrep":
        if sev in ("critical", "high"):
            return f"Refactor code to eliminate {msg} {location}."
        else:
            return f"Address security smells if feasible{location}."
    elif tool.lower() == "trufflehog":
        return f"Rotate discovered secret(s) immediately, validate no production leakage, and scrub from git history{location}."
    elif tool.lower() == "zap":
        if sev in ("critical", "high"):
            return f"Remediate the vulnerability {msg} found in {location} — consider input validation, authentication, or authorization controls."
        else:
            return f"Review web endpoint security posture{location}."
    elif tool.lower() == "garak":
        return f"Address prompt injection/config issues identified in LLM API(s) {location}."
    return ""


def build_risk_heatmap(reports_by_tool):
    """Generates a heatmap table of severities by tool."""
    sevs = ["Critical", "High", "Medium", "Low", "Info"]
    tool_names = list(reports_by_tool.keys())
    counts = {tool: {sev: 0 for sev in sevs} for tool in tool_names}
    for tool, findings in reports_by_tool.items():
        _, by_sev = group_and_sort_findings(findings)
        for sev in by_sev:
            sevcap = sev.capitalize()
            if sevcap in counts[tool]:
                counts[tool][sevcap] += len(by_sev[sev])
    md = "| Tool | " + " | ".join(sevs) + " |\n"
    md += "|---" + "|---" * len(sevs) + "|\n"
    for tool in tool_names:
        md += "| " + tool + " | " + " | ".join(str(counts[tool][sev]) for sev in sevs) + " |\n"
    return md


def build_prompt(trivy, semgrep, trufflehog, zap, garak):
    # Package all findings as context (Trivy/Semgrep/TruffleHog/ZAP: list or dict, Garak: list)
    context = (
        "# CI/CD Security Scan Results\n"
        "This report compiles and summarizes scan findings from:\n"
        "- [Trivy](https://github.com/aquasecurity/trivy) (Open source SCA/IaC)\n"
        "- [Semgrep](https://semgrep.dev/) (SAST)\n"
        "- [TruffleHog](https://trufflesecurity.com/) (Secrets scanning)\n"
        "- [OWASP ZAP](https://owasp.org/www-project-zap/) (DAST)\n"
        "- [Garak](https://github.com/leondz/garak) (LLM Security fuzzing)\n"
        "\n"
    )
    # Executive summary section, let model fill in
    context += (
        "## Executive Summary\n"
        "> Using results below, generate a concise statement of project security/risk posture for stakeholders.\n\n"
    )
    # Risk heatmap
    context += "## Heatmap of Findings\n"
    context += build_risk_heatmap({
        "Trivy": trivy, "Semgrep": semgrep,
        "TruffleHog": trufflehog, "ZAP": zap, "Garak": garak
    }) + "\n"

    # Tool-by-tool findings
    context += "\n---\n## Detailed Findings & Actions\n\n"

    context += "### Trivy (SCA/IaC)\n"
    context += summarize_findings_md(trivy, "Trivy") + "\n\n"

    context += "### Semgrep (SAST)\n"
    context += summarize_findings_md(semgrep, "Semgrep") + "\n\n"

    context += "### TruffleHog (Secrets)\n"
    context += summarize_findings_md(trufflehog, "TruffleHog") + "\n\n"

    context += "### ZAP (DAST)\n"
    context += summarize_findings_md(zap, "ZAP") + "\n\n"

    context += "### Garak (LLM Security)\n"
    context += summarize_findings_md(garak, "Garak") + "\n\n"

    context += (
        "---\n"
        "## Developer Guidance\n"
        "- Prioritize remediation of all Critical/High findings before production deploys.\n"
        "- Add and track security tickets for any medium-rated issue.\n"
        "- For any secret finding: immediately revoke and rotate, and purge from VCS.\n"
        "- For any code or dependency vulnerability: patch or refactor as noted.\n"
        "- For DAST/LLM findings: strengthen endpoint validation and input handling.\n"
        "\n"
        "#### End with a professional, concise, actionable summary for the development and security teams.\n"
    )
    return context


def summarize_with_gemini(prompt, api_key, model_name="gemini-2.0-flash"):
    genai.configure(api_key=api_key)
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        print("[INFO] Gemini API call: Success")
        return response.text
    except Exception as e:
        print(f"[ERROR] Gemini API failure: {e}")
        return "Failed to generate AI summary."


def flatten_trivy_findings(trivy):
    # Trivy sometimes returns {Results: [ ... {Vulnerabilities: []} ... ]}
    if isinstance(trivy, dict) and "Results" in trivy:
        all_vulns = []
        for r in trivy["Results"]:
            vs = r.get("Vulnerabilities", []) or r.get("vulnerabilities") or []
            all_vulns.extend(vs)
        return all_vulns
    elif isinstance(trivy, list):
        return trivy
    return []

def flatten_semgrep_findings(semgrep):
    # Semgrep may put findings in "results"
    if isinstance(semgrep, dict) and "results" in semgrep:
        return semgrep["results"]
    elif isinstance(semgrep, list):
        return semgrep
    return []

def flatten_trufflehog_findings(trufflehog):
    # trufflehog: {"scan_results":[...]}
    if isinstance(trufflehog, dict) and "scan_results" in trufflehog:
        return trufflehog["scan_results"]
    elif isinstance(trufflehog, list):
        return trufflehog
    return []

def flatten_zap_findings(zap):
    # zap full export: try "site" -> alerts, else top-level "alerts" or "site"
    if isinstance(zap, dict):
        if "site" in zap and "alerts" in zap["site"][0]:
            return zap["site"][0]["alerts"]
        if "alerts" in zap:
            return zap["alerts"]
    elif isinstance(zap, list):
        return zap
    return []

def flatten_garak_findings(garak):
    # Already a list, or may need to check "results"
    if isinstance(garak, list):
        return garak
    if isinstance(garak, dict) and "results" in garak:
        return garak["results"]
    return []

def main():
    parser = argparse.ArgumentParser(
        description="Generate a highly professional security summary using Gemini from CI/CD scan artifacts."
    )
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--trufflehog", required=True)
    parser.add_argument("--zap", required=True)
    parser.add_argument("--garak", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    trivy_raw = load_json_report(args.trivy)
    semgrep_raw = load_json_report(args.semgrep)
    trufflehog_raw = load_json_report(args.trufflehog)
    zap_raw = load_json_report(args.zap)
    garak_raw = load_jsonl_report(args.garak)

    trivy = flatten_trivy_findings(trivy_raw)
    semgrep = flatten_semgrep_findings(semgrep_raw)
    trufflehog = flatten_trufflehog_findings(trufflehog_raw)
    zap = flatten_zap_findings(zap_raw)
    garak = flatten_garak_findings(garak_raw)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY environment variable not set.")
        sys.exit(1)

    prompt = build_prompt(trivy, semgrep, trufflehog, zap, garak)
    print("[INFO] Prompt sent to Gemini...")

    summary = summarize_with_gemini(prompt, api_key)
    with open(args.output, "w", encoding="utf-8") as f:
        f.write(summary.strip() + "\n")

    print(f"[SUCCESS] AI security summary written to {args.output}\n")
    print("\n--- Summary Preview ---\n")
    print(summary.strip()[:2000])
    print("\n--- End of Preview ---")

if __name__ == "__main__":
    main()
