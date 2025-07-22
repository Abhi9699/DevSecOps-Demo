import argparse
import json
import os
import sys
import google.generativeai as genai

def load_json(path):
    """Load a JSON file (not JSONL)."""
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
            # Flatten known containers
            for key in ("results", "matches", "vulnerabilities", "violations", "scan_results", "alerts"):
                if isinstance(obj, dict) and key in obj and isinstance(obj[key], list):
                    return obj[key]
            # Trivy: Results->Vulnerabilities
            if isinstance(obj, dict) and "Results" in obj:
                vulns = []
                for r in obj["Results"]:
                    vulns.extend(r.get("Vulnerabilities") or [])
                if vulns:
                    return vulns
            return obj if isinstance(obj, list) else [obj]
    except Exception as e:
        print(f"[WARN] Could not parse {path}: {e}")
        return []

def load_jsonl(path):
    """Load a JSONL file (one JSON object per line)."""
    if not os.path.isfile(path):
        return []
    data = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        data.append(json.loads(line))
                    except Exception as e:
                        print(f"[WARN] Skipping malformed JSON line: {e}")
        return data
    except Exception as e:
        print(f"[WARN] Could not parse {path}: {e}")
        return []

def issue_title(item, tool):
    for field in ["issue", "rule_id", "title", "type"]:
        val = item.get(field)
        if val:
            if isinstance(val, list): val = " | ".join(str(x) for x in val)
            return str(val).strip()[:120]
    f = item.get("file") or item.get("filepath") or item.get("url") or item.get("resource")
    if f:
        kind = item.get("type") or item.get("rule_id") or "Issue"
        return f"{kind} in {f}"
    msg = item.get("message") or item.get("description")
    if msg: return str(msg).split(".", 1)[0][:120]
    return f"{tool} issue"

def impact_phrase(tool, issue):
    issue_l = str(issue).lower()
    if "xss" in issue_l:
        return "Attackers may steal credentials, hijack sessions, or inject malicious content."
    if "sql" in issue_l:
        return "Attackers could manipulate or extract sensitive database data."
    if "hardcoded" in issue_l or "secret" in issue_l or "key" in issue_l or "credential" in issue_l:
        return "Attackers may access sensitive systems or data."
    if "csrf" in issue_l:
        return "Enables attackers to perform unauthorized actions via session abuse."
    if tool == "Trivy" and ("outdated" in issue_l or "version" in issue_l):
        return "Outdated software may expose the system to known exploits."
    if tool == "Garak":
        return "Model may disclose confidential information or act on crafted prompts."
    if "deprecated" in issue_l:
        return "Could reduce application maintainability and security."
    if tool == "ZAP" and "cookie" in issue_l:
        return "May allow attackers to hijack user sessions."
    return "May reduce confidentiality, integrity, or availability of the app/system."

def remediation_advice(tool, severity, issue, item):
    severity = severity.lower()
    issue_l = str(issue).lower()
    bullets = []
    if tool == "Trivy":
        if severity in ("high", "critical"):
            bullets.append("Update the vulnerable dependency or image to the latest secure version.")
            bullets.append("Rebuild and redeploy the application.")
        if "misconfiguration" in issue_l or "port" in issue_l:
            bullets.append("Restrict and review exposed ports; remove unnecessary port exposure.")
        if severity in ("medium", "low"):
            bullets.append("Monitor and schedule update as part of routine maintenance.")
    elif tool == "Semgrep":
        if severity in ("high", "critical"):
            bullets.append("Remove hardcoded credentials and secrets from source and history.")
            bullets.append("Use environment variables or a secure secrets manager.")
        if "xss" in issue_l:
            bullets.append("Sanitize and validate all user input.")
            bullets.append("Apply output encoding for rendered content.")
        elif "deprecated" in issue_l:
            bullets.append("Refactor code to use supported APIs.")
        if severity in ("medium", "low"):
            bullets.append("Apply secure coding patterns in next development cycle.")
        if not bullets:
            bullets.append("Fix according to secure coding best practices.")
    elif tool == "TruffleHog":
        bullets.append("Immediately revoke and rotate exposed secrets.")
        bullets.append("Remove secrets from all source files and git history.")
        bullets.append("Use secrets management services.")
    elif tool == "ZAP":
        if severity in ("high", "critical"):
            bullets.append("Sanitize and validate all inputs to affected endpoints.")
            bullets.append("Implement strict output encoding or escaping.")
        if "cookie" in issue_l:
            bullets.append("Set Secure and HttpOnly flags on all cookies.")
        if severity in ("medium", "low"):
            bullets.append("Harden configuration as part of ongoing security review.")
    elif tool == "Garak":
        bullets.append("Sanitize user input and improve LLM prompt validations.")
        bullets.append("Restrict model responses for sensitive information.")
        bullets.append("Monitor usage and update prompt handling policies.")
    else:
        bullets.append("Remediate according to secure DevOps best practices.")
    if not bullets:
        bullets.append("Review and fix promptly.")
    return bullets

def formatted_findings(findings, tool):
    if not findings:
        return "_No issues detected._"
    lines = []
    for idx, item in enumerate(findings, 1):
        sev = str(item.get("severity") or item.get("level") or "Medium").capitalize()
        issue = issue_title(item, tool)
        impact = impact_phrase(tool, issue)
        rem = remediation_advice(tool, sev, issue, item)
        lines.append(
            f"{idx}. **{issue}**\n"
            f"   - **Severity:** {sev}\n"
            f"   - **Impact:** {impact}\n"
            f"   - **Remediation:**"
        )
        for b in rem:
            lines.append(f"     - {b}")
    return "\n".join(lines)

def build_prompt(trivy, semgrep, trufflehog, zap, garak):
    prompt = (
        "# CI/CD Security Scan Findings\n"
        "Each section lists all actionable issues for this pipeline run. "
        "For every finding: Issue name, Severity, Impact, and clear developer remediation steps are provided. "
        "Resolve all High/Critical issues before production deploy.\n\n"
        "## Trivy (Dependencies & IaC)\n" + formatted_findings(trivy, "Trivy") + "\n\n"
        "## Semgrep (Static Code Analysis)\n" + formatted_findings(semgrep, "Semgrep") + "\n\n"
        "## TruffleHog (Secrets Detection)\n" + formatted_findings(trufflehog, "TruffleHog") + "\n\n"
        "## ZAP (Web & API Security)\n" + formatted_findings(zap, "ZAP") + "\n\n"
        "## Garak (LLM Security)\n" + formatted_findings(garak, "Garak") + "\n"
    )
    return prompt

def summarize_with_gemini(prompt, api_key, model_name="gemini-2.0-flash"):
    genai.configure(api_key=api_key)
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        print("[INFO] Gemini summary generated.")
        return response.text
    except Exception as e:
        print(f"[ERROR] Gemini API error: {e}")
        return "AI summary failed."

def main():
    parser = argparse.ArgumentParser(description="Generate a world-class CI/CD security summary report.")
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--trufflehog", required=True)
    parser.add_argument("--zap", required=True)
    parser.add_argument("--garak", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    trivy      = load_json(args.trivy)
    semgrep    = load_json(args.semgrep)
    trufflehog = load_json(args.trufflehog)
    zap        = load_json(args.zap)
    garak      = load_jsonl(args.garak)   # <<< Garak scan is always loaded as JSONL!

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY environment variable not set.")
        sys.exit(1)

    prompt = build_prompt(trivy, semgrep, trufflehog, zap, garak)
    summary = summarize_with_gemini(prompt, api_key)

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(summary.strip() + "\n")
        print(f"[SUCCESS] Security summary written to {args.output}")
    except Exception as e:
        print(f"[ERROR] Failed to write report: {e}")
        sys.exit(1)

    print("\n--- Summary Preview ---\n")
    print(summary.strip()[:2000])
    print("\n--- End of Preview ---")

if __name__ == "__main__":
    main()
