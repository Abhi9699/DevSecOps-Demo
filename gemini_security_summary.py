import argparse
import json
import os
import sys
import google.generativeai as genai


def load_json(path):
    if not os.path.isfile(path):
        return []
    try:
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
            for key in ("results", "matches", "vulnerabilities", "violations", "scan_results", "alerts"):
                if isinstance(obj, dict) and key in obj and isinstance(obj[key], list):
                    return obj[key]
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
    if not os.path.isfile(path):
        return []
    data = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line_no, line in enumerate(f, 1):
                line = line.strip()
                if line:
                    try:
                        data.append(json.loads(line))
                    except Exception as e:
                        print(f"[WARN] Skipping malformed JSON line {line_no}: {e}")
        return data
    except Exception as e:
        print(f"[WARN] Could not parse {path}: {e}")
        return []


def standardize_garak_findings(garak_results):
    """
    Convert raw Garak JSONL entries into standardized vulnerability findings.
    Detects failures and potential AI security issues, and formats them properly.
    """
    findings = []
    for entry in garak_results:
        # Determine if this entry is a fail/vulnerability
        result = str(entry.get('result', '')).upper()
        outcome = str(entry.get('outcome', '')).upper()
        status = str(entry.get('status', '')).upper()

        is_fail = result == 'FAIL' or outcome == 'FAIL' or status == 'FAIL'

        # Additional heuristic: check relevant fields for "fail" keyword
        if not is_fail:
            fail_keywords = ['fail', 'error', 'leak', 'unsafe', 'jailbreak']
            for k in ('detector', 'probe', 'result', 'outcome', 'status', 'message'):
                val = str(entry.get(k, '')).lower()
                if any(keyword in val for keyword in fail_keywords):
                    is_fail = True
                    break

        if is_fail:
            probe = entry.get('probe') or entry.get('probes') or "Unknown Probe"
            detector = entry.get('detector') or entry.get('detectors') or "Unknown Detector"
            issue_title = f"Garak probe '{probe}' detected an issue in detector '{detector}'"
            severity = "High"
            impact = (
                "AI model triggered a Garak security probe indicating a potential vulnerability, " 
                "such as privacy leakage, prompt injection, jailbreaking, or unsafe output."
            )
            actionable = [
                "Review the Garak output and model behavior carefully to identify cause.",
                "Apply additional prompt filtering, red-teaming, or model fine-tuning as needed.",
                "Monitor subsequent scans to verify remediation effectiveness."
            ]
            findings.append({
                "issue_title": issue_title,
                "severity": severity,
                "impact": impact,
                "actionable": actionable,
                "details": entry
            })
    return findings


def build_prompt(trivy, semgrep, trufflehog, zap, garak_findings):
    prompt = (
        "You are an expert security AI. Using ONLY the JSON scan findings below, generate a concise, inclusive Markdown security report designed for all audiences (engineers, QA, managers, security leads):\n\n"
        "- Start with a concise, plain English summary describing general security health, presence or absence of critical/high issues, and next actions. Do not repeat issue findings in the summary.\n"
        "- For each tool below, present findings grouped and numbered (provide for each finding: issue title, severity, impact in plain language, and actionable bullets for remediation based only on data from the JSON; include file/line if available).\n"
        "- Any findings from Garak (including jailbreaks, privacy leaks, unsafe outputs) must be treated as critical security issues and highlighted clearly.\n"
        "- Use readable Markdown, concise and clear.\n"
        "- Do NOT generate a title (it will be inserted by the pipeline script).\n"
        "\n"
        "## CI/CD Pipeline Scan Data (JSON below):\n"
        "Trivy:\n" + json.dumps(trivy, indent=2)[:5000] + "\n\n"
        "Semgrep:\n" + json.dumps(semgrep, indent=2)[:5000] + "\n\n"
        "TruffleHog:\n" + json.dumps(trufflehog, indent=2)[:5000] + "\n\n"
        "ZAP:\n" + json.dumps(zap, indent=2)[:5000] + "\n\n"
        "Garak:\n" + json.dumps(garak_findings, indent=2)[:5000] + "\n"
        "---"
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
    parser = argparse.ArgumentParser(description="AI-driven security scan report for CI/CD pipelines with fixed title.")
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--trufflehog", required=True)
    parser.add_argument("--zap", required=True)
    parser.add_argument("--garak", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    trivy = load_json(args.trivy)
    semgrep = load_json(args.semgrep)
    trufflehog = load_json(args.trufflehog)
    zap = load_json(args.zap)
    garak_raw = load_jsonl(args.garak)

    # Standardize Garak findings before passing to prompt
    garak_findings = standardize_garak_findings(garak_raw)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY environment variable not set.")
        sys.exit(1)

    prompt = build_prompt(trivy, semgrep, trufflehog, zap, garak_findings)
    report_body = summarize_with_gemini(prompt, api_key)

    fixed_title = "# AI-Driven CI/CD Security Scan Report\n\n"
    report = fixed_title + (report_body.strip() if report_body else "")

    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(report + "\n")
        print(f"[SUCCESS] Security report written to {args.output}")
    except Exception as e:
        print(f"[ERROR] Failed to write report: {e}")
        sys.exit(1)

    print("\n--- Report Preview ---\n")
    print(report[:2000])
    print("\n--- End of Preview ---")


if __name__ == "__main__":
    main()
