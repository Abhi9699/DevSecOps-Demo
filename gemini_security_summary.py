import argparse
import json
import os
import sys
import google.generativeai as genai
from collections import defaultdict


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


def extract_failed_garak_attempts(garak_entries):
    """
    Group attempts by probe_classname and return a list containing 
    all failure attempts for probes that have any failure attempts.
    """
    probe_attempts = defaultdict(list)
    for entry in garak_entries:
        probe_name = entry.get("probe_classname", "N/A")
        probe_attempts[probe_name].append(entry)

    failed_attempts = []
    for probe_name, attempts in probe_attempts.items():
        has_failure = any(
            str(entry.get("status")).lower() in ("2", "fail") for entry in attempts
        )
        if has_failure:
            failed_attempts.extend(
                [a for a in attempts if str(a.get("status")).lower() in ("2", "fail")]
            )
    return failed_attempts


def build_prompt(trivy, semgrep, trufflehog, zap, garak_failed_attempts):
    garak_json_text = json.dumps(garak_failed_attempts, indent=2)[:5000] if garak_failed_attempts else "[]"

    prompt = (
        "You are an expert security AI. Using ONLY the JSON or JSONL scan findings below, generate a concise, inclusive Markdown security report "
        "designed for all audiences (engineers, QA, managers, security leads):\n\n"
        "- Begin with a brief summary describing overall security status, critical/high issues, and next actions.\n"
        "- For each tool (Trivy, Semgrep, TruffleHog, ZAP), present findings grouped and numbered, including title, severity, impact, remediation, and file/line if available.\n"
        "- Use clear Markdown, concise and professional.\n"
        "- Do NOT generate a title (it will be added externally).\n\n"
        "For Garak failed probe attempts (provided in JSON Lines format), each entry represents a failed probe attempt:\n"
        "- For each failed attempt, include:\n"
        "  * Probe Name (`probe_classname`)\n"
        "  * Prompt issued (code block)\n"
        "  * Model Output verbatim (code block)\n"
        "  * Explanation why it failed (hallucination, misinformation, privacy violation, etc.)\n"
        "  * Impact clearly described for all audiences\n"
        "  * Practical remediation steps\n"
        "  * Severity (default to 'Low' if unspecified)\n"
        "- If no failed attempts are present, clearly state 'No vulnerabilities found in Garak scans.'\n"
        "- Present only failures; omit success or informational entries.\n\n"
        "## CI/CD Pipeline Scan Data (JSON below):\n"
        "Trivy:\n" + json.dumps(trivy, indent=2)[:5000] + "\n\n"
        "Semgrep:\n" + json.dumps(semgrep, indent=2)[:5000] + "\n\n"
        "TruffleHog:\n" + json.dumps(trufflehog, indent=2)[:5000] + "\n\n"
        "ZAP:\n" + json.dumps(zap, indent=2)[:5000] + "\n\n"
        "Garak Failed Attempts:\n" + garak_json_text + "\n"
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
    garak = load_jsonl(args.garak)

    garak_failed_attempts = extract_failed_garak_attempts(garak)

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY environment variable not set.")
        sys.exit(1)

    prompt = build_prompt(trivy, semgrep, trufflehog, zap, garak_failed_attempts)
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
