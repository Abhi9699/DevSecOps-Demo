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


def build_prompt(trivy, semgrep, trufflehog, zap, garak):
    prompt = (
        "You are an expert security AI. Using ONLY the JSON or JSONL scan findings below, generate a concise, inclusive Markdown security report "
        "designed for all audiences (engineers, QA, managers, security leads):\n\n"
        "- Begin with a brief plain English summary describing the general security health, presence or absence of critical/high issues, and next recommended actions.\n"
        "- For each tool (Trivy, Semgrep, TruffleHog, ZAP), present findings grouped and numbered, including:\n"
        "  * Issue title\n"
        "  * Severity in plain language\n"
        "  * Impact in clear, understandable terms\n"
        "  * Actionable remediation steps\n"
        "  * File/line location if available\n"
        "- Use clear and readable Markdown formatting.\n"
        "- Do NOT generate a report title (it will be inserted externally).\n\n"
        "For the Garak tool results (provided in JSON Lines format), process every entry as follows:\n"
        "- Examine the `status` field.\n"
        "- If the status indicates a failure (e.g., contains 'fail', or numeric codes that mean failure), report the entry as a vulnerability with:\n"
        "  * Probe Name (`probe_classname`)\n"
        "  * Prompt issued (in fenced code block)\n"
        "  * Model Output verbatim (in fenced code block)\n"
        "  * A concise explanation of why this entry is considered a failure (hallucination, misinformation, privacy issue, etc.)\n"
        "  * The impact explained clearly for all audiences\n"
        "  * Practical remediation steps\n"
        "  * Severity (use 'Low' if not specified)\n"
        "- For entries with non-failure statuses (success, ok, informational), mention 'No vulnerability detected.' for clarity but do not elaborate.\n"
        "- Do NOT duplicate or aggregate failures; treat each failing entry individually.\n"
        "- Present findings professionally, concisely, avoiding redundant text, and format for clarity and ease of review.\n\n"
        "## CI/CD Pipeline Scan Data (JSON below):\n"
        "Trivy:\n" + json.dumps(trivy, indent=2)[:5000] + "\n\n"
        "Semgrep:\n" + json.dumps(semgrep, indent=2)[:5000] + "\n\n"
        "TruffleHog:\n" + json.dumps(trufflehog, indent=2)[:5000] + "\n\n"
        "ZAP:\n" + json.dumps(zap, indent=2)[:5000] + "\n\n"
        "Garak:\n" + json.dumps(garak, indent=2)[:5000] + "\n"
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

    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[ERROR] GEMINI_API_KEY environment variable not set.")
        sys.exit(1)

    prompt = build_prompt(trivy, semgrep, trufflehog, zap, garak)
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
