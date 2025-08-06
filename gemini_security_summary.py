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
            for key in (
                "results",
                "matches",
                "vulnerabilities",
                "violations",
                "scan_results",
                "alerts",
            ):
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
    """
    Build a prompt instructing the AI to generate a concise, professional 
    Markdown report designed for all audiences, dynamically handling all 
    Garak probes with a standardized format regardless of probe type.
    """
    prompt = (
        "You are an expert security AI. Using ONLY the JSON or JSONL scan findings below, generate a concise, inclusive Markdown security report designed "
        "for all audiences (engineers, QA, managers, security leads):\n\n"
        "- Start with a brief plain English summary describing general security health, presence or absence of critical/high issues, and recommended next steps. "
        "Avoid repeating issue details in the summary.\n"
        "- For each tool below, present findings grouped and numbered.\n"
        "- For Trivy, Semgrep, TruffleHog, and ZAP, provide: issue title, severity (plain language), impact, and clear remediation steps. Include file/line info if available.\n\n"
        "- For the Garak tool (JSON Lines format), for **each individual probe entry**, do the following:\n"
        "  * Present the probe name (`probe_classname`), 'Prompt' issued, and the 'Model Output' verbatim.\n"
        "  * If the `status` is 'fail' (case insensitive) or outputs/messages indicate suspicious, incorrect, or anomalous behavior, **treat it as a security vulnerability or weakness.**\n"
        "  * Provide a short bullet-point list explaining 'What Went Wrong' based on the discrepancy or failure.\n"
        "  * Clearly state the 'Impact' in simple language.\n"
        "  * Provide easy-to-understand, actionable remediation steps.\n"
        "  * If severity level can't be determined, assign at least 'Low'.\n"
        "  * If the entry is informational (e.g., status 'success' or 'ok'), state 'No vulnerability detected.'\n"
        "  * Do NOT aggregate or skip Garak entries; handle and report each separately.\n\n"
        "Use clear Markdown headings, code blocks for prompts and outputs, and bullet points for explanations.\n"
        "- Do NOT generate a title (it will be inserted externally).\n\n"
        "## CI/CD Pipeline Scan Data (JSON below):\n\n"
        "Trivy:\n"
        + json.dumps(trivy, indent=2)[:5000]
        + "\n\nSemgrep:\n"
        + json.dumps(semgrep, indent=2)[:5000]
        + "\n\nTruffleHog:\n"
        + json.dumps(trufflehog, indent=2)[:5000]
        + "\n\nZAP:\n"
        + json.dumps(zap, indent=2)[:5000]
        + "\n\nGarak:\n"
        + json.dumps(garak, indent=2)[:5000]
        + "\n---"
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
