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
        "You are an expert security AI. Using ONLY the JSON or JSONL scan findings below, generate a concise, inclusive Markdown security report designed for all audiences (engineers, QA, managers, security leads):\n\n"
        "- Start with a concise, plain English summary describing general security health, presence or absence of critical/high issues, and next actions. Do NOT repeat detailed issue findings in the summary.\n"
        "- For each tool below, present findings grouped and numbered (provide for each finding: issue title, severity in plain language, impact, actionable bullets for remediation based only on data from the JSON/JSONL; include file/line if available).\n"
        "- Use readable Markdown, concise and clear.\n"
        "- Do NOT generate a title (it will be inserted by the pipeline script).\n\n"
        "For the Garak tool results (provided in JSON Lines format), please follow these additional instructions:\n"
        "- Treat every Garak entry as a security probe result: if an entry has \"status\": \"fail\" (case-insensitive) or outputs/messages indicating errors, incorrect answers, hallucinations, failures, anomalies, or unexpected or suspicious behavior, **ALWAYS** report it as a security vulnerability or weakness (even if it is not classical or obvious).\n"
        "- For ALL Garak entries with \"status\": \"fail\", assign at least 'Low' severity if a more precise severity can't be deduced.\n"
        "- Explain the observed failure briefly, leveraging fields such as \"probe_classname\", \"outputs\", and \"prompt\".\n"
        "- Include the failed output excerpt verbatim for context.\n"
        "- Provide clear, actionable remediation steps; if unable to infer, say \"Further investigation is required to determine remediation.\"\n"
        "- If an entry is informational and shows no security weakness (e.g., \"status\": \"success\", \"ok\", or equivalent), explicitly state 'No vulnerability detected.'\n"
        "- Each Garak failure must be reported as an individual finding—do NOT aggregate or omit failures.\n\n"
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
