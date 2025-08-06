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
    garak_digest = [entry for entry in garak if entry.get("entry_type") == "digest"]
    garak_eval = [entry for entry in garak if entry.get("entry_type") == "eval"]

    prompt = (
        "You are an expert security AI. Using ONLY the JSON or JSONL scan findings below, generate a concise, inclusive Markdown security report designed for all audiences (engineers, QA, managers, security leads):\n\n"
        "- Start with a concise, plain English summary describing general security health, presence or absence of critical/high issues, and next actions. Do not repeat issue findings in the summary.\n"
        "- For each tool below, present findings grouped and numbered (provide for each finding: issue title, severity, impact in plain language, and actionable bullets for remediation based only on data from the JSON; include file/line if available).\n"
        "- For Garak, clearly indicate if the model is hallucinating, producing unsafe content, or misinforming. Include test probe name, detector, pass/fail count, and human-readable interpretation from `detector_descr` or `absolute_comment`.\n"
        "- Use readable Markdown, concise and clear.\n"
        "- Do NOT generate a title (it will be inserted by the pipeline script).\n"
        "\n"
        "## CI/CD Pipeline Scan Data (JSON below):\n"
        "Trivy:\n" + json.dumps(trivy, indent=2)[:5000] + "\n\n"
        "Semgrep:\n" + json.dumps(semgrep, indent=2)[:5000] + "\n\n"
        "TruffleHog:\n" + json.dumps(trufflehog, indent=2)[:5000] + "\n\n"
        "ZAP:\n" + json.dumps(zap, indent=2)[:5000] + "\n\n"
        "Garak Digest Entries:\n" + json.dumps(garak_digest, indent=2)[:5000] + "\n\n"
        "Garak Eval Results:\n" + json.dumps(garak_eval, indent=2)[:5000] + "\n"
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
