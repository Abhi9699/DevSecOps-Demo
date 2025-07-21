import argparse
import json
import os
import sys
import google.generativeai as genai

def load_json_report(path):
    """Load a standard JSON file."""
    if not os.path.isfile(path):
        print(f"[WARN] JSON not found: {path}")
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to load JSON from {path}: {e}")
        return None

def load_jsonl_report(path):
    """Load a JSONL (newline-delimited JSON) file as a list of objects."""
    if not os.path.isfile(path):
        print(f"[WARN] JSONL not found: {path}")
        return None
    report = []
    with open(path, "r", encoding="utf-8") as f:
        for i, line in enumerate(f, 1):
            line = line.strip()
            if not line:
                continue
            try:
                report.append(json.loads(line))
            except Exception as e:
                print(f"[WARN] Invalid JSONL at line {i}: {e}")
    return report

def summarize_findings(findings, max_items=10):
    """Format a summary bullet list for findings."""
    if not findings:
        return "_No results found._"
    items = []
    if isinstance(findings, dict):
        for key in ("results", "matches", "vulnerabilities", "violations"):
            if key in findings:
                items = findings[key]
                break
        if not items and "scan_results" in findings:  # trufflehog
            items = findings["scan_results"]
        if not items:
            items = list(findings.values())
    elif isinstance(findings, list):
        items = findings
    else:
        return "_No actionable findings found._"
    out = []
    count = 0
    for item in items:
        if count >= max_items:
            out.append(f"...({len(items)-max_items} more not shown)")
            break
        if isinstance(item, dict):
            desc = []
            for k in ["filepath", "reason", "line", "secret", "rule", "type", "issue", "message", "severity"]:
                v = item.get(k)
                if v:
                    desc.append(f"`{k}: {v}`")
            if "diff" in item:
                desc.append("`diff detected`")
            if not desc:
                desc.append(str(item))
            out.append("* " + " | ".join(desc))
        else:
            out.append(f"* {str(item)}")
        count += 1
    return "\n".join(out) if out else "_No findings to summarize._"

def build_prompt(trivy, semgrep, trufflehog, zap, garak):
    prompt = (
        "You are a senior DevSecOps AI assistant. Below are scan results from an automated CI/CD pipeline "
        "covering:\n"
        "- SCA/IaC (Trivy)\n"
        "- SAST (Semgrep)\n"
        "- Secrets (TruffleHog)\n"
        "- DAST (ZAP)\n"
        "- LLM Security (Garak)\n\n"
        "For each tool:\n"
        "* Summarize up to the top 10 most urgent or critical findings (with affected files/URLs if available)\n"
        "* Note critical/high/medium severities if present\n"
        "* Recommend actionable remediation steps for each finding or grouped issue\n"
        "* Write as professional, concise Markdown (no raw JSON, no redundant info)\n\n"
        "---\n"
    )
    prompt += "## Trivy (SCA/IaC)\n" + summarize_findings(trivy) + "\n\n"
    prompt += "## Semgrep (SAST)\n" + summarize_findings(semgrep) + "\n\n"
    prompt += "## TruffleHog (Secrets)\n" + summarize_findings(trufflehog) + "\n\n"
    prompt += "## ZAP (DAST)\n" + summarize_findings(zap) + "\n\n"
    prompt += "## Garak (LLM Security)\n" + summarize_findings(garak, max_items=10) + "\n\n"
    prompt += "---\nHighlight the most urgent actions for the dev team. End with a one-paragraph summary if possible."
    return prompt

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

def main():
    parser = argparse.ArgumentParser(
        description="Generate AI security summary (Gemini) from CI/CD scan artifacts."
    )
    parser.add_argument("--trivy", required=True)
    parser.add_argument("--semgrep", required=True)
    parser.add_argument("--trufflehog", required=True)
    parser.add_argument("--zap", required=True)
    parser.add_argument("--garak", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    trivy = load_json_report(args.trivy)
    semgrep = load_json_report(args.semgrep)
    trufflehog = load_json_report(args.trufflehog)
    zap = load_json_report(args.zap)
    garak = load_jsonl_report(args.garak)

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
