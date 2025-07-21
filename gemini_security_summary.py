import argparse
import json
import os
import sys
import google.generativeai as genai

def load_json(path):
    """Load a JSON file (standard or JSONL based on extension)."""
    if not os.path.isfile(path):
        print(f"[WARN] File not found: {path}")
        return None

    try:
        if path.endswith(".jsonl"):
            with open(path, "r", encoding="utf-8") as f:
                return [json.loads(line.strip()) for line in f if line.strip()]
        else:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        print(f"[ERROR] Failed to parse {path}: {e}")
        return None

def summarize_findings(findings, max_items=10):
    """Format key findings as a Markdown bullet list."""
    if not findings:
        return "_No results found._"

    items = []
    if isinstance(findings, dict):
        for key in ("results", "matches", "vulnerabilities", "violations", "scan_results"):
            if key in findings:
                items = findings[key]
                break
        if not items:
            items = list(findings.values())
    elif isinstance(findings, list):
        items = findings
    else:
        return "_No actionable findings._"

    output = []
    for i, item in enumerate(items[:max_items]):
        if isinstance(item, dict):
            parts = [
                f"`{k}: {v}`" for k in [
                    "filepath", "reason", "line", "secret",
                    "rule", "type", "issue", "message", "severity"
                ] if (v := item.get(k))
            ]
            if "diff" in item:
                parts.append("`diff detected`")
            output.append("* " + " | ".join(parts) if parts else f"* {item}")
        else:
            output.append(f"* {str(item)}")

    if len(items) > max_items:
        output.append(f"...({len(items) - max_items} more not shown)")
    
    return "\n".join(output)

def build_prompt(trivy, semgrep, trufflehog, zap, garak):
    """Construct the AI prompt for Gemini summarization."""
    sections = {
        "Trivy (SCA/IaC)": trivy,
        "Semgrep (SAST)": semgrep,
        "TruffleHog (Secrets)": trufflehog,
        "ZAP (DAST)": zap,
        "Garak (LLM Security)": garak
    }

    prompt = (
        "You are a senior DevSecOps AI assistant. Below are security scan outputs "
        "from an automated CI/CD pipeline across:\n\n"
        "- Software Composition Analysis (Trivy)\n"
        "- Static Analysis (Semgrep)\n"
        "- Secrets Detection (TruffleHog)\n"
        "- Dynamic Analysis (ZAP)\n"
        "- LLM Vulnerability Testing (Garak)\n\n"
        "### Instructions:\n"
        "- Highlight the top 10 most urgent or critical issues per tool.\n"
        "- Mention severity levels (Critical/High/Medium).\n"
        "- Recommend actionable remediations.\n"
        "- Format output in clean, professional Markdown (no raw JSON).\n\n"
        "---\n"
    )

    for title, data in sections.items():
        prompt += f"## {title}\n{summarize_findings(data)}\n\n"

    prompt += "---\n**Highlight the most urgent issues across the tools, suggest priority actions, and conclude with a professional summary paragraph.**"
    return prompt

def summarize_with_gemini(prompt, api_key, model_name="gemini-2.0-flash"):
    """Query the Gemini API with the generated prompt."""
    genai.configure(api_key=api_key)
    try:
        model = genai.GenerativeModel(model_name)
        response = model.generate_content(prompt)
        print("[INFO] Gemini API call: Success")
        return response.text
    except Exception as e:
        print(f"[ERROR] Gemini API request failed: {e}")
        return "⚠️ Failed to generate AI summary."

def main():
    parser = argparse.ArgumentParser(
        description="Generate a professional AI-driven security summary report using Gemini."
    )
    parser.add_argument("--trivy", required=True, help="Path to Trivy JSON report")
    parser.add_argument("--semgrep", required=True, help="Path to Semgrep JSON report")
    parser.add_argument("--trufflehog", required=True, help="Path to TruffleHog JSON report")
    parser.add_argument("--zap", required=True, help="Path to ZAP JSON report")
    parser.add_argument("--garak", required=True, help="Path to Garak JSONL report")
    parser.add_argument("--output", required=True, help="Path to write the final AI summary")
    args = parser.parse_args()

    # Load reports
    print("[INFO] Loading scan reports...")
    trivy = load_json(args.trivy)
    semgrep = load_json(args.semgrep)
    trufflehog = load_json(args.trufflehog)
    zap = load_json(args.zap)
    garak = load_json(args.garak)

    # Validate API key
    api_key = os.environ.get("GEMINI_API_KEY")
    if not api_key:
        print("[FATAL] Environment variable GEMINI_API_KEY is not set.")
        sys.exit(1)

    # Build prompt and get summary
    prompt = build_prompt(trivy, semgrep, trufflehog, zap, garak)
    print("[INFO] Sending prompt to Gemini API...")
    summary = summarize_with_gemini(prompt, api_key)

    # Write output
    try:
        with open(args.output, "w", encoding="utf-8") as f:
            f.write(summary.strip() + "\n")
        print(f"[SUCCESS] AI-generated security summary saved to: {args.output}")
    except Exception as e:
        print(f"[ERROR] Failed to write output: {e}")
        sys.exit(1)

    # Preview
    print("\n--- Summary Preview ---\n")
    print(summary.strip()[:2000])
    print("\n--- End of Preview ---")

if __name__ == "__main__":
    main()
