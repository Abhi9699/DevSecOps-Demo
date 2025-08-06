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
    Convert raw Garak entries into structured findings, preserving
    all key details and passing them for AI summarization.
    Detects vulnerabilities based on explicit FAIL indicators and 
    detector_results (e.g., zero scores).
    """
    findings = []
    for entry in garak_results:
        # Check explicit failure indicators
        failure_fields = ['result', 'outcome', 'status']
        is_vulnerable = any(str(entry.get(f, '')).upper() == 'FAIL' for f in failure_fields)

        # Check detector_results for 0.0 scores meaning failure
        detector_results = entry.get('detector_results', {})
        if not is_vulnerable and isinstance(detector_results, dict):
            for scores in detector_results.values():
                if isinstance(scores, list) and any(float(score) == 0.0 for score in scores):
                    is_vulnerable = True
                    break
                elif isinstance(scores, (float, int)) and float(scores) == 0.0:
                    is_vulnerable = True
                    break

        # Include heuristic keywords
        keywords = ['fail', 'error', 'leak', 'jailbreak', 'unsafe']
        if not is_vulnerable:
            values_to_check = (
                v.lower() if isinstance(v, str) else json.dumps(v).lower()
                for v in entry.values()
                if isinstance(v, (str, list, dict))
            )
            if any(any(kw in val for kw in keywords) for val in values_to_check):
                is_vulnerable = True

        if is_vulnerable:
            findings.append({
                "probe": entry.get("probe") or entry.get("probes") or "Unknown",
                "detector": entry.get("detector") or entry.get("detectors") or
                            next(iter(detector_results), "Unknown") if detector_results else "Unknown",
                "prompt": entry.get("prompt") or "",
                "output": entry.get("output") or "",
                "detector_results": detector_results,
                "full_entry": entry  # Pass the raw entry for AI's reference
            })
    print(f"[INFO] Garak findings detected: {len(findings)}")
    return findings


def build_prompt(trivy, semgrep, trufflehog, zap, garak_findings):
    """
    Builds a detailed prompt for Gemini AI to generate a professional
    security report, explicitly instructing the AI to interpret Garak findings.
    """

    def json_snippet(obj):
        try:
            return json.dumps(obj, indent=2)[:5000]
        except Exception:
            return "[]"

    prompt = (
        "You are an expert AI security analyst. Using ONLY the JSON scan findings below from multiple tools, "
        "create a professional Markdown security report for engineers, QA, managers, and security leads.\n\n"
        "- Begin with a concise, clear summary describing overall security posture, presence or absence of critical/high issues, and recommended next steps.\n"
        "- For each tool, list findings clearly and numbered:\n"
        "  * For **Garak**, use the detailed data (probe, detector, prompt, output, detector results) to **write a specific vulnerability title and explain the exact nature and impact of the AI vulnerability detected**.\n"
        "  * Provide clear, actionable remediation advice tailored to the finding.\n"
        "- Include relevant excerpts like probes and model output for clarity.\n"
        "- Use professional, accessible language; avoid generic or repetitive phrasing.\n"
        "- DO NOT generate a report title (it will be added separately).\n\n"
        "## CI/CD Pipeline Scan Data (JSON below):\n"
        "Trivy:\n" + json_snippet(trivy) + "\n\n"
        "Semgrep:\n" + json_snippet(semgrep) + "\n\n"
        "TruffleHog:\n" + json_snippet(trufflehog) + "\n\n"
        "ZAP:\n" + json_snippet(zap) + "\n\n"
        "Garak (Detailed AI Security Findings):\n" + json_snippet(garak_findings) + "\n"
        "---"
    )
    return prompt


def summarize_with_gemini(prompt, api_key, model_name="gemini-2.0-flash"):
    """
    Calls Google Gemini generative model to create the summary.
    """
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
    parser = argparse.ArgumentParser(description="Generate AI-driven CI/CD security scan report with detailed Garak findings.")
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
