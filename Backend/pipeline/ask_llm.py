import os
import openai
import json
from dotenv import load_dotenv

load_dotenv()
openai.api_key = os.getenv("OPENAI_API_KEY")

def summarize_findings_and_vulns(enriched_data):
    """
    Calls the LLM once to:
    1. Generate an executive summary of the overall findings.
    2. Generate 10-12 word summaries for each vulnerability.
    Returns:
        executive_summary (str)
        short_summaries (dict) -> {cve_id: short_summary}
    """

    # Build prompt with vulnerability list
    vuln_list_text = ""
    for item in enriched_data:
        service = item.get('product', 'Unknown')
        for vuln in item.get('vulnerabilities', []):
            vuln_list_text += (
                f"CVE ID: {vuln['cve_id']}\n"
                f"Severity: {vuln['severity']}\n"
                f"CVSS: {vuln['score']}\n"
                f"Service: {service}\n"
                f"Description: {vuln['description']}\n\n"
            )

    system_prompt = (
        "You are a cybersecurity expert tasked with generating a professional vulnerability report.\n"
    "You must:\n"
    "1. Provide an *executive summary* of the entire vulnerability scan results in a few paragraphs.\n"
    "2. Provide a *short 10–12 word summary* for each listed item (CVE IDs and Predicted CPE entries), "
    "focusing on the potential impact.\n"
    "The short summaries will be used in a compact table."
    )

    user_prompt = f"""
=== Vulnerability Data ===
{vuln_list_text}

Note: The above list may contain both CVE IDs and 'Predicted CPE X' entries.

Please respond in this exact JSON format:
{{
  "executive_summary": "Overall findings summary here...",
  "short_summaries": {{
    "CVE-XXXX-YYYY": "Short summary here",
    "Predicted CPE 1": "Short summary here"
  }}
}}
"""

    try:
        response = openai.chat.completions.create(
            model="gpt-4",
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            temperature=0.3
        )

        result = response.choices[0].message.content.strip()
        data = json.loads(result)

        return data.get("executive_summary", ""), data.get("short_summaries", {})

    except Exception as e:
        print("❌ Error contacting LLM:", e)
        return "Error generating executive summary.", {}